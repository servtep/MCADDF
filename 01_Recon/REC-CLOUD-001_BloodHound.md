# REC-CLOUD-001: BloodHound for Azure/Entra Privilege Paths

## 1. MODULE METADATA

| Field | Value |
|-------|-------|
| **Module ID** | REC-CLOUD-001 |
| **Technique Name** | BloodHound for Azure/Entra privilege paths |
| **MITRE ATT&CK ID** | T1087.004 – Account Discovery: Cloud Account (+ related Cloud Matrix techniques) |
| **CVE** | N/A (Legitimate penetration testing tool) |
| **Platform** | Microsoft Entra ID / Azure Cloud |
| **Viability Status** | ACTIVE ✓ |
| **Difficulty to Detect** | MEDIUM-to-HIGH (depends on logging configuration) |
| **Requires Authentication** | Yes (compromised credentials or tokens) |
| **Applicable Versions** | All Azure/Entra ID tenants |
| **Last Verified** | December 2025 |
| **Author** | SERVTEP (Pchelnikau Artur) |

---

## 2. EXECUTIVE SUMMARY

BloodHound with AzureHound is a sophisticated cloud reconnaissance and privilege path mapping framework that enables threat actors to systematically enumerate Azure/Entra ID environments and visualize privilege escalation routes. AzureHound, a Go-based data collector in the BloodHound suite, leverages publicly accessible Microsoft Graph and Azure REST APIs to extract comprehensive information about cloud identities, permissions, infrastructure, and applications—then transforms this raw data into interactive attack path graphs through BloodHound's visualization engine.

**Threat Profile:** An attacker with compromised cloud credentials or stolen tokens can execute AzureHound to:
- Enumerate all Entra ID users, devices, and service principals
- Map role assignments and group memberships across directory, subscriptions, and resources
- Identify high-privilege accounts (Global Administrators, Privileged Role Administrators)
- Discover privilege escalation paths (e.g., nested group inheritance, delegation chains)
- Locate critical infrastructure (key vaults, storage accounts, automation accounts)
- Identify misconfigured service principals or applications with excessive permissions
- Visualize attack paths to crown jewels (data exfiltration targets)

**Business Impact:**
- Complete cloud environment exposure (architecture, hierarchy, permissions visible)
- Identification of attack pathsto administrative access
- Enablement of persistent backdoors and lateral movement across subscriptions
- Data exfiltration opportunities (storage accounts, databases, key vaults)
- Supply chain compromise (through automation accounts and CI/CD pipelines)
- Compliance violations (GDPR, DORA, ISO 27001)

---

## 3. TECHNICAL PREREQUISITES

### Required Knowledge
- Understanding of Entra ID/Azure AD architecture and identities
- Familiarity with Microsoft Graph and Azure REST APIs
- Knowledge of Azure RBAC roles and role-based access control
- Understanding of cloud privilege escalation paths
- Awareness of Entra ID group types and membership models

### Required Tools
- **AzureHound Community Edition (CE)** – Go binary data collector
  - Available: https://github.com/SpecterOps/AzureHound (releases)
  - Pre-compiled binaries for Windows, Linux, macOS
  - Current version: 2.6.0+ (as of December 2025)
- **BloodHound Community Edition** – Graph visualization engine
  - Requirements: Java runtime, Neo4j database
  - Available: https://github.com/SpecterOps/BloodHound
  - Can also use BloodHound Enterprise (commercial)
- **Compromised Cloud Credentials** – One of:
  - Username/password (user account)
  - Refresh token (from stolen session or device code flow)
  - JWT/Access token
  - Service principal secret or certificate
  - MFA-bypassed credentials

### System Requirements
- Machine with outbound HTTPS access (no victim network required)
- ~2GB RAM minimum (more for large tenant processing)
- Disk space for JSON output (~100MB typical for enterprise tenant)
- No administrative privileges required on execution machine

### Cloud/Environment Considerations
- **Azure Global Cloud:** Full support
- **Azure Government (GCC/GCC-H):** Supported (different endpoints)
- **Azure China:** Supported (different endpoints)
- **Entra ID-only (no on-premises AD):** Full support
- **Hybrid AD + Entra ID Connect:** Full support (cloud portion)
- **Multi-tenant environments:** Supported (if credentials in multiple tenants)
- **Guest accounts:** Limited enumeration (depends on Entra ID guest policies)

---

## 4. ENVIRONMENTAL RECONNAISSANCE

### Information Gathering Phase

Before executing AzureHound, establish target scope:

1. **Identify Cloud Environment**
   - Confirm Azure commercial, government, or China cloud
   - Identify authentication endpoints (login.microsoftonline.com vs. login.microsoftonline.us)
   - Determine tenant ID or domain names

2. **Credential Acquisition**
   - Obtain valid Entra ID user credentials via:
     - Phishing and credential theft
     - Compromised employees
     - Infostealer malware (browser sessions, tokens)
     - Insider threats
   - Identify if user has MFA enabled (bypasses available)
   - Determine user's permission scope (Reader+ needed for full enum)

3. **Authentication Method Selection**
   - **Username/password:** Simplest; blocked by MFA/CAP
   - **Refresh token:** Bypass MFA; can authenticate without interactive login
   - **JWT/Access token:** Fastest; tied to token TTL (typically 1 hour)
   - **Service principal:** Long-term access; if app has Graph/ARM permissions

### Risk Assessment Before Execution

- **Operational Risk:** Low (read-only queries; no malware/payload required)
- **Detection Risk:** Medium-to-High (high API volume; distinctive query patterns)
- **Legal Risk:** High (unauthorized cloud enumeration may violate CFAA, GDPR)
- **Attribution Risk:** High (API calls traceable to source account/IP)

---

## 5. DETAILED EXECUTION

### Method 1: User Enumeration (Account Discovery T1087.004)

**Objective:** Extract complete Entra ID user roster for targeting.

```bash
# Authenticate with username/password
./azurehound -u "user@contoso.com" -p "Password123!" \
  list users --tenant "contoso.onmicrosoft.com" -o users.json

# Or with refresh token (bypass MFA)
./azurehound -r "0.ARwA6Wg123..." \
  list users --tenant "contoso.onmicrosoft.com" -o users.json

# Or with JWT
./azurehound -j "eyJhbGciOiJSUzI1NiI..." \
  list users --tenant "contoso.onmicrosoft.com" -o users.json
```

**Data Extracted Per User:**
- `displayName` (full name)
- `jobTitle` (identifies high-value targets: "Administrator", "Cloud Architect")
- `mail` (email address for phishing)
- `userPrincipalName` (UPN for authentication attacks)
- `lastPasswordChangeDateTime` (password age)
- `accountEnabled` (active vs. disabled accounts)
- `userType` (Member vs. Guest)
- `tenantId`, `tenantName`

**Example Processing:**
```bash
# Extract administrators
jq '.[] | select(.jobTitle | contains("Admin")) | .userPrincipalName' users.json

# Extract mail addresses (phishing targets)
jq '.[] | .mail' users.json > targets.txt
```

---

### Method 2: Privilege Escalation Path Discovery (Permission Groups T1069.003)

**Objective:** Map privilege escalation paths to Global Admin.

```bash
# Enumerate all Entra ID roles
./azurehound -r "$REFRESH_TOKEN" \
  list roles --tenant "contoso.onmicrosoft.com" -o roles.json

# Enumerate role assignments (who has what admin role)
./azurehound -r "$REFRESH_TOKEN" \
  list role-assignments --tenant "contoso.onmicrosoft.com" -o role-assignments.json

# Enumerate groups and members (nested group escalation)
./azurehound -r "$REFRESH_TOKEN" \
  list groups --tenant "contoso.onmicrosoft.com" -o groups.json

./azurehound -r "$REFRESH_TOKEN" \
  list group-members --tenant "contoso.onmicrosoft.com" -o group-members.json

# Enumerate application role assignments
./azurehound -r "$REFRESH_TOKEN" \
  list app-role-assignments --tenant "contoso.onmicrosoft.com" -o app-roles.json
```

**Privilege Escalation Paths Identified:**
1. **Direct role assignment:** User → Global Admin role
2. **Nested group inheritance:** User → Group → Global Admin group
3. **Service principal delegation:** User → SP with RoleManagement.ReadWrite.Directory → assign admin role to another user
4. **App permission escalation:** User → App with admin role → act as app to perform admin tasks

---

### Method 3: Infrastructure & Resource Discovery (T1580, T1619, T1526)

**Objective:** Map cloud resources for lateral movement and data exfiltration.

```bash
# Storage accounts (data exfiltration targets)
./azurehound -r "$REFRESH_TOKEN" \
  list storage-accounts --tenant "contoso.onmicrosoft.com" -o storage.json

./azurehound -r "$REFRESH_TOKEN" \
  list storage-containers --tenant "contoso.onmicrosoft.com" -o containers.json

# Key vaults (credential storage)
./azurehound -r "$REFRESH_TOKEN" \
  list key-vaults --tenant "contoso.onmicrosoft.com" -o keyvaults.json

# Key vault access policies (who can access secrets)
./azurehound -r "$REFRESH_TOKEN" \
  list key-vault-access-policies --tenant "contoso.onmicrosoft.com" -o kv-policies.json

# Applications (potential backdoors)
./azurehound -r "$REFRESH_TOKEN" \
  list apps --tenant "contoso.onmicrosoft.com" -o applications.json

# Automation accounts (code execution with high privilege)
./azurehound -r "$REFRESH_TOKEN" \
  list automation-accounts --tenant "contoso.onmicrosoft.com" -o automation.json

# Virtual machines
./azurehound -r "$REFRESH_TOKEN" \
  list virtual-machines --tenant "contoso.onmicrosoft.com" -o vms.json
```

**Data Extracted:**
- Storage accounts: Name, location, endpoints, ACLs, redundancy
- Key vaults: Name, location, access policies, secret names
- Applications: App ID, permissions, owner, secret expiration
- Automation accounts: Name, runbooks (PowerShell code), credentials
- VMs: Name, location, resource group, managed identity assignments

---

### Method 4: BloodHound Visualization & Attack Path Analysis

**Objective:** Ingest AzureHound JSON data and visualize attack paths.

```bash
# Combine all collected data
cat *.json > combined-output.json

# Upload to BloodHound via GUI or API
# BloodHound Web Interface:
# 1. Login to BloodHound (http://localhost:8080)
# 2. Click "Upload Data"
# 3. Select combined-output.json
# 4. Wait for processing (10-30 minutes for large tenant)

# Query attack paths programmatically
# Search: "User1" -> "Global Administrator"
# BloodHound displays:
#   User1 -> (member of) -> Department Admins Group
#   -> (inherited) -> Global Administrator Role

# Identify misconfigured service principals
# Search: ServicePrincipal with "RoleManagement.ReadWrite.Directory" permission
# Escalation path shown: SP can assign admin roles to any user
```

**BloodHound Attack Path Visualization:**
- Nodes: Users, Groups, Roles, Applications, Resources
- Edges: Membership, ownership, permissions, delegation relationships
- Color-coding: Red = high-risk paths, Green = acceptable permissions
- Example path: "User" → "Group" → "Global Admin Role" (privilege escalation)

---

### Method 5: Complete Tenant Enumeration (All Discovery Techniques)

**Objective:** Full automated enumeration in single command.

```bash
# List all available collection options
./azurehound list -h

# Execute full enumeration
./azurehound -r "$REFRESH_TOKEN" \
  list \
  --tenant "contoso.onmicrosoft.com" \
  --all-users \
  --all-devices \
  --all-groups \
  --all-roles \
  --all-subscriptions \
  --all-resource-groups \
  --all-virtual-machines \
  --all-key-vaults \
  --all-storage-accounts \
  --all-apps \
  -o complete-tenant-dump.json

# Monitor progress (large tenants may take 10-60 minutes)
# Output: JSON containing all organizational structure, identities, permissions
```

**Result:** Comprehensive representation of entire Azure/Entra ID environment suitable for offline analysis and visualization.

---

### Method 6: OPSEC-Aware Execution (Evasion Techniques)

**Objective:** Execute AzureHound while minimizing detection.

```bash
# OPSEC Technique 1: Use legitimate-looking refresh token
# Obtain via device code flow (appears as standard user login)
# Less suspicious than raw credential usage

# OPSEC Technique 2: Stagger queries (slower execution, less noisy)
./azurehound -r "$REFRESH_TOKEN" list users ... &
sleep 300  # Wait before next command
./azurehound -r "$REFRESH_TOKEN" list groups ... &

# OPSEC Technique 3: Execute from victim subscription (harder to attribute)
# Create VM in victim's Azure environment, run AzureHound locally
# Use managed identity (no credentials visible)

# OPSEC Technique 4: Filter queries (reduce API call volume)
# Query only specific OUs or groups, not entire tenant
./azurehound -r "$REFRESH_TOKEN" \
  list users --tenant "contoso.onmicrosoft.com" \
  --filter 'displayName eq "John*"' -o filtered.json

# OPSEC Technique 5: Clean logs from victim environment
# Remove AzureHound test calls and enumeration traces
# (if access to victim logs obtained)
```

---

## 6. TOOLS & COMMANDS REFERENCE

### AzureHound Command Matrix

| Command | Purpose | API Used | Logs Generated |
|---------|---------|----------|-----------------|
| `list users` | Enumerate users | Graph | Logged (RequestURI=/users) |
| `list groups` | Enumerate groups | Graph | Logged |
| `list roles` | Directory roles | Graph | Logged |
| `list role-assignments` | Role assignments | Graph | Logged |
| `list devices` | Cloud devices | Graph | Logged |
| `list service-principals` | Apps/SPs | Graph | Logged |
| `list storage-accounts` | Storage accounts | ARM REST | **NOT logged** (logging gap) |
| `list key-vaults` | Key vaults | ARM REST | **NOT logged** |
| `list virtual-machines` | VMs | ARM REST | **NOT logged** |
| `list subscriptions` | Subscriptions | ARM REST | **NOT logged** |
| `list container-registries` | Container images | ARM REST | **NOT logged** |
| `list automation-accounts` | Automation runbooks | ARM REST | **NOT logged** |

### Authentication Examples

```bash
# Device code flow (interactive, bypasses MFA if multi-factor fatigue succeeds)
$body = @{
  "client_id" = "1950a258-227b-4e31-a9cf-717495945fc2"
  "resource" = "https://graph.microsoft.com"
}
$response = Invoke-RestMethod -Uri "https://login.microsoftonline.com/common/oauth2/devicecode?api-version=1.0" `
  -Method Post -Body $body
# User visits https://microsoft.com/devicelogin and enters code
# Generates refresh token automatically

# Service principal with secret
./azurehound --client-id "application-id" \
  --client-secret "secret-value" \
  --tenant "contoso.onmicrosoft.com" \
  list users -o output.json

# Service principal with certificate
./azurehound --client-id "application-id" \
  --certificate-path "/path/to/cert.pem" \
  --tenant "contoso.onmicrosoft.com" \
  list users -o output.json
```

---

## 7. ATOMIC TESTS (RED TEAM VALIDATION)

### Test 1: AzureHound Execution & Authentication

**Procedure:**
```bash
# Test with valid refresh token
./azurehound -r "0.ARwA6Wg..." list users --tenant "contoso.onmicrosoft.com" -o test-users.json

# Verify output
if [ -f "test-users.json" ] && [ $(jq length test-users.json) -gt 0 ]; then
  echo "✓ Test PASSED: AzureHound authenticated and enumerated users"
else
  echo "✗ Test FAILED: No output or authentication failure"
fi
```

**Success Criteria:** JSON file generated with 1+ user objects.

### Test 2: Global Administrator Detection

**Procedure:**
```bash
# Enumerate roles
./azurehound -r "$REFRESH_TOKEN" list roles -o roles.json

# Search for Global Administrator role
GLOBAL_ADMIN=$(jq '.[] | select(.displayName == "Global Administrator")' roles.json)

if [ ! -z "$GLOBAL_ADMIN" ]; then
  echo "✓ Test PASSED: Global Administrator role found"
else
  echo "✗ Test FAILED: Global Administrator role not accessible"
fi
```

**Success Criteria:** Global Administrator role (or equivalent) enumerated.

### Test 3: Privilege Escalation Path Visualization

**Procedure:**
```bash
# Import to BloodHound (via GUI or API)
# Query: User -> Global Administrator

# Check if any paths found
PATHS=$(blcli interactive "MATCH (u:User)-[*]->(ga:Group {name: 'Global Administrators'}) RETURN count(u)")

if [ "$PATHS" -gt 0 ]; then
  echo "✓ Test PASSED: Privilege escalation paths identified"
else
  echo "⚠ Test PASSED (Expected): No escalation paths in this tenant"
fi
```

**Success Criteria:** Paths identified or confirmed as non-existent.

### Test 4: Data Extraction from Storage Accounts

**Procedure:**
```bash
# Enumerate storage accounts
./azurehound -r "$REFRESH_TOKEN" list storage-accounts -o storage.json

# Count storage accounts found
STORAGE_COUNT=$(jq length storage.json)

if [ $STORAGE_COUNT -gt 0 ]; then
  echo "✓ Test PASSED: Found $STORAGE_COUNT storage accounts"
  jq '.[0]' storage.json  # Display first account
else
  echo "⚠ Test PASSED (Expected): No storage accounts or insufficient permissions"
fi
```

**Success Criteria:** 0+ storage accounts enumerated (depends on user permissions).

---

## 8. MICROSOFT SENTINEL DETECTION

### Detection Rule 1: AzureHound Graph API Enumeration Pattern

**Rule Configuration:**
- **Required Table:** MicrosoftGraphActivityLogs (must be enabled & exported)
- **Alert Severity:** High
- **Frequency:** Real-time (every 5 minutes)
- **Applies To:** All Entra ID tenants with Graph logging enabled

**KQL Query:**
```kusto
let AzureHoundEndpoints = dynamic([
    "https://graph.microsoft.com/v1.0/users",
    "https://graph.microsoft.com/v1.0/groups",
    "https://graph.microsoft.com/v1.0/roles",
    "https://graph.microsoft.com/v1.0/servicePrincipals",
    "https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments",
    "https://graph.microsoft.com/v1.0/devices",
    "https://graph.microsoft.com/v1.0/applications",
    "https://graph.microsoft.com/beta/groups",
    "https://graph.microsoft.com/beta/servicePrincipals",
    "https://graph.microsoft.com/beta/roleManagement/directory/estimateAccess"
]);

MicrosoftGraphActivityLogs
| where TimeGenerated > ago(1h)
| where ResponseStatusCode == 200
| extend NormalizedUri = replace_regex(RequestUri, @'\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b', @'<UUID>')
| extend NormalizedUri = replace_regex(NormalizedUri, @'\?.*$', @'')
| where NormalizedUri in (AzureHoundEndpoints)
| summarize
    CallCount = count(),
    UniqueEndpoints = dcount(NormalizedUri),
    FirstCall = min(TimeGenerated),
    LastCall = max(TimeGenerated),
    UserAgents = make_set(UserAgent, 10)
    by UserId, IPAddress, bin(TimeGenerated, 5m)
| where CallCount > 50  // Threshold: 50+ API calls in 5 minutes
| extend AlertSeverity = "High", TechniqueID = "T1087.004"
| project UserId, IPAddress, CallCount, UniqueEndpoints, FirstCall, LastCall, UserAgents, AlertSeverity, TechniqueID
```

**What This Detects:**
- Bulk user/group/role enumeration queries
- Rapid succession of discovery API calls (>50 in 5 minutes)
- Distinctive AzureHound query patterns
- Multiple endpoint access from single account/IP in short window

**Manual Configuration Steps (Azure Portal):**
1. **Azure Portal** → **Microsoft Sentinel**
2. Select workspace → **Analytics** → **+ Create** → **Scheduled query rule**
3. **General Tab:**
   - Name: `AzureHound Graph API Enumeration Pattern`
   - Severity: `High`
4. **Set rule logic Tab:**
   - Paste KQL query above
   - Run every: `5 minutes`
   - Lookup data from last: `1 hour`
5. **Incident settings:**
   - Enable **Create incidents**
   - Group by: User, IP address
6. Click **Review + create**

---

### Detection Rule 2: AzureHound User-Agent Detection

**Rule Configuration:**
- **Required Table:** MicrosoftGraphActivityLogs or GraphAPIAuditEvents
- **Alert Severity:** High
- **Frequency:** Real-time
- **Applies To:** All tenants

**KQL Query:**
```kusto
MicrosoftGraphActivityLogs
| where TimeGenerated > ago(1h)
| where UserAgent contains "azurehound" or UserAgent contains "sharphound" or UserAgent contains "bloodhound"
| project TimeGenerated, UserId, UserPrincipalName, IPAddress, RequestUri, UserAgent, ResponseStatusCode
| extend AlertSeverity = "High", TechniqueID = "T1087.004"
```

**What This Detects:**
- Direct user-agent string matching (tool signature)
- Easiest detection (but attackers can spoof/randomize user-agent)

---

## 9. WINDOWS EVENT LOG MONITORING

**Note:** AzureHound executes externally; local Windows Event Logs do NOT capture activity. Monitor on:

1. **Entra ID Sign-in Logs** (Azure Portal)
   - Filter for non-interactive sign-ins
   - Search for UserAgent "azurehound"
   - Look for MFA bypass patterns

2. **Entra ID Audit Logs** (Azure Portal)
   - Changes to roles (adds to admin groups)
   - Service principal modifications
   - Application registrations

3. **Azure Activity Logs** (Control Plane events)
   - Resource creation/deletion
   - Policy changes
   - Does NOT capture read operations (logging gap)

---

## 10. SYSMON DETECTION PATTERNS

**Sysmon can detect local AzureHound execution:**

```xml
<Sysmon schemaversion="4.30">
  <EventFiltering>
    <!-- Detect AzureHound process execution -->
    <ProcessCreate onmatch="include">
      <CommandLine condition="contains">azurehound</CommandLine>
      <CommandLine condition="contains">list users</CommandLine>
      <CommandLine condition="contains">list groups</CommandLine>
      <CommandLine condition="contains">list roles</CommandLine>
    </ProcessCreate>
    
    <!-- Detect network connections to Microsoft Graph API -->
    <NetworkConnect onmatch="include">
      <DestinationHostname condition="contains">graph.microsoft.com</DestinationHostname>
      <DestinationHostname condition="contains">management.azure.com</DestinationHostname>
      <DestinationHostname condition="contains">login.microsoftonline.com</DestinationHostname>
      <DestinationPort>443</DestinationPort>
    </NetworkConnect>
    
    <!-- Detect BloodHound execution (Java + Neo4j) -->
    <ProcessCreate onmatch="include">
      <CommandLine condition="contains">bloodhound</CommandLine>
      <CommandLine condition="contains">neo4j</CommandLine>
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

**Alert Name:** "Reconnaissance activities detected via AzureHound enumeration"
- **Severity:** High
- **Description:** Bulk API queries to Microsoft Graph for user/group/role enumeration
- **Applies To:** All Entra ID environments with MDI enabled

**Configuration:**
1. **Azure Portal** → **Microsoft Defender for Cloud**
2. **Environment settings** → Select domain
3. Ensure **Defender for Identity** status = ON
4. Go to **Alerts** → Search for "enumeration" or "reconnaissance"

---

## 12. MICROSOFT PURVIEW (UNIFIED AUDIT LOG)

**Query:** Monitor for role assignments and app consent changes (follow-on activities after AzureHound reconnaissance).

```powershell
Search-UnifiedAuditLog -Operations "Add Member to Group", "Add Role" `
  -StartDate (Get-Date).AddDays(-1) `
  -EndDate (Get-Date) | Where-Object {
    $_.AuditData -match "Global Administrator" -or 
    $_.AuditData -match "Privileged Role Administrator"
  }
```

---

## 13. FALSE POSITIVE ANALYSIS

### Legitimate Activity Mimicking AzureHound

| Activity | Appears As | Legitimate Reason | Distinguish By |
|----------|-----------|------------------|-----------------|
| Compliance auditing tools | User/group enumeration | Security audit, SOC2 compliance | Scheduled jobs, expected service accounts |
| Azure AD reporting | Role enumeration | Access reviews, license reporting | Low frequency, known tools (PowerShell modules) |
| Identity governance solutions | Permission mapping | Delinea, Okta, access control sync | Expected tool binaries, service account context |
| Helpdesk automation | User lookups | Ticket system integration | Limited scope queries, specific user filters |
| EDR/MDR tools | Bulk enumeration | Threat detection, baseline building | Whitelisted agents, internal IP ranges |

**Tuning:**
```kusto
// Exclude known legitimate sources
let WhitelistedAccounts = dynamic(["svc_audit@contoso.com", "svc_identity@contoso.com"]);
let WhitelistedIPs = dynamic(["10.0.0.0/8"]);

MicrosoftGraphActivityLogs
| where !UserId in (WhitelistedAccounts)
| where !IPAddress startswith "10.0.0"
| where CallCount > 50
// ... rest of detection logic
```

---

## 14. DEFENSIVE MITIGATIONS

### Priority 1: CRITICAL

* **Enable Microsoft Graph Activity Logging**
  - **Applies To:** All Entra ID tenants
  
  **Manual Steps (Azure Portal):**
  1. **Azure Portal** → **Microsoft Entra ID** → **Monitoring & health** → **Audit logs**
  2. Click **Export Settings**
  3. Select **Log Analytics Workspace** (if not exists, create one)
  4. Enable **Microsoft Graph Activity Logs** export
  5. Wait 24 hours for data collection to begin
  
  **Manual Steps (PowerShell):**
  ```powershell
  # Enable Graph activity log export to Log Analytics
  $WorkspaceResourceId = "/subscriptions/{sub}/resourcegroups/{rg}/providers/microsoft.operationalinsights/workspaces/{workspace}"
  
  Set-AzDiagnosticSetting -ResourceId $WorkspaceResourceId `
    -Name "GraphActivityLogging" `
    -Enabled $true `
    -WorkspaceId $WorkspaceResourceId
  ```
  
  **Impact:** Enables detection of AzureHound Graph API queries (largest portion of enumeration).

* **Implement Conditional Access Policy: Block Legacy Authentication & Restrict APIs**
  - **Applies To:** All users
  
  **Manual Steps:**
  1. **Azure Portal** → **Entra ID** → **Security** → **Conditional Access**
  2. Click **+ New policy**
  3. Name: `Block Suspicious API Access`
  4. **Assignments:**
     - Users: **All users**
     - Cloud apps: **Microsoft Graph**, **Azure Management API**
  5. **Conditions:**
     - Client apps: **Mobile and desktop clients**, **Legacy authentication clients**
  6. **Access controls:**
     - Grant: **Require multi-factor authentication** (or **Block access**)
  7. Enable: **On**
  8. Click **Create**
  
  **Impact:** Blocks AzureHound unless attacker has valid MFA credentials or refresh token.

* **Enable Phishing-Resistant MFA (FIDO2 Security Keys)**
  - Prevents credential compromise that enables AzureHound
  
  **Manual Steps:**
  1. **Entra ID** → **Security** → **MFA** → **FIDO2 Security Keys**
  2. Set **Allow FIDO2 Security Keys** = **Yes**
  3. Distribute security keys to high-privilege users
  4. Mandate FIDO2 for admins via Conditional Access

### Priority 2: HIGH

* **Disable User App Registrations**
  - Prevents attacker creation of high-privilege service principals
  
  **Manual Steps:**
  1. **Entra ID** → **Manage** → **App registrations** → **Settings**
  2. **Restrict user ability to register applications** = **Yes**
  3. Require **Admin consent** for app registrations
  
  **Impact:** Limits persistence opportunities via malicious apps.

* **Implement Privileged Identity Management (PIM)**
  - Manages just-in-time admin access
  
  **Manual Steps:**
  1. **Azure Portal** → **Microsoft Entra ID Governance**
  2. **Privileged Identity Management** → **Settings**
  3. Configure **Require approval** for admin role activations
  4. Set **Approval workflow** = admin group
  
  **Impact:** Detects and logs all admin role usage; prevents standing admin accounts.

* **Enable Token Protection (Device Binding)**
  - Prevents stolen token usage from different device
  
  **Manual Steps:**
  1. **Entra ID** → **Security** → **Authentication methods**
  2. Under **Token Protection**, set to **Enforced**
  3. Configure device binding policy
  
  **Impact:** Invalidates tokens used from attacker machines.

* **Monitor for Impossible Travel & Anomalous Sign-ins**
  - Detects compromised credentials used from unusual locations
  
  **Sentinel Query:**
  ```kusto
  SigninLogs
  | where TimeGenerated > ago(1h)
  | where ResultType == 0  // Successful
  | where AuthenticationRequirement == "multiFactorAuthentication"
  | where ResourceDisplayName in ("Microsoft Graph", "Azure Management API")
  | summarize by UserPrincipalName, Location, IPAddress, TimeGenerated
  | where IPAddress !in ("<trusted_corp_ips>")
  ```

---

## 15. DETECTION & INCIDENT RESPONSE

### Forensic Artifact Collection

**If AzureHound reconnaissance is suspected:**

1. **Collect Microsoft Graph Activity Logs**
   ```powershell
   # Query Sentinel/Log Analytics
   MicrosoftGraphActivityLogs
   | where TimeGenerated > ago(7d)
   | where UserAgent contains "azurehound" or 
           RequestUri contains "/users" and CallCount > 100
   | export to CSV
   ```

2. **Collect Entra ID Sign-in Logs**
   ```powershell
   # Non-interactive sign-ins (token-based)
   Get-MgAuditLogSignIn -Filter "authenticationDetails/any(x:x/succeeded eq true)" `
     -Properties userPrincipalName,ipAddress,clientAppUsed,authenticationDetails | Export-Csv
   ```

3. **Identify Source Account**
   ```powershell
   # Who accessed Graph API for enumeration?
   $SourceUser = (MicrosoftGraphActivityLogs 
     | where RequestUri contains "/users" 
     | where CallCount > 100).UserId
   ```

### Incident Response Steps

1. **Verify Reconnaissance Occurred**
   - Confirm AzureHound API calls in Graph activity logs
   - Identify source user/service principal
   - Determine scope of enumeration (which endpoints queried)

2. **Identify Attack Scope**
   - Which data was enumerated (users, groups, roles, storage, etc.)
   - Which privilege escalation paths exist
   - Estimate attacker's knowledge of tenant structure

3. **Investigate Follow-On Attacks**
   - Check for role assignments to new/compromised users (post-AzureHound)
   - Monitor for service principal creation with high permissions
   - Review storage account access logs (may indicate data exfiltration)
   - Check for new app registrations or consents

4. **Containment**
   - Force password reset for compromised user account
   - Revoke refresh tokens: 
     ```powershell
     Revoke-AzureADUserAllRefreshToken -ObjectId "<UserObjectId>"
     ```
   - Revoke service principal credentials if compromised
   - Enable MFA enforcement via Conditional Access

5. **Eradication**
   - Delete any unauthorized service principals created post-compromise
   - Remove unauthorized role assignments
   - Disable or delete compromised user accounts
   - Apply conditional access blocks to attacker IP

---

## 16. RELATED ATTACK CHAINS

### T1087.004 Relationship to Other MITRE Cloud Techniques

| Preceding | Current | Following |
|-----------|---------|-----------|
| T1078 (Valid Accounts) | **T1087.004 (Account Discovery: Cloud)** | T1087.002 (on-prem account discovery) |
| T1586 (Compromise Accounts) | ← | T1069.003 (Permission Groups: Cloud) |
| T1111 (Multi-Factor Auth Interception) | ← | T1098.003 (Account Manipulation: Cloud) |
|  | | T1110 (Brute Force - informed targeting) |
|  | | T1526 (Cloud Service Discovery) |
|  | | T1580 (Cloud Infrastructure Discovery) |

### Real-World Kill Chain

```
Phase 1: Credential Compromise
├─ Phishing email with malicious link/attachment
├─ Employee clicks → browser session token stolen (infostealer)
└─ Token stored in browser cache (accessible to attacker)

Phase 2: Cloud Reconnaissance (T1087.004 - AzureHound)
├─ Attacker extracts refresh token from infostealer output
├─ Runs: azurehound list users --tenant contoso.com
├─ Discovers: 500+ users, 100+ admin role members
├─ Maps privilege escalation: User → Group → Global Admin
└─ Identifies: Automation account with runbook execution

Phase 3: Privilege Escalation
├─ BloodHound visualization shows: 
│   User has permissions to modify Service Principal
│   Service Principal has RoleManagement.ReadWrite.Directory
├─ Escalation path: Compromise user → Change SP secret → Assign admin role
└─ Result: Global Administrator access obtained

Phase 4: Persistence & Exfiltration
├─ Create new global admin account (backdoor)
├─ Disable MFA temporarily
├─ Dump NTDS.dit equivalent (Graph Export)
├─ Access Key Vault secrets
└─ Export sensitive data from Storage accounts

Phase 5: Lateral Movement
├─ Use admin access to connect to on-premises AD (if hybrid)
├─ Execute commands via Automation account runbooks
├─ Pivot to business applications (Dynamics, Exchange, Teams)
└─ Establish long-term persistence across hybrid environment
```

---

## 17. REAL-WORLD EXAMPLES

### Example 1: Curious Serpens (Peach Sandstorm) – 2025 Campaign

**Campaign Context:**
- Iranian-backed APT, active since 2013
- Shifted focus to Azure environments in 2024-2025
- Targets: Government agencies, critical infrastructure

**Execution:**
1. Initial compromise via spear-phishing
2. Stole Entra ID credentials from employee browser
3. Ran AzureHound to enumerate: 5,000+ users, 50+ admin accounts, storage accounts with customer data
4. Visualized attack paths in BloodHound → identified nested group escalation to Global Admin
5. Compromised service principal with RoleManagement permissions
6. Escalated to Global Admin, created backdoor account
7. Exfiltrated customer encryption keys from Key Vault

**Detection Opportunities:**
- Large volume of Graph API enumeration queries (users, groups, roles)
- User-agent containing "azurehound"
- Non-interactive sign-in with compromised credential
- Impossible travel (sign-in from Iran IP, then from legitimate employee location)
- Role assignment to new service principal shortly after enumeration

**Response:**
- Revoke refresh tokens for compromised user
- Disable and reset compromised SP secrets
- Remove newly created backdoor accounts
- Audit all role assignments from past 7 days
- Enable MFA enforcement via Conditional Access

---

### Example 2: Void Blizzard – May 2025 Campaign

**Campaign Context:**
- Russia-linked nation-state
- Targets: Financial institutions, technology companies
- Focus: Espionage and intellectual property theft

**Execution:**
1. Compromised Entra ID credentials of contractor with "Application Developer" role
2. Contractor's account had permissions to read application registrations
3. Ran AzureHound to enumerate apps, roles, key vaults
4. Identified apps with sensitive API permissions (SharePoint, Teams, Exchange)
5. Registered malicious app with same permissions as legitimate app
6. Used app token to access SharePoint & Teams data
7. Exfiltrated 18 months of confidential emails, architectural docs, strategy docs

**Detection Opportunities:**
- Bulk Graph API queries for applications & permissions (app-role-assignments)
- New app registration with overly broad permissions
- Access to SharePoint/Teams from new service principal
- Unusual data download patterns from SharePoint

**Prevention/Response:**
- Implement admin consent requirement for app registrations
- Monitor for new apps requesting sensitive permissions
- Enforce principle of least privilege (app should only access needed resources)
- Enable audit logging for app consent grants
- Use Conditional Access to restrict app access from non-corporate IPs

---

## 18. COMPLIANCE & STANDARDS MAPPING

| Standard | Requirement | Mapping |
|----------|-------------|---------|
| **CIS Controls v8** | CIS 6.1 (Account Management), CIS 3.2 (Logging) | Restrict cloud enumeration access; enable API logging |
| **DISA STIG** | Cloud security hardening | Implement MFA, CAP, disable legacy auth |
| **NIST 800-53** | AC-2 (Account Management), SI-4 (Monitoring), AU-12 (Audit Log Generation) | Log cloud API activity; monitor for anomalies; implement strong identity controls |
| **GDPR** | Article 32 (Security Measures), Article 33 (Breach Notification) | Detect unauthorized access to identity data; implement incident response |
| **DORA** | Digital Operational Resilience | Monitor cloud identity service security; maintain incident response capability |
| **NIS2** | Detection Capabilities | Establish baseline for normal API traffic; alert on deviations |
| **ISO 27001:2022** | 5.2 (Information Security Policies), 8.2 (Access Control), 8.15 (Logging) | Implement access controls for cloud identity; enable comprehensive audit trails |

---

## 19. APPENDIX: ATOMIC RED TEAM INTEGRATION

### Atomic Test Reference
- **MITRE Atomic ID:** T1087_004_AzureHound_Cloud_Enumeration
- **Status:** Community test (not official MITRE)
- **Repository:** https://github.com/atomic-red-team/atomic-red-team

### Example Atomic Test
```yaml
- name: Enumerate Entra ID Users with AzureHound
  description: Use AzureHound to list all Entra ID users
  supported_platforms:
    - windows
    - macos
    - linux
  input_arguments:
    refresh_token:
      description: Entra ID refresh token
      type: string
      default: "0.ARwA6Wg123..."
    tenant:
      description: Entra ID tenant name
      type: string
      default: "contoso.onmicrosoft.com"
  executor:
    name: bash
    elevation_required: false
    command: |
      ./azurehound -r "#{refresh_token}" list users --tenant "#{tenant}" -o users.json
      echo "Enumerated $(jq length users.json) users"
```

---

## 20. REFERENCES & ATTRIBUTION

1. **MITRE ATT&CK Cloud Matrix:**
   - T1087.004 – Account Discovery: Cloud Account: https://attack.mitre.org/techniques/T1087/004/
   - T1069.003 – Permission Groups Discovery: Cloud Groups: https://attack.mitre.org/techniques/T1069/003/
   - T1526 – Cloud Service Discovery: https://attack.mitre.org/techniques/T1526/
   - T1580 – Cloud Infrastructure Discovery: https://attack.mitre.org/techniques/T1580/
   - T1619 – Cloud Storage Object Discovery: https://attack.mitre.org/techniques/T1619/

2. **BloodHound & AzureHound:**
   - SpecterOps BloodHound: https://github.com/SpecterOps/BloodHound
   - AzureHound Community Edition: https://github.com/SpecterOps/AzureHound
   - BloodHound Docs: https://bloodhound.readthedocs.io/

3. **Threat Intelligence & Detection:**
   - Palo Alto Unit 42: Cloud Discovery With AzureHound (November 2025)
   - Microsoft Threat Intelligence: Curious Serpens, Void Blizzard, Storm-0501 reports
   - CloudBrothers: Detect threats using GraphAPIAuditEvents (August 2025)

4. **Microsoft Documentation:**
   - Microsoft Graph Activity Logs: https://learn.microsoft.com/en-us/graph/microsoft-graph-activity-logs-overview
   - Entra ID Authentication: https://learn.microsoft.com/en-us/entra/identity/authentication/
   - Azure RBAC: https://learn.microsoft.com/en-us/azure/role-based-access-control/

---