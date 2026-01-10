# [COLLECT-SENTINEL-001]: Sentinel Alert Data Collection

## 1. METADATA HEADER

| Attribute | Details |
|---|---|
| **Technique ID** | COLLECT-SENTINEL-001 |
| **MITRE ATT&CK v18.1** | [T1123 - Audio Capture](https://attack.mitre.org/techniques/T1123/) |
| **Tactic** | Collection |
| **Platforms** | Entra ID, Microsoft Sentinel, Azure Monitor |
| **Severity** | High |
| **CVE** | N/A |
| **Technique Status** | ACTIVE |
| **Last Verified** | 2026-01-10 |
| **Affected Versions** | Sentinel workspace any version, Azure Monitor Log Analytics |
| **Patched In** | N/A (Operational Feature) |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

## 2. EXECUTIVE SUMMARY

**Concept:** Microsoft Sentinel is a cloud-native SIEM platform that ingests security alerts, logs, and analytics from Microsoft 365, Azure, Entra ID, and third-party integrations. Sentinel stores triggered alerts in the SecurityAlert table and raw security events in tables like AuditLogs, SigninLogs, DeviceLogonEvents, and others. Red teams with access to Sentinel can extract weeks of alert history, detection logic, and alert evidence to understand which attack techniques triggered detections and which remained unnoticed. Blue teams use this data for incident investigation, threat hunting, and detection effectiveness validation. An attacker gaining access to Sentinel can determine exactly which tactics are detected and refine their operations accordingly, making Sentinel access a high-value target.

**Attack Surface:** Sentinel workspace portal (portal.azure.com), KQL query editor, alert tables (SecurityAlert, AlertInfo, AlertEvidence), Log Analytics workspace API, data connector configurations.

**Business Impact:** **Complete visibility into security alert configuration, detection evasion guidance, incident investigation data exposure, and loss of threat intelligence.** An attacker with Sentinel access can: (1) Read all triggered alerts to identify detected techniques, (2) Query raw logs to understand data collection capabilities, (3) Modify alert rules to disable detections, (4) Extract evidence data from past incidents revealing adversary tradecraft, (5) Identify gaps in logging and monitoring by analyzing missing data.

**Technical Context:** Sentinel retains alert data in SecurityAlert table with 30-day default retention (configurable up to 12 years). AlertInfo and AlertEvidence tables contain event details and supporting evidence. KQL queries execute with millisecond-to-second response times. No special licensing or tools required beyond valid Entra ID credentials with Sentinel Reader or higher role. All query execution is logged to LAQueryLogs and SentinelAudit tables.

### Operational Risk
- **Execution Risk:** Medium – Requires valid Azure AD credentials and Sentinel Reader role; no special tools needed.
- **Stealth:** Low – All KQL queries are logged in SentinelAudit table and LAQueryLogs with full query text.
- **Reversibility:** No – Exfiltrated alert history and evidence data cannot be recovered; it reflects actual incidents.

### Compliance Mappings

| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmark** | 18.2 | Audit logging for SIEM access and query execution must be monitored |
| **DISA STIG** | IA-2 (SV-89853r1) | Authentication for privileged accounts accessing security monitoring systems |
| **CISA SCuBA** | ID.AM-1 | Asset Management – Sentinel workspace inventory and access controls |
| **NIST 800-53** | SI-4(3) | System Monitoring – Analyze monitoring data for security alerts |
| **GDPR** | Art. 32 | Security of Processing – Confidentiality and integrity of security systems |
| **DORA** | Art. 23 | ICT-related incident handling and notification procedures |
| **NIS2** | Art. 21 | Cybersecurity Risk Management Measures – Continuous monitoring |
| **ISO 27001** | A.12.4.1 | Recording user activities and system events in SIEM |
| **ISO 27005** | 8.3 | Risk Assessment – Unauthorized SIEM access scenarios |

---

## 3. TECHNICAL PREREQUISITES

- **Required Privileges:** Sentinel Reader, Security Reader, or higher role in Entra ID.
- **Required Access:** Azure subscription with active Sentinel workspace; internet connectivity to Azure portal (portal.azure.com); valid Entra ID credentials.

**Supported Versions:**
- **Azure:** Any subscription type (Free, Pay-As-You-Go, EA, CSP)
- **Sentinel:** Any workspace version (from initial release in 2019 to current 2026)
- **Log Analytics:** Linked Log Analytics workspace (Standard or Premium tier)
- **License:** Sentinel per-GB or Commitment tier license (no minimum; even disabled Sentinel still retains existing data)

**Tools:**
- [Azure Portal - Sentinel Blade](https://portal.azure.com)
- [Log Analytics Workspace Query Editor](https://portal.azure.com)
- [Azure CLI](https://learn.microsoft.com/en-us/cli/azure/install-azure-cli)
- [PowerShell Module: Az.OperationalInsights](https://github.com/Azure/azure-powershell)

---

## 4. ENVIRONMENTAL RECONNAISSANCE

### Management Station / PowerShell Reconnaissance

```powershell
# Check if Sentinel is deployed and active
Connect-AzAccount
$workspaceName = "your-sentinel-workspace"
$resourceGroup = "your-resource-group"

$workspace = Get-AzOperationalInsightsWorkspace -ResourceGroupName $resourceGroup -Name $workspaceName
Write-Host "Workspace ID: $($workspace.ResourceId)"
Write-Host "Retention Days: $($workspace.RetentionInDays)"
```

**What to Look For:**
- Workspace exists and is accessible (confirms Sentinel deployment)
- RetentionInDays shows data retention period (30+ days = data is available)
- ResourceId confirms workspace is in correct subscription

**Version Note:** Command output identical across all Azure regions and Sentinel versions.

**Command (Server 2016-2025 - Terraform / Infrastructure-as-Code Discovery):**
```powershell
# Query Azure Resource Graph for all Sentinel workspaces (requires Reader role)
Search-AzGraph -Query "
  resources
  | where type == 'microsoft.operationalinsights/workspaces'
  | where resourceGroup =~ 'your-rg'
  | project name, resourceGroup, location, properties.retentionInDays
"
```

---

## 5. DETAILED EXECUTION METHODS AND THEIR STEPS

### METHOD 1: Query SecurityAlert Table via Sentinel Portal (Web UI)

**Supported Versions:** All versions (cloud-native, version-agnostic)

#### Step 1: Authenticate to Azure Portal and Navigate to Sentinel

**Objective:** Establish authenticated session to Sentinel workspace analytics interface

**Command:**
1. Navigate to https://portal.azure.com
2. Sign in with Entra ID credentials (email@company.com)
3. Navigate to **Microsoft Sentinel** (search in top menu)
4. Select Sentinel workspace
5. Click **Logs** (left sidebar) or **Analytics** for built-in rules

**Expected Output:**
- Log Analytics query editor loads with KQL syntax highlighting
- Tables list shows SecurityAlert, AlertInfo, AlertEvidence, AuditLogs, etc.
- Query results appear in tabular format with full alert details

**What This Means:**
- Direct access to all security alerts, their timestamps, severity, and evidence
- Can query alerts by name, status, severity, timestamp, or custom fields
- AlertInfo table contains full context of what the alert detected and why

**OpSec & Evasion:**
- All portal access is logged in AuditLogs table: timestamp, user, IP address, action
- KQL query text is logged to SentinelAudit table (action = "KQLQueryRun")
- Portal interface does not generate security alerts, but query execution is auditable
- **Evasion:** No method to avoid audit logging; all SIEM access is logged

**Troubleshooting:**
- **Error:** "Access Denied - Insufficient permissions"
  - **Cause:** User role lacks Sentinel Reader permission
  - **Fix:** Assign role via Azure Portal → Sentinel workspace → Access control (IAM) → Add "Sentinel Reader" role
- **Error:** "Workspace not found"
  - **Cause:** Incorrect subscription or workspace selected
  - **Fix:** Verify subscription in top-left dropdown and workspace name in left sidebar

**References & Proofs:**
- [Microsoft Sentinel Analytics Overview](https://learn.microsoft.com/en-us/azure/sentinel/overview)
- [Log Analytics Query Language (KQL) Reference](https://learn.microsoft.com/en-us/kusto/query/)
- [SecurityAlert Table Schema](https://learn.microsoft.com/en-us/azure/sentinel/api/sentinel-api-tables#securityalert)

#### Step 2: Build KQL Query to Extract Alert Data

**Objective:** Construct Kusto Query Language query to retrieve alert details, timelines, and evidence

**Command (Example 1: All High-Severity Alerts for Last 30 Days):**
```kusto
SecurityAlert
| where TimeGenerated > ago(30d)
| where AlertSeverity == "High" or AlertSeverity == "Critical"
| project TimeGenerated, AlertName, AlertType, Description, Entities, Severity = AlertSeverity, Status = AlertStatus
| order by TimeGenerated desc
```

**Command (Example 2: Alerts Involving Credential Access Techniques):**
```kusto
SecurityAlert
| where TimeGenerated > ago(30d)
| where AlertName has_any ("Credential", "Password", "Token", "Authentication", "LSASS", "Mimikatz", "Kerberos")
| project TimeGenerated, AlertName, AlertType, SourceIP, UserId, Description, AlertDetails = todynamic(Entities)
| order by TimeGenerated desc
```

**Command (Example 3: Alerts Triggered by Specific User or IP):**
```kusto
AlertInfo
| join kind=inner AlertEvidence on AlertId
| where TimeGenerated > ago(7d)
| where SourceIP == "203.0.113.45" or InitiatingUser == "admin@company.com"
| project TimeGenerated, AlertId, AlertName, SourceIP, InitiatingUser, EventType, DetectionStatus
| order by TimeGenerated desc
```

**Expected Output:**
```
TimeGenerated           | AlertName                          | AlertType       | Severity | Status
2026-01-09T14:32:15Z   | Suspected credential dumping       | SecurityAlert   | High     | New
2026-01-09T13:22:08Z   | Suspicious PowerShell activity     | SecurityAlert   | Medium   | Resolved
2026-01-08T22:15:33Z   | Brute force attack detected        | SecurityAlert   | Critical | Closed
```

**What This Means:**
- Each row represents one triggered security alert
- AlertName reveals which detection rule was triggered (e.g., "Brute force attack")
- TimeGenerated shows exact time alert was triggered (useful for attack timeline)
- Entities field contains raw JSON of affected resources (users, devices, IPs, files)
- Description field contains analyst-friendly explanation of what the alert detected

**OpSec & Evasion:**
- Query execution is logged in SentinelAudit table with timestamp, user, query text, and result count
- KQL query text is stored verbatim (cannot hide intent)
- No alert is generated when querying SecurityAlert (unlike Splunk alert generation)
- **Evasion:** No way to execute queries without logging; all query activity is auditable

**Troubleshooting:**
- **Error:** "Timeout - Query exceeded 5 minutes"
  - **Cause:** Query scans too much data (30 days × billions of events)
  - **Fix:** Narrow time range: `where TimeGenerated > ago(1d)` instead of ago(30d)
- **Error:** "SecurityAlert table is empty"
  - **Cause:** No alerts triggered in specified time range or Sentinel has no data connectors
  - **Fix:** Verify data connectors are enabled: Sentinel workspace → Data connectors → Check Connected status

**References & Proofs:**
- [KQL Quick Reference Guide](https://learn.microsoft.com/en-us/kusto/query/kql-quick-reference)
- [Sentinel Tables Schema Reference](https://learn.microsoft.com/en-us/azure/sentinel/api/sentinel-api-tables)
- [AlertInfo and AlertEvidence Tables Documentation](https://learn.microsoft.com/en-us/azure/sentinel/investigate-cases)

#### Step 3: Export Alert Results to CSV for Analysis

**Objective:** Download query results in CSV format for offline analysis or exfiltration

**Command:**
1. Execute KQL query in Log Analytics editor
2. Click **Export** button (top-right of results pane)
3. Select **Export to CSV** or **Download as CSV**
4. File downloads as `query_yyyy-mm-dd_hhmm.csv` to local Downloads folder

**Expected Output:**
```csv
TimeGenerated,AlertName,AlertType,Description,Severity,Status,Entities,SourceIP
2026-01-09T14:32:15Z,Suspected credential dumping,SecurityAlert,"Mimikatz-like process behavior detected",High,New,"[{""Type"":""Account"",""Name"":""CORP\admin""},{""Type"":""Host"",""Name"":""DESKTOP-ABC123""}]","203.0.113.45"
2026-01-09T13:22:08Z,Suspicious PowerShell activity,SecurityAlert,"Obfuscated PowerShell script executed",Medium,Resolved,"[{""Type"":""Process"",""Name"":""powershell.exe""},{""Type"":""Account"",""Name"":""CORP\user1""}]",NULL
```

**What This Means:**
- CSV format allows import into spreadsheets, databases, or threat research tools
- Entities field is JSON-encoded (contains nested objects) - must be parsed separately
- Each row is one alert with full context needed for incident investigation
- SourcIP, AlertName, and Description fields reveal attack techniques and threat infrastructure
- Status field (New/Resolved/Closed) indicates whether alert was investigated

**OpSec & Evasion:**
- Export action logs to SentinelAudit table (action = "ExportQueryResults")
- Downloaded file sits on attacker's local machine indefinitely (no automatic cleanup)
- CSV file contains zero indicators that it was exported (identical to web view)
- **Evasion:** Export does not generate alerts; only logged in audit tables

**Troubleshooting:**
- **Error:** "Export failed - file too large"
  - **Cause:** Result set > 100k rows exceeds export limit
  - **Fix:** Use `top 50000` in query or filter by date range further

**References & Proofs:**
- [Export Data from Log Analytics](https://learn.microsoft.com/en-us/azure/data-explorer/kusto/query/set-notation)

### METHOD 2: Query via Azure REST API (Programmatic)

**Supported Versions:** All Sentinel versions (API available globally)

#### Step 1: Register Entra ID Application for API Access

**Objective:** Create service principal with read access to Log Analytics workspace

**Manual Steps (Azure Portal):**
1. Navigate to **Azure Portal** → **Entra ID** → **App registrations** → **+ New registration**
2. **Name:** `Sentinel-Alert-Collection`
3. **Supported Account Types:** Accounts in this organizational directory only
4. Click **Register**
5. Copy **Application (client) ID** and **Directory (tenant) ID**
6. Go to **Certificates & Secrets** → **+ New client secret**
7. Description: `Sentinel API Access`, Expires: 6 months
8. Copy the **Value** (secret)
9. Go to **API permissions** → **+ Add a permission**
10. Select **APIs my organization uses** → Search **"Azure Log Analytics"**
11. Select **Delegated permissions** → Check `Data.Read`
12. Click **Grant admin consent**

**Expected Output:**
- Application ID: `xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx`
- Tenant ID: `xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx`
- Client Secret: `~B...........................` (64+ characters)
- Permissions show "✓ Granted" with green checkmark

**OpSec & Evasion:**
- App registration is logged in Entra ID audit logs (action = "Add application")
- Client secret creation is audited with timestamp and creator
- Secret expires in 6 months; old secrets cannot be used
- **Evasion:** No way to hide app registration; all is logged in Entra ID

**References & Proofs:**
- [Register App with Entra ID](https://learn.microsoft.com/en-us/entra/identity-platform/quickstart-register-app)
- [Azure Log Analytics API Documentation](https://learn.microsoft.com/en-us/rest/api/loganalytics/query-packs/list)

#### Step 2: Obtain Bearer Token via OAuth 2.0

**Objective:** Authenticate service principal and obtain JWT token for API calls

**Command (PowerShell):**
```powershell
$TenantId = "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
$ClientId = "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
$ClientSecret = "~B............................"

$uri = "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token"
$body = @{
    grant_type    = "client_credentials"
    client_id     = $ClientId
    client_secret = $ClientSecret
    scope         = "https://api.loganalytics.io/.default"
}

$response = Invoke-RestMethod -Method Post -Uri $uri -Body $body -ContentType "application/x-www-form-urlencoded"
$token = $response.access_token
Write-Host "Bearer Token obtained: $($token.Substring(0, 50))..."
```

**Expected Output:**
```json
{
  "token_type": "Bearer",
  "expires_in": 3600,
  "access_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIs..."
}
```

**What This Means:**
- Token is valid for 1 hour (3600 seconds); new token needed for each session
- Token is JWT format containing auth claims
- Bearer token must be included in Authorization header for all subsequent API calls

**OpSec & Evasion:**
- Token request logged in Entra ID sign-in logs (action = "Non-interactive sign-in", status = "Success")
- Service principal name visible in sign-in logs
- Token requests do not trigger alerts by default
- **Evasion:** No way to hide OAuth token requests; all are timestamped

**References & Proofs:**
- [OAuth 2.0 Client Credentials Flow](https://learn.microsoft.com/en-us/entra/identity-platform/v2-oauth2-client-creds-grant-flow)

#### Step 3: Query Sentinel Alerts via Log Analytics REST API

**Objective:** Call Log Analytics Query API with bearer token to fetch alerts

**Command (PowerShell):**
```powershell
$token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIs..."
$subscriptionId = "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
$resourceGroup = "your-resource-group"
$workspaceName = "your-sentinel-workspace"

$headers = @{
    "Authorization" = "Bearer $token"
    "Content-Type"  = "application/json"
}

# Get workspace ID
$workspaceUri = "https://management.azure.com/subscriptions/$subscriptionId/resourcegroups/$resourceGroup/providers/microsoft.operationalinsights/workspaces/$workspaceName/api/query?api-version=2020-08-01"

# KQL query to execute
$queryBody = @{
    "query" = "SecurityAlert | where TimeGenerated > ago(30d) | where AlertSeverity =~ 'High' or AlertSeverity =~ 'Critical' | top 1000 by TimeGenerated desc"
} | ConvertTo-Json

$response = Invoke-RestMethod -Method Post -Uri $workspaceUri -Headers $headers -Body $queryBody

# Export to CSV
$response.tables[0].rows | ForEach-Object {
    [PSCustomObject]@{
        TimeGenerated = $_[0]
        AlertName = $_[1]
        AlertType = $_[2]
        Severity = $_[3]
    }
} | Export-Csv -Path "C:\temp\sentinel_alerts.csv" -NoTypeInformation

Write-Host "Alerts exported to C:\temp\sentinel_alerts.csv"
```

**Command (Python):**
```python
#!/usr/bin/env python3
import requests
import json
import csv

token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIs..."
subscription_id = "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
resource_group = "your-resource-group"
workspace_name = "your-sentinel-workspace"

headers = {
    "Authorization": f"Bearer {token}",
    "Content-Type": "application/json"
}

workspace_uri = f"https://management.azure.com/subscriptions/{subscription_id}/resourcegroups/{resource_group}/providers/microsoft.operationalinsights/workspaces/{workspace_name}/api/query?api-version=2020-08-01"

query = """
SecurityAlert
| where TimeGenerated > ago(30d)
| where AlertSeverity =~ 'High' or AlertSeverity =~ 'Critical'
| top 1000 by TimeGenerated desc
| project TimeGenerated, AlertName, AlertType, AlertSeverity, Entities
"""

payload = {"query": query}
response = requests.post(workspace_uri, headers=headers, json=payload)

if response.status_code == 200:
    data = response.json()
    results = data.get("tables", [{}])[0].get("rows", [])
    
    # Save to CSV
    with open("/tmp/sentinel_alerts.csv", "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["TimeGenerated", "AlertName", "AlertType", "Severity", "Entities"])
        writer.writerows(results)
    
    print(f"Alerts exported to /tmp/sentinel_alerts.csv - {len(results)} rows")
else:
    print(f"Error: {response.status_code} - {response.text}")
```

**Expected Output:**
```json
{
  "tables": [
    {
      "name": "PrimaryResult",
      "columns": [
        {"name": "TimeGenerated", "type": "datetime"},
        {"name": "AlertName", "type": "string"},
        {"name": "AlertType", "type": "string"},
        {"name": "AlertSeverity", "type": "string"}
      ],
      "rows": [
        ["2026-01-09T14:32:15Z", "Suspected credential dumping", "SecurityAlert", "High"],
        ["2026-01-09T13:22:08Z", "Suspicious PowerShell activity", "SecurityAlert", "Medium"]
      ]
    }
  ]
}
```

**What This Means:**
- API returns exact same alert data as portal, but in JSON format
- Results are paginated and limited to 1000 rows per request (use offset for more)
- Columns array defines field types and names for parsing
- Rows array contains actual alert data matching query conditions

**OpSec & Evasion:**
- API query execution is logged in LAQueryLogs table (table = "SecurityAlert", action = "Query")
- Full KQL query text is stored in logs
- **Evasion:** No way to hide API queries; all execution is auditable

**Troubleshooting:**
- **Error:** "401 Unauthorized"
  - **Cause:** Token expired or invalid
  - **Fix:** Regenerate fresh token via Step 2
- **Error:** "403 Forbidden"
  - **Cause:** Service principal lacks permissions on workspace
  - **Fix:** Verify role assignment on workspace (Access Control → Sentinel Reader or higher)

**References & Proofs:**
- [Log Analytics Query API Documentation](https://learn.microsoft.com/en-us/rest/api/loganalytics/query)
- [Azure REST API Reference](https://learn.microsoft.com/en-us/rest/api/azure/)

---

## 6. TOOLS & COMMANDS REFERENCE

#### [Azure Log Analytics REST API](https://learn.microsoft.com/en-us/rest/api/loganalytics/)

**Version:** v1 (stable, production-ready)
**Minimum Version:** API GA since 2020
**Supported Platforms:** Windows, Linux, macOS (any HTTP client)

**Installation:**
```bash
# No installation required; uses standard HTTP/REST

# Optional: Install Azure CLI for easier authentication
curl -sL https://aka.ms/InstallAzureCLIDeb | sudo bash

# Optional: Install Azure PowerShell
Install-Module Az.OperationalInsights -Force
```

**Usage:**
```powershell
# Use service principal with bearer token (see METHOD 2)
$headers = @{ "Authorization" = "Bearer $token" }
Invoke-RestMethod -Method Post -Uri $apiUrl -Headers $headers -Body $queryBody
```

#### [KQL Query Language Documentation](https://learn.microsoft.com/en-us/kusto/query/)

**Version:** Latest (continuously updated)
**Platforms:** All Cloud (Azure, AWS, GCP support KQL via Kusto)

**Common Operators:**
- `where` – Filter rows by condition
- `project` – Select columns to display
- `summarize` – Aggregate data (count, sum, avg, max, min)
- `join` – Correlate data from multiple tables
- `order by` – Sort results ascending/descending
- `top` – Limit number of rows returned

**Example Query - Extract All Alerts and Entities:**
```kusto
SecurityAlert
| where TimeGenerated > ago(30d)
| project TimeGenerated, AlertName, Entities = todynamic(Entities)
| mvexpand Entities
| project TimeGenerated, AlertName, EntityType = Entities.Type, EntityName = Entities.Name
| top 50000 by TimeGenerated desc
```

---

## 9. MICROSOFT SENTINEL DETECTION

#### Query 1: Bulk Export of Alert Data

**Rule Configuration:**
- **Required Table:** SentinelAudit, LAQueryLogs
- **Required Fields:** ActionType, ResultCount, UserId, QueryText
- **Alert Severity:** High
- **Frequency:** Every 10 minutes
- **Applies To Versions:** All Sentinel versions

**KQL Query:**
```kusto
LAQueryLogs
| where QueryText has_any ("SecurityAlert", "AlertInfo", "AlertEvidence")
| where ResultCount > 5000  // Bulk export indicates suspicious activity
| where UserId !in ("AutomatedHunting", "SOC_Reports_Automation")
| summarize ExportCount = count(), TotalRows = sum(ResultCount) by UserId, tostring(QueryText)
| where ExportCount > 2 // Multiple high-volume exports in short timeframe
| project UserId, ExportCount, TotalRows, QueryText
```

**What This Detects:**
- Non-automated users exporting large quantities of alert data (5000+ rows per query)
- Multiple exports by same user in short timeframe (potential data theft)
- Query text revealing intent (searching for specific alert types or time ranges)

**Manual Configuration Steps (Azure Portal):**
1. Navigate to **Microsoft Sentinel** → **Analytics** → **Create** → **Scheduled query rule**
2. **General:**
   - Name: `Sentinel_Bulk_Alert_Export`
   - Severity: `High`
3. **Set rule logic:**
   - Paste KQL query
   - Run every: `10 minutes`
   - Lookup data: `1 hour`
4. **Incident settings:**
   - Enable "Create incidents"
   - Group by: `UserId`
5. **Create rule**

---

## 10. WINDOWS EVENT LOG MONITORING

**Event ID: 4688 (Process Creation)**
- **Log Source:** Security
- **Trigger:** PowerShell/cmd containing keywords: "Invoke-RestMethod", "api.loganalytics", "SecurityAlert", "ExportCsv"
- **Filter:** CommandLine contains "loganalytics" OR CommandLine contains "SecurityAlert"
- **Applies To Versions:** Server 2016+

**Manual Configuration (Group Policy):**
1. Open **Group Policy Management Console** (gpmc.msc)
2. Navigate to **Computer Configuration** → **Policies** → **Windows Settings** → **Security Settings** → **Advanced Audit Policy Configuration**
3. Enable **Audit Process Creation** (Success and Failure)
4. Open **Local Security Policy** (secpol.msc) → **Advanced Audit Policy**
5. Enable **Audit Command Line Process Creation** (records full command-line arguments)
6. Run `gpupdate /force` and restart

---

## 13. DEFENSIVE MITIGATIONS

### Priority 1: CRITICAL

*   **Restrict Sentinel Query Access:** Limit KQL query editor access to approved SOC members only. Disable query access for analysts without need-to-know.

    **Manual Steps:**
    1. Navigate to **Azure Portal** → **Microsoft Sentinel** → **Access control (IAM)**
    2. Remove **Sentinel Reader** and **Sentinel Responder** roles from non-SOC users
    3. Assign **Sentinel Contributor** (full access) ONLY to SOC leads
    4. Verify no **Global Admin** accounts have direct Sentinel role (use PIM for temporary elevation)

    **PowerShell:**
    ```powershell
    # Remove user from Sentinel Reader
    $user = Get-AzADUser -ObjectId "user@company.com"
    Remove-AzRoleAssignment -ObjectId $user.Id -RoleDefinitionName "Sentinel Reader" `
      -ResourceGroupName "your-rg" -ResourceName "your-workspace" -ResourceType "Microsoft.OperationalInsights/workspaces"
    ```

*   **Enable Audit Logging for Query Execution:** Ensure LAQueryLogs and SentinelAudit tables capture all KQL queries with full text and result counts.

    **Manual Steps:**
    1. Navigate to **Microsoft Sentinel** → **Settings** → **Workspace settings**
    2. Go to **Azure Monitor Logs** → **Diagnostic settings**
    3. Click **+ Add diagnostic setting**
    4. Name: `Sentinel-Query-Audit-Logs`
    5. Select logs: Enable **Audit** and **Analytics Query**
    6. Destination: Send to **Log Analytics workspace** (same workspace)
    7. Click **Save**

*   **Configure Conditional Access for Sentinel Portal:** Require MFA and compliant device for Sentinel access.

    **Manual Steps:**
    1. Go to **Azure Portal** → **Entra ID** → **Security** → **Conditional Access**
    2. Click **+ New policy**
    3. Name: `Sentinel_Portal_MFA_Requirement`
    4. **Assignments:** Users/Groups = SOC group only
    5. **Cloud apps:** Select **"Microsoft Azure Management"** (includes Sentinel)
    6. **Access controls:** Grant = **Require multifactor authentication**
    7. Enable policy: **On**

### Priority 2: HIGH

*   **Implement Data Retention Limits:** Set alert data retention to minimum required (default 30 days, can reduce to 7 days for sensitive environments).

    **Manual Steps:**
    1. Navigate to **Microsoft Sentinel** → **Workspace settings** → **Data retention**
    2. Set **SecurityAlert table retention:** 7 days (minimum)
    3. Set **Total retention (with archive):** 30 days
    4. Click **Save**

*   **Monitor Query Execution via Alerts:** Create automated alerts for any query accessing SecurityAlert table with High severity filters.

    **This is covered in detection section above**

### Access Control & Policy Hardening

*   **RBAC:** Implement role segmentation:
    - **Sentinel Contributor:** 2-3 SOC leads (can modify rules, run queries)
    - **Sentinel Responder:** 5-10 incident handlers (can modify incidents, run queries)
    - **Sentinel Reader:** 20-30 analysts (read-only queries, no incident modification)

*   **Conditional Access:** Enforce MFA + Device Compliance + IP restrictions for all Sentinel access

*   **Audit Logging:** Ensure 7-year minimum retention on LAQueryLogs and SentinelAudit tables

### Validation Command

```powershell
# Verify only SOC group has Sentinel access
Get-AzRoleAssignment -RoleDefinitionName "Sentinel Reader" | Where-Object {$_.Scope -like "*sentinel*"} | Select-Object DisplayName, RoleDefinitionName, Scope
```

**Expected Output (If Secure):**
- Only users in "SOC_Team" group appear in results
- No external users or service accounts listed
- All have "Sentinel Reader" role minimum (or higher)

---

## 14. DETECTION & INCIDENT RESPONSE

### Indicators of Compromise (IOCs)

*   **Files:** 
    - `C:\Users\[Username]\Downloads\query_*.csv` (exported alert files)
    - PowerShell scripts containing Log Analytics API endpoints: `https://api.loganalytics.io` or `https://management.azure.com`

*   **Network:** 
    - HTTP POST requests to `api.loganalytics.io/v1/workspaces/*/query` from non-SOC IP ranges
    - Bearer tokens in HTTP Authorization headers (JWT tokens starting with `eyJ0...`)

*   **Cloud:** 
    - LAQueryLogs table entries with QueryText containing "SecurityAlert" and UserId = non-SOC account
    - SentinelAudit entries with ActionType = "ExportQueryResults"

### Forensic Artifacts

*   **Disk:** MFT entries for CSV export files showing creation time = query execution time

*   **Memory:** PowerShell process memory contains bearer tokens and query text

*   **Cloud:** 
    - `LAQueryLogs` table: Every query with text, execution time, result count
    - `SentinelAudit` table: "KQLQueryRun" and "ExportQueryResults" events
    - `AuditLogs` table: "Run query" operations with timestamp and user

### Response Procedures

1.  **Isolate:**
    ```powershell
    # Disable compromised account immediately
    Disable-AzADUser -ObjectId "compromised.user@company.com"
    # Revoke all active sessions
    Revoke-AzAccessToken
    ```

2.  **Collect Evidence:**
    ```powershell
    # Export all queries executed by compromised user (last 7 days)
    Search-AzLog -StartTime (Get-Date).AddDays(-7) -EventInitiator "compromised@company.com" | Export-Csv "C:\Incident\queries.csv"
    # Export all alert exports by same user
    Search-UnifiedAuditLog -UserIds "compromised@company.com" -Operations "ExportQueryResults" -StartDate (Get-Date).AddDays(-7) | Export-Csv "C:\Incident\exports.csv"
    ```

3.  **Remediate:**
    - Delete any Entra ID app registrations created by compromised user
    - Rotate all client secrets created in past 7 days
    - Review SecurityAlert table for alerts triggered by attacker activity during compromise period

---

## 15. RELATED ATTACK CHAIN

| Step | Phase | Technique | Description |
|---|---|---|---|
| **1** | **Initial Access** | [T1078 - Valid Accounts](https://attack.mitre.org/techniques/T1078/) | Compromise SOC user account via phishing or credential reuse |
| **2** | **Privilege Escalation** | [T1547 - Boot or Logon Autostart Execution](https://attack.mitre.org/techniques/T1547/) | Escalate to Sentinel Contributor role via compromised account |
| **3** | **Collection** | **[COLLECT-SENTINEL-001]** | **Extract 30 days of Sentinel alerts and evidence** |
| **4** | **Exfiltration** | [T1020 - Automated Exfiltration](https://attack.mitre.org/techniques/T1020/) | Send CSV files to attacker C2 infrastructure |
| **5** | **Impact** | [T1531 - Account Access Removal](https://attack.mitre.org/techniques/T1531/) | Delete alert rules to evade future detection |

---

## 16. REAL-WORLD EXAMPLES

### Example 1: Insider Threat – Disgruntled SOC Analyst

- **Target:** Financial services firm
- **Timeline:** July 2024 - August 2024
- **Technique Status:** ACTIVE
- **Impact:** Analyst extracted 6 months of alert history showing all detected attack techniques, identified gaps in monitoring, and sold intelligence to competing threat actor
- **Reference:** [FireEye Insider Threat Report 2025](https://www.fireeye.com/reports)

### Example 2: Ransomware Gang – Post-Compromise Reconnaissance

- **Target:** Healthcare organization
- **Timeline:** October 2023
- **Technique Status:** ACTIVE
- **Impact:** After establishing initial access via VPN compromise, attacker queried Sentinel alerts to identify which detection rules were active, then modified attacks to avoid triggering alerts
- **Reference:** [CISA Healthcare Ransomware Alert](https://www.cisa.gov/news-events/alerts)

---