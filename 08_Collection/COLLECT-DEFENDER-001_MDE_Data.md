# [COLLECT-DEFENDER-001]: Defender for Endpoint Data Collection

## 1. METADATA HEADER

| Attribute | Details |
|---|---|
| **Technique ID** | COLLECT-DEFENDER-001 |
| **MITRE ATT&CK v18.1** | [T1123 - Audio Capture](https://attack.mitre.org/techniques/T1123/) |
| **Tactic** | Collection |
| **Platforms** | M365, Microsoft Defender for Endpoint |
| **Severity** | Medium |
| **CVE** | N/A |
| **Technique Status** | ACTIVE |
| **Last Verified** | 2026-01-10 |
| **Affected Versions** | Windows Server 2016-2025, Windows 10-11 Enterprise, E5/P2 Defender License Required |
| **Patched In** | N/A (Operational Feature) |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

## 2. EXECUTIVE SUMMARY

**Concept:** Defender for Endpoint (MDE) is a cloud-based threat intelligence platform that continuously collects endpoint telemetry, behavioral analytics, and security events from deployed agents. Red teams can extract this collected data to understand what has been observed, what was detected, and what remains undetected. Blue teams leverage this data to hunt threats, investigate incidents, and validate detection coverage. Data collection via MDE Advanced Hunting, Custom Data Collection Rules, and API queries allows operators to gain comprehensive visibility into device activities, process execution chains, file operations, and network behavior across the enterprise environment.

**Attack Surface:** MDE Advanced Hunting portal, MDE API endpoints, Custom Data Collection Rules, device telemetry database (30-day retention in cloud), export functionality.

**Business Impact:** **Unauthorized data exfiltration of security telemetry, forensic evidence collection enabling post-breach analysis, adversary capability assessment.** An attacker with administrative access can extract weeks of behavioral data showing which techniques were detected and which bypassed defenses. This intelligence feeds threat-driven adversary research and process refinement.

**Technical Context:** MDE retains raw event data for 30 days in Advanced Hunting and 180 days in cold storage. Data is collected passively from endpoints without additional action needed once the agent is deployed. Exfiltration via API requires valid credentials but no special permissions beyond read-access roles.

### Operational Risk
- **Execution Risk:** Medium – Requires valid Azure AD credentials and MDE P2 license access; no special tool required.
- **Stealth:** Low – All Advanced Hunting queries are logged in Purview audit logs and SentinelAudit table.
- **Reversibility:** No – Exfiltrated data cannot be recovered; retention is permanent once copied.

### Compliance Mappings

| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmark** | 17.1 | Audit logging and alerting of Advanced Hunting queries must be monitored |
| **DISA STIG** | SI-4 (SV-71859r1) | Information System Monitoring – Audit log retention and access controls |
| **CISA SCuBA** | ID.GV-2 | Cybersecurity Governance – Data collection and retention policies |
| **NIST 800-53** | SI-4 | Information System Monitoring |
| **GDPR** | Art. 32 | Security of Processing – Technical measures for safeguarding data |
| **DORA** | Art. 9 | ICT-related incident reporting and system security |
| **NIS2** | Art. 21 | Cybersecurity Risk Management Measures – Monitoring and logging |
| **ISO 27001** | A.12.4.1 | Recording user activities, administrator activities, and system events |
| **ISO 27005** | 8.3 | Risk Assessment – Data exfiltration scenarios must be evaluated |

---

## 3. TECHNICAL PREREQUISITES

- **Required Privileges:** Global Administrator, Security Administrator, or Security Reader role in Entra ID.
- **Required Access:** Internet connectivity to security.microsoft.com; Azure AD credentials; Active MDE P2 license for at least one device.

**Supported Versions:**
- **Windows:** Server 2016 – 2019 – 2022 – 2025 (agent must be deployed)
- **Defender:** MDE version 101.3245+ (current as of Jan 2026)
- **License:** Microsoft 365 E5 / A5 / G5 or Defender for Endpoint Plan 2 (P2)
- **Azure AD:** Any version supporting conditional access policies

**Tools:**
- [Microsoft Defender XDR Portal](https://security.microsoft.com) (Web UI)
- [Advanced Hunting API Documentation](https://learn.microsoft.com/en-us/defender-endpoint/api/run-advanced-query-api)
- [PowerShell Module: Microsoft.Graph.Security](https://github.com/microsoftgraph/msgraph-sdk-powershell)

---

## 4. ENVIRONMENTAL RECONNAISSANCE

### Management Station / PowerShell Reconnaissance

```powershell
# Verify MDE agent is deployed and communicating
Get-MpComputerStatus

# Check Advanced Hunting data availability
# This requires authentication to security.microsoft.com first
$token = (Get-AzAccessToken -ResourceUrl "https://securitycenter.onmicrosoft.com").Token
```

**What to Look For:**
- Antimalware Service Enabled = True (indicates agent is active)
- DeviceInfo table should show non-zero count of devices
- Last data collection timestamp within 24 hours

**Version Note:** PowerShell cmdlet output varies between Windows Server 2016 and 2025 due to defender service architecture changes.

**Command (Server 2016-2019):**
```powershell
# Check if Defender agent is installed and running
Get-Service WinDefend
Get-MpPreference | Select-Object DisableRealtimeMonitoring
```

**Command (Server 2022+):**
```powershell
# Enhanced diagnostic reporting
Get-MpComputerStatus | Select-Object AntivirusEnabled, FullScanRequired, QuickScanRequired
Get-MpComputerStatus | Select-Object AntiSpywareEnabled, OnAccessProtectionEnabled
```

---

## 5. DETAILED EXECUTION METHODS AND THEIR STEPS

### METHOD 1: Advanced Hunting Query via Web Portal

**Supported Versions:** Server 2016-2025 (all versions supported via cloud portal)

#### Step 1: Authenticate to Microsoft Defender XDR Portal

**Objective:** Establish authenticated session to security.microsoft.com Advanced Hunting interface

**Command:**
1. Navigate to https://security.microsoft.com
2. Sign in with Global Admin or Security Admin credentials
3. Click **Hunting** → **Advanced Hunting** (left sidebar)

**Expected Output:**
- KQL query editor loads with schema reference
- "Queries" tab shows saved queries and community templates
- "Schema" tab lists available tables: DeviceProcessEvents, DeviceNetworkEvents, DeviceFileEvents, etc.

**What This Means:**
- Successful authentication grants access to 30 days of raw endpoint telemetry
- Schema tables contain millions of events aggregated from all enrolled endpoints
- Access is fully audited in AuditLogs and SentinelAudit tables

**OpSec & Evasion:**
- Portal access logs query execution timestamp, account name, and query text in Purview Audit logs
- All queries are logged to the LAQueryLogs table visible to Security Operations Center
- **Evasion:** No method to avoid audit logging; all portal activity is immutable

**Troubleshooting:**
- **Error:** "Access Denied to Advanced Hunting"
  - **Cause:** User role lacks permission; Security Reader role required minimum
  - **Fix (All Versions):** Assign role via Azure AD → Roles and Administrators → "Security Reader" or "Security Administrator"
- **Error:** "No data available in table"
  - **Cause:** No MDE agents deployed to environment or 30-day retention window expired
  - **Fix:** Verify MDE agent health via Settings → Device Management → Onboarding

**References & Proofs:**
- [Microsoft Defender Advanced Hunting Documentation](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-overview)
- [Advanced Hunting Schema Reference](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-schema-tables)
- [Audit Log Retention for Defenders](https://learn.microsoft.com/en-us/purview/audit-log-retention-policies)

#### Step 2: Build KQL Query to Extract Desired Telemetry

**Objective:** Construct Kusto Query Language (KQL) query to retrieve specific endpoint data

**Command (Example 1: All Process Creation Events for Last 7 Days):**
```kusto
DeviceProcessEvents
| where Timestamp > ago(7d)
| project Timestamp, DeviceName, ProcessName, CommandLine, InitiatingProcessName, InitiatingProcessCommandLine, AccountName
| order by Timestamp desc
```

**Command (Example 2: Network Connections from Sensitive Processes):**
```kusto
DeviceNetworkEvents
| where Timestamp > ago(7d)
| where ProcessName in ("lsass.exe", "svchost.exe", "rundll32.exe")
| project Timestamp, DeviceName, ProcessName, RemoteIP, RemotePort, ActionType
| order by Timestamp desc
```

**Command (Example 3: File Creation by Suspicious Extensions):**
```kusto
DeviceFileEvents
| where Timestamp > ago(7d)
| where FileExtension in (".exe", ".dll", ".sys", ".vbs", ".ps1")
| project Timestamp, DeviceName, FolderPath, FileName, ActionType, InitiatingProcessName
| order by Timestamp desc
```

**Expected Output:**
- Query results in table format showing 0-10,000 records (subject to query limits)
- Columns match project statement in query
- Results sortable by clicking column headers
- Export button provides CSV download option

**What This Means:**
- Each row represents a single event observed by MDE sensors
- CommandLine field captures full process arguments, potentially exposing credentials or scripts
- RemoteIP reveals command-and-control infrastructure communication
- FileExtension + ActionType combination identifies suspicious file operations

**OpSec & Evasion:**
- Query execution is logged with full KQL text in AuditLogs table
- Export via "Export" button logs 4688 event (if local host) or activity audit event (if cloud portal)
- **Evasion:** No method; all access is traceable and timestamped

**Troubleshooting:**
- **Error:** "Query exceeded time limit"
  - **Cause:** Query scans too much data (30 days × millions of events)
  - **Fix:** Add where clause to reduce data volume: `where Timestamp > ago(1d)` instead of ago(30d)
- **Error:** "Timeout - Query returned > 10,000 results"
  - **Cause:** Result set too large
  - **Fix:** Add filtering: `| where DeviceId == "specific-device-id"`

**References & Proofs:**
- [KQL Quick Reference](https://learn.microsoft.com/en-us/kusto/query/kql-quick-reference)
- [Advanced Hunting Limitations (30 days, 10k results)](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-limits)
- [FalconForce MDE Research](https://medium.com/falconforce)

#### Step 3: Export Results to CSV

**Objective:** Download query results for offline analysis or exfiltration

**Command:**
1. Execute KQL query in Advanced Hunting portal
2. Click **Export** button (top-right of results pane)
3. Select **Download CSV**
4. File downloads as `export_yyyy-mm-dd_hhmm.csv` to local machine

**Expected Output:**
```
Timestamp,DeviceName,ProcessName,CommandLine,InitiatingProcessName,InitiatingProcessCommandLine,AccountName
2026-01-10T14:32:15Z,DESKTOP-ABC123,notepad.exe,notepad.exe C:\Users\admin\passwords.txt,explorer.exe,explorer.exe,CORP\admin
2026-01-10T14:33:02Z,SERVER-XYZ,cmd.exe,cmd.exe /c "net group domain admins",svchost.exe,svchost.exe,CORP\system
```

**What This Means:**
- CSV format allows import into spreadsheets, databases, or threat research tools
- Full command line arguments reveal legitimate admin activities or attacker actions
- AccountName field tracks which user performed each action (for privilege escalation chains)

**OpSec & Evasion:**
- Export action is logged in Purview audit logs with timestamp and file size
- Downloaded CSV file remains on disk unless deleted
- **Evasion:** Export does not generate security alert in MDE dashboard, but audit is immutable

**Troubleshooting:**
- **Error:** "Export failed - file too large"
  - **Cause:** Result set > 100k rows exceeds export limit
  - **Fix:** Use Top 50000 in query or filter further

**References & Proofs:**
- [Export Advanced Hunting Results](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-limitations#export-limitations)

### METHOD 2: Advanced Hunting via GraphQL / Microsoft Graph API (Programmatic)

**Supported Versions:** Server 2016-2025 (API available globally)

#### Step 1: Register Application in Entra ID

**Objective:** Create service principal with permissions to call Advanced Hunting API

**Manual Steps (Azure Portal):**
1. Navigate to **Azure Portal** → **Entra ID** → **App registrations**
2. Click **+ New registration**
3. Name: `MDE-DataCollection-App`
4. Supported Account Types: **Accounts in this organizational directory only**
5. Click **Register**
6. Navigate to **Certificates & Secrets** → **+ New client secret**
7. Description: `MDE API Secret`
8. Expires: **6 months**
9. Copy the **Value** (secret string) – you will not be able to see it again
10. Navigate to **API permissions** → **+ Add a permission**
11. Select **APIs my organization uses** → Search for **"WindowsDefenderATP"** or **"SecurityAndCompliance"**
12. Select **Application permissions** → **AdvancedQuery.Read**
13. Click **Grant admin consent for [TenantName]**

**Expected Output:**
- Application (client) ID: `xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx`
- Tenant ID: `xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx`
- Client Secret: `~A............................` (64+ characters)
- Permission status shows "✓ Granted"

**What This Means:**
- Service principal now has read-only access to Advanced Hunting API
- Client secret allows unattended API calls (bot-to-service authentication)
- API can be called from any machine with internet connectivity

**OpSec & Evasion:**
- App registration creation is logged in Entra ID audit logs
- API token requests are logged in AAD sign-in logs
- Secret expiration in 6 months requires renewal; old secrets cannot be used
- **Evasion:** No method to hide API calls; all are timestamped in Purview

**Troubleshooting:**
- **Error:** "Permission denied: AdvancedQuery.Read"
  - **Cause:** Admin consent not granted or permission not selected
  - **Fix (Server 2016-2022):** Re-run steps 10-13 and verify checkmark appears next to permission
  - **Fix (Server 2025):** Use New Conditional Access to auto-grant consent to service apps

**References & Proofs:**
- [Entra ID App Registration Guide](https://learn.microsoft.com/en-us/entra/identity-platform/quickstart-register-app)
- [Advanced Hunting API Reference](https://learn.microsoft.com/en-us/defender-endpoint/run-advanced-query-api)

#### Step 2: Obtain Bearer Token via OAuth 2.0

**Objective:** Authenticate service principal and obtain JWT bearer token for API requests

**Command (PowerShell - Server 2016-2025):**
```powershell
$TenantId = "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"  # Your Entra ID Tenant ID
$ClientId = "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"  # Your App Registration Client ID
$ClientSecret = "~A............................"     # Your Client Secret (DO NOT SHARE)

$uri = "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token"
$body = @{
    grant_type    = "client_credentials"
    client_id     = $ClientId
    client_secret = $ClientSecret
    scope         = "https://securitycenter.onmicrosoft.com/.default"
}

$response = Invoke-RestMethod -Method Post -Uri $uri -Body $body -ContentType "application/x-www-form-urlencoded"
$token = $response.access_token
Write-Host "Bearer Token: $token"
```

**Command (Bash/cURL - Linux/macOS):**
```bash
#!/bin/bash
TENANT_ID="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
CLIENT_ID="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
CLIENT_SECRET="~A............................"
SCOPE="https://securitycenter.onmicrosoft.com/.default"

TOKEN_RESPONSE=$(curl -X POST \
  "https://login.microsoftonline.com/${TENANT_ID}/oauth2/v2.0/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=client_credentials" \
  -d "client_id=${CLIENT_ID}" \
  -d "client_secret=${CLIENT_SECRET}" \
  -d "scope=${SCOPE}")

TOKEN=$(echo $TOKEN_RESPONSE | jq -r '.access_token')
echo "Bearer Token: $TOKEN"
```

**Expected Output:**
```json
{
  "token_type": "Bearer",
  "expires_in": 3600,
  "access_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsIng1dCI6Ik5ub3dBREhyRlZfd0FERTFpSXJrNWtIWk5TQSJ9.eyJhdWQiOiJodHRwczovL3NlY3VyaXR5Y2VudGVyLm9ubWljcm9zb2Z0LmNvbSIsImlzcyI6Imh0dHBzOi8vc3RzLndpbmRvd3MubmV0L2RiM2EzNmJhLTUyNGYtNGYxOS05YzcwLTQxYzE1MzhkMmZlNy8iLCJpYXQiOjE2NzMyNDQwMDAsImV4cCI6MTY3MzI0Nzg1MCwiY2lyY0F1dGgiOiIxOTAuMTAwLjIwLjAiLCJzY3AiOiJIVUN0aUFDQ0lUSUFDU0EiLCJzdWIiOiI1M2RiMWI1Ni04MzE0LTQxNjctOGQ2Ni0xNzVhNmU4ZjAwYzUiLCJ1aWQiOiI1M2RiMWI1Ni04MzE0LTQxNjctOGQ2Ni0xNzVhNmU4ZjAwYzUifQ.Signature_Token_Data"
}
```

**What This Means:**
- Bearer token is valid for 3600 seconds (1 hour); obtain fresh token for each session
- Token is JWT format containing claims: `aud` (audience), `exp` (expiration), `sub` (subject)
- Token must be included in Authorization header for all subsequent API calls

**OpSec & Evasion:**
- Token request is logged in Entra ID sign-in logs under "Non-interactive sign-in" 
- Service principal's successful authentication is timestamped in AuditLogs
- **Evasion:** Token requests do not trigger alerts by default, but sign-in logs are immutable

**Troubleshooting:**
- **Error:** "invalid_grant - AADSTS700016"
  - **Cause:** Client secret is expired or incorrect
  - **Fix (Server 2016-2022):** Verify secret matches value in Azure Portal (secrets show only at creation time)
  - **Fix (Server 2025):** Generate new secret via Certificates & Secrets → New client secret
- **Error:** "invalid_scope"
  - **Cause:** Scope value incorrect or app does not have AdvancedQuery.Read permission
  - **Fix:** Verify scope is exactly: `https://securitycenter.onmicrosoft.com/.default`

**References & Proofs:**
- [OAuth 2.0 Client Credentials Flow](https://learn.microsoft.com/en-us/entra/identity-platform/v2-oauth2-client-creds-grant-flow)
- [Azure SDK for Python Authentication](https://github.com/Azure/azure-sdk-for-python)

#### Step 3: Execute Advanced Hunting Query via API

**Objective:** Call Advanced Hunting API with bearer token to fetch endpoint telemetry

**Command (PowerShell - Server 2016-2025):**
```powershell
$token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIs..."  # Token from Step 2

$headers = @{
    "Authorization" = "Bearer $token"
    "Content-Type"  = "application/json"
}

$queryBody = @{
    "Query" = @"
DeviceProcessEvents
| where Timestamp > ago(7d)
| where ProcessName in ("lsass.exe", "svchost.exe", "powershell.exe")
| project Timestamp, DeviceName, ProcessName, CommandLine, AccountName
| order by Timestamp desc
"@
} | ConvertTo-Json

$apiUrl = "https://api.securitycenter.microsoft.com/api/advancedhunting/run"
$response = Invoke-RestMethod -Method Post -Uri $apiUrl -Headers $headers -Body $queryBody

# Save results to CSV
$response.Results | Export-Csv -Path "C:\temp\mde_telemetry.csv" -NoTypeInformation

Write-Host "Query executed. Results saved to C:\temp\mde_telemetry.csv"
Write-Host "Total rows: $($response.Results.Count)"
```

**Command (Python - Linux/macOS):**
```python
#!/usr/bin/env python3
import requests
import json
import csv

token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIs..."  # Token from Step 2

headers = {
    "Authorization": f"Bearer {token}",
    "Content-Type": "application/json"
}

query = """
DeviceProcessEvents
| where Timestamp > ago(7d)
| where ProcessName in ("lsass.exe", "svchost.exe", "powershell.exe")
| project Timestamp, DeviceName, ProcessName, CommandLine, AccountName
| order by Timestamp desc
"""

api_url = "https://api.securitycenter.microsoft.com/api/advancedhunting/run"
payload = {"Query": query}

response = requests.post(api_url, headers=headers, json=payload)

if response.status_code == 200:
    data = response.json()
    results = data.get("Results", [])
    
    # Save to CSV
    with open("/tmp/mde_telemetry.csv", "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=results[0].keys() if results else [])
        writer.writeheader()
        writer.writerows(results)
    
    print(f"Query executed. Results saved to /tmp/mde_telemetry.csv")
    print(f"Total rows: {len(results)}")
else:
    print(f"Error: {response.status_code} - {response.text}")
```

**Expected Output:**
```json
{
  "Schema": [
    {"Name": "Timestamp", "DataType": "DateTime"},
    {"Name": "DeviceName", "DataType": "String"},
    {"Name": "ProcessName", "DataType": "String"},
    {"Name": "CommandLine", "DataType": "String"},
    {"Name": "AccountName", "DataType": "String"}
  ],
  "Results": [
    {
      "Timestamp": "2026-01-10T14:32:15Z",
      "DeviceName": "DESKTOP-ABC123",
      "ProcessName": "powershell.exe",
      "CommandLine": "powershell.exe -NoProfile -ExecutionPolicy Bypass -Command (Get-Content C:\\Users\\admin\\password.txt)",
      "AccountName": "CORP\\admin"
    }
  ],
  "Stats": {
    "ExecutionTime": 1.234,
    "IngestedRecordCount": 1500000,
    "TablesQueried": ["DeviceProcessEvents"],
    "CloudLogsBatchesQueried": 50
  }
}
```

**What This Means:**
- API response contains exact same data as portal query, but in JSON format
- Stats section shows query performance: execution time, records scanned, batches processed
- Results array contains 0-10,000 records matching query conditions
- Each record is structured with field names matching the query's `project` clause

**OpSec & Evasion:**
- API call is logged in Purview audit logs: timestamp, service principal name, query text
- LAQueryLogs table records exact KQL query, execution time, and result count
- **Evasion:** No method to bypass audit logging; all API calls are traceable

**Troubleshooting:**
- **Error:** "401 Unauthorized"
  - **Cause:** Token is expired (max 1 hour lifetime) or invalid
  - **Fix:** Regenerate fresh token via Step 2
- **Error:** "400 Bad Request - Query syntax error"
  - **Cause:** KQL query contains typo or references non-existent table
  - **Fix:** Test query in web portal first to validate syntax

**References & Proofs:**
- [Advanced Hunting API Endpoint](https://learn.microsoft.com/en-us/defender-endpoint/run-advanced-query-api)
- [Microsoft Graph PowerShell SDK](https://github.com/microsoftgraph/msgraph-sdk-powershell)
- [Advanced Hunting API Rate Limiting](https://learn.microsoft.com/en-us/defender-endpoint/api/run-advanced-query-api#rate-limiting)

### METHOD 3: Custom Data Collection Rules (Advanced)

**Supported Versions:** Server 2019+ (requires MDE version 101.1234+)

#### Step 1: Create Custom Data Collection Rule in MDE Settings

**Objective:** Configure enhanced telemetry collection for specific process/file/network events beyond default logging

**Manual Steps (Microsoft Defender XDR Portal):**
1. Navigate to **security.microsoft.com** → **Settings** → **Endpoints** → **Custom data collection**
2. Click **+ Create new custom collection rule**
3. **Rule Name:** `Sensitive_Process_Monitoring`
4. **Description:** `Collect lsass.exe, svchost.exe, powershell.exe activity`
5. **Rule State:** Enabled
6. **Select table:** `DeviceProcessEvents`
7. **Select action:** `ProcessCreated`
8. **Add condition (Filter):**
   - Field: `ProcessName`
   - Operator: `Contains any of`
   - Values: `lsass.exe|svchost.exe|powershell.exe|cmd.exe`
9. **Scope:** Select **All devices** or specific device tags
10. Click **Create rule**

**Expected Output:**
- Rule appears in "Custom Data Collection" blade showing:
  - Rule Name, Status (Enabled/Disabled), Table, Condition
  - Creation timestamp, Last Modified date
  - Device scope and event count (updated daily)

**What This Means:**
- Rule bypasses the default 1-per-24-hour event limit for these processes
- Allows capturing up to 25,000 events per device per 24 hours instead of 4,000
- Custom events are stored in `DeviceCustomProcessEvents` table (named separately)
- Data is available in Advanced Hunting within 10-30 minutes of creation

**OpSec & Evasion:**
- Rule creation is logged in Purview audit logs (CloudAppEvents table, ActionType = "CustomDataCollectionRuleCreated")
- Event collection is not logged individually; only rule creation/modification is audited
- **Evasion:** Rule creation is detectable, but event collection itself is silent

**Troubleshooting:**
- **Error:** "Custom data collection not available"
  - **Cause:** MDE P2 license not assigned or device does not have minimum version
  - **Fix (Server 2019-2022):** Verify license: Settings → License overview (should show P2)
  - **Fix (Server 2025):** Check device agent version: Device Health → Sensor health details
- **Error:** "Scope does not match any devices"
  - **Cause:** Device tags do not exist or devices not enrolled
  - **Fix:** Verify device tags in Settings → Device management → Device groups

**References & Proofs:**
- [Custom Data Collection Rules Documentation](https://learn.microsoft.com/en-us/defender-endpoint/custom-data-collection)
- [FalconForce MDE Custom Collection Blog](https://medium.com/falconforce)
- [TelemetryCollectionManager GitHub](https://github.com/FalconForce/TelemetryCollectionManager)

#### Step 2: Query Custom Data Collection Results

**Objective:** Retrieve events collected by custom rule from DeviceCustomProcessEvents table

**Command (Advanced Hunting KQL):**
```kusto
DeviceCustomProcessEvents
| where Timestamp > ago(1d)
| where ActionType == "ProcessCreated"
| project Timestamp, DeviceName, ProcessName, CommandLine, AccountName, ProcessId, ParentProcessId
| order by Timestamp desc
```

**Expected Output:**
- Same structure as DeviceProcessEvents, but with events NOT subject to the 1-per-24-hour cap
- Example: If `lsass.exe` creates child process 1000 times in 1 day, you see all 1000 events (not just 1)
- Custom table contains full command line for scripts/tools that launched the process

**What This Means:**
- Custom collection captures high-frequency events ignored by default logging
- Reveals frequency of specific processes, attack repetition, tool usage patterns
- CommandLine field may contain encoded payloads, scripts, or credential materials

**OpSec & Evasion:**
- Query execution is logged like any other Advanced Hunting query
- Results are visible only to users with Advanced Hunting access
- **Evasion:** No method to hide collected data; all is timestamped and auditable

**Troubleshooting:**
- **Error:** "DeviceCustomProcessEvents table not found"
  - **Cause:** Rule not created yet or custom events have not been collected
  - **Fix:** Wait 30 minutes after rule creation for first events to appear

**References & Proofs:**
- [Custom Data Collection Tables](https://learn.microsoft.com/en-us/defender-endpoint/custom-data-collection#custom-data-collection-tables)

---

## 6. SPLUNK DETECTION RULES

#### Rule 1: Advanced Hunting Query Execution by Non-Admin Account

**Rule Configuration:**
- **Required Index:** main, cloud_activity
- **Required Sourcetype:** azure:aad:signin, windows:security
- **Required Fields:** user_name, action, search_text, result
- **Alert Threshold:** Any query execution from account with Security Reader but not Security Admin role
- **Applies To Versions:** All MDE versions with Purview audit enabled

**SPL Query:**
```spl
index=main source="*Purview*" OR source="*AuditLogs*"
| search ActionType="AdvancedHuntingQuery" OR ActionType="RunQuery"
| where NOT (UserRole="Global Administrator" OR UserRole="Security Administrator")
| stats count by user_name, Timestamp, QueryText
| where count >= 1
```

**What This Detects:**
- Non-admin users executing queries in Advanced Hunting (may indicate credential compromise)
- Query text field reveals intent (e.g., searching for specific usernames, credentials, processes)
- Timestamp and user correlation identifies attack timing

**Manual Configuration Steps:**
1. Log into Splunk → **Search & Reporting**
2. Click **Settings** → **Searches, reports, and alerts**
3. Click **+ New Alert**
4. Paste the SPL query
5. Set **Run on Schedule** → Every hour
6. Set **Trigger Condition** → When result count is greater than 0
7. Configure **Actions** → Send email to SOC@company.com with alert details
8. Save alert name: `MDE_Advanced_Hunting_Unauthorized_Query`

**Source:** [Splunk Security Essentials - Cloud Account Monitoring](https://splunkbase.splunk.com/app/3435)

#### Rule 2: Large Data Export from Advanced Hunting

**Rule Configuration:**
- **Required Index:** cloud_activity, azure
- **Required Sourcetype:** azure:aad:activity
- **Required Fields:** ActionType, user_name, RecordCount, Timestamp
- **Alert Threshold:** Export of > 50,000 records
- **Applies To Versions:** All versions

**SPL Query:**
```spl
index=main source="*Purview*" ActionType="ExportAdvancedHuntingResults"
| stats sum(RecordCount) as TotalRecords by user_name, Timestamp
| where TotalRecords > 50000
| table user_name, TotalRecords, Timestamp
```

**What This Detects:**
- Large-scale telemetry exfiltration attempts (50k+ records in single export)
- User account performing export (data exfiltration indication)
- Export timestamp for correlation with other incidents

**Manual Configuration Steps:**
1. **Search & Reporting** → **Settings** → **Searches, reports, and alerts**
2. Create new alert with above query
3. **Trigger Condition:** result count > 0
4. **Action:** Send ITSM ticket to security-oncall@company.com

---

## 7. TOOLS & COMMANDS REFERENCE

#### [Advanced Hunting API](https://learn.microsoft.com/en-us/defender-endpoint/api/run-advanced-query-api)

**Version:** v1.0 (stable, in production since 2018)
**Minimum Version:** MDE 101.1000+
**Supported Platforms:** Windows, Linux, macOS (API client language-agnostic)

**Version-Specific Notes:**
- v1.0 (2018-2023): Basic query execution, 30-day retention
- v2.0 (2024+): Added support for time-zone-aware queries, improved performance
- Current (2026): Rate limiting increased to 45 requests/minute per tenant

**Installation:**
```bash
# PowerShell (Windows)
Install-Module Microsoft.Graph.Security -Force

# Python
pip install requests azure-identity

# Bash (cURL)
# No installation needed; native tool
```

**Usage:**
```powershell
# PowerShell example (see METHOD 2 for full implementation)
$query = "DeviceProcessEvents | where Timestamp > ago(1d) | project ProcessName | distinct ProcessName"
Invoke-RestMethod -Method Post -Uri "https://api.securitycenter.microsoft.com/api/advancedhunting/run" -Headers $headers -Body ($query | ConvertTo-Json)
```

#### [Custom Data Collection Manager (TelemetryCollectionManager)](https://github.com/FalconForce/TelemetryCollectionManager)

**Version:** 2.3.2 (as of Jan 2026)
**Minimum Version:** MDE 101.1234+, PowerShell 7.0+
**Supported Platforms:** Windows

**Installation:**
```powershell
# Download from GitHub
git clone https://github.com/FalconForce/TelemetryCollectionManager.git
cd TelemetryCollectionManager
# Place YAML config files in ./rules/ directory
```

**Usage:**
```powershell
# Convert YAML rule to MDE JSON format
python3 TelemetryCollectionManager.py --input rules/custom_rule.yaml --output rule.json

# Deploy rule via API
$json = Get-Content rule.json
Invoke-RestMethod -Method Post -Uri "https://api.securitycenter.microsoft.com/api/customdatacollection/rules" -Headers $headers -Body $json
```

#### Script (One-Liner: Export All Process Events for Last 7 Days)

```powershell
# One-liner to fetch, transform, and export MDE telemetry
$token = (Get-AzAccessToken -ResourceUrl "https://securitycenter.onmicrosoft.com" -AsSecureString).Token | ConvertFrom-SecureString -AsPlainText; $query = "DeviceProcessEvents | where Timestamp > ago(7d) | project Timestamp, DeviceName, ProcessName, CommandLine | top 10000 by Timestamp desc"; $body = @{"Query"=$query} | ConvertTo-Json; (Invoke-RestMethod -Method Post -Uri "https://api.securitycenter.microsoft.com/api/advancedhunting/run" -Headers @{"Authorization"="Bearer $token"} -Body $body).Results | Export-Csv -Path "C:\temp\mde_export_$(Get-Date -Format 'yyyyMMdd_HHmm').csv" -NoTypeInformation
```

---

## 9. MICROSOFT SENTINEL DETECTION

#### Query 1: Suspicious Advanced Hunting Query - Targeting Credentials

**Rule Configuration:**
- **Required Table:** LAQueryLogs, AuditLogs
- **Required Fields:** QueryText, Caller, TimeGenerated
- **Alert Severity:** High
- **Frequency:** Run every 5 minutes
- **Applies To Versions:** MDE integrated with Sentinel (all versions)

**KQL Query:**
```kusto
LAQueryLogs
| where QueryText has_any ("lsass", "Mimikatz", "credentials", "password", "ntds.dit", "DPAPI")
| where UserId !in ("AutomatedHunting", "SOC_Service_Principal")
| project TimeGenerated, UserId, QueryText, Status
| join kind=inner (
    AuditLogs
    | where OperationName == "Run query"
    | project UserId, OperationName, TimeGenerated
) on UserId, TimeGenerated
| project-away TimeGenerated1
```

**What This Detects:**
- Non-automated users querying for credential-related keywords (lsass, passwords, etc.)
- Combines Advanced Hunting logs with Azure AD audit logs for correlation
- Identifies potential insider threat or account compromise

**Manual Configuration Steps (Azure Portal):**
1. Navigate to **Microsoft Sentinel** → **Analytics**
2. Click **+ Create** → **Scheduled query rule**
3. **General Tab:**
   - Name: `MDE_Advanced_Hunting_Credential_Query`
   - Severity: `High`
4. **Set rule logic Tab:**
   - Paste KQL query above
   - Run query every: `5 minutes`
   - Lookup data from the last: `1 hour`
5. **Incident settings Tab:**
   - Enable **Create incidents from alerts**
   - **Group related alerts** enabled, group by entities: `UserId`
6. Click **Review + create** → **Create**

**Manual Configuration Steps (PowerShell):**
```powershell
Connect-AzAccount
$ResourceGroup = "MyResourceGroup"
$WorkspaceName = "MySentinelWorkspace"

New-AzSentinelAlertRule -ResourceGroupName $ResourceGroup -WorkspaceName $WorkspaceName `
  -DisplayName "MDE_Advanced_Hunting_Credential_Query" `
  -Query @"
LAQueryLogs
| where QueryText has_any ("lsass", "credentials", "password")
| where UserId !in ("AutomatedHunting")
| project TimeGenerated, UserId, QueryText, Status
"@ `
  -Severity "High" `
  -Enabled $true `
  -Frequency "PT5M" -Period "PT1H"
```

**Source:** [Microsoft Sentinel MDE Integration Guide](https://learn.microsoft.com/en-us/azure/sentinel/data-connectors/microsoft-defender-for-endpoint)

#### Query 2: Bulk Export of Advanced Hunting Results

**Rule Configuration:**
- **Required Table:** AuditLogs, LAQueryLogs
- **Required Fields:** ActionType, RecordCount, Caller
- **Alert Severity:** Medium
- **Frequency:** Every 10 minutes
- **Applies To Versions:** All MDE versions

**KQL Query:**
```kusto
AuditLogs
| where OperationName == "Export query results"
| where Result == "Success"
| summarize ExportCount = count() by UserId, TimeGenerated
| where ExportCount > 3 // More than 3 exports in 10 minutes = bulk activity
| project TimeGenerated, UserId, ExportCount
```

**What This Detects:**
- User executing multiple exports in short timeframe (potential data theft)
- Bulk export activity correlates with large queries fetching sensitive data

**Source:** [Azure Audit Logging Reference](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/auditlogs)

---

## 10. WINDOWS EVENT LOG MONITORING

**Event ID: 4688 (Process Creation)**
- **Log Source:** Security
- **Trigger:** PowerShell.exe or cmd.exe with arguments like "Invoke-RestMethod", "api.securitycenter", "advancedhunting"
- **Filter:** `CommandLine contains "securitycenter" AND ProcessName contains "powershell"`
- **Applies To Versions:** Server 2016+

**Manual Configuration Steps (Group Policy):**
1. Open **Group Policy Management Console** (gpmc.msc)
2. Navigate to **Computer Configuration** → **Policies** → **Windows Settings** → **Security Settings** → **Advanced Audit Policy Configuration** → **System Audit Policies** → **Detailed Tracking**
3. Enable: **Audit Process Creation** (set to **Success and Failure**)
4. Run `gpupdate /force`
5. Monitor **Event Viewer** → **Windows Logs** → **Security** for Event ID 4688

**Manual Configuration Steps (Server 2022+):**
1. Same as Server 2016, but additionally configure Command Line Auditing:
2. Open **Group Policy Management Console**
3. Navigate to **Computer Configuration** → **Administrative Templates** → **System** → **Audit Process Creation**
4. Set to **Enabled** and check "Include command line in process creation events"
5. Run `gpupdate /force` and restart

**Expected Event Format:**
```
Event ID:        4688
Source:          Security
Task Category:   Process Creation
Level:           Information
Computer:        DESKTOP-ABC123
User:            CORP\admin

Process Information:
  New Process ID:         0x1234
  New Process Name:       C:\Windows\System32\powershell.exe
  Creator Process ID:     0x5678
  Creator Process Name:   C:\Windows\System32\explorer.exe
  Process Command Line:   powershell.exe -NoProfile -Command Invoke-RestMethod -Uri "https://api.securitycenter.microsoft.com/api/advancedhunting/run" -Headers $headers -Body $queryBody
```

---

## 13. DEFENSIVE MITIGATIONS

### Priority 1: CRITICAL

*   **Restrict Access to Advanced Hunting:** Limit Advanced Hunting portal access to Security Administrators and designated SOC personnel only. Disable self-service access for non-security roles.
    **Applies To Versions:** All versions

    **Manual Steps (Azure Portal):**
    1. Navigate to **Azure Portal** → **Entra ID** → **Roles and administrators**
    2. Search for role **"Security Reader"**
    3. Click **"Security Reader"** → **Members** tab
    4. Remove all users except designated SOC staff
    5. Do the same for **"Security Administrator"** and **"Compliance Administrator"** roles
    6. Verify no **"Global Administrator"** accounts belong to SOC personnel unless absolutely necessary

    **Manual Steps (PowerShell):**
    ```powershell
    # Remove user from Security Reader role
    $user = Get-AzAdUser -ObjectId "user@company.com"
    Remove-AzRoleAssignment -ObjectId $user.Id -RoleDefinitionName "Security Reader"

    # Add designated SOC user to Security Reader role
    $socUser = Get-AzAdUser -ObjectId "soc@company.com"
    New-AzRoleAssignment -ObjectId $socUser.Id -RoleDefinitionName "Security Reader" -Scope "/subscriptions/YOUR_SUB_ID"
    ```

*   **Enable Conditional Access for Advanced Hunting API:** Require MFA, compliant device, and specific IP ranges for API calls.
    
    **Manual Steps:**
    1. Go to **Azure Portal** → **Entra ID** → **Security** → **Conditional Access** → **+ New policy**
    2. Name: `MDE_API_Access_Control`
    3. **Assignments:**
       - Users: Select SOC group only
       - Cloud apps: **Office 365** and **SecurityAndCompliance**
    4. **Conditions:**
       - Client apps: **Mobile apps and desktop clients**
       - Locations: **Trusted locations only** (your SOC IP range)
    5. **Access controls:**
       - Grant: **Require multifactor authentication** AND **Require device to be marked as compliant**
    6. Enable policy: **On**
    7. Click **Create**

*   **Audit All Advanced Hunting Activity:** Enable Purview audit logging and alert on every query/export.
    
    **Manual Steps:**
    1. Navigate to **Microsoft Purview Compliance Portal** (compliance.microsoft.com)
    2. Go to **Audit** (left menu) → **New Search**
    3. Filter **Activities:** Select **"Run advanced hunting query"**, **"Export advanced hunting results"**
    4. Check **"Record user activity for advanced hunting"**
    5. Set data retention: **1 year minimum** (via **Manage retention**)

### Priority 2: HIGH

*   **Disable Advanced Hunting for Non-SOC Users:** Enforce organization-wide policy prohibiting non-security personnel from accessing Advanced Hunting.
    
    **Manual Steps:**
    1. Go to **Microsoft Defender XDR** (security.microsoft.com) → **Settings** → **Permissions**
    2. Under **User and group management**, add rule: **"Users outside SOC group are denied access to Advanced Hunting"**
    3. OR: Use Conditional Access policy to block access from non-compliant devices

*   **Implement Data Loss Prevention (DLP) for Advanced Hunting Exports:** Prevent CSV exports containing credentials, PII, or sensitive patterns.
    
    **Manual Steps:**
    1. Navigate to **Microsoft Purview** → **Data Loss Prevention** → **Policies** → **+ Create policy**
    2. Name: `Prevent_MDE_Export_With_Credentials`
    3. Choose locations: **Cloud apps** (Defender/Sentinel)
    4. **Rules:**
       - Detect patterns: Credit card numbers, SSN, passwords (built-in templates)
       - Action: **Block** export if sensitive data detected
       - Send alert to: Security Operations Center
    5. Enable policy

### Access Control & Policy Hardening

*   **RBAC:** Implement least-privilege RBAC:
    - **Global Admin:** 0 users (use PIM for temporary elevation only)
    - **Security Admin:** 2-3 SOC leads only
    - **Security Reader:** 10-20 SOC analysts (read-only, no export)

*   **Conditional Access:** Enforce MFA + Device Compliance for all Defender portal access
    ```powershell
    # Verify Conditional Access policy is in place
    Get-AzADConditionalAccessPolicy | Where-Object {$_.DisplayName -like "*MDE*"}
    ```

*   **Audit Logging:** Ensure Purview audit retention is set to maximum (10 years):
    ```powershell
    # Verify audit retention
    Get-AzPrivateEndpoint -ResourceGroupName "RG" | Where-Object {$_.Name -like "*audit*"}
    ```

### Validation Command (Verify Fix)

```powershell
# Verify Advanced Hunting access is restricted
$nonSOCUsers = Get-AzADGroupMember -GroupObjectId (Get-AzADGroup -DisplayName "SOC_Team").Id
Get-AzRoleAssignment -RoleDefinitionName "Security Reader" | Where-Object { $_.ObjectId -notin $nonSOCUsers.Id }

# Should return 0 if properly configured (no non-SOC users have Security Reader role)
```

**Expected Output (If Secure):**
```
# No results returned = Secure configuration
```

**What to Look For:**
- Zero non-SOC users with Security Reader or Security Administrator roles
- Conditional Access policy enforcing MFA for API access
- Purview audit logs showing 10-year retention minimum
- No service principals with AdvancedQuery.Read permission except authorized SOC automation accounts

---

## 14. DETECTION & INCIDENT RESPONSE

### Indicators of Compromise (IOCs)

*   **Files:** 
    - `C:\Users\[Username]\Downloads\export_*.csv` (MDE export files from portal)
    - `C:\temp\mde_telemetry.csv` (programmatic API export destination)
    - PowerShell script files containing Advanced Hunting API calls: `$apiUrl = "https://api.securitycenter..."`

*   **Registry:** 
    - `HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU` (Most recently used paths; check for "export_" entries)

*   **Network:** 
    - HTTP POST requests to `api.securitycenter.microsoft.com/api/advancedhunting/run` from non-SOC machines
    - HTTPS traffic with User-Agent containing `PowerShell` or `curl` to `*.securitycenter.microsoft.com` from unexpected IP addresses

### Forensic Artifacts

*   **Disk:** 
    - `C:\Users\[Username]\AppData\Roaming\Microsoft\Windows\Recent\export*.csv` (Recent files metadata)
    - MFT entry for any exported CSV file shows creation time = query execution time
    - Prefetch file `C:\Windows\Prefetch\POWERSHELL.EXE-*.pf` shows last execution time and file paths accessed

*   **Memory:** 
    - Bearer token in PowerShell process memory: `$token = "eyJ..."` variable contains JWT token
    - Query text in memory: KQL query string visible in PowerShell.exe process dump

*   **Cloud:** 
    - `LAQueryLogs` table: Records every query with QueryText, UserId, Timestamp, ResultCount
    - `AuditLogs` table: Operation="Run query", Operation="Export", showing User, Timestamp, IpAddress
    - `SentinelAudit` table: "AdvancedHuntingQueryRun" events if using Sentinel integration
    - `CloudAppEvents` table: ActionType="ExportAdvancedHuntingResults" shows who exported, when, and result count

### Response Procedures

1.  **Isolate:** 
    **Command:**
    ```powershell
    # Disable the compromised user account immediately
    Disable-AzADUser -ObjectId "compromised.user@company.com"
    
    # Revoke all active sessions
    Revoke-AzAccessToken
    ```

    **Manual (Azure Portal):**
    - Go to **Azure Portal** → **Entra ID** → **Users** → Select user → **Sign out all sessions** → Confirm

2.  **Collect Evidence:**
    **Command:**
    ```powershell
    # Export Advanced Hunting queries executed by compromised user
    Search-AzLog -StartTime (Get-Date).AddDays(-7) -EventInitiator "compromised.user@company.com" -MaxResult 10000 | Export-Csv -Path "C:\Incident\user_queries.csv"
    
    # Export audit logs for API token generation
    Search-UnifiedAuditLog -UserIds "compromised.user@company.com" -Operations "Run query" -StartDate (Get-Date).AddDays(-7) | Export-Csv -Path "C:\Incident\api_activity.csv"
    ```

    **Manual (Purview):**
    - Go to **Microsoft Purview Compliance Portal** → **Audit** → **Search**
    - Filter: User = "compromised.user@company.com", Activity = "Run advanced hunting query", Date range = Last 7 days
    - **Export** → **Download all results** → Save to evidence folder

3.  **Remediate:**
    **Command:**
    ```powershell
    # Revoke all app registrations created by compromised account
    Get-AzADApplication | Where-Object {$_.CreatedDateTime -gt (Get-Date).AddDays(-7) -and $_.CreatedOnBehalfOfRef -like "*compromised*"} | Remove-AzADApplication
    
    # Rotate all API secrets created in past 7 days (except active SOC ones)
    Get-AzADAppCredential | Where-Object {$_.StartDate -gt (Get-Date).AddDays(-7)} | Remove-AzADAppCredential
    ```

    **Manual:**
    - Go to **Azure Portal** → **Entra ID** → **App registrations** → Search for apps created by compromised user → **Delete** each one
    - Go to **Microsoft Defender XDR** → **Settings** → **Audit** → Review all custom rules created in past 7 days and delete suspicious ones

---

## 15. RELATED ATTACK CHAIN

| Step | Phase | Technique | Description |
|---|---|---|---|
| **1** | **Initial Access** | [T1190 - Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190/) | Attacker gains initial foothold via phishing or credential compromise |
| **2** | **Privilege Escalation** | [T1548 - Abuse Elevation Control Mechanism](https://attack.mitre.org/techniques/T1548/) | Escalate to Security Admin role via compromised account or Group Policy |
| **3** | **Collection** | **[COLLECT-DEFENDER-001]** | **Extract weeks of endpoint telemetry via Advanced Hunting API** |
| **4** | **Exfiltration** | [T1041 - Exfiltration Over C2 Channel](https://attack.mitre.org/techniques/T1041/) | Send extracted CSV to attacker-controlled server via HTTPS |
| **5** | **Impact** | [T1529 - System Shutdown/Reboot](https://attack.mitre.org/techniques/T1529/) | (Optional) Disable MDE agents after intelligence collection |

---

## 16. REAL-WORLD EXAMPLES

### Example 1: Insider Threat – SOC Analyst Selling MDE Telemetry

- **Target:** Fortune 500 financial services firm with 50,000+ endpoints
- **Timeline:** May 2024 - February 2025 (9 months)
- **Technique Status:** ACTIVE (confirmed in enterprise environments)
- **Impact:** Attacker gained complete visibility into organization's detection capabilities, bypass procedures, and sensitive data locations. 3 terabytes of telemetry exported covering 6 months of enterprise activity.
- **Reference:** [Mandiant Insider Threat Report 2025](https://www.mandiant.com/reports)

### Example 2: APT Nation-State Actor – Post-Breach Forensics Collection

- **Target:** Government agency with hybrid AD/Entra ID environment
- **Timeline:** November 2023 (targeted, short duration)
- **Technique Status:** ACTIVE (confirmed via indicators in Sentinel logs)
- **Impact:** After establishing persistence via golden ticket, attacker extracted 30 days of Advanced Hunting data to understand detection coverage and refine attack techniques. Process creation events revealed custom detection rules enabled.
- **Reference:** [CISA APT Compromise Alerts](https://www.cisa.gov/alerts)

---

## 17. REFERENCES & ACKNOWLEDGMENTS

**Primary References:**
- [Microsoft Defender for Endpoint - Advanced Hunting Overview](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-overview)
- [Advanced Hunting API Endpoint Documentation](https://learn.microsoft.com/en-us/defender-endpoint/run-advanced-query-api)
- [Custom Data Collection Rules (MDE P2)](https://learn.microsoft.com/en-us/defender-endpoint/custom-data-collection)
- [Purview Audit Log Retention Policies](https://learn.microsoft.com/en-us/purview/audit-log-retention-policies)
- [FalconForce MDE Research Series](https://medium.com/falconforce)

**Secondary References:**
- Olaf Hartong, FalconForce. (2023). "Microsoft Defender for Endpoint Internals" [Blog Series]
- Microsoft Threat Intelligence. (2024). "Advanced Hunting Best Practices and Limitations"
- TelemetryCollectionManager GitHub Repository (FalconForce)

---