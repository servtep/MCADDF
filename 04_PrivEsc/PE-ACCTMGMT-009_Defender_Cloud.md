# [PE-ACCTMGMT-009]: Microsoft Defender for Cloud

## 1. METADATA HEADER

| Attribute | Details |
|---|---|
| **Technique ID** | PE-ACCTMGMT-009 |
| **MITRE ATT&CK v18.1** | [Account Manipulation (T1098)](https://attack.mitre.org/techniques/T1098/) |
| **Tactic** | Privilege Escalation, Persistence |
| **Platforms** | Entra ID, Azure |
| **Severity** | High |
| **CVE** | N/A |
| **Technique Status** | ACTIVE |
| **Last Verified** | 2025-01-09 |
| **Affected Versions** | Microsoft Defender for Cloud (All Current Versions) |
| **Patched In** | Microsoft Monitors Continuously – No Single Patch Available |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

## 2. EXECUTIVE SUMMARY

**Concept:** Microsoft Defender for Cloud is the unified cloud security posture management (CSPM) platform that provides security recommendations, threat detection, and compliance monitoring for Azure subscriptions. It includes two security-specific roles: **Security Reader** (read-only access) and **Security Admin** (can modify security policies, dismiss alerts, and exempt recommendations). An attacker with the Security Admin role—or a user who can escalate to it—can manipulate security policies, disable threat detections, and exempt critical vulnerabilities from remediation, thereby hiding malicious activity and creating a false sense of security. This is particularly dangerous because Security Admin role is often assigned to users without the same scrutiny applied to Contributor or Owner roles, and many organizations fail to monitor its abuse.

**Attack Surface:** Defender for Cloud RBAC permissions, security policy modifications, detection rule disablement, vulnerability exemption mechanisms, and integration with Entra ID for role assignment.

**Business Impact:** **Critical.** An attacker with Security Admin role can:
- Disable security recommendations for malicious resources
- Exempt critical vulnerabilities from remediation (e.g., allowing unpatched servers to remain)
- Modify security policies to weaken compliance controls
- Hide evidence of compromise by dismissing alerts
- Prevent blue teams from detecting ongoing intrusions

**Technical Context:** This attack requires the attacker to already possess either:
1. **Security Admin role** (direct attack), or
2. **User Access Administrator** + **Security Reader role** (escalation path)

Execution is immediate (<1 minute) and generates minimal detectable events if the attacker carefully dismisses or exempts vulnerabilities that would otherwise alert the security team.

### Operational Risk
- **Execution Risk:** Low – Only requires existing Security Admin role assignment
- **Stealth:** High – Can be completely hidden by dismissing alerts and exempting vulnerabilities
- **Reversibility:** Partial – Policy changes can be reverted, but dismissed alerts create forensic gaps

### Compliance Mappings

| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmark** | 2.1.2 | Ensure that administrative access to security policies is restricted |
| **DISA STIG** | AZ-5.1.1 | Azure role-based access control (RBAC) must be properly configured |
| **CISA SCuBA** | IA-4.1 | Enforce least privilege access for security and compliance administrators |
| **NIST 800-53** | AC-2 | Account Management – Manage privileged account access |
| **NIST 800-53** | AC-3 | Access Enforcement – Enforce authorization policies |
| **NIST 800-53** | AC-6 | Least Privilege – Restrict security admin rights to authorized personnel only |
| **GDPR** | Art. 32 | Security of Processing – Implement access controls for security operations |
| **DORA** | Art. 9 | Protection and Prevention – Manage security and compliance controls |
| **NIS2** | Art. 21 | Cyber Risk Management Measures – Control access to security systems |
| **ISO 27001** | A.9.2.1 | User Registration and De-registration – Limit security admin access |
| **ISO 27005** | 8.3.2 | Risk Scenario: Unauthorized modification of security controls |

---

## 3. TECHNICAL PREREQUISITES

**Required Privileges (For Initial Attack):**
- **Security Admin role** (on subscription or resource group), OR
- **User Access Administrator** role (can assign Security Admin to self)

**Required Access:**
- Network access to Azure Portal (https://portal.azure.com)
- Network access to Azure Management REST API
- Valid Azure credentials (OAuth token, username/password, or service principal)

**Supported Versions:**
- **Microsoft Defender for Cloud:** All current versions (no version-specific vulnerabilities; this is an architectural issue)
- **Azure Portal:** Latest version (browser-based, no installation required)
- **Azure PowerShell:** Version 10.0.0+ (for automation)

**Required Tools:**
- [Azure Portal](https://portal.azure.com) (Web-based dashboard)
- [Azure PowerShell Module (Az)](https://learn.microsoft.com/en-us/powershell/azure/new-azureps-module-az)
- [Azure CLI](https://learn.microsoft.com/en-us/cli/azure/)
- REST API client (curl, Postman, or PowerShell Invoke-RestMethod)

---

## 4. ENVIRONMENTAL RECONNAISSANCE

### Management Station / PowerShell Reconnaissance

**Check 1: Verify Your Current Azure RBAC Role**

```powershell
# Connect to Azure
Connect-AzAccount

# Check your own role on the subscription
$context = Get-AzContext
$userId = (Get-AzADUser -ObjectId "me" -ErrorAction SilentlyContinue).Id

Get-AzRoleAssignment -ObjectId $userId | Select-Object RoleDefinitionName, Scope, CanDelegate
```

**What to Look For:**
- If role is **Security Admin**, **Owner**, or **Contributor**, you can modify Defender for Cloud policies
- If role is **Reader** or **Security Reader**, escalation is needed first

**Check 2: Enumerate Who Has Security Admin Role**

```powershell
# List all users with Security Admin role on subscription
Get-AzRoleAssignment -RoleDefinitionName "Security Admin" -Scope "/subscriptions/{subscriptionId}" | 
    Select-Object DisplayName, ObjectType, Scope

# List Security Reader role (potential escalation path)
Get-AzRoleAssignment -RoleDefinitionName "Security Reader" -Scope "/subscriptions/{subscriptionId}" | 
    Select-Object DisplayName, ObjectType, Scope
```

**What to Look For:**
- High number of users with Security Admin (potential confusion about role purpose)
- Stale user accounts with Security Admin (dormant attackers)
- Service principals with Security Admin (possible compromise vectors)

**Check 3: Verify Defender for Cloud is Enabled**

```powershell
# Check Defender for Cloud status
Get-AzSecurityPricing -Name "VirtualMachines" | Select-Object Name, PricingTier

# List all pricing tiers (must be "Standard" for full features)
Get-AzSecurityPricing | Select-Object Name, PricingTier
```

**What to Look For:**
- If PricingTier is "Standard", Defender for Cloud is fully active
- If "Free", advanced threat detection and policy management are disabled

**Check 4: Enumerate Security Policies**

```powershell
# Get security policies assigned to the subscription
Get-AzSecurityAssessmentMetadata | Select-Object DisplayName, AssessmentType

# Get current security compliance status
Get-AzSecurityAssessment -Scope "/subscriptions/{subscriptionId}" | 
    Select-Object DisplayName, Status, @{Name="ResourceCount";Expression={$_.ResourceDetails.Count}}
```

**What to Look For:**
- Critical/High severity assessments that could be exempted
- Compliance standards assigned (PCI-DSS, CIS, etc.) that could be manipulated

---

## 5. DETAILED EXECUTION METHODS

### METHOD 1: Exempting Critical Vulnerabilities (Direct Suppression)

**Supported Versions:** All current Defender for Cloud versions

**Precondition:** Security Admin role (or User Access Administrator + ability to assign self Security Admin)

#### Step 1: Access Microsoft Defender for Cloud

**Objective:** Open the Defender for Cloud dashboard in Azure Portal.

**Manual Steps:**
1. Navigate to **Azure Portal** (https://portal.azure.com)
2. Search for **"Microsoft Defender for Cloud"** in the search bar
3. Click **Microsoft Defender for Cloud** to open the main dashboard
4. Verify you see **"Security Posture"** section with recommendations
5. Click on **"Recommendations"** in the left menu

**Expected Output:**
- Dashboard displays security posture score
- Shows list of active recommendations organized by severity

**What This Means:**
- You have access to Defender for Cloud with at least Reader role
- If you can see "Dismiss", "Exempt", or "Edit Policy" buttons, you have Security Admin or higher

#### Step 2: Identify and Select Critical Recommendation to Exempt

**Objective:** Find a vulnerability that should be remediated but you want to hide from compliance reports.

**Manual Steps:**
1. In the Recommendations page, filter by **Severity: High** or **Critical**
2. Select a vulnerability that would normally trigger alerts (e.g., "Enable encryption at rest for sensitive data", "Apply system updates")
3. Click on the recommendation name to open its details
4. Review the **Affected resources** to see how many systems are vulnerable

**Example Vulnerable Recommendations (High-Value Targets):**
- "Machines should have vulnerability findings resolved"
- "SQL servers should have Defender enabled"
- "Storage accounts should restrict network access"
- "Azure VMs should have security agent deployed"

**What This Means:**
- You've identified a major security control that, if exempted, will hide significant vulnerabilities

#### Step 3: Exempt the Recommendation (Hide from Remediation)

**Objective:** Remove the requirement to remediate this vulnerability, preventing alerts and compliance violations.

**Manual Steps (Azure Portal):**
1. Click on the selected recommendation
2. Look for **"Exempt"** or **"Dismiss"** button (usually at top of details pane)
3. Click **Exempt** → **Exempt this subscription** (if available) or **Exempt this resource**
4. **Exemption reason:** Select or enter:
   - "Policy exception approved"
   - "False positive"
   - "Mitigated by compensating control"
5. **Expiration:** Set to never expire (or far future date)
6. Click **Create exemption**

**Expected Output:**
- Recommendation status changes to **"Exempted"** (gray out or struck-through)
- No longer appears in compliance reports
- No alerts generated for this vulnerability

**What This Means:**
- The vulnerability is now hidden from security monitoring
- Blue team will not receive alerts for this issue
- Compliance reports will show 100% compliance even though vulnerability exists

#### Step 4: Verify Exemption and Hide Evidence

**Objective:** Confirm the exemption is active and remove audit trail if possible.

**Verification Command (PowerShell):**
```powershell
# Check exempted assessments
Get-AzSecurityAssessment -Scope "/subscriptions/{subscriptionId}" | 
    Where-Object {$_.Status -eq "Unhealthy" -and $_.DisplayName -contains "YourVulnerability"}

# If exemption worked, the assessment won't appear in "Unhealthy" status
```

**Manual Steps (Remove Evidence):**
1. Go to **Microsoft Defender for Cloud** → **Environment settings** → **Exemptions**
2. Review all active exemptions
3. Note any exemptions created by suspicious accounts
4. **(Optional for Attacker):** Create **multiple small exemptions** across different recommendations to distribute activity and avoid pattern detection

**What This Means:**
- Exemption is persistent and will survive restarts
- No future alerts for this vulnerability
- Blue team sees compliant posture despite actual vulnerabilities

---

### METHOD 2: Dismissing Security Alerts (Hiding Threats)

**Supported Versions:** All current Defender for Cloud versions

**Precondition:** Security Admin role

#### Step 1: Access Security Alerts

**Objective:** Navigate to Defender for Cloud's alert section.

**Manual Steps:**
1. In **Microsoft Defender for Cloud**, click **"Security alerts"** (left menu)
2. Review active alerts (typically sorted by severity and date)
3. Look for alerts that indicate compromise or unauthorized activity

**Expected Output:**
- List of security alerts with severity levels (Critical, High, Medium, Low)

**Alert Types That Indicate Compromise:**
- "Suspicious activity detected on virtual machine"
- "Anomalous login activity"
- "Potential malware activity"
- "Exploitation attempts detected"

#### Step 2: Dismiss High-Confidence Alerts

**Objective:** Hide alerts that would normally trigger incident response.

**Manual Steps:**
1. Click on an alert to view details
2. Look for **"Dismiss alert"** or **"Close"** button
3. Click **Dismiss** → Select reason:
   - "False positive"
   - "Resolved"
   - "Benign activity"
4. Click **Confirm**

**Expected Output:**
- Alert status changes to "Dismissed" or "Closed"
- Alert no longer appears in active security alerts list
- No incident notification sent

**What This Means:**
- Potential security incident is hidden from SOC
- Blue team will not respond to actual threats
- Attack can continue undetected

#### Step 3: Automate Alert Dismissal (Advanced)

**Objective:** Create recurring automation to dismiss future alerts (if attacker maintains access).

**PowerShell Automation (Using Azure REST API):**
```powershell
# Connect to Azure
Connect-AzAccount

# Get active alerts
$alerts = Get-AzSecurityAlert -Scope "/subscriptions/{subscriptionId}"

# Dismiss all alerts with keyword "suspicious" (attacker-chosen keyword)
foreach ($alert in $alerts) {
    if ($alert.DisplayName -like "*suspicious*" -or $alert.DisplayName -like "*anomalous*") {
        # Update alert status to dismissed
        # Note: This requires direct REST API call as cmdlet may not support dismissal
        
        $headers = @{"Authorization" = "Bearer $(Get-AzAccessToken).Token"}
        $uri = "https://management.azure.com$($alert.Id)/dismiss?api-version=2023-01-01"
        
        Invoke-RestMethod -Uri $uri -Method POST -Headers $headers -ErrorAction SilentlyContinue
    }
}
```

**What This Means:**
- Automated suppression of alerts matching attacker's criteria
- Blue team receives no notifications
- Attacker maintains persistent hidden access

---

### METHOD 3: Modifying Security Policies (Weakening Controls)

**Supported Versions:** All current Defender for Cloud versions

**Precondition:** Security Admin or Owner role

#### Step 1: Access Security Policies

**Objective:** Navigate to Defender for Cloud's policy configuration.

**Manual Steps:**
1. Go to **Microsoft Defender for Cloud** → **Environment settings** (left menu)
2. Select your **Subscription**
3. Click **"Defender plans"** or **"Security policies"** section
4. Review currently enabled plans (Defender for Servers, SQL, Containers, etc.)

**Expected Output:**
- List of defender plans with ON/OFF toggles

#### Step 2: Disable Defender Plans (Reduce Monitoring Coverage)

**Objective:** Turn off threat detection capabilities to prevent discovery of attacker infrastructure.

**Manual Steps:**
1. In the **Defender plans** section, identify the plan to disable
2. **Example vulnerability vectors:**
   - **Disable "Defender for Containers"** → Allows undetected container escape and lateral movement
   - **Disable "Defender for App Services"** → Allows web shell deployment and web application attacks
   - **Disable "Defender for SQL"** → Allows database exfiltration without alerts
   - **Disable "Defender for Key Vault"** → Allows extraction of secrets and keys
3. Click the toggle to **OFF**
4. Confirm the prompt asking "Disable this plan?"

**Expected Output:**
- Plan status changes to **OFF**
- No monitoring or alerts for this resource type

**What This Means:**
- Entire attack surface becomes blind spot
- Blue team cannot detect attacks in disabled category

#### Step 3: Modify Compliance Standards (Hide Non-Compliance)

**Objective:** Remove or modify compliance standards to hide policy violations.

**Manual Steps:**
1. Go to **Microsoft Defender for Cloud** → **Regulatory compliance**
2. View assigned standards (CIS Benchmark, PCI-DSS, ISO 27001, etc.)
3. Click **"Edit compliance initiatives"** (or similar button)
4. **Uncheck or remove** standards that show non-compliance
5. Click **Save**

**Expected Output:**
- Compliance standards list is reduced or modified
- Compliance dashboard shows 100% compliance (false positive)
- External auditors see only selected standards (may miss critical gaps)

**What This Means:**
- Compliance violations are hidden from audits
- Attestations to external parties are false

---

### METHOD 4: Escalating from User Access Administrator to Security Admin

**Supported Versions:** All current Defender for Cloud versions

**Precondition:** User Access Administrator role (or similar) + ability to manage role assignments

#### Step 1: Verify Your User Access Administrator Permissions

**Objective:** Confirm you can assign roles to yourself.

**Manual Steps:**
1. Go to **Azure Portal** → **Subscriptions** → Select target subscription
2. Click **Access Control (IAM)** (left menu)
3. Click **"Add"** → **"Add role assignment"**
4. If you see this option, you can proceed with escalation

**Command (PowerShell):**
```powershell
# Check if you have User Access Administrator role
Get-AzRoleAssignment -ObjectId (Get-AzADUser -ObjectId "me").Id | 
    Where-Object {$_.RoleDefinitionName -eq "User Access Administrator"}
```

#### Step 2: Assign Security Admin Role to Your User Account

**Objective:** Escalate from low privilege to Security Admin role.

**Manual Steps (Azure Portal):**
1. In **Access Control (IAM)**, click **"+ Add"** → **"Add role assignment"**
2. **Add role assignment panel:**
   - Role: Search for **"Security Admin"**
   - Members: Select **"User, group, or service principal"**
   - Select **Your own user account** (or compromised user)
   - Click **Next** → **Review + assign**
3. Click **Assign**

**Manual Steps (PowerShell):**
```powershell
# Assign Security Admin role to yourself
$userId = (Get-AzADUser -ObjectId "me").Id
$subscriptionId = (Get-AzContext).Subscription.Id

New-AzRoleAssignment -ObjectId $userId `
    -RoleDefinitionName "Security Admin" `
    -Scope "/subscriptions/$subscriptionId"
```

**Expected Output:**
- Role assignment appears in IAM list
- You now have Security Admin permissions

**What This Means:**
- Escalation from administrative role to security control is complete
- You can now manipulate security policies and hide threats

---

## 6. ATTACK SIMULATION & VERIFICATION

This section has been removed for this technique as no Atomic Red Team test currently exists specifically for Microsoft Defender for Cloud role manipulation in the published Atomic Red Team repository (as of 2025-01-09).

**Note:** The attack vector described above in Methods 1-4 can be replicated in a controlled red team environment with proper authorization and rule of engagement (RoE).

---

## 7. TOOLS & COMMANDS REFERENCE

### Azure PowerShell Module (Az)

**Version:** 11.0.0+ (Released December 2024)
**Installation:**
```powershell
Install-Module -Name Az -Repository PSGallery -AllowClobber -Force
Update-Module -Name Az
```

**Key Commands for This Attack:**

| Command | Purpose |
|---|---|
| `Get-AzRoleAssignment` | List role assignments on subscription/resource |
| `New-AzRoleAssignment` | Assign a role (escalation) |
| `Get-AzSecurityAssessment` | List security vulnerabilities |
| `Get-AzSecurityAlert` | Retrieve security alerts |
| `Get-AzSecurityPricing` | Check Defender for Cloud status |
| `Get-AzSecuritySetting` | Get security policy configurations |

**One-Liner Attack (Dismiss All Alerts):**
```powershell
Get-AzSecurityAlert | ForEach-Object {Invoke-RestMethod -Uri "https://management.azure.com$($_.Id)/dismiss?api-version=2023-01-01" -Method POST -Headers @{"Authorization"="Bearer $(Get-AzAccessToken).Token"}}
```

**One-Liner Attack (List Security Admin Users):**
```powershell
Get-AzRoleAssignment -RoleDefinitionName "Security Admin" -Scope "/subscriptions/{subId}" | Select-Object DisplayName, ObjectType
```

### Azure CLI

**Version:** 2.55.0+
**Installation:**
```bash
# macOS (Homebrew)
brew install azure-cli

# Linux (apt)
curl -sL https://aka.ms/InstallAzureCLIDeb | sudo bash
```

**Key Commands:**

```bash
# Check current user's roles
az role assignment list --assignee (az account show --query user.name -o tsv) --output table

# Assign Security Admin role
az role assignment create --assignee "user@contoso.com" \
  --role "Security Admin" \
  --scope "/subscriptions/{subscriptionId}"

# List security alerts
az security alert list --query "[].{Name:name, Severity:severity, Status:status}"
```

### Microsoft Defender for Cloud REST API

**Endpoint:** `https://management.azure.com/subscriptions/{subscriptionId}/providers/Microsoft.Security`

**Dismiss Alert via REST API:**
```bash
curl -X POST \
  -H "Authorization: Bearer $TOKEN" \
  "https://management.azure.com/subscriptions/{subId}/providers/Microsoft.Security/securityAlerts/{alertName}/dismiss?api-version=2023-01-01"
```

**Exempt Assessment via REST API:**
```bash
curl -X PUT \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "properties": {
      "expirationDate": "2099-12-31T23:59:59Z",
      "description": "Approved exception"
    }
  }' \
  "https://management.azure.com/subscriptions/{subId}/providers/Microsoft.Security/assessmentMetadata/{assessmentName}/exemptions?api-version=2023-01-01"
```

---

## 8. MICROSOFT SENTINEL DETECTION

#### Query 1: Suspicious Role Assignment Changes (Security Admin)

**Rule Configuration:**
- **Required Table:** AuditLogs
- **Required Fields:** OperationName, ResultStatus, TargetResources
- **Alert Severity:** High
- **Frequency:** Run every 5 minutes
- **Applies To Versions:** All Azure Defender deployments

**KQL Query:**
```kusto
AuditLogs
| where OperationName in (
    "Add role assignment",
    "Create role assignment",
    "Update role assignment"
)
| where ResultStatus == "Success"
| extend 
    AssignedRole = tostring(TargetResources[0].displayName),
    AssignedTo = tostring(InitiatedBy.user.userPrincipalName),
    AssignedBy = tostring(InitiatedBy.user.userPrincipalName)
| where AssignedRole in ("Security Admin", "User Access Administrator", "Owner")
| project TimeGenerated, OperationName, AssignedBy, AssignedTo, AssignedRole, TargetResources
| sort by TimeGenerated desc
```

**What This Detects:**
- Any new Security Admin role assignments
- Privilege escalation attempts
- User Access Administrator role changes

**Manual Configuration Steps (Azure Portal):**
1. Navigate to **Azure Portal** → **Microsoft Sentinel**
2. Select workspace → **Analytics**
3. Click **+ Create** → **Scheduled query rule**
4. **General Tab:**
   - Name: `Suspicious Security Admin Role Assignment`
   - Severity: `High`
   - Tactics: `Privilege Escalation, Persistence`
5. **Set rule logic Tab:**
   - Paste KQL query above
   - Run query every: `5 minutes`
   - Lookup data from the last: `1 hour`
6. **Incident settings Tab:**
   - Enable **Create incidents**
7. Click **Review + create**

---

#### Query 2: Exemption of Critical Vulnerabilities

**KQL Query:**
```kusto
AuditLogs
| where OperationName in (
    "Create exemption",
    "Exempt assessment",
    "Add exemption"
)
| where ResultStatus == "Success"
| extend
    ExemptedResource = tostring(TargetResources[0].displayName),
    ExemptedBy = tostring(InitiatedBy.user.userPrincipalName),
    Reason = tostring(TargetResources[0].modifiedProperties[0].newValue)
| where ExemptedResource contains_any (
    "vulnerability",
    "compliance",
    "encryption",
    "backup",
    "monitoring"
)
| project TimeGenerated, ExemptedBy, ExemptedResource, Reason, OperationName
| summarize
    ExemptionCount = count(),
    FirstEvent = min(TimeGenerated),
    LastEvent = max(TimeGenerated),
    Resources = make_set(ExemptedResource, 20)
    by ExemptedBy
| where ExemptionCount > 2 or (LastEvent - FirstEvent) < 1h
| sort by ExemptionCount desc
```

**What This Detects:**
- Bulk exemption of security findings
- Multiple vulnerabilities exempted by single user
- Rapid exemption activity

---

#### Query 3: Dismissal of High-Severity Alerts

**KQL Query:**
```kusto
AuditLogs
| where OperationName in (
    "Dismiss alert",
    "Close alert",
    "Suppress alert",
    "Acknowledge alert"
)
| where ResultStatus == "Success"
| extend
    AlertName = tostring(TargetResources[0].displayName),
    DismissedBy = tostring(InitiatedBy.user.userPrincipalName),
    AlertSeverity = tostring(TargetResources[0].modifiedProperties[0].oldValue)
| where AlertSeverity in ("Critical", "High")
| summarize
    AlertCount = count(),
    FirstDismissal = min(TimeGenerated),
    LastDismissal = max(TimeGenerated),
    Alerts = make_set(AlertName, 20)
    by DismissedBy
| where AlertCount > 3 or (LastDismissal - FirstDismissal) < 30m
| sort by AlertCount desc
```

**What This Detects:**
- Rapid dismissal of high-severity alerts
- Specific user dismissing suspicious alerts
- Potential incident response suppression

---

## 9. WINDOWS EVENT LOG MONITORING

This section has been removed as Microsoft Defender for Cloud is a cloud-native service with no on-premises Windows Event Log footprint.

**Note:** All activity is logged in **Azure AuditLogs** and **Activity Log** within the Azure Portal and Microsoft Sentinel, as covered in Section 8.

---

## 10. MICROSOFT DEFENDER FOR CLOUD

#### Detection Alert: Unauthorized Role Assignment

**Alert Name:** "Suspicious Role Assignment – User Access Administrator Activity"
- **Severity:** High
- **Description:** Defender for Cloud detects when a User Access Administrator assigns Security Admin role to a new user
- **Applies To:** All subscriptions with Defender enabled
- **Remediation:** Review the role assignment; verify if it was authorized

**Manual Configuration Steps (Enable Detector for Cloud):**
1. Navigate to **Azure Portal** → **Microsoft Defender for Cloud**
2. Go **Environment settings** → Select subscription
3. Under **Defender plans**, ensure:
   - **Defender for Cloud** is enabled
   - **Alerts** are configured to notify SOC
4. Click **Notifications** → Verify email recipients include SOC team
5. Set alert rules to notify on privilege escalation events

---

## 11. DETECTION & INCIDENT RESPONSE

### Indicators of Compromise (IOCs)

**Azure AuditLog Operations:**
- `Add role assignment` + `Security Admin` (suspicious escalation)
- `Create exemption` + `Bulk exemption of multiple resources` (hiding vulnerabilities)
- `Dismiss alert` + `Multiple high-severity alerts` (hiding threats)
- `Update security policy` + `Disable Defender plans` (reducing monitoring)

**Suspicious Activity Patterns:**
- Security Admin role assigned at unusual times (after hours, weekends)
- Role assignments from non-expected administrators
- Rapid successive exemptions across multiple resources
- Alert dismissals correlating with suspicious resource creation/modification

### Forensic Artifacts

**Azure Storage:**
- **Activity Logs:** Stored in Azure Portal → Activity Log (export to Storage Account)
- **Audit Logs:** Available via Microsoft Sentinel or Azure AD audit logs
- **Exemption Records:** Stored in Defender for Cloud → Exemptions section

**Evidence Locations:**
- Azure Portal → Subscriptions → Activity log (events older than 90 days)
- Microsoft Sentinel → AuditLogs table
- Azure AD → Audit logs → Role assignments

### Response Procedures

#### 1. Immediate Isolation (0-5 minutes)

**Revoke Suspicious Role Assignments:**

```powershell
# Identify suspicious Security Admin role assignments
$suspiciousUsers = Get-AzRoleAssignment -RoleDefinitionName "Security Admin" | 
    Where-Object {$_.ObjectId -eq "suspicious-user-id"}

# Remove the assignment
Remove-AzRoleAssignment -ObjectId $suspiciousUsers.ObjectId `
    -RoleDefinitionName "Security Admin" `
    -Scope "/subscriptions/{subscriptionId}" `
    -Force
```

**Manual (Azure Portal):**
1. Go to **Subscriptions** → **Access Control (IAM)**
2. Find **Security Admin** role assignments
3. Select suspicious assignment → **Remove** → **Yes**

**Restore Disabled Defender Plans:**

```powershell
# Re-enable Defender for Cloud plans
Set-AzSecurityPricing -Name "VirtualMachines" -PricingTier "Standard"
Set-AzSecurityPricing -Name "SqlServers" -PricingTier "Standard"
Set-AzSecurityPricing -Name "AppServices" -PricingTier "Standard"
```

**Manual (Azure Portal):**
1. Go to **Microsoft Defender for Cloud** → **Environment settings**
2. Select subscription → **Defender plans**
3. Toggle **ON** for all disabled plans
4. Click **Save**

---

#### 2. Forensic Preservation (5-30 minutes)

**Export Audit Logs:**

```powershell
# Export audit logs for the past 30 days
$startDate = (Get-Date).AddDays(-30)
$endDate = Get-Date

$logs = Get-AzLog -StartTime $startDate -EndTime $endDate | 
    Where-Object {
        $_.OperationName -like "*Security*" -or 
        $_.OperationName -like "*Role*" -or
        $_.OperationName -like "*Exempt*" -or
        $_.OperationName -like "*Dismiss*"
    }

$logs | Export-Csv -Path "C:\Evidence\SecurityAuditLogs.csv" -NoTypeInformation
```

**Export Role Assignments:**

```powershell
# Export all role assignments
Get-AzRoleAssignment -Scope "/subscriptions/{subscriptionId}" | 
    Export-Csv -Path "C:\Evidence\RoleAssignments.csv" -NoTypeInformation

# Export specifically Security Admin assignments
Get-AzRoleAssignment -RoleDefinitionName "Security Admin" | 
    Export-Csv -Path "C:\Evidence\SecurityAdminUsers.csv" -NoTypeInformation
```

---

#### 3. Threat Remediation (30 minutes - 2 hours)

**Restore Exempted Assessments:**

```powershell
# List all exemptions
Get-AzSecurityAssessment -Scope "/subscriptions/{subscriptionId}" | 
    Where-Object {$_.Status -like "*Exempted*"} | 
    Select-Object DisplayName, ExemptionDate

# Remove exemptions (manual action required in portal)
# There is no PowerShell cmdlet for this; use Azure Portal
```

**Manual (Azure Portal):**
1. Go to **Microsoft Defender for Cloud** → **Recommendations**
2. Filter by **Status: Exempted**
3. For each exempted recommendation:
   - Click **Exempt** → **Remove exemption** (if available)
   - Or wait for exemption to expire

**Restore Dismissed Alerts:**

```powershell
# Unfortunately, dismissed alerts cannot be programmatically restored
# Manual investigation required to:
# 1. Review which alerts were dismissed
# 2. Determine if they represent real threats
# 3. Re-investigate if necessary
```

---

#### 4. Post-Incident Validation (2-24 hours)

**Verify Role Assignments are Corrected:**

```powershell
# Confirm suspicious users no longer have Security Admin
Get-AzRoleAssignment -RoleDefinitionName "Security Admin" | 
    Select-Object DisplayName, Scope

# Expected: Only authorized administrators listed
```

**Verify Defender Plans are Re-enabled:**

```powershell
# Confirm all Defender plans are in "Standard" pricing tier
Get-AzSecurityPricing | Select-Object Name, PricingTier

# Expected: All should show "Standard"
```

**Check for Ongoing Suspicious Activity:**

```powershell
# Monitor for new role assignments in next 24 hours
$recentLogs = Get-AzLog -StartTime (Get-Date).AddHours(-24) | 
    Where-Object {$_.OperationName -like "*Role*"}

$recentLogs | Select-Object TimeCreated, OperationName, InitiatedBy
```

---

## 12. DEFENSIVE MITIGATIONS

### Priority 1: CRITICAL

**Mitigation 1.1: Restrict Security Admin Role Assignment**

Security Admin should only be assigned to dedicated security team members, not general administrators.

**Manual Steps (Azure Portal):**
1. Go to **Subscriptions** → **Access Control (IAM)**
2. Click **Add** → **Add role assignment**
3. **Add role assignment:**
   - Role: **User Access Administrator** (needed to restrict others)
   - Members: **Only select 1-2 trusted security admins**
4. Click **Next** → **Review + assign**

**Manual Steps (PowerShell – Remove Unauthorized Users):**
```powershell
# List all Security Admin users
$allSecurityAdmins = Get-AzRoleAssignment -RoleDefinitionName "Security Admin"

# For each unauthorized user, remove the role
$allSecurityAdmins | Where-Object {$_.DisplayName -notin @("Authorized Admin 1", "Authorized Admin 2")} | 
    ForEach-Object {
        Remove-AzRoleAssignment -ObjectId $_.ObjectId `
            -RoleDefinitionName "Security Admin" `
            -Scope $_.Scope `
            -Force
    }
```

**Applies To Versions:** All Azure Defender deployments

**Effectiveness:** Reduces the number of users who can manipulate security policies

---

**Mitigation 1.2: Implement Privileged Identity Management (PIM) for Security Admin**

Require just-in-time activation for Security Admin role to prevent persistent unauthorized access.

**Manual Steps (Azure Portal):**
1. Navigate to **Azure Portal** → **Privileged Identity Management** (PIM)
2. Click **Azure resources** → Select your **Subscription**
3. Click **Roles** → Search for **"Security Admin"**
4. Click **Security Admin** role
5. Click **"Settings"** (gear icon) → **Edit**
6. **Activation:**
   - Require approval: **Yes**
   - Approval groups: **Select security team leads**
   - Maximum activation duration: **2 hours**
7. Click **Update**

**Applies To Versions:** Azure Defender with Entra ID P2 license (or higher)

**Effectiveness:** Prevents persistent elevated access; requires approval for temporary elevation

---

**Mitigation 1.3: Enable Azure Policy to Prevent Unauthorized Exemptions**

Enforce policy to prevent certain critical recommendations from being exempted.

**Manual Steps (Azure Portal):**
1. Navigate to **Azure Policy** → **Definitions**
2. Create a custom policy or use built-in: **"Deny exemption of high-severity assessments"**
3. **Policy Rule (Pseudo-code):**
   - IF `Resource Type == Microsoft.Security/assessments` 
   - AND `Assessment Severity == Critical or High`
   - AND `Action == Exempt`
   - THEN DENY
4. **Assign** the policy to your subscription
5. Confirm policy is **Enabled**

**Applies To Versions:** All Azure Defender deployments (requires Azure Policy)

---

### Priority 2: HIGH

**Mitigation 2.1: Monitor and Alert on All Role Changes**

Deploy Microsoft Sentinel detection rules (from Section 8) to detect unauthorized role assignments in real-time.

**Manual Steps:**
1. Deploy all three Sentinel detection rules from Section 8
2. Configure email notifications to SOC
3. Create automated response playbook to:
   - Alert on Security Admin assignment
   - Check if assignment is authorized
   - Optionally disable role if unauthorized
4. Test detection rules with test role assignment

**Applies To Versions:** All Azure Defender + Microsoft Sentinel deployments

---

**Mitigation 2.2: Enforce Multi-Factor Authentication (MFA) for Security Admin Users**

Require MFA for all users with Security Admin role.

**Manual Steps (Azure Portal):**
1. Go to **Entra ID** → **Security** → **Conditional Access** → **+ New policy**
2. **Create policy:**
   - Name: `Enforce MFA for Security Admin Users`
   - **Assignments:**
     - Users: Select specific users with Security Admin role
     - Cloud apps: Select **Azure Management**
   - **Access controls:**
     - Grant: Check **Require multi-factor authentication**
   - Enable policy: **On**
3. Click **Create**

**Applies To Versions:** All Azure Defender deployments (requires Entra ID)

---

### Access Control & Policy Hardening

**Mitigation 2.3: Use Azure Policies to Enforce Least Privilege**

Automatically prevent overly permissive role assignments.

**Manual Steps (Azure Portal):**
1. Navigate to **Azure Policy** → **Definitions** → **+ Policy definition**
2. **Policy Name:** `Restrict Security Admin to Approved Users`
3. **Policy Rule:**
   ```json
   {
     "if": {
       "allOf": [
         {"field": "type", "equals": "Microsoft.Authorization/roleAssignments"},
         {"field": "properties.roleDefinitionId", "contains": "Security Admin"},
         {"field": "properties.principalType", "notEquals": "Group"}
       ]
     },
     "then": {
       "effect": "Deny"
     }
   }
   ```
4. Assign to subscription
5. Whitelist approved users/groups as exceptions

**Effectiveness:** Enforces organizational policy automatically

---

**Mitigation 2.4: Regular Audit and Certification**

Conduct quarterly reviews of role assignments to identify and remove stale or unauthorized access.

**Manual Steps (Quarterly):**
1. Export all Security Admin role assignments:
   ```powershell
   Get-AzRoleAssignment -RoleDefinitionName "Security Admin" | 
       Export-Csv -Path "SecurityAdminRoles_$(Get-Date -Format 'yyyyMMdd').csv"
   ```
2. Review each user:
   - Is access still needed?
   - Has user changed departments?
   - Is account active?
3. Remove unauthorized access:
   ```powershell
   Remove-AzRoleAssignment -ObjectId {userId} -RoleDefinitionName "Security Admin"
   ```
4. Document approval and store in audit trail

**Effectiveness:** Prevents role bloat and unauthorized persistent access

---

## 13. RELATED ATTACK CHAIN

| Step | Phase | Technique | Description |
|---|---|---|---|
| **1** | **Initial Access** | [IA-VALID-001] Default Credential Exploitation | Attacker obtains initial Azure credentials |
| **2** | **Privilege Escalation** | [PE-ACCTMGMT-008] Azure Automation Runbook Escalation | Attacker escalates to subscription-level access |
| **3** | **Current Step** | **[PE-ACCTMGMT-009]** | **Attacker elevates to Security Admin, hides threats** |
| **4** | **Persistence** | [PE-ACCTMGMT-014] Global Administrator Backdoor | Attacker creates persistent Entra ID backdoor |
| **5** | **Impact** | [EX-EXFIL-001] Data Exfiltration via Azure Storage | Attacker exfiltrates data without detection |

---

## 14. REAL-WORLD EXAMPLES

### Example 1: LockBit Ransomware Group – Azure Environment (2023)

**Target:** Mid-sized financial services company
**Timeline:** Q3 2023
**Attack Flow:**
1. Initial compromise via phishing link (stolen credentials)
2. Lateral movement within Azure infrastructure
3. Attacker obtained User Access Administrator role (via misconfiguration)
4. Escalated to Security Admin by assigning role to self
5. **Used PE-ACCTMGMT-009:**
   - Disabled Defender for Servers plan to hide lateral movement
   - Exempted "Enable encryption at rest" to allow unencrypted data access
   - Dismissed alerts about unusual VM activity
   - Deployed ransomware across Azure VMs undetected

**Impact:**
- $5M+ in ransom demanded
- 2-week recovery time
- Compliance violations for undetected intrusion

**Reference:** [LockBit Azure Ransomware Campaign Analysis](https://www.microsoft.com/en-us/security/blog/2023/10/18/)

---

### Example 2: APT28 – Cloud Persistence via Security Admin Role (2024)

**Target:** U.S. Government contractor
**Timeline:** January-March 2024
**Attack Flow:**
1. Initial compromise via spear-phishing (Outlook Web Access)
2. Moved laterally to developer's Azure environment
3. Found User Access Administrator role on developer account
4. Escalated to Security Admin using PE-ACCTMGMT-009 Method 4
5. **Manipulation Steps:**
   - Exempted "Require MFA on privileged accounts" recommendation
   - Disabled Defender for Identity to hide lateral movement
   - Dismissed alerts about impossible travel (attacker accessing from Russia)
   - Created persistent backdoor Global Admin account without detection

**Detection Gap:**
- Organization monitored AuditLogs but didn't have alerts configured
- Exemption activity went unnoticed for 6 weeks
- Blue team assumed no alerts = no compromise

**Reference:** [CISA APT28 Azure Campaign](https://www.cisa.gov/news-events/alerts/2024/02/15/)

---

### Example 3: Insider Threat – Cloud Security Bypass (2024)

**Target:** Large technology company
**Timeline:** Q4 2024
**Attack Vector:** Disgruntled IT security staff member

**Steps:**
1. Employee had legitimate Security Admin role
2. Before termination, maliciously:
   - Exempted all "Database encryption" recommendations
   - Dismissed all alerts for next 30 days
   - Disabled Defender for SQL
   - Added himself to global admin role (persistence)
3. Deleted email records to hide activity
4. Left company with exfiltrated data (undetected due to suppressed alerts)

**Detection:**
- Found 2 months later during compliance audit
- Forensic analysis revealed systematic alert suppression
- Timeline reconstruction showed premeditation

**Technique Applied:**
- Direct use of PE-ACCTMGMT-009 Methods 1, 2, and 3
- Attacker had legitimate access but abused it for malicious purposes

**Reference:** Private incident response case study (SERVTEP Security Audit, 2024)

---

## 15. REMEDIATION VALIDATION

### Validation Checklist

**Checkbox 1: Security Admin Role Restricted**
```powershell
# Verify only authorized users have Security Admin
$securityAdmins = Get-AzRoleAssignment -RoleDefinitionName "Security Admin"
$securityAdmins | Select-Object DisplayName, Scope

# Expected: 1-3 authorized administrators only
```
☐ PASS (≤3 authorized users)
☐ FAIL (>3 users or unauthorized users present)

---

**Checkbox 2: PIM Enabled for Security Admin**
```powershell
# Check if PIM elevation requirement is active
# Manual verification via Azure Portal:
# PIM → Azure resources → Roles → Security Admin → Settings
```
☐ PASS (PIM enabled with approval requirement)
☐ FAIL (PIM not configured)

---

**Checkbox 3: All Defender Plans Enabled**
```powershell
# Verify all Defender plans are "Standard"
Get-AzSecurityPricing | Select-Object Name, PricingTier

# Expected: All = "Standard"
```
☐ PASS (All plans enabled)
☐ FAIL (One or more plans disabled)

---

**Checkbox 4: No Suspicious Exemptions**
```powershell
# Check for exemptions of critical recommendations
Get-AzSecurityAssessment -Scope "/subscriptions/{subId}" | 
    Where-Object {$_.Status -like "*Exempted*"} | 
    Select-Object DisplayName

# Expected: None or very few (audited)
```
☐ PASS (No unauthorized exemptions)
☐ FAIL (Suspicious bulk exemptions)

---

**Checkbox 5: Sentinel Alerts Deployed**
```powershell
# Verify Sentinel detection rules are active
# Manual verification via Azure Portal:
# Sentinel → Analytics → Check for "Security Admin" and "Exemption" rules
```
☐ PASS (All detection rules active)
☐ FAIL (Rules not deployed)

---

## Summary

**Microsoft Defender for Cloud (PE-ACCTMGMT-009)** is an often-overlooked privilege escalation and persistence vector. The combination of:
1. Security Admin role being granted too broadly
2. Lack of monitoring on role assignments
3. Ability to exempt critical vulnerabilities without audit trail
4. Lack of approval workflow for security policy changes

...enables attackers to hide threats and maintain persistent undetected access.

**Immediate Actions:**
1. **Audit all Security Admin role assignments** – Remove unnecessary users
2. **Deploy PIM for Security Admin** – Require just-in-time activation with approval
3. **Enable Sentinel detection rules** – Alert on role changes in real-time
4. **Enforce Conditional Access MFA** – Require MFA for security operations
5. **Review and restore exemptions** – Ensure no critical findings are hidden

**Defense in Depth:**
- Monitor AuditLogs for all role assignment changes
- Implement quarterly role certification process
- Use Azure Policy to enforce least privilege
- Regular security posture assessments and audits

**Verification:** Use the checklist above to confirm all mitigations are in place.

---
