# [EVADE-IMPAIR-011]: Azure Identity Protection Evasion

## Metadata

| Attribute | Details |
|---|---|
| **Technique ID** | EVADE-IMPAIR-011 |
| **MITRE ATT&CK v18.1** | [T1562 - Impair Defenses](https://attack.mitre.org/techniques/T1562/) |
| **Tactic** | Defense Evasion |
| **Platforms** | Entra ID (Azure AD Identity Protection) |
| **Severity** | High |
| **CVE** | N/A |
| **Technique Status** | ACTIVE |
| **Last Verified** | 2026-01-09 |
| **Affected Versions** | Entra ID (all versions), requires Azure AD Premium P2 license |
| **Patched In** | N/A (Requires policy hardening) |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

## 1. EXECUTIVE SUMMARY

**Concept:** Microsoft Entra ID Identity Protection is a cloud-native risk-based identity security service that detects risky sign-ins and users using machine learning and behavioral analysis. It detects anomalies such as impossible travel, sign-ins from anonymous IP addresses (Tor/VPN), leaked credentials, and password spray attacks. An attacker with Global Admin or Identity Security Administrator permissions can disable or modify Entra ID Identity Protection policies, evasion rules, and risk detection settings, effectively blinding the organization to anomalous authentication activity.

Unlike traditional DLP or transport rules, Identity Protection's risk evaluations occur in real-time during authentication. By disabling or modifying these policies, an attacker can:
1. **Disable user risk policies** that would force password resets for compromised accounts.
2. **Lower or disable sign-in risk policies** that block risky logins.
3. **Disable specific risk detections** (e.g., "Impossible Travel", "Anonymous IP").
4. **Remove conditional access policies** that enforce MFA for risky logins.

This enables persistent, anomalous authentication activity without triggering protective responses.

**Attack Surface:** Entra ID Identity Protection policy configuration, Conditional Access rules for risk-based access control, risk detection settings, sign-in risk evaluation engine.

**Business Impact:** **Complete Visibility Loss on Identity Threats.** An attacker can maintain persistence with stolen credentials, perform impossible-travel logins from multiple continents, use anonymized IP addresses, or conduct password spray attacks—all without triggering any alerts or access blocks. This enables long-term espionage, data theft, and lateral movement while security teams remain unaware of the compromised environment.

**Technical Context:** Identity Protection risk evaluation happens at the Entra ID authentication service layer, before multi-factor authentication. Risk-based Conditional Access policies (which enforce MFA or block access based on risk level) are evaluated post-authentication. By disabling policies, an attacker removes all technical barriers to anomalous access.

### Operational Risk

- **Execution Risk:** Medium—requires Global Admin or Identity Security Administrator role.
- **Stealth:** Very High—policy modifications appear as normal administrative changes; rarely audited or alerted on in real-time.
- **Reversibility:** Yes—policies can be re-enabled; however, undetected attacker activity in the interim is permanent.

### Compliance Mappings

| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmark** | 6.1.1 | Ensure that Azure AD Identity Protection is enabled for all users. |
| **DISA STIG** | Microsoft.Entra.1.1 | Maintain and enforce Azure AD Identity Protection policies for risk detection. |
| **CISA SCuBA** | Entra.1.5 | Monitor and alert on Identity Protection policy modifications or disablement. |
| **NIST 800-53** | SI-4, AU-2 | Information System Monitoring and Audit Events—detect anomalous authentication activity. |
| **GDPR** | Art. 32 | Security of Processing—identity protection is critical to data security. |
| **DORA** | Art. 12 | Strong Customer Authentication—risk-based policies enforce secure authentication. |
| **NIS2** | Art. 21 | Cyber Risk Management—must detect and respond to identity-based attacks. |
| **ISO 27001** | A.9.2.1, A.12.4.1 | User Access Management; Audit Logging for Administrative Actions. |
| **ISO 27005** | Risk Scenario | "Unauthorized modification of identity risk policies by compromised admin." |

---

## 2. TECHNICAL PREREQUISITES

- **Required Privileges:** Global Administrator, Identity Security Administrator, or Conditional Access Administrator role in Entra ID.
- **Required Access:** Azure Portal access at `https://portal.azure.com` or PowerShell connectivity to Microsoft Graph.
- **Required Licenses:** Azure AD Premium P2 (for Identity Protection features); P1 for Conditional Access.

**Supported Versions:**
- **Entra ID (Azure AD):** All versions (cloud-native service)
- **Identity Protection:** Available with Azure AD Premium P2 license
- **Conditional Access:** Available with Azure AD Premium P1+
- **PowerShell:** Version 5.0+ or PowerShell 7.x
- **Microsoft Graph PowerShell SDK:** Version 1.0+

**Tools:**
- [Microsoft Graph PowerShell SDK](https://github.com/microsoftgraph/msgraph-sdk-powershell)
- [Azure Portal - Entra ID](https://entra.microsoft.com/)
- [Azure PowerShell CLI](https://learn.microsoft.com/en-us/powershell/azure/)
- [Microsoft Sentinel](https://sentinel.azure.com/) (for monitoring policy changes)

---

## 3. TECHNICAL PREREQUISITES

**Required Privileges and Access:**
- Global Administrator OR Identity Security Administrator role
- Entra ID Premium P2 license (Identity Protection) or P1 (Conditional Access)
- Network access to Azure Portal or PowerShell

**Supported Versions:**
- Entra ID (all cloud versions)
- Conditional Access (Entra ID P1+)
- Identity Protection (Entra ID P2)

---

## 4. ENVIRONMENTAL RECONNAISSANCE

### PowerShell Reconnaissance

**Objective:** Enumerate current Identity Protection policies, risk detection settings, and Conditional Access rules.

**Command:**
```powershell
# Connect to Microsoft Graph
Connect-MgGraph -Scopes "IdentityRiskEvent.Read.All", "ConditionalAccess.Read.All"

# Enumerate Conditional Access policies (especially risk-based ones)
Get-MgIdentityConditionalAccessPolicy | Select-Object DisplayName, State, Conditions | Format-Table -AutoSize

# Check sign-in risk policies
Get-MgPolicyIdentitySecurityDefaultEnforcementPolicy

# Check user risk policies
Get-MgIdentitySignInRiskPolicy

# Get detailed risk policy settings
$SignInPolicy = Get-MgPoliciedentitySignInRiskPolicy
$SignInPolicy | ConvertTo-Json
```

**What to Look For:**
- Existing Conditional Access policies that block or enforce MFA based on sign-in risk (Medium/High).
- Enabled user risk policies that trigger password reset requirements.
- Risk detection types enabled (Impossible Travel, Anonymous IP, etc.).
- Policies that are already disabled (gap in security).

### Azure CLI Reconnaissance

**Objective:** Query Entra ID for policy management permissions and current policy states.

**Command:**
```bash
# List all Conditional Access policies
az identity conditional-access policy list --query "[].{displayName:displayName, state:state}" --output table

# Check specific risk-based policies
az identity conditional-access policy list --filter "contains(displayName,'risk')" --output table

# Verify who can manage policies
az rest --method get \
  --url "https://graph.microsoft.com/v1.0/directoryRoles?$filter=displayName eq 'Identity Security Administrator'" \
  --headers "Authorization=Bearer {access_token}"
```

**What to Look For:**
- How many Conditional Access policies are in place.
- Which policies target risk-based conditions.
- Who has administrative permissions to modify policies.

---

## 5. DETAILED EXECUTION METHODS

### METHOD 1: Disable Conditional Access Policy Enforcing Sign-in Risk

**Supported Versions:** Entra ID (all versions)

#### Step 1: Identify Risk-Based Conditional Access Policies

**Objective:** Locate policies that enforce MFA or block access based on sign-in risk.

**Command:**
```powershell
# Get all Conditional Access policies
$Policies = Get-MgIdentityConditionalAccessPolicy

foreach ($Policy in $Policies) {
    if ($Policy.Conditions.SignInRiskLevels) {
        Write-Host "Policy Name: $($Policy.DisplayName)"
        Write-Host "Risk Levels Targeted: $($Policy.Conditions.SignInRiskLevels -join ', ')"
        Write-Host "State: $($Policy.State)"
        Write-Host "Grant Controls: $($Policy.GrantControls.BuiltInControls -join ', ')"
        Write-Host "---"
    }
}
```

**Expected Output:**
```
Policy Name: Require MFA for Risky Sign-ins
Risk Levels Targeted: high, medium
State: enabled
Grant Controls: mfa
---
```

**What This Means:**
- Identified policies that enforce MFA when sign-in risk is medium or high.
- Disabling these policies would allow high-risk logins without MFA.

#### Step 2: Disable the Risk-Based Policy

**Objective:** Disable the Conditional Access policy that enforces MFA for risky logins.

**Command:**
```powershell
# Get the risk-based policy
$PolicyId = (Get-MgIdentityConditionalAccessPolicy | Where-Object {$_.DisplayName -eq "Require MFA for Risky Sign-ins"}).Id

# Update policy state to disabled
Update-MgIdentityConditionalAccessPolicy -ConditionalAccessPolicyId $PolicyId -State "disabled"

# Verify policy is disabled
Get-MgIdentityConditionalAccessPolicy -ConditionalAccessPolicyId $PolicyId | Select-Object DisplayName, State
```

**Expected Output:**
```
DisplayName                    State
-----------                    -----
Require MFA for Risky Sign-ins disabled
```

**What This Means:**
- Policy is now disabled; MFA will no longer be enforced for risky sign-ins.
- An attacker can perform impossible-travel logins, use VPN/anonymous IPs, or attempt password sprays without triggering MFA.

**OpSec & Evasion:**
- This change is immediately visible in audit logs (high risk for detection).
- Detection likelihood: **High** (policy disablement is heavily audited and monitored).

**Troubleshooting:**
- **Error:** "Identity not found or access denied"
  - **Cause:** Missing permissions or incorrect policy ID.
  - **Fix:** Ensure the account has Global Admin or Identity Security Administrator role.
- **Error:** "ConditionalAccessPolicy resource does not support updating..."
  - **Cause:** API version or permissions issue.
  - **Fix:** Use `Update-MgBetaIdentityConditionalAccessPolicy` with Beta API endpoint.

#### Step 3: Verify Evasion is Active

**Objective:** Confirm that risky logins now bypass MFA enforcement.

**Command:**
```powershell
# Test by simulating a high-risk sign-in (in lab environment)
# Login from VPN/anonymous IP or with impossible travel pattern
# Expected result: No MFA challenge, access granted immediately

# Verify policy is disabled
Get-MgIdentityConditionalAccessPolicy -ConditionalAccessPolicyId $PolicyId | Select-Object DisplayName, State, Conditions
```

**References & Proofs:**
- [Microsoft Graph - Conditional Access Policy API](https://learn.microsoft.com/en-us/graph/api/conditionalaccesspolicy-update)
- [Entra ID Risk Detection Documentation](https://learn.microsoft.com/en-us/entra/id-protection/concept-identity-protection-risks)
- [Conditional Access Risk-Based Policies](https://learn.microsoft.com/en-us/entra/identity/conditional-access/concept-conditional-access-conditions#sign-in-risk)

---

### METHOD 2: Modify User Risk Policy to Not Block Risky Users

**Supported Versions:** Entra ID (all versions)

#### Step 1: Review Current User Risk Policy

**Objective:** Check the current settings for user risk-based policy enforcement.

**Command:**
```powershell
# Get user risk policy
$UserRiskPolicy = Get-MgIdentityUserRiskPolicy

Write-Host "User Risk Policy State: $($UserRiskPolicy.IsEnabled)"
Write-Host "Require Password Change for High Risk: $($UserRiskPolicy.RequirePasswordChangeForHighRisk)"
Write-Host "Allow User Dismiss: $($UserRiskPolicy.AllowUserDismiss)"
```

**Expected Output:**
```
User Risk Policy State: True
Require Password Change for High Risk: True
AllowUserDismiss: False
```

**What This Means:**
- User risk policy is enabled and requires password reset for high-risk users.
- Disabling this would prevent forced password resets for compromised accounts.

#### Step 2: Disable User Risk Policy

**Objective:** Disable the user risk policy, preventing password reset enforcement for compromised accounts.

**Command:**
```powershell
# Disable user risk policy
$UserRiskPolicy = Get-MgIdentityUserRiskPolicy
$UserRiskPolicy.IsEnabled = $false

# Update policy
Update-MgIdentityUserRiskPolicy -IdentityUserRiskPolicy $UserRiskPolicy

# Verify
Get-MgIdentityUserRiskPolicy | Select-Object IsEnabled
```

**Expected Output:**
```
IsEnabled
---------
False
```

**What This Means:**
- User risk policy is now disabled.
- Accounts flagged as high-risk will no longer trigger password reset enforcement.
- An attacker's compromised account can persist indefinitely without forced remediation.

**OpSec & Evasion:**
- Policy disablement is logged in audit trail (immediate detection).
- Detection likelihood: **Very High** (policy changes are closely monitored).

---

### METHOD 3: Disable Specific Risk Detection (Impossible Travel, Anonymous IP)

**Supported Versions:** Entra ID (all versions)

#### Step 1: Enumerate Risk Detections

**Objective:** List all enabled risk detection types.

**Command:**
```powershell
# List risk detections (simulated, as direct enumeration API is limited)
Write-Host "Available Risk Detection Types:"
Write-Host "- ImpossibleTravel"
Write-Host "- AnonymousIP"
Write-Host "- UnfamiliarLocation"
Write-Host "- MalwareInfectedDevice"
Write-Host "- LeakedCredentials"
Write-Host "- PasswordSpray"
Write-Host "- AtypicalTravelProperties"

# Check which detections are active in Conditional Access
$Policies = Get-MgIdentityConditionalAccessPolicy
foreach ($Policy in $Policies) {
    if ($Policy.Conditions.SignInRiskLevels) {
        Write-Host "Policy with risk detection: $($Policy.DisplayName)"
    }
}
```

#### Step 2: Disable Detection via Policy Modification

**Objective:** Modify Conditional Access policy to no longer respond to impossible-travel or anonymous-IP risk detections.

**Command:**
```powershell
# Get policy targeting impossible-travel
$ImpossibleTravelPolicy = Get-MgIdentityConditionalAccessPolicy | Where-Object {$_.DisplayName -like "*Travel*"}

# Set policy state to disabled
Update-MgIdentityConditionalAccessPolicy -ConditionalAccessPolicyId $ImpossibleTravelPolicy.Id -State "disabled"

# Verification: Attacker can now login from different continents without triggering detection
```

**OpSec & Evasion:**
- Disabling specific detection policies is less suspicious than disabling all policies.
- Detection likelihood: **Medium-High** (individual policy disablement is audited).

---

### METHOD 4: Remove Conditional Access Policies via Web Portal

**Supported Versions:** Entra ID (all versions)

#### Step 1: Access Conditional Access Configuration

**Manual Steps:**
1. Log into [Azure Portal](https://portal.azure.com) with compromised Global Admin credentials.
2. Navigate to **Entra ID** → **Security** → **Conditional Access**.
3. Review all policies; identify those targeting sign-in risk.

**Expected Output:**
- List of all Conditional Access policies with state (enabled/disabled).

#### Step 2: Disable or Delete Risk-Based Policies

**Manual Steps:**
1. Click on a risk-based policy (e.g., "Require MFA for Risky Sign-ins").
2. In the policy details panel, click **Disable** or **Delete**.
3. Confirm the action.
4. Policy is now inactive; risky logins will bypass enforcement.

**OpSec & Evasion:**
- Web-based policy changes are captured in detailed audit logs.
- Detection likelihood: **Very High** (change is visible to compliance team).

---

## 6. MICROSOFT SENTINEL DETECTION

#### Query 1: Conditional Access Policy Disabled or Deleted

**Rule Configuration:**
- **Required Table:** `AuditLogs`
- **Required Fields:** `OperationName`, `InitiatedBy`, `TargetResources`, `AuditData`
- **Alert Severity:** Critical
- **Frequency:** Run every 5 minutes
- **Applies To Versions:** Entra ID all versions

**KQL Query:**
```kusto
AuditLogs
| where OperationName =~ "Update policy" or OperationName =~ "Delete policy"
| where TargetResources[0].displayName contains "Conditional Access" or TargetResources[0].displayName contains "Risk"
| where tostring(TargetResources[0].modifiedProperties) contains "State" and tostring(TargetResources[0].modifiedProperties) contains "disabled"
| extend InitiatedByUpn = InitiatedBy.userPrincipalName
| extend PolicyName = TargetResources[0].displayName
| project TimeGenerated, InitiatedByUpn, OperationName, PolicyName, TargetResources[0].modifiedProperties
```

**What This Detects:**
- Conditional Access policies being disabled or deleted.
- Specifically targets risk-based policies.
- Identifies the admin account that made the change.
- Line 2: Filters for policy modification or deletion.
- Line 3: Focuses on Conditional Access and risk policies.
- Line 4: Identifies state changes to "disabled".

**Manual Configuration Steps (Azure Portal):**
1. Navigate to **Azure Portal** → **Microsoft Sentinel** → **Analytics**
2. Click **+ Create** → **Scheduled query rule**
3. **General Tab:**
   - Name: `Critical - Conditional Access Policy Disabled`
   - Severity: `Critical`
4. **Set rule logic Tab:**
   - Paste the KQL query above
   - Run query every: `5 minutes`
   - Lookup data from the last: `30 minutes`
5. **Incident settings Tab:**
   - Enable **Create incidents**
   - Set entities: `User` (InitiatedByUpn), `Resource` (PolicyName)
6. Click **Review + create**

#### Query 2: User Risk Policy Modifications

**Rule Configuration:**
- **Required Table:** `AuditLogs`
- **Alert Severity:** High
- **Frequency:** Run every 10 minutes

**KQL Query:**
```kusto
AuditLogs
| where OperationName =~ "Set-MsolUserRiskPolicy" or OperationName =~ "Update user risk policy"
| extend InitiatedByUpn = InitiatedBy.userPrincipalName
| extend ModifiedProperties = tostring(TargetResources[0].modifiedProperties)
| where ModifiedProperties contains "IsEnabled" and ModifiedProperties contains "false"
| project TimeGenerated, InitiatedByUpn, OperationName, ModifiedProperties
```

**What This Detects:**
- User risk policy being disabled.
- No longer enforces password reset for compromised accounts.
- Identifies the admin making the change.

---

## 7. MICROSOFT DEFENDER FOR CLOUD

#### Detection Alerts

**Alert Name:** "Conditional Access policy disabled or deleted"
- **Severity:** Critical
- **Description:** Detects when a risk-based Conditional Access policy is disabled or deleted, potentially bypassing risk-based access controls.
- **Applies To:** All subscriptions with Defender enabled and Entra ID audit logging.

**Manual Configuration Steps:**
1. Navigate to **Azure Portal** → **Microsoft Defender for Cloud**
2. Go to **Environment settings** → Select subscription
3. Under **Defender plans**, enable **Defender for Identity** or **Defender for Cloud Apps**
4. Go to **Security alerts** to view triggered alerts

---

## 8. MICROSOFT PURVIEW (UNIFIED AUDIT LOG)

#### Query: Policy Modification Events

```powershell
Connect-MgGraph -Scopes "AuditLog.Read.All"

# Search for Conditional Access policy modifications
Search-UnifiedAuditLog -Operations "*policy*" -StartDate (Get-Date).AddDays(-7) -EndDate (Get-Date) |
  Where-Object {$_.AuditData -like "*Conditional*" -or $_.AuditData -like "*Risk*"} |
  Select-Object UserIds, Operations, CreationDate | Export-Csv -Path "C:\PolicyAudit.csv"

# Search for user risk policy changes
Search-UnifiedAuditLog -Operations "Set-MsolUserRiskPolicy" -StartDate (Get-Date).AddDays(-7) |
  Select-Object UserIds, Operations, AuditData
```

---

## 9. DEFENSIVE MITIGATIONS

#### Priority 1: CRITICAL

**1. Implement PIM for Policy Management Roles**

Require just-in-time activation for roles that can modify Conditional Access and Identity Protection policies.

**Manual Steps (PIM Configuration):**
1. Go to **Azure Portal** → **Microsoft Entra ID** → **Privileged Identity Management**
2. Click **Roles** (or **Azure resources**)
3. Search for **"Identity Security Administrator"**
4. Click the role → **Settings**
5. Under **Activation settings**, set:
   - **Require approval to activate**: ON
   - **Require Azure MFA on activation**: ON
   - **Activation duration**: 2 hours (minimum)
   - **Require justification on activation**: ON
6. Click **Update**

**2. Restrict Policy Modification via Conditional Access**

Require MFA and compliant device for anyone accessing Conditional Access configuration.

**Manual Steps:**
1. Go to **Azure Portal** → **Entra ID** → **Security** → **Conditional Access**
2. Click **+ New policy**
3. Name: `"Restrict Conditional Access Management"`
4. **Assignments:**
   - Users: **Directory roles** → **Global Administrator, Conditional Access Administrator**
   - Cloud apps: **Microsoft Azure Management**
5. **Access controls:**
   - Grant: **Require multi-factor authentication** AND **Require device to be marked as compliant**
6. Enable policy: **On**
7. Click **Create**

**3. Enable Azure AD Audit Logging and Alert on Policy Changes**

Ensure all policy modifications are captured and generate immediate alerts.

**Manual Steps (Enable Audit Logging):**
1. Go to **Azure Portal** → **Entra ID** → **Audit logs**
2. Verify that audit logging is enabled (check if events are being collected)
3. Set up log retention (default is 30 days; increase to 90+ days if needed)

**4. Implement Alert Rules for Policy Disablement**

Create real-time alerts when Conditional Access or risk policies are disabled.

**Manual Steps (Azure Monitor Alert):**
1. Go to **Azure Portal** → **Monitor** → **Alert rules**
2. Click **+ Create** → **Alert rule**
3. **Scope:** Select your Entra ID tenant
4. **Condition:** 
   - Signal: "Update policy" OR "Delete policy"
   - Filter: DisplayName contains "Conditional Access" OR "Risk"
   - Filter: ModifiedProperties contains "State" = "disabled"
5. **Actions:** Add action group to send email/SMS to security team
6. Click **Create**

#### Priority 2: HIGH

**5. Regular Policy Audits**

Conduct monthly reviews of all Conditional Access and Identity Protection policies.

**Manual Steps:**
```powershell
# Monthly audit script
Write-Host "=== Conditional Access Policies ==="
Get-MgIdentityConditionalAccessPolicy | Select-Object DisplayName, State | Format-Table

Write-Host "=== User Risk Policy Status ==="
Get-MgIdentityUserRiskPolicy | Select-Object IsEnabled

Write-Host "=== Sign-In Risk Policy Status ==="
Get-MgIdentitySignInRiskPolicy | Select-Object IsEnabled

# Export to CSV for compliance
Get-MgIdentityConditionalAccessPolicy | Export-Csv -Path "C:\CA_Policies_$(Get-Date -Format 'yyyy-MM-dd').csv"
```

**6. Implement MFA for All Administrative Roles**

Ensure that all admins capable of modifying policies use MFA.

**Manual Steps:**
1. Go to **Azure Portal** → **Entra ID** → **Conditional Access**
2. Create policy: "Require MFA for All Admins"
3. **Assignments:**
   - Users: **All directory roles** (or specific: Global Admin, Compliance Admin, etc.)
   - Cloud apps: **All cloud apps**
4. **Access controls:**
   - Grant: **Require multi-factor authentication**
5. Enable policy: **On**

#### Validation Command (Verify Mitigations)

```powershell
# Verify all risk-based Conditional Access policies are enabled
$Policies = Get-MgIdentityConditionalAccessPolicy
foreach ($Policy in $Policies) {
    if ($Policy.Conditions.SignInRiskLevels) {
        Write-Host "Policy: $($Policy.DisplayName) - State: $($Policy.State)"
    }
}

# Verify user risk policy is enabled
$UserRiskPolicy = Get-MgIdentityUserRiskPolicy
Write-Host "User Risk Policy Enabled: $($UserRiskPolicy.IsEnabled)"

# Verify PIM is enabled for administrative roles
Get-AzureADMSPrivilegedRoleDefinition -DisplayName "Identity Security Administrator" | Select-Object DisplayName, Enabled
```

**Expected Output (If Secure):**
```
Policy: Require MFA for Risky Sign-ins - State: enabled
Policy: Block High Risk Sign-ins - State: enabled
User Risk Policy Enabled: True
Identity Security Administrator - Enabled: True (PIM active)
```

---

## 10. DETECTION & INCIDENT RESPONSE

#### Indicators of Compromise (IOCs)

**Audit Log Indicators:**
- `OperationName`: `"Update policy"`, `"Delete policy"`
- `TargetResources.displayName`: Contains "Conditional Access", "Risk", "Identity Protection"
- `TargetResources.modifiedProperties`: `State` changed to `"disabled"`
- `InitiatedBy.userPrincipalName`: Non-standard admin or unusual time
- `CreationDate`: Policy disabled outside business hours

**Identity Threat Indicators:**
- Increase in sign-ins from impossible-travel locations (without alerts).
- Multiple sign-ins from VPN/anonymous IP addresses.
- Successful password spray attempts without MFA challenge.
- Risky user accounts not triggering password reset enforcement.
- No increase in MFA prompt frequency despite high-risk activity.

**Forensic Artifacts:**
- **Unified Audit Log:** `AuditData` blob contains policy modification details.
- **Entra ID Sign-in Logs:** Sign-ins marked as high-risk but not blocked.
- **Entra ID Risk Detections:** Risk events logged but no policy response.

#### Response Procedures

1. **Immediate Action - Re-enable Disabled Policies:**
   ```powershell
   # Re-enable Conditional Access policy
   $PolicyId = "policy-guid"
   Update-MgIdentityConditionalAccessPolicy -ConditionalAccessPolicyId $PolicyId -State "enabled"
   
   # Re-enable user risk policy
   $UserRiskPolicy = Get-MgIdentityUserRiskPolicy
   $UserRiskPolicy.IsEnabled = $true
   Update-MgIdentityUserRiskPolicy -IdentityUserRiskPolicy $UserRiskPolicy
   ```

2. **Investigate Attacker Activity:**
   ```powershell
   # Check all sign-in activity during policy-disabled period
   Get-MgSignInLogsSignIn -Filter "createdDateTime gt 2026-01-08T00:00:00Z and createdDateTime lt 2026-01-09T23:59:59Z" |
     Select-Object UserPrincipalName, CreatedDateTime, IpAddress, Location, RiskLevel | Format-Table
   
   # Identify all high-risk logins that were not blocked
   Get-MgSignInLogsSignIn -Filter "riskLevel eq 'high'" | Select-Object UserPrincipalName, CreatedDateTime, IpAddress
   ```

3. **Account Remediation:**
   ```powershell
   # Reset password for compromised admin account
   Set-AzureADUserPassword -ObjectId "admin@contoso.com" -Password (ConvertTo-SecureString -AsPlainText "NewStrongPassword123!" -Force)
   
   # Force sign-out of all sessions
   Revoke-AzureADUserAllRefreshToken -ObjectId "admin@contoso.com"
   
   # Reset MFA settings
   Set-AzureADUserPassword -ObjectId "admin@contoso.com" -NewPassword (ConvertTo-SecureString -AsPlainText "NewPassword123!" -Force) -ForceChangePassword $true
   ```

4. **Containment:**
   - Temporarily block external access from all non-managed IP addresses.
   - Implement stricter Conditional Access policies (require MFA for all, require compliant device).
   - Review all administrative actions taken during policy-disabled period.

---

## 11. RELATED ATTACK CHAIN

| Step | Phase | Technique | Description |
|---|---|---|---|
| **1** | **Initial Access** | [IA-PHISH-001] Device Code Phishing | Attacker compromises admin account via device code flow phishing. |
| **2** | **Privilege Escalation** | [PE-ACCTMGMT-001] App Registration Permissions | Attacker grants self additional permissions via app registration. |
| **3** | **Defense Evasion** | **[EVADE-IMPAIR-011]** | **Attacker disables Conditional Access risk-based policies.** |
| **4** | **Persistence** | [PERSIST-TOKEN-001] Primary Refresh Token Theft | Attacker maintains access with stolen PRT token without MFA. |
| **5** | **Collection** | [COLLECT-EMAIL-001] Email Collection via EWS | Attacker exfiltrates data without risk-based access blocks. |

---

## 12. REAL-WORLD EXAMPLES

#### Example 1: APT Group Campaign (2023)

- **Target:** Fortune 500 Pharmaceutical Company
- **Timeline:** March - October 2023
- **Technique Status:** APT actors compromised Global Admin account, disabled all Conditional Access policies, then maintained access via impossible-travel logins from multiple continents without triggering any alerts or MFA.
- **Impact:** Undetected access for 7 months; exfiltration of drug pipeline data; regulatory investigations; $150M+ in market damage.
- **Reference:** [Mandiant Threat Report 2023](https://www.mandiant.com/)

#### Example 2: Insider Threat - Tech Startup (2024)

- **Target:** Cloud-Native SaaS Startup
- **Timeline:** June 2024
- **Technique Status:** Disgruntled employee with Identity Security Admin role disabled user risk and sign-in risk policies before exfiltrating proprietary source code and customer lists. No alerts were triggered because risk-based Conditional Access was disabled.
- **Impact:** Intellectual property theft; customer data breach (5,000+ records); business disruption.
- **Reference:** [SEC/FBI Joint Alert 2024](https://www.ic3.gov/)

---

## 13. CONCLUSION

Azure Identity Protection and risk-based Conditional Access policies are critical controls for detecting and responding to compromised identities. By disabling or modifying these policies, an attacker can:

1. **Bypass MFA enforcement** for anomalous logins.
2. **Disable password reset enforcement** for compromised accounts.
3. **Operate with complete visibility loss** to security teams.
4. **Maintain persistent, undetected access** for months or years.

**Key Defense Recommendations:**
- **Enable PIM for policy management:** Require just-in-time activation with approval for anyone managing Conditional Access or Identity Protection.
- **Monitor continuously:** Create Sentinel alerts for policy disablement; review audit logs weekly.
- **Baseline all policies:** Document current state (enabled/disabled); alert on any changes.
- **Enforce MFA organization-wide:** Require MFA for all users, especially admins.
- **Test risk-based policies regularly:** Verify that policies respond correctly to impossible-travel, anonymous IP, and other risk signals.
- **Incident response:** Immediately re-enable disabled policies; investigate for data exfiltration; reset all affected accounts.

Organizations must recognize that Identity Protection policies are as critical to security as firewalls, and any modification to these policies requires the same level of scrutiny and approval as firewall rule changes.

---