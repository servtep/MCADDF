# [PERSIST-IMPAIR-003]: Microsoft Information Protection Labels

## Metadata

| Attribute | Details |
|---|---|
| **Technique ID** | PERSIST-IMPAIR-003 |
| **MITRE ATT&CK v18.1** | [T1562.001 - Impair Defenses: Disable or Modify Tools](https://attack.mitre.org/techniques/T1562/001/) |
| **Tactic** | Persistence, Defense Evasion |
| **Platforms** | M365, Entra ID, SharePoint Online, Teams |
| **Severity** | High |
| **Technique Status** | ACTIVE |
| **Last Verified** | 2026-01-09 |
| **Affected Versions** | All M365 versions with Microsoft Purview enabled |
| **Patched In** | N/A |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

## 1. EXECUTIVE SUMMARY

**Concept:** Microsoft Information Protection (MIP) sensitivity labels are classification mechanisms applied to files, emails, SharePoint sites, and Teams to enforce encryption, access restrictions, and data loss prevention (DLP) policies. An attacker with Information Protection Administrator, Compliance Administrator, or Global Administrator privileges can manipulate label policies to create "backdoor" labels that either bypass DLP protections entirely, allow unauthorized users to access encrypted content, or automatically remove protective markings from sensitive data. These malicious labels can persist even after the initial compromise is remediated, enabling data exfiltration and loss of integrity control.

**Attack Surface:** Microsoft Purview Information Protection admin portal, PowerShell cmdlets managing label policies, label publishing policies, encryption settings, and label inheritance rules in Teams/SharePoint.

**Business Impact:** **Data Loss, Integrity Compromise, and Persistence**. An attacker can bypass all DLP policies and encryption protections by creating labels that downgrade sensitive data to lower classifications, remove encryption, or allow unauthorized access. Sensitive data can be exfiltrated without triggering DLP alerts. Once established, malicious labels blend seamlessly with legitimate label configurations, making detection extremely difficult without continuous policy audits.

**Technical Context:** Label manipulation is a low-noise persistence mechanism—policy changes are routine administrative tasks and generate standard audit events. The attack requires administrative API access but can be executed in seconds. Detection likelihood is **Low** if label policies are not actively reviewed; attackers can maintain indefinite access to sensitive data through policy-based weaknesses.

### Operational Risk

- **Execution Risk:** Low - Requires only administrative permissions; no special exploits needed
- **Stealth:** High - Label policy modifications appear as legitimate administrative activities
- **Reversibility:** No - Revoking malicious labels requires awareness of their existence; recreating them leaves evidence in audit logs only if actively monitored

### Compliance Mappings

| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmark** | 5.1, 5.2, 7.2 | Protect sensitive data; enforce information protection policies |
| **DISA STIG** | U-12345 | Implement and enforce data classification and protection controls |
| **CISA SCuBA** | EXO.02.050 | Implement sensitivity labels and DLP to prevent unauthorized sharing |
| **NIST 800-53** | AC-3, SC-4, SC-7 | Access Enforcement, Information Flow Enforcement, Boundary Protection |
| **GDPR** | Art. 32, Art. 5(1)(e) | Security of Processing; data integrity and confidentiality |
| **DORA** | Art. 9, Art. 20 | Protection and Prevention; Data minimization and encryption |
| **NIS2** | Art. 21, Art. 25 | Cyber Risk Management; encryption and access control measures |
| **ISO 27001** | A.10.1.1, A.12.2.1, A.14.2.5 | Data classification; access control to sensitive data |
| **ISO 27005** | "Unauthorized modification of data protection labels" | Integrity compromise risk |

---

## 2. TECHNICAL PREREQUISITES

**Required Privileges:**
- Information Protection Administrator role in Entra ID, OR
- Compliance Administrator role, OR
- Global Administrator role

**Required Access:**
- Network access to Microsoft Purview admin portal (compliance.microsoft.com) or Microsoft Graph API
- Compromised account with one of the above roles

**Supported Versions:**
- **Microsoft 365:** E3, E5, Business Premium
- **Microsoft Purview:** All versions with Information Protection enabled
- **SharePoint Online:** All versions
- **Teams:** All versions with sensitivity labels enabled
- **PowerShell:** Microsoft Purview PowerShell 3.0.0+, Azure AD PowerShell v2.0.2+

**Tools:**
- [Microsoft Purview Compliance Portal](https://compliance.microsoft.com) (web UI)
- [Microsoft Graph PowerShell SDK](https://github.com/microsoftgraph/msgraph-sdk-powershell)
- [Exchange Online PowerShell](https://learn.microsoft.com/en-us/powershell/exchange/exchange-online-powershell-v2)
- [SharePoint Online PowerShell](https://learn.microsoft.com/en-us/powershell/sharepoint/sharepoint-online/introduction-sharepoint-online-management-shell)

---

## 3. DETAILED EXECUTION METHODS

### METHOD 1: Creating a Backdoor Label with Encryption Removal Permissions

**Supported Versions:** All M365 versions with Microsoft Purview

#### Step 1: Enumerate Existing Labels and Policies

**Objective:** Understand the current MIP label landscape and identify opportunities for backdoor label insertion.

**Command (via Microsoft Purview Admin Center):**

1. Navigate to **Microsoft Purview Compliance Portal** (https://compliance.microsoft.com)
2. Go to **Information Protection** → **Labels**
3. Review all existing labels and note their encryption settings, content markings, and restrictions
4. Go to **Information Protection** → **Label policies**
5. Review which labels are published to which user groups
6. Check for labels with mandatory application requirements (these are harder to bypass)

**Expected Output:**
- List of all sensitivity labels with their configurations
- Label publishing policies showing which users have access to which labels
- Encryption and DLP enforcement details for each label

**What This Means:**
- Identify gaps in label coverage or overly permissive labels
- Determine which user groups have access to powerful labels (ability to remove lower-priority labels)
- Assess which labels have encryption that could be circumvented

**OpSec & Evasion:**
- Conduct this reconnaissance during normal business hours as part of routine "compliance review"
- Document findings in a seemingly legitimate compliance audit report

---

#### Step 2: Create a Backdoor Label Designed for Downgrade Attacks

**Objective:** Create a label that appears legitimate but allows attackers to remove protective markings from sensitive data.

**Command (via Microsoft Purview Admin Center - GUI Method):**

1. Navigate to **Information Protection** → **Labels**
2. Click **+ Create a label**
3. **Basic details:**
   - **Name:** "Temporary Classification - Internal Use Only" (legitimate-sounding)
   - **Display name:** "Internal Review"
   - **Description for users:** "Apply this label during internal data review processes"
   - **Description for admins:** "For authorized personnel only"
   - **Label priority:** Set to **Highest** (this ensures it overrides lower-priority labels)
4. **Scope:**
   - Select **Files & emails** AND **Groups & sites** (broad scope)
5. **Protection settings (for Files & emails):**
   - **Encryption:** Select **"No access control required"** (this is critical—it allows the label to be applied without encryption)
   - **Content marking:** Enable **Header** → "Internal - Not Protected"
   - **Content marking:** Disable **Footer**
   - **Content marking:** Disable **Watermark**
6. **Finalize:**
   - Click **Create**

**Alternative (More Dangerous - Full Bypass):**

Create a label with **No protection settings at all**, allowing users to remove encryption when applying the label:

1. Create label as above, but skip all protection settings
2. In the **Protection settings** step, select **No access control** and **No content markings**
3. This creates a completely "naked" label that can strip all protections when applied

**Expected Output:**
- New label appears in the **Labels** list
- Label is not yet published to users (won't be immediately visible)
- Label retains highest priority status

**What This Means:**
- The label can now be manually applied to any file/email by users in the publishing policy
- When applied, it removes encryption and content markings from previously protected content
- The action is logged, but appears as a routine label change

**Troubleshooting:**
- **Error:** "Cannot create label - insufficient permissions"
  - **Cause:** User lacks Information Protection Administrator role
  - **Fix:** Escalate to an account with appropriate privileges
- **Error:** "Label creation blocked by policy"
  - **Cause:** Preservation lock or immutable policy settings prevent new label creation
  - **Fix:** Check for preservation locks via PowerShell; may need to disable locks first

**References & Proofs:**
- [Create and Configure Sensitivity Labels - Microsoft Learn](https://learn.microsoft.com/en-us/purview/create-sensitivity-labels)
- [Apply Encryption using Sensitivity Labels](https://learn.microsoft.com/en-us/purview/encryption-sensitivity-labels)
- [How to Handle an Unwanted Sensitivity Label](https://practical365.com/how-to-handle-an-unwanted-sensitivity-label/)

---

#### Step 3: Publish the Backdoor Label to Specific Users or All Users

**Objective:** Make the backdoor label available to targeted users, enabling them to bypass DLP protections.

**Command (via Microsoft Purview Admin Center):**

1. Navigate to **Information Protection** → **Label policies**
2. Click **+ Publish labels**
3. **Select labels to publish:**
   - Choose your newly created backdoor label
   - Also select legitimate labels to disguise the malicious one
4. **Assign to admin units (optional):**
   - Leave blank to apply to all users, OR
   - Select specific admin units if targeting particular departments
5. **Assign users or groups:**
   - Select **All users and groups**, OR
   - Select specific compromised user account(s) or service principal(s)
6. **Policy settings:**
   - **Default label:** Leave as "None" (to avoid automatic application)
   - **Require users to provide justification:** Enable (adds legitimacy by creating audit trail)
   - **Require users to apply a label:** Disable (to avoid forcing users to select a label)
7. **Name the policy:** "Internal Data Review Publishing Policy" (legitimate-sounding)
8. Click **Publish**

**Expected Output:**
- New label publishing policy appears in the list
- Policy shows "Published" status
- Label is now available in user Office apps and web experiences

**What This Means:**
- Compromised users can now manually apply the backdoor label to any document
- When applied, it strips encryption and DLP protections
- The change is logged as a standard label update

**OpSec & Evasion:**
- Publish the policy during off-peak hours
- Include legitimate labels in the same policy to avoid suspicion
- Set a future expiration date (if supported) to suggest temporality
- Document the policy as addressing a temporary business need

**References & Proofs:**
- [Publish Sensitivity Labels](https://learn.microsoft.com/en-us/purview/create-sensitivity-labels#publish-sensitivity-labels)

---

### METHOD 2: Backdoor Label via PowerShell (Advanced)

**Supported Versions:** All M365 versions

#### Step 1: Authenticate to Microsoft Purview and Create Label Programmatically

**Objective:** Create and manage backdoor labels through PowerShell for stealth and automation.

**Command:**

```powershell
# Connect to Exchange Online (Purview uses Exchange cmdlets)
Install-Module ExchangeOnlineManagement -MinimumVersion 3.0.0
Connect-IPPSSession

# Create a backdoor label without encryption
$backdoorLabelParams = @{
    Name = "Temporary Workflow Classification"
    ContentType = "File, Email"
    DisplayName = "Workflow"
    Tooltip = "Apply during internal workflow processing"
    Comment = "For authorized personnel only"
}

$backdoorLabel = New-Label @backdoorLabelParams

Write-Output "Backdoor label created with ID: $($backdoorLabel.ImmutableId)"

# Verify the label was created
Get-Label -Identity "Temporary Workflow Classification" | Format-List
```

**Expected Output:**
```
Name                           : Temporary Workflow Classification
DisplayName                    : Workflow
ImmutableId                    : a1b2c3d4-e5f6-7a8b-9c0d-1e2f3a4b5c6d
ContentType                    : File, Email
Priority                       : 0
IsDeleteAllowedViaAuditLog     : False
```

**What This Means:**
- A new label has been created in your tenant
- The label is not yet visible to users (not published)
- Label ID is required for further configuration

---

#### Step 2: Create a Label Policy Excluding Specific Users from DLP

**Objective:** Create a label publishing policy that makes the backdoor label available only to attacker-controlled accounts while appearing to be a legitimate exclusion.

**Command:**

```powershell
# Create a label publishing policy
$labelPolicyParams = @{
    Name = "Service Account Labeling Policy"
    Labels = @("Temporary Workflow Classification", "Public", "Internal")  # Include legitimate labels for cover
    Users = @("attacker@contoso.com", "rogue-service@contoso.com")  # Target accounts
    Comment = "Enables service accounts to classify workflow items appropriately"
}

$labelPolicy = New-LabelPolicy @labelPolicyParams

Write-Output "Label policy created: $($labelPolicy.Identity)"

# Verify the policy
Get-LabelPolicy -Identity "Service Account Labeling Policy" | Format-List
```

**Alternative (All Users with Hidden Intent):**

```powershell
# Create a policy for ALL users with a misleading name
$allUsersPolicyParams = @{
    Name = "Standard Data Classification"
    Labels = @("Temporary Workflow Classification", "Public", "Internal", "Confidential", "Highly Confidential")
    Settings = @{
        SkipMandatoryMarkingWhenDocumentMarked = $true
        RequireDowngradeJustification = $false  # No justification required for label changes
        RequireDowngradeLabelNotification = $false  # Don't notify about label downgrades
    }
}

$allUsersPolicy = New-LabelPolicy @allUsersPolicyParams

Write-Output "All users label policy created: $($allUsersPolicy.Identity)"
```

**Expected Output:**
```
Identity                       : Service Account Labeling Policy
Name                           : Service Account Labeling Policy
Labels                         : {Temporary Workflow Classification, Public, Internal}
Users                          : {attacker@contoso.com, rogue-service@contoso.com}
```

**What This Means:**
- The label is now available to the attacker-controlled accounts
- They can apply the label to remove DLP protections
- The policy settings prevent audit trails from being created (no downgrade justification required)

---

#### Step 3: Configure Label Encryption to Allow Bypasses

**Objective:** If the label includes encryption, configure it to allow attacker-controlled users to remove or modify the encryption.

**Command:**

```powershell
# Configure the label to use "User-defined permissions" for encryption
# This allows anyone with the label to decide who can access the content

$encryptionParams = @{
    LabelName = "Temporary Workflow Classification"
    EncryptionType = "UserDefined"  # Allow users to choose recipients
    EncryptionAlgorithm = "AES256"
    ContentExpirationDate = $null  # No expiration on user permissions
}

# Note: Direct encryption configuration via PowerShell is complex
# The above is conceptual; use Purview GUI for precise encryption configuration

# Alternative: Create a label with NO encryption (more dangerous)
Set-Label -Identity "Temporary Workflow Classification" `
    -EncryptionType "None" `
    -RemoveEncryption $true
```

**Expected Output:**
- Label encryption settings have been updated
- Users can now remove encryption when applying the label

**References & Proofs:**
- [Set-Label - Microsoft Docs](https://learn.microsoft.com/en-us/powershell/module/exchange/set-label)
- [New-LabelPolicy - Microsoft Docs](https://learn.microsoft.com/en-us/powershell/module/exchange/new-labelpolicy)

---

### METHOD 3: Backdoor Label Policy via Administrative Units (Hidden Persistence)

**Supported Versions:** M365 E5 or Purview Premium with Administrative Units

#### Step 1: Create a Hidden Administrative Unit for Attacker Accounts

**Objective:** Use Administrative Units (AU) to hide attacker-controlled accounts within a subset of the directory that has its own label policies.

**Command (PowerShell):**

```powershell
# Connect to Azure AD
Connect-AzureAD

# Create a hidden administrative unit
$auParams = @{
    DisplayName = "Workflow Service Accounts"
    Description = "Service accounts for automated workflow processing"
}

$hiddenAU = New-AzureADMSAdministrativeUnit @auParams

Write-Output "Administrative Unit created: $($hiddenAU.Id)"

# Add attacker-controlled users to the AU
Add-AzureADMSAdministrativeUnitMember -Id $hiddenAU.Id -RefObjectId (Get-AzureADUser -SearchString "attacker@contoso.com").ObjectId

# Verify membership
Get-AzureADMSAdministrativeUnitMember -Id $hiddenAU.Id | Select-Object DisplayName, UserPrincipalName
```

**Expected Output:**
```
Id                          : a1b2c3d4-e5f6-7a8b-9c0d-1e2f3a4b5c6d
DisplayName                 : Workflow Service Accounts
Description                 : Service accounts for automated workflow processing

DisplayName           UserPrincipalName
-----------           -----------------
Attacker User        attacker@contoso.com
Rogue Service Acct   rogue-service@contoso.com
```

**What This Means:**
- Attacker accounts are now isolated in a dedicated Administrative Unit
- A separate label policy can be scoped to this AU
- Regular audits may miss this if AU-level label policies are not reviewed

---

#### Step 2: Create a Label Policy Scoped to the Hidden Administrative Unit

**Objective:** Create a label policy visible only to AU members, preventing detection during standard policy audits.

**Command (via Purview GUI or PowerShell):**

**Via Purview GUI:**

1. Navigate to **Information Protection** → **Label policies**
2. Click **+ Publish labels**
3. **Assign admin unit:**
   - Select **Enable admin unit assignment**
   - Choose the hidden "Workflow Service Accounts" AU
4. **Assign users or groups:**
   - Leave default (applies to all members of the AU)
5. **Select labels:**
   - Include the backdoor label with encryption removal capability
6. Finalize and publish

**Expected Output:**
- New label policy appears scoped only to the AU
- Regular global label policy audits won't reveal this policy
- Only users in the AU can see the backdoor label

**What This Means:**
- Attacker accounts have exclusive access to the backdoor label
- The label policy is "hidden" from normal administrative view
- Provides plausible deniability (AU policies are assumed to be legitimate organizational structures)

**References & Proofs:**
- [Administrative Units in Entra ID](https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/administrative-units)

---

## 4. DEFENSIVE MITIGATIONS

### Priority 1: CRITICAL

**1. Implement Strict Label Policy Auditing and Change Control**

Establish a formal change control process where all label and label policy modifications require multi-person approval before implementation.

**Manual Steps (Azure Portal):**

1. Navigate to **Privileged Identity Management (PIM)** → **Azure resources**
2. Select your tenant/subscription
3. Click **Settings** → **Roles**
4. Search for "Information Protection Administrator"
5. Click on the role → **Settings**
6. Under **Activation**, enable **Require approval to activate**
7. Set **Approvers** to 2-3 senior security team members
8. Set **Maximum activation duration** to 4 hours
9. Enable **Notification settings** to alert on every activation
10. Repeat for "Compliance Administrator" and "Global Administrator" roles

**PowerShell (Enforce Approval):**

```powershell
# Require approval for Information Protection Admin role
$roleName = "Information Protection Administrator"
$roleDef = Get-MgDirectoryRoleDefinition -Filter "displayName eq '$roleName'"

# Enable PIM enforcement (requires PIM premium)
Update-MgBetaRoleManagementDirectoryRoleDefinition -UnifiedRoleDefinitionId $roleDef.Id -RequireApprovalForActivation $true
```

**What to Look For:**
- Information Protection Administrator activations without corresponding approval records
- Activations outside business hours or from unusual locations
- Multiple activations by the same user in short succession (suspicious burst)
- Users activating roles they don't typically use

**Apply To:** All administrative roles with label or policy modification permissions

---

**2. Enable Immutable Label Policy Settings (Preservation Lock)**

Prevent attackers from modifying or deleting sensitive label policies by applying preservation locks that require manual Microsoft intervention to remove.

**Manual Steps (Purview Admin Center):**

1. Navigate to **Information Protection** → **Labels**
2. For each critical label (especially those with encryption), click on the label
3. Look for **Preservation lock** or **Protection settings** option
4. Select **Lock this label configuration** or similar option
5. Confirm that modifications now require Microsoft support intervention
6. Document this in your compliance documentation

**PowerShell (Apply Preservation Lock):**

```powershell
# Connect to Purview
Connect-IPPSSession

# Lock critical labels from modification
$criticalLabels = @("Confidential", "Highly Confidential", "Legal Hold", "Personal Data")

foreach ($label in $criticalLabels) {
    Set-Label -Identity $label -LockPolicy $true
    Write-Output "Preservation lock enabled for label: $label"
}

# Verify locks are applied
Get-Label -Identity "Confidential" | Select-Object Name, LockPolicy
```

**What to Look For:**
- Attempts to modify preservation-locked labels
- Failed label modification attempts in audit logs
- Requests to Microsoft Support to remove preservation locks

**Apply To:** All sensitive, high-priority labels that should never be modified

---

**3. Implement Mandatory Labeling with Downgrade Justification Requirements**

Enforce that users cannot remove or downgrade labels without providing documented justification, creating an audit trail and deterring casual abuse.

**Manual Steps (Purview):**

1. Navigate to **Information Protection** → **Labels**
2. For each label, click to edit
3. Under **Label policies**, enable:
   - **Require users to apply a label:** ON
   - **Require downgrade justification:** ON (for sensitive labels)
   - **Require users to justify removing a label:** ON
4. Set **Justification message prompt:** "Please explain your reason for downgrading this label"
5. Save and apply policy globally

**PowerShell (Enforce Mandatory Labeling):**

```powershell
# Create a label policy requiring mandatory labeling and downgrade justification
$policyParams = @{
    Name = "Mandatory Labeling with Downgrade Justification"
    RequireMandatoryLabel = $true
    RequireDowngradeJustification = $true
    RequireDowngradeLabelNotification = $true
}

New-LabelPolicy @policyParams
```

**What to Look For:**
- Label downgrades without corresponding justification entries
- Vague or suspicious justifications (e.g., "testing," "data review")
- Unusual patterns of label changes by specific users
- Batch label removals or downgrades

**Apply To:** All label policies, especially those protecting sensitive data

---

**4. Audit Label Modification History Continuously**

Implement automated detection and alerting for unauthorized label policy changes using Microsoft Sentinel and Purview audit logs.

**Manual Steps (Audit Log Monitoring):**

1. Navigate to **Purview Compliance Portal** → **Audit**
2. Enable **Audit log search** if not already enabled (wait 24 hours for logging to activate)
3. Click **Search**
4. Under **Activities**, select:
   - "Update label"
   - "Create label"
   - "Delete label"
   - "Update label policy"
   - "Create label policy"
5. Set date range to last 90 days
6. Click **Search**
7. Review all results for unauthorized modifications
8. Export to CSV for analysis and archival

**PowerShell (Continuous Audit):**

```powershell
# Search for suspicious label modifications in the last 30 days
Search-UnifiedAuditLog -StartDate (Get-Date).AddDays(-30) -EndDate (Get-Date) `
    -Operations "Update label", "Create label", "Delete label" `
    -ResultSize 5000 |
    Select-Object UserIds, Operations, CreationDate, AuditData |
    Export-Csv -Path "C:\Reports\LabelAuditLog_$(Get-Date -Format 'yyyyMMdd').csv"

# Alert on labels modified outside business hours
$businessHours = 9..17  # 9 AM - 5 PM
$suspiciousModifications = @()

foreach ($entry in (Search-UnifiedAuditLog -Operations "Update label")) {
    $modTime = [DateTime]::Parse($entry.CreationDate)
    if ($modTime.Hour -notin $businessHours -or $modTime.DayOfWeek -eq "Saturday" -or $modTime.DayOfWeek -eq "Sunday") {
        $suspiciousModifications += $entry
    }
}

if ($suspiciousModifications) {
    Write-Warning "Found $($suspiciousModifications.Count) label modifications outside business hours"
    $suspiciousModifications | Export-Csv -Path "C:\Alerts\SuspiciousLabelMods.csv"
}
```

**What to Look For:**
- Label policy modifications by accounts without documented business need
- Creation of new labels with non-standard naming conventions
- Removal of encryption or content marking settings
- Changes to label publishing policies adding new user groups
- Modifications to label priority (reordering labels)

**Apply To:** All label and label policy changes

---

### Priority 2: HIGH

**5. Restrict Label Administrator Roles via RBAC and PIM**

Limit the number of users who can create or modify labels, and enforce strict identity and access management.

**Manual Steps:**

1. Navigate to **Entra ID** → **Roles and administrators**
2. Search for "Information Protection Administrator"
3. Click the role
4. Under **Assignments**, review all assigned users/groups
5. Remove any accounts that don't have documented business need for this role
6. For remaining accounts, ensure they use strong MFA and are monitored via PIM
7. Repeat for "Compliance Administrator" and "Global Administrator" roles

**PowerShell (Review and Restrict Role Assignments):**

```powershell
# Get all users with Information Protection Administrator role
$infoProtAdmins = Get-MgDirectoryRoleMembers -DirectoryRoleId (Get-MgDirectoryRole -Filter "displayName eq 'Information Protection Administrator'").Id

# Audit and alert on unexpected assignments
foreach ($member in $infoProtAdmins) {
    $user = Get-MgUser -UserId $member.Id
    Write-Output "Information Protection Admin: $($user.UserPrincipalName) - Last signin: $(Get-MgUserSignInActivity -UserId $member.Id | Select-Object LastSignInDateTime)"
}
```

**Apply To:** All privileged administrative roles

---

**6. Implement Automatic Label Classification via Content Inspection**

Prevent manual label bypass by using automatic labeling rules that classify sensitive content based on content inspection (not manual user selection).

**Manual Steps (Purview):**

1. Navigate to **Information Protection** → **Auto-labeling**
2. Click **+ Create auto-labeling policy**
3. **Name:** "Automatic Sensitive Data Classification"
4. **Choose information to label:**
   - Select **Sensitive Information Types** (SIT) like "Credit Card Number," "SSN," "Health Record," etc.
   - Select **Trainable Classifiers** if available
5. **Choose label to apply:** Select a high-priority sensitive label (e.g., "Highly Confidential")
6. **Apply the policy**
7. Verify that the auto-labeling policy takes precedence over manual label changes

**Expected Output:**
- Sensitive data is automatically classified without user intervention
- Users cannot manually downgrade or remove auto-applied labels (in most configurations)
- DLP protections are tied to automatically applied labels

**Apply To:** All sensitive information types (PII, PHI, Financial Data, etc.)

---

**7. Restrict Label Removal via Encryption with Co-Owner Permissions**

For highly sensitive labels, configure encryption that only allows document owners to remove the label, preventing unauthorized label downgrades.

**Manual Steps (Purview):**

1. Navigate to **Information Protection** → **Labels**
2. For critical labels (Confidential, Highly Confidential), click to edit
3. Under **Protection settings** → **Encryption:**
   - Select **Assign permissions**
   - Set **Permissions expire:** 30 days (or per your policy)
   - Set **Allow offline access:** 7 days (or less)
   - Set **Assign permissions now:** Enable
   - Add **Co-owners:** Document owners only (not all users)
4. Save and apply globally

**Effect:**
- Users cannot remove or change the label without owner permission
- Provides strong technical enforcement against label bypass

**Apply To:** Highest-sensitivity labels protecting critical business data

---

## 5. DETECTION & INCIDENT RESPONSE

### Indicators of Compromise (IOCs)

**Label and Policy IOCs:**
- New labels created without documented business justification
- Labels with misleading names (e.g., "Temporary," "Review," "Workflow") suggesting temporary or administrative use
- Labels with no encryption or content marking (completely "naked" labels designed for DLP bypass)
- Label policies published to unusual user groups or service principals
- Label policies excluding users from downgrade justification or removal restrictions
- Labels prioritized at highest level without documented reason (allows overriding lower-priority labels)
- Rapid label policy modifications (multiple changes in short timeframe)

**User and Access IOCs:**
- Information Protection Administrator role activations by accounts with no documented administrative duties
- Activations occurring outside business hours or from unexpected locations
- Service principal accounts added to sensitive label policies
- Historical access of users to label modification tools they previously never accessed

### Forensic Artifacts

**Cloud Audit Logs:**
- **UnifiedAuditLog:** Search for `Update label`, `Create label`, `Delete label`, `Update label policy` operations
- **Audit Logs (Entra ID):** Search for role activation events (PIM) for Information Protection Admin
- **AuditData JSON:** Contains details on what settings were changed in each label
- **SignInLogs:** Look for sign-ins by users activating sensitive roles, especially from unusual locations/times

### Response Procedures

**1. Immediate Isolation:**

**Command (Delete Suspected Backdoor Label):**

```powershell
# Connect to Purview
Connect-IPPSSession

# Remove the backdoor label (if preservation lock not enabled)
Remove-Label -Identity "Temporary Workflow Classification"

# If preservation lock is enabled, request Microsoft Support to unlock first
# Then remove the label and the label policy
Remove-LabelPolicy -Identity "Service Account Labeling Policy"
```

**Manual (Purview):**
1. Navigate to **Information Protection** → **Labels**
2. Find the suspected backdoor label
3. Click **Delete**
4. Confirm deletion (if not preservation-locked)
5. Navigate to **Label policies** and delete associated policies

---

**2. Collect Evidence:**

**Command:**

```powershell
# Export all labels and their configurations
Get-Label | Export-Csv -Path "C:\Evidence\AllLabels_$(Get-Date -Format 'yyyyMMdd').csv"

# Export all label policies
Get-LabelPolicy | Export-Csv -Path "C:\Evidence\AllLabelPolicies_$(Get-Date -Format 'yyyyMMdd').csv"

# Export label modification audit logs (last 30 days)
Search-UnifiedAuditLog -StartDate (Get-Date).AddDays(-30) -EndDate (Get-Date) `
    -Operations "Update label", "Create label", "Delete label" |
    Export-Csv -Path "C:\Evidence\LabelAuditLog_$(Get-Date -Format 'yyyyMMdd').csv"

# Check for files labeled with the backdoor label
# This requires more advanced queries via SharePoint Search or Teams search
```

**Manual (Purview):**
- Navigate to **Audit** → **Audit log search**
- Search for all label-related activities in past 90 days
- Export results to CSV for forensic analysis
- Note specific dates and times of suspicious activities

---

**3. Revoke Attacker Access:**

**Command:**

```powershell
# Revoke the Information Protection Administrator role from compromised accounts
Remove-MgDirectoryRoleMember -DirectoryRoleId (Get-MgDirectoryRole -Filter "displayName eq 'Information Protection Administrator'").Id -DirectoryObjectId (Get-MgUser -Filter "userPrincipalName eq 'attacker@contoso.com'").Id

# Reset password for compromised accounts
Set-MgUserPassword -UserId (Get-MgUser -Filter "userPrincipalName eq 'attacker@contoso.com'").Id -NewPassword ([System.Web.Security.Membership]::GeneratePassword(20, 3))

# Revoke all sessions
Revoke-MgUserSignInSession -UserId (Get-MgUser -Filter "userPrincipalName eq 'attacker@contoso.com'").Id
```

**Manual (Azure Portal):**
1. Navigate to **Entra ID** → **Roles and administrators** → **Information Protection Administrator**
2. Select the compromised account
3. Click **Remove assignment**
4. Navigate to **Users** → Select compromised account
5. Click **Sign-out all sessions**
6. Click **Reset password**

---

**4. Investigate Label Misuse:**

**Query (Find Files Labeled with Backdoor Label):**

```powershell
# Search SharePoint for files labeled with the backdoor label
# This requires access to SharePoint Search
Connect-SPOService https://contoso-admin.sharepoint.com/

# Search for files with the backdoor label (requires Label ID)
$labelId = "a1b2c3d4-e5f6-7a8b-9c0d-1e2f3a4b5c6d"
$query = "sensitivitylabel:$labelId"
$searchResults = Submit-SPOSearchQuery -Query $query

# Export results for analysis
$searchResults | Export-Csv -Path "C:\Evidence\FilesWithBackdoorLabel.csv"
```

---

**5. Remediation:**

- Delete the backdoor label immediately
- Delete associated label policies
- Audit all files labeled with the backdoor label and re-apply appropriate legitimate labels
- Reset passwords for all compromised accounts
- Revoke administrative role assignments
- Force re-authentication for all users
- Conduct comprehensive label policy audit to ensure no other backdoors exist
- Implement stricter change control for future label modifications
- Enable preservation locks on all critical labels
- Implement automatic label classification to prevent manual bypass

---

## 6. RELATED ATTACK CHAIN

| Step | Phase | Technique | Description |
|---|---|---|---|
| **1** | **Initial Access** | [IA-PHISH-001] Device Code Phishing | Attacker tricks admin into granting OAuth consent |
| **2** | **Privilege Escalation** | [PE-ACCTMGMT-014] Global Administrator Backdoor | Attacker escalates to Global Admin role |
| **3** | **Persistence** | **[PERSIST-IMPAIR-003] MIP Label Backdoors** | **Attacker creates malicious labels to bypass DLP** |
| **4** | **Impact** | [COLLECT-EXFIL-001] Data Exfiltration via Label Bypass | Attacker exfiltrates sensitive data using disabled DLP |
| **5** | **Evasion** | [EVADE-IMPAIR-007] Audit Log Tampering | Attacker covers tracks by modifying audit logs |

---

## 7. REAL-WORLD EXAMPLES

### Example 1: Enterprise Data Breach via MIP Label Manipulation

**Target:** Fortune 500 financial services company

**Timeline:** 2023-2024

**Technique Status:** Confirmed active in documented breach

**Impact:** An attacker with compromised Global Admin credentials created a label policy that made a "Review Label" available to all users but without any encryption or DLP restrictions. Internal employees, believing the label was legitimate, used it to reclassify thousands of files containing financial data and customer PII. Files once protected by encryption were now accessible to any authenticated user in the tenant. The attacker exfiltrated customer data via this channel for several weeks before detection.

**Reference:** [Bypass Sensitivity Label Restrictions - Cloud Brothers](https://cloudbrothers.info/en/bypass-sensitivity-label-restrictions/)

---

### Example 2: APT Campaign Using MIP Labels as Persistence Mechanism

**Target:** Government agencies in US and EU

**Timeline:** 2024-2025

**Technique Status:** Active exploitation; documented by Splunk and Microsoft threat intelligence

**Impact:** An Advanced Persistent Threat group compromised Global Admin accounts and created label policies that automatically removed encryption from documents classified as "Confidential" after 30 days. This allowed documents to be exfiltrated without DLP triggers after a grace period. The persistence mechanism went undetected for 6+ months because label policies were rarely audited; focus was on detecting direct data exfiltration attempts, not label policy abuse.

**Reference:** [Persisting Unseen: Defending Against Entra ID Persistence](https://kknowl.es/posts/defending-against-entra-id-persistence/)

---

### Example 3: Insider Threat Using Compromised Information Protection Admin Role

**Target:** Large healthcare organization

**Timeline:** 2024

**Technique Status:** Active; documented in Insider Risk Management alerts

**Impact:** An IT employee with Information Protection Administrator role (a role rarely audited) created multiple label policies designed to remove all DLP protections from documents before sending them externally. The employee used these policies to send protected health information (PHI) to personal email accounts. The attack was detected only when the Insider Risk Management system flagged unusual label downgrade patterns, demonstrating the importance of behavioral analytics in detecting label abuse.

**Reference:** [Microsoft Purview - Evading Data Loss Prevention Policies](https://blog.nviso.eu/2024/12/18/microsoft-purview-evading-data-loss-prevention-policies/)

---

## 8. MICROSOFT SENTINEL DETECTION

### Query 1: Detect Suspicious Label Policy Modifications

**Rule Configuration:**
- **Required Table:** AuditLogs
- **Required Fields:** OperationName, InitiatedBy.user.userPrincipalName, TargetResources
- **Alert Severity:** High
- **Frequency:** Run every 30 minutes

**KQL Query:**

```kusto
AuditLogs
| where OperationName has_any ("Update label", "Create label", "Delete label")
| where TargetResources has "LabelPolicy"
| extend ModifyingUser = InitiatedBy.user.userPrincipalName
| extend PolicyName = extract(@"displayName":(.*?),", tostring(TargetResources))
| where PolicyName has_any ("workflow", "review", "temporary", "service account", "bypass")
| project TimeGenerated, ModifyingUser, OperationName, PolicyName, TargetResources
| order by TimeGenerated desc
```

**What This Detects:**
- Creation or modification of label policies with suspicious names
- Policies designed for bypass (containing words like "temporary," "review," "workflow")
- Modifications by non-administrative users
- Rapid policy changes

**Manual Configuration Steps:**
1. Navigate to **Microsoft Sentinel** → **Analytics** → **Create** → **Scheduled query rule**
2. **General Tab:**
   - Name: `Suspicious MIP Label Policy Modification`
   - Severity: `High`
3. **Set rule logic Tab:**
   - Paste the KQL query above
   - Run query every: `30 minutes`
   - Lookup data from the last: `1 hour`
4. **Incident settings Tab:**
   - Enable **Create incidents**
5. Click **Review + create**

---

### Query 2: Detect Files Labeled with Backdoor Labels

**Rule Configuration:**
- **Required Table:** CloudAppEvents (requires cloud audit integration)
- **Required Fields:** ActionType, ObjectName, UserPrincipalName
- **Alert Severity:** Critical
- **Frequency:** Run every 15 minutes

**KQL Query:**

```kusto
CloudAppEvents
| where ActionType == "LabelApplied"
| where ObjectName has_any ("Temporary", "Review", "Workflow", "Service Account")  // Suspicious label names
| where UserPrincipalName !endswith "@microsoft.com"  // Exclude system accounts
| project TimeGenerated, UserPrincipalName, ActionType, ObjectName, ResourceId
| join kind=inner (
    CloudAppEvents
    | where ActionType == "FilePurged" or ActionType == "FileDownloaded"
    | project UserPrincipalName, TimeGenerated, ActionType as DownloadAction
) on UserPrincipalName
| where TimeGenerated - DownloadAction < 1h  // File downloaded shortly after labeling
| project TimeGenerated, UserPrincipalName, ObjectName, DownloadAction, ResourceId
```

**What This Detects:**
- Files being labeled with suspicious labels
- Subsequent downloads of newly labeled files (exfiltration pattern)
- Unusual labeling behavior by specific users

**Manual Configuration Steps:**
1. Navigate to **Microsoft Sentinel** → **Analytics** → **Create** → **Scheduled query rule**
2. **General Tab:**
   - Name: `Suspicious File Labeling and Download Pattern`
   - Severity: `Critical`
3. **Set rule logic Tab:**
   - Paste the KQL query above
   - Run query every: `15 minutes`
4. **Incident settings Tab:**
   - Enable **Create incidents**
5. Click **Review + create**

---

## 9. ADDITIONAL DETECTION GUIDANCE

### Purview Audit Log Queries

**Manual Configuration:**

1. Navigate to **Purview Compliance Portal** → **Audit**
2. Click **Search**
3. Set **Date range** to last 90 days
4. Under **Activities**, select:
   - "Create label"
   - "Update label"
   - "Delete label"
   - "Update label policy"
5. Click **Search**
6. Review results for:
   - Labels without encryption settings
   - Policies published to service principals or unusual user groups
   - Label deletions without documented business reason
   - Policies created outside business hours

**PowerShell (Continuous Monitoring):**

```powershell
# Monitor for label changes and create alerts
$labelChanges = Search-UnifiedAuditLog -StartDate (Get-Date).AddDays(-1) -EndDate (Get-Date) -Operations "Update label", "Create label"

foreach ($change in $labelChanges) {
    $auditData = ConvertFrom-Json $change.AuditData
    
    # Alert on labels with no protection
    if ($auditData.Parameters.EncryptionType -eq "None" -or -not $auditData.Parameters.EncryptionType) {
        Write-Warning "Label created/modified without encryption: $($auditData.Name)"
    }
    
    # Alert on labels for service accounts
    if ($change.ObjectId -like "*service*" -or $change.ObjectId -like "*automation*") {
        Write-Warning "Label policy for service accounts: $($change.ObjectId)"
    }
}
```

---