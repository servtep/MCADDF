# [MISCONFIG-016]: Privileged Account Not Monitored

## 1. METADATA HEADER

| Attribute | Details |
|---|---|
| **Technique ID** | MISCONFIG-016 |
| **MITRE ATT&CK v18.1** | [T1556 - Modify Authentication Process](https://attack.mitre.org/techniques/T1556/) |
| **Tactic** | Privilege Escalation / Persistence |
| **Platforms** | Multi-Env (Windows AD, Entra ID, Azure, M365) |
| **Severity** | Critical |
| **Technique Status** | ACTIVE |
| **Last Verified** | 2026-01-10 |
| **Affected Versions** | All versions (configuration oversight) |
| **Patched In** | N/A (Configuration-based, requires monitoring setup) |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

## 2. EXECUTIVE SUMMARY

- **Concept:** Privileged accounts (Global Admins, Domain Admins, Exchange Online Admins, Security Admins) are **high-value targets** for adversaries seeking to maintain persistence and escalate privileges. Organizations often fail to implement dedicated monitoring, alerting, and logging for these accounts. Consequently, attackers can compromise privileged accounts and operate undetected for weeks or months while performing authentication persistence techniques (e.g., golden ticket generation, OAuth token theft, conditional access policy manipulation) without triggering any alerts.

- **Attack Surface:** Lack of real-time sign-in monitoring for privileged accounts, no Conditional Access policies restricting privileged admin access, absent or misconfigured audit logging, no alert rules for unusual privileged operations, no dedicated Privileged Identity Management (PIM) or Just-In-Time (JIT) access controls.

- **Business Impact:** **Undetected compromise of administrative accounts enabling wholesale infrastructure takeover, data exfiltration, ransomware deployment, and persistent backdoor installation.** Once an attacker controls a Global Admin or Domain Admin account, they have unrestricted access to all tenant resources, can disable security controls, forge golden tickets, and establish long-term persistence.

- **Technical Context:** Privilege escalation and persistence via compromised privileged accounts are **stealthy by nature**—if not monitored explicitly, the attack is invisible. Attack detection window: typically **weeks to months** if monitoring is absent.

### Operational Risk
- **Execution Risk:** Medium – Requires initial compromise of privileged account, but exploitation is trivial post-compromise.
- **Stealth:** Extremely High – Lacks detection if monitoring is not configured.
- **Reversibility:** No – Once persistence is established via golden tickets or oauth tokens, revocation requires complete account reset and audit trail analysis.

### Compliance Mappings

| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmark** | 1.1.1 | Ensure Privileged Identity Management is Enabled for Entra ID Roles |
| **CIS Benchmark** | 1.1.3 | Ensure that Privileged Identity Management Alert for Azure Roles is Configured |
| **DISA STIG** | V-226554 | Entra ID must enforce monitoring of privileged account access |
| **CISA SCuBA** | CA-7(1) | Control Access Sessions – Privileged accounts must have real-time monitoring |
| **NIST 800-53** | AC-2(1) | Account Management – Privileged accounts require separate monitoring |
| **NIST 800-53** | AU-2 | Audit Events – Privileged account activity must be logged |
| **NIST 800-53** | SI-4(1) | Information System Monitoring – Continuous monitoring of administrative access |
| **GDPR** | Art. 5(1)(f) | Accountability – Organizations must demonstrate monitoring of privileged access |
| **DORA** | Art. 8 | Third-Party Risk – Admin account monitoring is critical operational resilience |
| **NIS2** | Art. 21 | Cyber Risk Management – Privileged account monitoring is mandatory |
| **ISO 27001** | A.9.1 | User Access Management – All privileged accounts must be monitored |
| **ISO 27001** | A.12.4 | Logging – Audit logs for privileged operations must be centralized and retained |
| **ISO 27005** | Risk Scenario | "Undetected compromise of privileged account due to missing monitoring" |

---

## 3. TECHNICAL PREREQUISITES

- **Required Monitoring Tools:** Microsoft Sentinel, Azure Monitor, Splunk, or equivalent SIEM solution with log aggregation capability.
- **Required Logging:** Azure Activity Log (for Entra ID and Azure), Microsoft 365 Unified Audit Log, Windows Security Event Log (for on-premises AD).
- **Required Platforms:**
  - **Cloud:** Azure, Entra ID, Microsoft 365, Microsoft Defender for Cloud
  - **On-Premises:** Windows Server 2016+, Active Directory with audit policies enabled

**Supported Versions:**
- **Windows:** Server 2016, 2019, 2022, 2025
- **Entra ID:** All versions
- **Azure:** All versions
- **M365:** All versions

**Tools for Monitoring Setup:**
- [Microsoft Sentinel](https://learn.microsoft.com/en-us/azure/sentinel/overview)
- [Azure Monitor](https://learn.microsoft.com/en-us/azure/azure-monitor/)
- [Splunk Enterprise](https://www.splunk.com/)
- [Elastic Stack (ELK)](https://www.elastic.co/what-is/elk-stack)

---

## 4. ENVIRONMENTAL RECONNAISSANCE

### Check if Privileged Account Monitoring is Configured

**PowerShell (Entra ID):**

```powershell
# Check if PIM is enabled
Connect-MgGraph -Scopes "RoleManagement.Read.Directory"

Get-MgRoleManagementDirectoryRoleEligibilitySchedule | Select-Object -First 5

# If empty, PIM is not configured for admin roles
if (-not (Get-MgRoleManagementDirectoryRoleEligibilitySchedule)) {
    Write-Host "[-] CRITICAL: PIM not configured for admin role assignments" -ForegroundColor Red
}
```

**Azure CLI:**

```bash
# Check if Sentinel is deployed and monitoring admin activities
az sentinel list --resource-group <rg> --workspace-name <workspace>

# Check if Analytics Rules exist for privileged account monitoring
az sentinel alert-rule list --resource-group <rg> --workspace-name <workspace> \
  | grep -i "privileged\|admin\|authentication"
```

**Manual Check (Azure Portal):**

1. Go to **Azure Portal** → **Microsoft Sentinel** → **Analytics** → **Rule templates**
2. Search for "Privileged Account"
3. If no rules are enabled = **monitoring gap exists**

---

## 5. DETAILED EXECUTION METHODS AND THEIR STEPS

### METHOD 1: Establish Privileged Account Monitoring (Microsoft Sentinel)

**Supported Versions:** Entra ID, Azure, M365 all versions

#### Step 1: Enable Audit Logging for Privileged Accounts

**Objective:** Ensure all admin operations are logged and forwarded to Sentinel.

**Manual Steps (Entra ID Admin Center):**

1. Navigate to **Entra ID** → **Audit logs**
2. Verify that **Audit log retention** is set to **Minimum 30 days** (or your compliance requirement)
3. Go to **Monitoring** → **Diagnostic settings**
4. Click **Add diagnostic setting**
5. Configure:
   - Name: `AAD-Audit-Logs-to-Sentinel`
   - Categories: Select all (Sign-in logs, Audit logs, Provisioning logs)
   - Destination: Log Analytics Workspace (your Sentinel workspace)
6. Click **Save**

**Manual Steps (Unified Audit Log / M365):**

1. Go to **Microsoft Purview Compliance Portal** (compliance.microsoft.com)
2. **Audit** (left menu)
3. If not enabled, click **Turn on auditing**
4. Navigate to **Audit log retention policies**
5. Ensure retention is set to **≥90 days** for admin activities
6. Return to **Audit** and export logs to Log Analytics or Splunk

#### Step 2: Create Sentinel Analytics Rule for Privileged Account Access

**Objective:** Set up automated detection for unusual admin sign-ins.

**Manual Steps (Sentinel):**

1. Go to **Azure Portal** → **Microsoft Sentinel**
2. **Analytics** → **Rule templates**
3. Search: "Authentications of Privileged Accounts Outside of Expected Controls"
4. Click **Create rule**
5. Configure:
   - **General:**
     - Status: Enabled
     - Severity: High
   - **Set rule logic:**
     - Paste the KQL query (see section 7 below)
     - Run query every: **1 hour**
     - Lookup data from the last: **7 days**
   - **Incident settings:**
     - Enable **Create incidents from alerts triggered by this analytics rule**
   - **Actions:**
     - (Optional) Attach playbook for automated response
6. Click **Review + create** → **Create**

#### Step 3: Create Custom Alert for Privilege Escalation Attempts

**Objective:** Detect when non-admin users attempt to perform admin operations.

**KQL Query (for manual implementation):**

```kusto
AuditLogs
| where OperationName contains "Add" and OperationName contains "role" and OperationName contains "assignment"
| where Result == "success"
| extend TargetUser = TargetResources[0].displayName
| extend InitiatedBy = InitiatedBy.user.userPrincipalName
| where not(InitiatedBy in ("admin@company.com", "serviceaccount@company.com"))
| project TimeGenerated, InitiatedBy, OperationName, TargetUser, Result
```

**Manual Steps (Sentinel):**

1. **Analytics** → **Create** → **Scheduled query rule**
2. **Set rule logic:**
   - Paste the KQL query above
   - Run every: **15 minutes**
   - Lookup: **1 hour**
3. **Incident settings:**
   - Severity: Critical
   - Create incidents: Enabled
4. **Actions:**
   - Configure email alert or Teams notification
5. Click **Create**

#### Step 4: Deploy Playbook for Automated Response

**Objective:** Automatically disable compromised admin accounts pending investigation.

**PowerShell (Azure Automation Runbook):**

```powershell
# This runbook will be triggered by Sentinel alert
# It disables the potentially compromised admin account

param(
    [Parameter(Mandatory = $true)]
    [string]$AdminUserPrincipalName
)

# Connect to Azure
Connect-AzAccount -Identity

# Disable the admin account
try {
    $user = Get-AzADUser -UserPrincipalName $AdminUserPrincipalName
    
    # Disable the account
    Update-AzADUser -ObjectId $user.Id -Enabled $false
    
    Write-Output "[+] Disabled admin account: $AdminUserPrincipalName"
    
    # Send alert email
    Send-NotificationEmail -To "securityteam@company.com" `
        -Subject "ALERT: Disabled admin account due to suspicious activity" `
        -Body "Admin account $AdminUserPrincipalName has been automatically disabled pending investigation."
        
    exit 0
    
} catch {
    Write-Error "[-] Failed to disable account: $_"
    exit 1
}
```

**Manual Setup (Automation Account):**

1. **Azure Portal** → **Automation Accounts** → Create new automation account
2. **Runbooks** → **+ Create a runbook**
3. Paste the PowerShell code above
4. **Publish** → **Start**
5. Test by triggering manually
6. Configure Sentinel playbook to invoke this runbook on high-severity alerts

#### Step 5: Set Up Conditional Access for Privileged Admin Accounts

**Objective:** Require extra authentication factors and device compliance for admin sign-ins.

**Manual Steps (Conditional Access):**

1. Go to **Entra ID** → **Security** → **Conditional Access**
2. Click **+ New policy**
3. Name: `Enforce MFA for Admins`
4. **Assignments:**
   - Users: **Select users and groups** → Search for "Global Admin" role
   - Cloud apps: **All cloud apps**
   - Conditions:
     - Sign-in risk: **All**
     - Device platforms: **All platforms**
5. **Access controls:**
   - **Grant:**
     - Grant access: **Require multi-factor authentication**
     - Require device to be marked as compliant
     - Require approved client app
6. Enable policy: **On**
7. Click **Create**

---

### METHOD 2: Establish Monitoring for On-Premises Privileged Accounts (Windows AD)

**Supported Versions:** Windows Server 2016-2025

#### Step 1: Enable Audit Logging for Domain Admin Actions

**Objective:** Configure Active Directory to log all admin operations.

**Group Policy (Server 2016-2019):**

1. Open **Group Policy Management Console** (gpmc.msc)
2. Navigate to **Computer Configuration** → **Policies** → **Windows Settings** → **Security Settings** → **Advanced Audit Policy Configuration**
3. Enable the following audit categories:
   - **Account Logon** → **Audit Credential Validation** (Success and Failure)
   - **Account Management** → **Audit User Account Management** (Success and Failure)
   - **Privilege Use** → **Audit Sensitive Privilege Use** (Success and Failure)
   - **Detailed Tracking** → **Audit Process Creation** (Success)
4. Run `gpupdate /force` on domain controllers

**PowerShell (Server 2022+):**

```powershell
# Enable advanced audit policies for domain controllers

# Credential validation
auditpol /set /subcategory:"Credential Validation" /success:enable /failure:enable

# User account management
auditpol /set /subcategory:"User Account Management" /success:enable /failure:enable

# Group membership (to track admin group changes)
auditpol /set /subcategory:"Distribution Group Management" /success:enable /failure:enable

# Sensitive privilege use
auditpol /set /subcategory:"Sensitive Privilege Use" /success:enable /failure:enable

# Verify configuration
auditpol /get /category:* /v
```

#### Step 2: Forward Windows Security Logs to Splunk/Sentinel

**Objective:** Centralize Windows event logs for correlation and analysis.

**Using Windows Event Forwarding (WEF):**

1. Create a new Event Forwarding collector machine (or use existing SIEM agent)
2. On each domain controller, create an Event Forwarding subscription:
   ```powershell
   # Create WEF subscription to forward logs to collector
   wecutil cs <subscription_XML_file>
   ```

3. Or use Splunk Universal Forwarder on each DC:
   ```cmd
   # Install Splunk UF
   splunk add forward-server <splunk-indexer>:9997 -auth admin:password
   
   # Configure to forward security logs
   splunk add monitor "C:\Windows\System32\winevt\Logs\Security.evtx" -auth admin:password
   ```

#### Step 3: Create Detection Rules for Privileged Account Activity

**PowerShell / Splunk Search:**

```spl
# Splunk search: Detect Domain Admin activity
index=windows source="WinEventLog:Security" EventCode=4672 Account_Name!=SYSTEM AND Account_Name!="Window Manager"
| stats count by Account_Name, Computer, src_ip
| where count > 5
```

**Windows Event ID Reference:**
- **4672**: Special Privileges Assigned to New Logon (Domain Admin sign-in)
- **4688**: Process Creation (admin process spawning)
- **4738**: User Account Changed (admin modifying accounts)
- **4724**: Attempt to reset password (admin password reset)

---

## 6. DETECTION & FORENSIC ARTIFACTS

### Indicators of Compromise (IOCs) for Unmonitored Privileged Accounts

- **Absence of Monitoring:** No Sentinel rules, no PIM configured, no audit logging enabled.
- **Missing Alerts:** No alerts triggered for:
  - Privileged account sign-ins from unusual locations
  - Multiple failed authentication attempts (brute force)
  - Privilege escalation or role changes
  - Suspicious OAuth consent grants as admin
  - Golden ticket generation (on-premises)
- **Log Gaps:** Security logs show gaps or are not being forwarded to SIEM.

### Forensic Artifacts (What Should Be Monitored)

- **Entra ID Sign-In Logs:** Admin account logins with unusual properties (IP location, device compliance, MFA method).
- **Audit Logs:** Role assignments, Conditional Access policy changes, PIM activations.
- **Azure Activity Log:** Changes to storage, networking, SQL database access for admin accounts.
- **Windows Security Log:** EventID 4672 (special privileges assigned), 4688 (process creation).
- **Graph API Audit:** Unusual permissions granted to service principals by admin accounts.

---

## 7. DEFENSIVE MITIGATIONS

### Priority 1: CRITICAL

- **Action 1: Enable Microsoft Entra Privileged Identity Management (PIM)**
  - **Applies To:** All tenant admin roles
  
  **Manual Steps (Entra ID Admin Center):**
  1. Navigate to **Entra ID** → **Identity Governance** → **Privileged Identity Management**
  2. Click **Activate your tenant for PIM**
  3. For each admin role:
     - Click role name
     - **Settings** → Configure:
       - Require Approval: **On** (for activation requests)
       - Maximum Duration: **8 hours** (limit session length)
       - Require MFA: **On**
       - Require Justification: **On** (admin must explain why they need access)
  4. Click **Update**
  
  **Manual Steps (PowerShell):**
  ```powershell
  Connect-MgGraph -Scopes "RoleManagement.ReadWrite.Directory"
  
  # Enable PIM activation requirement for Global Admin role
  $role = Get-MgDirectoryRole -Filter "displayName eq 'Global Administrator'"
  
  Update-MgRoleManagementDirectoryRoleEligibilityScheduleRequest -RoleDefinitionId $role.Id `
    -PrincipalId "<user_id>" `
    -RequireMFA $true `
    -ApprovalRequired $true
  ```

- **Action 2: Require Multi-Factor Authentication (MFA) for All Admin Accounts**
  - **Applies To:** All privileged users
  
  **Manual Steps (Entra ID):**
  1. **Entra ID** → **Security** → **Conditional Access**
  2. Create policy: `Enforce MFA for Admins`
  3. **Users:** Admin role assignments (Global Admin, Security Admin, etc.)
  4. **Grant:** Require MFA
  5. Enable policy
  
  **Manual Steps (PowerShell):**
  ```powershell
  # Enforce MFA registration for admins
  New-MgPolicyAdminConsentRequestPolicy -IsAdminConsentRequestEnabled $true
  ```

- **Action 3: Deploy Microsoft Sentinel Analytics Rules for Privileged Account Monitoring**
  - **Applies To:** All organizations with Entra ID and/or Azure
  
  **Manual Steps (Sentinel):**
  1. Go to **Microsoft Sentinel** → **Analytics** → **Rule templates**
  2. Search and activate the following rules:
     - "Authentications of Privileged Accounts Outside of Expected Controls"
     - "Suspicious Entra ID role assignment"
     - "Multiple failed sign-in attempts"
     - "New Global Admin assigned"
  3. Configure alert thresholds and notification channels

- **Action 4: Enable Continuous Access Evaluation (CAE) for Real-Time Revocation**
  - **Applies To:** All admin accounts with active sessions
  
  **Manual Steps:**
  1. **Entra ID** → **Identity** → **Continuous Access Evaluation**
  2. Enable CAE for:
     - Sign-in token revocation (immediate if account is disabled)
     - Location-based policies (revoke if access from blocked location)
     - Device compliance enforcement
  3. Configure CAE in your applications via Microsoft Graph API

### Priority 2: HIGH

- **Action 1: Implement Just-In-Time (JIT) Admin Access via PIM**
  - **Applies To:** Sensitive admin roles (Global Admin, Security Admin, Exchange Admin)
  
  **Manual Steps:**
  1. **Entra ID** → **Privileged Identity Management** → **Roles**
  2. For each privileged role:
     - Set **Activation method** to **Require Approval**
     - Set **Approval chain** to at least 2 approvers
     - Set **Activation duration** to **4 hours max**
  3. Require MFA at activation time

- **Action 2: Enable Azure Defender for Identity (for On-Premises AD Monitoring)**
  
  **Manual Steps:**
  1. Deploy Azure Defender for Identity sensor on domain controllers
  2. Configure alert rules:
     - "Suspicious lateral movement"
     - "Brute force attacks"
     - "Golden ticket generation"
     - "Pass-the-hash attempts"
  3. Configure notifications to your SOC

- **Action 3: Create Custom Detection Rules in Sentinel**
  
  **KQL Query Template:**
  ```kusto
  # Detect privilege escalation by non-standard users
  AuditLogs
  | where OperationName contains "Add" and OperationName contains "role"
  | where not(InitiatedBy.user.userPrincipalName in ("admin1@company.com", "admin2@company.com"))
  | extend TargetUser = TargetResources[0].displayName
  | project TimeGenerated, InitiatedBy.user.userPrincipalName as Initiator, TargetUser, Result
  ```

### Access Control & Compliance Validation

- **Regular Admin Audits:** Monthly review of all admin role assignments.
  
  **PowerShell Script (Monthly Audit):**
  ```powershell
  Connect-MgGraph -Scopes "RoleManagement.Read.Directory"
  
  # List all global admins
  $globalAdminRole = Get-MgDirectoryRole -Filter "displayName eq 'Global Administrator'"
  Get-MgDirectoryRoleMember -DirectoryRoleId $globalAdminRole.Id | Select-Object -Property DisplayName, UserPrincipalName
  ```

- **Segregation of Duties:** No single user should hold multiple high-privilege roles.

### Validation Command (Verify Monitoring is Active)

```powershell
# Check if Sentinel is receiving admin logs
az sentinel list --resource-group <rg> --workspace-name <workspace> | jq '.[] | .kind'

# Should output: "Scheduled" or "NRT" (Near Real-Time) for analytics rules
```

**Expected Output (If Monitoring Active):**
```
[
  "Scheduled",
  "NRT",
  "Scheduled"
]
```

---

## 8. DETECTION & INCIDENT RESPONSE

### Microsoft Sentinel KQL Queries

**Query 1: Detect Unusual Admin Sign-Ins (Geographic Anomaly)**

```kusto
SigninLogs
| where tolower(UserPrincipalName) in ("admin1@company.com", "admin2@company.com")
| where ResultType == 0
| extend Location = parse_json(LocationDetails)
| summarize by Location.countryOrRegion, TimeGenerated, UserPrincipalName
| where Location.countryOrRegion !in ("United States", "France", "Germany")  // Set to org's normal countries
```

**What This Detects:**
- Admin signs in from unexpected geographic location (potential account compromise).

**Query 2: Privilege Escalation via Unexpected Role Assignment**

```kusto
AuditLogs
| where OperationName == "Add member to role"
| where Result == "success"
| extend Initiator = InitiatedBy.user.userPrincipalName
| extend TargetUser = TargetResources[0].displayName
| extend Role = TargetResources[0].modifiedProperties[0].newValue
| where not(Initiator in ("admin1@company.com", "changemanagement@company.com"))
```

**What This Detects:**
- Unauthorized users attempting to grant themselves or others admin roles.

**Query 3: Detect Suspicious OAuth Consent by Admin Accounts**

```kusto
AuditLogs
| where OperationName == "Consent to application"
| where InitiatedBy.user.userPrincipalName in (
    // List of known admin accounts
    "admin1@company.com", "admin2@company.com"
)
| where TargetResources[0].displayName !in ("Microsoft Graph", "Office 365 Management API")
```

**What This Detects:**
- Admin accounts granting consent to non-Microsoft applications (potential persistence mechanism).

---

## 9. RELATED ATTACK CHAIN

| Step | Phase | Technique | Description |
|---|---|---|---|
| **1** | **Initial Access** | [IA-PHISH-001] Device Code Phishing | Attacker compromises privileged user account |
| **2** | **Privilege Escalation** | T1547 / T1556 | Attacker elevates or maintains admin access |
| **3** | **Current Step** | **[MISCONFIG-016]** | **Organization fails to detect admin activity** |
| **4** | **Persistence** | Golden Ticket / OAuth Token Theft | Attacker establishes persistent backdoor |
| **5** | **Impact** | Ransomware / Data Exfiltration | Attacker operates undetected for weeks |

---

## 10. REAL-WORLD EXAMPLES

#### Example 1: MOVEit Transfer Zero-Day (2023) – Undetected Admin Access

- **Target:** Thousands of organizations using MOVEit Transfer
- **Timeline:** 2023 (May–June)
- **Technique Status:** Attackers gained admin access but many organizations didn't detect it due to missing monitoring.
- **Impact:** Data exfiltration of PII from breached servers; ransom demands.
- **Reference:** [CISA Advisory on MOVEit Exploitation](https://www.cisa.gov/news-events/alerts/2023/06/01/cisa-adds-two-known-exploited-vulnerabilities-catalog)

#### Example 2: Microsoft Exchange Server ProxyLogon / ProxyShell (2021) – Admin Account Compromise

- **Target:** Enterprise Exchange Server deployments
- **Timeline:** 2021 (March onwards)
- **Technique Status:** Attackers compromised Exchange admin accounts; many organizations didn't detect persistence for months.
- **Impact:** Email exfiltration, ransomware deployment, lateral movement to Azure AD.
- **Reference:** [Microsoft Security Blog: ProxyLogon Post-Exploitation Attempts](https://msrc-blog.microsoft.com/2021/03/02/3-23-21-patch-tuesday-exchange-server-security-updates/)

#### Example 3: Okta Admin Console Breach (2023) – Undetected Admin Access

- **Target:** Okta customers
- **Timeline:** 2023 (September)
- **Technique Status:** Attacker accessed Okta admin console but failed to maintain persistence due to detection; however, organizations depending on Okta authentication were exposed.
- **Impact:** Potential for session token theft and lateral movement to downstream applications.
- **Reference:** [Okta Security Incident Report 2023](https://www.okta.com/security-incident-2023/)

---

## 11. REMEDIATION CHECKLIST

- [ ] Enabled Microsoft Entra Privileged Identity Management (PIM)
- [ ] Configured PIM to require approval for all admin activations
- [ ] Enforced MFA for all admin role assignments
- [ ] Set maximum admin session duration to 8 hours
- [ ] Deployed Microsoft Sentinel with privileged account monitoring rules
- [ ] Enabled continuous audit logging for all admin operations
- [ ] Configured alert thresholds for unusual admin activity
- [ ] Implemented Conditional Access policies for admin sign-in
- [ ] Deployed Azure Defender for Identity (on-premises)
- [ ] Created and tested incident response playbooks for admin compromise
- [ ] Scheduled monthly admin access audits
- [ ] Implemented Just-In-Time (JIT) access for sensitive roles
- [ ] Enabled real-time log forwarding to SIEM
- [ ] Trained security team on alert triage and investigation procedures
- [ ] Documented privileged account monitoring policy
- [ ] Verified all admin accounts have approved MFA methods enrolled

---

## 12. ADDITIONAL NOTES

- **Cost Considerations:** PIM and Sentinel licensing costs may impact smaller organizations; consider Microsoft Defender for Cloud as a lower-cost alternative for basic monitoring.
- **Tuning Detection Rules:** Initial false positive rates may be high; work with SOC team to adjust thresholds over time.
- **Compliance Automation:** Use Azure Policy to automatically enforce audit logging and monitoring prerequisites across subscriptions.
- **Recovery Procedures:** Document break-glass account procedures (emergency admin access) separate from monitored admin accounts; encrypt and store in vault.

---