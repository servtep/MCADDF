# CA-UNSC-012: MIP Master Key Theft

**MITRE ATT&CK Technique:** T1552.001 (Unsecured Credentials: Credentials in Files)  
**CVE:** N/A (Configuration-based vulnerability)  
**Platforms:** Microsoft 365 (M365)  
**Severity:** CRITICAL  
**Viability:** ACTIVE  
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

## 1. EXECUTIVE SUMMARY

MIP (Microsoft Information Protection) master key theft is a critical credential access attack that exploits weakly protected encryption keys used to decrypt sensitive organizational data. Threat actors who obtain MIP tenant keys, encryption keys from Azure Key Vault, or signing keys can forge access tokens, decrypt protected documents, and impersonate users across Microsoft 365 services. The Storm-0558 incident (July 2023) demonstrated real-world exploitation, where Chinese threat actors compromised an MSA signing key and accessed Exchange Online for 25+ organizations. This module covers detection, response, and mitigation strategies specific to M365 environments.

---

## 2. ATTACK NARRATIVE

### Attack Chain Overview

**Stage 1: Initial Access & Reconnaissance**
- Compromised administrator account or insider with access to Azure Key Vault or on-premises HSM
- Exploitation of overly permissive RBAC (Role-Based Access Control) roles
- Lateral movement from compromised on-premises AD RMS servers
- Supply chain compromise targeting HSM or Key Vault administrators

**Stage 2: Key Extraction**
- Direct access to Azure Key Vault using stolen credentials
- Export of customer-managed BYOK (Bring Your Own Key) materials
- Extraction of encryption keys from on-premises HSM devices
- Download of Trusted Publishing Domain (TPD) files from AD RMS
- Access to DPAPI-encrypted key material on compromised servers

**Stage 3: Token Forging & Lateral Movement**
- Use of extracted signing keys to forge Azure AD access tokens
- Impersonation of legitimate users and service principals
- Access to Exchange Online, SharePoint, Teams, OneDrive, and custom applications
- Bulk export of sensitive data without leaving traditional authentication logs

**Stage 4: Persistence & Data Exfiltration**
- Creation of rogue service principals with API permissions
- Bulk download of encrypted documents with decryption using stolen keys
- Modification of encryption settings to re-encrypt data under attacker-controlled keys
- Establishment of long-term backdoor access

### Real-World Example: Storm-0558 (July 2023)

**Timeline:**
- **May 2023:** Storm-0558 compromised a legacy MSA (Microsoft Service Account) signing key in Microsoft's internal environment
- **Exploitation Period:** ~2 months with minimal detection
- **Discovery:** Wiz Research identified forged tokens in customer audit logs
- **Impact:** 25+ organizations including US government agencies
- **Access:** Exchange Online mailboxes containing classified communications

**Attack Characteristics:**
- No traditional VPN/multi-factor authentication logs (tokens already validated)
- Victim organizations could not detect token forgery without E5 audit logs
- Attacker maintained access after key revocation through previously established sessions
- Affected multiple app types: Personal Account (v2.0), Multi-tenant AD (v2.0), and organizational OAuth apps

---

## 3. TECHNICAL DETAILS

### MIP Key Types & Hierarchy

| Key Type | Owner | Use Case | Viability | Detection Difficulty |
|----------|-------|----------|-----------|----------------------|
| **Tenant Root Key (Microsoft-managed)** | Microsoft | Default encryption for all MIP data | ACTIVE | Medium |
| **BYOK (Customer-managed in Key Vault)** | Customer | High compliance requirements (GDPR, HIPAA) | ACTIVE | Hard |
| **DKE (Double Key Encryption)** | Customer + Microsoft | Dual control / zero-knowledge encryption | ACTIVE | Very Hard |
| **AD RMS TPD Keys** | Legacy / On-premises | Migrated from on-premises AD RMS | DEPRECATED | Medium |
| **Application Signing Keys** | Microsoft / Customer | OAuth2 token validation | ACTIVE | Medium |

### Key Storage Locations

**Azure Key Vault (Cloud-based BYOK):**
```
/subscriptions/{subscription}/resourcegroups/{resource-group}/providers/microsoft.keyvault/vaults/{vault-name}
Key names: ContosoRmsKey, ContosoEncryptionKey
Key versions: Multiple (rotation tracked by version GUID)
```

**On-Premises HSM (nCipher, Luna, Thales):**
```
HSM Slot: 0, 1, 2 (depends on hardware configuration)
Key Labels: AIP-Master-Key, RMS-Encryption-Key-2024
Backup: Tokenized key files + security world files
```

**Windows Registry (Legacy/Cached):**
```
HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\MSIPC\ServiceLocation
HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\MSIPC\OFFLINE_KEY
HKEY_CURRENT_USER\Software\Microsoft\Office\16.0\Outlook\Security
```

**Azure Rights Management Service Storage:**
```
Service Fabric encrypted storage
Key identifiers: <GUID-format>
Metadata: Key creation date, rotation schedule, dependent applications
```

### Attack Execution Methods

**Method 1: Azure Key Vault Export (Requires "Get", "UnwrapKey" Permissions)**
```powershell
# Attacker with Key Vault access
$key = Get-AzKeyVaultKey -VaultName "production-keyvault" -Name "MIP-Master-Key"
$key | Export-AzKeyVaultKey -Destination "C:\stolen-key.pfx"
# Result: Plaintext key exported to attackable location
```

**Method 2: Azure RMS Super User Bypass**
```powershell
# If attacker enables super user feature
Enable-AipServiceSuperUserFeature
Add-AipServiceSuperUser -EmailAddress attacker@domain.com
# Attacker can now decrypt any document in tenant
```

**Method 3: BYOK Access During Transfer**
- Intercept key transfer during BYOK import to Key Vault
- Compromise HSM security world before Key Vault import
- Extract from unencrypted backup files

**Method 4: Service Principal Credential Theft**
```powershell
# Stolen service principal with Microsoft.KeyVault/vaults/keys/read permission
$credential = Get-AzAccessToken -ResourceUrl "https://vault.azure.net"
# Use token to query Key Vault API for key material
```

---

## 4. MITRE ATT&CK MAPPING

**Technique:** T1552.001 - Unsecured Credentials: Credentials in Files  
**Tactics Executed:**
- **Credential Access (TA0006):** Extract encryption keys from files/registry/vault
- **Defense Evasion (TA0005):** Bypass encryption by obtaining keys directly
- **Lateral Movement (TA0008):** Use compromised keys to access other tenants/services
- **Exfiltration (TA0010):** Decrypt and exfiltrate protected data

**Sub-techniques Associated:**
- T1552.002 - Credentials in Registry
- T1552.004 - Private Keys
- T1552.005 - Cloud Instance Metadata API (for managed identities)
- T1098.004 - SSH Authorized Keys (if using SSH-based signing)

**Related Techniques:**
- T1110 - Brute Force (attacking key vault access)
- T1078.004 - Cloud Accounts (compromised service principal)
- T1555 - Credentials from Password Stores
- T1187 - Forced Authentication (harvesting tokens via AiTM proxy)

---

## 5. TOOLS & TECHNIQUES

### Attacker Tools

| Tool | Purpose | ViabilityStatus | Download URL |
|------|---------|-----------------|--------------|
| **LaZagne** | Credential harvesting from browsers, email, cloud apps | ACTIVE | https://github.com/AlessandroZ/LaZagne |
| **Mimikatz** | LSASS memory credential dumping | ACTIVE | https://github.com/gentilkiwi/mimikatz |
| **SessionGopher** | PowerShell session history + WinRM credential extraction | ACTIVE | https://github.com/Arvanaghi/SessionGopher |
| **Snaffler** | Network share enumeration for credential files | ACTIVE | https://github.com/SnaffCon/Snaffler |
| **WinPwn** | Integrated toolkit for sensitive file discovery | ACTIVE | https://github.com/S3cur3Th1sSh1t/WinPwn |
| **Az.KeyVault Module** | PowerShell key export (if permissions exist) | ACTIVE | Built-in to Azure PowerShell |
| **Get-AipServiceKeys** | Query MIP tenant keys | ACTIVE | AIPService PowerShell module |

### Atomic Red Team Tests (T1552.001)

**Supported Platforms:** Windows, macOS, Linux

| Test Name | Command | Executor | Detection Trigger |
|-----------|---------|----------|------------------|
| Find AWS credentials | `find / -name "credentials" -type f` | bash/sh | File enumeration, process execution |
| Extract with LaZagne | `python2 laZagne.py all` | bash | Child process creation, network calls |
| Extract with grep | `grep -ri password /` | sh | Recursive file search, process execution |
| Extracting with findstr | `findstr /si pass *.xml *.doc *.txt` | PowerShell | File system enumeration |
| Access unattend.xml | `type C:\Windows\Panther\unattend.xml` | cmd.exe | Registry/file access audit |
| Find GitHub credentials | `find /home -name .netrc` | bash | Sensitive file access |
| WinPwn sensitivefiles | IEX + sensitivefiles function | PowerShell | Command-line logging, network downloads |
| WinPwn Snaffler | IEX + Snaffler function | PowerShell | Network share enumeration logs |
| List Credential Files | `Get-ChildItem -Hidden C:\Users\*\AppData\Roaming\Microsoft\Credentials` | PowerShell | Registry + file system auditing |
| Find Azure credentials | `find / -name "msal_token_cache.json"` | bash | Token file access logging |
| Find GCP credentials | `find / -path "*/.config/gcloud"` | bash | Config file enumeration |

**Execution Example:**
```powershell
# Atomic test execution
Invoke-AtomicTest T1552.001 -TestName "Extracting passwords with findstr"

# Expected telemetry:
# - Process: PowerShell.exe (PID: 4521)
# - CommandLine: findstr /si pass *.xml *.doc *.txt
# - Target files: web.config, machine.config, connection strings
```

---

## 6. FORENSIC ARTIFACTS

### Registry Keys Accessed During Attack

| Registry Path | Event ID | Significance | Attacker Indicator |
|---------------|----------|--------------|-------------------|
| `HKLM\SOFTWARE\Microsoft\Cryptography` | 4657, 4663 | Crypto provider status | Unusual read access frequency |
| `HKEY_LOCAL_MACHINE\SECURITY\Policy\Secrets\*` | 4657 | LSA secrets (DPAPI-encrypted) | Privilege elevation for access |
| `HKCU\Software\Microsoft\MSIPC\ServiceLocation` | 4657 | MIP service endpoint config | Modification = suspicious |
| `HKCU\Software\Microsoft\Office\16.0\Outlook\Outlook Security` | 4657 | Outlook encryption settings | Disablement of security features |
| `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\CredentialsDom` | 4657 | Credential delegation policy | Relaxed policy = attack precondition |
| `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs` | 4663 | Recently accessed files | Encryption keys or config files |

### File System Artifacts

| Artifact Path | Artifact Type | Significance |
|---------------|---------------|--------------|
| `%APPDATA%\Microsoft\Credentials\*` | Binary files | Windows Credential Manager encrypted credentials |
| `%LOCALAPPDATA%\Microsoft\Credentials\*` | Binary files | Additional credential storage |
| `C:\Users\%USERNAME%\.azure\msal_token_cache.json` | JSON | Azure CLI/PowerShell token cache |
| `C:\Users\%USERNAME%\.config\gcloud\` | Directory | GCP credentials (if multi-cloud environment) |
| `C:\Users\%USERNAME%\.aws\credentials` | Text file (plaintext) | AWS access key storage |
| `/home/*/.netrc` | Text file (plaintext) | GitHub/FTP credentials (Unix-like) |
| `C:\Windows\Panther\unattend.xml` | XML | Installation credentials (legacy) |
| `C:\Users\%USERNAME%\AppData\Local\Microsoft\OneDrive\settings\Personal` | Registry hive | OneDrive encryption keys |
| `C:\Program Files\Microsoft Azure AD Connect\Data\` | Directory | Azure AD Connect sync keys |

### Windows Event Log Indicators

| Event ID | Log Source | Significance | Detection Condition |
|----------|-----------|--------------|-------------------|
| **4657** | Security | Audit Registry Value Modified | REG_SZ or REG_BINARY changes to crypto paths |
| **4663** | Security | Audit File/Object Access | Read access to %APPDATA%\Microsoft\Credentials |
| **4768** | Security | Kerberos TGT Granted | Forged token detection requires E5 audit logs |
| **4769** | Security | Kerberos Service Ticket Granted | Unusual service principal requests |
| **5136** | Directory Services | Active Directory Object Changed | Replication metadata tampering |
| **4688** | Security | Process Creation | Child processes spawned by suspicious tools |
| **17** | Sysmon | PipeEvent | Named pipe connections to elevated processes |
| **12-14** | Sysmon | RegistryEvent | Registry operations on key material paths |
| **10** | Sysmon | ProcessAccess | LSASS access attempts for credential dumping |
| **23** | Sysmon | FileDelete | Deletion of audit logs or key backups |

---

## 7. SPLUNK DETECTION

### Splunk Prerequisites
- **Data Source:** Azure Audit Logs, Office 365 Management API, Sysmon Event Logs
- **Required Add-on:** Splunk Add-on for Microsoft Cloud Services v4.0+
- **Source Types:** `azure:aad:audit`, `o365:management:activity`, `wineventlog:security`, `XmlWinEventLog:Microsoft-Windows-Sysmon/Operational`

### Detection 1: Suspicious Azure Key Vault Access

**Detection Type:** Anomaly Detection  
**Alert Severity:** HIGH  
**Frequency:** Every 5 minutes  
**Applies To:** Azure Subscriptions with Key Vault resources

**Splunk Query:**
```spl
index=azure sourcetype=azure:aad:audit operationName IN ("Decrypt Key", "Get Key", "Get Key Versions", "Export Key", "Backup Key", "Restore Key") 
| stats count, values(initiatedBy.user.userPrincipalName) as User, values(resourceDisplayName) as KeyName, values(result) as Result by correlationId 
| where count > 5 
| eval RiskScore=case(
    Result=="Failure" AND count>10, 95,
    operationName=="Export Key" AND count>=1, 98,
    User LIKE "%service%", 85,
    1=1, 70
) 
| where RiskScore > 80
```

**What This Detects:**
- Bulk key access operations indicating enumeration
- Failed key export attempts (brute force on key recovery)
- Service principal accessing keys outside business hours
- Unusual geographic IP addresses querying key vault

**Alert Action:** Create incident, notify security team, initiate Key Vault access review

---

### Detection 2: Azure RMS Super User Feature Activation

**Detection Type:** Behavioral Anomaly  
**Alert Severity:** CRITICAL  
**Frequency:** Real-time

**Splunk Query:**
```spl
index=azure sourcetype=azure:aad:audit operationName IN ("Enable-AipServiceSuperUserFeature", "Add-AipServiceSuperUser", "Set-AipServiceSuperUserGroup") result=success 
| dedup correlationId 
| table creationTime, initiatedBy.user.userPrincipalName, operationName, targetResources 
| eval SuspiciousRoleAssignment=if(match(initiatedBy.user.userPrincipalName, "(?i)(svc_|robot|automation|service)"), 1, 0) 
| where SuspiciousRoleAssignment=1 OR operationName="Enable-AipServiceSuperUserFeature"
```

**False Positive Analysis:**
- Legitimate IT support staff enabling super user for compliance discovery
- Authorized eDiscovery operations requiring bulk decryption
- Tuning: Whitelist known eDiscovery administrators; require approval logs

**Tuning:**
```spl
index=azure sourcetype=azure:aad:audit operationName="Enable-AipServiceSuperUserFeature" 
| where NOT (initiatedBy.user.userPrincipalName IN ("compliance@domain.com", "ediscovery-svc@domain.com"))
```

---

### Detection 3: Unauthorized MIP Key Export Attempts

**Detection Type:** TTP Detection  
**Alert Severity:** CRITICAL  
**Applies To:** Organizations using BYOK

**Splunk Query:**
```spl
index=azure sourcetype=o365:management:activity Workload=AzureRMS Operation IN ("ExportTenantKey", "DownloadTemplate", "Get-AipServiceKeys") 
| lookup builtin_list result as IsAuthorized 
| where IsAuthorized=false 
| stats count by UserId, Operation, ClientIP, UserAgent 
| eval RiskIndicator=if(ClientIP NOT IN ("10.0.0.0/8", "172.16.0.0/12"), "External IP", "Internal IP") 
| where RiskIndicator="External IP" OR count > 2
```

**Forensic Pivot:**
```spl
index=azure sourcetype=o365:management:activity Operation="ExportTenantKey" 
| search UserId=attacker@domain.com 
| transaction UserId clientIP 
| where duration > 300 
| table UserId, Operation, ClientIP, UsageLocation, TimeGenerated
```

---

### Detection 4: Sysmon Registry Access to Credential Paths

**Detection Type:** Host-based Detection  
**Alert Severity:** HIGH  
**Requires:** Sysmon Event Logs from client/server machines

**Splunk Query:**
```spl
index=windows source=XmlWinEventLog:Microsoft-Windows-Sysmon/Operational EventCode IN (12, 13, 14) 
| regex TargetObject="(?i)(MSIPC|CredentialsDom|Outlook.*Security)" 
| stats count, values(Image) as Process, values(User) as User by Computer, TargetObject 
| where count > 10 
| eval Severity=case(
    Image LIKE "%powershell%", "High",
    Image LIKE "%cmd.exe%", "Medium",
    Image LIKE "%explorer.exe%", "Low",
    1=1, "Medium"
)
```

**Detection Condition:**
- Registry path: `HKLM\SOFTWARE\Microsoft\MSIPC\*`
- Registry path: `HKCU\Software\Microsoft\Office\16.0\Outlook\Security`
- Process: powershell.exe, cmd.exe, regedit.exe, reg.exe
- Action: Read (suspicious for crypto-related paths)

---

## 8. MICROSOFT SENTINEL DETECTION

### Sentinel Prerequisites
- **Required Tables:** AuditLogs, SigninLogs, AzureRMS, SecurityEvent
- **Required Fields:** OperationName, InitiatedBy, TargetResources, Result, CorrelationId
- **Data Connector:** Entra ID (Azure AD), Azure Activity, Office 365

### Query 1: Detect MIP Master Key Export Attempts

**Rule Configuration:**
- **Required Table:** AuditLogs, AzureRMS  
- **Required Fields:** OperationName, InitiatedBy, Result, TargetResources[0].displayName, CorrelationId
- **Alert Severity:** Critical  
- **Frequency:** Every 5 minutes  
- **Lookback Window:** 1 hour  
- **Applies To Versions:** M365 E3+, Azure AD all versions

**KQL Query:**
```kusto
AuditLogs
| where OperationName in ("Decrypt Key", "Get Key", "Export Key", "ExportTenantKey", "Download Template")
    and Result == "Success"
| extend InitiatedByUser = tostring(InitiatedBy.user.userPrincipalName)
| extend TargetKeyName = tostring(TargetResources[0].displayName)
| extend OperationTime = TimeGenerated
| summarize KeyAccessCount = dcount(OperationName), AccessedKeys = make_set(TargetKeyName), 
    UniqueInitiators = dcount(InitiatedByUser) by InitiatedByUser, ClientIP = InitiatedBy.user.ipAddress, tostring(UserAgent)
| where KeyAccessCount > 3 
    or AccessedKeys has "MasterKey" 
    or AccessedKeys has "RmsKey"
| extend RiskScore = 
    case(
        InitiatedByUser matches regex @"(svc_|service|robot|automation)" , 75,
        KeyAccessCount > 10, 90,
        ClientIP startswith "192.168" or ClientIP startswith "10.", 40,
        1=1, 60
    )
| where RiskScore >= 75
| project TimeGenerated, InitiatedByUser, ClientIP, KeyAccessCount, AccessedKeys, RiskScore, OperationName
```

**What This Detects:**
- Multiple successful key decryption operations (threshold: >3 in 1 hour)
- Service principals or automation accounts accessing MasterKey
- External IP addresses exporting keys
- Anomalous access patterns compared to baseline (requires ML model integration)

**Manual Configuration Steps (Azure Portal):**
1. Navigate to **Azure Portal** → **Microsoft Sentinel**
2. Select your workspace → **Analytics**
3. Click **+ Create** → **Scheduled query rule**
4. **General Tab:**
   - Name: `Detect MIP Master Key Export Attempts`
   - Severity: `Critical`
5. **Set rule logic Tab:**
   - Paste KQL query above
   - Run query every: `5 minutes`
   - Lookup data from the last: `1 hour`
6. **Incident settings Tab:**
   - Enable **Create incidents**
   - Grouping: By CorrelationId
7. Click **Review + create**

**Manual Configuration Steps (PowerShell):**
```powershell
# Connect to Sentinel workspace
Connect-AzAccount
$ResourceGroup = "YourResourceGroup"
$WorkspaceName = "YourSentinelWorkspace"

# Create the analytics rule
New-AzSentinelAlertRule -ResourceGroupName $ResourceGroup -WorkspaceName $WorkspaceName `
  -DisplayName "Detect MIP Master Key Export Attempts" `
  -Query @"
AuditLogs
| where OperationName in ("Decrypt Key", "Get Key", "Export Key")
| where Result == "Success"
| extend InitiatedByUser = tostring(InitiatedBy.user.userPrincipalName)
| summarize KeyAccessCount = count() by InitiatedByUser
| where KeyAccessCount > 3
"@ `
  -Severity "Critical" `
  -Enabled $true `
  -SuppressionDuration (New-TimeSpan -Hours 1) `
  -Frequency (New-TimeSpan -Minutes 5) `
  -Period (New-TimeSpan -Hours 1)
```

**Source:** [Microsoft Sentinel GitHub - Entra ID Detection Rules](https://github.com/Azure/Azure-Sentinel)

---

### Query 2: Anomalous Service Principal Key Access

**Rule Configuration:**
- **Required Table:** AuditLogs, SigninLogs
- **Alert Severity:** High
- **Applies To:** M365 E3+, Entra ID

**KQL Query:**
```kusto
SigninLogs
| where ServicePrincipalName != ""
| where ResultType == 0  // Successful logon
| extend ServicePrincipalId = ServicePrincipalId
| join kind=inner (
    AuditLogs
    | where OperationName in ("Get Key", "Decrypt Key", "List Keys")
    | extend ServicePrincipalId = extractjson("$.TargetResources[0].id", tostring(TargetResources))
) on ServicePrincipalId
| summarize SigninCount = count(), KeyOpsCount = dcount(OperationName) by ServicePrincipalName, ClientIP, TimeGenerated
| where KeyOpsCount >= 5 and SigninCount >= 2
| extend AnomalyScore = (KeyOpsCount * SigninCount) / 10
| where AnomalyScore > 1.5
```

**What This Detects:**
- Service principals authenticating and immediately accessing keys
- Multiple key operations in rapid succession post-authentication
- Out-of-policy service principal privilege escalation

---

## 9. WINDOWS EVENT LOG MONITORING

### Event ID: 4657 (Registry Value Modified)

**Log Source:** Security  
**Trigger:** Modification to Registry values under HKLM\SOFTWARE\Microsoft\MSIPC or HKCU\Office encryption paths  
**Filter:** Object Name contains "MSIPC" or "Outlook" and "Security"  
**Applies To Versions:** Server 2016+, Windows 10+

**Manual Configuration Steps (Group Policy):**
1. Open **Group Policy Management Console** (gpmc.msc)
2. Navigate to **Computer Configuration** → **Policies** → **Windows Settings** → **Security Settings** → **Advanced Audit Policy Configuration**
3. Expand **Object Access**
4. Enable: **Audit Registry**
5. Set to: **Success and Failure**
6. Run `gpupdate /force` on target machines

**Forensic Query (PowerShell):**
```powershell
$StartTime = (Get-Date).AddHours(-24)
Get-WinEvent -FilterHashtable @{
    LogName = "Security"
    Id = 4657
    StartTime = $StartTime
} | Where-Object {
    $_.Properties[10].Value -match "MSIPC|Outlook" -and
    $_.Properties[13].Value -ne "%%1900"  # Not System account
} | Select-Object TimeCreated, @{N="User";E={$_.Properties[1].Value}}, 
    @{N="Registry Path";E={$_.Properties[10].Value}},
    @{N="Old Value";E={$_.Properties[14].Value}},
    @{N="New Value";E={$_.Properties[15].Value}}
```

---

### Event ID: 4663 (Attempt to Access Object)

**Log Source:** Security  
**Trigger:** Read access to credential files in %APPDATA%\Microsoft\Credentials  
**Applies To Versions:** Server 2016+

**Manual Configuration Steps (Local Policy):**
1. Open **Local Security Policy** (secpol.msc)
2. Navigate to **Security Settings** → **Advanced Audit Policy Configuration** → **System Audit Policies** → **Object Access**
3. Enable: **Audit File System**
4. Set to: **Success and Failure**
5. Run `auditpol /set /subcategory:"File System" /success:enable /failure:enable`

---

### Event ID: 5136 (Directory Service Object Was Modified)

**Log Source:** Directory Services  
**Trigger:** Replication metadata changes indicating key rollover or breach response  
**Applies To:** Domain Controllers  
**Example:** Azure AD Connect sync key rotation

**Detection (PowerShell):**
```powershell
Get-WinEvent -FilterHashtable @{
    LogName = "Directory Service"
    Id = 5136
    StartTime = (Get-Date).AddHours(-24)
} | Where-Object {
    $_.Message -match "(msDS-KeyVersionNumber|msDS-EncodedRDN)" -and
    $_.Message -match "Attribute Modification"
} | Measure-Object
```

---

## 10. SYSMON DETECTION PATTERNS

**Minimum Sysmon Version:** 13.0+  
**Supported Platforms:** Windows 10, Windows Server 2016+

**Sysmon Event IDs to Monitor:**
- **Event ID 12/13/14:** Registry operations (MSIPC, Office encryption paths)
- **Event ID 10:** Process memory access (LSASS credential dumping)
- **Event ID 11:** File creation (temp files, key exports)
- **Event ID 23:** File deletion (log tampering, key cleanup)

**Sysmon XML Configuration:**
```xml
<Sysmon schemaversion="4.22">
  <HashAlgorithms>md5,sha256</HashAlgorithms>
  
  <!-- Detect Registry Access to Encryption Key Paths -->
  <RegistryEvent onmatch="include">
    <TargetObject condition="contains">MSIPC</TargetObject>
    <TargetObject condition="contains">Outlook\Security</TargetObject>
    <TargetObject condition="contains">Office\16.0\Encryption</TargetObject>
  </RegistryEvent>
  
  <!-- Detect LSASS Access (Credential Dumping) -->
  <ProcessAccess onmatch="include">
    <TargetImage condition="image">lsass.exe</TargetImage>
    <GrantedAccess condition="is">0x1438</GrantedAccess>
    <GrantedAccess condition="is">0x1400</GrantedAccess>
    <GrantedAccess condition="is">0x1010</GrantedAccess>
  </ProcessAccess>
  
  <!-- Detect Key Export/Backup File Creation -->
  <FileCreate onmatch="include">
    <TargetFilename condition="contains">\.pfx</TargetFilename>
    <TargetFilename condition="contains">\.pem</TargetFilename>
    <TargetFilename condition="contains">\.key</TargetFilename>
    <TargetFilename condition="contains">backup</TargetFilename>
    <Image condition="is">powershell.exe</Image>
  </FileCreate>
  
  <!-- Detect Malicious Credential Harvesting Tools -->
  <ProcessCreate onmatch="include">
    <CommandLine condition="contains">LaZagne</CommandLine>
    <CommandLine condition="contains">SessionGopher</CommandLine>
    <CommandLine condition="contains">Snaffler</CommandLine>
  </ProcessCreate>
</Sysmon>
```

**Manual Configuration Steps:**
1. Download Sysmon from [Microsoft Sysinternals](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)
2. Create config file `sysmon-mip-config.xml` with XML above
3. Install Sysmon with config:
   ```cmd
   sysmon64.exe -accepteula -i sysmon-mip-config.xml
   ```
4. Verify installation:
   ```powershell
   Get-Service Sysmon64
   Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 10
   ```

---

## 11. MICROSOFT DEFENDER FOR CLOUD

### Sentinel/MDC Alert: "Suspicious Key Vault Access Pattern Detected"

**Alert Name:** KeyVaultSuspiciousAccess  
**Severity:** High  
**Description:** Microsoft Defender for Cloud detects multiple failed key retrieval attempts followed by a successful export operation, indicating potential key theft via brute force or compromised credentials  
**Applies To:** All subscriptions with Defender for Cloud enabled + Key Vault resources  
**Remediation:**  
1. Rotate compromised keys immediately
2. Review Key Vault access logs (last 90 days)
3. Reset credentials for all service principals with Key Vault access
4. Enable Key Vault purge protection and soft delete

**Manual Configuration Steps (Enable Defender for Cloud):**
1. Navigate to **Azure Portal** → **Microsoft Defender for Cloud**
2. Go to **Environment settings**
3. Select your subscription
4. Under **Defender plans**, enable:
   - **Defender for Servers**: ON (detects malware accessing local credential stores)
   - **Defender for Key Vault**: ON (monitors key access patterns)
   - **Defender for SQL**: ON (detects database encryption key access)
5. Click **Save**
6. Go to **Security alerts** to view triggered alerts
7. Configure automated response using Sentinel playbooks

**Reference:** [Microsoft Defender for Cloud Alerts - Key Vault](https://learn.microsoft.com/en-us/defender-cloud/alerts-reference)

---

## 12. MICROSOFT PURVIEW (UNIFIED AUDIT LOG)

### Query: Suspicious MIP Key Operations

**Operation:** GetAipServiceKeys, AddAipServiceSuperUser, ExportTenantKey  
**Workload:** Azure Active Directory, AzureRMS  
**Details:** Monitor AuditData JSON blob for key export events

**PowerShell Query:**
```powershell
Search-UnifiedAuditLog `
  -Operations "Get Key", "Export Key", "Decrypt Key", "Enable-AipServiceSuperUserFeature" `
  -StartDate (Get-Date).AddDays(-7) `
  -EndDate (Get-Date) `
  -FreeText "MIP" `
  -ResultSize 10000 | Select-Object CreationDate, UserIds, Operations, AuditData | 
  Export-Csv -Path "C:\MIP-Key-Audit.csv"
```

**Manual Configuration Steps (Enable Unified Audit Log):**
1. Navigate to **Microsoft Purview Compliance Portal** (https://compliance.microsoft.com)
2. Go to **Audit** (left menu)
3. If not enabled, click **Turn on auditing**
4. Wait 24-48 hours for log retention to activate

**Manual Configuration Steps (Search Audit Logs):**
1. Go to **Audit** → **Audit log search**
2. Set **Date range:** Last 7 days
3. Under **Activities**, select: **All activities** or filter for:
   - `Export Tenant Key`
   - `Get Key`
   - `Decrypt Key`
   - `Enable Super User Feature`
4. Under **Users**, enter any user or leave blank for all
5. Click **Search**
6. Review results; export to CSV for forensic analysis

**PowerShell Alternative:**
```powershell
Connect-ExchangeOnline
Search-UnifiedAuditLog -StartDate "01/01/2024" -EndDate "12/31/2024" -Operations "Get Key", "Export Key" | 
  Select-Object CreationDate, UserIds, ClientIP, ObjectId, AuditData | 
  Export-Csv -Path "C:\AuditExport.csv" -NoTypeInformation
```

---

## 13. FORENSIC RESPONSE PROCEDURES

### Incident Response Timeline

**T+0 (Detection):**
- Alert triggered on key export or super user activation
- Immediately isolate affected service principal or user account

**T+15 minutes:**
- Export all MIP-related audit logs to preserve evidence
- Take Azure Key Vault snapshot (backup current state)
- Identify all users/SPs with Key Vault access in last 90 days

**T+1 hour:**
- Initiate password reset for all admin/privileged accounts
- Revoke compromised keys in Azure Key Vault
- Enable Key Vault purge protection (prevents deletion)

**T+4 hours:**
- Complete forensic analysis of encryption key access logs
- Identify scope of potential data exposure
- Begin rekey of MIP tenant key (via Set-AipServiceKeyProperties)

**T+24 hours:**
- Complete tenant key rekey process
- Re-encrypt all sensitive documents with new key material
- Publish incident report and remediation status

---

## 14. DEFENSIVE MITIGATIONS

### Priority 1: CRITICAL

**1.1 Enable Azure Key Vault Purge Protection & Soft Delete**

**Rationale:** Prevents attackers from permanently deleting keys after compromise; enforces recovery window

**Applies To Versions:** All Azure Key Vault versions

**Manual Steps (Azure Portal):**
1. Go to **Azure Portal** → **Key Vaults** → Select vault
2. Click **Settings** → **Properties**
3. Enable: **Purge Protection** (prevents deletion for 90 days)
4. Enable: **Soft Delete** (retains deleted keys for recovery)
5. Click **Save**

**Manual Steps (PowerShell):**
```powershell
# Enable purge protection on Key Vault
Update-AzKeyVault -ResourceGroupName "MyResourceGroup" -VaultName "MyKeyVault" `
  -EnablePurgeProtection $true

# Verify configuration
Get-AzKeyVault -ResourceGroupName "MyResourceGroup" -VaultName "MyKeyVault" | 
  Select-Object EnablePurgeProtection, EnableSoftDelete
```

**Verification:**
```powershell
Get-AzKeyVault -ResourceGroupName "MyResourceGroup" | 
  Select-Object VaultName, EnablePurgeProtection, EnableSoftDelete, 
  @{N="SoftDeleteRetentionDays";E={$_.SoftDeleteRetentionInDays}}
```

---

**1.2 Implement Azure Key Vault RBAC with Least Privilege**

**Rationale:** Restrict key access to named individuals; prevent overprivileged service accounts

**Applies To:** BYOK customers

**Manual Steps (Azure Portal):**
1. Go to **Key Vault** → **Access Control (IAM)**
2. Click **+ Add role assignment**
3. **Role:** `Key Vault Crypto User` (read-only access to keys)
4. **Assign to:** Specific user or service principal
5. Click **Review + assign**
6. **DO NOT USE:** `Key Vault Contributor` or `Owner` roles for routine key access

**Manual Steps (PowerShell):**
```powershell
# Assign minimal Key Vault role to user
$PrincipalId = (Get-AzADUser -UserPrincipalName "user@domain.com").Id
New-AzRoleAssignment -ObjectId $PrincipalId `
  -RoleDefinitionName "Key Vault Crypto User" `
  -Scope "/subscriptions/SUBSCRIPTION_ID/resourcegroups/RESOURCE_GROUP/providers/Microsoft.KeyVault/vaults/VAULT_NAME"

# Verify role assignment
Get-AzRoleAssignment -Scope "/subscriptions/SUBSCRIPTION_ID/resourcegroups/RESOURCE_GROUP/providers/Microsoft.KeyVault/vaults/VAULT_NAME" | 
  Where-Object RoleDefinitionName -Match "Crypto"
```

**Forbidden Roles (Audit & Remove):**
```powershell
# Identify overprivileged users
Get-AzRoleAssignment -Scope "/subscriptions/SUBSCRIPTION_ID" | 
  Where-Object RoleDefinitionName -In @("Owner", "Key Vault Contributor", "Contributor") | 
  Select-Object DisplayName, RoleDefinitionName, Scope
```

---

**1.3 Enable Azure Key Vault Diagnostic Logging**

**Rationale:** Audit all key access for incident investigation; detect unauthorized operations

**Manual Steps (Azure Portal):**
1. Go to **Key Vault** → **Diagnostic settings**
2. Click **+ Add diagnostic setting**
3. Name: `KeyVaultAuditLogging`
4. **Logs** → Enable: `AuditEvent`
5. **Destination details:**
   - Select: `Send to Log Analytics workspace`
   - Workspace: Select your Log Analytics workspace
6. Click **Save**
7. Wait 10-15 minutes for first events to appear

**Manual Steps (PowerShell):**
```powershell
# Enable diagnostic logging
$ResourceGroupName = "MyResourceGroup"
$VaultName = "MyKeyVault"
$WorkspaceId = "/subscriptions/SUBSCRIPTION_ID/resourcegroups/RESOURCE_GROUP/providers/microsoft.operationalinsights/workspaces/WORKSPACE_NAME"

New-AzDiagnosticSetting -Name "KeyVaultDiagnostics" `
  -ResourceId "/subscriptions/SUBSCRIPTION_ID/resourcegroups/$ResourceGroupName/providers/Microsoft.KeyVault/vaults/$VaultName" `
  -WorkspaceId $WorkspaceId `
  -Enabled $true `
  -Category AuditEvent

# Verify
Get-AzDiagnosticSetting -ResourceId "/subscriptions/SUBSCRIPTION_ID/resourcegroups/$ResourceGroupName/providers/Microsoft.KeyVault/vaults/$VaultName"
```

---

**1.4 Rotate MIP Tenant Key Immediately After Suspected Breach**

**Rationale:** Invalidates stolen keys; ensures future data is encrypted with new key material

**Applies To:** Both Microsoft-managed and BYOK topologies

**Manual Steps (PowerShell - Microsoft-managed):**
```powershell
# Connect to AIP Service
Connect-AipService

# Identify current active key
Get-AipServiceKeys | Where-Object IsPrimary -EQ $true | 
  Select-Object KeyId, CreationTime

# Create new key (if BYOK)
# Or select existing Microsoft-managed key to activate
$NewKey = Get-AipServiceKeys | Sort-Object CreationTime -Descending | Select-Object -First 1 -Skip 1

# Set as primary (rekey operation)
Set-AipServiceKeyProperties -KeyId $NewKey.KeyId -IsPrimary $true

# Verification
Get-AipServiceKeys | Select-Object KeyId, CreationTime, IsPrimary
```

**Manual Steps (PowerShell - BYOK Rekey):**
```powershell
# Identify new Azure Key Vault key
$NewKeyVaultKey = Get-AzKeyVaultKey -VaultName "MyKeyVault" -Name "NewMIPKey"

# Authorize AIP Service to use key vault
Set-AzKeyVaultAccessPolicy -VaultName "MyKeyVault" `
  -ServicePrincipalName "00000012-0000-0000-c000-000000000000" `
  -PermissionsToKeys get, decrypt, unwrapKey, wrapKey

# Configure new key for AIP Service
Use-AipServiceKeyVaultKey -KeyVaultKey $NewKeyVaultKey

# Activate as primary tenant key
Set-AipServiceKeyProperties -KeyId $NewKeyVaultKey.KeyIdentifier -IsPrimary $true
```

**Impact Assessment:**
- New content encrypted with new key immediately
- Existing content remains accessible (old key archived but retained)
- ~72 hours for full tenant rekey propagation
- No user-facing downtime

---

### Priority 2: HIGH

**2.1 Disable Azure RMS Super User Feature (if not required)**

**Rationale:** Super users can decrypt all tenant data; restricts attack surface

**Manual Steps (PowerShell):**
```powershell
# Check super user status
Get-AipServiceSuperUser

# If feature not required, disable
Disable-AipServiceSuperUserFeature

# Verification
Get-AipServiceSuperUserFeature | Select-Object Enabled
```

**Operational Impact:** eDiscovery and DLP may require re-enabling; requires case-by-case approval

---

**2.2 Implement Multi-Factor Authentication (MFA) for All Administrative Roles**

**Manual Steps (Azure Portal - Entra ID):**
1. Go to **Azure Portal** → **Entra ID** → **Roles and administrators**
2. Select each privileged role (Global Admin, Key Vault Admin, etc.)
3. Click **Settings**
4. Enable: **Require MFA for this role**
5. Save

**Manual Steps (PowerShell):**
```powershell
# Check current MFA enforcement
Get-MsolCompanyInformation | Select-Object StrongAuthenticationPolicy

# Enforce MFA for all users
$MFAUsers = Get-MsolUser -All | Where-Object {$_.IsLicensed -eq $true}
foreach ($User in $MFAUsers) {
  Set-MsolUser -UserPrincipalName $User.UserPrincipalName `
    -StrongAuthenticationRequirements @(New-Object `
    -TypeName Microsoft.Online.Administration.StrongAuthenticationRequirement)
}
```

---

**2.3 Enable Conditional Access Policy to Require Compliant Devices**

**Manual Steps (Azure Portal):**
1. Go to **Azure Portal** → **Entra ID** → **Security** → **Conditional Access**
2. Click **+ New policy**
3. Name: `Require Compliant Device for Key Vault Access`
4. **Assignments:**
   - Users: **All users**
   - Cloud apps: Select **Azure Key Vault** app
   - Conditions:
     - Platforms: **All platforms**
     - Locations: **Any location** (or restrict to corporate networks)
5. **Access controls:**
   - **Grant:** **Require device to be marked as compliant**
   - MFA: **Require multi-factor authentication**
   - Session: **Sign-in frequency:** `4 hours`
6. Enable policy: **On**
7. Click **Create**

**Manual Steps (PowerShell):**
```powershell
# Create Conditional Access policy
$PolicyName = "Require Compliant Device for Key Vault Access"
$AppId = "00000012-0000-0000-c000-000000000000"  # Azure Key Vault

# Policy creation via Microsoft Graph PowerShell
Connect-MgGraph -Scopes "Policy.ReadWrite.ConditionalAccess"

$policy = @{
  displayName = $PolicyName
  state = "enabled"
  conditions = @{
    applications = @{
      includeApplications = @($AppId)
    }
    users = @{
      includeUsers = @("All")
    }
  }
  grantControls = @{
    operator = "AND"
    builtInControls = @("compliantDevice", "mfa")
  }
}

New-MgIdentityConditionalAccessPolicy -BodyParameter $policy
```

---

### Compliance Mapping

| Compliance Framework | Control ID | Requirement | Mitigation |
|---|---|---|---|
| **NIST 800-53** | SC-12 | Cryptographic Key Establishment and Management | Enable Key Vault diagnostic logging; implement RBAC; rotate keys annually |
| **CIS Microsoft 365 v6.0** | 5.1 | Encryption at Rest with Strong Ciphers | Use RSA-3072 or AES-256; enable DKE for highly sensitive data |
| **DISA STIG (Office 365)** | SRG-APP-000014 | Cryptographic Mechanisms | Enforce BYOK with HSM protection; require MFA for key operations |
| **ISO 27001:2022** | A.10.1.1 | Policy on the Use of Cryptographic Controls | Document key lifecycle; implement automated rotation |
| **GDPR Article 32** | Encryption of Data | Protective Measures in Transit and at Rest | Enable encryption with customer-managed keys; maintain access logs |
| **DORA (EU)** | Article 17 | ICT Cryptographic Security | Implement FIPS 140-3 validation; enable HSM-based protection |
| **NIS2 Directive** | 4.2.1 | Technical Security Measures | Enable audit logging; implement threat detection; conduct quarterly reviews |

---

## 15. INCIDENT RESPONSE PLAYBOOK

### Scenario: MIP Master Key Compromised

**Assume Breach Timeline:**
1. **T+0h00m:** Alert triggered on suspicious key export
2. **T+0h15m:** Immediate containment actions
3. **T+1h00m:** Forensic analysis and scope determination
4. **T+4h00m:** Recovery and rekey execution
5. **T+24h00m:** Post-incident review

**Containment Actions:**
```powershell
# Step 1: Immediately revoke compromised account
$CompromisedUser = "attacker@domain.com"
Set-AzADUser -ObjectId (Get-AzADUser -UserPrincipalName $CompromisedUser).Id -AccountEnabled $false

# Step 2: Invalidate all refresh tokens for compromised user
Revoke-AzureADUserAllRefreshToken -ObjectId (Get-AzADUser -UserPrincipalName $CompromisedUser).Id

# Step 3: Reset MFA devices for account
Set-AzureADUser -ObjectId (Get-AzADUser -UserPrincipalName $CompromisedUser).Id -StrongAuthenticationPhoneNumber ""

# Step 4: Disable all service principals with elevated Key Vault access
Get-AzADServicePrincipal | Where-Object { # Check for suspicious creation dates } | 
  ForEach-Object { Disable-AzADServicePrincipal -ObjectId $_.Id }

# Step 5: Revoke all active Key Vault access tokens
Get-AzKeyVault -ResourceGroupName "Prod" | 
  ForEach-Object { Update-AzKeyVaultNetworkRuleSet -VaultName $_.VaultName `
    -DefaultAction "Deny" -Bypass "None" }
```

---

## APPENDIX: DETECTION RULE SOURCES

- **Web ID 3**: https://threatlabsnews.xcitium.com/blog/token-theft-incident-response-playbook-for-microsoft-365/ (Token Theft IR Playbook)
- **Web ID 4**: https://spin.ai/blog/stolen-microsoft-key-an-open-door-to-malicious-saas-apps/ (Stolen Microsoft Key Analysis)
- **Web ID 5**: https://attack.mitre.org/techniques/T1552/001/ (MITRE T1552.001 Mapping)
- **Web ID 6**: https://naveum.ch/en/microsoft-master-key-hack-and-importance-of-a-hybrid-cloud-strategy/ (Storm-0558 Analysis)
- **Web ID 7**: https://www.microsoft.com/en-us/security/blog/2025/02/06/code-injection-attacks-using-publicly-disclosed-asp-net-machine-keys/ (ASP.NET Key Compromise)
- **Web ID 18**: https://learn.microsoft.com/en-us/purview/rights-management-tenant-key (Microsoft Tenant Key Management)
- **Web ID 24**: https://learn.microsoft.com/en-us/purview/azure-rights-management-learn-about (Azure RMS Overview)
- **Web ID 28**: https://www.microsoft.com/en-us/security/blog/2020/12/21/advice-for-incident-responders-on-recovery-from-systemic-identity-compr/ (SAML Token Compromise IR)
- **Web ID 29**: https://heimdalsecurity.com/blog/stolen-microsoft-key-the-impact-is-higher-than-expected/ (Storm-0558 Full Impact)
- **Web ID 40**: https://research.splunk.com/detections/tactics/credential-access/ (Splunk Credential Access Detections)

---
