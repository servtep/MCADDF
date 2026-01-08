# CA-UNSC-013: TPM Key Extraction

**MITRE ATT&CK Technique:** T1552.004 (Unsecured Credentials: Private Keys)  
**CVE:** N/A (Logical vulnerability)  
**Platforms:** Entra ID, Windows Server, Enterprise Cloud Infrastructure  
**Severity:** CRITICAL  
**Viability:** ACTIVE  
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

## 1. EXECUTIVE SUMMARY

TPM (Trusted Platform Module) key extraction is a critical credential access attack that compromises cryptographic keys protected by the TPM, enabling attackers to impersonate devices, forge authentication tokens, and decrypt sensitive data in hybrid cloud environments. Threat actors who extract TPM-sealed keys, device authentication certificates, or service principal credentials can bypass multi-factor authentication, circumvent Conditional Access policies, and maintain persistent access across on-premises and cloud infrastructure. The Storm-0501 incident (August 2025) demonstrated real-world exploitation of hybrid environments lacking TPM protection on Entra Connect Sync servers, enabling account takeover of privileged identities. This module covers detection, response, and mitigation strategies specific to Entra ID hybrid deployments and Windows security infrastructure.

---

## 2. ATTACK NARRATIVE

### Attack Chain Overview

**Stage 1: Reconnaissance & Access Acquisition**
- Identify Entra Connect Sync servers lacking TPM protection
- Compromise local administrator account on on-premises infrastructure
- Obtain access to service principal credentials stored in local registry or files
- Identify device-bound authentication methods in use (PRT, device keys)
- Network reconnaissance for Entra Connect server IP addresses and authentication patterns

**Stage 2: TPM Key Extraction**
- **Local method:** Execute AADInternals or custom credential dumping tools from Entra Connect server
- **Remote method:** Exploit RDP/WinRM access to extract certificates via CNG API
- **Boot-level method:** Perform PCR reset attacks via UEFI firmware manipulation or sleep mode exploitation
- **HSM bypass:** If customer-managed keys, attempt to extract from unprotected backup files
- Extract device keys used for Entra ID device authentication (hybrid-joined devices)

**Stage 3: Token Forging & Impersonation**
- Use extracted service principal certificate to forge access tokens
- Impersonate cloud-managed identities without triggering MFA
- Bypass Conditional Access policies that trust device compliance status
- Perform operations as compromised service principal with Graph API permissions
- Reset passwords for high-privilege Entra ID accounts (if Sync Account obtained)

**Stage 4: Lateral Movement & Persistence**
- Access Exchange Online, SharePoint, Teams via forged tokens
- Modify Entra Connect Sync configuration to maintain backdoor access
- Create rogue service principals with persistence backdoors
- Establish federated domain trust for long-term cloud access
- Exfiltrate sensitive directory data via stolen PRT (Primary Refresh Token)

### Real-World Example: Storm-0501 (August 2025)

**Timeline:**
- **Initial Compromise:** Entra Connect Sync server running on Windows without TPM protection
- **Credential Theft:** Local admin compromise → extracted Entra Connector Account credentials
- **Privilege Escalation:** Password sync identified non-human synced identity with Global Admin role (MFA excluded)
- **Backdoor:** Registered attacker-owned Entra ID tenant as federated domain
- **Data Exfiltration:** Accessed Azure resources with escalated permissions

**Attack Characteristics:**
- Sync account had no TPM-backed certificate protection
- Direct credential access without token interception
- Sync account traditionally excluded from MFA policies
- Attack succeeded within 72 hours of initial compromise
- No traditional VPN/multi-factor authentication logs generated

**Microsoft's Response:**
- Microsoft Entra Connect v2.5.3.0+ introduced TPM-backed app authentication
- Announcement: "Enable Trusted Platform Module (TPM) on the Entra Connect Sync server to mitigate Storm-0501's credential extraction techniques"
- Recommended mitigation: Migrate from password-based to TPM-backed certificate authentication

---

## 3. TECHNICAL DETAILS

### TPM Architecture & Key Types

| Component | Function | Protection Level | Extractability |
|-----------|----------|-----------------|-----------------|
| **Storage Root Key (SRK)** | Primary wrapping key in TPM | Hardware-protected | Non-exportable |
| **Endorsement Key (EK)** | RSA key pair for attestation | Hardware-protected | Non-exportable |
| **Platform Configuration Registers (PCRs)** | Hash values of boot components (0-7 measured, 8-15 app-controlled) | Hardware-protected | Readable but tamper-obvious |
| **Sealed Keys** | Keys bound to specific PCR values | Hardware-protected + firmware measurement | Unseals only if PCRs match |
| **Device Keys** | Keys for Entra ID device authentication | TPM-protected if TPM available, else software | Hardware: non-exportable, Software: extracted via CNG |
| **Service Principal Certificates** | OAuth2 certificates in CNG KSP | Software-based encryption (DPAPI) | DPAPI decryptable with system privileges |

### TPM Sealing/Unsealing Mechanism

**Sealing Process (During Boot):**
1. BIOS/UEFI measures bootloader → PCR[4] = hash(bootloader)
2. Bootloader measures Windows kernel → PCR[11] = hash(kernel)
3. BitLocker/MIP creates encryption key, seals to PCR[7,11]
4. TPM stores sealed key with authorization policy
5. Key can only unseal if PCR values match expected values

**Unsealing Process (Normal Boot):**
1. System boots with unmodified firmware/kernel
2. PCR values match original measurements
3. TPM unseals key automatically
4. Encryption key released for data decryption
5. System continues normal operation

**Attack Scenario (Rootkit/Bootkit):**
1. Attacker modifies bootloader or kernel
2. PCR values change during boot
3. TPM refuses to unseal key (mismatch detected)
4. System cannot decrypt drive → security maintained
5. BUT: If attacker gains firmware-level access, can reset PCRs → unsealing succeeds

### Key Extraction Attack Vectors

**Attack Vector 1: Entra Connect Sync Credential Extraction**

Tool: **AADInternals PowerShell Module v0.9.4**
```powershell
# Attacker gains local admin on Entra Connect server
$SyncCredentials = Get-AADIntSyncCredentials
# Decrypts DPAPI-encrypted Entra Connector Account password
# Result: Plaintext credentials for cloud admin account
```

**Extraction Points:**
- Entra Connect database (LocalDB or SQL Server)
- DPAPI-protected registry keys
- Configuration files in Program Files
- ADSync service running context memory

---

**Attack Vector 2: TPM PCR Bypass (Boot-Level)**

Method: **PCR Reset via Firmware/Sleep Mode**
```bash
# Attacker with physical access or UEFI backdoor
# Option 1: Reset TPM via UEFI
tpm2_startup --clear

# Option 2: Manipulate PCR values via S3 sleep exploitation
# Reboot into custom OS, record PCR extensions
# S3 sleep state leaves some PCRs unmeasured
# On resume, extend PCRs to expected values
# TPM unseals key with fake measurement

# Option 3: Direct TPM power glitching
# Briefly disconnect TPM power, restart with reset values
# Requires hardware equipment (~$200 budget)
```

**Impact:** Bypass of BitLocker/MIP encryption without knowing encryption key

---

**Attack Vector 3: Device Key Export (Hybrid-Joined Device)**

```powershell
# Attacker with RDP access to Entra ID-joined device
# Query CNG (Cryptography API: Next Generation) for device keys
$KeyStore = Get-Item "HKLM:\Software\Microsoft\Cryptography\Calais"
# Device transport key + device authentication key accessible
# Export via CNG provider (if permissions allow)
```

**Impact:** Impersonate device to Entra ID, bypass device compliance checks

---

**Attack Vector 4: Service Principal Certificate Extraction**

```powershell
# Attacker with local admin on server running Azure AD Connect
# Access service principal certificates from registry/files
$CertPath = "C:\ProgramData\Microsoft\Crypto\RSA\S-1-5-18"
# DPAPI-encrypted certificate material
# Decrypt using SYSTEM privileges
$Cert = Get-Item $CertPath -Force

# Use extracted certificate to forge tokens
$Token = New-SignedJWT -Certificate $Cert -Claim {...}
```

**Impact:** Forge Azure AD access tokens, impersonate service principal

---

## 4. MITRE ATT&CK MAPPING

**Technique:** T1552.004 - Unsecured Credentials: Private Keys  
**Tactics Executed:**
- **Credential Access (TA0006):** Extract TPM-sealed keys, device certificates, service principal certs
- **Defense Evasion (TA0005):** Bypass MFA, Conditional Access, device compliance
- **Lateral Movement (TA0008):** Access cloud services using forged tokens
- **Persistence (TA0003):** Create rogue service principals, federated domains

**Sub-techniques Associated:**
- T1552.001 - Credentials in Files (Entra Connect database)
- T1552.002 - Credentials in Registry (DPAPI-encrypted keys)
- T1187 - Forced Authentication (token theft via AiTM)
- T1098 - Account Manipulation (add cloud credentials)
- T1078.004 - Cloud Accounts (impersonate compromised identities)

**Related Techniques:**
- T1621 - Multi-Factor Authentication Bypass
- T1556 - Modify Authentication Process
- T1528 - Steal Application Access Token
- T1199 - Trusted Relationship (federated domain takeover)

---

## 5. TOOLS & TECHNIQUES

### Attacker Tools

| Tool | Purpose | Viability Status | Download URL |
|------|---------|-----------------|--------------|
| **AADInternals** | Entra Connect credential dumping | ACTIVE | https://github.com/Gerenios/AADInternals |
| **Chipsec** | TPM and firmware analysis | ACTIVE | https://github.com/chipsec/chipsec |
| **tpm2-tools** | TPM 2.0 command-line interface | ACTIVE | https://github.com/tpm2-software/tpm2-tools |
| **Mimikatz CRYPTO** | Certificate extraction from CNG | ACTIVE | https://github.com/gentilkiwi/mimikatz |
| **Impacket GetNPUsers** | Kerberos preauthentication bypass | ACTIVE | https://github.com/fortra/impacket |
| **WinPwn** | Sensitive file discovery & credential harvesting | ACTIVE | https://github.com/S3cur3Th1sSh1t/WinPwn |
| **adconnectdump** | Extract credentials from AD Connect database | ACTIVE | https://github.com/fox-it/adconnectdump |
| **Infineon TPM Tools** | TPM manufacturer-specific tools | ACTIVE | Manufacturer support portals |

### Atomic Red Team Tests (T1552.004)

**Supported Platforms:** Windows, Linux, macOS

| Test Name | Command | Executor | Detection Trigger |
|-----------|---------|----------|------------------|
| Find private SSH keys | `find / -name "id_rsa" -o -name "id_dsa"` | bash/sh | File enumeration process |
| Export PKCS12 certificate | `openssl pkcs12 -export -in cert.pem -inkey key.pem` | bash | Child process + file write |
| Enumerate Windows certs | `Get-ChildItem Cert:\LocalMachine\My` | PowerShell | Certificate store access |
| Extract device keys (Windows) | `certutil -store MY` | cmd.exe | Certificate enumeration |
| LSASS memory dump (Mimikatz) | `mimikatz.exe "crypto::certificates /export"` | cmd.exe | Credential dumping detection |
| TPM key extraction (tpm2-tools) | `tpm2_readpublic -c 0x81000001` | bash | TPM command execution |
| Extract from AD Connect database | `adconnectdump.py` | python3 | Database query + file access |

**Execution Example:**
```powershell
# Atomic test execution
Invoke-AtomicTest T1552.004 -TestName "Find private SSH keys"

# Expected telemetry:
# - Process: bash/PowerShell.exe
# - Event: File enumeration in ~/.ssh directories
# - Registry: HKLM\Software\Microsoft\Cryptography access
```

---

## 6. FORENSIC ARTIFACTS

### Registry Keys Associated with TPM/Certificate Storage

| Registry Path | Event ID | Significance | Attacker Indicator |
|---------------|----------|--------------|-------------------|
| `HKLM\SYSTEM\CurrentControlSet\Services\TPM` | 4657 | TPM service status | Service disabled = mitigation bypass |
| `HKLM\SYSTEM\CurrentControlSet\Services\Tbs` | 4657 | TPM Base Services | Service restart attempts |
| `HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Device` | 4657 | Device compliance policy | Policy modifications |
| `HKLM\Software\Microsoft\Cryptography\Calais` | 4663 | CNG key store | Unauthorized key enumeration |
| `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Cryptography\RNG` | 4663 | Random number generator config | Tampering indicators |
| `HKCU\Software\Microsoft\Office\Outlook\Security` | 4657 | Certificate-based auth config | Security setting changes |
| `HKLM\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard` | 4657 | Hypervisor Code Integrity | Disabled virtualization protection |

### File System Artifacts

| Artifact Path | Artifact Type | Significance |
|---------------|---------------|--------------|
| `C:\Windows\System32\drivers\etc\hosts` | Text | TPM service domain redirection |
| `C:\ProgramData\Microsoft\Crypto\RSA\*` | Binary | Service principal certificates (DPAPI-encrypted) |
| `C:\Program Files\Microsoft Azure AD Connect\Data\*` | Database | Entra Connect configuration + credentials |
| `%APPDATA%\Microsoft\Crypto\RSA\*` | Binary | User certificate storage |
| `C:\Windows\Tasks\*` | XML | Scheduled tasks for credential harvesting |
| `C:\ProgramData\Microsoft\Crypto\RSA\S-1-5-18\*` | Binary | SYSTEM account certificates |
| `D:\Entra Connect Backup\*` | Files | Unencrypted backups containing secrets |
| `/sys/kernel/security/tpm0/` | Directory (Linux) | TPM device interface (if Entra on Linux) |

### Windows Event Log Indicators

| Event ID | Log Source | Significance | Detection Condition |
|----------|-----------|--------------|-------------------|
| **4663** | Security | Object Access | TPM device or cryptography registry accessed |
| **4657** | Security | Registry Value Modified | TPM policy or device compliance settings changed |
| **4688** | Security | Process Creation | AADInternals, Mimikatz, tpm2-tools executed |
| **4696** | Security | Backup/Restore Key | Attempt to export/backup encryption keys |
| **4768** | Security | Kerberos TGT Requested | Forged tokens with unusual pre-auth types |
| **4769** | Security | Service Ticket Requested | Anomalous service ticket requests |
| **1** | Sysmon | Process Creation | Parent process chain analysis for suspicious tools |
| **10** | Sysmon | Process Access | LSASS access for credential dumping |
| **12/13/14** | Sysmon | Registry Operations | Registry access to cryptography paths |
| **18** | Sysmon | Pipe Created | Named pipe connections to elevated processes |

---

## 7. SPLUNK DETECTION

### Splunk Prerequisites
- **Data Sources:** Windows Event Logs, Entra ID Sign-In Logs, PowerShell operational logs
- **Required Add-on:** Splunk Add-on for Microsoft Cloud Services v4.0+
- **Source Types:** `wineventlog:security`, `azure:aad:signin`, `powershell:operations`, `XmlWinEventLog:Microsoft-Windows-Sysmon/Operational`

### Detection 1: AADInternals Credential Extraction

**Detection Type:** Threat Pattern Matching  
**Alert Severity:** CRITICAL  
**Frequency:** Real-time  
**Applies To:** Windows Systems running Entra Connect Sync

**Splunk Query:**
```spl
index=windows source=XmlWinEventLog:Microsoft-Windows-Sysmon/Operational EventCode=1
  (CommandLine="*AADInternals*" OR CommandLine="*Get-AADIntSyncCredentials*" OR CommandLine="*Set-AADIntSyncPassword*")
  OR (Image="*powershell.exe" AND ParentImage="*services.exe" AND CommandLine CONTAINS "AAD")
| stats count, values(User) as ExecutingUser, values(ComputerName) as ComputerName, 
    values(CommandLine) as CommandLines by Image
| where count >= 1
| eval RiskScore = 100
```

**What This Detects:**
- Direct execution of AADInternals functions on Entra Connect servers
- Powershell running as SYSTEM executing AADInternals cmdlets
- Credential extraction attempts targeting sync service accounts
- Detection of specific keyword patterns associated with tool

**Alert Action:** Immediate isolation of affected system, credential reset, forensic analysis

---

### Detection 2: TPM Service Manipulation or Disablement

**Detection Type:** Configuration Baseline  
**Alert Severity:** HIGH  
**Frequency:** Every 15 minutes

**Splunk Query:**
```spl
index=windows source=wineventlog:security EventCode=4657 
  (ObjectName="*\\Services\\TPM\\*" OR ObjectName="*\\Services\\Tbs\\*" OR 
   ObjectName="*\\Policies\\System\\Device\\*")
  NewValue IN ("0", "Stopped", "Disabled")
| stats count, values(SubjectUserName) as User, values(Computer) as Host, 
    values(ObjectName) as ModifiedKey, values(OperationType) as Operation by _time
| where count >= 1
| eval Severity=if(SubjectUserName LIKE "%SYSTEM%", "Critical", "High")
```

**False Positive Analysis:**
- Legitimate Windows updates may temporarily stop TPM service
- Authorized administrators performing maintenance
- Tuning: Create allow-list for scheduled maintenance windows

**Tuning:**
```spl
index=windows source=wineventlog:security EventCode=4657 
  ObjectName LIKE "%Services%TPM%" NewValue="0"
| where NOT (SubjectUserName IN ("admin@domain.com", "SystemAccount") 
  AND _time >= "2024-01-01 02:00:00" AND _time < "2024-01-01 04:00:00")
```

---

### Detection 3: Suspicious Certificate Operations

**Detection Type:** Behavioral Anomaly  
**Alert Severity:** HIGH  
**Applies To:** Server with service principals

**Splunk Query:**
```spl
index=windows source=XmlWinEventLog:Microsoft-Windows-Sysmon/Operational EventCode IN (12, 13, 14)
  TargetObject LIKE "%Cryptography%"
  OR TargetObject LIKE "%Crypto\RSA%"
| stats count by Computer, User, TargetObject, CommandLine
| where count > 20 AND User != "NT AUTHORITY\SYSTEM"
| eval RiskScore=case(
    Image LIKE "%mimikatz%", 95,
    Image LIKE "%powershell%", 80,
    count > 50, 85,
    1=1, 70
)
```

---

## 8. MICROSOFT SENTINEL DETECTION

### Sentinel Prerequisites
- **Required Tables:** SigninLogs, AuditLogs, SecurityEvent, DeviceInfo
- **Required Fields:** UserAgent, DeviceId, ServicePrincipalName, OperationName, Result
- **Data Connectors:** Azure AD, Azure Activity, Security Events, Entra Connect Health

### Query 1: Detect Suspicious Entra Connect Sync Activity

**Rule Configuration:**
- **Required Table:** SigninLogs, AuditLogs
- **Required Fields:** ServicePrincipalName, ClientAppUsed, DeviceDetail, NetworkLocationDetails
- **Alert Severity:** High
- **Frequency:** Every 30 minutes
- **Lookback Window:** 1 hour
- **Applies To:** All subscriptions with Entra Connect deployment

**KQL Query:**
```kusto
SigninLogs
| where ServicePrincipalName contains "Microsoft Azure Active Directory Connect"
    and ResultType == 0  // Successful authentication
| extend SyncAccountName = ServicePrincipalName
| join kind=inner (
    AuditLogs
    | where OperationName in ("Update Directory Settings", "Enable-AipServiceSuperUserFeature", "Add Temporary Access Pass")
    | extend AuditActivityTime = TimeGenerated
) on $left.TimeGenerated, $right.TimeGenerated
| where TimeGenerated between ((now(-1h)) .. now())
| extend IPRiskLevel = case(
    ClientIP startswith "192.168" or ClientIP startswith "10.", "Low",
    ClientIP startswith "172.16" or ClientIP startswith "172.31", "Low",
    1=1, "Unknown"
)
| summarize SigninCount = count(), 
    AuditChangeCount = dcount(OperationName),
    UniqueClaims = dcount(Claims),
    MostRecentSignin = max(TimeGenerated) 
    by SyncAccountName, ClientIP, IPRiskLevel, DeviceDetail
| where SigninCount > 5 or AuditChangeCount > 2
| extend RiskScore = 
    case(
        IPRiskLevel == "Unknown" and SigninCount > 10, 85,
        AuditChangeCount > 3, 90,
        1=1, 65
    )
| where RiskScore >= 70
```

**What This Detects:**
- Entra Connect service principal signing in from unusual IP addresses
- Sync service making directory configuration changes immediately post-authentication
- Multiple authentication attempts from non-corporate networks
- Anomalous claims or tokens with unusual properties
- Correlation between sync authentication and privilege escalation activities

**Manual Configuration Steps (Azure Portal):**
1. Navigate to **Azure Portal** → **Microsoft Sentinel**
2. Select your workspace → **Analytics**
3. Click **+ Create** → **Scheduled query rule**
4. **General Tab:**
   - Name: `Detect Suspicious Entra Connect Sync Activity`
   - Severity: `High`
5. **Set rule logic Tab:**
   - Paste KQL query above
   - Run query every: `30 minutes`
   - Lookup data from the last: `1 hour`
6. **Incident settings Tab:**
   - Enable **Create incidents**
   - Grouping: By ServicePrincipalName
7. Click **Review + create**

**Manual Configuration Steps (PowerShell):**
```powershell
# Connect to Sentinel workspace
Connect-AzAccount
$ResourceGroup = "YourResourceGroup"
$WorkspaceName = "YourSentinelWorkspace"

# Create the analytics rule
New-AzSentinelAlertRule -ResourceGroupName $ResourceGroup -WorkspaceName $WorkspaceName `
  -DisplayName "Detect Suspicious Entra Connect Sync Activity" `
  -Query @"
SigninLogs
| where ServicePrincipalName contains 'Microsoft Azure Active Directory Connect'
| where ResultType == 0
| stats count() by ServicePrincipalName, ClientIP
| where count > 5
"@ `
  -Severity "High" `
  -Enabled $true `
  -Frequency (New-TimeSpan -Minutes 30) `
  -Period (New-TimeSpan -Hours 1)
```

---

### Query 2: Device Key Extraction Detection

**Rule Configuration:**
- **Required Table:** SecurityEvent, DeviceInfo
- **Alert Severity:** High
- **Applies To:** All Entra ID-joined/hybrid-joined devices

**KQL Query:**
```kusto
SecurityEvent
| where EventID == 4663  // File accessed
    and ObjectName contains "Cryptography"
| extend ExtractedPath = tostring(split(ObjectName, "\\")[-1])
| join kind=inner (
    DeviceInfo
    | where IsCompliant == false  // Non-compliant devices = higher risk
) on $left.Computer == $right.DeviceName
| summarize AccessCount = count(), 
    FirstAccess = min(TimeGenerated),
    LastAccess = max(TimeGenerated),
    Users = make_set(Account) 
    by Computer, ObjectName, ExtractedPath, IsCompliant
| where AccessCount > 10 or TimeGenerated < ago(1h)
| extend RiskIndicator = case(
    IsCompliant == false and AccessCount > 15, "Very High",
    AccessCount > 25, "High",
    1=1, "Medium"
)
```

---

## 9. WINDOWS EVENT LOG MONITORING

### Event ID: 4663 (Attempt to Access Object)

**Log Source:** Security  
**Trigger:** Read/Write access to TPM device or cryptography registry keys  
**Applies To Versions:** Server 2016+, Windows 10+

**Manual Configuration Steps (Group Policy):**
1. Open **Group Policy Management Console** (gpmc.msc)
2. Navigate to **Computer Configuration** → **Policies** → **Windows Settings** → **Security Settings** → **Advanced Audit Policy Configuration**
3. Expand **Object Access**
4. Enable: **Audit File System** and **Audit Registry**
5. Set both to: **Success and Failure**
6. Run `gpupdate /force` on target machines

**Forensic Query (PowerShell):**
```powershell
$StartTime = (Get-Date).AddHours(-24)
Get-WinEvent -FilterHashtable @{
    LogName = "Security"
    Id = 4663
    StartTime = $StartTime
} | Where-Object {
    $_.Properties[10].Value -match "Cryptography|TPM" -and
    $_.Properties[7].Value -match "Read|Write"
} | Select-Object TimeCreated, 
    @{N="User";E={$_.Properties[1].Value}}, 
    @{N="Object";E={$_.Properties[10].Value}},
    @{N="AccessType";E={$_.Properties[7].Value}}
```

---

### Event ID: 4688 (Process Creation)

**Log Source:** Security  
**Trigger:** Execution of credential harvesting or TPM manipulation tools  
**Detection Condition:** CommandLine contains "AADInternals", "mimikatz", "tpm2-tools", "chipsec"

**Manual Configuration Steps (Local Policy):**
1. Open **Local Security Policy** (secpol.msc)
2. Navigate to **Security Settings** → **Advanced Audit Policy Configuration** → **Process Tracking**
3. Enable: **Audit Process Creation**
4. Set to: **Success and Failure**
5. Run `auditpol /set /subcategory:"Process Creation" /success:enable /failure:enable`

---

## 10. SYSMON DETECTION PATTERNS

**Minimum Sysmon Version:** 13.0+  
**Supported Platforms:** Windows 10, Windows Server 2016+

**Sysmon Event IDs to Monitor:**
- **Event ID 1:** Process creation (AADInternals, Mimikatz)
- **Event ID 10:** Process memory access (LSASS for credential dumping)
- **Event ID 12/13/14:** Registry operations (TPM, cryptography keys)
- **Event ID 23:** File deletion (cleanup of logs, evidence)

**Sysmon XML Configuration:**
```xml
<Sysmon schemaversion="4.22">
  <HashAlgorithms>md5,sha256</HashAlgorithms>
  
  <!-- Detect credential harvesting tools -->
  <ProcessCreate onmatch="include">
    <Image condition="image">AADInternals.ps1</Image>
    <Image condition="image">mimikatz.exe</Image>
    <CommandLine condition="contains">Get-AADIntSyncCredentials</CommandLine>
    <CommandLine condition="contains">crypto::certificates</CommandLine>
  </ProcessCreate>
  
  <!-- Detect LSASS access for credential dumping -->
  <ProcessAccess onmatch="include">
    <TargetImage condition="image">lsass.exe</TargetImage>
    <GrantedAccess condition="is">0x1438</GrantedAccess>  <!-- Full access -->
  </ProcessAccess>
  
  <!-- Detect TPM/Cryptography registry access -->
  <RegistryEvent onmatch="include">
    <TargetObject condition="contains">Services\TPM</TargetObject>
    <TargetObject condition="contains">Cryptography\RNG</TargetObject>
    <TargetObject condition="contains">Crypto\RSA</TargetObject>
  </RegistryEvent>
  
  <!-- Detect suspicious file operations -->
  <FileCreate onmatch="include">
    <TargetFilename condition="contains">\.pfx</TargetFilename>
    <TargetFilename condition="contains">\.p12</TargetFilename>
    <TargetFilename condition="contains">\.cer</TargetFilename>
    <Image condition="is">powershell.exe</Image>
  </FileCreate>
</Sysmon>
```

**Manual Configuration Steps:**
1. Download Sysmon from [Microsoft Sysinternals](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)
2. Create config file `sysmon-tpm-config.xml` with XML above
3. Install Sysmon:
   ```cmd
   sysmon64.exe -accepteula -i sysmon-tpm-config.xml
   ```
4. Verify installation:
   ```powershell
   Get-Service Sysmon64
   Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 10
   ```

---

## 11. MICROSOFT DEFENDER FOR CLOUD

### MDC Alert: "Suspicious Cryptographic Key Access Pattern"

**Alert Name:** CryptoKeyExtractionAttempt  
**Severity:** High  
**Description:** Microsoft Defender for Cloud detects process attempting to access or export cryptographic keys protected by TPM or CNG, indicating potential credential theft  
**Applies To:** All servers with Defender for Servers enabled  
**Remediation:**
1. Isolate affected server immediately
2. Review TPM and cryptographic key access logs
3. Reset credentials for all service principals/accounts
4. Enable TPM protection on unprotected systems
5. Rotate certificates and encryption keys

**Manual Configuration Steps:**
1. Navigate to **Azure Portal** → **Microsoft Defender for Cloud**
2. Go to **Environment settings**
3. Select your subscription
4. Under **Defender plans**, enable:
   - **Defender for Servers**: ON
   - **Defender for Key Vault**: ON
5. Go to **Security alerts** → **Filter** by "Cryptographic Key"
6. Configure automated playbooks for auto-remediation

**Reference:** [Microsoft Defender for Cloud Alerts](https://learn.microsoft.com/en-us/defender-cloud/alerts-reference)

---

## 12. MICROSOFT PURVIEW (UNIFIED AUDIT LOG)

### Query: Entra Connect Configuration Changes & Service Principal Operations

**Operations:** Update Directory Settings, Add Credentials, Modify Sync Settings  
**Workload:** Azure Active Directory, Azure Administrative Activity

**PowerShell Query:**
```powershell
Search-UnifiedAuditLog `
  -Operations "Update Directory Settings", "Add service principal credentials", 
    "Update application", "Set service principal" `
  -StartDate (Get-Date).AddDays(-7) `
  -EndDate (Get-Date) `
  -ResultSize 10000 | 
  Where-Object {$_.UserIds -like "*sync*" -or $_.UserIds -like "*Connector*"} |
  Select-Object CreationDate, UserIds, Operations, AuditData | 
  Export-Csv -Path "C:\EntraConnect-Audit.csv"
```

**Manual Configuration Steps (Enable Audit Log):**
1. Navigate to **Microsoft Purview Compliance Portal** (https://compliance.microsoft.com)
2. Go to **Audit** (left navigation)
3. If not enabled, click **Turn on auditing**
4. Wait 24-48 hours for logs to activate

**Manual Configuration Steps (Search):**
1. Go to **Audit** → **Audit log search**
2. Set **Date range:** Last 30 days
3. Under **Activities**, select:
   - `Update Directory Settings`
   - `Add Temporary Access Pass`
   - `Modify Service Principal`
   - `Update Sync Features`
4. Under **Users**, search for: `*sync*` or `*Connector*`
5. Click **Search** and export results

---

## 13. DEFENSIVE MITIGATIONS

### Priority 1: CRITICAL

**1.1 Enable TPM 2.0 on All Entra Connect Servers**

**Rationale:** TPM 2.0 provides hardware-protected key storage with anti-hammering protection against brute force attacks; prevents local key extraction attacks

**Applies To:** Entra Connect Sync servers, hybrid-joined devices

**Manual Steps (BIOS/UEFI):**
1. Restart server and enter BIOS/UEFI setup (typically F2, DEL, or F10)
2. Navigate to **Security** tab
3. Locate **Trusted Platform Module (TPM)** setting
4. Change from **Disabled** to **Enabled** or **Active**
5. Save settings and exit BIOS
6. System will reboot; Windows will initialize TPM

**Manual Steps (Verify TPM in Windows):**
```powershell
# Check TPM status
Get-WmiObject -Namespace "root\cimv2\security\microsofttpm" -Class Win32_Tpm | 
  Select-Object IsEnabled, IsActivated

# Verify TPM 2.0
Get-Item -Path Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tbs |
  Get-ItemProperty | Select-Object -ExpandProperty Description
```

**Manual Steps (Group Policy - Windows Server):**
1. Open **Group Policy Management Console** (gpmc.msc)
2. Navigate to **Computer Configuration** → **Administrative Templates** → **System** → **Device Guard**
3. Enable: **Turn on virtualization-based security**
4. Enable: **Require UEFI Memory Attributes Table**
5. Run `gpupdate /force`

---

**1.2 Migrate Entra Connect to TPM-backed Certificate Authentication (v2.5.3.0+)**

**Rationale:** Eliminates plaintext password storage on Entra Connect servers; uses TPM-protected certificates instead

**Applies To:** New deployments or upgrades of Entra Connect Sync v2.5.3.0+

**Manual Steps (Upgrade Entra Connect):**
```powershell
# Download latest Entra Connect from Microsoft
# https://www.microsoft.com/en-us/download/details.aspx?id=47594

# Stop Entra Connect sync service
Stop-Service ADSync

# Backup current configuration (CRITICAL)
$BackupPath = "C:\ADConnectBackup\$(Get-Date -Format 'yyyyMMdd_HHmmss')"
New-Item -Path $BackupPath -ItemType Directory | Out-Null
Copy-Item "C:\Program Files\Microsoft Azure AD Connect" -Destination $BackupPath -Recurse

# Install upgraded version
# Run installer: AzureADConnect.msi
# Select "Configure device options"
# Choose "Application-based authentication with TPM backing"

# Verify TPM-backed certificate created
Get-ChildItem Cert:\LocalMachine\My | Where-Object {$_.Subject -like "*Entra*"} |
  Select-Object Subject, Thumbprint, @{N="StorageProvider";E={$_.PrivateKey.CspKeyContainerInfo.MachineKeyStore}}
```

**Expected Output:**
```
StorageProvider: True  # Indicates TPM storage
```

---

**1.3 Enforce MFA for Directory Synchronization Service Account**

**Rationale:** Adds second factor to sync account authentication, preventing account takeover even if password compromised

**Applies To:** All Entra Connect Sync service accounts

**Manual Steps (Azure Portal):**
1. Go to **Azure Portal** → **Entra ID** → **Security** → **Conditional Access**
2. Click **+ New policy**
3. Name: `Require MFA for Sync Accounts`
4. **Assignments:**
   - Users: Select **Directory Synchronization Accounts** role members
   - Cloud apps: **All cloud apps**
5. **Conditions:**
   - Locations: **Named locations** (restrict to Entra Connect server IP)
6. **Access controls:**
   - Grant: **Require multi-factor authentication**
7. Enable policy: **On**
8. Click **Create**

**Manual Steps (PowerShell):**
```powershell
# Identify sync accounts
$SyncAccounts = Get-MgRoleManagementDirectoryRoleAssignment -Filter "roleDefinitionId eq 'Directory Synchronization Accounts'"

# For each account, enforce MFA
foreach ($Account in $SyncAccounts) {
  $User = Get-MgUser -UserId $Account.PrincipalId
  # MFA enforcement via Conditional Access (not direct assignment in modern Azure)
  Write-Output "Sync Account: $($User.UserPrincipalName)"
}
```

---

**1.4 Restrict Entra Connect Server Access via Network Segmentation**

**Rationale:** Limits lateral movement and credential extraction by isolating Entra Connect on dedicated subnet

**Manual Steps (Network Security Group):**
1. Go to **Azure Portal** → **Network Security Groups**
2. Create NSG: `Entra-Connect-Server-NSG`
3. **Inbound rules:**
   - Allow HTTPS (443) from Azure AD service IP ranges only
   - Allow HTTPS (443) to Azure Key Vault (if BYOK)
   - Deny all other inbound traffic
4. **Outbound rules:**
   - Allow HTTPS (443) to Azure AD endpoints
   - Allow HTTPS (443) to Microsoft endpoint protection (if using MDE)
   - Deny RDP (3389) outbound to non-Tier0 networks
5. Associate NSG with Entra Connect server's network interface

---

### Priority 2: HIGH

**2.1 Enable Measured Boot and TPM Attestation**

**Rationale:** Creates cryptographic record of boot components; enables detection of tampering

**Manual Steps (Group Policy):**
1. Open **gpmc.msc**
2. Navigate to **Computer Configuration** → **Administrative Templates** → **System** → **Device Guard**
3. Enable: **Configured Measured Boot**
4. Select: **With standard DMA protection**
5. Run `gpupdate /force`

**Verification:**
```powershell
# Check Measured Boot status
Get-WmiObject -Namespace "root\cimv2\security\microsofttpm" -Class Win32_Tpm |
  Select-Object @{N="MeasuredBootSupported";E={$_.IsEnabled}}

# View PCR values
Get-WmiObject -Namespace "root\cimv2\security\microsofttpm" -Class Win32_LogicalProcessorGroup |
  ForEach-Object {$_.Description}
```

---

**2.2 Configure TPM Anti-Hammering Parameters**

**Rationale:** Prevents brute force attacks on TPM-protected keys

**Manual Steps (Group Policy):**
1. Open **gpmc.msc**
2. Navigate to **Computer Configuration** → **Administrative Templates** → **System** → **Trusted Platform Module Services**
3. Enable: **Configure Dictionary Attack Prevention Parameters**
4. Set:
   - Lock threshold: `32`
   - Lockout duration: `10` minutes
   - Failure reset duration: `320` minutes
5. Run `gpupdate /force`

---

**2.3 Implement Certificate Pinning for Entra Connect Service Principal**

**Rationale:** Prevents certificate substitution attacks; binds service principal to specific certificate

**Manual Steps (PowerShell):**
```powershell
# Get current service principal certificate
$ServicePrincipal = Get-MgServicePrincipal -Filter "displayName eq 'Microsoft Azure Active Directory Connect'"
$CurrentCert = $ServicePrincipal.KeyCredentials[0]

# Extract certificate thumbprint for pinning
$Thumbprint = $CurrentCert.CustomKeyIdentifier | ForEach-Object {([System.Convert]::ToHexString($_))}

# Store in secure location for baseline comparison
"Thumbprint,$Thumbprint" | Out-File "C:\Secure\AzureAD_SPN_Cert_Baseline.txt" -Force

# Regularly compare against baseline
$CurrentThumbprint = (Get-MgServicePrincipal -Filter "displayName eq 'Microsoft Azure Active Directory Connect'").KeyCredentials[0].CustomKeyIdentifier
if ($CurrentThumbprint -ne $Thumbprint) {
  Write-Error "ALERT: Service principal certificate has changed!"
  # Trigger incident response
}
```

---

### Compliance Mapping

| Compliance Framework | Control ID | Requirement | Mitigation |
|---|---|---|---|
| **NIST 800-53** | SC-12 | Cryptographic Key Establishment and Management | Enable TPM on all systems; enforce 90-day key rotation |
| **NIST 800-53** | SC-7 | Boundary Protection | Network segmentation for Entra Connect servers |
| **CIS Microsoft 365** | 5.2 | MFA for Privileged Accounts | Enable MFA for sync service accounts |
| **DISA STIG (Windows)** | WN10-00-000050 | TPM Initialization | Enable and initialize TPM 2.0 |
| **ISO 27001:2022** | A.10.1.1 | Policy on use of cryptographic controls | Document TPM usage; implement key lifecycle management |
| **DORA (EU)** | Article 17 | ICT cryptographic security | Use FIPS 140-3 validated TPM; implement HSM for sensitive keys |
| **NIS2 Directive** | 4.2.1 | Technical security measures | Implement TPM attestation; monitor key access logs |

---

## 14. INCIDENT RESPONSE PLAYBOOK

### Scenario: TPM Key Extracted from Entra Connect Server

**Assume Breach Timeline:**
1. **T+0h00m:** Alert triggered on AADInternals execution or TPM service manipulation
2. **T+0h15m:** Immediate containment actions
3. **T+1h00m:** Forensic analysis and scope determination
4. **T+4h00m:** Recovery and credential rotation
5. **T+24h00m:** Post-incident review and hardening

**Containment Actions:**
```powershell
# Step 1: Isolate Entra Connect server from network
Get-WmiObject Win32_NetworkAdapterConfiguration -Filter "IPEnabled=true" |
  ForEach-Object { $_.SetDNSServerSearchOrder(@()) } # Clear DNS

# Step 2: Force password reset for all service accounts
$ServiceAccounts = Get-ADUser -Filter {Name -like "*sync*" -or Name -like "*Connector*"}
foreach ($Account in $ServiceAccounts) {
  Set-ADAccountPassword -Identity $Account -Reset -NewPassword (ConvertTo-SecureString -AsPlainText (New-Guid).Guid -Force)
  Set-ADUser -Identity $Account -ChangePasswordAtLogon $true
}

# Step 3: Invalidate all active refresh tokens
Revoke-AzureADUserAllRefreshToken -ObjectId (Get-AzADUser -UserPrincipalName "sync_*@domain.onmicrosoft.com").Id

# Step 4: Clear cached credentials
Remove-Item -Path "HKLM:\Software\Microsoft\Cryptography\Calais" -Force

# Step 5: Rotate service principal credentials
$ServicePrincipal = Get-MgServicePrincipal -Filter "displayName eq 'Microsoft Azure Active Directory Connect'"
Remove-MgServicePrincipalKey -ServicePrincipalId $ServicePrincipal.Id -KeyId $OldKeyId
New-MgServicePrincipalPasswordCredential -ServicePrincipalId $ServicePrincipal.Id
```

---

## APPENDIX: SOURCE CITATIONS

- **Web ID 113**: https://attack.cloudfall.cn/techniques/T1552/004/ (MITRE T1552.004 Mapping)
- **Web ID 114**: https://thehackernews.com/2025/08/storm-0501-exploits-entra-id-to.html (Storm-0501 August 2025 Campaign)
- **Web ID 115**: https://cyberraiden.wordpress.com/2025/03/28/tpm-and-windows-os/ (TPM Sealing/Unsealing Technical Details)
- **Web ID 116**: https://www.intellisecsolutions.com/2024/08/28/protect-against-token-theft/ (Entra ID Token Protection)
- **Web ID 119**: https://blog.nviso.eu/2025/09/25/securing-microsoft-entra-id/ (TPM vs Certificate-based Authentication)
- **Web ID 134**: https://hacky.solutions/blog/2024/02/tpm-attack/ (TPM Bypass Techniques & PCR Reset)
- **Web ID 133**: https://www.anoopcnair.com/entra-connect-sync-tpm-app-authentication/ (TPM-backed App Authentication for Entra Connect)
- **Web ID 144**: https://github.com/Cloud-Architekt/AzureAD-Attack-Defense/blob/main/AADCSyncServiceAccount.md (Comprehensive Entra Connect Attack/Defense)
- **Web ID 151**: https://www.ctrlshiftenter.cloud/2025/05/29/entra-connect/ (Entra Connect Security Hardening)
- **Web ID 153**: https://www.semperis.com/blog/microsoft-entra-connect-compromise/ (Entra Connect Compromise Detection)

---
